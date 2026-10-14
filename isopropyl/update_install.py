"""Stage official updates and replace installations after the exact app exits.

This module also runs as an isolated, standard-library-only helper. Never
import GUI modules here: on Windows its interpreter lives outside the runtime
being replaced, so neither Python nor Qt keeps that runtime locked.
"""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import argparse
import email.parser
import hashlib
import importlib.metadata
import json
import os
import platform
import plistlib
import re
import secrets
import select
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import time
import uuid
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath


class UpdateInstallError(RuntimeError):
    pass


@dataclass(frozen=True)
class Installation:
    kind: str
    supported: bool
    reason: str
    root: str
    python: str
    restart_argv: tuple[str, ...]
    pointer: str = ''


@dataclass(frozen=True)
class InstallPlan:
    kind: str
    version: str
    root: str
    staged: str
    work: str
    python: str
    restart_argv: tuple[str, ...]
    status_path: str
    log_path: str
    pointer: str = ''
    old_pointer: str = ''
    members: tuple[str, ...] = ()
    token: str = ''


@dataclass(frozen=True)
class InstallLaunch:
    pid: int
    status_path: str
    log_path: str


def _state_directory():
    if sys.platform == 'win32':
        root = Path(os.environ.get('LOCALAPPDATA', Path.home()/'AppData/Local'))/'ISOpropyl'
    elif sys.platform == 'darwin':
        root = Path.home()/'Library/Application Support/ISOpropyl'
    else:
        root = Path(os.environ.get('XDG_STATE_HOME', Path.home()/'.local/state'))/'isopropyl'
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def _json_write(path, value):
    path = Path(path)
    temporary = path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    try:
        with temporary.open('x', encoding='utf-8') as output:
            json.dump(value, output); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_update_status(installation=None):
    path = _state_directory()/'update-status.json'
    try:
        if path.stat().st_size > 65536:
            return None
        result = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(result, dict) or result.get('state') not in {
                'prepared', 'waiting', 'installing', 'installed', 'rolled-back', 'failed'}:
            return None
        if installation is not None and installation.root not in {result.get('root'),result.get('active_root')}:
            return None
        return result
    except (OSError, ValueError):
        return None


def detect_installation():
    python = str(Path(sys.executable).absolute())
    package = Path(__file__).resolve().parent
    if sys.platform == 'win32':
        root = Path(sys.executable).absolute().parent.parent
        supported = (root/'launch.py').is_file() and (root/'runtime/pythonw.exe').is_file()
        return Installation('portable-zip', supported,
            '' if supported else 'Updates require the complete Windows portable installation.',
            str(root), python, (str(root/'runtime/pythonw.exe'), str(root/'launch.py'))+
            (('--portable',) if '--portable' in sys.argv else ()))
    if sys.platform == 'darwin':
        pointer = Path.home()/'Applications/ISOpropyl.app/Contents/Resources/runtime.txt'
        if pointer.is_file():
            try:
                runtime = Path(pointer.read_text().strip()).absolute()
                if (Path(sys.prefix).resolve() == runtime.resolve() and package.is_relative_to(runtime.resolve())
                        and (runtime/'pyvenv.cfg').is_file()):
                    return Installation('offline-wheelhouse', True, '', str(runtime), python,
                                        (str(pointer.parents[2]/'Contents/MacOS/ISOpropyl'),), str(pointer))
            except OSError:
                pass
    if sys.prefix != sys.base_prefix and (Path(sys.prefix)/'pyvenv.cfg').is_file():
        site = Path(sysconfig.get_path('purelib')).absolute()
        supported = package.parent == site.resolve() and os.access(site, os.W_OK)
        launcher = Path(sys.prefix)/'bin/isopropyl'
        return Installation('wheel', supported,
            '' if supported else 'Source checkouts and editable installations cannot be replaced in place.',
            str(site), python, (python, '-I', str(launcher)))
    if sys.platform == 'linux' and str(package).startswith('/usr/lib/python3/dist-packages/'):
        supported = all(Path(path).is_file() for path in ('/usr/bin/pkexec','/usr/bin/apt-get','/usr/bin/dpkg-deb','/usr/bin/dpkg'))
        return Installation('deb', supported, '' if supported else 'The desktop package installer is unavailable.',
                            '/usr', python, ('/usr/bin/isopropyl',))
    return Installation('wheel', False,
        'Install a managed application or a dedicated virtual environment to enable in-app installation.',
        str(package.parent), python, ())


def _safe_member(name):
    if not name or '\\' in name or '\x00' in name or ':' in name:
        raise UpdateInstallError('The update archive contains an unsafe filename')
    pure = PurePosixPath(name)
    if pure.is_absolute() or any(part in {'', '.', '..'} for part in name.rstrip('/').split('/')):
        raise UpdateInstallError('The update archive contains a path outside its destination')
    for part in pure.parts:
        if part.rstrip(' .') != part or part.split('.')[0].upper() in {
                'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1,10)), *(f'LPT{i}' for i in range(1,10))}:
            raise UpdateInstallError('The update archive contains a nonportable filename')
    return pure


def _extract(archive, destination):
    """Extract bounded regular entries only; never call ZipFile.extractall."""
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if len(entries) > 100000 or sum(item.file_size for item in entries) > 5*1024**3:
            raise UpdateInstallError('The update archive exceeds its extraction limits')
        seen = set();spellings = {}
        for item in entries:
            # ZipInfo normalizes separators on Windows and truncates NULs.
            # Validate the original stored name before using its parsed form.
            raw_name = item.orig_filename
            pure = _safe_member(raw_name)
            if item.filename != raw_name:
                raise UpdateInstallError('The update archive contains a normalized filename')
            for index in range(1,len(pure.parts)+1):
                spelling='/'.join(pure.parts[:index]);folded=spelling.casefold()
                if folded in spellings and spellings[folded]!=spelling:
                    raise UpdateInstallError('The update archive contains colliding path spellings')
                spellings[folded]=spelling
            key = str(pure).casefold()
            mode = item.external_attr >> 16
            if key in seen or item.flag_bits & 1 or stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise UpdateInstallError('The update archive contains duplicate, encrypted, or nonregular entries')
            seen.add(key)
            path = destination.joinpath(*pure.parts)
            if item.is_dir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with source.open(item) as input_file, path.open('xb') as output:
                shutil.copyfileobj(input_file, output, length=1024*1024)
            path.chmod(0o755 if mode & 0o111 else 0o644)
    return destination


def _snapshot(payload, destination, checksum):
    if not re.fullmatch(r'[0-9a-fA-F]{64}', checksum):
        raise UpdateInstallError('The official update checksum is invalid')
    digest = hashlib.sha256()
    with Path(payload).open('rb') as source, destination.open('xb') as output:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise UpdateInstallError('The update must be a regular file')
        while block := source.read(1024*1024):
            digest.update(block); output.write(block)
        output.flush(); os.fsync(output.fileno())
    if digest.hexdigest().lower() != checksum.lower():
        raise UpdateInstallError('The update failed its independent SHA-256 verification')


def _run(argv, log, *, timeout=300, env=None):
    result = subprocess.run([str(arg) for arg in argv], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=env, shell=False)
    with Path(log).open('ab') as output:
        output.write(result.stdout[-32768:])
    if result.returncode:
        raise UpdateInstallError(f'Update command failed with exit status {result.returncode}; see {log}')


def _health(python, version, log):
    code = ('import importlib.metadata; '
            'assert importlib.metadata.version("isopropyl")=='+repr(version)+'; '
            'import isopropyl.entrypoints, isopropyl.update_install; from PyQt6.QtWidgets import QApplication; '
            'app=QApplication([]); '
            'import sys; '
            'from isopropyl.helper_tools import helper; '
            '[helper(name) for name in ("mke2fs","mkntfs","ntfs-tree","mkudffs","wimlib-imagex","7z","qemu-img","gpgv")] '
            'if sys.platform in {"darwin","win32"} else None')
    env = dict(os.environ, QT_QPA_PLATFORM='offscreen')
    _run([python, '-I', '-c', code], log, timeout=60, env=env)


def _wheel_metadata(wheel, version):
    with zipfile.ZipFile(wheel) as archive:
        metadata = [name for name in archive.namelist() if re.fullmatch(r'isopropyl-[^/]+\.dist-info/METADATA',name)]
        if len(metadata) != 1:
            raise UpdateInstallError('The wheel does not contain one ISOpropyl distribution')
        if archive.getinfo(metadata[0]).file_size>1024*1024:
            raise UpdateInstallError('The update wheel metadata exceeds its size limit')
        message = email.parser.BytesParser().parsebytes(archive.read(metadata[0]))
        if message.get('Name','').lower() != 'isopropyl' or message.get('Version') != version:
            raise UpdateInstallError('The update wheel does not match the selected release')
        return metadata[0].split('/')[0], message


def prepare_update(release, payload, installation=None, progress=None):
    return prepare_install(payload, release.asset.sha256, release.asset.kind, release.version,
                           installation=installation, progress=progress)


def prepare_install(payload, checksum, kind, version, *, installation=None, progress=None):
    installation = installation or detect_installation()
    if not installation.supported:
        raise UpdateInstallError(installation.reason)
    if kind != installation.kind or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*(?:[A-Za-z0-9.+-]*)',version):
        raise UpdateInstallError('The update does not match this installation')
    root = Path(installation.root).absolute()
    parent = root.parent if kind in {'portable-zip','wheel'} else _state_directory()
    work = parent/('.isopropyl-update-'+uuid.uuid4().hex)
    if sys.platform=='win32':
        from .portable_fs import os as private_os
        private_os.mkdir(work,0o700)
    else:work.mkdir(mode=0o700)
    state = _state_directory(); log = work/'update.log'; log.touch()
    progress = progress or (lambda *args: None)
    try:
        snapshot = work/('payload'+Path(payload).suffix)
        _snapshot(payload, snapshot, checksum)
        progress('Preparing verified application update',0,1)
        staged = snapshot; members = (); old_pointer = ''
        if kind == 'portable-zip':
            unpacked = _extract(snapshot, work/'unpacked')
            children = list(unpacked.iterdir())
            if len(children) != 1 or not children[0].is_dir():
                raise UpdateInstallError('The portable update must contain one application directory')
            staged = children[0]
            if not (staged/'runtime/pythonw.exe').is_file() or not (staged/'runtime/python.exe').is_file() or not (staged/'launch.py').is_file():
                raise UpdateInstallError('The portable update is missing its runtime or launcher')
            _health(staged/'runtime/python.exe',version,log)
        elif kind == 'wheel':
            dist, metadata = _wheel_metadata(snapshot,version)
            current = importlib.metadata.distribution('isopropyl')
            if sorted(metadata.get_all('Requires-Dist',[])) != sorted(current.requires or []):
                raise UpdateInstallError('This update changes dependencies; install the complete managed application instead.')
            staged = _extract(snapshot,work/'unpacked')
            members = ('isopropyl',dist)
            if not (staged/'isopropyl/entrypoints.py').is_file():
                raise UpdateInstallError('The update wheel is missing its application entry point')
            allowed = {'isopropyl',dist}
            for path in staged.iterdir():
                if path.name not in allowed and not path.name.endswith('.data'):
                    raise UpdateInstallError('The update wheel contains an unexpected top-level package')
        elif kind == 'offline-wheelhouse':
            unpacked = _extract(snapshot,work/'unpacked')
            manifest = json.loads((unpacked/'macos-update.json').read_text())
            versions = manifest.get('python',[])
            if isinstance(versions,str):versions=[versions]
            if manifest.get('schema') != 1 or manifest.get('version') != version or f'{sys.version_info.major}.{sys.version_info.minor}' not in versions:
                raise UpdateInstallError('The offline update does not support this installed Python version')
            expected = {'macos-update.json'}; application = []
            for wheel in manifest.get('wheels',[]):
                relative = str(_safe_member(wheel['path']))
                if len(PurePosixPath(relative).parts)!=2 or not relative.startswith('wheelhouse/') or not relative.endswith('.whl'):
                    raise UpdateInstallError('The offline update contains an invalid wheel path')
                path = unpacked/relative
                if hashlib.sha256(path.read_bytes()).hexdigest() != wheel['sha256']:
                    raise UpdateInstallError('An offline dependency failed its checksum')
                expected.add(relative)
                if path.name.startswith('isopropyl-'):
                    _wheel_metadata(path,version); application.append(path)
            actual = {str(path.relative_to(unpacked)).replace(os.sep,'/') for path in unpacked.rglob('*') if path.is_file()}
            if actual != expected or len(application)!=1:
                raise UpdateInstallError('The offline update has unexpected or missing files')
            base = Path(getattr(sys,'_base_executable',sys.executable)).resolve()
            if base.is_relative_to(root.resolve()):
                raise UpdateInstallError('The managed update needs a durable base Python outside the old runtime')
            versions_root = _state_directory()/'runtimes'; versions_root.mkdir(exist_ok=True)
            staged = versions_root/(version+'-'+uuid.uuid4().hex)
            _run([base,'-I','-m','venv','--symlinks',staged],log)
            python = staged/'bin/python'
            _run([python,'-I','-m','pip','install','--no-index','--find-links',unpacked/'wheelhouse',application[0]],log)
            _run([python,'-I','-m','pip','check'],log)
            _health(python,version,log)
            old_pointer = Path(installation.pointer).read_text()
        elif kind == 'deb':
            _run(['/usr/bin/dpkg-deb','--info',snapshot],log)
            info = subprocess.run(['/usr/bin/dpkg-deb','--field',str(snapshot),'Package','Version','Architecture'],
                check=True,stdout=subprocess.PIPE,text=True,shell=False).stdout.splitlines()
            values = dict(line.split(': ',1) for line in info if ': ' in line)
            if values.get('Package')!='isopropyl' or values.get('Version','').split('-')[0]!=version:
                raise UpdateInstallError('The Debian package does not match the selected release')
            architecture=subprocess.run(['/usr/bin/dpkg','--print-architecture'],check=True,stdout=subprocess.PIPE,text=True,shell=False).stdout.strip()
            if values.get('Architecture') not in {'all',architecture}:
                raise UpdateInstallError('The Debian package does not match this operating-system architecture')
        else:
            raise UpdateInstallError('Unsupported update installation type')
        plan = InstallPlan(kind,version,str(root),str(staged),str(work),installation.python,
            installation.restart_argv,str(state/'update-status.json'),str(log),installation.pointer,old_pointer,members,secrets.token_hex(32))
        _json_write(work/'plan.json',asdict(plan))
        _status(plan,'prepared','The verified update is ready to install.')
        progress('Application update is ready',1,1)
        return plan
    except BaseException as error:
        if kind=='offline-wheelhouse' and 'versions_root' in locals() and staged!=snapshot:
            shutil.rmtree(staged,ignore_errors=True)
        for child in work.iterdir():
            if child==log:continue
            if child.is_dir():shutil.rmtree(child,ignore_errors=True)
            else:child.unlink(missing_ok=True)
        with log.open('a') as output:output.write(str(error)+'\n')
        _json_write(state/'update-status.json',{'state':'failed','version':version,'root':str(root),
            'message':str(error),'log_path':str(log),'time':time.time()})
        raise


def discard_update(plan):
    """Discard a prepared update only before the helper owns the transaction."""
    work=Path(plan.work)
    if (work/'launched').exists():
        raise UpdateInstallError('The update helper already owns this transaction')
    if plan.kind=='offline-wheelhouse':shutil.rmtree(plan.staged,ignore_errors=True)
    shutil.rmtree(work,ignore_errors=True)


def notify_update_ready():
    """Confirm GUI startup only for the authenticated pending transaction."""
    name=os.environ.pop('ISOPROPYL_UPDATE_READY_FILE','')
    token=os.environ.pop('ISOPROPYL_UPDATE_TOKEN','')
    if not name:return False
    marker=Path(name);work=marker.parent
    if marker.name!='application-ready' or not work.name.startswith('.isopropyl-update-'):
        raise UpdateInstallError('Invalid update startup confirmation path')
    info=work.lstat()
    if not stat.S_ISDIR(info.st_mode) or work.is_symlink() or getattr(info,'st_file_attributes',0)&0x400:
        raise UpdateInstallError('Invalid update startup transaction directory')
    if sys.platform!='win32' and (info.st_uid!=os.getuid() or info.st_mode&0o077):
        raise UpdateInstallError('The update startup transaction is not private')
    plan_path=work/'plan.json'
    if plan_path.is_symlink() or plan_path.stat().st_size>65536:
        raise UpdateInstallError('Invalid update startup transaction metadata')
    plan=InstallPlan(**json.loads(plan_path.read_text()))
    if plan.work!=str(work) or not token or not secrets.compare_digest(plan.token,token):
        raise UpdateInstallError('The update startup token does not match its transaction')
    if Path(plan.status_path)!=_state_directory()/'update-status.json':
        raise UpdateInstallError('The update startup status path is invalid')
    status=read_update_status()
    allowed={'installing','rolled-back'}|({'failed'} if plan.kind=='deb' else set())
    if not status or status.get('root')!=plan.root or status.get('state') not in allowed:
        raise UpdateInstallError('The update transaction is no longer waiting for this application')
    with marker.open('x') as output:output.write('ready')
    return True


def _status(plan,state,message):
    _json_write(plan.status_path,{'state':state,'version':plan.version,'root':plan.root,
        'active_root':plan.staged if plan.kind=='offline-wheelhouse' and state in {'installing','installed'} else plan.root,
        'message':message,'log_path':plan.log_path,'time':time.time()})


def _helper_python(plan):
    if sys.platform != 'win32':return sys.executable
    source = Path(sys.executable).parent
    target = Path(plan.work)/'helper-runtime'; target.mkdir()
    for path in source.iterdir():
        if path.is_file() and not path.is_symlink():shutil.copy2(path,target/path.name)
    if (source/'DLLs').is_dir():shutil.copytree(source/'DLLs',target/'DLLs')
    if (source/'Lib').is_dir():
        shutil.copytree(source/'Lib',target/'Lib',ignore=shutil.ignore_patterns('site-packages','__pycache__','*.pyc'))
    # Embedded Python's old _pth includes the app's site-packages and parent.
    # The helper uses only its copied standard library and extension modules.
    archive = next(target.glob('python*.zip'),None)
    if archive is None and not (target/'Lib/encodings').is_dir():
        raise UpdateInstallError('The independent Python standard library is missing')
    paths=([archive.name] if archive else [])+['.','Lib','DLLs']
    for name in {f'python{sys.version_info.major}{sys.version_info.minor}._pth','python._pth'}|{path.name for path in target.glob('python*._pth')}:
        (target/name).write_text('\n'.join(paths)+'\n',encoding='utf-8')
    python = target/'python.exe'
    if not python.is_file():raise UpdateInstallError('Cannot create an independent update helper runtime')
    return str(python)


def launch_install(plan, *, busy=False):
    if busy:
        raise UpdateInstallError('Finish or cancel the current operation before installing an update.')
    work = Path(plan.work)
    if not (work/'plan.json').is_file():raise UpdateInstallError('The staged update is unavailable')
    helper = work/'update_helper.py'; shutil.copy2(__file__,helper)
    python = _helper_python(plan)
    ready = work/'helper-ready.json'
    if (work/'launched').exists():raise UpdateInstallError('This update was already handed to its installer')
    (work/'launched').touch(exist_ok=False)
    argv = [python,'-I',str(helper),'--apply',str(work/'plan.json'),'--parent',str(os.getpid())]
    if sys.platform=='win32':
        kernel,handle=_windows_process(os.getpid())
        try:argv += ['--parent-token',str(_windows_process_token(kernel,handle))]
        finally:kernel.CloseHandle(handle)
    process=None
    try:
        process = subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,close_fds=True,shell=False,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0) if sys.platform=='win32' else 0,
            start_new_session=sys.platform!='win32')
        deadline = time.monotonic()+30
        while time.monotonic()<deadline:
            if ready.is_file():
                message = json.loads(ready.read_text())
                if message.get('ready') is True:return InstallLaunch(process.pid,plan.status_path,plan.log_path)
                raise UpdateInstallError(message.get('error','The update helper could not start'))
            if process.poll() is not None:
                raise UpdateInstallError('The update helper exited before acquiring its parent-process watcher')
            time.sleep(0.05)
        raise UpdateInstallError('The update helper did not become ready; the application can remain open.')
    except BaseException as error:
        if process is not None:
            if process.poll() is None:process.terminate()
            try:process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill();process.wait(timeout=15)
        # Only a confirmed-dead helper relinquishes transaction ownership.
        (work/'launched').unlink(missing_ok=True);ready.unlink(missing_ok=True)
        _status(plan,'failed','The update helper could not take ownership: '+str(error))
        raise


def _windows_process(pid):
    import ctypes
    from ctypes import wintypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
    kernel.WaitForSingleObject.restype=wintypes.DWORD
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    handle=kernel.OpenProcess(0x00101000,False,pid)
    if not handle:raise ctypes.WinError(ctypes.get_last_error())
    return kernel,handle


def _windows_process_token(kernel,handle):
    import ctypes
    from ctypes import wintypes
    kernel.GetProcessTimes.argtypes=[wintypes.HANDLE]+[ctypes.POINTER(ctypes.c_uint64)]*4
    kernel.GetProcessTimes.restype=wintypes.BOOL
    creation,exit_time,kernel_time,user_time=[ctypes.c_uint64() for _ in range(4)]
    if not kernel.GetProcessTimes(handle,ctypes.byref(creation),ctypes.byref(exit_time),ctypes.byref(kernel_time),ctypes.byref(user_time)):
        raise ctypes.WinError(ctypes.get_last_error())
    return creation.value


def _parent_watcher(pid,expected_token=''):
    """Acquire an exact process object before signalling readiness to the GUI."""
    if sys.platform == 'win32':
        kernel,handle=_windows_process(pid)
        if expected_token and str(_windows_process_token(kernel,handle))!=expected_token:
            kernel.CloseHandle(handle)
            raise UpdateInstallError('The original application process no longer exists')
        def wait():
            try:
                if kernel.WaitForSingleObject(handle,0xFFFFFFFF)!=0:raise UpdateInstallError('Parent-process wait failed')
            finally:kernel.CloseHandle(handle)
        return wait
    if os.getppid()!=pid:
        raise UpdateInstallError('The application exited before its update helper was ready')
    if sys.platform == 'darwin':
        queue=select.kqueue()
        queue.control([select.kevent(pid,filter=select.KQ_FILTER_PROC,flags=select.KQ_EV_ADD|select.KQ_EV_ONESHOT,
                                   fflags=select.KQ_NOTE_EXIT)],0,0)
        if os.getppid()!=pid:
            queue.close();raise UpdateInstallError('The original application process already exited')
        def wait():
            try:queue.control(None,1,None)
            finally:queue.close()
        return wait
    if hasattr(os,'pidfd_open'):
        descriptor=os.pidfd_open(pid)
        if os.getppid()!=pid:
            os.close(descriptor);raise UpdateInstallError('The original application process already exited')
        def wait():
            try:
                poll=select.poll();poll.register(descriptor,select.POLLIN);poll.poll()
            finally:os.close(descriptor)
        return wait
    raise UpdateInstallError('This Linux kernel cannot safely watch the exact application process')


def _restart(plan,argv=None):
    marker=Path(plan.work)/'application-ready';marker.unlink(missing_ok=True)
    env=dict(os.environ,ISOPROPYL_UPDATE_READY_FILE=str(marker),ISOPROPYL_UPDATE_TOKEN=plan.token)
    process=subprocess.Popen(list(argv or plan.restart_argv),stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,shell=False,close_fds=True,
        start_new_session=sys.platform!='win32')
    deadline=time.monotonic()+45
    while time.monotonic()<deadline:
        if marker.is_file() and marker.read_text()=='ready':return
        if process.poll() is not None:
            raise UpdateInstallError('The updated application exited before startup completed')
        time.sleep(0.1)
    # This is the exact child we just started, before GUI readiness. Stop only
    # that startup attempt so Windows releases files needed for rollback.
    if sys.platform=='win32':process.terminate()
    else:
        import signal
        os.killpg(process.pid,signal.SIGTERM)
    process.wait(timeout=15)
    raise UpdateInstallError('The updated application did not confirm startup')


def apply_install(plan, *, restart=_restart):
    """Called only after the exact parent has exited; rollback on failed startup."""
    root=Path(plan.root);staged=Path(plan.staged);work=Path(plan.work)
    backup=work/'rollback';backup.mkdir()
    moved=[];installed=[];pointer_changed=False;old_plist=None
    _status(plan,'installing','Installing the verified application update.')
    try:
        if plan.kind=='portable-zip':
            for name in ('isopropyl.ini','ready.txt'):
                source=root/name
                if source.exists() or source.is_symlink():
                    info=source.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or getattr(info,'st_file_attributes',0)&0x400:
                        raise UpdateInstallError('Portable settings must be an ordinary unlinked file')
                    shutil.copy2(source,staged/name)
            os.replace(root,backup/'application');moved.append(('application',root))
            os.replace(staged,root);installed.append(root)
            _health(root/'runtime/python.exe',plan.version,plan.log_path)
        elif plan.kind=='wheel':
            old=[path for path in root.iterdir() if path.name=='isopropyl' or
                 re.fullmatch(r'isopropyl-[^/]+\.dist-info',path.name)]
            if not any(path.name=='isopropyl' for path in old):raise UpdateInstallError('The installed application package disappeared')
            for path in old:
                os.replace(path,backup/path.name);moved.append((path.name,path))
            for name in plan.members:
                destination=root/name;os.replace(staged/name,destination);installed.append(destination)
            _health(plan.python,plan.version,plan.log_path)
        elif plan.kind=='offline-wheelhouse':
            if Path(plan.pointer).read_text()!=plan.old_pointer:
                raise UpdateInstallError('The managed application launcher changed after update preparation')
            pointer=Path(plan.pointer);temporary=pointer.with_name('runtime-update-'+uuid.uuid4().hex+'.txt')
            temporary.write_text(str(staged)+'\n');os.replace(temporary,pointer);pointer_changed=True
            plist=pointer.parents[1]/'Info.plist';old_plist=plist.read_bytes()
            info=plistlib.loads(old_plist);info['CFBundleShortVersionString']=plan.version;info['CFBundleVersion']=plan.version
            plist.write_bytes(plistlib.dumps(info))
            _run(['/usr/bin/codesign','--force','--sign','-',str(pointer.parents[2])],plan.log_path)
        elif plan.kind=='deb':
            _run(['/usr/bin/pkexec','/usr/bin/apt-get','--yes','--no-remove','--no-install-recommends','install',staged],plan.log_path)
        else:raise UpdateInstallError('Unknown staged update kind')
        restart(plan)
        message='ISOpropyl '+plan.version+' was installed and restarted successfully.'
        if plan.kind=='portable-zip':message+=' Previous files are retained at '+str(backup/'application')+'.'
        _status(plan,'installed',message)
        if plan.kind!='portable-zip':shutil.rmtree(backup,ignore_errors=True)
    except Exception as error:
        rollback_error=None
        try:
            for path in reversed(installed):
                if path.is_dir():shutil.rmtree(path)
                else:path.unlink(missing_ok=True)
            for name,path in reversed(moved):os.replace(backup/name,path)
            if pointer_changed:
                pointer=Path(plan.pointer);temporary=pointer.with_name('runtime-rollback-'+uuid.uuid4().hex+'.txt')
                temporary.write_text(plan.old_pointer);os.replace(temporary,pointer)
                if old_plist is not None:(pointer.parents[1]/'Info.plist').write_bytes(old_plist)
                _run(['/usr/bin/codesign','--force','--sign','-',str(pointer.parents[2])],plan.log_path)
        except Exception as rollback:rollback_error=rollback
        message=str(error)
        if plan.kind=='deb':
            message+=' The system package manager may need dependency repair; its log is preserved.'
        elif rollback_error:
            message+=' Rollback could not complete: '+str(rollback_error)
        else:message+=' The previous installation was restored.'
        with Path(plan.log_path).open('a') as output:output.write(message+'\n')
        _status(plan,'failed' if plan.kind=='deb' or rollback_error else 'rolled-back',message)
        if not rollback_error:
            try:restart(plan)
            except Exception:pass
        raise UpdateInstallError(message) from error


def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--apply',required=True);parser.add_argument('--parent',required=True,type=int)
    parser.add_argument('--parent-token',default='')
    args=parser.parse_args(argv);plan=InstallPlan(**json.loads(Path(args.apply).read_text()))
    try:
        wait=_parent_watcher(args.parent,args.parent_token)
        _status(plan,'waiting','Waiting for ISOpropyl to close before installing the update.')
        _json_write(Path(plan.work)/'helper-ready.json',{'ready':True})
        wait();apply_install(plan)
        return 0
    except Exception as error:
        _json_write(Path(plan.work)/'helper-ready.json',{'ready':False,'error':str(error)})
        if not read_update_status() or read_update_status().get('state') not in {'rolled-back','failed'}:
            _status(plan,'failed',str(error))
        return 1


if __name__=='__main__':raise SystemExit(main())
