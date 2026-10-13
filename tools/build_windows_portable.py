"""Build the offline Windows x86-64 or ARM64 native GUI test bundle on any host."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import argparse
import hashlib
import json
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_URL = 'https://www.python.org/ftp/python/3.13.16/python-3.13.16-embed-amd64.zip'
PYTHON_SHA256 = '97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture',choices=('x86-64','arm64'),default='x86-64')
    parser.add_argument('--dependency-wheels',type=Path,required=True,help='Complete offline dependency wheelhouse for the target architecture')
    parser.add_argument('--wheel',type=Path,required=True)
    parser.add_argument('--qt-wheels',type=Path,required=True)
    parser.add_argument('--zstandard-wheel',type=Path,required=True,help='native CPython 3.13 AMD64 zstandard wheel')
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    args.output=args.output or ROOT/('dist/ISOpropyl-Windows-'+args.architecture+'-test.zip')
    tag='win_amd64' if args.architecture=='x86-64' else 'win_arm64'
    python_url=PYTHON_URL if args.architecture=='x86-64' else PYTHON_URL.replace('amd64','arm64')
    python_sha=PYTHON_SHA256 if args.architecture=='x86-64' else '790d097697a2020477549a6764d89d22194c88d6e42caebcb2db63791e004c94'
    wheels = sorted(args.qt_wheels.glob('*.whl'))
    if len(wheels) != 3 or any(tag not in wheel.name for wheel in wheels):
        raise ValueError('Supply the three native Windows AMD64 PyQt6, Qt6 and SIP wheels')
    if not args.zstandard_wheel.name.startswith('zstandard-') or not args.zstandard_wheel.name.endswith('-cp313-cp313-'+tag+'.whl'):
        raise ValueError('Supply a native CPython 3.13 AMD64 zstandard wheel')
    with tempfile.TemporaryDirectory(prefix='isopropyl-win-build-') as directory:
        work = Path(directory); bundle=work/('ISOpropyl-Windows-'+args.architecture);bundle.mkdir()
        runtime=bundle/'runtime';runtime.mkdir()
        with urllib.request.urlopen(python_url,timeout=60) as response:
            payload=response.read(32*1024*1024)
        if hashlib.sha256(payload).hexdigest()!=python_sha:
            raise ValueError('The Python runtime does not match its published SHA-256')
        archive=work/'python.zip';archive.write_bytes(payload)
        with zipfile.ZipFile(archive) as source:source.extractall(runtime)
        site=runtime/'Lib/site-packages';site.mkdir(parents=True)
        manifest={'python':{'url':python_url,'sha256':python_sha},'wheels':[]}
        dependencies=sorted(args.dependency_wheels.glob('*.whl'))
        if not dependencies:
            raise ValueError('Complete offline dependency wheelhouse is required')
        all_wheels=list(dict.fromkeys([args.wheel,*wheels,args.zstandard_wheel,*dependencies]))
        for wheel in all_wheels:
            if not (wheel.name.endswith('none-any.whl') or tag in wheel.name):
                raise ValueError('Wheel architecture does not match target: '+wheel.name)
            with zipfile.ZipFile(wheel) as source:source.extractall(site)
            manifest['wheels'].append({'name':wheel.name,'sha256':hashlib.sha256(wheel.read_bytes()).hexdigest()})
        native_platform='windows-'+args.architecture
        native_manifest=site/'isopropyl/data/native-tools-v1.json'
        native_payload=json.loads(native_manifest.read_text())
        helpers=native_payload['platforms'].get(native_platform,{})
        missing={'mke2fs','mkntfs','ntfs-tree','mkudffs','wimlib-imagex','7z','qemu-img','gpgv'}-set(helpers)
        if missing:raise ValueError('Incomplete native helper package: '+', '.join(sorted(missing)))
        native_payload['platforms']={native_platform:helpers}
        native_manifest.write_text(json.dumps(native_payload,indent=2)+'\n')
        for directory in (site/'isopropyl/helpers').iterdir():
            if directory.name!=native_platform:shutil.rmtree(directory)
        manifest['native_platform']=native_platform
        manifest['native_helpers']=helpers
        distributions={}
        import email
        from packaging.requirements import Requirement
        from packaging.markers import default_environment
        for metadata in site.glob('*.dist-info/METADATA'):
            message=email.message_from_string(metadata.read_text())
            distributions[message['Name'].lower().replace('_','-')]=message
        environment=default_environment()
        environment.update(sys_platform='win32',platform_system='Windows',platform_machine='AMD64' if args.architecture=='x86-64' else 'ARM64',python_version='3.13',python_full_version='3.13.16',extra='')
        for message in distributions.values():
            for raw in message.get_all('Requires-Dist',[]):
                requirement=Requirement(raw)
                if requirement.marker and not requirement.marker.evaluate(environment):
                    continue
                dependency=distributions.get(requirement.name.lower().replace('_','-'))
                if dependency is None or dependency['Version'] not in requirement.specifier:
                    raise ValueError('Missing or incompatible offline dependency: '+raw)
        (runtime/'python313._pth').write_text('python313.zip\n.\nLib/site-packages\n..\nimport site\n')
        shutil.copytree(ROOT/'tests',bundle/'tests',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        (bundle/'tools').mkdir()
        for tool in ('bundle_native_helpers.py','validate_native_helpers.py'):
            shutil.copyfile(ROOT/'tools'/tool,bundle/'tools'/tool)
        for name in ('LICENSE','THIRD_PARTY_NOTICES.md','CROSS_PLATFORM.md'):
            shutil.copyfile(ROOT/name,bundle/name)
        shutil.copytree(ROOT/'licenses',bundle/'licenses')
        (bundle/'launch.py').write_text('''import ctypes, traceback, os
from pathlib import Path
os.environ['ISOPROPYL_LAUNCHER']=str(Path(__file__).resolve())
try:
    from isopropyl.entrypoints import gui
    raise SystemExit(gui())
except Exception:
    detail=traceback.format_exc()
    log=Path(__file__).parent/'startup-error.txt'
    log.write_text(detail,encoding='utf-8')
    ctypes.windll.user32.MessageBoxW(None, 'ISOpropyl could not start. See '+str(log)+'\\n\\n'+detail[-1500:], 'ISOpropyl startup error', 16)
''')
        (bundle/'Open ISOpropyl.cmd').write_bytes(b'@echo off\r\nstart "ISOpropyl" "%~dp0runtime\\pythonw.exe" "%~dp0launch.py" %*\r\n')
        (bundle/'test_windows.py').write_text('''import json, platform, struct, sys, unittest
from pathlib import Path
log=Path(__file__).parent/'windows-test-results.txt'
with log.open('w',encoding='utf-8') as stream:
    print(json.dumps({'platform':sys.platform,'machine':platform.machine(),'bits':struct.calcsize('P')*8,'python':sys.version}),file=stream)
    if sys.platform!='win32' or platform.machine().lower() not in EXPECTED_MACHINES or struct.calcsize('P')!=8:
        print('Expected native Windows target architecture.',file=stream);sys.exit(1)
    suites=['tests.test_native_extract','tests.test_native_options','tests.test_native_media','tests.test_compress_z','tests.test_native_drive_parity','tests.test_helper_tools','tests.test_native_platform','tests.test_native_devices','tests.test_native_disk_io','tests.test_native_writer','tests.test_native_inputs','tests.test_native_inspection','tests.test_native_downloads','tests.test_native_tools','tests.test_native_virtual','tests.test_native_cli','tests.test_native_app','tests.test_native_elevation','tests.test_mac_write','tests.test_devices','tests.test_windows_media']
    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(suites))
print('Test log:',log)
sys.exit(0 if result.wasSuccessful() else 1)
'''.replace('EXPECTED_MACHINES',repr(('amd64','x86_64') if args.architecture=='x86-64' else ('arm64','aarch64'))))
        (bundle/'ISOpropyl CLI.cmd').write_bytes(b'@echo off\r\n"%~dp0runtime\\python.exe" -m isopropyl %*\r\n')
        (bundle/'Run Windows tests.cmd').write_bytes(b'@echo off\r\nset "QT_QPA_PLATFORM=offscreen"\r\n"%~dp0runtime\\python.exe" "%~dp0test_windows.py"\r\npause\r\n')
        (bundle/'README.txt').write_text('''ISOpropyl Windows TARGET TEST BUILD

Extract the entire zip to a local folder on Windows 11 TARGET.
Double-click Open ISOpropyl.cmd. Python and Qt are included; no installation or internet connection is needed.
Run "ISOpropyl CLI.cmd" --help in a terminal for the included command-line interface.
Double-click Run Windows tests.cmd for checks using mock disks. These checks do not erase or write physical drives. Results go to windows-test-results.txt.

Try the interface, plug in a USB stick, then click Refresh. Check model and capacity.
To test writing, use a Windows installer ISO, raw .img or hybrid Linux .iso and a disposable USB drive.
Click Enable writing and approve UAC, then Write and verify and click Yes in the erase confirmation. The selected USB will be erased.
Unplug/replug the USB and boot the intended computer after verification completes.

The native helper provenance and integrity hashes are included in the installed package. This is an unsigned portable package.
If startup fails, share startup-error.txt. For test failures, share windows-test-results.txt.
'''.replace('TARGET',args.architecture))
        (bundle/'BUILD-MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n')
        args.output.parent.mkdir(parents=True,exist_ok=True)
        with zipfile.ZipFile(args.output,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
            for path in sorted(bundle.rglob('*')):
                if path.is_file():archive.write(path,path.relative_to(work))
        print(args.output)
        print('SHA-256:',hashlib.sha256(args.output.read_bytes()).hexdigest())


if __name__=='__main__':main()
