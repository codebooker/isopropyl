"""Native filesystem publication for shared authenticated image downloads."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import hmac
import os
import shutil
import stat
import time
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from . import verified_download as verified
from .native_writer import path_file_identity


def _directory(path, policy):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink()
            or getattr(info,'st_file_attributes',0) & 0x400):
        raise policy.error('Download workspace is not an ordinary directory')
    return info.st_dev,info.st_ino


def execute_windows_download(artifact,destination,authorize_source,progress,*,cancel_event,
                             cancel_check,overall_timeout,opener,policy):
    parent = destination.parent.resolve(strict=True)
    destination = parent/destination.name
    parent_identity = _directory(parent,policy)
    if destination.exists() or destination.is_symlink():
        raise policy.error('Download destination already exists; it will not be overwritten')
    stage = parent/verified.resume_stage_name(artifact)
    from .portable_fs import os as portable_os
    try:portable_os.mkdir(stage,0o700)
    except FileExistsError:pass
    private=portable_os.lstat(stage)
    if private.st_uid!=portable_os.geteuid() or stat.S_IMODE(private.st_mode)!=0o700:
        raise policy.error("Download resume workspace is not private")
    stage_identity = _directory(stage,policy)
    if any(path.name != 'partial' for path in stage.iterdir()):
        raise policy.error('Download resume workspace has unexpected entries')
    partial = stage/'partial'
    if partial.exists() or partial.is_symlink():
        info = partial.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or getattr(info,'st_file_attributes',0)&0x400:
            raise policy.error('Download partial is not a private regular file')
    deadline = time.monotonic()+overall_timeout
    committed = False
    try:
        with partial.open('r+b' if partial.exists() else 'x+b',buffering=0) as output:
            initial = os.fstat(output.fileno())
            if initial.st_nlink != 1 or not stat.S_ISREG(initial.st_mode) or initial.st_size > artifact.size:
                raise policy.error('Download partial has unsafe metadata or exceeds the expected size')
            verified.check_cancel(cancel_event,cancel_check,policy=policy)
            source = authorize_source(opener,deadline,cancel_event,cancel_check)
            if type(source) is not verified.ResolvedDownloadSource:
                raise policy.error('Download authority returned an invalid source')
            final, checksum = verified.download_image(artifact,source.url,output.fileno(),initial,
                opener,progress,deadline=deadline,cancel_event=cancel_event,cancel_check=cancel_check,
                policy=policy,available_space=shutil.disk_usage(parent).free)
            # Independent final hashing protects publication from changed resume
            # bytes and filesystem damage; only a complete exact artifact appears.
            actual = verified.hash_partial(output.fileno(),artifact.size,deadline=deadline,
                cancel_event=cancel_event,cancel_check=cancel_check,policy=policy).hexdigest()
            if not hmac.compare_digest(actual,artifact.sha256):
                raise policy.error('Completed image failed its independent SHA-256 verification')
            verified.check_cancel(cancel_event,cancel_check,policy=policy)
            verified.deadline_check(deadline,policy=policy)
            if (_directory(parent,policy)!=parent_identity or _directory(stage,policy)!=stage_identity
                    or not verified.same_file(final,os.fstat(output.fileno()))
                    or path_file_identity(partial)!=(final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns,final.st_ctime_ns)):
                raise policy.error('Download workspace or image changed before publication')
            os.link(partial,destination)
            committed = True
        partial.unlink(); stage.rmdir()
        return verified.DownloadedVerifiedImage(destination,artifact.id,artifact.size,checksum)
    except BaseException as error:
        # Cancellation/connection errors keep the bound partial for resuming.
        # A committed file remains valid even if workspace cleanup fails.
        if committed:
            return verified.DownloadedVerifiedImage(destination,artifact.id,artifact.size,artifact.sha256)
        if (isinstance(error,verified.VerifiedDownloadError)
                and any(word in str(error).lower() for word in ('checksum','sha-256'))
                and _directory(stage,policy)==stage_identity):
            # A checksum failure is not resumable. Avoid trapping subsequent
            # retries behind a permanently corrupt completed partial.
            partial.unlink(missing_ok=True)
        raise


def verify_native_manifest(manifest,signature,keyring,fingerprint,deadline,cancel_event,cancel_check,policy):
    from .native_virtual import run_native_command
    from .helper_tools import helper
    selected=Path(helper('gpgv'))
    identity = path_file_identity(selected)
    def check():
        verified.check_cancel(cancel_event,cancel_check,policy=policy)
        verified.deadline_check(deadline,policy=policy)
    with tempfile.TemporaryDirectory(prefix='isopropyl-signature-') as directory:
        root = Path(directory)
        for name,value in [('keyring.gpg',keyring),('SHA256SUMS',manifest),('SHA256SUMS.gpg',signature)]:
            (root/name).write_bytes(value)
        result = run_native_command([str(selected),'--homedir',str(root),'--status-fd','1','--keyring',
            str(root/'keyring.gpg'),str(root/'SHA256SUMS.gpg'),str(root/'SHA256SUMS')],
            SimpleNamespace(check_cancelled=check), timeout=min(180,max(.001,deadline-time.monotonic())),limit=65536)
    if path_file_identity(selected) != identity:
        raise policy.error('The signature verifier changed during verification')
    valid = []
    for line in result.stdout.decode('utf-8',errors='replace').splitlines():
        if line.startswith('[GNUPG:] '):
            fields = line[9:].split()
            if fields and fields[0] in {'BADSIG','ERRSIG','REVKEYSIG','EXPKEYSIG','EXPSIG','NO_PUBKEY'}:
                raise policy.error('Ubuntu metadata signature is invalid')
            if len(fields)>=2 and fields[0]=='VALIDSIG':
                valid.append(fields[1])
    if valid != [fingerprint]:
        raise policy.error('Ubuntu metadata was not signed by the pinned key')


def download_freedos(release,destination,progress,*,cancel_event,cancel_check,overall_timeout,opener):
    import zipfile
    from . import freedos_downloads as dos
    parent = destination.parent.resolve(strict=True)
    destination = parent/destination.name
    policy = dos._FREEDOS_POLICY
    parent_identity = _directory(parent,policy)
    if destination.exists() or destination.is_symlink():
        raise policy.error('FreeDOS destination exists; choose another folder')
    if shutil.disk_usage(parent).free < release.archive_size+release.image_size+verified.FREE_SPACE_RESERVE:
        raise policy.error('Not enough free space for the FreeDOS archive and image')
    deadline = time.monotonic()+overall_timeout
    from .portable_fs import os as portable_os
    from .native_lock import exclusive_file_lock
    root=parent/dos._private_stage_name(release)
    try:portable_os.mkdir(root,0o700)
    except FileExistsError:pass
    info=portable_os.lstat(root)
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700
            or info.st_uid!=portable_os.geteuid()):raise policy.error('FreeDOS resume workspace is not private')
    root_identity=_directory(root,policy)
    with exclusive_file_lock(root/'active.lock'):
        existing=root/'image.partial'
        if existing.exists() or existing.is_symlink():
            info=existing.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise policy.error('Unsafe stale extracted image')
            existing.unlink()

        artifact = dos._ArchiveArtifact(release.id+'.archive',release.archive_filename,release.archive_size,release.archive_sha256)
        def authorize(selected_opener,selected_deadline,event,callback):
            dos._verify_official_hash_row(release,selected_opener,deadline=selected_deadline,
                cancel_event=event,cancel_check=callback)
            return verified.ResolvedDownloadSource(release.archive_url)
        archive_path=root/release.archive_filename
        if not archive_path.exists():
            execute_windows_download(artifact,archive_path,authorize,
                lambda done,total:progress(done,release.archive_size+release.image_size) if progress else None,
                cancel_event=cancel_event,cancel_check=cancel_check,overall_timeout=max(.001,deadline-time.monotonic()),opener=opener,policy=policy)
        else:
            info=archive_path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size!=release.archive_size:
                raise policy.error('Cached FreeDOS archive has unsafe metadata')
            with archive_path.open('rb') as cached:
                digest=verified.hash_partial(cached.fileno(),release.archive_size,deadline=deadline,cancel_event=cancel_event,cancel_check=cancel_check,policy=policy)
            if digest.hexdigest()!=release.archive_sha256:
                archive_path.unlink();raise policy.error('Cached FreeDOS archive failed SHA-256 verification; retry to download it again')
            if progress:progress(release.archive_size,release.archive_size+release.image_size)
        image = root/'image.partial'
        with zipfile.ZipFile(root/release.archive_filename) as archive, image.open('x+b') as output:
            selected = dos._validate_zip_catalog(archive,release)
            digest = hashlib.sha256(); done = 0
            with archive.open(selected) as source:
                while data := source.read(verified.READ_SIZE):
                    verified.check_cancel(cancel_event,cancel_check,policy=policy)
                    verified.deadline_check(deadline,policy=policy)
                    done += len(data)
                    if done > release.image_size:
                        raise policy.error('FreeDOS image exceeds its exact size')
                    output.write(data); digest.update(data)
                    if progress:
                        progress(release.archive_size+done,release.archive_size+release.image_size)
            output.flush(); os.fsync(output.fileno())
            if done != release.image_size or digest.hexdigest() != release.image_sha256:
                raise policy.error('FreeDOS inner image failed SHA-256 verification')
            dos._validate_disk_structure(output.fileno(),release)
            actual = verified.hash_partial(output.fileno(),done,deadline=deadline,cancel_event=cancel_event,
                cancel_check=cancel_check,policy=policy)
            if actual.hexdigest() != release.image_sha256:
                raise policy.error('FreeDOS image failed independent verification')
            verified.check_cancel(cancel_event,cancel_check,policy=policy)
            if _directory(parent,policy) != parent_identity or _directory(root,policy)!=root_identity:
                raise policy.error('FreeDOS destination directory or resume workspace changed')
            os.link(image,destination)
    if _directory(root,policy)==root_identity:shutil.rmtree(root)
    info = path_file_identity(destination)
    return dos.DownloadedFreeDosImage(destination,release.id,release.image_size,release.image_sha256,
                                     release.archive_sha256,(info[0],info[1],info[2],info[3]))
