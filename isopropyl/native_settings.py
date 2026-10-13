"""Native settings and bounded, data-only elevation state."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import base64,json,sys,os
from dataclasses import asdict
from pathlib import Path
from PyQt6.QtCore import QSettings
from .native_media import NativeMediaOptions
from .windows import WindowsCustomization,WindowsBootExOptions
from .wim import WimSelection,WimEdition

def settings(portable=False):
    launcher=Path(os.environ.get('ISOPROPYL_LAUNCHER',sys.argv[0])).absolute()
    path=launcher.parent/'isopropyl.ini'
    if portable or path.is_file():return QSettings(str(path),QSettings.Format.IniFormat)
    return QSettings('codebooker','ISOpropyl')

def encode_state(options,customization,bootex):
    data=asdict(options);data.pop('uefi_ntfs_artifact',None)
    data['zip_overlay']=str(options.zip_overlay) if options.zip_overlay else None
    data['customization']=asdict(customization);data['bootex']=asdict(bootex)
    return base64.urlsafe_b64encode(json.dumps(data,separators=(',',':')).encode()).decode()

def decode_state(value,*,maximum=32768):
    if len(value)>maximum:raise ValueError('Session settings exceed their limit')
    data=json.loads(base64.b64decode(value,altchars=b'-_',validate=True))
    customization=data.pop('customization');bootex=WindowsBootExOptions(**data.pop('bootex'))
    selected=customization.get('install_image')
    if selected:
        selected['editions']=tuple(WimEdition(**item) for item in selected['editions'])
        customization['install_image']=WimSelection(**selected)
    customization=WindowsCustomization(**customization)
    if data.get('zip_overlay'):data['zip_overlay']=Path(data['zip_overlay'])
    return NativeMediaOptions(**data),customization,bootex

def load_state_file(path,expected_sha256):
    """Read a private, hash-bound relaunch payload without command-line limits."""
    import hashlib,stat,re
    from .portable_fs import os as bound_os
    if not re.fullmatch('[0-9a-f]{64}',expected_sha256 or ''):raise ValueError('Invalid session digest')
    path=Path(path);parent=bound_os.lstat(path.parent);named=bound_os.lstat(path)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_mode&0o077
            or not stat.S_ISREG(named.st_mode) or named.st_nlink!=1
            or named.st_uid!=parent.st_uid or named.st_mode&0o022 or named.st_size>16*1024*1024):
        raise ValueError('Unsafe session settings file')
    descriptor=bound_os.open(path,bound_os.O_RDONLY|getattr(bound_os,'O_NOFOLLOW',0))
    try:
        before=bound_os.fstat(descriptor);parts=[];total=0
        identity=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        if identity(before)!=identity(named):raise ValueError('Session settings changed while opening')
        while data:=bound_os.read(descriptor,65536):
            total+=len(data)
            if total>16*1024*1024:raise ValueError('Session settings exceed their limit')
            parts.append(data)
        payload=b''.join(parts)
        if total!=before.st_size or identity(before)!=identity(bound_os.fstat(descriptor)) or identity(before)!=identity(bound_os.lstat(path)):
            raise ValueError('Session settings changed while reading')
        if hashlib.sha256(payload).hexdigest()!=expected_sha256:raise ValueError('Session settings digest does not match')
        return decode_state(payload.decode('ascii'),maximum=16*1024*1024)
    finally:bound_os.close(descriptor)
