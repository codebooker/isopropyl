"""Read-only optical discovery and verified no-overwrite ISO capture."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path
import hashlib
import os
import plistlib
import re
import shutil
import stat
import struct
import sys
import tempfile

from .native_devices import command, DISKUTIL, MAC_DISK
from .native_disk_io import WindowsApi, WindowsDisk, MacDisk, authorized_mac_open
from .native_writer import NativeWriteError, BLOCK

WINDOWS_OPTICAL_DISCOVERY = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$result = @(Get-CimInstance Win32_CDROMDrive | Where-Object { $_.Drive -and $_.MediaLoaded } | ForEach-Object {
  $d = $_
  [pscustomobject]@{ Drive=[string]$d.Drive; Name=[string]$d.Name; PNPDeviceID=[string]$d.PNPDeviceID }
})
ConvertTo-Json -InputObject $result -Depth 3 -Compress
"""
WIN_OPTICAL = re.compile(r'\\\\\.\\([A-Z]):\Z')


@dataclass(frozen=True)
class NativeOpticalSource:
    path: str
    size: int
    label: str
    hardware_id: str
    host: str
    sector_size: int = 2048
    mountpoints: tuple[str, ...] = ()


@dataclass(frozen=True)
class NativeOpticalPlan:
    source: NativeOpticalSource
    destination: Path
    parent_identity: tuple

    @property
    def confirmation(self): return 'CAPTURE ' + self.source.path


@contextmanager
def open_optical(source):
    """Neither backend requests GENERIC_WRITE/O_RDWR or dismounts a volume."""
    if source.host == 'darwin':
        import fcntl
        name=source.path.removeprefix('/dev/')
        if not MAC_DISK.fullmatch(name):raise NativeWriteError('Invalid optical source path')
        raw='/dev/r'+name
        flags=os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW
        try:descriptor=os.open(raw,flags)
        except PermissionError:descriptor=authorized_mac_open(raw,flags & ~os.O_NOFOLLOW)
        try:
            info=os.fstat(descriptor)
            if not stat.S_ISCHR(info.st_mode) or info.st_rdev!=os.stat(raw).st_rdev:
                raise NativeWriteError('Opened optical source identity changed')
            sector=struct.unpack('=I',fcntl.ioctl(descriptor,0x40046418,bytes(4)))[0]
            count=struct.unpack('=Q',fcntl.ioctl(descriptor,0x40086419,bytes(8)))[0]
            if sector!=2048 or source.size and count*sector!=source.size:
                raise NativeWriteError('Optical media geometry changed or has no 2048-byte data sectors')
            yield MacDisk(descriptor),count*sector
        finally:os.close(descriptor)
    elif source.host == 'win32':
        if not WIN_OPTICAL.fullmatch(source.path):raise NativeWriteError('Invalid optical drive path')
        api=WindowsApi();handle=api.open(source.path,read_only=True)
        try:
            geometry=api.control(handle,0x2404C,24)  # IOCTL_CDROM_GET_DRIVE_GEOMETRY
            sector=struct.unpack_from('<I',geometry,20)[0]
            try:size=struct.unpack('<q',api.control(handle,0x7405C,8))[0]
            except OSError:
                cylinders,_,tracks,sectors,_=struct.unpack('<qIIII',geometry)
                size=cylinders*tracks*sectors*sector
            if sector!=2048 or size<=0 or source.size and size!=source.size:
                raise NativeWriteError('Optical media geometry changed or has no 2048-byte data sectors')
            yield WindowsDisk(api,handle),size
        finally:api.kernel.CloseHandle(handle)
    else:raise NativeWriteError('Unsupported optical host')


def discover_optical(host=None, *, runner=None, opener=open_optical):
    host=host or sys.platform
    sources=[]
    if host=='darwin':
        listing=plistlib.loads(command([DISKUTIL,'list','-plist'],runner=runner))
        for name in listing.get('WholeDisks',[]):
            if not isinstance(name,str) or not MAC_DISK.fullmatch(name):continue
            info=plistlib.loads(command([DISKUTIL,'info','-plist','/dev/'+name],runner=runner))
            if not (info.get('OpticalDeviceType') or info.get('OpticalMediaType') or info.get('MediaType') in {'CD-ROM','DVD-ROM','BD-ROM'}):continue
            if info.get('Whole') is not True:continue
            source=NativeOpticalSource('/dev/'+name,int(info.get('TotalSize',0)),str(info.get('MediaName') or name),
                                       str(info.get('DeviceTreePath') or info.get('IORegistryEntryName') or name),host,
                                       mountpoints=tuple([info['MountPoint']] if info.get('MountPoint') else []))
            sources.append(source)
    elif host=='win32':
        import json
        result=json.loads(command(['powershell.exe','-NoProfile','-NonInteractive','-Command',WINDOWS_OPTICAL_DISCOVERY],runner=runner))
        if isinstance(result,dict):result=[result]
        for entry in result or []:
            drive=entry.get('Drive','')
            if not re.fullmatch('[A-Z]:',drive):continue
            provisional=NativeOpticalSource('\\\\.\\'+drive,0,str(entry.get('Name') or drive),str(entry.get('PNPDeviceID') or ''),host)
            with opener(provisional) as (_,size):
                sources.append(NativeOpticalSource(provisional.path,size,provisional.label,provisional.hardware_id,host,
                                                   mountpoints=(drive+'\\',)))
    else:raise NativeWriteError('Unsupported optical host')
    return sources


def build_optical_plan(source,destination):
    if source.size<=0 or source.size%2048 or source.sector_size!=2048:
        raise NativeWriteError('The optical source has no complete readable data sectors')
    path=Path(destination).absolute();parent=path.parent.resolve(strict=True);path=parent/path.name
    if path.suffix.lower()!='.iso':raise NativeWriteError('Save an optical capture as .iso')
    if path.exists() or path.is_symlink():raise NativeWriteError('The optical destination already exists')
    for mount in source.mountpoints:
        if mount and parent.is_relative_to(Path(mount).resolve()):
            raise NativeWriteError('Save the optical capture on a different drive')
    info=parent.stat()
    if shutil.disk_usage(parent).free<source.size+BLOCK:raise NativeWriteError('Not enough space for the optical capture')
    return NativeOpticalPlan(source,path,(info.st_dev,info.st_ino))


def run_optical(plan,writer,*,confirmation=None,progress=lambda *args:None,discovery=discover_optical,opener=open_optical):
    from .native_tools import _read_exact
    if writer.used:raise NativeWriteError('Each optical runner can run only once')
    writer.used=True
    if confirmation is not None and confirmation!=plan.confirmation:raise NativeWriteError('The exact optical capture confirmation was not supplied')
    if build_optical_plan(plan.source,plan.destination)!=plan:raise NativeWriteError('Optical capture plan changed')
    def revalidate():
        matches=[item for item in discovery(plan.source.host) if item.path==plan.source.path]
        if len(matches)!=1 or matches[0]!=plan.source:raise NativeWriteError('The optical drive or inserted media changed')
        parent=plan.destination.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or (parent.st_dev,parent.st_ino)!=plan.parent_identity:
            raise NativeWriteError('Optical destination directory changed')
    writer.check_cancelled();revalidate()
    descriptor,name=tempfile.mkstemp(prefix='.isopropyl-optical-',dir=plan.destination.parent)
    temporary=Path(name)
    try:
        with os.fdopen(descriptor,'w+b') as output,opener(plan.source) as (disk,size):
            if size!=plan.source.size:raise NativeWriteError('Optical media size changed')
            digest=hashlib.sha256();disk.seek(0)
            for offset in range(0,size,BLOCK):
                data=_read_exact(disk,min(BLOCK,size-offset),writer)
                output.write(data);digest.update(data);progress('Capturing optical disc',offset+len(data),size)
            output.flush();os.fsync(output.fileno());output.seek(0)
            actual=hashlib.sha256()
            for offset in range(0,size,BLOCK):
                writer.check_cancelled();data=output.read(min(BLOCK,size-offset))
                if not data:raise NativeWriteError('Optical capture ended unexpectedly')
                actual.update(data);progress('Verifying optical capture',offset+len(data),size)
            if actual.digest()!=digest.digest():raise NativeWriteError('Optical capture SHA-256 failed')
            disk.seek(0); source_digest=hashlib.sha256()
            for offset in range(0,size,BLOCK):
                data=_read_exact(disk,min(BLOCK,size-offset),writer)
                source_digest.update(data);progress('Verifying optical source',offset+len(data),size)
            if source_digest.digest()!=digest.digest():
                raise NativeWriteError('The optical disc changed or returned inconsistent data during capture')
            writer.check_cancelled();revalidate();os.link(temporary,plan.destination)
        return digest.hexdigest()
    finally:temporary.unlink(missing_ok=True)
