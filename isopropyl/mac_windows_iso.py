"""Prepare UEFI Windows installer media as a verified regular FAT32 image."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import os
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .native_devices import NativeDevice, mac_info
from .native_writer import (
    BLOCK,
    NativeWriteError,
    build_plan,
    file_identity,
    path_file_identity,
)
from .windows import (
    WindowsBootExOptions,
    WindowsCustomization,
    add_autounattend_to_staging,
    generate_autounattend,
)

FAT_LIMIT = (1 << 32) - 1
MAX_ENTRIES = 16384


@dataclass(frozen=True)
class WindowsIsoPlan:
    source: Path
    source_identity: tuple[int, ...]
    target: NativeDevice
    include_fixed: bool
    expected_sha256: str | None
    customization: WindowsCustomization = field(default_factory=WindowsCustomization)
    bootex: WindowsBootExOptions = field(default_factory=WindowsBootExOptions)

    @property
    def size(self):
        return self.source_identity[2]

    @property
    def confirmation(self):
        return f'ERASE {self.target.device.path}'


def build_windows_plan(source, target, *, include_fixed=False, expected_sha256=None,
                       customization=None, bootex=None):
    path = Path(source).absolute()
    info = path.lstat()
    device = target.device
    if not stat.S_ISREG(info.st_mode) or path.suffix.lower() != '.iso' or info.st_size < 512:
        raise NativeWriteError('Choose a regular Windows installer ISO')
    if device.read_only or device.logical_sector_size != 512 or device.size % 512:
        raise NativeWriteError('Windows media requires a writable 512-byte-sector target')
    if not device.removable and not include_fixed:
        raise NativeWriteError('Fixed USB disks require explicit opt-in')
    if info.st_size >= device.size:
        raise NativeWriteError('The installer ISO cannot fit on this target')
    if expected_sha256:
        if not re.fullmatch('[0-9a-fA-F]{64}', expected_sha256):
            raise NativeWriteError('Expected SHA-256 must contain 64 hexadecimal characters')
        expected_sha256 = expected_sha256.lower()
    return WindowsIsoPlan(path, path_file_identity(path), target, include_fixed, expected_sha256,
                          customization or WindowsCustomization(), bootex or WindowsBootExOptions())


def wim_tool():
    from .helper_tools import helper
    return helper('wimlib-imagex')


@contextmanager
def mounted_iso(source, mount, writer):
    device = None
    try:
        attached = plistlib.loads(run_tool(['/usr/bin/hdiutil','attach','-readonly','-nobrowse','-noautoopen','-noautofsck','-plist','-mountpoint',str(mount),str(source)],writer,timeout=120))
        entities = attached.get('system-entities',[])
        wholes = [entry['dev-entry'] for entry in entities if re.fullmatch(r'/dev/disk[0-9]+',entry.get('dev-entry',''))]
        if len(wholes) != 1:
            raise NativeWriteError('The ISO did not attach as one virtual whole disk')
        device = wholes[0]
        info = mac_info(device)
        if info.get('VirtualOrPhysical') != 'Virtual' or info.get('WritableMedia') is not False:
            raise NativeWriteError('The ISO attachment is not a read-only virtual device')
        if not any(entry.get('mount-point') and Path(entry['mount-point']).resolve() == mount.resolve() for entry in entities):
            raise NativeWriteError('The ISO did not mount at the private mountpoint')
        yield mount
    finally:
        if device:
            subprocess.run(['/usr/bin/hdiutil','detach',device],check=True,capture_output=True,timeout=30)


@dataclass(frozen=True)
class WindowsInstallCandidate:
    path: str
    size: int


@dataclass(frozen=True)
class WindowsSourceMetadata:
    source_identity: tuple
    architecture: str
    install_path: str
    install_size: int
    editions: tuple
    sha256: str
    bootex_supported: bool
    install_candidates: tuple[WindowsInstallCandidate, ...] = ()
    install_source_count: int = 1


def inspect_windows_source(source, writer, selected_member=None):
    from .windows_media import inspect_windows_source as portable_inspect
    return portable_inspect(source,writer,selected_member=selected_member)


def customize_tree(plan, tree, index, install, machine, snapshot, workspace, writer, progress):
    options = plan.customization
    architecture = 'amd64' if machine == 0x8664 else 'arm64'
    if options.enabled:
        if options.install_image:
            from .iso import ArchiveEntry
            from .iso_staging import _validate_wim_selection_catalog
            files=collect_files(tree)
            _validate_wim_selection_catalog(tuple(ArchiveEntry(path.as_posix(),size) for path,size in files),options.install_image)
            _candidates,source_count=installer_candidates(files)
            if (source_count>1 or options.install_image.source_name.casefold()!='sources/install.wim') and options.install_image.source_name.casefold().endswith('/install.wim'):
                if options.install_image_path!=options.install_image.source_name:raise NativeWriteError('A nested or multi-source Windows selection requires its exact answer-file WIM path')

            from .wim import parse_wim_info_xml
            member = tree/index[install]
            observed = parse_wim_info_xml(run_tool([wim_tool(),'info',str(member),'--xml'],writer,timeout=120))
            selected = options.install_image
            if (selected.source_name != index[install].as_posix() or selected.source_size != member.stat().st_size
                    or selected.editions != observed):
                raise NativeWriteError('Windows edition metadata changed; inspect the ISO again')
        if any(path.as_posix().casefold() == 'autounattend.xml' for path,_ in collect_files(tree)):
            raise NativeWriteError('This ISO already contains autounattend.xml; custom settings will not overwrite it')
        progress('Applying Windows installer settings',0,1)
        add_autounattend_to_staging(tree,generate_autounattend(options,architecture))
    if plan.bootex.enabled:
        from .windows_bootex import BootExRequest, apply_bootex_plan, build_bootex_plan
        if not plan.bootex.acknowledge_firmware_compatibility:
            raise NativeWriteError('Confirm that the target firmware trusts Windows UEFI CA 2023')
        extracted = workspace/'bootex'; extracted.mkdir()
        progress('Preparing Windows 2023 boot files',0,1)
        run_tool([wim_tool(),'extract',str(tree/index['sources/boot.wim']),'2',
                  'Windows/Boot/EFI_EX','Windows/Boot/Fonts_EX',f'--dest-dir={extracted}',
                  '--preserve-dir-structure','--no-acls'],writer)
        transform = build_bootex_plan(BootExRequest(snapshot,extracted/'Windows/Boot',tree,architecture),cancel_check=writer.check_cancelled)
        apply_bootex_plan(transform,cancel_check=writer.check_cancelled)


def run_tool(arguments, writer, *, timeout=1800):
    with tempfile.TemporaryFile() as log:
        options = {'creationflags': subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {}
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=log,
                                   stderr=subprocess.STDOUT, shell=False, **options)
        deadline = time.monotonic()+timeout
        try:
            while process.poll() is None:
                writer.check_cancelled()
                if time.monotonic() > deadline:
                    raise NativeWriteError('Installer preparation command timed out')
                time.sleep(.05)
        except BaseException:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise
        log.seek(0, os.SEEK_END)
        length = log.tell()
        if process.returncode:
            log.seek(max(0,length-2048))
            raise NativeWriteError(log.read().decode('utf-8','replace') or 'Installer preparation failed')
        if length > 2*1024*1024:
            raise NativeWriteError('Installer preparation command produced excessive output')
        log.seek(0)
        return log.read()


def collect_files(root: Path, *, ignore_system_entries=False):
    files = []
    count = 0
    seen = set()
    for directory, directories, names in os.walk(root, followlinks=False):
        if ignore_system_entries and Path(directory) == root:
            ignored = {'system volume information', '$recycle.bin'}
            directories[:] = [name for name in directories if name.casefold() not in ignored]
            names[:] = [name for name in names if name.casefold() not in ignored]
        for name in [*directories, *names]:
            path = Path(directory)/name
            info = path.lstat()
            relative = path.relative_to(root)
            key = relative.as_posix().casefold()
            if key in seen or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise NativeWriteError('The ISO contains ambiguous names or non-regular entries')
            if stat.S_ISDIR(info.st_mode) and (key=='sources/install.esd' or key=='sources/install.wim' or key.endswith('/sources/install.wim')):
                raise NativeWriteError('A Windows installer image candidate must be a regular file')
            if len(relative.parts) > 32:
                raise NativeWriteError('The installer directory tree is too deep')
            seen.add(key)
            count += 1
            if count > MAX_ENTRIES:
                raise NativeWriteError('The installer contains too many entries')
            if stat.S_ISREG(info.st_mode):
                files.append((relative, info.st_size))
    return files


def installer_candidates(files):
    from .images import ImageMember,classify_windows_installer_members
    classified=classify_windows_installer_members(tuple(ImageMember(path.as_posix(),size,'file') for path,size in files))
    if not classified.valid or not classified.has_installer:raise NativeWriteError('The Windows installer source catalog is unsafe or unsupported')
    by_path={path.as_posix():size for path,size in files}
    paths=classified.wim_paths or ((classified.esd_path,) if classified.esd_path else ())
    return tuple(WindowsInstallCandidate(path,by_path[path]) for path in paths),len(classified.wim_paths)+bool(classified.esd_path)


def installer_profile(files, selected_member=None):
    index = {path.as_posix().casefold():path for path, _ in files}
    if not {'setup.exe','sources/boot.wim'} <= index.keys():
        raise NativeWriteError('This optical ISO is not a supported Windows installer')
    loaders = [(name, machine) for name,machine in [('efi/boot/bootx64.efi',0x8664), ('efi/boot/bootaa64.efi',0xAA64)] if name in index]
    if len(loaders)!=1:raise NativeWriteError('The installer must have one x64 or ARM64 UEFI loader')
    candidates,_=installer_candidates(files)
    if selected_member is not None:
        chosen=next((c.path for c in candidates if c.path==selected_member),None)
        if chosen is None:raise NativeWriteError('The selected Windows install source is not in the supported bound catalog')
    else:
        chosen=next((c.path for c in candidates if c.path.casefold()=='sources/install.wim'),candidates[0].path)
    return index, loaders[0], chosen.casefold()


def verify_loader(path, machine):
    with path.open('rb') as source:
        header = source.read(64)
        if len(header) != 64 or header[:2] != b'MZ':
            raise NativeWriteError('The UEFI fallback loader has no valid PE header')
        offset = struct.unpack_from('<I', header, 60)[0]
        if not 64 <= offset <= 1024*1024:
            raise NativeWriteError('The UEFI fallback loader has an invalid PE offset')
        source.seek(offset)
        pe = source.read(96)
    if len(pe) != 96 or pe[:4] != b'PE\0\0' or struct.unpack_from('<H',pe,4)[0] != machine or struct.unpack_from('<H',pe,92)[0] != 10:
        raise NativeWriteError('The UEFI loader architecture or EFI application subsystem is invalid')


def split_large_install(tree, index, install_name, writer, progress):
    source = tree/index[install_name]
    if source.stat().st_size <= FAT_LIMIT:
        return
    candidates,count=installer_candidates(collect_files(tree))
    if count!=1 or install_name not in {'sources/install.wim','sources/install.esd'}:
        raise NativeWriteError('FAT32 splitting requires a sole canonical install.wim or install.esd; nested or multi-source images require NTFS')
    tool = wim_tool()
    from .wim import _validate_staged_parts,parse_wim_info_xml
    expected=parse_wim_info_xml(run_tool([tool,'info',str(source),'--xml'],writer))
    progress('Preparing split Windows install image',0,1)
    with tempfile.TemporaryDirectory(prefix='split-',dir=tree.parent) as directory:
        parts = Path(directory)
        split_source=source
        if install_name.endswith('.esd'):
            split_source=parts.parent/(parts.name+'-export.wim')
            run_tool([tool,'export',str(source),'all',str(split_source),'--compress=LZX','--check'],writer)
            observed=parse_wim_info_xml(run_tool([tool,'info',str(split_source),'--xml'],writer))
            if observed!=expected:raise NativeWriteError('ESD export changed Windows edition metadata')
        run_tool([tool,'split',str(split_source),str(parts/'install.swm'),'3800','--check'],writer)
        validated, _ = _validate_staged_parts(parts)
        observed=parse_wim_info_xml(run_tool([tool,'info',str(validated[0]),'--xml'],writer))
        if observed!=expected:raise NativeWriteError('Split WIM edition metadata changed')
        run_tool([tool,'verify',str(validated[0]),f'--ref={parts / "install*.swm"}'],writer)
        for part in validated:
            destination = source.parent/part.name
            if destination.exists():raise NativeWriteError('The installer contains conflicting split WIM files')
        for part in validated:shutil.move(str(part),source.parent/part.name)
        source.unlink()
        if split_source!=source:split_source.unlink()


def compose_fat32(tree: Path, workspace: Path, image: Path, target_size: int, writer, progress):
    from . import private_fat32 as fat
    from .fat_image import inspect_regular_fat32_image
    files = collect_files(tree)
    content = sum(size for _,size in files)
    if any(size > FAT_LIMIT for _,size in files):
        raise NativeWriteError('An installer file still exceeds the FAT32 limit')
    unit = 256*1024*1024
    image_size = max(512*1024*1024, ((content + content//10 + 64*1024*1024 + unit-1)//unit)*unit)
    if image_size > target_size:
        raise NativeWriteError('The constructed installer filesystem will not fit the target')
    if shutil.disk_usage(workspace).free < image_size*3 + BLOCK:
        raise NativeWriteError('Not enough temporary space to construct and stage Windows media')
    plan = fat.build_generic_private_fat32_plan(tree,workspace,image_size=image_size,cancel_check=writer.check_cancelled)
    with image.open('x+b') as output:
        image.chmod(0o600)
        output.truncate(image_size)
        descriptor = output.fileno()
        def write(data, offset):
            done = 0
            while done < len(data):
                writer.check_cancelled()
                count = os.pwrite(descriptor,data[done:],offset+done)
                if count <= 0:
                    raise NativeWriteError('FAT32 construction made no progress')
                done += count
        geometry = plan.geometry
        boot, info, table = fat._boot_sector(plan), fat._fsinfo(plan), fat._fat(plan)
        write(fat._mbr(plan),0)
        for sector,data in [(0,boot),(1,info),(6,boot),(7,info)]:
            write(data,geometry.volume_offset+sector*512)
        for number in range(2):
            write(table,geometry.volume_offset+(32+number*geometry.sectors_per_fat)*512)
        for directory in plan.directories:
            write(fat._directory_content(plan,directory),fat._cluster_offset(geometry,directory.first_cluster))
        root_fd = fat._open_source_root(plan.source_root,plan.directories[0].source)
        directories = {item.source.parts:item.source for item in plan.directories}
        done = 0
        try:
            for item in plan.files:
                offset = fat._cluster_offset(geometry,item.first_cluster) if item.cluster_count else 0
                observed = fat._consume_source_file(root_fd,directories,item.source,
                    lambda data,relative,start=offset: write(data,start+relative),cancel_check=writer.check_cancelled)
                if observed != item.sha256:
                    raise NativeWriteError('An installer file changed while building FAT32')
                done += item.source.size
                progress('Constructing Windows USB image',done,max(1,content))
        finally:
            os.close(root_fd)
        output.flush()
        os.fsync(descriptor)
        progress('Verifying installer file tree',0,1)
        inspected = inspect_regular_fat32_image(descriptor,cancel_check=writer.check_cancelled)
        if inspected.entries != fat._expected_entries(plan) or inspected.content_bytes != content:
            raise NativeWriteError('Independent FAT32 file verification failed')
    return image


def prepare_windows_image(plan, workspace: Path, writer, progress=lambda stage, done, total:None):
    from .windows_media import prepare_windows_image as portable_prepare
    return portable_prepare(plan,workspace,writer,progress)


def run_windows_iso(plan,confirmation,writer,*,progress=lambda stage,done,total:None):
    if confirmation != plan.confirmation:
        raise NativeWriteError('The exact erase confirmation was not supplied')
    from .mac_write import run_macos_write
    with tempfile.TemporaryDirectory(prefix='isopropyl-windows-') as directory:
        image = prepare_windows_image(plan,Path(directory),writer,progress)
        raw = build_plan(image,plan.target,include_fixed=plan.include_fixed)
        return run_macos_write(raw,confirmation,writer,progress=progress)
