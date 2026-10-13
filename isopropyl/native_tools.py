"""Native whole-drive backup, logical zeroing and destructive surface tests.

Every transaction retains the same exclusive handle through verification. These
tools use disk bytes directly, without shell commands or physical formatters.
"""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .native_writer import BLOCK, NativeWriteError, NativeWriter

OPERATIONS = {'backup', 'zero', 'fast_zero', 'surface', 'capacity', 'format_fat32', 'restore'}


def validate_target(target, include_fixed=False, *, logical_sectors=(512,)):
    device = target.device
    if device.read_only or device.size <= 0 or device.logical_sector_size not in logical_sectors or device.size % device.logical_sector_size:
        raise NativeWriteError('Choose a writable whole drive with supported logical sectors')
    if not device.removable and not include_fixed:
        raise NativeWriteError('Fixed USB disks require explicit opt-in')


@dataclass(frozen=True)
class NativeToolPlan:
    operation: str
    target: object
    include_fixed: bool = False
    destination: Path | None = None
    parent_identity: tuple | None = None
    sparse: bool = False
    filesystem: str = 'fat32'
    partition_table: str = 'mbr'
    label: str = 'ISOPROPYL'
    cluster_size: int | None = None
    quick: bool = True
    passes: int = 4
    capacity_first: bool = False

    @property
    def confirmation(self):
        return f'{self.operation.upper()} {self.target.device.path}'

    @property
    def size(self):
        return self.target.device.size


def build_tool_plan(operation, target, *, include_fixed=False, destination=None, sparse=False,
                    filesystem="fat32", partition_table="mbr", label="ISOPROPYL", cluster_size=None, quick=True, passes=4, capacity_first=False):
    if operation == "backup":
        if target.device.size <= 0:
            raise NativeWriteError("The source drive has no readable capacity")
    else:
        validate_target(target, include_fixed,logical_sectors=(512,) if operation=='format_fat32' else (512,1024,2048,4096))
    if operation not in OPERATIONS:
        raise NativeWriteError('Unknown drive tool')
    if operation == 'format_fat32':
        if not 64*1024*1024 <= target.device.size <= 2*1024**4:
            raise NativeWriteError('Native FAT32 formatting supports drives from 64 MiB through 2 TiB')
        from .fat32_layout import _geometry
        _geometry(target.device.size, maximum=2*1024**4)
    if type(passes) is not int or not 1 <= passes <= 4:
        raise NativeWriteError('Surface testing requires one through four passes')
    parent_identity = None
    path = None
    if operation == 'backup':
        if not destination:
            raise NativeWriteError('Choose a destination for the backup')
        path = Path(destination).absolute()
        parent = path.parent.resolve(strict=True)
        path = parent / path.name
        if path.suffix.lower() not in {'.img', '.raw', '.vhd', '.vhdx'}:
            raise NativeWriteError('Save the backup as .img, .raw, .vhd or .vhdx')
        maximum={'.vhd':0xFF000000*512,'.vhdx':64*1024**4}.get(path.suffix.lower())
        if maximum is not None and target.device.size>maximum:
            raise NativeWriteError('The drive exceeds the selected virtual backup format capacity')
        if path.exists() or path.is_symlink():
            raise NativeWriteError('Backup destination already exists; choose a new filename')
        for mount in target.device.mountpoints:
            if mount and parent.is_relative_to(Path(mount).resolve()):
                raise NativeWriteError('Save the backup on a different drive')
        info = parent.stat()
        parent_identity = (info.st_dev, info.st_ino)
        required=(target.device.size*2+max(64*1024*1024,(target.device.size+127)//128)
                  if path.suffix.lower() in {'.vhd','.vhdx'} else BLOCK if sparse else target.device.size+BLOCK)
        if shutil.disk_usage(parent).free < required:
            raise NativeWriteError('Not enough destination space for a full-drive backup')
    elif destination is not None:
        raise NativeWriteError('This tool does not use an output file')
    if operation == 'restore':
        from .native_restore import validate_restore_options
        validate_restore_options(target.device.size, filesystem, partition_table, label, cluster_size,logical_sector_size=target.device.logical_sector_size)
    return NativeToolPlan(operation, target, include_fixed, path, parent_identity, bool(sparse),
                          filesystem, partition_table, label, cluster_size, bool(quick), passes, bool(capacity_first))


def _require_parent(plan):
    info = plan.destination.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != plan.parent_identity:
        raise NativeWriteError('The backup destination directory changed')


def _read_exact(disk, size, writer):
    data = bytearray()
    while len(data) < size:
        writer.check_cancelled()
        chunk = disk.read(size-len(data))
        if not chunk or len(chunk) > size-len(data):
            raise NativeWriteError('The drive returned incomplete data')
        data.extend(chunk)
    return bytes(data)


def _locked_target(writer, plan):
    if plan.operation == 'backup':
        matches = [item for item in writer.discovery(plan.include_fixed, host=writer.host)
                   if item.device.path == plan.target.device.path]
        if len(matches) != 1 or matches[0].physical_identity != plan.target.physical_identity:
            raise NativeWriteError('The source disappeared or its identity changed')
        return
    current = writer.revalidate(plan, locked=True)
    if writer.host != 'darwin' and not writer.write_started and current.volumes != plan.target.volumes:
        raise NativeWriteError('The target volume set changed while locking')
    if writer.host == 'darwin' and current.device.mountpoints:
        raise NativeWriteError('The target still has mounted filesystems')


def _backup(plan, disk, writer, progress):
    _require_parent(plan)
    descriptor, temporary_name = tempfile.mkstemp(prefix='.isopropyl-backup-', dir=plan.destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, 'w+b') as output:
            if plan.sparse:
                from .native_layout import sparse_file
                sparse_file(output, plan.size)
            digest = hashlib.sha256()
            disk.seek(0)
            done = 0
            while done < plan.size:
                data = _read_exact(disk, min(BLOCK, plan.size-done), writer)
                if not plan.sparse or any(data):
                    output.seek(done); output.write(data)
                digest.update(data); done += len(data)
                progress('Backing up drive', done, plan.size)
            output.flush(); os.fsync(output.fileno())
            output.seek(0)
            actual = hashlib.sha256()
            done = 0
            while done < plan.size:
                writer.check_cancelled()
                data = output.read(min(BLOCK, plan.size-done))
                if not data:
                    raise NativeWriteError('Backup verification read ended unexpectedly')
                actual.update(data); done += len(data)
                progress('Verifying backup file', done, plan.size)
            if actual.digest() != digest.digest():
                raise NativeWriteError('Backup file failed SHA-256 verification')
            # Re-read the source too: a mounted or changing source is never
            # silently advertised as a coherent whole-drive backup.
            disk.seek(0); source_digest = hashlib.sha256(); done = 0
            while done < plan.size:
                data = _read_exact(disk, min(BLOCK, plan.size-done), writer)
                source_digest.update(data); done += len(data)
                progress('Verifying backup source', done, plan.size)
            if source_digest.digest() != digest.digest():
                raise NativeWriteError('The source changed during backup; close applications using the drive and retry')
            writer.check_cancelled(); _locked_target(writer, plan); _require_parent(plan)
            # Hardlink publication refuses an existing destination, including a
            # symlink introduced after confirmation. No partial backup appears.
            if plan.destination.suffix.lower() in {'.vhd', '.vhdx'}:
                export_private_backup(temporary, plan.destination, writer, progress, before_publish=lambda: (_locked_target(writer,plan), _require_parent(plan)))
            else:
                os.link(temporary, plan.destination)
        return digest.hexdigest()
    finally:
        temporary.unlink(missing_ok=True)


def _pattern(key, offset, size):
    return hashlib.shake_256(key + offset.to_bytes(8, 'little')).digest(size)


def _write_verify(plan, disk, writer, progress):
    metadata = None
    if plan.operation == 'format_fat32':
        from .native_format import blank_fat32, formatted_chunk
        metadata = blank_fat32(plan.size, writer.check_cancelled)
    # The final surface pass is unique to each disk offset, so an aliased or
    # counterfeit capacity cannot pass by repeating a constant pattern.
    passes = ((b'\xaa', b'\x55', b'\xff')[:plan.passes-1] + (secrets.token_bytes(32),)) if plan.operation == 'surface' else (b'\x00',)
    for number, key in enumerate(passes, 1):
        label = ('Formatting FAT32' if metadata is not None else
                 'Zeroing drive' if plan.operation == 'zero' else f'Surface test {number}/{len(passes)}')
        _locked_target(writer, plan)
        disk.seek(0)
        done = 0
        while done < plan.size:
            writer.check_cancelled()
            size = min(BLOCK, plan.size-done)
            data = formatted_chunk(metadata, done, size) if metadata is not None else key*size if len(key) == 1 else _pattern(key, done, size)
            writer.write_started = True
            writer.write_all(disk, data); done += size
            progress(label + ' · writing', done, plan.size)
        disk.flush(); disk.seek(0)
        done = 0
        while done < plan.size:
            size = min(BLOCK, plan.size-done)
            expected = formatted_chunk(metadata, done, size) if metadata is not None else key*size if len(key) == 1 else _pattern(key, done, size)
            if _read_exact(disk, size, writer) != expected:
                raise NativeWriteError(f'Drive verification failed at byte {done}; the drive may be damaged or report false capacity')
            done += size
            progress(label + ' · verifying', done, plan.size)
    writer.check_cancelled(); _locked_target(writer, plan)
    if metadata is not None:
        return 'FAT32 format and full-drive overwrite verified. Eject and reconnect the drive to use it.'
    return f'Every advertised byte ({plan.size} bytes) was verified as zero.' if plan.operation == 'zero' else f'{"Quick capacity sampling and a" if plan.capacity_first else "A"}ll {"four" if plan.passes == 4 else plan.passes} full-drive write/read passes succeeded across {plan.size} advertised bytes. Reformat the drive before use.'


def run_tool(plan, confirmation, writer, *, progress=lambda *args: None):
    if writer.used:
        raise NativeWriteError('Each drive-tool runner can run only once')
    writer.used = True
    if confirmation != plan.confirmation:
        raise NativeWriteError('The confirmed drive operation was not supplied')
    if build_tool_plan(plan.operation, plan.target, include_fixed=plan.include_fixed,
                       destination=plan.destination, sparse=plan.sparse, filesystem=plan.filesystem,
                       partition_table=plan.partition_table, label=plan.label, cluster_size=plan.cluster_size, quick=plan.quick, passes=plan.passes, capacity_first=plan.capacity_first) != plan:
        raise NativeWriteError('The drive-tool plan changed after confirmation')
    writer.check_cancelled(); writer.privilege_check(writer.host)
    if plan.operation in {'restore','format_fat32'}:
        from .native_restore import run_restore
        if plan.operation=='format_fat32':
            from dataclasses import replace
            plan=replace(plan,filesystem='fat32',quick=False)
        return run_restore(plan, writer, progress)
    if plan.operation == 'backup':
        _locked_target(writer, plan)
        target = plan.target
        from .native_disk_io import open_disk, open_read_disk
        opener = open_read_disk if writer.opener is open_disk else writer.opener
    else:
        target = writer.revalidate(plan)
        opener = writer.opener
    with opener(target, writer.host) as disk:
        _locked_target(writer, plan)
        if plan.operation == 'backup':
            return _backup(plan, disk, writer, progress)
        if plan.operation == 'fast_zero':
            return _fast_zero(plan, disk, writer, progress)
        if plan.operation == 'capacity':
            return _capacity(plan, disk, writer, progress)
        if plan.operation == 'surface' and plan.capacity_first:
            _capacity(plan, disk, writer, progress)
        return _write_verify(plan, disk, writer, progress)


def _fast_zero(plan, disk, writer, progress):
    written = skipped = 0
    for offset in range(0, plan.size, BLOCK):
        size = min(BLOCK, plan.size-offset)
        disk.seek(offset)
        existing = _read_exact(disk, size, writer)
        if any(existing):
            _locked_target(writer, plan)
            disk.seek(offset); writer.write_started = True
            writer.write_all(disk, bytes(size)); written += size
        else:
            skipped += size
        progress('Scanning and zeroing drive', offset+size, plan.size)
    disk.flush(); disk.seek(0)
    for offset in range(0, plan.size, BLOCK):
        size = min(BLOCK, plan.size-offset)
        if any(_read_exact(disk, size, writer)):
            raise NativeWriteError(f'Zero verification failed at byte {offset}')
        progress('Verifying zeroed drive', offset+size, plan.size)
    _locked_target(writer, plan)
    return f'Every advertised byte verified as zero. Written: {written} bytes; already zero: {skipped} bytes.'


def _capacity(plan, disk, writer, progress):
    # Keep every sample live until all writes finish. Immediate write/read
    # sampling misses firmware that aliases a later address onto an earlier one.
    size = min(1024*1024, plan.size)
    count = min(256, max(1, plan.size // size))
    sector=plan.target.device.logical_sector_size
    offsets = sorted({((plan.size-size)*i//max(1,count-1))//sector*sector for i in range(count)})
    key = secrets.token_bytes(32)
    _locked_target(writer, plan)
    for number, offset in enumerate(offsets):
        writer.check_cancelled(); disk.seek(offset); writer.write_started = True
        writer.write_all(disk, _pattern(key, offset, size))
        progress('Quick capacity test · writing samples', number+1, len(offsets))
    disk.flush()
    for number, offset in enumerate(offsets):
        disk.seek(offset)
        if _read_exact(disk, size, writer) != _pattern(key, offset, size):
            raise NativeWriteError(f'Capacity sample failed at byte {offset}; damaged or aliased capacity')
        progress('Quick capacity test · verifying samples', number+1, len(offsets))
    _locked_target(writer, plan)
    return f'{len(offsets)} address-specific samples verified across {plan.size} advertised bytes. Sampling is not a full capacity certification. Reformat the drive before use.'


def export_private_backup(raw, destination, writer, progress, *, before_publish=lambda: None):
    from .native_virtual import qemu_tool, run_native_command, _require_tool
    tool = qemu_tool(writer.host)
    fmt = 'vpc' if destination.suffix.lower() == '.vhd' else 'vhdx'
    descriptor, name = tempfile.mkstemp(prefix='.isopropyl-virtual-', dir=destination.parent)
    os.close(descriptor); temporary = Path(name)
    try:
        _require_tool(tool)
        options = ['-o', 'subformat=dynamic,force_size=on'] if fmt == 'vpc' else ['-o', 'subformat=dynamic']
        progress('Converting verified backup', 0, 1)
        run_native_command([str(tool.path), 'convert', '-f', 'raw', '-O', fmt, *options, str(raw), str(temporary)], writer)
        _require_tool(tool)
        run_native_command([str(tool.path), 'compare', '-q', '-f', 'raw', '-F', fmt, str(raw), str(temporary)], writer)
        _require_tool(tool); writer.check_cancelled()
        with temporary.open('rb') as output: os.fsync(output.fileno())
        before_publish()
        os.link(temporary, destination)
        progress('Converting verified backup', 1, 1)
    finally:
        temporary.unlink(missing_ok=True)
