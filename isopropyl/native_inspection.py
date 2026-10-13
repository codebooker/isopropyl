"""Read-only source checksums and partition inspection, shared by native hosts."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import os
import stat
from pathlib import Path

from .portable_io import descriptor_status
from .native_writer import BLOCK, NativeWriteError, file_identity, path_file_identity
from .partition_tables import PARTITION_TABLE_CAPTURE_BYTES, inspect_partition_tables_capture


def inspect_source(path, writer, progress=lambda *args: None):
    path = Path(path).absolute()
    if not stat.S_ISREG(path.lstat().st_mode):
        raise NativeWriteError('Choose a regular image file')
    identity = path_file_identity(path)
    hashes = {'MD5':hashlib.md5(usedforsecurity=False), 'SHA-1':hashlib.sha1(usedforsecurity=False),
              'SHA-256':hashlib.sha256(), 'SHA-512':hashlib.sha512()}
    with path.open('rb') as source:
        if file_identity(descriptor_status(source.fileno())) != identity:
            raise NativeWriteError('The source image changed before inspection')
        done = 0
        while data := source.read(BLOCK):
            writer.check_cancelled()
            if file_identity(descriptor_status(source.fileno())) != identity:
                raise NativeWriteError('The source image changed during inspection')
            for digest in hashes.values():
                digest.update(data)
            done += len(data)
            progress('Inspecting image and calculating checksums', done, max(1,identity[2]))
        source.seek(0)
        capture = min(identity[2],PARTITION_TABLE_CAPTURE_BYTES)
        prefix = source.read(capture)
        source.seek(identity[2]-capture)
        tail = source.read(capture)
        if (done != identity[2] or file_identity(descriptor_status(source.fileno())) != identity
                or path_file_identity(path) != identity):
            raise NativeWriteError('The source image changed during inspection')
    writer.check_cancelled()
    rows = [f'Image: {path.name}', f'Source size: {done:,} bytes']
    from .images import inspect_image
    progress('Inspecting boot records, filesystems and signatures',0,1)
    from .native_inputs import PREPARED_SUFFIXES,prepare_image
    try:
        if path.suffix.lower() in PREPARED_SUFFIXES:
            from types import SimpleNamespace
            import tempfile
            from .images import MAX_INSPECTION_EXPANDED_BYTES
            plan=SimpleNamespace(source=path,source_identity=identity,size=identity[2],expected_sha256=None,
                target=SimpleNamespace(device=SimpleNamespace(size=MAX_INSPECTION_EXPANDED_BYTES)))
            with tempfile.TemporaryDirectory(prefix='isopropyl-inspection-') as directory:
                expanded=prepare_image(plan,Path(directory),writer,progress,return_source=True)
                inspection=inspect_image(expanded,cancel_check=writer.check_cancelled)
        else:
            inspection=inspect_image(path,expected_identity=identity,cancel_check=writer.check_cancelled)
    except OSError as error:
        try:unchanged=path_file_identity(path)==identity
        except OSError:unchanged=False
        if not unchanged:
            raise NativeWriteError('The source image changed during inspection') from error
        raise
    rows += [f'Type: {inspection.kind}',f'Expanded size: {inspection.size:,} bytes',
             f'Volume label: {inspection.volume_label or "none"}',
             f'Boot modes: {", ".join(inspection.boot_modes) or "none detected"}',
             f'Architectures: {", ".join(inspection.architectures) or "none detected"}',
             f'Bootloader: {inspection.bootloader or "none detected"} {inspection.bootloader_version}',
             f'File catalog: {len(inspection.members)} entries; {"complete" if inspection.contents_scanned else "not complete"}']
    rows.extend(f'Bootloader warning: {issue}' for issue in inspection.bootloader_issues)
    rows.extend(f'UEFI warning: {issue}' for issue in inspection.uefi_analysis_issues)
    for payload in inspection.uefi_payloads:
        rows.append(f'EFI: {payload.path} · {payload.architecture} · signature table {payload.signature_state.value}')
        if payload.authenticode:rows.append(f'  Authenticode: {payload.authenticode.state.value} {payload.authenticode.error}')
        if payload.dbx:rows.append(f'  DBX: {payload.dbx.state.value}')
    progress('Inspecting boot records, filesystems and signatures',1,1)
    try:unchanged=path_file_identity(path)==identity
    except OSError as error:
        raise NativeWriteError('The source image changed or became unavailable during inspection') from error
    if not unchanged:
        raise NativeWriteError('The source image changed during inspection')
    if path.suffix.lower() in {'.img','.raw','.usb','.wic','.iso'} and done >= 512:
        partitions = inspect_partition_tables_capture(prefix,tail,done)
        rows.append('Partition map: ' + (partitions.kind or 'none'))
        rows.extend(f'Partition warning: {issue}' for issue in partitions.issues)
        if len(prefix) >= 17*2048 and prefix[16*2048+1:16*2048+6] == b'CD001':
            label = prefix[16*2048+40:16*2048+72].decode('ascii',errors='replace').strip()
            rows.append('Optical filesystem: ISO 9660' + (f' · {label}' if label else ''))
    rows.append('')
    rows.extend(f'{name}: {digest.hexdigest()}' for name,digest in hashes.items())
    rows.append('\nChecksums identify the source file; they do not establish bootability or publisher authenticity.')
    return '\n'.join(rows)
