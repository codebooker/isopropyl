"""Private, catalog-bound ISO extraction on native hosts."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .native_archive import seven_zip,bound_archive
from .portable_io import descriptor_status
from .native_writer import BLOCK,NativeWriteError,file_identity,path_file_identity
from .timestamps import MIN_PORTABLE_ARCHIVE_MTIME_NS,MAX_PORTABLE_ARCHIVE_MTIME_NS


def snapshot_file(source,identity,destination,writer,progress=lambda *args:None):
    digest=hashlib.sha256();done=0
    with source.open('rb') as original,destination.open('xb') as output:
        destination.chmod(0o600)
        if file_identity(descriptor_status(original.fileno()))!=identity:raise NativeWriteError('Source changed after confirmation')
        while data:=original.read(BLOCK):
            writer.check_cancelled();output.write(data);digest.update(data);done+=len(data)
            if done>identity[2]:raise NativeWriteError('Source grew while staging')
            progress('Staging source',done,max(1,identity[2]))
        if done!=identity[2] or file_identity(descriptor_status(original.fileno()))!=identity or path_file_identity(source)!=identity:
            raise NativeWriteError('Source changed during staging')
        output.flush();os.fsync(output.fileno())
    return digest.hexdigest()


def extract_member(source,descriptor,member,destination,expected_size,namespace,writer):
    executable=seven_zip()
    if not executable:raise NativeWriteError('7-Zip is unavailable')
    flags=[] if namespace is None else ['-t'+namespace.value]
    options={'creationflags':subprocess.CREATE_NO_WINDOW} if sys.platform=='win32' else {}
    with bound_archive(source,descriptor),destination.open('xb') as output,tempfile.TemporaryFile() as errors:
        destination.chmod(0o600)
        process=subprocess.Popen([executable,'x','-so','-spd','-y',*flags,'--',str(source),member],
            stdin=subprocess.DEVNULL,stdout=output,stderr=errors,shell=False,**options)
        deadline=time.monotonic()+1800
        try:
            while process.poll() is None:
                writer.check_cancelled()
                if time.monotonic()>deadline or os.fstat(output.fileno()).st_size>expected_size or os.fstat(errors.fileno()).st_size>65536:
                    raise NativeWriteError('ISO extraction exceeded its time, size or diagnostic bound')
                try:process.wait(timeout=.1)
                except subprocess.TimeoutExpired:pass
            writer.check_cancelled();output.flush();os.fsync(output.fileno())
            if process.returncode or os.fstat(output.fileno()).st_size!=expected_size:
                raise NativeWriteError(f'ISO member extraction failed: {member}')
        finally:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=2)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=2)


def extract_iso(source,tree,writer,progress=lambda *args:None):
    from .images import inspect_image,scan_image_catalog
    from .iso import ArchiveEntry,EntryKind,validate_portable_fat_entries
    identity=path_file_identity(source)
    progress('Inspecting ISO structure and boot files',0,1)
    inspection=inspect_image(source,expected_identity=identity,cancel_check=writer.check_cancelled)
    with source.open('rb') as stream:
        scan=scan_image_catalog(source,image_fd=stream.fileno(),cancel_check=writer.check_cancelled)
        if not scan.complete:raise NativeWriteError('The complete ISO catalog could not be inspected')
        entries=tuple(ArchiveEntry(item.path,item.size,EntryKind(item.kind),
            item.link_target or None,item.modified_ns) for item in scan.members)
        from .iso_staging import preview_embedded_fat_catalog,_validate_distro_iso_policy
        _validate_distro_iso_policy(entries)
        validate_portable_fat_entries(entries)
        from .eltorito import inspect_eltorito_file,ElToritoNotFound
        from .fat_image import inspect_uefi_eltorito_fats,materialize_embedded_fat
        embedded=();boot_catalog=None
        try:boot_catalog=inspect_eltorito_file(source,image_fd=stream.fileno())
        except ElToritoNotFound:pass
        if boot_catalog:embedded=inspect_uefi_eltorito_fats(stream.fileno(),boot_catalog,cancel_check=writer.check_cancelled)
        preview=preview_embedded_fat_catalog(entries,embedded)
        validate_portable_fat_entries(preview.merged_entries)
        total=sum(item.size for item in entries if item.kind is EntryKind.FILE)+preview.content_bytes
        if shutil.disk_usage(tree.parent).free<total+64*1024*1024:
            raise NativeWriteError('Not enough temporary space to extract the ISO')
        tree.mkdir(mode=0o700)
        done=0;directory_times=[]
        for item in sorted(entries,key=lambda e:(len(Path(e.path).parts),e.path.casefold())):
            writer.check_cancelled();path=tree.joinpath(*Path(item.path.replace('\\','/')).parts)
            path.parent.mkdir(parents=True,exist_ok=True)
            if item.kind is EntryKind.DIRECTORY:
                path.mkdir(exist_ok=True);directory_times.append((path,item.modified_ns));continue
            extract_member(source,stream.fileno(),item.path,path,item.size,scan.namespace,writer)
            if item.modified_ns is not None and MIN_PORTABLE_ARCHIVE_MTIME_NS<=item.modified_ns<=MAX_PORTABLE_ARCHIVE_MTIME_NS:
                os.utime(path,ns=(item.modified_ns,item.modified_ns))
            done+=item.size;progress('Extracting ISO files',done,max(1,total))
        for path,modified in reversed(directory_times):
            if modified is not None and MIN_PORTABLE_ARCHIVE_MTIME_NS<=modified<=MAX_PORTABLE_ARCHIVE_MTIME_NS:
                os.utime(path,ns=(modified,modified))
        for fat,targets in zip(embedded,preview.target_sets,strict=True):
            if targets:
                materialize_embedded_fat(stream.fileno(),boot_catalog,fat,tree,targets,
                    cancel_check=writer.check_cancelled,
                    progress=lambda path,done,total:progress('Reconstructing embedded EFI files',done,max(1,total)))
        if file_identity(descriptor_status(stream.fileno()))!=identity:raise NativeWriteError('ISO changed during extraction')
    return inspection,preview.merged_entries
