"""One-shot native raw writes with source staging and mandatory read-back.

This backend does not emulate Linux memfd/Polkit guarantees. macOS and Windows
require an explicitly elevated process, with their own device locking APIs.
"""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from .native_devices import NativeDevice, discover
from .native_disk_io import open_disk, require_privileges
from .partition_tables import (
    PARTITION_TABLE_CAPTURE_BYTES,
    inspect_partition_tables_capture,
)

BLOCK = 4 * 1024 * 1024
SUFFIXES = {".iso", ".img", ".raw", ".usb", ".wic"}


class NativeWriteError(RuntimeError):
    pass


class NativeCancelled(NativeWriteError):
    pass


def file_identity(info) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def path_file_identity(path: Path) -> tuple[int, ...]:
    # On Windows stat(path).ctime can mean creation time while fstat(fd).ctime
    # means metadata-change time. Use handle metadata on both sides of a bind.
    with path.open('rb') as source:
        return file_identity(os.fstat(source.fileno()))


@dataclass(frozen=True)
class NativeWritePlan:
    source: Path
    source_identity: tuple[int, ...]
    target: NativeDevice
    include_fixed: bool
    expected_sha256: str | None

    @property
    def size(self) -> int:
        return self.source_identity[2]

    @property
    def confirmation(self) -> str:
        return f"ERASE {self.target.device.path}"


def build_plan(source: str | Path, target: NativeDevice, *, include_fixed: bool = False,
               expected_sha256: str | None = None) -> NativeWritePlan:
    path = Path(source).absolute()
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise NativeWriteError("Choose a regular disk image file")
    if path.suffix.lower() not in SUFFIXES:
        from .native_inputs import build_prepared_plan
        return build_prepared_plan(path, target, include_fixed=include_fixed,
                                   expected_sha256=expected_sha256)
    device = target.device
    if device.read_only or device.size <= 0 or device.size % 512 or device.logical_sector_size != 512:
        raise NativeWriteError("Native raw writes require a writable disk with 512-byte logical sectors")
    if not device.removable and not include_fixed:
        raise NativeWriteError("Fixed USB disks require explicit opt-in")
    if info.st_size < 512 or info.st_size > device.size or info.st_size % 512:
        raise NativeWriteError("The image must fit the target and contain complete 512-byte sectors")
    if expected_sha256 is not None:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
            raise NativeWriteError("Expected SHA-256 must contain exactly 64 hexadecimal characters")
        expected_sha256 = expected_sha256.lower()
    identity = path_file_identity(path)
    if identity[2] != info.st_size:
        raise NativeWriteError('The source image changed during preflight')
    if path.suffix.lower() == ".iso":
        # Reject optical-only installer media before asking for administrator
        # access or staging gigabytes that cannot produce a raw-bootable USB.
        with path.open("rb") as source:
            size = min(info.st_size, PARTITION_TABLE_CAPTURE_BYTES)
            prefix = source.read(size)
            source.seek(info.st_size - size)
            tail = source.read(size)
            if file_identity(os.fstat(source.fileno())) != identity or path_file_identity(path) != identity:
                raise NativeWriteError("The source image changed during preflight")
        partitions = inspect_partition_tables_capture(prefix, tail, info.st_size)
        if not partitions.valid or not partitions.complete or partitions.sector_size != 512:
            raise NativeWriteError("This ISO has no valid 512-byte disk partition map. Native raw mode supports hybrid ISOs; use filesystem ISO mode for optical installers")
    return NativeWritePlan(path, identity, target, include_fixed, expected_sha256)


class NativeWriter:
    def __init__(self, *, host: str | None = None, discovery=discover, opener=open_disk,
                 privilege_check=require_privileges, temp_directory: str | None = None):
        self.host = host or sys.platform
        self.discovery, self.opener, self.privilege_check = discovery, opener, privilege_check
        self.temp_directory = temp_directory
        self.cancelled = threading.Event()
        self.used = False
        self.write_started = False
        self.final_verification = False

    def cancel(self) -> None:
        self.cancelled.set()

    def check_cancelled(self) -> None:
        if self.cancelled.is_set():
            suffix = " The target is incomplete and must be rewritten." if self.write_started else ""
            raise NativeCancelled("Operation cancelled." + suffix)

    def revalidate(self, plan: NativeWritePlan, *, locked: bool = False) -> NativeDevice:
        self.check_cancelled()
        matches = [item for item in self.discovery(plan.include_fixed, host=self.host)
                   if item.device.path == plan.target.device.path]
        physical_only = locked
        expected = plan.target.physical_identity if physical_only else plan.target.identity
        actual = (matches[0].physical_identity if physical_only else matches[0].identity) if len(matches) == 1 else None
        if actual != expected or matches[0].device.read_only:
            raise NativeWriteError("The target disappeared or its identity/safety metadata changed")
        return matches[0]

    def run(self, plan: NativeWritePlan, confirmation: str, *, progress=lambda stage, done, total: None) -> str:
        from .native_inputs import PreparedImagePlan, run_prepared_image
        if isinstance(plan, PreparedImagePlan):
            return run_prepared_image(plan, confirmation, self, progress=progress)
        if self.used:
            raise NativeWriteError("Each writer can run only once")
        self.used = True
        if confirmation != plan.confirmation:
            raise NativeWriteError("The exact erase confirmation was not supplied")
        if build_plan(plan.source, plan.target, include_fixed=plan.include_fixed,
                      expected_sha256=plan.expected_sha256) != plan:
            raise NativeWriteError("The source image changed after confirmation")
        self.privilege_check(self.host)
        self.revalidate(plan)
        directory = self.temp_directory or tempfile.gettempdir()
        reuse=getattr(self,'_worker_private_source',False)
        if reuse:
            from .portable_fs import os as private_os
            parent=private_os.lstat(plan.source.parent);source_status=private_os.lstat(plan.source)
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_mode&0o077 or source_status.st_nlink!=1
                    or source_status.st_uid!=parent.st_uid or source_status.st_mode&0o077):
                raise NativeWriteError('The worker source is not a private staged image')
        if not reuse and shutil.disk_usage(directory).free < plan.size + BLOCK:
            raise NativeWriteError("Not enough temporary space for a complete image snapshot")
        # All source bytes are copied and checked before any unmount or disk open.
        # TemporaryFile is private and automatically removed on every exit path.
        with (plan.source.open("rb") if reuse else tempfile.TemporaryFile(dir=directory)) as snapshot:
            digest = hashlib.sha256()
            with plan.source.open("rb") as source:
                if file_identity(os.fstat(source.fileno())) != plan.source_identity:
                    raise NativeWriteError("The source image changed after confirmation")
                done = 0
                while done < plan.size:
                    self.check_cancelled()
                    chunk = source.read(min(BLOCK, plan.size - done))
                    if not chunk:
                        raise NativeWriteError("The source image ended unexpectedly")
                    if not reuse:snapshot.write(chunk)
                    digest.update(chunk)
                    done += len(chunk)
                    progress("Staging image", done, plan.size)
                if (source.read(1) or file_identity(os.fstat(source.fileno())) != plan.source_identity
                        or path_file_identity(plan.source) != plan.source_identity):
                    raise NativeWriteError("The source image changed while staging")
            checksum = digest.hexdigest()
            if plan.expected_sha256 and checksum != plan.expected_sha256:
                raise NativeWriteError("Image SHA-256 does not match the expected checksum")
            snapshot.flush()
            snapshot.seek(0)
            capture_size = min(plan.size, PARTITION_TABLE_CAPTURE_BYTES)
            prefix = snapshot.read(capture_size)
            snapshot.seek(plan.size - capture_size)
            tail = snapshot.read(capture_size)
            partitions = inspect_partition_tables_capture(prefix, tail, plan.size)
            if partitions.malformed or not partitions.complete or (
                    partitions.valid and partitions.sector_size != 512):
                raise NativeWriteError("The image partition map is malformed, incomplete or uses unsupported sector geometry")
            if plan.source.suffix.lower() == ".iso" and not partitions.valid:
                raise NativeWriteError("This ISO has no disk partition map. Native raw mode supports hybrid ISOs; use filesystem ISO mode for optical installers")
            snapshot.seek(0)
            target = self.revalidate(plan)
            with self.opener(target, self.host) as disk:
                current = self.revalidate(plan, locked=True)
                # macOS EXLOCK hides partitions and synthesized APFS volumes.
                # Successful unmount plus the exclusive handle protects them;
                # IOMedia lifetime and handle geometry still bind the target.
                if self.host != 'darwin' and current.volumes != target.volumes:
                    raise NativeWriteError("The target volume set changed while locking")
                if self.host == "darwin" and current.device.mountpoints:
                    raise NativeWriteError("The target still has mounted filesystems")
                # Withhold every boot/partition-table activation header until
                # all payload bytes and stale-tail cleanup have passed read-back.
                activation=[(0,512)]
                if prefix[512:520]==b"EFI PART":
                    activation.append((512,512))
                if tail[-512:-504]==b"EFI PART":
                    activation.append((plan.size-512,512))
                activation=sorted(set(activation))
                headers={}
                for offset,length in activation:
                    snapshot.seek(offset);headers[offset]=snapshot.read(length)
                    if len(headers[offset])!=length:
                        raise NativeWriteError("The staged activation header is truncated")
                    disk.seek(offset);self.write_started=True;self.write_all(disk,bytes(length))
                done=0
                while done<plan.size:
                    self.check_cancelled()
                    next_header=next(((offset,length) for offset,length in activation if offset>=done),None)
                    if next_header and next_header[0]==done:
                        done+=next_header[1];continue
                    length=min(BLOCK,plan.size-done)
                    if next_header:length=min(length,next_header[0]-done)
                    snapshot.seek(done);chunk=snapshot.read(length)
                    if len(chunk)!=length:raise NativeWriteError("The staged image ended unexpectedly")
                    disk.seek(done);self.write_all(disk,chunk);done+=length
                    progress("Writing",done,plan.size)
                tail_start=max(plan.size,plan.target.device.size-1024*1024)
                tail_size=plan.target.device.size-tail_start
                if tail_size:
                    self.check_cancelled();disk.seek(tail_start);self.write_all(disk,bytes(tail_size))
                disk.flush()
                actual=hashlib.sha256();done=0
                while done<plan.size:
                    self.check_cancelled()
                    header=next(((offset,length) for offset,length in activation if offset==done),None)
                    next_offset=min((offset for offset,length in activation if offset>done),default=plan.size)
                    length=header[1] if header else min(BLOCK,plan.size-done,next_offset-done)
                    disk.seek(done);chunk=disk.read(length)
                    if len(chunk)!=length:raise NativeWriteError("Target read-back ended unexpectedly")
                    if header:
                        if any(chunk):raise NativeWriteError("An inactive activation header changed during writing")
                        chunk=headers[done]
                    actual.update(chunk);done+=length;progress("Verifying",done,plan.size)
                if actual.hexdigest()!=checksum:
                    raise NativeWriteError("Read-back verification failed. Activation headers were not published.")
                if tail_size:
                    disk.seek(tail_start)
                    remaining=tail_size
                    while remaining:
                        chunk=disk.read(remaining)
                        if not chunk or len(chunk)>remaining or any(chunk):
                            raise NativeWriteError("Stale partition metadata cleanup failed verification")
                        remaining-=len(chunk)
                self.check_cancelled();self.revalidate(plan,locked=True)
                # Backup GPT first, primary GPT next, MBR/VBR last. Every header
                # is read back before publishing the following activation point.
                for offset,length in sorted(activation,reverse=True):
                    self.check_cancelled();disk.seek(offset);self.write_all(disk,headers[offset]);disk.flush()
                    disk.seek(offset)
                    if disk.read(length)!=headers[offset]:
                        raise NativeWriteError("Activation-header verification failed")
                progress("Writing",plan.size,plan.size)
                if tail_size:
                    disk.seek(tail_start)
                    remaining = tail_size
                    while remaining:
                        self.check_cancelled()
                        chunk = disk.read(remaining)
                        if not chunk or len(chunk) > remaining or any(chunk):
                            raise NativeWriteError("Stale partition metadata cleanup failed verification")
                        remaining -= len(chunk)
                self.check_cancelled()
                if self.final_verification:
                    final=hashlib.sha256();done=0
                    disk.seek(0)
                    while done<plan.size:
                        self.check_cancelled();chunk=disk.read(min(BLOCK,plan.size-done))
                        if not chunk:raise NativeWriteError("Final verification read-back ended unexpectedly")
                        final.update(chunk);done+=len(chunk);progress("Final verification",done,plan.size)
                    if final.hexdigest()!=checksum:raise NativeWriteError("Final verification failed. The target must be rewritten.")
                    self.revalidate(plan,locked=True)
            return checksum

    def write_all(self, disk, data: bytes) -> None:
        done = 0
        while done < len(data):
            self.check_cancelled()
            count = disk.write(data[done:])
            if type(count) is not int or count <= 0 or count > len(data) - done or count % 512:
                raise NativeWriteError("Native disk write made invalid or unaligned progress")
            done += count
