from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import fcntl
import errno
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import isopropyl.restore_device_helper as restore
from isopropyl.formatting import Filesystem, FormatPlan, PartitionTable
from isopropyl.syslinux_device_helper import (
    BLKFLSBUF,
    BLKGETDISKSEQ,
    BLKGETSIZE64,
    BLKROGET,
    BLKSSZGET,
)


DEVICE_NUMBER = os.makedev(8, 240)
PARTITION_NUMBER = os.makedev(8, 241)
DISK_SEQUENCE = 998877
CAPACITY = 16 * 1024 * 1024
SECTOR = 512


def block_status(device_number: int) -> SimpleNamespace:
    return SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=device_number)


def plan(
    filesystem: Filesystem = Filesystem.FAT32,
    *,
    allocation_unit_size: int | None = None,
) -> FormatPlan:
    return FormatPlan(
        "/dev/sdz",
        ("/dev/sdz", CAPACITY, "SERIAL", "", "Test USB", "8:240"),
        filesystem,
        PartitionTable.GPT,
        "TEST",
        allocation_unit_size,
    )


def fat32_metadata(request: restore.RestoreDeviceRequest) -> dict[int, bytes]:
    sector = request.logical_sector_size
    sectors_per_cluster = (
        request.plan.allocation_unit_size // sector
        if request.plan.allocation_unit_size is not None else 1
    )
    reserved = 32
    fats = 2
    sectors_per_fat = 1
    while True:
        clusters = (
            request.partition_sector_count - reserved - fats * sectors_per_fat
        ) // sectors_per_cluster
        wanted = (clusters + 2) * 4
        wanted = (wanted + sector - 1) // sector
        if wanted == sectors_per_fat:
            break
        sectors_per_fat = wanted
    boot = bytearray(sector)
    boot[:3] = b"\xebX\x90"
    boot[3:11] = b"mkfs.fat"
    struct.pack_into("<H", boot, 11, sector)
    boot[13] = sectors_per_cluster
    struct.pack_into("<H", boot, 14, reserved)
    boot[16] = fats
    boot[21] = 0xF8
    struct.pack_into("<I", boot, 28, request.partition_start_sector)
    struct.pack_into("<I", boot, 32, request.partition_sector_count)
    struct.pack_into("<I", boot, 36, sectors_per_fat)
    struct.pack_into("<I", boot, 44, 2)
    struct.pack_into("<H", boot, 48, 1)
    struct.pack_into("<H", boot, 50, 6)
    boot[64] = 0x80
    boot[66] = 0x29
    struct.pack_into("<I", boot, 67, 0x12345678)
    label = (
        request.plan.label.encode("ascii") if request.plan.label else b"NO NAME"
    ).ljust(11, b" ")
    boot[71:82] = label
    boot[82:90] = b"FAT32   "
    boot[510:512] = b"\x55\xaa"
    fsinfo = bytearray(sector)
    fsinfo[:4] = b"RRaA"
    fsinfo[484:488] = b"rrAa"
    struct.pack_into("<I", fsinfo, 488, 0xFFFFFFFF)
    struct.pack_into("<I", fsinfo, 492, 0xFFFFFFFF)
    fsinfo[510:512] = b"\x55\xaa"
    root_offset = (reserved + fats * sectors_per_fat) * sector
    root = bytearray(sector * sectors_per_cluster)
    if request.plan.label:
        root[:11] = label
        root[11] = 0x08
    return {
        0: bytes(boot),
        sector: bytes(fsinfo),
        6 * sector: bytes(boot),
        7 * sector: bytes(fsinfo),
        root_offset: bytes(root),
    }


def ntfs_metadata(request: restore.RestoreDeviceRequest) -> dict[int, bytes]:
    sector = request.logical_sector_size
    sectors_per_cluster = (
        request.plan.allocation_unit_size // sector
        if request.plan.allocation_unit_size is not None else 8
    )
    cluster_size = sector * sectors_per_cluster
    total_sectors = request.partition_sector_count - 1
    cluster_count = (total_sectors + 1) // sectors_per_cluster
    mft_cluster = 4
    mirror_cluster = max(mft_cluster + 1, cluster_count // 2)
    boot = bytearray(sector)
    boot[:3] = b"\xebR\x90"
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 11, sector)
    boot[13] = sectors_per_cluster
    boot[21] = 0xF8
    struct.pack_into("<I", boot, 28, request.partition_start_sector)
    struct.pack_into("<Q", boot, 40, total_sectors)
    struct.pack_into("<Q", boot, 48, mft_cluster)
    struct.pack_into("<Q", boot, 56, mirror_cluster)
    struct.pack_into("b", boot, 64, -10)
    struct.pack_into("b", boot, 68, -12)
    struct.pack_into("<Q", boot, 72, 0x0123456789ABCDEF)
    boot[510:512] = b"\x55\xaa"

    record = bytearray(1024)
    record[:4] = b"FILE"
    struct.pack_into("<HH", record, 4, 48, 3)
    struct.pack_into("<H", record, 20, 56)
    struct.pack_into("<H", record, 22, 1)
    struct.pack_into("<I", record, 28, len(record))
    struct.pack_into("<I", record, 44, 3)
    sequence = b"\xa5Z"
    record[48:50] = sequence
    record[50:54] = b"\0\0\0\0"
    record[510:512] = sequence
    record[1022:1024] = sequence
    label = request.plan.label.encode("utf-16-le")
    attribute_length = (24 + len(label) + 7) & ~7
    struct.pack_into("<II", record, 56, 0x60, attribute_length)
    struct.pack_into("<I", record, 72, len(label))
    struct.pack_into("<H", record, 76, 24)
    record[80:80 + len(label)] = label
    end = 56 + attribute_length
    struct.pack_into("<I", record, end, 0xFFFFFFFF)
    struct.pack_into("<I", record, 24, end + 8)
    record_offset = mft_cluster * cluster_size + 3 * len(record)
    return {
        0: bytes(boot),
        total_sectors * sector: bytes(boot),
        record_offset: bytes(record),
    }


class Harness:
    def __init__(
        self,
        filesystem: Filesystem = Filesystem.FAT32,
        *,
        allocation_unit_size: int | None = None,
    ) -> None:
        self.target = tempfile.TemporaryFile()
        self.target.truncate(CAPACITY)
        self.target.seek(0)
        self.target.write(b"not-zero" * 1024)
        self.target.flush()
        self.partition = tempfile.TemporaryFile()
        self.target_fds: set[int] = set()
        self.partition_fds: set[int] = set()
        self.partition_created = False
        self.open_flags: list[tuple[str, int]] = []
        self.lock_calls: list[tuple[int, int]] = []
        self.close_calls: list[int] = []
        self.children: list[tuple[tuple[str, ...], bytes | None, tuple[int, ...]]] = []
        self.flushes: list[tuple[int, int]] = []
        self.progress: list[tuple[str, int, int]] = []
        self.prepared_calls = 0
        self.request = restore.build_restore_device_request(
            plan(filesystem, allocation_unit_size=allocation_unit_size),
            request_id=bytes(range(16)),
            disk_sequence=DISK_SEQUENCE,
            logical_sector_size=SECTOR,
            chunk_size=1024 * 1024,
        )
        self.partition.truncate(self.request.partition_sector_count * SECTOR)
        self.metadata_mutator = None

    def close(self) -> None:
        self.target.close()
        self.partition.close()

    @property
    def observation(self) -> restore.KernelTargetObservation:
        related = {DEVICE_NUMBER}
        if self.partition_created:
            related.add(PARTITION_NUMBER)
        return restore.KernelTargetObservation(
            DEVICE_NUMBER,
            frozenset(related),
            "usb",
            True,
            False,
            SECTOR,
            False,
            DISK_SEQUENCE,
        )

    def open(self, path: str, flags: int) -> int:
        self.open_flags.append((path, flags))
        if path == "/dev/sdz":
            descriptor = os.dup(self.target.fileno())
            self.target_fds.add(descriptor)
            return descriptor
        if path == "/dev/sdz1" and self.partition_created:
            descriptor = os.dup(self.partition.fileno())
            self.partition_fds.add(descriptor)
            return descriptor
        raise FileNotFoundError(path)

    def fstat(self, descriptor: int):
        if descriptor in self.target_fds:
            return block_status(DEVICE_NUMBER)
        if descriptor in self.partition_fds:
            return block_status(PARTITION_NUMBER)
        return os.fstat(descriptor)

    def ioctl_uint(self, descriptor: int, operation: int) -> int:
        if operation == BLKSSZGET:
            return SECTOR
        if operation == BLKROGET:
            return 0
        raise AssertionError(operation)

    def ioctl_u64(self, descriptor: int, operation: int) -> int:
        if operation == BLKGETSIZE64:
            return (
                self.request.partition_sector_count * SECTOR
                if descriptor in self.partition_fds else CAPACITY
            )
        if operation == BLKGETDISKSEQ:
            return DISK_SEQUENCE
        raise AssertionError(operation)

    def ioctl_void(self, descriptor: int, operation: int) -> None:
        self.flushes.append((descriptor, operation))

    def run_child(
        self,
        argv: tuple[str, ...],
        stdin: bytes | None,
        pass_fds: tuple[int, ...],
        _timeout: float,
    ) -> restore.ChildResult:
        self.children.append((argv, stdin, pass_fds))
        if argv[0] == "/usr/sbin/sfdisk" and "--json" not in argv:
            self.partition_created = True
        if argv[:2] == ("/usr/sbin/sfdisk", "--json"):
            script = restore.partition_script(
                self.request.plan, self.request.logical_sector_size,
            ).decode("ascii")
            type_value = next(
                item.split("=", 1)[1]
                for item in script.splitlines()[-1].split(", ")
                if item.startswith("type=")
            )
            payload = json.dumps({"partitiontable": {
                "label": (
                    "dos" if self.request.plan.partition_table is PartitionTable.MBR
                    else "gpt"
                ),
                "unit": "sectors",
                "sectorsize": SECTOR,
                "partitions": [{
                    "start": self.request.partition_start_sector,
                    "size": self.request.partition_sector_count,
                    "type": type_value,
                }],
            }}).encode("ascii")
            return restore.ChildResult(argv, payload)
        if argv[0] in {"/usr/sbin/mkfs.fat", "/usr/sbin/mkntfs"}:
            metadata = (
                fat32_metadata(self.request)
                if self.request.plan.filesystem is restore.Filesystem.FAT32
                else ntfs_metadata(self.request)
            )
            for offset, payload in metadata.items():
                os.pwrite(self.partition.fileno(), payload, offset)
                os.pwrite(
                    self.target.fileno(),
                    payload,
                    self.request.partition_start_sector * SECTOR + offset,
                )
            if self.metadata_mutator is not None:
                self.metadata_mutator(self)
        return restore.ChildResult(argv, b"")

    def discover(self, parent: int, number: int) -> restore.PartitionObservation:
        if not self.partition_created:
            raise restore.HelperTargetError("not created")
        return restore.PartitionObservation(
            "/dev/sdz1",
            PARTITION_NUMBER,
            parent,
            number,
            self.request.partition_start_sector,
            self.request.partition_sector_count,
        )

    def close_fd(self, descriptor: int) -> None:
        self.close_calls.append(descriptor)
        os.close(descriptor)

    def operations(self) -> restore.RestoreOperations:
        return restore.RestoreOperations(
            lstat=lambda path: block_status(DEVICE_NUMBER),
            fstat=self.fstat,
            open=self.open,
            close=self.close_fd,
            pread=os.pread,
            pwrite=os.pwrite,
            fsync=os.fsync,
            flock=lambda fd, operation: self.lock_calls.append((fd, operation)),
            ioctl_uint=self.ioctl_uint,
            ioctl_u64=self.ioctl_u64,
            ioctl_void=self.ioctl_void,
            inspect_target=lambda _dev: self.observation,
            active_devices=lambda: frozenset(),
            discover_partition=self.discover,
            run_child=self.run_child,
        )

    def execute(self, *, commit: bool = True) -> restore.RestoreDeviceResult:
        return restore.execute_restore_device_transaction(
            self.request,
            await_commit=lambda: commit,
            prepared=lambda: setattr(self, "prepared_calls", self.prepared_calls + 1),
            progress=lambda phase, done, total: self.progress.append((phase, done, total)),
            operations=self.operations(),
            require_root=False,
        )


class RestoreDeviceHelperTests(unittest.TestCase):
    def retry_context(
        self,
        harness: Harness,
        operations: restore.RestoreOperations,
        *,
        child: bool = False,
    ) -> tuple[restore._IoRetryContext, int, int]:
        whole = harness.open("/dev/sdz", os.O_RDWR)
        partition = -1
        observation = None
        if child:
            harness.partition_created = True
            observation = harness.discover(DEVICE_NUMBER, 1)
            partition = harness.open(observation.path, os.O_RDWR)
        self.addCleanup(lambda: os.close(whole))
        if partition >= 0:
            self.addCleanup(lambda: os.close(partition))
        return (
            restore._IoRetryContext(
                harness.request,
                whole,
                DEVICE_NUMBER,
                operations,
                partition,
                observation,
            ),
            whole,
            partition,
        )

    @staticmethod
    def _assert_process_absent(process_id: int) -> None:
        with unittest.TestCase().assertRaises(ProcessLookupError):
            os.kill(process_id, 0)

    def test_successful_child_with_lingering_group_member_is_killed_reaped_and_rejected(self) -> None:
        with tempfile.NamedTemporaryFile() as evidence:
            script = (
                "import os,time; "
                "child=os.fork(); "
                "(os.close(0),os.close(1),os.close(2),time.sleep(30),os._exit(0)) "
                "if child==0 else "
                f"(open({evidence.name!r},'w').write(str(child)),os._exit(0))"
            )
            with (
                patch.object(restore, "_trusted_tool"),
                self.assertRaisesRegex(restore.HelperError, "lingering process-group"),
            ):
                restore.run_exact_child((sys.executable, "-c", script), None, (), 2.0)
            evidence.seek(0)
            child = int(evidence.read().decode("ascii"))
        self._assert_process_absent(child)

    def test_successful_child_with_setsid_descendant_is_killed_reaped_and_rejected(self) -> None:
        with tempfile.NamedTemporaryFile() as evidence:
            script = f"""
import os
import time

read_fd, write_fd = os.pipe()
child = os.fork()
if child == 0:
    os.close(read_fd)
    os.setsid()
    os.close(0)
    os.close(1)
    os.close(2)
    with open({evidence.name!r}, "w") as stream:
        stream.write(str(os.getpid()))
    os.write(write_fd, b"x")
    os.close(write_fd)
    time.sleep(30)
    os._exit(0)
os.close(write_fd)
os.read(read_fd, 1)
os.close(read_fd)
os._exit(0)
"""
            with (
                patch.object(restore, "_trusted_tool"),
                self.assertRaisesRegex(restore.HelperError, "lingering process-group"),
            ):
                restore.run_exact_child((sys.executable, "-c", script), None, (), 2.0)
            evidence.seek(0)
            child = int(evidence.read().decode("ascii"))
        self._assert_process_absent(child)

    def test_run_exact_child_restores_prior_subreaper_state(self) -> None:
        previous = restore._child_subreaper_enabled()
        with patch.object(restore, "_trusted_tool"):
            result = restore.run_exact_child(
                (sys.executable, "-c", "pass"), None, (), 2.0,
            )
        self.assertEqual(result.output, b"")
        self.assertEqual(restore._child_subreaper_enabled(), previous)

    def test_timed_out_child_group_is_terminated_killed_and_fully_reaped(self) -> None:
        with tempfile.NamedTemporaryFile() as evidence:
            script = (
                "import os,time; "
                "child=os.fork(); "
                "open(" + repr(evidence.name) + ",'w').write(str(child)); "
                "time.sleep(30)"
            )
            with (
                patch.object(restore, "_trusted_tool"),
                self.assertRaisesRegex(restore.HelperError, "timed out"),
            ):
                restore.run_exact_child((sys.executable, "-c", script), None, (), 0.1)
            evidence.seek(0)
            child = int(evidence.read().decode("ascii"))
        self._assert_process_absent(child)

    def test_one_retained_descriptor_spans_zero_partition_and_format(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)

        result = harness.execute()

        self.assertEqual(harness.prepared_calls, 1)
        self.assertEqual(result.scanned_bytes, CAPACITY)
        self.assertEqual(result.verified_bytes, CAPACITY)
        self.assertEqual(result.written_bytes + result.skipped_bytes, CAPACITY)
        restore.validate_filesystem_receipt(harness.request, result.filesystem_receipt)
        self.assertIs(result.filesystem, restore.Filesystem.FAT32)
        self.assertEqual(result.filesystem_receipt.normalized_label, "TEST")
        partition_offset = harness.request.partition_start_sector * SECTOR
        self.assertEqual(
            os.pread(harness.target.fileno(), SECTOR, partition_offset),
            os.pread(harness.partition.fileno(), SECTOR, 0),
        )
        self.assertEqual(len(harness.lock_calls), 1)
        self.assertEqual(harness.lock_calls[0][1], fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertEqual(len(harness.children), 5)
        sfdisk, udevadm, metadata_before, mkfs, metadata_after = harness.children
        retained_fd = sfdisk[2][0]
        whole_flags = next(flags for path, flags in harness.open_flags if path == "/dev/sdz")
        self.assertTrue(whole_flags & os.O_EXCL)
        self.assertIn(f"/proc/self/fd/{retained_fd}", sfdisk[0])
        self.assertEqual(sfdisk[0][0], "/usr/sbin/sfdisk")
        self.assertEqual(udevadm[0], ("/usr/bin/udevadm", "settle", "--timeout=30"))
        self.assertEqual(metadata_before[0][:2], ("/usr/sbin/sfdisk", "--json"))
        self.assertEqual(metadata_after[0][:2], ("/usr/sbin/sfdisk", "--json"))
        self.assertEqual(mkfs[0][0], "/usr/sbin/mkfs.fat")
        self.assertEqual(mkfs[2], (int(mkfs[0][-1].rsplit("/", 1)[1]),))
        self.assertIn((retained_fd, restore.BLKRRPART), harness.flushes)
        self.assertIn((retained_fd, BLKFLSBUF), harness.flushes)
        self.assertIn(retained_fd, harness.close_calls)

    def test_verified_zero_retries_only_eagain_with_exact_backoff_and_offsets(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)
        base = harness.operations()
        read_calls: list[tuple[int, int, int]] = []
        write_calls: list[tuple[int, bytes, int]] = []
        waits: list[float] = []
        injected = {"scan": False, "write": False, "readback": False}

        def pread(descriptor: int, size: int, offset: int) -> bytes:
            read_calls.append((descriptor, size, offset))
            if not injected["scan"]:
                injected["scan"] = True
                raise BlockingIOError(errno.EAGAIN, "scan not ready")
            # Sixteen successful scan reads precede the first read-back call.
            successful = len(read_calls) - 1
            if successful == CAPACITY // harness.request.chunk_size and not injected["readback"]:
                injected["readback"] = True
                raise BlockingIOError(errno.EWOULDBLOCK, "read-back not ready")
            return os.pread(descriptor, size, offset)

        def pwrite(descriptor: int, data: bytes, offset: int) -> int:
            write_calls.append((descriptor, data, offset))
            if not injected["write"]:
                injected["write"] = True
                raise BlockingIOError(errno.EAGAIN, "write not ready")
            return os.pwrite(descriptor, data, offset)

        operations = replace(base, pread=pread, pwrite=pwrite, sleep=waits.append)
        context, whole, _partition = self.retry_context(harness, operations)
        result = restore._zero_and_verify(
            whole,
            harness.request,
            operations,
            lambda _phase, _done, _total: None,
            context,
        )

        self.assertEqual(result[0], CAPACITY)
        self.assertEqual(result[3], CAPACITY)
        self.assertEqual(injected, {"scan": True, "write": True, "readback": True})
        self.assertEqual(read_calls[0], read_calls[1])
        self.assertEqual(write_calls[0], write_calls[1])
        self.assertAlmostEqual(sum(waits), 0.3)
        self.assertTrue(all(0 < delay <= 0.05 for delay in waits))

    def test_eintr_is_immediate_and_partial_progress_resets_eagain_budget(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)
        base = harness.operations()
        waits: list[float] = []
        values: list[int | BaseException] = [
            InterruptedError(errno.EINTR, "one"),
            InterruptedError(errno.EINTR, "two"),
            BlockingIOError(errno.EAGAIN, "before progress"),
            2,
            BlockingIOError(errno.EAGAIN, "after progress one"),
            BlockingIOError(errno.EAGAIN, "after progress two"),
            BlockingIOError(errno.EAGAIN, "after progress three"),
            4,
        ]
        calls: list[tuple[int, bytes, int]] = []

        def pwrite(descriptor: int, data: bytes, offset: int) -> int:
            calls.append((descriptor, data, offset))
            value = values.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value

        operations = replace(base, pwrite=pwrite, sleep=waits.append)
        context, whole, _partition = self.retry_context(harness, operations)
        restore._write_exact(whole, b"abcdef", 4096, operations, context)

        self.assertEqual([call[2] for call in calls[:4]], [4096] * 4)
        self.assertEqual(calls[4][1:], (b"cdef", 4098))
        self.assertEqual(calls[-1][1:], (b"cdef", 4098))
        self.assertAlmostEqual(sum(waits), 0.1 + 0.1 + 0.5 + 2.0)
        self.assertEqual(values, [])

    def test_read_eintr_exhausts_at_independent_bound_without_sleep(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)
        base = harness.operations()
        calls = 0
        waits: list[float] = []

        def pread(_descriptor: int, _size: int, _offset: int) -> bytes:
            nonlocal calls
            calls += 1
            raise InterruptedError(errno.EINTR, "interrupted")

        operations = replace(base, pread=pread, sleep=waits.append)
        context, whole, _partition = self.retry_context(harness, operations)
        with self.assertRaisesRegex(
            restore.HelperVerificationError,
            "Interrupted retained-target I/O failed after 1024 attempts",
        ):
            restore._read_exact(whole, 1, 0, operations, context)

        self.assertEqual(restore._IO_EINTR_ATTEMPTS, 1024)
        self.assertEqual(calls, restore._IO_EINTR_ATTEMPTS)
        self.assertEqual(waits, [])

    def test_write_eintr_exhausts_at_independent_bound_without_sleep(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)
        base = harness.operations()
        calls = 0
        waits: list[float] = []

        def pwrite(_descriptor: int, _data: bytes, _offset: int) -> int:
            nonlocal calls
            calls += 1
            raise InterruptedError(errno.EINTR, "interrupted")

        operations = replace(base, pwrite=pwrite, sleep=waits.append)
        context, whole, _partition = self.retry_context(harness, operations)
        with self.assertRaisesRegex(
            restore.HelperVerificationError,
            "Interrupted retained-target I/O failed after 1024 attempts",
        ):
            restore._write_exact(whole, b"x", 0, operations, context)

        self.assertEqual(calls, restore._IO_EINTR_ATTEMPTS)
        self.assertEqual(waits, [])

    def test_eintr_bound_resets_after_positive_read_progress(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)
        base = harness.operations()
        calls = 0
        phase_interruptions = 0
        waits: list[float] = []

        def pread(_descriptor: int, _size: int, _offset: int) -> bytes:
            nonlocal calls, phase_interruptions
            calls += 1
            if phase_interruptions < restore._IO_EINTR_ATTEMPTS - 1:
                phase_interruptions += 1
                raise InterruptedError(errno.EINTR, "interrupted")
            phase_interruptions = 0
            return b"a" if calls <= restore._IO_EINTR_ATTEMPTS else b"b"

        operations = replace(base, pread=pread, sleep=waits.append)
        context, whole, _partition = self.retry_context(harness, operations)
        self.assertEqual(
            restore._read_exact(whole, 2, 0, operations, context),
            b"ab",
        )

        self.assertEqual(calls, restore._IO_EINTR_ATTEMPTS * 2)
        self.assertEqual(waits, [])

    def test_fourth_eagain_exhausts_and_fatal_errnos_never_retry(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)
        base = harness.operations()

        calls = 0
        waits: list[float] = []

        def exhausted(_descriptor: int, _size: int, _offset: int) -> bytes:
            nonlocal calls
            calls += 1
            raise BlockingIOError(errno.EAGAIN, "again")

        operations = replace(base, pread=exhausted, sleep=waits.append)
        context, whole, _partition = self.retry_context(harness, operations)
        with self.assertRaisesRegex(restore.HelperVerificationError, "after 4 attempts"):
            restore._read_exact(whole, 1, 0, operations, context)
        self.assertEqual(calls, 4)
        self.assertEqual(restore._IO_RETRY_BACKOFF_SECONDS, (0.1, 0.5, 2.0))
        self.assertAlmostEqual(sum(waits), 0.1 + 0.5 + 2.0)

        for error_number in (
            errno.EIO,
            errno.EREMOTEIO,
            errno.ETIMEDOUT,
            errno.ENODEV,
            errno.ENXIO,
            errno.ESTALE,
            errno.EBUSY,
            errno.ENOSPC,
            errno.EROFS,
            errno.EACCES,
            errno.EPERM,
            errno.EINVAL,
            errno.EBADF,
        ):
            fatal_calls = 0

            def fatal(_descriptor: int, _data: bytes, _offset: int) -> int:
                nonlocal fatal_calls
                fatal_calls += 1
                raise OSError(error_number, "fatal")

            fatal_waits: list[float] = []
            fatal_operations = replace(base, pwrite=fatal, sleep=fatal_waits.append)
            fatal_context = replace(context, operations=fatal_operations)
            with self.subTest(error_number=error_number), self.assertRaises(
                restore.HelperError,
            ):
                restore._write_exact(
                    whole, b"x", 0, fatal_operations, fatal_context,
                )
            self.assertEqual(fatal_calls, 1)
            self.assertEqual(fatal_waits, [])

    def test_retry_rechecks_whole_identity_before_second_io(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)
        base = harness.operations()
        changed = False
        calls = 0

        def pread(_descriptor: int, _size: int, _offset: int) -> bytes:
            nonlocal calls, changed
            calls += 1
            changed = True
            raise BlockingIOError(errno.EAGAIN, "again")

        def ioctl_u64(descriptor: int, operation: int) -> int:
            if operation == BLKGETDISKSEQ and changed:
                return DISK_SEQUENCE + 1
            return harness.ioctl_u64(descriptor, operation)

        operations = replace(
            base,
            pread=pread,
            ioctl_u64=ioctl_u64,
            sleep=lambda _delay: None,
        )
        context, whole, _partition = self.retry_context(harness, operations)
        with self.assertRaisesRegex(
            restore.HelperVerificationError,
            "authorized disk generation",
        ):
            restore._read_exact(whole, 1, 0, operations, context)
        self.assertEqual(calls, 1)

    def test_retry_rechecks_whole_identity_again_after_backoff(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)
        base = harness.operations()
        changed_during_wait = False
        calls = 0

        def pread(_descriptor: int, _size: int, _offset: int) -> bytes:
            nonlocal calls
            calls += 1
            raise BlockingIOError(errno.EAGAIN, "again")

        def sleep(_delay: float) -> None:
            nonlocal changed_during_wait
            changed_during_wait = True

        def ioctl_u64(descriptor: int, operation: int) -> int:
            if operation == BLKGETDISKSEQ and changed_during_wait:
                return DISK_SEQUENCE + 1
            return harness.ioctl_u64(descriptor, operation)

        operations = replace(
            base,
            pread=pread,
            ioctl_u64=ioctl_u64,
            sleep=sleep,
        )
        context, whole, _partition = self.retry_context(harness, operations)
        with self.assertRaisesRegex(
            restore.HelperVerificationError,
            "authorized disk generation",
        ):
            restore._read_exact(whole, 1, 0, operations, context)
        self.assertTrue(changed_during_wait)
        self.assertEqual(calls, 1)

    def test_fat32_and_ntfs_receipt_reads_retry_parent_and_exact_child(self) -> None:
        for filesystem in (Filesystem.FAT32, Filesystem.NTFS):
            with self.subTest(filesystem=filesystem):
                harness = Harness(filesystem)
                self.addCleanup(harness.close)
                harness.partition_created = True
                harness.run_child(
                    (("/usr/sbin/mkfs.fat" if filesystem is Filesystem.FAT32 else "/usr/sbin/mkntfs"),),
                    None,
                    (),
                    1.0,
                )
                base = harness.operations()
                waits: list[float] = []
                failed_descriptors: set[int] = set()

                def pread(descriptor: int, size: int, offset: int) -> bytes:
                    if descriptor not in failed_descriptors:
                        failed_descriptors.add(descriptor)
                        raise BlockingIOError(errno.EAGAIN, "metadata not ready")
                    return os.pread(descriptor, size, offset)

                operations = replace(base, pread=pread, sleep=waits.append)
                context, whole, partition = self.retry_context(
                    harness, operations, child=True,
                )
                receipt = restore._post_format_receipt(
                    whole,
                    partition,
                    harness.request,
                    PARTITION_NUMBER,
                    operations,
                    context,
                )
                restore.validate_filesystem_receipt(harness.request, receipt)
                self.assertEqual(failed_descriptors, {whole, partition})
                self.assertAlmostEqual(sum(waits), 0.2)

    def test_child_geometry_change_blocks_metadata_retry(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)
        harness.partition_created = True
        base = harness.operations()
        calls = 0

        def pread(_descriptor: int, _size: int, _offset: int) -> bytes:
            nonlocal calls
            calls += 1
            raise BlockingIOError(errno.EAGAIN, "again")

        def changed_partition(parent: int, number: int) -> restore.PartitionObservation:
            return replace(
                harness.discover(parent, number),
                start_sector=harness.request.partition_start_sector + 1,
            )

        operations = replace(
            base,
            pread=pread,
            discover_partition=changed_partition,
            sleep=lambda _delay: None,
        )
        context, whole, partition = self.retry_context(harness, base, child=True)
        context = replace(context, operations=operations)
        with self.assertRaises(restore.HelperVerificationError):
            restore._partition_readback(
                whole, partition, harness.request, 0, SECTOR, operations, context,
            )
        self.assertEqual(calls, 1)

    def test_emergency_boundary_cleanup_retries_eagain_on_retained_whole_fd(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)
        base = harness.operations()
        failed = False
        injected = False
        calls: list[tuple[int, bytes, int]] = []
        waits: list[float] = []

        def run_child(*_args) -> restore.ChildResult:
            nonlocal failed
            failed = True
            raise restore.HelperError("injected partition failure")

        def pwrite(descriptor: int, data: bytes, offset: int) -> int:
            nonlocal injected
            if failed:
                calls.append((descriptor, data, offset))
                if not injected:
                    injected = True
                    raise BlockingIOError(errno.EAGAIN, "cleanup not ready")
            return os.pwrite(descriptor, data, offset)

        operations = replace(
            base,
            run_child=run_child,
            pwrite=pwrite,
            sleep=waits.append,
        )
        with self.assertRaisesRegex(restore.HelperError, "partition failure"):
            restore.execute_restore_device_transaction(
                harness.request,
                await_commit=lambda: True,
                operations=operations,
                require_root=False,
            )
        self.assertTrue(injected)
        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(calls[0], calls[1])
        self.assertAlmostEqual(sum(waits), 0.1)
        boundary = min(16 * 1024 * 1024, CAPACITY)
        self.assertEqual(
            os.pread(harness.target.fileno(), boundary, 0),
            b"\0" * boundary,
        )

    def test_cancel_before_commit_never_zeroes_or_dispatches_child(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)
        original = os.pread(harness.target.fileno(), 8192, 0)

        with self.assertRaises(restore.HelperCancelled):
            harness.execute(commit=False)

        self.assertEqual(os.pread(harness.target.fileno(), 8192, 0), original)
        self.assertEqual(harness.children, [])
        self.assertEqual(harness.prepared_calls, 1)

    def test_diskseq_drift_after_commit_refuses_mutation_and_cleanup(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)
        operations = harness.operations()
        calls = 0

        def diskseq(descriptor: int, operation: int) -> int:
            nonlocal calls
            if operation == BLKGETDISKSEQ:
                calls += 1
                return DISK_SEQUENCE if calls == 1 else DISK_SEQUENCE + 1
            return harness.ioctl_u64(descriptor, operation)

        with self.assertRaisesRegex(
            restore.HelperVerificationError,
            "emergency boundary cleanup was not verified",
        ):
            restore.execute_restore_device_transaction(
                harness.request,
                await_commit=lambda: True,
                operations=replace(operations, ioctl_u64=diskseq),
                require_root=False,
            )
        self.assertEqual(harness.children, [])
        self.assertNotEqual(os.pread(harness.target.fileno(), 8, 0), b"\0" * 8)

    def test_bad_partition_geometry_never_reaches_formatter_and_cleans_boundaries(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)
        original_discover = harness.discover

        def bad_discover(parent: int, number: int) -> restore.PartitionObservation:
            return replace(
                original_discover(parent, number),
                start_sector=harness.request.partition_start_sector + 1,
            )

        with self.assertRaises(restore.HelperVerificationError):
            restore.execute_restore_device_transaction(
                harness.request,
                await_commit=lambda: True,
                operations=replace(harness.operations(), discover_partition=bad_discover),
                require_root=False,
            )
        self.assertEqual([child[0][0] for child in harness.children], [
            "/usr/sbin/sfdisk", "/usr/bin/udevadm", "/usr/sbin/sfdisk",
        ])
        boundary = min(16 * 1024 * 1024, CAPACITY)
        self.assertEqual(os.pread(harness.target.fileno(), boundary, 0), b"\0" * boundary)

    def test_request_is_exactly_bound_and_only_exposes_fat32_ntfs(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)
        restore.validate_restore_device_request(harness.request)
        with self.assertRaises(restore.HelperTargetError):
            restore.validate_restore_device_request(replace(
                harness.request,
                expected_disk_sequence=0,
            ))
        with self.assertRaises(restore.HelperTargetError):
            restore.validate_restore_device_request(replace(
                harness.request,
                expected_major_minor="8:241",
            ))
        with self.assertRaises(restore.HelperTargetError):
            restore.build_restore_device_request(
                plan(Filesystem.EXT4),
                request_id=b"x" * 16,
                disk_sequence=DISK_SEQUENCE,
                logical_sector_size=SECTOR,
            )

    def test_ntfs_formatter_is_fixed_mkntfs_with_inherited_procfd(self) -> None:
        harness = Harness(Filesystem.NTFS, allocation_unit_size=4096)
        self.addCleanup(harness.close)
        result = harness.execute()
        mkfs = harness.children[-2]
        self.assertEqual(mkfs[0][0], "/usr/sbin/mkntfs")
        self.assertIn("-f", mkfs[0])
        self.assertIn("-s", mkfs[0])
        self.assertIn("-p", mkfs[0])
        self.assertIs(result.filesystem, restore.Filesystem.NTFS)
        self.assertEqual(result.filesystem_receipt.cluster_size, 4096)
        self.assertEqual(result.filesystem_receipt.normalized_label, "TEST")
        restore.validate_filesystem_receipt(harness.request, result.filesystem_receipt)
        self.assertEqual(result.partition.device_number, PARTITION_NUMBER)

    def test_post_format_metadata_must_match_parent_and_exact_child(self) -> None:
        harness = Harness()
        self.addCleanup(harness.close)

        def poison_parent(value: Harness) -> None:
            offset = value.request.partition_start_sector * SECTOR + 82
            os.pwrite(value.target.fileno(), b"NOTFAT32", offset)

        harness.metadata_mutator = poison_parent
        with self.assertRaisesRegex(
            restore.HelperVerificationError,
            "Parent and child descriptors disagree",
        ):
            harness.execute()
        self.assertEqual(harness.close_calls.count(next(iter(harness.target_fds))), 1)

    def test_malformed_ntfs_volume_record_is_rejected_and_boundaries_cleaned(self) -> None:
        harness = Harness(Filesystem.NTFS)
        self.addCleanup(harness.close)

        def poison_record(value: Harness) -> None:
            metadata = ntfs_metadata(value.request)
            record_offset = next(offset for offset in metadata if offset not in {
                0, (value.request.partition_sector_count - 1) * SECTOR,
            })
            os.pwrite(value.partition.fileno(), b"FAIL", record_offset)
            parent_offset = value.request.partition_start_sector * SECTOR + record_offset
            os.pwrite(value.target.fileno(), b"FAIL", parent_offset)

        harness.metadata_mutator = poison_record
        with self.assertRaisesRegex(
            restore.HelperVerificationError,
            "NTFS volume record",
        ):
            harness.execute()
        boundary = min(16 * 1024 * 1024, CAPACITY)
        self.assertEqual(os.pread(harness.target.fileno(), boundary, 0), b"\0" * boundary)

    def test_receipt_rejects_explicit_allocation_unit_forgery(self) -> None:
        harness = Harness(allocation_unit_size=4096)
        self.addCleanup(harness.close)
        result = harness.execute()
        receipt = replace(
            result.filesystem_receipt,
            sectors_per_cluster=1,
            cluster_size=SECTOR,
        )
        receipt = replace(
            receipt,
            receipt_sha256=restore._filesystem_receipt_digest(
                harness.request,
                receipt.filesystem,
                receipt.partition_major_minor,
                receipt.sectors_per_cluster,
                receipt.normalized_label,
                receipt.metadata_sha256,
            ),
        )
        with self.assertRaisesRegex(
            restore.HelperVerificationError,
            "receipt is inconsistent",
        ):
            restore.validate_filesystem_receipt(harness.request, receipt)

    def test_real_host_formatters_produce_accepted_descriptor_metadata(self) -> None:
        available = [
            (restore.Filesystem.FAT32, "/usr/sbin/mkfs.fat"),
            (restore.Filesystem.NTFS, "/usr/sbin/mkntfs"),
        ]
        available = [(filesystem, tool) for filesystem, tool in available if os.path.exists(tool)]
        if not available:
            self.skipTest("The fixed FAT32 and NTFS formatters are unavailable")
        parent_size = 65 * 1024 * 1024
        child_size = 64 * 1024 * 1024
        for filesystem, tool in available:
            with self.subTest(filesystem=filesystem.value), tempfile.TemporaryDirectory() as directory:
                parent_path = os.path.join(directory, "parent.img")
                child_path = os.path.join(directory, "child.img")
                with open(parent_path, "w+b") as parent, open(child_path, "w+b") as child:
                    parent.truncate(parent_size)
                    child.truncate(child_size)
                request = restore.build_restore_device_request(
                    restore.FormatPlan(
                        "/dev/sdz",
                        ("/dev/sdz", parent_size, "", "", "", "8:240"),
                        filesystem,
                        restore.PartitionTable.MBR,
                        "TEST",
                    ),
                    request_id=b"r" * 16,
                    disk_sequence=1,
                    logical_sector_size=SECTOR,
                )
                command = list(restore._formatter_argv(request, 9))
                command[-1] = child_path
                if filesystem is restore.Filesystem.NTFS:
                    command.insert(2, "-F")
                subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=True,
                    timeout=30,
                )
                with open(child_path, "rb") as source, open(parent_path, "r+b") as target:
                    target.seek(request.partition_start_sector * SECTOR)
                    while block := source.read(4 * 1024 * 1024):
                        target.write(block)
                parent_fd = os.open(parent_path, os.O_RDONLY)
                child_fd = os.open(child_path, os.O_RDONLY)
                try:
                    receipt = restore._post_format_receipt(
                        parent_fd,
                        child_fd,
                        request,
                        PARTITION_NUMBER,
                        restore.RestoreOperations(pread=os.pread),
                    )
                finally:
                    os.close(child_fd)
                    os.close(parent_fd)
                restore.validate_filesystem_receipt(request, receipt)
                self.assertEqual(receipt.normalized_label, "TEST")
                self.assertEqual(receipt.partition_major_minor, "8:241")


if __name__ == "__main__":
    unittest.main()
