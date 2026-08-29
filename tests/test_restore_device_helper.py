from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import fcntl
import json
import os
import stat
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


def plan(filesystem: Filesystem = Filesystem.FAT32) -> FormatPlan:
    return FormatPlan(
        "/dev/sdz",
        ("/dev/sdz", CAPACITY, "SERIAL", "", "Test USB", "8:240"),
        filesystem,
        PartitionTable.GPT,
        "TEST",
    )


class Harness:
    def __init__(self, filesystem: Filesystem = Filesystem.FAT32) -> None:
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
            plan(filesystem),
            request_id=bytes(range(16)),
            disk_sequence=DISK_SEQUENCE,
            logical_sector_size=SECTOR,
            chunk_size=1024 * 1024,
        )

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
        self.assertEqual(harness.target.seek(0), 0)
        self.assertEqual(harness.target.read(), b"\0" * CAPACITY)
        self.assertEqual(len(harness.lock_calls), 1)
        self.assertEqual(harness.lock_calls[0][1], fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertEqual(len(harness.children), 5)
        sfdisk, udevadm, metadata_before, mkfs, metadata_after = harness.children
        retained_fd = sfdisk[2][0]
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
        harness = Harness(Filesystem.NTFS)
        self.addCleanup(harness.close)
        result = harness.execute()
        mkfs = harness.children[-2]
        self.assertEqual(mkfs[0][0], "/usr/sbin/mkntfs")
        self.assertIn("-f", mkfs[0])
        self.assertEqual(result.partition.device_number, PARTITION_NUMBER)


if __name__ == "__main__":
    unittest.main()
