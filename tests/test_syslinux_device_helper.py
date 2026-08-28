from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import array
import errno
import fcntl
import hashlib
import os
import socket
import stat
import struct
import tempfile
import unittest
from functools import lru_cache
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import isopropyl.syslinux_device_helper as helper
from isopropyl.syslinux_device_helper import (
    BLKFLSBUF,
    BLKGETDISKSEQ,
    BLKGETSIZE64,
    BLKROGET,
    BLKSSZGET,
    HELPER_PROFILE,
    HelperError,
    HelperOperations,
    HelperRequest,
    HelperRequestError,
    HelperSourceError,
    HelperTargetError,
    HelperVerificationError,
    KernelTargetObservation,
    active_kernel_devices,
    execute_helper_transaction,
    inspect_kernel_target,
    pack_helper_request,
    unpack_helper_request,
    unpack_server_packet,
)
from isopropyl.syslinux import SYSLINUX_MBR_602


IMAGE_SIZE = 34 * 1024 * 1024
DISK_SIGNATURE = 0x12345678
VOLUME_ID = 0x87654321
DEVICE_NUMBER = os.makedev(8, 240)
DISK_SEQUENCE = 4242
REQUEST_ID = bytes(range(16))


@lru_cache(maxsize=2)
def synthetic_syslinux_image(size: int = IMAGE_SIZE) -> bytes:
    volume_offset = 2_048 * 512
    partition_sectors = (size - volume_offset) // 512
    if size != IMAGE_SIZE:
        raise ValueError("The synthetic canonical FAT32 fixture has one fixed geometry")
    sectors_per_fat = 520
    cluster_count = 66_512
    image = bytearray(size)
    mbr = memoryview(image)[:512]
    mbr[:440] = SYSLINUX_MBR_602
    struct.pack_into("<I", mbr, 440, DISK_SIGNATURE)
    mbr[446:454] = b"\x80\x20\x21\x00\x0c\xfe\xff\xff"
    struct.pack_into("<I", mbr, 454, 2_048)
    struct.pack_into("<I", mbr, 458, partition_sectors)
    mbr[510:512] = b"\x55\xaa"

    def boot_sector(offset: int) -> None:
        boot = memoryview(image)[offset:offset + 512]
        boot[:11] = b"\xeb\x58\x90SYSLINUX"
        struct.pack_into("<H", boot, 11, 512)
        boot[13] = 1
        struct.pack_into("<H", boot, 14, 32)
        boot[16] = 2
        boot[21] = 0xF8
        struct.pack_into("<H", boot, 24, 63)
        struct.pack_into("<H", boot, 26, 255)
        struct.pack_into("<I", boot, 28, 2_048)
        struct.pack_into("<I", boot, 32, partition_sectors)
        struct.pack_into("<I", boot, 36, sectors_per_fat)
        struct.pack_into("<I", boot, 44, 2)
        struct.pack_into("<H", boot, 48, 1)
        struct.pack_into("<H", boot, 50, 6)
        boot[64] = 0x80
        boot[66] = 0x29
        struct.pack_into("<I", boot, 67, VOLUME_ID)
        boot[71:82] = b"ISOPROPYL  "
        boot[82:90] = b"FAT32   "
        boot[90:510] = bytes((index * 17 + 3) & 0xFF for index in range(420))
        struct.pack_into("<I", boot, helper.SYSLINUX_SECTOR1_LOW_OFFSET, 1_072)
        struct.pack_into("<I", boot, helper.SYSLINUX_SECTOR1_HIGH_OFFSET, 0)
        boot[510:512] = b"\x55\xaa"

    boot_sector(volume_offset)
    boot_sector(volume_offset + 6 * 512)
    def fsinfo_sector(offset: int) -> None:
        fsinfo = memoryview(image)[offset:offset + 512]
        struct.pack_into("<I", fsinfo, 0, 0x41615252)
        struct.pack_into("<I", fsinfo, 484, 0x61417272)
        struct.pack_into("<I", fsinfo, 488, cluster_count - 2)
        struct.pack_into("<I", fsinfo, 492, 4)
        struct.pack_into("<I", fsinfo, 508, 0xAA550000)

    fsinfo_sector(volume_offset + 512)
    fsinfo_sector(volume_offset + 7 * 512)
    # Give the read/write loops nontrivial content outside the metadata.
    image[-512:] = bytes(range(256)) * 2
    return bytes(image)


def request_for(image: bytes) -> HelperRequest:
    return HelperRequest(
        REQUEST_ID,
        HELPER_PROFILE,
        "/dev/sdz",
        "8:240",
        DISK_SEQUENCE,
        len(image),
        512,
        DISK_SIGNATURE,
        VOLUME_ID,
        hashlib.sha256(image).hexdigest(),
    )


def fake_block_status(device_number: int = DEVICE_NUMBER) -> SimpleNamespace:
    return SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=device_number)


class TransactionHarness:
    def __init__(self, image: bytes) -> None:
        self.image = image
        self.source = tempfile.TemporaryFile()
        os.fchmod(self.source.fileno(), 0o600)
        self.source.write(image)
        self.source.flush()
        self.target = tempfile.TemporaryFile()
        self.target.write(b"\xa5" * len(image))
        self.target.flush()
        self.target_fds: set[int] = set()
        self.open_flags: list[int] = []
        self.write_calls: list[tuple[int, bytes, int]] = []
        self.fsync_calls: list[int] = []
        self.flush_calls: list[int] = []
        self.close_calls: list[int] = []
        self.progress: list[tuple[str, int, int]] = []
        self.mutation_calls = 0
        self.observation = KernelTargetObservation(
            DEVICE_NUMBER,
            frozenset({DEVICE_NUMBER, os.makedev(8, 241)}),
            "usb",
            True,
            False,
            512,
            False,
            DISK_SEQUENCE,
        )
        self.active = frozenset()

    def close(self) -> None:
        self.source.close()
        self.target.close()

    def open_target(self, path: str, flags: int) -> int:
        if path != "/dev/sdz":
            raise AssertionError(path)
        self.open_flags.append(flags)
        descriptor = os.dup(self.target.fileno())
        self.target_fds.add(descriptor)
        return descriptor

    def fstat(self, descriptor: int):
        if descriptor in self.target_fds:
            return fake_block_status()
        return os.fstat(descriptor)

    def pwrite(self, descriptor: int, data: bytes, offset: int) -> int:
        self.write_calls.append((descriptor, bytes(data), offset))
        return os.pwrite(descriptor, data, offset)

    def fsync(self, descriptor: int) -> None:
        self.fsync_calls.append(descriptor)
        os.fsync(descriptor)

    def ioctl_uint(self, descriptor: int, operation: int) -> int:
        self.assert_target(descriptor)
        if operation == BLKSSZGET:
            return 512
        if operation == BLKROGET:
            return 0
        raise AssertionError(operation)

    def ioctl_u64(self, descriptor: int, operation: int) -> int:
        self.assert_target(descriptor)
        if operation == BLKGETSIZE64:
            return len(self.image)
        if operation == BLKGETDISKSEQ:
            return DISK_SEQUENCE
        raise AssertionError(operation)

    def ioctl_void(self, descriptor: int, operation: int) -> None:
        self.assert_target(descriptor)
        if operation != BLKFLSBUF:
            raise AssertionError(operation)
        self.flush_calls.append(descriptor)

    def close_fd(self, descriptor: int) -> None:
        self.close_calls.append(descriptor)
        os.close(descriptor)

    def assert_target(self, descriptor: int) -> None:
        if descriptor not in self.target_fds:
            raise AssertionError(f"not target fd {descriptor}")

    def operations(self, **overrides) -> HelperOperations:
        values = dict(
            lstat=lambda _path: fake_block_status(),
            stat=os.stat,
            fstat=self.fstat,
            open=self.open_target,
            close=self.close_fd,
            pread=os.pread,
            pwrite=self.pwrite,
            fsync=self.fsync,
            flock=fcntl.flock,
            get_flags=lambda fd: fcntl.fcntl(fd, fcntl.F_GETFL),
            ioctl_uint=self.ioctl_uint,
            ioctl_u64=self.ioctl_u64,
            ioctl_void=self.ioctl_void,
            inspect_target=lambda _dev: self.observation,
            active_devices=lambda: self.active,
        )
        values.update(overrides)
        return HelperOperations(**values)

    def execute(self, **overrides):
        operations = overrides.pop("operations", self.operations())
        mutation_started = overrides.pop("mutation_started", self._mutation_started)
        return execute_helper_transaction(
            overrides.pop("request", request_for(self.image)),
            source_descriptor=self.source.fileno(),
            invoking_uid=os.getuid(),
            operations=operations,
            progress=lambda phase, done, total: self.progress.append(
                (phase, done, total),
            ),
            mutation_started=mutation_started,
            **overrides,
        )

    def _mutation_started(self) -> None:
        self.mutation_calls += 1


class HelperTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.image = synthetic_syslinux_image()
        vbr = self.image[2_048 * 512:(2_048 + 1) * 512]
        accepted = helper.SYSLINUX_VBR_MASKED_SHA256 | {
            helper._masked_syslinux_vbr_sha256(vbr),
        }
        self.vbr_profiles = patch.object(
            helper,
            "SYSLINUX_VBR_MASKED_SHA256",
            frozenset(accepted),
        )
        self.vbr_profiles.start()
        self.harness = TransactionHarness(self.image)

    def tearDown(self) -> None:
        self.harness.close()
        self.vbr_profiles.stop()

    def test_noncanonical_fat32_geometry_and_vbr_fail_before_target_open(self):
        too_small = replace(request_for(self.image), expected_size=2 * 1024 * 1024)
        with self.assertRaisesRegex(HelperSourceError, "canonical FAT32 geometry"):
            helper._validate_syslinux_image_layout(
                self.harness.source.fileno(),
                too_small,
                read_at=os.pread,
            )

        volume_offset = 2_048 * 512
        mutations = (
            (volume_offset + 13, b"\x08", "boot sector"),
            (volume_offset + 36, struct.pack("<I", 519), "boot sector"),
            (volume_offset + 100, b"X", "pinned Syslinux"),
            (volume_offset + 7 * 512 + 492, struct.pack("<I", 9), "allocation metadata"),
        )
        for offset, value, message in mutations:
            source = tempfile.TemporaryFile()
            try:
                os.fchmod(source.fileno(), 0o600)
                source.write(self.image)
                os.pwrite(source.fileno(), value, offset)
                if message == "pinned Syslinux":
                    os.pwrite(source.fileno(), value, offset + 6 * 512)
                with self.subTest(offset=offset), self.assertRaisesRegex(
                    HelperSourceError,
                    message,
                ):
                    helper._validate_syslinux_image_layout(
                        source.fileno(),
                        request_for(os.pread(source.fileno(), len(self.image), 0)),
                        read_at=os.pread,
                    )
            finally:
                source.close()

    def test_same_descriptor_exclusive_sector_zero_last_and_full_readback(self):
        result = self.harness.execute()
        self.assertEqual(result.source_sha256, hashlib.sha256(self.image).hexdigest())
        self.assertEqual(result.written_sha256, result.source_sha256)
        self.assertEqual(result.readback_sha256, result.source_sha256)
        self.assertTrue(result.exclusive_open)
        self.assertTrue(result.cache_invalidated)
        self.assertEqual(self.harness.mutation_calls, 1)
        self.assertEqual(len(self.harness.open_flags), 1)
        flags = self.harness.open_flags[0]
        self.assertTrue(flags & os.O_EXCL)
        self.assertTrue(flags & os.O_NOFOLLOW)
        target_fds = {call[0] for call in self.harness.write_calls}
        self.assertEqual(len(target_fds), 1)
        self.assertEqual(target_fds, set(self.harness.fsync_calls))
        self.assertEqual(target_fds, set(self.harness.flush_calls))
        self.assertEqual(target_fds, set(self.harness.close_calls))
        first = self.harness.write_calls[0]
        last = self.harness.write_calls[-1]
        self.assertEqual(
            (first[2], first[1]),
            (0, b"\0" * 1_024),
        )
        self.assertEqual(
            (
                self.harness.write_calls[1][2],
                self.harness.write_calls[1][1],
            ),
            (len(self.image) - 512, b"\0" * 512),
        )
        self.assertEqual((last[2], last[1]), (0, self.image[:512]))
        self.assertTrue(all(
            offset >= 512 or (offset == 0 and not any(data))
            for _, data, offset in self.harness.write_calls[:-1]
        ))
        self.assertEqual(os.pread(self.harness.target.fileno(), len(self.image), 0), self.image)
        phases = {item[0] for item in self.harness.progress}
        self.assertEqual(
            phases,
            {"source-validation", "writing", "preactivation-readback", "readback"},
        )

    def test_short_io_and_eintr_are_retried_exactly(self):
        read_interrupts = {0: 1, 512: 1}

        def short_pread(fd: int, count: int, offset: int) -> bytes:
            if read_interrupts.get(offset, 0):
                read_interrupts[offset] -= 1
                raise InterruptedError()
            return os.pread(fd, min(count, 997), offset)

        interrupted = True

        def short_pwrite(fd: int, data: bytes, offset: int) -> int:
            nonlocal interrupted
            if interrupted and offset >= 512:
                interrupted = False
                raise InterruptedError()
            self.harness.write_calls.append((fd, bytes(data[:713]), offset))
            return os.pwrite(fd, data[:713], offset)

        operations = self.harness.operations(pread=short_pread, pwrite=short_pwrite)
        result = self.harness.execute(operations=operations)
        self.assertEqual(result.readback_sha256, hashlib.sha256(self.image).hexdigest())
        self.assertFalse(interrupted)

    def test_all_source_failures_happen_before_target_open(self):
        candidates = (
            replace(request_for(self.image), expected_sha256="00" * 32),
            replace(request_for(self.image), expected_size=len(self.image) + 512),
            replace(request_for(self.image), expected_disk_signature=9),
            replace(request_for(self.image), expected_volume_id=9),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                self.harness.open_flags.clear()
                with self.assertRaises((HelperRequestError, HelperSourceError)):
                    self.harness.execute(request=candidate)
                self.assertEqual(self.harness.open_flags, [])

    def test_linked_or_wrong_mode_source_is_rejected_before_open(self):
        source_status = os.fstat(self.harness.source.fileno())
        for changes in ({"st_nlink": 1}, {"st_mode": stat.S_IFREG | 0o640}, {"st_uid": os.getuid() + 1}):
            fake = SimpleNamespace(**{
                name: getattr(source_status, name)
                for name in (
                    "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
                    "st_size", "st_mtime_ns", "st_ctime_ns",
                )
            })
            for name, value in changes.items():
                setattr(fake, name, value)
            operations = self.harness.operations(
                fstat=lambda fd, fake=fake: (
                    fake if fd == self.harness.source.fileno() else fake_block_status()
                ),
            )
            with self.subTest(changes=changes), self.assertRaises(HelperSourceError):
                self.harness.execute(operations=operations)
            self.assertEqual(self.harness.open_flags, [])

    def test_active_resident_internal_partition_and_read_only_targets_fail_prewrite(self):
        bad = (
            replace(self.harness.observation, related_device_numbers=frozenset({DEVICE_NUMBER, os.fstat(self.harness.source.fileno()).st_dev})),
            replace(self.harness.observation, transport=""),
            replace(self.harness.observation, transport="mmc", removable=False),
            replace(self.harness.observation, read_only=True),
            replace(self.harness.observation, logical_sector_size=4096),
            replace(self.harness.observation, has_holders=True),
        )
        for observation in bad:
            with self.subTest(observation=observation):
                self.harness.observation = observation
                self.harness.open_flags.clear()
                with self.assertRaises(HelperTargetError):
                    self.harness.execute()
                self.assertEqual(self.harness.open_flags, [])
        self.harness.observation = replace(bad[0], related_device_numbers=frozenset({DEVICE_NUMBER}))
        self.harness.active = frozenset({DEVICE_NUMBER})
        with self.assertRaises(HelperTargetError):
            self.harness.execute()

    def test_exclusive_open_busy_and_geometry_fail_before_any_write(self):
        def busy(_path: str, _flags: int) -> int:
            raise OSError(errno.EBUSY, "busy")

        with self.assertRaisesRegex(HelperTargetError, "busy"):
            self.harness.execute(operations=self.harness.operations(open=busy))
        self.assertEqual(self.harness.write_calls, [])

        operations = self.harness.operations(ioctl_u64=lambda _fd, _op: len(self.image) + 512)
        with self.assertRaisesRegex(HelperTargetError, "capacity"):
            self.harness.execute(operations=operations)
        self.assertEqual(self.harness.write_calls, [])

    def test_same_dev_t_and_capacity_with_replacement_diskseq_fail_prewrite(self):
        self.harness.observation = replace(
            self.harness.observation,
            disk_sequence=DISK_SEQUENCE + 1,
        )
        with self.assertRaisesRegex(HelperTargetError, "safety properties"):
            self.harness.execute()
        self.assertEqual(self.harness.open_flags, [])
        self.assertEqual(self.harness.write_calls, [])

        self.harness.observation = replace(
            self.harness.observation,
            disk_sequence=DISK_SEQUENCE,
        )

        def replacement_ioctl(_fd: int, operation: int) -> int:
            if operation == BLKGETSIZE64:
                return len(self.image)
            if operation == BLKGETDISKSEQ:
                return DISK_SEQUENCE + 1
            raise AssertionError(operation)

        with self.assertRaisesRegex(HelperTargetError, "authorized disk generation"):
            self.harness.execute(
                operations=self.harness.operations(ioctl_u64=replacement_ioctl),
            )
        self.assertEqual(self.harness.write_calls, [])

    def test_preactivation_corruption_leaves_zero_mbr(self):
        calls = 0

        def corrupt_after_flush(fd: int, operation: int) -> None:
            nonlocal calls
            self.harness.ioctl_void(fd, operation)
            calls += 1
            if calls == 1:
                os.pwrite(fd, b"X", len(self.image) - 1)

        operations = self.harness.operations(ioctl_void=corrupt_after_flush)
        with self.assertRaisesRegex(HelperVerificationError, "before MBR activation"):
            self.harness.execute(operations=operations)
        self.assertEqual(os.pread(self.harness.target.fileno(), 512, 0), b"\0" * 512)
        self.assertEqual(self.harness.mutation_calls, 1)

    def test_backup_header_failure_follows_durable_primary_deactivation(self):
        def fail_tail(fd: int, data: bytes, offset: int) -> int:
            if offset >= 512 and data and not any(data):
                self.assertTrue(self.harness.fsync_calls)
                raise OSError(errno.EIO, "injected tail clear failure")
            return self.harness.pwrite(fd, data, offset)

        with self.assertRaisesRegex(HelperError, "injected tail clear failure"):
            self.harness.execute(
                operations=self.harness.operations(pwrite=fail_tail),
            )
        self.assertEqual(
            os.pread(self.harness.target.fileno(), 512, 0),
            b"\0" * 512,
        )

    def test_final_readback_corruption_is_fatal(self):
        calls = 0

        def corrupt_after_activation(fd: int, operation: int) -> None:
            nonlocal calls
            self.harness.ioctl_void(fd, operation)
            calls += 1
            if calls == 2:
                os.pwrite(fd, b"X", len(self.image) - 1)

        with self.assertRaisesRegex(HelperVerificationError, "read-back"):
            self.harness.execute(
                operations=self.harness.operations(ioctl_void=corrupt_after_activation),
            )
        self.assertEqual(os.pread(self.harness.target.fileno(), 512, 0), b"\0" * 512)

    def test_diskseq_change_after_readback_cannot_produce_success(self):
        diskseq_reads = 0

        def changing_diskseq(_fd: int, operation: int) -> int:
            nonlocal diskseq_reads
            if operation == BLKGETSIZE64:
                return len(self.image)
            if operation == BLKGETDISKSEQ:
                diskseq_reads += 1
                return DISK_SEQUENCE if diskseq_reads <= 3 else DISK_SEQUENCE + 1
            raise AssertionError(operation)

        with self.assertRaisesRegex(
            HelperVerificationError,
            "identity or geometry.*deactivation was skipped",
        ):
            self.harness.execute(
                operations=self.harness.operations(ioctl_u64=changing_diskseq),
            )
        self.assertEqual(diskseq_reads, 5)
        self.assertEqual(
            os.pread(self.harness.target.fileno(), 512, 0),
            self.image[:512],
        )

    def test_diskseq_change_during_commit_lease_fails_before_first_write(self):
        diskseq_reads = 0

        def changing_diskseq(_fd: int, operation: int) -> int:
            nonlocal diskseq_reads
            if operation == BLKGETSIZE64:
                return len(self.image)
            if operation == BLKGETDISKSEQ:
                diskseq_reads += 1
                return DISK_SEQUENCE if diskseq_reads == 1 else DISK_SEQUENCE + 1
            raise AssertionError(operation)

        with self.assertRaisesRegex(HelperTargetError, "authorized disk generation"):
            self.harness.execute(
                operations=self.harness.operations(ioctl_u64=changing_diskseq),
            )
        self.assertEqual(self.harness.write_calls, [])

    def test_source_change_during_commit_lease_fails_before_first_write(self):
        def mutate_source() -> None:
            self.harness._mutation_started()
            os.pwrite(self.harness.source.fileno(), b"X", len(self.image) - 1)

        with self.assertRaisesRegex(HelperSourceError, "commit lease"):
            self.harness.execute(mutation_started=mutate_source)
        self.assertEqual(self.harness.write_calls, [])

    def test_postactivation_error_reports_emergency_deactivation_failure(self):
        flushes = 0
        zero_writes = 0

        def corrupt_after_activation(fd: int, operation: int) -> None:
            nonlocal flushes
            self.harness.ioctl_void(fd, operation)
            flushes += 1
            if flushes == 2:
                os.pwrite(fd, b"X", len(self.image) - 1)

        def fail_second_zero(fd: int, data: bytes, offset: int) -> int:
            nonlocal zero_writes
            if offset == 0 and data and not any(data):
                zero_writes += 1
                if zero_writes == 2:
                    raise OSError(errno.EIO, "injected deactivation failure")
            return self.harness.pwrite(fd, data, offset)

        operations = self.harness.operations(
            ioctl_void=corrupt_after_activation,
            pwrite=fail_second_zero,
        )
        with self.assertRaisesRegex(
            HelperVerificationError,
            "read-back.*emergency MBR deactivation also failed.*injected",
        ):
            self.harness.execute(operations=operations)

    def test_zero_or_oversized_write_progress_is_rejected_and_closed(self):
        for value in (0, -1, 10_000_000, None):
            with self.subTest(value=value):
                self.harness.write_calls.clear()
                operations = self.harness.operations(pwrite=lambda _fd, _data, _offset, value=value: value)
                with self.assertRaisesRegex(HelperError, "invalid progress"):
                    self.harness.execute(operations=operations)
                self.assertTrue(self.harness.close_calls)

    def test_source_identity_change_before_write_never_mutates_target(self):
        original = os.fstat(self.harness.source.fileno())
        calls = 0

        def changed_fstat(fd: int):
            nonlocal calls
            if fd in self.harness.target_fds:
                return fake_block_status()
            calls += 1
            if calls >= 3:
                return SimpleNamespace(**{
                    name: getattr(original, name) + (1 if name == "st_ctime_ns" else 0)
                    for name in (
                        "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
                        "st_size", "st_mtime_ns", "st_ctime_ns",
                    )
                })
            return original

        operations = self.harness.operations(fstat=changed_fstat)
        with self.assertRaisesRegex(HelperSourceError, "before writing"):
            self.harness.execute(operations=operations)
        self.assertEqual(self.harness.write_calls, [])
        self.assertEqual(self.harness.mutation_calls, 0)

    def test_late_source_mutation_is_detected_before_mbr_activation(self):
        mutated = False

        def mutate_after_copy(fd: int, data: bytes, offset: int) -> int:
            nonlocal mutated
            count = self.harness.pwrite(fd, data, offset)
            if offset >= 512 and not mutated:
                os.pwrite(self.harness.source.fileno(), b"X", 1_024)
                mutated = True
            return count

        operations = self.harness.operations(pwrite=mutate_after_copy)
        with self.assertRaisesRegex(HelperSourceError, "changed while"):
            self.harness.execute(operations=operations)
        self.assertTrue(mutated)
        self.assertEqual(os.pread(self.harness.target.fileno(), 512, 0), b"\0" * 512)


class ProtocolTests(unittest.TestCase):
    def test_request_is_fixed_binary_and_target_path_comes_from_kernel(self):
        with tempfile.TemporaryDirectory() as directory:
            sys_root = Path(directory)
            block = sys_root / "dev" / "block" / "8:240"
            block.mkdir(parents=True)
            (block / "uevent").write_text("MAJOR=8\nMINOR=240\nDEVNAME=sdz\n", encoding="ascii")
            packet = pack_helper_request(
                REQUEST_ID,
                8,
                240,
                DISK_SEQUENCE,
                IMAGE_SIZE,
                512,
                DISK_SIGNATURE,
                VOLUME_ID,
                "ab" * 32,
            )
            request = unpack_helper_request(packet, sys_root=sys_root)
            self.assertEqual(request.request_id, REQUEST_ID)
            self.assertEqual(request.target_path, "/dev/sdz")
            self.assertEqual(request.expected_major_minor, "8:240")
            self.assertEqual(request.expected_sha256, "ab" * 32)
            self.assertNotIn(b"/dev/", packet)

    def test_protocol_rejects_every_shape_or_header_change(self):
        packet = pack_helper_request(
            REQUEST_ID, 8, 240, DISK_SEQUENCE, IMAGE_SIZE, 512,
            DISK_SIGNATURE, VOLUME_ID, "ab" * 32,
        )
        for candidate in (
            packet[:-1],
            packet + b"x",
            b"X" + packet[1:],
            packet[:16] + b"\x02" + packet[17:],
            packet[:17] + b"\xff" + packet[18:],
            packet[:18] + b"\x00\x01" + packet[20:],
        ):
            with self.subTest(length=len(candidate)), self.assertRaises(HelperRequestError):
                unpack_helper_request(candidate)

    def test_server_packets_are_exact_and_request_bound(self):
        ready = helper._HEADER.pack(
            helper.PROTOCOL_MAGIC,
            helper.PROTOCOL_VERSION,
            helper.PACKET_READY,
            0,
        )
        self.assertEqual(unpack_server_packet(ready), ("ready",))
        progress = helper._PROGRESS_PACKET.pack(
            helper.PROTOCOL_MAGIC,
            helper.PROTOCOL_VERSION,
            helper.PACKET_PROGRESS,
            0,
            REQUEST_ID,
            helper.PHASE_CODES["writing"],
            10,
            20,
        )
        self.assertEqual(
            unpack_server_packet(progress),
            ("progress", REQUEST_ID, "writing", 10, 20),
        )
        with self.assertRaises(HelperRequestError):
            unpack_server_packet(progress + b"x")

        prepared = helper._CONTROL_PACKET.pack(
            helper.PROTOCOL_MAGIC,
            helper.PROTOCOL_VERSION,
            helper.PACKET_PREPARED,
            0,
            REQUEST_ID,
        )
        mutation = helper._MUTATION_PACKET.pack(
            helper.PROTOCOL_MAGIC,
            helper.PROTOCOL_VERSION,
            helper.PACKET_MUTATION_STARTED,
            0,
            REQUEST_ID,
        )
        self.assertEqual(unpack_server_packet(prepared), ("prepared", REQUEST_ID))
        self.assertEqual(
            unpack_server_packet(mutation),
            ("mutation-started", REQUEST_ID),
        )

    def test_authenticated_commit_cancel_and_bounded_lease(self):
        for commit in (False, True):
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                parent.send(helper.pack_helper_control(REQUEST_ID, commit=commit))
                self.assertIs(
                    helper._receive_control(
                        child,
                        expected_uid=os.getuid(),
                        request_id=REQUEST_ID,
                    ),
                    commit,
                )
            finally:
                parent.close()
                child.close()

        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            with patch.object(
                helper.select,
                "select",
                return_value=([], [], []),
            ), self.assertRaisesRegex(HelperRequestError, "timed out"):
                helper._receive_control(
                    child,
                    expected_uid=os.getuid(),
                    request_id=REQUEST_ID,
                )
        finally:
            parent.close()
            child.close()

    def test_progress_disconnect_aborts_before_commit_and_detaches_after(self):
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        progress = helper._ProtocolProgress(parent, REQUEST_ID, os.getuid())
        child.close()
        try:
            with self.assertRaises(HelperError):
                progress("source-validation", 0, IMAGE_SIZE)
        finally:
            parent.close()

        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        progress = helper._ProtocolProgress(parent, REQUEST_ID, os.getuid())
        try:
            progress.begin_mutation()
            child.recv(helper.MAX_PROTOCOL_PACKET)
            child.close()
            progress("writing", 0, IMAGE_SIZE)
            progress("writing", 512, IMAGE_SIZE)
        finally:
            parent.close()
            try:
                child.close()
            except OSError:
                pass

    def test_request_receiver_requires_one_fd_and_matching_kernel_credentials(self):
        packet = pack_helper_request(
            REQUEST_ID, 8, 240, DISK_SEQUENCE, IMAGE_SIZE, 512,
            DISK_SIGNATURE, VOLUME_ID, "ab" * 32,
        )
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            with tempfile.TemporaryFile() as source:
                rights = array.array("i", [source.fileno()])
                parent.sendmsg(
                    [packet],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                )
                observed, descriptor = helper._receive_request(
                    child,
                    expected_uid=os.getuid(),
                )
                try:
                    self.assertEqual(observed, packet)
                    self.assertFalse(os.get_inheritable(descriptor))
                    self.assertEqual(os.fstat(descriptor).st_ino, os.fstat(source.fileno()).st_ino)
                finally:
                    os.close(descriptor)
        finally:
            parent.close()
            child.close()

    def test_request_receiver_rejects_multiple_fds_and_uid_mismatch(self):
        packet = pack_helper_request(
            REQUEST_ID, 8, 240, DISK_SEQUENCE, IMAGE_SIZE, 512,
            DISK_SIGNATURE, VOLUME_ID, "ab" * 32,
        )
        for mismatch_uid, descriptor_count in ((False, 2), (True, 1)):
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                with tempfile.TemporaryFile() as first, tempfile.TemporaryFile() as second:
                    values = [first.fileno(), second.fileno()][:descriptor_count]
                    parent.sendmsg(
                        [packet],
                        [(
                            socket.SOL_SOCKET,
                            socket.SCM_RIGHTS,
                            array.array("i", values),
                        )],
                    )
                    expected_uid = os.getuid() + 1 if mismatch_uid else os.getuid()
                    with self.subTest(
                        mismatch_uid=mismatch_uid,
                        descriptor_count=descriptor_count,
                    ), self.assertRaises(HelperRequestError):
                        helper._receive_request(child, expected_uid=expected_uid)
            finally:
                parent.close()
                child.close()


class KernelInspectionTests(unittest.TestCase):
    def _sysfs(self, root: Path, *, transport: str = "usb", partition: bool = False) -> Path:
        devices = root / "devices"
        bus = root / "bus" / transport
        bus.mkdir(parents=True)
        ancestor = devices / "pci0000:00" / "transport"
        node = ancestor / "block" / "sdz"
        (node / "queue").mkdir(parents=True)
        (ancestor / "subsystem").symlink_to(bus)
        (node / "dev").write_text("8:240\n", encoding="ascii")
        (node / "removable").write_text("1\n", encoding="ascii")
        (node / "ro").write_text("0\n", encoding="ascii")
        (node / "diskseq").write_text(f"{DISK_SEQUENCE}\n", encoding="ascii")
        (node / "queue" / "logical_block_size").write_text("512\n", encoding="ascii")
        (node / "uevent").write_text("DEVNAME=sdz\n", encoding="ascii")
        if partition:
            (node / "partition").write_text("1\n", encoding="ascii")
        child = node / "sdz1"
        child.mkdir()
        (child / "partition").write_text("1\n", encoding="ascii")
        (child / "dev").write_text("8:241\n", encoding="ascii")
        link = root / "dev" / "block" / "8:240"
        link.parent.mkdir(parents=True)
        link.symlink_to(node)
        return node

    def test_sysfs_proves_whole_usb_disk_and_recurses_partitions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._sysfs(root)
            observed = inspect_kernel_target(DEVICE_NUMBER, sys_root=root)
            self.assertEqual(observed.transport, "usb")
            self.assertTrue(observed.removable)
            self.assertEqual(
                observed.related_device_numbers,
                frozenset({DEVICE_NUMBER, os.makedev(8, 241)}),
            )

    def test_partition_or_non_usb_mmc_target_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._sysfs(root, partition=True)
            with self.assertRaisesRegex(HelperTargetError, "whole disk"):
                inspect_kernel_target(DEVICE_NUMBER, sys_root=root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = self._sysfs(root, transport="scsi")
            with self.assertRaisesRegex(HelperTargetError, "USB or SD/MMC"):
                inspect_kernel_target(DEVICE_NUMBER, sys_root=root)
            (node / "removable").write_text("0\n", encoding="ascii")

    def test_mounts_and_swap_are_derived_from_proc(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "self").mkdir()
            (proc / "self" / "mountinfo").write_text(
                "36 25 8:241 / /media/usb rw - vfat /dev/sdz1 rw\n",
                encoding="utf-8",
            )
            (proc / "swaps").write_text(
                "Filename\tType\tSize\tUsed\tPriority\n/dev/sdy2 partition 1 0 -2\n",
                encoding="utf-8",
            )
            found = active_kernel_devices(
                proc_root=proc,
                stat_func=lambda _path: fake_block_status(os.makedev(8, 226)),
            )
            self.assertEqual(found, frozenset({os.makedev(8, 241), os.makedev(8, 226)}))

    def test_swapfile_backing_device_is_treated_as_active(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "self").mkdir()
            (proc / "self" / "mountinfo").write_text(
                "36 25 0:29 / / rw - tmpfs tmpfs rw\n",
                encoding="utf-8",
            )
            (proc / "swaps").write_text(
                "Filename\tType\tSize\tUsed\tPriority\n/swapfile file 1 0 -2\n",
                encoding="utf-8",
            )
            backing = os.makedev(8, 241)
            found = active_kernel_devices(
                proc_root=proc,
                stat_func=lambda _path: SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o600,
                    st_dev=backing,
                ),
            )
            self.assertEqual(found, frozenset({os.makedev(0, 29), backing}))


if __name__ == "__main__":
    unittest.main()
