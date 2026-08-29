from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import fcntl
import hashlib
import os
import socket
import stat
import struct
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from functools import lru_cache
from types import SimpleNamespace
from unittest.mock import patch

import isopropyl.syslinux_device_helper as helper


IMAGE_SIZE = 34 * 1024 * 1024
DISK_SIGNATURE = 0x12345678
VOLUME_ID = 0x87654321
DEVICE_NUMBER = os.makedev(8, 240)
DISK_SEQUENCE = 4242
REQUEST_ID = bytes(range(16))


@lru_cache(maxsize=1)
def synthetic_grub_image() -> tuple[bytes, str, str]:
    image = bytearray(IMAGE_SIZE)
    partition_sectors, sectors_per_cluster, sectors_per_fat, cluster_count = (
        helper._canonical_fat32_geometry(IMAGE_SIZE)
    )
    bootstrap = bytearray(
        (index * 29 + 7) & 0xFF for index in range(helper.GRUB_BOOTSTRAP_SIZE)
    )
    struct.pack_into("<Q", bootstrap, 0x5C, 1)
    bootstrap[0x64] = 0xFF
    bootstrap[0x66:0x68] = b"\x90\x90"
    image[:helper.GRUB_BOOTSTRAP_SIZE] = bootstrap
    struct.pack_into("<I", image, 440, DISK_SIGNATURE)
    image[446:454] = b"\x80\x20\x21\x00\x0c\xfe\xff\xff"
    struct.pack_into("<I", image, 454, helper.PARTITION_START_SECTOR)
    struct.pack_into("<I", image, 458, partition_sectors)
    image[510:512] = b"\x55\xaa"

    core = bytearray(
        (index * 11 + 3) & 0xFF for index in range(helper.GRUB_CORE_SIZE)
    )
    start = helper.GRUB_CORE_BLOCKLIST_OFFSET
    core[start:start + len(helper.GRUB_CORE_BLOCKLIST)] = helper.GRUB_CORE_BLOCKLIST
    image[helper.GRUB_CORE_OFFSET:helper.GRUB_CORE_OFFSET + len(core)] = core

    volume_offset = helper.PARTITION_START_SECTOR * helper.SECTOR_SIZE
    boot = helper._grub_empty_boot_sector(
        partition_sectors=partition_sectors,
        sectors_per_cluster=sectors_per_cluster,
        sectors_per_fat=sectors_per_fat,
        volume_id=VOLUME_ID,
    )
    image[volume_offset:volume_offset + 512] = boot
    image[volume_offset + 6 * 512:volume_offset + 7 * 512] = boot
    fsinfo = bytearray(512)
    struct.pack_into("<I", fsinfo, 0, 0x41615252)
    struct.pack_into("<I", fsinfo, 484, 0x61417272)
    struct.pack_into("<I", fsinfo, 488, cluster_count - 1)
    struct.pack_into("<I", fsinfo, 492, 3)
    struct.pack_into("<I", fsinfo, 508, 0xAA550000)
    image[volume_offset + 512:volume_offset + 2 * 512] = fsinfo
    image[volume_offset + 7 * 512:volume_offset + 8 * 512] = fsinfo
    fat_size = sectors_per_fat * 512
    fat = bytearray(fat_size)
    struct.pack_into("<III", fat, 0, 0x0FFFFFF8, 0x0FFFFFFF, 0x0FFFFFFF)
    first_fat = volume_offset + helper.RESERVED_SECTORS * 512
    image[first_fat:first_fat + fat_size] = fat
    image[first_fat + fat_size:first_fat + 2 * fat_size] = fat
    data_offset = first_fat + 2 * fat_size
    image[data_offset:data_offset + 11] = b"ISOPROPYL  "
    image[data_offset + 11] = 0x08
    dos_date = ((2026 - 1980) << 9) | (8 << 5) | 29
    dos_time = (12 << 11) | (34 << 5) | (56 // 2)
    struct.pack_into("<H", image, data_offset + 14, dos_time)
    struct.pack_into("<H", image, data_offset + 16, dos_date)
    struct.pack_into("<H", image, data_offset + 18, dos_date)
    struct.pack_into("<H", image, data_offset + 22, dos_time)
    struct.pack_into("<H", image, data_offset + 24, dos_date)
    return (
        bytes(image),
        hashlib.sha256(bootstrap).hexdigest(),
        hashlib.sha256(core).hexdigest(),
    )


@contextmanager
def synthetic_grub_hashes():
    _, bootstrap_sha256, core_sha256 = synthetic_grub_image()
    with (
        patch.object(helper, "GRUB_BOOTSTRAP_SHA256", bootstrap_sha256),
        patch.object(helper, "GRUB_CORE_SHA256", core_sha256),
    ):
        yield


def request_for(image: bytes) -> helper.GrubRescueHelperRequest:
    return helper.GrubRescueHelperRequest(
        REQUEST_ID,
        helper.GRUB_RESCUE_HELPER_PROFILE,
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
        self.write_calls: list[tuple[bytes, int]] = []
        self.flush_calls = 0
        self.mutation_calls = 0
        self.activated = False
        self.observation = helper.KernelTargetObservation(
            DEVICE_NUMBER,
            frozenset({DEVICE_NUMBER, os.makedev(8, 241)}),
            "usb",
            True,
            False,
            512,
            False,
            DISK_SEQUENCE,
        )

    def close(self) -> None:
        self.source.close()
        self.target.close()

    def open_target(self, path: str, flags: int) -> int:
        self.assertEqual(path, "/dev/sdz")
        self.open_flags.append(flags)
        descriptor = os.dup(self.target.fileno())
        self.target_fds.add(descriptor)
        return descriptor

    @staticmethod
    def assertEqual(left, right) -> None:
        if left != right:
            raise AssertionError((left, right))

    def fstat(self, descriptor: int):
        return fake_block_status() if descriptor in self.target_fds else os.fstat(descriptor)

    def pwrite(self, descriptor: int, data: bytes, offset: int) -> int:
        self.write_calls.append((bytes(data), offset))
        if offset == 0 and len(data) == 512 and any(data):
            self.activated = True
        return os.pwrite(descriptor, data, offset)

    def ioctl_uint(self, descriptor: int, operation: int) -> int:
        if descriptor not in self.target_fds:
            raise AssertionError("not a target descriptor")
        if operation == helper.BLKSSZGET:
            return 512
        if operation == helper.BLKROGET:
            return 0
        raise AssertionError(operation)

    def ioctl_u64(self, descriptor: int, operation: int) -> int:
        if descriptor not in self.target_fds:
            raise AssertionError("not a target descriptor")
        if operation == helper.BLKGETSIZE64:
            return len(self.image)
        if operation == helper.BLKGETDISKSEQ:
            return DISK_SEQUENCE
        raise AssertionError(operation)

    def ioctl_void(self, descriptor: int, operation: int) -> None:
        if descriptor not in self.target_fds or operation != helper.BLKFLSBUF:
            raise AssertionError((descriptor, operation))
        self.flush_calls += 1

    def operations(self, **overrides) -> helper.HelperOperations:
        values = dict(
            lstat=lambda _path: fake_block_status(),
            stat=os.stat,
            fstat=self.fstat,
            open=self.open_target,
            close=os.close,
            pread=os.pread,
            pwrite=self.pwrite,
            fsync=os.fsync,
            flock=fcntl.flock,
            get_flags=lambda fd: fcntl.fcntl(fd, fcntl.F_GETFL),
            ioctl_uint=self.ioctl_uint,
            ioctl_u64=self.ioctl_u64,
            ioctl_void=self.ioctl_void,
            inspect_target=lambda _device: self.observation,
            active_devices=lambda: frozenset(),
        )
        values.update(overrides)
        return helper.HelperOperations(**values)

    def execute(self, **overrides):
        operations = overrides.pop("operations", self.operations())
        mutation_started = overrides.pop("mutation_started", self.begin_mutation)
        return helper.execute_helper_transaction(
            overrides.pop("request", request_for(self.image)),
            source_descriptor=self.source.fileno(),
            invoking_uid=os.getuid(),
            operations=operations,
            mutation_started=mutation_started,
            **overrides,
        )

    def begin_mutation(self) -> None:
        self.mutation_calls += 1


class GrubRescueProtocolTests(unittest.TestCase):
    def test_pinned_exact_grub_constants_are_not_fixture_values(self) -> None:
        self.assertEqual(len(helper.GRUB_RESCUE_PROTOCOL_MAGIC), 16)
        self.assertEqual(helper.GRUB_BOOTSTRAP_SIZE, 432)
        self.assertEqual(
            helper.GRUB_BOOTSTRAP_SHA256,
            "82d8879ed51b42cab56ad071eb3b0d28d60cd83d57f24fe788014a639940e41e",
        )
        self.assertEqual(helper.GRUB_CORE_SIZE, 42_742)
        self.assertEqual(
            helper.GRUB_CORE_SHA256,
            "9a2c946704017fa8dc4e03a8a58d754d2d1607c2d2cd74f0e2920133f1192809",
        )

    def test_request_and_control_packets_are_protocol_distinct(self) -> None:
        image, _, _ = synthetic_grub_image()
        packet = helper.pack_grub_rescue_helper_request(
            REQUEST_ID, 8, 240, DISK_SEQUENCE, len(image), 512,
            DISK_SIGNATURE, VOLUME_ID, hashlib.sha256(image).hexdigest(),
        )
        with patch.object(helper, "_target_path_from_kernel", return_value="/dev/sdz"):
            request = helper.unpack_grub_rescue_helper_request(packet)
        self.assertEqual(request, request_for(image))
        with self.assertRaises(helper.HelperRequestError):
            helper.unpack_helper_request(packet)
        for commit, packet_type in (
            (True, helper.PACKET_COMMIT), (False, helper.PACKET_CANCEL),
        ):
            control = helper.pack_grub_rescue_helper_control(REQUEST_ID, commit=commit)
            self.assertEqual(control[:16], helper.GRUB_RESCUE_PROTOCOL_MAGIC)
            self.assertEqual(helper._CONTROL_PACKET.unpack(control)[2], packet_type)

    def test_progress_channel_accepts_and_emits_the_grub_protocol(self) -> None:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            progress = helper._ProtocolProgress(
                parent,
                REQUEST_ID,
                os.getuid(),
                helper.GRUB_RESCUE_PROTOCOL_MAGIC,
            )
            progress("source-validation", 0, IMAGE_SIZE)
            packet = child.recv(helper.MAX_PROTOCOL_PACKET)
            self.assertEqual(packet[:16], helper.GRUB_RESCUE_PROTOCOL_MAGIC)
            self.assertEqual(
                helper.unpack_grub_rescue_server_packet(packet),
                ("progress", REQUEST_ID, "source-validation", 0, IMAGE_SIZE),
            )
        finally:
            parent.close()
            child.close()

    def test_result_packet_is_exactly_bound_and_cross_protocol_rejected(self) -> None:
        digest = "ab" * 32
        result = helper.GrubRescueHelperResult(
            REQUEST_ID, helper.GRUB_RESCUE_HELPER_PROFILE, "/dev/sdz", "8:240",
            DISK_SEQUENCE, IMAGE_SIZE, digest, digest, digest, 512,
            DISK_SIGNATURE, VOLUME_ID, True, True,
        )
        packet = helper.pack_grub_rescue_helper_result(result)
        decoded = helper.unpack_grub_rescue_server_packet(packet)
        self.assertEqual(decoded[0], "success")
        self.assertEqual(decoded[1], REQUEST_ID)
        self.assertEqual(decoded[-3:], (digest, digest, digest))
        with self.assertRaises(helper.HelperRequestError):
            helper.unpack_server_packet(packet)
        with self.assertRaises(helper.HelperRequestError):
            helper.pack_grub_rescue_helper_result(replace(result, readback_sha256="cd" * 32))

    def test_request_requires_exact_grub_type_profile_and_geometry(self) -> None:
        image, _, _ = synthetic_grub_image()
        request = request_for(image)
        helper.validate_grub_rescue_helper_request(request)
        with self.assertRaises(helper.HelperRequestError):
            helper.validate_grub_rescue_helper_request(replace(request, profile=helper.HELPER_PROFILE))
        with self.assertRaises(helper.HelperRequestError):
            helper.validate_grub_rescue_helper_request(replace(request, expected_sector_size=4096))
        with self.assertRaises(helper.HelperRequestError):
            helper.validate_grub_rescue_helper_request(  # type: ignore[arg-type]
                helper.HelperRequest(*request.__dict__.values()),
            )


class GrubRescueLayoutTests(unittest.TestCase):
    def validate(self, image: bytes) -> bytes:
        source = tempfile.TemporaryFile()
        try:
            source.write(image)
            source.flush()
            with synthetic_grub_hashes():
                return helper._validate_grub_rescue_image_layout(
                    source.fileno(), request_for(image), read_at=os.pread,
                )
        finally:
            source.close()

    def test_accepts_only_the_canonical_empty_private_layout(self) -> None:
        image, _, _ = synthetic_grub_image()
        self.assertEqual(self.validate(image), image[:512])

    def test_rejects_bootstrap_core_mbr_gap_and_fat_forgeries(self) -> None:
        original, _, _ = synthetic_grub_image()
        _, _, sectors_per_fat, _ = helper._canonical_fat32_geometry(len(original))
        volume = helper.PARTITION_START_SECTOR * 512
        fat = volume + helper.RESERVED_SECTORS * 512
        data = fat + 2 * sectors_per_fat * 512
        corruptions = {
            "bootstrap": 0,
            "core": helper.GRUB_CORE_OFFSET + 100,
            "partition-type": 450,
            "embedding-gap": helper.GRUB_CORE_OFFSET + helper.GRUB_CORE_SIZE + 1,
            "primary-boot": volume + 90,
            "backup-fsinfo": volume + 7 * 512 + 488,
            "fat": fat + 12,
            "second-fat": fat + sectors_per_fat * 512 + 12,
            "root-extra-entry": data + 32,
            "data": data + 4096,
        }
        for label, offset in corruptions.items():
            with self.subTest(label=label):
                forged = bytearray(original)
                forged[offset] ^= 0x01
                with self.assertRaises(helper.HelperSourceError):
                    self.validate(bytes(forged))


class GrubRescueTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.image = synthetic_grub_image()[0]
        self.harness = TransactionHarness(self.image)

    def tearDown(self) -> None:
        self.harness.close()

    def test_full_transaction_is_sector_zero_last_and_returns_grub_result(self) -> None:
        with synthetic_grub_hashes():
            result = self.harness.execute()
        self.assertIs(type(result), helper.GrubRescueHelperResult)
        self.assertEqual(result.profile, helper.GRUB_RESCUE_HELPER_PROFILE)
        self.assertEqual(result.source_sha256, hashlib.sha256(self.image).hexdigest())
        self.assertEqual(result.source_sha256, result.written_sha256)
        self.assertEqual(result.source_sha256, result.readback_sha256)
        self.assertEqual(self.harness.mutation_calls, 1)
        self.assertEqual(self.harness.write_calls[0], (b"\0" * 1024, 0))
        self.assertEqual(self.harness.write_calls[1], (b"\0" * 512, len(self.image) - 512))
        activation_indexes = [
            index for index, (data, offset) in enumerate(self.harness.write_calls)
            if offset == 0 and len(data) == 512 and any(data)
        ]
        self.assertEqual(activation_indexes, [len(self.harness.write_calls) - 1])
        self.harness.target.seek(0)
        self.assertEqual(self.harness.target.read(), self.image)

    def test_precommit_cancel_never_opens_or_mutates_target(self) -> None:
        def cancel() -> None:
            raise helper.HelperCancelled("cancelled")

        with synthetic_grub_hashes(), self.assertRaises(helper.HelperCancelled):
            self.harness.execute(precommit_cancel=cancel)
        self.assertEqual(self.harness.open_flags, [])
        self.assertEqual(self.harness.write_calls, [])
        self.assertEqual(self.harness.mutation_calls, 0)

    def test_strict_removable_usb_filter_rejects_fixed_media(self) -> None:
        self.harness.observation = replace(self.harness.observation, removable=False)
        with synthetic_grub_hashes(), self.assertRaises(helper.HelperTargetError):
            self.harness.execute()
        self.assertEqual(self.harness.open_flags, [])
        self.assertEqual(self.harness.write_calls, [])

    def test_preactivation_readback_failure_leaves_sector_zero_inactive(self) -> None:
        corrupted = False

        def pread(descriptor: int, size: int, offset: int) -> bytes:
            nonlocal corrupted
            block = os.pread(descriptor, size, offset)
            if (
                descriptor in self.harness.target_fds
                and self.harness.flush_calls
                and not self.harness.activated
                and offset >= 512
                and block
                and not corrupted
            ):
                corrupted = True
                return bytes([block[0] ^ 1]) + block[1:]
            return block

        with synthetic_grub_hashes(), self.assertRaises(helper.HelperVerificationError):
            self.harness.execute(operations=self.harness.operations(pread=pread))
        self.assertFalse(self.harness.activated)
        self.harness.target.seek(0)
        self.assertEqual(self.harness.target.read(512), b"\0" * 512)

    def test_postactivation_failure_durably_deactivates_sector_zero(self) -> None:
        corrupted = False

        def pread(descriptor: int, size: int, offset: int) -> bytes:
            nonlocal corrupted
            block = os.pread(descriptor, size, offset)
            if (
                descriptor in self.harness.target_fds
                and self.harness.activated
                and block
                and not corrupted
            ):
                corrupted = True
                return bytes([block[0] ^ 1]) + block[1:]
            return block

        with synthetic_grub_hashes(), self.assertRaises(helper.HelperVerificationError):
            self.harness.execute(operations=self.harness.operations(pread=pread))
        self.assertTrue(self.harness.activated)
        self.assertEqual(self.harness.write_calls[-1], (b"\0" * 512, 0))
        self.harness.target.seek(0)
        self.assertEqual(self.harness.target.read(512), b"\0" * 512)

    def test_target_capacity_must_exactly_equal_source_capacity(self) -> None:
        operations = self.harness.operations()
        original = operations.ioctl_u64

        def wrong_size(descriptor: int, operation: int) -> int:
            if operation == helper.BLKGETSIZE64:
                return len(self.image) + 512
            return original(descriptor, operation)

        operations = replace(operations, ioctl_u64=wrong_size)
        with synthetic_grub_hashes(), self.assertRaises(helper.HelperTargetError):
            self.harness.execute(operations=operations)
        self.assertEqual(self.harness.write_calls, [])


if __name__ == "__main__":
    unittest.main()
