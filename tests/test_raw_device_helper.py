from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import errno
import fcntl
import hashlib
import os
import socket
import stat
import tempfile
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import isopropyl.syslinux_device_helper as helper
from isopropyl.syslinux_device_helper import (
    BLKFLSBUF,
    BLKGETDISKSEQ,
    BLKGETSIZE64,
    BLKROGET,
    BLKSSZGET,
    RAW_FRONT_GUARD_BYTES,
    RAW_HELPER_PROFILE,
    RAW_OPERATION,
    RAW_PROTOCOL_MAGIC,
    HelperError,
    HelperOperations,
    HelperRequestError,
    HelperSourceError,
    HelperTargetError,
    HelperVerificationError,
    KernelTargetObservation,
    RawHelperRequest,
    RawHelperResult,
    execute_raw_helper_transaction,
    pack_raw_helper_control,
    pack_raw_helper_request,
    unpack_raw_helper_request,
    unpack_raw_server_packet,
    validate_raw_helper_request,
)


SECTOR_SIZE = 512
SOURCE_SIZE = RAW_FRONT_GUARD_BYTES + 3 * SECTOR_SIZE
SHORT_TARGET_SIZE = SOURCE_SIZE + 5 * SECTOR_SIZE
DEVICE_NUMBER = os.makedev(8, 240)
CHILD_DEVICE_NUMBER = os.makedev(8, 241)
DISK_SEQUENCE = 7331
REQUEST_ID = bytes(range(16))


def raw_image(size: int = SOURCE_SIZE) -> bytes:
    pattern = bytes(range(256))
    return (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]


def raw_request(
    image: bytes,
    target_size: int,
    *,
    final_verification: bool = True,
) -> RawHelperRequest:
    return RawHelperRequest(
        REQUEST_ID,
        RAW_HELPER_PROFILE,
        "/dev/sdz",
        "8:240",
        DISK_SEQUENCE,
        target_size,
        SECTOR_SIZE,
        len(image),
        hashlib.sha256(image).hexdigest(),
        final_verification,
    )


def fake_block_status(
    device_number: int = DEVICE_NUMBER,
) -> SimpleNamespace:
    return SimpleNamespace(
        st_mode=stat.S_IFBLK | 0o600,
        st_rdev=device_number,
    )


def changed_status(status: os.stat_result, field: str) -> SimpleNamespace:
    names = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    return SimpleNamespace(**{
        name: getattr(status, name) + (1 if name == field else 0)
        for name in names
    })


class RawTransactionHarness:
    def __init__(
        self,
        *,
        image: bytes | None = None,
        target_size: int = SHORT_TARGET_SIZE,
        final_verification: bool = True,
    ) -> None:
        self.image = image if image is not None else raw_image()
        self.target_size = target_size
        self.final_verification = final_verification
        self.source = tempfile.TemporaryFile()
        os.fchmod(self.source.fileno(), 0o600)
        self.source.write(self.image)
        self.source.flush()
        self.target = tempfile.TemporaryFile()
        self.target.write(b"\xa5" * target_size)
        self.target.flush()
        self.target_fds: set[int] = set()
        self.open_flags: list[int] = []
        self.write_calls: list[tuple[int, bytes, int]] = []
        self.read_calls: list[tuple[int, int, int, int]] = []
        self.fsync_calls: list[int] = []
        self.flush_calls: list[int] = []
        self.flock_calls: list[tuple[int, int]] = []
        self.close_calls: list[int] = []
        self.progress: list[tuple[str, int, int]] = []
        self.mutation_calls = 0
        self.observation = KernelTargetObservation(
            DEVICE_NUMBER,
            frozenset({DEVICE_NUMBER, CHILD_DEVICE_NUMBER}),
            "usb",
            False,
            False,
            SECTOR_SIZE,
            False,
            DISK_SEQUENCE,
        )
        self.active = frozenset()

    def close(self) -> None:
        self.source.close()
        self.target.close()

    @property
    def request(self) -> RawHelperRequest:
        return raw_request(
            self.image,
            self.target_size,
            final_verification=self.final_verification,
        )

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

    def pread(self, descriptor: int, size: int, offset: int) -> bytes:
        block = os.pread(descriptor, size, offset)
        self.read_calls.append((descriptor, size, offset, len(block)))
        return block

    def pwrite(self, descriptor: int, data: bytes, offset: int) -> int:
        self.write_calls.append((descriptor, bytes(data), offset))
        return os.pwrite(descriptor, data, offset)

    def fsync(self, descriptor: int) -> None:
        self.fsync_calls.append(descriptor)
        os.fsync(descriptor)

    def flock(self, descriptor: int, operation: int) -> None:
        self.flock_calls.append((descriptor, operation))
        fcntl.flock(descriptor, operation)

    def ioctl_uint(self, descriptor: int, operation: int) -> int:
        self.assert_target(descriptor)
        if operation == BLKSSZGET:
            return SECTOR_SIZE
        if operation == BLKROGET:
            return 0
        raise AssertionError(operation)

    def ioctl_u64(self, descriptor: int, operation: int) -> int:
        self.assert_target(descriptor)
        if operation == BLKGETSIZE64:
            return self.target_size
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

    def operations(self, **overrides: object) -> HelperOperations:
        values = dict(
            lstat=lambda _path: fake_block_status(),
            stat=os.stat,
            fstat=self.fstat,
            open=self.open_target,
            close=self.close_fd,
            pread=self.pread,
            pwrite=self.pwrite,
            fsync=self.fsync,
            flock=self.flock,
            get_flags=lambda fd: fcntl.fcntl(fd, fcntl.F_GETFL),
            ioctl_uint=self.ioctl_uint,
            ioctl_u64=self.ioctl_u64,
            ioctl_void=self.ioctl_void,
            inspect_target=lambda _dev: self.observation,
            inspect_raw_target=lambda _dev: self.observation,
            active_devices=lambda: self.active,
        )
        values.update(overrides)
        return HelperOperations(**values)

    def execute(self, **overrides: object) -> RawHelperResult:
        operations = overrides.pop("operations", self.operations())
        request = overrides.pop("request", self.request)
        mutation_started = overrides.pop(
            "mutation_started",
            self._mutation_started,
        )
        return execute_raw_helper_transaction(
            request,
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

    def target_bytes(self, size: int, offset: int = 0) -> bytes:
        return os.pread(self.target.fileno(), size, offset)


class RawRequestTests(unittest.TestCase):
    def test_request_binds_sizes_digest_sector_and_verification_policy(self):
        image = raw_image()
        request = raw_request(image, SHORT_TARGET_SIZE)
        validate_raw_helper_request(request)
        validate_raw_helper_request(
            replace(
                request,
                expected_target_size=1024 * 1024 * 1024 * 1024,
            ),
        )
        invalid = (
            replace(request, request_id=b"short"),
            replace(request, profile="wrong"),
            replace(request, target_path="/tmp/not-a-device"),
            replace(request, expected_major_minor="08:240"),
            replace(request, expected_disk_sequence=0),
            replace(request, expected_target_size=SHORT_TARGET_SIZE - 1),
            replace(request, expected_sector_size=4096),
            replace(request, source_size=SHORT_TARGET_SIZE + SECTOR_SIZE),
            replace(request, source_size=SOURCE_SIZE - 1),
            replace(request, source_sha256="AA" * 32),
            replace(request, final_verification=1),
        )
        for forged in invalid:
            with self.subTest(forged=forged), self.assertRaises(HelperRequestError):
                validate_raw_helper_request(forged)


class RawProtocolTests(unittest.TestCase):
    @staticmethod
    def _sysfs(root: str) -> None:
        block = os.path.join(root, "dev", "block", "8:240")
        os.makedirs(block)
        with open(os.path.join(block, "uevent"), "w", encoding="ascii") as stream:
            stream.write("MAJOR=8\nMINOR=240\nDEVNAME=sdz\n")

    def test_request_is_fixed_binary_kernel_resolved_and_binds_verification_flag(self):
        digest = "ab" * 32
        for final_verification in (False, True):
            packet = pack_raw_helper_request(
                REQUEST_ID,
                8,
                240,
                DISK_SEQUENCE,
                SHORT_TARGET_SIZE,
                SECTOR_SIZE,
                SOURCE_SIZE,
                digest,
                final_verification=final_verification,
            )
            self.assertEqual(len(packet), helper._RAW_REQUEST_PACKET.size)
            self.assertEqual(packet[:16], RAW_PROTOCOL_MAGIC)
            self.assertNotIn(b"/dev/", packet)
            with tempfile.TemporaryDirectory() as directory:
                self._sysfs(directory)
                request = unpack_raw_helper_request(
                    packet,
                    sys_root=helper.Path(directory),
                )
            self.assertEqual(request.target_path, "/dev/sdz")
            self.assertEqual(request.expected_major_minor, "8:240")
            self.assertEqual(request.expected_target_size, SHORT_TARGET_SIZE)
            self.assertEqual(request.source_size, SOURCE_SIZE)
            self.assertEqual(request.source_sha256, digest)
            self.assertIs(request.final_verification, final_verification)

    def test_request_rejects_shape_header_reserved_and_noncanonical_flag(self):
        packet = pack_raw_helper_request(
            REQUEST_ID,
            8,
            240,
            DISK_SEQUENCE,
            SHORT_TARGET_SIZE,
            SECTOR_SIZE,
            SOURCE_SIZE,
            "ab" * 32,
            final_verification=True,
        )
        fields = list(helper._RAW_REQUEST_PACKET.unpack(packet))
        bad_flag = fields.copy()
        bad_flag[11] = 2
        nonzero_padding = bytearray(packet)
        nonzero_padding[len(packet) - 32 - 1] = 1
        candidates = (
            packet[:-1],
            packet + b"x",
            b"X" + packet[1:],
            packet[:16] + b"\x02" + packet[17:],
            packet[:17] + b"\xff" + packet[18:],
            packet[:18] + b"\x00\x01" + packet[20:],
            helper._RAW_REQUEST_PACKET.pack(*bad_flag),
            bytes(nonzero_padding),
        )
        with tempfile.TemporaryDirectory() as directory:
            self._sysfs(directory)
            sys_root = helper.Path(directory)
            for candidate in candidates:
                with (
                    self.subTest(length=len(candidate)),
                    self.assertRaises(HelperRequestError),
                ):
                    unpack_raw_helper_request(candidate, sys_root=sys_root)

    def test_raw_commit_and_cancel_use_only_raw_magic_and_bound_request_id(self):
        for commit, packet_type in (
            (True, helper.PACKET_COMMIT),
            (False, helper.PACKET_CANCEL),
        ):
            packet = pack_raw_helper_control(REQUEST_ID, commit=commit)
            self.assertEqual(
                helper._CONTROL_PACKET.unpack(packet),
                (
                    RAW_PROTOCOL_MAGIC,
                    helper.PROTOCOL_VERSION,
                    packet_type,
                    0,
                    REQUEST_ID,
                ),
            )
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                parent.send(packet)
                self.assertIs(
                    helper._receive_control(
                        child,
                        expected_uid=os.getuid(),
                        request_id=REQUEST_ID,
                        protocol_magic=RAW_PROTOCOL_MAGIC,
                    ),
                    commit,
                )
            finally:
                parent.close()
                child.close()
        with self.assertRaises(HelperRequestError):
            pack_raw_helper_control(REQUEST_ID, commit=1)

    def test_server_packets_reject_cross_profile_shapes_and_invalid_flags(self):
        ready = helper._HEADER.pack(
            RAW_PROTOCOL_MAGIC,
            helper.PROTOCOL_VERSION,
            helper.PACKET_READY,
            0,
        )
        self.assertEqual(unpack_raw_server_packet(ready), ("ready",))
        syslinux_ready = helper._HEADER.pack(
            helper.PROTOCOL_MAGIC,
            helper.PROTOCOL_VERSION,
            helper.PACKET_READY,
            0,
        )
        with self.assertRaises(HelperRequestError):
            unpack_raw_server_packet(syslinux_ready)

        digest = bytes.fromhex("ab" * 32)

        def success(tail_flag: int, verify_flag: int, readback: bytes) -> bytes:
            return helper._RAW_SUCCESS_PACKET.pack(
                RAW_PROTOCOL_MAGIC,
                helper.PROTOCOL_VERSION,
                helper.PACKET_SUCCESS,
                0,
                REQUEST_ID,
                8,
                240,
                DISK_SEQUENCE,
                SHORT_TARGET_SIZE,
                SECTOR_SIZE,
                SOURCE_SIZE,
                RAW_FRONT_GUARD_BYTES,
                tail_flag,
                verify_flag,
                b"\0" * 2,
                digest,
                digest,
                readback,
            )

        decoded = unpack_raw_server_packet(success(1, 1, digest))
        self.assertEqual(decoded[:11], (
            "success",
            REQUEST_ID,
            8,
            240,
            DISK_SEQUENCE,
            SHORT_TARGET_SIZE,
            SECTOR_SIZE,
            SOURCE_SIZE,
            RAW_FRONT_GUARD_BYTES,
            True,
            True,
        ))
        self.assertEqual(decoded[-1], "ab" * 32)
        self.assertEqual(
            unpack_raw_server_packet(success(1, 0, b"\0" * 32))[-1],
            "",
        )
        for packet in (
            success(2, 1, digest),
            success(1, 2, digest),
            success(1, 0, digest),
        ):
            with self.assertRaises(HelperRequestError):
                unpack_raw_server_packet(packet)
        nonzero_padding = bytearray(success(1, 1, digest))
        nonzero_padding[len(nonzero_padding) - 3 * 32 - 1] = 1
        with self.assertRaises(HelperRequestError):
            unpack_raw_server_packet(bytes(nonzero_padding))

    def test_main_raw_operation_dispatches_only_raw_transaction_and_response(self):
        image = raw_image()
        request = raw_request(image, SHORT_TARGET_SIZE)
        digest = request.source_sha256
        result = RawHelperResult(
            REQUEST_ID,
            RAW_HELPER_PROFILE,
            "/dev/sdz",
            "8:240",
            DISK_SEQUENCE,
            SHORT_TARGET_SIZE,
            SOURCE_SIZE,
            digest,
            digest,
            digest,
            SECTOR_SIZE,
            RAW_FRONT_GUARD_BYTES,
            True,
            True,
            True,
            True,
        )
        packet = pack_raw_helper_request(
            REQUEST_ID,
            8,
            240,
            DISK_SEQUENCE,
            SHORT_TARGET_SIZE,
            SECTOR_SIZE,
            SOURCE_SIZE,
            digest,
            final_verification=True,
        )
        sent: list[bytes] = []
        source = tempfile.TemporaryFile()
        source_fd = os.dup(source.fileno())
        channel = SimpleNamespace(close=lambda: None)
        with (
            patch.object(helper, "_reset_ordinary_termination"),
            patch.object(helper.signal, "signal"),
            patch.object(helper.os, "geteuid", return_value=0),
            patch.object(helper, "_verify_installed_helper"),
            patch.object(helper, "_invoking_uid", return_value=os.getuid()),
            patch.object(helper, "_require_initial_namespaces"),
            patch.object(helper, "_harden_process"),
            patch.object(helper, "_protocol_channel", return_value=channel),
            patch.object(helper, "_send_packet", side_effect=lambda _channel, data: sent.append(data)),
            patch.object(helper, "_receive_request", return_value=(packet, source_fd)),
            patch.object(helper, "unpack_raw_helper_request", return_value=request) as unpack_raw,
            patch.object(helper, "unpack_helper_request") as unpack_syslinux,
            patch.object(helper, "execute_raw_helper_transaction", return_value=result) as execute_raw,
            patch.object(helper, "execute_helper_transaction") as execute_syslinux,
        ):
            self.assertEqual(helper.main([RAW_OPERATION]), 0)
        source.close()
        unpack_raw.assert_called_once_with(packet)
        unpack_syslinux.assert_not_called()
        execute_raw.assert_called_once()
        execute_syslinux.assert_not_called()
        self.assertEqual(unpack_raw_server_packet(sent[0]), ("ready",))
        self.assertEqual(unpack_raw_server_packet(sent[-1])[0], "success")


class RawHelperTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = RawTransactionHarness()

    def tearDown(self) -> None:
        self.harness.close()

    def test_short_source_writes_exact_image_and_sanitizes_physical_tail(self):
        result = self.harness.execute()
        self.assertEqual(result.profile, RAW_HELPER_PROFILE)
        self.assertEqual(result.target_size, SHORT_TARGET_SIZE)
        self.assertEqual(result.bytes_written, SOURCE_SIZE)
        self.assertEqual(result.front_guard_bytes, RAW_FRONT_GUARD_BYTES)
        self.assertTrue(result.target_tail_sanitized)
        self.assertTrue(result.final_verification)
        expected_hash = hashlib.sha256(self.harness.image).hexdigest()
        self.assertEqual(result.source_sha256, expected_hash)
        self.assertEqual(result.written_sha256, expected_hash)
        self.assertEqual(result.readback_sha256, expected_hash)
        self.assertEqual(
            self.harness.target_bytes(SOURCE_SIZE),
            self.harness.image,
        )
        self.assertEqual(
            self.harness.target_bytes(SECTOR_SIZE, SHORT_TARGET_SIZE - SECTOR_SIZE),
            b"\0" * SECTOR_SIZE,
        )
        # Sanitizing the physical final LBA must not be mislabeled as erasing
        # every unused byte between the image and that final sector.
        self.assertEqual(
            self.harness.target_bytes(
                SHORT_TARGET_SIZE - SOURCE_SIZE - SECTOR_SIZE,
                SOURCE_SIZE,
            ),
            b"\xa5" * (SHORT_TARGET_SIZE - SOURCE_SIZE - SECTOR_SIZE),
        )

    def test_equal_size_target_has_no_distinct_physical_tail(self):
        self.harness.close()
        self.harness = RawTransactionHarness(target_size=SOURCE_SIZE)
        result = self.harness.execute()
        self.assertFalse(result.target_tail_sanitized)
        self.assertEqual(self.harness.target_bytes(SOURCE_SIZE), self.harness.image)
        zero_tail_writes = [
            call for call in self.harness.write_calls
            if call[2] == SOURCE_SIZE - SECTOR_SIZE
            and call[1] == b"\0" * SECTOR_SIZE
        ]
        self.assertEqual(len(zero_tail_writes), 1)

    def test_front_guard_is_deactivated_and_source_tail_activates_first(self):
        self.harness.execute()
        guard_zero = (
            next(
                index for index, (_fd, data, offset) in enumerate(self.harness.write_calls)
                if offset == 0 and data == b"\0" * RAW_FRONT_GUARD_BYTES
            )
        )
        source_tail_zero = next(
            index for index, (_fd, data, offset) in enumerate(self.harness.write_calls)
            if offset == SOURCE_SIZE - SECTOR_SIZE and data == b"\0" * SECTOR_SIZE
        )
        source_tail_activation = next(
            index for index, (_fd, data, offset) in enumerate(self.harness.write_calls)
            if offset == SOURCE_SIZE - SECTOR_SIZE
            and data == self.harness.image[-SECTOR_SIZE:]
        )
        front_activation = next(
            index for index, (_fd, data, offset) in enumerate(self.harness.write_calls)
            if offset == 0 and data == self.harness.image[:RAW_FRONT_GUARD_BYTES]
        )
        self.assertLess(guard_zero, source_tail_zero)
        self.assertLess(source_tail_zero, source_tail_activation)
        self.assertLess(source_tail_activation, front_activation)
        fsync_before_tail = any(
            fd == self.harness.write_calls[source_tail_activation][0]
            for fd in self.harness.fsync_calls
        )
        self.assertTrue(fsync_before_tail)

    def test_one_target_descriptor_is_used_for_writes_flushes_and_readback(self):
        self.harness.execute()
        self.assertEqual(len(self.harness.open_flags), 1)
        self.assertEqual(len(self.harness.target_fds), 1)
        target_fd = next(iter(self.harness.target_fds))
        self.assertTrue(self.harness.write_calls)
        self.assertEqual({fd for fd, _data, _offset in self.harness.write_calls}, {target_fd})
        self.assertEqual(set(self.harness.fsync_calls), {target_fd})
        self.assertEqual(set(self.harness.flush_calls), {target_fd})
        self.assertEqual(
            {fd for fd, _wanted, _offset, _got in self.harness.read_calls if fd in self.harness.target_fds},
            {target_fd},
        )
        self.assertEqual(self.harness.close_calls, [target_fd])

    def test_final_full_verification_is_optional_but_activation_checks_remain(self):
        self.harness.close()
        self.harness = RawTransactionHarness(final_verification=False)
        result = self.harness.execute()
        self.assertFalse(result.final_verification)
        self.assertEqual(result.readback_sha256, "")
        self.assertNotIn("readback", {phase for phase, _done, _total in self.harness.progress})
        self.assertIn(
            "preactivation-readback",
            {phase for phase, _done, _total in self.harness.progress},
        )
        self.assertEqual(self.harness.target_bytes(SOURCE_SIZE), self.harness.image)
        self.assertEqual(
            self.harness.target_bytes(SECTOR_SIZE, SHORT_TARGET_SIZE - SECTOR_SIZE),
            b"\0" * SECTOR_SIZE,
        )

    def test_open_is_exclusive_and_source_and_target_are_nonblocking_locked(self):
        self.harness.execute()
        flags = self.harness.open_flags[0]
        self.assertTrue(flags & os.O_EXCL)
        self.assertTrue(flags & getattr(os, "O_NOFOLLOW", 0))
        self.assertTrue(flags & getattr(os, "O_CLOEXEC", 0))
        expected_lock = fcntl.LOCK_EX | fcntl.LOCK_NB
        self.assertIn((self.harness.source.fileno(), expected_lock), self.harness.flock_calls)
        target_fd = next(iter(self.harness.target_fds))
        self.assertIn((target_fd, expected_lock), self.harness.flock_calls)

    def test_busy_open_or_target_lock_fails_before_writing_and_closes(self):
        def busy(_path: str, _flags: int) -> int:
            raise OSError(errno.EBUSY, "busy")

        with self.assertRaisesRegex(HelperTargetError, "busy"):
            self.harness.execute(operations=self.harness.operations(open=busy))
        self.assertEqual(self.harness.write_calls, [])

        def fail_target_lock(fd: int, operation: int) -> None:
            if fd in self.harness.target_fds:
                raise OSError(errno.EWOULDBLOCK, "locked")
            self.harness.flock(fd, operation)

        with self.assertRaisesRegex(HelperTargetError, "lock-aware"):
            self.harness.execute(
                operations=self.harness.operations(flock=fail_target_lock),
            )
        self.assertEqual(self.harness.write_calls, [])
        self.assertTrue(self.harness.close_calls)

    def test_fixed_usb_is_allowed_but_fixed_mmc_is_rejected_preopen(self):
        self.assertFalse(self.harness.observation.removable)
        self.harness.execute()

        self.harness.close()
        self.harness = RawTransactionHarness()
        self.harness.observation = replace(
            self.harness.observation,
            transport="mmc",
            removable=False,
        )
        with self.assertRaisesRegex(HelperTargetError, "safety properties"):
            self.harness.execute()
        self.assertEqual(self.harness.open_flags, [])

    def test_mount_swap_holders_and_source_residency_fail_preopen(self):
        source_device = os.fstat(self.harness.source.fileno()).st_dev
        cases = (
            (
                replace(self.harness.observation, has_holders=True),
                frozenset(),
                "holders",
            ),
            (
                self.harness.observation,
                frozenset({CHILD_DEVICE_NUMBER}),
                "active",
            ),
            (
                replace(
                    self.harness.observation,
                    related_device_numbers=frozenset({DEVICE_NUMBER, source_device}),
                ),
                frozenset(),
                "resident",
            ),
        )
        for observation, active, label in cases:
            with self.subTest(case=label):
                self.harness.observation = observation
                self.harness.active = active
                self.harness.open_flags.clear()
                with self.assertRaises(HelperTargetError):
                    self.harness.execute()
                self.assertEqual(self.harness.open_flags, [])

    def test_wrong_source_hash_and_status_drift_never_open_target(self):
        wrong_hash = replace(self.harness.request, source_sha256="00" * 32)
        with self.assertRaisesRegex(HelperSourceError, "SHA-256"):
            self.harness.execute(request=wrong_hash)
        self.assertEqual(self.harness.open_flags, [])

        original = os.fstat(self.harness.source.fileno())
        calls = 0

        def drifting_fstat(fd: int):
            nonlocal calls
            if fd in self.harness.target_fds:
                return fake_block_status()
            calls += 1
            return changed_status(original, "st_ctime_ns") if calls >= 2 else original

        with self.assertRaisesRegex(HelperSourceError, "changed during validation"):
            self.harness.execute(
                operations=self.harness.operations(fstat=drifting_fstat),
            )
        self.assertEqual(self.harness.open_flags, [])

    def test_source_status_drift_before_commit_never_mutates_target(self):
        original = os.fstat(self.harness.source.fileno())
        calls = 0

        def drifting_fstat(fd: int):
            nonlocal calls
            if fd in self.harness.target_fds:
                return fake_block_status()
            calls += 1
            return changed_status(original, "st_ctime_ns") if calls >= 3 else original

        with self.assertRaisesRegex(HelperSourceError, "before commit"):
            self.harness.execute(
                operations=self.harness.operations(fstat=drifting_fstat),
            )
        self.assertEqual(self.harness.write_calls, [])
        self.assertEqual(self.harness.mutation_calls, 0)

    def test_source_drift_during_copy_fails_with_activation_regions_zero(self):
        mutated = False

        def mutate_after_bulk(fd: int, data: bytes, offset: int) -> int:
            nonlocal mutated
            count = self.harness.pwrite(fd, data, offset)
            if (
                not mutated
                and offset >= RAW_FRONT_GUARD_BYTES
                and data != b"\0" * len(data)
            ):
                os.pwrite(self.harness.source.fileno(), b"X", 0)
                mutated = True
            return count

        with self.assertRaisesRegex(HelperSourceError, "changed while writing"):
            self.harness.execute(
                operations=self.harness.operations(pwrite=mutate_after_bulk),
            )
        self.assertTrue(mutated)
        self.assertEqual(
            self.harness.target_bytes(RAW_FRONT_GUARD_BYTES),
            b"\0" * RAW_FRONT_GUARD_BYTES,
        )
        self.assertEqual(
            self.harness.target_bytes(SECTOR_SIZE, SOURCE_SIZE - SECTOR_SIZE),
            b"\0" * SECTOR_SIZE,
        )

    def test_diskseq_change_in_commit_lease_fails_before_first_write(self):
        mutation_notified = False

        def notify() -> None:
            nonlocal mutation_notified
            mutation_notified = True
            self.harness._mutation_started()

        def changing_diskseq(fd: int, operation: int) -> int:
            if operation == BLKGETSIZE64:
                return self.harness.target_size
            if operation == BLKGETDISKSEQ:
                return DISK_SEQUENCE + 1 if mutation_notified else DISK_SEQUENCE
            raise AssertionError(operation)

        with self.assertRaisesRegex(HelperTargetError, "authorized disk generation"):
            self.harness.execute(
                mutation_started=notify,
                operations=self.harness.operations(ioctl_u64=changing_diskseq),
            )
        self.assertEqual(self.harness.write_calls, [])
        self.assertEqual(self.harness.mutation_calls, 1)

    def test_final_diskseq_change_skips_identity_guarded_emergency_cleanup(self):
        activated = False

        def observe_activation(fd: int, data: bytes, offset: int) -> int:
            nonlocal activated
            count = self.harness.pwrite(fd, data, offset)
            if offset == 0 and data == self.harness.image[:RAW_FRONT_GUARD_BYTES]:
                activated = True
            return count

        def changing_diskseq(fd: int, operation: int) -> int:
            if operation == BLKGETSIZE64:
                return self.harness.target_size
            if operation == BLKGETDISKSEQ:
                return DISK_SEQUENCE + 1 if activated else DISK_SEQUENCE
            raise AssertionError(operation)

        with self.assertRaisesRegex(
            HelperVerificationError,
            "emergency raw deactivation was skipped",
        ):
            self.harness.execute(operations=self.harness.operations(
                pwrite=observe_activation,
                ioctl_u64=changing_diskseq,
            ))
        self.assertTrue(activated)
        self.assertEqual(
            self.harness.target_bytes(RAW_FRONT_GUARD_BYTES),
            self.harness.image[:RAW_FRONT_GUARD_BYTES],
        )
        self.assertEqual(
            self.harness.target_bytes(SECTOR_SIZE, SOURCE_SIZE - SECTOR_SIZE),
            self.harness.image[-SECTOR_SIZE:],
        )

    def test_preactivation_corruption_leaves_all_activation_regions_zero(self):
        flushes = 0

        def corrupt_after_bulk_flush(fd: int, operation: int) -> None:
            nonlocal flushes
            self.harness.ioctl_void(fd, operation)
            flushes += 1
            if flushes == 1:
                os.pwrite(fd, b"X", RAW_FRONT_GUARD_BYTES)

        with self.assertRaisesRegex(HelperVerificationError, "before activation"):
            self.harness.execute(
                operations=self.harness.operations(ioctl_void=corrupt_after_bulk_flush),
            )
        self.assertEqual(
            self.harness.target_bytes(RAW_FRONT_GUARD_BYTES),
            b"\0" * RAW_FRONT_GUARD_BYTES,
        )
        self.assertEqual(
            self.harness.target_bytes(SECTOR_SIZE, SOURCE_SIZE - SECTOR_SIZE),
            b"\0" * SECTOR_SIZE,
        )
        self.assertEqual(
            self.harness.target_bytes(SECTOR_SIZE, SHORT_TARGET_SIZE - SECTOR_SIZE),
            b"\0" * SECTOR_SIZE,
        )

    def test_partial_initial_guard_write_triggers_durable_emergency_deactivation(self):
        initial_write_started = False
        injected_failure = False
        cleanup_guard_seen = False

        def fail_once_during_initial_guard(
            descriptor: int,
            data: bytes,
            offset: int,
        ) -> int:
            nonlocal initial_write_started, injected_failure, cleanup_guard_seen
            if descriptor in self.harness.target_fds and not injected_failure:
                if not initial_write_started and offset == 0:
                    initial_write_started = True
                    partial = min(4_096, len(data))
                    return self.harness.pwrite(descriptor, data[:partial], offset)
                if initial_write_started and offset == 4_096:
                    injected_failure = True
                    raise OSError(errno.EIO, "injected initial guard failure")
            if (
                descriptor in self.harness.target_fds
                and injected_failure
                and offset == 0
                and data == b"\0" * RAW_FRONT_GUARD_BYTES
            ):
                cleanup_guard_seen = True
            return self.harness.pwrite(descriptor, data, offset)

        with self.assertRaisesRegex(HelperError, "injected initial guard failure"):
            self.harness.execute(operations=self.harness.operations(
                pwrite=fail_once_during_initial_guard,
            ))
        self.assertTrue(initial_write_started)
        self.assertTrue(injected_failure)
        self.assertTrue(cleanup_guard_seen)
        self.assertEqual(self.harness.mutation_calls, 1)
        self.assertEqual(len(self.harness.fsync_calls), 1)
        self.assertEqual(len(self.harness.flush_calls), 1)
        for offset, size in (
            (0, RAW_FRONT_GUARD_BYTES),
            (SOURCE_SIZE - SECTOR_SIZE, SECTOR_SIZE),
            (SHORT_TARGET_SIZE - SECTOR_SIZE, SECTOR_SIZE),
        ):
            with self.subTest(offset=offset):
                self.assertEqual(
                    self.harness.target_bytes(size, offset),
                    b"\0" * size,
                )

    def test_zero_front_guard_is_physically_read_back_before_activation(self):
        guard_probe_seen = False
        source_tail_activated = False

        def observe_writes(fd: int, data: bytes, offset: int) -> int:
            nonlocal source_tail_activated
            count = self.harness.pwrite(fd, data, offset)
            if (
                offset == SOURCE_SIZE - SECTOR_SIZE
                and data == self.harness.image[-SECTOR_SIZE:]
            ):
                source_tail_activated = True
            return count

        def corrupt_only_inactive_guard_read(
            descriptor: int,
            size: int,
            offset: int,
        ) -> bytes:
            nonlocal guard_probe_seen
            block = self.harness.pread(descriptor, size, offset)
            if (
                descriptor in self.harness.target_fds
                and not source_tail_activated
                and offset == 0
                and size == RAW_FRONT_GUARD_BYTES
                and block == b"\0" * RAW_FRONT_GUARD_BYTES
            ):
                guard_probe_seen = True
                return b"X" + block[1:]
            return block

        with self.assertRaisesRegex(HelperVerificationError, "front guard"):
            self.harness.execute(operations=self.harness.operations(
                pread=corrupt_only_inactive_guard_read,
                pwrite=observe_writes,
            ))
        self.assertTrue(guard_probe_seen)
        self.assertFalse(source_tail_activated)
        self.assertEqual(
            self.harness.target_bytes(RAW_FRONT_GUARD_BYTES),
            b"\0" * RAW_FRONT_GUARD_BYTES,
        )

    def test_final_corruption_emergency_zeros_guard_source_tail_and_target_tail(self):
        flushes = 0

        def corrupt_after_activation(fd: int, operation: int) -> None:
            nonlocal flushes
            self.harness.ioctl_void(fd, operation)
            flushes += 1
            if flushes == 2:
                os.pwrite(fd, b"X", RAW_FRONT_GUARD_BYTES)

        with self.assertRaisesRegex(HelperVerificationError, "complete raw target"):
            self.harness.execute(
                operations=self.harness.operations(ioctl_void=corrupt_after_activation),
            )
        for offset, size in (
            (0, RAW_FRONT_GUARD_BYTES),
            (SOURCE_SIZE - SECTOR_SIZE, SECTOR_SIZE),
            (SHORT_TARGET_SIZE - SECTOR_SIZE, SECTOR_SIZE),
        ):
            with self.subTest(offset=offset):
                self.assertEqual(self.harness.target_bytes(size, offset), b"\0" * size)

    def test_cleanup_revalidates_diskseq_before_emergency_zero(self):
        corrupted = False

        def corrupt_final_read(
            descriptor: int,
            size: int,
            offset: int,
        ) -> bytes:
            nonlocal corrupted
            block = self.harness.pread(descriptor, size, offset)
            if (
                descriptor in self.harness.target_fds
                and offset == 0
                and any(block)
                and self.harness.flush_calls
                and len(self.harness.flush_calls) >= 2
            ):
                corrupted = True
                return b"X" + block[1:]
            return block

        def cleanup_diskseq(fd: int, operation: int) -> int:
            if operation == BLKGETSIZE64:
                return self.harness.target_size
            if operation == BLKGETDISKSEQ:
                return DISK_SEQUENCE + 1 if corrupted else DISK_SEQUENCE
            raise AssertionError(operation)

        with self.assertRaisesRegex(
            HelperVerificationError,
            "emergency raw deactivation was skipped",
        ):
            self.harness.execute(operations=self.harness.operations(
                pread=corrupt_final_read,
                ioctl_u64=cleanup_diskseq,
            ))
        self.assertTrue(corrupted)
        self.assertEqual(
            self.harness.target_bytes(RAW_FRONT_GUARD_BYTES),
            self.harness.image[:RAW_FRONT_GUARD_BYTES],
        )

    def test_short_and_interrupted_reads_writes_and_fsyncs_make_progress(self):
        read_interrupt = True
        write_interrupt = True
        fsync_interrupt = True

        def short_pread(descriptor: int, size: int, offset: int) -> bytes:
            nonlocal read_interrupt
            if read_interrupt:
                read_interrupt = False
                raise InterruptedError(errno.EINTR, "interrupted read")
            return self.harness.pread(descriptor, min(size, 997), offset)

        def short_pwrite(descriptor: int, data: bytes, offset: int) -> int:
            nonlocal write_interrupt
            if write_interrupt:
                write_interrupt = False
                raise InterruptedError(errno.EINTR, "interrupted write")
            return self.harness.pwrite(descriptor, data[: min(len(data), 983)], offset)

        def interrupted_fsync(descriptor: int) -> None:
            nonlocal fsync_interrupt
            if fsync_interrupt:
                fsync_interrupt = False
                raise InterruptedError(errno.EINTR, "interrupted fsync")
            self.harness.fsync(descriptor)

        result = self.harness.execute(operations=self.harness.operations(
            pread=short_pread,
            pwrite=short_pwrite,
            fsync=interrupted_fsync,
        ))
        self.assertEqual(result.readback_sha256, hashlib.sha256(self.harness.image).hexdigest())
        self.assertEqual(self.harness.target_bytes(SOURCE_SIZE), self.harness.image)
        self.assertFalse(read_interrupt)
        self.assertFalse(write_interrupt)
        self.assertFalse(fsync_interrupt)

    def test_invalid_short_io_progress_fails_closed(self):
        for value in (b"", bytearray(b"x"), None):
            with self.subTest(read=value):
                with self.assertRaises((HelperError, HelperSourceError)):
                    self.harness.execute(
                        operations=self.harness.operations(
                            pread=lambda _fd, _size, _offset, value=value: value,
                        ),
                    )
                self.assertEqual(self.harness.open_flags, [])

        for value in (0, -1, 10_000_000, None):
            with self.subTest(write=value):
                with self.assertRaisesRegex(HelperError, "invalid progress"):
                    self.harness.execute(
                        operations=self.harness.operations(
                            pwrite=lambda _fd, _data, _offset, value=value: value,
                        ),
                    )
                self.assertTrue(self.harness.close_calls)


if __name__ == "__main__":
    unittest.main()
