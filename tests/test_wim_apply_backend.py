# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import io
import fcntl
import os
import stat
import struct
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from isopropyl.wim import WimCancelled
from isopropyl.wim_apply_backend import (
    MAX_NTFS_TARGET_BYTES,
    NTFS_BOOT_SIGNATURE,
    NTFS_OEM_ID,
    WIM_HEADER_MAGIC,
    WimApplyBackendError,
    WimApplyCertificationPlan,
    WimApplyTargetContaminated,
    _hash_descriptor,
    _require_locked_down_process,
    apply_wim_to_certification_image,
    inspect_ntfs_target_descriptor,
    inspect_wim_source_descriptor,
    lock_down_wim_apply_process,
    validate_wim_apply_certification_plan,
    wimlib_apply_command,
)


SERIAL = 0x0123456789ABCDEF
START_SECTOR = 796_672
TARGET_SIZE = 1024 * 1024


def ntfs_boot(*, serial: int = SERIAL) -> bytes:
    boot = bytearray(512)
    boot[:3] = b"\xebR\x90"
    boot[3:11] = NTFS_OEM_ID
    struct.pack_into("<H", boot, 11, 512)
    boot[13] = 8
    boot[21] = 0xF8
    struct.pack_into("<I", boot, 28, START_SECTOR)
    struct.pack_into("<Q", boot, 40, TARGET_SIZE // 512 - 1)
    struct.pack_into("<Q", boot, 48, 4)
    struct.pack_into("<Q", boot, 56, 8)
    boot[64] = 0xF6
    boot[68] = 1
    struct.pack_into("<Q", boot, 72, serial)
    boot[510:512] = NTFS_BOOT_SIGNATURE
    return bytes(boot)


class FakeProcess:
    def __init__(self, argv, *, stdout_data=b"", stderr_data=b"", code=0, **kwargs):
        self.argv = argv
        self.kwargs = kwargs
        self.stdout = io.BytesIO(stdout_data)
        self.stderr = io.BytesIO(stderr_data)
        self.returncode = code
        self.terminated = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.argv, timeout)
        return self.returncode


class WimApplyBackendTests(unittest.TestCase):
    def setUp(self):
        isolation = patch(
            "isopropyl.wim_apply_backend._require_locked_down_process",
        )
        isolation.start()
        self.addCleanup(isolation.stop)
        self.temporary = tempfile.TemporaryDirectory()
        os.chmod(self.temporary.name, 0o700)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source.wim"
        self.source.write_bytes(WIM_HEADER_MAGIC + b"fixture payload")
        self.target = self.root / "target.img"
        self.reset_target()
        self.digest = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.plan = WimApplyCertificationPlan(
            source_size=self.source.stat().st_size,
            source_sha256=self.digest,
            image_index=3,
            target_size=TARGET_SIZE,
            fresh_target_sha256=hashlib.sha256(self.target.read_bytes()).hexdigest(),
            partition_start_sector=START_SECTOR,
            ntfs_volume_serial=SERIAL,
            temporary_directory=self.temporary.name,
        )

    def reset_target(self):
        with self.target.open("wb") as stream:
            stream.truncate(TARGET_SIZE)
        os.chmod(self.target, 0o600)
        with self.target.open("r+b") as stream:
            boot = ntfs_boot()
            stream.write(boot)
            stream.seek(TARGET_SIZE - 512)
            stream.write(boot)

    def tearDown(self):
        self.temporary.cleanup()

    def descriptors(self):
        source = os.open(self.source, os.O_RDONLY | os.O_CLOEXEC)
        target = os.open(self.target, os.O_RDWR | os.O_CLOEXEC)
        os.unlink(self.target)
        return source, target

    def test_validates_exact_source_ntfs_identity_and_command(self):
        source, target = self.descriptors()
        try:
            self.assertEqual(
                inspect_wim_source_descriptor(
                    source,
                    expected_size=self.plan.source_size,
                    expected_sha256=self.digest,
                ),
                self.digest,
            )
            ntfs = inspect_ntfs_target_descriptor(
                target,
                expected_size=TARGET_SIZE,
                expected_start_sector=START_SECTOR,
                expected_volume_serial=SERIAL,
            )
            self.assertEqual(ntfs.volume_serial, SERIAL)
            self.assertEqual(ntfs.total_sectors, TARGET_SIZE // 512 - 1)
            command = wimlib_apply_command(self.plan, source, target)
            self.assertEqual(
                command,
                (
                    "/usr/bin/wimlib-imagex",
                    "apply",
                    "--check",
                    "--norpfix",
                    "--strict-acls",
                    "--quiet",
                    "--",
                    f"/proc/self/fd/{source}",
                    "3",
                    f"/proc/self/fd/{target}",
                ),
            )
        finally:
            os.close(source)
            os.close(target)

    def test_rejects_writable_source_and_bpb_identity_mutations(self):
        writable = os.open(self.source, os.O_RDWR | os.O_CLOEXEC)
        try:
            with self.assertRaises(WimApplyBackendError):
                inspect_wim_source_descriptor(
                    writable,
                    expected_size=self.plan.source_size,
                    expected_sha256=self.digest,
                )
        finally:
            os.close(writable)

        mutations = (
            (3, b"BADFS   "),
            (28, (1).to_bytes(4, "little")),
            (40, (1).to_bytes(8, "little")),
            (72, (1).to_bytes(8, "little")),
            (510, b"\0\0"),
        )
        original = ntfs_boot()
        target = os.open(self.target, os.O_RDWR | os.O_CLOEXEC)
        os.unlink(self.target)
        try:
            for offset, value in mutations:
                with self.subTest(offset=offset):
                    os.pwrite(target, original, 0)
                    os.pwrite(target, value, offset)
                    with self.assertRaises(WimApplyBackendError):
                        inspect_ntfs_target_descriptor(
                            target,
                            expected_size=TARGET_SIZE,
                            expected_start_sector=START_SECTOR,
                            expected_volume_serial=SERIAL,
                        )
        finally:
            os.close(target)

    def test_explicitly_rejects_block_device_status(self):
        target = os.open(self.target, os.O_RDWR | os.O_CLOEXEC)
        fake = os.stat_result((stat.S_IFBLK | 0o600, 0, 0, 1, 0, 0, TARGET_SIZE, 0, 0, 0))
        try:
            with patch("isopropyl.wim_apply_backend._descriptor_status", return_value=fake):
                with self.assertRaisesRegex(WimApplyBackendError, "not certified"):
                    inspect_ntfs_target_descriptor(
                        target,
                        expected_size=TARGET_SIZE,
                        expected_start_sector=START_SECTOR,
                        expected_volume_serial=SERIAL,
                    )
        finally:
            os.close(target)

    def test_rejects_named_or_public_target_before_apply(self):
        named = os.open(self.target, os.O_RDWR | os.O_CLOEXEC)
        try:
            with self.assertRaisesRegex(WimApplyBackendError, "anonymous"):
                inspect_ntfs_target_descriptor(
                    named,
                    expected_size=TARGET_SIZE,
                    expected_start_sector=START_SECTOR,
                    expected_volume_serial=SERIAL,
                )
        finally:
            os.close(named)

    def test_process_isolation_gate_rejects_dumpable_owner(self):
        with (
            patch("isopropyl.wim_apply_backend._prctl", return_value=1),
            self.assertRaisesRegex(WimApplyBackendError, "non-dumpable"),
        ):
            _require_locked_down_process()

    def test_process_lockdown_sets_no_new_privileges_and_nondumpable(self):
        with patch(
            "isopropyl.wim_apply_backend._prctl",
            side_effect=(0, 1, 0, 0),
        ) as prctl:
            lock_down_wim_apply_process()
        self.assertEqual(
            [call.args for call in prctl.call_args_list],
            [(38, 1), (39,), (4, 0), (3,)],
        )

    def test_success_uses_sealed_environment_and_accepts_only_exact_warning(self):
        calls = []

        def popen(argv, **kwargs):
            calls.append((argv, kwargs))
            source_fd = int(argv[7].rsplit("/", 1)[1])
            warning = (
                b'\r[WARNING] "'
                + argv[7].encode("ascii")
                + b'" does not contain integrity information.  Skipping integrity check.\n'
            )
            self.assertEqual(source_fd, kwargs["pass_fds"][0])
            self.assertEqual(fcntl.fcntl(source_fd, fcntl.F_GETLEASE), fcntl.F_RDLCK)
            return FakeProcess(argv, stderr_data=warning, **kwargs)

        source, target = self.descriptors()
        try:
            with patch("isopropyl.wim_apply_backend._trusted_wimlib"):
                result = apply_wim_to_certification_image(
                    self.plan,
                    source,
                    target,
                    popen=popen,
                )
            self.assertEqual(fcntl.fcntl(source, fcntl.F_GETLEASE), fcntl.F_UNLCK)
        finally:
            os.close(source)
            os.close(target)
        self.assertTrue(result.missing_integrity_table)
        self.assertFalse(result.block_devices_supported)
        options = calls[0][1]
        self.assertEqual(options["cwd"], "/")
        self.assertEqual(
            options["env"],
            {
                "LC_ALL": "C",
                "LANG": "C",
                "TZ": "UTC",
                "TMPDIR": self.temporary.name,
            },
        )
        self.assertTrue(options["close_fds"])
        self.assertTrue(options["start_new_session"])

    def test_existing_source_writer_prevents_apply_before_child_start(self):
        called = []
        writer = os.open(self.source, os.O_WRONLY | os.O_CLOEXEC)
        source, target = self.descriptors()
        try:
            with patch("isopropyl.wim_apply_backend._trusted_wimlib"):
                with self.assertRaisesRegex(WimApplyBackendError, "write-excluded"):
                    apply_wim_to_certification_image(
                        self.plan,
                        source,
                        target,
                        popen=lambda *args, **kwargs: called.append((args, kwargs)),
                    )
        finally:
            os.close(writer)
            os.close(source)
            os.close(target)
        self.assertEqual(called, [])

    def test_non_bpb_target_reuse_fails_fresh_format_receipt_before_spawn(self):
        with self.target.open("r+b") as stream:
            stream.seek(4096)
            stream.write(b"previous user data")
        called = []
        source, target = self.descriptors()
        try:
            with patch("isopropyl.wim_apply_backend._trusted_wimlib"):
                with self.assertRaisesRegex(WimApplyBackendError, "fresh-format"):
                    apply_wim_to_certification_image(
                        self.plan,
                        source,
                        target,
                        popen=lambda *args, **kwargs: called.append((args, kwargs)),
                    )
        finally:
            os.close(source)
            os.close(target)
        self.assertEqual(called, [])

    def test_started_failure_unexpected_output_and_identity_drift_contaminate(self):
        def exercise(popen):
            self.reset_target()
            source, target = self.descriptors()
            try:
                with patch("isopropyl.wim_apply_backend._trusted_wimlib"):
                    with self.assertRaises(WimApplyTargetContaminated):
                        apply_wim_to_certification_image(
                            self.plan,
                            source,
                            target,
                            popen=popen,
                        )
            finally:
                os.close(source)
                os.close(target)

        exercise(lambda argv, **kwargs: FakeProcess(argv, code=5, **kwargs))
        exercise(
            lambda argv, **kwargs: FakeProcess(
                argv,
                stdout_data=b"unexpected",
                **kwargs,
            ),
        )

        def mutate(argv, **kwargs):
            target_fd = int(argv[9].rsplit("/", 1)[1])
            os.pwrite(target_fd, (SERIAL + 1).to_bytes(8, "little"), 72)
            return FakeProcess(argv, **kwargs)

        exercise(mutate)

        class BrokenStream(io.BytesIO):
            def read(self, _size=-1):
                raise OSError("broken diagnostic pipe")

        def broken_reader(argv, **kwargs):
            process = FakeProcess(argv, **kwargs)
            process.stdout = BrokenStream()
            return process

        exercise(broken_reader)

    def test_reader_thread_start_failure_contaminates_and_reaps_child(self):
        processes = []

        def popen(argv, **kwargs):
            process = FakeProcess(argv, code=0, **kwargs)
            process.returncode = None
            processes.append(process)
            return process

        class BrokenThread:
            def __init__(self, **_kwargs):
                pass

            def start(self):
                raise RuntimeError("thread unavailable")

            def join(self, timeout=None):
                pass

        source, target = self.descriptors()
        try:
            with (
                patch("isopropyl.wim_apply_backend._trusted_wimlib"),
                patch("isopropyl.wim.threading.Thread", BrokenThread),
            ):
                with self.assertRaises(WimApplyTargetContaminated):
                    apply_wim_to_certification_image(
                        self.plan,
                        source,
                        target,
                        popen=popen,
                    )
        finally:
            os.close(source)
            os.close(target)
        self.assertEqual(len(processes), 1)
        self.assertTrue(processes[0].terminated)

    def test_prestart_cancellation_is_not_reported_as_contamination(self):
        cancelled = threading.Event()
        cancelled.set()
        source, target = self.descriptors()
        try:
            with patch("isopropyl.wim_apply_backend._trusted_wimlib"):
                with self.assertRaises(WimApplyBackendError) as caught:
                    apply_wim_to_certification_image(
                        self.plan,
                        source,
                        target,
                        cancel_event=cancelled,
                    )
            self.assertNotIsInstance(caught.exception, WimApplyTargetContaminated)
        finally:
            os.close(source)
            os.close(target)

    def test_descriptor_hash_honors_midstream_cancellation_and_deadline(self):
        descriptor = os.open(self.source, os.O_RDONLY | os.O_CLOEXEC)

        class CancelAfterFirstCheck:
            checks = 0

            def is_set(self):
                self.checks += 1
                return self.checks > 1

        try:
            with (
                patch("isopropyl.wim_apply_backend.COPY_BYTES", 8),
                self.assertRaisesRegex(WimCancelled, "cancelled"),
            ):
                _hash_descriptor(
                    descriptor,
                    self.plan.source_size,
                    cancel_event=CancelAfterFirstCheck(),
                )
            with (
                patch("isopropyl.wim_apply_backend.time.monotonic", return_value=10),
                self.assertRaisesRegex(WimApplyBackendError, "timed out"),
            ):
                _hash_descriptor(descriptor, self.plan.source_size, deadline=5)
        finally:
            os.close(descriptor)

    def test_plan_rejects_public_or_forged_scratch_and_fields(self):
        os.chmod(self.temporary.name, 0o755)
        with self.assertRaises(WimApplyBackendError):
            validate_wim_apply_certification_plan(self.plan)
        os.chmod(self.temporary.name, 0o700)
        for changes in (
            {"source_size": 0},
            {"source_sha256": "A" * 64},
            {"image_index": 0},
            {"target_size": 0},
            {"target_size": MAX_NTFS_TARGET_BYTES + 1},
            {"fresh_target_sha256": "0" * 64},
            {"partition_start_sector": 0},
            {"ntfs_volume_serial": 0},
            {"temporary_directory": "relative"},
            {"wimlib_imagex": "/tmp/wimlib-imagex"},
        ):
            with self.subTest(changes=changes), self.assertRaises(WimApplyBackendError):
                validate_wim_apply_certification_plan(
                    WimApplyCertificationPlan(
                        **{**self.plan.__dict__, **changes},
                    ),
                )


if __name__ == "__main__":
    unittest.main()
