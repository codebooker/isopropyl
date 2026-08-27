# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from isopropyl.backup import (
    VHD_MAX_SIZE, BackupPublishError, DriveImager, VirtualBackupError,
    VirtualDriveImager, copy_exact, virtual_backup_required_space,
)
from isopropyl.devices import Device
from isopropyl.writer import WriteCancelled, WriterError, WriterSafetyError


def removable_device(**changes) -> Device:
    values = dict(
        path="/dev/sdz", size=15, model="Flash", vendor="Acme",
        transport="usb", serial="SERIAL", wwn="WWN", major_minor="65:144",
        removable=True, hotplug=True, read_only=False,
        mountpoints=("/media/usb",), partitions=("/dev/sdz1",),
    )
    values.update(changes)
    return Device(**values)


def trusted_tool(name: str) -> str:
    return f"/usr/bin/{name}"


def block_status(major_minor=(65, 144)):
    return SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=os.makedev(*major_minor))


def completed(code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class FakeReadProcess:
    def __init__(
        self, argv, *, data=b"removable drive", error=b"", code=0,
        running=False, on_wait=None, **kwargs,
    ):
        self.argv = argv
        self.kwargs = kwargs
        self.stdout = io.BytesIO(data)
        self.stderr = io.BytesIO(error)
        self.returncode = None if running else code
        self.completion_code = code
        self.on_wait = on_wait
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.on_wait:
            callback, self.on_wait = self.on_wait, None
            callback()
        if self.returncode is None:
            self.returncode = self.completion_code
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9


class FakeQemuProcess:
    def __init__(self, argv, *, on_wait=None, running=False, error=b"", code=0, **kwargs):
        self.argv = argv
        self.kwargs = kwargs
        self.on_wait = on_wait
        raw = Path(argv[-2])
        self.raw_contents = raw.read_bytes()
        self.raw_mode = raw.stat().st_mode & 0o777
        self.directory_mode = raw.parent.stat().st_mode & 0o777
        self.output = Path(argv[-1])
        if argv[1] == "convert":
            self.output.write_bytes(b"virtual container" + b"\0" * 495)
        self.stdout = io.BytesIO(b"(0.00/100%)\r(50.00/100%)\r(100.00/100%)\r")
        self.stderr = io.BytesIO(error)
        self.returncode = None if running else code
        self.completion_code = code
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.on_wait:
            callback, self.on_wait = self.on_wait, None
            callback()
        if self.returncode is None:
            self.returncode = self.completion_code
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9


class BackupHarness:
    def __init__(self, device=None):
        self.device = device or removable_device()
        self.current = self.device
        self.run_calls = []
        self.processes = []
        self.process_factory = lambda argv, kwargs: FakeReadProcess(argv, **kwargs)

    def lookup(self, _path):
        return self.current

    def runner(self, argv, **kwargs):
        self.run_calls.append((argv, kwargs))
        return completed()

    def popen(self, argv, **kwargs):
        process = self.process_factory(argv, kwargs)
        self.processes.append(process)
        return process

    def imager(self, *, block_stat_func=None, destination_on_device=None):
        return DriveImager(
            which=trusted_tool, runner=self.runner, popen=self.popen,
            device_lookup=self.lookup,
            block_stat=block_stat_func or (lambda _path: block_status()),
            destination_on_device=(
                destination_on_device or (lambda _path, _device: False)
            ),
        )


class BackupTests(unittest.TestCase):
    def test_copies_exact_bytes_and_reports_progress(self):
        source = io.BytesIO(b"removable drive")
        destination = io.BytesIO()
        updates = []
        copy_exact(source, destination, 15, lambda done, total: updates.append((done, total)))
        self.assertEqual(destination.getvalue(), b"removable drive")
        self.assertEqual(updates[-1], (15, 15))

    def test_refuses_a_short_source(self):
        with self.assertRaises(OSError):
            copy_exact(io.BytesIO(b"short"), io.BytesIO(), 10, lambda _d, _t: None)

    def test_honors_cancellation(self):
        with self.assertRaises(WriteCancelled):
            copy_exact(
                io.BytesIO(b"content"), io.BytesIO(), 7, lambda _d, _t: None,
                cancelled=lambda: True,
            )

    def test_sparse_copy_keeps_logical_contents_and_length(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sparse.img"
            data = b"\0" * 4096
            with path.open("w+b") as output:
                copy_exact(io.BytesIO(data), output, len(data), lambda _d, _t: None, sparse=True)
            self.assertEqual(path.stat().st_size, len(data))
            self.assertEqual(path.read_bytes(), data)

    def test_backup_revalidates_and_uses_bounded_exact_shell_free_read(self):
        harness = BackupHarness()
        updates = []
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "backup.img"
            harness.imager().backup(
                harness.device, destination,
                lambda done, total: updates.append((done, total)),
            )
            self.assertEqual(destination.read_bytes(), b"removable drive")
            self.assertEqual(list(Path(directory).glob(".backup.img.*.partial")), [])
        process = harness.processes[0]
        self.assertEqual(
            process.argv[:9],
            [
                "/usr/bin/pkexec", "/usr/bin/flock", "--exclusive",
                "--nonblock", "--conflict-exit-code", "75", "--no-fork",
                "/dev/sdz", "/usr/bin/dd",
            ],
        )
        self.assertIn("count=15", process.argv)
        self.assertIn("iflag=fullblock,count_bytes", process.argv)
        self.assertFalse(process.kwargs["shell"])
        self.assertEqual(updates[-1], (15, 15))
        self.assertTrue(all(call[1]["shell"] is False for call in harness.run_calls))

    def test_backup_lock_conflict_is_reported_without_publication(self):
        harness = BackupHarness()
        harness.process_factory = lambda argv, kwargs: FakeReadProcess(
            argv, code=75, error=b"busy", **kwargs,
        )
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "backup.img"
            with self.assertRaisesRegex(WriterError, "lock-aware"):
                harness.imager().backup(
                    harness.device, destination, lambda _d, _t: None,
                )
            self.assertFalse(destination.exists())

    def test_destination_relationship_change_stops_before_privileged_read(self):
        harness = BackupHarness()
        observations = iter((False, False, True))
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "backup.img"
            with self.assertRaisesRegex(WriterSafetyError, "moved onto"):
                harness.imager(
                    destination_on_device=lambda _path, _device: next(observations),
                ).backup(harness.device, destination, lambda _d, _t: None)
            self.assertFalse(destination.exists())
        self.assertEqual(harness.processes, [])

    def test_read_only_removable_media_can_be_backed_up(self):
        harness = BackupHarness(removable_device(read_only=True))
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "backup.img"
            harness.imager().backup(harness.device, destination, lambda _d, _t: None)
            self.assertTrue(destination.exists())

    def test_existing_destination_is_never_overwritten(self):
        harness = BackupHarness()
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "backup.img"
            destination.write_bytes(b"keep me")
            with self.assertRaisesRegex(WriterSafetyError, "already exists"):
                harness.imager().backup(harness.device, destination, lambda _d, _t: None)
            self.assertEqual(destination.read_bytes(), b"keep me")
        self.assertEqual(harness.run_calls, [])
        self.assertEqual(harness.processes, [])

    def test_destination_race_cannot_clobber_another_file(self):
        harness = BackupHarness()
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "backup.img"

            def process_factory(argv, kwargs):
                return FakeReadProcess(
                    argv, on_wait=lambda: destination.write_bytes(b"racing file"), **kwargs,
                )

            harness.process_factory = process_factory
            with self.assertRaisesRegex(WriterSafetyError, "already exists"):
                harness.imager().backup(harness.device, destination, lambda _d, _t: None)
            self.assertEqual(destination.read_bytes(), b"racing file")
            self.assertEqual(list(Path(directory).glob(".backup.img.*.partial")), [])

    def test_publication_failure_truthfully_reports_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            temporary = root / ".backup.partial"
            destination = root / "backup.img"
            temporary.write_bytes(b"image")
            with (
                patch("isopropyl.backup.os.fsync", side_effect=OSError("injected")),
                self.assertRaises(BackupPublishError) as raised,
            ):
                DriveImager._commit_without_overwrite(temporary, destination)

            self.assertTrue(raised.exception.published)
            self.assertIn("was published", str(raised.exception))
            self.assertEqual(destination.read_bytes(), b"image")
            self.assertFalse(temporary.exists())

    def test_identity_change_after_unmount_stops_before_privileged_read(self):
        harness = BackupHarness()

        def runner(argv, **kwargs):
            harness.run_calls.append((argv, kwargs))
            if "unmount" in argv:
                harness.current = removable_device(serial="REPLACED")
            return completed()

        harness.runner = runner
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(WriterSafetyError, "identity changed"):
                harness.imager().backup(
                    harness.device, Path(directory) / "backup.img", lambda _d, _t: None,
                )
        self.assertEqual(harness.processes, [])

    def test_identity_change_after_read_discards_complete_temporary(self):
        harness = BackupHarness()
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "backup.img"
            harness.process_factory = lambda argv, kwargs: FakeReadProcess(
                argv,
                on_wait=lambda: setattr(
                    harness, "current", removable_device(serial="REPLACED")
                ),
                **kwargs,
            )
            with self.assertRaisesRegex(WriterSafetyError, "identity changed"):
                harness.imager().backup(harness.device, destination, lambda _d, _t: None)
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(directory).glob(".backup.img.*.partial")), [])

    def test_actual_block_number_mismatch_stops_before_unmount(self):
        harness = BackupHarness()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(WriterSafetyError, "kernel device number"):
                harness.imager(
                    block_stat_func=lambda _path: block_status((8, 1))
                ).backup(
                    harness.device, Path(directory) / "backup.img", lambda _d, _t: None,
                )
        self.assertEqual(harness.run_calls, [])
        self.assertEqual(harness.processes, [])

    def test_callback_failure_terminates_reader_and_removes_temporary(self):
        harness = BackupHarness()
        harness.process_factory = lambda argv, kwargs: FakeReadProcess(
            argv, running=True, **kwargs,
        )
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "backup.img"
            with self.assertRaisesRegex(RuntimeError, "callback failed"):
                harness.imager().backup(
                    harness.device, destination,
                    lambda _d, _t: (_ for _ in ()).throw(RuntimeError("callback failed")),
                )
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(directory).glob(".backup.img.*.partial")), [])
        self.assertTrue(harness.processes[0].terminated)

    def test_cancel_before_start_and_worker_reuse_fail_closed(self):
        harness = BackupHarness()
        imager = harness.imager()
        imager.cancel()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(WriteCancelled):
                imager.backup(
                    harness.device, Path(directory) / "backup.img", lambda _d, _t: None,
                )
        self.assertEqual(harness.run_calls, [])
        self.assertEqual(harness.processes, [])


class VirtualBackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.tool = self.root / "qemu-img"
        self.tool.write_bytes(b"trusted qemu-img")
        self.tool.chmod(0o700)
        self.device = removable_device(size=4096)
        self.raw_data = bytes(range(256)) * 16
        self.qemu_processes = []
        self.info_calls = []
        self.info_payload = {
            "format": "vhdx", "virtual-size": self.device.size,
            "actual-size": 1024,
            "format-specific": {"type": "vhdx", "data": {}},
        }

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def ample_space(_path):
        return SimpleNamespace(total=10**12, used=0, free=10**12)

    def info_runner(self, argv, **kwargs):
        self.info_calls.append((argv, kwargs))
        return subprocess.CompletedProcess(
            argv, 0, json.dumps(self.info_payload).encode(), b"",
        )

    def qemu_popen(self, argv, **kwargs):
        process = FakeQemuProcess(argv, **kwargs)
        self.qemu_processes.append(process)
        return process

    def harness(self):
        harness = BackupHarness(self.device)
        harness.process_factory = lambda argv, kwargs: FakeReadProcess(
            argv, data=self.raw_data, **kwargs,
        )
        return harness

    def imager(self, harness=None, **changes):
        harness = harness or self.harness()
        values = dict(
            raw_imager=harness.imager(), qemu_img=self.tool,
            qemu_runner=self.info_runner, qemu_popen=self.qemu_popen,
            disk_usage=self.ample_space,
        )
        values.update(changes)
        return VirtualDriveImager(**values), harness

    def test_vhd_and_vhdx_capture_privately_validate_and_atomically_publish(self):
        for suffix, image_format in ((".vhd", "vpc"), (".VHDX", "vhdx")):
            with self.subTest(suffix=suffix):
                self.info_payload["format"] = image_format
                self.info_payload["format-specific"]["type"] = image_format
                imager, harness = self.imager(
                    disk_usage=lambda _path: SimpleNamespace(free=10**16),
                )
                destination = self.root / f"drive{suffix}"
                updates = []
                imager.backup(
                    self.device, destination,
                    lambda done, total: updates.append((done, total)),
                )

                self.assertTrue(destination.read_bytes().startswith(b"virtual container"))
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
                self.assertEqual(updates[-1], (12288, 12288))
                self.assertEqual(len(harness.processes), 1)
                convert, compare = self.qemu_processes[-2:]
                expected_convert = [
                    str(self.tool), "convert", "-p", "-f", "raw", "-T", "none",
                    "-O", image_format,
                ]
                if image_format == "vpc":
                    expected_convert.extend(("-o", "force_size=on"))
                expected_convert.extend((convert.argv[-2], convert.argv[-1]))
                self.assertEqual(convert.argv, expected_convert)
                self.assertEqual(compare.argv, [
                    str(self.tool), "compare", "-p", "-f", "raw", "-F",
                    image_format, "-T", "none",
                    convert.argv[-2], convert.argv[-1],
                ])
                self.assertNotIn("-s", compare.argv)
                self.assertFalse(convert.kwargs["shell"])
                self.assertFalse(compare.kwargs["shell"])
                self.assertEqual(convert.raw_contents, self.raw_data)
                self.assertEqual(convert.raw_mode, 0o600)
                self.assertEqual(convert.directory_mode, 0o700)
                info_argv, info_kwargs = self.info_calls[-1]
                self.assertEqual(info_argv[:3], [str(self.tool), "info", "--output=json"])
                self.assertFalse(info_kwargs["shell"])
                self.assertEqual(list(self.root.glob(f".{destination.name}.*.private")), [])

    def test_preflight_rejects_bad_suffix_capacity_and_existing_destination(self):
        imager, harness = self.imager()
        with self.assertRaisesRegex(WriterSafetyError, r"\.vhd or \.vhdx"):
            imager.backup(self.device, self.root / "drive.img", lambda _d, _t: None)
        self.assertEqual(harness.processes, [])

        VirtualDriveImager._validate_size("vpc", VHD_MAX_SIZE)
        with self.assertRaisesRegex(WriterSafetyError, "too large for VHD"):
            VirtualDriveImager._validate_size("vpc", VHD_MAX_SIZE + 512)

        destination = self.root / "existing.vhdx"
        destination.write_bytes(b"keep")
        imager, harness = self.imager()
        with self.assertRaisesRegex(WriterSafetyError, "already exists"):
            imager.backup(self.device, destination, lambda _d, _t: None)
        self.assertEqual(destination.read_bytes(), b"keep")
        self.assertEqual(harness.processes, [])

        imager, harness = self.imager(
            disk_usage=lambda _path: SimpleNamespace(
                free=virtual_backup_required_space(self.device.size) - 1,
            ),
        )
        with self.assertRaisesRegex(VirtualBackupError, "needs .* free bytes"):
            imager.backup(self.device, self.root / "full.vhdx", lambda _d, _t: None)
        self.assertEqual(harness.processes, [])

        imager, harness = self.imager(
            destination_on_device=lambda _path, _device: True,
        )
        with self.assertRaisesRegex(WriterSafetyError, "on the drive being imaged"):
            imager.backup(
                self.device, self.root / "on-source.vhdx", lambda _d, _t: None,
            )
        self.assertEqual(harness.processes, [])
        self.assertEqual(list(self.root.glob(".on-source.vhdx.*.private")), [])

    def test_qemu_is_bound_before_capture_and_change_aborts_before_conversion(self):
        harness = self.harness()

        def change_tool():
            self.tool.write_bytes(b"replacement qemu-img")
            self.tool.chmod(0o700)

        harness.process_factory = lambda argv, kwargs: FakeReadProcess(
            argv, data=self.raw_data, on_wait=change_tool, **kwargs,
        )
        imager, _ = self.imager(harness)
        destination = self.root / "changed.vhdx"
        with self.assertRaisesRegex(VirtualBackupError, "qemu-img changed"):
            imager.backup(self.device, destination, lambda _d, _t: None)
        self.assertFalse(destination.exists())
        self.assertEqual(self.qemu_processes, [])
        self.assertEqual(list(self.root.glob(".changed.vhdx.*.private")), [])

    def test_raw_capture_change_during_conversion_is_rejected(self):
        def mutating_qemu(argv, **kwargs):
            raw = Path(argv[-2])
            before = raw.stat()

            def mutate_raw():
                raw.write_bytes(b"x" * self.device.size)
                os.utime(raw, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))

            process = FakeQemuProcess(argv, on_wait=mutate_raw, **kwargs)
            self.qemu_processes.append(process)
            return process

        imager, _harness = self.imager(qemu_popen=mutating_qemu)
        destination = self.root / "mutated.vhdx"
        with self.assertRaisesRegex(VirtualBackupError, "raw capture.*changed"):
            imager.backup(self.device, destination, lambda _d, _t: None)
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".mutated.vhdx.*.private")), [])

    def test_destination_directory_rebind_is_detected_and_cleaned_by_descriptor(self):
        parent = self.root / "destination"
        moved = self.root / "destination-moved"
        parent.mkdir()

        def rebind_parent():
            parent.rename(moved)
            parent.mkdir()

        def rebinding_qemu(argv, **kwargs):
            process = FakeQemuProcess(
                argv,
                on_wait=rebind_parent if argv[1] == "convert" else None,
                **kwargs,
            )
            self.qemu_processes.append(process)
            return process

        imager, _harness = self.imager(qemu_popen=rebinding_qemu)
        destination = parent / "rebound.vhdx"
        with self.assertRaisesRegex(
            WriterSafetyError, "renamed or replaced|moved or became unavailable",
        ):
            imager.backup(self.device, destination, lambda _d, _t: None)

        self.assertFalse(destination.exists())
        self.assertEqual(list(parent.iterdir()), [])
        self.assertEqual(list(moved.iterdir()), [])

    def test_destination_rebind_during_raw_capture_cannot_leak_private_raw(self):
        parent = self.root / "raw-destination"
        moved = self.root / "raw-destination-moved"
        parent.mkdir()
        harness = self.harness()

        def rebind_during_privileged_read(argv, kwargs):
            workspace = next(parent.iterdir())
            parent.rename(moved)
            parent.mkdir()
            (parent / workspace.name).mkdir(mode=0o700)
            return FakeReadProcess(argv, data=self.raw_data, **kwargs)

        harness.process_factory = rebind_during_privileged_read
        imager, _harness = self.imager(harness)
        destination = parent / "raw-rebound.vhdx"
        with self.assertRaisesRegex(
            WriterSafetyError, "renamed or replaced|moved or became unavailable",
        ):
            imager.backup(self.device, destination, lambda _d, _t: None)

        self.assertEqual(len(harness.processes), 1)
        self.assertEqual(self.qemu_processes, [])
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.rglob("capture.raw")), [])
        self.assertEqual(list(self.root.rglob("*.partial")), [])
        self.assertEqual(list(moved.iterdir()), [])
        replacement_workspaces = list(parent.glob(".raw-rebound.vhdx.*.private"))
        self.assertEqual(len(replacement_workspaces), 1)
        self.assertEqual(list(replacement_workspaces[0].iterdir()), [])

    def test_output_mutation_after_compare_stops_immediate_publication(self):
        harness = self.harness()

        class MutatingVirtualImager(VirtualDriveImager):
            def _convert(inner_self, *args, **kwargs):
                identity = super()._convert(*args, **kwargs)
                output = args[2]
                output.write_bytes(output.read_bytes() + b"mutation")
                return identity

        imager = MutatingVirtualImager(
            raw_imager=harness.imager(), qemu_img=self.tool,
            qemu_runner=self.info_runner, qemu_popen=self.qemu_popen,
            disk_usage=self.ample_space,
        )
        destination = self.root / "post-compare-mutation.vhdx"
        with self.assertRaisesRegex(
            VirtualBackupError, "changed immediately before publication",
        ):
            imager.backup(self.device, destination, lambda _d, _t: None)
        self.assertFalse(destination.exists())
        self.assertEqual(
            list(self.root.glob(".post-compare-mutation.vhdx.*.private")), [],
        )

    def test_free_space_is_rechecked_after_the_exact_raw_capture(self):
        calls = 0

        def shrinking_space(_path):
            nonlocal calls
            calls += 1
            if calls == 1:
                return SimpleNamespace(free=virtual_backup_required_space(self.device.size))
            return SimpleNamespace(free=self.device.size)

        imager, harness = self.imager(disk_usage=shrinking_space)
        destination = self.root / "shrunk.vhdx"
        with self.assertRaisesRegex(VirtualBackupError, "free space changed"):
            imager.backup(self.device, destination, lambda _d, _t: None)
        self.assertEqual(len(harness.processes), 1)
        self.assertEqual(self.qemu_processes, [])
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".shrunk.vhdx.*.private")), [])

    def test_unsafe_or_unexpected_output_metadata_is_never_published(self):
        cases = (
            ({
                "format": "vhdx", "virtual-size": 4096,
                "backing-filename": "attacker.raw",
            }, "backing"),
            ({
                "format": "vhdx", "virtual-size": 4096,
                "snapshots": [{"id": "unexpected"}],
            }, "snapshots"),
            ({"format": "vpc", "virtual-size": 4096}, "unexpected format"),
        )
        for payload, message in cases:
            with self.subTest(message=message):
                self.info_payload = payload
                destination = self.root / "unsafe.vhdx"
                imager, _harness = self.imager()
                with self.assertRaisesRegex(VirtualBackupError, message):
                    imager.backup(self.device, destination, lambda _d, _t: None)
                self.assertFalse(destination.exists())
                self.assertEqual(list(self.root.glob(".unsafe.vhdx.*.private")), [])

    def test_virtual_size_mismatch_fails_before_compare_or_publication(self):
        self.info_payload = {"format": "vhdx", "virtual-size": 3584}
        imager, _harness = self.imager()
        destination = self.root / "wrong-size.vhdx"
        with self.assertRaisesRegex(VirtualBackupError, "unexpected format or virtual size"):
            imager.backup(self.device, destination, lambda _d, _t: None)
        self.assertEqual([process.argv[1] for process in self.qemu_processes], ["convert"])
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".wrong-size.vhdx.*.private")), [])

    def test_destination_race_is_preserved_and_private_files_are_removed(self):
        destination = self.root / "race.vhdx"

        def racing_info(argv, **kwargs):
            destination.write_bytes(b"racing file")
            return self.info_runner(argv, **kwargs)

        imager, _harness = self.imager(qemu_runner=racing_info)
        with self.assertRaisesRegex(WriterSafetyError, "already exists"):
            imager.backup(self.device, destination, lambda _d, _t: None)
        self.assertEqual(destination.read_bytes(), b"racing file")
        self.assertEqual(list(self.root.glob(".race.vhdx.*.private")), [])

    def test_published_backup_reports_sensitive_raw_cleanup_failure(self):
        destination = self.root / "cleanup-failure.vhdx"
        imager, _harness = self.imager()
        original_unlink = os.unlink

        def refuse_raw_capture(path, *args, **kwargs):
            if path == "capture.raw":
                raise PermissionError("injected raw cleanup refusal")
            return original_unlink(path, *args, **kwargs)

        with (
            patch("isopropyl.backup.os.unlink", new=refuse_raw_capture),
            self.assertRaisesRegex(
                VirtualBackupError,
                "safely published.*sensitive exact raw drive capture",
            ),
        ):
            imager.backup(self.device, destination, lambda _d, _t: None)

        self.assertTrue(destination.exists())
        private_directories = list(
            self.root.glob(".cleanup-failure.vhdx.*.private")
        )
        self.assertEqual(len(private_directories), 1)
        raw = private_directories[0] / "capture.raw"
        self.assertEqual(raw.read_bytes(), self.raw_data)
        raw.unlink()
        private_directories[0].rmdir()

    def test_cancellation_during_qemu_terminates_and_cleans_private_capture(self):
        started = threading.Event()

        def blocking_qemu(argv, **kwargs):
            process = FakeQemuProcess(argv, running=True, **kwargs)
            self.qemu_processes.append(process)
            started.set()
            return process

        imager, _harness = self.imager(qemu_popen=blocking_qemu)
        destination = self.root / "cancel.vhdx"
        errors = []

        def run_backup():
            try:
                imager.backup(self.device, destination, lambda _d, _t: None)
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=run_backup)
        worker.start()
        self.assertTrue(started.wait(2))
        imager.cancel()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertTrue(errors and isinstance(errors[0], WriteCancelled))
        self.assertTrue(self.qemu_processes[-1].terminated)
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".cancel.vhdx.*.private")), [])

    def test_content_compare_mismatch_or_error_never_publishes(self):
        for code, diagnostic, message in (
            (1, b"", "does not match"),
            (4, b"read error", "read error"),
        ):
            with self.subTest(code=code):
                def failing_compare(argv, **kwargs):
                    process = FakeQemuProcess(
                        argv,
                        code=code if argv[1] == "compare" else 0,
                        error=diagnostic if argv[1] == "compare" else b"",
                        **kwargs,
                    )
                    self.qemu_processes.append(process)
                    return process

                imager, _harness = self.imager(qemu_popen=failing_compare)
                destination = self.root / "mismatch.vhdx"
                with self.assertRaisesRegex(VirtualBackupError, message):
                    imager.backup(self.device, destination, lambda _d, _t: None)
                self.assertFalse(destination.exists())
                self.assertEqual(list(self.root.glob(".mismatch.vhdx.*.private")), [])

    def test_cancellation_during_content_compare_is_bounded_and_cleans_up(self):
        compare_started = threading.Event()

        def blocking_compare(argv, **kwargs):
            running = argv[1] == "compare"
            process = FakeQemuProcess(argv, running=running, **kwargs)
            self.qemu_processes.append(process)
            if running:
                compare_started.set()
            return process

        imager, _harness = self.imager(qemu_popen=blocking_compare)
        destination = self.root / "compare-cancel.vhdx"
        errors = []

        def run_backup():
            try:
                imager.backup(self.device, destination, lambda _d, _t: None)
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=run_backup)
        worker.start()
        self.assertTrue(compare_started.wait(2))
        imager.cancel()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertTrue(errors and isinstance(errors[0], WriteCancelled))
        compare = self.qemu_processes[-1]
        self.assertEqual(compare.argv[1], "compare")
        self.assertTrue(compare.terminated)
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".compare-cancel.vhdx.*.private")), [])

    def test_stubborn_qemu_kill_timeout_still_cleans_private_workspace(self):
        started = threading.Event()

        class StubbornQemuProcess(FakeQemuProcess):
            def poll(self):
                return None

            def wait(self, timeout=None):
                raise subprocess.TimeoutExpired(self.argv, timeout or 0)

            def terminate(self):
                self.terminated = True

            def kill(self):
                self.killed = True

        def stubborn_qemu(argv, **kwargs):
            process = StubbornQemuProcess(argv, running=True, **kwargs)
            self.qemu_processes.append(process)
            started.set()
            return process

        imager, _harness = self.imager(qemu_popen=stubborn_qemu)
        destination = self.root / "stubborn.vhdx"
        errors = []

        def run_backup():
            try:
                imager.backup(self.device, destination, lambda _d, _t: None)
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=run_backup)
        worker.start()
        self.assertTrue(started.wait(2))
        imager.cancel()
        worker.join(3)

        self.assertFalse(worker.is_alive())
        self.assertTrue(errors)
        self.assertIn("did not stop", str(errors[0]))
        self.assertTrue(self.qemu_processes[-1].killed)
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".stubborn.vhdx.*.private")), [])

if __name__ == "__main__":
    unittest.main()
