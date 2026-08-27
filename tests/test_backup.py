# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import io
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from isopropyl.backup import DriveImager, copy_exact
from isopropyl.devices import Device
from isopropyl.writer import WriteCancelled, WriterSafetyError


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

    def imager(self, *, block_stat_func=None):
        return DriveImager(
            which=trusted_tool, runner=self.runner, popen=self.popen,
            device_lookup=self.lookup,
            block_stat=block_stat_func or (lambda _path: block_status()),
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
        self.assertEqual(process.argv[:2], ["/usr/bin/pkexec", "/usr/bin/dd"])
        self.assertIn("count=15", process.argv)
        self.assertIn("iflag=fullblock,count_bytes", process.argv)
        self.assertFalse(process.kwargs["shell"])
        self.assertEqual(updates[-1], (15, 15))
        self.assertTrue(all(call[1]["shell"] is False for call in harness.run_calls))

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


if __name__ == "__main__":
    unittest.main()
