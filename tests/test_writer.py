# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import io
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from isopropyl.app import Bridge, looks_like_windows_image
from isopropyl.devices import Device
from isopropyl.writer import (
    MAX_DIAGNOSTIC_BYTES,
    ImageWriter,
    WriteCancelled,
    WriterError,
    WriterSafetyError,
    WriterToolUnavailable,
    resolve_writer_tools,
    sha256_file,
    validate_device_selection,
    verify_image,
)


def removable_device(**changes) -> Device:
    values = dict(
        path="/dev/sdz", size=12, model="Flash", vendor="Acme",
        transport="usb", serial="SERIAL", wwn="WWN", major_minor="65:144",
        removable=True, hotplug=True, read_only=False,
        mountpoints=("/media/usb",), partitions=("/dev/sdz1",),
    )
    values.update(changes)
    return Device(**values)


def trusted_tool(name: str) -> str:
    return f"/usr/bin/{name}"


def block_status(major_minor: tuple[int, int] = (65, 144)):
    return SimpleNamespace(
        st_mode=stat.S_IFBLK,
        st_rdev=os.makedev(*major_minor),
    )


def completed(code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class FakeProcess:
    def __init__(
        self, argv, *, stdout_data=b"", stderr_data=b"", code=0,
        running=False, on_wait=None, **kwargs,
    ):
        self.argv = argv
        self.kwargs = kwargs
        self.stdout = io.BytesIO(stdout_data) if kwargs.get("stdout") == subprocess.PIPE else None
        self.stderr = io.BytesIO(stderr_data) if kwargs.get("stderr") == subprocess.PIPE else None
        self.stdin = io.BytesIO() if kwargs.get("stdin") == subprocess.PIPE else None
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


class WriterHarness:
    def __init__(self, device: Device | None = None):
        self.device = device or removable_device()
        self.current = self.device
        self.run_calls = []
        self.processes = []
        self.process_factory = lambda argv, kwargs: FakeProcess(
            argv, stderr_data=f"{self.device.size} bytes copied\n".encode(), **kwargs,
        )

    def lookup(self, _path):
        return self.current

    def runner(self, argv, **kwargs):
        self.run_calls.append((argv, kwargs))
        return completed()

    def popen(self, argv, **kwargs):
        process = self.process_factory(argv, kwargs)
        self.processes.append(process)
        return process

    def writer(self):
        return ImageWriter(
            which=trusted_tool,
            runner=self.runner,
            popen=self.popen,
            device_lookup=self.lookup,
            block_stat=lambda _path: block_status(),
        )


class WriterTests(unittest.TestCase):
    def test_cancel_before_worker_starts_is_not_lost(self):
        writer = ImageWriter()
        writer.cancel()
        with self.assertRaises(WriteCancelled):
            writer.write(Path("unused.img"), removable_device(), lambda _d, _t: None)

    def test_progress_signal_does_not_overflow_at_four_gib(self):
        received = []
        bridge = Bridge()
        bridge.progress.connect(lambda done, total, stage: received.append((done, total, stage)))
        bridge.progress.emit(5_000_000_000, 6_000_000_000, "Writing")
        self.assertEqual(received, [(5_000_000_000, 6_000_000_000, "Writing")])

    def test_warns_for_obvious_windows_iso_name(self):
        self.assertTrue(looks_like_windows_image(Path("en-us_windows_11.iso")))
        self.assertFalse(looks_like_windows_image(Path("ubuntu-26.04.iso")))

    def test_hash_with_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data"
            path.write_bytes(b"abcdef")
            self.assertEqual(sha256_file(path, limit=3), hashlib.sha256(b"abc").hexdigest())

    def test_verifies_only_image_length(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            device = Path(directory) / "device"
            image.write_bytes(b"boot image")
            device.write_bytes(b"boot image" + b"old trailing bytes")
            self.assertTrue(verify_image(image, str(device), lambda _d, _t: None))

    def test_managed_regular_file_verification_progress_is_monotonic(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            device = Path(directory) / "device"
            image.write_bytes(b"verified data")
            device.write_bytes(b"verified data")
            updates = []
            self.assertTrue(
                ImageWriter().verify(
                    image, str(device), lambda done, total: updates.append((done, total)),
                )
            )
            self.assertEqual(updates[-1], (len(b"verified data") * 2,) * 2)
            self.assertEqual([done for done, _ in updates], sorted(done for done, _ in updates))

    @patch("isopropyl.writer.shutil.which")
    def test_tool_resolution_uses_only_fixed_system_path(self, which):
        which.side_effect = lambda name, path: f"/usr/bin/{name}"
        tools = resolve_writer_tools()
        self.assertEqual(tools.pkexec, "/usr/bin/pkexec")
        self.assertTrue(all(
            call.kwargs["path"] == "/usr/sbin:/usr/bin:/sbin:/bin"
            for call in which.call_args_list
        ))
        for unsafe in ("pkexec", "/tmp/pkexec", "/usr/bin/../bin/pkexec"):
            with self.subTest(unsafe=unsafe), self.assertRaises(WriterToolUnavailable):
                resolve_writer_tools(
                    lambda name, unsafe=unsafe: unsafe if name == "pkexec" else trusted_tool(name)
                )

    def test_device_selection_rejects_unsafe_whole_disks(self):
        unsafe = (
            removable_device(path="/dev/sdz1"),
            removable_device(transport="nvme", removable=False, hotplug=False),
            removable_device(removable=False, hotplug=False),
            removable_device(read_only=True),
            removable_device(mountpoints=("/",)),
            removable_device(partitions=("/dev/sdy1",)),
            removable_device(major_minor=""),
            removable_device(size=12.5),
            removable_device(removable=1),
            removable_device(partitions=["/dev/sdz1"]),
        )
        for device in unsafe:
            with self.subTest(device=device), self.assertRaises(WriterSafetyError):
                validate_device_selection(device, writable=True)
        # Reading a hardware write-protected removable drive for backup remains valid.
        validate_device_selection(removable_device(read_only=True), writable=False)

    def test_raw_write_revalidates_and_uses_absolute_shell_free_commands(self):
        harness = WriterHarness()
        writer = harness.writer()
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            image.write_bytes(b"hello world!")
            updates = []
            writer.write(image, harness.device, lambda done, total: updates.append((done, total)))
        self.assertEqual(updates[-1], (12, 12))
        argv = harness.processes[0].argv
        self.assertEqual(argv[:2], ["/usr/bin/pkexec", "/usr/bin/flock"])
        self.assertEqual(argv[2:9], [
            "--exclusive", "--nonblock", "--conflict-exit-code", "75",
            "--no-fork", "/dev/sdz", "/usr/bin/dd",
        ])
        self.assertIn("of=/dev/sdz", argv)
        self.assertFalse(harness.processes[0].kwargs["shell"])
        self.assertTrue(all(call[1]["shell"] is False for call in harness.run_calls))
        self.assertIn(
            ["/usr/bin/udisksctl", "unmount", "--block-device", "/dev/sdz1"],
            [call[0] for call in harness.run_calls],
        )

    def test_missing_or_untrusted_flock_fails_before_unmount(self):
        for value in (None, "flock", "/tmp/flock", "/usr/bin/../bin/flock"):
            with self.subTest(value=value):
                harness = WriterHarness()

                def finder(name, value=value):
                    return value if name == "flock" else trusted_tool(name)

                writer = ImageWriter(
                    which=finder, runner=harness.runner, popen=harness.popen,
                    device_lookup=harness.lookup,
                    block_stat=lambda _path: block_status(),
                )
                with self.assertRaises(WriterToolUnavailable):
                    writer.write(Path("unused.img"), harness.device, lambda _d, _t: None)
                self.assertEqual(harness.run_calls, [])
                self.assertEqual(harness.processes, [])

    def test_raw_write_lock_conflict_has_specific_message(self):
        harness = WriterHarness()
        harness.process_factory = lambda argv, kwargs: FakeProcess(
            argv, stderr_data=b"generic flock diagnostic", code=75, **kwargs,
        )
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            image.write_bytes(b"hello world!")
            with self.assertRaisesRegex(
                WriterError, "Another lock-aware storage operation",
            ):
                harness.writer().write(image, harness.device, lambda _d, _t: None)

    def test_actual_block_number_mismatch_stops_before_unmount_or_write(self):
        harness = WriterHarness()
        writer = ImageWriter(
            which=trusted_tool, runner=harness.runner, popen=harness.popen,
            device_lookup=harness.lookup,
            block_stat=lambda _path: block_status((8, 1)),
        )
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            image.write_bytes(b"hello world!")
            with self.assertRaisesRegex(WriterSafetyError, "kernel device number"):
                writer.write(image, harness.device, lambda _d, _t: None)
        self.assertEqual(harness.run_calls, [])
        self.assertEqual(harness.processes, [])

    def test_identity_change_during_unmount_stops_before_privileged_write(self):
        harness = WriterHarness()

        def runner(argv, **kwargs):
            harness.run_calls.append((argv, kwargs))
            if "unmount" in argv:
                harness.current = removable_device(serial="REPLACED")
            return completed()

        harness.runner = runner
        writer = harness.writer()
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            image.write_bytes(b"hello world!")
            with self.assertRaisesRegex(WriterSafetyError, "identity changed"):
                writer.write(image, harness.device, lambda _d, _t: None)
        self.assertEqual(harness.processes, [])

    def test_logical_sector_change_stops_before_unmount_or_write(self):
        selected = removable_device(logical_sector_size=512)
        harness = WriterHarness(selected)
        harness.current = removable_device(logical_sector_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            image.write_bytes(b"hello world!")

            with self.assertRaisesRegex(WriterSafetyError, "logical sector size changed"):
                harness.writer().write(
                    image, selected, lambda _d, _t: None,
                )

        self.assertEqual(harness.run_calls, [])
        self.assertEqual(harness.processes, [])

    def test_source_change_during_unmount_stops_before_privileged_write(self):
        harness = WriterHarness()
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            image.write_bytes(b"hello world!")

            def runner(argv, **kwargs):
                harness.run_calls.append((argv, kwargs))
                if "unmount" in argv:
                    image.write_bytes(b"changed data")
                return completed()

            harness.runner = runner
            with self.assertRaisesRegex(WriterSafetyError, "image changed"):
                harness.writer().write(image, harness.device, lambda _d, _t: None)
        self.assertEqual(harness.processes, [])

    def test_expected_source_identity_includes_ctime_and_fails_before_unmount(self):
        harness = WriterHarness()
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            image.write_bytes(b"A" * 4096)
            before = image.stat()
            expected = (
                before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns,
            )
            image.write_bytes(b"B" * 4096)
            os.utime(image, ns=(before.st_atime_ns, before.st_mtime_ns))

            with self.assertRaisesRegex(WriterSafetyError, "after confirmation"):
                harness.writer().write(
                    image, harness.device, lambda _d, _t: None,
                    expected_identity=expected,
                )

        self.assertEqual(harness.run_calls, [])
        self.assertEqual(harness.processes, [])

    def test_writer_closes_source_when_measurement_fails(self):
        harness = WriterHarness()
        source = Mock()
        source.identity = SimpleNamespace(
            device=1, inode=2, size=3, modified_ns=4, changed_ns=5,
        )
        source.measure.side_effect = RuntimeError("measurement failed")

        with (
            patch("isopropyl.writer.open_image_source", return_value=source),
            self.assertRaisesRegex(RuntimeError, "measurement failed"),
        ):
            harness.writer().write(
                Path("image.img"), harness.device, lambda _d, _t: None,
            )

        source.close.assert_called_once()

    def test_verification_closes_source_when_target_probe_fails(self):
        source = Mock()
        writer = ImageWriter(block_stat=Mock(side_effect=OSError("gone")))

        with (
            patch("isopropyl.writer.open_image_source", return_value=source),
            self.assertRaisesRegex(WriterSafetyError, "target is unavailable"),
        ):
            writer.verify(Path("image.img"), "target", lambda _d, _t: None)

        source.close.assert_called_once()

    def test_source_change_during_raw_write_is_reported(self):
        harness = WriterHarness()
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            image.write_bytes(b"hello world!")
            harness.process_factory = lambda argv, kwargs: FakeProcess(
                argv,
                stderr_data=b"12 bytes copied\n",
                on_wait=lambda: image.write_bytes(b"changed data!"),
                **kwargs,
            )
            with self.assertRaisesRegex(WriterSafetyError, "image changed"):
                harness.writer().write(image, harness.device, lambda _d, _t: None)

    def test_progress_callback_failure_terminates_privileged_writer(self):
        harness = WriterHarness()
        harness.process_factory = lambda argv, kwargs: FakeProcess(
            argv, stderr_data=b"6 bytes copied\n", running=True, **kwargs,
        )
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            image.write_bytes(b"hello world!")
            with self.assertRaisesRegex(RuntimeError, "callback failed"):
                harness.writer().write(
                    image, harness.device,
                    lambda _d, _t: (_ for _ in ()).throw(RuntimeError("callback failed")),
                )
        self.assertTrue(harness.processes[0].terminated)

    def test_failure_diagnostics_are_bounded(self):
        harness = WriterHarness()
        harness.process_factory = lambda argv, kwargs: FakeProcess(
            argv, stderr_data=b"x" * (MAX_DIAGNOSTIC_BYTES * 2), code=2, **kwargs,
        )
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            image.write_bytes(b"hello world!")
            with self.assertRaises(WriterError) as caught:
                harness.writer().write(image, harness.device, lambda _d, _t: None)
        self.assertLessEqual(len(str(caught.exception)), MAX_DIAGNOSTIC_BYTES)

    def test_block_verification_is_bound_to_written_source_and_device(self):
        harness = WriterHarness()
        writer = harness.writer()
        content = b"hello world!"
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            image.write_bytes(content)
            writer.write(image, harness.device, lambda _d, _t: None)
            harness.process_factory = lambda argv, kwargs: FakeProcess(
                argv, stdout_data=content, **kwargs,
            )
            self.assertTrue(writer.verify(image, harness.device.path, lambda _d, _t: None))
            verify_process = harness.processes[-1]
            self.assertEqual(
                verify_process.argv[:2], ["/usr/bin/pkexec", "/usr/bin/flock"],
            )
            self.assertEqual(
                verify_process.argv[verify_process.argv.index("/dev/sdz") + 1],
                "/usr/bin/dd",
            )
            self.assertIn(f"count={len(content)}", verify_process.argv)
            self.assertFalse(verify_process.kwargs["shell"])
            image.write_bytes(b"changed data")
            with self.assertRaisesRegex(WriterSafetyError, "image changed"):
                writer.verify(image, harness.device.path, lambda _d, _t: None)

    def test_block_verification_lock_conflict_is_not_reported_as_hash_mismatch(self):
        harness = WriterHarness()
        writer = harness.writer()
        content = b"hello world!"
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            image.write_bytes(content)
            writer.write(image, harness.device, lambda _d, _t: None)
            harness.process_factory = lambda argv, kwargs: FakeProcess(
                argv, stderr_data=b"busy", code=75, **kwargs,
            )
            with self.assertRaisesRegex(
                WriterError, "Another lock-aware storage operation",
            ):
                writer.verify(image, harness.device.path, lambda _d, _t: None)

    def test_bare_block_verification_and_changed_poweroff_target_fail_closed(self):
        harness = WriterHarness()
        writer = harness.writer()
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.img"
            image.write_bytes(b"hello world!")
            with self.assertRaisesRegex(WriterSafetyError, "requires the ImageWriter"):
                writer.verify(image, harness.device.path, lambda _d, _t: None)
        harness.current = removable_device(serial="OTHER")
        with self.assertRaisesRegex(WriterSafetyError, "identity changed"):
            writer.power_off(harness.device)
        self.assertFalse(any("power-off" in call[0] for call in harness.run_calls))


if __name__ == "__main__":
    unittest.main()
