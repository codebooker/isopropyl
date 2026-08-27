from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

from isopropyl.optical import (
    MAX_ERROR_CHARACTERS,
    OPTICAL_SECTOR_BYTES,
    OUTPUT_SPACE_RESERVE_BYTES,
    OpticalCancelled,
    OpticalCaptureRunner,
    OpticalDevice,
    OpticalError,
    OpticalSafetyError,
    OpticalTools,
    OpticalUnavailable,
    build_optical_capture_plan,
    list_optical_devices,
    optical_read_command,
    parse_optical_devices,
    resolve_optical_tools,
    validate_optical_capture_plan,
)


def optical_device(**changes: object) -> OpticalDevice:
    values: dict[str, object] = {
        "path": "/dev/sr0",
        "size": 8192,
        "model": "DVD Writer",
        "vendor": "Acme",
        "serial": "DRIVE-123",
        "wwn": "",
        "major_minor": "11:0",
        "mountpoints": ("/media/disc",),
        "label": "INSTALL",
        "media_uuid": "DISC-UUID",
        "block_type": "rom",
    }
    values.update(changes)
    return OpticalDevice(**values)  # type: ignore[arg-type]


PROGRAMS = {
    "pkexec": "/usr/bin/pkexec",
    "udisksctl": "/usr/bin/udisksctl",
    "lsblk": "/usr/bin/lsblk",
    "blockdev": "/usr/sbin/blockdev",
    "dd": "/usr/bin/dd",
}


def find_program(name: str) -> str | None:
    return PROGRAMS.get(name)


def completed(code: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def size_runner(size: int = 8192):
    def run(argv, **_kwargs):
        if "blockdev" in argv[0]:
            return completed(stdout=f"{size}\n")
        return completed()

    return run


class SourceBlockStat:
    st_mode = stat.S_IFBLK | 0o440
    st_rdev = os.makedev(11, 0)


def source_and_real_stat(path):
    if os.fspath(path) == "/dev/sr0":
        return SourceBlockStat()
    return os.stat(path)


class FakeProcess:
    def __init__(self, code: int = 0, stderr: bytes = b"") -> None:
        self.returncode = code
        self.stderr = io.BytesIO(stderr)
        self.terminated = False
        self.killed = False

    def poll(self) -> int:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


class BlockingStream:
    def __init__(self, finished: threading.Event) -> None:
        self.finished = finished

    def read1(self, _size: int) -> bytes:
        self.finished.wait(2)
        return b""


class BlockingProcess:
    def __init__(self) -> None:
        self.finished = threading.Event()
        self.stderr = BlockingStream(self.finished)
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return -15 if self.finished.is_set() else None

    def wait(self, timeout: float | None = None) -> int:
        if not self.finished.wait(timeout):
            raise subprocess.TimeoutExpired("fake optical dd", timeout)
        return -15

    def terminate(self) -> None:
        self.terminated = True
        self.finished.set()

    def kill(self) -> None:
        self.killed = True
        self.finished.set()


class ApparentlyRunningProcess(FakeProcess):
    def poll(self) -> int | None:
        return self.returncode if self.terminated or self.killed else None


def build_plan(
    directory: str,
    *,
    device: OpticalDevice | None = None,
    probed_size: int = 8192,
    destination_name: str = "disc.iso",
):
    return build_optical_capture_plan(
        device or optical_device(),
        Path(directory) / destination_name,
        finder=find_program,
        run_command=size_runner(probed_size),
    )


class DiscoveryAndPlanTests(unittest.TestCase):
    def test_parses_only_valid_whole_optical_devices(self):
        payload = json.dumps({"blockdevices": [
            {
                "path": "/dev/sr0", "size": 4096, "type": "rom",
                "model": "DVD", "vendor": "Acme", "serial": "S",
                "wwn": "", "maj:min": "11:0", "mountpoints": ["/media/cd"],
                "label": "DISC", "uuid": "UUID",
            },
            {"path": "/dev/sda", "size": 100000, "type": "disk", "maj:min": "8:0"},
            {"path": "/dev/sr1", "size": 0, "type": "rom", "maj:min": "11:1"},
            {"path": "/tmp/sr2", "size": 4096, "type": "rom", "maj:min": "11:2"},
        ]})
        devices = parse_optical_devices(payload)
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].path, "/dev/sr0")
        self.assertEqual(devices[0].identity[-2:], ("DISC", "UUID"))

    def test_discovery_uses_absolute_lsblk_and_never_a_shell(self):
        calls = []
        payload = json.dumps({"blockdevices": [{
            "path": "/dev/sr0", "size": 4096, "type": "rom",
            "maj:min": "11:0", "mountpoints": [],
        }]})

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return completed(stdout=payload)

        result = list_optical_devices(finder=find_program, run_command=run)
        self.assertEqual([item.path for item in result], ["/dev/sr0"])
        self.assertEqual(calls[0][0][0], "/usr/bin/lsblk")
        self.assertIs(calls[0][1]["shell"], False)

    @patch("isopropyl.optical.shutil.which")
    def test_tool_resolution_ignores_the_calling_users_path(self, which):
        which.side_effect = lambda name, **_kwargs: PROGRAMS[name]
        self.assertEqual(resolve_optical_tools(), OpticalTools(**PROGRAMS))
        self.assertTrue(all(
            call.kwargs["path"] == "/usr/sbin:/usr/bin:/sbin:/bin"
            for call in which.call_args_list
        ))

    def test_rejects_relative_untrusted_or_missing_tools(self):
        for bad in (None, "dd", "/tmp/dd", "/usr/bin/not-dd"):
            with self.subTest(path=bad):
                with self.assertRaises(OpticalUnavailable):
                    resolve_optical_tools(
                        lambda name, bad=bad: bad if name == "dd" else PROGRAMS[name]
                    )

    def test_plan_uses_minimum_size_rounded_to_complete_optical_sectors(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = build_plan(
                directory, device=optical_device(size=10001), probed_size=9001,
            )
        self.assertEqual(plan.probed_bytes, 9001)
        self.assertEqual(plan.readable_bytes, 8192)
        self.assertEqual(plan.readable_bytes % OPTICAL_SECTOR_BYTES, 0)

    def test_plan_is_frozen_and_command_is_read_only_stdout_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = build_plan(directory)
            command = optical_read_command(plan)
        self.assertEqual(command[:3], (
            "/usr/bin/pkexec", "/usr/bin/dd", "if=/dev/sr0",
        ))
        self.assertFalse(any(item.startswith("of=") for item in command))
        self.assertIn("count=8192", command)
        self.assertIn("iflag=count_bytes,fullblock", command)
        with self.assertRaises(FrozenInstanceError):
            plan.readable_bytes = 1  # type: ignore[misc]

    def test_rejects_non_optical_empty_or_root_backing_sources(self):
        unsafe = (
            optical_device(path="/dev/sda"),
            optical_device(block_type="disk"),
            optical_device(size=0),
            optical_device(major_minor=""),
            optical_device(mountpoints=("/",)),
        )
        with tempfile.TemporaryDirectory() as directory:
            for device in unsafe:
                with self.subTest(device=device):
                    with self.assertRaises(OpticalSafetyError):
                        build_plan(directory, device=device)

    def test_destination_must_be_new_absolute_iso_in_writable_folder(self):
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / "exists.iso"
            existing.write_bytes(b"keep")
            with self.assertRaises(OpticalSafetyError):
                build_plan(directory, destination_name="exists.iso")
            with self.assertRaises(OpticalSafetyError):
                build_optical_capture_plan(
                    optical_device(), "relative.iso", finder=find_program,
                    run_command=size_runner(),
                )
            with self.assertRaises(OpticalSafetyError):
                build_plan(directory, destination_name="disc.img")
            with self.assertRaisesRegex(OpticalSafetyError, "not writable"):
                build_optical_capture_plan(
                    optical_device(), Path(directory) / "new.iso",
                    finder=find_program, run_command=size_runner(),
                    access_func=lambda _path, _mode: False,
                )

    def test_insufficient_space_fails_during_planning(self):
        usage = shutil._ntuple_diskusage(100, 100, 0)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(OpticalSafetyError, "free bytes"):
                build_optical_capture_plan(
                    optical_device(), Path(directory) / "disc.iso",
                    finder=find_program, run_command=size_runner(),
                    disk_usage=lambda _path: usage,
                )

    def test_forged_plan_fields_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = build_plan(directory)
            forged = (
                replace(plan, readable_bytes=1),
                replace(plan, destination=Path(directory) / "disc.img"),
                replace(plan, destination_parent_identity=(-1, -1)),
                replace(plan, tools=replace(plan.tools, dd="/tmp/dd")),
            )
            for item in forged:
                with self.subTest(plan=item):
                    with self.assertRaises(OpticalSafetyError):
                        validate_optical_capture_plan(item)


class RunnerTests(unittest.TestCase):
    def make_runner(
        self,
        popen,
        calls: list[tuple],
        *,
        lister=None,
        run_override=None,
        disk_usage=shutil.disk_usage,
        stat_func=source_and_real_stat,
    ) -> OpticalCaptureRunner:
        def run(argv, **kwargs):
            calls.append(("run", argv, kwargs))
            if run_override is not None:
                return run_override(argv, **kwargs)
            if "blockdev" in argv[0]:
                return completed(stdout="8192\n")
            return completed()

        def spawn(argv, **kwargs):
            calls.append(("popen", argv, kwargs))
            return popen(argv, **kwargs)

        return OpticalCaptureRunner(
            popen=spawn,
            run_command=run,
            device_lister=lister or (lambda: [optical_device()]),
            stat_func=stat_func,
            disk_usage=disk_usage,
        )

    def test_success_unmounts_revalidates_and_atomically_publishes_user_file(self):
        calls: list[tuple] = []
        content = b"I" * 8192

        def popen(_argv, **kwargs):
            kwargs["stdout"].write(content)
            return FakeProcess(stderr=b"4096 bytes copied\r8192 bytes copied\n")

        with tempfile.TemporaryDirectory() as directory:
            plan = build_plan(directory)
            updates = []
            result = self.make_runner(popen, calls).run(plan, updates.append)
            self.assertEqual(plan.destination.read_bytes(), content)
            self.assertEqual(result.bytes_written, 8192)
            self.assertEqual(result.destination, plan.destination)
            self.assertEqual(plan.destination.stat().st_uid, os.geteuid())
            self.assertFalse(list(Path(directory).glob("*.partial")))

        unmount = next(item for item in calls if item[0] == "run" and "udisksctl" in item[1][0])
        self.assertEqual(unmount[1], [
            "/usr/bin/udisksctl", "unmount", "--block-device", "/dev/sr0",
        ])
        self.assertIs(unmount[2]["shell"], False)
        spawned = next(item for item in calls if item[0] == "popen")
        self.assertFalse(any(arg.startswith("of=") for arg in spawned[1]))
        self.assertIs(spawned[2]["shell"], False)
        self.assertEqual(updates[0].fraction, 0.0)
        self.assertEqual(updates[-1].fraction, 1.0)
        self.assertEqual(
            [item.bytes_done for item in updates],
            sorted(item.bytes_done for item in updates),
        )

    def test_preflight_free_space_failure_occurs_before_source_or_unmount(self):
        calls: list[tuple] = []
        usage = shutil._ntuple_diskusage(100, 100, 0)
        with tempfile.TemporaryDirectory() as directory:
            plan = build_plan(directory)
            runner = self.make_runner(
                lambda *_args, **_kwargs: FakeProcess(), calls,
                disk_usage=lambda _path: usage,
            )
            with self.assertRaises(OpticalSafetyError):
                runner.run(plan)
        self.assertEqual(calls, [])

    def test_changed_disc_identity_or_non_block_source_never_starts_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = build_plan(directory)
            for lister, stat_func in (
                (lambda: [optical_device(media_uuid="OTHER")], source_and_real_stat),
                (
                    lambda: [optical_device()],
                    lambda path: (
                        type("Regular", (), {"st_mode": stat.S_IFREG, "st_rdev": 0})()
                        if os.fspath(path) == "/dev/sr0" else os.stat(path)
                    ),
                ),
            ):
                calls: list[tuple] = []
                runner = self.make_runner(
                    lambda *_args, **_kwargs: FakeProcess(), calls,
                    lister=lister, stat_func=stat_func,
                )
                with self.assertRaises(OpticalSafetyError):
                    runner.run(plan)
                self.assertFalse(any(item[0] == "popen" for item in calls))

    def test_changed_major_minor_or_probed_size_never_starts_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = build_plan(directory)
            wrong_block = type("OtherBlock", (), {
                "st_mode": stat.S_IFBLK | 0o440,
                "st_rdev": os.makedev(11, 1),
            })()
            for stat_func, run_override in (
                (
                    lambda path: wrong_block if os.fspath(path) == "/dev/sr0" else os.stat(path),
                    None,
                ),
                (
                    source_and_real_stat,
                    lambda argv, **_kwargs: (
                        completed(stdout="12288\n") if "blockdev" in argv[0] else completed()
                    ),
                ),
            ):
                calls: list[tuple] = []
                runner = self.make_runner(
                    lambda *_args, **_kwargs: FakeProcess(), calls,
                    stat_func=stat_func, run_override=run_override,
                )
                with self.assertRaises(OpticalSafetyError):
                    runner.run(plan)
                self.assertFalse(any(item[0] == "popen" for item in calls))

    def test_unmount_failure_prevents_reader_and_bounds_error(self):
        calls: list[tuple] = []

        def run(argv, **_kwargs):
            if "blockdev" in argv[0]:
                return completed(stdout="8192\n")
            return completed(1, stderr="x" * 10000)

        with tempfile.TemporaryDirectory() as directory:
            plan = build_plan(directory)
            runner = self.make_runner(
                lambda *_args, **_kwargs: FakeProcess(), calls, run_override=run,
            )
            with self.assertRaises(OpticalSafetyError) as caught:
                runner.run(plan)
        self.assertLessEqual(len(str(caught.exception)), MAX_ERROR_CHARACTERS)
        self.assertFalse(any(item[0] == "popen" for item in calls))

    def test_short_or_failed_read_never_publishes_partial_iso(self):
        for process in (
            FakeProcess(),
            FakeProcess(code=1, stderr=b"z" * 50000),
        ):
            calls: list[tuple] = []

            def popen(_argv, **kwargs):
                kwargs["stdout"].write(b"short")
                return process

            with tempfile.TemporaryDirectory() as directory:
                plan = build_plan(directory)
                with self.assertRaises(OpticalError) as caught:
                    self.make_runner(popen, calls).run(plan)
                self.assertFalse(plan.destination.exists())
                self.assertFalse(list(Path(directory).glob("*.partial")))
                self.assertLessEqual(len(str(caught.exception)), MAX_ERROR_CHARACTERS)

    def test_destination_race_does_not_overwrite_existing_file(self):
        calls: list[tuple] = []
        with tempfile.TemporaryDirectory() as directory:
            plan = build_plan(directory)

            def popen(_argv, **kwargs):
                kwargs["stdout"].write(b"D" * 8192)
                plan.destination.write_bytes(b"keep")
                return FakeProcess()

            with self.assertRaises(OpticalSafetyError):
                self.make_runner(popen, calls).run(plan)
            self.assertEqual(plan.destination.read_bytes(), b"keep")
            self.assertFalse(list(Path(directory).glob("*.partial")))

    def test_cancel_before_start_does_not_touch_source_or_destination(self):
        calls: list[tuple] = []
        with tempfile.TemporaryDirectory() as directory:
            plan = build_plan(directory)
            runner = self.make_runner(
                lambda *_args, **_kwargs: FakeProcess(), calls,
            )
            runner.cancel()
            with self.assertRaises(OpticalCancelled):
                runner.run(plan)
            self.assertFalse(plan.destination.exists())
        self.assertEqual(calls, [])

    def test_cancel_terminates_in_flight_reader_and_removes_partial(self):
        calls: list[tuple] = []
        process = BlockingProcess()
        spawned = threading.Event()
        errors: list[BaseException] = []

        def popen(_argv, **_kwargs):
            spawned.set()
            return process

        with tempfile.TemporaryDirectory() as directory:
            plan = build_plan(directory)
            runner = self.make_runner(popen, calls)

            def execute():
                try:
                    runner.run(plan)
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=execute)
            thread.start()
            self.assertTrue(spawned.wait(1))
            runner.cancel()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertFalse(plan.destination.exists())
            self.assertFalse(list(Path(directory).glob("*.partial")))
        self.assertTrue(process.terminated)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], OpticalCancelled)

    def test_progress_failure_cannot_orphan_privileged_reader(self):
        calls: list[tuple] = []
        process = ApparentlyRunningProcess()

        def popen(_argv, **_kwargs):
            return process

        with tempfile.TemporaryDirectory() as directory:
            plan = build_plan(directory)

            def broken(_update):
                raise RuntimeError("window closed")

            with self.assertRaisesRegex(RuntimeError, "window closed"):
                self.make_runner(popen, calls).run(plan, broken)
            self.assertFalse(plan.destination.exists())
        self.assertTrue(process.terminated)

    def test_runner_is_single_use(self):
        calls: list[tuple] = []

        def popen(_argv, **kwargs):
            kwargs["stdout"].write(b"I" * 8192)
            return FakeProcess()

        with tempfile.TemporaryDirectory() as directory:
            plan = build_plan(directory)
            runner = self.make_runner(popen, calls)
            runner.run(plan)
            with self.assertRaisesRegex(OpticalSafetyError, "cannot be reused"):
                runner.run(plan)


if __name__ == "__main__":
    unittest.main()
