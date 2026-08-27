from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import io
import os
import stat
import subprocess
import threading
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from isopropyl.devices import Device
from isopropyl.media_test import (
    BADBLOCK_PATTERNS,
    BadblocksProgressParser,
    CapacityStatus,
    MediaTestCancelled,
    MediaTestMode,
    MediaTestRunner,
    MediaTestSafetyError,
    MediaTestUnavailable,
    build_media_test_plan,
    parse_bad_block_lines,
)


def removable_device(**changes: object) -> Device:
    values: dict[str, object] = {
        "path": "/dev/sdb",
        "size": 16_000_000_000,
        "model": "Flash Drive",
        "vendor": "Acme",
        "transport": "usb",
        "serial": "SERIAL-123",
        "wwn": "",
        "major_minor": "8:16",
        "removable": True,
        "hotplug": True,
        "read_only": False,
        "mountpoints": ("/media/usb",),
        "partitions": ("/dev/sdb1",),
    }
    values.update(changes)
    return Device(**values)  # type: ignore[arg-type]


PROGRAMS = {
    "pkexec": "/usr/bin/pkexec",
    "udisksctl": "/usr/bin/udisksctl",
    "badblocks": "/usr/sbin/badblocks",
    "f3probe": "/usr/bin/f3probe",
}


def find_program(name: str) -> str | None:
    return PROGRAMS.get(name)


class FakeProcess:
    def __init__(
        self,
        code: int = 0,
        stdout: bytes = b"",
        stderr: bytes = b"",
    ) -> None:
        self.returncode = code
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.terminated = False
        self.killed = False

    def poll(self) -> int:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


class FakeStat:
    st_mode = stat.S_IFBLK | 0o660
    st_rdev = os.makedev(8, 16)


class BlockingStream:
    def __init__(self, finished: threading.Event) -> None:
        self.finished = finished

    def read1(self, _size: int) -> bytes:
        self.finished.wait(2)
        return b""


class BlockingProcess:
    def __init__(self) -> None:
        self.finished = threading.Event()
        self.stdout = BlockingStream(self.finished)
        self.stderr = BlockingStream(self.finished)
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return -15 if self.finished.is_set() else None

    def wait(self, timeout: float | None = None) -> int:
        if not self.finished.wait(timeout):
            raise subprocess.TimeoutExpired("fake", timeout)
        return -15

    def terminate(self) -> None:
        self.terminated = True
        self.finished.set()

    def kill(self) -> None:
        self.killed = True
        self.finished.set()


class PlanTests(unittest.TestCase):
    def test_builds_one_to_four_documented_write_read_patterns(self):
        for passes in range(1, 5):
            with self.subTest(passes=passes):
                plan = build_media_test_plan(
                    removable_device(), MediaTestMode.FULL_SURFACE,
                    passes=passes, finder=find_program,
                )
                self.assertEqual(plan.passes, passes)
                self.assertEqual(
                    [phase.pattern for phase in plan.phases],
                    list(BADBLOCK_PATTERNS[:passes]),
                )
                for phase in plan.phases:
                    self.assertEqual(phase.argv[0], "/usr/bin/pkexec")
                    self.assertEqual(phase.argv[1], "/usr/sbin/badblocks")
                    self.assertIn("-w", phase.argv)
                    self.assertEqual(phase.argv[-1], "/dev/sdb")

    def test_complete_plan_probes_capacity_then_covers_surface(self):
        plan = build_media_test_plan(
            removable_device(), MediaTestMode.COMPLETE,
            passes=2, finder=find_program,
        )
        self.assertEqual([phase.kind for phase in plan.phases], [
            "f3probe", "badblocks", "badblocks",
        ])
        self.assertEqual(
            plan.phases[0].argv,
            (
                "/usr/bin/pkexec", "/usr/bin/f3probe", "--destructive",
                "--time-ops", "/dev/sdb",
            ),
        )

    def test_plan_is_frozen_and_contains_exact_separate_confirmation(self):
        plan = build_media_test_plan(
            removable_device(), MediaTestMode.FULL_SURFACE, finder=find_program,
        )
        self.assertEqual(plan.confirmation_phrase, "ERASE /dev/sdb")
        self.assertIn("THIS TEST IS DESTRUCTIVE AND CANNOT BE UNDONE.", plan.warnings)
        self.assertTrue(any("type exactly: ERASE /dev/sdb" in item for item in plan.warnings))
        with self.assertRaises(FrozenInstanceError):
            plan.passes = 3  # type: ignore[misc]

    def test_rejects_invalid_passes_fixed_read_only_and_non_device_paths(self):
        for passes in (0, 5):
            with self.assertRaises(ValueError):
                build_media_test_plan(
                    removable_device(), MediaTestMode.FULL_SURFACE,
                    passes=passes, finder=find_program,
                )
        for device in (
            removable_device(removable=False),
            removable_device(read_only=True),
            removable_device(path="/tmp/sdb"),
            removable_device(major_minor=""),
            removable_device(transport="sata"),
        ):
            with self.assertRaises(MediaTestSafetyError):
                build_media_test_plan(
                    device, MediaTestMode.FULL_SURFACE, finder=find_program,
                )

    def test_fails_closed_when_mode_dependency_is_missing(self):
        no_f3 = lambda name: None if name == "f3probe" else find_program(name)
        with self.assertRaisesRegex(MediaTestUnavailable, "f3probe"):
            build_media_test_plan(
                removable_device(), MediaTestMode.FAKE_CAPACITY, finder=no_f3,
            )
        no_badblocks = lambda name: None if name == "badblocks" else find_program(name)
        with self.assertRaisesRegex(MediaTestUnavailable, "badblocks"):
            build_media_test_plan(
                removable_device(), MediaTestMode.FULL_SURFACE, finder=no_badblocks,
            )

    def test_rejects_relative_program_resolution(self):
        with self.assertRaises(MediaTestUnavailable):
            build_media_test_plan(
                removable_device(), MediaTestMode.FULL_SURFACE,
                finder=lambda name: name,
            )

    @patch("isopropyl.media_test.shutil.which")
    def test_default_tool_search_ignores_the_calling_users_path(self, which):
        which.side_effect = lambda name, **_kwargs: PROGRAMS.get(name)
        build_media_test_plan(removable_device(), MediaTestMode.FULL_SURFACE)
        self.assertTrue(which.call_args_list)
        for call in which.call_args_list:
            self.assertEqual(call.kwargs["path"], "/usr/sbin:/usr/bin:/sbin:/bin")


class ParsingTests(unittest.TestCase):
    def test_badblocks_progress_accounts_for_write_and_read_compare(self):
        parser = BadblocksProgressParser()
        self.assertAlmostEqual(
            parser.feed(b"Testing with pattern 0xaa: 20.00% done") or -1,
            0.10,
        )
        self.assertAlmostEqual(
            parser.feed(b" done\nReading and comparing: 40.00% done") or -1,
            0.70,
        )

    def test_badblocks_progress_marker_can_cross_chunks(self):
        parser = BadblocksProgressParser()
        self.assertIsNone(parser.feed(b"Reading and comp"))
        self.assertAlmostEqual(parser.feed(b"aring: 50.00% done") or -1, 0.75)

    def test_parses_only_numeric_bad_block_lines(self):
        self.assertEqual(
            parse_bad_block_lines(b"44\nnoise 52\n7\n44\n"),
            (7, 44),
        )


class RunnerTests(unittest.TestCase):
    def make_runner(self, processes: list[FakeProcess], calls: list[tuple]) -> MediaTestRunner:
        def popen(argv, **kwargs):
            calls.append(("popen", argv, kwargs))
            return processes.pop(0)

        def run(argv, **kwargs):
            calls.append(("run", argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, "", "")

        device = removable_device()
        return MediaTestRunner(
            popen=popen,
            run_command=run,
            device_lister=lambda: [device],
            stat_func=lambda _path: FakeStat(),  # type: ignore[arg-type]
        )

    def test_wrong_confirmation_cannot_probe_unmount_or_spawn(self):
        calls: list[tuple] = []
        lister_called = False

        def lister():
            nonlocal lister_called
            lister_called = True
            return [removable_device()]

        runner = MediaTestRunner(
            popen=lambda *args, **kwargs: calls.append((args, kwargs)),  # type: ignore[arg-type]
            run_command=lambda *args, **kwargs: calls.append((args, kwargs)),  # type: ignore[arg-type]
            device_lister=lister,
        )
        plan = build_media_test_plan(
            removable_device(), MediaTestMode.FULL_SURFACE, finder=find_program,
        )
        with self.assertRaises(MediaTestSafetyError):
            runner.run(plan, "ERASE /dev/sdc")
        self.assertFalse(lister_called)
        self.assertEqual(calls, [])

    def test_cancel_before_run_prevents_all_device_actions(self):
        calls: list[tuple] = []
        runner = MediaTestRunner(device_lister=lambda: calls.append(("listed",)) or [])
        runner.cancel()
        plan = build_media_test_plan(
            removable_device(), MediaTestMode.FULL_SURFACE, finder=find_program,
        )
        with self.assertRaises(MediaTestCancelled):
            runner.run(plan, plan.confirmation_phrase)
        self.assertEqual(calls, [])

    def test_cancel_terminates_an_in_flight_privileged_process(self):
        spawned = threading.Event()
        process = BlockingProcess()
        errors: list[BaseException] = []

        def popen(_argv, **_kwargs):
            spawned.set()
            return process

        runner = MediaTestRunner(
            popen=popen,
            run_command=lambda argv, **_kwargs: subprocess.CompletedProcess(
                argv, 0, "", "",
            ),
            device_lister=lambda: [removable_device()],
            stat_func=lambda _path: FakeStat(),  # type: ignore[arg-type]
        )
        plan = build_media_test_plan(
            removable_device(), MediaTestMode.FULL_SURFACE, finder=find_program,
        )

        def execute() -> None:
            try:
                runner.run(plan, plan.confirmation_phrase)
            except BaseException as error:  # Captured for assertion in this thread.
                errors.append(error)

        thread = threading.Thread(target=execute)
        thread.start()
        self.assertTrue(spawned.wait(1))
        runner.cancel()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(process.terminated)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], MediaTestCancelled)

    def test_rechecks_identity_and_block_device_before_destructive_command(self):
        calls: list[tuple] = []
        planned = removable_device()
        changed = removable_device(serial="OTHER")
        runner = MediaTestRunner(
            popen=lambda *args, **kwargs: calls.append(("popen", args, kwargs)),  # type: ignore[arg-type]
            run_command=lambda *args, **kwargs: calls.append(("run", args, kwargs)),  # type: ignore[arg-type]
            device_lister=lambda: [changed],
            stat_func=lambda _path: FakeStat(),  # type: ignore[arg-type]
        )
        plan = build_media_test_plan(
            planned, MediaTestMode.FULL_SURFACE, finder=find_program,
        )
        with self.assertRaisesRegex(MediaTestSafetyError, "identity changed"):
            runner.run(plan, plan.confirmation_phrase)
        self.assertEqual(calls, [])

    def test_runs_without_shell_unmounts_and_reports_bad_blocks_and_progress(self):
        calls: list[tuple] = []
        processes = [FakeProcess(
            stdout=b"9\n123\n",
            stderr=(
                b"Testing with pattern 0xaa: 20.00% done\n"
                b"Reading and comparing: 60.00% done\n"
            ),
        )]
        runner = self.make_runner(processes, calls)
        plan = build_media_test_plan(
            removable_device(), MediaTestMode.FULL_SURFACE, finder=find_program,
        )
        updates = []
        result = runner.run(plan, plan.confirmation_phrase, updates.append)

        self.assertEqual(result.bad_blocks, (9, 123))
        self.assertEqual(result.capacity_status, CapacityStatus.NOT_TESTED)
        self.assertFalse(result.passed)
        self.assertEqual(calls[0][0], "run")
        self.assertEqual(calls[0][1], [
            "/usr/bin/udisksctl", "unmount", "--block-device", "/dev/sdb1",
        ])
        popen_call = calls[1]
        self.assertEqual(popen_call[0], "popen")
        self.assertNotIn("shell", popen_call[2])
        self.assertIsInstance(popen_call[1], list)
        self.assertEqual(popen_call[2]["env"]["LC_ALL"], "C")
        self.assertAlmostEqual(updates[-1].fraction, 1.0)
        self.assertTrue(any(0.79 <= update.phase_fraction <= 0.81 for update in updates))

    def test_maps_f3probe_counterfeit_exit_to_result_not_execution_failure(self):
        calls: list[tuple] = []
        runner = self.make_runner([
            FakeProcess(103, stdout=b"Bad news: counterfeit of type wraparound\n"),
        ], calls)
        plan = build_media_test_plan(
            removable_device(), MediaTestMode.FAKE_CAPACITY, finder=find_program,
        )
        result = runner.run(plan, plan.confirmation_phrase)
        self.assertEqual(result.capacity_status, CapacityStatus.COUNTERFEIT)
        self.assertFalse(result.passed)

    def test_fails_if_target_path_is_not_a_block_device(self):
        calls: list[tuple] = []
        runner = MediaTestRunner(
            popen=lambda *args, **kwargs: calls.append(("popen", args, kwargs)),  # type: ignore[arg-type]
            run_command=lambda *args, **kwargs: calls.append(("run", args, kwargs)),  # type: ignore[arg-type]
            device_lister=lambda: [removable_device()],
            stat_func=lambda _path: type(
                "Regular", (), {"st_mode": stat.S_IFREG | 0o600, "st_rdev": 0},
            )(),  # type: ignore[arg-type]
        )
        plan = build_media_test_plan(
            removable_device(), MediaTestMode.FULL_SURFACE, finder=find_program,
        )
        with self.assertRaisesRegex(MediaTestSafetyError, "not a block device"):
            runner.run(plan, plan.confirmation_phrase)
        self.assertEqual(calls, [])

    def test_runner_is_single_use(self):
        calls: list[tuple] = []
        runner = self.make_runner([FakeProcess()], calls)
        plan = build_media_test_plan(
            removable_device(), MediaTestMode.FULL_SURFACE, finder=find_program,
        )
        runner.run(plan, plan.confirmation_phrase)
        with self.assertRaisesRegex(MediaTestSafetyError, "cannot be reused"):
            runner.run(plan, plan.confirmation_phrase)


if __name__ == "__main__":
    unittest.main()
