from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import io
import json
import os
import stat
import subprocess
import threading
import unittest
from dataclasses import FrozenInstanceError, replace
from unittest.mock import patch

from isopropyl.devices import Device
from isopropyl.erase import (
    MAX_ERROR_CHARACTERS,
    QUICK_BOUNDARY_BYTES,
    EraseCancelled,
    EraseError,
    EraseMode,
    EraseRange,
    EraseRunner,
    EraseSafetyError,
    EraseTools,
    EraseUnavailable,
    build_erase_plan,
    erase_command,
    resolve_erase_tools,
    validate_erase_plan,
)


def removable_device(**changes: object) -> Device:
    values: dict[str, object] = {
        "path": "/dev/sdb",
        "size": 32_000_000_000,
        "model": "Flash Drive",
        "vendor": "Acme",
        "transport": "usb",
        "serial": "ERASE-SERIAL",
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
    "lsblk": "/usr/bin/lsblk",
    "dd": "/usr/bin/dd",
    "flock": "/usr/bin/flock",
}


def find_program(name: str) -> str | None:
    return PROGRAMS.get(name)


class FakeStat:
    st_mode = stat.S_IFBLK | 0o660
    st_rdev = os.makedev(8, 16)


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
        self.stdout = BlockingStream(self.finished)
        self.stderr = BlockingStream(self.finished)
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return -15 if self.finished.is_set() else None

    def wait(self, timeout: float | None = None) -> int:
        if not self.finished.wait(timeout):
            raise subprocess.TimeoutExpired("fake dd", timeout)
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


class TermIgnoringProcess:
    def __init__(self) -> None:
        self.finished = threading.Event()
        self.stdout = BlockingStream(self.finished)
        self.stderr = BlockingStream(self.finished)
        self.terminated = False
        self.killed = False
        self.reaped = False
        self.events: list[str] = []

    def poll(self) -> int | None:
        return -9 if self.reaped else None

    def wait(self, timeout: float | None = None) -> int:
        self.events.append("wait")
        if not self.killed:
            raise subprocess.TimeoutExpired("fake dd", timeout)
        self.reaped = True
        return -9

    def terminate(self) -> None:
        self.events.append("terminate")
        self.terminated = True

    def kill(self) -> None:
        self.events.append("kill")
        self.killed = True
        self.finished.set()


class UnreapableProcess:
    def __init__(self) -> None:
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.terminated = False
        self.killed = False
        self.wait_calls = 0

    def poll(self) -> None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        raise subprocess.TimeoutExpired("fake dd", timeout)

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


def completed(code: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class PlanTests(unittest.TestCase):
    def test_full_zero_has_one_exact_full_device_range(self):
        device = removable_device()
        plan = build_erase_plan(device, EraseMode.FULL_ZERO, finder=find_program)
        self.assertEqual(plan.ranges, (EraseRange(0, device.size),))
        self.assertEqual(plan.total_bytes, device.size)
        self.assertEqual(plan.confirmation_phrase, "ERASE /dev/sdb 8:16")
        self.assertTrue(any("one pass of zeros" in item for item in plan.warnings))
        self.assertTrue(any("not a hardware secure erase" in item for item in plan.warnings))
        with self.assertRaises(FrozenInstanceError):
            plan.mode = EraseMode.QUICK_BOUNDARY_ZERO  # type: ignore[misc]

    def test_quick_zero_has_precise_non_overlapping_boundary_ranges(self):
        device = removable_device()
        plan = build_erase_plan(
            device, EraseMode.QUICK_BOUNDARY_ZERO, finder=find_program,
        )
        self.assertEqual(plan.ranges, (
            EraseRange(0, QUICK_BOUNDARY_BYTES),
            EraseRange(device.size - QUICK_BOUNDARY_BYTES, QUICK_BOUNDARY_BYTES),
        ))
        self.assertEqual(plan.total_bytes, QUICK_BOUNDARY_BYTES * 2)
        warning = " ".join(plan.warnings)
        self.assertIn("only the first and last 16 MiB", warning)
        self.assertIn("untouched and may remain recoverable", warning)

    def test_quick_zero_merges_overlap_for_small_drives(self):
        size = QUICK_BOUNDARY_BYTES + 123
        plan = build_erase_plan(
            removable_device(size=size), EraseMode.QUICK_BOUNDARY_ZERO,
            finder=find_program,
        )
        self.assertEqual(plan.ranges, (EraseRange(0, size),))
        self.assertEqual(plan.total_bytes, size)

    def test_rejects_any_target_not_strictly_removable_safe_whole_media(self):
        unsafe = (
            removable_device(removable=False),
            removable_device(read_only=True),
            removable_device(transport="sata"),
            removable_device(path="/dev/sdb1"),
            removable_device(path="--help"),
            removable_device(major_minor=""),
            removable_device(size=0),
            removable_device(mountpoints=("/",)),
            removable_device(partitions=("/dev/sdc1",)),
        )
        for device in unsafe:
            with self.subTest(device=device):
                with self.assertRaises(EraseSafetyError):
                    build_erase_plan(device, EraseMode.FULL_ZERO, finder=find_program)

    def test_only_trusted_absolute_program_paths_are_accepted(self):
        for bad in ("dd", "/tmp/dd", "/usr/bin/not-dd"):
            with self.subTest(path=bad):
                with self.assertRaises(EraseUnavailable):
                    resolve_erase_tools(
                        lambda name, bad=bad: bad if name == "dd" else PROGRAMS[name]
                    )

    @patch("isopropyl.erase.shutil.which")
    def test_default_resolution_ignores_the_calling_users_path(self, which):
        which.side_effect = lambda name, **_kwargs: PROGRAMS[name]
        self.assertEqual(resolve_erase_tools(), EraseTools(**PROGRAMS))
        self.assertTrue(which.call_args_list)
        self.assertTrue(all(
            call.kwargs["path"] == "/usr/sbin:/usr/bin:/sbin:/bin"
            for call in which.call_args_list
        ))

    def test_command_is_fixed_argv_with_byte_exact_count_and_seek(self):
        plan = build_erase_plan(
            removable_device(), EraseMode.QUICK_BOUNDARY_ZERO, finder=find_program,
        )
        second = erase_command(plan, plan.ranges[1])
        self.assertEqual(second[:9], (
            "/usr/bin/pkexec", "/usr/bin/flock", "--exclusive", "--nonblock",
            "--conflict-exit-code", "75", "--no-fork", "/dev/sdb", "/usr/bin/dd",
        ))
        self.assertEqual(second[9:11], ("if=/dev/zero", "of=/dev/sdb"))
        self.assertIn(f"count={QUICK_BOUNDARY_BYTES}", second)
        self.assertIn(f"seek={plan.device.size - QUICK_BOUNDARY_BYTES}", second)
        self.assertIn("iflag=count_bytes", second)
        self.assertIn("oflag=seek_bytes", second)
        self.assertIn("conv=fsync,notrunc", second)
        with self.assertRaises(EraseSafetyError):
            erase_command(plan, EraseRange(1, 2))

    def test_missing_flock_fails_during_plan_build(self):
        with self.assertRaisesRegex(EraseUnavailable, "requires util-linux flock"):
            build_erase_plan(
                removable_device(), EraseMode.FULL_ZERO,
                finder=lambda name: None if name == "flock" else PROGRAMS[name],
            )

    def test_forged_plan_fields_are_rejected(self):
        plan = build_erase_plan(
            removable_device(), EraseMode.FULL_ZERO, finder=find_program,
        )
        forged = (
            replace(plan, ranges=(EraseRange(0, 1),)),
            replace(plan, confirmation_phrase="yes"),
            replace(plan, tools=replace(plan.tools, dd="/tmp/dd")),
            replace(plan, tools=replace(plan.tools, flock="/tmp/flock")),
            replace(plan, tools=replace(plan.tools, flock="/usr/bin/../bin/flock")),
            replace(plan, warnings=()),
        )
        for item in forged:
            with self.subTest(plan=item):
                with self.assertRaises(EraseSafetyError):
                    validate_erase_plan(item)


class RunnerTests(unittest.TestCase):
    def build_runner(
        self,
        processes: list[FakeProcess],
        calls: list[tuple],
        *,
        device_lister=None,
        stat_func=lambda _path: FakeStat(),
    ) -> EraseRunner:
        def popen(argv, **kwargs):
            calls.append(("popen", argv, kwargs))
            return processes.pop(0)

        def run(argv, **kwargs):
            calls.append(("run", argv, kwargs))
            return completed()

        return EraseRunner(
            popen=popen,
            run_command=run,
            device_lister=device_lister or (lambda: [removable_device()]),
            stat_func=stat_func,
        )

    def test_wrong_confirmation_prevents_listing_unmount_and_spawn(self):
        calls: list[tuple] = []
        runner = EraseRunner(
            popen=lambda *args, **kwargs: calls.append(("popen", args, kwargs)),  # type: ignore[arg-type]
            run_command=lambda *args, **kwargs: calls.append(("run", args, kwargs)),  # type: ignore[arg-type]
            device_lister=lambda: calls.append(("list",)) or [removable_device()],
        )
        plan = build_erase_plan(
            removable_device(), EraseMode.FULL_ZERO, finder=find_program,
        )
        with self.assertRaisesRegex(EraseSafetyError, "exactly match"):
            runner.run(plan, "ERASE /dev/sdb")
        self.assertEqual(calls, [])

    def test_cancel_before_run_prevents_all_device_actions(self):
        calls: list[tuple] = []
        runner = EraseRunner(device_lister=lambda: calls.append(("list",)) or [])
        runner.cancel()
        plan = build_erase_plan(
            removable_device(), EraseMode.FULL_ZERO, finder=find_program,
        )
        with self.assertRaises(EraseCancelled):
            runner.run(plan, plan.confirmation_phrase)
        self.assertEqual(calls, [])

    def test_revalidates_block_identity_unmounts_then_runs_without_shell(self):
        calls: list[tuple] = []
        process = FakeProcess(stderr=(
            b"4194304 bytes copied, 1 s, 4 MB/s\r"
            b"32000000000 bytes copied, 2 s, 16 GB/s\n"
        ))
        runner = self.build_runner([process], calls)
        plan = build_erase_plan(
            removable_device(), EraseMode.FULL_ZERO, finder=find_program,
        )
        updates = []
        result = runner.run(plan, plan.confirmation_phrase, updates.append)

        self.assertEqual(result.bytes_written, plan.device.size)
        self.assertEqual(result.ranges_completed, 1)
        self.assertEqual(calls[0][0:2], (
            "run",
            ["/usr/bin/udisksctl", "unmount", "--block-device", "/dev/sdb1"],
        ))
        popen_call = next(item for item in calls if item[0] == "popen")
        self.assertEqual(popen_call[1][:9], [
            "/usr/bin/pkexec", "/usr/bin/flock", "--exclusive", "--nonblock",
            "--conflict-exit-code", "75", "--no-fork", "/dev/sdb", "/usr/bin/dd",
        ])
        self.assertIs(popen_call[2]["shell"], False)
        self.assertEqual(popen_call[2]["env"]["LC_ALL"], "C")
        self.assertEqual(updates[0].fraction, 0.0)
        self.assertEqual(updates[-1].fraction, 1.0)
        self.assertEqual(updates[-1].bytes_done, plan.device.size)

    def test_quick_mode_reports_monotonic_aggregate_progress(self):
        calls: list[tuple] = []
        half = QUICK_BOUNDARY_BYTES // 2
        processes = [
            FakeProcess(stderr=f"{half} bytes copied\r".encode()),
            FakeProcess(stderr=f"{half} bytes copied\r".encode()),
        ]
        runner = self.build_runner(processes, calls)
        plan = build_erase_plan(
            removable_device(), EraseMode.QUICK_BOUNDARY_ZERO, finder=find_program,
        )
        updates = []
        result = runner.run(plan, plan.confirmation_phrase, updates.append)
        values = [update.bytes_done for update in updates]
        self.assertEqual(values, sorted(values))
        self.assertEqual(values[-1], QUICK_BOUNDARY_BYTES * 2)
        self.assertEqual(result.ranges_completed, 2)
        self.assertEqual(len([item for item in calls if item[0] == "popen"]), 2)

    def test_identity_change_before_second_range_stops_second_write(self):
        calls: list[tuple] = []
        listing_count = 0

        def lister():
            nonlocal listing_count
            listing_count += 1
            if listing_count >= 4:
                return [removable_device(serial="REPLACED")]
            return [removable_device()]

        runner = self.build_runner([FakeProcess()], calls, device_lister=lister)
        plan = build_erase_plan(
            removable_device(), EraseMode.QUICK_BOUNDARY_ZERO, finder=find_program,
        )
        with self.assertRaisesRegex(EraseSafetyError, "identity changed"):
            runner.run(plan, plan.confirmation_phrase)
        self.assertEqual(len([item for item in calls if item[0] == "popen"]), 1)

    def test_non_block_or_changed_major_minor_never_starts_dd(self):
        cases = (
            type("Regular", (), {"st_mode": stat.S_IFREG | 0o600, "st_rdev": 0})(),
            type("OtherBlock", (), {
                "st_mode": stat.S_IFBLK | 0o660,
                "st_rdev": os.makedev(8, 32),
            })(),
        )
        for fake_stat in cases:
            calls: list[tuple] = []
            runner = self.build_runner([], calls, stat_func=lambda _path, value=fake_stat: value)
            plan = build_erase_plan(
                removable_device(), EraseMode.FULL_ZERO, finder=find_program,
            )
            with self.assertRaises(EraseSafetyError):
                runner.run(plan, plan.confirmation_phrase)
            self.assertFalse(any(item[0] == "popen" for item in calls))

    def test_unmount_failure_stops_before_zero_write_and_bounds_error(self):
        calls: list[tuple] = []

        def run(argv, **kwargs):
            calls.append(("run", argv, kwargs))
            return completed(1, stderr="x" * 10000)

        runner = EraseRunner(
            popen=lambda *args, **kwargs: calls.append(("popen", args, kwargs)),  # type: ignore[arg-type]
            run_command=run,
            device_lister=lambda: [removable_device()],
            stat_func=lambda _path: FakeStat(),  # type: ignore[arg-type]
        )
        plan = build_erase_plan(
            removable_device(), EraseMode.FULL_ZERO, finder=find_program,
        )
        with self.assertRaises(EraseSafetyError) as caught:
            runner.run(plan, plan.confirmation_phrase)
        self.assertLessEqual(len(str(caught.exception)), MAX_ERROR_CHARACTERS)
        self.assertFalse(any(item[0] == "popen" for item in calls))

    def test_dd_failure_is_bounded(self):
        calls: list[tuple] = []
        runner = self.build_runner([FakeProcess(code=1, stderr=b"z" * 50000)], calls)
        plan = build_erase_plan(
            removable_device(), EraseMode.FULL_ZERO, finder=find_program,
        )
        with self.assertRaises(EraseError) as caught:
            runner.run(plan, plan.confirmation_phrase)
        self.assertLessEqual(len(str(caught.exception)), MAX_ERROR_CHARACTERS)

    def test_lock_conflict_has_specific_message(self):
        calls: list[tuple] = []
        runner = self.build_runner(
            [FakeProcess(code=75, stderr=b"generic flock diagnostic")], calls,
        )
        plan = build_erase_plan(
            removable_device(), EraseMode.FULL_ZERO, finder=find_program,
        )
        with self.assertRaisesRegex(
            EraseError, "Another lock-aware storage operation",
        ):
            runner.run(plan, plan.confirmation_phrase)

    def test_cancel_terminates_in_flight_privileged_process(self):
        process = BlockingProcess()
        spawned = threading.Event()
        errors: list[BaseException] = []

        def popen(_argv, **_kwargs):
            spawned.set()
            return process

        runner = EraseRunner(
            popen=popen,
            run_command=lambda argv, **_kwargs: completed(),
            device_lister=lambda: [removable_device()],
            stat_func=lambda _path: FakeStat(),  # type: ignore[arg-type]
        )
        plan = build_erase_plan(
            removable_device(), EraseMode.FULL_ZERO, finder=find_program,
        )

        def execute():
            try:
                runner.run(plan, plan.confirmation_phrase)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=execute)
        thread.start()
        self.assertTrue(spawned.wait(1))
        runner.cancel()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(process.terminated)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], EraseCancelled)

    def test_cancel_term_timeout_kills_then_waits_for_reap(self):
        process = TermIgnoringProcess()
        spawned = threading.Event()
        errors: list[BaseException] = []

        runner = EraseRunner(
            popen=lambda _argv, **_kwargs: spawned.set() or process,  # type: ignore[arg-type]
            run_command=lambda argv, **_kwargs: completed(),
            device_lister=lambda: [removable_device()],
            stat_func=lambda _path: FakeStat(),  # type: ignore[arg-type]
            process_stop_timeout=0.001,
        )
        plan = build_erase_plan(
            removable_device(), EraseMode.FULL_ZERO, finder=find_program,
        )

        def execute() -> None:
            try:
                runner.run(plan, plan.confirmation_phrase)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=execute)
        thread.start()
        self.assertTrue(spawned.wait(1))
        runner.cancel()
        thread.join(2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(process.events[:4], ["terminate", "wait", "kill", "wait"])
        self.assertTrue(process.reaped)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], EraseCancelled)

    def test_progress_callback_failure_cannot_orphan_privileged_writer(self):
        calls: list[tuple] = []
        process = ApparentlyRunningProcess()
        runner = self.build_runner([process], calls)
        plan = build_erase_plan(
            removable_device(), EraseMode.FULL_ZERO, finder=find_program,
        )

        def broken_progress(_update):
            raise RuntimeError("UI closed")

        with self.assertRaisesRegex(RuntimeError, "UI closed"):
            runner.run(plan, plan.confirmation_phrase, broken_progress)
        self.assertTrue(process.terminated)

    def test_callback_failure_escalates_to_kill_and_reaps_after_term_timeout(self):
        process = TermIgnoringProcess()
        runner = EraseRunner(
            popen=lambda _argv, **_kwargs: process,  # type: ignore[arg-type]
            run_command=lambda argv, **_kwargs: completed(),
            device_lister=lambda: [removable_device()],
            stat_func=lambda _path: FakeStat(),  # type: ignore[arg-type]
            process_stop_timeout=0.001,
        )
        plan = build_erase_plan(
            removable_device(), EraseMode.FULL_ZERO, finder=find_program,
        )

        with self.assertRaisesRegex(RuntimeError, "UI closed"):
            runner.run(
                plan, plan.confirmation_phrase,
                lambda _update: (_ for _ in ()).throw(RuntimeError("UI closed")),
            )

        self.assertEqual(process.events, ["terminate", "wait", "kill", "wait"])
        self.assertTrue(process.reaped)

    def test_unreapable_child_raises_bounded_erase_error_after_kill(self):
        process = UnreapableProcess()
        runner = EraseRunner(
            popen=lambda _argv, **_kwargs: process,  # type: ignore[arg-type]
            run_command=lambda argv, **_kwargs: completed(),
            device_lister=lambda: [removable_device()],
            stat_func=lambda _path: FakeStat(),  # type: ignore[arg-type]
            process_stop_timeout=0.001,
        )
        plan = build_erase_plan(
            removable_device(), EraseMode.FULL_ZERO, finder=find_program,
        )

        with self.assertRaisesRegex(EraseError, "could not be stopped and reaped"):
            runner.run(
                plan, plan.confirmation_phrase,
                lambda _update: (_ for _ in ()).throw(RuntimeError("UI closed")),
            )

        self.assertTrue(process.terminated)
        self.assertTrue(process.killed)
        self.assertEqual(process.wait_calls, 2)

    def test_default_revalidation_uses_planned_absolute_lsblk(self):
        calls: list[tuple] = []
        device = removable_device(mountpoints=(), partitions=())
        payload = json.dumps({"blockdevices": [{
            "path": device.path,
            "size": device.size,
            "type": "disk",
            "rm": True,
            "hotplug": True,
            "tran": "usb",
            "model": device.model,
            "vendor": device.vendor,
            "serial": device.serial,
            "wwn": device.wwn,
            "maj:min": device.major_minor,
            "mountpoints": [],
            "ro": False,
        }]})

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return completed(stdout=payload)

        runner = EraseRunner(
            popen=lambda _argv, **_kwargs: FakeProcess(),
            run_command=run,
            stat_func=lambda _path: FakeStat(),  # type: ignore[arg-type]
        )
        plan = build_erase_plan(device, EraseMode.FULL_ZERO, finder=find_program)
        runner.run(plan, plan.confirmation_phrase)
        self.assertTrue(calls)
        self.assertTrue(all(call[0][0] == "/usr/bin/lsblk" for call in calls))
        self.assertTrue(all(call[1]["shell"] is False for call in calls))

    def test_runner_is_single_use(self):
        calls: list[tuple] = []
        runner = self.build_runner([FakeProcess()], calls)
        plan = build_erase_plan(
            removable_device(), EraseMode.FULL_ZERO, finder=find_program,
        )
        runner.run(plan, plan.confirmation_phrase)
        with self.assertRaisesRegex(EraseSafetyError, "cannot be reused"):
            runner.run(plan, plan.confirmation_phrase)


if __name__ == "__main__":
    unittest.main()
