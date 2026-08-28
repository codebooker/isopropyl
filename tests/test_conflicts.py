from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from isopropyl.conflicts import (
    ConflictReport, ConflictingProcess, conflict_diagnostic_suffix,
    probe_conflicting_processes, unmount_response_is_inactive,
)


class FakeProcess:
    def __init__(self, stdout: bytes, stderr: bytes = b"", returncode: int = 0):
        self.stdout = tempfile.TemporaryFile()
        self.stderr = tempfile.TemporaryFile()
        self.stdout.write(stdout)
        self.stderr.write(stderr)
        self.stdout.seek(0)
        self.stderr.seek(0)
        self.returncode = returncode
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9


class ConflictDiagnosticTests(unittest.TestCase):
    @staticmethod
    def write_proc_stat(process: Path, pid: int, starttime: int) -> None:
        fields = ["S", *("0" for _ in range(18)), str(starttime)]
        (process / "stat").write_text(
            f"{pid} (fixture process) " + " ".join(fields) + "\n"
        )

    def test_unmount_inactive_responses_are_narrow_and_normalized(self):
        for message in (
            "not mounted",
            "Object is not a mounted filesystem.",
            "Object /org/freedesktop/UDisks2/block_devices/sda1 is not a "
            "mountable filesystem.",
            "  NOT   A MOUNTABLE\nFILESYSTEM  ",
        ):
            with self.subTest(message=message):
                self.assertTrue(unmount_response_is_inactive(message))
        for message in (
            "device is busy",
            "not mounted; device is busy",
            "not a mountable filesystem; permission denied",
            "",
            None,
        ):
            with self.subTest(message=message):
                self.assertFalse(unmount_response_is_inactive(message))

    def test_fixed_fuser_probe_reports_descriptor_bound_process_names(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)
            for pid, name in ((321, "file-manager\n"), (654, "bash\n")):
                process = proc_root / str(pid)
                process.mkdir()
                (process / "comm").write_text(name)
                self.write_proc_stat(process, pid, 1000 + pid)

            calls = []

            def popen(argv, **kwargs):
                calls.append((argv, kwargs))
                return FakeProcess(b" 321 654 321")

            report = probe_conflicting_processes(
                "/dev/sdz1",
                finder=lambda name: "/usr/bin/fuser" if name == "fuser" else None,
                popen=popen,
                proc_root=proc_root,
            )

        self.assertEqual(report.observed_count, 2)
        self.assertEqual(
            report.processes,
            (
                ConflictingProcess(321, "file-manager", os.getuid()),
                ConflictingProcess(654, "bash", os.getuid()),
            ),
        )
        self.assertEqual(calls[0][0], ["/usr/bin/fuser", "-m", "/dev/sdz1"])
        self.assertFalse(calls[0][1]["shell"])
        self.assertEqual(len(calls), 2)

    def test_untrusted_or_failed_probe_returns_no_diagnostics(self):
        popen = Mock()
        self.assertEqual(
            probe_conflicting_processes(
                "/dev/sdz", finder=lambda _name: "/tmp/fuser", popen=popen,
            ),
            ConflictReport((), 0),
        )
        popen.assert_not_called()
        for process in (
            FakeProcess(b"", b"not found", 1),
            FakeProcess(b"9" * 70000),
        ):
            with self.subTest(returncode=process.returncode):
                self.assertEqual(
                    probe_conflicting_processes(
                        "/dev/sdz",
                        finder=lambda _name: "/usr/bin/fuser",
                        popen=lambda *_args, process=process, **_kwargs: process,
                    ),
                    ConflictReport((), 0),
                )

    def test_suffix_is_bounded_to_names_pids_and_users(self):
        report = ConflictReport(
            (ConflictingProcess(10, "Files", 1000),), 3,
        )
        self.assertEqual(
            conflict_diagnostic_suffix(
                "/tmp/not-a-device", exists=lambda _path: True,
            ),
            "",
        )

        # Keep one direct formatting assertion independent from /proc timing.
        with patch(
            "isopropyl.conflicts.probe_conflicting_processes",
            return_value=report,
        ):
            rendered = conflict_diagnostic_suffix(
                "/dev/sdz1", exists=lambda _path: True,
            )
        self.assertIn("Files (PID 10, UID 1000)", rendered)
        self.assertIn("and 2 more", rendered)

    def test_vanished_or_replaced_pid_is_omitted(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)
            process = proc_root / "321"
            process.mkdir()
            (process / "comm").write_text("old-owner\n")
            self.write_proc_stat(process, 321, 1000)
            outputs = iter((b"321", b"654"))

            report = probe_conflicting_processes(
                "/dev/sdz1",
                finder=lambda _name: "/usr/bin/fuser",
                popen=lambda *_args, **_kwargs: FakeProcess(next(outputs)),
                proc_root=proc_root,
            )

        self.assertEqual(report, ConflictReport((), 0))

    def test_reused_pid_starttime_is_not_misattributed(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)
            process = proc_root / "321"
            process.mkdir()
            (process / "comm").write_text("old-owner\n")
            self.write_proc_stat(process, 321, 1000)
            calls = 0

            def popen(*_args, **_kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    self.write_proc_stat(process, 321, 2000)
                    (process / "comm").write_text("replacement\n")
                return FakeProcess(b"321")

            report = probe_conflicting_processes(
                "/dev/sdz1",
                finder=lambda _name: "/usr/bin/fuser",
                popen=popen,
                proc_root=proc_root,
            )

        self.assertEqual(report.processes, ())
