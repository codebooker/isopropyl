# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import io
import os
import subprocess
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from isopropyl.wim import (
    DEFAULT_SPLIT_PART_MIB,
    FAT32_MAX_FILE_SIZE,
    MAX_SPLIT_PART_MIB,
    CommandResult,
    WimCancelled,
    WimCommandError,
    WimMetadataError,
    WimSplitExecutor,
    WimToolUnavailable,
    WimValidationError,
    create_split_plan,
    inspect_wim,
    parse_wim_info_xml,
    requires_fat32_split,
    resolve_wimlib,
    run_bounded_command,
    split_command,
    validate_split_plan,
)

TOOL = "/usr/bin/wimlib-imagex"

INFO_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<WIM>
  <IMAGE INDEX="2">
    <NAME>Windows 11 Pro</NAME>
    <DESCRIPTION>Windows 11 Pro</DESCRIPTION>
    <WINDOWS>
      <ARCH>9</ARCH>
      <EDITIONID>Professional</EDITIONID>
      <VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>26100</BUILD><SPBUILD>2454</SPBUILD></VERSION>
    </WINDOWS>
  </IMAGE>
  <IMAGE INDEX="1">
    <NAME>Windows 11 Home ARM</NAME>
    <WINDOWS>
      <ARCH>12</ARCH>
      <EDITIONID>Core</EDITIONID>
      <VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>26100</BUILD></VERSION>
    </WINDOWS>
  </IMAGE>
</WIM>
"""


class FakeProcess:
    def __init__(
        self, argv, *, stdout_data=b"", stderr_data=b"", code=0,
        blocked=False, **kwargs,
    ):
        self.argv = argv
        self.kwargs = kwargs
        self.stdout = io.BytesIO(stdout_data)
        self.stderr = io.BytesIO(stderr_data)
        self.returncode = None if blocked else code
        self._completion_code = code
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.argv, timeout)
        return self.returncode


def trusted(_name):
    return TOOL


class WimInfoTests(unittest.TestCase):
    def test_parses_edition_index_architecture_and_build(self):
        editions = parse_wim_info_xml(INFO_XML)
        self.assertEqual([edition.index for edition in editions], [1, 2])
        self.assertEqual(editions[0].architecture, "arm64")
        self.assertEqual(editions[0].edition_id, "Core")
        self.assertEqual(editions[0].build, 26100)
        self.assertEqual(editions[0].service_pack_build, 0)
        self.assertEqual(editions[1].architecture, "amd64")
        self.assertEqual(editions[1].name, "Windows 11 Pro")
        # `wimlib-imagex info --xml` emits UTF-16LE with a byte-order mark.
        utf16 = INFO_XML.decode("utf-8").replace("UTF-8", "UTF-16").encode("utf-16")
        self.assertEqual(parse_wim_info_xml(utf16), editions)

    def test_rejects_malformed_unsafe_or_incomplete_xml(self):
        invalid = (
            b"not xml",
            b"<!DOCTYPE WIM [<!ENTITY x 'boom'>]><WIM>&x;</WIM>",
            "<!DOCTYPE WIM><WIM/>".encode("utf-16"),
            b"<NOTWIM><IMAGE INDEX='1'/></NOTWIM>",
            INFO_XML.replace(b'<IMAGE INDEX="2">', b'<IMAGE INDEX="1">'),
            INFO_XML.replace(b"<ARCH>9</ARCH>", b"<ARCH>99</ARCH>"),
            INFO_XML.replace(b"<EDITIONID>Professional</EDITIONID>", b""),
            INFO_XML.replace(b"<BUILD>26100</BUILD>", b"<BUILD>nope</BUILD>", 1),
        )
        for payload in invalid:
            with self.subTest(payload=payload[:50]), self.assertRaises(WimMetadataError):
                parse_wim_info_xml(payload)

    def test_inspection_uses_fixed_argv_and_accepts_esd(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return CommandResult(0, INFO_XML, b"")

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "install.esd"
            source.write_bytes(b"esd")
            info = inspect_wim(source, which=trusted, runner=runner)
        self.assertEqual(info.path, str(source.resolve()))
        self.assertEqual(len(info.editions), 2)
        self.assertEqual(calls[0][0], [TOOL, "info", str(source.resolve()), "--xml"])
        self.assertEqual(calls[0][1]["max_output"], 4 * 1024 * 1024)

    def test_missing_tool_or_command_failure_fails_closed(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return CommandResult(3, b"", b"broken\x00 metadata")

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "install.wim"
            source.write_bytes(b"wim")
            with self.assertRaises(WimToolUnavailable):
                inspect_wim(source, which=lambda _name: None, runner=runner)
            self.assertEqual(calls, [])
            with self.assertRaisesRegex(WimCommandError, "broken metadata"):
                inspect_wim(source, which=trusted, runner=runner)

    @patch("isopropyl.wim.shutil.which")
    def test_resolution_ignores_session_path_and_rejects_untrusted_paths(self, which):
        which.return_value = TOOL
        self.assertEqual(resolve_wimlib(), TOOL)
        which.assert_called_once_with(
            "wimlib-imagex", path="/usr/sbin:/usr/bin:/sbin:/bin",
        )
        for value in (
            "wimlib-imagex", "/tmp/wimlib-imagex", "/usr/bin/../bin/wimlib-imagex",
            "/usr/bin/not-wimlib",
        ):
            with self.subTest(value=value), self.assertRaises(WimToolUnavailable):
                resolve_wimlib(lambda _name, value=value: value)

    def test_bounded_runner_never_uses_a_shell_and_caps_output(self):
        seen = []

        def popen(argv, **kwargs):
            seen.append((argv, kwargs))
            return FakeProcess(argv, stdout_data=b"12345", **kwargs)

        with self.assertRaisesRegex(WimCommandError, "too much output"):
            run_bounded_command(
                [TOOL, "info", "/tmp/a.wim", "--xml"], timeout_seconds=1,
                max_output=4, popen=popen,
            )
        self.assertFalse(seen[0][1]["shell"])
        self.assertEqual(seen[0][1]["stdin"], subprocess.DEVNULL)


class WimSplitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "install.wim"
        with self.source.open("wb") as stream:
            stream.truncate(FAT32_MAX_FILE_SIZE + 1024)
        self.destination = self.root / "split-media"

    def tearDown(self):
        self.temporary.cleanup()

    def plan(self, **kwargs):
        return create_split_plan(
            self.source, self.destination, which=trusted, **kwargs,
        )

    def test_fat32_boundary_is_exact(self):
        self.assertFalse(requires_fat32_split(FAT32_MAX_FILE_SIZE))
        self.assertTrue(requires_fat32_split(FAT32_MAX_FILE_SIZE + 1))
        for value in (-1, True, 1.2):
            with self.subTest(value=value), self.assertRaises(WimValidationError):
                requires_fat32_split(value)  # type: ignore[arg-type]

    def test_plan_is_bound_to_source_identity_and_exact_command(self):
        plan = self.plan()
        self.assertEqual(plan.part_size_mib, DEFAULT_SPLIT_PART_MIB)
        self.assertEqual(plan.wimlib_imagex, TOOL)
        staged = self.root / "stage" / "install.swm"
        command = split_command(plan, staged)
        self.assertEqual(command, [
            TOOL, "split", str(self.source.resolve()), str(staged),
            str(DEFAULT_SPLIT_PART_MIB), "--check",
        ])

    def test_plan_rejects_unneeded_wrong_named_or_unsafe_splits(self):
        small = self.root / "small.wim"
        small.write_bytes(b"small")
        with self.assertRaisesRegex(WimValidationError, "install.wim"):
            create_split_plan(small, self.destination, which=trusted)
        self.source.unlink()
        self.source.write_bytes(b"small")
        with self.assertRaisesRegex(WimValidationError, "does not require"):
            create_split_plan(self.source, self.destination, which=trusted)
        with self.assertRaises(WimValidationError):
            create_split_plan(self.source, self.destination, part_size_mib=0, which=trusted)
        with self.assertRaises(WimValidationError):
            create_split_plan(
                self.source, self.destination, part_size_mib=MAX_SPLIT_PART_MIB + 1,
                which=trusted,
            )

    def test_existing_destination_is_never_used(self):
        self.destination.mkdir()
        with self.assertRaisesRegex(WimValidationError, "must not already exist"):
            self.plan()

    def test_success_commits_complete_parts_as_one_directory_rename(self):
        plan = self.plan()
        processes = []

        def popen(argv, **kwargs):
            first = Path(argv[3])
            first.write_bytes(b"part one")
            first.with_name("install2.swm").write_bytes(b"part two")
            process = FakeProcess(argv, **kwargs)
            processes.append(process)
            return process

        stages = []
        result = WimSplitExecutor(popen=popen).execute(plan, stages.append)
        self.assertEqual(result.directory, str(self.destination))
        self.assertEqual(
            [Path(part).name for part in result.parts], ["install.swm", "install2.swm"],
        )
        self.assertEqual(result.total_size, len(b"part one") + len(b"part two"))
        self.assertTrue(all(Path(part).is_file() for part in result.parts))
        self.assertFalse(processes[0].kwargs["shell"])
        self.assertEqual(processes[0].argv, split_command(plan, Path(processes[0].argv[3])))
        self.assertEqual(stages[-1], "Complete")
        self.assertEqual(list(self.root.glob(".split-media.*.partial")), [])

    def test_changed_source_is_rejected_before_staging_or_spawn(self):
        plan = self.plan()
        with self.source.open("r+b") as stream:
            stream.truncate(FAT32_MAX_FILE_SIZE + 2048)
        called = []
        executor = WimSplitExecutor(popen=lambda *args, **kwargs: called.append(args))
        with self.assertRaisesRegex(WimValidationError, "changed"):
            executor.execute(plan)
        self.assertEqual(called, [])
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".split-media.*.partial")), [])

    def test_cancellation_before_start_creates_nothing(self):
        plan = self.plan()
        called = []
        executor = WimSplitExecutor(popen=lambda *args, **kwargs: called.append(args))
        executor.cancel()
        with self.assertRaises(WimCancelled):
            executor.execute(plan)
        self.assertEqual(called, [])
        self.assertFalse(self.destination.exists())

    def test_in_flight_cancellation_terminates_and_removes_staging(self):
        plan = self.plan()
        started = threading.Event()
        holder = {}

        def popen(argv, **kwargs):
            process = FakeProcess(argv, blocked=True, **kwargs)
            holder["process"] = process
            started.set()
            return process

        executor = WimSplitExecutor(popen=popen)
        errors = []

        def run():
            try:
                executor.execute(plan)
            except Exception as error:  # captured for assertion in the main test thread
                errors.append(error)

        thread = threading.Thread(target=run)
        thread.start()
        self.assertTrue(started.wait(timeout=2))
        executor.cancel()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertTrue(holder["process"].terminated)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], WimCancelled)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".split-media.*.partial")), [])

    def test_failure_or_malformed_outputs_never_commit(self):
        plan = self.plan()

        def failed(argv, **kwargs):
            return FakeProcess(argv, stderr_data=b"split failed", code=5, **kwargs)

        with self.assertRaisesRegex(WimCommandError, "split failed"):
            WimSplitExecutor(popen=failed).execute(plan)
        self.assertFalse(self.destination.exists())

        def gap(argv, **kwargs):
            first = Path(argv[3])
            first.write_bytes(b"one")
            first.with_name("install3.swm").write_bytes(b"three")
            return FakeProcess(argv, **kwargs)

        with self.assertRaisesRegex(WimCommandError, "incomplete"):
            WimSplitExecutor(popen=gap).execute(plan)
        self.assertFalse(self.destination.exists())

        def oversized(argv, **kwargs):
            first = Path(argv[3])
            with first.open("wb") as stream:
                stream.truncate(FAT32_MAX_FILE_SIZE + 1)
            first.with_name("install2.swm").write_bytes(b"two")
            return FakeProcess(argv, **kwargs)

        with self.assertRaisesRegex(WimCommandError, "too large for FAT32"):
            WimSplitExecutor(popen=oversized).execute(plan)
        self.assertFalse(self.destination.exists())

    def test_forged_plan_and_reuse_fail_closed(self):
        plan = self.plan()
        with self.assertRaises(WimToolUnavailable):
            validate_split_plan(replace(plan, wimlib_imagex="/tmp/wimlib-imagex"))
        executor = WimSplitExecutor(popen=lambda argv, **kwargs: FakeProcess(argv, code=4, **kwargs))
        with self.assertRaises(WimCommandError):
            executor.execute(plan)
        with self.assertRaisesRegex(WimValidationError, "only be used once"):
            executor.execute(plan)


if __name__ == "__main__":
    unittest.main()
