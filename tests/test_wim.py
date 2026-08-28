# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import io
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
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
    WimExtractExecutor,
    WimInfo,
    WimMetadataError,
    WimSplitExecutor,
    WimToolUnavailable,
    WimValidationError,
    _stop_process,
    create_extract_plan,
    create_split_plan,
    extract_command,
    inspect_wim,
    parse_wim_info_xml,
    requires_fat32_split,
    resolve_wimlib,
    run_bounded_command,
    split_command,
    validate_extract_plan,
    validate_split_plan,
    validate_wim_selection,
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
        self.assertEqual(editions[1].expanded_bytes, 0)
        # `wimlib-imagex info --xml` emits UTF-16LE with a byte-order mark.
        utf16 = INFO_XML.decode("utf-8").replace("UTF-8", "UTF-16").encode("utf-16")
        self.assertEqual(parse_wim_info_xml(utf16), editions)

    def test_parses_64_bit_expanded_image_size(self):
        payload = INFO_XML.replace(
            b'<IMAGE INDEX="2">',
            b'<IMAGE INDEX="2"><TOTALBYTES>17179869184</TOTALBYTES>',
        )
        editions = parse_wim_info_xml(payload)
        self.assertEqual(editions[1].expanded_bytes, 16 * 1024**3)
        for value in (b"-1", b"9223372036854775808"):
            with self.subTest(value=value), self.assertRaises(WimMetadataError):
                parse_wim_info_xml(payload.replace(b"17179869184", value))

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
        self.assertEqual(info.source_identity[2], 3)
        self.assertEqual(calls[0][0][:2], [TOOL, "info"])
        self.assertRegex(calls[0][0][2], r"^/proc/self/fd/[0-9]+$")
        self.assertEqual(calls[0][0][3], "--xml")
        self.assertEqual(
            calls[0][1]["pass_fds"],
            (int(calls[0][0][2].rsplit("/", 1)[1]),),
        )
        self.assertEqual(calls[0][1]["max_output"], 4 * 1024 * 1024)

    def test_selection_binds_catalog_metadata_and_has_a_gui_label(self):
        editions = parse_wim_info_xml(INFO_XML)
        info = WimInfo("/tmp/install.esd", 123, editions, (1, 2, 123, 4, 5, 1))
        selection = info.select("sources/install.esd", 2, expected_size=123)
        validate_wim_selection(selection)
        self.assertEqual(selection.edition.edition_id, "Professional")
        self.assertEqual(selection.edition.version, "10.0.26100.2454")
        self.assertIn("Index 2", selection.display_label)
        self.assertIn("build 10.0.26100.2454", selection.display_label)
        self.assertIn("AMD64", selection.display_label)
        with self.assertRaisesRegex(WimValidationError, "catalog size"):
            info.select("sources/install.esd", 2, expected_size=124)
        for forged in (
            replace(selection, selected_index=99),
            replace(selection, source_name="sources/boot.wim"),
            replace(selection, source_name="../sources/install.wim"),
            replace(selection, source_name="C:/sources/install.wim"),
            replace(selection, source_name="x64/sources/install.wim:stream"),
            replace(selection, source_name="x64/sources/install.esd"),
            replace(selection, source_name="x64%name/sources/install.wim"),
            replace(selection, source_name="x64/CONIN$/sources/install.wim"),
            replace(selection, source_name="x64/CONOUT$.txt/sources/install.wim"),
            replace(selection, source_name="x64/COM¹/sources/install.wim"),
            replace(selection, source_name="x64/LPT².log/sources/install.wim"),
            replace(selection, source_name="x64/ leading/sources/install.wim"),
            replace(selection, source_name="x64/trailing /sources/install.wim"),
            replace(selection, source_name="x64/\x85/sources/install.wim"),
            replace(selection, source_name="x64/\u2066/sources/install.wim"),
            replace(selection, source_name="x64/\ud800/sources/install.wim"),
            replace(selection, source_name="x64/e\u0301/sources/install.wim"),
            replace(selection, source_name=f"{'a' * 256}/sources/install.wim"),
            replace(
                selection,
                source_name=f"{'/'.join(['a' * 200] * 6)}/sources/install.wim",
            ),
            replace(
                selection,
                source_name=f"{'/'.join(['a'] * 15)}/sources/install.wim",
            ),
            replace(selection, editions=(editions[0], editions[0])),
        ):
            with self.subTest(forged=forged), self.assertRaises(WimValidationError):
                validate_wim_selection(forged)

        nested = replace(selection, source_name="x64/sources/install.wim")
        validate_wim_selection(nested)
        self.assertEqual(nested.source_name, "x64/sources/install.wim")

    def test_inspection_rejects_source_identity_change_during_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "install.wim"
            source.write_bytes(b"before")

            def runner(_argv, **_kwargs):
                source.write_bytes(b"changed source")
                return CommandResult(0, INFO_XML, b"")

            with self.assertRaisesRegex(WimValidationError, "changed"):
                inspect_wim(source, which=trusted, runner=runner)

    def test_inspection_rejects_same_size_rewrite_with_restored_mtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "install.wim"
            source.write_bytes(b"GOOD")
            before = source.stat()

            def runner(_argv, **_kwargs):
                source.write_bytes(b"EVIL")
                os.utime(
                    source,
                    ns=(before.st_atime_ns, before.st_mtime_ns),
                )
                return CommandResult(0, INFO_XML, b"")

            with self.assertRaisesRegex(WimValidationError, "changed"):
                inspect_wim(source, which=trusted, runner=runner)

    def test_inspection_uses_bound_descriptor_during_path_rebind(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "install.wim"
            source.write_bytes(b"GOOD")
            original = source.with_name("original.wim")
            observed = []

            def runner(argv, **kwargs):
                self.assertEqual(
                    kwargs["pass_fds"], (int(argv[2].rsplit("/", 1)[1]),),
                )
                source.rename(original)
                source.write_bytes(b"EVIL")
                observed.append(Path(argv[2]).read_bytes())
                source.unlink()
                original.rename(source)
                return CommandResult(0, INFO_XML, b"")

            with self.assertRaisesRegex(WimValidationError, "changed"):
                inspect_wim(source, which=trusted, runner=runner)
            self.assertEqual(observed, [b"GOOD"])

    def test_inspection_propagates_cancellation_to_bounded_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "install.wim"
            source.write_bytes(b"wim")
            cancelled = threading.Event()
            cancelled.set()
            with self.assertRaises(WimCancelled):
                inspect_wim(
                    source, which=trusted, cancel_event=cancelled,
                )

    def test_in_flight_info_cancellation_terminates_child(self):
        cancelled = threading.Event()
        started = threading.Event()
        processes = []

        def popen(argv, **kwargs):
            process = FakeProcess(argv, blocked=True, **kwargs)
            processes.append(process)
            return process

        def runner(argv, **kwargs):
            return run_bounded_command(
                argv,
                popen=popen,
                process_started=lambda _process: started.set(),
                **kwargs,
            )

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "install.wim"
            source.write_bytes(b"wim")
            errors = []

            def inspect() -> None:
                try:
                    inspect_wim(
                        source, which=trusted, runner=runner,
                        cancel_event=cancelled,
                    )
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(target=inspect)
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            cancelled.set()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], WimCancelled)
            self.assertEqual(len(processes), 1)
            self.assertTrue(processes[0].terminated)

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

    def test_inspection_rejects_symlink_and_multiply_linked_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.wim"
            source.write_bytes(b"wim")
            symlink = root / "symlink.wim"
            symlink.symlink_to(source)
            hardlink = root / "hardlink.wim"
            os.link(source, hardlink)
            for candidate in (symlink, source, hardlink):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(WimValidationError):
                        inspect_wim(candidate, which=trusted)

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

    def test_bounded_runner_accepts_only_explicit_safe_environment_and_cwd(self):
        calls = []

        def popen(argv, **kwargs):
            calls.append((argv, kwargs))
            return FakeProcess(argv, **kwargs)

        result = run_bounded_command(
            [TOOL, "--version"],
            timeout_seconds=1,
            max_output=1024,
            popen=popen,
            environment={"LC_ALL": "C", "TZ": "UTC"},
            working_directory="/",
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(calls[0][1]["env"], {"LC_ALL": "C", "TZ": "UTC"})
        self.assertEqual(calls[0][1]["cwd"], "/")
        self.assertTrue(calls[0][1]["close_fds"])
        self.assertFalse(calls[0][1]["start_new_session"])
        for environment, directory in (
            ({"BAD=KEY": "value"}, "/"),
            ({"KEY": "bad\0value"}, "/"),
            ({"KEY": True}, "/"),
            ({"KEY": "value"}, "relative"),
            ({"KEY": "value"}, "/tmp/../tmp"),
        ):
            with self.subTest(environment=environment, directory=directory), self.assertRaises(
                WimValidationError,
            ):
                run_bounded_command(
                    [TOOL, "--version"],
                    timeout_seconds=1,
                    max_output=1024,
                    popen=popen,
                    environment=environment,  # type: ignore[arg-type]
                    working_directory=directory,
                )

    def test_group_cleanup_kills_descendants_after_leader_exit(self):
        process = FakeProcess([TOOL], code=0)
        process.pid = 4242
        group_checks = 0
        signals = []

        def killpg(_pid, requested):
            nonlocal group_checks
            signals.append(requested)
            if requested == 0:
                group_checks += 1
                if group_checks >= 3:
                    raise ProcessLookupError

        with (
            patch("isopropyl.wim.os.killpg", side_effect=killpg),
            patch("isopropyl.wim.time.monotonic", side_effect=(0, 3, 3, 6)),
        ):
            _stop_process(process, process_group=True)
        self.assertIn(signal.SIGTERM, signals)
        self.assertIn(signal.SIGKILL, signals)

    def test_group_cleanup_reaps_real_forked_term_ignoring_descendant(self):
        cancelled = threading.Event()
        leader_pids = []
        timer = threading.Timer(0.25, cancelled.set)
        timer.start()
        started = time.monotonic()
        try:
            with self.assertRaises(WimCancelled):
                run_bounded_command(
                    (
                        sys.executable,
                        "-c",
                        "import os,signal,time;"
                        "pid=os.fork();"
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN) "
                        "if pid == 0 else None;"
                        "time.sleep(30)",
                    ),
                    timeout_seconds=10,
                    max_output=1024,
                    cancel_event=cancelled,
                    process_started=lambda process: leader_pids.append(process.pid),
                    new_session=True,
                )
        finally:
            timer.cancel()
        self.assertLess(time.monotonic() - started, 6)
        self.assertEqual(len(leader_pids), 1)
        with self.assertRaises(ProcessLookupError):
            os.killpg(leader_pids[0], 0)

    def test_success_rejects_and_reaps_left_behind_descendant(self):
        leader_pids = []
        started = time.monotonic()
        with self.assertRaisesRegex(WimCommandError, "descendant"):
            run_bounded_command(
                (
                    sys.executable,
                    "-c",
                    "import os,signal,time;"
                    "pid=os.fork();"
                    "(os.close(1),os.close(2),"
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN),"
                    "time.sleep(30)) if pid == 0 else os._exit(0)",
                ),
                timeout_seconds=10,
                max_output=1024,
                process_started=lambda process: leader_pids.append(process.pid),
                new_session=True,
            )
        self.assertLess(time.monotonic() - started, 6)
        self.assertEqual(len(leader_pids), 1)
        with self.assertRaises(ProcessLookupError):
            os.killpg(leader_pids[0], 0)


class WimExtractTests(unittest.TestCase):
    PATHS = ("Windows/Boot/EFI_EX", "Windows/Boot/Fonts_EX")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "boot.wim"
        self.source.write_bytes(b"bound boot wim")
        self.destination = self.root / "bootex"

    def tearDown(self):
        self.temporary.cleanup()

    def plan(self, **kwargs):
        values = {
            "image_index": 2,
            "paths": self.PATHS,
            "wimlib_imagex": TOOL,
        }
        values.update(kwargs)
        return create_extract_plan(self.source, self.destination, **values)

    @staticmethod
    def populate(argv, *, extra=None):
        destination_argument = next(
            argument for argument in argv if argument.startswith("--dest-dir=")
        )
        destination = Path(destination_argument.split("=", 1)[1])
        efi = destination / "Windows" / "Boot" / "EFI_EX"
        fonts = destination / "Windows" / "Boot" / "Fonts_EX"
        efi.mkdir(parents=True)
        fonts.mkdir()
        (efi / "bootmgfw_EX.efi").write_bytes(b"signed efi")
        (fonts / "wgl4_boot.ttf").write_bytes(b"font")
        if extra is not None:
            extra(destination)

    def test_plan_binds_one_source_and_builds_exact_no_glob_argv(self):
        plan = self.plan()
        self.assertEqual(plan.source, str(self.source.resolve()))
        self.assertEqual(plan.source_identity[2], len(b"bound boot wim"))
        staged = (self.root / "private-stage").resolve()
        self.assertEqual(extract_command(plan, staged), [
            TOOL,
            "extract",
            str(self.source.resolve()),
            "2",
            *self.PATHS,
            f"--dest-dir={staged}",
            "--no-globs",
            "--preserve-dir-structure",
            "--no-acls",
            "--no-attributes",
            "--check",
        ])

    def test_success_uses_bound_descriptor_and_commits_private_tree(self):
        calls = []

        def popen(argv, **kwargs):
            self.populate(argv)
            calls.append((argv, kwargs))
            return FakeProcess(argv, **kwargs)

        stages = []
        result = WimExtractExecutor(popen=popen).execute(self.plan(), stages.append)
        self.assertEqual(result.directory, str(self.destination))
        self.assertEqual(result.total_size, len(b"signed efi") + len(b"font"))
        self.assertEqual(
            [Path(path).relative_to(self.destination).as_posix() for path in result.files],
            [
                "Windows/Boot/EFI_EX/bootmgfw_EX.efi",
                "Windows/Boot/Fonts_EX/wgl4_boot.ttf",
            ],
        )
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)
        self.assertRegex(calls[0][0][2], r"^/proc/self/fd/[0-9]+$")
        descriptor = int(calls[0][0][2].rsplit("/", 1)[1])
        self.assertEqual(calls[0][1]["pass_fds"], (descriptor,))
        self.assertFalse(calls[0][1]["shell"])
        self.assertEqual(stages[-1], "Complete")
        self.assertEqual(list(self.root.glob(".bootex.*.partial")), [])

    def test_rejects_unsafe_overlapping_or_forged_requests(self):
        invalid_paths = (
            (),
            ("Windows\\Boot\\EFI_EX",),
            ("/Windows/Boot/EFI_EX",),
            ("--to-stdout",),
            ("@attacker-list",),
            ("Windows/../EFI_EX",),
            ("Windows/Boot/*",),
            ("Windows/Boot/EFI_EX", "windows/boot/efi_ex"),
            ("Windows/Boot", "Windows/Boot/EFI_EX"),
            ("Windows/COM1/file",),
            ("Windows/Boot/ trailing",),
            ("Windows/Boot/e\u0301",),
        )
        for paths in invalid_paths:
            with self.subTest(paths=paths), self.assertRaises(WimValidationError):
                self.plan(paths=paths)
        plan = self.plan()
        for forged in (
            replace(plan, image_index=True),
            replace(plan, source="boot.wim"),
            replace(plan, paths=list(plan.paths)),
            replace(plan, destination_directory="relative"),
            replace(plan, wimlib_imagex="/tmp/wimlib-imagex"),
            replace(plan, source_identity=(1, 2, 3)),
        ):
            with self.subTest(forged=forged), self.assertRaises(
                (WimValidationError, WimToolUnavailable)
            ):
                validate_extract_plan(forged)
        esd = self.root / "boot.esd"
        esd.write_bytes(b"esd")
        with self.assertRaisesRegex(WimValidationError, "non-spanned"):
            create_extract_plan(
                esd, self.root / "esd-output", image_index=1,
                paths=("Windows/Boot/EFI_EX",), wimlib_imagex=TOOL,
            )

    def test_changed_source_is_rejected_before_spawn(self):
        plan = self.plan()
        self.source.write_bytes(b"a changed boot wim")
        calls = []
        with self.assertRaisesRegex(WimValidationError, "changed"):
            WimExtractExecutor(
                popen=lambda *args, **kwargs: calls.append((args, kwargs))
            ).execute(plan)
        self.assertEqual(calls, [])
        self.assertFalse(self.destination.exists())

    def test_bound_descriptor_survives_path_rebind_but_operation_fails_closed(self):
        plan = self.plan()
        original = self.root / "original.wim"
        observed = []

        def popen(argv, **kwargs):
            self.source.rename(original)
            self.source.write_bytes(b"attacker source")
            observed.append(Path(argv[2]).read_bytes())
            self.source.unlink()
            original.rename(self.source)
            self.populate(argv)
            return FakeProcess(argv, **kwargs)

        with self.assertRaisesRegex(WimValidationError, "changed"):
            WimExtractExecutor(popen=popen).execute(plan)
        self.assertEqual(observed, [b"bound boot wim"])
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".bootex.*.partial")), [])

    def test_missing_unexpected_special_or_excessive_outputs_never_commit(self):
        def run(extra=None, *, populate=True):
            def popen(argv, **kwargs):
                if populate:
                    self.populate(argv, extra=extra)
                return FakeProcess(argv, **kwargs)

            return WimExtractExecutor(popen=popen).execute(self.plan())

        with self.assertRaisesRegex(WimCommandError, "every requested"):
            run(populate=False)
        self.assertFalse(self.destination.exists())

        def unexpected(destination):
            (destination / "outside.txt").write_bytes(b"no")

        with self.assertRaisesRegex(WimCommandError, "unexpected extraction file"):
            run(unexpected)
        self.assertFalse(self.destination.exists())

        def symlink(destination):
            (destination / "Windows" / "Boot" / "EFI_EX" / "link").symlink_to(
                "/etc/passwd"
            )

        with self.assertRaisesRegex(WimCommandError, "non-regular"):
            run(symlink)
        self.assertFalse(self.destination.exists())

        def outside_hardlink(destination):
            external = self.root / "outside-hardlink"
            external.write_bytes(b"linked")
            os.link(
                external,
                destination / "Windows" / "Boot" / "EFI_EX" / "linked.efi",
            )

        with self.assertRaisesRegex(WimCommandError, "links outside"):
            run(outside_hardlink)
        self.assertFalse(self.destination.exists())

        def oversized(destination):
            with (destination / "Windows" / "Boot" / "EFI_EX" / "huge").open(
                "wb"
            ) as stream:
                stream.truncate(512 * 1024 * 1024 + 1)

        with self.assertRaisesRegex(WimCommandError, "too large"):
            run(oversized)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".bootex.*.partial")), [])

    def test_internal_hardlinks_are_contained_and_allowed(self):
        def popen(argv, **kwargs):
            def link_copy(destination):
                efi = destination / "Windows" / "Boot" / "EFI_EX"
                os.link(efi / "bootmgfw_EX.efi", efi / "bootmgr_EX.efi")

            self.populate(argv, extra=link_copy)
            return FakeProcess(argv, **kwargs)

        result = WimExtractExecutor(popen=popen).execute(self.plan())
        boot_files = [path for path in result.files if path.endswith(".efi")]
        self.assertEqual(len(boot_files), 2)
        self.assertEqual(os.stat(boot_files[0]).st_ino, os.stat(boot_files[1]).st_ino)

    def test_command_failure_and_output_overflow_fail_closed(self):
        def failed(argv, **kwargs):
            return FakeProcess(argv, stderr_data=b"extract failed", code=5, **kwargs)

        with self.assertRaisesRegex(WimCommandError, "extract failed"):
            WimExtractExecutor(popen=failed).execute(self.plan())
        self.assertFalse(self.destination.exists())

        def noisy(argv, **kwargs):
            return FakeProcess(argv, stdout_data=b"x" * (1024 * 1024 + 1), **kwargs)

        with self.assertRaisesRegex(WimCommandError, "too much output"):
            WimExtractExecutor(popen=noisy).execute(self.plan())
        self.assertFalse(self.destination.exists())

    def test_preflight_and_in_flight_cancellation_leave_nothing(self):
        executor = WimExtractExecutor(popen=lambda *_args, **_kwargs: None)
        executor.cancel()
        with self.assertRaises(WimCancelled):
            executor.execute(self.plan())
        self.assertFalse(self.destination.exists())

        started = threading.Event()
        holder = {}

        def popen(argv, **kwargs):
            process = FakeProcess(argv, blocked=True, **kwargs)
            holder["process"] = process
            started.set()
            return process

        executor = WimExtractExecutor(popen=popen)
        errors = []

        def execute():
            try:
                executor.execute(self.plan())
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=execute)
        thread.start()
        self.assertTrue(started.wait(timeout=2))
        executor.cancel()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertTrue(holder["process"].terminated)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], WimCancelled)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".bootex.*.partial")), [])

    @unittest.skipUnless(
        Path(TOOL).is_file(),
        "wimlib-imagex is required for the production extraction integration test",
    )
    def test_real_wimlib_extracts_exact_index_two_paths_with_structure(self):
        empty = self.root / "empty-image"
        empty.mkdir()
        source_tree = self.root / "setup-image"
        efi = source_tree / "Windows" / "Boot" / "EFI_EX"
        fonts = source_tree / "Windows" / "Boot" / "Fonts_EX"
        efi.mkdir(parents=True)
        fonts.mkdir(parents=True)
        (efi / "bootmgfw_EX.efi").write_bytes(b"MZfixture")
        (fonts / "font_EX.ttf").write_bytes(b"font")
        source_wim = self.root / "synthetic-boot.wim"
        environment = {**os.environ, "LC_ALL": "C", "LANG": "C"}
        subprocess.run(
            [
                TOOL, "capture", str(empty), str(source_wim), "placeholder",
                "--compress=none",
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        subprocess.run(
            [TOOL, "append", str(source_tree), str(source_wim), "setup"],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )

        destination = self.root / "real-extract"
        plan = create_extract_plan(
            source_wim,
            destination,
            image_index=2,
            paths=("Windows/Boot/EFI_EX", "Windows/Boot/Fonts_EX"),
            wimlib_imagex=TOOL,
        )
        result = WimExtractExecutor().execute(plan)

        self.assertEqual(result.directory, str(destination))
        self.assertEqual(result.total_size, 13)
        self.assertEqual(
            (destination / "Windows/Boot/EFI_EX/bootmgfw_EX.efi").read_bytes(),
            b"MZfixture",
        )
        self.assertEqual(
            (destination / "Windows/Boot/Fonts_EX/font_EX.ttf").read_bytes(),
            b"font",
        )


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
        expected_command = split_command(plan, Path(processes[0].argv[3]))
        expected_command[2] = processes[0].argv[2]
        self.assertEqual(processes[0].argv, expected_command)
        self.assertRegex(processes[0].argv[2], r"^/proc/self/fd/[0-9]+$")
        self.assertEqual(
            processes[0].kwargs["pass_fds"],
            (int(processes[0].argv[2].rsplit("/", 1)[1]),),
        )
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

    def test_splitter_reads_bound_descriptor_and_rejects_path_rebind(self):
        plan = self.plan()
        original = self.source.with_name("original-install.wim")
        observed = []

        def popen(argv, **kwargs):
            self.source.rename(original)
            with self.source.open("wb") as stream:
                stream.write(b"EVIL")
                stream.truncate(plan.source_identity[2])
            with Path(argv[2]).open("rb") as stream:
                observed.append(stream.read(4))
            self.source.unlink()
            original.rename(self.source)
            first = Path(argv[3])
            first.write_bytes(b"part one")
            first.with_name("install2.swm").write_bytes(b"part two")
            return FakeProcess(argv, **kwargs)

        with self.assertRaisesRegex(WimValidationError, "changed"):
            WimSplitExecutor(popen=popen).execute(plan)
        self.assertEqual(observed, [b"\0\0\0\0"])
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
