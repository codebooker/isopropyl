from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import io
import os
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from isopropyl.cli import (
    CancellationController,
    CliDependencies,
    ExitCode,
    ProgressReporter,
    run,
)
from isopropyl.devices import Device
from isopropyl.images import ImageInspection
from isopropyl.raw_device import RawDeviceWritePlan, RawSourceEvidence
from isopropyl.raw_device_runner import RawDeviceWriteResult
from isopropyl.raw_workflow import (
    RawWorkflowCancelled,
    RawWorkflowError,
    RawWorkflowState,
)


class TtyStringIO(io.StringIO):
    def isatty(self) -> bool:
        return True


class SignalOnReadTty(TtyStringIO):
    def __init__(self, signum: int) -> None:
        super().__init__()
        self.signum = signum

    def readline(self, *args, **kwargs):
        os.kill(os.getpid(), self.signum)
        return super().readline(*args, **kwargs)


class SignalOnCompletionOutput(io.StringIO):
    def __init__(self, signum: int) -> None:
        super().__init__()
        self.signum = signum
        self.triggered = False

    def write(self, value: str) -> int:
        if not self.triggered and value.startswith("Write complete"):
            self.triggered = True
            os.kill(os.getpid(), self.signum)
        return super().write(value)


class FailingCompletionOutput(io.StringIO):
    def write(self, value: str) -> int:
        if value.startswith("Write complete"):
            raise OSError("terminal disconnected")
        return super().write(value)


def image_inspection(**changes: object) -> ImageInspection:
    original = ImageInspection(
        size=4096,
        kind="Raw disk image",
        volume_label="",
        has_mbr=True,
        has_gpt=False,
        is_iso9660=False,
        looks_windows=False,
        boot_modes=("BIOS",),
        architectures=("x64",),
        bootloader="Unknown",
        has_windows_installer=False,
        contents_scanned=False,
    )
    return replace(original, **changes)


def target(**changes: object) -> Device:
    original = Device(
        "/dev/sdz",
        8192,
        "Test drive",
        "ISOpropyl",
        "usb",
        "PRIVATE-SERIAL",
        "PRIVATE-WWN",
        "8:240",
        True,
        True,
        False,
        ("/media/test",),
        ("/dev/sdz1",),
        512,
    )
    return replace(original, **changes)


def source_evidence() -> RawSourceEvidence:
    return RawSourceEvidence(
        source_sha256="a" * 64,
        source_size=4096,
        original_device=1,
        original_inode=2,
        original_size=4096,
        original_modified_ns=3,
        original_changed_ns=4,
        workspace_device=5,
        raw_snapshot_plan_sha256="b" * 64,
    )


def raw_plan(device: Device, *, verify: bool = True) -> RawDeviceWritePlan:
    evidence = source_evidence()
    return RawDeviceWritePlan(
        evidence,
        device,
        7,
        evidence.raw_snapshot_plan_sha256,
        evidence.snapshot_plan_sha256,
        evidence.source_sha256,
        evidence.source_size,
        evidence.original_identity,
        evidence.workspace_device,
        False,
        None,
        device.size,
        device.logical_sector_size,
        True,
        verify,
        "io.github.codebooker.isopropyl/raw-device-writer/v1",
        ("Everything on the exact target will be erased.",),
        f"WRITE RAW {device.path} {device.major_minor}",
        "c" * 64,
    )


def raw_result(plan: RawDeviceWritePlan) -> RawDeviceWriteResult:
    return RawDeviceWriteResult(
        plan.plan_sha256,
        "d" * 64,
        plan.raw_snapshot_plan_sha256,
        "00" * 32,
        plan.device.path,
        plan.device.major_minor,
        plan.disk_sequence,
        plan.target_capacity,
        plan.source_size,
        plan.source_sha256,
        plan.source_sha256,
        plan.source_sha256,
        1024,
        True,
        plan.logical_sector_size,
        plan.required_executor_profile,
        True,
        True,
        True,
        plan.final_verification_requested,
        False,
    )


class FakeWorkflow:
    def __init__(
        self,
        device: Device,
        events: list[str],
        *,
        verify: bool = True,
        prepare_error: BaseException | None = None,
        execute_error: BaseException | None = None,
    ) -> None:
        self.device = device
        self.events = events
        self.plan = raw_plan(device, verify=verify)
        self.result: RawDeviceWriteResult | None = None
        self.prepare_error = prepare_error
        self.execute_error = execute_error
        self.cancelled = False
        self.closed = False
        self.state = RawWorkflowState.CREATED

    def prepare(self, progress):
        self.events.append("prepare")
        self.state = RawWorkflowState.PREPARING
        progress("snapshot", 4096, 4096)
        if self.prepare_error is not None:
            raise self.prepare_error
        self.state = RawWorkflowState.PREPARED
        return self.plan

    def confirm(self, phrase: str):
        self.events.append("confirm")
        if phrase != self.plan.confirmation_phrase:
            raise AssertionError("CLI passed a mismatched phrase to the workflow")
        self.state = RawWorkflowState.CONFIRMED
        return object()

    def execute(self, progress):
        self.events.append("execute")
        self.state = RawWorkflowState.EXECUTING
        progress("writing", 4096, 4096)
        if self.execute_error is not None:
            raise self.execute_error
        self.result = raw_result(self.plan)
        self.state = RawWorkflowState.COMPLETED
        return self.result

    def cancel(self) -> None:
        self.events.append("cancel")
        self.cancelled = True
        self.state = RawWorkflowState.CANCELLED

    def close(self) -> None:
        self.events.append("close")
        self.closed = True
        self.state = RawWorkflowState.CLOSED


class BlockingCancelWorkflow(FakeWorkflow):
    def __init__(self, device: Device, events: list[str]) -> None:
        super().__init__(device, events)
        self.cancel_entered = threading.Event()
        self.allow_cancel = threading.Event()

    def cancel(self) -> None:
        self.cancel_entered.set()
        self.allow_cancel.wait(2)
        super().cancel()


class SignalDuringPrepareWorkflow(FakeWorkflow):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.cancel_seen = threading.Event()

    def prepare(self, progress):
        self.events.append("prepare")
        self.state = RawWorkflowState.PREPARING
        progress("snapshot", 2048, 4096)
        os.kill(os.getpid(), signal.SIGTERM)
        if not self.cancel_seen.wait(2):
            raise AssertionError("cooperative prepare cancellation was not dispatched")
        raise RawWorkflowCancelled("cancelled during preparation")

    def cancel(self) -> None:
        super().cancel()
        self.cancel_seen.set()


class SignalDuringExecuteWorkflow(FakeWorkflow):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.cancel_seen = threading.Event()

    def execute(self, progress):
        self.events.append("execute")
        self.state = RawWorkflowState.EXECUTING
        progress("writing", 2048, 4096)
        os.kill(os.getpid(), signal.SIGINT)
        if not self.cancel_seen.wait(2):
            raise AssertionError("cooperative write cancellation was not dispatched")
        raise RawWorkflowCancelled("cancelled before COMMIT")

    def cancel(self) -> None:
        super().cancel()
        self.cancel_seen.set()


class SignalAfterCommitWorkflow(FakeWorkflow):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.cancel_seen = threading.Event()

    def execute(self, progress):
        self.events.append("execute")
        self.state = RawWorkflowState.EXECUTING
        progress("verifying", 4096, 4096)
        self.result = replace(raw_result(self.plan), cancellation_deferred=True)
        self.state = RawWorkflowState.COMPLETED
        os.kill(os.getpid(), signal.SIGTERM)
        if not self.cancel_seen.wait(2):
            raise AssertionError("post-COMMIT cancellation was not dispatched")
        return self.result

    def cancel(self) -> None:
        self.events.append("cancel")
        self.cancelled = True
        self.cancel_seen.set()


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.image = Path(self.temporary.name) / "source.img"
        self.image.write_bytes(b"I" * 4096)
        self.device = target()
        self.events: list[str] = []
        self.workflows: list[FakeWorkflow] = []

    def dependencies(
        self,
        *,
        inspection: ImageInspection | None = None,
        devices: list[Device] | None = None,
        prepare_error: BaseException | None = None,
        execute_error: BaseException | None = None,
        inspect_side_effect=None,
        workflow_type: type[FakeWorkflow] = FakeWorkflow,
    ) -> CliDependencies:
        selected_inspection = inspection or image_inspection()
        selected_devices = devices if devices is not None else [self.device]

        def inspect(path, **kwargs):
            self.events.append("inspect")
            self.assertEqual(path, self.image)
            self.assertIn("expected_identity", kwargs)
            self.assertIn("cancel_check", kwargs)
            if inspect_side_effect is not None:
                inspect_side_effect()
            return selected_inspection

        def discover(*, include_usb_hdds=False):
            self.events.append(f"discover:{include_usb_hdds}")
            return selected_devices

        def workflow_factory(
            path,
            inspected,
            device,
            identity,
            *,
            final_verification,
        ):
            del identity
            self.events.append("workflow")
            self.assertEqual(path, self.image)
            self.assertIs(inspected, selected_inspection)
            self.assertIs(device, self.device)
            workflow = workflow_type(
                device,
                self.events,
                verify=final_verification,
                prepare_error=prepare_error,
                execute_error=execute_error,
            )
            self.workflows.append(workflow)
            return workflow

        return CliDependencies(inspect, discover, workflow_factory)

    def invoke(
        self,
        argv: list[str],
        stdin: io.StringIO,
        dependencies: CliDependencies,
    ) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        code = run(
            argv,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            dependencies=dependencies,
            install_signal_handlers=False,
        )
        return code, stdout.getvalue(), stderr.getvalue()

    def test_unknown_option_is_usage_error_without_discovery(self):
        code, _, error = self.invoke(
            ["list", "--surprise"], TtyStringIO(), self.dependencies(),
        )
        self.assertEqual(code, ExitCode.USAGE)
        self.assertIn("unrecognized arguments", error)
        self.assertEqual(self.events, [])

    def test_list_hides_sensitive_identifiers_and_passes_fixed_opt_in(self):
        code, output, error = self.invoke(
            ["list", "--include-usb-hard-drives"],
            TtyStringIO(),
            self.dependencies(),
        )
        self.assertEqual(code, ExitCode.OK)
        self.assertEqual(error, "")
        self.assertIn("/dev/sdz", output)
        self.assertNotIn("PRIVATE-SERIAL", output)
        self.assertNotIn("PRIVATE-WWN", output)
        self.assertEqual(self.events, ["discover:True"])

    def test_noninteractive_write_refuses_before_inspection(self):
        code, _, error = self.invoke(
            ["write", os.fspath(self.image), "--target", "/dev/sdz"],
            io.StringIO(),
            self.dependencies(),
        )
        self.assertEqual(code, ExitCode.CONFIRMATION_REFUSED)
        self.assertIn("non-interactive", error)
        self.assertEqual(self.events, [])

    def test_noncanonical_target_is_usage_error_before_inspection(self):
        code, _, error = self.invoke(
            ["write", os.fspath(self.image), "--target", "/dev/../dev/sdz"],
            TtyStringIO(),
            self.dependencies(),
        )
        self.assertEqual(code, ExitCode.USAGE)
        self.assertIn("canonical /dev", error)
        self.assertEqual(self.events, [])

    def test_target_must_match_one_exact_discovered_device(self):
        for devices in ([], [self.device, self.device]):
            with self.subTest(count=len(devices)):
                self.events.clear()
                code, _, error = self.invoke(
                    ["write", os.fspath(self.image), "--target", "/dev/sdz"],
                    TtyStringIO(),
                    self.dependencies(devices=devices),
                )
                self.assertEqual(code, ExitCode.PREFLIGHT_FAILED)
                self.assertIn("missing, duplicated, or no longer eligible", error)
                self.assertNotIn("workflow", self.events)

    def test_hidden_fixed_internal_and_root_targets_fail_before_workflow(self):
        unsafe_targets = (
            target(removable=False),
            target(transport="ata"),
            target(mountpoints=("/",)),
            target(read_only=True),
        )
        for unsafe in unsafe_targets:
            with self.subTest(target=unsafe):
                self.events.clear()
                self.device = unsafe
                code, _, error = self.invoke(
                    ["write", os.fspath(self.image), "--target", "/dev/sdz"],
                    TtyStringIO(),
                    self.dependencies(devices=[unsafe]),
                )
                self.assertEqual(code, ExitCode.PREFLIGHT_FAILED)
                self.assertIn("not an eligible writable 512-byte-sector", error)
                self.assertNotIn("workflow", self.events)

    def test_list_filters_targets_the_raw_helper_cannot_accept(self):
        devices = [
            self.device,
            target(path="/dev/sdy", read_only=True),
            target(path="/dev/sdx", logical_sector_size=4096),
        ]
        code, output, error = self.invoke(
            ["list"], TtyStringIO(), self.dependencies(devices=devices),
        )
        self.assertEqual(code, ExitCode.OK)
        self.assertEqual(error, "")
        self.assertIn("/dev/sdz", output)
        self.assertNotIn("/dev/sdy", output)
        self.assertNotIn("/dev/sdx", output)

    def test_fixed_usb_requires_opt_in_and_second_phrase(self):
        self.device = target(removable=False)
        phrase = "PREPARE RAW /dev/sdz\n"
        final = "WRITE RAW /dev/sdz 8:240\n"
        code, _, error = self.invoke(
            [
                "write", os.fspath(self.image), "--target", "/dev/sdz",
                "--include-usb-hard-drives",
            ],
            TtyStringIO(phrase + final),
            self.dependencies(devices=[self.device]),
        )
        self.assertEqual(code, ExitCode.OK)
        self.assertIn("fixed USB hard drive or SSD", error)
        self.assertEqual(
            self.events,
            ["inspect", "discover:True", "workflow", "prepare", "confirm", "execute", "close"],
        )

    def test_wrong_preparation_phrase_never_creates_workflow(self):
        warning = image_inspection(has_windows_installer=True)
        code, _, error = self.invoke(
            ["write", os.fspath(self.image), "--target", "/dev/sdz"],
            TtyStringIO("no\n"),
            self.dependencies(inspection=warning),
        )
        self.assertEqual(code, ExitCode.CONFIRMATION_REFUSED)
        self.assertIn("target was not changed", error)
        self.assertEqual(self.events, ["inspect", "discover:False"])

    def test_sector_mismatch_and_dbx_match_require_preparation_phrase(self):
        profiles = (
            image_inspection(
                partition_table_valid=True,
                partition_table_sector_size=4096,
            ),
            image_inspection(
                uefi_payloads=(
                    SimpleNamespace(dbx=SimpleNamespace(matched=True)),
                ),
            ),
        )
        expected_warnings = (
            "different logical-sector interpretations",
            "Microsoft Secure Boot DBX snapshot",
        )
        for profile, warning in zip(profiles, expected_warnings, strict=True):
            with self.subTest(warning=warning):
                self.events.clear()
                code, _, error = self.invoke(
                    ["write", os.fspath(self.image), "--target", "/dev/sdz"],
                    TtyStringIO("no\n"),
                    self.dependencies(inspection=profile),
                )
                self.assertEqual(code, ExitCode.CONFIRMATION_REFUSED)
                self.assertIn(warning, error)
                self.assertNotIn("workflow", self.events)

    def test_wrong_final_phrase_never_confirms_or_executes(self):
        code, _, error = self.invoke(
            ["write", os.fspath(self.image), "--target", "/dev/sdz"],
            TtyStringIO("WRONG\n"),
            self.dependencies(),
        )
        self.assertEqual(code, ExitCode.CONFIRMATION_REFUSED)
        self.assertIn("did not match", error)
        self.assertEqual(
            self.events,
            ["inspect", "discover:False", "workflow", "prepare", "close"],
        )
        self.assertTrue(self.workflows[0].closed)

    def test_success_order_defaults_to_complete_final_verification(self):
        phrase = "WRITE RAW /dev/sdz 8:240\n"
        code, _, error = self.invoke(
            ["write", os.fspath(self.image), "--target", "/dev/sdz"],
            TtyStringIO(phrase),
            self.dependencies(),
        )
        self.assertEqual(code, ExitCode.OK)
        self.assertIn("complete post-activation SHA-256 verification", error)
        self.assertEqual(
            self.events,
            ["inspect", "discover:False", "workflow", "prepare", "confirm", "execute", "close"],
        )
        self.assertTrue(self.workflows[0].plan.final_verification_requested)

    def test_verification_opt_out_is_explicit_and_reconfirmed(self):
        stdin = TtyStringIO(
            "PREPARE RAW /dev/sdz\nWRITE RAW /dev/sdz 8:240\n"
        )
        code, _, error = self.invoke(
            [
                "write", os.fspath(self.image), "--target", "/dev/sdz",
                "--no-final-verification",
            ],
            stdin,
            self.dependencies(),
        )
        self.assertEqual(code, ExitCode.OK)
        self.assertIn("Full post-activation SHA-256 verification is disabled", error)
        self.assertFalse(self.workflows[0].plan.final_verification_requested)

    def test_source_mutation_after_inspection_fails_before_workflow(self):
        def mutate() -> None:
            self.image.write_bytes(b"M" * 4096)

        code, _, error = self.invoke(
            ["write", os.fspath(self.image), "--target", "/dev/sdz"],
            TtyStringIO(),
            self.dependencies(inspect_side_effect=mutate),
        )
        self.assertEqual(code, ExitCode.PREFLIGHT_FAILED)
        self.assertIn("changed after inspection", error)
        self.assertNotIn("workflow", self.events)

    def test_workflow_cancellation_and_failure_have_stable_exit_codes(self):
        for failure, expected in (
            (RawWorkflowCancelled("cancelled before COMMIT"), ExitCode.CANCELLED),
            (RawWorkflowError("helper unavailable"), ExitCode.WRITE_FAILED),
        ):
            with self.subTest(failure=failure):
                self.events.clear()
                self.workflows.clear()
                code, _, error = self.invoke(
                    ["write", os.fspath(self.image), "--target", "/dev/sdz"],
                    TtyStringIO("WRITE RAW /dev/sdz 8:240\n"),
                    self.dependencies(prepare_error=failure),
                )
                self.assertEqual(code, expected)
                self.assertIn("close", self.events)
                self.assertNotIn("execute", self.events)
                self.assertNotIn("PRIVATE-SERIAL", error)
                self.assertNotIn("PRIVATE-WWN", error)

    def test_long_control_bearing_diagnostic_is_safe_but_actionable(self):
        failure = RawWorkflowError("A" * 1500 + "\nDETAIL\x1b]0;spoof\x07" + "Z" * 1500)
        code, _, error = self.invoke(
            ["write", os.fspath(self.image), "--target", "/dev/sdz"],
            TtyStringIO("WRITE RAW /dev/sdz 8:240\n"),
            self.dependencies(prepare_error=failure),
        )
        self.assertEqual(code, ExitCode.WRITE_FAILED)
        failure_lines = [line for line in error.splitlines() if line.startswith("Write failed:")]
        self.assertEqual(len(failure_lines), 1)
        self.assertIn("DETAIL", failure_lines[0])
        self.assertNotIn("\x1b", failure_lines[0])
        self.assertNotIn("\x07", failure_lines[0])
        self.assertLessEqual(len(failure_lines[0]), len("Write failed: ") + 2048)

    def test_progress_handles_unknown_and_huge_totals(self):
        output = io.StringIO()
        progress = ProgressReporter(output)
        progress("stage\nwith control", 0, 0)
        progress("huge", 10**80, 10**81)
        progress("huge", 10**81, 10**81)
        progress("extreme", 10**9999, 10**10000)
        rendered = output.getvalue()
        self.assertIn("stage with control...", rendered)
        self.assertIn("huge: 10%", rendered)
        self.assertIn("huge: 100%", rendered)
        self.assertIn("extreme: 10%", rendered)
        self.assertIn("bit byte count", rendered)

    def test_device_metadata_cannot_inject_terminal_controls_or_lines(self):
        self.device = target(
            vendor="VEN\nDOR\x1b]0;owned\x07",
            model="MODEL\rspoof" + "X" * 500,
        )
        dependencies = self.dependencies(devices=[self.device])
        list_code, output, _ = self.invoke(["list"], TtyStringIO(), dependencies)
        self.assertEqual(list_code, ExitCode.OK)
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\x07", output)
        self.assertEqual(len(output.splitlines()), 1)
        self.assertLessEqual(len(output.split("\t")[-1].rstrip("\n")), 120)

        self.events.clear()
        self.workflows.clear()
        code, _, error = self.invoke(
            ["write", os.fspath(self.image), "--target", "/dev/sdz"],
            TtyStringIO("WRITE RAW /dev/sdz 8:240\n"),
            dependencies,
        )
        self.assertEqual(code, ExitCode.OK)
        self.assertNotIn("\x1b", error)
        self.assertNotIn("\x07", error)
        model_lines = [
            line for line in error.splitlines() if line.startswith("  Target model:")
        ]
        self.assertEqual(len(model_lines), 1)
        self.assertLessEqual(len(model_lines[0]), len("  Target model: ") + 120)

    def test_signal_controller_cancels_bound_workflow_and_uses_shell_code(self):
        workflow = FakeWorkflow(self.device, self.events)
        controller = CancellationController()
        controller.bind(workflow)  # type: ignore[arg-type]
        try:
            with self.assertRaisesRegex(RuntimeError, "cancelled by signal"):
                controller.handle(signal.SIGINT)
            self.assertTrue(controller.cancel_dispatched.wait(1))
            self.assertTrue(workflow.cancelled)
            self.assertEqual(controller.exit_code, 130)
        finally:
            controller.release(workflow)  # type: ignore[arg-type]
            controller.unbind(workflow)  # type: ignore[arg-type]

    def test_signal_handler_never_calls_lock_taking_cancel_reentrantly(self):
        workflow = BlockingCancelWorkflow(self.device, self.events)
        controller = CancellationController()
        controller.bind(workflow)  # type: ignore[arg-type]
        try:
            with controller.workflow_call():
                # This must return while cancel is blocked in the watcher thread.
                controller.handle(signal.SIGTERM)
                self.assertTrue(workflow.cancel_entered.wait(1))
                self.assertFalse(controller.cancel_dispatched.is_set())
                workflow.allow_cancel.set()
            self.assertTrue(controller.cancel_dispatched.wait(1))
            self.assertEqual(controller.exit_code, 143)
        finally:
            workflow.allow_cancel.set()
            controller.release(workflow)  # type: ignore[arg-type]
            controller.unbind(workflow)  # type: ignore[arg-type]

    def test_signal_during_cleanup_span_does_not_interrupt_close(self):
        workflow = FakeWorkflow(self.device, self.events)
        controller = CancellationController()
        controller.bind(workflow)  # type: ignore[arg-type]
        with controller.workflow_call():
            controller.release(workflow)  # type: ignore[arg-type]
            controller.handle(signal.SIGINT)
            workflow.close()
            controller.unbind(workflow)  # type: ignore[arg-type]
        self.assertTrue(workflow.closed)
        self.assertEqual(controller.exit_code, 130)

    def test_signal_at_final_prompt_unwinds_run_and_closes_workflow(self):
        previous = signal.getsignal(signal.SIGINT)
        code = run(
            ["write", os.fspath(self.image), "--target", "/dev/sdz"],
            stdin=SignalOnReadTty(signal.SIGINT),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
            dependencies=self.dependencies(),
            install_signal_handlers=True,
        )
        self.assertEqual(code, 130)
        self.assertEqual(signal.getsignal(signal.SIGINT), previous)
        self.assertTrue(self.workflows[0].cancelled)
        self.assertTrue(self.workflows[0].closed)
        self.assertNotIn("confirm", self.events)
        self.assertNotIn("execute", self.events)

    def test_signals_during_prepare_and_execute_cancel_complete_run(self):
        cases = (
            (SignalDuringPrepareWorkflow, 143, "execute"),
            (SignalDuringExecuteWorkflow, 130, None),
        )
        for workflow_type, expected, absent_event in cases:
            with self.subTest(workflow=workflow_type.__name__):
                self.events.clear()
                self.workflows.clear()
                code = run(
                    ["write", os.fspath(self.image), "--target", "/dev/sdz"],
                    stdin=TtyStringIO("WRITE RAW /dev/sdz 8:240\n"),
                    stdout=io.StringIO(),
                    stderr=io.StringIO(),
                    dependencies=self.dependencies(workflow_type=workflow_type),
                    install_signal_handlers=True,
                )
                self.assertEqual(code, expected)
                self.assertTrue(self.workflows[0].cancelled)
                self.assertTrue(self.workflows[0].closed)
                self.assertIn("cancel", self.events)
                if absent_event is not None:
                    self.assertNotIn(absent_event, self.events)

    def test_signal_after_commit_returns_verified_success_and_closes(self):
        error = io.StringIO()
        code = run(
            ["write", os.fspath(self.image), "--target", "/dev/sdz"],
            stdin=TtyStringIO("WRITE RAW /dev/sdz 8:240\n"),
            stdout=io.StringIO(),
            stderr=error,
            dependencies=self.dependencies(workflow_type=SignalAfterCommitWorkflow),
            install_signal_handlers=True,
        )
        self.assertEqual(code, ExitCode.OK)
        self.assertTrue(self.workflows[0].cancelled)
        self.assertTrue(self.workflows[0].closed)
        self.assertIn("cancellation request arrived after irreversible commit", error.getvalue())
        self.assertLess(self.events.index("execute"), self.events.index("cancel"))
        self.assertLess(self.events.index("cancel"), self.events.index("close"))

    def test_signal_after_authoritative_result_cannot_misreport_cancellation(self):
        error = SignalOnCompletionOutput(signal.SIGINT)
        code = run(
            ["write", os.fspath(self.image), "--target", "/dev/sdz"],
            stdin=TtyStringIO("WRITE RAW /dev/sdz 8:240\n"),
            stdout=io.StringIO(),
            stderr=error,
            dependencies=self.dependencies(),
            install_signal_handlers=True,
        )
        self.assertEqual(code, ExitCode.OK)
        self.assertTrue(error.triggered)
        self.assertIn("Write complete", error.getvalue())
        self.assertTrue(self.workflows[0].cancelled)
        self.assertTrue(self.workflows[0].closed)

    def test_completion_output_failure_cannot_reclassify_verified_write(self):
        error = FailingCompletionOutput()
        code = run(
            ["write", os.fspath(self.image), "--target", "/dev/sdz"],
            stdin=TtyStringIO("WRITE RAW /dev/sdz 8:240\n"),
            stdout=io.StringIO(),
            stderr=error,
            dependencies=self.dependencies(),
            install_signal_handlers=False,
        )
        self.assertEqual(code, ExitCode.OK)
        self.assertTrue(self.workflows[0].closed)
        self.assertNotIn("Write failed", error.getvalue())

    def test_cli_import_does_not_construct_or_import_qt(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; import isopropyl.cli; "
                "print(any(name.startswith('PyQt6') for name in sys.modules))",
            ],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "False")

    def test_console_script_is_packaged_separately_from_gui(self):
        pyproject = (
            Path(__file__).resolve().parents[1] / "pyproject.toml"
        ).read_text(encoding="utf-8")
        self.assertIn('[project.gui-scripts]\nisopropyl = "isopropyl.app:main"', pyproject)
        self.assertIn('[project.scripts]\nisopropyl-cli = "isopropyl.cli:main"', pyproject)

    def test_root_is_rejected_before_argument_or_dependency_processing(self):
        dependencies = CliDependencies(
            inspect=Mock(side_effect=AssertionError("inspection reached")),
            discover=Mock(side_effect=AssertionError("discovery reached")),
            workflow_factory=Mock(side_effect=AssertionError("workflow reached")),
        )
        error = io.StringIO()
        with patch("isopropyl.cli.os.geteuid", return_value=0):
            code = run(
                ["list"],
                stdout=io.StringIO(),
                stderr=error,
                dependencies=dependencies,
                install_signal_handlers=False,
            )
        self.assertEqual(code, ExitCode.PREFLIGHT_FAILED)
        self.assertIn("regular desktop user, not root", error.getvalue())
        dependencies.inspect.assert_not_called()
        dependencies.discover.assert_not_called()
        dependencies.workflow_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
