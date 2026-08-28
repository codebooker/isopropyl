from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Safety-equivalent command-line access to ISOpropyl's raw writer.

The CLI deliberately owns no device-writing implementation.  It discovers one
exact target and drives :class:`RawWriteWorkflow`, which is also the GUI's sole
raw/DD transaction.  There is no unattended confirmation, target index, glob,
``dd`` fallback, or direct privileged-helper entry point here.
"""

import argparse
import os
import re
import signal
import stat
import sys
import threading
from collections.abc import Callable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from types import FrameType
from typing import Iterator, TextIO

from .devices import Device, DeviceDiscoveryError, format_size, list_devices
from .images import (
    ImageInspection,
    ImageInspectionCancelled,
    inspect_image,
)
from .iso import partition_sector_mismatch, partition_sector_unverified
from .raw_device import RawDeviceWritePlan
from .raw_device_runner import RawDeviceWriteResult
from .raw_workflow import (
    RawWorkflowCancelled,
    RawWorkflowError,
    RawWriteWorkflow,
)


class ExitCode(IntEnum):
    OK = 0
    USAGE = 2
    CANCELLED = 3
    PREFLIGHT_FAILED = 4
    WRITE_FAILED = 5
    CONFIRMATION_REFUSED = 6


class CliUsageError(ValueError):
    """Arguments could not be parsed without mutating external state."""


class CliCancelled(RuntimeError):
    """A signal cancelled pre-write inspection or target discovery."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliUsageError(message)


@dataclass(frozen=True)
class CliDependencies:
    """Injectable, non-Qt boundary used by deterministic command tests."""

    inspect: Callable[..., ImageInspection] = inspect_image
    discover: Callable[..., list[Device]] = list_devices
    workflow_factory: Callable[..., RawWriteWorkflow] = RawWriteWorkflow


def _source_identity(path: Path) -> tuple[int, int, int, int, int]:
    status = path.stat()
    if not stat.S_ISREG(status.st_mode):
        raise OSError("The selected image is not a regular file")
    return (
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _safe_text(value: object, limit: int, fallback: str) -> str:
    rendered = str(value or fallback)
    rendered = "".join(
        character if character.isprintable() and character not in "\r\n\t" else " "
        for character in rendered
    )
    return " ".join(rendered.split())[:limit] or fallback


def _safe_stage(stage: object) -> str:
    return _safe_text(stage, 120, "Working")


def _diagnostic(error: object) -> str:
    return _safe_text(error, 2_048, "Operation failed")


class ProgressReporter:
    """Bounded line-oriented progress suitable for terminals and log capture."""

    def __init__(self, stream: TextIO) -> None:
        self.stream = stream
        self._last: tuple[str, int | None] | None = None

    def __call__(self, stage: str, done: int, total: int) -> None:
        label = _safe_stage(stage)
        if (
            type(done) is not int
            or isinstance(done, bool)
            or type(total) is not int
            or isinstance(total, bool)
            or done < 0
            or total <= 0
        ):
            state: tuple[str, int | None] = (label, None)
            message = f"{label}..."
        else:
            percent = min(100, (min(done, total) * 100) // total)
            # Avoid turning a fast writer into a terminal-output benchmark.
            bucket = 100 if percent == 100 else (percent // 5) * 5
            state = (label, bucket)
            completed = min(done, total)
            message = (
                f"{label}: {percent}% "
                f"({_progress_size(completed)} of {_progress_size(total)})"
            )
        if state == self._last:
            return
        self._last = state
        print(message, file=self.stream, flush=True)


class CancellationController:
    """Route SIGINT/SIGTERM into the currently owned one-shot workflow."""

    def __init__(self) -> None:
        self.event = threading.Event()
        self.received_signal: int | None = None
        self.workflow: RawWriteWorkflow | None = None
        self._workflow_call_active = False
        self._workflow_completed = False
        self._watcher: threading.Thread | None = None
        self._watcher_stop = threading.Event()
        self.cancel_dispatched = threading.Event()
        self._previous: dict[int, signal.Handlers] = {}

    def bind(self, workflow: RawWriteWorkflow) -> None:
        if self.workflow is not None or self._watcher is not None:
            raise RuntimeError("A CLI cancellation controller can bind only once")
        self.workflow = workflow

        def watch() -> None:
            while True:
                if self.event.wait(0.05):
                    try:
                        workflow.cancel()
                    finally:
                        self.cancel_dispatched.set()
                    return
                if self._watcher_stop.is_set():
                    return

        watcher = threading.Thread(
            target=watch,
            name="isopropyl-cli-cancellation",
            daemon=True,
        )
        try:
            watcher.start()
        except BaseException:
            self.workflow = None
            self._watcher_stop.set()
            raise
        self._watcher = watcher

    def release(self, workflow: RawWriteWorkflow) -> None:
        if self.workflow is not workflow:
            raise RuntimeError("The CLI cancellation workflow binding changed")
        self._watcher_stop.set()
        watcher = self._watcher
        if watcher is not None:
            # A signalled destructive transaction must finish dispatching its
            # cooperative cancellation instead of abandoning a lock-taking
            # cancel call in a daemon thread.
            watcher.join()
        self._watcher = None

    def unbind(self, workflow: RawWriteWorkflow) -> None:
        if self.workflow is not workflow or self._watcher is not None:
            raise RuntimeError("The CLI cancellation workflow was not released")
        self.workflow = None

    def check(self) -> None:
        if self.event.is_set():
            raise CliCancelled("Operation cancelled by signal")

    def mark_completed(self, workflow: RawWriteWorkflow) -> None:
        if self.workflow is not workflow or not self._workflow_call_active:
            raise RuntimeError("Only the active bound workflow can complete")
        self._workflow_completed = True

    @contextmanager
    def workflow_call(self) -> Iterator[None]:
        if self._workflow_call_active:
            raise RuntimeError("Nested CLI workflow calls are not supported")
        self._workflow_call_active = True
        try:
            yield
        finally:
            self._workflow_call_active = False

    def handle(self, signum: int, _frame: FrameType | None = None) -> None:
        if self.received_signal is None:
            self.received_signal = signum
        self.event.set()
        if self._workflow_completed:
            # Once an authoritative completed result is latched, reporting a
            # signal exit status would falsely imply that the write stopped.
            return
        if self.workflow is None:
            # Raising is intentional here: a returning Python signal handler can
            # otherwise leave an interactive readline or a restarted syscall
            # blocked indefinitely even though cancellation was requested.
            raise CliCancelled("Operation cancelled by signal")
        if not self._workflow_call_active:
            # The CLI is between workflow calls or blocked at a prompt, so it is
            # safe and necessary to unwind immediately. PREPARING/CONFIRMING/
            # EXECUTING calls instead return through cooperative cancellation;
            # this avoids injecting an unrelated exception into their state
            # transition or post-COMMIT verification logic.
            raise CliCancelled("Operation cancelled by signal")

    def install(self) -> None:
        for signum in (signal.SIGINT, signal.SIGTERM):
            self._previous[signum] = signal.getsignal(signum)
            signal.signal(signum, self.handle)

    def restore(self) -> None:
        for signum, previous in self._previous.items():
            signal.signal(signum, previous)
        self._previous.clear()

    @property
    def exit_code(self) -> int:
        return (
            128 + self.received_signal
            if self.received_signal is not None
            else int(ExitCode.CANCELLED)
        )


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="isopropyl-cli",
        description=(
            "Inspect protected removable targets and perform authenticated "
            "raw/DD writes through ISOpropyl's one-shot PolicyKit transaction."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    devices = commands.add_parser(
        "list", help="list raw-writable 512-byte-sector USB and SD targets",
    )
    devices.add_argument(
        "--include-usb-hard-drives",
        action="store_true",
        help="also reveal hot-pluggable fixed USB HDDs and SSDs",
    )

    write = commands.add_parser(
        "write", help="write one image to one exact discovered target",
    )
    write.add_argument("image", help="raw, compressed, sparse, or virtual image")
    write.add_argument(
        "--target",
        required=True,
        metavar="/dev/DEVICE",
        help="exact whole-disk path from the list command",
    )
    write.add_argument(
        "--include-usb-hard-drives",
        action="store_true",
        help="allow an exact hot-pluggable fixed USB HDD/SSD target",
    )
    write.add_argument(
        "--no-final-verification",
        action="store_true",
        help=(
            "skip the post-activation full-device hash (the mandatory "
            "pre-activation read-back still runs)"
        ),
    )
    return parser


def _canonical_target_argument(value: object) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise CliUsageError("--target must be one exact /dev whole-disk path")
    if (
        re.fullmatch(r"/dev/[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", value) is None
        or os.path.normpath(value) != value
    ):
        raise CliUsageError("--target must be one canonical /dev whole-disk path")
    return value


def _progress_size(value: int) -> str:
    # Kernel device sizes are far smaller, but injected progress callbacks must
    # not be able to trigger float overflow or enormous decimal conversion.
    if value > 10**18:
        return f"{value.bit_length()}-bit byte count"
    try:
        return format_size(value)
    except (OverflowError, TypeError, ValueError):
        return "invalid byte count"


def _select_exact_target(
    path: str,
    devices: Sequence[Device],
    *,
    allow_fixed_usb: bool,
) -> Device:
    matches = [device for device in devices if type(device) is Device and device.path == path]
    if len(matches) != 1:
        raise DeviceDiscoveryError(
            "The exact target is missing, duplicated, or no longer eligible; "
            "refresh the protected device list and try again"
        )
    selected = matches[0]
    if not _eligible_raw_target(selected, allow_fixed_usb=allow_fixed_usb):
        raise DeviceDiscoveryError(
            "The exact target is not an eligible writable 512-byte-sector "
            "removable drive or explicitly revealed hot-pluggable USB disk"
        )
    return selected


def _eligible_raw_target(device: Device, *, allow_fixed_usb: bool) -> bool:
    removable_transport = device.removable and device.transport in {"usb", "mmc"}
    opted_in_fixed_usb = (
        allow_fixed_usb
        and not device.removable
        and device.hotplug
        and device.transport == "usb"
    )
    return bool(
        (removable_transport or opted_in_fixed_usb)
        and not device.read_only
        and "/" not in device.mountpoints
        and device.logical_sector_size == 512
    )


def _is_interactive(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        return False


def _read_phrase(stream: TextIO) -> str | None:
    try:
        value = stream.readline(4_097)
    except (OSError, UnicodeError):
        return None
    if not value or len(value) > 4_096 or not value.endswith("\n"):
        return None
    return value[:-1].removesuffix("\r")


def _preparation_warnings(
    inspection: ImageInspection,
    device: Device,
    *,
    final_verification: bool,
) -> tuple[str, ...]:
    warnings: list[str] = []
    if not device.removable:
        warnings.append(
            "The target reports itself as a fixed USB hard drive or SSD."
        )
    if inspection.partition_table_malformed:
        warnings.append("The image contains malformed MBR or GPT metadata.")
    elif inspection.partition_table_incomplete:
        warnings.append("The image partition table could not be fully validated.")
    elif partition_sector_mismatch(inspection, device.logical_sector_size):
        warnings.append(
            "The image and target use different logical-sector interpretations; "
            "structured partition LBAs may be wrong after a byte-for-byte copy."
        )
    elif partition_sector_unverified(inspection, device.logical_sector_size):
        warnings.append(
            "The target did not report the logical-sector size needed to validate "
            "the image's structured partition LBAs."
        )
    elif inspection.has_windows_installer:
        warnings.append(
            "This Windows installer may need filesystem-aware ISO mode to boot from USB."
        )
    elif not inspection.raw_compatible:
        warnings.append(
            "This optical-only ISO has no validated raw USB partition layout."
        )
    dbx_matches = sum(
        bool(payload.dbx is not None and payload.dbx.matched)
        for payload in inspection.uefi_payloads
    )
    if dbx_matches:
        warnings.append(
            f"{dbx_matches} selected EFI payload(s) match entries in ISOpropyl's "
            "bundled Microsoft Secure Boot DBX snapshot; matching firmware may "
            "reject them."
        )
    if not final_verification:
        warnings.append("Full post-activation SHA-256 verification is disabled.")
    return tuple(warnings)


def _confirm_preparation(
    warnings: Sequence[str],
    target_path: str,
    stdin: TextIO,
    stderr: TextIO,
) -> bool:
    if not warnings:
        return True
    phrase = f"PREPARE RAW {target_path}"
    print("\nAdditional expert warning:", file=stderr)
    for warning in warnings:
        print(f"  - {warning}", file=stderr)
    print(
        "No device will be changed during authenticated snapshot preparation.\n"
        f"Type this exact phrase to continue: {phrase}",
        file=stderr,
        flush=True,
    )
    return _read_phrase(stdin) == phrase


def _show_plan(plan: RawDeviceWritePlan, stderr: TextIO) -> None:
    model = _safe_stage(" ".join(
        part.strip()
        for part in (plan.device.vendor, plan.device.model)
        if part.strip()
    ) or "not reported")
    print("\nFinal authenticated write plan", file=stderr)
    print(f"  Expanded image: {format_size(plan.source_size)} ({plan.source_size} bytes)", file=stderr)
    print(f"  SHA-256: {plan.source_sha256}", file=stderr)
    print(f"  Target path: {_safe_stage(plan.device.path)}", file=stderr)
    print(f"  Target model: {model}", file=stderr)
    print(
        f"  Target capacity: {format_size(plan.target_capacity)} "
        f"({plan.target_capacity} bytes)",
        file=stderr,
    )
    print(f"  Logical sector: {plan.logical_sector_size} bytes", file=stderr)
    for warning in plan.warnings:
        print(f"  WARNING: {_safe_stage(warning)}", file=stderr)
    print(
        "\nALL DATA ON THIS EXACT TARGET WILL BE ERASED.\n"
        f"Type this exact phrase to authorize the write: {plan.confirmation_phrase}",
        file=stderr,
        flush=True,
    )


def _run_list(
    include_usb_hdds: bool,
    stdout: TextIO,
    dependencies: CliDependencies,
) -> int:
    devices = dependencies.discover(include_usb_hdds=include_usb_hdds)
    for device in devices:
        if type(device) is not Device:
            raise DeviceDiscoveryError("Device discovery returned an invalid target")
        if not _eligible_raw_target(device, allow_fixed_usb=include_usb_hdds):
            continue
        kind = "removable" if device.removable else "fixed USB (expert opt-in)"
        model = _safe_stage(" ".join(
            part.strip() for part in (device.vendor, device.model) if part.strip()
        ) or "USB/SD drive")
        print(
            f"{_safe_stage(device.path)}\t{format_size(device.size)}\t{kind}\t{model}",
            file=stdout,
        )
    return int(ExitCode.OK)


def _run_write(
    arguments: argparse.Namespace,
    stdin: TextIO,
    stdout: TextIO,
    stderr: TextIO,
    dependencies: CliDependencies,
    cancellation: CancellationController,
) -> int:
    del stdout
    if not _is_interactive(stdin):
        print(
            "Refusing a non-interactive destructive confirmation. Run this command "
            "from a terminal and type every requested phrase yourself.",
            file=stderr,
        )
        return int(ExitCode.CONFIRMATION_REFUSED)

    target_path = _canonical_target_argument(arguments.target)
    image = Path(arguments.image).expanduser()
    try:
        image = image.resolve(strict=True)
        selected_identity = _source_identity(image)
        inspection = dependencies.inspect(
            image,
            expected_identity=selected_identity,
            cancel_check=cancellation.check,
        )
        cancellation.check()
        if type(inspection) is not ImageInspection:
            raise OSError("Image inspection returned an invalid result")
        devices = dependencies.discover(
            include_usb_hdds=bool(arguments.include_usb_hard_drives),
        )
        cancellation.check()
        device = _select_exact_target(
            target_path,
            devices,
            allow_fixed_usb=bool(arguments.include_usb_hard_drives),
        )
        if _source_identity(image) != selected_identity:
            raise OSError("The selected image changed after inspection")
    except (CliCancelled, ImageInspectionCancelled):
        return cancellation.exit_code
    except (DeviceDiscoveryError, OSError, ValueError) as error:
        print(f"Preflight failed: {_diagnostic(error)}", file=stderr)
        return int(ExitCode.PREFLIGHT_FAILED)

    final_verification = not bool(arguments.no_final_verification)
    warnings = _preparation_warnings(
        inspection,
        device,
        final_verification=final_verification,
    )
    if not _confirm_preparation(warnings, target_path, stdin, stderr):
        print("Preparation refused; the target was not changed.", file=stderr)
        return int(ExitCode.CONFIRMATION_REFUSED)

    workflow: RawWriteWorkflow | None = None
    cancellation_bound = False
    try:
        try:
            workflow = dependencies.workflow_factory(
                image,
                inspection,
                device,
                selected_identity,
                final_verification=final_verification,
            )
        except (RawWorkflowError, OSError, ValueError) as error:
            print(f"Raw write unavailable: {_diagnostic(error)}", file=stderr)
            return int(ExitCode.PREFLIGHT_FAILED)

        progress = ProgressReporter(stderr)
        with cancellation.workflow_call():
            cancellation.bind(workflow)
            cancellation_bound = True
        cancellation.check()
        with cancellation.workflow_call():
            plan = workflow.prepare(progress)
        cancellation.check()
        if type(plan) is not RawDeviceWritePlan or plan is not workflow.plan:
            raise RawWorkflowError(
                "Raw preparation returned a non-authoritative target plan"
            )
        _show_plan(plan, stderr)
        phrase = _read_phrase(stdin)
        if phrase != plan.confirmation_phrase:
            print("Confirmation did not match; the target was not changed.", file=stderr)
            return int(ExitCode.CONFIRMATION_REFUSED)
        with cancellation.workflow_call():
            workflow.confirm(phrase)
        cancellation.check()
        with cancellation.workflow_call():
            result = workflow.execute(progress)
            if (
                type(result) is not RawDeviceWriteResult
                or result is not workflow.result
            ):
                raise RawWorkflowError(
                    "The raw transaction returned a non-authoritative result"
                )
            cancellation.mark_completed(workflow)
        try:
            suffix = (
                " The cancellation request arrived after irreversible commit, so "
                "the verified transaction finished safely."
                if result.cancellation_deferred else ""
            )
            verification = (
                "with complete post-activation SHA-256 verification"
                if result.final_verification
                else "with mandatory pre-activation read-back"
            )
            print(
                f"Write complete {verification}.{suffix}",
                file=stderr,
            )
        except (OSError, UnicodeError, ValueError):
            # The authoritative completed result must not become a write failure
            # merely because the user's terminal closed before this notice.
            pass
        return int(ExitCode.OK)
    except RawWorkflowCancelled as error:
        print(f"Write cancelled safely: {_diagnostic(error)}", file=stderr)
        return cancellation.exit_code
    except (RawWorkflowError, OSError, ValueError) as error:
        print(f"Write failed: {_diagnostic(error)}", file=stderr)
        return int(ExitCode.WRITE_FAILED)
    finally:
        if workflow is None:
            pass
        elif cancellation_bound:
            with cancellation.workflow_call():
                cancellation.release(workflow)
                try:
                    workflow.close()
                finally:
                    cancellation.unbind(workflow)
        else:
            workflow.close()


def run(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    dependencies: CliDependencies = CliDependencies(),
    install_signal_handlers: bool = True,
) -> int:
    """Run one CLI invocation and return a stable process exit status."""

    if type(dependencies) is not CliDependencies:
        print("Internal CLI dependency configuration is invalid.", file=stderr)
        return int(ExitCode.PREFLIGHT_FAILED)
    try:
        arguments = build_parser().parse_args(list(argv) if argv is not None else None)
    except CliUsageError as error:
        print(f"isopropyl-cli: error: {_diagnostic(error)}", file=stderr)
        return int(ExitCode.USAGE)

    cancellation = CancellationController()
    installed = False
    try:
        if install_signal_handlers:
            cancellation.install()
            installed = True
        if arguments.command == "list":
            try:
                return _run_list(
                    bool(arguments.include_usb_hard_drives), stdout, dependencies,
                )
            except (DeviceDiscoveryError, OSError, ValueError) as error:
                print(f"Device discovery failed: {_diagnostic(error)}", file=stderr)
                return int(ExitCode.PREFLIGHT_FAILED)
        if arguments.command == "write":
            try:
                return _run_write(
                    arguments,
                    stdin,
                    stdout,
                    stderr,
                    dependencies,
                    cancellation,
                )
            except CliUsageError as error:
                print(f"isopropyl-cli: error: {_diagnostic(error)}", file=stderr)
                return int(ExitCode.USAGE)
        raise CliUsageError("a supported command is required")
    except CliCancelled:
        return cancellation.exit_code
    except KeyboardInterrupt:
        try:
            cancellation.handle(signal.SIGINT)
        except CliCancelled:
            pass
        return cancellation.exit_code
    finally:
        if installed:
            cancellation.restore()


def main(argv: Sequence[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":  # pragma: no cover - console-script parity
    raise SystemExit(main())
