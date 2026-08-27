from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Destructive removable-media validation.

This module intentionally has no GUI integration.  Callers must build an
immutable plan, display every warning from that plan, and pass the plan's
exact confirmation phrase back to :meth:`MediaTestRunner.run`.

``badblocks`` write mode covers the complete advertised surface.  Each ISOpropyl
pass is one of badblocks' documented patterns (AA, 55, FF, 00), including a
write and read/compare cycle.  ``f3probe`` is a separate, quick counterfeit
capacity probe; it does not replace the full-surface test.
"""

import hmac
import logging
import os
import queue
import re
import shutil
import stat
import subprocess
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import BinaryIO

from .devices import Device, SizeUnitMode, format_size, list_devices
from .conflicts import conflict_diagnostic_suffix
from .locking import (
    CooperativeLockError,
    cooperative_lock_command,
    lock_conflict_message,
    resolve_flock,
)

logger = logging.getLogger("isopropyl")

BADBLOCK_PATTERNS = ("0xaa", "0x55", "0xff", "0x00")
MAX_CAPTURE_BYTES = 1024 * 1024
PROCESS_STOP_TIMEOUT_SECONDS = 2.0
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_TRUSTED_TOOL_DIRECTORIES = frozenset(_TRUSTED_TOOL_PATH.split(":"))
_WHOLE_DISK = re.compile(
    r"/dev/(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|mmcblk\d+|ubd[a-z]+)"
)
_MAJOR_MINOR = re.compile(r"\d+:\d+")
_BLOCK_PATH = re.compile(r"/dev/[A-Za-z0-9._+:-]+")


class MediaTestMode(Enum):
    """The independently selectable destructive validation scopes."""

    FULL_SURFACE = "full_surface"
    FAKE_CAPACITY = "fake_capacity"
    COMPLETE = "complete"


class CapacityStatus(Enum):
    NOT_TESTED = "not_tested"
    GENUINE = "genuine"
    DAMAGED = "damaged"
    COUNTERFEIT = "counterfeit"


class MediaTestError(RuntimeError):
    pass


class MediaTestUnavailable(MediaTestError):
    """A required system utility is missing or unusable."""


class MediaTestSafetyError(MediaTestError):
    """The target or confirmation failed a safety check."""


class MediaTestCancelled(MediaTestError):
    pass


@dataclass(frozen=True)
class MediaTestPhase:
    name: str
    argv: tuple[str, ...]
    kind: str
    pattern: str = ""


@dataclass(frozen=True)
class MediaTestPlan:
    """A complete, immutable description of commands that may erase a drive."""

    device: Device
    mode: MediaTestMode
    passes: int
    phases: tuple[MediaTestPhase, ...]
    udisksctl_path: str
    confirmation_phrase: str
    size_unit_mode: SizeUnitMode
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class MediaTestProgress:
    phase_name: str
    phase_index: int
    phase_count: int
    phase_fraction: float

    @property
    def fraction(self) -> float:
        if self.phase_count <= 0:
            return 0.0
        bounded = min(1.0, max(0.0, self.phase_fraction))
        return min(1.0, (self.phase_index + bounded) / self.phase_count)


@dataclass(frozen=True)
class MediaTestResult:
    device_identity: tuple[str, int, str, str, str, str]
    mode: MediaTestMode
    completed_phases: int
    bad_blocks: tuple[int, ...]
    capacity_status: CapacityStatus
    diagnostics: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.bad_blocks and self.capacity_status not in {
            CapacityStatus.DAMAGED,
            CapacityStatus.COUNTERFEIT,
        }


def _validate_program_path(name: str, path: object) -> str:
    if not isinstance(path, str) or not path:
        raise MediaTestUnavailable(
            f"{name} is required for this media test but was not found"
        )
    normalized = os.path.normpath(path)
    if (
        not os.path.isabs(path)
        or normalized != path
        or os.path.dirname(path) not in _TRUSTED_TOOL_DIRECTORIES
        or os.path.basename(path) != name
    ):
        raise MediaTestUnavailable(f"Refusing untrusted {name} path: {path!r}")
    return path


def _required_program(name: str, finder: Callable[[str], str | None]) -> str:
    return _validate_program_path(name, finder(name))


def _trusted_which(name: str) -> str | None:
    """Never elevate a binary found through the user's mutable PATH."""
    return shutil.which(name, path=_TRUSTED_TOOL_PATH)


def _partition_belongs_to_device(device_path: str, partition_path: str) -> bool:
    separator = "p" if device_path[-1].isdigit() else ""
    return re.fullmatch(re.escape(device_path) + separator + r"\d+", partition_path) is not None


def _validate_device(device: Device) -> None:
    if not isinstance(device, Device):
        raise MediaTestSafetyError("A discovered removable Device is required")
    if not device.removable:
        raise MediaTestSafetyError(
            "Destructive media validation is restricted to drives marked removable"
        )
    if device.read_only:
        raise MediaTestSafetyError("The selected removable drive is read-only")
    if device.size <= 0:
        raise MediaTestSafetyError("The selected drive has an invalid capacity")
    if not _WHOLE_DISK.fullmatch(device.path):
        raise MediaTestSafetyError("The target must be a supported whole-disk path under /dev")
    if not _MAJOR_MINOR.fullmatch(device.major_minor):
        raise MediaTestSafetyError("The target has no stable kernel device identity")
    if device.transport not in {"usb", "mmc"}:
        raise MediaTestSafetyError("Only removable USB and SD/MMC media can be tested")
    if "/" in device.mountpoints:
        raise MediaTestSafetyError("The drive backing the running system cannot be tested")
    for partition in device.partitions:
        if (
            not isinstance(partition, str)
            or not _BLOCK_PATH.fullmatch(partition)
            or not _partition_belongs_to_device(device.path, partition)
        ):
            raise MediaTestSafetyError(
                f"Unsafe partition path reported for target: {partition!r}"
            )


def _confirmation_for(device: Device) -> str:
    return f"ERASE {device.path}"


def _warnings_for(
    device: Device,
    size_unit_mode: SizeUnitMode,
) -> tuple[str, ...]:
    confirmation = _confirmation_for(device)
    return (
        "THIS TEST IS DESTRUCTIVE AND CANNOT BE UNDONE.",
        (
            f"It will irreversibly erase ALL data on {device.path} "
            "including every partition, filesystem, and file."
        ),
        (
            f"Verify the target again: {device.display_label(size_unit_mode)}; "
            f"serial {device.serial or 'not reported'}; capacity "
            f"{format_size(device.size, size_unit_mode)}."
        ),
        "Do not unplug the drive, suspend the computer, or remove power during the test.",
        f"To authorize this separate destructive operation, type exactly: {confirmation}",
    )


def build_media_test_plan(
    device: Device,
    mode: MediaTestMode,
    *,
    passes: int = 1,
    finder: Callable[[str], str | None] = _trusted_which,
    size_unit_mode: SizeUnitMode = SizeUnitMode.SI,
) -> MediaTestPlan:
    """Validate choices and construct all privileged argv without a shell."""
    if not isinstance(mode, MediaTestMode):
        raise ValueError("mode must be a MediaTestMode")
    if not isinstance(size_unit_mode, SizeUnitMode):
        raise ValueError("size_unit_mode must be a SizeUnitMode")
    _validate_device(device)
    if not 1 <= passes <= len(BADBLOCK_PATTERNS):
        raise ValueError("passes must be between 1 and 4")

    pkexec = _required_program("pkexec", finder)
    udisksctl = _required_program("udisksctl", finder)
    try:
        flock = resolve_flock(finder)
    except CooperativeLockError as error:
        raise MediaTestUnavailable(str(error)) from error
    phases: list[MediaTestPhase] = []

    if mode in {MediaTestMode.FAKE_CAPACITY, MediaTestMode.COMPLETE}:
        f3probe = _required_program("f3probe", finder)
        phases.append(MediaTestPhase(
            name="Counterfeit-capacity probe",
            argv=tuple(cooperative_lock_command(
                pkexec, flock, device.path,
                (f3probe, "--destructive", "--time-ops", device.path),
            )),
            kind="f3probe",
        ))

    effective_passes = passes if mode in {
        MediaTestMode.FULL_SURFACE, MediaTestMode.COMPLETE,
    } else 0
    if effective_passes:
        badblocks = _required_program("badblocks", finder)
        for index, pattern in enumerate(BADBLOCK_PATTERNS[:effective_passes], start=1):
            phases.append(MediaTestPhase(
                name=f"Full-surface pattern {index}/{effective_passes} ({pattern})",
                argv=tuple(cooperative_lock_command(
                    pkexec, flock, device.path,
                    (
                        badblocks, "-w", "-s", "-v", "-b", "4096",
                        "-c", "1024", "-t", pattern, device.path,
                    ),
                )),
                kind="badblocks",
                pattern=pattern,
            ))

    confirmation = _confirmation_for(device)
    warnings = _warnings_for(device, size_unit_mode)
    return MediaTestPlan(
        device=device,
        mode=mode,
        passes=effective_passes,
        phases=tuple(phases),
        udisksctl_path=udisksctl,
        confirmation_phrase=confirmation,
        size_unit_mode=size_unit_mode,
        warnings=warnings,
    )


def validate_media_test_plan(plan: MediaTestPlan) -> None:
    """Reject forged executable intent before target lookup or unmounting."""
    if not isinstance(plan, MediaTestPlan):
        raise MediaTestSafetyError("A MediaTestPlan is required")
    if not isinstance(plan.mode, MediaTestMode):
        raise MediaTestSafetyError("The media-test plan contains an invalid mode")
    _validate_device(plan.device)
    if plan.mode is MediaTestMode.FAKE_CAPACITY:
        if plan.passes != 0:
            raise MediaTestSafetyError("The media-test plan contains an invalid pass count")
    elif not isinstance(plan.passes, int) or isinstance(plan.passes, bool) or not (
        1 <= plan.passes <= len(BADBLOCK_PATTERNS)
    ):
        raise MediaTestSafetyError("The media-test plan contains an invalid pass count")
    if plan.confirmation_phrase != _confirmation_for(plan.device):
        raise MediaTestSafetyError("The media-test plan contains an invalid confirmation phrase")
    if not isinstance(plan.size_unit_mode, SizeUnitMode):
        raise MediaTestSafetyError("The media-test plan contains an invalid size-unit mode")
    if plan.warnings != _warnings_for(plan.device, plan.size_unit_mode):
        raise MediaTestSafetyError("The media-test plan contains invalid safety warnings")
    try:
        _validate_program_path("udisksctl", plan.udisksctl_path)
    except MediaTestUnavailable as error:
        raise MediaTestSafetyError("The media-test plan contains an untrusted tool path") from error

    expected_specs: list[tuple[str, str, str, tuple[str, ...]]] = []
    if plan.mode in {MediaTestMode.FAKE_CAPACITY, MediaTestMode.COMPLETE}:
        expected_specs.append((
            "Counterfeit-capacity probe", "f3probe", "",
            ("--destructive", "--time-ops", plan.device.path),
        ))
    if plan.mode in {MediaTestMode.FULL_SURFACE, MediaTestMode.COMPLETE}:
        for index, pattern in enumerate(BADBLOCK_PATTERNS[:plan.passes], start=1):
            expected_specs.append((
                f"Full-surface pattern {index}/{plan.passes} ({pattern})",
                "badblocks",
                pattern,
                (
                    "-w", "-s", "-v", "-b", "4096", "-c", "1024", "-t",
                    pattern, plan.device.path,
                ),
            ))
    if not isinstance(plan.phases, tuple) or len(plan.phases) != len(expected_specs):
        raise MediaTestSafetyError("The media-test plan contains unexpected phases")

    first = plan.phases[0] if plan.phases else None
    if not isinstance(first, MediaTestPhase) or not isinstance(first.argv, tuple) or len(first.argv) < 9:
        raise MediaTestSafetyError("The media-test plan contains an invalid command")
    try:
        pkexec = _validate_program_path("pkexec", first.argv[0])
        flock = _validate_program_path("flock", first.argv[1])
    except MediaTestUnavailable as error:
        raise MediaTestSafetyError("The media-test plan contains an untrusted tool path") from error

    bound_tools: dict[str, str] = {}
    for phase, (name, kind, pattern, arguments) in zip(plan.phases, expected_specs, strict=True):
        if not isinstance(phase, MediaTestPhase) or not isinstance(phase.argv, tuple):
            raise MediaTestSafetyError("The media-test plan contains an invalid phase")
        if len(phase.argv) < 9:
            raise MediaTestSafetyError("The media-test plan contains an invalid command")
        try:
            tool = _validate_program_path(kind, phase.argv[8])
            expected_argv = tuple(cooperative_lock_command(
                pkexec, flock, plan.device.path, (tool, *arguments),
            ))
        except (MediaTestUnavailable, CooperativeLockError) as error:
            raise MediaTestSafetyError(
                "The media-test plan contains an unsafe locked command"
            ) from error
        previous = bound_tools.setdefault(kind, tool)
        if previous != tool:
            raise MediaTestSafetyError("The media-test plan changed a bound tool path")
        expected = MediaTestPhase(name, expected_argv, kind, pattern)
        if phase != expected:
            raise MediaTestSafetyError("The media-test plan contains unexpected executable intent")


class BadblocksProgressParser:
    """Parse C-locale badblocks write/read percentages without regressions."""

    _percent = re.compile(rb"(\d{1,3}(?:\.\d+)?)%\s+done")

    def __init__(self) -> None:
        self._reading = False
        self._tail = b""

    def feed(self, chunk: bytes) -> float | None:
        data = self._tail + chunk
        if b"Reading and comparing:" in data:
            self._reading = True
        matches = list(self._percent.finditer(data))
        self._tail = data[-256:]
        if not matches:
            return None
        percent = min(100.0, max(0.0, float(matches[-1].group(1)))) / 100.0
        # A destructive pattern consists of an entire write followed by an
        # entire read/compare.  badblocks resets its percentage for the latter.
        return (0.5 + percent * 0.5) if self._reading else (percent * 0.5)


def parse_bad_block_lines(output: bytes) -> tuple[int, ...]:
    """Parse the block-number-only stdout emitted by badblocks."""
    found: set[int] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.isdigit():
            found.add(int(line))
    return tuple(sorted(found))


Progress = Callable[[MediaTestProgress], None]
DeviceLister = Callable[[], Sequence[Device]]


class MediaTestRunner:
    """Execute a confirmed plan; instances are deliberately single-use."""

    def __init__(
        self,
        *,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        run_command: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        device_lister: DeviceLister = list_devices,
        stat_func: Callable[[str], os.stat_result] = os.stat,
        process_stop_timeout: float = PROCESS_STOP_TIMEOUT_SECONDS,
    ) -> None:
        if process_stop_timeout <= 0:
            raise ValueError("process_stop_timeout must be positive")
        self._popen = popen
        self._run_command = run_command
        self._device_lister = device_lister
        self._stat = stat_func
        self._process_stop_timeout = process_stop_timeout
        self._cancelled = threading.Event()
        self._process: subprocess.Popen[bytes] | None = None
        self._process_lock = threading.Lock()
        self._process_stop_lock = threading.Lock()
        self._started = False

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def _terminate_and_reap(self, process: subprocess.Popen[bytes]) -> None:
        """Bounded terminate -> kill -> wait, safe under cancellation races."""
        with self._process_stop_lock:
            if process.poll() is None:
                try:
                    process.terminate()
                except OSError:
                    # The process may have exited between poll() and terminate().
                    pass
            try:
                process.wait(timeout=self._process_stop_timeout)
                return
            except subprocess.TimeoutExpired:
                pass
            except OSError:
                if process.poll() is not None:
                    return
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=self._process_stop_timeout)
            except subprocess.TimeoutExpired as error:
                raise MediaTestError(
                    "The privileged media-test process could not be stopped and reaped"
                ) from error
            except OSError as error:
                if process.poll() is None:
                    raise MediaTestError(
                        "The privileged media-test process could not be stopped and reaped"
                    ) from error

    def cancel(self) -> None:
        self._cancelled.set()
        with self._process_lock:
            process = self._process
        if process is not None:
            self._terminate_and_reap(process)

    def _check_cancelled(self) -> None:
        if self.cancelled:
            raise MediaTestCancelled("Media validation was cancelled")

    def _verify_target(self, plan: MediaTestPlan) -> None:
        try:
            matching = [
                candidate for candidate in self._device_lister()
                if candidate.path == plan.device.path
            ]
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            raise MediaTestSafetyError(f"Could not revalidate the target: {error}") from error
        if len(matching) != 1 or matching[0].identity != plan.device.identity:
            raise MediaTestSafetyError(
                "The selected drive disappeared or its identity changed; rescan and confirm again"
            )
        try:
            info = self._stat(plan.device.path)
        except OSError as error:
            raise MediaTestSafetyError(f"The target is no longer available: {error}") from error
        if not stat.S_ISBLK(info.st_mode):
            raise MediaTestSafetyError("The target path is not a block device")
        if plan.device.major_minor:
            actual = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
            if actual != plan.device.major_minor:
                raise MediaTestSafetyError(
                    "The target device number changed; rescan and confirm again"
                )

    def _unmount(self, plan: MediaTestPlan) -> None:
        targets = plan.device.partitions or (
            (plan.device.path,) if plan.device.mountpoints else ()
        )
        for target in targets:
            self._check_cancelled()
            try:
                result = self._run_command(
                    [plan.udisksctl_path, "unmount", "--block-device", target],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except (OSError, subprocess.SubprocessError) as error:
                message = f"Could not unmount {target}: {error}"
                raise MediaTestSafetyError(
                    message + conflict_diagnostic_suffix(target)
                ) from error
            combined = f"{result.stdout or ''}{result.stderr or ''}".lower()
            if result.returncode and "not mounted" not in combined:
                message = combined.strip() or f"Could not unmount {target}"
                raise MediaTestSafetyError(
                    message + conflict_diagnostic_suffix(target)
                )

    @staticmethod
    def _pipe_reader(
        stream: BinaryIO,
        channel: str,
        messages: queue.Queue[tuple[str, bytes | None]],
    ) -> None:
        reader = getattr(stream, "read1", None)
        if reader is None:
            reader = stream.read
        try:
            while True:
                chunk = reader(4096)
                if not chunk:
                    break
                messages.put((channel, chunk))
        except OSError:
            pass
        finally:
            messages.put((channel, None))

    def _execute_phase(
        self,
        phase: MediaTestPhase,
        phase_index: int,
        phase_count: int,
        progress: Progress,
    ) -> tuple[int, bytes, bytes]:
        self._check_cancelled()
        # C locale makes the deliberately narrow badblocks progress parser
        # deterministic.  argv is always a tuple/list; shell is never enabled.
        environment = os.environ.copy()
        environment.update({"LC_ALL": "C", "LANG": "C"})
        try:
            process = self._popen(
                list(phase.argv),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                shell=False,
            )
        except OSError as error:
            raise MediaTestError(f"Could not start {phase.name}: {error}") from error
        with self._process_lock:
            self._process = process
        readers: list[threading.Thread] = []
        try:
            self._check_cancelled()
            if process.stdout is None or process.stderr is None:
                raise MediaTestError(f"Could not capture output from {phase.name}")

            messages: queue.Queue[tuple[str, bytes | None]] = queue.Queue()
            readers = [
                threading.Thread(
                    target=self._pipe_reader, args=(process.stdout, "stdout", messages),
                    daemon=True,
                ),
                threading.Thread(
                    target=self._pipe_reader, args=(process.stderr, "stderr", messages),
                    daemon=True,
                ),
            ]
            for reader in readers:
                reader.start()

            parser = BadblocksProgressParser() if phase.kind == "badblocks" else None
            stdout = bytearray()
            stderr = bytearray()
            open_channels = len(readers)
            progress(MediaTestProgress(phase.name, phase_index, phase_count, 0.0))
            while open_channels:
                self._check_cancelled()
                try:
                    channel, chunk = messages.get(timeout=0.2)
                except queue.Empty:
                    continue
                if chunk is None:
                    open_channels -= 1
                    continue
                destination = stdout if channel == "stdout" else stderr
                room = MAX_CAPTURE_BYTES - len(destination)
                if room > 0:
                    destination.extend(chunk[:room])
                if parser is not None and channel == "stderr":
                    fraction = parser.feed(chunk)
                    if fraction is not None:
                        progress(MediaTestProgress(
                            phase.name, phase_index, phase_count, fraction,
                        ))

            code = process.wait()
        finally:
            try:
                self._terminate_and_reap(process)
            finally:
                for reader in readers:
                    reader.join(timeout=self._process_stop_timeout)
                with self._process_lock:
                    if self._process is process:
                        self._process = None
        self._check_cancelled()
        if code == 0 or (phase.kind == "f3probe" and 101 <= code <= 104):
            progress(MediaTestProgress(phase.name, phase_index, phase_count, 1.0))
        return code, bytes(stdout), bytes(stderr)

    def run(
        self,
        plan: MediaTestPlan,
        confirmation: str,
        progress: Progress = lambda _progress: None,
    ) -> MediaTestResult:
        if self._started:
            raise MediaTestSafetyError("A media-test runner cannot be reused")
        self._started = True
        self._check_cancelled()
        validate_media_test_plan(plan)
        if not hmac.compare_digest(confirmation, plan.confirmation_phrase):
            raise MediaTestSafetyError(
                f"Confirmation did not exactly match {plan.confirmation_phrase!r}"
            )

        # Verify before and after unmounting.  This catches replacement at the
        # device path both before authorization work and immediately before the
        # first destructive command.
        self._verify_target(plan)
        self._unmount(plan)
        self._check_cancelled()
        self._verify_target(plan)

        bad_blocks: set[int] = set()
        capacity_status = CapacityStatus.NOT_TESTED
        diagnostics: list[str] = []
        for phase_index, phase in enumerate(plan.phases):
            # Re-check before every process, not merely once before a long
            # multi-pattern test.  A removed/replaced drive must stop the plan.
            self._verify_target(plan)
            logger.info("Starting destructive media-test phase: %s", phase.name)
            code, stdout, stderr = self._execute_phase(
                phase, phase_index, len(plan.phases), progress,
            )
            rendered = (stdout + stderr).decode(errors="replace").strip()
            if rendered:
                diagnostics.append(rendered[-16384:])

            if phase.kind == "badblocks":
                if code:
                    raise MediaTestError(
                        lock_conflict_message(
                            code,
                            rendered[-2048:]
                            or f"badblocks failed with exit status {code}",
                        )
                    )
                bad_blocks.update(parse_bad_block_lines(stdout))
            elif code == 0:
                capacity_status = CapacityStatus.GENUINE
            elif code == 101:
                capacity_status = CapacityStatus.DAMAGED
            elif 102 <= code <= 104:
                capacity_status = CapacityStatus.COUNTERFEIT
            else:
                raise MediaTestError(
                    lock_conflict_message(
                        code,
                        rendered[-2048:]
                        or f"f3probe failed with exit status {code}",
                    )
                )

        return MediaTestResult(
            device_identity=plan.device.identity,
            mode=plan.mode,
            completed_phases=len(plan.phases),
            bad_blocks=tuple(sorted(bad_blocks)),
            capacity_status=capacity_status,
            diagnostics=tuple(diagnostics),
        )
