from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Safety-focused whole-drive zeroing backend.

Neither mode in this module is a hardware secure erase.  ``FULL_ZERO`` writes
one logical pass of zero bytes over the advertised device size.  Flash media,
SSDs, remapped sectors, and over-provisioned storage can retain data that an
ordinary host write cannot address.

``QUICK_BOUNDARY_ZERO`` has deliberately narrow semantics: it overwrites the
union of the first and last 16 MiB of the drive.  This normally removes primary
and backup partition tables, boot records, and common filesystem metadata, but
bytes outside those ranges are untouched and may remain recoverable.

The module has no GUI integration.  A caller must first create an immutable
plan, present its warnings, and pass the plan's exact confirmation phrase to a
fresh :class:`EraseRunner` instance.
"""

import hmac
import json
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

from .devices import Device, SizeUnitMode, format_size, parse_lsblk
from .conflicts import conflict_diagnostic_suffix, unmount_response_is_inactive
from .locking import (
    CooperativeLockError,
    cooperative_lock_command,
    lock_conflict_message,
    resolve_flock,
)

QUICK_BOUNDARY_BYTES = 16 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 16 * 1024
MAX_ERROR_CHARACTERS = 2048
PROCESS_STOP_TIMEOUT_SECONDS = 2.0
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_TRUSTED_TOOL_DIRECTORIES = tuple(_TRUSTED_TOOL_PATH.split(":"))
_WHOLE_DISK = re.compile(
    r"/dev/(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|mmcblk\d+|ubd[a-z]+)"
)
_BLOCK_PATH = re.compile(r"/dev/[A-Za-z0-9._+:-]+")
_MAJOR_MINOR = re.compile(r"\d+:\d+")
_DD_BYTES = re.compile(rb"(?:^|[\r\n])\s*(\d+)\s+bytes\b")


class EraseMode(Enum):
    """Available logical overwrite scopes; neither is secure erase."""

    FULL_ZERO = "full_zero"
    QUICK_BOUNDARY_ZERO = "quick_boundary_zero"


class EraseError(RuntimeError):
    pass


class EraseUnavailable(EraseError):
    """A required trusted system utility is unavailable."""


class EraseSafetyError(EraseError):
    """The target, plan, or confirmation failed a safety check."""


class EraseCancelled(EraseError):
    pass


@dataclass(frozen=True)
class EraseRange:
    """A half-open byte range [offset, offset + length) to overwrite."""

    offset: int
    length: int


@dataclass(frozen=True)
class EraseTools:
    pkexec: str
    udisksctl: str
    lsblk: str
    dd: str
    flock: str


@dataclass(frozen=True)
class ErasePlan:
    """Immutable zero-write intent bound to one observed kernel device."""

    device: Device
    mode: EraseMode
    ranges: tuple[EraseRange, ...]
    tools: EraseTools
    confirmation_phrase: str
    size_unit_mode: SizeUnitMode
    warnings: tuple[str, ...]

    @property
    def total_bytes(self) -> int:
        return sum(item.length for item in self.ranges)


@dataclass(frozen=True)
class EraseProgress:
    range_index: int
    range_count: int
    range_offset: int
    range_length: int
    range_bytes_done: int
    bytes_done: int
    total_bytes: int

    @property
    def fraction(self) -> float:
        if self.total_bytes <= 0:
            return 0.0
        return min(1.0, max(0.0, self.bytes_done / self.total_bytes))


@dataclass(frozen=True)
class EraseResult:
    device_identity: tuple[str, int, str, str, str, str]
    mode: EraseMode
    ranges_completed: int
    bytes_written: int


Progress = Callable[[EraseProgress], None]
DeviceLister = Callable[[], Sequence[Device]]


def _partition_belongs_to_device(device_path: str, partition_path: str) -> bool:
    separator = "p" if device_path[-1].isdigit() else ""
    return re.fullmatch(re.escape(device_path) + separator + r"\d+", partition_path) is not None


def _bounded_message(value: object, fallback: str) -> str:
    rendered = str(value or "").strip()
    return rendered[-MAX_ERROR_CHARACTERS:] if rendered else fallback


def _trusted_which(name: str) -> str | None:
    """Never resolve an elevated program through the user's mutable PATH."""
    return shutil.which(name, path=_TRUSTED_TOOL_PATH)


def _validate_tool_path(name: str, value: str | None) -> str:
    if not isinstance(value, str) or not value:
        raise EraseUnavailable(f"{name} is required to erase a drive but was not found")
    if not os.path.isabs(value):
        raise EraseUnavailable(f"Could not resolve a safe absolute path for {name}")
    # Trust the root-owned entry selected from the fixed system path.  Do not
    # reject distro-managed alternatives/symlinks whose implementation lives
    # elsewhere (for example /usr/bin/dd -> /usr/lib/.../coreutils/dd).
    resolved = os.path.normpath(value)
    if (
        resolved != value
        or os.path.dirname(resolved) not in _TRUSTED_TOOL_DIRECTORIES
        or os.path.basename(resolved) != name
    ):
        raise EraseUnavailable(f"Refusing untrusted {name} path: {value!r}")
    return resolved


def resolve_erase_tools(
    finder: Callable[[str], str | None] = _trusted_which,
) -> EraseTools:
    resolved = {
        name: _validate_tool_path(name, finder(name))
        for name in ("pkexec", "udisksctl", "lsblk", "dd")
    }
    try:
        resolved["flock"] = resolve_flock(finder)
    except CooperativeLockError as error:
        raise EraseUnavailable(str(error)) from error
    return EraseTools(**resolved)


def _validate_device(device: Device) -> None:
    if not isinstance(device, Device):
        raise EraseSafetyError("A discovered removable Device is required")
    if not _WHOLE_DISK.fullmatch(device.path):
        raise EraseSafetyError("The erase target must be a supported whole-disk path under /dev")
    if not _MAJOR_MINOR.fullmatch(device.major_minor):
        raise EraseSafetyError("The target has no stable kernel major:minor identity")
    if device.size <= 0:
        raise EraseSafetyError("The selected drive has an invalid capacity")
    if device.read_only:
        raise EraseSafetyError("The selected removable drive is read-only")
    # Deliberately stricter than the normal writer's optional USB HDD support.
    if not device.removable:
        raise EraseSafetyError("Drive erase is restricted to media marked removable")
    if device.transport not in {"usb", "mmc"}:
        raise EraseSafetyError("Only removable USB and SD/MMC media can be erased")
    if "/" in device.mountpoints:
        raise EraseSafetyError("The drive backing the running system cannot be erased")
    for partition in device.partitions:
        if (
            not _BLOCK_PATH.fullmatch(partition)
            or not _partition_belongs_to_device(device.path, partition)
        ):
            raise EraseSafetyError(f"Unsafe partition path reported for target: {partition!r}")


def _erase_ranges(size: int, mode: EraseMode) -> tuple[EraseRange, ...]:
    if mode is EraseMode.FULL_ZERO:
        return (EraseRange(0, size),)
    if mode is not EraseMode.QUICK_BOUNDARY_ZERO:
        raise ValueError("mode must be an EraseMode")

    span = min(QUICK_BOUNDARY_BYTES, size)
    first = EraseRange(0, span)
    last_offset = size - span
    # Merge overlapping/touching boundary spans so every planned byte is
    # written once and progress has an exact denominator.
    if last_offset <= first.offset + first.length:
        return (EraseRange(0, size),)
    return (first, EraseRange(last_offset, span))


def _confirmation_for(device: Device) -> str:
    return f"ERASE {device.path} {device.major_minor}"


def _warnings_for(
    device: Device,
    mode: EraseMode,
    size_unit_mode: SizeUnitMode,
) -> tuple[str, ...]:
    confirmation = _confirmation_for(device)
    common = (
        "THIS OPERATION IS DESTRUCTIVE AND CANNOT BE UNDONE.",
        (
            f"Target: {device.display_label(size_unit_mode)}; "
            f"serial {device.serial or 'not reported'}; "
            f"kernel identity {device.major_minor}."
        ),
        "This is a logical overwrite, not a hardware secure erase or sanitization command.",
    )
    if mode is EraseMode.FULL_ZERO:
        scope = (
            "ISOpropyl will write one pass of zeros across all "
            f"{format_size(device.size, size_unit_mode)} "
            "of the drive's advertised logical address space.",
        )
    else:
        scope = (
            "Quick boundary zero writes only the first and last "
            f"{format_size(QUICK_BOUNDARY_BYTES, size_unit_mode)} "
            "(or their merged union on a very small drive).",
            "Data outside those boundary ranges is untouched and may remain recoverable.",
        )
    return common + scope + (
        "Do not unplug the drive, suspend the computer, or remove power during the operation.",
        f"To authorize this separate destructive operation, type exactly: {confirmation}",
    )


def build_erase_plan(
    device: Device,
    mode: EraseMode,
    *,
    finder: Callable[[str], str | None] = _trusted_which,
    size_unit_mode: SizeUnitMode = SizeUnitMode.SI,
) -> ErasePlan:
    """Validate a selection and bind an erase plan to its observed identity."""
    if not isinstance(mode, EraseMode):
        raise ValueError("mode must be an EraseMode")
    if not isinstance(size_unit_mode, SizeUnitMode):
        raise ValueError("size_unit_mode must be a SizeUnitMode")
    _validate_device(device)
    tools = resolve_erase_tools(finder)
    ranges = _erase_ranges(device.size, mode)
    confirmation = _confirmation_for(device)
    return ErasePlan(
        device, mode, ranges, tools, confirmation, size_unit_mode,
        _warnings_for(device, mode, size_unit_mode),
    )


def validate_erase_plan(plan: ErasePlan) -> None:
    """Reject manually forged or mutated plans before any device interaction."""
    if not isinstance(plan, ErasePlan):
        raise EraseSafetyError("An ErasePlan is required")
    if not isinstance(plan.mode, EraseMode):
        raise EraseSafetyError("The erase plan contains an invalid mode")
    _validate_device(plan.device)
    if plan.ranges != _erase_ranges(plan.device.size, plan.mode):
        raise EraseSafetyError("The erase plan contains unexpected byte ranges")
    if plan.confirmation_phrase != _confirmation_for(plan.device):
        raise EraseSafetyError("The erase plan contains an invalid confirmation phrase")
    if not isinstance(plan.size_unit_mode, SizeUnitMode):
        raise EraseSafetyError("The erase plan contains an invalid size-unit mode")
    if plan.warnings != _warnings_for(
        plan.device, plan.mode, plan.size_unit_mode,
    ):
        raise EraseSafetyError("The erase plan contains invalid safety warnings")
    for name in ("pkexec", "udisksctl", "lsblk", "dd", "flock"):
        try:
            _validate_tool_path(name, getattr(plan.tools, name, None))
        except EraseUnavailable as error:
            raise EraseSafetyError("The erase plan contains an untrusted tool path") from error


def erase_command(plan: ErasePlan, byte_range: EraseRange) -> tuple[str, ...]:
    """Return a GNU dd argv that writes exactly one planned byte range."""
    validate_erase_plan(plan)
    if byte_range not in plan.ranges:
        raise EraseSafetyError("The requested byte range is not part of this erase plan")
    try:
        return tuple(cooperative_lock_command(
            plan.tools.pkexec,
            plan.tools.flock,
            plan.device.path,
            (
                plan.tools.dd,
                "if=/dev/zero",
                f"of={plan.device.path}",
                "bs=4194304",
                f"count={byte_range.length}",
                "iflag=count_bytes",
                f"seek={byte_range.offset}",
                "oflag=seek_bytes",
                "conv=fsync,notrunc",
                "status=progress",
            ),
        ))
    except CooperativeLockError as error:
        raise EraseSafetyError("The erase plan contains an unsafe locked command") from error


class _DDProgressParser:
    def __init__(self) -> None:
        self._tail = b""

    def feed(self, chunk: bytes) -> int | None:
        data = self._tail + chunk
        matches = list(_DD_BYTES.finditer(data))
        self._tail = data[-256:]
        return int(matches[-1].group(1)) if matches else None


class _BoundedTail:
    def __init__(self, limit: int = MAX_DIAGNOSTIC_BYTES) -> None:
        self.limit = limit
        self.data = bytearray()

    def append(self, chunk: bytes) -> None:
        self.data.extend(chunk)
        if len(self.data) > self.limit:
            del self.data[:-self.limit]

    def text(self) -> str:
        return bytes(self.data).decode(errors="replace").strip()


class EraseRunner:
    """Execute one confirmed ErasePlan without passing any data through a shell."""

    def __init__(
        self,
        *,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        run_command: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        device_lister: DeviceLister | None = None,
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

    def _terminate_process(self, process: subprocess.Popen[bytes]) -> None:
        """Bounded terminate -> wait -> kill -> wait, including race-safe reaping."""
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
                raise EraseError(
                    "The privileged erase process could not be stopped and reaped"
                ) from error
            except OSError as error:
                if process.poll() is None:
                    raise EraseError(
                        "The privileged erase process could not be stopped and reaped"
                    ) from error

    def cancel(self) -> None:
        self._cancelled.set()
        with self._process_lock:
            process = self._process
        if process is not None:
            self._terminate_process(process)

    def _check_cancelled(self) -> None:
        if self.cancelled:
            raise EraseCancelled("Drive erase was cancelled")

    def _list_devices(self, plan: ErasePlan) -> Sequence[Device]:
        if self._device_lister is not None:
            return self._device_lister()
        fields = "PATH,SIZE,TYPE,RM,HOTPLUG,TRAN,MODEL,VENDOR,SERIAL,WWN,MAJ:MIN,MOUNTPOINTS,RO"
        result = self._run_command(
            [
                plan.tools.lsblk, "--tree", "--bytes", "--json", "--output",
                fields, plan.device.path,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
        )
        if result.returncode:
            message = (result.stdout or "") + (result.stderr or "")
            raise EraseSafetyError(_bounded_message(message, "lsblk could not inspect the target"))
        try:
            return parse_lsblk(result.stdout, include_usb_hdds=False)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise EraseSafetyError("lsblk returned invalid target information") from error

    def _verify_target(self, plan: ErasePlan) -> Device:
        self._check_cancelled()
        try:
            matching = [
                device for device in self._list_devices(plan)
                if device.path == plan.device.path
            ]
        except EraseError:
            raise
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            raise EraseSafetyError(
                _bounded_message(error, "Could not revalidate the erase target")
            ) from error
        if len(matching) != 1 or matching[0].identity != plan.device.identity:
            raise EraseSafetyError(
                "The selected drive disappeared or its identity changed; rescan and confirm again"
            )
        current = matching[0]
        _validate_device(current)
        try:
            info = self._stat(plan.device.path)
        except OSError as error:
            raise EraseSafetyError(
                _bounded_message(error, "The target is no longer available")
            ) from error
        if not stat.S_ISBLK(info.st_mode):
            raise EraseSafetyError("The target path is not a block device")
        actual = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
        if actual != plan.device.major_minor:
            raise EraseSafetyError(
                "The target device number changed; rescan and confirm again"
            )
        return current

    def _unmount(self, plan: ErasePlan, current: Device) -> bool:
        normalized_nonzero = False
        targets = current.partitions or ((current.path,) if current.mountpoints else ())
        for target in targets:
            self._check_cancelled()
            try:
                result = self._run_command(
                    [plan.tools.udisksctl, "unmount", "--block-device", target],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False,
                )
            except (OSError, subprocess.SubprocessError) as error:
                message = _bounded_message(error, f"Could not unmount {target}")
                raise EraseSafetyError(
                    message + conflict_diagnostic_suffix(target)
                ) from error
            combined = (result.stdout or "") + (result.stderr or "")
            if result.returncode:
                if not unmount_response_is_inactive(combined):
                    message = _bounded_message(combined, f"Could not unmount {target}")
                    raise EraseSafetyError(
                        message + conflict_diagnostic_suffix(target)
                    )
                normalized_nonzero = True
        return normalized_nonzero

    @staticmethod
    def _pipe_reader(
        stream: BinaryIO,
        channel: str,
        messages: queue.Queue[tuple[str, bytes | None]],
    ) -> None:
        read = getattr(stream, "read1", None) or stream.read
        try:
            while True:
                chunk = read(4096)
                if not chunk:
                    break
                messages.put((channel, chunk))
        except OSError:
            pass
        finally:
            messages.put((channel, None))

    def _execute_range(
        self,
        plan: ErasePlan,
        byte_range: EraseRange,
        range_index: int,
        completed_bytes: int,
        progress: Progress,
    ) -> None:
        self._check_cancelled()
        argv = erase_command(plan, byte_range)
        environment = os.environ.copy()
        environment.update({"LC_ALL": "C", "LANG": "C"})
        try:
            process = self._popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                shell=False,
            )
        except OSError as error:
            raise EraseError(_bounded_message(error, "Could not start the zero-write process")) from error
        with self._process_lock:
            self._process = process
        if self.cancelled:
            try:
                self._terminate_process(process)
            finally:
                with self._process_lock:
                    self._process = None
            self._check_cancelled()
        if process.stdout is None or process.stderr is None:
            try:
                self._terminate_process(process)
            finally:
                with self._process_lock:
                    self._process = None
            raise EraseError("Could not capture zero-write process output")

        messages: queue.Queue[tuple[str, bytes | None]] = queue.Queue()
        readers = [
            threading.Thread(
                target=self._pipe_reader, args=(process.stdout, "stdout", messages), daemon=True,
            ),
            threading.Thread(
                target=self._pipe_reader, args=(process.stderr, "stderr", messages), daemon=True,
            ),
        ]
        for reader in readers:
            reader.start()

        parser = _DDProgressParser()
        diagnostics = _BoundedTail()
        open_channels = len(readers)
        last_range_done = 0

        def report(range_done: int) -> None:
            nonlocal last_range_done
            bounded = min(byte_range.length, max(last_range_done, range_done))
            last_range_done = bounded
            progress(EraseProgress(
                range_index=range_index,
                range_count=len(plan.ranges),
                range_offset=byte_range.offset,
                range_length=byte_range.length,
                range_bytes_done=bounded,
                bytes_done=completed_bytes + bounded,
                total_bytes=plan.total_bytes,
            ))

        try:
            report(0)
            while open_channels:
                self._check_cancelled()
                try:
                    channel, chunk = messages.get(timeout=0.2)
                except queue.Empty:
                    continue
                if chunk is None:
                    open_channels -= 1
                    continue
                diagnostics.append(chunk)
                if channel == "stderr":
                    parsed = parser.feed(chunk)
                    if parsed is not None:
                        report(parsed)
            code = process.wait()
        finally:
            try:
                # A progress callback or parser failure must never leave a
                # privileged writer running after this method has unwound.
                self._terminate_process(process)
            finally:
                for reader in readers:
                    reader.join(timeout=self._process_stop_timeout)
                with self._process_lock:
                    if self._process is process:
                        self._process = None
        self._check_cancelled()
        if code:
            raise EraseError(
                lock_conflict_message(
                    code,
                    _bounded_message(
                        diagnostics.text(), f"Zero-write failed with exit status {code}",
                    ),
                )
            )
        report(byte_range.length)

    def run(
        self,
        plan: ErasePlan,
        confirmation: str,
        progress: Progress = lambda _progress: None,
    ) -> EraseResult:
        if self._started:
            raise EraseSafetyError("An erase runner cannot be reused")
        self._started = True
        self._check_cancelled()
        validate_erase_plan(plan)
        if not isinstance(confirmation, str) or not hmac.compare_digest(
            confirmation, plan.confirmation_phrase
        ):
            raise EraseSafetyError(
                f"Confirmation did not exactly match {plan.confirmation_phrase!r}"
            )

        # Revalidate on both sides of unmounting and again immediately before
        # every destructive command.  A path reuse or device replacement fails
        # closed before the next byte range can start.
        current = self._verify_target(plan)
        normalized_unmount = self._unmount(plan, current)
        current = self._verify_target(plan)
        if normalized_unmount and current.mountpoints:
            raise EraseSafetyError(
                "The target still reports mounted filesystems after unmounting"
            )

        completed = 0
        for index, byte_range in enumerate(plan.ranges):
            self._verify_target(plan)
            self._execute_range(plan, byte_range, index, completed, progress)
            completed += byte_range.length

        return EraseResult(
            device_identity=plan.device.identity,
            mode=plan.mode,
            ranges_completed=len(plan.ranges),
            bytes_written=completed,
        )
