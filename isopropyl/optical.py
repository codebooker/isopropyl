from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Read-only optical-disc capture with identity and destination safeguards.

The privileged subprocess in this module is only ever given an optical source
as ``dd`` input.  Its stdout is connected to a temporary regular file opened by
the unprivileged ISOpropyl process, so elevated code never chooses or opens the
destination path.  A complete file is published without replacement via an
atomic hard link only after the captured length and fsync checks succeed.
"""

import json
import os
import queue
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .conflicts import conflict_diagnostic_suffix

OPTICAL_SECTOR_BYTES = 2048
OUTPUT_SPACE_RESERVE_BYTES = 16 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 16 * 1024
MAX_ERROR_CHARACTERS = 2048
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_TRUSTED_TOOL_DIRECTORIES = tuple(_TRUSTED_TOOL_PATH.split(":"))
_OPTICAL_PATH = re.compile(r"/dev/(?:sr\d+|scd\d+|cdrom\d*)")
_MAJOR_MINOR = re.compile(r"\d+:\d+")
_DD_BYTES = re.compile(rb"(?:^|[\r\n])\s*(\d+)\s+bytes\b")
_SIZE_OUTPUT = re.compile(r"[0-9]+")


class OpticalError(RuntimeError):
    pass


class OpticalUnavailable(OpticalError):
    """A required trusted system utility is unavailable."""


class OpticalSafetyError(OpticalError):
    """A source identity, destination, or preflight check failed."""


class OpticalCancelled(OpticalError):
    pass


OpticalIdentity = tuple[str, int, str, str, str, str, str, str]


@dataclass(frozen=True)
class OpticalDevice:
    path: str
    size: int
    model: str
    vendor: str
    serial: str
    wwn: str
    major_minor: str
    mountpoints: tuple[str, ...]
    label: str = ""
    media_uuid: str = ""
    block_type: str = "rom"

    @property
    def identity(self) -> OpticalIdentity:
        # Mountpoints are intentionally excluded because unmounting changes
        # them.  Media label/UUID and reported size help detect disc swaps.
        return (
            self.path, self.size, self.serial, self.wwn, self.model,
            self.major_minor, self.label, self.media_uuid,
        )


@dataclass(frozen=True)
class OpticalTools:
    pkexec: str
    udisksctl: str
    lsblk: str
    blockdev: str
    dd: str


@dataclass(frozen=True)
class OpticalCapturePlan:
    device: OpticalDevice
    destination: Path
    probed_bytes: int
    readable_bytes: int
    destination_parent_identity: tuple[int, int]
    tools: OpticalTools


@dataclass(frozen=True)
class OpticalProgress:
    bytes_done: int
    total_bytes: int

    @property
    def fraction(self) -> float:
        if self.total_bytes <= 0:
            return 0.0
        return min(1.0, max(0.0, self.bytes_done / self.total_bytes))


@dataclass(frozen=True)
class OpticalCaptureResult:
    device_identity: OpticalIdentity
    destination: Path
    bytes_written: int


Progress = Callable[[OpticalProgress], None]
DeviceLister = Callable[[], Sequence[OpticalDevice]]
RunCommand = Callable[..., subprocess.CompletedProcess[str]]


def _bounded_message(value: object, fallback: str) -> str:
    rendered = str(value or "").strip()
    return rendered[-MAX_ERROR_CHARACTERS:] if rendered else fallback


def _trusted_which(name: str) -> str | None:
    return shutil.which(name, path=_TRUSTED_TOOL_PATH)


def _validate_tool_path(name: str, value: str | None) -> str:
    if not value:
        raise OpticalUnavailable(f"{name} is required for optical capture but was not found")
    if not os.path.isabs(value):
        raise OpticalUnavailable(f"Could not resolve a safe absolute path for {name}")
    normalized = os.path.normpath(value)
    if (
        os.path.dirname(normalized) not in _TRUSTED_TOOL_DIRECTORIES
        or os.path.basename(normalized) != name
    ):
        raise OpticalUnavailable(f"Refusing untrusted {name} path: {value!r}")
    return normalized


def resolve_optical_tools(
    finder: Callable[[str], str | None] = _trusted_which,
) -> OpticalTools:
    return OpticalTools(**{
        name: _validate_tool_path(name, finder(name))
        for name in ("pkexec", "udisksctl", "lsblk", "blockdev", "dd")
    })


def _mountpoints(node: dict) -> tuple[str, ...]:
    values = list(node.get("mountpoints") or [])
    if node.get("mountpoint"):
        values.append(node["mountpoint"])
    return tuple(dict.fromkeys(str(item) for item in values if item))


def parse_optical_devices(payload: str) -> list[OpticalDevice]:
    """Parse only top-level whole optical devices from an lsblk JSON result."""
    try:
        nodes = json.loads(payload).get("blockdevices", [])
    except (AttributeError, TypeError, json.JSONDecodeError) as error:
        raise OpticalError("lsblk returned invalid optical-device data") from error
    if not isinstance(nodes, list):
        raise OpticalError("lsblk returned invalid optical-device data")

    found: list[OpticalDevice] = []
    for node in nodes:
        if not isinstance(node, dict) or node.get("type") != "rom":
            continue
        path = str(node.get("path") or "")
        if not _OPTICAL_PATH.fullmatch(path):
            continue
        try:
            device = OpticalDevice(
                path=path,
                size=int(node.get("size") or 0),
                model=str(node.get("model") or "").strip(),
                vendor=str(node.get("vendor") or "").strip(),
                serial=str(node.get("serial") or "").strip(),
                wwn=str(node.get("wwn") or "").strip(),
                major_minor=str(node.get("maj:min") or "").strip(),
                mountpoints=_mountpoints(node),
                label=str(node.get("label") or "").strip(),
                media_uuid=str(node.get("uuid") or "").strip(),
                block_type="rom",
            )
            _validate_optical_device(device)
        except (OpticalSafetyError, TypeError, ValueError):
            # Discovery is fail-closed per entry: malformed/non-readable tray
            # records are not presented as capture choices.
            continue
        found.append(device)
    return sorted(found, key=lambda item: item.path)


def list_optical_devices(
    *,
    finder: Callable[[str], str | None] = _trusted_which,
    run_command: RunCommand = subprocess.run,
) -> list[OpticalDevice]:
    lsblk = _validate_tool_path("lsblk", finder("lsblk"))
    fields = "PATH,SIZE,TYPE,MODEL,VENDOR,SERIAL,WWN,MAJ:MIN,MOUNTPOINTS,LABEL,UUID"
    try:
        result = run_command(
            [lsblk, "--tree", "--bytes", "--json", "--output", fields],
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise OpticalError(_bounded_message(error, "Could not inspect optical drives")) from error
    if result.returncode:
        message = (result.stdout or "") + (result.stderr or "")
        raise OpticalError(_bounded_message(message, "Could not inspect optical drives"))
    return parse_optical_devices(result.stdout)


def _validate_optical_device(device: OpticalDevice) -> None:
    if not isinstance(device, OpticalDevice) or device.block_type != "rom":
        raise OpticalSafetyError("A discovered whole optical device is required")
    if not _OPTICAL_PATH.fullmatch(device.path):
        raise OpticalSafetyError("The source must be a supported whole optical path under /dev")
    if not _MAJOR_MINOR.fullmatch(device.major_minor):
        raise OpticalSafetyError("The source has no stable kernel major:minor identity")
    if device.size < OPTICAL_SECTOR_BYTES:
        raise OpticalSafetyError("No readable data disc is present in the optical drive")
    if "/" in device.mountpoints:
        raise OpticalSafetyError("The optical source unexpectedly backs the running system")


def _conservative_readable_bytes(reported: int, probed: int) -> int:
    if reported < OPTICAL_SECTOR_BYTES or probed < OPTICAL_SECTOR_BYTES:
        raise OpticalSafetyError("The optical disc has no conservatively readable data extent")
    # Never read beyond either independent size report, and capture complete
    # 2048-byte optical data sectors only.
    readable = min(reported, probed)
    readable -= readable % OPTICAL_SECTOR_BYTES
    if readable < OPTICAL_SECTOR_BYTES:
        raise OpticalSafetyError("The optical disc has no complete readable data sector")
    return readable


def probe_optical_size(
    device_path: str,
    tools: OpticalTools,
    run_command: RunCommand = subprocess.run,
) -> int:
    if not _OPTICAL_PATH.fullmatch(device_path):
        raise OpticalSafetyError("Refusing to probe a non-optical device path")
    try:
        result = run_command(
            [tools.blockdev, "--getsize64", device_path],
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise OpticalError(_bounded_message(error, "Could not determine optical-disc size")) from error
    output = str(result.stdout or "").strip()
    if result.returncode or not _SIZE_OUTPUT.fullmatch(output):
        message = (result.stdout or "") + (result.stderr or "")
        raise OpticalError(_bounded_message(message, "Could not determine optical-disc size"))
    size = int(output)
    if size <= 0:
        raise OpticalSafetyError("The optical drive reports no readable media")
    return size


def _destination_path(value: Path | str) -> Path:
    raw = Path(value)
    if not raw.is_absolute():
        raise OpticalSafetyError("The ISO destination must be an absolute path")
    if raw.suffix.casefold() != ".iso":
        raise OpticalSafetyError("The optical capture destination must end in .iso")
    try:
        parent = raw.parent.resolve(strict=True)
    except OSError as error:
        raise OpticalSafetyError(
            _bounded_message(error, "The destination folder is unavailable")
        ) from error
    return parent / raw.name


def _validate_destination(
    destination: Path,
    readable_bytes: int,
    *,
    stat_func: Callable[[os.PathLike[str] | str], os.stat_result],
    access_func: Callable[[os.PathLike[str] | str, int], bool],
    disk_usage: Callable[[os.PathLike[str] | str], shutil._ntuple_diskusage],
) -> tuple[int, int]:
    if os.path.lexists(destination):
        raise OpticalSafetyError("The ISO destination already exists; choose a new filename")
    try:
        parent_info = stat_func(destination.parent)
    except OSError as error:
        raise OpticalSafetyError(
            _bounded_message(error, "The destination folder is unavailable")
        ) from error
    if not stat.S_ISDIR(parent_info.st_mode):
        raise OpticalSafetyError("The ISO destination parent is not a directory")
    if not access_func(destination.parent, os.W_OK | os.X_OK):
        raise OpticalSafetyError("The ISO destination folder is not writable")
    try:
        free = disk_usage(destination.parent).free
    except OSError as error:
        raise OpticalSafetyError(
            _bounded_message(error, "Could not determine destination free space")
        ) from error
    required = readable_bytes + OUTPUT_SPACE_RESERVE_BYTES
    if free < required:
        raise OpticalSafetyError(
            f"The destination needs {required} free bytes, but only {free} are available"
        )
    return (parent_info.st_dev, parent_info.st_ino)


def build_optical_capture_plan(
    device: OpticalDevice,
    destination: Path | str,
    *,
    finder: Callable[[str], str | None] = _trusted_which,
    run_command: RunCommand = subprocess.run,
    stat_func: Callable[[os.PathLike[str] | str], os.stat_result] = os.stat,
    access_func: Callable[[os.PathLike[str] | str, int], bool] = os.access,
    disk_usage: Callable[[os.PathLike[str] | str], shutil._ntuple_diskusage] = shutil.disk_usage,
) -> OpticalCapturePlan:
    _validate_optical_device(device)
    tools = resolve_optical_tools(finder)
    probed = probe_optical_size(device.path, tools, run_command)
    readable = _conservative_readable_bytes(device.size, probed)
    output = _destination_path(destination)
    parent_identity = _validate_destination(
        output, readable, stat_func=stat_func, access_func=access_func,
        disk_usage=disk_usage,
    )
    return OpticalCapturePlan(
        device, output, probed, readable, parent_identity, tools,
    )


def validate_optical_capture_plan(plan: OpticalCapturePlan) -> None:
    if not isinstance(plan, OpticalCapturePlan):
        raise OpticalSafetyError("An OpticalCapturePlan is required")
    _validate_optical_device(plan.device)
    if not isinstance(plan.probed_bytes, int) or plan.probed_bytes <= 0:
        raise OpticalSafetyError("The capture plan contains an invalid probed size")
    if plan.readable_bytes != _conservative_readable_bytes(
        plan.device.size, plan.probed_bytes,
    ):
        raise OpticalSafetyError("The capture plan contains an invalid readable extent")
    if plan.destination != _destination_path(plan.destination):
        raise OpticalSafetyError("The capture plan contains an invalid destination")
    if (
        not isinstance(plan.destination_parent_identity, tuple)
        or len(plan.destination_parent_identity) != 2
        or not all(isinstance(value, int) and value >= 0 for value in plan.destination_parent_identity)
    ):
        raise OpticalSafetyError("The capture plan contains an invalid destination identity")
    for name in ("pkexec", "udisksctl", "lsblk", "blockdev", "dd"):
        try:
            _validate_tool_path(name, getattr(plan.tools, name, None))
        except OpticalUnavailable as error:
            raise OpticalSafetyError("The capture plan contains an untrusted tool path") from error


def optical_read_command(plan: OpticalCapturePlan) -> tuple[str, ...]:
    """Return read-only GNU dd argv; captured bytes are emitted on stdout."""
    validate_optical_capture_plan(plan)
    return (
        plan.tools.pkexec,
        plan.tools.dd,
        f"if={plan.device.path}",
        "bs=2097152",
        f"count={plan.readable_bytes}",
        "iflag=count_bytes,fullblock",
        "status=progress",
    )


class _ProgressParser:
    def __init__(self) -> None:
        self._tail = b""

    def feed(self, chunk: bytes) -> int | None:
        data = self._tail + chunk
        matches = list(_DD_BYTES.finditer(data))
        self._tail = data[-256:]
        return int(matches[-1].group(1)) if matches else None


class _BoundedTail:
    def __init__(self) -> None:
        self.data = bytearray()

    def append(self, chunk: bytes) -> None:
        self.data.extend(chunk)
        if len(self.data) > MAX_DIAGNOSTIC_BYTES:
            del self.data[:-MAX_DIAGNOSTIC_BYTES]

    def text(self) -> str:
        return bytes(self.data).decode(errors="replace").strip()


class OpticalCaptureRunner:
    """Execute one immutable read-only optical capture plan."""

    def __init__(
        self,
        *,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        run_command: RunCommand = subprocess.run,
        device_lister: DeviceLister | None = None,
        stat_func: Callable[[os.PathLike[str] | str], os.stat_result] = os.stat,
        access_func: Callable[[os.PathLike[str] | str, int], bool] = os.access,
        disk_usage: Callable[[os.PathLike[str] | str], shutil._ntuple_diskusage] = shutil.disk_usage,
    ) -> None:
        self._popen = popen
        self._run_command = run_command
        self._device_lister = device_lister
        self._stat = stat_func
        self._access = access_func
        self._disk_usage = disk_usage
        self._cancelled = threading.Event()
        self._process: subprocess.Popen[bytes] | None = None
        self._process_lock = threading.Lock()
        self._started = False

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    @staticmethod
    def _terminate_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
        except OSError:
            pass

    def cancel(self) -> None:
        self._cancelled.set()
        with self._process_lock:
            process = self._process
        if process is not None:
            self._terminate_process(process)

    def _check_cancelled(self) -> None:
        if self.cancelled:
            raise OpticalCancelled("Optical capture was cancelled")

    def _list_devices(self, plan: OpticalCapturePlan) -> Sequence[OpticalDevice]:
        if self._device_lister is not None:
            return self._device_lister()
        fields = "PATH,SIZE,TYPE,MODEL,VENDOR,SERIAL,WWN,MAJ:MIN,MOUNTPOINTS,LABEL,UUID"
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
            raise OpticalSafetyError(
                _bounded_message(message, "Could not revalidate the optical source")
            )
        return parse_optical_devices(result.stdout)

    def _verify_source(self, plan: OpticalCapturePlan) -> OpticalDevice:
        self._check_cancelled()
        try:
            matching = [
                device for device in self._list_devices(plan)
                if device.path == plan.device.path
            ]
        except OpticalError:
            raise
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            raise OpticalSafetyError(
                _bounded_message(error, "Could not revalidate the optical source")
            ) from error
        if len(matching) != 1 or matching[0].identity != plan.device.identity:
            raise OpticalSafetyError(
                "The optical drive or inserted disc changed; rescan and choose it again"
            )
        current = matching[0]
        _validate_optical_device(current)
        try:
            info = self._stat(plan.device.path)
        except OSError as error:
            raise OpticalSafetyError(
                _bounded_message(error, "The optical source is no longer available")
            ) from error
        if not stat.S_ISBLK(info.st_mode):
            raise OpticalSafetyError("The optical source path is not a block device")
        actual = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
        if actual != plan.device.major_minor:
            raise OpticalSafetyError(
                "The optical source device number changed; rescan and choose it again"
            )
        probed = probe_optical_size(plan.device.path, plan.tools, self._run_command)
        if probed != plan.probed_bytes or _conservative_readable_bytes(
            current.size, probed,
        ) != plan.readable_bytes:
            raise OpticalSafetyError(
                "The inserted disc size changed; rescan and choose it again"
            )
        return current

    def _verify_destination(self, plan: OpticalCapturePlan, *, check_space: bool) -> None:
        if os.path.lexists(plan.destination):
            raise OpticalSafetyError(
                "The ISO destination appeared after planning; refusing to overwrite it"
            )
        try:
            info = self._stat(plan.destination.parent)
        except OSError as error:
            raise OpticalSafetyError(
                _bounded_message(error, "The destination folder is unavailable")
            ) from error
        if not stat.S_ISDIR(info.st_mode) or (
            info.st_dev, info.st_ino
        ) != plan.destination_parent_identity:
            raise OpticalSafetyError(
                "The destination folder changed; choose the destination again"
            )
        if not self._access(plan.destination.parent, os.W_OK | os.X_OK):
            raise OpticalSafetyError("The ISO destination folder is not writable")
        if check_space:
            try:
                free = self._disk_usage(plan.destination.parent).free
            except OSError as error:
                raise OpticalSafetyError(
                    _bounded_message(error, "Could not determine destination free space")
                ) from error
            required = plan.readable_bytes + OUTPUT_SPACE_RESERVE_BYTES
            if free < required:
                raise OpticalSafetyError(
                    f"The destination needs {required} free bytes, but only {free} are available"
                )

    def _unmount(self, plan: OpticalCapturePlan, current: OpticalDevice) -> None:
        if not current.mountpoints:
            return
        try:
            result = self._run_command(
                [
                    plan.tools.udisksctl, "unmount", "--block-device",
                    current.path,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            message = _bounded_message(error, f"Could not unmount {current.path}")
            raise OpticalSafetyError(
                message + conflict_diagnostic_suffix(current.path)
            ) from error
        combined = (result.stdout or "") + (result.stderr or "")
        if result.returncode and not any(
            item in combined.casefold()
            for item in ("not mounted", "not a mounted filesystem")
        ):
            message = _bounded_message(combined, f"Could not unmount {current.path}")
            raise OpticalSafetyError(
                message + conflict_diagnostic_suffix(current.path)
            )

    @staticmethod
    def _stderr_reader(
        stream: BinaryIO,
        messages: queue.Queue[bytes | None],
    ) -> None:
        read = getattr(stream, "read1", None) or stream.read
        try:
            while True:
                chunk = read(4096)
                if not chunk:
                    break
                messages.put(chunk)
        except OSError:
            pass
        finally:
            messages.put(None)

    def _capture_to_open_file(
        self,
        plan: OpticalCapturePlan,
        output: BinaryIO,
        progress: Progress,
    ) -> None:
        self._check_cancelled()
        environment = os.environ.copy()
        environment.update({"LC_ALL": "C", "LANG": "C"})
        try:
            process = self._popen(
                list(optical_read_command(plan)),
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.PIPE,
                env=environment,
                shell=False,
            )
        except OSError as error:
            raise OpticalError(
                _bounded_message(error, "Could not start optical-disc reading")
            ) from error
        with self._process_lock:
            self._process = process
        if self.cancelled:
            try:
                self._terminate_process(process)
            finally:
                with self._process_lock:
                    self._process = None
            self._check_cancelled()
        if process.stderr is None:
            try:
                self._terminate_process(process)
            finally:
                with self._process_lock:
                    self._process = None
            raise OpticalError("Could not capture optical-reader diagnostics")

        messages: queue.Queue[bytes | None] = queue.Queue()
        reader = threading.Thread(
            target=self._stderr_reader, args=(process.stderr, messages), daemon=True,
        )
        reader.start()
        parser = _ProgressParser()
        diagnostics = _BoundedTail()
        last_done = 0

        def report(done: int) -> None:
            nonlocal last_done
            last_done = min(plan.readable_bytes, max(last_done, done))
            progress(OpticalProgress(last_done, plan.readable_bytes))

        try:
            report(0)
            while True:
                self._check_cancelled()
                try:
                    chunk = messages.get(timeout=0.2)
                except queue.Empty:
                    continue
                if chunk is None:
                    break
                diagnostics.append(chunk)
                parsed = parser.feed(chunk)
                if parsed is not None:
                    report(parsed)
            code = process.wait()
            reader.join(timeout=1)
        finally:
            try:
                # Callback or parsing failures cannot orphan a privileged
                # optical reader that still has an open output descriptor.
                self._terminate_process(process)
            finally:
                with self._process_lock:
                    if self._process is process:
                        self._process = None
        self._check_cancelled()
        if code:
            raise OpticalError(
                _bounded_message(
                    diagnostics.text(), f"Optical reader failed with exit status {code}",
                )
            )
        report(plan.readable_bytes)

    @staticmethod
    def _publish_without_overwrite(temporary: Path, destination: Path) -> None:
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError as error:
            raise OpticalSafetyError(
                "The ISO destination appeared during capture; the existing file was not changed"
            ) from error
        except OSError as error:
            raise OpticalError(
                _bounded_message(error, "Could not publish the completed ISO atomically")
            ) from error
        temporary.unlink()

    def run(
        self,
        plan: OpticalCapturePlan,
        progress: Progress = lambda _progress: None,
    ) -> OpticalCaptureResult:
        if self._started:
            raise OpticalSafetyError("An optical capture runner cannot be reused")
        self._started = True
        self._check_cancelled()
        validate_optical_capture_plan(plan)
        self._verify_destination(plan, check_space=True)
        current = self._verify_source(plan)
        self._unmount(plan, current)
        # Revalidate the source and destination after unmount, immediately
        # before opening a temporary output and starting the privileged reader.
        self._verify_source(plan)
        self._verify_destination(plan, check_space=True)

        descriptor = -1
        temporary: Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{plan.destination.name}.",
                suffix=".partial",
                dir=plan.destination.parent,
            )
            temporary = Path(temporary_name)
            output_info = os.fstat(descriptor)
            if not stat.S_ISREG(output_info.st_mode) or output_info.st_uid != os.geteuid():
                raise OpticalSafetyError("The temporary ISO output is not a user-owned regular file")
            with os.fdopen(descriptor, "w+b", buffering=0) as output:
                descriptor = -1
                self._capture_to_open_file(plan, output, progress)
                output.flush()
                os.fsync(output.fileno())
            captured = temporary.stat().st_size
            if captured != plan.readable_bytes:
                raise OpticalError(
                    f"The optical reader produced {captured} of {plan.readable_bytes} expected bytes"
                )
            self._verify_destination(plan, check_space=False)
            self._publish_without_overwrite(temporary, plan.destination)
            temporary = None
            return OpticalCaptureResult(
                plan.device.identity, plan.destination, captured,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            with self._process_lock:
                process = self._process
            if process is not None:
                self._terminate_process(process)
            with self._process_lock:
                self._process = None
            if temporary is not None:
                temporary.unlink(missing_ok=True)
