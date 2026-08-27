from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Safe, read-only ingestion and raw staging of virtual disk containers.

Virtual disk containers must never be passed to the raw device writer.  This
module first inspects them with a fixed, absolute ``qemu-img`` executable and
then converts the bound container identity into a private raw regular file.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

SUPPORTED_FORMATS = frozenset({"vpc", "vhdx", "qcow", "qcow2"})
MAX_INFO_JSON = 256 * 1024
MAX_DIAGNOSTIC = 64 * 1024
MAX_VIRTUAL_SIZE = 64 * 1024**4
DEFAULT_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
PROGRESS_PATTERN = re.compile(rb"\(([0-9]+(?:\.[0-9]+)?)/100%\)")

Progress = Callable[[int, int], None]
RunCommand = Callable[..., subprocess.CompletedProcess[bytes]]


class VirtualDiskError(RuntimeError):
    pass


class VirtualDiskChanged(VirtualDiskError):
    pass


class VirtualConversionCancelled(VirtualDiskError):
    pass


class ProcessLike(Protocol):
    stdout: Any
    stderr: Any
    returncode: int | None

    def poll(self) -> int | None: ...
    def wait(self, timeout: float | None = None) -> int: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...


ProcessFactory = Callable[..., ProcessLike]


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class ToolIdentity:
    path: Path
    identity: FileIdentity


@dataclass(frozen=True)
class VirtualDiskInfo:
    path: Path
    identity: FileIdentity
    qemu_img: ToolIdentity
    format: str
    virtual_size: int
    actual_size: int | None
    has_snapshots: bool

    @property
    def display_format(self) -> str:
        return "VHD" if self.format == "vpc" else self.format.upper()


@dataclass
class StagedVirtualDisk:
    path: Path
    size: int
    allocated_size: int
    source_format: str
    source_identity: FileIdentity
    _directory: Path
    _closed: bool = False

    def close(self) -> None:
        if self._closed:
            return
        _cleanup_stage(self._directory, self.path)
        self._closed = True

    def __enter__(self) -> StagedVirtualDisk:
        if self._closed:
            raise VirtualDiskError("The staged virtual disk has already been cleaned up")
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def _file_identity(path: Path, label: str) -> FileIdentity:
    try:
        status = path.stat()
    except OSError as error:
        raise VirtualDiskError(f"{label} is not available: {error}") from error
    if not stat.S_ISREG(status.st_mode):
        raise VirtualDiskError(f"{label} must be a regular file")
    return FileIdentity(
        status.st_dev, status.st_ino, status.st_size,
        status.st_mtime_ns, status.st_ctime_ns,
    )


def resolve_qemu_img(path: Path | None = None) -> ToolIdentity:
    """Resolve qemu-img without consulting the calling session's PATH."""

    if path is None:
        found = shutil.which("qemu-img", path=DEFAULT_TOOL_PATH)
        if not found:
            raise VirtualDiskError("Reading virtual disks requires the qemu-img command")
        candidate = Path(found)
    else:
        if not path.is_absolute():
            raise VirtualDiskError("The trusted qemu-img path must be absolute")
        candidate = path
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise VirtualDiskError(f"The qemu-img command is not available: {error}") from error
    identity = _file_identity(resolved, "qemu-img")
    if not os.access(resolved, os.X_OK):
        raise VirtualDiskError("The qemu-img command is not executable")
    return ToolIdentity(resolved, identity)


def _unchanged(path: Path, expected: FileIdentity, label: str) -> None:
    current = _file_identity(path, label)
    if current != expected:
        raise VirtualDiskChanged(f"{label} changed while it was being prepared")


def _nonempty_security_value(value: object) -> bool:
    if value in (None, False, 0, "", [], {}):
        return False
    return True


def _find_restricted_metadata(value: object) -> tuple[str, str] | None:
    if isinstance(value, dict):
        for raw_key, child in value.items():
            key = str(raw_key).casefold().replace("_", "-")
            if (key == "backing" or key.startswith("backing-")) and _nonempty_security_value(child):
                return "backing", str(raw_key)
            if ("encrypt" in key or key == "key-secret") and _nonempty_security_value(child):
                return "encryption", str(raw_key)
            if key in {"corrupt", "corrupted"} and child is True:
                return "corruption", str(raw_key)
            found = _find_restricted_metadata(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_restricted_metadata(child)
            if found:
                return found
    return None


def _required_int(payload: dict[str, object], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise VirtualDiskError(f"qemu-img JSON field {key!r} must be an integer")
    return value


def _run_info_limited(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    """Run trusted qemu-img while bounding both output retained and runtime."""

    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, shell=False,
    )
    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    oversized = threading.Event()
    reader_errors: list[BaseException] = []

    def read_stdout() -> None:
        try:
            while block := process.stdout.read(4096):
                room = MAX_INFO_JSON + 1 - len(stdout)
                if room > 0:
                    stdout.extend(block[:room])
                if len(stdout) > MAX_INFO_JSON:
                    oversized.set()
                    if process.poll() is None:
                        process.terminate()
                    return
        except BaseException as error:
            reader_errors.append(error)

    def read_stderr() -> None:
        try:
            while block := process.stderr.read(4096):
                _append_bounded(stderr, block)
        except BaseException as error:
            reader_errors.append(error)

    threads = (
        threading.Thread(target=read_stdout, daemon=True),
        threading.Thread(target=read_stderr, daemon=True),
    )
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 20
    try:
        while process.poll() is None:
            if time.monotonic() >= deadline:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                raise subprocess.TimeoutExpired(command, 20)
            time.sleep(0.02)
        code = process.wait()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        for thread in threads:
            thread.join(timeout=2)
    if any(thread.is_alive() for thread in threads):
        raise VirtualDiskError("qemu-img inspection output pipes did not close")
    if reader_errors:
        raise VirtualDiskError(f"Could not read qemu-img inspection output: {reader_errors[0]}")
    if oversized.is_set():
        # Return the sentinel-sized stdout so the common strict parser reports
        # the same error for injected runners and the production subprocess.
        stdout = stdout[:MAX_INFO_JSON + 1]
    return subprocess.CompletedProcess(command, code, bytes(stdout), bytes(stderr))


def inspect_virtual_disk(
    path: Path,
    *,
    qemu_img: Path | None = None,
    runner: RunCommand | None = None,
    maximum_virtual_size: int = MAX_VIRTUAL_SIZE,
) -> VirtualDiskInfo:
    """Inspect a virtual disk and bind the result to its regular-file identity."""

    if not 0 < maximum_virtual_size <= MAX_VIRTUAL_SIZE:
        raise ValueError(
            f"maximum_virtual_size must be between 1 and {MAX_VIRTUAL_SIZE}"
        )
    try:
        resolved_path = path.resolve(strict=True)
    except OSError as error:
        raise VirtualDiskError(f"The selected virtual disk is not available: {error}") from error
    identity = _file_identity(resolved_path, "The selected virtual disk")
    if identity.size == 0:
        raise VirtualDiskError("The selected virtual disk is empty")
    tool = resolve_qemu_img(qemu_img)
    command = [
        str(tool.path), "info", "--output=json", str(resolved_path),
    ]
    try:
        if runner is None:
            result = _run_info_limited(command)
        else:
            result = runner(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=20, check=False, shell=False,
            )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VirtualDiskError(f"Could not inspect the virtual disk: {error}") from error
    _unchanged(resolved_path, identity, "The selected virtual disk")
    _unchanged(tool.path, tool.identity, "qemu-img")
    stdout = result.stdout if isinstance(result.stdout, bytes) else str(result.stdout).encode()
    stderr = result.stderr if isinstance(result.stderr, bytes) else str(result.stderr).encode()
    if len(stdout) > MAX_INFO_JSON:
        raise VirtualDiskError("qemu-img returned an oversized JSON description")
    if result.returncode:
        message = stderr[-MAX_DIAGNOSTIC:].decode(errors="replace").strip()
        raise VirtualDiskError(message or "qemu-img could not inspect the virtual disk")
    try:
        payload = json.loads(stdout.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VirtualDiskError("qemu-img returned malformed JSON") from error
    if not isinstance(payload, dict):
        raise VirtualDiskError("qemu-img JSON description must be an object")

    image_format = payload.get("format")
    if not isinstance(image_format, str) or image_format not in SUPPORTED_FORMATS:
        shown = image_format if isinstance(image_format, str) else "unknown"
        raise VirtualDiskError(f"Unsupported virtual disk format: {shown}")
    virtual_size = _required_int(payload, "virtual-size")
    if virtual_size <= 0 or virtual_size > maximum_virtual_size:
        raise VirtualDiskError(
            f"Virtual disk size {virtual_size} is outside the allowed range"
        )
    if virtual_size % 512:
        raise VirtualDiskError("Virtual disk size is not aligned to a 512-byte sector")
    actual_raw = payload.get("actual-size")
    if actual_raw is None:
        actual_size = None
    elif isinstance(actual_raw, int) and not isinstance(actual_raw, bool) and actual_raw >= 0:
        actual_size = actual_raw
    else:
        raise VirtualDiskError("qemu-img JSON field 'actual-size' is invalid")
    snapshots = payload.get("snapshots", [])
    if not isinstance(snapshots, list):
        raise VirtualDiskError("qemu-img JSON field 'snapshots' must be a list")
    format_specific = payload.get("format-specific")
    if format_specific is not None:
        if not isinstance(format_specific, dict):
            raise VirtualDiskError("qemu-img format-specific metadata must be an object")
        declared_type = format_specific.get("type")
        if declared_type is not None and declared_type != image_format:
            raise VirtualDiskError("qemu-img returned conflicting virtual disk formats")
    restricted = _find_restricted_metadata(payload)
    if restricted:
        kind, field = restricted
        raise VirtualDiskError(
            f"Virtual disks with {kind} metadata are not accepted ({field})"
        )
    return VirtualDiskInfo(
        resolved_path, identity, tool, image_format, virtual_size,
        actual_size, bool(snapshots),
    )


def _append_bounded(buffer: bytearray, block: bytes) -> None:
    buffer.extend(block)
    if len(buffer) > MAX_DIAGNOSTIC:
        del buffer[:len(buffer) - MAX_DIAGNOSTIC]


def _cleanup_stage(directory: Path, output: Path) -> None:
    """Remove only the exact file and directory allocated by this module."""

    try:
        output.unlink(missing_ok=True)
    except OSError:
        pass
    try:
        directory.rmdir()
    except OSError:
        # Do not recursively delete unexpected entries, even in our temporary
        # directory. Leaving an anomalous private directory is safer than
        # broadening cleanup after an external process behaved unexpectedly.
        pass


class VirtualDiskStager:
    """Convert a bound virtual container into a private raw regular file."""

    def __init__(self, process_factory: ProcessFactory = subprocess.Popen) -> None:
        self._process_factory = process_factory
        self._process: ProcessLike | None = None
        self._cancelled = threading.Event()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        self._cancelled.set()
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()

    def _raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise VirtualConversionCancelled("Virtual disk conversion was cancelled")

    def stage(
        self,
        info: VirtualDiskInfo,
        progress: Progress = lambda _done, _total: None,
        *,
        temporary_root: Path | None = None,
        require_full_free_space: bool = True,
    ) -> StagedVirtualDisk:
        """Stage current virtual contents as raw; the caller must close the result.

        The conservative default reserves enough free space for a fully
        allocated raw image even though qemu-img normally creates sparse output.
        """

        self._raise_if_cancelled()
        _unchanged(info.path, info.identity, "The selected virtual disk")
        _unchanged(info.qemu_img.path, info.qemu_img.identity, "qemu-img")
        root = temporary_root or Path(tempfile.gettempdir())
        try:
            root = root.resolve(strict=True)
        except OSError as error:
            raise VirtualDiskError(f"The staging directory is unavailable: {error}") from error
        if not root.is_dir():
            raise VirtualDiskError("The staging root must be a directory")
        if require_full_free_space and shutil.disk_usage(root).free < info.virtual_size:
            raise VirtualDiskError(
                "There is not enough free space to safely stage the full virtual disk"
            )

        directory = Path(tempfile.mkdtemp(prefix="isopropyl-virtual-", dir=root))
        directory.chmod(0o700)
        output = directory / "staged.raw"
        stdout_tail = bytearray()
        stderr_tail = bytearray()
        reader_errors: list[BaseException] = []
        latest_done = 0
        progress_lock = threading.Lock()

        def read_stdout(stream: Any) -> None:
            nonlocal latest_done
            scan_tail = b""
            try:
                while block := stream.read(4096):
                    _append_bounded(stdout_tail, block)
                    searchable = scan_tail + block
                    for match in PROGRESS_PATTERN.finditer(searchable):
                        percentage = min(100.0, float(match.group(1)))
                        done = min(info.virtual_size, int(info.virtual_size * percentage / 100.0))
                        with progress_lock:
                            if done > latest_done:
                                latest_done = done
                                progress(done, info.virtual_size)
                    scan_tail = searchable[-128:]
            except BaseException as error:
                reader_errors.append(error)

        def read_stderr(stream: Any) -> None:
            try:
                while block := stream.read(4096):
                    _append_bounded(stderr_tail, block)
            except BaseException as error:
                reader_errors.append(error)

        try:
            command = [
                str(info.qemu_img.path), "convert", "--progress", "--source-format",
                info.format, "--source-cache", "none", "--target-format", "raw",
                "--sparse-size", "4k",
                str(info.path), str(output),
            ]
            self._process = self._process_factory(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, shell=False,
            )
            if self._process.stdout is None or self._process.stderr is None:
                raise VirtualDiskError("qemu-img conversion pipes were not available")
            stdout_thread = threading.Thread(
                target=read_stdout, args=(self._process.stdout,), daemon=True
            )
            stderr_thread = threading.Thread(
                target=read_stderr, args=(self._process.stderr,), daemon=True
            )
            stdout_thread.start()
            stderr_thread.start()
            while self._process.poll() is None:
                if self.cancelled:
                    self._process.terminate()
                    try:
                        self._process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self._process.kill()
                    break
                time.sleep(0.05)
            code = self._process.wait()
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            if stdout_thread.is_alive() or stderr_thread.is_alive():
                raise VirtualDiskError("qemu-img output pipes did not close")
            self._raise_if_cancelled()
            if reader_errors:
                raise VirtualDiskError(f"Could not read qemu-img output: {reader_errors[0]}")
            if code:
                message = bytes(stderr_tail).decode(errors="replace").strip()
                raise VirtualDiskError(message or "qemu-img could not convert the virtual disk")
            _unchanged(info.path, info.identity, "The selected virtual disk")
            _unchanged(info.qemu_img.path, info.qemu_img.identity, "qemu-img")
            try:
                status = output.lstat()
            except OSError as error:
                raise VirtualDiskError(f"qemu-img did not create raw staging output: {error}") from error
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                raise VirtualDiskError("qemu-img staging output is not a private regular file")
            if status.st_size != info.virtual_size:
                raise VirtualDiskError(
                    f"Converted raw image has {status.st_size} bytes; expected {info.virtual_size}"
                )
            output.chmod(0o600)
            with output.open("rb", buffering=0) as stream:
                os.fsync(stream.fileno())
            with progress_lock:
                if latest_done < info.virtual_size:
                    progress(info.virtual_size, info.virtual_size)
            return StagedVirtualDisk(
                output, info.virtual_size, status.st_blocks * 512, info.format,
                info.identity, directory,
            )
        except BaseException:
            if self._process is not None and self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait()
            _cleanup_stage(directory, output)
            raise
        finally:
            self._process = None
