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

from .sources import (
    ImageSourceError, SourceChanged, SourceIdentity, open_image_source,
)

SUPPORTED_FORMATS = frozenset({"vpc", "vhdx", "qcow", "qcow2"})
MAX_INFO_JSON = 256 * 1024
MAX_DIAGNOSTIC = 64 * 1024
MAX_VIRTUAL_SIZE = 64 * 1024**4
MAX_COMPRESSED_VIRTUAL_BYTES = 64 * 1024**3
COMPRESSED_VIRTUAL_FREE_RESERVE_BYTES = 64 * 1024**2
VIRTUAL_STAGING_FREE_RESERVE_BYTES = 64 * 1024**2
DEFAULT_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
PROGRESS_PATTERN = re.compile(rb"\(([0-9]+(?:\.[0-9]+)?)/100%\)")
VIRTUAL_SUFFIX_FORMATS = {
    ".vhd": "vpc",
    ".vhdx": "vhdx",
    ".qcow": "qcow",
    ".qcow2": "qcow2",
}

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


@dataclass
class PreparedCompressedVirtualDisk:
    """A private decoded virtual container bound to its original source."""

    path: Path
    info: VirtualDiskInfo
    original_identity: SourceIdentity
    compression: str
    decoded_size: int
    _directory: Path
    _descriptor: int
    _closed: bool = False

    def close(self) -> None:
        if self._closed:
            return
        try:
            os.close(self._descriptor)
        finally:
            _cleanup_stage(self._directory, self.path)
            self._closed = True

    def __enter__(self) -> PreparedCompressedVirtualDisk:
        if self._closed:
            raise VirtualDiskError(
                "The prepared compressed virtual disk has already been cleaned up"
            )
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def _identity_from_status(status: os.stat_result, label: str) -> FileIdentity:
    if not stat.S_ISREG(status.st_mode):
        raise VirtualDiskError(f"{label} must be a regular file")
    return FileIdentity(
        status.st_dev, status.st_ino, status.st_size,
        status.st_mtime_ns, status.st_ctime_ns,
    )


def _file_identity(path: Path, label: str) -> FileIdentity:
    try:
        status = path.stat()
    except OSError as error:
        raise VirtualDiskError(f"{label} is not available: {error}") from error
    return _identity_from_status(status, label)


def _descriptor_identity(descriptor: int, label: str) -> FileIdentity:
    try:
        status = os.fstat(descriptor)
    except OSError as error:
        raise VirtualDiskChanged(f"{label} descriptor is unavailable") from error
    return _identity_from_status(status, label)


def _require_descriptor_identity(
    descriptor: int,
    expected: FileIdentity,
    label: str,
) -> None:
    if _descriptor_identity(descriptor, label) != expected:
        raise VirtualDiskChanged(f"{label} changed while it was being prepared")


def _open_bound_source(path: Path, label: str) -> tuple[Path, int, FileIdentity]:
    try:
        normalized = Path(os.path.abspath(os.fspath(path)))
    except (TypeError, ValueError, OSError) as error:
        raise VirtualDiskError(f"{label} path is invalid") from error
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(normalized, flags)
    except OSError as error:
        raise VirtualDiskError(f"{label} could not be opened safely: {error}") from error
    try:
        identity = _descriptor_identity(descriptor, label)
    except BaseException:
        os.close(descriptor)
        raise
    return normalized, descriptor, identity


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


def _stop_process(process: ProcessLike) -> None:
    """Best-effort bounded termination followed by reaping."""

    try:
        if process.poll() is None:
            process.terminate()
    except OSError:
        pass
    try:
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _run_info_limited(
    command: list[str],
    descriptor: int,
    cancel_check: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run trusted qemu-img while bounding both output retained and runtime."""

    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, shell=False, pass_fds=(descriptor,),
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
            if cancel_check is not None:
                cancel_check()
            if time.monotonic() >= deadline:
                _stop_process(process)
                raise subprocess.TimeoutExpired(command, 20)
            time.sleep(0.02)
        code = process.wait()
    finally:
        if process.poll() is None:
            _stop_process(process)
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


def _parse_virtual_info(
    path: Path,
    identity: FileIdentity,
    tool: ToolIdentity,
    result: subprocess.CompletedProcess[bytes],
    maximum_virtual_size: int,
) -> VirtualDiskInfo:
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
        path, identity, tool, image_format, virtual_size,
        actual_size, bool(snapshots),
    )


def _inspect_virtual_disk_descriptor(
    descriptor: int,
    path: Path,
    identity: FileIdentity,
    tool: ToolIdentity,
    *,
    runner: RunCommand | None,
    maximum_virtual_size: int,
    cancel_check: Callable[[], None] | None,
) -> VirtualDiskInfo:
    cancel_failure: BaseException | None = None

    def check_cancelled() -> None:
        nonlocal cancel_failure
        if cancel_check is None:
            return
        try:
            cancel_check()
        except BaseException as error:
            cancel_failure = error
            raise

    check_cancelled()
    _require_descriptor_identity(descriptor, identity, "The selected virtual disk")
    _unchanged(path, identity, "The selected virtual disk")
    _unchanged(tool.path, tool.identity, "qemu-img")
    source = f"/proc/self/fd/{descriptor}"
    try:
        if _file_identity(Path(source), "The selected virtual disk") != identity:
            raise VirtualDiskChanged(
                "The inherited virtual-disk descriptor identity is inconsistent"
            )
        command = [str(tool.path), "info", "--output=json", source]
        if runner is None:
            result = _run_info_limited(command, descriptor, check_cancelled)
        else:
            result = runner(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=20, check=False, shell=False,
                pass_fds=(descriptor,),
            )
    except (OSError, subprocess.TimeoutExpired) as error:
        if error is cancel_failure:
            raise
        raise VirtualDiskError(f"Could not inspect the virtual disk: {error}") from error
    check_cancelled()
    _require_descriptor_identity(descriptor, identity, "The selected virtual disk")
    _unchanged(path, identity, "The selected virtual disk")
    _unchanged(tool.path, tool.identity, "qemu-img")
    info = _parse_virtual_info(
        path, identity, tool, result, maximum_virtual_size,
    )
    check_cancelled()
    _require_descriptor_identity(descriptor, identity, "The selected virtual disk")
    _unchanged(path, identity, "The selected virtual disk")
    _unchanged(tool.path, tool.identity, "qemu-img")
    return info


def inspect_virtual_disk(
    path: Path,
    *,
    qemu_img: Path | None = None,
    runner: RunCommand | None = None,
    maximum_virtual_size: int = MAX_VIRTUAL_SIZE,
    cancel_check: Callable[[], None] | None = None,
) -> VirtualDiskInfo:
    """Inspect one no-follow descriptor and never give qemu its pathname."""

    if not 0 < maximum_virtual_size <= MAX_VIRTUAL_SIZE:
        raise ValueError(
            f"maximum_virtual_size must be between 1 and {MAX_VIRTUAL_SIZE}"
        )
    if cancel_check is not None:
        cancel_check()
    normalized, descriptor, identity = _open_bound_source(
        path, "The selected virtual disk",
    )
    try:
        if identity.size == 0:
            raise VirtualDiskError("The selected virtual disk is empty")
        tool = resolve_qemu_img(qemu_img)
        return _inspect_virtual_disk_descriptor(
            descriptor, normalized, identity, tool, runner=runner,
            maximum_virtual_size=maximum_virtual_size,
            cancel_check=cancel_check,
        )
    finally:
        os.close(descriptor)


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


def _source_identity_values(identity: SourceIdentity) -> tuple[int, int, int, int, int]:
    return (
        identity.device,
        identity.inode,
        identity.size,
        identity.modified_ns,
        identity.changed_ns,
    )


def _expected_source_identity_values(
    expected: SourceIdentity | tuple[int, int, int, int, int],
) -> tuple[int, int, int, int, int]:
    if type(expected) is SourceIdentity:
        values = _source_identity_values(expected)
    elif type(expected) is tuple and len(expected) == 5:
        values = expected
    else:
        raise ValueError(
            "expected_identity must be a SourceIdentity or exact five-integer tuple"
        )
    if any(type(value) is not int for value in values):
        raise ValueError(
            "expected_identity must be a SourceIdentity or exact five-integer tuple"
        )
    return values


def _write_all(descriptor: int, payload: bytes) -> None:
    position = 0
    while position < len(payload):
        try:
            written = os.write(descriptor, payload[position:])
        except OSError as error:
            raise VirtualDiskError(
                f"Could not stage the decoded virtual container: {error}"
            ) from error
        if written <= 0:
            raise VirtualDiskError("Could not stage the decoded virtual container")
        position += written


class CompressedVirtualDiskPreparer:
    """Decode one compression wrapper into a private, inspected container."""

    def __init__(
        self,
        *,
        qemu_img: Path | None = None,
        info_runner: RunCommand | None = None,
    ) -> None:
        self._qemu_img = qemu_img
        self._info_runner = info_runner
        self._cancelled = threading.Event()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        self._cancelled.set()

    def _check_cancelled(
        self,
        cancel_check: Callable[[], None] | None,
    ) -> None:
        if self.cancelled:
            raise VirtualConversionCancelled(
                "Compressed virtual-disk preparation was cancelled"
            )
        if cancel_check is not None:
            cancel_check()

    def prepare(
        self,
        path: Path,
        *,
        expected_identity: SourceIdentity | tuple[int, int, int, int, int] | None = None,
        expected_format: str | None = None,
        expected_virtual_size: int | None = None,
        temporary_root: Path | None = None,
        maximum_decoded_size: int = MAX_COMPRESSED_VIRTUAL_BYTES,
        maximum_virtual_size: int = MAX_VIRTUAL_SIZE,
        cancel_check: Callable[[], None] | None = None,
    ) -> PreparedCompressedVirtualDisk:
        """Decode, fsync, inspect, and return one closeable private stage."""

        if (
            type(maximum_decoded_size) is not int
            or not 1 <= maximum_decoded_size <= MAX_COMPRESSED_VIRTUAL_BYTES
        ):
            raise ValueError(
                "maximum_decoded_size must be between 1 and "
                f"{MAX_COMPRESSED_VIRTUAL_BYTES}"
            )
        if (
            type(maximum_virtual_size) is not int
            or not 1 <= maximum_virtual_size <= MAX_VIRTUAL_SIZE
        ):
            raise ValueError(
                f"maximum_virtual_size must be between 1 and {MAX_VIRTUAL_SIZE}"
            )
        if expected_format is not None and (
            type(expected_format) is not str or expected_format not in SUPPORTED_FORMATS
        ):
            raise ValueError("expected_format is not a supported qemu format code")
        if expected_virtual_size is not None and (
            type(expected_virtual_size) is not int
            or expected_virtual_size <= 0
            or expected_virtual_size > MAX_VIRTUAL_SIZE
            or expected_virtual_size % 512
        ):
            raise ValueError("expected_virtual_size is invalid")
        expected_values = (
            _expected_source_identity_values(expected_identity)
            if expected_identity is not None else None
        )
        cancel_failure: BaseException | None = None

        def check_cancelled() -> None:
            nonlocal cancel_failure
            if self.cancelled:
                raise VirtualConversionCancelled(
                    "Compressed virtual-disk preparation was cancelled"
                )
            if cancel_check is None:
                return
            try:
                cancel_check()
            except BaseException as error:
                cancel_failure = error
                raise

        check_cancelled()

        root = temporary_root or Path(tempfile.gettempdir())
        try:
            root = root.resolve(strict=True)
        except OSError as error:
            raise VirtualDiskError(
                f"The staging directory is unavailable: {error}"
            ) from error
        if not root.is_dir():
            raise VirtualDiskError("The staging root must be a directory")
        if shutil.disk_usage(root).free <= COMPRESSED_VIRTUAL_FREE_RESERVE_BYTES:
            raise VirtualDiskError(
                "There is not enough free space to preserve the compressed-virtual "
                "staging reserve"
            )

        source = None
        directory: Path | None = None
        output: Path | None = None
        descriptor = -1
        try:
            source = open_image_source(path, cancel_check=check_cancelled)
            if not source.compressed:
                raise VirtualDiskError(
                    "Compressed virtual-disk preparation requires exactly one wrapper"
                )
            original_identity = source.identity
            if (
                expected_values is not None
                and _source_identity_values(original_identity) != expected_values
            ):
                raise VirtualDiskChanged(
                    "The compressed virtual disk changed after confirmation"
                )
            decoded_name = source.decoded_name(
                cancel_check=check_cancelled,
            )
            if type(decoded_name) is not str or not decoded_name or "\x00" in decoded_name:
                raise VirtualDiskError("The decoded virtual-disk name is invalid")
            suffix = Path(decoded_name).suffix.casefold()
            required_format = VIRTUAL_SUFFIX_FORMATS.get(suffix)
            if required_format is None:
                raise VirtualDiskError(
                    "The compressed source does not contain a supported virtual disk"
                )

            directory = Path(tempfile.mkdtemp(
                prefix="isopropyl-compressed-virtual-", dir=root,
            ))
            directory.chmod(0o700)
            output = directory / f"decoded{suffix}"
            flags = (
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(output, flags, 0o600)
            os.fchmod(descriptor, 0o600)
            decoded_size = 0
            for block in source.chunks(
                cancel_check=check_cancelled,
            ):
                check_cancelled()
                if len(block) > maximum_decoded_size - decoded_size:
                    raise VirtualDiskError(
                        "The decoded virtual container exceeds the configured "
                        "safety cap (at most 64 GiB)"
                    )
                if (
                    shutil.disk_usage(root).free
                    < len(block) + COMPRESSED_VIRTUAL_FREE_RESERVE_BYTES
                ):
                    raise VirtualDiskError(
                        "Decoding would consume the compressed-virtual free-space reserve"
                    )
                _write_all(descriptor, block)
                decoded_size += len(block)
                check_cancelled()
            if decoded_size == 0:
                raise VirtualDiskError("The decoded virtual container is empty")
            os.fsync(descriptor)
            check_cancelled()
            status = os.fstat(descriptor)
            if (
                not stat.S_ISREG(status.st_mode)
                or status.st_nlink != 1
                or stat.S_IMODE(status.st_mode) != 0o600
                or status.st_size != decoded_size
            ):
                raise VirtualDiskError(
                    "The decoded virtual container is not a private exact regular file"
                )
            decoded_identity = _identity_from_status(
                status, "The decoded virtual container",
            )
            os.close(descriptor)
            descriptor = -1
            descriptor = os.open(
                output,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            _require_descriptor_identity(
                descriptor, decoded_identity, "The decoded virtual container",
            )
            tool = resolve_qemu_img(self._qemu_img)
            info = _inspect_virtual_disk_descriptor(
                descriptor, output, decoded_identity, tool,
                runner=self._info_runner,
                maximum_virtual_size=maximum_virtual_size,
                cancel_check=check_cancelled,
            )
            final_status = os.fstat(descriptor)
            try:
                final_path_status = output.lstat()
            except OSError as error:
                raise VirtualDiskChanged(
                    "The decoded virtual container disappeared during inspection"
                ) from error
            if (
                _identity_from_status(
                    final_status, "The decoded virtual container",
                ) != decoded_identity
                or final_status.st_nlink != 1
                or stat.S_IMODE(final_status.st_mode) != 0o600
                or final_status.st_size != decoded_size
                or final_path_status.st_dev != final_status.st_dev
                or final_path_status.st_ino != final_status.st_ino
                or final_path_status.st_nlink != 1
            ):
                raise VirtualDiskChanged(
                    "The decoded virtual container changed during inspection"
                )
            source.fileno()
            if info.format != required_format:
                raise VirtualDiskError(
                    f"The decoded {suffix} name does not match qemu format {info.format}"
                )
            if expected_format is not None and info.format != expected_format:
                raise VirtualDiskChanged(
                    "The decoded virtual-disk format changed after confirmation"
                )
            if (
                expected_virtual_size is not None
                and info.virtual_size != expected_virtual_size
            ):
                raise VirtualDiskChanged(
                    "The decoded virtual-disk size changed after confirmation"
                )
            check_cancelled()
            prepared = PreparedCompressedVirtualDisk(
                output,
                info,
                original_identity,
                source.compression,
                decoded_size,
                directory,
                descriptor,
            )
            descriptor = -1
            directory = None
            output = None
            return prepared
        except SourceChanged as error:
            if error is cancel_failure:
                raise
            raise VirtualDiskChanged(str(error)) from error
        except ImageSourceError as error:
            if error is cancel_failure:
                raise
            raise VirtualDiskError(str(error)) from error
        finally:
            if source is not None:
                source.close()
            if descriptor >= 0:
                os.close(descriptor)
            if directory is not None and output is not None:
                _cleanup_stage(directory, output)


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
        if require_full_free_space:
            free = shutil.disk_usage(root).free
            if (
                free <= VIRTUAL_STAGING_FREE_RESERVE_BYTES
                or info.virtual_size
                > free - VIRTUAL_STAGING_FREE_RESERVE_BYTES
            ):
                raise VirtualDiskError(
                    "There is not enough free space to stage the full virtual "
                    "disk while preserving the safety reserve"
                )

        directory = Path(tempfile.mkdtemp(prefix="isopropyl-virtual-", dir=root))
        directory.chmod(0o700)
        output = directory / "staged.raw"
        stdout_tail = bytearray()
        stderr_tail = bytearray()
        reader_errors: list[BaseException] = []
        latest_done = 0
        progress_lock = threading.Lock()
        source_descriptor = -1

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
            bound_path, source_descriptor, current_identity = _open_bound_source(
                info.path, "The selected virtual disk",
            )
            if bound_path != info.path or current_identity != info.identity:
                raise VirtualDiskChanged(
                    "The selected virtual disk changed before conversion"
                )
            _require_descriptor_identity(
                source_descriptor, info.identity, "The selected virtual disk",
            )
            _unchanged(info.qemu_img.path, info.qemu_img.identity, "qemu-img")
            source = f"/proc/self/fd/{source_descriptor}"
            if _file_identity(Path(source), "The selected virtual disk") != info.identity:
                raise VirtualDiskChanged(
                    "The inherited virtual-disk descriptor identity is inconsistent"
                )
            command = [
                str(info.qemu_img.path), "convert", "--progress", "--source-format",
                info.format, "--source-cache", "none", "--target-format", "raw",
                "--sparse-size", "4k",
                source, str(output),
            ]
            self._process = self._process_factory(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, shell=False,
                pass_fds=(source_descriptor,),
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
            if (
                require_full_free_space
                and shutil.disk_usage(root).free
                < VIRTUAL_STAGING_FREE_RESERVE_BYTES
            ):
                raise VirtualDiskError(
                    "Virtual-disk conversion consumed the staging safety reserve"
                )
            _require_descriptor_identity(
                source_descriptor, info.identity, "The selected virtual disk",
            )
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
            if source_descriptor >= 0:
                os.close(source_descriptor)
