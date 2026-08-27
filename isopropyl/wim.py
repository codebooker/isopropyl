# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import io
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

FAT32_MAX_FILE_SIZE = (4 * 1024 * 1024 * 1024) - 1
MIB = 1024 * 1024
DEFAULT_SPLIT_PART_MIB = 3800
MAX_SPLIT_PART_MIB = FAT32_MAX_FILE_SIZE // MIB
MAX_INFO_OUTPUT = 4 * MIB
MAX_COMMAND_OUTPUT = MIB
MAX_IMAGES = 128
MAX_XML_ELEMENTS = 20_000
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_TRUSTED_TOOL_DIRECTORIES = frozenset(_TRUSTED_TOOL_PATH.split(":"))
_PART_NAME = re.compile(r"install(?:(?P<number>[2-9][0-9]*))?\.swm", re.IGNORECASE)


class WimError(RuntimeError):
    """Base class for WIM/ESD backend failures."""


class WimToolUnavailable(WimError):
    pass


class WimValidationError(WimError, ValueError):
    pass


class WimMetadataError(WimError):
    pass


class WimCommandError(WimError):
    pass


class WimCancelled(WimError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class WimEdition:
    index: int
    name: str
    description: str
    edition_id: str
    architecture: str
    major_version: int
    minor_version: int
    build: int
    service_pack_build: int


@dataclass(frozen=True)
class WimInfo:
    path: str
    size: int
    editions: tuple[WimEdition, ...]


FileIdentity = tuple[int, int, int, int]


@dataclass(frozen=True)
class WimSplitPlan:
    source: str
    source_identity: FileIdentity
    destination_directory: str
    part_size_mib: int
    wimlib_imagex: str

    @property
    def command_part_size(self) -> str:
        return str(self.part_size_mib)


@dataclass(frozen=True)
class WimSplitResult:
    directory: str
    parts: tuple[str, ...]
    total_size: int


CommandRunner = Callable[..., CommandResult]
StageCallback = Callable[[str], None]


def _trusted_which(name: str) -> str | None:
    return shutil.which(name, path=_TRUSTED_TOOL_PATH)


def _validate_wimlib_path(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise WimToolUnavailable("wimlib-imagex was not found in a trusted system directory")
    normalized = os.path.normpath(value)
    if (
        not os.path.isabs(value)
        or normalized != value
        or os.path.dirname(value) not in _TRUSTED_TOOL_DIRECTORIES
        or os.path.basename(value) != "wimlib-imagex"
    ):
        raise WimToolUnavailable(f"Refusing untrusted wimlib-imagex path: {value!r}")
    return value


def resolve_wimlib(
    which: Callable[[str], str | None] = _trusted_which,
) -> str:
    return _validate_wimlib_path(which("wimlib-imagex") or "")


def _regular_file(path: str | os.PathLike[str]) -> tuple[Path, os.stat_result]:
    try:
        resolved = Path(path).expanduser().resolve(strict=True)
        status = resolved.stat()
    except (OSError, RuntimeError) as error:
        raise WimValidationError(f"WIM/ESD source is unavailable: {path}") from error
    if not stat.S_ISREG(status.st_mode):
        raise WimValidationError("The WIM/ESD source must be a regular file")
    if status.st_size <= 0:
        raise WimValidationError("The WIM/ESD source is empty")
    return resolved, status


def _identity(status: os.stat_result) -> FileIdentity:
    return status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns


def _bounded_reader(
    stream: io.BufferedReader,
    sink: bytearray,
    limit: int,
    overflow: threading.Event,
) -> None:
    try:
        while True:
            block = stream.read(64 * 1024)
            if not block:
                return
            remaining = max(0, limit + 1 - len(sink))
            if remaining:
                sink.extend(block[:remaining])
            if len(sink) > limit:
                overflow.set()
    finally:
        stream.close()


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def run_bounded_command(
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    max_output: int,
    cancel_event: threading.Event | None = None,
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    process_started: Callable[[subprocess.Popen[bytes]], None] | None = None,
) -> CommandResult:
    """Run fixed argv without a shell while bounding time and captured output."""

    if not argv or any(not isinstance(argument, str) for argument in argv):
        raise WimValidationError("A non-empty text argv is required")
    if timeout_seconds <= 0 or timeout_seconds > 24 * 60 * 60:
        raise WimValidationError("Command timeout must be between 0 and 86400 seconds")
    if max_output <= 0 or max_output > 16 * MIB:
        raise WimValidationError("Command output bound must be between 1 byte and 16 MiB")
    if cancel_event is not None and cancel_event.is_set():
        raise WimCancelled("WIM operation was cancelled")

    try:
        process = popen(
            list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, shell=False,
        )
    except OSError as error:
        raise WimCommandError("Could not start wimlib-imagex") from error
    if process_started is not None:
        try:
            process_started(process)
        except Exception:
            _stop_process(process)
            raise
    if process.stdout is None or process.stderr is None:
        _stop_process(process)
        raise WimCommandError("Could not capture wimlib-imagex output")

    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    readers = (
        threading.Thread(
            target=_bounded_reader,
            args=(process.stdout, stdout, max_output, overflow),
            daemon=True,
        ),
        threading.Thread(
            target=_bounded_reader,
            args=(process.stderr, stderr, max_output, overflow),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + timeout_seconds
    failure: WimError | None = None
    while process.poll() is None:
        if cancel_event is not None and cancel_event.is_set():
            failure = WimCancelled("WIM operation was cancelled")
            break
        if overflow.is_set():
            failure = WimCommandError("wimlib-imagex produced too much output")
            break
        if time.monotonic() >= deadline:
            failure = WimCommandError("wimlib-imagex timed out")
            break
        time.sleep(0.01)

    if failure is not None:
        _stop_process(process)
    for reader in readers:
        reader.join(timeout=2)
    if any(reader.is_alive() for reader in readers):
        _stop_process(process)
        raise WimCommandError("Could not finish reading wimlib-imagex output")
    if overflow.is_set() and failure is None:
        failure = WimCommandError("wimlib-imagex produced too much output")
    if cancel_event is not None and cancel_event.is_set():
        failure = WimCancelled("WIM operation was cancelled")
    if failure is not None:
        raise failure
    return CommandResult(process.returncode or 0, bytes(stdout), bytes(stderr))


def _error_text(payload: bytes) -> str:
    text = payload.decode("utf-8", errors="replace").replace("\x00", "").strip()
    return text[:1000]


def _child(parent: ET.Element, name: str) -> ET.Element | None:
    for item in parent:
        if item.tag.rsplit("}", 1)[-1].upper() == name:
            return item
    return None


def _required_text(parent: ET.Element, name: str, context: str) -> str:
    item = _child(parent, name)
    value = "" if item is None or item.text is None else item.text.strip()
    if not value or len(value) > 1024:
        raise WimMetadataError(f"Missing or invalid {context} {name}")
    return value


def _optional_text(parent: ET.Element, name: str) -> str:
    item = _child(parent, name)
    if item is None or item.text is None:
        return ""
    value = item.text.strip()
    if len(value) > 1024:
        raise WimMetadataError(f"WIM metadata field {name} is too long")
    return value


def _integer(parent: ET.Element, name: str, context: str, *, minimum: int = 0) -> int:
    value = _required_text(parent, name, context)
    if not value.isascii() or not value.isdecimal():
        raise WimMetadataError(f"Invalid numeric {context} {name}")
    parsed = int(value)
    if parsed < minimum or parsed > 2_147_483_647:
        raise WimMetadataError(f"Out-of-range {context} {name}")
    return parsed


def _optional_integer(parent: ET.Element, name: str, context: str) -> int:
    item = _child(parent, name)
    if item is None or item.text is None or not item.text.strip():
        return 0
    value = item.text.strip()
    if not value.isascii() or not value.isdecimal():
        raise WimMetadataError(f"Invalid numeric {context} {name}")
    parsed = int(value)
    if parsed > 2_147_483_647:
        raise WimMetadataError(f"Out-of-range {context} {name}")
    return parsed


_ARCHITECTURES = {
    0: "x86",
    5: "arm",
    6: "ia64",
    9: "amd64",
    12: "arm64",
}


def parse_wim_info_xml(payload: bytes | str) -> tuple[WimEdition, ...]:
    if isinstance(payload, str):
        encoded = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        encoded = payload
    else:
        raise WimMetadataError("wimlib-imagex returned non-text metadata")
    if not encoded or len(encoded) > MAX_INFO_OUTPUT:
        raise WimMetadataError("wimlib-imagex XML metadata is empty or too large")
    try:
        if encoded.startswith(b"\xff\xfe") or encoded.startswith(b"<\x00"):
            security_text = encoded.decode("utf-16-le")
        elif encoded.startswith(b"\xfe\xff") or encoded.startswith(b"\x00<"):
            security_text = encoded.decode("utf-16-be")
        else:
            security_text = encoded.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise WimMetadataError("wimlib-imagex returned invalid XML text encoding") from error
    upper = security_text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise WimMetadataError("DTD and entity declarations are not allowed in WIM metadata")
    try:
        root = ET.fromstring(encoded)
    except (ET.ParseError, ValueError) as error:
        raise WimMetadataError("wimlib-imagex returned malformed XML") from error
    if root.tag.rsplit("}", 1)[-1].upper() != "WIM":
        raise WimMetadataError("wimlib-imagex XML has an unexpected root element")
    if sum(1 for _ in root.iter()) > MAX_XML_ELEMENTS:
        raise WimMetadataError("wimlib-imagex XML contains too many elements")

    image_elements = [
        item for item in root
        if item.tag.rsplit("}", 1)[-1].upper() == "IMAGE"
    ]
    if not image_elements or len(image_elements) > MAX_IMAGES:
        raise WimMetadataError("WIM metadata contains no images or too many images")

    editions: list[WimEdition] = []
    indexes: set[int] = set()
    for image in image_elements:
        raw_index = image.attrib.get("INDEX", "")
        if not raw_index.isascii() or not raw_index.isdecimal():
            raise WimMetadataError("WIM image has an invalid index")
        index = int(raw_index)
        if index <= 0 or index in indexes:
            raise WimMetadataError("WIM image indexes must be positive and unique")
        indexes.add(index)
        windows = _child(image, "WINDOWS")
        if windows is None:
            raise WimMetadataError(f"WIM image {index} has no Windows metadata")
        architecture_id = _integer(windows, "ARCH", f"image {index}")
        architecture = _ARCHITECTURES.get(architecture_id)
        if architecture is None:
            raise WimMetadataError(
                f"WIM image {index} has unsupported architecture {architecture_id}"
            )
        version = _child(windows, "VERSION")
        if version is None:
            raise WimMetadataError(f"WIM image {index} has no Windows version")
        editions.append(WimEdition(
            index=index,
            name=_optional_text(image, "NAME"),
            description=_optional_text(image, "DESCRIPTION"),
            edition_id=_required_text(windows, "EDITIONID", f"image {index}"),
            architecture=architecture,
            major_version=_integer(version, "MAJOR", f"image {index} version"),
            minor_version=_integer(version, "MINOR", f"image {index} version"),
            build=_integer(version, "BUILD", f"image {index} version", minimum=1),
            service_pack_build=_optional_integer(version, "SPBUILD", f"image {index} version"),
        ))
    return tuple(sorted(editions, key=lambda item: item.index))


def inspect_wim(
    path: str | os.PathLike[str],
    *,
    which: Callable[[str], str | None] = _trusted_which,
    runner: CommandRunner = run_bounded_command,
    timeout_seconds: float = 20,
) -> WimInfo:
    source, status = _regular_file(path)
    tool = resolve_wimlib(which)
    result = runner(
        [tool, "info", str(source), "--xml"],
        timeout_seconds=timeout_seconds,
        max_output=MAX_INFO_OUTPUT,
    )
    if len(result.stdout) > MAX_INFO_OUTPUT or len(result.stderr) > MAX_INFO_OUTPUT:
        raise WimCommandError("wimlib-imagex produced too much output")
    if result.returncode:
        detail = _error_text(result.stderr)
        raise WimCommandError(detail or "wimlib-imagex could not inspect the image")
    editions = parse_wim_info_xml(result.stdout)
    return WimInfo(str(source), status.st_size, editions)


def requires_fat32_split(size: int) -> bool:
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise WimValidationError("Image size must be a non-negative integer")
    return size > FAT32_MAX_FILE_SIZE


def _destination_path(path: str | os.PathLike[str]) -> Path:
    raw = Path(path).expanduser()
    if raw.name in {"", ".", ".."}:
        raise WimValidationError("A dedicated split-output directory is required")
    try:
        parent = raw.parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise WimValidationError("The split-output parent directory is unavailable") from error
    if not parent.is_dir():
        raise WimValidationError("The split-output parent must be a directory")
    destination = parent / raw.name
    if destination.exists() or destination.is_symlink():
        raise WimValidationError("The split-output directory must not already exist")
    return destination


def create_split_plan(
    source: str | os.PathLike[str],
    destination_directory: str | os.PathLike[str],
    *,
    part_size_mib: int = DEFAULT_SPLIT_PART_MIB,
    which: Callable[[str], str | None] = _trusted_which,
) -> WimSplitPlan:
    source_path, status = _regular_file(source)
    if source_path.name.casefold() != "install.wim":
        raise WimValidationError("Only an install.wim is eligible for FAT32 splitting")
    if not requires_fat32_split(status.st_size):
        raise WimValidationError("install.wim fits on FAT32 and does not require splitting")
    if (
        not isinstance(part_size_mib, int) or isinstance(part_size_mib, bool)
        or not 1 <= part_size_mib <= MAX_SPLIT_PART_MIB
    ):
        raise WimValidationError(
            f"Split part size must be between 1 and {MAX_SPLIT_PART_MIB} MiB"
        )
    destination = _destination_path(destination_directory)
    return WimSplitPlan(
        source=str(source_path), source_identity=_identity(status),
        destination_directory=str(destination), part_size_mib=part_size_mib,
        wimlib_imagex=resolve_wimlib(which),
    )


def validate_split_plan(plan: WimSplitPlan) -> None:
    if not isinstance(plan, WimSplitPlan):
        raise WimValidationError("A WimSplitPlan is required")
    _validate_wimlib_path(plan.wimlib_imagex)
    if Path(plan.source).name.casefold() != "install.wim" or not os.path.isabs(plan.source):
        raise WimValidationError("Split plan contains an invalid source")
    if not os.path.isabs(plan.destination_directory):
        raise WimValidationError("Split plan contains a relative destination")
    if (
        not isinstance(plan.part_size_mib, int) or isinstance(plan.part_size_mib, bool)
        or not 1 <= plan.part_size_mib <= MAX_SPLIT_PART_MIB
    ):
        raise WimValidationError("Split plan contains an invalid part size")
    if (
        not isinstance(plan.source_identity, tuple) or len(plan.source_identity) != 4
        or any(not isinstance(value, int) for value in plan.source_identity)
    ):
        raise WimValidationError("Split plan contains an invalid source identity")


def split_command(plan: WimSplitPlan, staged_first_part: Path) -> list[str]:
    validate_split_plan(plan)
    if staged_first_part.name.casefold() != "install.swm" or not staged_first_part.is_absolute():
        raise WimValidationError("The staged first split part must be an absolute install.swm path")
    return [
        plan.wimlib_imagex, "split", plan.source, str(staged_first_part),
        plan.command_part_size, "--check",
    ]


def _part_number(path: Path) -> int:
    match = _PART_NAME.fullmatch(path.name)
    if match is None:
        raise WimCommandError(f"wimlib-imagex created an unexpected file: {path.name}")
    number = match.group("number")
    return 1 if number is None else int(number)


def _validate_staged_parts(directory: Path) -> tuple[tuple[Path, ...], int]:
    entries = list(directory.iterdir())
    if not entries:
        raise WimCommandError("wimlib-imagex did not create any split parts")
    numbered: list[tuple[int, Path]] = []
    total = 0
    for entry in entries:
        status = entry.lstat()
        if not stat.S_ISREG(status.st_mode):
            raise WimCommandError("wimlib-imagex created a non-regular split output")
        number = _part_number(entry)
        if status.st_size <= 0 or status.st_size > FAT32_MAX_FILE_SIZE:
            raise WimCommandError(f"Split part {entry.name} is empty or too large for FAT32")
        numbered.append((number, entry))
        total += status.st_size
    numbered.sort(key=lambda item: item[0])
    actual = [number for number, _ in numbered]
    expected = list(range(1, len(numbered) + 1))
    if actual != expected or len(numbered) < 2:
        raise WimCommandError("wimlib-imagex created an incomplete split-part sequence")
    return tuple(path for _, path in numbered), total


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class WimSplitExecutor:
    """Create a complete SWM set in a new directory with one atomic commit."""

    def __init__(
        self,
        *,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        timeout_seconds: float = 2 * 60 * 60,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 24 * 60 * 60:
            raise WimValidationError("Split timeout must be between 0 and 86400 seconds")
        self._popen = popen
        self._timeout_seconds = timeout_seconds
        self._cancelled = threading.Event()
        self._process: subprocess.Popen[bytes] | None = None
        self._used = False
        self._lock = threading.Lock()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        self._cancelled.set()
        with self._lock:
            process = self._process
        if process is not None:
            _stop_process(process)

    def _process_started(self, process: subprocess.Popen[bytes]) -> None:
        with self._lock:
            self._process = process

    def _check_cancelled(self) -> None:
        if self.cancelled:
            raise WimCancelled("WIM split was cancelled")

    def execute(
        self,
        plan: WimSplitPlan,
        stage: StageCallback = lambda _message: None,
    ) -> WimSplitResult:
        if self._used:
            raise WimValidationError("A WIM split executor can only be used once")
        self._used = True
        validate_split_plan(plan)
        self._check_cancelled()

        source, status = _regular_file(plan.source)
        if str(source) != plan.source or _identity(status) != plan.source_identity:
            raise WimValidationError("install.wim changed after the split was planned")
        if not requires_fat32_split(status.st_size):
            raise WimValidationError("install.wim no longer requires splitting")
        destination = _destination_path(plan.destination_directory)
        staging = Path(tempfile.mkdtemp(
            prefix=f".{destination.name}.", suffix=".partial", dir=destination.parent,
        ))
        try:
            self._check_cancelled()
            stage("Splitting install.wim")
            first_part = staging / "install.swm"
            result = run_bounded_command(
                split_command(plan, first_part),
                timeout_seconds=self._timeout_seconds,
                max_output=MAX_COMMAND_OUTPUT,
                cancel_event=self._cancelled,
                popen=self._popen,
                process_started=self._process_started,
            )
            with self._lock:
                self._process = None
            if result.returncode:
                detail = _error_text(result.stderr)
                raise WimCommandError(detail or "wimlib-imagex could not split install.wim")
            self._check_cancelled()
            stage("Validating split parts")
            parts, total_size = _validate_staged_parts(staging)
            for part in parts:
                with part.open("rb") as stream:
                    os.fsync(stream.fileno())
            _fsync_directory(staging)
            self._check_cancelled()
            if destination.exists() or destination.is_symlink():
                raise WimValidationError("The split-output destination appeared during the operation")
            staging.rename(destination)
            _fsync_directory(destination.parent)
            committed_parts = tuple(str(destination / part.name) for part in parts)
            # The atomic rename is the commit point.  A presentation callback
            # must not turn a successfully committed result into a reported
            # failure that callers might try to repeat.
            try:
                stage("Complete")
            except Exception:
                pass
            return WimSplitResult(str(destination), committed_parts, total_size)
        finally:
            with self._lock:
                process = self._process
                self._process = None
            if process is not None:
                _stop_process(process)
            if staging.exists():
                shutil.rmtree(staging)
