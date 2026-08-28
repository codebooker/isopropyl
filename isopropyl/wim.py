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
import unicodedata
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .windows_paths import validate_install_image_member_path

FAT32_MAX_FILE_SIZE = (4 * 1024 * 1024 * 1024) - 1
MIB = 1024 * 1024
DEFAULT_SPLIT_PART_MIB = 3800
MAX_SPLIT_PART_MIB = FAT32_MAX_FILE_SIZE // MIB
MAX_INFO_OUTPUT = 4 * MIB
MAX_COMMAND_OUTPUT = MIB
MAX_IMAGES = 128
MAX_XML_ELEMENTS = 20_000
MAX_EXTRACT_PATHS = 32
MAX_EXTRACT_PATH_CHARACTERS = 1024
MAX_EXTRACT_PATH_BYTES = 4096
MAX_EXTRACT_PATH_COMPONENTS = 32
MAX_EXTRACT_FILES = 8192
MAX_EXTRACT_BYTES = 512 * MIB
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
    expanded_bytes: int = 0

    @property
    def version(self) -> str:
        value = f"{self.major_version}.{self.minor_version}.{self.build}"
        return f"{value}.{self.service_pack_build}" if self.service_pack_build else value

    @property
    def display_label(self) -> str:
        title = self.name or self.edition_id
        edition = f" · {self.edition_id}" if self.edition_id != title else ""
        return (
            f"Index {self.index} · {title}{edition} · build {self.version} · "
            f"{self.architecture.upper()}"
        )


FileIdentity = tuple[int, int, int, int, int, int]


@dataclass(frozen=True)
class WimInfo:
    path: str
    size: int
    editions: tuple[WimEdition, ...]
    source_identity: FileIdentity

    def select(self, source_name: str, index: int, *, expected_size: int | None = None) -> "WimSelection":
        size = self.size if expected_size is None else expected_size
        if size != self.size:
            raise WimValidationError("The ISO catalog size does not match the inspected WIM/ESD")
        selection = WimSelection(source_name, size, self.editions, index)
        validate_wim_selection(selection)
        return selection


@dataclass(frozen=True)
class WimSelection:
    """An exact ISO member/catalog binding for one Windows Setup image index."""

    source_name: str
    source_size: int
    editions: tuple[WimEdition, ...]
    selected_index: int

    @property
    def edition(self) -> WimEdition:
        validate_wim_selection(self)
        return next(item for item in self.editions if item.index == self.selected_index)

    @property
    def display_label(self) -> str:
        return self.edition.display_label


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


@dataclass(frozen=True)
class WimExtractPlan:
    """An exact, identity-bound extraction from one non-spanned WIM."""

    source: str
    source_identity: FileIdentity
    image_index: int
    paths: tuple[str, ...]
    destination_directory: str
    wimlib_imagex: str


@dataclass(frozen=True)
class WimExtractResult:
    directory: str
    files: tuple[str, ...]
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


_SOURCE_FLAGS = (
    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
)


def _identity(status: os.stat_result) -> FileIdentity:
    return (
        status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns,
        status.st_ctime_ns, status.st_nlink,
    )


def _open_regular_file(
    path: str | os.PathLike[str],
) -> tuple[Path, int, os.stat_result]:
    descriptor = -1
    try:
        raw = Path(path).expanduser()
        parent = raw.parent.resolve(strict=True)
        resolved = parent / raw.name
        descriptor = os.open(resolved, _SOURCE_FLAGS)
        status = os.fstat(descriptor)
        linked = os.lstat(resolved)
    except (OSError, RuntimeError) as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise WimValidationError(f"WIM/ESD source is unavailable: {path}") from error
    try:
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or (status.st_dev, status.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise WimValidationError(
                "The WIM/ESD source must be one no-follow regular file"
            )
        if status.st_size <= 0:
            raise WimValidationError("The WIM/ESD source is empty")
        return resolved, descriptor, status
    except Exception:
        os.close(descriptor)
        raise


def _regular_file(path: str | os.PathLike[str]) -> tuple[Path, os.stat_result]:
    resolved, descriptor, status = _open_regular_file(path)
    os.close(descriptor)
    return resolved, status


def _descriptor_path(descriptor: int) -> str:
    return f"/proc/self/fd/{descriptor}"


def _descriptor_still_bound(
    path: Path, descriptor: int, expected: FileIdentity,
) -> bool:
    try:
        descriptor_status = os.fstat(descriptor)
        path_status = os.lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISREG(descriptor_status.st_mode)
        and stat.S_ISREG(path_status.st_mode)
        and _identity(descriptor_status) == expected
        and _identity(path_status) == expected
    )


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
    pass_fds: Sequence[int] = (),
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
    bound_fds = tuple(pass_fds)
    if any(type(descriptor) is not int or descriptor < 0 for descriptor in bound_fds):
        raise WimValidationError("Inherited WIM descriptors must be non-negative integers")

    try:
        process = popen(
            list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, shell=False, pass_fds=bound_fds,
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


def _optional_u63(parent: ET.Element, name: str, context: str) -> int:
    """Parse optional byte counts without the 32-bit metadata-field ceiling."""

    item = _child(parent, name)
    if item is None or item.text is None or not item.text.strip():
        return 0
    value = item.text.strip()
    if not value.isascii() or not value.isdecimal():
        raise WimMetadataError(f"Invalid numeric {context} {name}")
    parsed = int(value)
    if parsed > (1 << 63) - 1:
        raise WimMetadataError(f"Out-of-range {context} {name}")
    return parsed


_ARCHITECTURES = {
    0: "x86",
    5: "arm",
    6: "ia64",
    9: "amd64",
    12: "arm64",
}


def validate_wim_editions(editions: tuple[WimEdition, ...]) -> None:
    if (
        not isinstance(editions, tuple)
        or not editions
        or len(editions) > MAX_IMAGES
        or any(not isinstance(item, WimEdition) for item in editions)
    ):
        raise WimMetadataError("WIM metadata contains no images or too many images")
    indexes: set[int] = set()
    for item in editions:
        integer_values = (
            item.index, item.major_version, item.minor_version, item.build,
            item.service_pack_build, item.expanded_bytes,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) for value in integer_values):
            raise WimMetadataError("WIM edition contains invalid numeric metadata")
        if (
            item.index <= 0 or item.index in indexes or item.major_version < 0
            or item.minor_version < 0 or item.build <= 0 or item.service_pack_build < 0
            or any(value > 2_147_483_647 for value in integer_values[:-1])
            or item.expanded_bytes < 0 or item.expanded_bytes > (1 << 63) - 1
        ):
            raise WimMetadataError("WIM edition contains ambiguous or invalid numeric metadata")
        indexes.add(item.index)
        text_values = (item.name, item.description, item.edition_id, item.architecture)
        if any(not isinstance(value, str) or len(value) > 1024 for value in text_values):
            raise WimMetadataError("WIM edition contains invalid text metadata")
        if not item.edition_id or item.architecture not in _ARCHITECTURES.values():
            raise WimMetadataError("WIM edition has an invalid edition or architecture")
    if tuple(item.index for item in editions) != tuple(sorted(indexes)):
        raise WimMetadataError("WIM image indexes are not in a canonical order")


def validate_wim_selection(selection: WimSelection) -> None:
    if not isinstance(selection, WimSelection):
        raise WimValidationError("A WIM image selection is required")
    try:
        validate_install_image_member_path(selection.source_name)
    except ValueError as error:
        raise WimValidationError(
            "The selection must name a safe */sources/install.wim or canonical install.esd"
        ) from error
    if (
        not isinstance(selection.source_size, int)
        or isinstance(selection.source_size, bool)
        or selection.source_size <= 0
    ):
        raise WimValidationError("The selected WIM/ESD has an invalid catalog size")
    try:
        validate_wim_editions(selection.editions)
    except WimMetadataError as error:
        raise WimValidationError(str(error)) from error
    if (
        not isinstance(selection.selected_index, int)
        or isinstance(selection.selected_index, bool)
        or sum(
            item.index == selection.selected_index for item in selection.editions
        ) != 1
    ):
        raise WimValidationError("The selected WIM image index is missing or ambiguous")


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
            expanded_bytes=_optional_u63(image, "TOTALBYTES", f"image {index}"),
        ))
    result = tuple(sorted(editions, key=lambda item: item.index))
    validate_wim_editions(result)
    return result


def inspect_wim(
    path: str | os.PathLike[str],
    *,
    which: Callable[[str], str | None] = _trusted_which,
    runner: CommandRunner = run_bounded_command,
    timeout_seconds: float = 20,
    cancel_event: threading.Event | None = None,
) -> WimInfo:
    source, descriptor, status = _open_regular_file(path)
    source_identity = _identity(status)
    try:
        tool = resolve_wimlib(which)
        result = runner(
            [tool, "info", _descriptor_path(descriptor), "--xml"],
            timeout_seconds=timeout_seconds,
            max_output=MAX_INFO_OUTPUT,
            cancel_event=cancel_event,
            pass_fds=(descriptor,),
        )
        if len(result.stdout) > MAX_INFO_OUTPUT or len(result.stderr) > MAX_INFO_OUTPUT:
            raise WimCommandError("wimlib-imagex produced too much output")
        if result.returncode:
            detail = _error_text(result.stderr)
            raise WimCommandError(detail or "wimlib-imagex could not inspect the image")
        editions = parse_wim_info_xml(result.stdout)
        if not _descriptor_still_bound(source, descriptor, source_identity):
            raise WimValidationError(
                "The WIM/ESD source changed while metadata was inspected"
            )
        return WimInfo(str(source), status.st_size, editions, source_identity)
    finally:
        os.close(descriptor)


_EXTRACT_DRIVE_PATH = re.compile(r"^[A-Za-z]:")
_EXTRACT_RESERVED_COMPONENT = re.compile(
    r"^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|"
    r"com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$",
    re.IGNORECASE,
)
_EXTRACT_FORBIDDEN_CHARACTERS = frozenset('<>:"\\|?*')


def _validate_extract_paths(paths: object) -> tuple[str, ...]:
    if (
        not isinstance(paths, (tuple, list))
        or not paths
        or len(paths) > MAX_EXTRACT_PATHS
    ):
        raise WimValidationError(
            f"Between 1 and {MAX_EXTRACT_PATHS} exact WIM paths are required"
        )
    validated: list[str] = []
    aliases: list[tuple[str, ...]] = []
    for path in paths:
        if not isinstance(path, str) or not path:
            raise WimValidationError("Each exact WIM path must be non-empty text")
        if len(path) > MAX_EXTRACT_PATH_CHARACTERS:
            raise WimValidationError("An exact WIM path is too long")
        try:
            encoded = path.encode("utf-8")
        except UnicodeEncodeError as error:
            raise WimValidationError("An exact WIM path contains invalid Unicode") from error
        if len(encoded) > MAX_EXTRACT_PATH_BYTES:
            raise WimValidationError("An exact WIM path is too long")
        if unicodedata.normalize("NFC", path) != path:
            raise WimValidationError("An exact WIM path is not NFC-normalized")
        if any(
            unicodedata.category(character) in {"Cc", "Cf", "Cs"}
            for character in path
        ):
            raise WimValidationError("An exact WIM path contains unsafe Unicode")
        if (
            path.startswith(("/", "\\"))
            or path.startswith(("-", "@"))
            or "\\" in path
            or _EXTRACT_DRIVE_PATH.match(path)
            or any(character in _EXTRACT_FORBIDDEN_CHARACTERS for character in path)
        ):
            raise WimValidationError("An exact WIM path has unsafe Windows syntax")
        components = tuple(path.split("/"))
        if (
            not 1 <= len(components) <= MAX_EXTRACT_PATH_COMPONENTS
            or any(component in {"", ".", ".."} for component in components)
        ):
            raise WimValidationError("An exact WIM path has an unsafe component")
        for component in components:
            if component != component.strip() or component.endswith("."):
                raise WimValidationError(
                    "An exact WIM path has component whitespace or dots"
                )
            if _EXTRACT_RESERVED_COMPONENT.fullmatch(component):
                raise WimValidationError(
                    "An exact WIM path contains a reserved device name"
                )
            if (
                len(component.encode("utf-8")) > 255
                or len(component.encode("utf-16-le")) // 2 > 255
            ):
                raise WimValidationError("An exact WIM path has an overlong component")
        alias = tuple(component.casefold() for component in components)
        if alias in aliases:
            raise WimValidationError("Exact WIM paths must be unique")
        if any(
            alias[:len(other)] == other or other[:len(alias)] == alias
            for other in aliases
        ):
            raise WimValidationError("Exact WIM paths must not overlap")
        validated.append(path)
        aliases.append(alias)
    return tuple(validated)


def _extract_destination_path(path: str | os.PathLike[str]) -> Path:
    raw = Path(path).expanduser()
    if raw.name in {"", ".", ".."}:
        raise WimValidationError("A dedicated WIM extraction directory is required")
    try:
        parent = raw.parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise WimValidationError(
            "The WIM extraction parent directory is unavailable"
        ) from error
    if not parent.is_dir():
        raise WimValidationError("The WIM extraction parent must be a directory")
    destination = parent / raw.name
    if destination.exists() or destination.is_symlink():
        raise WimValidationError("The WIM extraction directory must not already exist")
    return destination


def create_extract_plan(
    source: str | os.PathLike[str],
    destination_directory: str | os.PathLike[str],
    *,
    image_index: int,
    paths: Sequence[str],
    wimlib_imagex: str,
) -> WimExtractPlan:
    source_path, status = _regular_file(source)
    if source_path.suffix.casefold() != ".wim":
        raise WimValidationError("Only one non-spanned .wim source can be extracted")
    if (
        not isinstance(image_index, int)
        or isinstance(image_index, bool)
        or not 1 <= image_index <= 2_147_483_647
    ):
        raise WimValidationError("The WIM image index must be a positive integer")
    exact_paths = _validate_extract_paths(paths)
    destination = _extract_destination_path(destination_directory)
    return WimExtractPlan(
        source=str(source_path),
        source_identity=_identity(status),
        image_index=image_index,
        paths=exact_paths,
        destination_directory=str(destination),
        wimlib_imagex=_validate_wimlib_path(wimlib_imagex),
    )


def validate_extract_plan(plan: WimExtractPlan) -> None:
    if not isinstance(plan, WimExtractPlan):
        raise WimValidationError("A WimExtractPlan is required")
    _validate_wimlib_path(plan.wimlib_imagex)
    if (
        not os.path.isabs(plan.source)
        or Path(plan.source).suffix.casefold() != ".wim"
    ):
        raise WimValidationError("WIM extraction plan contains an invalid source")
    if (
        not isinstance(plan.image_index, int)
        or isinstance(plan.image_index, bool)
        or not 1 <= plan.image_index <= 2_147_483_647
    ):
        raise WimValidationError("WIM extraction plan contains an invalid image index")
    if _validate_extract_paths(plan.paths) != plan.paths:
        raise WimValidationError("WIM extraction paths are not canonical")
    if not os.path.isabs(plan.destination_directory):
        raise WimValidationError("WIM extraction plan contains a relative destination")
    destination = Path(plan.destination_directory)
    if destination.name in {"", ".", ".."}:
        raise WimValidationError("WIM extraction plan contains an invalid destination")
    if (
        not isinstance(plan.source_identity, tuple)
        or len(plan.source_identity) != 6
        or any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in plan.source_identity
        )
    ):
        raise WimValidationError("WIM extraction plan contains an invalid source identity")


def extract_command(plan: WimExtractPlan, staged_destination: Path) -> list[str]:
    validate_extract_plan(plan)
    if not staged_destination.is_absolute():
        raise WimValidationError("The staged WIM extraction directory must be absolute")
    return [
        plan.wimlib_imagex,
        "extract",
        plan.source,
        str(plan.image_index),
        *plan.paths,
        f"--dest-dir={staged_destination}",
        "--no-globs",
        "--preserve-dir-structure",
        "--no-acls",
        "--no-attributes",
        "--check",
    ]


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
        not isinstance(plan.source_identity, tuple) or len(plan.source_identity) != 6
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


def _validate_extracted_tree(
    directory: Path,
    requested_paths: tuple[str, ...],
) -> tuple[tuple[Path, ...], int]:
    root_status = directory.lstat()
    if (
        not stat.S_ISDIR(root_status.st_mode)
        or stat.S_IMODE(root_status.st_mode) & 0o077
    ):
        raise WimCommandError("The WIM extraction root is not a private directory")

    requested = tuple(
        tuple(component.casefold() for component in path.split("/"))
        for path in requested_paths
    )
    materialized: set[tuple[str, ...]] = set()
    aliases: set[tuple[str, ...]] = set()
    files: list[Path] = []
    file_statuses: list[os.stat_result] = []
    total_size = 0
    entries_seen = 0
    pending = [directory]
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as iterator:
                entries = sorted(iterator, key=lambda item: item.name.casefold())
        except OSError as error:
            raise WimCommandError("Could not inspect extracted WIM output") from error
        for entry in entries:
            entries_seen += 1
            if entries_seen > MAX_EXTRACT_FILES:
                raise WimCommandError("wimlib-imagex created too many extraction entries")
            output = Path(entry.path)
            try:
                status = entry.stat(follow_symlinks=False)
                relative = output.relative_to(directory).as_posix()
                _validate_extract_paths((relative,))
            except (OSError, ValueError, WimValidationError) as error:
                raise WimCommandError(
                    "wimlib-imagex created an unsafe extraction path"
                ) from error
            alias = tuple(component.casefold() for component in relative.split("/"))
            if alias in aliases:
                raise WimCommandError(
                    "wimlib-imagex created case-ambiguous extraction paths"
                )
            aliases.add(alias)
            exact = alias in requested
            descendant = any(alias[:len(root)] == root for root in requested)
            ancestor = any(root[:len(alias)] == alias for root in requested)
            if exact:
                materialized.add(alias)

            if stat.S_ISDIR(status.st_mode):
                if not (exact or descendant or ancestor):
                    raise WimCommandError(
                        "wimlib-imagex created an unexpected extraction directory"
                    )
                pending.append(output)
                continue
            if not stat.S_ISREG(status.st_mode):
                raise WimCommandError(
                    "wimlib-imagex created a non-regular extraction output"
                )
            if not (exact or descendant):
                raise WimCommandError(
                    "wimlib-imagex created an unexpected extraction file"
                )
            total_size += status.st_size
            if total_size > MAX_EXTRACT_BYTES:
                raise WimCommandError("wimlib-imagex extraction is too large")
            descriptor = -1
            try:
                descriptor = os.open(output, _SOURCE_FLAGS)
                descriptor_status = os.fstat(descriptor)
                if _identity(descriptor_status) != _identity(status):
                    raise WimCommandError(
                        "An extracted WIM file changed during validation"
                    )
                os.fsync(descriptor)
            except OSError as error:
                raise WimCommandError(
                    "Could not validate an extracted WIM file"
                ) from error
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            files.append(output)
            file_statuses.append(status)

    missing = set(requested) - materialized
    if missing:
        raise WimCommandError("wimlib-imagex did not extract every requested path")
    internal_links: dict[tuple[int, int], int] = {}
    for status in file_statuses:
        key = (status.st_dev, status.st_ino)
        internal_links[key] = internal_links.get(key, 0) + 1
    if any(
        status.st_nlink != internal_links[(status.st_dev, status.st_ino)]
        for status in file_statuses
    ):
        raise WimCommandError("An extracted WIM file has links outside the private tree")
    files.sort(key=lambda path: path.relative_to(directory).as_posix().casefold())
    return tuple(files), total_size


class WimExtractExecutor:
    """Extract literal WIM paths into a new private directory, or commit nothing."""

    def __init__(
        self,
        *,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        timeout_seconds: float = 20 * 60,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 24 * 60 * 60:
            raise WimValidationError(
                "Extraction timeout must be between 0 and 86400 seconds"
            )
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
            raise WimCancelled("WIM extraction was cancelled")

    def execute(
        self,
        plan: WimExtractPlan,
        stage: StageCallback = lambda _message: None,
    ) -> WimExtractResult:
        if self._used:
            raise WimValidationError("A WIM extraction executor can only be used once")
        self._used = True
        validate_extract_plan(plan)
        self._check_cancelled()

        source, source_descriptor, status = _open_regular_file(plan.source)
        if str(source) != plan.source or _identity(status) != plan.source_identity:
            os.close(source_descriptor)
            raise WimValidationError("The WIM source changed after extraction was planned")
        staging: Path | None = None
        try:
            destination = _extract_destination_path(plan.destination_directory)
            staging = Path(tempfile.mkdtemp(
                prefix=f".{destination.name}.",
                suffix=".partial",
                dir=destination.parent,
            ))
            os.chmod(staging, 0o700)
            self._check_cancelled()
            stage("Extracting Windows boot files")
            command = extract_command(plan, staging)
            command[2] = _descriptor_path(source_descriptor)
            result = run_bounded_command(
                command,
                timeout_seconds=self._timeout_seconds,
                max_output=MAX_COMMAND_OUTPUT,
                cancel_event=self._cancelled,
                popen=self._popen,
                process_started=self._process_started,
                pass_fds=(source_descriptor,),
            )
            with self._lock:
                self._process = None
            if not _descriptor_still_bound(
                source, source_descriptor, plan.source_identity,
            ):
                raise WimValidationError("The WIM source changed while it was extracted")
            if result.returncode:
                detail = _error_text(result.stderr)
                raise WimCommandError(
                    detail or "wimlib-imagex could not extract the requested paths"
                )
            self._check_cancelled()
            stage("Validating extracted Windows boot files")
            files, total_size = _validate_extracted_tree(staging, plan.paths)
            _fsync_directory(staging)
            self._check_cancelled()
            if destination.exists() or destination.is_symlink():
                raise WimValidationError(
                    "The WIM extraction destination appeared during the operation"
                )
            staging.rename(destination)
            _fsync_directory(destination.parent)
            committed_files = tuple(
                str(destination / path.relative_to(staging)) for path in files
            )
            try:
                stage("Complete")
            except Exception:
                pass
            return WimExtractResult(str(destination), committed_files, total_size)
        finally:
            os.close(source_descriptor)
            with self._lock:
                process = self._process
                self._process = None
            if process is not None:
                _stop_process(process)
            if staging is not None and staging.exists():
                shutil.rmtree(staging)


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

        source, source_descriptor, status = _open_regular_file(plan.source)
        if str(source) != plan.source or _identity(status) != plan.source_identity:
            os.close(source_descriptor)
            raise WimValidationError("install.wim changed after the split was planned")
        if not requires_fat32_split(status.st_size):
            os.close(source_descriptor)
            raise WimValidationError("install.wim no longer requires splitting")
        staging: Path | None = None
        try:
            destination = _destination_path(plan.destination_directory)
            staging = Path(tempfile.mkdtemp(
                prefix=f".{destination.name}.", suffix=".partial",
                dir=destination.parent,
            ))
            self._check_cancelled()
            stage("Splitting install.wim")
            first_part = staging / "install.swm"
            command = split_command(plan, first_part)
            command[2] = _descriptor_path(source_descriptor)
            result = run_bounded_command(
                command,
                timeout_seconds=self._timeout_seconds,
                max_output=MAX_COMMAND_OUTPUT,
                cancel_event=self._cancelled,
                popen=self._popen,
                process_started=self._process_started,
                pass_fds=(source_descriptor,),
            )
            with self._lock:
                self._process = None
            if result.returncode:
                detail = _error_text(result.stderr)
                raise WimCommandError(detail or "wimlib-imagex could not split install.wim")
            if not _descriptor_still_bound(
                source, source_descriptor, plan.source_identity,
            ):
                raise WimValidationError("install.wim changed while it was being split")
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
            os.close(source_descriptor)
            with self._lock:
                process = self._process
                self._process = None
            if process is not None:
                _stop_process(process)
            if staging is not None and staging.exists():
                shutil.rmtree(staging)
