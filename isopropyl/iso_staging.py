from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Prepare an ISO as an atomically published UEFI staging tree.

This module deliberately stops at a regular, unprivileged directory.  It does
not mount, format, inspect, or write a block device.  The published directory
is suitable for :class:`isopropyl.constructed.ConstructedMediaExecutor` after a
caller builds a target-specific constructed-media plan from it.
"""

import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import unicodedata
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .constructed import (
    ConstructedMediaSafetyError,
    scan_staging_tree,
)
from .extraction import (
    OUTPUT_SPACE_RESERVE,
    ExtractionCancelled,
    ExtractionError,
    ExtractionProgress,
    ExtractionSafetyError,
    ExtractionUnavailable,
    SafeIsoExtractor,
    build_extraction_plan,
)
from .iso import (
    FAT32_MAX_FILE_SIZE,
    ArchiveEntry,
    BootStrategy,
    EntryKind,
    FileSystem,
    FirmwareTarget,
    Transformation,
    UnsafeArchiveError,
    WriteMode,
    WritePlan,
    validate_extraction_entries,
)
from .wim import (
    WimCancelled,
    WimError,
    WimInfo,
    WimSelection,
    WimSplitExecutor,
    WimSplitPlan,
    WimSplitResult,
    WimToolUnavailable,
    WimValidationError,
    create_split_plan,
    inspect_wim,
    resolve_wimlib,
    validate_wim_editions,
    validate_wim_selection,
)
from .windows import (
    UNATTEND_NS,
    WindowsCustomization,
    add_autounattend_to_staging,
    answer_file_install_index,
    generate_autounattend,
)


class IsoStagingError(RuntimeError):
    """Base class for ISO-to-directory staging failures."""


class IsoStagingUnavailable(IsoStagingError):
    """A required, trusted host capability is unavailable."""


class IsoStagingSafetyError(IsoStagingError):
    """Planning or execution no longer satisfies the safety contract."""


class IsoStagingCancelled(IsoStagingError):
    """The caller cancelled staging before its atomic commit point."""


FileIdentity = tuple[int, int, int, int]
ParentIdentity = tuple[int, int]
Progress = Callable[["IsoStagingProgress"], None]
Publisher = Callable[[Path, Path, int], None]
SplitPlanBuilder = Callable[[Path, Path, str], WimSplitPlan]
WimInspector = Callable[[Path, str, threading.Event], WimInfo]

_DIR_FLAGS = (
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_AT_FDCWD = -100
_RENAME_NOREPLACE = 1
_WIM_PART = re.compile(r"install(?:(?P<number>[2-9][0-9]*))?\.swm", re.IGNORECASE)
_FALLBACK_LOADER = re.compile(r"boot[A-Za-z0-9]+\.efi", re.IGNORECASE)


@dataclass(frozen=True)
class IsoStagingPlan:
    image: Path
    image_identity: FileIdentity
    destination: Path
    destination_parent_identity: ParentIdentity
    entries: tuple[ArchiveEntry, ...]
    catalog_digest: str
    write_plan: WritePlan
    seven_zip: str
    content_bytes: int
    required_free_bytes: int
    wim_source: str | None
    wim_selection: WimSelection | None
    wimlib_imagex: str | None
    autounattend_xml: str | None

    @property
    def needs_wim_split(self) -> bool:
        return self.wim_source is not None


@dataclass(frozen=True)
class IsoStagingProgress:
    stage: str
    relative_path: str
    bytes_done: int
    total_bytes: int

    @property
    def fraction(self) -> float:
        if self.total_bytes <= 0:
            return 1.0 if self.stage == "Complete" else 0.0
        return min(1.0, max(0.0, self.bytes_done / self.total_bytes))


@dataclass(frozen=True)
class IsoStagingResult:
    destination: Path
    image_identity: FileIdentity
    catalog_digest: str
    directories: int
    files: int
    bytes_staged: int
    wim_parts: tuple[str, ...]
    autounattend_added: bool


def _identity(path: Path) -> FileIdentity:
    try:
        info = path.stat()
    except OSError as error:
        raise IsoStagingSafetyError("The ISO source is unavailable") from error
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise IsoStagingSafetyError("The ISO source must be a non-empty regular file")
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _wim_identity(path: Path) -> FileIdentity:
    try:
        info = os.lstat(path)
    except OSError as error:
        raise IsoStagingSafetyError("The selected WIM/ESD disappeared") from error
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
        raise IsoStagingSafetyError("The selected WIM/ESD is no longer a safe regular file")
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _case_key(path: str) -> tuple[str, ...]:
    return tuple(
        unicodedata.normalize("NFC", part).casefold()
        for part in PurePosixPath(path).parts
    )


def _catalog_digest(entries: Sequence[ArchiveEntry]) -> str:
    encoded = json.dumps(
        [
            {
                "path": entry.path,
                "size": entry.size,
                "kind": entry.kind.value,
                "link_target": entry.link_target,
            }
            for entry in entries
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_write_plan(plan: WritePlan, entries: Sequence[ArchiveEntry]) -> str | None:
    if not isinstance(plan, WritePlan):
        raise IsoStagingSafetyError("A WritePlan is required")
    layout = plan.layout
    if not plan.executable:
        detail = plan.blockers[0] if plan.blockers else "the plan is not executable"
        raise IsoStagingSafetyError(f"Refusing a non-executable write plan: {detail}")
    if plan.mode is not WriteMode.EXTRACTED_ISO:
        raise IsoStagingSafetyError("ISO staging requires extracted-ISO write mode")
    if plan.firmware_target is not FirmwareTarget.UEFI_ONLY:
        raise IsoStagingSafetyError("ISO staging currently requires an explicit UEFI-only plan")
    fat32_layout = (
        layout is not None
        and layout.main_filesystem is FileSystem.FAT32
        and layout.partition_count == 1
        and layout.boot_strategy is BootStrategy.IMAGE_NATIVE
    )
    uefi_ntfs_layout = (
        layout is not None
        and layout.main_filesystem is FileSystem.NTFS
        and layout.partition_count == 2
        and layout.boot_strategy is BootStrategy.UEFI_NTFS
    )
    if (
        layout is None
        or layout.boot_partition_filesystem is not None
        or not layout.uefi_bootable
        or layout.bios_bootable
        or not (fat32_layout or uefi_ntfs_layout)
    ):
        raise IsoStagingSafetyError(
            "ISO staging requires the supported UEFI/FAT32 or UEFI:NTFS layout"
        )
    if not plan.content_constraints_checked or plan.blockers:
        raise IsoStagingSafetyError("The write plan has not passed all content checks")

    files = tuple(entry for entry in entries if entry.kind is EntryKind.FILE)
    content_bytes = sum(entry.size for entry in files)
    if plan.minimum_content_bytes != content_bytes:
        raise IsoStagingSafetyError("The write plan is not bound to this ISO catalog")
    oversized = (
        tuple(entry for entry in files if entry.size > FAT32_MAX_FILE_SIZE)
        if fat32_layout else ()
    )
    eligible = tuple(
        entry for entry in oversized
        if entry.path.casefold() == "sources/install.wim"
    )
    if any(entry not in eligible for entry in oversized):
        raise IsoStagingSafetyError(
            "The ISO contains a non-WIM file that cannot be represented on FAT32"
        )
    requires_split = fat32_layout and bool(eligible)
    expected_transformations = (
        (Transformation.SPLIT_WINDOWS_WIM,) if requires_split else ()
    )
    if plan.transformations != expected_transformations:
        raise IsoStagingSafetyError("The write plan has inconsistent WIM splitting metadata")
    if len(eligible) > 1:
        raise IsoStagingSafetyError("The ISO catalog contains multiple install.wim entries")

    loaders = [
        entry for entry in files
        if len(PurePosixPath(entry.path).parts) == 3
        and PurePosixPath(entry.path).parts[0].casefold() == "efi"
        and PurePosixPath(entry.path).parts[1].casefold() == "boot"
        and _FALLBACK_LOADER.fullmatch(PurePosixPath(entry.path).parts[2])
        and entry.size > 0
    ]
    if not loaders:
        raise IsoStagingSafetyError(
            "The ISO catalog has no non-empty removable-media UEFI fallback loader"
        )
    return eligible[0].path if eligible else None


def _expected_directories(entries: Sequence[ArchiveEntry]) -> dict[tuple[str, ...], str]:
    expected: dict[tuple[str, ...], str] = {(): "."}
    for entry in entries:
        parts = PurePosixPath(entry.path).parts
        stop = len(parts) if entry.kind is EntryKind.DIRECTORY else len(parts) - 1
        for length in range(1, stop + 1):
            rendered = PurePosixPath(*parts[:length]).as_posix()
            expected[_case_key(rendered)] = rendered
    return expected


def _validate_catalog_shape(entries: Sequence[ArchiveEntry], wim_source: str | None) -> None:
    for entry in entries:
        if entry.kind not in {EntryKind.FILE, EntryKind.DIRECTORY}:
            raise IsoStagingSafetyError(
                "Constructed-media staging refuses links and special archive entries"
            )
    if wim_source is None:
        return
    wim_parent = PurePosixPath(wim_source).parent
    for entry in entries:
        path = PurePosixPath(entry.path)
        if path.parent == wim_parent and _WIM_PART.fullmatch(path.name):
            raise IsoStagingSafetyError(
                f"WIM splitting would collide with existing archive member {entry.path!r}"
            )


def _validate_answer_file(xml: str) -> None:
    try:
        root = ET.fromstring(xml)
    except (ET.ParseError, ValueError) as error:
        raise IsoStagingSafetyError("The generated Windows answer file is invalid") from error
    if root.tag != f"{{{UNATTEND_NS}}}unattend":
        raise IsoStagingSafetyError("The generated Windows answer file has an invalid root")


def _validate_wim_selection_catalog(
    entries: Sequence[ArchiveEntry], selection: WimSelection | None,
) -> None:
    if selection is None:
        return
    try:
        validate_wim_selection(selection)
    except WimValidationError as error:
        raise IsoStagingSafetyError(str(error)) from error
    candidates = tuple(
        entry for entry in entries
        if entry.kind is EntryKind.FILE and entry.path.casefold() in {
            "sources/install.wim", "sources/install.esd",
        }
    )
    if len(candidates) != 1:
        raise IsoStagingSafetyError(
            "A selected Windows image requires one unambiguous install.wim or install.esd"
        )
    source = candidates[0]
    if source.path != selection.source_name or source.size != selection.source_size:
        raise IsoStagingSafetyError(
            "The selected Windows image is not bound to this ISO catalog"
        )


def _fixed_wim_resolver(path: str) -> Callable[[str], str | None]:
    return lambda name: path if name == "wimlib-imagex" else None


def build_iso_staging_plan(
    image: Path,
    destination: Path,
    entries: Sequence[ArchiveEntry],
    write_plan: WritePlan,
    *,
    seven_zip: str | None = None,
    windows_customization: WindowsCustomization | None = None,
    windows_architecture: str = "amd64",
    wimlib_resolver: Callable[[], str] = resolve_wimlib,
) -> IsoStagingPlan:
    """Bind a validated catalog and UEFI/FAT32 write plan to a new output path."""

    try:
        safe_entries = validate_extraction_entries(entries)
    except (UnsafeArchiveError, ValueError) as error:
        raise IsoStagingSafetyError(str(error)) from error
    if not safe_entries:
        raise IsoStagingSafetyError("The ISO member catalog is empty")
    wim_source = _validate_write_plan(write_plan, safe_entries)
    _validate_catalog_shape(safe_entries, wim_source)
    wim_selection = (
        windows_customization.install_image
        if windows_customization is not None else None
    )
    _validate_wim_selection_catalog(safe_entries, wim_selection)

    answer_file: str | None = None
    if windows_customization is not None and windows_customization.enabled:
        if any(
            len(PurePosixPath(entry.path).parts) == 1
            and entry.path.casefold() == "autounattend.xml"
            for entry in safe_entries
        ):
            raise IsoStagingSafetyError(
                "The ISO already contains autounattend.xml; it will not be overwritten"
            )
        try:
            answer_file = generate_autounattend(
                windows_customization, windows_architecture,
            )
        except ValueError as error:
            raise IsoStagingSafetyError(str(error)) from error
        _validate_answer_file(answer_file)
        try:
            answer_index = answer_file_install_index(answer_file)
        except ValueError as error:
            raise IsoStagingSafetyError(str(error)) from error
        expected_index = (
            wim_selection.selected_index if wim_selection is not None else None
        )
        if answer_index != expected_index:
            raise IsoStagingSafetyError(
                "The Windows answer file is not bound to the selected image index"
            )

    try:
        extraction = build_extraction_plan(
            image, destination, safe_entries, seven_zip=seven_zip,
        )
    except ExtractionUnavailable as error:
        raise IsoStagingUnavailable(str(error)) from error
    except (ExtractionSafetyError, ExtractionError, OSError) as error:
        raise IsoStagingSafetyError(str(error)) from error

    wimlib_imagex: str | None = None
    if wim_source is not None or wim_selection is not None:
        try:
            wimlib_imagex = wimlib_resolver()
            # Reuse wim.py's exact trusted-path validation instead of accepting
            # an arbitrary executable-shaped string from an injected resolver.
            wimlib_imagex = resolve_wimlib(_fixed_wim_resolver(wimlib_imagex))
        except WimToolUnavailable as error:
            raise IsoStagingUnavailable(str(error)) from error

    split_extra = next(
        (entry.size for entry in safe_entries if entry.path == wim_source), 0,
    )
    required_free = extraction.content_bytes + split_extra + OUTPUT_SPACE_RESERVE
    try:
        if shutil.disk_usage(extraction.destination.parent).free < required_free:
            raise IsoStagingSafetyError(
                "There is not enough free space to extract and transform the ISO privately"
            )
    except OSError as error:
        raise IsoStagingSafetyError("Could not determine staging free space") from error

    return IsoStagingPlan(
        image=extraction.image,
        image_identity=extraction.image_identity,
        destination=extraction.destination,
        destination_parent_identity=extraction.destination_parent_identity,
        entries=safe_entries,
        catalog_digest=_catalog_digest(safe_entries),
        write_plan=write_plan,
        seven_zip=extraction.seven_zip,
        content_bytes=extraction.content_bytes,
        required_free_bytes=required_free,
        wim_source=wim_source,
        wim_selection=wim_selection,
        wimlib_imagex=wimlib_imagex,
        autounattend_xml=answer_file,
    )


def validate_iso_staging_plan(plan: IsoStagingPlan) -> None:
    """Rebuild all externally observable planning facts for a frozen plan."""

    if not isinstance(plan, IsoStagingPlan):
        raise IsoStagingSafetyError("An IsoStagingPlan is required")
    try:
        entries = validate_extraction_entries(plan.entries)
    except (UnsafeArchiveError, ValueError) as error:
        raise IsoStagingSafetyError(str(error)) from error
    if entries != plan.entries or _catalog_digest(entries) != plan.catalog_digest:
        raise IsoStagingSafetyError("The ISO catalog binding is invalid")
    wim_source = _validate_write_plan(plan.write_plan, entries)
    _validate_catalog_shape(entries, wim_source)
    _validate_wim_selection_catalog(entries, plan.wim_selection)
    if wim_source != plan.wim_source:
        raise IsoStagingSafetyError("The plan contains inconsistent WIM transformation data")
    if plan.autounattend_xml is not None:
        _validate_answer_file(plan.autounattend_xml)
        try:
            answer_index = answer_file_install_index(
                plan.autounattend_xml,
                (
                    plan.wim_selection.edition.architecture
                    if plan.wim_selection is not None else None
                ),
            )
        except ValueError as error:
            raise IsoStagingSafetyError(str(error)) from error
        expected_index = (
            plan.wim_selection.selected_index
            if plan.wim_selection is not None else None
        )
        if answer_index != expected_index:
            raise IsoStagingSafetyError(
                "The answer file image index does not match the staging plan"
            )
        if any(
            len(PurePosixPath(entry.path).parts) == 1
            and entry.path.casefold() == "autounattend.xml"
            for entry in entries
        ):
            raise IsoStagingSafetyError("The answer file would replace ISO content")
    elif plan.wim_selection is not None:
        raise IsoStagingSafetyError(
            "A selected Windows image requires a bound answer file"
        )
    try:
        rebuilt = build_extraction_plan(
            plan.image, plan.destination, entries, seven_zip=plan.seven_zip,
        )
    except ExtractionUnavailable as error:
        raise IsoStagingUnavailable(str(error)) from error
    except (ExtractionError, OSError) as error:
        raise IsoStagingSafetyError(str(error)) from error
    if (
        rebuilt.image_identity != plan.image_identity
        or rebuilt.destination_parent_identity != plan.destination_parent_identity
        or rebuilt.content_bytes != plan.content_bytes
    ):
        raise IsoStagingSafetyError("The ISO, destination, or content binding changed")
    if wim_source is None and plan.wim_selection is None:
        if plan.wimlib_imagex is not None:
            raise IsoStagingSafetyError("The plan contains an unnecessary WIM tool")
    else:
        if plan.wimlib_imagex is None:
            raise IsoStagingSafetyError("The plan does not bind a trusted WIM tool")
        try:
            resolved = resolve_wimlib(_fixed_wim_resolver(plan.wimlib_imagex))
        except WimToolUnavailable as error:
            raise IsoStagingUnavailable(str(error)) from error
        if resolved != plan.wimlib_imagex:
            raise IsoStagingSafetyError("The plan contains inconsistent WIM tool data")
    split_extra = next((entry.size for entry in entries if entry.path == wim_source), 0)
    expected_free = plan.content_bytes + split_extra + OUTPUT_SPACE_RESERVE
    if plan.required_free_bytes != expected_free:
        raise IsoStagingSafetyError("The plan contains invalid free-space accounting")
    try:
        if shutil.disk_usage(plan.destination.parent).free < expected_free:
            raise IsoStagingSafetyError(
                "There is not enough free space to extract and transform the ISO privately"
            )
    except OSError as error:
        raise IsoStagingSafetyError("Could not determine staging free space") from error


@dataclass(frozen=True)
class _ScannedFile:
    path: str
    size: int


def _scan_extracted_fd(
    directory_fd: int,
    parts: tuple[str, ...],
    root_device: int,
    directories: dict[tuple[str, ...], str],
    files: dict[tuple[str, ...], _ScannedFile],
) -> None:
    before_directory = os.fstat(directory_fd)
    try:
        names = sorted(os.listdir(directory_fd), key=str.casefold)
    except OSError as error:
        raise IsoStagingSafetyError("Could not enumerate the extracted ISO tree") from error
    for name in names:
        child_parts = parts + (name,)
        rendered = PurePosixPath(*child_parts).as_posix()
        key = tuple(unicodedata.normalize("NFC", item).casefold() for item in child_parts)
        if key in directories or key in files:
            raise IsoStagingSafetyError(f"Case-colliding extracted path: {rendered!r}")
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as error:
            raise IsoStagingSafetyError(
                f"Could not inspect extracted path {rendered!r}"
            ) from error
        if info.st_dev != root_device:
            raise IsoStagingSafetyError(f"Cross-filesystem extracted path: {rendered!r}")
        if stat.S_ISLNK(info.st_mode):
            raise IsoStagingSafetyError(f"Symbolic links are forbidden: {rendered!r}")
        if stat.S_ISDIR(info.st_mode):
            try:
                child_fd = os.open(name, _DIR_FLAGS, dir_fd=directory_fd)
            except OSError as error:
                raise IsoStagingSafetyError(
                    f"Could not safely open extracted directory {rendered!r}"
                ) from error
            try:
                opened = os.fstat(child_fd)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise IsoStagingSafetyError(
                        f"Extracted directory changed while opening: {rendered!r}"
                    )
                directories[key] = rendered
                _scan_extracted_fd(
                    child_fd, child_parts, root_device, directories, files,
                )
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise IsoStagingSafetyError(f"Hard-linked file is forbidden: {rendered!r}")
            files[key] = _ScannedFile(rendered, info.st_size)
        else:
            raise IsoStagingSafetyError(
                f"Special extracted filesystem entry is forbidden: {rendered!r}"
            )
    after_directory = os.fstat(directory_fd)
    if (
        after_directory.st_dev,
        after_directory.st_ino,
        after_directory.st_mtime_ns,
        after_directory.st_ctime_ns,
    ) != (
        before_directory.st_dev,
        before_directory.st_ino,
        before_directory.st_mtime_ns,
        before_directory.st_ctime_ns,
    ):
        raise IsoStagingSafetyError("The extracted ISO tree changed while it was scanned")


def _verify_extracted_catalog(root: Path, entries: Sequence[ArchiveEntry]) -> None:
    initial = os.lstat(root)
    if stat.S_ISLNK(initial.st_mode) or not stat.S_ISDIR(initial.st_mode):
        raise IsoStagingSafetyError("The extractor did not produce a real directory")
    root_fd = os.open(root, _DIR_FLAGS)
    try:
        opened = os.fstat(root_fd)
        if (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino):
            raise IsoStagingSafetyError("The extracted root changed while opening")
        directories: dict[tuple[str, ...], str] = {(): "."}
        files: dict[tuple[str, ...], _ScannedFile] = {}
        _scan_extracted_fd(root_fd, (), opened.st_dev, directories, files)
    finally:
        os.close(root_fd)

    expected_directories = _expected_directories(entries)
    expected_files = {
        _case_key(entry.path): _ScannedFile(entry.path, entry.size)
        for entry in entries if entry.kind is EntryKind.FILE
    }
    if directories != expected_directories:
        raise IsoStagingSafetyError("The extracted directory tree does not match the ISO catalog")
    if files != expected_files:
        raise IsoStagingSafetyError("The extracted files do not match the ISO catalog")


def _validate_split_result(
    result: WimSplitResult,
    split_directory: Path,
) -> tuple[tuple[Path, ...], int]:
    if not isinstance(result, WimSplitResult):
        raise IsoStagingSafetyError("The WIM splitter returned an invalid result")
    if Path(result.directory) != split_directory:
        raise IsoStagingSafetyError("The WIM splitter published to an unexpected directory")
    try:
        scanned_root, directories, files = scan_staging_tree(split_directory)
    except ConstructedMediaSafetyError as error:
        raise IsoStagingSafetyError(str(error)) from error
    if scanned_root != split_directory or len(directories) != 1:
        raise IsoStagingSafetyError("The WIM splitter created unexpected directories")
    numbered: list[tuple[int, Path, int]] = []
    for item in files:
        if len(item.parts) != 1:
            raise IsoStagingSafetyError("The WIM splitter created a nested output")
        match = _WIM_PART.fullmatch(item.parts[0])
        if match is None or item.size <= 0:
            raise IsoStagingSafetyError("The WIM splitter created an unexpected part")
        number = 1 if match.group("number") is None else int(match.group("number"))
        numbered.append((number, split_directory / item.parts[0], item.size))
    numbered.sort(key=lambda item: item[0])
    if [item[0] for item in numbered] != list(range(1, len(numbered) + 1)) or len(numbered) < 2:
        raise IsoStagingSafetyError("The WIM splitter created an incomplete part sequence")
    paths = tuple(item[1] for item in numbered)
    total = sum(item[2] for item in numbered)
    if tuple(Path(item) for item in result.parts) != paths or result.total_size != total:
        raise IsoStagingSafetyError("The WIM splitter result does not match its files")
    return paths, total


def _default_split_plan_builder(source: Path, destination: Path, tool: str) -> WimSplitPlan:
    return create_split_plan(
        source, destination, which=_fixed_wim_resolver(tool),
    )


def _default_wim_inspector(
    source: Path, tool: str, cancel_event: threading.Event,
) -> WimInfo:
    return inspect_wim(
        source, which=_fixed_wim_resolver(tool), cancel_event=cancel_event,
    )


def _rename_noreplace(source: Path, destination: Path, destination_parent_fd: int) -> None:
    """Atomically publish a directory without replacing even an empty target."""

    try:
        library = ctypes.CDLL(None, use_errno=True)
        renameat2 = library.renameat2
    except (OSError, AttributeError) as error:
        raise IsoStagingUnavailable(
            "Atomic no-replace directory publication is unavailable on this Linux system"
        ) from error
    renameat2.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        _AT_FDCWD, os.fsencode(source), destination_parent_fd,
        os.fsencode(destination.name), _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise IsoStagingSafetyError("The staging destination appeared before publication")
    if error_number in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
        raise IsoStagingUnavailable(
            "The staging filesystem does not support atomic no-replace publication"
        )
    raise IsoStagingSafetyError(
        f"Could not atomically publish the staged tree: {os.strerror(error_number)}"
    )


def _check_parent(plan: IsoStagingPlan, parent_fd: int) -> None:
    opened = os.fstat(parent_fd)
    try:
        current = plan.destination.parent.stat()
    except OSError as error:
        raise IsoStagingSafetyError("The staging destination parent disappeared") from error
    expected = plan.destination_parent_identity
    if (opened.st_dev, opened.st_ino) != expected or (current.st_dev, current.st_ino) != expected:
        raise IsoStagingSafetyError("The staging destination parent changed")


class IsoStagingExecutor:
    """Execute one immutable ISO staging plan and publish at one commit point."""

    def __init__(
        self,
        *,
        extractor: SafeIsoExtractor | None = None,
        wim_splitter: WimSplitExecutor | None = None,
        split_plan_builder: SplitPlanBuilder = _default_split_plan_builder,
        wim_inspector: WimInspector = _default_wim_inspector,
        publisher: Publisher = _rename_noreplace,
    ) -> None:
        self._extractor = extractor or SafeIsoExtractor()
        self._wim_splitter = wim_splitter
        self._split_plan_builder = split_plan_builder
        self._wim_inspector = wim_inspector
        self._publisher = publisher
        self._cancelled = threading.Event()
        self._lock = threading.Lock()
        self._active: object | None = None
        self._used = False

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        self._cancelled.set()
        with self._lock:
            active = self._active
        cancel = getattr(active, "cancel", None)
        if callable(cancel):
            cancel()

    def _check_cancelled(self) -> None:
        if self.cancelled:
            raise IsoStagingCancelled("ISO staging was cancelled")

    def _set_active(self, operation: object | None) -> None:
        with self._lock:
            self._active = operation
        if operation is not None and self.cancelled:
            cancel = getattr(operation, "cancel", None)
            if callable(cancel):
                cancel()
            self._check_cancelled()

    def _update_from_extraction(
        self, update: ExtractionProgress, progress: Progress,
    ) -> None:
        progress(IsoStagingProgress(
            "Extracting ISO", update.member, update.bytes_done, update.total_bytes,
        ))
        self._check_cancelled()

    def execute(
        self,
        plan: IsoStagingPlan,
        progress: Progress = lambda _update: None,
    ) -> IsoStagingResult:
        if self._used:
            raise IsoStagingSafetyError("An ISO staging executor can only be used once")
        self._used = True
        validate_iso_staging_plan(plan)
        self._check_cancelled()

        parent_fd = os.open(plan.destination.parent, _DIR_FLAGS)
        private_root: Path | None = None
        committed = False
        try:
            _check_parent(plan, parent_fd)
            if os.path.lexists(plan.destination):
                raise IsoStagingSafetyError("The staging destination already exists")
            private_root = Path(tempfile.mkdtemp(
                prefix=f".{plan.destination.name}.", suffix=".partial",
                dir=plan.destination.parent,
            ))
            tree = private_root / "tree"
            self._check_cancelled()
            progress(IsoStagingProgress("Preparing", "", 0, plan.content_bytes))

            extraction_plan = build_extraction_plan(
                plan.image, tree, plan.entries, seven_zip=plan.seven_zip,
            )
            if extraction_plan.image_identity != plan.image_identity:
                raise IsoStagingSafetyError("The ISO source changed before extraction")
            self._set_active(self._extractor)
            self._extractor.execute(
                extraction_plan,
                lambda update: self._update_from_extraction(update, progress),
            )
            self._set_active(None)
            self._check_cancelled()
            if _identity(plan.image) != plan.image_identity:
                raise IsoStagingSafetyError("The ISO source changed during extraction")
            _verify_extracted_catalog(tree, plan.entries)

            selected_wim_path: Path | None = None
            selected_wim_identity: FileIdentity | None = None
            if plan.wim_selection is not None:
                self._check_cancelled()
                selection = plan.wim_selection
                source = tree.joinpath(*PurePosixPath(selection.source_name).parts)
                progress(IsoStagingProgress(
                    "Validating Windows editions", selection.source_name, 0,
                    plan.content_bytes,
                ))
                assert plan.wimlib_imagex is not None
                info = self._wim_inspector(
                    source, plan.wimlib_imagex, self._cancelled,
                )
                if not isinstance(info, WimInfo):
                    raise IsoStagingSafetyError(
                        "The WIM inspector returned invalid metadata"
                    )
                try:
                    validate_wim_editions(info.editions)
                except WimError as error:
                    raise IsoStagingSafetyError(str(error)) from error
                source_status = source.stat()
                source_identity = (
                    source_status.st_dev, source_status.st_ino,
                    source_status.st_size, source_status.st_mtime_ns,
                )
                if (
                    info.path != str(source.resolve())
                    or info.size != selection.source_size
                    or info.source_identity != source_identity
                    or info.editions != selection.editions
                ):
                    raise IsoStagingSafetyError(
                        "The WIM/ESD metadata changed after the image index was selected"
                    )
                selected_wim_path = source
                selected_wim_identity = source_identity

            wim_parts: tuple[str, ...] = ()
            expected_files = {
                _case_key(entry.path): _ScannedFile(entry.path, entry.size)
                for entry in plan.entries if entry.kind is EntryKind.FILE
            }
            if plan.wim_source is not None:
                self._check_cancelled()
                progress(IsoStagingProgress(
                    "Splitting install.wim", plan.wim_source, 0, plan.content_bytes,
                ))
                source = tree.joinpath(*PurePosixPath(plan.wim_source).parts)
                if (
                    selected_wim_path == source
                    and selected_wim_identity is not None
                    and _wim_identity(source) != selected_wim_identity
                ):
                    raise IsoStagingSafetyError(
                        "install.wim changed after its selected image metadata was validated"
                    )
                split_directory = private_root / "split-wim"
                assert plan.wimlib_imagex is not None
                split_plan = self._split_plan_builder(
                    source, split_directory, plan.wimlib_imagex,
                )
                splitter = self._wim_splitter or WimSplitExecutor()
                self._set_active(splitter)
                result = splitter.execute(
                    split_plan,
                    lambda stage: progress(IsoStagingProgress(
                        stage, plan.wim_source or "", 0, plan.content_bytes,
                    )),
                )
                self._set_active(None)
                self._check_cancelled()
                parts, _part_total = _validate_split_result(result, split_directory)
                # The splitter itself binds this identity.  Rechecking before
                # removal closes the window between its return and our private
                # transformation.
                source_info = os.lstat(source)
                if (
                    not stat.S_ISREG(source_info.st_mode)
                    or source_info.st_nlink != 1
                    or (
                        source_info.st_dev,
                        source_info.st_ino,
                        source_info.st_size,
                        source_info.st_mtime_ns,
                    ) != split_plan.source_identity
                ):
                    raise IsoStagingSafetyError("install.wim changed during splitting")
                original = private_root / "original-install.wim"
                os.rename(source, original)
                expected_files.pop(_case_key(plan.wim_source))
                parent = source.parent
                relative_parts: list[str] = []
                for part in parts:
                    destination = parent / part.name
                    if os.path.lexists(destination):
                        raise IsoStagingSafetyError(
                            f"Split part would replace staged file {part.name!r}"
                        )
                    os.rename(part, destination)
                    relative = PurePosixPath(
                        *PurePosixPath(plan.wim_source).parent.parts, part.name,
                    ).as_posix()
                    info = destination.stat()
                    expected_files[_case_key(relative)] = _ScannedFile(relative, info.st_size)
                    relative_parts.append(relative)
                split_directory.rmdir()
                wim_parts = tuple(relative_parts)

            answer_added = False
            if plan.autounattend_xml is not None:
                self._check_cancelled()
                progress(IsoStagingProgress(
                    "Adding Windows customization", "autounattend.xml", 0,
                    plan.content_bytes,
                ))
                if (
                    selected_wim_path is not None
                    and selected_wim_identity is not None
                    and plan.wim_source is None
                    and _wim_identity(selected_wim_path) != selected_wim_identity
                ):
                    raise IsoStagingSafetyError(
                        "The selected WIM/ESD changed before customization was added"
                    )
                try:
                    answer_path = add_autounattend_to_staging(tree, plan.autounattend_xml)
                except ValueError as error:
                    raise IsoStagingSafetyError(str(error)) from error
                answer_size = answer_path.stat().st_size
                expected_files[_case_key("autounattend.xml")] = _ScannedFile(
                    "autounattend.xml", answer_size,
                )
                answer_added = True

            self._check_cancelled()
            progress(IsoStagingProgress("Validating staging tree", "", 0, plan.content_bytes))
            try:
                scanned_root, directories, files = scan_staging_tree(
                    tree,
                    max_file_bytes=(
                        FAT32_MAX_FILE_SIZE
                        if plan.write_plan.layout is not None
                        and plan.write_plan.layout.main_filesystem is FileSystem.FAT32
                        else None
                    ),
                )
            except ConstructedMediaSafetyError as error:
                raise IsoStagingSafetyError(str(error)) from error
            if scanned_root != tree:
                raise IsoStagingSafetyError("The final staging root changed during validation")
            actual_files = {
                _case_key(item.path): _ScannedFile(item.path, item.size) for item in files
            }
            if actual_files != expected_files:
                raise IsoStagingSafetyError(
                    "The final staging files do not match the transformed ISO catalog"
                )
            expected_directories = _expected_directories(plan.entries)
            actual_directories = {_case_key(item.path): item.path for item in directories}
            if actual_directories != expected_directories:
                raise IsoStagingSafetyError(
                    "The final staging directories do not match the ISO catalog"
                )
            if _identity(plan.image) != plan.image_identity:
                raise IsoStagingSafetyError("The ISO source changed during staging")
            if validate_extraction_entries(plan.entries) != plan.entries:
                raise IsoStagingSafetyError("The ISO catalog changed during staging")
            if _catalog_digest(plan.entries) != plan.catalog_digest:
                raise IsoStagingSafetyError("The ISO catalog binding changed during staging")
            if (
                selected_wim_path is not None
                and selected_wim_identity is not None
                and plan.wim_source is None
                and _wim_identity(selected_wim_path) != selected_wim_identity
            ):
                raise IsoStagingSafetyError(
                    "The selected WIM/ESD changed before staging was published"
                )
            _check_parent(plan, parent_fd)
            if os.path.lexists(plan.destination):
                raise IsoStagingSafetyError("The staging destination appeared before publication")
            self._check_cancelled()
            self._publisher(tree, plan.destination, parent_fd)
            committed = True
            os.fsync(parent_fd)
            total_bytes = sum(item.size for item in files)
            result = IsoStagingResult(
                destination=plan.destination,
                image_identity=plan.image_identity,
                catalog_digest=plan.catalog_digest,
                directories=len(directories),
                files=len(files),
                bytes_staged=total_bytes,
                wim_parts=wim_parts,
                autounattend_added=answer_added,
            )
            try:
                progress(IsoStagingProgress(
                    "Complete", "", total_bytes, total_bytes,
                ))
            except Exception:
                pass
            return result
        except (ExtractionCancelled, WimCancelled, IsoStagingCancelled) as error:
            raise IsoStagingCancelled("ISO staging was cancelled") from error
        except ExtractionUnavailable as error:
            raise IsoStagingUnavailable(str(error)) from error
        except (ExtractionSafetyError, WimValidationError) as error:
            raise IsoStagingSafetyError(str(error)) from error
        except (ExtractionError, WimError) as error:
            raise IsoStagingError(str(error)) from error
        finally:
            self._set_active(None)
            os.close(parent_fd)
            if private_root is not None and private_root.exists():
                shutil.rmtree(private_root)
            # Once renameat2 succeeds, cancellation or a presentation callback
            # cannot roll back a valid committed tree.  `committed` documents
            # that intentional commit boundary for reviewers and debuggers.
            _ = committed
