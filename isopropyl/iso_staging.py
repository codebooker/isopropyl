from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Prepare an ISO and optional additive ZIP as an atomic UEFI staging tree.

This module deliberately stops at a regular, unprivileged directory.  It does
not mount, format, inspect, or write a block device.  The published directory
is suitable for :class:`isopropyl.constructed.ConstructedMediaExecutor` after a
caller builds a target-specific constructed-media plan from it.
"""

import ctypes
import errno
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import time
import unicodedata
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .staging_tree import (
    StagingTreeManifest,
    StagingTreeSafetyError,
    build_staging_tree_manifest,
    scan_staging_tree,
    validate_staging_tree_manifest,
)
from .boot_identity import (
    BootloaderAnalysis,
    analyze_iso_bootloaders,
    read_archive_member_with_7z,
)
from .bootloaders import BoundBootBundle
from .distro_policies import (
    DistroPolicyError,
    match_distro_member_exclusion,
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
from .eltorito import (
    ElToritoError,
    ElToritoNotFound,
    inspect_eltorito_file,
)
from .fat_image import (
    EmbeddedFatImage,
    FatImageError,
    materialize_embedded_fat,
    validate_uefi_eltorito_fat,
)
from .iso import (
    FAT32_MAX_FILE_SIZE,
    ArchiveEntry,
    BootStrategy,
    EntryKind,
    FileSystem,
    FirmwareTarget,
    PartitionTable,
    Transformation,
    UnsafeArchiveError,
    WriteMode,
    WritePlan,
    merge_additive_embedded_entries,
    merge_additive_generated_entries,
    merge_additive_overlay_entries,
    validate_extraction_entries,
)
from .images import ImageMember, SevenZipNamespace, scan_image_contents
from .timestamps import (
    STAGING_MTIME_TOLERANCE_NS,
    TimestampPreservationError,
    apply_descriptor_mtime,
    mtime_matches,
)
from .syslinux_staging import (
    StageDisposition,
    SyslinuxStageFile,
    SyslinuxStagingError,
    SyslinuxStagingPlan,
    plan_syslinux_staging,
    syslinux_staging_analysis_paths,
    syslinux_staging_read_paths,
    validate_syslinux_staging_plan,
)
from .wim import (
    MAX_EXTRACT_BYTES as WIM_MAX_EXTRACT_BYTES,
    FileIdentity as WimFileIdentity,
    WimCancelled,
    WimError,
    WimExtractExecutor,
    WimExtractPlan,
    WimExtractResult,
    WimInfo,
    WimSelection,
    WimSplitExecutor,
    WimSplitPlan,
    WimSplitResult,
    WimToolUnavailable,
    WimValidationError,
    create_extract_plan,
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
    answer_file_install_path,
    generate_autounattend,
)
from .windows_bootex import (
    MAX_EXTRACTED_TOTAL_BYTES as BOOTEX_MAX_EXTRACTED_TOTAL_BYTES,
    BootExError,
    BootExPlan,
    BootExRequest,
    BootExResult,
    BootExSourceBinding,
    WindowsBootExOptions,
    apply_bootex_plan,
    bind_bootex_source,
    build_bootex_plan,
    validate_bootex_source_binding,
    validate_bootex_result,
)
from .zip_overlay import (
    ZipOverlayChanged,
    ZipOverlayDeadlineExceeded,
    ZipOverlayError,
    ZipOverlayPlan,
    ZipOverlayProgress,
    ZipOverlayResult,
    ZipOverlaySafetyError,
    apply_zip_overlay,
    validate_zip_overlay_plan,
)


class IsoStagingError(RuntimeError):
    """Base class for ISO-to-directory staging failures."""


class IsoStagingUnavailable(IsoStagingError):
    """A required, trusted host capability is unavailable."""


class IsoStagingSafetyError(IsoStagingError):
    """Planning or execution no longer satisfies the safety contract."""


class IsoStagingCancelled(IsoStagingError):
    """The caller cancelled staging before its atomic commit point."""


FileIdentity = tuple[int, int, int, int, int]
ParentIdentity = tuple[int, int]
Progress = Callable[["IsoStagingProgress"], None]
Publisher = Callable[[Path, Path, int], None]
SplitPlanBuilder = Callable[[Path, Path, str], WimSplitPlan]
WimInspector = Callable[[Path, str, threading.Event], WimInfo]
ExtractPlanBuilder = Callable[..., WimExtractPlan]
BootExSourceBinder = Callable[..., BootExSourceBinding]
BootExPlanBuilder = Callable[..., BootExPlan]
BootExApplier = Callable[..., BootExResult]
OverlayApplier = Callable[..., ZipOverlayResult]
CatalogScanner = Callable[..., tuple[list[ImageMember], bool]]

_DIR_FLAGS = (
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_AT_FDCWD = -100
_RENAME_NOREPLACE = 1
_WIM_PART = re.compile(r"install(?:(?P<number>[2-9][0-9]*))?\.swm", re.IGNORECASE)
_FALLBACK_LOADER = re.compile(r"boot[A-Za-z0-9]+\.efi", re.IGNORECASE)
_CATALOG_WITNESS_TOKEN = object()
_RESULT_WITNESS_TOKEN = object()
_SYSLINUX_BIND_TIMEOUT_SECONDS = 60.0
_BOOTEX_WIM_PATHS = (
    "Windows/Boot/EFI_EX",
    "Windows/Boot/Fonts_EX",
)
_BOOTEX_EXTRA_SPACE = (
    WIM_MAX_EXTRACT_BYTES + BOOTEX_MAX_EXTRACTED_TOTAL_BYTES
)
_WINDOWS_DUAL_TRANSITIONAL_BLOCKER = (
    "BIOS construction is not enabled; choose UEFI-only or use DD mode."
)


def _is_install_wim_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return (
        len(parts) >= 2
        and parts[-1].casefold() == "install.wim"
        and parts[-2].casefold() == "sources"
    )


@dataclass(frozen=True)
class IsoStagingPlan:
    """One bound private-tree plan.

    ``effective_entries`` is the base/embedded/overlay catalog.
    ``staged_entries`` additionally includes planned Syslinux files, but is
    intentionally still before WIM splitting and generated answer files.  Its
    digest is a planning/result binding, not a hash manifest of the final tree.
    """

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
    archive_namespace: SevenZipNamespace = SevenZipNamespace.UDF
    windows_customization: WindowsCustomization | None = None
    windows_architecture: str | None = None
    overlay: ZipOverlayPlan | None = None
    effective_entries: tuple[ArchiveEntry, ...] = ()
    effective_catalog_digest: str = ""
    _catalog_witness: object | None = None
    embedded_fat: EmbeddedFatImage | None = None
    embedded_entries: tuple[ArchiveEntry, ...] = ()
    embedded_targets: tuple[str, ...] = ()
    base_with_embedded_entries: tuple[ArchiveEntry, ...] = ()
    base_with_embedded_catalog_digest: str = ""
    embedded_content_bytes: int = 0
    syslinux_analysis: BootloaderAnalysis | None = None
    syslinux_c32_bundle: BoundBootBundle | None = None
    syslinux_payload_bundle: BoundBootBundle | None = None
    syslinux_staging: SyslinuxStagingPlan | None = None
    syslinux_content_bytes: int = 0
    staged_entries: tuple[ArchiveEntry, ...] = ()
    staged_catalog_digest: str = ""
    windows_bootex_options: WindowsBootExOptions | None = None
    windows_bootex_source: BootExSourceBinding | None = None
    windows_boot_wim_source: str | None = None

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
    """Published tree metadata and an optional authenticated tree receipt.

    Syslinux-capable results carry a complete post-publication content manifest.
    Ordinary UEFI-only staging avoids that additional full-tree hashing cost.
    """

    destination: Path
    image_identity: FileIdentity
    catalog_digest: str
    directories: int
    files: int
    bytes_staged: int
    wim_parts: tuple[str, ...]
    autounattend_added: bool
    tree_manifest: StagingTreeManifest | None = field(default=None, repr=False)
    windows_bootex: BootExResult | None = field(default=None, repr=False)
    _receipt: _PublishedReceipt | None = field(
        default=None, init=False, repr=False, compare=False,
    )


@dataclass(frozen=True)
class _PublishedReceipt:
    token: object
    plan: IsoStagingPlan = field(repr=False, compare=False)
    manifest: StagingTreeManifest = field(repr=False)
    destination: Path
    image_identity: FileIdentity
    catalog_digest: str
    directories: int
    files: int
    bytes_staged: int
    wim_parts: tuple[str, ...]
    autounattend_added: bool
    windows_bootex: BootExResult | None


@dataclass(frozen=True)
class _CatalogWitness:
    token: object
    image_identity: FileIdentity
    catalog_digest: str
    archive_namespace: SevenZipNamespace


def _identity(path: Path) -> FileIdentity:
    try:
        info = path.stat()
    except OSError as error:
        raise IsoStagingSafetyError("The ISO source is unavailable") from error
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise IsoStagingSafetyError("The ISO source must be a non-empty regular file")
    return (
        info.st_dev, info.st_ino, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns,
    )


def _wim_identity(path: Path) -> WimFileIdentity:
    try:
        info = os.lstat(path)
    except OSError as error:
        raise IsoStagingSafetyError("The selected WIM/ESD disappeared") from error
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
        raise IsoStagingSafetyError("The selected WIM/ESD is no longer a safe regular file")
    return (
        info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
        info.st_ctime_ns, info.st_nlink,
    )


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
                "modified_ns": entry.modified_ns,
            }
            for entry in entries
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _verify_complete_source_catalog(
    image: Path,
    expected_entries: tuple[ArchiveEntry, ...],
    scanner: CatalogScanner,
    cancel_check: Callable[[], None] | None,
    archive_namespace: SevenZipNamespace | None = None,
) -> tuple[FileIdentity, SevenZipNamespace]:
    """Relist the bound source and prove the caller supplied its full catalog."""

    try:
        source = image.expanduser().resolve(strict=True)
        descriptor = os.open(
            source,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise IsoStagingSafetyError(
            "The ISO source could not be opened for catalog verification"
        ) from error
    try:
        try:
            before = os.fstat(descriptor)
        except OSError as error:
            raise IsoStagingSafetyError(
                "The ISO source could not be bound for catalog verification"
            ) from error
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
            raise IsoStagingSafetyError(
                "The ISO source must be a non-empty regular file"
            )
        if cancel_check is not None:
            cancel_check()
        candidates = (
            (archive_namespace,)
            if archive_namespace is not None
            else (SevenZipNamespace.UDF, SevenZipNamespace.ISO9660)
        )
        members: list[ImageMember] = []
        complete = False
        selected_namespace: SevenZipNamespace | None = None
        try:
            for candidate in candidates:
                if type(candidate) is not SevenZipNamespace:
                    raise TypeError("invalid optical namespace")
                members, complete = scanner(
                    source,
                    image_fd=descriptor,
                    namespace=candidate,
                    cancel_check=cancel_check,
                )
                if complete is True and type(members) is list and members:
                    selected_namespace = candidate
                    break
        except (OSError, TypeError, ValueError) as error:
            raise IsoStagingSafetyError(
                "The ISO source catalog could not be verified"
            ) from error
        try:
            after = os.fstat(descriptor)
        except OSError as error:
            raise IsoStagingSafetyError(
                "The ISO source catalog binding could not be rechecked"
            ) from error
        if (
            before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns,
        ) != (
            after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns,
        ):
            raise IsoStagingSafetyError(
                "The ISO source changed during catalog verification"
            )
    finally:
        os.close(descriptor)
    if (
        complete is not True
        or type(members) is not list
        or type(selected_namespace) is not SevenZipNamespace
    ):
        raise IsoStagingSafetyError(
            "The complete ISO source catalog could not be verified"
        )
    kinds = {
        "file": EntryKind.FILE,
        "directory": EntryKind.DIRECTORY,
        "symlink": EntryKind.SYMLINK,
    }
    try:
        scanned_entries = validate_extraction_entries(tuple(
            ArchiveEntry(
                member.path,
                member.size,
                kinds[member.kind],
                member.link_target or None,
                member.modified_ns,
            )
            for member in members
            if type(member) is ImageMember
        ))
    except (KeyError, UnsafeArchiveError, ValueError) as error:
        raise IsoStagingSafetyError(
            "The relisted ISO source catalog is unsafe"
        ) from error
    if len(scanned_entries) != len(members) or scanned_entries != expected_entries:
        raise IsoStagingSafetyError(
            "The supplied ISO catalog does not match the complete bound source catalog"
        )
    return (
        (
            before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns,
        ),
        selected_namespace,
    )


def _merge_effective_catalog(
    entries: Sequence[ArchiveEntry],
    overlay: ZipOverlayPlan | None,
) -> tuple[tuple[ArchiveEntry, ...], tuple[ArchiveEntry, ...]]:
    """Return the final catalog and archive-member-aligned extraction targets."""

    if overlay is None:
        return tuple(entries), ()
    if not isinstance(overlay, ZipOverlayPlan):
        raise IsoStagingSafetyError("The ZIP overlay plan is invalid")
    try:
        merged = merge_additive_overlay_entries(
            entries, (member.entry for member in overlay.members),
        )
    except (UnsafeArchiveError, ValueError) as error:
        raise IsoStagingSafetyError(str(error)) from error
    if len(merged.overlay_targets) != len(overlay.members):
        raise IsoStagingSafetyError(
            "The ZIP overlay is not bound to the effective catalog"
        )
    return merged.merged_entries, merged.overlay_targets


def _embedded_archive_entries(
    embedded: EmbeddedFatImage | None,
) -> tuple[ArchiveEntry, ...]:
    if embedded is None:
        return ()
    return tuple(
        ArchiveEntry(
            entry.path,
            entry.size,
            EntryKind.DIRECTORY if entry.is_directory else EntryKind.FILE,
        )
        for entry in embedded.entries
    )


def _merge_embedded_catalog(
    entries: Sequence[ArchiveEntry],
    embedded: EmbeddedFatImage | None,
) -> tuple[
    tuple[ArchiveEntry, ...],
    tuple[ArchiveEntry, ...],
    tuple[str, ...],
    int,
]:
    embedded_entries = _embedded_archive_entries(embedded)
    if not embedded_entries:
        return tuple(entries), (), (), 0
    base_file_keys = {
        _case_key(entry.path)
        for entry in entries if entry.kind is EntryKind.FILE
    }
    embedded_file_keys = {
        _case_key(entry.path)
        for entry in embedded_entries if entry.kind is EntryKind.FILE
    }
    colliding_files = base_file_keys & embedded_file_keys
    if embedded_file_keys and colliding_files == embedded_file_keys:
        # Optical bridge images commonly expose fallback EFI paths both in the
        # complete UDF tree and in their El Torito FAT image.  When every
        # embedded file path is already covered, prefer the cataloged UDF tree
        # and materialize none of the optical-only copy.  A mixed
        # collision/addition set remains ambiguous and is rejected below.
        return tuple(entries), (), (), 0
    try:
        merged = merge_additive_embedded_entries(entries, embedded_entries)
    except (UnsafeArchiveError, ValueError) as error:
        raise IsoStagingSafetyError(str(error)) from error
    if len(merged.overlay_targets) != len(embedded_entries):
        raise IsoStagingSafetyError(
            "The embedded boot-image tree is not bound to its staging targets"
        )
    content_bytes = sum(
        entry.size for entry in merged.overlay_entries
        if entry.kind is EntryKind.FILE
    )
    return (
        merged.merged_entries,
        embedded_entries,
        tuple(entry.path for entry in merged.overlay_targets),
        content_bytes,
    )


def _validate_embedded_source(
    image: Path,
    image_identity: FileIdentity,
    embedded: EmbeddedFatImage | None,
    cancel_check: Callable[[], None] | None,
) -> None:
    if embedded is None:
        return
    if not isinstance(embedded, EmbeddedFatImage):
        raise IsoStagingSafetyError("The embedded boot-image plan is invalid")
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(image, flags)
    except OSError as error:
        raise IsoStagingSafetyError(
            "The ISO could not be opened for embedded boot-image validation"
        ) from error
    try:
        status = os.fstat(descriptor)
        observed = (
            status.st_dev,
            status.st_ino,
            status.st_size,
            status.st_mtime_ns,
            status.st_ctime_ns,
        )
        if not stat.S_ISREG(status.st_mode) or observed != image_identity:
            raise IsoStagingSafetyError(
                "The ISO identity changed before embedded boot-image validation"
            )
        expected_source = embedded.source_identity
        if observed != (
            expected_source.device,
            expected_source.inode,
            expected_source.size,
            expected_source.modified_ns,
            expected_source.changed_ns,
        ):
            raise IsoStagingSafetyError(
                "The embedded boot-image plan belongs to another ISO identity"
            )
        catalog = inspect_eltorito_file(image, image_fd=descriptor)
        validate_uefi_eltorito_fat(
            descriptor,
            catalog,
            embedded,
            cancel_check=cancel_check,
        )
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != observed:
            raise IsoStagingSafetyError(
                "The ISO changed during embedded boot-image validation"
            )
    except (ElToritoNotFound, ElToritoError, FatImageError, OSError) as error:
        raise IsoStagingSafetyError(str(error)) from error
    finally:
        os.close(descriptor)


def _validate_overlay(
    overlay: ZipOverlayPlan | None,
    *,
    cancel_check: Callable[[], None] | None = None,
) -> None:
    if overlay is None:
        return
    if not isinstance(overlay, ZipOverlayPlan):
        raise IsoStagingSafetyError("The ZIP overlay plan is invalid")
    try:
        validate_zip_overlay_plan(overlay, cancel_check=cancel_check)
    except (ZipOverlayChanged, ZipOverlaySafetyError) as error:
        raise IsoStagingSafetyError(str(error)) from error
    except ZipOverlayDeadlineExceeded as error:
        raise IsoStagingError(str(error)) from error
    except ZipOverlayError as error:
        raise IsoStagingError(str(error)) from error


def _validate_staging_scalar_bindings(plan: IsoStagingPlan) -> None:
    if type(plan.archive_namespace) is not SevenZipNamespace:
        raise IsoStagingSafetyError(
            "The staging plan optical namespace binding is invalid"
        )
    for name, value in (
        ("content bytes", plan.content_bytes),
        ("required free bytes", plan.required_free_bytes),
        ("Syslinux content bytes", plan.syslinux_content_bytes),
    ):
        if type(value) is not int or value < 0:
            raise IsoStagingSafetyError(f"The staging plan {name} value is invalid")
    identities = (
        ("image identity", plan.image_identity, 5),
        ("destination parent identity", plan.destination_parent_identity, 2),
    )
    for name, identity, length in identities:
        if (
            not isinstance(identity, tuple)
            or len(identity) != length
            or any(type(value) is not int or value < 0 for value in identity)
            or identity[1] <= 0
        ):
            raise IsoStagingSafetyError(f"The staging plan {name} is invalid")
    if plan.image_identity[2] <= 0:
        raise IsoStagingSafetyError("The staging plan image identity is invalid")
    for name, digest in (
        ("catalog digest", plan.catalog_digest),
        ("effective catalog digest", plan.effective_catalog_digest),
        ("staged catalog digest", plan.staged_catalog_digest),
    ):
        if (
            type(digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise IsoStagingSafetyError(f"The staging plan {name} is invalid")


def _is_transitional_windows_plan(plan: WritePlan) -> bool:
    if type(plan) is not WritePlan:
        return False
    layout = plan.layout
    return (
        plan.firmware_target is FirmwareTarget.BOTH
        and layout is not None
        and layout.partition_table is PartitionTable.MBR
        and layout.main_filesystem is FileSystem.FAT32
        and layout.partition_count == 1
        and layout.boot_partition_filesystem is None
        and layout.bios_bootable
        and layout.uefi_bootable
        and layout.main_partition_active
        and layout.boot_strategy is BootStrategy.WINDOWS_BOOTMGR_FAT32
        and plan.blockers == (_WINDOWS_DUAL_TRANSITIONAL_BLOCKER,)
    )


def _validate_transitional_windows_staging_scope(
    write_plan: WritePlan,
    *,
    overlay: object,
    embedded_fat: object,
    windows_customization: object,
    windows_bootex: object,
    syslinux_c32_bundle: object,
    syslinux_payload_bundle: object,
) -> None:
    """Keep the legacy blocked-plan exception inside its reviewed profile."""

    if _is_transitional_windows_plan(write_plan) and any(
        value is not None
        for value in (
            overlay,
            embedded_fat,
            windows_customization,
            windows_bootex,
            syslinux_c32_bundle,
            syslinux_payload_bundle,
        )
    ):
        raise IsoStagingSafetyError(
            "The transitional Windows BIOS+UEFI profile does not compose with "
            "overlays, customization, embedded images, BootEx, or Syslinux",
        )


def _validate_write_plan(plan: WritePlan, entries: Sequence[ArchiveEntry]) -> str | None:
    if type(plan) is not WritePlan:
        raise IsoStagingSafetyError("A WritePlan is required")
    layout = plan.layout
    if plan.mode is not WriteMode.EXTRACTED_ISO:
        raise IsoStagingSafetyError("ISO staging requires extracted-ISO write mode")
    uefi_fat32_layout = (
        layout is not None
        and layout.main_filesystem is FileSystem.FAT32
        and layout.partition_count == 1
        and layout.boot_strategy is BootStrategy.IMAGE_NATIVE
    )
    windows_dual_layout = (
        layout is not None
        and plan.firmware_target is FirmwareTarget.BOTH
        and layout.partition_table is PartitionTable.MBR
        and layout.main_filesystem is FileSystem.FAT32
        and layout.partition_count == 1
        and layout.boot_partition_filesystem is None
        and layout.bios_bootable
        and layout.uefi_bootable
        and layout.main_partition_active
        and layout.boot_strategy is BootStrategy.WINDOWS_BOOTMGR_FAT32
    )
    transitional_windows_plan = _is_transitional_windows_plan(plan)
    if not plan.executable and not transitional_windows_plan:
        detail = plan.blockers[0] if plan.blockers else "the plan is not executable"
        raise IsoStagingSafetyError(f"Refusing a non-executable write plan: {detail}")
    if (
        plan.firmware_target is not FirmwareTarget.UEFI_ONLY
        and not windows_dual_layout
    ):
        raise IsoStagingSafetyError(
            "ISO staging requires an explicit supported firmware profile",
        )
    fat32_layout = uefi_fat32_layout or windows_dual_layout
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
        or (layout.bios_bootable and not windows_dual_layout)
        or not (fat32_layout or uefi_ntfs_layout)
    ):
        raise IsoStagingSafetyError(
            "ISO staging requires the supported UEFI/FAT32 or UEFI:NTFS layout"
        )
    if (
        not plan.content_constraints_checked
        or (plan.blockers and not transitional_windows_plan)
    ):
        raise IsoStagingSafetyError("The write plan has not passed all content checks")

    files = tuple(entry for entry in entries if entry.kind is EntryKind.FILE)
    content_bytes = sum(entry.size for entry in files)
    if plan.minimum_content_bytes != content_bytes:
        raise IsoStagingSafetyError("The write plan is not bound to this ISO catalog")
    oversized = (
        tuple(entry for entry in files if entry.size > FAT32_MAX_FILE_SIZE)
        if fat32_layout else ()
    )
    install_sources = tuple(
        entry for entry in files
        if _is_install_wim_path(entry.path)
        or entry.path.casefold() == "sources/install.esd"
    )
    eligible = tuple(
        entry for entry in oversized
        if len(install_sources) == 1
        and entry.path.casefold() == "sources/install.wim"
    )
    if any(entry not in eligible for entry in oversized):
        raise IsoStagingSafetyError(
            "The ISO contains a file that cannot be safely transformed for FAT32"
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


def _validate_distro_iso_policy(entries: tuple[ArchiveEntry, ...]) -> None:
    """Recheck the identity-bound base ISO catalog before reconstruction."""

    members = tuple(
        ImageMember(
            entry.path,
            entry.size,
            entry.kind.value,
            entry.link_target or "",
            entry.modified_ns,
        )
        for entry in entries
    )
    try:
        exclusion = match_distro_member_exclusion(members)
    except DistroPolicyError as error:
        raise IsoStagingSafetyError(
            f"ISO-mode compatibility evidence is unsafe: {error}"
        ) from error
    if exclusion is not None:
        raise IsoStagingSafetyError(exclusion.reason)


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
    except (ET.ParseError, UnicodeError, ValueError) as error:
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
    wim_sources = tuple(
        entry for entry in entries
        if entry.kind is EntryKind.FILE and _is_install_wim_path(entry.path)
    )
    canonical_esd = tuple(
        entry for entry in entries
        if entry.kind is EntryKind.FILE
        and entry.path.casefold() == "sources/install.esd"
    )
    if len(wim_sources) > 4:
        raise IsoStagingSafetyError(
            "Windows image selection supports at most four install.wim sources"
        )
    if (
        selection.source_name.casefold() == "sources/install.esd"
        and len(wim_sources) + len(canonical_esd) != 1
    ):
        raise IsoStagingSafetyError(
            "A canonical install.esd can be selected only when it is the sole install source"
        )
    matches = tuple(
        entry for entry in entries
        if entry.kind is EntryKind.FILE and entry.path == selection.source_name
    )
    if len(matches) != 1:
        raise IsoStagingSafetyError(
            "The selected Windows image must occur exactly once in the ISO catalog"
        )
    source = matches[0]
    if source.size != selection.source_size:
        raise IsoStagingSafetyError(
            "The selected Windows image is not bound to this ISO catalog"
        )


def _fixed_wim_resolver(path: str) -> Callable[[str], str | None]:
    return lambda name: path if name == "wimlib-imagex" else None


def _bootex_architecture(value: str) -> str:
    normalized = value.casefold() if isinstance(value, str) else ""
    if normalized in {"amd64", "x64"}:
        return "x64"
    if normalized == "arm64":
        return "arm64"
    raise IsoStagingSafetyError(
        "Windows 2023-generation boot media requires x64 or ARM64 Windows"
    )


def _bootex_wim_source(entries: Sequence[ArchiveEntry]) -> ArchiveEntry:
    exact = tuple(
        entry for entry in entries
        if entry.kind is EntryKind.FILE and entry.path == "sources/boot.wim"
    )
    aliases = tuple(
        entry for entry in entries
        if entry.kind is EntryKind.FILE
        and entry.path.casefold() == "sources/boot.wim"
    )
    if len(exact) != 1 or aliases != exact:
        raise IsoStagingSafetyError(
            "Windows 2023-generation boot media requires one canonical "
            "sources/boot.wim"
        )
    return exact[0]


def _validate_bootex_layout(
    write_plan: WritePlan,
    overlay: ZipOverlayPlan | None,
    syslinux_c32_bundle: BoundBootBundle | None,
) -> None:
    layout = write_plan.layout
    if (
        layout is None
        or layout.main_filesystem is not FileSystem.FAT32
        or layout.partition_count != 1
        or layout.boot_strategy is not BootStrategy.IMAGE_NATIVE
    ):
        raise IsoStagingSafetyError(
            "Windows 2023-generation boot files initially require direct "
            "UEFI/FAT32 ISO mode; UEFI:NTFS uses a separate 2011-CA bridge"
        )
    if overlay is not None:
        raise IsoStagingSafetyError(
            "Windows 2023-generation boot files do not yet compose with ZIP overlays"
        )
    if syslinux_c32_bundle is not None:
        raise IsoStagingSafetyError(
            "Windows 2023-generation boot files do not compose with Syslinux"
        )


_WINDOWS_ANSWER_FILE_PATHS = frozenset({
    "autounattend.xml",
    "sources/$oem$/$$/panther/unattend.xml",
})


def _existing_windows_answer_file(
    entries: Sequence[ArchiveEntry],
) -> str | None:
    """Return a known Windows Setup answer-file path, case-insensitively."""
    for entry in entries:
        path = PurePosixPath(entry.path).as_posix()
        if path.casefold() in _WINDOWS_ANSWER_FILE_PATHS:
            return path
    return None


def _status_identity(info: os.stat_result) -> FileIdentity:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_bound_syslinux_inputs(
    image: Path,
    image_identity: FileIdentity,
    entries: tuple[ArchiveEntry, ...],
    module_bundle: BoundBootBundle,
    payload_bundle: BoundBootBundle,
    *,
    analysis_entries: tuple[ArchiveEntry, ...] | None = None,
    cancel_check: Callable[[], None] | None = None,
) -> tuple[
    BootloaderAnalysis,
    dict[str, bytes],
    dict[str, bytes],
    SyslinuxStagingPlan,
]:
    """Rebuild the Syslinux decision from one identity-bound ISO descriptor."""

    descriptor = -1
    deadline = time.monotonic() + _SYSLINUX_BIND_TIMEOUT_SECONDS
    try:
        if cancel_check is not None:
            cancel_check()
        descriptor = os.open(
            image,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _status_identity(opened) != image_identity:
            raise IsoStagingSafetyError(
                "The ISO changed before Syslinux staging was bound"
            )
        analysis_catalog = entries if analysis_entries is None else analysis_entries
        analysis_paths = syslinux_staging_analysis_paths(analysis_catalog)
        analysis_sizes = {
            entry.path: entry.size
            for entry in analysis_catalog
            if entry.path in analysis_paths
        }

        def read_analysis_member(_image: Path, member: str) -> bytes:
            remaining_read = deadline - time.monotonic()
            if remaining_read <= 0:
                raise TimeoutError(
                    "Syslinux staging reached its overall time limit"
                )
            expected_size = analysis_sizes.get(member)
            if expected_size is None:
                raise OSError("The Isolinux candidate left the bound base catalog")
            return read_archive_member_with_7z(
                image,
                member,
                timeout=min(15.0, remaining_read),
                image_fd=descriptor,
                cancel_check=cancel_check,
                max_bytes=expected_size,
            )

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Syslinux staging reached its overall time limit")
        analysis = analyze_iso_bootloaders(
            image,
            analysis_paths,
            reader=read_analysis_member,
            timeout=min(30.0, remaining),
            image_fd=descriptor,
            cancel_check=cancel_check,
        )
        read_paths = syslinux_staging_read_paths(entries, analysis)
        entry_by_path = {entry.path: entry for entry in entries}
        base_paths = {
            entry.path
            for entry in analysis_catalog
            if entry.kind is EntryKind.FILE
        }
        if any(path not in base_paths for path in read_paths):
            raise IsoStagingSafetyError(
                "The initial Syslinux profile requires all evidence to originate "
                "in the base ISO"
            )
        payloads: dict[str, bytes] = {}
        for path in read_paths:
            if cancel_check is not None:
                cancel_check()
            entry = entry_by_path.get(path)
            if entry is None or entry.kind is not EntryKind.FILE:
                raise IsoStagingSafetyError(
                    "The Syslinux read set is not bound to the effective ISO catalog"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    "Syslinux staging reached its overall time limit"
                )
            payload = read_archive_member_with_7z(
                image,
                path,
                timeout=min(15.0, remaining),
                image_fd=descriptor,
                cancel_check=cancel_check,
                max_bytes=entry.size,
            )
            if len(payload) != entry.size:
                raise IsoStagingSafetyError(
                    f"The Syslinux source member {path!r} changed size"
                )
            payloads[path] = payload
        final = os.fstat(descriptor)
        if _status_identity(final) != image_identity:
            raise IsoStagingSafetyError(
                "The ISO changed while Syslinux staging was bound"
            )
        existing_files = {
            path: data for path, data in payloads.items()
            if PurePosixPath(path).name.casefold().endswith(".c32")
        }
        source_files = {
            path: data for path, data in payloads.items()
            if path not in existing_files
        }
        staging = plan_syslinux_staging(
            entries,
            analysis,
            module_bundle,
            payload_bundle,
            source_files=source_files,
            existing_files=existing_files,
        )
        return analysis, source_files, existing_files, staging
    except IsoStagingSafetyError:
        raise
    except (OSError, TimeoutError, ValueError, SyslinuxStagingError) as error:
        raise IsoStagingSafetyError(
            f"Could not bind the Syslinux staging profile: {error}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _merge_syslinux_staging_catalog(
    entries: tuple[ArchiveEntry, ...],
    staging: SyslinuxStagingPlan | None,
) -> tuple[tuple[ArchiveEntry, ...], int]:
    if staging is None:
        return entries, 0
    generated = tuple(
        ArchiveEntry(item.path, len(item.data))
        for item in staging.additions
    )
    try:
        merged = merge_additive_generated_entries(entries, generated)
    except (UnsafeArchiveError, ValueError) as error:
        raise IsoStagingSafetyError(str(error)) from error
    added_bytes = sum(item.size for item in merged.overlay_entries)
    if added_bytes != sum(len(item.data) for item in staging.additions):
        raise IsoStagingSafetyError(
            "The generated Syslinux byte accounting is inconsistent"
        )
    return merged.merged_entries, added_bytes


def build_iso_staging_plan(
    image: Path,
    destination: Path,
    entries: Sequence[ArchiveEntry],
    write_plan: WritePlan,
    *,
    seven_zip: str | None = None,
    overlay: ZipOverlayPlan | None = None,
    embedded_fat: EmbeddedFatImage | None = None,
    cancel_check: Callable[[], None] | None = None,
    windows_customization: WindowsCustomization | None = None,
    windows_architecture: str = "amd64",
    windows_bootex: WindowsBootExOptions | None = None,
    wimlib_resolver: Callable[[], str] = resolve_wimlib,
    bootex_source_binder: BootExSourceBinder = bind_bootex_source,
    syslinux_c32_bundle: BoundBootBundle | None = None,
    syslinux_payload_bundle: BoundBootBundle | None = None,
) -> IsoStagingPlan:
    """Bind validated ISO/overlay catalogs and a write plan to a new output path.

    The two Syslinux bundles are backend-only, already-bound data inputs.  They
    must be supplied together.  This function never downloads them, authorizes
    BIOS mode, maps sectors, patches boot code, or touches a device.
    """

    if cancel_check is not None:
        cancel_check()
    if (syslinux_c32_bundle is None) != (syslinux_payload_bundle is None):
        raise IsoStagingSafetyError(
            "The Syslinux C32 and BIOS payload bundles must be supplied together"
        )
    _validate_transitional_windows_staging_scope(
        write_plan,
        overlay=overlay,
        embedded_fat=embedded_fat,
        windows_customization=windows_customization,
        windows_bootex=windows_bootex,
        syslinux_c32_bundle=syslinux_c32_bundle,
        syslinux_payload_bundle=syslinux_payload_bundle,
    )
    try:
        safe_entries = validate_extraction_entries(entries)
    except (UnsafeArchiveError, ValueError) as error:
        raise IsoStagingSafetyError(str(error)) from error
    if not safe_entries:
        raise IsoStagingSafetyError("The ISO member catalog is empty")
    _validate_distro_iso_policy(safe_entries)
    (
        base_with_embedded_entries,
        embedded_entries,
        embedded_targets,
        embedded_content_bytes,
    ) = _merge_embedded_catalog(safe_entries, embedded_fat)
    _validate_overlay(overlay, cancel_check=cancel_check)
    effective_entries, _overlay_targets = _merge_effective_catalog(
        base_with_embedded_entries, overlay,
    )
    wim_source = _validate_write_plan(write_plan, effective_entries)
    _validate_catalog_shape(effective_entries, wim_source)
    wim_selection = (
        windows_customization.install_image
        if windows_customization is not None else None
    )
    _validate_wim_selection_catalog(effective_entries, wim_selection)

    bound_bootex_options: WindowsBootExOptions | None = None
    bound_bootex_source: BootExSourceBinding | None = None
    boot_wim_source: str | None = None
    bootex_architecture: str | None = None
    if windows_bootex is not None:
        if not isinstance(windows_bootex, WindowsBootExOptions):
            raise IsoStagingSafetyError(
                "Windows 2023-generation boot options are invalid"
            )
        if windows_bootex.enabled:
            if not windows_bootex.acknowledge_firmware_compatibility:
                raise IsoStagingSafetyError(
                    "Windows 2023-generation boot files require explicit firmware "
                    "compatibility acknowledgment"
                )
            _validate_bootex_layout(write_plan, overlay, syslinux_c32_bundle)
            boot_wim_source = _bootex_wim_source(effective_entries).path
            bootex_architecture = _bootex_architecture(windows_architecture)
            bound_bootex_options = windows_bootex

    answer_file: str | None = None
    bound_windows_customization: WindowsCustomization | None = None
    bound_windows_architecture: str | None = None
    if windows_customization is not None and windows_customization.enabled:
        existing_answer_file = _existing_windows_answer_file(effective_entries)
        if existing_answer_file is not None:
            raise IsoStagingSafetyError(
                f"The ISO already contains the Windows answer file "
                f"{existing_answer_file}; it will not be combined with or overwritten"
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
            answer_path = answer_file_install_path(
                answer_file, windows_architecture,
            )
        except ValueError as error:
            raise IsoStagingSafetyError(str(error)) from error
        install_source_count = sum(
            entry.kind is EntryKind.FILE and (
                _is_install_wim_path(entry.path)
                or entry.path.casefold() == "sources/install.esd"
            )
            for entry in effective_entries
        )
        if wim_selection is not None:
            selected_is_wim = _is_install_wim_path(wim_selection.source_name)
            if answer_path is not None and answer_path != wim_selection.source_name:
                raise IsoStagingSafetyError(
                    "The Windows answer file path does not match the selected source"
                )
            if (
                selected_is_wim
                and (
                    install_source_count > 1
                    or wim_selection.source_name.casefold() != "sources/install.wim"
                )
                and answer_path is None
            ):
                raise IsoStagingSafetyError(
                    "A nested or multi-source Windows image requires an explicit "
                    "answer-file WIM path"
                )
        bound_windows_customization = windows_customization
        bound_windows_architecture = windows_architecture

    source_catalog_identity, archive_namespace = _verify_complete_source_catalog(
        image, safe_entries, scan_image_contents, cancel_check,
    )
    try:
        extraction = build_extraction_plan(
            image,
            destination,
            safe_entries,
            seven_zip=seven_zip,
            archive_namespace=archive_namespace,
        )
    except ExtractionUnavailable as error:
        raise IsoStagingUnavailable(str(error)) from error
    except (ExtractionSafetyError, ExtractionError, OSError) as error:
        raise IsoStagingSafetyError(str(error)) from error
    if source_catalog_identity != extraction.image_identity:
        raise IsoStagingSafetyError(
            "The ISO source identity changed during catalog binding"
        )
    if bound_bootex_options is not None:
        assert bootex_architecture is not None
        try:
            bound_bootex_source = bootex_source_binder(
                extraction.image,
                architecture=bootex_architecture,
                cancel_check=cancel_check,
            )
            validate_bootex_source_binding(bound_bootex_source)
        except BootExError as error:
            raise IsoStagingSafetyError(str(error)) from error
        if (
            bound_bootex_source.source_iso.path != extraction.image
            or bound_bootex_source.source_iso.identity[:5]
            != extraction.image_identity
            or bound_bootex_source.profile.architecture != bootex_architecture
        ):
            raise IsoStagingSafetyError(
                "The Windows 2023-generation source binding does not match this ISO"
            )
    _validate_embedded_source(
        extraction.image,
        extraction.image_identity,
        embedded_fat,
        cancel_check,
    )

    syslinux_analysis: BootloaderAnalysis | None = None
    syslinux_staging: SyslinuxStagingPlan | None = None
    if syslinux_c32_bundle is not None:
        assert syslinux_payload_bundle is not None
        (
            syslinux_analysis,
            _syslinux_sources,
            _syslinux_existing,
            syslinux_staging,
        ) = _read_bound_syslinux_inputs(
            extraction.image,
            extraction.image_identity,
            effective_entries,
            syslinux_c32_bundle,
            syslinux_payload_bundle,
            analysis_entries=safe_entries,
            cancel_check=cancel_check,
        )
    staged_entries, syslinux_content_bytes = _merge_syslinux_staging_catalog(
        effective_entries,
        syslinux_staging,
    )

    wimlib_imagex: str | None = None
    if (
        wim_source is not None
        or wim_selection is not None
        or bound_bootex_source is not None
    ):
        try:
            wimlib_imagex = wimlib_resolver()
            # Reuse wim.py's exact trusted-path validation instead of accepting
            # an arbitrary executable-shaped string from an injected resolver.
            wimlib_imagex = resolve_wimlib(_fixed_wim_resolver(wimlib_imagex))
        except WimToolUnavailable as error:
            raise IsoStagingUnavailable(str(error)) from error

    split_extra = next(
        (entry.size for entry in effective_entries if entry.path == wim_source), 0,
    )
    content_bytes = sum(
        entry.size for entry in staged_entries if entry.kind is EntryKind.FILE
    )
    overlay_bytes = overlay.content_bytes if overlay is not None else 0
    if (
        content_bytes
        != (
            extraction.content_bytes
            + embedded_content_bytes
            + overlay_bytes
            + syslinux_content_bytes
        )
    ):
        raise IsoStagingSafetyError(
            "The embedded/overlay expanded-size accounting is inconsistent"
        )
    bootex_extra = _BOOTEX_EXTRA_SPACE if bound_bootex_source is not None else 0
    required_free = (
        content_bytes + split_extra + bootex_extra + OUTPUT_SPACE_RESERVE
    )
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
        content_bytes=content_bytes,
        required_free_bytes=required_free,
        wim_source=wim_source,
        wim_selection=wim_selection,
        wimlib_imagex=wimlib_imagex,
        windows_customization=bound_windows_customization,
        windows_architecture=bound_windows_architecture,
        autounattend_xml=answer_file,
        archive_namespace=extraction.archive_namespace,
        overlay=overlay,
        effective_entries=effective_entries,
        effective_catalog_digest=_catalog_digest(effective_entries),
        _catalog_witness=_CatalogWitness(
            _CATALOG_WITNESS_TOKEN,
            extraction.image_identity,
            _catalog_digest(safe_entries),
            extraction.archive_namespace,
        ),
        embedded_fat=embedded_fat,
        embedded_entries=embedded_entries,
        embedded_targets=embedded_targets,
        base_with_embedded_entries=base_with_embedded_entries,
        base_with_embedded_catalog_digest=_catalog_digest(
            base_with_embedded_entries,
        ),
        embedded_content_bytes=embedded_content_bytes,
        syslinux_analysis=syslinux_analysis,
        syslinux_c32_bundle=syslinux_c32_bundle,
        syslinux_payload_bundle=syslinux_payload_bundle,
        syslinux_staging=syslinux_staging,
        syslinux_content_bytes=syslinux_content_bytes,
        staged_entries=staged_entries,
        staged_catalog_digest=_catalog_digest(staged_entries),
        windows_bootex_options=bound_bootex_options,
        windows_bootex_source=bound_bootex_source,
        windows_boot_wim_source=boot_wim_source,
    )


def validate_iso_staging_plan(
    plan: IsoStagingPlan,
    *,
    cancel_check: Callable[[], None] | None = None,
) -> None:
    """Rebuild all externally observable planning facts for a frozen plan."""

    if cancel_check is not None:
        cancel_check()
    if type(plan) is not IsoStagingPlan:
        raise IsoStagingSafetyError("An IsoStagingPlan is required")
    _validate_staging_scalar_bindings(plan)
    _validate_transitional_windows_staging_scope(
        plan.write_plan,
        overlay=plan.overlay,
        embedded_fat=plan.embedded_fat,
        windows_customization=plan.windows_customization,
        windows_bootex=plan.windows_bootex_options,
        syslinux_c32_bundle=plan.syslinux_c32_bundle,
        syslinux_payload_bundle=plan.syslinux_payload_bundle,
    )
    try:
        entries = validate_extraction_entries(plan.entries)
    except (UnsafeArchiveError, ValueError) as error:
        raise IsoStagingSafetyError(str(error)) from error
    if entries != plan.entries or _catalog_digest(entries) != plan.catalog_digest:
        raise IsoStagingSafetyError("The ISO catalog binding is invalid")
    _validate_distro_iso_policy(entries)
    _validate_embedded_source(
        plan.image,
        plan.image_identity,
        plan.embedded_fat,
        cancel_check,
    )
    (
        base_with_embedded_entries,
        embedded_entries,
        embedded_targets,
        embedded_content_bytes,
    ) = _merge_embedded_catalog(entries, plan.embedded_fat)
    if (
        embedded_entries != plan.embedded_entries
        or embedded_targets != plan.embedded_targets
        or embedded_content_bytes != plan.embedded_content_bytes
        or base_with_embedded_entries != plan.base_with_embedded_entries
        or _catalog_digest(base_with_embedded_entries)
        != plan.base_with_embedded_catalog_digest
    ):
        raise IsoStagingSafetyError(
            "The embedded boot-image catalog binding is invalid"
        )
    _validate_overlay(plan.overlay, cancel_check=cancel_check)
    effective_entries, _overlay_targets = _merge_effective_catalog(
        base_with_embedded_entries, plan.overlay,
    )
    if (
        effective_entries != plan.effective_entries
        or _catalog_digest(effective_entries) != plan.effective_catalog_digest
    ):
        raise IsoStagingSafetyError("The effective staging catalog binding is invalid")
    wim_source = _validate_write_plan(plan.write_plan, effective_entries)
    _validate_catalog_shape(effective_entries, wim_source)
    _validate_wim_selection_catalog(effective_entries, plan.wim_selection)
    if wim_source != plan.wim_source:
        raise IsoStagingSafetyError("The plan contains inconsistent WIM transformation data")

    syslinux_fields = (
        plan.syslinux_analysis,
        plan.syslinux_c32_bundle,
        plan.syslinux_payload_bundle,
        plan.syslinux_staging,
    )
    if all(value is None for value in syslinux_fields):
        if plan.syslinux_content_bytes != 0:
            raise IsoStagingSafetyError(
                "The staging plan has unbound Syslinux byte accounting"
            )
        rebuilt_syslinux: SyslinuxStagingPlan | None = None
    elif any(value is None for value in syslinux_fields):
        raise IsoStagingSafetyError(
            "The staging plan contains an incomplete Syslinux binding"
        )
    else:
        if (
            type(plan.syslinux_analysis) is not BootloaderAnalysis
            or type(plan.syslinux_c32_bundle) is not BoundBootBundle
            or type(plan.syslinux_payload_bundle) is not BoundBootBundle
            or type(plan.syslinux_staging) is not SyslinuxStagingPlan
        ):
            raise IsoStagingSafetyError(
                "The staging plan contains invalid Syslinux inputs"
            )
        assert plan.syslinux_analysis is not None
        assert plan.syslinux_c32_bundle is not None
        assert plan.syslinux_payload_bundle is not None
        assert plan.syslinux_staging is not None
        (
            fresh_analysis,
            fresh_sources,
            fresh_existing,
            rebuilt_syslinux,
        ) = _read_bound_syslinux_inputs(
            plan.image,
            plan.image_identity,
            effective_entries,
            plan.syslinux_c32_bundle,
            plan.syslinux_payload_bundle,
            analysis_entries=entries,
            cancel_check=cancel_check,
        )
        if fresh_analysis != plan.syslinux_analysis:
            raise IsoStagingSafetyError(
                "The Syslinux bootloader analysis changed"
            )
        try:
            validate_syslinux_staging_plan(
                plan.syslinux_staging,
                effective_entries,
                fresh_analysis,
                plan.syslinux_c32_bundle,
                plan.syslinux_payload_bundle,
                source_files=fresh_sources,
                existing_files=fresh_existing,
            )
        except SyslinuxStagingError as error:
            raise IsoStagingSafetyError(str(error)) from error
        if rebuilt_syslinux != plan.syslinux_staging:
            raise IsoStagingSafetyError(
                "The Syslinux private-tree plan changed"
            )
    staged_entries, syslinux_content_bytes = _merge_syslinux_staging_catalog(
        effective_entries,
        rebuilt_syslinux,
    )
    if (
        staged_entries != plan.staged_entries
        or _catalog_digest(staged_entries) != plan.staged_catalog_digest
        or syslinux_content_bytes != plan.syslinux_content_bytes
    ):
        raise IsoStagingSafetyError(
            "The staged catalog binding is invalid or conflicts with generated content"
        )
    bootex_fields = (
        plan.windows_bootex_options,
        plan.windows_bootex_source,
        plan.windows_boot_wim_source,
    )
    if all(value is None for value in bootex_fields):
        pass
    elif any(value is None for value in bootex_fields):
        raise IsoStagingSafetyError(
            "The staging plan contains an incomplete Windows BootEx binding"
        )
    else:
        if (
            not isinstance(plan.windows_bootex_options, WindowsBootExOptions)
            or not plan.windows_bootex_options.enabled
            or not plan.windows_bootex_options.acknowledge_firmware_compatibility
            or not isinstance(plan.windows_bootex_source, BootExSourceBinding)
            or plan.windows_boot_wim_source != "sources/boot.wim"
        ):
            raise IsoStagingSafetyError(
                "The staging plan contains invalid Windows BootEx inputs"
            )
        _validate_bootex_layout(
            plan.write_plan,
            plan.overlay,
            plan.syslinux_c32_bundle,
        )
        if _bootex_wim_source(effective_entries).path != plan.windows_boot_wim_source:
            raise IsoStagingSafetyError(
                "The Windows BootEx WIM binding changed"
            )
        try:
            validate_bootex_source_binding(plan.windows_bootex_source)
        except BootExError as error:
            raise IsoStagingSafetyError(str(error)) from error
        if (
            plan.windows_bootex_source.source_iso.path != plan.image
            or plan.windows_bootex_source.source_iso.identity[:5]
            != plan.image_identity
        ):
            raise IsoStagingSafetyError(
                "The Windows BootEx ISO binding changed"
            )
    if plan.autounattend_xml is not None and not isinstance(
        plan.autounattend_xml, str,
    ):
        raise IsoStagingSafetyError("The Windows answer file must be text")
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
        try:
            answer_path = answer_file_install_path(
                plan.autounattend_xml,
                (
                    plan.wim_selection.edition.architecture
                    if plan.wim_selection is not None else None
                ),
            )
        except ValueError as error:
            raise IsoStagingSafetyError(str(error)) from error
        install_source_count = sum(
            entry.kind is EntryKind.FILE and (
                _is_install_wim_path(entry.path)
                or entry.path.casefold() == "sources/install.esd"
            )
            for entry in effective_entries
        )
        if plan.wim_selection is not None:
            selected_is_wim = _is_install_wim_path(plan.wim_selection.source_name)
            if answer_path is not None and answer_path != plan.wim_selection.source_name:
                raise IsoStagingSafetyError(
                    "The answer-file WIM path does not match the staging plan"
                )
            if (
                selected_is_wim
                and (
                    install_source_count > 1
                    or plan.wim_selection.source_name.casefold()
                    != "sources/install.wim"
                )
                and answer_path is None
            ):
                raise IsoStagingSafetyError(
                    "The staging plan does not bind its nested or multi-source WIM path"
                )
        existing_answer_file = _existing_windows_answer_file(effective_entries)
        if existing_answer_file is not None:
            raise IsoStagingSafetyError(
                f"The generated answer file conflicts with existing ISO content at "
                f"{existing_answer_file}"
            )
    elif plan.wim_selection is not None:
        raise IsoStagingSafetyError(
            "A selected Windows image requires a bound answer file"
        )
    if plan.windows_customization is None:
        if plan.windows_architecture is not None or plan.autounattend_xml is not None:
            raise IsoStagingSafetyError(
                "The staging plan does not bind its Windows customization inputs"
            )
    else:
        if not isinstance(plan.windows_customization, WindowsCustomization):
            raise IsoStagingSafetyError(
                "The staging plan contains invalid Windows customization inputs"
            )
        if not plan.windows_customization.enabled:
            raise IsoStagingSafetyError(
                "The staging plan contains an empty Windows customization"
            )
        if plan.windows_customization.install_image != plan.wim_selection:
            raise IsoStagingSafetyError(
                "The staging plan Windows image selection is inconsistent"
            )
        if not isinstance(plan.windows_architecture, str):
            raise IsoStagingSafetyError(
                "The staging plan does not bind its Windows answer-file architecture"
            )
        try:
            expected_answer_file = generate_autounattend(
                plan.windows_customization, plan.windows_architecture,
            )
        except ValueError as error:
            raise IsoStagingSafetyError(str(error)) from error
        try:
            exact_match = (
                plan.autounattend_xml is not None
                and plan.autounattend_xml.encode("utf-8")
                == expected_answer_file.encode("utf-8")
            )
        except UnicodeEncodeError as error:
            raise IsoStagingSafetyError(
                "The Windows answer file is not valid UTF-8 text"
            ) from error
        if not exact_match:
            raise IsoStagingSafetyError(
                "The Windows answer file does not match its bound customization exactly"
            )
    witness = plan._catalog_witness
    if (
        type(witness) is not _CatalogWitness
        or witness.token is not _CATALOG_WITNESS_TOKEN
        or witness.image_identity != plan.image_identity
        or witness.catalog_digest != plan.catalog_digest
        or witness.archive_namespace is not plan.archive_namespace
    ):
        raise IsoStagingSafetyError(
            "The complete ISO source catalog witness is invalid"
        )
    try:
        rebuilt = build_extraction_plan(
            plan.image,
            plan.destination,
            entries,
            seven_zip=plan.seven_zip,
            archive_namespace=plan.archive_namespace,
        )
    except ExtractionUnavailable as error:
        raise IsoStagingUnavailable(str(error)) from error
    except (ExtractionError, OSError) as error:
        raise IsoStagingSafetyError(str(error)) from error
    if (
        rebuilt.image_identity != plan.image_identity
        or rebuilt.destination_parent_identity != plan.destination_parent_identity
        or rebuilt.archive_namespace is not plan.archive_namespace
    ):
        raise IsoStagingSafetyError("The ISO, destination, or content binding changed")
    overlay_bytes = plan.overlay.content_bytes if plan.overlay is not None else 0
    expected_content = (
        rebuilt.content_bytes
        + embedded_content_bytes
        + overlay_bytes
        + syslinux_content_bytes
    )
    catalog_content = sum(
        entry.size for entry in staged_entries if entry.kind is EntryKind.FILE
    )
    if plan.content_bytes != expected_content or expected_content != catalog_content:
        raise IsoStagingSafetyError(
            "The staged ISO expanded-size accounting is invalid"
        )
    if (
        wim_source is None
        and plan.wim_selection is None
        and plan.windows_bootex_source is None
    ):
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
    split_extra = next(
        (entry.size for entry in effective_entries if entry.path == wim_source), 0,
    )
    bootex_extra = (
        _BOOTEX_EXTRA_SPACE
        if plan.windows_bootex_source is not None
        else 0
    )
    expected_free = (
        plan.content_bytes + split_extra + bootex_extra + OUTPUT_SPACE_RESERVE
    )
    if plan.required_free_bytes != expected_free:
        raise IsoStagingSafetyError("The plan contains invalid free-space accounting")
    try:
        if shutil.disk_usage(plan.destination.parent).free < expected_free:
            raise IsoStagingSafetyError(
                "There is not enough free space to extract and transform the ISO privately"
            )
    except OSError as error:
        raise IsoStagingSafetyError("Could not determine staging free space") from error


def validate_published_syslinux_staging(
    plan: IsoStagingPlan,
    result: IsoStagingResult,
    *,
    cancel_check: Callable[[], None] | None = None,
) -> StagingTreeManifest:
    """Reauthenticate one published Syslinux tree without reopening its ISO.

    The ordinary planning validator cannot run after publication because its
    extraction contract requires a destination that does not yet exist.  This
    narrower boundary therefore accepts only the exact plan object witnessed by
    its executor, rejects later WIM/answer-file transforms, and rebuilds the
    complete descriptor-safe content manifest from the published directory.
    """

    if cancel_check is not None:
        cancel_check()
    if type(plan) is not IsoStagingPlan:
        raise IsoStagingSafetyError("An exact ISO staging plan is required")
    receipt = result._receipt if type(result) is IsoStagingResult else None
    if (
        type(result) is not IsoStagingResult
        or type(receipt) is not _PublishedReceipt
        or receipt.token is not _RESULT_WITNESS_TOKEN
        or receipt.plan is not plan
        or receipt.manifest is not result.tree_manifest
        or (
            receipt.destination,
            receipt.image_identity,
            receipt.catalog_digest,
            receipt.directories,
            receipt.files,
            receipt.bytes_staged,
            receipt.wim_parts,
            receipt.autounattend_added,
            receipt.windows_bootex,
        )
        != (
            result.destination,
            result.image_identity,
            result.catalog_digest,
            result.directories,
            result.files,
            result.bytes_staged,
            result.wim_parts,
            result.autounattend_added,
            result.windows_bootex,
        )
    ):
        raise IsoStagingSafetyError(
            "An authentic result for this exact ISO staging plan is required",
        )
    if (
        type(plan.syslinux_staging) is not SyslinuxStagingPlan
        or type(plan.syslinux_c32_bundle) is not BoundBootBundle
        or type(plan.syslinux_payload_bundle) is not BoundBootBundle
        or type(plan.syslinux_analysis) is not BootloaderAnalysis
    ):
        raise IsoStagingSafetyError(
            "The published staging plan has no complete Syslinux binding",
        )
    if any((
        plan.wim_source is not None,
        plan.wim_selection is not None,
        plan.wimlib_imagex is not None,
        plan.autounattend_xml is not None,
        plan.windows_customization is not None,
        plan.windows_architecture is not None,
        plan.windows_bootex_options is not None,
        plan.windows_bootex_source is not None,
        plan.windows_boot_wim_source is not None,
    )):
        raise IsoStagingSafetyError(
            "The initial Syslinux image profile does not compose with Windows transforms",
        )
    if _validate_write_plan(plan.write_plan, plan.effective_entries) is not None:
        raise IsoStagingSafetyError(
            "The initial Syslinux image profile requires an unsplit FAT32 tree",
        )
    rebuilt_entries, rebuilt_bytes = _merge_syslinux_staging_catalog(
        plan.effective_entries,
        plan.syslinux_staging,
    )
    if (
        rebuilt_entries != plan.staged_entries
        or rebuilt_bytes != plan.syslinux_content_bytes
        or _catalog_digest(rebuilt_entries) != plan.staged_catalog_digest
    ):
        raise IsoStagingSafetyError(
            "The published Syslinux catalog binding is inconsistent",
        )

    scalar_shape = (
        isinstance(result.destination, Path)
        and result.destination == plan.destination
        and result.image_identity == plan.image_identity
        and result.catalog_digest == plan.staged_catalog_digest
        and type(result.directories) is int
        and result.directories > 0
        and type(result.files) is int
        and result.files > 0
        and type(result.bytes_staged) is int
        and result.bytes_staged >= 0
        and type(result.wim_parts) is tuple
        and not result.wim_parts
        and result.autounattend_added is False
        and result.windows_bootex is None
        and type(result.tree_manifest) is StagingTreeManifest
    )
    if not scalar_shape:
        raise IsoStagingSafetyError(
            "The published Syslinux result fields are invalid or inconsistent",
        )
    manifest = result.tree_manifest
    assert manifest is not None
    try:
        validate_staging_tree_manifest(
            manifest,
            cancel_check=cancel_check,
        )
    except StagingTreeSafetyError as error:
        raise IsoStagingSafetyError(str(error)) from error
    if manifest.root != plan.destination:
        raise IsoStagingSafetyError(
            "The published staging manifest belongs to another directory",
        )

    expected_directories = _expected_directories(plan.staged_entries)
    actual_directories = {
        _case_key(item.path): item.path for item in manifest.directories
    }
    expected_files = {
        _case_key(entry.path): _ScannedFile(entry.path, entry.size)
        for entry in plan.staged_entries
        if entry.kind is EntryKind.FILE
    }
    actual_files = {
        _case_key(item.path): _ScannedFile(item.path, item.size)
        for item in manifest.files
    }
    if (
        actual_directories != expected_directories
        or actual_files != expected_files
        or result.directories != len(manifest.directories)
        or result.files != len(manifest.files)
        or result.bytes_staged != manifest.total_bytes
        or result.bytes_staged != plan.content_bytes
    ):
        raise IsoStagingSafetyError(
            "The published tree does not match its complete Syslinux staging catalog",
        )
    if cancel_check is not None:
        cancel_check()
    return manifest


def validate_published_windows_staging(
    plan: IsoStagingPlan,
    result: IsoStagingResult,
    *,
    cancel_check: Callable[[], None] | None = None,
) -> StagingTreeManifest:
    """Reauthenticate one executor-published Windows BIOS+UEFI FAT32 tree.

    The result receipt is created only after extraction, optional split-WIM
    replacement, full descriptor-safe manifesting, atomic publication, and a
    second manifest comparison.  This first composition profile deliberately
    excludes overlays and Windows customization/BootEx so the only admitted
    catalog mutation is the witnessed conventional install.wim split.
    """

    if cancel_check is not None:
        cancel_check()
    if type(plan) is not IsoStagingPlan:
        raise IsoStagingSafetyError("An exact ISO staging plan is required")
    receipt = result._receipt if type(result) is IsoStagingResult else None
    if (
        type(result) is not IsoStagingResult
        or type(receipt) is not _PublishedReceipt
        or receipt.token is not _RESULT_WITNESS_TOKEN
        or receipt.plan is not plan
        or receipt.manifest is not result.tree_manifest
        or (
            receipt.destination,
            receipt.image_identity,
            receipt.catalog_digest,
            receipt.directories,
            receipt.files,
            receipt.bytes_staged,
            receipt.wim_parts,
            receipt.autounattend_added,
            receipt.windows_bootex,
        )
        != (
            result.destination,
            result.image_identity,
            result.catalog_digest,
            result.directories,
            result.files,
            result.bytes_staged,
            result.wim_parts,
            result.autounattend_added,
            result.windows_bootex,
        )
    ):
        raise IsoStagingSafetyError(
            "An authentic result for this exact ISO staging plan is required",
        )
    layout = plan.write_plan.layout
    if (
        plan.write_plan.firmware_target is not FirmwareTarget.BOTH
        or layout is None
        or layout.partition_table is not PartitionTable.MBR
        or layout.main_filesystem is not FileSystem.FAT32
        or layout.partition_count != 1
        or layout.boot_partition_filesystem is not None
        or not layout.bios_bootable
        or not layout.uefi_bootable
        or not layout.main_partition_active
        or layout.boot_strategy is not BootStrategy.WINDOWS_BOOTMGR_FAT32
    ):
        raise IsoStagingSafetyError(
            "The published tree is outside the Windows BIOS+UEFI FAT32 profile",
        )
    if any((
        plan.overlay is not None,
        plan.embedded_fat is not None,
        plan.syslinux_staging is not None,
        plan.syslinux_c32_bundle is not None,
        plan.syslinux_payload_bundle is not None,
        plan.wim_selection is not None,
        plan.autounattend_xml is not None,
        plan.windows_customization is not None,
        plan.windows_architecture is not None,
        plan.windows_bootex_options is not None,
        plan.windows_bootex_source is not None,
        plan.windows_boot_wim_source is not None,
    )):
        raise IsoStagingSafetyError(
            "The initial Windows dual-firmware profile does not compose with "
            "overlays or customization",
        )
    wim_source = _validate_write_plan(plan.write_plan, plan.effective_entries)
    if wim_source != plan.wim_source:
        raise IsoStagingSafetyError("The published split-WIM binding is inconsistent")
    expected_split = wim_source is not None
    if (
        result.destination != plan.destination
        or result.image_identity != plan.image_identity
        or result.catalog_digest != plan.staged_catalog_digest
        or type(result.directories) is not int
        or result.directories <= 0
        or type(result.files) is not int
        or result.files <= 0
        or type(result.bytes_staged) is not int
        or result.bytes_staged <= 0
        or type(result.wim_parts) is not tuple
        or bool(result.wim_parts) != expected_split
        or result.autounattend_added is not False
        or result.windows_bootex is not None
        or type(result.tree_manifest) is not StagingTreeManifest
    ):
        raise IsoStagingSafetyError(
            "The published Windows result fields are invalid or inconsistent",
        )
    manifest = result.tree_manifest
    assert manifest is not None
    try:
        validate_staging_tree_manifest(manifest, cancel_check=cancel_check)
    except StagingTreeSafetyError as error:
        raise IsoStagingSafetyError(str(error)) from error
    if (
        manifest.root != plan.destination
        or result.directories != len(manifest.directories)
        or result.files != len(manifest.files)
        or result.bytes_staged != manifest.total_bytes
    ):
        raise IsoStagingSafetyError(
            "The published Windows tree does not match its authenticated manifest",
        )
    if cancel_check is not None:
        cancel_check()
    return manifest


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


def _open_staged_directory(
    root_fd: int,
    parts: tuple[str, ...],
    root_device: int,
) -> int:
    if (
        type(parts) is not tuple
        or any(
            type(component) is not str
            or component in {"", ".", "..", "/"}
            or "/" in component
            or "\\" in component
            or "\x00" in component
            for component in parts
        )
    ):
        raise IsoStagingSafetyError(
            "A private staging directory path is not canonical and relative"
        )
    current = os.dup(root_fd)
    try:
        for component in parts:
            following = os.open(component, _DIR_FLAGS, dir_fd=current)
            os.close(current)
            current = following
            info = os.fstat(current)
            if not stat.S_ISDIR(info.st_mode) or info.st_dev != root_device:
                raise IsoStagingSafetyError(
                    "A timestamped staging directory changed or escaped the private tree"
                )
        return current
    except OSError as error:
        os.close(current)
        raise IsoStagingSafetyError(
            "Could not safely open a timestamped staging directory"
        ) from error
    except BaseException:
        os.close(current)
        raise


def _stable_staged_file_fields(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _staged_relative_parts(path: str) -> tuple[str, ...]:
    if type(path) is not str:
        raise IsoStagingSafetyError("A private staging path must be text")
    pure = PurePosixPath(path)
    parts = pure.parts
    if (
        not path
        or pure.is_absolute()
        or pure.as_posix() != path
        or not parts
        or any(
            component in {"", ".", "..", "/"}
            or "/" in component
            or "\\" in component
            or "\x00" in component
            for component in parts
        )
    ):
        raise IsoStagingSafetyError(
            "A private staging path is not canonical and relative"
        )
    return parts


def _read_staged_file_bytes(
    root_fd: int,
    path: str,
    expected_size: int,
    root_device: int,
    cancel_check: Callable[[], None],
) -> bytes:
    """Read one exact private-tree file through stable no-follow descriptors."""

    parts = _staged_relative_parts(path)
    if type(expected_size) is not int or expected_size < 0:
        raise IsoStagingSafetyError("A Syslinux staged-file binding is invalid")
    parent_parts = parts[:-1]
    parent = _open_staged_directory(root_fd, parent_parts, root_device)
    descriptor = -1
    try:
        try:
            observed = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            descriptor = os.open(
                parts[-1],
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent,
            )
        except OSError as error:
            raise IsoStagingSafetyError(
                f"Could not safely open staged Syslinux file {path!r}"
            ) from error
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != root_device
            or opened.st_nlink != 1
            or opened.st_size != expected_size
            or _stable_staged_file_fields(opened)
            != _stable_staged_file_fields(observed)
        ):
            raise IsoStagingSafetyError(
                f"Staged Syslinux file {path!r} changed while opening"
            )
        payload = bytearray()
        remaining = expected_size
        while remaining:
            cancel_check()
            try:
                block = os.read(descriptor, min(1024 * 1024, remaining))
            except OSError as error:
                raise IsoStagingSafetyError(
                    f"Could not read staged Syslinux file {path!r}"
                ) from error
            if not block:
                raise IsoStagingSafetyError(
                    f"Staged Syslinux file {path!r} ended early"
                )
            payload.extend(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise IsoStagingSafetyError(
                f"Staged Syslinux file {path!r} grew while reading"
            )
        after = os.fstat(descriptor)
        reopened_parent = _open_staged_directory(
            root_fd, parent_parts, root_device,
        )
        try:
            rebound = os.stat(
                parts[-1], dir_fd=reopened_parent, follow_symlinks=False,
            )
            if (
                (os.fstat(reopened_parent).st_dev, os.fstat(reopened_parent).st_ino)
                != (os.fstat(parent).st_dev, os.fstat(parent).st_ino)
                or _stable_staged_file_fields(after)
                != _stable_staged_file_fields(opened)
                or _stable_staged_file_fields(rebound)
                != _stable_staged_file_fields(opened)
            ):
                raise IsoStagingSafetyError(
                    f"Staged Syslinux file {path!r} changed while reading"
                )
        finally:
            os.close(reopened_parent)
        return bytes(payload)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _create_staged_syslinux_file(
    root_fd: int,
    item: SyslinuxStageFile,
    root_device: int,
    cancel_check: Callable[[], None],
) -> None:
    if (
        type(item) is not SyslinuxStageFile
        or item.disposition is not StageDisposition.CREATE
        or type(item.path) is not str
        or type(item.data) is not bytes
        or type(item.sha256) is not str
        or not hmac.compare_digest(
            hashlib.sha256(item.data).hexdigest(), item.sha256,
        )
    ):
        raise IsoStagingSafetyError("A generated Syslinux file is invalid")
    parts = _staged_relative_parts(item.path)
    parent_parts = parts[:-1]
    parent = _open_staged_directory(root_fd, parent_parts, root_device)
    descriptor = -1
    created_identity: tuple[int, int] | None = None
    try:
        cancel_check()
        try:
            descriptor = os.open(
                parts[-1],
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent,
            )
        except OSError as error:
            raise IsoStagingSafetyError(
                f"Could not exclusively create Syslinux file {item.path!r}"
            ) from error
        opened = os.fstat(descriptor)
        created_identity = opened.st_dev, opened.st_ino
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != root_device
            or opened.st_nlink != 1
            or opened.st_size != 0
        ):
            raise IsoStagingSafetyError(
                f"Generated Syslinux file {item.path!r} is unsafe"
            )
        view = memoryview(item.data)
        offset = 0
        while offset < len(view):
            cancel_check()
            try:
                written = os.write(descriptor, view[offset:offset + 1024 * 1024])
            except OSError as error:
                raise IsoStagingSafetyError(
                    f"Could not write Syslinux file {item.path!r}"
                ) from error
            if written <= 0:
                raise IsoStagingSafetyError(
                    f"Could not completely write Syslinux file {item.path!r}"
                )
            offset += written
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        if (
            (final.st_dev, final.st_ino) != created_identity
            or not stat.S_ISREG(final.st_mode)
            or final.st_nlink != 1
            or final.st_size != len(item.data)
        ):
            raise IsoStagingSafetyError(
                f"Generated Syslinux file {item.path!r} changed while writing"
            )
        os.close(descriptor)
        descriptor = -1
        os.fsync(parent)
        reopened_parent = _open_staged_directory(
            root_fd, parent_parts, root_device,
        )
        try:
            if (
                (os.fstat(reopened_parent).st_dev, os.fstat(reopened_parent).st_ino)
                != (os.fstat(parent).st_dev, os.fstat(parent).st_ino)
            ):
                raise IsoStagingSafetyError(
                    f"The parent of generated Syslinux file {item.path!r} moved"
                )
        finally:
            os.close(reopened_parent)
        rebound = _read_staged_file_bytes(
            root_fd,
            item.path,
            len(item.data),
            root_device,
            cancel_check,
        )
        if not hmac.compare_digest(hashlib.sha256(rebound).hexdigest(), item.sha256):
            raise IsoStagingSafetyError(
                f"Generated Syslinux file {item.path!r} failed read-back"
            )
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        if created_identity is not None:
            try:
                current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == created_identity:
                    os.unlink(parts[-1], dir_fd=parent)
            except OSError:
                pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _validate_staged_syslinux_sources(
    root_fd: int,
    plan: IsoStagingPlan,
    root_device: int,
    cancel_check: Callable[[], None],
) -> None:
    """Rebuild the pure Syslinux plan from the current private-tree bytes."""

    assert plan.syslinux_staging is not None
    assert plan.syslinux_analysis is not None
    assert plan.syslinux_c32_bundle is not None
    assert plan.syslinux_payload_bundle is not None
    paths = syslinux_staging_read_paths(
        plan.effective_entries,
        plan.syslinux_analysis,
    )
    entry_by_path = {entry.path: entry for entry in plan.effective_entries}
    try:
        payloads = {
            path: _read_staged_file_bytes(
                root_fd,
                path,
                entry_by_path[path].size,
                root_device,
                cancel_check,
            )
            for path in paths
        }
    except KeyError as error:
        raise IsoStagingSafetyError(
            "The Syslinux read set left the effective staging catalog"
        ) from error
    existing_files = {
        path: data for path, data in payloads.items()
        if PurePosixPath(path).name.casefold().endswith(".c32")
    }
    source_files = {
        path: data for path, data in payloads.items()
        if path not in existing_files
    }
    try:
        validate_syslinux_staging_plan(
            plan.syslinux_staging,
            plan.effective_entries,
            plan.syslinux_analysis,
            plan.syslinux_c32_bundle,
            plan.syslinux_payload_bundle,
            source_files=source_files,
            existing_files=existing_files,
        )
    except SyslinuxStagingError as error:
        raise IsoStagingSafetyError(str(error)) from error


def _open_private_syslinux_root(root: Path) -> tuple[int, int]:
    try:
        initial = os.lstat(root)
        descriptor = os.open(root, _DIR_FLAGS)
    except OSError as error:
        raise IsoStagingSafetyError(
            "Could not safely open the private Syslinux staging tree"
        ) from error
    try:
        opened = os.fstat(descriptor)
        if (
            stat.S_ISLNK(initial.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino)
        ):
            raise IsoStagingSafetyError(
                "The private Syslinux staging root changed while opening"
            )
        return descriptor, opened.st_dev
    except BaseException:
        os.close(descriptor)
        raise


def _materialize_syslinux_staging(
    root: Path,
    plan: IsoStagingPlan,
    cancel_check: Callable[[], None],
) -> None:
    if plan.syslinux_staging is None:
        return
    root_fd, root_device = _open_private_syslinux_root(root)
    try:
        _validate_staged_syslinux_sources(
            root_fd, plan, root_device, cancel_check,
        )
        for item in plan.syslinux_staging.additions:
            _create_staged_syslinux_file(
                root_fd, item, root_device, cancel_check,
            )
    finally:
        os.close(root_fd)
    _verify_extracted_catalog(root, plan.staged_entries)


def _revalidate_materialized_syslinux_staging(
    root: Path,
    plan: IsoStagingPlan,
    cancel_check: Callable[[], None],
) -> None:
    """Recheck every Syslinux-bound byte immediately before publication."""

    if plan.syslinux_staging is None:
        return
    root_fd, root_device = _open_private_syslinux_root(root)
    try:
        _validate_staged_syslinux_sources(
            root_fd, plan, root_device, cancel_check,
        )
        for item in plan.syslinux_staging.additions:
            payload = _read_staged_file_bytes(
                root_fd,
                item.path,
                len(item.data),
                root_device,
                cancel_check,
            )
            if (
                not hmac.compare_digest(payload, item.data)
                or not hmac.compare_digest(
                    hashlib.sha256(payload).hexdigest(), item.sha256,
                )
            ):
                raise IsoStagingSafetyError(
                    f"Generated Syslinux file {item.path!r} changed before publication"
                )
    finally:
        os.close(root_fd)


def _bind_catalog_directory_mtimes(
    root: Path,
    entries: Sequence[ArchiveEntry],
    cancel_check: Callable[[], None],
) -> tuple[tuple[tuple[str, ...], int], ...]:
    """Bind the workspace-normalized values of explicit catalog directories."""

    timestamped = tuple(
        entry for entry in entries
        if entry.kind is EntryKind.DIRECTORY and entry.modified_ns is not None
    )
    if not timestamped:
        return ()
    try:
        initial = os.lstat(root)
    except OSError as error:
        raise IsoStagingSafetyError(
            "The transformed staging tree is unavailable"
        ) from error
    if stat.S_ISLNK(initial.st_mode) or not stat.S_ISDIR(initial.st_mode):
        raise IsoStagingSafetyError("The transformed staging tree is not a real directory")
    try:
        root_fd = os.open(root, _DIR_FLAGS)
    except OSError as error:
        raise IsoStagingSafetyError(
            "Could not safely open the transformed staging tree"
        ) from error
    try:
        try:
            opened = os.fstat(root_fd)
        except OSError as error:
            raise IsoStagingSafetyError(
                "Could not bind the transformed staging tree"
            ) from error
        if (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino):
            raise IsoStagingSafetyError("The transformed staging root changed while opening")
        bound: list[tuple[tuple[str, ...], int]] = []
        for entry in sorted(
            timestamped,
            key=lambda item: len(PurePosixPath(item.path).parts),
            reverse=True,
        ):
            cancel_check()
            parts = PurePosixPath(entry.path).parts
            descriptor = _open_staged_directory(
                root_fd, parts, opened.st_dev,
            )
            try:
                modified_ns = entry.modified_ns
                assert modified_ns is not None
                observed_ns = os.fstat(descriptor).st_mtime_ns
                if not mtime_matches(
                    modified_ns, observed_ns, STAGING_MTIME_TOLERANCE_NS,
                ):
                    raise IsoStagingSafetyError(
                        f"The extracted directory time for {entry.path!r} was "
                        "normalized beyond the supported workspace resolution"
                    )
                bound.append((parts, observed_ns))
            finally:
                os.close(descriptor)
        return tuple(bound)
    finally:
        os.close(root_fd)


def _reapply_bound_directory_mtimes(
    root: Path,
    bound_mtimes: Sequence[tuple[tuple[str, ...], int]],
    cancel_check: Callable[[], None],
) -> None:
    """Restore first-observed directory times after private transformations."""

    if not bound_mtimes:
        return
    try:
        initial = os.lstat(root)
    except OSError as error:
        raise IsoStagingSafetyError(
            "The transformed staging tree is unavailable"
        ) from error
    if stat.S_ISLNK(initial.st_mode) or not stat.S_ISDIR(initial.st_mode):
        raise IsoStagingSafetyError("The transformed staging tree is not a real directory")
    try:
        root_fd = os.open(root, _DIR_FLAGS)
    except OSError as error:
        raise IsoStagingSafetyError(
            "Could not safely open the transformed staging tree"
        ) from error
    try:
        opened = os.fstat(root_fd)
        if (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino):
            raise IsoStagingSafetyError("The transformed staging root changed while opening")
        for parts, bound_ns in sorted(
            bound_mtimes, key=lambda item: len(item[0]), reverse=True,
        ):
            cancel_check()
            descriptor = _open_staged_directory(
                root_fd, parts, opened.st_dev,
            )
            try:
                try:
                    observed_ns = apply_descriptor_mtime(
                        descriptor,
                        bound_ns,
                        tolerance_ns=STAGING_MTIME_TOLERANCE_NS,
                    )
                except TimestampPreservationError as error:
                    raise IsoStagingSafetyError(
                        f"Could not restore the bound directory time for "
                        f"{PurePosixPath(*parts).as_posix()!r}: {error}"
                    ) from error
                if observed_ns != bound_ns:
                    raise IsoStagingSafetyError(
                        f"The workspace changed its normalized directory time for "
                        f"{PurePosixPath(*parts).as_posix()!r}"
                    )
            finally:
                os.close(descriptor)
    finally:
        os.close(root_fd)


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
    except StagingTreeSafetyError as error:
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
        wim_extractor: WimExtractExecutor | None = None,
        split_plan_builder: SplitPlanBuilder = _default_split_plan_builder,
        extract_plan_builder: ExtractPlanBuilder = create_extract_plan,
        wim_inspector: WimInspector = _default_wim_inspector,
        bootex_plan_builder: BootExPlanBuilder = build_bootex_plan,
        bootex_applier: BootExApplier = apply_bootex_plan,
        overlay_applier: OverlayApplier = apply_zip_overlay,
        publisher: Publisher = _rename_noreplace,
    ) -> None:
        self._extractor = extractor or SafeIsoExtractor()
        self._wim_splitter = wim_splitter
        self._wim_extractor = wim_extractor
        self._split_plan_builder = split_plan_builder
        self._extract_plan_builder = extract_plan_builder
        self._wim_inspector = wim_inspector
        self._bootex_plan_builder = bootex_plan_builder
        self._bootex_applier = bootex_applier
        self._overlay_applier = overlay_applier
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
        self,
        update: ExtractionProgress,
        progress: Progress,
        total_bytes: int,
    ) -> None:
        progress(IsoStagingProgress(
            "Extracting ISO", update.member, update.bytes_done, total_bytes,
        ))
        self._check_cancelled()

    def _update_from_overlay(
        self,
        update: ZipOverlayProgress,
        progress: Progress,
        base_bytes: int,
        total_bytes: int,
    ) -> None:
        if not isinstance(update, ZipOverlayProgress):
            raise IsoStagingSafetyError("The ZIP overlay reported invalid progress")
        progress(IsoStagingProgress(
            "Adding ZIP overlay",
            update.member,
            base_bytes + update.bytes_done,
            total_bytes,
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
        validate_iso_staging_plan(plan, cancel_check=self._check_cancelled)
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
                plan.image,
                tree,
                plan.entries,
                seven_zip=plan.seven_zip,
                archive_namespace=plan.archive_namespace,
            )
            if extraction_plan.image_identity != plan.image_identity:
                raise IsoStagingSafetyError("The ISO source changed before extraction")
            self._set_active(self._extractor)
            self._extractor.execute(
                extraction_plan,
                lambda update: self._update_from_extraction(
                    update, progress, plan.content_bytes,
                ),
            )
            self._set_active(None)
            self._check_cancelled()
            if _identity(plan.image) != plan.image_identity:
                raise IsoStagingSafetyError("The ISO source changed during extraction")
            _verify_extracted_catalog(tree, plan.entries)
            bound_directory_mtimes = _bind_catalog_directory_mtimes(
                tree, plan.entries, self._check_cancelled,
            )

            if plan.embedded_entries:
                self._check_cancelled()
                progress(IsoStagingProgress(
                    "Expanding embedded UEFI boot image",
                    "",
                    sum(
                        entry.size for entry in plan.entries
                        if entry.kind is EntryKind.FILE
                    ),
                    plan.content_bytes,
                ))
                descriptor = -1
                try:
                    descriptor = os.open(
                        plan.image,
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                    )
                    status = os.fstat(descriptor)
                    observed = (
                        status.st_dev,
                        status.st_ino,
                        status.st_size,
                        status.st_mtime_ns,
                        status.st_ctime_ns,
                    )
                    if not stat.S_ISREG(status.st_mode) or observed != plan.image_identity:
                        raise IsoStagingSafetyError(
                            "The ISO changed before embedded boot-image staging"
                        )
                    catalog = inspect_eltorito_file(
                        plan.image,
                        image_fd=descriptor,
                    )
                    base_bytes = sum(
                        entry.size for entry in plan.entries
                        if entry.kind is EntryKind.FILE
                    )
                    written = materialize_embedded_fat(
                        descriptor,
                        catalog,
                        plan.embedded_fat,
                        tree,
                        plan.embedded_targets,
                        cancel_check=self._check_cancelled,
                        progress=lambda relative, done, _total: progress(
                            IsoStagingProgress(
                                "Expanding embedded UEFI boot image",
                                relative,
                                base_bytes + done,
                                plan.content_bytes,
                            )
                        ),
                    )
                    if written != plan.embedded_content_bytes:
                        raise IsoStagingSafetyError(
                            "The embedded boot-image byte count changed"
                        )
                except (ElToritoError, FatImageError, OSError) as error:
                    raise IsoStagingSafetyError(str(error)) from error
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                self._check_cancelled()
                _verify_extracted_catalog(
                    tree,
                    plan.base_with_embedded_entries,
                )

            if plan.overlay is not None:
                self._check_cancelled()
                effective_entries, overlay_targets = _merge_effective_catalog(
                    plan.base_with_embedded_entries, plan.overlay,
                )
                if effective_entries != plan.effective_entries:
                    raise IsoStagingSafetyError(
                        "The effective staging catalog changed before ZIP extraction"
                    )
                base_bytes = sum(
                    entry.size for entry in plan.base_with_embedded_entries
                    if entry.kind is EntryKind.FILE
                )
                progress(IsoStagingProgress(
                    "Adding ZIP overlay", "", base_bytes, plan.content_bytes,
                ))
                try:
                    overlay_result = self._overlay_applier(
                        plan.overlay,
                        tree,
                        overlay_targets,
                        cancel_check=self._check_cancelled,
                        progress=lambda update: self._update_from_overlay(
                            update, progress, base_bytes, plan.content_bytes,
                        ),
                    )
                except (ZipOverlayChanged, ZipOverlaySafetyError) as error:
                    raise IsoStagingSafetyError(str(error)) from error
                except ZipOverlayDeadlineExceeded as error:
                    raise IsoStagingError(str(error)) from error
                except ZipOverlayError as error:
                    raise IsoStagingError(str(error)) from error
                if (
                    not isinstance(overlay_result, ZipOverlayResult)
                    or overlay_result.bytes_written != plan.overlay.content_bytes
                    or overlay_result.archive_sha256 != plan.overlay.archive_sha256
                    or overlay_result.catalog_digest != plan.overlay.catalog_digest
                ):
                    raise IsoStagingSafetyError(
                        "The ZIP overlay result does not match its staging plan"
                    )
                self._check_cancelled()
                _verify_extracted_catalog(tree, plan.effective_entries)

            if plan.syslinux_staging is not None:
                self._check_cancelled()
                pre_syslinux_bytes = plan.content_bytes - plan.syslinux_content_bytes
                progress(IsoStagingProgress(
                    "Preparing Syslinux boot files",
                    "",
                    pre_syslinux_bytes,
                    plan.content_bytes,
                ))
                _materialize_syslinux_staging(
                    tree,
                    plan,
                    self._check_cancelled,
                )
                self._check_cancelled()

            selected_wim_path: Path | None = None
            selected_wim_identity: WimFileIdentity | None = None
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
                source_identity = _wim_identity(source)
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
            bootex_result: BootExResult | None = None
            expected_files = {
                _case_key(entry.path): _ScannedFile(entry.path, entry.size)
                for entry in plan.staged_entries if entry.kind is EntryKind.FILE
            }
            if plan.windows_bootex_source is not None:
                self._check_cancelled()
                assert plan.windows_boot_wim_source == "sources/boot.wim"
                assert plan.wimlib_imagex is not None
                boot_wim = tree / "sources" / "boot.wim"
                payload_destination = private_root / "bootex-payload"
                progress(IsoStagingProgress(
                    "Extracting Windows 2023-generation boot files",
                    plan.windows_boot_wim_source,
                    0,
                    plan.content_bytes,
                ))
                extract_plan = self._extract_plan_builder(
                    boot_wim,
                    payload_destination,
                    image_index=2,
                    paths=_BOOTEX_WIM_PATHS,
                    wimlib_imagex=plan.wimlib_imagex,
                )
                wim_extractor = self._wim_extractor or WimExtractExecutor()
                self._set_active(wim_extractor)
                extracted = wim_extractor.execute(
                    extract_plan,
                    lambda stage: progress(IsoStagingProgress(
                        stage,
                        plan.windows_boot_wim_source or "",
                        0,
                        plan.content_bytes,
                    )),
                )
                self._set_active(None)
                self._check_cancelled()
                if (
                    not isinstance(extracted, WimExtractResult)
                    or extracted.directory != str(payload_destination)
                    or not extracted.files
                    or extracted.total_size <= 0
                    or extracted.total_size > WIM_MAX_EXTRACT_BYTES
                ):
                    raise IsoStagingSafetyError(
                        "The WIM extractor returned invalid Windows BootEx data"
                    )
                extracted_root = payload_destination / "Windows" / "Boot"
                source_binding = plan.windows_bootex_source
                bootex_plan = self._bootex_plan_builder(
                    BootExRequest(
                        plan.image,
                        extracted_root,
                        tree,
                        architecture=source_binding.profile.architecture,
                        expected_release_id=source_binding.profile.release_id,
                    ),
                    cancel_check=self._check_cancelled,
                )
                if (
                    not isinstance(bootex_plan, BootExPlan)
                    or bootex_plan.profile != source_binding.profile
                    or bootex_plan.source_iso != source_binding.source_iso
                ):
                    raise IsoStagingSafetyError(
                        "The executed Windows BootEx plan does not match its "
                        "confirmed whole-ISO binding"
                    )
                progress(IsoStagingProgress(
                    "Replacing Windows 2023-generation boot files",
                    "efi/boot",
                    0,
                    plan.content_bytes,
                ))
                bootex_result = self._bootex_applier(
                    bootex_plan,
                    cancel_check=self._check_cancelled,
                )
                try:
                    validate_bootex_result(bootex_plan, bootex_result)
                except BootExError as error:
                    raise IsoStagingSafetyError(
                        "The Windows BootEx result does not match its execution plan"
                    ) from error
                for replacement in bootex_result.replacements:
                    key = _case_key(replacement.destination_path)
                    current = expected_files.get(key)
                    if (
                        current is None
                        or current.path != replacement.destination_path
                        or current.size != replacement.old_size
                    ):
                        raise IsoStagingSafetyError(
                            "A Windows BootEx destination was not bound to the "
                            "staged ISO catalog"
                        )
                    expected_files[key] = _ScannedFile(
                        replacement.destination_path,
                        replacement.new_size,
                    )
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
                if _wim_identity(source) != split_plan.source_identity:
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
                    and plan.wim_source != plan.wim_selection.source_name
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
            _reapply_bound_directory_mtimes(
                tree, bound_directory_mtimes, self._check_cancelled,
            )
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
            except StagingTreeSafetyError as error:
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
            expected_directories = _expected_directories(plan.staged_entries)
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
                _catalog_digest(plan.staged_entries)
                != plan.staged_catalog_digest
            ):
                raise IsoStagingSafetyError(
                    "The staged catalog binding changed during staging"
                )
            if (
                selected_wim_path is not None
                and selected_wim_identity is not None
                and plan.wim_source != plan.wim_selection.source_name
                and _wim_identity(selected_wim_path) != selected_wim_identity
            ):
                raise IsoStagingSafetyError(
                    "The selected WIM/ESD changed before staging was published"
                )
            _revalidate_materialized_syslinux_staging(
                tree,
                plan,
                self._check_cancelled,
            )
            private_manifest: StagingTreeManifest | None = None
            windows_dual_manifest = (
                plan.write_plan.firmware_target is FirmwareTarget.BOTH
                and plan.write_plan.layout is not None
                and plan.write_plan.layout.boot_strategy
                is BootStrategy.WINDOWS_BOOTMGR_FAT32
            )
            if (
                plan.syslinux_staging is not None
                or plan.windows_bootex_source is not None
                or windows_dual_manifest
            ):
                manifest_file_limit = (
                    FAT32_MAX_FILE_SIZE
                    if plan.write_plan.layout is not None
                    and plan.write_plan.layout.main_filesystem is FileSystem.FAT32
                    else None
                )
                try:
                    private_manifest = build_staging_tree_manifest(
                        tree,
                        max_file_bytes=manifest_file_limit,
                        cancel_check=self._check_cancelled,
                    )
                except StagingTreeSafetyError as error:
                    raise IsoStagingSafetyError(str(error)) from error
                if (
                    private_manifest.source_directories != directories
                    or private_manifest.source_files != files
                    or private_manifest.total_bytes != sum(item.size for item in files)
                ):
                    raise IsoStagingSafetyError(
                        "The private transformed tree changed before publication",
                    )
                if bootex_result is not None:
                    manifest_files = {
                        _case_key(item.path): item
                        for item in private_manifest.files
                    }
                    for replacement in bootex_result.replacements:
                        item = manifest_files.get(
                            _case_key(replacement.destination_path)
                        )
                        if (
                            item is None
                            or item.path != replacement.destination_path
                            or item.size != replacement.new_size
                            or item.sha256 != replacement.new_sha256
                        ):
                            raise IsoStagingSafetyError(
                                "The final staging manifest does not match the "
                                "Windows BootEx replacement receipt"
                            )
            _check_parent(plan, parent_fd)
            if os.path.lexists(plan.destination):
                raise IsoStagingSafetyError("The staging destination appeared before publication")
            self._check_cancelled()
            self._publisher(tree, plan.destination, parent_fd)
            committed = True
            os.fsync(parent_fd)
            total_bytes = sum(item.size for item in files)
            published_manifest: StagingTreeManifest | None = None
            if private_manifest is not None:
                try:
                    # Publication is the commit point.  Finish the receipt even
                    # if cancellation arrives now so callers never receive an
                    # unauthenticated success for an already-visible tree.
                    published_manifest = build_staging_tree_manifest(
                        plan.destination,
                        max_file_bytes=manifest_file_limit,
                    )
                except StagingTreeSafetyError as error:
                    raise IsoStagingSafetyError(str(error)) from error
                if (
                    published_manifest.manifest_sha256
                    != private_manifest.manifest_sha256
                    or published_manifest.total_bytes != total_bytes
                ):
                    raise IsoStagingSafetyError(
                        "The transformed staging tree changed during publication",
                    )
            result = IsoStagingResult(
                destination=plan.destination,
                image_identity=plan.image_identity,
                catalog_digest=plan.staged_catalog_digest,
                directories=len(directories),
                files=len(files),
                bytes_staged=total_bytes,
                wim_parts=wim_parts,
                autounattend_added=answer_added,
                tree_manifest=published_manifest,
                windows_bootex=bootex_result,
            )
            if published_manifest is not None:
                object.__setattr__(
                    result,
                    "_receipt",
                    _PublishedReceipt(
                        _RESULT_WITNESS_TOKEN,
                        plan,
                        published_manifest,
                        result.destination,
                        result.image_identity,
                        result.catalog_digest,
                        result.directories,
                        result.files,
                        result.bytes_staged,
                        result.wim_parts,
                        result.autounattend_added,
                        result.windows_bootex,
                    ),
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
        except (ExtractionSafetyError, WimValidationError, BootExError) as error:
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
