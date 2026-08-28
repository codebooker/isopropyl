from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Iterable

from isopropyl.distro_policies import (
    DistroPolicyError,
    match_distro_iso_exclusion,
)
from isopropyl.images import ImageInspection
from isopropyl.timestamps import (
    MAX_PORTABLE_ARCHIVE_MTIME_NS, MIN_PORTABLE_ARCHIVE_MTIME_NS,
)
from isopropyl.uefi import fallback_loader_matches_architecture


# FAT stores a file's size in an unsigned 32-bit field.  The largest valid
# individual file is therefore one byte smaller than 4 GiB.
FAT32_MAX_FILE_SIZE = (4 * 1024**3) - 1
WIM_SPLIT_PART_SIZE = 3800 * 1024**2
ISO_OVERLAY_EFFECTIVE_MEMBER_MAX_COUNT = 65_536
_FALLBACK_LOADER = re.compile(r"boot[A-Za-z0-9]+\.efi", re.IGNORECASE)


class WriteMode(str, Enum):
    DD = "dd"
    EXTRACTED_ISO = "extracted-iso"


class FirmwareTarget(str, Enum):
    AUTOMATIC = "automatic"
    UEFI_ONLY = "uefi-only"
    BIOS_ONLY = "bios-only"
    BOTH = "bios-and-uefi"


class PartitionTable(str, Enum):
    MBR = "mbr"
    GPT = "gpt"


class FileSystem(str, Enum):
    FAT32 = "fat32"
    NTFS = "ntfs"


class BootStrategy(str, Enum):
    IMAGE_NATIVE = "image-native"
    UEFI_NTFS = "uefi-ntfs"


class EntryKind(str, Enum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    HARDLINK = "hardlink"
    BLOCK_DEVICE = "block-device"
    CHARACTER_DEVICE = "character-device"
    FIFO = "fifo"
    SOCKET = "socket"


class RequirementSource(str, Enum):
    SYSTEM = "system"
    IMAGE = "image"
    SYSTEM_OR_VERIFIED_DOWNLOAD = "system-or-verified-download"
    VERIFIED_DOWNLOAD = "verified-download"


class Transformation(str, Enum):
    SPLIT_WINDOWS_WIM = "split-windows-wim"


class PlanError(ValueError):
    """Raised when the requested write plan cannot produce a safe layout."""


class _DistroIsoPolicyPlanError(PlanError):
    """ISO-mode planning was removed by distro compatibility policy."""


class UnsafeArchiveError(PlanError):
    """Raised when an archive member cannot be extracted safely and portably."""


@dataclass(frozen=True)
class ArchiveEntry:
    path: str
    size: int = 0
    kind: EntryKind = EntryKind.FILE
    link_target: str | None = None
    modified_ns: int | None = None

    def __post_init__(self) -> None:
        if type(self.path) is not str:
            raise ValueError("Archive entry paths must be text")
        if type(self.size) is not int or self.size < 0:
            raise ValueError("Archive entry sizes must be non-negative integers")
        if type(self.kind) is not EntryKind:
            raise ValueError("Archive entry kinds must be EntryKind values")
        if self.kind in {EntryKind.SYMLINK, EntryKind.HARDLINK}:
            if type(self.link_target) is not str or not self.link_target:
                raise ValueError(f"{self.kind.value} entries require a link target")
        elif self.link_target is not None:
            raise ValueError("Only link entries may have a link target")
        if self.modified_ns is not None:
            if (
                isinstance(self.modified_ns, bool)
                or not isinstance(self.modified_ns, int)
                or not (
                    MIN_PORTABLE_ARCHIVE_MTIME_NS
                    <= self.modified_ns
                    <= MAX_PORTABLE_ARCHIVE_MTIME_NS
                )
            ):
                raise ValueError("Archive modification times are outside the portable range")
            if self.kind not in {EntryKind.FILE, EntryKind.DIRECTORY}:
                raise ValueError("Only files and directories may carry modification times")


@dataclass(frozen=True)
class DependencyRequirement:
    key: str
    alternatives: tuple[str, ...]
    source: RequirementSource
    reason: str
    version_constraint: str | None = None


@dataclass(frozen=True)
class TargetLayout:
    partition_table: PartitionTable
    main_filesystem: FileSystem
    partition_count: int
    boot_partition_filesystem: FileSystem | None
    bios_bootable: bool
    uefi_bootable: bool
    boot_strategy: BootStrategy = BootStrategy.IMAGE_NATIVE

    @property
    def uses_uefi_ntfs(self) -> bool:
        return self.boot_strategy is BootStrategy.UEFI_NTFS


@dataclass(frozen=True)
class WritePlan:
    mode: WriteMode
    firmware_target: FirmwareTarget
    layout: TargetLayout | None
    requirements: tuple[DependencyRequirement, ...]
    transformations: tuple[Transformation, ...]
    warnings: tuple[str, ...]
    minimum_content_bytes: int
    minimum_target_bytes: int
    content_constraints_checked: bool
    blockers: tuple[str, ...]

    @property
    def needs_wim_split(self) -> bool:
        return Transformation.SPLIT_WINDOWS_WIM in self.transformations

    @property
    def executable(self) -> bool:
        return self.content_constraints_checked and not self.blockers


@dataclass(frozen=True)
class WriteMethodRecommendation:
    available_modes: tuple[WriteMode, ...]
    recommended_mode: WriteMode | None
    reason: str
    dd_plan: WritePlan
    iso_plan: WritePlan | None
    iso_unavailable_reason: str = ""
    distro_iso_exclusion_reason: str = ""


_WINDOWS_DRIVE = re.compile(r"^[a-zA-Z]:")
_WINDOWS_DEVICE = re.compile(
    r"^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])(?:\..*)?$", re.IGNORECASE,
)
_FAT_RESERVED_STEM = re.compile(
    r"^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])$", re.IGNORECASE,
)
_FAT_FORBIDDEN_CHARACTERS = frozenset('<>:"\\|?*')
FAT_MAX_COMPONENT_UTF16_UNITS = 255
FAT_MAX_PATH_DEPTH = 64
FAT_MAX_PATH_UTF8_BYTES = 1024
_SPECIAL_KINDS = {
    EntryKind.BLOCK_DEVICE,
    EntryKind.CHARACTER_DEVICE,
    EntryKind.FIFO,
    EntryKind.SOCKET,
}


def _is_install_wim_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return (
        len(parts) >= 2
        and parts[-1].casefold() == "install.wim"
        and parts[-2].casefold() == "sources"
    )


def _portable_component(component: str, member: str) -> str:
    if not component or component in {".", ".."}:
        raise UnsafeArchiveError(f"Unsafe path component in archive member: {member!r}")
    if any(ord(character) < 32 for character in component):
        raise UnsafeArchiveError(f"Control character in archive member: {member!r}")
    if ":" in component:
        raise UnsafeArchiveError(f"Windows drive or stream syntax in archive member: {member!r}")
    if component.endswith((" ", ".")):
        raise UnsafeArchiveError(f"Trailing dot or space in archive member: {member!r}")
    normalized = unicodedata.normalize("NFC", component)
    if _WINDOWS_DEVICE.fullmatch(normalized):
        raise UnsafeArchiveError(f"Reserved device name in archive member: {member!r}")
    return normalized


def _member_parts(path: str) -> tuple[str, ...]:
    if not path or "\x00" in path:
        raise UnsafeArchiveError("Archive member has an empty path or contains NUL")
    portable = path.replace("\\", "/")
    if portable.startswith("/") or _WINDOWS_DRIVE.match(portable):
        raise UnsafeArchiveError(f"Absolute archive path is forbidden: {path!r}")
    raw_parts = portable.split("/")
    if any(part == ".." for part in raw_parts):
        raise UnsafeArchiveError(f"Parent traversal is forbidden: {path!r}")
    return tuple(_portable_component(part, path) for part in raw_parts)


def _link_destination(member_parts: tuple[str, ...], target: str) -> tuple[str, ...]:
    if not target or "\x00" in target:
        raise UnsafeArchiveError("Link target is empty or contains NUL")
    portable = target.replace("\\", "/")
    if portable.startswith("/") or _WINDOWS_DRIVE.match(portable):
        raise UnsafeArchiveError(f"Absolute link target is forbidden: {target!r}")

    resolved = list(member_parts[:-1])
    for part in portable.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                raise UnsafeArchiveError(f"Link target escapes extraction root: {target!r}")
            resolved.pop()
            continue
        resolved.append(_portable_component(part, target))
    if not resolved:
        raise UnsafeArchiveError(f"Link target resolves to extraction root: {target!r}")
    return tuple(resolved)


def _case_key(parts: tuple[str, ...]) -> tuple[str, ...]:
    # FAT32 and NTFS are case-insensitive by default.  Unicode normalization
    # avoids a second class of aliases (for example, composed/decomposed e-acute).
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in parts)


def validate_extraction_entries(entries: Iterable[ArchiveEntry]) -> tuple[ArchiveEntry, ...]:
    """Validate archive metadata before an extractor is allowed to write.

    The returned entries have normalized POSIX paths.  This function performs
    no filesystem access and is not a substitute for an extractor that uses
    directory file descriptors and refuses to follow links at write time.
    """
    validated: list[ArchiveEntry] = []
    by_key: dict[tuple[str, ...], ArchiveEntry] = {}
    parts_by_key: dict[tuple[str, ...], tuple[str, ...]] = {}

    for entry in entries:
        if entry.kind in _SPECIAL_KINDS:
            raise UnsafeArchiveError(
                f"Special archive entry {entry.kind.value!r} is forbidden: {entry.path!r}"
            )
        parts = _member_parts(entry.path)
        key = _case_key(parts)
        if key in by_key:
            other = by_key[key]
            raise UnsafeArchiveError(
                f"Duplicate or case-colliding archive paths: {other.path!r} and {entry.path!r}"
            )

        link_target = entry.link_target
        if link_target is not None:
            _link_destination(parts, link_target)

        normalized = ArchiveEntry(
            path=PurePosixPath(*parts).as_posix(), size=entry.size,
            kind=entry.kind, link_target=link_target,
            modified_ns=entry.modified_ns,
        )
        by_key[key] = normalized
        parts_by_key[key] = parts
        validated.append(normalized)

    # Reject writes below a file or link.  In particular, an archive must not
    # create a symlink and then use it as a path component to escape the root.
    for key, entry in by_key.items():
        parts = parts_by_key[key]
        for length in range(1, len(parts)):
            ancestor = by_key.get(_case_key(parts[:length]))
            if ancestor is None or ancestor.kind is EntryKind.DIRECTORY:
                continue
            if ancestor.kind is EntryKind.SYMLINK:
                message = "Archive member would be written through a symlink"
            else:
                message = "Archive member has a non-directory ancestor"
            raise UnsafeArchiveError(f"{message}: {entry.path!r}")

    return tuple(validated)


@dataclass(frozen=True)
class AdditiveOverlayMerge:
    """A validated additive namespace ready for a later staging executor.

    ``overlay_entries`` contains only entries that staging still needs to add.
    Overlay directories that already exist in the base namespace are harmless
    merge points and are omitted. Paths below base directories use the base
    namespace's exact spelling. ``merged_entries`` is the complete, revalidated
    catalog after those no-op directory merges have been removed.
    ``overlay_targets`` is aligned one-to-one with the validated input overlay
    catalog and retains canonicalized no-op directories for staging lookup.
    """

    base_entries: tuple[ArchiveEntry, ...]
    overlay_entries: tuple[ArchiveEntry, ...]
    merged_entries: tuple[ArchiveEntry, ...]
    overlay_targets: tuple[ArchiveEntry, ...]


def _utf16_units(value: str, path: str) -> int:
    try:
        return len(value.encode("utf-16-le", errors="strict")) // 2
    except UnicodeEncodeError as error:
        raise UnsafeArchiveError(
            f"FAT path contains invalid Unicode: {path!r}"
        ) from error


def validate_portable_fat_entries(
    entries: Iterable[ArchiveEntry],
) -> tuple[ArchiveEntry, ...]:
    """Validate and NFC-normalize a catalog for a portable FAT namespace.

    The policy is intentionally stricter than any one Linux FAT driver. It
    models the portable intersection needed for removable installation media,
    and performs no filesystem access.
    """

    candidates = tuple(entries)
    for entry in candidates:
        if "\\" in entry.path:
            raise UnsafeArchiveError(
                f"Backslashes are forbidden in portable FAT paths: {entry.path!r}"
            )
    validated = validate_extraction_entries(candidates)

    for entry in validated:
        parts = PurePosixPath(entry.path).parts
        if len(parts) > FAT_MAX_PATH_DEPTH:
            raise UnsafeArchiveError(
                f"FAT path exceeds {FAT_MAX_PATH_DEPTH} components: {entry.path!r}"
            )
        for component in parts:
            if any(ord(character) < 0x20 or ord(character) == 0x7F for character in component):
                raise UnsafeArchiveError(
                    f"Control characters are forbidden in FAT paths: {entry.path!r}"
                )
            if any(character in _FAT_FORBIDDEN_CHARACTERS for character in component):
                raise UnsafeArchiveError(
                    f"FAT-forbidden characters <>:\"/\\|?* appear in: {entry.path!r}"
                )
            if component.endswith((" ", ".")):
                raise UnsafeArchiveError(
                    f"Trailing dot or space is forbidden in FAT paths: {entry.path!r}"
                )
            stem = component.split(".", 1)[0].rstrip(" .")
            if _FAT_RESERVED_STEM.fullmatch(stem):
                raise UnsafeArchiveError(
                    f"Reserved DOS device stem in FAT path: {entry.path!r}"
                )
            if _utf16_units(component, entry.path) > FAT_MAX_COMPONENT_UTF16_UNITS:
                raise UnsafeArchiveError(
                    "FAT path component exceeds "
                    f"{FAT_MAX_COMPONENT_UTF16_UNITS} UTF-16 units: {entry.path!r}"
                )
        try:
            encoded_path = entry.path.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise UnsafeArchiveError(
                f"FAT path contains invalid Unicode: {entry.path!r}"
            ) from error
        if len(encoded_path) > FAT_MAX_PATH_UTF8_BYTES:
            raise UnsafeArchiveError(
                f"FAT path exceeds {FAT_MAX_PATH_UTF8_BYTES} UTF-8 bytes: {entry.path!r}"
            )
    return validated


def _directory_spellings(
    entries: tuple[ArchiveEntry, ...], *, namespace: str,
) -> dict[tuple[str, ...], tuple[str, ...]]:
    """Return canonical spellings for explicit and implied directories."""

    spellings: dict[tuple[str, ...], tuple[str, ...]] = {}
    for entry in entries:
        parts = PurePosixPath(entry.path).parts
        prefix_count = len(parts) if entry.kind is EntryKind.DIRECTORY else len(parts) - 1
        for length in range(1, prefix_count + 1):
            prefix = parts[:length]
            key = _case_key(prefix)
            previous = spellings.get(key)
            if previous is not None and previous != prefix:
                previous_path = PurePosixPath(*previous).as_posix()
                prefix_path = PurePosixPath(*prefix).as_posix()
                raise UnsafeArchiveError(
                    f"Inconsistent {namespace} directory spellings: "
                    f"{previous_path!r} and {prefix_path!r}"
                )
            spellings[key] = prefix
    return spellings


def _reserved_overlay_path(parts: tuple[str, ...]) -> bool:
    folded = tuple(part.casefold() for part in parts)
    if (
        len(folded) >= 3
        and folded[:2] == ("efi", "boot")
        and folded[2].startswith("boot")
        and folded[2].endswith(".efi")
    ):
        return True
    if len(folded) >= 2 and folded[0] == "sources":
        name = folded[1]
        return name in {"install.wim", "install.esd"} or (
            name.startswith("install") and name.endswith(".swm")
        )
    return False


def _entry_with_path(entry: ArchiveEntry, parts: tuple[str, ...]) -> ArchiveEntry:
    return ArchiveEntry(
        PurePosixPath(*parts).as_posix(), entry.size, entry.kind,
        entry.link_target, entry.modified_ns,
    )


def _merge_additive_entries(
    base_entries: Iterable[ArchiveEntry],
    added_entries: Iterable[ArchiveEntry],
    *,
    namespace: str,
    reject_reserved: bool,
) -> AdditiveOverlayMerge:
    base = validate_portable_fat_entries(base_entries)
    overlay = validate_portable_fat_entries(added_entries)
    base_by_key = {
        _case_key(PurePosixPath(entry.path).parts): entry for entry in base
    }
    base_directories = _directory_spellings(base, namespace="base")
    # This rejects ambiguous overlay aliases before base spelling is adopted.
    _directory_spellings(overlay, namespace=namespace)

    additions: list[ArchiveEntry] = []
    targets: list[ArchiveEntry] = []
    for entry in overlay:
        parts = PurePosixPath(entry.path).parts
        if reject_reserved and _reserved_overlay_path(parts):
            raise UnsafeArchiveError(
                f"Overlay path is reserved for boot or installer payloads: {entry.path!r}"
            )
        key = _case_key(parts)
        rewritten = list(parts)
        prefix_count = len(parts) if entry.kind is EntryKind.DIRECTORY else len(parts) - 1
        for length in range(1, prefix_count + 1):
            base_spelling = base_directories.get(_case_key(parts[:length]))
            if base_spelling is not None:
                rewritten[:length] = base_spelling
        target = _entry_with_path(entry, tuple(rewritten))

        base_entry = base_by_key.get(key)
        if base_entry is not None:
            if (
                base_entry.kind is EntryKind.DIRECTORY
                and entry.kind is EntryKind.DIRECTORY
            ):
                targets.append(target)
                continue
            raise UnsafeArchiveError(
                f"{namespace.capitalize()} path collides with the base image: "
                f"{entry.path!r}"
            )

        # A non-directory at an implied base-directory key would become an
        # ancestor of existing base content. An explicit overlay directory at
        # that key is the same harmless directory merge as above.
        if key in base_directories:
            if entry.kind is EntryKind.DIRECTORY:
                targets.append(target)
                continue
            raise UnsafeArchiveError(
                f"{namespace.capitalize()} file would be an ancestor of base "
                f"content: {entry.path!r}"
            )

        for length in range(1, len(parts)):
            ancestor = base_by_key.get(_case_key(parts[:length]))
            if ancestor is not None and ancestor.kind is not EntryKind.DIRECTORY:
                raise UnsafeArchiveError(
                    f"Base file would be an ancestor of overlay content: {entry.path!r}"
                )

        targets.append(target)
        additions.append(target)

    # Re-run both general extraction validation and the complete FAT policy on
    # the final namespace; callers never need to trust the merge implementation.
    if len(base) + len(additions) > ISO_OVERLAY_EFFECTIVE_MEMBER_MAX_COUNT:
        raise UnsafeArchiveError(
            f"The combined ISO and {namespace} catalog contains too many members"
        )
    merged = validate_portable_fat_entries((*base, *additions))
    normalized_additions = validate_portable_fat_entries(additions)
    normalized_targets = validate_portable_fat_entries(targets)
    return AdditiveOverlayMerge(base, normalized_additions, merged, normalized_targets)


def merge_additive_overlay_entries(
    base_entries: Iterable[ArchiveEntry],
    overlay_entries: Iterable[ArchiveEntry],
) -> AdditiveOverlayMerge:
    """Merge an untrusted ZIP overlay without replacing reserved base paths."""

    return _merge_additive_entries(
        base_entries,
        overlay_entries,
        namespace="ZIP overlay",
        reject_reserved=True,
    )


def merge_additive_embedded_entries(
    base_entries: Iterable[ArchiveEntry],
    embedded_entries: Iterable[ArchiveEntry],
) -> AdditiveOverlayMerge:
    """Merge a parsed embedded boot tree without replacing any base file.

    Unlike a user overlay, an embedded tree is allowed to supply the reserved
    removable-media fallback loader that makes construction possible. It still
    cannot overwrite, alias, or become an ancestor of any ordinary ISO member.
    """

    return _merge_additive_entries(
        base_entries,
        embedded_entries,
        namespace="embedded boot image",
        reject_reserved=False,
    )


def merge_additive_generated_entries(
    base_entries: Iterable[ArchiveEntry],
    generated_entries: Iterable[ArchiveEntry],
) -> AdditiveOverlayMerge:
    """Add application-generated files without replacing media content.

    Generated boot files are already constrained by their feature-specific
    planner.  This shared merge still revalidates the complete portable FAT
    namespace, including case aliases and implied-directory collisions.
    """

    return _merge_additive_entries(
        base_entries,
        generated_entries,
        namespace="generated boot",
        reject_reserved=False,
    )


def select_write_mode(inspection: ImageInspection, requested: WriteMode | None = None) -> WriteMode:
    if requested is WriteMode.EXTRACTED_ISO and not (
        inspection.is_iso9660 or inspection.kind == "Optical ISO"
    ):
        raise PlanError("Extracted mode requires an ISO filesystem image")
    if requested is not None:
        return requested
    return WriteMode.EXTRACTED_ISO if (
        inspection.is_iso9660 or inspection.kind == "Optical ISO"
    ) else WriteMode.DD


def _requirement(
    key: str,
    alternatives: tuple[str, ...],
    source: RequirementSource,
    reason: str,
    version_constraint: str | None = None,
) -> DependencyRequirement:
    return DependencyRequirement(key, alternatives, source, reason, version_constraint)


def _boot_requirements(
    inspection: ImageInspection, layout: TargetLayout,
) -> list[DependencyRequirement]:
    requirements: list[DependencyRequirement] = []
    bootloader = inspection.bootloader.casefold()

    if layout.bios_bootable and "syslinux" in bootloader:
        requirements.append(_requirement(
            "matching-syslinux-bios", ("syslinux", "extlinux"),
            RequirementSource.SYSTEM_OR_VERIFIED_DOWNLOAD,
            "Install BIOS boot code compatible with the image's Syslinux files.",
            inspection.bootloader_dependency or "match-image-version",
        ))
    elif layout.bios_bootable and "grub" in bootloader:
        requirements.append(_requirement(
            "matching-grub-i386-pc", ("grub-install",),
            RequirementSource.SYSTEM_OR_VERIFIED_DOWNLOAD,
            "Install GRUB BIOS boot code compatible with the image.",
            inspection.bootloader_dependency or "match-image-version",
        ))
    elif layout.bios_bootable and "windows boot manager" in bootloader:
        requirements.append(_requirement(
            "windows-bios-boot-files", ("bootmgr", "boot/bcd"),
            RequirementSource.IMAGE,
            "Preserve the Windows BIOS boot files supplied by the ISO.",
        ))
        requirements.append(_requirement(
            "windows-bios-boot-code", ("ms-sys", "bootsect.exe"),
            RequirementSource.SYSTEM_OR_VERIFIED_DOWNLOAD,
            "Install compatible Windows MBR and partition boot-record code.",
            "match-windows-generation",
        ))
    elif layout.bios_bootable:
        requirements.append(_requirement(
            "supported-bios-installer", ("grub-install", "syslinux"),
            RequirementSource.SYSTEM_OR_VERIFIED_DOWNLOAD,
            "The image's BIOS bootloader was not recognized and needs a supported installer.",
        ))

    if layout.uefi_bootable:
        architectures = inspection.architectures or ("unknown",)
        for architecture in architectures:
            requirements.append(_requirement(
                f"efi-removable-loader-{architecture.casefold()}", ("EFI/BOOT/BOOT*.EFI",),
                RequirementSource.IMAGE,
                f"Preserve the removable-media UEFI loader for {architecture}.",
            ))

    if layout.uses_uefi_ntfs:
        requirements.append(_requirement(
            "uefi-ntfs", ("uefi-ntfs.img",), RequirementSource.VERIFIED_DOWNLOAD,
            "UEFI firmware generally cannot read the NTFS data partition directly.",
            "catalog-pinned-version",
        ))
    return requirements


def build_write_plan(
    inspection: ImageInspection,
    entries: Iterable[ArchiveEntry] = (),
    *,
    requested_mode: WriteMode | None = None,
    requested_filesystem: FileSystem | None = None,
    firmware_target: FirmwareTarget = FirmwareTarget.AUTOMATIC,
    target_size: int | None = None,
    target_logical_sector_size: int | None = None,
) -> WritePlan:
    """Build a pure, immutable plan; never partitions, formats, mounts, or writes."""
    mode = select_write_mode(inspection, requested_mode)
    if not isinstance(firmware_target, FirmwareTarget):
        raise PlanError("The firmware target is invalid")
    if target_size is not None and target_size < 0:
        raise PlanError("Target size cannot be negative")
    if (
        target_logical_sector_size is not None
        and (
            isinstance(target_logical_sector_size, bool)
            or not isinstance(target_logical_sector_size, int)
            or target_logical_sector_size < 0
        )
    ):
        raise PlanError("Target logical sector size cannot be negative")

    if mode is WriteMode.DD:
        if inspection.sparse_format:
            if inspection.sparse_format != "VTSI":
                raise PlanError("The sparse image format is not supported")
            if target_size is not None and target_size != inspection.size:
                raise PlanError(
                    "A VTSI restore requires a target whose capacity exactly "
                    "matches the expanded disk image"
                )
            if (
                target_logical_sector_size is not None
                and target_logical_sector_size != 512
            ):
                raise PlanError(
                    "A VTSI restore requires a target that reports 512-byte "
                    "logical sectors"
                )
        if target_size is not None and target_size < inspection.size:
            raise PlanError("The target is smaller than the byte-for-byte image")
        warnings: tuple[str, ...] = ()
        if inspection.partition_table_malformed:
            warnings = (
                "This image contains malformed MBR or GPT metadata. DD mode remains "
                "available only as an explicit byte-for-byte choice and may not boot.",
            )
        elif inspection.partition_table_incomplete:
            warnings = (
                "The compressed image's partition table could not be fully inspected "
                "within the bounded prefix/tail metadata capture. DD mode remains an "
                "explicit exact-copy choice, but ISOpropyl cannot recommend it as a "
                "validated disk layout.",
            )
        elif partition_sector_mismatch(
            inspection, target_logical_sector_size,
        ):
            mismatch = _sector_mismatch_reason(inspection)
            warnings = (
                mismatch + " DD mode remains an explicit exact-copy choice, but "
                "the resulting partition table will not describe the target correctly.",
            )
        elif partition_sector_unverified(
            inspection, target_logical_sector_size,
        ):
            warnings = (
                "The selected target did not report its logical sector size. DD mode "
                "remains an explicit exact-copy choice, but ISOpropyl cannot validate "
                "the image's structured partition LBAs against this drive.",
            )
        elif not inspection.raw_compatible:
            warnings = ("This optical-only ISO may not boot when copied byte-for-byte.",)
        return WritePlan(
            mode=mode, firmware_target=FirmwareTarget.AUTOMATIC, layout=None,
            requirements=(), transformations=(), warnings=warnings,
            minimum_content_bytes=inspection.size, minimum_target_bytes=inspection.size,
            content_constraints_checked=True, blockers=(),
        )

    try:
        distro_exclusion = match_distro_iso_exclusion(inspection)
    except DistroPolicyError as error:
        raise _DistroIsoPolicyPlanError(
            f"ISO-mode compatibility evidence is unsafe: {error}"
        ) from error
    if distro_exclusion is not None:
        raise _DistroIsoPolicyPlanError(distro_exclusion.reason)

    supplied_entries = tuple(entries)
    safe_entries = validate_extraction_entries(supplied_entries)
    content_bytes = sum(
        entry.size for entry in safe_entries if entry.kind is EntryKind.FILE
    )
    oversized = tuple(
        entry for entry in safe_entries
        if entry.kind is EntryKind.FILE and entry.size > FAT32_MAX_FILE_SIZE
    )
    install_sources = tuple(
        entry for entry in safe_entries
        if entry.kind is EntryKind.FILE and (
            _is_install_wim_path(entry.path)
            or entry.path.casefold() == "sources/install.esd"
        )
    )
    # Windows Setup knows how to consume split SWM parts at the conventional
    # sources/install.wim location.  A nested source may be referenced by an
    # answer-file Path; splitting it would remove that exact path and is not a
    # semantics-preserving transformation.  Preserve nested and multi-source
    # media unchanged on NTFS instead.
    large_wims = tuple(
        entry for entry in oversized
        if len(install_sources) == 1
        and entry.path.casefold() == "sources/install.wim"
    )
    non_wim_oversized = tuple(entry for entry in oversized if entry not in large_wims)

    transformations: list[Transformation] = []
    if requested_filesystem is FileSystem.FAT32 and non_wim_oversized:
        blocked = non_wim_oversized[0]
        raise PlanError(
            f"FAT32 cannot hold {blocked.path!r}; its per-file limit is 4 GiB minus 1 byte"
        )
    if requested_filesystem is not None:
        filesystem = requested_filesystem
    elif non_wim_oversized:
        filesystem = FileSystem.NTFS
    else:
        filesystem = FileSystem.FAT32
    if filesystem is FileSystem.FAT32 and large_wims:
        transformations.append(Transformation.SPLIT_WINDOWS_WIM)

    detected_bios = "BIOS" in inspection.boot_modes
    detected_uefi = "UEFI" in inspection.boot_modes
    if firmware_target is FirmwareTarget.UEFI_ONLY:
        if not detected_uefi:
            raise PlanError("The image has no detected UEFI boot path")
        bios, uefi = False, True
    elif firmware_target is FirmwareTarget.BIOS_ONLY:
        if not detected_bios:
            raise PlanError("The image has no detected BIOS boot path")
        bios, uefi = True, False
    elif firmware_target is FirmwareTarget.BOTH:
        if not (detected_bios and detected_uefi):
            raise PlanError("The image does not contain both BIOS and UEFI boot paths")
        bios, uefi = True, True
    else:
        bios, uefi = detected_bios, detected_uefi
    partition_table = PartitionTable.MBR if bios or not uefi else PartitionTable.GPT
    uefi_ntfs = uefi and filesystem is FileSystem.NTFS
    layout = TargetLayout(
        partition_table=partition_table,
        main_filesystem=filesystem,
        partition_count=2 if uefi_ntfs else 1,
        # UEFI:NTFS uses a catalog-pinned raw FAT12 image, not a formatter-
        # created FAT32 filesystem. Keep the field empty rather than
        # misrepresenting the on-media structure.
        boot_partition_filesystem=None,
        bios_bootable=bios,
        uefi_bootable=uefi,
        boot_strategy=(
            BootStrategy.UEFI_NTFS if uefi_ntfs else BootStrategy.IMAGE_NATIVE
        ),
    )

    requirements = [
        _requirement(
            "iso-extractor", ("7z", "xorriso"), RequirementSource.SYSTEM,
            "Extract ISO members without interpreting archive paths as host paths.",
        ),
        _requirement(
            "partitioner", ("sfdisk",), RequirementSource.SYSTEM,
            f"Create the planned {partition_table.value.upper()} layout.",
        ),
        _requirement(
            f"formatter-{filesystem.value}",
            ("mkfs.vfat",) if filesystem is FileSystem.FAT32 else ("mkfs.ntfs",),
            RequirementSource.SYSTEM,
            f"Create the planned {filesystem.value.upper()} filesystem.",
        ),
    ]
    if transformations:
        requirements.append(_requirement(
            "wim-splitter", ("wimlib-imagex",), RequirementSource.SYSTEM,
            f"Split the sole install.wim into parts no larger than {WIM_SPLIT_PART_SIZE} bytes.",
        ))
    requirements.extend(_boot_requirements(inspection, layout))

    # Partition alignment, filesystem metadata, directory entries, split-WIM
    # metadata and an optional EFI partition all require space beyond the sum
    # of file payloads. This conservative lower bound is still rechecked by an
    # eventual executor after creating the real filesystems.
    overhead = max(64 * 1024**2, content_bytes // 100)
    if layout.partition_count > 1:
        overhead += 16 * 1024**2
    minimum_target = content_bytes + overhead
    if target_size is not None and minimum_target > target_size:
        raise PlanError(
            "The target is too small for the extracted content, partitions, and filesystem metadata"
        )

    warnings: list[str] = []
    blockers: list[str] = []
    if not supplied_entries or inspection.contents_scanned is not True:
        warnings.append(
            "ISO file sizes and extraction paths have not been checked; rescan before execution."
        )
        blockers.append("The ISO member catalog has not been scanned and validated.")
    if not inspection.boot_modes:
        warnings.append("No BIOS or UEFI boot path was detected in the image.")
        blockers.append("No supported firmware boot path was detected.")
    if bios:
        blockers.append(
            "BIOS construction is not enabled; choose UEFI-only or use DD mode."
        )
    if not uefi:
        blockers.append("The constructed-media executor currently requires a UEFI boot path.")
    elif not inspection.architectures:
        blockers.append(
            "No recognized EFI/BOOT removable-media fallback loader was found."
        )
    else:
        fallback_paths = {
            entry.path.casefold()
            for entry in safe_entries
            if entry.kind is EntryKind.FILE
            and len(PurePosixPath(entry.path).parts) == 3
            and PurePosixPath(entry.path).parts[0].casefold() == "efi"
            and PurePosixPath(entry.path).parts[1].casefold() == "boot"
            and _FALLBACK_LOADER.fullmatch(PurePosixPath(entry.path).parts[2])
            and entry.size > 0
        }
        validated_payloads = {
            payload.target_path.casefold(): payload.architecture
            for payload in inspection.uefi_payloads
            if payload.is_uefi_image
        }
        invalid_fallbacks = sorted(fallback_paths - validated_payloads.keys())
        mismatched_fallbacks = sorted(
            path for path in fallback_paths & validated_payloads.keys()
            if not fallback_loader_matches_architecture(
                PurePosixPath(path).name,
                validated_payloads[path],
            )
        )
        if not fallback_paths:
            blockers.append(
                "The validated ISO catalog contains no non-empty EFI/BOOT fallback loader."
            )
        elif invalid_fallbacks:
            blockers.append(
                f"Fallback loader {invalid_fallbacks[0]!r} was not structurally "
                "validated as an EFI application."
            )
        elif mismatched_fallbacks:
            path = mismatched_fallbacks[0]
            blockers.append(
                f"Fallback loader {path!r} contains {validated_payloads[path]} code, "
                "which does not match its removable-media filename."
            )
    if not (
        (filesystem is FileSystem.FAT32 and layout.partition_count == 1)
        or (
            layout.boot_strategy is BootStrategy.UEFI_NTFS
            and filesystem is FileSystem.NTFS
            and layout.partition_count == 2
            and firmware_target is FirmwareTarget.UEFI_ONLY
        )
    ):
        blockers.append("No constructed-media executor supports the requested layout.")
    if layout.boot_strategy is BootStrategy.UEFI_NTFS:
        unsupported = next(
            (
                architecture for architecture in inspection.architectures
                if architecture not in {"x64", "x86", "ARM64", "ARM", "RISC-V64"}
            ),
            None,
        )
        if unsupported == "LoongArch64":
            blockers.append(
                "The pinned UEFI:NTFS image has no complete LoongArch64 payload pair."
            )
        elif unsupported is not None:
            blockers.append(
                f"UEFI:NTFS execution is not enabled for {unsupported}."
            )
        unsigned = tuple(
            architecture for architecture in inspection.architectures
            if architecture in {"ARM", "RISC-V64"}
        )
        if unsigned:
            warnings.append(
                "The " + ", ".join(unsigned) + " UEFI:NTFS payload is unsigned; "
                "it requires explicit consent and Secure Boot disabled."
            )
    if any(entry.kind in {EntryKind.SYMLINK, EntryKind.HARDLINK} for entry in safe_entries):
        blockers.append(
            "Constructed-media execution does not yet materialize ISO symbolic or hard links."
        )
    if bios and inspection.bootloader == "Unknown":
        blockers.append("The BIOS bootloader is unknown; ISOpropyl will not guess an installer.")
    if bios and inspection.bootloader_identity_ambiguous:
        blockers.append(
            f"The {inspection.bootloader} identity is incomplete or conflicting."
        )
    elif (
        bios and inspection.bootloader in {"GRUB", "Syslinux/Isolinux"}
        and not inspection.bootloader_dependency
    ):
        blockers.append(
            f"The exact {inspection.bootloader} build has not been identified for dependency matching."
        )

    return WritePlan(
        mode=mode, firmware_target=firmware_target, layout=layout,
        requirements=tuple(requirements),
        transformations=tuple(transformations), warnings=tuple(warnings),
        minimum_content_bytes=content_bytes, minimum_target_bytes=minimum_target,
        content_constraints_checked=(
            bool(supplied_entries) and inspection.contents_scanned is True
        ),
        blockers=tuple(blockers),
    )


def partition_sector_mismatch(
    inspection: ImageInspection,
    target_logical_sector_size: int | None,
) -> bool:
    """Return whether a validated disk layout uses target-incompatible LBAs."""

    return bool(
        inspection.partition_table_valid is True
        and inspection.partition_table_sector_size > 0
        and target_logical_sector_size is not None
        and target_logical_sector_size > 0
        and inspection.partition_table_sector_size != target_logical_sector_size
    )


def partition_sector_unverified(
    inspection: ImageInspection,
    target_logical_sector_size: int | None,
) -> bool:
    """Return whether a selected target omitted needed sector-size metadata."""

    return bool(
        inspection.partition_table_valid is True
        and inspection.partition_table_sector_size > 0
        and target_logical_sector_size == 0
    )


def _sector_mismatch_reason(inspection: ImageInspection) -> str:
    if inspection.partition_table_kind == "mbr":
        return (
            "Under the conventional assumed 512-byte MBR interpretation, the "
            "image and selected target have different logical sector sizes."
        )
    return "The image and selected target use different logical sector sizes."


def recommend_write_method(
    inspection: ImageInspection,
    entries: Iterable[ArchiveEntry] = (),
    *,
    target_size: int | None = None,
    target_logical_sector_size: int | None = None,
) -> WriteMethodRecommendation:
    """Recommend a visible write method without silently changing the user's choice."""
    if target_size is not None and (
        isinstance(target_size, bool) or not isinstance(target_size, int)
        or target_size < 0
    ):
        raise PlanError("Target size cannot be negative")
    if (
        target_logical_sector_size is not None
        and (
            isinstance(target_logical_sector_size, bool)
            or not isinstance(target_logical_sector_size, int)
            or target_logical_sector_size < 0
        )
    ):
        raise PlanError("Target logical sector size cannot be negative")
    frozen_entries = tuple(entries)
    is_vtsi = inspection.sparse_format == "VTSI"
    dd_plan = build_write_plan(
        inspection, frozen_entries, requested_mode=WriteMode.DD,
        target_logical_sector_size=(
            None if is_vtsi else target_logical_sector_size
        ),
    )
    vtsi_capacity_matches = target_size is None or target_size == inspection.size
    vtsi_sector_matches = (
        target_logical_sector_size is None or target_logical_sector_size == 512
    )
    dd_available = (
        (target_size is None or dd_plan.minimum_target_bytes <= target_size)
        and (not is_vtsi or vtsi_capacity_matches)
        and (not is_vtsi or vtsi_sector_matches)
    )
    sector_mismatch = partition_sector_mismatch(
        inspection, target_logical_sector_size,
    )
    sector_unverified = partition_sector_unverified(
        inspection, target_logical_sector_size,
    )
    is_iso = inspection.is_iso9660 or inspection.kind == "Optical ISO"
    if not is_iso:
        modes = (WriteMode.DD,) if dd_available else ()
        malformed = inspection.partition_table_malformed
        incomplete = inspection.partition_table_incomplete
        requires_explicit_dd = (
            malformed or incomplete or sector_mismatch or sector_unverified
        )
        return WriteMethodRecommendation(
            modes,
            WriteMode.DD if dd_available and not requires_explicit_dd else None,
            (
                "VTSI restore expands every described data extent and zero-filled "
                "gap into a target with the exact original disk capacity."
                if dd_available and is_vtsi else
                "The selected target capacity does not exactly match the expanded "
                "VTSI disk image."
                if is_vtsi and not vtsi_capacity_matches else
                "VTSI restore requires a target that reports 512-byte logical sectors."
                if is_vtsi and not vtsi_sector_matches else
                "The image contains malformed partition metadata. DD mode remains "
                "available as an explicit byte-for-byte choice, but is not recommended."
                if dd_available and malformed else
                "The compressed image's partition table could not be fully inspected. "
                "DD remains an explicit exact-copy choice, but is not recommended."
                if dd_available and incomplete else
                _sector_mismatch_reason(inspection) + " DD remains an explicit "
                "exact-copy choice, but is not recommended."
                if dd_available and sector_mismatch else
                "The selected target did not report its logical sector size. DD "
                "remains an explicit exact-copy choice, but its structured partition "
                "layout cannot be recommended without that geometry."
                if dd_available and sector_unverified else
                "DD mode is required for raw and virtual disk images because it "
                "preserves their existing partition layout."
                if dd_available else
                "The selected target is too small for this byte-for-byte image."
            ),
            dd_plan,
            None,
            "ISO mode requires an ISO filesystem image.",
        )

    iso_plan: WritePlan | None = None
    iso_error = ""
    distro_iso_exclusion_reason = ""
    try:
        iso_plan = build_write_plan(
            inspection,
            frozen_entries,
            requested_mode=WriteMode.EXTRACTED_ISO,
            firmware_target=FirmwareTarget.UEFI_ONLY,
        )
    except _DistroIsoPolicyPlanError as error:
        iso_error = str(error)
        distro_iso_exclusion_reason = iso_error
    except PlanError as error:
        iso_error = str(error)
    iso_available = bool(iso_plan and iso_plan.executable)
    if iso_available and target_size is not None:
        assert iso_plan is not None
        if iso_plan.minimum_target_bytes > target_size:
            iso_available = False
            iso_error = (
                "The selected target is too small for the extracted ISO layout."
            )
    if iso_plan is not None and not iso_plan.executable and not iso_error:
        iso_error = iso_plan.blockers[0] if iso_plan.blockers else (
            "The ISO does not have an executable filesystem-aware plan."
        )

    available: list[WriteMode] = []
    if dd_available:
        available.append(WriteMode.DD)
    if iso_available:
        available.append(WriteMode.EXTRACTED_ISO)

    if iso_available and inspection.has_windows_installer:
        recommended = WriteMode.EXTRACTED_ISO
        reason = (
            "ISO mode is recommended for this Windows installer so its files, "
            "large-WIM handling, and selected customization can be applied."
        )
    elif iso_available and (
        not inspection.raw_compatible or sector_mismatch or sector_unverified
    ):
        recommended = WriteMode.EXTRACTED_ISO
        reason = (
            "ISO mode is recommended because "
            + _sector_mismatch_reason(inspection).removesuffix(".").lower()
            + "."
            if sector_mismatch else
            "ISO mode is recommended because the selected target did not report "
            "the logical sector size needed to validate the image's partition LBAs."
            if sector_unverified else
            "ISO mode is recommended because the compressed image's partition table "
            "could not be fully inspected within the bounded prefix/tail metadata "
            "capture."
            if inspection.partition_table_incomplete else
            "ISO mode is recommended because the image's MBR or GPT metadata is "
            "malformed and should not be treated as a raw-write-ready disk layout."
            if inspection.partition_table_malformed else
            "ISO mode is recommended because this optical-only image has no "
            "USB-native MBR or GPT layout to preserve with DD."
        )
    elif (
        dd_available and inspection.raw_compatible
        and not sector_mismatch and not sector_unverified
    ):
        recommended = WriteMode.DD
        reason = (
            "DD mode is recommended for this hybrid ISO because it preserves the "
            "image's native BIOS/UEFI disk layout exactly."
        )
    elif iso_available:
        recommended = WriteMode.EXTRACTED_ISO
        reason = "Only the filesystem-aware ISO layout fits the selected target."
    elif dd_available:
        recommended = None
        reason = (
            _sector_mismatch_reason(inspection) + " DD remains an explicit "
            "exact-copy choice, but is not recommended."
            if sector_mismatch else
            "The selected target did not report its logical sector size. DD remains "
            "an explicit exact-copy choice, but is not recommended for a structured "
            "partition image."
            if sector_unverified else
            "The compressed image's partition table could not be fully inspected. DD "
            "remains an explicit exact-copy choice, but is not recommended."
            if inspection.partition_table_incomplete else
            "The image's MBR or GPT metadata is malformed. DD mode remains available "
            "as an explicit byte-for-byte choice, but is not recommended."
            if inspection.partition_table_malformed else
            "DD mode remains available only as an explicit byte-for-byte choice, "
            "but this optical-only image has no USB-native disk layout and may not boot."
        )
    else:
        recommended = None
        reason = (
            "The selected target is too small for this byte-for-byte image."
            if target_size is not None and target_size < inspection.size else
            iso_error or "No safe write method fits the selected target."
        )

    return WriteMethodRecommendation(
        tuple(available), recommended, reason, dd_plan, iso_plan, iso_error,
        distro_iso_exclusion_reason,
    )
