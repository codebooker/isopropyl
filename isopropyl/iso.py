from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Iterable

from isopropyl.images import ImageInspection


# FAT stores a file's size in an unsigned 32-bit field.  The largest valid
# individual file is therefore one byte smaller than 4 GiB.
FAT32_MAX_FILE_SIZE = (4 * 1024**3) - 1
WIM_SPLIT_PART_SIZE = 3800 * 1024**2
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


class UnsafeArchiveError(PlanError):
    """Raised when an archive member cannot be extracted safely and portably."""


@dataclass(frozen=True)
class ArchiveEntry:
    path: str
    size: int = 0
    kind: EntryKind = EntryKind.FILE
    link_target: str | None = None

    def __post_init__(self) -> None:
        if self.size < 0:
            raise ValueError("Archive entry sizes cannot be negative")
        if self.kind in {EntryKind.SYMLINK, EntryKind.HARDLINK}:
            if not self.link_target:
                raise ValueError(f"{self.kind.value} entries require a link target")
        elif self.link_target is not None:
            raise ValueError("Only link entries may have a link target")


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

    @property
    def uses_uefi_ntfs(self) -> bool:
        return self.uefi_bootable and self.main_filesystem is FileSystem.NTFS


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


_WINDOWS_DRIVE = re.compile(r"^[a-zA-Z]:")
_WINDOWS_DEVICE = re.compile(
    r"^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])(?:\..*)?$", re.IGNORECASE,
)
_SPECIAL_KINDS = {
    EntryKind.BLOCK_DEVICE,
    EntryKind.CHARACTER_DEVICE,
    EntryKind.FIFO,
    EntryKind.SOCKET,
}


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
) -> WritePlan:
    """Build a pure, immutable plan; never partitions, formats, mounts, or writes."""
    mode = select_write_mode(inspection, requested_mode)
    if not isinstance(firmware_target, FirmwareTarget):
        raise PlanError("The firmware target is invalid")
    if target_size is not None and target_size < 0:
        raise PlanError("Target size cannot be negative")

    if mode is WriteMode.DD:
        if target_size is not None and target_size < inspection.size:
            raise PlanError("The target is smaller than the byte-for-byte image")
        warnings: tuple[str, ...] = ()
        if not inspection.raw_compatible:
            warnings = ("This optical-only ISO may not boot when copied byte-for-byte.",)
        return WritePlan(
            mode=mode, firmware_target=FirmwareTarget.AUTOMATIC, layout=None,
            requirements=(), transformations=(), warnings=warnings,
            minimum_content_bytes=inspection.size, minimum_target_bytes=inspection.size,
            content_constraints_checked=True, blockers=(),
        )

    supplied_entries = tuple(entries)
    safe_entries = validate_extraction_entries(supplied_entries)
    content_bytes = sum(
        entry.size for entry in safe_entries if entry.kind is EntryKind.FILE
    )
    oversized = tuple(
        entry for entry in safe_entries
        if entry.kind is EntryKind.FILE and entry.size > FAT32_MAX_FILE_SIZE
    )
    large_wims = tuple(
        entry for entry in oversized if entry.path.casefold() == "sources/install.wim"
    )
    non_wim_oversized = tuple(entry for entry in oversized if entry not in large_wims)

    transformations: list[Transformation] = []
    if requested_filesystem is FileSystem.FAT32 and non_wim_oversized:
        raise PlanError(
            f"FAT32 cannot hold {non_wim_oversized[0].path!r}; its per-file limit is 4 GiB minus 1 byte"
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
        boot_partition_filesystem=FileSystem.FAT32 if uefi_ntfs else None,
        bios_bootable=bios,
        uefi_bootable=uefi,
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
            f"Split sources/install.wim into parts no larger than {WIM_SPLIT_PART_SIZE} bytes.",
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
    if not supplied_entries:
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
            payload.path.casefold()
            for payload in inspection.uefi_payloads
            if payload.is_uefi_image
        }
        invalid_fallbacks = sorted(fallback_paths - validated_payloads)
        if not fallback_paths:
            blockers.append(
                "The validated ISO catalog contains no non-empty EFI/BOOT fallback loader."
            )
        elif invalid_fallbacks:
            blockers.append(
                f"Fallback loader {invalid_fallbacks[0]!r} was not structurally "
                "validated as an EFI application."
            )
    if filesystem is not FileSystem.FAT32 or layout.partition_count != 1:
        blockers.append(
            "Constructed-media execution currently supports one FAT32 partition only."
        )
    if any(entry.kind in {EntryKind.SYMLINK, EntryKind.HARDLINK} for entry in safe_entries):
        blockers.append(
            "FAT32 construction does not yet materialize ISO symbolic or hard links."
        )
    if bios and inspection.bootloader == "Unknown":
        blockers.append("The BIOS bootloader is unknown; ISOpropyl will not guess an installer.")
    if bios and inspection.bootloader_identity_ambiguous:
        blockers.append(f"Conflicting {inspection.bootloader} identities were detected.")
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
        content_constraints_checked=bool(supplied_entries),
        blockers=tuple(blockers),
    )
