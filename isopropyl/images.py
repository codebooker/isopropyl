from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import calendar
import enum
import hashlib
import hmac
import os
import re
import select
import shutil
import stat
import struct
import subprocess
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath

from .sources import ExpandedImageTooLarge, ImageSource, open_image_source
from .timestamps import (
    MAX_PORTABLE_ARCHIVE_MTIME_NS, MIN_PORTABLE_ARCHIVE_MTIME_NS,
)
from .partition_tables import (
    PARTITION_TABLE_CAPTURE_BYTES, PartitionTableInspection,
    inspect_partition_tables_capture,
    inspect_partition_tables_fd,
)
from .boot_identity import BootloaderAnalysis, analyze_iso_bootloaders
from .eltorito import (
    BootPlatform, ElToritoError, ElToritoInspection, ElToritoNotFound,
    inspect_eltorito_file,
)
from .fat_image import (
    EmbeddedFatImage,
    FatImageError,
    inspect_uefi_eltorito_fats,
    read_embedded_fat_file,
)
from .uefi import (
    MAX_PE_SIZE,
    MAX_UEFI_MEMBERS,
    ImageUefiAnalysis,
    ImageUefiPayload,
    fallback_loader_architecture,
    fallback_loader_matches_architecture,
    inspect_iso_uefi_payloads,
    inspect_pe_bytes,
)
from .virtual import CompressedVirtualDiskPreparer, inspect_virtual_disk
from .windows_paths import validate_install_image_member_path

Progress = Callable[[int, int], None]

CHECKSUM_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
RAW_IMAGE_SUFFIXES = frozenset({".img", ".raw", ".usb", ".wic"})
VIRTUAL_SUFFIXES = frozenset({".vhd", ".vhdx", ".qcow", ".qcow2"})
SPARSE_SUFFIXES = frozenset({".vtsi"})
NON_RAW_SUFFIXES = frozenset({".wim", ".esd", ".ffu"})
COMPRESSION_SUFFIXES = frozenset({
    ".gz", ".gzip", ".bz2", ".bzip2", ".xz", ".lzma", ".zst", ".zstd",
    ".z", ".zip",
})
MAX_INSPECTION_EXPANDED_BYTES = 64 * 1024**4
INSPECTION_TIMEOUT_SECONDS = 5 * 60.0
_TRUSTED_7Z_PATH = "/usr/bin:/bin"
_TRUSTED_7Z_DIRECTORIES = frozenset(_TRUSTED_7Z_PATH.split(":"))
MAX_7Z_CATALOG_BYTES = 16 * 1024 * 1024
MAX_IMAGE_MEMBERS = 65_536
MAX_WINDOWS_WIM_CANDIDATES = 4
_SEVEN_ZIP_MODIFIED = re.compile(
    r"(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?"
)
_SQUASHFS_SUPERBLOCK = struct.Struct("<IIIIIHHHHHHQQQQQQQQ")
_SQUASHFS_MAGIC = 0x73717368
_SQUASHFS_INVALID_TABLE = 0xFFFFFFFFFFFFFFFF
_SQUASHFS_COMPRESSIONS = {
    1: "zlib",
    2: "LZMA",
    3: "LZO",
    4: "XZ",
    5: "LZ4",
    6: "Zstandard",
}


class ImageInspectionCancelled(Exception):
    pass


class SevenZipNamespace(enum.Enum):
    """One explicit optical namespace understood by 7-Zip."""

    UDF = "Udf"
    ISO9660 = "Iso"


@dataclass(frozen=True)
class ImageCatalogScan:
    members: tuple["ImageMember", ...]
    complete: bool
    namespace: SevenZipNamespace | None


class ImageInspectionTimedOut(OSError):
    pass


class ChecksumCancelled(Exception):
    """Checksum calculation was cancelled before publishing a result."""


@dataclass(frozen=True)
class ImageMember:
    path: str
    size: int
    kind: str
    link_target: str = ""
    modified_ns: int | None = None


@dataclass(frozen=True)
class WindowsInstallerCandidates:
    """Bounded Windows installer payload candidates from one member catalog.

    ``valid`` is false when installer-looking members are unsafe, aliased, or
    exceed the supported WIM bound.  Callers must then ignore every candidate.
    """

    wim_paths: tuple[str, ...] = ()
    esd_path: str | None = None
    valid: bool = True

    @property
    def has_installer(self) -> bool:
        return self.valid and bool(self.wim_paths or self.esd_path)


@dataclass(frozen=True)
class SquashFsInspection:
    """Validated fields from one standalone SquashFS 4.0 superblock."""

    inode_count: int
    created_at: int
    block_size: int
    fragment_count: int
    compression: str
    bytes_used: int
    version: str = "4.0"


@dataclass(frozen=True)
class ImageInspection:
    size: int
    kind: str
    volume_label: str
    has_mbr: bool
    has_gpt: bool
    is_iso9660: bool
    looks_windows: bool
    boot_modes: tuple[str, ...]
    architectures: tuple[str, ...]
    bootloader: str
    has_windows_installer: bool
    contents_scanned: bool
    compression: str = "none"
    members: tuple[ImageMember, ...] = ()
    bootloader_version: str = ""
    bootloader_build: str = ""
    bootloader_dependency: str = ""
    bootloader_identity_ambiguous: bool = False
    bootloader_issues: tuple[str, ...] = ()
    uefi_payloads: tuple[ImageUefiPayload, ...] = ()
    uefi_analysis_issues: tuple[str, ...] = ()
    eltorito: ElToritoInspection | None = None
    eltorito_issues: tuple[str, ...] = ()
    virtual_format: str = ""
    container_size: int = 0
    partition_table_valid: bool | None = None
    partition_table_kind: str = ""
    partition_table_sector_size: int = 0
    partition_table_issues: tuple[str, ...] = ()
    mbr_kind: str = ""
    mbr_boot_code: str = ""
    partition_table_inspection_complete: bool = True
    sparse_format: str = ""
    decoded_container_size: int = 0
    uefi_analysis_complete: bool = True
    uefi_candidate_count: int = 0
    uefi_selected_count: int = 0
    embedded_uefi_fat: EmbeddedFatImage | None = None
    embedded_uefi_issues: tuple[str, ...] = ()
    squashfs: SquashFsInspection | None = None
    embedded_uefi_fats: tuple[EmbeddedFatImage, ...] = ()

    def __post_init__(self) -> None:
        """Normalize the legacy singular embedded-FAT view.

        ``embedded_uefi_fats`` is authoritative for new callers. Accepting a
        legacy singular constructor argument keeps saved/test inspection
        fixtures usable, while the singular attribute deliberately becomes
        unavailable when an ISO contains more than one embedded EFI image.
        """

        fats = self.embedded_uefi_fats
        legacy = self.embedded_uefi_fat
        if legacy is not None and not fats:
            fats = (legacy,)
            object.__setattr__(self, "embedded_uefi_fats", fats)
        elif legacy is not None and fats != (legacy,):
            raise ValueError(
                "embedded_uefi_fat must match the sole embedded_uefi_fats item"
            )
        compatible = fats[0] if len(fats) == 1 else None
        if legacy is not compatible:
            object.__setattr__(self, "embedded_uefi_fat", compatible)

    @property
    def partition_table_incomplete(self) -> bool:
        return bool(
            (self.has_mbr or self.has_gpt)
            and not self.partition_table_inspection_complete
        )

    @property
    def partition_table_malformed(self) -> bool:
        return bool(
            (self.has_mbr or self.has_gpt)
            and self.partition_table_inspection_complete
            and self.partition_table_valid is False
        )

    @property
    def raw_compatible(self) -> bool:
        # Raw disk images are inherently intended to represent a disk. Optical
        # ISOs need an MBR/GPT wrapper (commonly called an ISOHybrid image) to
        # be a reliable USB raw-write candidate.
        if self.partition_table_malformed or self.partition_table_incomplete:
            return False
        return self.kind != "Optical ISO" or self.has_mbr or self.has_gpt

    @property
    def layout(self) -> str:
        if self.sparse_format:
            return f"Sparse {self.sparse_format} disk image"
        if self.virtual_format:
            return f"Virtual {self.virtual_format} disk"
        if self.squashfs is not None:
            return (
                f"SquashFS {self.squashfs.version} "
                f"({self.squashfs.compression}) filesystem image"
            )
        if self.partition_table_incomplete:
            return "Disk image with an incompletely inspected partition table"
        if self.partition_table_malformed:
            return "Malformed MBR/GPT disk image"
        if self.partition_table_kind == "hybrid-gpt":
            return "Hybrid MBR/GPT disk image"
        if self.has_gpt:
            return "GPT disk image"
        if self.has_mbr:
            return "Hybrid/MBR disk image"
        if self.is_iso9660:
            return "Optical-only ISO"
        return "Raw disk image"

    @property
    def summary(self) -> str:
        parts = [self.layout]
        if self.compression != "none":
            parts.append(f"{self.compression.upper()} compressed")
        if self.volume_label:
            parts.append(self.volume_label)
        if self.boot_modes:
            boot = "/".join(self.boot_modes)
            if self.architectures:
                boot += " " + ", ".join(self.architectures)
            parts.append(boot)
        if self.bootloader_build:
            parts.append(f"{self.bootloader} {self.bootloader_build}")
        parts.append("raw-write ready" if self.raw_compatible else "may not boot from USB")
        return "  ·  ".join(parts)


def inspect_squashfs_superblock(
    header: bytes,
    image_size: int,
) -> SquashFsInspection | None:
    """Recognize a structurally credible SquashFS 4.0 image at byte zero.

    A four-byte magic match alone is not enough to change write advice. The
    bounded header captured from the already descriptor-bound image must also
    describe supported geometry and keep every mandatory metadata table inside
    ``bytes_used`` and the selected image.
    """

    if (
        type(header) is not bytes
        or type(image_size) is not int
        or isinstance(image_size, bool)
        or image_size < _SQUASHFS_SUPERBLOCK.size
        or len(header) < _SQUASHFS_SUPERBLOCK.size
    ):
        return None
    (
        magic,
        inode_count,
        created_at,
        block_size,
        fragment_count,
        compression_id,
        block_log,
        _flags,
        id_count,
        major,
        minor,
        root_inode,
        bytes_used,
        id_table_start,
        xattr_table_start,
        inode_table_start,
        directory_table_start,
        fragment_table_start,
        lookup_table_start,
    ) = _SQUASHFS_SUPERBLOCK.unpack_from(header)
    if magic != _SQUASHFS_MAGIC:
        return None
    if (
        inode_count == 0
        or id_count == 0
        or id_count > inode_count * 2
        or fragment_count > inode_count
        or major != 4
        or minor != 0
        or compression_id not in _SQUASHFS_COMPRESSIONS
        or not 12 <= block_log <= 20
        or block_size != 1 << block_log
        or not _SQUASHFS_SUPERBLOCK.size <= bytes_used <= image_size
    ):
        return None
    # The upper root-inode bits are relative to inode_table_start, not an
    # absolute byte position in the filesystem.
    root_block = root_inode >> 16
    root_offset = root_inode & 0xFFFF
    if (
        root_offset >= 8_192
        or root_block >= bytes_used
        or inode_table_start > bytes_used - root_block
        or inode_table_start + root_block >= bytes_used
    ):
        return None
    mandatory_tables = (
        id_table_start,
        inode_table_start,
        directory_table_start,
    )
    optional_tables = (
        xattr_table_start,
        fragment_table_start,
        lookup_table_start,
    )
    if any(
        offset < _SQUASHFS_SUPERBLOCK.size or offset >= bytes_used
        for offset in mandatory_tables
    ):
        return None
    if any(
        offset != _SQUASHFS_INVALID_TABLE
        and (offset < _SQUASHFS_SUPERBLOCK.size or offset >= bytes_used)
        for offset in optional_tables
    ):
        return None
    if fragment_count > 0 and fragment_table_start == _SQUASHFS_INVALID_TABLE:
        return None
    return SquashFsInspection(
        inode_count,
        created_at,
        block_size,
        fragment_count,
        _SQUASHFS_COMPRESSIONS[compression_id],
        bytes_used,
    )


def _looks_like_windows(path: Path, volume_label: str) -> bool:
    text = f"{path.name} {volume_label}".casefold()
    return any(marker in text for marker in (
        "windows", "win10", "win11", "win_10", "win_11", "cccoma", "cccomx",
    ))


def classify_windows_installer_members(
    members: Sequence[ImageMember],
) -> WindowsInstallerCandidates:
    """Classify a small, unambiguous set of regular Windows installer images.

    The canonical ``sources/install.wim`` and up to three additional nested
    ``*/sources/install.wim`` paths may coexist, for a total maximum of four.
    Only the canonical ``sources/install.esd`` remains recognized.  Any unsafe
    installer-looking path, non-regular candidate, alias, or fifth WIM makes the
    complete result invalid so later workflows cannot act on a partial catalog.
    """

    wim_paths: list[str] = []
    wim_keys: set[tuple[str, ...]] = set()
    esd_path: str | None = None
    esd_key: tuple[str, ...] | None = None

    if len(members) > MAX_IMAGE_MEMBERS:
        return WindowsInstallerCandidates(valid=False)
    for member in members:
        if not isinstance(member, ImageMember) or not isinstance(member.path, str):
            return WindowsInstallerCandidates(valid=False)
        rough = member.path.replace("\\", "/").casefold()
        looks_wim = rough == "sources/install.wim" or rough.endswith(
            "/sources/install.wim"
        )
        looks_esd = rough == "sources/install.esd"
        if not (looks_wim or looks_esd):
            continue
        try:
            validated = validate_install_image_member_path(member.path)
        except ValueError:
            return WindowsInstallerCandidates(valid=False)
        normalized, key = validated.path, validated.alias_key
        canonical_wim = key == ("sources", "install.wim")
        nested_wim = len(key) >= 3 and key[-2:] == ("sources", "install.wim")
        canonical_esd = key == ("sources", "install.esd")
        if not (canonical_wim or nested_wim or canonical_esd):
            continue
        if (
            member.kind != "file"
            or member.link_target
            or type(member.size) is not int
            or member.size <= 0
        ):
            return WindowsInstallerCandidates(valid=False)
        if canonical_esd:
            if esd_key is not None:
                return WindowsInstallerCandidates(valid=False)
            esd_key = key
            esd_path = normalized
            continue
        if key in wim_keys:
            return WindowsInstallerCandidates(valid=False)
        wim_keys.add(key)
        wim_paths.append(normalized)
        if len(wim_paths) > MAX_WINDOWS_WIM_CANDIDATES:
            return WindowsInstallerCandidates(valid=False)

    return WindowsInstallerCandidates(tuple(wim_paths), esd_path, True)


def classify_boot_paths(
    paths: list[str], *, members: Sequence[ImageMember] | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...], str, bool]:
    normalized = {path.replace("\\", "/").casefold().lstrip("/") for path in paths}
    regular_files = (
        {
            member.path.replace("\\", "/").casefold().lstrip("/")
            for member in members
            if member.kind == "file" and member.size > 0
        }
        if members is not None else set()
    )
    freedos_markers = {
        "kernel.sys", "command.com", "fdconfig.sys", "fdauto.bat", "setup.bat",
    }
    has_freedos = bool(members is not None and freedos_markers <= regular_files)
    architecture_files = {
        "efi/boot/bootx64.efi": "x64",
        "efi/boot/bootia32.efi": "x86",
        "efi/boot/bootaa64.efi": "ARM64",
        "efi/boot/bootarm.efi": "ARM",
        "efi/boot/bootriscv64.efi": "RISC-V64",
        "efi/boot/bootloongarch64.efi": "LoongArch64",
        "efi/boot/bootia64.efi": "IA-64",
        "efi/boot/bootebc.efi": "EBC",
    }
    architectures = tuple(
        label for filename, label in architecture_files.items() if filename in normalized
    )
    has_uefi = bool(architectures) or any(path.startswith("efi/boot/") for path in normalized)
    if has_freedos and "x86" not in architectures:
        architectures += ("x86",)
    bios_markers = (
        "isolinux/isolinux.bin", "syslinux/syslinux.bin", "boot/grub/i386-pc/eltorito.img",
        "bootmgr", "grldr", "freeldr.sys",
    )
    has_bios = has_freedos or any(marker in normalized for marker in bios_markers)
    modes = tuple(mode for mode, present in (("BIOS", has_bios), ("UEFI", has_uefi)) if present)
    if has_freedos:
        bootloader = "FreeDOS"
    elif any("isolinux" in path or "syslinux" in path for path in normalized):
        bootloader = "Syslinux/Isolinux"
    elif any("grub" in path for path in normalized):
        bootloader = "GRUB"
    elif "bootmgr" in normalized:
        bootloader = "Windows Boot Manager"
    else:
        bootloader = "Unknown"
    if members is None:
        # Preserve the original path-only API for canonical sources. Nested WIM
        # candidates require member kinds and therefore remain disabled unless
        # the complete catalog is supplied by inspection.
        canonical = tuple(
            ImageMember(path, 1, "file") for path in paths
            if path.replace("\\", "/").casefold() in {
                "sources/install.wim", "sources/install.esd",
            }
        )
        windows_installer = classify_windows_installer_members(canonical).has_installer
    else:
        windows_installer = classify_windows_installer_members(members).has_installer
    return modes, architectures, bootloader, windows_installer


def boot_identity_fields(
    analysis: BootloaderAnalysis, declared_bootloader: str,
) -> tuple[str, str, str, bool, tuple[str, ...]]:
    identity = analysis.resolved(declared_bootloader)
    related = [
        item for item in analysis.identities
        if (
            item.family == declared_bootloader
            or {item.family, declared_bootloader} <= {
                "Syslinux", "Isolinux", "Syslinux/Isolinux",
            }
        )
    ]
    dependency_family = declared_bootloader in {
        "GRUB", "Syslinux", "Isolinux", "Syslinux/Isolinux",
    }
    ambiguous = identity is None and (
        bool(related) or (dependency_family and not analysis.complete)
    )
    if not identity:
        return "", "", "", ambiguous, analysis.issues
    return (
        identity.version or "", identity.build or "", identity.dependency_key or "",
        identity.ambiguous, analysis.issues,
    )


def _inspect_embedded_uefi_payloads(
    image_fd: int,
    plan: EmbeddedFatImage,
    *,
    cancel_check: Callable[[], None] | None = None,
    timeout: float = 30.0,
) -> ImageUefiAnalysis:
    """Inspect a globally bounded EFI selection from one parsed FAT image."""

    candidates = []
    for entry in plan.entries:
        if entry.is_directory or not entry.path.casefold().endswith(".efi"):
            continue
        lowered = tuple(part.casefold() for part in Path(entry.path).parts)
        name = lowered[-1]
        if (
            len(lowered) == 3
            and lowered[:2] == ("efi", "boot")
            and name.startswith("boot")
        ):
            priority = 0
        elif name in {"bootmgfw.efi", "cdboot.efi", "cdboot_noprompt.efi"}:
            priority = 1
        else:
            priority = 2
        candidates.append((priority, entry.path.casefold(), entry))
    candidates.sort(key=lambda item: (item[0], item[1]))
    selected = candidates[:MAX_UEFI_MEMBERS]
    complete = len(selected) == len(candidates)
    issues: list[str] = []
    payloads: list[ImageUefiPayload] = []
    started = time.monotonic()
    for _priority, _key, entry in selected:
        if cancel_check is not None:
            cancel_check()
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            issues.append("embedded UEFI payload inspection reached its time limit")
            complete = False
            break
        try:
            blob = read_embedded_fat_file(
                image_fd,
                plan,
                entry.path,
                maximum_bytes=MAX_PE_SIZE,
                cancel_check=cancel_check,
            )
            parsed = inspect_pe_bytes(
                blob,
                authenticode_timeout=min(remaining, 10.0),
                authenticode_cancel_check=cancel_check,
            )
        except (FatImageError, OSError, TimeoutError, ValueError) as error:
            if cancel_check is not None:
                cancel_check()
            issues.append(f"{entry.path}: {error}")
            complete = False
            continue
        payloads.append(ImageUefiPayload(
            f"El Torito #{plan.boot_entry.catalog_index}: {entry.path}",
            parsed.architecture,
            parsed.subsystem_name,
            parsed.is_uefi_image,
            parsed.certificate_table.state,
            parsed.sbat.state,
            parsed.warnings,
            parsed.authenticode,
            parsed.dbx,
            "eltorito-fat",
            entry.path,
        ))
    if len(payloads) != len(selected):
        complete = False
    if len(candidates) > len(selected):
        issues.append(
            f"selected {len(selected)} of {len(candidates)} embedded EFI candidates"
        )
    return ImageUefiAnalysis(
        tuple(payloads),
        tuple(issues),
        len(candidates),
        len(selected),
        complete,
    )


def parse_7z_listing(
    output: str, *, maximum_members: int = MAX_IMAGE_MEMBERS,
) -> list[ImageMember]:
    marker = "----------\n"
    if marker not in output:
        return []
    records = output.split(marker, 1)[1]
    parsed: list[ImageMember] = []
    current: dict[str, str] = {}

    def modified_ns(value: str) -> int | None:
        match = _SEVEN_ZIP_MODIFIED.fullmatch(value)
        if match is None:
            return None
        try:
            value_datetime = datetime(*map(int, match.groups()[:6]))
        except ValueError:
            return None
        fraction = (match.group(7) or "").ljust(9, "0")
        value_ns = (
            calendar.timegm(value_datetime.timetuple()) * 1_000_000_000
            + (int(fraction) if fraction else 0)
        )
        if not (
            MIN_PORTABLE_ARCHIVE_MTIME_NS
            <= value_ns
            <= MAX_PORTABLE_ARCHIVE_MTIME_NS
        ):
            return None
        return value_ns

    def finish() -> None:
        if not current.get("Path"):
            current.clear()
            return
        if len(parsed) >= maximum_members:
            raise ValueError("The image catalog contains too many members")
        try:
            size = int(current.get("Size") or 0)
        except ValueError:
            size = 0
        link = current.get("Symbolic Link", "")
        kind = "symlink" if link else ("directory" if current.get("Folder") == "+" else "file")
        parsed.append(ImageMember(
            current["Path"], size, kind, link,
            (
                modified_ns(current.get("Modified", ""))
                if kind in {"file", "directory"} else None
            ),
        ))
        current.clear()

    for line in records.splitlines():
        if not line:
            finish()
        elif " = " in line:
            key, value = line.split(" = ", 1)
            current[key] = value
    finish()
    return parsed


def _trusted_7z() -> str | None:
    executable = shutil.which("7z", path=_TRUSTED_7Z_PATH)
    if not executable:
        return None
    normalized = os.path.normpath(executable)
    if (
        not os.path.isabs(normalized)
        or os.path.dirname(normalized) not in _TRUSTED_7Z_DIRECTORIES
        or os.path.basename(normalized) != "7z"
    ):
        return None
    return normalized


def _scan_image_contents_once(
    path: Path,
    executable: str,
    *,
    image_fd: int | None,
    namespace: SevenZipNamespace | None,
    cancel_check: Callable[[], None] | None,
) -> tuple[list[ImageMember], str]:
    if not executable:
        return [], "failed"
    source = str(path) if image_fd is None else f"/proc/self/fd/{image_fd}"
    type_switch = (() if namespace is None else (f"-t{namespace.value}",))
    try:
        process = subprocess.Popen(
            [executable, "l", "-slt", *type_switch, "--", source],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=(() if image_fd is None else (image_fd,)),
            env={
                "LC_ALL": "C", "LANG": "C", "TZ": "UTC",
                "PATH": _TRUSTED_7Z_PATH,
            },
        )
    except (OSError, subprocess.SubprocessError):
        return [], "failed"
    if process.stdout is None:
        _stop_catalog_process(process)
        return [], "failed"
    descriptor = process.stdout.fileno()
    output = bytearray()
    deadline = time.monotonic() + 20.0
    failed = False
    try:
        os.set_blocking(descriptor, False)
        while True:
            if cancel_check is not None:
                cancel_check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failed = True
                break
            try:
                readable, _, _ = select.select(
                    (descriptor,), (), (), min(0.1, remaining),
                )
            except (OSError, ValueError):
                failed = True
                break
            if not readable:
                continue
            try:
                block = os.read(
                    descriptor,
                    min(64 * 1024, MAX_7Z_CATALOG_BYTES + 1 - len(output)),
                )
            except BlockingIOError:
                continue
            except OSError:
                failed = True
                break
            if not block:
                break
            output.extend(block)
            if len(output) > MAX_7Z_CATALOG_BYTES:
                failed = True
                break
        if failed:
            return [], "failed"
        while process.poll() is None:
            if cancel_check is not None:
                cancel_check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return [], "failed"
            try:
                process.wait(timeout=min(0.1, remaining))
            except subprocess.TimeoutExpired:
                continue
        returncode = process.poll()
        if returncode:
            return [], "unavailable"
        try:
            listing = output.decode("utf-8", errors="replace")
            members = parse_7z_listing(listing)
            return (members, "complete") if members else ([], "unavailable")
        except ValueError:
            return [], "failed"
    finally:
        if process.poll() is None:
            _stop_catalog_process(process)
        try:
            process.stdout.close()
        except OSError:
            pass


def scan_image_catalog(
    path: Path,
    *,
    image_fd: int | None = None,
    namespace: SevenZipNamespace | None = None,
    allow_auto_fallback: bool = True,
    cancel_check: Callable[[], None] | None = None,
    seven_zip: str | None = None,
) -> ImageCatalogScan:
    """List one descriptor-bound namespace, preferring UDF over ISO9660.

    ``namespace`` makes the request exact.  Without it, UDF and ISO9660 are
    tried explicitly in that order.  Legacy 7-Zip auto-detection is retained
    only as a final compatibility path for non-optical disk/archive formats;
    ISO extraction callers disable it.
    """

    if namespace is not None and type(namespace) is not SevenZipNamespace:
        return ImageCatalogScan((), False, None)
    executable = seven_zip or _trusted_7z()
    if not executable:
        return ImageCatalogScan((), False, None)
    normalized = os.path.normpath(executable)
    if (
        not os.path.isabs(normalized)
        or os.path.dirname(normalized) not in _TRUSTED_7Z_DIRECTORIES
        or os.path.basename(normalized) != "7z"
    ):
        return ImageCatalogScan((), False, None)
    candidates: tuple[SevenZipNamespace | None, ...]
    if namespace is not None:
        candidates = (namespace,)
    else:
        candidates = (
            SevenZipNamespace.UDF,
            SevenZipNamespace.ISO9660,
            *((None,) if allow_auto_fallback else ()),
        )
    for candidate in candidates:
        members, state = _scan_image_contents_once(
            path,
            normalized,
            image_fd=image_fd,
            namespace=candidate,
            cancel_check=cancel_check,
        )
        if state == "complete":
            return ImageCatalogScan(tuple(members), True, candidate)
        if state == "failed":
            return ImageCatalogScan((), False, None)
    return ImageCatalogScan((), False, None)


def scan_image_contents(
    path: Path, *, image_fd: int | None = None,
    namespace: SevenZipNamespace | None = None,
    allow_auto_fallback: bool = True,
    cancel_check: Callable[[], None] | None = None,
) -> tuple[list[ImageMember], bool]:
    result = scan_image_catalog(
        path,
        image_fd=image_fd,
        namespace=namespace,
        allow_auto_fallback=allow_auto_fallback,
        cancel_check=cancel_check,
    )
    return list(result.members), result.complete


def _stop_catalog_process(process: subprocess.Popen[bytes]) -> None:
    """Bounded terminate/kill/reap for the unprivileged archive lister."""

    try:
        if process.poll() is None:
            process.terminate()
    except OSError:
        pass
    try:
        process.wait(timeout=0.25)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=0.25)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _read_partition_evidence(
    source: ImageSource,
    *,
    cancel_check: Callable[[], None] | None = None,
    maximum_expanded_bytes: int | None = MAX_INSPECTION_EXPANDED_BYTES,
) -> tuple[int, bytes, bytes, PartitionTableInspection]:
    """Read bounded image headers and partition metadata from one bound source."""

    if source.sparse_format:
        size = source.measure(
            maximum=maximum_expanded_bytes,
            cancel_check=cancel_check,
        )
        needed = max(17 * 2048, PARTITION_TABLE_CAPTURE_BYTES)
        prefix_size = min(size, needed)
        tail_size = min(size, PARTITION_TABLE_CAPTURE_BYTES)
        prefix = source.read_sparse_at(
            0, prefix_size, cancel_check=cancel_check,
        )
        tail = source.read_sparse_at(
            size - tail_size, tail_size, cancel_check=cancel_check,
        )
        header = prefix[:4096]
        descriptor = prefix[16 * 2048:17 * 2048]
        partition_tables = inspect_partition_tables_capture(prefix, tail, size)
        return size, header, descriptor, partition_tables

    if source.compressed:
        needed = max(17 * 2048, PARTITION_TABLE_CAPTURE_BYTES)
        prefix = bytearray()
        tail_chunks: deque[bytes] = deque()
        tail_size = 0
        size = 0
        for block in source.chunks(cancel_check=cancel_check):
            size += len(block)
            if (
                maximum_expanded_bytes is not None
                and size > maximum_expanded_bytes
            ):
                raise ExpandedImageTooLarge(
                    "The decompressed image exceeds ISOpropyl's "
                    f"{maximum_expanded_bytes:,}-byte inspection limit"
                )
            if len(prefix) < needed:
                prefix.extend(block[:needed - len(prefix)])
            tail_chunks.append(block)
            tail_size += len(block)
            while tail_size > PARTITION_TABLE_CAPTURE_BYTES:
                excess = tail_size - PARTITION_TABLE_CAPTURE_BYTES
                first = tail_chunks[0]
                if len(first) <= excess:
                    tail_chunks.popleft()
                    tail_size -= len(first)
                else:
                    tail_chunks[0] = first[excess:]
                    tail_size -= excess
        header = bytes(prefix[:4096])
        descriptor = bytes(prefix[16 * 2048:17 * 2048])
        partition_tables = inspect_partition_tables_capture(
            bytes(prefix), b"".join(tail_chunks), size,
        )
        return size, header, descriptor, partition_tables

    descriptor_fd = source.fileno()
    expected_identity = (
        source.identity.device, source.identity.inode,
        source.identity.size, source.identity.modified_ns,
    )
    status = os.fstat(descriptor_fd)
    if (
        status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns,
    ) != expected_identity:
        raise OSError("The selected image changed before it could be inspected")
    size = status.st_size
    header = os.pread(descriptor_fd, 4096, 0)
    descriptor = os.pread(descriptor_fd, 2048, 16 * 2048)
    partition_tables = inspect_partition_tables_fd(
        descriptor_fd, expected_identity=expected_identity,
    )
    return size, header, descriptor, partition_tables


def inspect_image(
    path: Path,
    *,
    expected_identity: tuple[int, int, int, int, int] | None = None,
    cancel_check: Callable[[], None] | None = None,
    maximum_expanded_bytes: int | None = MAX_INSPECTION_EXPANDED_BYTES,
    timeout_seconds: float | None = INSPECTION_TIMEOUT_SECONDS,
) -> ImageInspection:
    started = time.monotonic()

    def check_inspection() -> None:
        if cancel_check is not None:
            cancel_check()
        if (
            timeout_seconds is not None
            and time.monotonic() - started > timeout_seconds
        ):
            raise ImageInspectionTimedOut(
                "Image inspection exceeded its time limit"
            )

    check_inspection()
    status = path.stat()
    if not stat.S_ISREG(status.st_mode):
        raise OSError("The selected image is not a regular file")
    observed_identity = (
        status.st_dev, status.st_ino, status.st_size,
        status.st_mtime_ns, status.st_ctime_ns,
    )
    if expected_identity is not None and observed_identity != expected_identity:
        raise OSError("The selected image changed before inspection began")
    suffix = path.suffix.casefold()
    if suffix in NON_RAW_SUFFIXES:
        raise OSError(
            f"Standalone {suffix.upper()} input needs a filesystem-aware apply "
            "workflow and cannot be written as raw disk bytes"
        )
    if suffix in COMPRESSION_SUFFIXES:
        with open_image_source(path, cancel_check=check_inspection) as probe:
            decoded_name = probe.decoded_name(cancel_check=check_inspection)
            probe_identity = (
                probe.identity.device, probe.identity.inode, probe.identity.size,
                probe.identity.modified_ns, probe.identity.changed_ns,
            )
        if probe_identity != observed_identity:
            raise OSError("The selected compressed image changed before inspection")
        decoded_suffix = Path(decoded_name).suffix.casefold()
        if decoded_suffix in NON_RAW_SUFFIXES or decoded_suffix in SPARSE_SUFFIXES:
            raise OSError(
                "Compressed WIM/ESD, FFU, and VTSI containers are not accepted "
                "until a chained decode-and-apply workflow is available"
            )
        if decoded_suffix in COMPRESSION_SUFFIXES:
            raise OSError("Nested compressed disk images are not supported")
        if decoded_suffix in VIRTUAL_SUFFIXES:
            check_inspection()
            prepared = CompressedVirtualDiskPreparer().prepare(
                path,
                expected_identity=observed_identity,
                cancel_check=check_inspection,
            )
            try:
                virtual = prepared.info
                if (
                    maximum_expanded_bytes is not None
                    and virtual.virtual_size > maximum_expanded_bytes
                ):
                    raise ExpandedImageTooLarge(
                        "The virtual disk exceeds ISOpropyl's expanded-image limit"
                    )
                check_inspection()
                final = path.stat()
                final_identity = (
                    final.st_dev, final.st_ino, final.st_size,
                    final.st_mtime_ns, final.st_ctime_ns,
                )
                if final_identity != observed_identity:
                    raise OSError(
                        "The selected compressed virtual disk changed before inspection"
                    )
                return ImageInspection(
                    size=virtual.virtual_size,
                    kind=f"Virtual disk ({virtual.display_format})",
                    volume_label="",
                    has_mbr=False,
                    has_gpt=False,
                    is_iso9660=False,
                    looks_windows=_looks_like_windows(path, ""),
                    boot_modes=(),
                    architectures=(),
                    bootloader="Unknown",
                    has_windows_installer=False,
                    contents_scanned=False,
                    compression=prepared.compression,
                    virtual_format=virtual.display_format,
                    container_size=observed_identity[2],
                    decoded_container_size=prepared.decoded_size,
                )
            finally:
                prepared.close()
    if suffix in VIRTUAL_SUFFIXES:
        check_inspection()
        virtual = inspect_virtual_disk(path)
        check_inspection()
        virtual_identity = (
            virtual.identity.device, virtual.identity.inode,
            virtual.identity.size, virtual.identity.modified_ns,
            virtual.identity.changed_ns,
        )
        final = path.stat()
        final_identity = (
            final.st_dev, final.st_ino, final.st_size,
            final.st_mtime_ns, final.st_ctime_ns,
        )
        if virtual_identity != observed_identity or final_identity != observed_identity:
            raise OSError("The selected virtual disk changed before inspection")
        return ImageInspection(
            size=virtual.virtual_size,
            kind=f"Virtual disk ({virtual.display_format})",
            volume_label="",
            has_mbr=False,
            has_gpt=False,
            is_iso9660=False,
            looks_windows=_looks_like_windows(path, ""),
            boot_modes=(),
            architectures=(),
            bootloader="Unknown",
            has_windows_installer=False,
            contents_scanned=False,
            virtual_format=virtual.display_format,
            container_size=virtual.identity.size,
        )
    source = open_image_source(
        path,
        cancel_check=check_inspection,
    )
    try:
        source_identity = (
            source.identity.device, source.identity.inode,
            source.identity.size, source.identity.modified_ns,
            source.identity.changed_ns,
        )
        if source_identity != observed_identity:
            raise OSError("The selected image changed before it could be opened")
        size, header, descriptor, partition_tables = _read_partition_evidence(
            source,
            cancel_check=check_inspection,
            maximum_expanded_bytes=maximum_expanded_bytes,
        )
        is_compressed = source.compressed
        compression = source.compression
        sparse_format = source.sparse_format
        container_size = source.identity.size if sparse_format else 0
    finally:
        source.close()

    has_mbr = partition_tables.has_mbr
    has_gpt = partition_tables.has_gpt
    # VTSI is a sparse disk container and remains a raw-write workflow even if
    # arbitrary expanded bytes resemble an optical volume descriptor.
    is_iso9660 = (
        not sparse_format
        and len(descriptor) >= 6
        and descriptor[1:6] == b"CD001"
    )
    volume_label = ""
    if is_iso9660 and len(descriptor) >= 72:
        volume_label = descriptor[40:72].decode("ascii", errors="replace").strip()
    squashfs = (
        inspect_squashfs_superblock(header, size)
        if not sparse_format and not has_mbr and not has_gpt and not is_iso9660
        else None
    )
    if sparse_format:
        kind = "Sparse disk image (VTSI)"
    elif is_iso9660:
        kind = "Optical ISO"
    elif squashfs is not None:
        kind = "SquashFS filesystem image"
    elif suffix == ".iso":
        kind = "Optical ISO"
    elif suffix in RAW_IMAGE_SUFFIXES:
        kind = "Raw disk image"
    else:
        # Keep accepting explicitly chosen unknown regular files as raw bytes;
        # structured formats above remain a fail-closed denylist.
        kind = "Raw image"
    inspection_fd = -1
    if not is_compressed and not sparse_format:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        inspection_fd = os.open(path, flags)
        bound = os.fstat(inspection_fd)
        bound_identity = (
            bound.st_dev, bound.st_ino, bound.st_size,
            bound.st_mtime_ns, bound.st_ctime_ns,
        )
        if not stat.S_ISREG(bound.st_mode) or bound_identity != observed_identity:
            os.close(inspection_fd)
            raise OSError("The selected image changed before catalog inspection")
    try:
        members, contents_scanned = (
            scan_image_contents(
                path,
                image_fd=inspection_fd,
                allow_auto_fallback=not (is_iso9660 or suffix == ".iso"),
                cancel_check=check_inspection,
            )
            if inspection_fd >= 0 else ([], False)
        )
        modes, architectures, bootloader, windows_installer = classify_boot_paths(
            [member.path for member in members], members=members,
        )
        eltorito: ElToritoInspection | None = None
        eltorito_issues: tuple[str, ...] = ()
        if inspection_fd >= 0 and is_iso9660:
            try:
                eltorito = inspect_eltorito_file(path, image_fd=inspection_fd)
            except ElToritoNotFound:
                pass
            except ElToritoError as error:
                eltorito_issues = (str(error),)
        if eltorito is not None:
            catalog_modes = {
                BootPlatform.BIOS_X86: "BIOS",
                BootPlatform.EFI: "UEFI",
                BootPlatform.POWERPC: "PowerPC",
                BootPlatform.MAC: "Mac",
            }
            detected = set(modes)
            detected.update(
                catalog_modes[platform] for platform in eltorito.bootable_platforms
            )
            modes = tuple(
                mode for mode in ("BIOS", "UEFI", "PowerPC", "Mac")
                if mode in detected
            )
        embedded_uefi_fats: tuple[EmbeddedFatImage, ...] = ()
        embedded_uefi_issues: tuple[str, ...] = ()
        if (
            inspection_fd >= 0
            and eltorito is not None
            and BootPlatform.EFI in eltorito.bootable_platforms
        ):
            try:
                embedded_uefi_fats = inspect_uefi_eltorito_fats(
                    inspection_fd,
                    eltorito,
                    cancel_check=check_inspection,
                )
            except FatImageError as error:
                embedded_uefi_issues = (str(error),)
        version = build = dependency = ""
        identity_ambiguous = False
        identity_issues: tuple[str, ...] = ()
        if inspection_fd >= 0 and bootloader in {"GRUB", "Syslinux/Isolinux"}:
            analysis = analyze_iso_bootloaders(
                path, [member.path for member in members], image_fd=inspection_fd,
            )
            version, build, dependency, identity_ambiguous, identity_issues = boot_identity_fields(
                analysis, bootloader
            )
        uefi_payloads: tuple[ImageUefiPayload, ...] = ()
        uefi_issues: tuple[str, ...] = ()
        uefi_complete = True
        uefi_candidate_count = 0
        uefi_selected_count = 0
        if inspection_fd >= 0 and "UEFI" in modes:
            uefi_analysis = inspect_iso_uefi_payloads(
                path, [member.path for member in members], image_fd=inspection_fd,
                cancel_check=check_inspection,
            )
            uefi_payloads = uefi_analysis.payloads
            uefi_issues = uefi_analysis.issues
            uefi_complete = uefi_analysis.complete
            uefi_candidate_count = uefi_analysis.candidate_count
            uefi_selected_count = uefi_analysis.selected_count
            if not contents_scanned:
                uefi_complete = False
                uefi_issues += (
                    "a complete ISO file catalog was unavailable for DBX analysis",
                )
            if embedded_uefi_fats:
                detected_architectures = list(architectures)
                for embedded_uefi_fat in embedded_uefi_fats:
                    embedded_analysis = _inspect_embedded_uefi_payloads(
                        inspection_fd,
                        embedded_uefi_fat,
                        cancel_check=check_inspection,
                    )
                    label = (
                        "embedded El Torito FAT "
                        f"#{embedded_uefi_fat.boot_entry.catalog_index}"
                    )
                    uefi_payloads += embedded_analysis.payloads
                    labeled_issues = tuple(
                        f"{label}: {issue}" for issue in embedded_analysis.issues
                    )
                    uefi_issues += labeled_issues
                    embedded_uefi_issues += labeled_issues
                    uefi_complete = uefi_complete and embedded_analysis.complete
                    uefi_candidate_count += embedded_analysis.candidate_count
                    uefi_selected_count += embedded_analysis.selected_count

                    embedded_payloads = {
                        payload.target_path.casefold(): payload
                        for payload in embedded_analysis.payloads
                    }
                    for loader in embedded_uefi_fat.fallback_loaders:
                        name = PurePosixPath(loader.path).name.casefold()
                        expected = fallback_loader_architecture(name)
                        payload = embedded_payloads.get(loader.path.casefold())
                        if (
                            expected is None
                            or payload is None
                            or not payload.is_uefi_image
                            or not fallback_loader_matches_architecture(
                                name,
                                payload.architecture,
                            )
                        ):
                            uefi_complete = False
                            issue = (
                                f"{label}: fallback loader {loader.path!r} did not "
                                "validate as matching UEFI PE code"
                            )
                            uefi_issues += (issue,)
                            embedded_uefi_issues += (issue,)
                            continue
                        if expected not in detected_architectures:
                            detected_architectures.append(expected)
                architectures = tuple(detected_architectures)
            elif (
                eltorito is not None
                and BootPlatform.EFI in eltorito.bootable_platforms
            ):
                uefi_complete = False
                uefi_issues += (
                    "the EFI El Torito boot image could not be parsed for DBX analysis",
                )
                uefi_issues += tuple(
                    f"embedded El Torito FAT inspection: {issue}"
                    for issue in embedded_uefi_issues
                )
            if eltorito_issues:
                uefi_complete = False
                uefi_issues += (
                    "the malformed El Torito catalog prevents complete DBX analysis",
                )
        if inspection_fd >= 0:
            final_bound = os.fstat(inspection_fd)
            final_bound_identity = (
                final_bound.st_dev, final_bound.st_ino, final_bound.st_size,
                final_bound.st_mtime_ns, final_bound.st_ctime_ns,
            )
            if final_bound_identity != observed_identity:
                raise OSError("The selected image changed while it was being inspected")
    finally:
        if inspection_fd >= 0:
            os.close(inspection_fd)
    result = ImageInspection(
        size=size, kind=kind, volume_label=volume_label, has_mbr=has_mbr,
        has_gpt=has_gpt, is_iso9660=is_iso9660,
        looks_windows=_looks_like_windows(path, volume_label),
        boot_modes=modes, architectures=architectures, bootloader=bootloader,
        has_windows_installer=windows_installer, contents_scanned=contents_scanned,
        compression=compression, members=tuple(members),
        bootloader_version=version, bootloader_build=build,
        bootloader_dependency=dependency,
        bootloader_identity_ambiguous=identity_ambiguous,
        bootloader_issues=identity_issues,
        uefi_payloads=uefi_payloads,
        uefi_analysis_issues=uefi_issues,
        uefi_analysis_complete=uefi_complete,
        uefi_candidate_count=uefi_candidate_count,
        uefi_selected_count=uefi_selected_count,
        eltorito=eltorito,
        eltorito_issues=eltorito_issues,
        partition_table_valid=(
            partition_tables.valid
            if (has_mbr or has_gpt) and partition_tables.complete else None
        ),
        partition_table_kind=partition_tables.kind,
        partition_table_sector_size=partition_tables.sector_size,
        partition_table_issues=partition_tables.issues,
        mbr_kind=partition_tables.mbr_kind,
        mbr_boot_code=partition_tables.mbr_boot_code,
        partition_table_inspection_complete=partition_tables.complete,
        sparse_format="VTSI" if sparse_format == "vtsi" else "",
        container_size=container_size,
        embedded_uefi_fats=embedded_uefi_fats,
        embedded_uefi_issues=embedded_uefi_issues,
        squashfs=squashfs,
    )
    check_inspection()
    final = path.stat()
    final_identity = (
        final.st_dev, final.st_ino, final.st_size,
        final.st_mtime_ns, final.st_ctime_ns,
    )
    if final_identity != observed_identity:
        raise OSError("The selected image changed while it was being inspected")
    return result


def calculate_checksums(
    path: Path,
    progress: Progress | None = None,
    *,
    expected_identity: tuple[int, int, int, int, int] | None = None,
    cancel_check: Callable[[], None] | None = None,
) -> dict[str, str]:
    """Hash one no-follow descriptor and fail closed if its identity changes."""

    def check_cancelled() -> None:
        if cancel_check is not None:
            cancel_check()

    def identity(status: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            status.st_dev, status.st_ino, status.st_size,
            status.st_mtime_ns, status.st_ctime_ns,
        )

    check_cancelled()
    # O_NONBLOCK prevents a pathname race to a FIFO from hanging before fstat
    # can reject it. It does not change ordinary regular-file reads on Linux.
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise OSError(f"Could not securely open the selected image: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError("The selected image is not a regular file")
        opened_identity = identity(opened)
        if expected_identity is not None and opened_identity != expected_identity:
            raise OSError("The selected image changed before checksums were calculated")

        total = opened.st_size
        digests = {
            "MD5": hashlib.md5(usedforsecurity=False),
            "SHA-1": hashlib.sha1(usedforsecurity=False),
            "SHA-256": hashlib.sha256(),
            "SHA-512": hashlib.sha512(),
        }
        done = 0
        while True:
            check_cancelled()
            if identity(os.fstat(descriptor)) != opened_identity:
                raise OSError("The image changed while checksums were being calculated")
            block = os.read(descriptor, 4 * 1024 * 1024)
            check_cancelled()
            if identity(os.fstat(descriptor)) != opened_identity:
                raise OSError("The image changed while checksums were being calculated")
            if not block:
                break
            done += len(block)
            if done > total:
                raise OSError("The image changed while checksums were being calculated")
            for digest in digests.values():
                digest.update(block)
            if progress is not None:
                progress(done, total)
            check_cancelled()

        if done != total:
            raise OSError("The image changed while checksums were being calculated")
        final = os.lstat(path)
        if not stat.S_ISREG(final.st_mode) or identity(final) != opened_identity:
            raise OSError("The selected image changed while checksums were being calculated")
        check_cancelled()
        return {name: digest.hexdigest() for name, digest in digests.items()}
    finally:
        os.close(descriptor)


def parse_expected_checksum(text: str) -> tuple[str, str]:
    """Extract one conventional checksum from pasted provider text.

    This accepts a bare digest, common `digest filename` files, and forms such
    as `SHA256 (image.iso) = digest`. Ambiguous text is rejected instead of
    guessing which image/hash the user intended.
    """
    candidates: list[tuple[str, str]] = []
    for match in re.finditer(r"(?<![0-9a-fA-F])([0-9a-fA-F]{32,128})(?![0-9a-fA-F])", text):
        value = match.group(1).casefold()
        algorithm = CHECKSUM_LENGTHS.get(len(value))
        if algorithm:
            candidates.append((algorithm, value))
    unique = list(dict.fromkeys(candidates))
    if not unique:
        raise ValueError("Paste an MD5, SHA-1, SHA-256, or SHA-512 checksum")
    if len(unique) != 1:
        raise ValueError("More than one checksum was found; paste only the value for this image")
    return unique[0]


def compare_expected_checksum(
    calculated: dict[str, str], expected_text: str
) -> tuple[str, bool]:
    algorithm, expected = parse_expected_checksum(expected_text)
    actual = calculated.get(algorithm)
    if actual is None:
        raise ValueError(f"A calculated {algorithm} value is not available")
    return algorithm, hmac.compare_digest(actual.casefold(), expected)
