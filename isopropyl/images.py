from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import calendar
import hashlib
import hmac
import os
import re
import select
import shutil
import stat
import subprocess
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

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
from .uefi import ImageUefiPayload, inspect_iso_uefi_payloads
from .virtual import inspect_virtual_disk
from .windows_paths import validate_install_image_member_path

Progress = Callable[[int, int], None]

CHECKSUM_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
RAW_IMAGE_SUFFIXES = frozenset({".img", ".raw", ".usb", ".wic"})
VIRTUAL_SUFFIXES = frozenset({".vhd", ".vhdx", ".qcow", ".qcow2"})
NON_RAW_SUFFIXES = frozenset({".wim", ".esd", ".ffu", ".vtsi"})
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


class ImageInspectionCancelled(Exception):
    pass


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
        if self.virtual_format:
            return f"Virtual {self.virtual_format} disk"
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
    architecture_files = {
        "efi/boot/bootx64.efi": "x64",
        "efi/boot/bootia32.efi": "x86",
        "efi/boot/bootaa64.efi": "ARM64",
        "efi/boot/bootarm.efi": "ARM",
        "efi/boot/bootriscv64.efi": "RISC-V64",
        "efi/boot/bootloongarch64.efi": "LoongArch64",
    }
    architectures = tuple(
        label for filename, label in architecture_files.items() if filename in normalized
    )
    has_uefi = bool(architectures) or any(path.startswith("efi/boot/") for path in normalized)
    bios_markers = (
        "isolinux/isolinux.bin", "syslinux/syslinux.bin", "boot/grub/i386-pc/eltorito.img",
        "bootmgr", "grldr", "freeldr.sys",
    )
    has_bios = any(marker in normalized for marker in bios_markers)
    modes = tuple(mode for mode, present in (("BIOS", has_bios), ("UEFI", has_uefi)) if present)
    if any("isolinux" in path or "syslinux" in path for path in normalized):
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


def scan_image_contents(
    path: Path, *, image_fd: int | None = None,
    cancel_check: Callable[[], None] | None = None,
) -> tuple[list[ImageMember], bool]:
    executable = _trusted_7z()
    if not executable:
        return [], False
    source = str(path) if image_fd is None else f"/proc/self/fd/{image_fd}"
    try:
        process = subprocess.Popen(
            [executable, "l", "-slt", source],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=(() if image_fd is None else (image_fd,)),
            env={
                "LC_ALL": "C", "LANG": "C", "TZ": "UTC",
                "PATH": _TRUSTED_7Z_PATH,
            },
        )
    except (OSError, subprocess.SubprocessError):
        return [], False
    if process.stdout is None:
        _stop_catalog_process(process)
        return [], False
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
            return [], False
        while process.poll() is None:
            if cancel_check is not None:
                cancel_check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return [], False
            try:
                process.wait(timeout=min(0.1, remaining))
            except subprocess.TimeoutExpired:
                continue
        returncode = process.poll()
        if returncode:
            return [], False
        try:
            listing = output.decode("utf-8", errors="replace")
            return parse_7z_listing(listing), True
        except ValueError:
            return [], False
    finally:
        if process.poll() is None:
            _stop_catalog_process(process)
        try:
            process.stdout.close()
        except OSError:
            pass


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
        inner_suffix = Path(path.stem).suffix.casefold()
        if inner_suffix in VIRTUAL_SUFFIXES or inner_suffix in NON_RAW_SUFFIXES:
            raise OSError(
                "Compressed virtual, WIM/ESD, FFU, and VTSI containers are not "
                "accepted until a chained decode-and-apply workflow is available"
            )
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
    source = open_image_source(path)
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
    finally:
        source.close()

    has_mbr = partition_tables.has_mbr
    has_gpt = partition_tables.has_gpt
    is_iso9660 = len(descriptor) >= 6 and descriptor[1:6] == b"CD001"
    volume_label = ""
    if is_iso9660 and len(descriptor) >= 72:
        volume_label = descriptor[40:72].decode("ascii", errors="replace").strip()
    if is_iso9660 or suffix == ".iso":
        kind = "Optical ISO"
    elif suffix in RAW_IMAGE_SUFFIXES:
        kind = "Raw disk image"
    else:
        # Keep accepting explicitly chosen unknown regular files as raw bytes;
        # structured formats above remain a fail-closed denylist.
        kind = "Raw image"
    inspection_fd = -1
    if not is_compressed:
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
                path, image_fd=inspection_fd, cancel_check=check_inspection,
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
        if inspection_fd >= 0 and "UEFI" in modes:
            uefi_analysis = inspect_iso_uefi_payloads(
                path, [member.path for member in members], image_fd=inspection_fd,
                cancel_check=check_inspection,
            )
            uefi_payloads = uefi_analysis.payloads
            uefi_issues = uefi_analysis.issues
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
