from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import hmac
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .sources import open_image_source
from .boot_identity import BootloaderAnalysis, analyze_iso_bootloaders
from .eltorito import (
    BootPlatform, ElToritoError, ElToritoInspection, ElToritoNotFound,
    inspect_eltorito_file,
)
from .uefi import ImageUefiPayload, inspect_iso_uefi_payloads
from .virtual import inspect_virtual_disk

Progress = Callable[[int, int], None]

CHECKSUM_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
VIRTUAL_SUFFIXES = frozenset({".vhd", ".vhdx", ".qcow", ".qcow2"})
NON_RAW_SUFFIXES = frozenset({".wim", ".esd", ".ffu", ".vtsi"})
COMPRESSION_SUFFIXES = frozenset({
    ".gz", ".gzip", ".bz2", ".bzip2", ".xz", ".lzma", ".zst", ".zstd",
    ".z", ".zip",
})


@dataclass(frozen=True)
class ImageMember:
    path: str
    size: int
    kind: str
    link_target: str = ""


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

    @property
    def raw_compatible(self) -> bool:
        # Raw disk images are inherently intended to represent a disk. Optical
        # ISOs need an MBR/GPT wrapper (commonly called an ISOHybrid image) to
        # be a reliable USB raw-write candidate.
        return self.kind != "Optical ISO" or self.has_mbr or self.has_gpt

    @property
    def layout(self) -> str:
        if self.virtual_format:
            return f"Virtual {self.virtual_format} disk"
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


def classify_boot_paths(paths: list[str]) -> tuple[tuple[str, ...], tuple[str, ...], str, bool]:
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
    windows_installer = "sources/install.wim" in normalized or "sources/install.esd" in normalized
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
    ambiguous = bool(related) and identity is None
    if not identity:
        return "", "", "", ambiguous, analysis.issues
    return (
        identity.version or "", identity.build or "", identity.dependency_key or "",
        identity.ambiguous, analysis.issues,
    )


def parse_7z_listing(output: str) -> list[ImageMember]:
    marker = "----------\n"
    if marker not in output:
        return []
    records = output.split(marker, 1)[1]
    parsed: list[ImageMember] = []
    current: dict[str, str] = {}

    def finish() -> None:
        if not current.get("Path"):
            current.clear()
            return
        try:
            size = int(current.get("Size") or 0)
        except ValueError:
            size = 0
        link = current.get("Symbolic Link", "")
        kind = "symlink" if link else ("directory" if current.get("Folder") == "+" else "file")
        parsed.append(ImageMember(current["Path"], size, kind, link))
        current.clear()

    for line in records.splitlines():
        if not line:
            finish()
        elif " = " in line:
            key, value = line.split(" = ", 1)
            current[key] = value
    finish()
    return parsed


def scan_image_contents(path: Path) -> tuple[list[ImageMember], bool]:
    executable = shutil.which("7z")
    if not executable:
        return [], False
    try:
        result = subprocess.run(
            [executable, "l", "-slt", str(path)], capture_output=True, text=True,
            timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [], False
    if result.returncode:
        return [], False
    return parse_7z_listing(result.stdout), True


def inspect_image(path: Path) -> ImageInspection:
    if not path.is_file():
        raise OSError("The selected image is not a regular file")
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
        virtual = inspect_virtual_disk(path)
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
    if source.compressed:
        needed = 17 * 2048
        prefix = bytearray()
        size = 0
        for block in source.chunks():
            size += len(block)
            if len(prefix) < needed:
                prefix.extend(block[:needed - len(prefix)])
        header = bytes(prefix[:4096])
        descriptor = bytes(prefix[16 * 2048:17 * 2048])
    else:
        size = path.stat().st_size
        with path.open("rb", buffering=0) as stream:
            header = stream.read(4096)
            stream.seek(16 * 2048)
            descriptor = stream.read(2048)

    has_mbr = len(header) >= 512 and header[510:512] == b"\x55\xaa"
    has_gpt = len(header) >= 520 and header[512:520] == b"EFI PART"
    is_iso9660 = len(descriptor) >= 6 and descriptor[1:6] == b"CD001"
    volume_label = ""
    if is_iso9660 and len(descriptor) >= 72:
        volume_label = descriptor[40:72].decode("ascii", errors="replace").strip()
    kind = "Optical ISO" if is_iso9660 or path.suffix.casefold() == ".iso" else "Raw image"
    members, contents_scanned = scan_image_contents(path) if not source.compressed else ([], False)
    modes, architectures, bootloader, windows_installer = classify_boot_paths(
        [member.path for member in members]
    )
    eltorito: ElToritoInspection | None = None
    eltorito_issues: tuple[str, ...] = ()
    if not source.compressed and is_iso9660:
        try:
            eltorito = inspect_eltorito_file(path)
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
    if not source.compressed and bootloader in {"GRUB", "Syslinux/Isolinux"}:
        analysis = analyze_iso_bootloaders(path, [member.path for member in members])
        version, build, dependency, identity_ambiguous, identity_issues = boot_identity_fields(
            analysis, bootloader
        )
    uefi_payloads: tuple[ImageUefiPayload, ...] = ()
    uefi_issues: tuple[str, ...] = ()
    if not source.compressed and "UEFI" in modes:
        uefi_analysis = inspect_iso_uefi_payloads(
            path, [member.path for member in members]
        )
        uefi_payloads = uefi_analysis.payloads
        uefi_issues = uefi_analysis.issues
    return ImageInspection(
        size=size, kind=kind, volume_label=volume_label, has_mbr=has_mbr,
        has_gpt=has_gpt, is_iso9660=is_iso9660,
        looks_windows=_looks_like_windows(path, volume_label),
        boot_modes=modes, architectures=architectures, bootloader=bootloader,
        has_windows_installer=windows_installer, contents_scanned=contents_scanned,
        compression=source.compression, members=tuple(members),
        bootloader_version=version, bootloader_build=build,
        bootloader_dependency=dependency,
        bootloader_identity_ambiguous=identity_ambiguous,
        bootloader_issues=identity_issues,
        uefi_payloads=uefi_payloads,
        uefi_analysis_issues=uefi_issues,
        eltorito=eltorito,
        eltorito_issues=eltorito_issues,
    )


def calculate_checksums(path: Path, progress: Progress | None = None) -> dict[str, str]:
    total = path.stat().st_size
    digests = {
        "MD5": hashlib.md5(usedforsecurity=False),
        "SHA-1": hashlib.sha1(usedforsecurity=False),
        "SHA-256": hashlib.sha256(),
        "SHA-512": hashlib.sha512(),
    }
    done = 0
    with path.open("rb", buffering=0) as stream:
        while block := stream.read(4 * 1024 * 1024):
            for digest in digests.values():
                digest.update(block)
            done += len(block)
            if progress:
                progress(done, total)
    if done != total:
        raise OSError("The image changed while checksums were being calculated")
    return {name: digest.hexdigest() for name, digest in digests.items()}


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
