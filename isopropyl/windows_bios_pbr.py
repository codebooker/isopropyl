from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Device-free foundation for ISOpropyl's project-authored FAT32 BIOS PBR.

This module does not authorize or write a physical device.  It verifies the
reproducible GNU-binutils build, creates immutable writes for a bounded regular
file image, and independently checks a caller-applied patch.  Plans are
caller-owned, untrusted same-process witnesses rather than authorization
tokens.  Authentic Microsoft BOOTMGR compatibility remains a separate
certification gate.
"""

import hashlib
import os
import re
import stat
import struct
import subprocess
import tempfile
from dataclasses import dataclass, replace
from enum import Enum
from importlib import resources
from pathlib import Path

from .rufus_prompt_mbr import (
    RUFUS_PROMPT_MBR_SHA256,
    load_rufus_prompt_mbr,
)
from .syslinux import (
    SYSLINUX_MBR_602,
    SYSLINUX_MBR_602_SHA256,
    SyslinuxPatchError,
    prepare_syslinux_mbr,
)


SECTOR_SIZE = 512
STAGE_SECTOR = 12
STAGE_SECTORS = 2
STAGE_SIZE = STAGE_SECTORS * SECTOR_SIZE
MODERN_BOOTMGR_ENTRY_STUB = b"\xe9\xd5\x01\xeb\x04\x90"
MODERN_BOOTMGR_MIN_SIZE = 0x1D9
MODERN_BOOTMGR_MAX_SIZE = 0x7E000
STAGE0_SHA256 = "852ac6b9a78d3ed2a092d051ef1674e76f1c0b319d7eb4d7f684067b5951072d"
STAGE2_SHA256 = "127a6e7eda4545ba329c43af810ae9e85587302a9a588fafa05c06b8d6dd3a60"
_HEX_LINE = re.compile(r"[0-9a-f]{128}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_TOOL_OUTPUT = 64 * 1024
_UINT64_MAX = (1 << 64) - 1

# Provenance for the observed file handoff ABI only.  No ms-sys/Rufus byte
# array is copied: both stages shipped by this project are original source.
BOOTMGR_ABI_PROVENANCE = (
    "https://github.com/pbatard/rufus/tree/"
    "2368e49a82e854d3e702f824648cc723953dbb53/src/ms-sys"
)
BOOTMGR_PE_SELECTION_PROVENANCE = (
    "https://github.com/pbatard/rufus/blob/"
    "2368e49a82e854d3e702f824648cc723953dbb53/src/format.c#L1038",
    "https://github.com/pbatard/rufus/blob/"
    "2368e49a82e854d3e702f824648cc723953dbb53/src/ms-sys/fat32.c#L177-L221",
)


class WindowsBiosPbrError(ValueError):
    pass


class WindowsBootmgrBiosProfile(Enum):
    MODERN_ENTRY_ZERO = "modern-entry-zero"


class WindowsMbrProfile(Enum):
    """Closed project-known Windows legacy-MBR bootstrap choices."""

    SYSLINUX_602_DIRECT = "syslinux-6.02-direct"
    RUFUS_PROMPT_V1 = "rufus-prompt-v1"


DEFAULT_WINDOWS_MBR_PROFILE = WindowsMbrProfile.SYSLINUX_602_DIRECT


def classify_windows_bootmgr_bios(
    header: bytes,
    *,
    file_size: int,
) -> WindowsBootmgrBiosProfile:
    """Classify the one exact modern BOOTMGR profile this loader supports."""

    if type(header) is not bytes or len(header) != len(MODERN_BOOTMGR_ENTRY_STUB):
        raise WindowsBiosPbrError("Exactly six BOOTMGR header bytes are required")
    if (
        type(file_size) is not int
        or not MODERN_BOOTMGR_MIN_SIZE <= file_size <= MODERN_BOOTMGR_MAX_SIZE
    ):
        raise WindowsBiosPbrError("The BOOTMGR size is outside the modern BIOS profile")
    displacement = struct.unpack_from("<h", header, 1)[0]
    jump_target = 3 + displacement
    if header != MODERN_BOOTMGR_ENTRY_STUB or not 6 <= jump_target < file_size:
        raise WindowsBiosPbrError("The BOOTMGR entry stub is unsupported")
    return WindowsBootmgrBiosProfile.MODERN_ENTRY_ZERO


@dataclass(frozen=True)
class BootCodeArtifacts:
    stage0: bytes
    stage2: bytes
    stage0_sha256: str
    stage2_sha256: str


@dataclass(frozen=True)
class PbrWrite:
    offset: int
    before_sha256: str
    data: bytes
    role: str


@dataclass(frozen=True)
class Fat32BootmgrPbrPlan:
    windows_mbr_profile: WindowsMbrProfile
    mbr_offset: int
    volume_offset: int
    volume_size: int
    fsinfo_offset: int
    backup_vbr_offset: int
    backup_fsinfo_offset: int
    stage_offset: int
    primary_fsinfo_sha256: str
    backup_fsinfo_sha256: str
    artifact_stage0_sha256: str
    artifact_stage2_sha256: str
    mbr_bootstrap_sha256: str
    writes: tuple[PbrWrite, ...]
    plan_sha256: str


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _artifact(name: str, size: int, expected_sha256: str) -> bytes:
    text = resources.files("isopropyl").joinpath(f"data/{name}").read_text(
        encoding="ascii",
    )
    lines = text.splitlines()
    if not lines or any(_HEX_LINE.fullmatch(line) is None for line in lines):
        raise WindowsBiosPbrError("The packaged BIOS artifact has a non-canonical encoding")
    value = bytes.fromhex("".join(lines))
    if len(value) != size or _digest(value) != expected_sha256:
        raise WindowsBiosPbrError("The packaged BIOS artifact does not match its source pin")
    return value


def load_boot_code_artifacts() -> BootCodeArtifacts:
    stage0 = _artifact("fat32-bootmgr-stage0.hex", SECTOR_SIZE, STAGE0_SHA256)
    stage2 = _artifact("fat32-bootmgr-stage2.hex", STAGE_SIZE, STAGE2_SHA256)
    if (
        stage0[:3] != b"\xeb\x58\x90"
        or any(stage0[3:90])
        or stage0[510:512] != b"\x55\xaa"
        or b"BOOTMGR    " not in stage2
        or MODERN_BOOTMGR_ENTRY_STUB[:4] not in stage2
        or b"\x04\x90" not in stage2
    ):
        raise WindowsBiosPbrError("The packaged BIOS artifact layout is invalid")
    return BootCodeArtifacts(stage0, stage2, _digest(stage0), _digest(stage2))


def _trusted_build_tool(path: Path) -> None:
    try:
        resolved = path.resolve(strict=True)
        status = resolved.stat(follow_symlinks=False)
        parent = resolved.parent.stat(follow_symlinks=False)
    except OSError as error:
        raise WindowsBiosPbrError(f"The required build tool is unavailable: {path}") from error
    if (
        not path.is_absolute()
        or not stat.S_ISREG(status.st_mode)
        or status.st_uid != 0
        or status.st_mode & 0o022
        or not status.st_mode & 0o111
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or parent.st_mode & 0o022
    ):
        raise WindowsBiosPbrError(f"The required build tool is not trusted: {path}")


def _build_stage(source: Path, destination: Path, *, assembler: Path, linker: Path) -> bytes:
    if not source.is_file() or source.is_symlink():
        raise WindowsBiosPbrError(f"The BIOS source is unavailable: {source}")
    object_path = destination.with_suffix(".o")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    commands = (
        (os.fspath(assembler), "--32", "-o", os.fspath(object_path), os.fspath(source)),
        (
            os.fspath(linker), "-m", "elf_i386", "-Ttext", "0", "--oformat", "binary",
            "-nostdlib", "-o", os.fspath(destination), os.fspath(object_path),
        ),
    )
    for command in commands:
        try:
            completed = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=environment, check=False, timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise WindowsBiosPbrError("The reproducible BIOS build could not run") from error
        if (
            completed.returncode != 0
            or len(completed.stdout) > _MAX_TOOL_OUTPUT
            or len(completed.stderr) > _MAX_TOOL_OUTPUT
        ):
            raise WindowsBiosPbrError("The reproducible BIOS build failed")
    try:
        return destination.read_bytes()
    except OSError as error:
        raise WindowsBiosPbrError("The reproducible BIOS build produced no artifact") from error


def verify_reproducible_boot_code(
    source_root: Path,
    *,
    assembler: Path = Path("/usr/bin/as"),
    linker: Path = Path("/usr/bin/ld"),
) -> BootCodeArtifacts:
    """Rebuild both stages and require byte identity with packaged artifacts."""

    if not isinstance(source_root, Path) or not source_root.is_absolute():
        raise WindowsBiosPbrError("The source root must be an absolute Path")
    _trusted_build_tool(assembler)
    _trusted_build_tool(linker)
    packaged = load_boot_code_artifacts()
    with tempfile.TemporaryDirectory(prefix="isopropyl-bios-build-") as directory:
        root = Path(directory)
        stage0 = _build_stage(
            source_root / "boot/fat32_bootmgr_stage0.S", root / "stage0.bin",
            assembler=assembler, linker=linker,
        )
        stage2 = _build_stage(
            source_root / "boot/fat32_bootmgr_stage2.S", root / "stage2.bin",
            assembler=assembler, linker=linker,
        )
    rebuilt = BootCodeArtifacts(stage0, stage2, _digest(stage0), _digest(stage2))
    if rebuilt != packaged:
        raise WindowsBiosPbrError("The BIOS sources do not reproduce the packaged artifacts")
    return rebuilt


def _pread_exact(descriptor: int, offset: int, size: int, label: str) -> bytes:
    blocks: list[bytes] = []
    consumed = 0
    while consumed < size:
        try:
            value = os.pread(descriptor, size - consumed, offset + consumed)
        except InterruptedError:
            continue
        except OSError as error:
            raise WindowsBiosPbrError(f"Could not read the {label}") from error
        if not value:
            raise WindowsBiosPbrError(f"Could not read the {label} completely")
        blocks.append(value)
        consumed += len(value)
    return b"".join(blocks)


def _fat32_layout(boot: bytes, volume_offset: int, volume_size: int) -> tuple[int, int]:
    if len(boot) != SECTOR_SIZE or boot[510:512] != b"\x55\xaa":
        raise WindowsBiosPbrError("The FAT32 boot signature is missing")
    sector = struct.unpack_from("<H", boot, 11)[0]
    cluster_sectors = boot[13]
    reserved = struct.unpack_from("<H", boot, 14)[0]
    fats = boot[16]
    root_entries = struct.unpack_from("<H", boot, 17)[0]
    total16 = struct.unpack_from("<H", boot, 19)[0]
    fat16 = struct.unpack_from("<H", boot, 22)[0]
    hidden = struct.unpack_from("<I", boot, 28)[0]
    total = struct.unpack_from("<I", boot, 32)[0]
    fat_size = struct.unpack_from("<I", boot, 36)[0]
    flags = struct.unpack_from("<H", boot, 40)[0]
    version = struct.unpack_from("<H", boot, 42)[0]
    root_cluster = struct.unpack_from("<I", boot, 44)[0]
    fsinfo = struct.unpack_from("<H", boot, 48)[0]
    backup = struct.unpack_from("<H", boot, 50)[0]
    if (
        sector != SECTOR_SIZE
        or cluster_sectors == 0
        or cluster_sectors > 64
        or cluster_sectors & (cluster_sectors - 1)
        or reserved < STAGE_SECTOR + STAGE_SECTORS
        or fats != 2
        or root_entries != 0
        or total16 != 0
        or fat16 != 0
        or total == 0
        or fat_size == 0
        or flags != 0
        or version != 0
        or boot[21] != 0xF8
        or boot[66] != 0x29
        or boot[82:90] != b"FAT32   "
        or hidden != volume_offset // SECTOR_SIZE
        or total * SECTOR_SIZE != volume_size
    ):
        raise WindowsBiosPbrError("The image is outside the supported FAT32 BIOS profile")
    metadata = reserved + fats * fat_size
    if metadata >= total:
        raise WindowsBiosPbrError("The FAT32 data region is empty")
    clusters = (total - metadata) // cluster_sectors
    if (
        clusters < 65_525
        or clusters + 2 > 0x0FFFFFF0
        or clusters + 2 > fat_size * 128
        or not 2 <= root_cluster < clusters + 2
    ):
        raise WindowsBiosPbrError("The FAT32 cluster geometry is invalid")
    backup_fsinfo = backup + fsinfo
    protected = {0, fsinfo, backup, backup_fsinfo}
    if (
        fsinfo <= 0
        or backup <= 0
        or backup_fsinfo >= reserved
        or len(protected) != 4
        or protected & set(range(STAGE_SECTOR, STAGE_SECTOR + STAGE_SECTORS))
    ):
        raise WindowsBiosPbrError("The FAT32 reserved-sector layout is unsupported")
    return fsinfo, backup


def _merged_vbr(formatted: bytes, artifact: bytes) -> bytes:
    merged = bytearray(formatted)
    preserved_bpb = formatted[3:90]
    preserved_signature = formatted[510:512]
    merged[:3] = artifact[:3]
    merged[90:510] = artifact[90:510]
    if merged[3:90] != preserved_bpb or merged[510:512] != preserved_signature:
        raise WindowsBiosPbrError("The BIOS merge changed formatter-owned VBR bytes")
    return bytes(merged)


def _mbr_bootstrap(profile: WindowsMbrProfile) -> tuple[bytes, str]:
    if type(profile) is not WindowsMbrProfile:
        raise WindowsBiosPbrError("An exact Windows MBR profile is required")
    if profile is WindowsMbrProfile.SYSLINUX_602_DIRECT:
        bootstrap = SYSLINUX_MBR_602
        expected_sha256 = SYSLINUX_MBR_602_SHA256
    elif profile is WindowsMbrProfile.RUFUS_PROMPT_V1:
        try:
            bootstrap = load_rufus_prompt_mbr()
        except (OSError, ValueError) as error:
            raise WindowsBiosPbrError(
                "The packaged Rufus prompt MBR does not match its project pin",
            ) from error
        expected_sha256 = RUFUS_PROMPT_MBR_SHA256
    else:  # pragma: no cover - Enum exhaustiveness guard.
        raise WindowsBiosPbrError("The Windows MBR profile is unsupported")
    if (
        type(bootstrap) is not bytes
        or len(bootstrap) != 440
        or _digest(bootstrap) != expected_sha256
    ):
        raise WindowsBiosPbrError(
            "The selected Windows MBR bootstrap does not match its project pin",
        )
    return bootstrap, expected_sha256


def windows_mbr_bootstrap_sha256(profile: WindowsMbrProfile) -> str:
    """Return the pin for one exact, successfully loaded project bootstrap."""

    return _mbr_bootstrap(profile)[1]


def _prepare_windows_mbr(
    formatted_mbr: bytes,
    *,
    profile: WindowsMbrProfile,
    partition_start_sector: int,
    partition_sector_count: int,
) -> tuple[bytes, str]:
    """Validate the common layout, then merge only one closed bootstrap."""

    try:
        validated = prepare_syslinux_mbr(
            formatted_mbr,
            partition_start_sector=partition_start_sector,
            partition_sector_count=partition_sector_count,
        )
    except SyslinuxPatchError as error:
        raise WindowsBiosPbrError(str(error)) from error
    bootstrap, bootstrap_sha256 = _mbr_bootstrap(profile)
    merged = bootstrap + validated.mbr[440:]
    if merged[440:] != formatted_mbr[440:]:
        raise WindowsBiosPbrError("The Windows MBR metadata changed while merging boot code")
    return merged, bootstrap_sha256


def _plan_digest(plan: Fat32BootmgrPbrPlan) -> str:
    digest = hashlib.sha256(b"isopropyl-fat32-bootmgr-pbr-v2\0")
    try:
        digest.update(plan.windows_mbr_profile.value.encode("ascii") + b"\0")
    except (AttributeError, UnicodeError):
        return ""
    for value in (
        plan.mbr_offset, plan.volume_offset, plan.volume_size, plan.fsinfo_offset,
        plan.backup_vbr_offset, plan.backup_fsinfo_offset, plan.stage_offset,
    ):
        digest.update(struct.pack("<Q", value))
    for value in (
        plan.primary_fsinfo_sha256, plan.backup_fsinfo_sha256,
        plan.artifact_stage0_sha256, plan.artifact_stage2_sha256,
        plan.mbr_bootstrap_sha256,
    ):
        digest.update(bytes.fromhex(value))
    for write in plan.writes:
        digest.update(struct.pack("<Q", write.offset))
        digest.update(write.role.encode("ascii") + b"\0")
        digest.update(bytes.fromhex(write.before_sha256))
        digest.update(hashlib.sha256(write.data).digest())
    return digest.hexdigest()


def plan_fat32_bootmgr_pbr(
    descriptor: int,
    *,
    volume_offset: int,
    volume_size: int,
    windows_mbr_profile: WindowsMbrProfile = DEFAULT_WINDOWS_MBR_PROFILE,
    artifacts: BootCodeArtifacts | None = None,
) -> Fat32BootmgrPbrPlan:
    """Plan four exact writes against a regular-file FAT32 image descriptor."""

    if type(descriptor) is not int or descriptor < 0:
        raise WindowsBiosPbrError("A valid image descriptor is required")
    try:
        status = os.fstat(descriptor)
    except OSError as error:
        raise WindowsBiosPbrError("Could not inspect the image descriptor") from error
    if not stat.S_ISREG(status.st_mode):
        raise WindowsBiosPbrError("The BIOS foundation accepts regular-file images only")
    if (
        type(volume_offset) is not int
        or type(volume_size) is not int
        or volume_offset != 2_048 * SECTOR_SIZE
        or volume_offset % SECTOR_SIZE
        or volume_size <= 0
        or volume_size % SECTOR_SIZE
        or volume_offset > status.st_size
        or volume_size > status.st_size - volume_offset
    ):
        raise WindowsBiosPbrError("The bounded FAT32 volume extent is invalid")
    artifact = load_boot_code_artifacts() if artifacts is None else artifacts
    if type(artifact) is not BootCodeArtifacts or (
        len(artifact.stage0) != SECTOR_SIZE
        or len(artifact.stage2) != STAGE_SIZE
        or _digest(artifact.stage0) != artifact.stage0_sha256
        or _digest(artifact.stage2) != artifact.stage2_sha256
        or artifact.stage0_sha256 != STAGE0_SHA256
        or artifact.stage2_sha256 != STAGE2_SHA256
    ):
        raise WindowsBiosPbrError("The BIOS artifacts are not self-consistent")
    formatted_mbr = _pread_exact(descriptor, 0, SECTOR_SIZE, "formatted MBR")
    mbr, mbr_bootstrap_sha256 = _prepare_windows_mbr(
        formatted_mbr,
        profile=windows_mbr_profile,
        partition_start_sector=volume_offset // SECTOR_SIZE,
        partition_sector_count=volume_size // SECTOR_SIZE,
    )
    primary = _pread_exact(descriptor, volume_offset, SECTOR_SIZE, "primary VBR")
    fsinfo_sector, backup_sector = _fat32_layout(primary, volume_offset, volume_size)
    fsinfo_offset = volume_offset + fsinfo_sector * SECTOR_SIZE
    backup_offset = volume_offset + backup_sector * SECTOR_SIZE
    backup_fsinfo_offset = volume_offset + (backup_sector + fsinfo_sector) * SECTOR_SIZE
    stage_offset = volume_offset + STAGE_SECTOR * SECTOR_SIZE
    backup = _pread_exact(descriptor, backup_offset, SECTOR_SIZE, "backup VBR")
    primary_fsinfo = _pread_exact(descriptor, fsinfo_offset, SECTOR_SIZE, "primary FSInfo")
    backup_fsinfo = _pread_exact(
        descriptor, backup_fsinfo_offset, SECTOR_SIZE, "backup FSInfo",
    )
    stage_before = _pread_exact(descriptor, stage_offset, STAGE_SIZE, "stage region")
    if backup != primary:
        raise WindowsBiosPbrError("The primary and backup FAT32 VBRs disagree")
    if primary_fsinfo != backup_fsinfo or (
        primary_fsinfo[:4] != b"RRaA"
        or primary_fsinfo[484:488] != b"rrAa"
        or primary_fsinfo[508:512] != b"\0\0\x55\xaa"
    ):
        raise WindowsBiosPbrError("The primary and backup FAT32 FSInfo sectors disagree")
    if any(stage_before):
        raise WindowsBiosPbrError("The reserved BIOS stage region is not empty")
    merged = _merged_vbr(primary, artifact.stage0)
    writes = (
        PbrWrite(stage_offset, _digest(stage_before), artifact.stage2, "stage"),
        PbrWrite(backup_offset, _digest(backup), merged, "backup-vbr"),
        PbrWrite(volume_offset, _digest(primary), merged, "primary-vbr"),
        PbrWrite(0, _digest(formatted_mbr), mbr, "mbr"),
    )
    candidate = Fat32BootmgrPbrPlan(
        windows_mbr_profile, 0, volume_offset, volume_size, fsinfo_offset, backup_offset,
        backup_fsinfo_offset, stage_offset, _digest(primary_fsinfo),
        _digest(backup_fsinfo), artifact.stage0_sha256, artifact.stage2_sha256,
        mbr_bootstrap_sha256, writes, "",
    )
    return replace(candidate, plan_sha256=_plan_digest(candidate))


def attest_fat32_bootmgr_pbr(descriptor: int, plan: Fat32BootmgrPbrPlan) -> None:
    """Require exact write results and unchanged FSInfo on a regular image."""

    if (
        type(plan) is not Fat32BootmgrPbrPlan
        or type(plan.windows_mbr_profile) is not WindowsMbrProfile
        or type(plan.writes) is not tuple
        or len(plan.writes) != 4
        or any(type(write) is not PbrWrite for write in plan.writes)
        or any(
            type(write.offset) is not int
            or not 0 <= write.offset <= _UINT64_MAX
            or type(write.before_sha256) is not str
            or type(write.data) is not bytes
            or type(write.role) is not str
            for write in plan.writes
        )
        or any(
            type(value) is not int or not 0 <= value <= _UINT64_MAX
            for value in (
                plan.mbr_offset,
                plan.volume_offset,
                plan.volume_size,
                plan.fsinfo_offset,
                plan.backup_vbr_offset,
                plan.backup_fsinfo_offset,
                plan.stage_offset,
            )
        )
    ):
        raise WindowsBiosPbrError("The FAT32 BIOS patch plan is malformed")
    hashes = (
        plan.primary_fsinfo_sha256,
        plan.backup_fsinfo_sha256,
        plan.artifact_stage0_sha256,
        plan.artifact_stage2_sha256,
        plan.mbr_bootstrap_sha256,
        plan.plan_sha256,
        *(write.before_sha256 for write in plan.writes),
    )
    if (
        any(type(value) is not str or _SHA256.fullmatch(value) is None for value in hashes)
        or plan.mbr_offset != 0
        or plan.volume_offset != 2_048 * SECTOR_SIZE
        or type(plan.volume_size) is not int
        or plan.volume_size <= 0
        or plan.volume_size % SECTOR_SIZE
        or plan.stage_offset != plan.volume_offset + STAGE_SECTOR * SECTOR_SIZE
        or plan.artifact_stage0_sha256 != STAGE0_SHA256
        or plan.artifact_stage2_sha256 != STAGE2_SHA256
        or plan.mbr_bootstrap_sha256
        != windows_mbr_bootstrap_sha256(plan.windows_mbr_profile)
        or tuple(write.role for write in plan.writes)
        != ("stage", "backup-vbr", "primary-vbr", "mbr")
        or tuple(write.offset for write in plan.writes)
        != (plan.stage_offset, plan.backup_vbr_offset, plan.volume_offset, plan.mbr_offset)
        or tuple(len(write.data) for write in plan.writes)
        != (STAGE_SIZE, SECTOR_SIZE, SECTOR_SIZE, SECTOR_SIZE)
        or _digest(plan.writes[0].data) != STAGE2_SHA256
        or plan.writes[1].data != plan.writes[2].data
        or plan.writes[2].data[510:512] != b"\x55\xaa"
        or plan.writes[2].data[3:90] != plan.writes[1].data[3:90]
        or _digest(plan.writes[3].data[:440]) != plan.mbr_bootstrap_sha256
        or plan.plan_sha256 != _plan_digest(plan)
    ):
        raise WindowsBiosPbrError("The FAT32 BIOS patch plan is malformed")
    try:
        fsinfo_sector, backup_sector = _fat32_layout(
            plan.writes[2].data, plan.volume_offset, plan.volume_size,
        )
        expected_fsinfo = plan.volume_offset + fsinfo_sector * SECTOR_SIZE
        expected_backup = plan.volume_offset + backup_sector * SECTOR_SIZE
        expected_backup_fsinfo = expected_backup + fsinfo_sector * SECTOR_SIZE
        artifacts = load_boot_code_artifacts()
        expected_vbr = _merged_vbr(plan.writes[2].data, artifacts.stage0)
        expected_mbr, expected_mbr_sha256 = _prepare_windows_mbr(
            plan.writes[3].data,
            profile=plan.windows_mbr_profile,
            partition_start_sector=plan.volume_offset // SECTOR_SIZE,
            partition_sector_count=plan.volume_size // SECTOR_SIZE,
        )
    except WindowsBiosPbrError as error:
        raise WindowsBiosPbrError("The FAT32 BIOS patch plan is malformed") from error
    if (
        (plan.fsinfo_offset, plan.backup_vbr_offset, plan.backup_fsinfo_offset)
        != (expected_fsinfo, expected_backup, expected_backup_fsinfo)
        or plan.mbr_bootstrap_sha256 != expected_mbr_sha256
        or plan.writes[2].data != expected_vbr
        or plan.writes[3].data != expected_mbr
    ):
        raise WindowsBiosPbrError("The FAT32 BIOS patch plan is malformed")
    try:
        status = os.fstat(descriptor)
    except OSError as error:
        raise WindowsBiosPbrError("Could not inspect the patched image") from error
    if not stat.S_ISREG(status.st_mode):
        raise WindowsBiosPbrError("The BIOS foundation accepts regular-file images only")
    if (
        plan.volume_offset > status.st_size
        or plan.volume_size > status.st_size - plan.volume_offset
    ):
        raise WindowsBiosPbrError("The patched image no longer contains the planned volume")
    for write in plan.writes:
        if _pread_exact(descriptor, write.offset, len(write.data), write.role) != write.data:
            raise WindowsBiosPbrError(f"The {write.role} patch did not verify")
    if (
        _digest(_pread_exact(descriptor, plan.fsinfo_offset, SECTOR_SIZE, "primary FSInfo"))
        != plan.primary_fsinfo_sha256
        or _digest(_pread_exact(
            descriptor, plan.backup_fsinfo_offset, SECTOR_SIZE, "backup FSInfo",
        )) != plan.backup_fsinfo_sha256
    ):
        raise WindowsBiosPbrError("FAT32 FSInfo changed while applying the BIOS patch")
