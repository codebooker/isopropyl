from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bounded, non-destructive Syslinux installation primitives.

This module deliberately stops before filesystem or block-device mutation.  It
accepts an exact, already-bound Syslinux bundle plus an explicit sector map and
returns the bytes a future regular-file installer must verify before writing.
The patch and ADV formats follow Syslinux's GPL-2.0-or-later installer at the
exact versions cataloged by ISOpropyl.
"""

import hashlib
import re
import struct
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from .bootloaders import BoundBootBundle


SECTOR_SIZE: Final = 512
ADV_SIZE: Final = 512
LDLINUX_MAGIC: Final = 0x3EB202FE
ADV_MAGIC1: Final = 0x5A2D2FA5
ADV_MAGIC2: Final = 0xA3041767
ADV_MAGIC3: Final = 0xDD28BF64
_PATCH_AREA = struct.Struct("<IIHHIIHH")
_EXT_PATCH_AREA = struct.Struct("<10H")
_EXTENT = struct.Struct("<QH")
_UINT64_MAX = (1 << 64) - 1
_UINT32_MAX = (1 << 32) - 1
_UINT16_MAX = (1 << 16) - 1
MAX_LDLINUX_SYS_BYTES = 16 * 1024 * 1024
_DIRECTORY_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]*\Z")

# Syslinux 6.02 ``mbr.bin`` as embedded by Rufus. The 440-byte bootstrap is
# independent of the matched 6.03/6.04 ldlinux payload and never includes disk
# signature, reserved, partition-table, or MBR-signature bytes.
SYSLINUX_MBR_602 = bytes.fromhex(
    "33c0fa8ed88ed0bc007c89e606578ec0fbfcbf0006b90001f3a5ea1f0600005252b441bbaa5531c930f6f9cd"
    "13721381fb55aa750dd1e9730966c7068d06b442eb155ab408cd1383e13f510fb6c640f7e152506631c06699"
    "e86600e835014d697373696e67206f7065726174696e672073797374656d2e0d0a66606631d2bb007c665266"
    "5006536a016a1089e666f736f47bc0e40688e188c592f636f87b88c608e141b801028a16fa7bcd138d641066"
    "61c3e8c4ffbebe7dbfbe07b92000f3a5c3666089e5bbbe07b9040031c05351f6078074034089de83c310e2f3"
    "48745b7939595b8a47043c0f7406247f3c057522668b4708668b56146601d06621d275036689c2e8acff7203"
    "e8b6ff668b461ce8a0ff83c310e2cc6661c3e876004d756c7469706c65206163746976652070617274697469"
    "6f6e732e0d0a668b44086603461c66894408e830ff722766813e007c5846534275096683c004e81cff721381"
    "3efe7d55aa0f85f2febcfa7b5a5f07faffe4e81e004f7065726174696e672073797374656d206c6f61642065"
    "72726f722e0d0a5eacb40e8a3e6204b307cd103c0a75f1cd18f4ebfd00000000000000000000000000000000"
)
SYSLINUX_MBR_602_SHA256 = "4746f74bc9b9d3d579c41988a4a29bb7ac932ad1c70470ea779ea161eb799b64"
SYSLINUX_MBR_602_LICENSE = "MIT"
SYSLINUX_MBR_602_SOURCE = (
    "https://git.kernel.org/pub/scm/boot/syslinux/syslinux.git/plain/"
    "mbr/mbr.S?id=67aaaeeb22832a0b82e5043877d26d1a9602bf2a"
)
SYSLINUX_MBR_602_RUFUS_SOURCE = (
    "https://github.com/pbatard/rufus/blob/"
    "2368e49a82e854d3e702f824648cc723953dbb53/src/ms-sys/inc/mbr_syslinux.h"
)
SYSLINUX_MBR_602_UPSTREAM_COMMIT = "67aaaeeb22832a0b82e5043877d26d1a9602bf2a"
SYSLINUX_MBR_602_RELEASE_SHA256 = (
    "afa31b7cbf72e1c0c1752a0636ba724ce01c0e374366e46e61db6862b4685478"
)


# Independently re-pin every byte accepted by this safety-critical consumer.
# The generic catalog remains the acquisition source, but cannot silently
# broaden this module's supported versions or artifact set.
PINNED_SYSLINUX_PAYLOADS = MappingProxyType({
    "6.03-2014-10-06": MappingProxyType({
        "ldlinux.bss": (
            512,
            "8814e576abc1aa44dde943b0caaee833a5810142614adeeb4cc725e78a5045b7",
        ),
        "ldlinux.sys": (
            68_599,
            "3f1206e0cc45dbe180e73adaeb221bfc7d5a800095738549390379d7d0282ac3",
        ),
    }),
    "6.04-pre1": MappingProxyType({
        "ldlinux.bss": (
            512,
            "cc40ba0349782cb4c9021e54dcc0a4540c3a8b96088b3a5648671926ef44d2f0",
        ),
        "ldlinux.sys": (
            68_121,
            "73b62767a16200b9af193a7d5c94e9c294c6dbb6d5b17c15038c9f3173c9a7bc",
        ),
    }),
})
PINNED_SYSLINUX_PROVENANCE = MappingProxyType({
    "6.03-2014-10-06": (
        "https://github.com/pbatard/rufus-web/tree/"
        "e6e2182d325ae95ac15166ea2ee750cebccff3c1/files/syslinux-6.03"
    ),
    "6.04-pre1": (
        "https://github.com/pbatard/rufus-web/tree/"
        "e6e2182d325ae95ac15166ea2ee750cebccff3c1/files/syslinux-6.04/pre1"
    ),
})


class SyslinuxPatchError(ValueError):
    """The proposed Syslinux installation input is malformed or unsupported."""


@dataclass(frozen=True)
class SyslinuxPayloads:
    version: str
    ldlinux_sys: bytes
    ldlinux_bss: bytes


@dataclass(frozen=True)
class SectorExtent:
    lba: int
    length: int


@dataclass(frozen=True)
class SyslinuxPatchResult:
    """Immutable bytes and metadata for a future write-and-verify executor."""

    version: str
    ldlinux_file: bytes
    boot_sector: bytes
    backup_boot_sector: int
    patch_offset: int
    extents: tuple[SectorExtent, ...]
    sector_map: tuple[int, ...]

    @property
    def ldlinux_sha256(self) -> str:
        return hashlib.sha256(self.ldlinux_file).hexdigest()

    @property
    def boot_sector_sha256(self) -> str:
        return hashlib.sha256(self.boot_sector).hexdigest()


@dataclass(frozen=True)
class SyslinuxMbrResult:
    mbr: bytes
    partition_start_sector: int
    partition_sector_count: int
    bootstrap_sha256: str

    @property
    def mbr_sha256(self) -> str:
        return hashlib.sha256(self.mbr).hexdigest()


def prepare_syslinux_mbr(
    formatted_mbr: bytes,
    *,
    partition_start_sector: int,
    partition_sector_count: int,
    bootstrap: bytes = SYSLINUX_MBR_602,
) -> SyslinuxMbrResult:
    """Merge exact Syslinux code without changing bytes 440..511.

    This pure helper accepts only the planned one-active-partition MBR/FAT32-LBA
    profile. It does not open or write a disk.
    """

    if type(formatted_mbr) is not bytes or len(formatted_mbr) != SECTOR_SIZE:
        raise SyslinuxPatchError("the formatted MBR must be exactly 512 bytes")
    if type(bootstrap) is not bytes or len(bootstrap) != 440:
        raise SyslinuxPatchError("the Syslinux MBR bootstrap must be exactly 440 bytes")
    if (
        hashlib.sha256(bootstrap).hexdigest() != SYSLINUX_MBR_602_SHA256
        or bootstrap != SYSLINUX_MBR_602
    ):
        raise SyslinuxPatchError("the Syslinux MBR bootstrap does not match its pin")
    if (
        type(partition_start_sector) is not int
        or partition_start_sector != 2_048
        or type(partition_sector_count) is not int
        or partition_sector_count <= 0
        or partition_sector_count > _UINT32_MAX
        or partition_start_sector + partition_sector_count > _UINT32_MAX + 1
    ):
        raise SyslinuxPatchError("the planned Syslinux MBR partition geometry is invalid")
    if formatted_mbr[510:512] != b"\x55\xaa":
        raise SyslinuxPatchError("the formatted MBR signature is missing")
    if formatted_mbr[444:446] != b"\0\0":
        raise SyslinuxPatchError("the formatted MBR reserved bytes are nonzero")

    first = formatted_mbr[446:462]
    if (
        first[0] != 0x80
        or first[4] != 0x0C
        or struct.unpack_from("<I", first, 8)[0] != partition_start_sector
        or struct.unpack_from("<I", first, 12)[0] != partition_sector_count
    ):
        raise SyslinuxPatchError("the formatted MBR does not match the active FAT32 plan")
    if formatted_mbr[462:510] != b"\0" * 48:
        raise SyslinuxPatchError("the formatted MBR contains additional partitions")

    merged = bootstrap + formatted_mbr[440:]
    if merged[440:] != formatted_mbr[440:] or merged[510:512] != b"\x55\xaa":
        raise SyslinuxPatchError("the MBR metadata changed while merging boot code")
    return SyslinuxMbrResult(
        merged,
        partition_start_sector,
        partition_sector_count,
        SYSLINUX_MBR_602_SHA256,
    )


def bind_syslinux_bundle(bundle: BoundBootBundle) -> SyslinuxPayloads:
    """Accept only one independently pinned, complete Syslinux payload pair."""

    if not isinstance(bundle, BoundBootBundle):
        raise SyslinuxPatchError("a bound Syslinux bundle is required")
    if (
        bundle.family != "syslinux"
        or bundle.purpose != "matched-bios-payloads"
        or bundle.license != "GPL-2.0-or-later"
        or bundle.provenance_url != PINNED_SYSLINUX_PROVENANCE.get(bundle.version)
    ):
        raise SyslinuxPatchError("the bundle is not a supported Syslinux BIOS bundle")
    expected = PINNED_SYSLINUX_PAYLOADS.get(bundle.version)
    if expected is None:
        raise SyslinuxPatchError("the Syslinux version is not enabled for patching")
    if tuple(item.name for item in bundle.artifacts) != tuple(expected):
        raise SyslinuxPatchError("the Syslinux bundle is incomplete or out of order")

    accepted: dict[str, bytes] = {}
    for artifact in bundle.artifacts:
        size, digest = expected[artifact.name]
        if type(artifact.data) is not bytes:
            raise SyslinuxPatchError(f"{artifact.name} is not immutable bytes")
        actual = hashlib.sha256(artifact.data).hexdigest()
        if (
            len(artifact.data) != size
            or artifact.sha256 != digest
            or actual != digest
        ):
            raise SyslinuxPatchError(
                f"{artifact.name} does not match ISOpropyl's pinned payload",
            )
        accepted[artifact.name] = artifact.data

    return SyslinuxPayloads(
        version=bundle.version,
        ldlinux_sys=accepted["ldlinux.sys"],
        ldlinux_bss=accepted["ldlinux.bss"],
    )


def make_empty_adv() -> bytes:
    """Return the two identical, checksummed empty Syslinux ADV sectors."""

    first = bytearray(ADV_SIZE)
    struct.pack_into("<I", first, 0, ADV_MAGIC1)
    checksum = ADV_MAGIC2
    for offset in range(8, ADV_SIZE - 4, 4):
        checksum = (checksum - struct.unpack_from("<I", first, offset)[0]) & 0xFFFFFFFF
    struct.pack_into("<I", first, 4, checksum)
    struct.pack_into("<I", first, ADV_SIZE - 4, ADV_MAGIC3)
    return bytes(first + first)


def _checked_directory(directory: str) -> bytes:
    if not isinstance(directory, str):
        raise SyslinuxPatchError("the Syslinux configuration directory must be text")
    try:
        encoded = directory.encode("ascii")
    except UnicodeEncodeError as error:
        raise SyslinuxPatchError(
            "the Syslinux configuration directory must be ASCII",
        ) from error
    if (
        "\x00" in directory
        or "\\" in directory
        or (directory and not directory.startswith("/"))
        or directory.endswith("/")
        or any(part in {"", ".", ".."} for part in directory.split("/")[1:])
        or any(
            _DIRECTORY_COMPONENT.fullmatch(part) is None
            for part in directory.split("/")[1:]
        )
    ):
        raise SyslinuxPatchError("the Syslinux configuration directory is not canonical")
    return encoded + b"\0"


def _checked_sector_map(sectors: tuple[int, ...] | list[int], expected: int) -> tuple[int, ...]:
    if not isinstance(sectors, (tuple, list)):
        raise SyslinuxPatchError("the ldlinux.sys sector map must be an explicit sequence")
    result = tuple(sectors)
    if len(result) != expected:
        raise SyslinuxPatchError(
            f"ldlinux.sys requires exactly {expected} mapped sectors",
        )
    if any(type(sector) is not int or not 0 < sector <= _UINT64_MAX for sector in result):
        raise SyslinuxPatchError("the ldlinux.sys sector map contains an invalid sector")
    if len(set(result)) != len(result):
        raise SyslinuxPatchError("the ldlinux.sys sector map contains duplicate sectors")
    return result


def _sector_extents(sectors: tuple[int, ...]) -> tuple[SectorExtent, ...]:
    """Reproduce Syslinux's real-mode transfer/64-KiB extent boundaries."""

    if not sectors:
        return ()
    address = 0x8000
    base = address
    lba = sectors[0]
    length = 1
    extents: list[SectorExtent] = []
    address += SECTOR_SIZE

    for sector in sectors[1:]:
        transfer_bytes = (length + 1) * SECTOR_SIZE
        if (
            sector == lba + length
            and transfer_bytes < 65_536
            and ((address ^ (base + transfer_bytes - 1)) & 0xFFFF0000) == 0
        ):
            length += 1
        else:
            extents.append(SectorExtent(lba, length))
            base = address
            lba = sector
            length = 1
        address += SECTOR_SIZE
    extents.append(SectorExtent(lba, length))
    return tuple(extents)


def _only_patch_offset(image: bytes) -> int:
    magic = struct.pack("<I", LDLINUX_MAGIC)
    offsets = tuple(
        offset
        for offset in range(0, len(image) - _PATCH_AREA.size + 1, 4)
        if image[offset:offset + 4] == magic
    )
    if len(offsets) != 1:
        raise SyslinuxPatchError("ldlinux.sys must contain one aligned patch area")
    return offsets[0]


def _bounded_region(offset: int, length: int, total: int, label: str) -> None:
    if offset < 0 or length < 0 or offset > total or length > total - offset:
        raise SyslinuxPatchError(f"the {label} points outside ldlinux.sys")


def _require_disjoint_regions(
    regions: tuple[tuple[int, int, str], ...],
    *,
    location: str,
) -> None:
    populated = tuple(region for region in regions if region[1] > 0)
    for index, (left_offset, left_length, left_label) in enumerate(populated):
        left_end = left_offset + left_length
        for right_offset, right_length, right_label in populated[index + 1:]:
            right_end = right_offset + right_length
            if left_offset < right_end and right_offset < left_end:
                raise SyslinuxPatchError(
                    f"the {location} {left_label} overlaps its {right_label}",
                )


def patch_ldlinux(
    ldlinux_sys: bytes,
    ldlinux_bss: bytes,
    sectors: tuple[int, ...] | list[int],
    *,
    directory: str = "",
) -> tuple[bytes, bytes, int, tuple[SectorExtent, ...], tuple[int, ...]]:
    """Patch immutable payload bytes using an already verified FAT sector map.

    Returned values are the complete ``ldlinux.sys`` file (including two ADV
    sectors), the patched 512-byte boot-code template, patch offset, encoded
    extents, and the frozen input sector map.  Sector numbers are relative to
    the FAT volume, exactly as Syslinux's FAT installer expects.  No path or
    device is opened.
    """

    if (
        type(ldlinux_sys) is not bytes
        or len(ldlinux_sys) < _PATCH_AREA.size
        or len(ldlinux_sys) > MAX_LDLINUX_SYS_BYTES
    ):
        raise SyslinuxPatchError("ldlinux.sys has an invalid size")
    if type(ldlinux_bss) is not bytes or len(ldlinux_bss) != SECTOR_SIZE:
        raise SyslinuxPatchError("ldlinux.bss must be exactly 512 bytes")
    if (
        ldlinux_bss[0] not in {0xE9, 0xEB}
        or (ldlinux_bss[0] == 0xEB and ldlinux_bss[2] != 0x90)
        or ldlinux_bss[510:512] != b"\x55\xaa"
    ):
        raise SyslinuxPatchError("ldlinux.bss is not a valid boot-sector template")

    expected_sectors = (len(ldlinux_sys) + 2 * ADV_SIZE + SECTOR_SIZE - 1) // SECTOR_SIZE
    sector_map = _checked_sector_map(sectors, expected_sectors)
    if expected_sectors < 4:
        raise SyslinuxPatchError("ldlinux.sys has too few sectors to patch")
    if expected_sectors - 2 > _UINT16_MAX or len(ldlinux_sys) // 4 > _UINT32_MAX:
        raise SyslinuxPatchError("ldlinux.sys exceeds the patch-format integer limits")
    directory_bytes = _checked_directory(directory)
    patch_offset = _only_patch_offset(ldlinux_sys)

    image = bytearray(ldlinux_sys)
    boot = bytearray(ldlinux_bss)
    (
        magic, _instance, _data_sectors, _adv_sectors, _dwords,
        _checksum, _maxtransfer, epa_offset,
    ) = _PATCH_AREA.unpack_from(image, patch_offset)
    if magic != LDLINUX_MAGIC:
        raise SyslinuxPatchError("ldlinux.sys has an invalid patch magic")
    _bounded_region(epa_offset, _EXT_PATCH_AREA.size, len(image), "extended patch area")
    (
        adv_pointer_offset, directory_offset, directory_length,
        subvolume_offset, subvolume_length, extent_offset, extent_count,
        sector1_low_offset, sector1_high_offset, raid_offset,
    ) = _EXT_PATCH_AREA.unpack_from(image, epa_offset)

    _bounded_region(adv_pointer_offset, 16, len(image), "ADV pointer table")
    _bounded_region(directory_offset, directory_length, len(image), "directory field")
    _bounded_region(subvolume_offset, subvolume_length, len(image), "subvolume field")
    _bounded_region(extent_offset, extent_count * _EXTENT.size, len(image), "extent table")
    _bounded_region(sector1_low_offset, 4, len(boot), "first-sector low pointer")
    _bounded_region(sector1_high_offset, 4, len(boot), "first-sector high pointer")
    _bounded_region(raid_offset, 2, len(boot), "RAID patch pointer")
    _require_disjoint_regions((
        (patch_offset, _PATCH_AREA.size, "patch area"),
        (epa_offset, _EXT_PATCH_AREA.size, "extended patch area"),
        (adv_pointer_offset, 16, "ADV pointer table"),
        (directory_offset, directory_length, "directory field"),
        (subvolume_offset, subvolume_length, "subvolume field"),
        (extent_offset, extent_count * _EXTENT.size, "extent table"),
    ), location="ldlinux.sys")
    _require_disjoint_regions((
        (sector1_low_offset, 4, "first-sector low pointer"),
        (sector1_high_offset, 4, "first-sector high pointer"),
        (raid_offset, 2, "RAID patch pointer"),
    ), location="ldlinux.bss")
    if (
        sector1_low_offset < 90
        or sector1_low_offset + 4 > 510
        or sector1_high_offset < 90
        or sector1_high_offset + 4 > 510
    ):
        raise SyslinuxPatchError("a first-sector pointer lies outside FAT32 boot code")
    if len(directory_bytes) > directory_length:
        raise SyslinuxPatchError("the Syslinux configuration directory is too long")

    data_sector_map = sector_map[1:-2]
    extents = _sector_extents(data_sector_map)
    if len(extents) > extent_count:
        raise SyslinuxPatchError("the ldlinux.sys extent table is too small")

    struct.pack_into("<I", boot, sector1_low_offset, sector_map[0] & 0xFFFFFFFF)
    struct.pack_into("<I", boot, sector1_high_offset, sector_map[0] >> 32)
    struct.pack_into("<H", image, patch_offset + 8, expected_sectors - 2)
    struct.pack_into("<H", image, patch_offset + 10, 2)
    dwords = len(image) // 4
    struct.pack_into("<I", image, patch_offset + 12, dwords)

    image[extent_offset:extent_offset + extent_count * _EXTENT.size] = (
        b"\0" * (extent_count * _EXTENT.size)
    )
    for index, extent in enumerate(extents):
        _EXTENT.pack_into(image, extent_offset + index * _EXTENT.size, extent.lba, extent.length)
    struct.pack_into("<Q", image, adv_pointer_offset, sector_map[-2])
    struct.pack_into("<Q", image, adv_pointer_offset + 8, sector_map[-1])
    image[directory_offset:directory_offset + len(directory_bytes)] = directory_bytes

    struct.pack_into("<I", image, patch_offset + 16, 0)
    checksum = LDLINUX_MAGIC
    for offset in range(0, dwords * 4, 4):
        checksum = (checksum - struct.unpack_from("<I", image, offset)[0]) & 0xFFFFFFFF
    struct.pack_into("<I", image, patch_offset + 16, checksum)
    if sum(struct.unpack_from(f"<{dwords}I", image, 0)) & 0xFFFFFFFF != LDLINUX_MAGIC:
        raise SyslinuxPatchError("the patched ldlinux.sys checksum is inconsistent")

    return (
        bytes(image) + make_empty_adv(), bytes(boot), patch_offset, extents, sector_map,
    )


def merge_fat32_boot_sector(formatted_vbr: bytes, patched_bss: bytes) -> tuple[bytes, int]:
    """Merge Syslinux code into a strictly validated 512-byte FAT32 VBR."""

    if type(formatted_vbr) is not bytes or len(formatted_vbr) != SECTOR_SIZE:
        raise SyslinuxPatchError("the formatted FAT32 VBR must be exactly 512 bytes")
    if type(patched_bss) is not bytes or len(patched_bss) != SECTOR_SIZE:
        raise SyslinuxPatchError("the patched ldlinux.bss must be exactly 512 bytes")
    if formatted_vbr[510:512] != b"\x55\xaa" or patched_bss[510:512] != b"\x55\xaa":
        raise SyslinuxPatchError("the FAT32 or Syslinux boot signature is missing")

    bytes_per_sector = struct.unpack_from("<H", formatted_vbr, 11)[0]
    sectors_per_cluster = formatted_vbr[13]
    reserved_sectors = struct.unpack_from("<H", formatted_vbr, 14)[0]
    fat_count = formatted_vbr[16]
    root_entries = struct.unpack_from("<H", formatted_vbr, 17)[0]
    total16 = struct.unpack_from("<H", formatted_vbr, 19)[0]
    media = formatted_vbr[21]
    fat16_size = struct.unpack_from("<H", formatted_vbr, 22)[0]
    total_sectors = struct.unpack_from("<I", formatted_vbr, 32)[0]
    fat_size = struct.unpack_from("<I", formatted_vbr, 36)[0]
    fat_flags = struct.unpack_from("<H", formatted_vbr, 40)[0]
    filesystem_version = struct.unpack_from("<H", formatted_vbr, 42)[0]
    root_cluster = struct.unpack_from("<I", formatted_vbr, 44)[0]
    fsinfo_sector = struct.unpack_from("<H", formatted_vbr, 48)[0]
    backup_sector = struct.unpack_from("<H", formatted_vbr, 50)[0]

    if bytes_per_sector != SECTOR_SIZE:
        raise SyslinuxPatchError("only 512-byte FAT32 sectors are supported")
    if (
        sectors_per_cluster == 0
        or sectors_per_cluster > 128
        or sectors_per_cluster & (sectors_per_cluster - 1)
    ):
        raise SyslinuxPatchError("the FAT32 sectors-per-cluster value is invalid")
    if (
        reserved_sectors < 3
        or fat_count != 2
        or root_entries != 0
        or total16 != 0
        or fat16_size != 0
        or fat_size == 0
        or fat_flags != 0
        or filesystem_version != 0
        or media != 0xF8
        or any(formatted_vbr[52:64])
        or formatted_vbr[66] != 0x29
        or formatted_vbr[82:90] != b"FAT32   "
    ):
        raise SyslinuxPatchError("the VBR is not a supported FAT32 volume")
    metadata_sectors = reserved_sectors + fat_count * fat_size
    if total_sectors <= metadata_sectors:
        raise SyslinuxPatchError("the FAT32 data region is empty")
    cluster_count = (total_sectors - metadata_sectors) // sectors_per_cluster
    if cluster_count < 65_525 or cluster_count + 2 > 0x0FFFFFF0:
        raise SyslinuxPatchError("the VBR does not describe a FAT32-sized volume")
    if cluster_count + 2 > fat_size * SECTOR_SIZE // 4:
        raise SyslinuxPatchError("the FAT32 allocation table is too small")
    if not 2 <= root_cluster < cluster_count + 2:
        raise SyslinuxPatchError("the FAT32 root cluster is outside the data region")
    if (
        fsinfo_sector <= 0
        or fsinfo_sector >= reserved_sectors
        or backup_sector <= 0
        or backup_sector >= reserved_sectors
        or fsinfo_sector == backup_sector
    ):
        raise SyslinuxPatchError("the FAT32 FSInfo or backup VBR location is invalid")

    merged = bytearray(formatted_vbr)
    preserved_bpb = bytes(merged[11:90])
    merged[0:11] = patched_bss[0:11]
    merged[90:510] = patched_bss[90:510]
    if merged[11:90] != preserved_bpb or merged[510:512] != b"\x55\xaa":
        raise SyslinuxPatchError("the FAT32 BPB changed while merging boot code")
    return bytes(merged), backup_sector


def prepare_syslinux_patch(
    bundle: BoundBootBundle,
    formatted_vbr: bytes,
    sectors: tuple[int, ...] | list[int],
    *,
    volume_offset: int,
    directory: str = "",
) -> SyslinuxPatchResult:
    """Bind, patch, and merge volume-relative bytes without changing a target."""

    payloads = bind_syslinux_bundle(bundle)
    if not isinstance(sectors, (tuple, list)):
        raise SyslinuxPatchError("the ldlinux.sys sector map must be an explicit sequence")
    frozen_sectors = tuple(sectors)
    if type(volume_offset) is not int or volume_offset < 0 or volume_offset % SECTOR_SIZE:
        raise SyslinuxPatchError("the FAT32 volume offset is not sector aligned")
    # Validate the VBR before trusting its geometry, then bind every sector to
    # the declared FAT32 data region.  The read-only FAT mapper provides the
    # stronger chain/content proof used by the intended production caller.
    merge_fat32_boot_sector(formatted_vbr, payloads.ldlinux_bss)
    total_sectors = struct.unpack_from("<I", formatted_vbr, 32)[0]
    reserved_sectors = struct.unpack_from("<H", formatted_vbr, 14)[0]
    fat_count = formatted_vbr[16]
    fat_size = struct.unpack_from("<I", formatted_vbr, 36)[0]
    hidden_sectors = struct.unpack_from("<I", formatted_vbr, 28)[0]
    data_start_sector = reserved_sectors + fat_count * fat_size
    if volume_offset // SECTOR_SIZE > _UINT32_MAX or hidden_sectors != volume_offset // SECTOR_SIZE:
        raise SyslinuxPatchError("the FAT32 hidden-sector field does not match its image offset")
    if any(
        type(sector) is not int
        or sector < data_start_sector
        or sector >= total_sectors
        for sector in frozen_sectors
    ):
        raise SyslinuxPatchError("the ldlinux.sys sector map leaves the FAT32 data region")
    ldlinux_file, patched_bss, patch_offset, extents, sector_map = patch_ldlinux(
        payloads.ldlinux_sys,
        payloads.ldlinux_bss,
        frozen_sectors,
        directory=directory,
    )
    boot_sector, backup_sector = merge_fat32_boot_sector(formatted_vbr, patched_bss)
    return SyslinuxPatchResult(
        version=payloads.version,
        ldlinux_file=ldlinux_file,
        boot_sector=boot_sector,
        backup_boot_sector=backup_sector,
        patch_offset=patch_offset,
        extents=extents,
        sector_map=sector_map,
    )
