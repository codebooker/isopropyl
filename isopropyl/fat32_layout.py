"""Portable FAT32 geometry and metadata; no host I/O or privilege imports."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations
import struct
from dataclasses import dataclass

SECTOR_SIZE = 512
PARTITION_START_SECTOR = 2_048
RESERVED_SECTORS = 32
FAT_COUNT = 2
FSINFO_SECTOR = 1
BACKUP_BOOT_SECTOR = 6
VOLUME_LABEL = b"ISOPROPYL  "
MAX_PRIVATE_FAT32_IMAGE_BYTES = 128 * 1024**3

class PrivateFat32Error(RuntimeError):
    """A private FAT32 image could not be built or attested safely."""


@dataclass(frozen=True)
class PrivateFat32Geometry:
    image_size: int
    volume_offset: int
    volume_size: int
    partition_sectors: int
    sectors_per_cluster: int
    sectors_per_fat: int
    data_start_sector: int
    cluster_count: int

    @property
    def cluster_bytes(self) -> int:
        return self.sectors_per_cluster * SECTOR_SIZE


def _geometry(image_size: int, cluster_size: int | None = None, *, maximum=MAX_PRIVATE_FAT32_IMAGE_BYTES) -> PrivateFat32Geometry:
    if type(maximum) is not int or not 0 < maximum <= 2*1024**4:
        raise PrivateFat32Error("The FAT32 geometry size limit is invalid")
    if (
        type(image_size) is not int
        or image_size <= PARTITION_START_SECTOR * SECTOR_SIZE
        or image_size > maximum
        or image_size % SECTOR_SIZE
    ):
        raise PrivateFat32Error("The private FAT32 image size is invalid")
    image_sectors = image_size // SECTOR_SIZE
    partition_sectors = image_sectors - PARTITION_START_SECTOR
    if partition_sectors <= 0 or partition_sectors > 0xFFFFFFFF:
        raise PrivateFat32Error("The private FAT32 partition exceeds MBR bounds")
    if partition_sectors < 532_480:
        sectors_per_cluster = 1
    elif partition_sectors < 16_777_216:
        sectors_per_cluster = 8
    elif partition_sectors < 33_554_432:
        sectors_per_cluster = 16
    elif partition_sectors < 67_108_864:
        sectors_per_cluster = 32
    else:
        sectors_per_cluster = 64
    if cluster_size is not None:
        if cluster_size not in {512,1024,2048,4096,8192,16384,32768,65536}:
            raise PrivateFat32Error("Unsupported FAT32 allocation unit")
        sectors_per_cluster=cluster_size//SECTOR_SIZE
    sectors_per_fat = max(
        1,
        ((partition_sectors - RESERVED_SECTORS) // sectors_per_cluster + 2) * 4
        // SECTOR_SIZE,
    )
    seen: set[int] = set()
    while True:
        data_sectors = partition_sectors - RESERVED_SECTORS - FAT_COUNT * sectors_per_fat
        if data_sectors <= 0:
            raise PrivateFat32Error("The FAT32 metadata consumes the private image")
        cluster_count = data_sectors // sectors_per_cluster
        required = (cluster_count + 2) * 4
        required = (required + SECTOR_SIZE - 1) // SECTOR_SIZE
        if required == sectors_per_fat:
            break
        if required in seen:
            sectors_per_fat = max(sectors_per_fat, required)
            break
        seen.add(sectors_per_fat)
        sectors_per_fat = required
    data_start = RESERVED_SECTORS + FAT_COUNT * sectors_per_fat
    cluster_count = (partition_sectors - data_start) // sectors_per_cluster
    if (
        cluster_count < 65_525
        or cluster_count + 2 > 0x0FFFFFF0
        or cluster_count + 2 > sectors_per_fat * SECTOR_SIZE // 4
    ):
        raise PrivateFat32Error("The image does not produce supported FAT32 geometry")
    return PrivateFat32Geometry(
        image_size,
        PARTITION_START_SECTOR * SECTOR_SIZE,
        partition_sectors * SECTOR_SIZE,
        partition_sectors,
        sectors_per_cluster,
        sectors_per_fat,
        data_start,
        cluster_count,
    )


def _mbr(plan: PrivateFat32Plan) -> bytes:
    result = bytearray(SECTOR_SIZE)
    struct.pack_into("<I", result, 440, plan.disk_signature)
    entry = bytearray(16)
    entry[0] = 0x80
    entry[1:4] = b"\x20\x21\x00"
    entry[4] = 0x0C
    entry[5:8] = b"\xfe\xff\xff"
    struct.pack_into("<I", entry, 8, PARTITION_START_SECTOR)
    struct.pack_into("<I", entry, 12, plan.geometry.partition_sectors)
    result[446:462] = entry
    result[510:512] = b"\x55\xaa"
    return bytes(result)


def _boot_sector(plan: PrivateFat32Plan) -> bytes:
    geometry = plan.geometry
    result = bytearray(SECTOR_SIZE)
    result[:3] = b"\xeb\x58\x90"
    result[3:11] = b"ISOPROPY"
    struct.pack_into("<H", result, 11, SECTOR_SIZE)
    result[13] = geometry.sectors_per_cluster
    struct.pack_into("<H", result, 14, RESERVED_SECTORS)
    result[16] = FAT_COUNT
    result[21] = 0xF8
    struct.pack_into("<H", result, 24, 63)
    struct.pack_into("<H", result, 26, 255)
    struct.pack_into("<I", result, 28, PARTITION_START_SECTOR)
    struct.pack_into("<I", result, 32, geometry.partition_sectors)
    struct.pack_into("<I", result, 36, geometry.sectors_per_fat)
    struct.pack_into("<I", result, 44, 2)
    struct.pack_into("<H", result, 48, FSINFO_SECTOR)
    struct.pack_into("<H", result, 50, BACKUP_BOOT_SECTOR)
    result[64] = 0x80
    result[66] = 0x29
    struct.pack_into("<I", result, 67, plan.volume_id)
    result[71:82] = getattr(plan,'volume_label',VOLUME_LABEL)
    result[82:90] = b"FAT32   "
    result[510:512] = b"\x55\xaa"
    return bytes(result)


def _fsinfo(plan: PrivateFat32Plan) -> bytes:
    result = bytearray(SECTOR_SIZE)
    free_clusters = plan.geometry.cluster_count - plan.allocated_clusters
    next_free = 2 + plan.allocated_clusters if free_clusters else 0xFFFFFFFF
    struct.pack_into("<I", result, 0, 0x41615252)
    struct.pack_into("<I", result, 484, 0x61417272)
    struct.pack_into("<I", result, 488, free_clusters)
    struct.pack_into("<I", result, 492, next_free)
    struct.pack_into("<I", result, 508, 0xAA550000)
    return bytes(result)


def _fat(plan: PrivateFat32Plan) -> bytes:
    result = bytearray(plan.geometry.sectors_per_fat * SECTOR_SIZE)
    struct.pack_into("<I", result, 0, 0x0FFFFFF8)
    struct.pack_into("<I", result, 4, 0x0FFFFFFF)
    for item in (*plan.directories, *plan.files):
        if item.cluster_count == 0:
            continue
        for index in range(item.cluster_count):
            cluster = item.first_cluster + index
            following = (
                cluster + 1 if index + 1 < item.cluster_count else 0x0FFFFFFF
            )
            struct.pack_into("<I", result, cluster * 4, following)
    return bytes(result)


def _cluster_offset(geometry: PrivateFat32Geometry, first_cluster: int) -> int:
    return geometry.volume_offset + (
        geometry.data_start_sector
        + (first_cluster - 2) * geometry.sectors_per_cluster
    ) * SECTOR_SIZE


