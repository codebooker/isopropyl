from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Read-only FAT32 sector mapping for a staged root ``ldlinux.sys``.

The future BIOS executor must first create and flush the unpatched file, then
use this descriptor-only boundary to prove its exact bytes and obtain the
volume-relative sectors required by :mod:`isopropyl.syslinux`.  This module
does not open paths, mount filesystems, or write any byte.
"""

import hashlib
import os
import re
import stat
import struct
import unicodedata
from dataclasses import dataclass

from .bootloaders import BoundBootBundle
from .syslinux import (
    SECTOR_SIZE,
    SyslinuxPatchError,
    SyslinuxMbrResult,
    SyslinuxPatchResult,
    bind_syslinux_bundle,
    make_empty_adv,
    prepare_syslinux_patch,
    prepare_syslinux_mbr,
)


MAX_ROOT_DIRECTORY_BYTES = 8 * 1024 * 1024
MAX_LDLINUX_BYTES = 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SHORT_NAME = b"LDLINUX SYS"
_EOC = 0x0FFFFFF8
_BAD = 0x0FFFFFF7


@dataclass(frozen=True)
class Fat32SourceIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class Fat32FileMap:
    source_identity: Fat32SourceIdentity
    volume_offset: int
    volume_size: int
    file_size: int
    file_sha256: str
    first_cluster: int
    clusters: tuple[int, ...]
    sectors: tuple[int, ...]
    boot_sector: bytes
    backup_boot_sector: int


@dataclass(frozen=True)
class SyslinuxRegularFilePlan:
    """A complete, still non-destructive MBR/FAT32 patch byte plan."""

    mapping: Fat32FileMap
    mbr: SyslinuxMbrResult
    syslinux: SyslinuxPatchResult


@dataclass(frozen=True)
class _Layout:
    volume_offset: int
    volume_size: int
    sectors_per_cluster: int
    reserved_sectors: int
    fat_count: int
    sectors_per_fat: int
    total_sectors: int
    root_cluster: int
    fsinfo_sector: int
    backup_boot_sector: int
    data_start_sector: int
    cluster_count: int


class _Reader:
    def __init__(self, descriptor: int, identity: Fat32SourceIdentity) -> None:
        self.descriptor = descriptor
        self.identity = identity

    def exact(self, offset: int, length: int, label: str) -> bytes:
        if (
            type(offset) is not int
            or type(length) is not int
            or offset < 0
            or length < 0
            or offset > self.identity.size
            or length > self.identity.size - offset
        ):
            raise SyslinuxPatchError(f"the {label} lies outside the regular-file image")
        try:
            value = os.pread(self.descriptor, length, offset)
        except OSError as error:
            raise SyslinuxPatchError(f"could not read the {label}: {error}") from error
        if len(value) != length:
            raise SyslinuxPatchError(f"could not read the {label} completely")
        return value


def _identity(status: os.stat_result) -> Fat32SourceIdentity:
    return Fat32SourceIdentity(
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _layout(boot: bytes, volume_offset: int, volume_size: int) -> _Layout:
    if (
        len(boot) != SECTOR_SIZE
        or boot[0] not in {0xE9, 0xEB}
        or (boot[0] == 0xEB and boot[2] != 0x90)
        or boot[510:512] != b"\x55\xaa"
    ):
        raise SyslinuxPatchError("the volume does not have a supported FAT32 VBR")
    bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
    sectors_per_cluster = boot[13]
    reserved = struct.unpack_from("<H", boot, 14)[0]
    fat_count = boot[16]
    root_entries = struct.unpack_from("<H", boot, 17)[0]
    total16 = struct.unpack_from("<H", boot, 19)[0]
    fat16_size = struct.unpack_from("<H", boot, 22)[0]
    total_sectors = struct.unpack_from("<I", boot, 32)[0]
    hidden_sectors = struct.unpack_from("<I", boot, 28)[0]
    sectors_per_fat = struct.unpack_from("<I", boot, 36)[0]
    flags = struct.unpack_from("<H", boot, 40)[0]
    version = struct.unpack_from("<H", boot, 42)[0]
    root_cluster = struct.unpack_from("<I", boot, 44)[0]
    fsinfo_sector = struct.unpack_from("<H", boot, 48)[0]
    backup_sector = struct.unpack_from("<H", boot, 50)[0]
    if bytes_per_sector != SECTOR_SIZE:
        raise SyslinuxPatchError("only 512-byte FAT32 sectors are supported")
    if (
        sectors_per_cluster == 0
        or sectors_per_cluster > 128
        or sectors_per_cluster & (sectors_per_cluster - 1)
        or reserved < 3
        or fat_count != 2
        or root_entries != 0
        or total16 != 0
        or fat16_size != 0
        or total_sectors == 0
        or sectors_per_fat == 0
        or flags != 0
        or version != 0
        or any(boot[52:64])
        or boot[21] != 0xF8
        or boot[66] != 0x29
        or boot[82:90] != b"FAT32   "
    ):
        raise SyslinuxPatchError("the volume BPB is outside the supported FAT32 profile")
    if total_sectors * SECTOR_SIZE != volume_size:
        raise SyslinuxPatchError("the FAT32 BPB does not match the bounded volume size")
    if volume_offset // SECTOR_SIZE > 0xFFFFFFFF or hidden_sectors != volume_offset // SECTOR_SIZE:
        raise SyslinuxPatchError("the FAT32 hidden-sector field does not match its image offset")
    data_start = reserved + fat_count * sectors_per_fat
    if data_start >= total_sectors:
        raise SyslinuxPatchError("the FAT32 metadata consumes the volume")
    cluster_count = (total_sectors - data_start) // sectors_per_cluster
    if cluster_count < 65_525 or cluster_count + 2 > 0x0FFFFFF0:
        raise SyslinuxPatchError("the volume geometry is not FAT32-sized")
    if cluster_count + 2 > sectors_per_fat * SECTOR_SIZE // 4:
        raise SyslinuxPatchError("the FAT32 allocation table is too small")
    if not 2 <= root_cluster < cluster_count + 2:
        raise SyslinuxPatchError("the FAT32 root cluster is outside the data region")
    if (
        fsinfo_sector <= 0
        or fsinfo_sector >= reserved
        or backup_sector <= 0
        or backup_sector >= reserved
        or fsinfo_sector == backup_sector
    ):
        raise SyslinuxPatchError("the FAT32 reserved-sector pointers are invalid")
    return _Layout(
        volume_offset, volume_size, sectors_per_cluster, reserved, fat_count,
        sectors_per_fat, total_sectors, root_cluster, fsinfo_sector,
        backup_sector, data_start, cluster_count,
    )


class _Fat:
    def __init__(self, reader: _Reader, layout: _Layout) -> None:
        self.reader = reader
        self.layout = layout
        self.cache: dict[int, int] = {}
        first = self.value(0)
        second = self.value(1)
        if first & 0xFF != 0xF8 or first < 0x0FFFFFF0 or second < _EOC:
            raise SyslinuxPatchError("the FAT32 reserved entries are invalid")

    def value(self, cluster: int) -> int:
        if type(cluster) is not int or cluster < 0 or cluster >= self.layout.cluster_count + 2:
            raise SyslinuxPatchError("a FAT32 cluster index is outside the volume")
        cached = self.cache.get(cluster)
        if cached is not None:
            return cached
        values = []
        for copy_index in range(self.layout.fat_count):
            byte_offset = (
                self.layout.volume_offset
                + (self.layout.reserved_sectors + copy_index * self.layout.sectors_per_fat)
                * SECTOR_SIZE
                + cluster * 4
            )
            values.append(
                struct.unpack("<I", self.reader.exact(
                    byte_offset, 4, f"FAT32 copy {copy_index + 1} entry",
                ))[0] & 0x0FFFFFFF
            )
        if len(set(values)) != 1:
            raise SyslinuxPatchError("the FAT32 allocation-table copies disagree")
        self.cache[cluster] = values[0]
        return values[0]

    def chain(self, first: int, label: str, *, max_clusters: int) -> tuple[int, ...]:
        if not 2 <= first < self.layout.cluster_count + 2:
            raise SyslinuxPatchError(f"the {label} starts at an invalid FAT32 cluster")
        result: list[int] = []
        seen: set[int] = set()
        current = first
        while True:
            if current in seen:
                raise SyslinuxPatchError(f"the {label} contains a FAT32 cluster loop")
            if not 2 <= current < self.layout.cluster_count + 2:
                raise SyslinuxPatchError(f"the {label} leaves the FAT32 data region")
            seen.add(current)
            result.append(current)
            if len(result) > max_clusters:
                raise SyslinuxPatchError(f"the {label} exceeds its FAT32 cluster limit")
            following = self.value(current)
            if following >= _EOC:
                return tuple(result)
            if following in {0, 1} or following == _BAD or 0x0FFFFFF0 <= following < _EOC:
                raise SyslinuxPatchError(f"the {label} ends in a free, reserved, or bad cluster")
            current = following


def _cluster_offset(layout: _Layout, cluster: int) -> int:
    sector = layout.data_start_sector + (cluster - 2) * layout.sectors_per_cluster
    length = layout.sectors_per_cluster * SECTOR_SIZE
    relative = sector * SECTOR_SIZE
    if relative > layout.volume_size or length > layout.volume_size - relative:
        raise SyslinuxPatchError("a FAT32 cluster lies outside the bounded volume")
    return layout.volume_offset + relative


def _lfn_checksum(short_name: bytes) -> int:
    checksum = 0
    for byte in short_name:
        checksum = (((checksum & 1) << 7) | (checksum >> 1)) + byte
        checksum &= 0xFF
    return checksum


def _lfn_units(entry: bytes) -> tuple[int, ...]:
    return struct.unpack("<13H", entry[1:11] + entry[14:26] + entry[28:32])


def _decode_lfn(chunks: dict[int, tuple[int, ...]], count: int) -> str:
    units = [unit for index in range(1, count + 1) for unit in chunks[index]]
    try:
        terminator = units.index(0)
    except ValueError:
        terminator = len(units)
    if any(unit not in {0, 0xFFFF} for unit in units[terminator + 1:]):
        raise SyslinuxPatchError("the FAT32 root contains malformed long-name padding")
    useful = units[:terminator]
    if not useful or any(unit == 0xFFFF for unit in useful):
        raise SyslinuxPatchError("the FAT32 root contains an empty long name")
    try:
        raw = b"".join(struct.pack("<H", unit) for unit in useful)
        return unicodedata.normalize("NFC", raw.decode("utf-16-le", errors="strict"))
    except (UnicodeDecodeError, struct.error) as error:
        raise SyslinuxPatchError("the FAT32 root contains malformed UTF-16") from error


def _root_entry(
    reader: _Reader,
    fat: _Fat,
    layout: _Layout,
) -> tuple[int, int, tuple[int, ...]]:
    cluster_bytes = layout.sectors_per_cluster * SECTOR_SIZE
    max_clusters = MAX_ROOT_DIRECTORY_BYTES // cluster_bytes
    root_chain = fat.chain(layout.root_cluster, "root directory", max_clusters=max_clusters)
    target: tuple[int, int] | None = None
    lfn_chunks: dict[int, tuple[int, ...]] = {}
    lfn_count = 0
    lfn_expected = 0
    lfn_checksum: int | None = None
    finished = False
    for cluster in root_chain:
        raw = reader.exact(_cluster_offset(layout, cluster), cluster_bytes, "FAT32 root directory")
        for offset in range(0, len(raw), 32):
            entry = raw[offset:offset + 32]
            if entry[0] == 0x00:
                if lfn_chunks:
                    raise SyslinuxPatchError("the FAT32 root ends with an orphan long name")
                finished = True
                break
            if entry[0] == 0xE5:
                lfn_chunks.clear()
                lfn_count = lfn_expected = 0
                lfn_checksum = None
                continue
            attributes = entry[11]
            if attributes == 0x0F:
                ordinal_raw = entry[0]
                ordinal = ordinal_raw & 0x1F
                is_last = bool(ordinal_raw & 0x40)
                if (
                    ordinal_raw & 0xA0
                    or ordinal == 0
                    or ordinal > 20
                    or entry[12] != 0
                    or entry[26:28] != b"\0\0"
                ):
                    raise SyslinuxPatchError("the FAT32 root contains a malformed long name")
                if is_last:
                    if lfn_chunks:
                        raise SyslinuxPatchError("the FAT32 root contains nested long names")
                    lfn_count = ordinal
                    lfn_expected = ordinal
                    lfn_checksum = entry[13]
                if not lfn_chunks and not is_last:
                    raise SyslinuxPatchError("the FAT32 long name has no final marker")
                if ordinal != lfn_expected or entry[13] != lfn_checksum:
                    raise SyslinuxPatchError("the FAT32 long-name sequence is out of order")
                lfn_chunks[ordinal] = _lfn_units(entry)
                lfn_expected -= 1
                continue
            if attributes & 0xC0:
                raise SyslinuxPatchError("the FAT32 root contains reserved attributes")
            visible_lfn: str | None = None
            if lfn_chunks:
                if lfn_expected != 0 or _lfn_checksum(entry[:11]) != lfn_checksum:
                    raise SyslinuxPatchError("the FAT32 long name does not match its short entry")
                visible_lfn = _decode_lfn(lfn_chunks, lfn_count)
            if visible_lfn is not None and visible_lfn.casefold() == "ldlinux.sys":
                raise SyslinuxPatchError("ldlinux.sys is hidden behind a FAT long-name alias")
            if entry[:11] == _SHORT_NAME:
                if target is not None:
                    raise SyslinuxPatchError("the FAT32 root contains duplicate ldlinux.sys entries")
                if attributes & 0x18:
                    raise SyslinuxPatchError("ldlinux.sys is a directory or volume label")
                high = struct.unpack_from("<H", entry, 20)[0]
                low = struct.unpack_from("<H", entry, 26)[0]
                target = ((high << 16) | low, struct.unpack_from("<I", entry, 28)[0])
            lfn_chunks.clear()
            lfn_count = lfn_expected = 0
            lfn_checksum = None
        if finished:
            break
    if not finished:
        if lfn_chunks:
            raise SyslinuxPatchError("the FAT32 root ends with an orphan long name")
        raise SyslinuxPatchError("the bounded FAT32 root directory has no end marker")
    if target is None:
        raise SyslinuxPatchError("the FAT32 root does not contain ldlinux.sys")
    return target[0], target[1], root_chain


def map_root_ldlinux(
    descriptor: int,
    *,
    volume_offset: int,
    volume_size: int,
    expected_file: bytes,
) -> Fat32FileMap:
    """Bind and map an exact root ``ldlinux.sys`` in a regular-file image."""

    if type(descriptor) is not int or descriptor < 0:
        raise SyslinuxPatchError("a valid regular-file descriptor is required")
    if (
        type(volume_offset) is not int
        or type(volume_size) is not int
        or volume_offset < 0
        or volume_size <= 0
        or volume_offset % SECTOR_SIZE
        or volume_size % SECTOR_SIZE
    ):
        raise SyslinuxPatchError("the FAT32 volume bounds are not sector aligned")
    if type(expected_file) is not bytes or not 0 < len(expected_file) <= MAX_LDLINUX_BYTES:
        raise SyslinuxPatchError("the expected ldlinux.sys bytes are invalid")
    try:
        before_status = os.fstat(descriptor)
    except OSError as error:
        raise SyslinuxPatchError(f"could not inspect the regular-file image: {error}") from error
    if not stat.S_ISREG(before_status.st_mode) or before_status.st_size <= 0:
        raise SyslinuxPatchError("the FAT32 image descriptor is not a regular file")
    identity = _identity(before_status)
    if volume_offset > identity.size or volume_size > identity.size - volume_offset:
        raise SyslinuxPatchError("the FAT32 volume exceeds the regular-file image")
    reader = _Reader(descriptor, identity)
    boot = reader.exact(volume_offset, SECTOR_SIZE, "primary FAT32 VBR")
    layout = _layout(boot, volume_offset, volume_size)
    backup = reader.exact(
        volume_offset + layout.backup_boot_sector * SECTOR_SIZE,
        SECTOR_SIZE,
        "backup FAT32 VBR",
    )
    if backup != boot:
        raise SyslinuxPatchError("the primary and backup FAT32 VBRs disagree")
    fsinfo = reader.exact(
        volume_offset + layout.fsinfo_sector * SECTOR_SIZE,
        SECTOR_SIZE,
        "FAT32 FSInfo sector",
    )
    if (
        struct.unpack_from("<I", fsinfo, 0)[0] != 0x41615252
        or struct.unpack_from("<I", fsinfo, 484)[0] != 0x61417272
        or struct.unpack_from("<I", fsinfo, 508)[0] != 0xAA550000
    ):
        raise SyslinuxPatchError("the FAT32 FSInfo signatures are invalid")

    fat = _Fat(reader, layout)
    first_cluster, file_size, root_clusters = _root_entry(reader, fat, layout)
    if file_size != len(expected_file):
        raise SyslinuxPatchError("the staged ldlinux.sys size changed")
    cluster_bytes = layout.sectors_per_cluster * SECTOR_SIZE
    required_clusters = (file_size + cluster_bytes - 1) // cluster_bytes
    clusters = fat.chain(first_cluster, "ldlinux.sys", max_clusters=required_clusters)
    if len(clusters) != required_clusters or set(root_clusters).intersection(clusters):
        raise SyslinuxPatchError("the ldlinux.sys cluster chain is over-sized or cross-linked")

    required_sectors = (file_size + SECTOR_SIZE - 1) // SECTOR_SIZE
    sectors = tuple(
        layout.data_start_sector + (cluster - 2) * layout.sectors_per_cluster + index
        for cluster in clusters
        for index in range(layout.sectors_per_cluster)
    )[:required_sectors]
    if len(sectors) != required_sectors or len(set(sectors)) != len(sectors):
        raise SyslinuxPatchError("the ldlinux.sys sector map is incomplete or duplicated")
    remaining = file_size
    digest = hashlib.sha256()
    for sector in sectors:
        take = min(SECTOR_SIZE, remaining)
        digest.update(reader.exact(
            volume_offset + sector * SECTOR_SIZE,
            take,
            "staged ldlinux.sys",
        ))
        remaining -= take
    actual_digest = digest.hexdigest()
    expected_digest = hashlib.sha256(expected_file).hexdigest()
    if remaining != 0 or not _SHA256.fullmatch(actual_digest) or actual_digest != expected_digest:
        raise SyslinuxPatchError("the staged ldlinux.sys bytes changed")

    try:
        after_status = os.fstat(descriptor)
    except OSError as error:
        raise SyslinuxPatchError(f"could not revalidate the regular-file image: {error}") from error
    if _identity(after_status) != identity:
        raise SyslinuxPatchError("the regular-file image changed while it was inspected")
    return Fat32FileMap(
        identity, volume_offset, volume_size, file_size, actual_digest,
        first_cluster, clusters, sectors, boot, layout.backup_boot_sector,
    )


def prepare_syslinux_patch_from_map(
    bundle: BoundBootBundle,
    descriptor: int,
    mapping: Fat32FileMap,
    *,
    directory: str = "",
) -> SyslinuxPatchResult:
    """Bind one exact bundle to a descriptor-derived, volume-relative map.

    The live descriptor is remapped immediately; a constructible or stale
    ``Fat32FileMap`` can never supply authoritative sectors. This function
    remains read-only and non-destructive.
    """

    if not isinstance(mapping, Fat32FileMap):
        raise SyslinuxPatchError("a descriptor-derived FAT32 file map is required")
    payloads = bind_syslinux_bundle(bundle)
    unpatched_file = payloads.ldlinux_sys + make_empty_adv()
    if (
        mapping.file_size != len(unpatched_file)
        or mapping.file_sha256 != hashlib.sha256(unpatched_file).hexdigest()
        or len(mapping.sectors) != (len(unpatched_file) + SECTOR_SIZE - 1) // SECTOR_SIZE
    ):
        raise SyslinuxPatchError("the FAT32 map is not bound to this Syslinux bundle")
    fresh_mapping = map_root_ldlinux(
        descriptor,
        volume_offset=mapping.volume_offset,
        volume_size=mapping.volume_size,
        expected_file=unpatched_file,
    )
    if fresh_mapping != mapping:
        raise SyslinuxPatchError("the descriptor-derived FAT32 map changed since inspection")
    return prepare_syslinux_patch(
        bundle,
        fresh_mapping.boot_sector,
        fresh_mapping.sectors,
        volume_offset=fresh_mapping.volume_offset,
        directory=directory,
    )


def prepare_syslinux_regular_file_plan(
    bundle: BoundBootBundle,
    descriptor: int,
    mapping: Fat32FileMap,
    *,
    directory: str = "",
) -> SyslinuxRegularFilePlan:
    """Bind live MBR, VBR, FAT chain, and payload bytes without writing."""

    syslinux = prepare_syslinux_patch_from_map(
        bundle,
        descriptor,
        mapping,
        directory=directory,
    )
    try:
        before_status = os.fstat(descriptor)
    except OSError as error:
        raise SyslinuxPatchError(f"could not inspect the regular-file image: {error}") from error
    if _identity(before_status) != mapping.source_identity:
        raise SyslinuxPatchError("the regular-file image changed before its MBR was inspected")
    formatted_mbr = _Reader(descriptor, mapping.source_identity).exact(
        0, SECTOR_SIZE, "formatted MBR",
    )
    try:
        after_status = os.fstat(descriptor)
    except OSError as error:
        raise SyslinuxPatchError(f"could not revalidate the regular-file image: {error}") from error
    if _identity(after_status) != mapping.source_identity:
        raise SyslinuxPatchError("the regular-file image changed while its MBR was inspected")
    partition_start = mapping.volume_offset // SECTOR_SIZE
    partition_sectors = mapping.volume_size // SECTOR_SIZE
    mbr = prepare_syslinux_mbr(
        formatted_mbr,
        partition_start_sector=partition_start,
        partition_sector_count=partition_sectors,
    )
    return SyslinuxRegularFilePlan(mapping, mbr, syslinux)
