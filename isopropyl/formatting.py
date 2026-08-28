from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import os
import re
import shutil
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum

from .devices import Device, parse_lsblk
from .conflicts import conflict_diagnostic_suffix, unmount_response_is_inactive
from .locking import (
    CooperativeLockError,
    add_native_sfdisk_lock,
    cooperative_lock_command,
    is_cooperative_lock_command,
    lock_conflict_message,
    resolve_flock,
)


class FormattingError(RuntimeError):
    """Base class for safe-formatting failures."""


class FormatValidationError(FormattingError, ValueError):
    pass


class MissingFormatToolError(FormattingError):
    pass


class DeviceChangedError(FormattingError):
    pass


class FormatCancelled(FormattingError):
    pass


class Filesystem(str, Enum):
    FAT12 = "fat12"
    FAT16 = "fat16"
    FAT32 = "fat32"
    EXFAT = "exfat"
    NTFS = "ntfs"
    UDF = "udf"
    EXT2 = "ext2"
    EXT3 = "ext3"
    EXT4 = "ext4"


class PartitionTable(str, Enum):
    MBR = "mbr"
    GPT = "gpt"


class PartitionRole(str, Enum):
    """Semantic partition roles used by constructed-media workflows."""

    DATA = "data"
    EFI_SYSTEM = "efi-system"
    PERSISTENCE = "persistence"
    MICROSOFT_RESERVED = "microsoft-reserved"
    WINDOWS_OS = "windows-os"
    UEFI_NTFS = "uefi-ntfs"


DeviceIdentity = tuple[str, int, str, str, str, str]
StageCallback = Callable[[str], None]
DeviceLookup = Callable[[str], Device | None]


@dataclass(frozen=True)
class FormatPlan:
    """A validated intent bound to the drive selected by the user."""

    device_path: str
    device_identity: DeviceIdentity
    filesystem: Filesystem
    partition_table: PartitionTable
    label: str = ""
    allocation_unit_size: int | None = None


@dataclass(frozen=True)
class PartitionSpec:
    """One ordered partition in a multi-partition layout.

    ``size_mib=None`` means consume the remaining device space and is accepted
    only for the final partition.  Partitions such as the Microsoft Reserved
    Partition deliberately have no filesystem and are not formatted.
    """

    role: PartitionRole
    filesystem: Filesystem | None
    label: str = ""
    size_mib: int | None = None
    bootable: bool = False
    start_sector: int | None = None
    sector_count: int | None = None


@dataclass(frozen=True)
class MultiFormatPlan:
    """A complete ordered partitioning intent bound to one selected drive."""

    device_path: str
    device_identity: DeviceIdentity
    partition_table: PartitionTable
    partitions: tuple[PartitionSpec, ...]
    logical_sector_size: int | None = None


@dataclass(frozen=True)
class FormatTools:
    pkexec: str
    udisksctl: str
    sfdisk: str
    partprobe: str
    udevadm: str
    lsblk: str
    mkfs: str


@dataclass(frozen=True)
class MultiFormatTools:
    pkexec: str
    udisksctl: str
    sfdisk: str
    partprobe: str
    udevadm: str
    lsblk: str
    mkfs_tools: tuple[tuple[Filesystem, str], ...]

    def mkfs_for(self, filesystem: Filesystem) -> str:
        for candidate, path in self.mkfs_tools:
            if candidate is filesystem:
                return path
        raise MissingFormatToolError(
            f"The multi-partition plan has no formatter for {filesystem.value}"
        )


_WHOLE_DISK = re.compile(
    r"/dev/(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|mmcblk\d+|ubd[a-z]+)"
)
_BLOCK_PATH = re.compile(r"/dev/[A-Za-z0-9._+:-]+")
_MAJOR_MINOR = re.compile(r"\d+:\d+")
_WINDOWS_FORBIDDEN = frozenset('"*/:<>?\\|')
_FAT_FORBIDDEN = _WINDOWS_FORBIDDEN | frozenset("+,.;=[]")
_MINIMUM_DEVICE_SIZE = 16 * 1024 * 1024
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"

_MKFS_NAMES: Mapping[Filesystem, str] = {
    Filesystem.FAT12: "mkfs.vfat",
    Filesystem.FAT16: "mkfs.vfat",
    Filesystem.FAT32: "mkfs.vfat",
    Filesystem.EXFAT: "mkfs.exfat",
    Filesystem.NTFS: "mkfs.ntfs",
    Filesystem.UDF: "mkudffs",
    Filesystem.EXT2: "mkfs.ext2",
    Filesystem.EXT3: "mkfs.ext3",
    Filesystem.EXT4: "mkfs.ext4",
}

_MBR_TYPES: Mapping[Filesystem, str] = {
    Filesystem.FAT12: "1",
    Filesystem.FAT16: "e",
    Filesystem.FAT32: "c",
    Filesystem.EXFAT: "7",
    Filesystem.NTFS: "7",
    Filesystem.UDF: "7",
    Filesystem.EXT2: "83",
    Filesystem.EXT3: "83",
    Filesystem.EXT4: "83",
}

_GPT_TYPES: Mapping[Filesystem, str] = {
    Filesystem.FAT12: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    Filesystem.FAT16: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    Filesystem.FAT32: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    Filesystem.EXFAT: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    Filesystem.NTFS: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    Filesystem.UDF: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    Filesystem.EXT2: "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
    Filesystem.EXT3: "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
    Filesystem.EXT4: "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
}

_MBR_ROLE_TYPES: Mapping[PartitionRole, str] = {
    PartitionRole.EFI_SYSTEM: "ef",
    PartitionRole.PERSISTENCE: "83",
    PartitionRole.WINDOWS_OS: "7",
    PartitionRole.UEFI_NTFS: "ef",
}

_GPT_ROLE_TYPES: Mapping[PartitionRole, str] = {
    PartitionRole.DATA: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    PartitionRole.EFI_SYSTEM: "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
    PartitionRole.PERSISTENCE: "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
    PartitionRole.MICROSOFT_RESERVED: "E3C9E316-0B5C-4DB8-817D-F92DF00215AE",
    PartitionRole.WINDOWS_OS: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    PartitionRole.UEFI_NTFS: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
}

_PARTITION_NAMES: Mapping[PartitionRole, str] = {
    PartitionRole.DATA: "ISOpropyl data",
    PartitionRole.EFI_SYSTEM: "ISOpropyl boot",
    PartitionRole.PERSISTENCE: "ISOpropyl persistence",
    PartitionRole.MICROSOFT_RESERVED: "Microsoft reserved",
    PartitionRole.WINDOWS_OS: "Windows",
    PartitionRole.UEFI_NTFS: "UEFI:NTFS",
}

_MINIMUM_PARTITION_MIB = 1
_MINIMUM_UEFI_NTFS_DATA_MIB = 32
_MAXIMUM_GPT_PARTITIONS = 128
_MAXIMUM_MBR_PARTITIONS = 4
MIB_BYTES = 1024 * 1024
# dosfstools starts FAT12/16 at four sectors per cluster and will grow to at
# most 128 sectors per cluster.  These are formatter capability envelopes, not
# broad OS-compatibility promises: near the maxima, large clusters can reduce
# interoperability.  The whole-device maxima leave at least the leading
# aligned MiB outside the filesystem, keeping a 512-byte-sector FAT12 below
# 4085 clusters and FAT16 below 65525 clusters.  FAT16's lower bound also leaves
# enough clusters on supported 4096-byte-sector media after alignment.
_FAT12_MAX_DEVICE_SIZE = 256 * MIB_BYTES
_FAT16_MIN_DEVICE_SIZE = 128 * MIB_BYTES
_FAT16_MAX_DEVICE_SIZE = 4096 * MIB_BYTES
# FAT32's total-sector field is 32-bit.  Capping the whole drive at 2 TiB
# means the smaller aligned partition remains below UINT32_MAX sectors even
# with the smallest supported 512-byte logical sector.
_FAT32_MAX_DEVICE_SIZE = 2 * 1024**4
# UDF 2.01 addresses at most 2**32 logical blocks.  Capping at the 512-byte
# case is conservative for every logical block size accepted below.
_UDF_MAX_DEVICE_SIZE = 2 * 1024**4
_RESTORE_ONLY_FILESYSTEMS = frozenset({
    Filesystem.FAT12, Filesystem.FAT16, Filesystem.UDF,
})
_PROCESS_TIMEOUT_SECONDS = 30 * 60
_PROCESS_STOP_GRACE_SECONDS = 2
_PROBE_TIMEOUT_SECONDS = 15
_UNMOUNT_TIMEOUT_SECONDS = 30
_MKUDFFS_PREFLIGHT_TIMEOUT_SECONDS = 5
_MKUDFFS_PREFLIGHT_MAX_OUTPUT = 64 * 1024
_MINIMUM_MKUDFFS_VERSION = (1, 1)
_GPT_PARTITION_ENTRY_BYTES = _MAXIMUM_GPT_PARTITIONS * 128
_TRUSTED_TOOL_DIRECTORIES = frozenset(_TRUSTED_TOOL_PATH.split(":"))
_MKUDFFS_VERSION_LINE = re.compile(
    rb"(?m)^mkudffs from udftools ([0-9]+)\.([0-9]+)(?:\.[0-9]+)?\r?$"
)
_FAT_ALLOCATION_UNITS = tuple(1 << power for power in range(9, 17))
_EXFAT_ALLOCATION_UNITS = tuple(1 << power for power in range(9, 26))
_NTFS_ALLOCATION_UNITS = tuple(1 << power for power in range(9, 22))
_EXT_ALLOCATION_UNITS = (1024, 2048, 4096)
_ALLOCATION_UNIT_CHOICES: Mapping[Filesystem, tuple[int, ...]] = {
    Filesystem.FAT12: _FAT_ALLOCATION_UNITS,
    Filesystem.FAT16: _FAT_ALLOCATION_UNITS,
    Filesystem.FAT32: _FAT_ALLOCATION_UNITS,
    Filesystem.EXFAT: _EXFAT_ALLOCATION_UNITS,
    Filesystem.NTFS: _NTFS_ALLOCATION_UNITS,
    Filesystem.EXT2: _EXT_ALLOCATION_UNITS,
    Filesystem.EXT3: _EXT_ALLOCATION_UNITS,
    Filesystem.EXT4: _EXT_ALLOCATION_UNITS,
}
_SUPPORTED_ALLOCATION_LOGICAL_SECTORS = frozenset({512, 1024, 2048, 4096})
_FAT_CLUSTER_LIMITS: Mapping[Filesystem, tuple[int, int]] = {
    Filesystem.FAT12: (16, 4084),
    Filesystem.FAT16: (4087, 65524),
    Filesystem.FAT32: (65525, 268435446),
}
_FAT_ENTRY_BYTES_FOR_TWO_TABLES: Mapping[Filesystem, int] = {
    Filesystem.FAT12: 3,
    Filesystem.FAT16: 4,
    Filesystem.FAT32: 8,
}
_EXFAT_MAX_CLUSTERS = 0xFFFFFFF5
_NTFS_MAX_CLUSTERS = 0xFFFFFFFF
_NTFS_MAX_CLUSTER_SIZE = 2 * MIB_BYTES
_EXT2_3_MAX_BLOCKS = 0xFFFFFFFF
_MBR_MAX_PARTITION_SECTORS = 0xFFFFFFFF


def _partition_belongs_to_device(device_path: str, partition_path: str) -> bool:
    separator = "p" if device_path[-1].isdigit() else ""
    return re.fullmatch(re.escape(device_path) + separator + r"\d+", partition_path) is not None


def _coerce_filesystem(value: Filesystem | str) -> Filesystem:
    try:
        return Filesystem(value)
    except ValueError as error:
        choices = ", ".join(item.value for item in Filesystem)
        raise FormatValidationError(
            f"Unsupported filesystem {value!r}; choose {choices}"
        ) from error


def _coerce_table(value: PartitionTable | str) -> PartitionTable:
    try:
        return PartitionTable(value)
    except ValueError as error:
        choices = ", ".join(item.value for item in PartitionTable)
        raise FormatValidationError(
            f"Unsupported partition table {value!r}; choose {choices}"
        ) from error


def validate_device(device: Device) -> None:
    """Reject anything outside ISOpropyl's removable/external whole-disk model."""
    if not _WHOLE_DISK.fullmatch(device.path):
        raise FormatValidationError(f"Unsafe or unsupported whole-disk path: {device.path!r}")
    if not _MAJOR_MINOR.fullmatch(device.major_minor):
        raise FormatValidationError("The drive has no stable kernel major:minor identity")
    if device.size < _MINIMUM_DEVICE_SIZE:
        raise FormatValidationError("The drive is too small to create a safe aligned partition")
    if device.read_only:
        raise FormatValidationError("The selected drive is read-only")
    if device.transport not in {"usb", "mmc"}:
        raise FormatValidationError("Only USB and SD/MMC drives can be formatted")
    if not device.removable and not (device.transport == "usb" and device.hotplug):
        raise FormatValidationError("The selected drive is not removable or hot-pluggable")
    for path in device.partitions:
        if not _BLOCK_PATH.fullmatch(path) or not _partition_belongs_to_device(device.path, path):
            raise FormatValidationError(f"Unsafe partition path reported for drive: {path!r}")


def validate_label(filesystem: Filesystem | str, label: str) -> str:
    fs = _coerce_filesystem(filesystem)
    if not isinstance(label, str):
        raise FormatValidationError("The volume label must be text")
    if label != label.strip():
        raise FormatValidationError("The volume label cannot start or end with whitespace")
    if any(ord(character) < 32 or ord(character) == 127 for character in label):
        raise FormatValidationError("The volume label cannot contain control characters")
    try:
        utf8 = label.encode("utf-8")
        utf16_units = len(label.encode("utf-16-le")) // 2
    except UnicodeEncodeError as error:
        raise FormatValidationError(
            "The volume label contains an invalid Unicode character"
        ) from error
    if fs in {Filesystem.FAT12, Filesystem.FAT16, Filesystem.FAT32}:
        if not label.isascii():
            raise FormatValidationError(
                f"{fs.value.upper()} labels must contain only ASCII characters"
            )
        if len(label) > 11:
            raise FormatValidationError(
                f"{fs.value.upper()} labels can be at most 11 ASCII characters"
            )
        if label.casefold() == "no name".casefold():
            raise FormatValidationError(
                f"{fs.value.upper()} label NO NAME means no label; leave the field empty instead"
            )
        if any(character in _FAT_FORBIDDEN for character in label):
            raise FormatValidationError(
                f"The {fs.value.upper()} label contains an unsupported character"
            )
    elif fs is Filesystem.EXFAT:
        if utf16_units > 15:
            raise FormatValidationError("exFAT labels can be at most 15 UTF-16 characters")
        if any(character in _WINDOWS_FORBIDDEN for character in label):
            raise FormatValidationError("The exFAT label contains an unsupported character")
    elif fs is Filesystem.NTFS:
        if utf16_units > 32:
            raise FormatValidationError("NTFS labels can be at most 32 UTF-16 characters")
        if any(character in _WINDOWS_FORBIDDEN for character in label):
            raise FormatValidationError("The NTFS label contains an unsupported character")
    elif fs is Filesystem.UDF:
        # --label sets both the 128-byte logical-volume identifier and the
        # narrower 32-byte volume identifier. Its dstring reserves one byte
        # for the OSTA compression ID and one final byte for the encoded
        # length, leaving 30 ASCII bytes or 15 UTF-16 code units.
        limit = 30 if label.isascii() else 15
        length = len(label) if label.isascii() else utf16_units
        if length > limit:
            raise FormatValidationError(
                f"UDF labels can be at most {limit} "
                + ("ASCII characters" if label.isascii() else "UTF-16 characters")
            )
        if any(character in _WINDOWS_FORBIDDEN for character in label):
            raise FormatValidationError("The UDF label contains an unsupported character")
        if any(ord(character) > 0xFFFF for character in label):
            raise FormatValidationError(
                "UDF labels must use Unicode Basic Multilingual Plane characters"
            )
    else:
        if len(utf8) > 16:
            raise FormatValidationError(
                f"{fs.value} labels can be at most 16 UTF-8 bytes"
            )
        if "/" in label:
            raise FormatValidationError(
                f"The {fs.value} label cannot contain a slash"
            )
    return label


def _validate_restore_filesystem_size(filesystem: Filesystem, size: object) -> None:
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise FormatValidationError("The format plan contains an invalid device size")
    if filesystem is Filesystem.FAT12 and size > _FAT12_MAX_DEVICE_SIZE:
        raise FormatValidationError("FAT12 restore formatting is limited to 256 MiB drives")
    if filesystem is Filesystem.FAT16 and not (
        _FAT16_MIN_DEVICE_SIZE <= size <= _FAT16_MAX_DEVICE_SIZE
    ):
        raise FormatValidationError(
            "FAT16 restore formatting requires a drive from 128 MiB through 4 GiB"
        )
    if filesystem is Filesystem.FAT32 and size > _FAT32_MAX_DEVICE_SIZE:
        raise FormatValidationError(
            "FAT32 restore formatting is conservatively limited to 2 TiB drives"
        )
    if filesystem is Filesystem.UDF and size > _UDF_MAX_DEVICE_SIZE:
        raise FormatValidationError(
            "UDF 2.01 restore formatting is conservatively limited to 2 TiB drives"
        )


def restore_filesystem_size_supported(
    filesystem: Filesystem | str,
    size: object,
) -> bool:
    """Return whether *size* fits the same envelope used by format plans.

    This intentionally never raises, so presentation layers can filter choices
    without duplicating destructive-operation policy constants.
    """

    try:
        fs = _coerce_filesystem(filesystem)
        _validate_restore_filesystem_size(fs, size)
    except (TypeError, ValueError):
        return False
    return True


def _validate_allocation_unit_size(
    filesystem: Filesystem,
    allocation_unit_size: object,
) -> None:
    if allocation_unit_size is None:
        return
    if (
        isinstance(allocation_unit_size, bool)
        or not isinstance(allocation_unit_size, int)
        or allocation_unit_size <= 0
    ):
        raise FormatValidationError(
            "The allocation-unit size must be a positive whole number of bytes"
        )
    choices = _ALLOCATION_UNIT_CHOICES.get(filesystem)
    if choices is None:
        if filesystem is Filesystem.UDF:
            raise FormatValidationError(
                "UDF block size is fixed to the target logical sector size"
            )
        raise FormatValidationError(
            f"Explicit allocation-unit sizing is not supported for {filesystem.value}"
        )
    if allocation_unit_size not in choices:
        minimum, maximum = choices[0], choices[-1]
        raise FormatValidationError(
            f"{filesystem.value.upper()} allocation units must be a supported "
            f"power of two from {minimum} through {maximum} bytes"
        )


def _single_partition_capacity_bytes(
    device_size: object,
    partition_table: PartitionTable,
    logical_sector_size: object,
) -> int:
    if (
        isinstance(device_size, bool)
        or not isinstance(device_size, int)
        or device_size <= 0
        or isinstance(logical_sector_size, bool)
        or not isinstance(logical_sector_size, int)
        or logical_sector_size not in _SUPPORTED_ALLOCATION_LOGICAL_SECTORS
        or device_size % logical_sector_size
    ):
        return 0
    total_sectors = device_size // logical_sector_size
    trailing_sectors = (
        1 + (_GPT_PARTITION_ENTRY_BYTES + logical_sector_size - 1)
        // logical_sector_size
        if partition_table is PartitionTable.GPT else 0
    )
    partition_sectors = total_sectors - 2048 - trailing_sectors
    if (
        partition_table is PartitionTable.MBR
        and total_sectors > _MBR_MAX_PARTITION_SECTORS
    ):
        return 0
    return max(0, partition_sectors) * logical_sector_size


def _allocation_unit_geometry_supported(
    filesystem: Filesystem,
    allocation_unit_size: int,
    partition_capacity: int,
    logical_sector_size: int,
) -> bool:
    if (
        logical_sector_size not in _SUPPORTED_ALLOCATION_LOGICAL_SECTORS
        or allocation_unit_size < logical_sector_size
        or allocation_unit_size % logical_sector_size
        or partition_capacity <= 0
    ):
        return False
    if filesystem in _FAT_CLUSTER_LIMITS:
        sectors_per_cluster = allocation_unit_size // logical_sector_size
        if sectors_per_cluster < 1 or sectors_per_cluster > 128:
            return False
        if filesystem in {Filesystem.FAT12, Filesystem.FAT16} and (
            logical_sector_size not in {512, 4096}
        ):
            return False
        minimum, maximum = _FAT_CLUSTER_LIMITS[filesystem]
        raw_cluster_count = partition_capacity // allocation_unit_size
        # Two FATs consume the encoded entry bytes below.  Reserving a further
        # MiB covers boot/reserved sectors, the FAT alignment round-up, and the
        # fixed FAT12/16 root directory, so the lower bound fails conservatively.
        conservative_data_clusters = max(0, partition_capacity - MIB_BYTES) // (
            allocation_unit_size + _FAT_ENTRY_BYTES_FOR_TWO_TABLES[filesystem]
        )
        return (
            raw_cluster_count <= maximum
            and conservative_data_clusters >= minimum
        )
    if filesystem is Filesystem.EXFAT:
        raw_cluster_count = partition_capacity // allocation_unit_size
        conservative_data_clusters = max(
            0, partition_capacity - 2 * MIB_BYTES,
        ) // allocation_unit_size
        return (
            raw_cluster_count <= _EXFAT_MAX_CLUSTERS
            and conservative_data_clusters >= 16
        )
    if filesystem is Filesystem.NTFS:
        raw_cluster_count = partition_capacity // allocation_unit_size
        conservative_data_clusters = max(
            0, partition_capacity - MIB_BYTES,
        ) // allocation_unit_size
        return (
            raw_cluster_count <= _NTFS_MAX_CLUSTERS
            and conservative_data_clusters >= 16
        )
    if filesystem in {Filesystem.EXT2, Filesystem.EXT3, Filesystem.EXT4}:
        blocks = partition_capacity // allocation_unit_size
        # mke2fs rejects a geometry whose block-group descriptor count would
        # overflow 32 bits.  With the normal eight-block-size blocks per
        # group, its source expresses this as 2**(log2(block size) + 35) - 1
        # filesystem blocks.
        descriptor_limit = (
            1 << (allocation_unit_size.bit_length() - 1 + 35)
        ) - 1
        return (
            blocks >= 1024
            and blocks <= descriptor_limit
            and (
                filesystem is Filesystem.EXT4
                or blocks <= _EXT2_3_MAX_BLOCKS
            )
        )
    return False


def _automatic_allocation_geometry_supported(
    filesystem: Filesystem,
    partition_capacity: int,
    logical_sector_size: int,
) -> bool:
    """Conservatively validate the formatter-selected default geometry."""

    if filesystem in {Filesystem.FAT12, Filesystem.FAT16, Filesystem.FAT32}:
        return any(
            _allocation_unit_geometry_supported(
                filesystem, choice, partition_capacity, logical_sector_size,
            )
            for choice in _ALLOCATION_UNIT_CHOICES[filesystem]
        )
    if filesystem is Filesystem.EXFAT:
        # exfatprogs selects one of four exact defaults from the partition
        # capacity and does not continue growing it above 128 KiB.
        default = (
            512 if partition_capacity < 7 * MIB_BYTES else
            4096 if partition_capacity <= 256 * MIB_BYTES else
            32 * 1024 if partition_capacity <= 32 * 1024**3 else
            128 * 1024
        )
        return _allocation_unit_geometry_supported(
            filesystem, default, partition_capacity, logical_sector_size,
        )
    if filesystem is Filesystem.NTFS:
        # Current mkntfs starts at max(4 KiB, sector size), then doubles until
        # the cluster count fits in 32 bits.  Reaching its 2 MiB ceiling in
        # that loop is an error even though an explicit 2 MiB cluster remains
        # legal, so Automatic and explicit geometry must be treated separately.
        default = max(4096, logical_sector_size)
        while partition_capacity >> (default.bit_length() - 1 + 32):
            default <<= 1
            if default >= _NTFS_MAX_CLUSTER_SIZE:
                return False
        return _allocation_unit_geometry_supported(
            filesystem, default, partition_capacity, logical_sector_size,
        )
    if filesystem in {Filesystem.EXT2, Filesystem.EXT3, Filesystem.EXT4}:
        # Distribution mke2fs profiles can influence the automatic block size.
        # Validate against the smallest portable size compatible with the
        # reported sector so every permitted default remains inside both the
        # legacy block-count and block-group descriptor ceilings.
        default = next(
            (
                size for size in _EXT_ALLOCATION_UNITS
                if size >= logical_sector_size and size % logical_sector_size == 0
            ),
            0,
        )
        return bool(
            default
            and _allocation_unit_geometry_supported(
                filesystem, default, partition_capacity, logical_sector_size,
            )
        )
    return filesystem is Filesystem.UDF


def restore_filesystem_geometry_supported(
    filesystem: Filesystem | str,
    device_size: object,
    logical_sector_size: object,
    partition_table: PartitionTable | str = PartitionTable.MBR,
) -> bool:
    """Return whether an automatic restore can safely format this geometry.

    A zero logical-sector hint means discovery did not report one; execution
    still performs the same check before unmounting.  Invalid nonzero values
    fail closed so a GUI can hide choices it already knows cannot execute.
    """

    try:
        fs = _coerce_filesystem(filesystem)
        table = _coerce_table(partition_table)
        _validate_restore_filesystem_size(fs, device_size)
    except (TypeError, ValueError):
        return False
    if logical_sector_size == 0:
        return True
    if (
        isinstance(logical_sector_size, bool)
        or not isinstance(logical_sector_size, int)
        or logical_sector_size not in _SUPPORTED_ALLOCATION_LOGICAL_SECTORS
        or (
            fs in {Filesystem.FAT12, Filesystem.FAT16}
            and logical_sector_size not in {512, 4096}
        )
    ):
        return False
    capacity = _single_partition_capacity_bytes(
        device_size, table, logical_sector_size,
    )
    return bool(
        capacity
        and _automatic_allocation_geometry_supported(
            fs, capacity, logical_sector_size,
        )
    )


def restore_allocation_unit_sizes(
    filesystem: Filesystem | str,
    device_size: object,
    logical_sector_size: object,
    partition_table: PartitionTable | str = PartitionTable.MBR,
) -> tuple[int, ...]:
    """Return safe explicit byte sizes for one restore geometry, or ``()``.

    ``None`` remains the normal formatter-selected default.  This helper is
    intentionally non-throwing so a presentation layer can omit incompatible
    expert choices without duplicating filesystem limits.
    """

    try:
        fs = _coerce_filesystem(filesystem)
        table = _coerce_table(partition_table)
        _validate_restore_filesystem_size(fs, device_size)
    except (TypeError, ValueError):
        return ()
    choices = _ALLOCATION_UNIT_CHOICES.get(fs, ())
    if not choices:
        return ()
    capacity = _single_partition_capacity_bytes(
        device_size, table, logical_sector_size,
    )
    if not capacity or not isinstance(logical_sector_size, int):
        return ()
    return tuple(
        choice for choice in choices
        if _allocation_unit_geometry_supported(
            fs, choice, capacity, logical_sector_size,
        )
    )


def _validate_plan_allocation_geometry(
    plan: FormatPlan,
    logical_sector_size: int,
) -> None:
    allocation_unit_size = plan.allocation_unit_size
    capacity = _single_partition_capacity_bytes(
        plan.device_identity[1], plan.partition_table, logical_sector_size,
    )
    if capacity <= 0:
        if (
            plan.partition_table is PartitionTable.MBR
            and plan.device_identity[1] // logical_sector_size
            > _MBR_MAX_PARTITION_SECTORS
        ):
            raise FormatValidationError(
                "MBR cannot represent one full-capacity partition on this drive; "
                "choose GPT"
            )
        raise FormatValidationError(
            "The selected partition table cannot represent a safe full-capacity "
            "partition on this drive"
        )
    if allocation_unit_size is None:
        if not _automatic_allocation_geometry_supported(
            plan.filesystem, capacity, logical_sector_size,
        ):
            raise FormatValidationError(
                f"{plan.filesystem.value.upper()} formatter defaults are "
                "incompatible with this drive's capacity or logical sector size"
            )
        return
    if not _allocation_unit_geometry_supported(
        plan.filesystem, allocation_unit_size, capacity, logical_sector_size,
    ):
        raise FormatValidationError(
            f"{plan.filesystem.value.upper()} allocation unit "
            f"{allocation_unit_size} bytes is incompatible with this drive's "
            "capacity or logical sector size"
        )


def create_format_plan(
    device: Device,
    filesystem: Filesystem | str,
    partition_table: PartitionTable | str,
    label: str = "",
    allocation_unit_size: int | None = None,
) -> FormatPlan:
    validate_device(device)
    fs = _coerce_filesystem(filesystem)
    table = _coerce_table(partition_table)
    _validate_restore_filesystem_size(fs, device.size)
    _validate_allocation_unit_size(fs, allocation_unit_size)
    return FormatPlan(
        device.path, device.identity, fs, table, validate_label(fs, label),
        allocation_unit_size,
    )


def _validate_partition_spec(
    spec: PartitionSpec,
    table: PartitionTable,
    index: int,
    count: int,
) -> None:
    if not isinstance(spec, PartitionSpec):
        raise FormatValidationError("Every partition must be a PartitionSpec")
    if not isinstance(spec.role, PartitionRole):
        raise FormatValidationError("A partition contains an invalid semantic role")
    if spec.filesystem is not None and not isinstance(spec.filesystem, Filesystem):
        raise FormatValidationError("A partition contains an invalid filesystem")
    if spec.filesystem in _RESTORE_ONLY_FILESYSTEMS:
        raise FormatValidationError(
            f"{spec.filesystem.value.upper()} is supported only by single-partition restore formatting"
        )
    explicit_geometry = (
        spec.start_sector is not None or spec.sector_count is not None
    )
    if (spec.start_sector is None) != (spec.sector_count is None):
        raise FormatValidationError(
            "Explicit partition geometry requires both a start and a sector count"
        )
    if explicit_geometry and spec.size_mib is not None:
        raise FormatValidationError(
            "A partition cannot mix MiB sizing with explicit sector geometry"
        )
    for field_name, value in (
        ("start sector", spec.start_sector),
        ("sector count", spec.sector_count),
    ):
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
        ):
            raise FormatValidationError(
                f"Partition {index + 1} has an invalid {field_name}"
            )
    if spec.size_mib is not None and (
        isinstance(spec.size_mib, bool)
        or not isinstance(spec.size_mib, int)
        or spec.size_mib < _MINIMUM_PARTITION_MIB
    ):
        raise FormatValidationError(
            f"Partition {index + 1} must be at least {_MINIMUM_PARTITION_MIB} MiB"
        )
    if spec.size_mib is None and not explicit_geometry and index != count - 1:
        raise FormatValidationError(
            "Only the final partition may consume the remaining device space"
        )
    if spec.role is PartitionRole.UEFI_NTFS and (
        spec.filesystem is not None
        or spec.size_mib is not None
        or spec.sector_count != 2048
        or spec.label
    ):
        raise FormatValidationError(
            "A UEFI:NTFS partition must be an unformatted, unlabeled 1 MiB raw image target"
        )
    if spec.filesystem is None:
        if spec.label:
            raise FormatValidationError("An unformatted partition cannot have a volume label")
    else:
        validate_label(spec.filesystem, spec.label)
    if spec.role is PartitionRole.DATA and spec.filesystem is None:
        raise FormatValidationError("A data partition requires a filesystem")
    if spec.role is PartitionRole.EFI_SYSTEM and spec.filesystem is not Filesystem.FAT32:
        raise FormatValidationError("An EFI System Partition must use FAT32")
    if spec.role is PartitionRole.PERSISTENCE and spec.filesystem is not Filesystem.EXT4:
        raise FormatValidationError("A persistence partition must use ext4")
    if spec.role is PartitionRole.MICROSOFT_RESERVED:
        if table is not PartitionTable.GPT or spec.filesystem is not None:
            raise FormatValidationError(
                "A Microsoft Reserved Partition must be unformatted and use GPT"
            )
    if spec.role is PartitionRole.WINDOWS_OS and spec.filesystem is not Filesystem.NTFS:
        raise FormatValidationError("A Windows OS partition must use NTFS")
    if spec.bootable and table is not PartitionTable.MBR:
        raise FormatValidationError("The legacy bootable flag is valid only for MBR")


def validate_multi_plan(plan: MultiFormatPlan) -> None:
    if not isinstance(plan, MultiFormatPlan):
        raise FormatValidationError("A MultiFormatPlan is required")
    if not isinstance(plan.partition_table, PartitionTable):
        raise FormatValidationError("The multi-partition plan has an invalid partition table")
    if not _WHOLE_DISK.fullmatch(plan.device_path):
        raise FormatValidationError("The multi-partition plan has an unsafe device path")
    explicit_geometry = any(
        spec.start_sector is not None or spec.sector_count is not None
        for spec in plan.partitions
    )
    if explicit_geometry:
        if plan.logical_sector_size not in {512, 4096}:
            raise FormatValidationError(
                "An explicit layout requires a supported logical sector size"
            )
        if any(
            spec.start_sector is None or spec.sector_count is None
            for spec in plan.partitions
        ):
            raise FormatValidationError(
                "Every partition in an explicit layout requires sector geometry"
            )
    elif plan.logical_sector_size is not None:
        raise FormatValidationError(
            "A logical sector size is valid only with explicit partition geometry"
        )
    limit = (
        _MAXIMUM_MBR_PARTITIONS
        if plan.partition_table is PartitionTable.MBR
        else _MAXIMUM_GPT_PARTITIONS
    )
    if not plan.partitions or len(plan.partitions) > limit:
        raise FormatValidationError(
            f"A {plan.partition_table.value.upper()} plan requires 1 to {limit} partitions"
        )
    seen_singletons: set[PartitionRole] = set()
    for index, spec in enumerate(plan.partitions):
        _validate_partition_spec(spec, plan.partition_table, index, len(plan.partitions))
        if spec.role in {
            PartitionRole.EFI_SYSTEM,
            PartitionRole.MICROSOFT_RESERVED,
            PartitionRole.WINDOWS_OS,
            PartitionRole.UEFI_NTFS,
        }:
            if spec.role in seen_singletons:
                raise FormatValidationError(
                    f"The plan contains more than one {spec.role.value} partition"
                )
            seen_singletons.add(spec.role)
    if explicit_geometry:
        assert plan.logical_sector_size is not None
        total_sectors = plan.device_identity[1] // plan.logical_sector_size
        previous_end = 0
        for spec in plan.partitions:
            assert spec.start_sector is not None and spec.sector_count is not None
            end = spec.start_sector + spec.sector_count
            if spec.start_sector < previous_end or end > total_sectors:
                raise FormatValidationError(
                    "Explicit partition geometry overlaps or exceeds the selected drive"
                )
            previous_end = end
    helper_indexes = [
        index for index, spec in enumerate(plan.partitions)
        if spec.role is PartitionRole.UEFI_NTFS
    ]
    if helper_indexes:
        total_sectors = plan.device_identity[1] // 512
        last_exclusive = (
            total_sectors - 33
            if plan.partition_table is PartitionTable.GPT else total_sectors
        )
        expected_boot_start = ((last_exclusive - 2048) // 2048) * 2048
        expected_data_start = 2048
        expected_data_count = expected_boot_start - expected_data_start
        if (
            len(plan.partitions) != 2
            or helper_indexes != [1]
            or plan.logical_sector_size != 512
            or plan.partitions[0].role is not PartitionRole.DATA
            or plan.partitions[0].filesystem not in {Filesystem.NTFS, Filesystem.EXFAT}
            or plan.partitions[0].start_sector != expected_data_start
            or plan.partitions[0].sector_count != expected_data_count
            or plan.partitions[1].start_sector != expected_boot_start
            or plan.partitions[1].sector_count != 2048
            or expected_data_count < _MINIMUM_UEFI_NTFS_DATA_MIB * 2048
        ):
            raise FormatValidationError(
                "UEFI:NTFS requires one device-sized NTFS/exFAT data partition "
                "followed by the exact 1 MiB raw helper partition"
            )
    if not explicit_geometry:
        fixed_bytes = sum(
            spec.size_mib * MIB_BYTES
            for spec in plan.partitions
            if spec.size_mib is not None
        )
        # Automatic layouts leave the default 1 MiB leading alignment and a
        # final MiB for table metadata/alignment.
        device_size = plan.device_identity[1]
        if fixed_bytes + 2 * MIB_BYTES > device_size:
            raise FormatValidationError("The fixed partitions do not fit on the selected drive")


def create_multi_format_plan(
    device: Device,
    partition_table: PartitionTable | str,
    partitions: Sequence[PartitionSpec],
    *,
    logical_sector_size: int | None = None,
) -> MultiFormatPlan:
    validate_device(device)
    table = _coerce_table(partition_table)
    frozen = tuple(partitions)
    plan = MultiFormatPlan(
        device.path, device.identity, table, frozen, logical_sector_size,
    )
    validate_multi_plan(plan)
    return plan


def create_uefi_ntfs_format_plan(
    device: Device,
    partition_table: PartitionTable | str,
    *,
    filesystem: Filesystem = Filesystem.NTFS,
    label: str = "ISO_DATA",
    bios_bootable: bool = False,
    logical_sector_size: int = 512,
) -> MultiFormatPlan:
    """Create Rufus-compatible data + tail-helper geometry.

    The main partition begins at sfdisk's aligned default (normally 1 MiB).
    Its fixed size leaves one MiB for the raw UEFI:NTFS image and a final MiB
    for alignment/GPT backup metadata.  This avoids guessing where an
    unconstrained first partition ends.
    """
    validate_device(device)
    table = _coerce_table(partition_table)
    if filesystem not in {Filesystem.NTFS, Filesystem.EXFAT}:
        raise FormatValidationError("UEFI:NTFS data must use NTFS or exFAT")
    if bios_bootable and table is not PartitionTable.MBR:
        raise FormatValidationError("Legacy BIOS bootable data requires MBR")
    if logical_sector_size != 512:
        raise FormatValidationError(
            "The pinned UEFI:NTFS image is certified only for 512-byte logical sectors"
        )
    total_sectors = device.size // logical_sector_size
    last_exclusive = (
        total_sectors - 33 if table is PartitionTable.GPT else total_sectors
    )
    boot_start = ((last_exclusive - 2048) // 2048) * 2048
    data_start = 2048
    data_count = boot_start - data_start
    if data_count < _MINIMUM_UEFI_NTFS_DATA_MIB * 2048:
        raise FormatValidationError("The drive is too small for a UEFI:NTFS layout")
    return create_multi_format_plan(device, table, (
        PartitionSpec(
            PartitionRole.DATA, filesystem, label,
            bootable=bios_bootable,
            start_sector=data_start,
            sector_count=data_count,
        ),
        PartitionSpec(
            PartitionRole.UEFI_NTFS, None,
            start_sector=boot_start, sector_count=2048,
        ),
    ), logical_sector_size=logical_sector_size)


def validate_plan(plan: FormatPlan) -> None:
    if not isinstance(plan, FormatPlan):
        raise FormatValidationError("A FormatPlan is required")
    if not isinstance(plan.filesystem, Filesystem):
        raise FormatValidationError("The format plan contains an invalid filesystem")
    if not isinstance(plan.partition_table, PartitionTable):
        raise FormatValidationError("The format plan contains an invalid partition table")
    if not _WHOLE_DISK.fullmatch(plan.device_path):
        raise FormatValidationError("The format plan contains an unsafe device path")
    if (
        not isinstance(plan.device_identity, tuple)
        or len(plan.device_identity) != 6
        or plan.device_identity[0] != plan.device_path
    ):
        raise FormatValidationError("The format plan contains an invalid device identity")
    _validate_restore_filesystem_size(plan.filesystem, plan.device_identity[1])
    validate_label(plan.filesystem, plan.label)
    _validate_allocation_unit_size(plan.filesystem, plan.allocation_unit_size)


def required_tool_names(plan: FormatPlan) -> tuple[str, ...]:
    validate_plan(plan)
    return (
        "pkexec", "udisksctl", "sfdisk", "partprobe", "udevadm", "lsblk",
        _MKFS_NAMES[plan.filesystem],
    )


def _trusted_which(name: str) -> str | None:
    """Never elevate a binary found through the calling user's mutable PATH."""
    return shutil.which(name, path=_TRUSTED_TOOL_PATH)


def resolve_tools(
    plan: FormatPlan,
    which: Callable[[str], str | None] = _trusted_which,
) -> FormatTools:
    resolved: dict[str, str] = {}
    missing: list[str] = []
    for name in required_tool_names(plan):
        path = which(name)
        if not path:
            missing.append(name)
        else:
            resolved[name] = os.path.abspath(path)
    if missing:
        raise MissingFormatToolError(
            "Formatting requires missing system tool" + ("s" if len(missing) != 1 else "")
            + ": " + ", ".join(missing)
        )
    return FormatTools(
        pkexec=resolved["pkexec"], udisksctl=resolved["udisksctl"],
        sfdisk=resolved["sfdisk"], partprobe=resolved["partprobe"],
        udevadm=resolved["udevadm"], lsblk=resolved["lsblk"],
        mkfs=resolved[_MKFS_NAMES[plan.filesystem]],
    )


def required_multi_tool_names(plan: MultiFormatPlan) -> tuple[str, ...]:
    validate_multi_plan(plan)
    base = ("pkexec", "udisksctl", "sfdisk", "partprobe", "udevadm", "lsblk")
    formatters = tuple(dict.fromkeys(
        _MKFS_NAMES[spec.filesystem]
        for spec in plan.partitions
        if spec.filesystem is not None
    ))
    return base + formatters


def resolve_multi_tools(
    plan: MultiFormatPlan,
    which: Callable[[str], str | None] = _trusted_which,
) -> MultiFormatTools:
    resolved: dict[str, str] = {}
    missing: list[str] = []
    for name in required_multi_tool_names(plan):
        path = which(name)
        if not path:
            missing.append(name)
        else:
            resolved[name] = os.path.abspath(path)
    if missing:
        raise MissingFormatToolError(
            "Multi-partition formatting requires missing system tool"
            + ("s" if len(missing) != 1 else "") + ": " + ", ".join(missing)
        )
    filesystems = tuple(dict.fromkeys(
        spec.filesystem for spec in plan.partitions if spec.filesystem is not None
    ))
    return MultiFormatTools(
        pkexec=resolved["pkexec"], udisksctl=resolved["udisksctl"],
        sfdisk=resolved["sfdisk"], partprobe=resolved["partprobe"],
        udevadm=resolved["udevadm"], lsblk=resolved["lsblk"],
        mkfs_tools=tuple((filesystem, resolved[_MKFS_NAMES[filesystem]]) for filesystem in filesystems),
    )


def _single_partition_geometry(
    plan: FormatPlan,
    logical_sector_size: int,
) -> tuple[int, int]:
    """Return the exact start and size used by single-partition restores."""

    capacity = _single_partition_capacity_bytes(
        plan.device_identity[1], plan.partition_table, logical_sector_size,
    )
    if capacity <= 0:
        raise FormatValidationError(
            "The target has no room for the requested partition geometry"
        )
    return 2048, capacity // logical_sector_size


def partition_script(plan: FormatPlan, logical_sector_size: int) -> bytes:
    validate_plan(plan)
    label = "dos" if plan.partition_table is PartitionTable.MBR else "gpt"
    types = _MBR_TYPES if plan.partition_table is PartitionTable.MBR else _GPT_TYPES
    start_sector, sector_count = _single_partition_geometry(
        plan, logical_sector_size,
    )
    # Explicit geometry prevents sfdisk from rounding an otherwise omitted GPT
    # end down to its alignment grain.  Validation reuses the same calculation.
    return (
        f"label: {label}\nunit: sectors\n\n"
        f"start={start_sector}, size={sector_count}, type={types[plan.filesystem]}\n"
    ).encode("ascii")


def _partition_type(spec: PartitionSpec, table: PartitionTable) -> str:
    if table is PartitionTable.GPT:
        if spec.role is PartitionRole.DATA:
            assert spec.filesystem is not None
            return _GPT_TYPES[spec.filesystem]
        return _GPT_ROLE_TYPES[spec.role]
    if spec.role is PartitionRole.DATA:
        assert spec.filesystem is not None
        return _MBR_TYPES[spec.filesystem]
    try:
        return _MBR_ROLE_TYPES[spec.role]
    except KeyError as error:
        raise FormatValidationError(
            f"Partition role {spec.role.value!r} is not supported with MBR"
        ) from error


def multi_partition_script(plan: MultiFormatPlan) -> bytes:
    """Return a complete deterministic sfdisk script for a frozen layout."""
    validate_multi_plan(plan)
    label = "dos" if plan.partition_table is PartitionTable.MBR else "gpt"
    lines = [f"label: {label}"]
    if plan.logical_sector_size is not None:
        lines.extend([
            "unit: sectors",
            f"sector-size: {plan.logical_sector_size}",
        ])
    lines.append("")
    for spec in plan.partitions:
        fields: list[str] = []
        if spec.start_sector is not None:
            assert spec.sector_count is not None
            fields.extend([
                f"start={spec.start_sector}",
                f"size={spec.sector_count}",
            ])
        elif spec.size_mib is not None:
            fields.append(f"size={spec.size_mib}MiB")
        fields.append(f"type={_partition_type(spec, plan.partition_table)}")
        if plan.partition_table is PartitionTable.GPT:
            fields.append(f'name="{_PARTITION_NAMES[spec.role]}"')
            if spec.role is PartitionRole.UEFI_NTFS:
                # Rufus uses GPT attribute bit 63 so operating systems leave
                # the boot helper partition hidden from normal automounting.
                fields.append("attrs=63")
        elif spec.bootable:
            fields.append("bootable")
        lines.append(", ".join(fields))
    return ("\n".join(lines) + "\n").encode("ascii")


def partition_command(plan: FormatPlan, tools: FormatTools) -> list[str]:
    return add_native_sfdisk_lock([
        tools.pkexec, tools.sfdisk, "--wipe", "always", "--wipe-partitions",
        "always", plan.device_path,
    ], tools.sfdisk)


def multi_partition_command(
    plan: MultiFormatPlan, tools: MultiFormatTools,
) -> list[str]:
    validate_multi_plan(plan)
    return add_native_sfdisk_lock([
        tools.pkexec, tools.sfdisk, "--wipe", "always", "--wipe-partitions",
        "always", plan.device_path,
    ], tools.sfdisk)


def _format_command(
    filesystem: Filesystem,
    label: str,
    mkfs: str,
    partition: str,
    allocation_unit_size: int | None = None,
    logical_sector_size: int | None = None,
) -> list[str]:
    command = [mkfs]
    if filesystem in {Filesystem.FAT12, Filesystem.FAT16, Filesystem.FAT32}:
        fat_bits = {
            Filesystem.FAT12: "12",
            Filesystem.FAT16: "16",
            Filesystem.FAT32: "32",
        }[filesystem]
        command.extend(["-F", fat_bits])
        if allocation_unit_size is not None:
            if logical_sector_size is None:
                raise FormatValidationError(
                    "FAT allocation-unit sizing requires a bound logical sector size"
                )
            command.extend([
                "-s", str(allocation_unit_size // logical_sector_size),
            ])
        if label:
            command.extend(["-n", label])
    elif filesystem is Filesystem.EXFAT:
        if allocation_unit_size is not None:
            command.extend(["-c", str(allocation_unit_size)])
        if label:
            command.extend(["-L", label])
    elif filesystem is Filesystem.NTFS:
        command.append("-f")
        if allocation_unit_size is not None:
            command.extend(["-c", str(allocation_unit_size)])
        if label:
            command.extend(["-L", label])
    elif filesystem is Filesystem.UDF:
        # mkudffs option ordering is significant: encoding first, media type
        # before the revision it selects defaults for.  Omitting --blocksize
        # makes mkudffs use and validate the device's logical sector size.
        command.extend([
            "--utf8", "--media-type=hd", "--udfrev=0x0201",
            f"--label={label}",
        ])
    else:
        command.append("-F")
        if allocation_unit_size is not None:
            command.extend(["-b", str(allocation_unit_size)])
        if label:
            command.extend(["-L", label])
    command.append(partition)
    return command


def format_command(
    plan: FormatPlan,
    tools: FormatTools,
    partition: str,
    logical_sector_size: int | None = None,
) -> list[str]:
    validate_plan(plan)
    if (
        not _BLOCK_PATH.fullmatch(partition)
        or not _partition_belongs_to_device(plan.device_path, partition)
    ):
        raise FormatValidationError(f"Unsafe partition path: {partition!r}")
    if plan.allocation_unit_size is not None:
        if logical_sector_size is None:
            raise FormatValidationError(
                "An explicit allocation unit requires a bound logical sector size"
            )
        _validate_plan_allocation_geometry(plan, logical_sector_size)
    return [tools.pkexec, *_format_command(
        plan.filesystem, plan.label, tools.mkfs, partition,
        plan.allocation_unit_size, logical_sector_size,
    )]


def multi_format_commands(
    plan: MultiFormatPlan,
    tools: MultiFormatTools,
    partitions: Sequence[str],
) -> tuple[list[str], ...]:
    validate_multi_plan(plan)
    if len(partitions) != len(plan.partitions):
        raise FormatValidationError(
            "The discovered partition count does not match the frozen layout"
        )
    commands: list[list[str]] = []
    for spec, partition in zip(plan.partitions, partitions, strict=True):
        if (
            not _BLOCK_PATH.fullmatch(partition)
            or not _partition_belongs_to_device(plan.device_path, partition)
        ):
            raise FormatValidationError(f"Unsafe partition path: {partition!r}")
        if spec.filesystem is None:
            continue
        commands.append([tools.pkexec, *_format_command(
            spec.filesystem, spec.label, tools.mkfs_for(spec.filesystem), partition,
        )])
    return tuple(commands)


def parse_partitions(payload: str, device_path: str) -> tuple[str, ...]:
    """Extract partitions descended from a specific whole disk in lsblk JSON."""
    if not _WHOLE_DISK.fullmatch(device_path):
        raise FormatValidationError(f"Unsafe whole-disk path: {device_path!r}")
    try:
        nodes = json.loads(payload).get("blockdevices", [])
    except (AttributeError, TypeError, json.JSONDecodeError) as error:
        raise FormattingError("lsblk returned invalid partition data") from error
    found: list[str] = []

    def visit(node: object, below_target: bool = False) -> None:
        if not isinstance(node, dict):
            return
        path = str(node.get("path") or "")
        is_target = path == device_path and node.get("type") == "disk"
        below = below_target or is_target
        if (
            below and node.get("type") == "part" and _BLOCK_PATH.fullmatch(path)
            and _partition_belongs_to_device(device_path, path)
        ):
            found.append(path)
        for child in node.get("children") or []:
            visit(child, below)

    for node in nodes:
        visit(node)
    prefix = device_path + ("p" if device_path[-1].isdigit() else "")
    unique = dict.fromkeys(found)
    return tuple(sorted(unique, key=lambda path: int(path.removeprefix(prefix))))


def parse_partition_identities(
    payload: str, device_path: str,
) -> tuple[tuple[str, str], ...]:
    """Bind each direct partition path to its kernel major:minor identity."""
    if not _WHOLE_DISK.fullmatch(device_path):
        raise FormatValidationError(f"Unsafe whole-disk path: {device_path!r}")
    try:
        nodes = json.loads(payload).get("blockdevices", [])
    except (AttributeError, TypeError, json.JSONDecodeError) as error:
        raise FormattingError("lsblk returned invalid partition identities") from error
    if (
        not isinstance(nodes, list)
        or len(nodes) != 1
        or not isinstance(nodes[0], dict)
        or nodes[0].get("path") != device_path
        or nodes[0].get("type") != "disk"
    ):
        raise FormattingError("lsblk did not return the selected whole device")
    children = nodes[0].get("children", [])
    if not isinstance(children, list):
        raise FormattingError("lsblk returned invalid partition children")
    prefix = device_path + ("p" if device_path[-1].isdigit() else "")
    found: list[tuple[str, str]] = []
    for child in children:
        if not isinstance(child, dict) or child.get("type") != "part":
            raise FormattingError("lsblk returned a non-partition child")
        path = child.get("path")
        parent = child.get("pkname")
        major_minor = child.get("maj:min")
        if isinstance(parent, str) and parent and not parent.startswith("/dev/"):
            parent = "/dev/" + parent
        if (
            not isinstance(path, str)
            or not _BLOCK_PATH.fullmatch(path)
            or not _partition_belongs_to_device(device_path, path)
            or parent != device_path
            or not isinstance(major_minor, str)
            or not re.fullmatch(r"\d+:\d+", major_minor)
        ):
            raise FormattingError("lsblk returned an unsafe partition identity")
        found.append((path, major_minor))
    paths = [path for path, _identity in found]
    if len(paths) != len(set(paths)):
        raise FormattingError("lsblk returned duplicate partition paths")
    return tuple(sorted(
        found, key=lambda item: int(item[0].removeprefix(prefix)),
    ))


def parse_logical_sector_size(payload: str, device_path: str) -> int:
    """Return one whole device's kernel-reported logical sector size."""
    if not _WHOLE_DISK.fullmatch(device_path):
        raise FormatValidationError(f"Unsafe whole-disk path: {device_path!r}")
    try:
        nodes = json.loads(payload).get("blockdevices", [])
    except (AttributeError, TypeError, json.JSONDecodeError) as error:
        raise FormattingError("lsblk returned invalid logical-sector metadata") from error
    if (
        not isinstance(nodes, list)
        or len(nodes) != 1
        or not isinstance(nodes[0], dict)
        or nodes[0].get("path") != device_path
        or nodes[0].get("type") != "disk"
    ):
        raise FormattingError(
            "lsblk did not uniquely identify the selected whole device"
        )
    value = nodes[0].get("log-sec")
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 256
        or value > 65_536
        or value & (value - 1)
    ):
        raise FormattingError("The target has an invalid logical sector size")
    return value


def _normalized_mbr_type(value: object) -> str:
    rendered = str(value or "").casefold().removeprefix("0x").lstrip("0")
    return rendered or "0"


def _gpt_attribute_bits(value: object) -> set[int] | None:
    if value in {None, ""}:
        return set()
    rendered = str(value)
    if rendered.startswith("GUID:"):
        rendered = rendered.removeprefix("GUID:")
    bits: set[int] = set()
    for token in re.split(r"[ ,]+", rendered):
        if not token:
            continue
        if not token.isdecimal() or not 0 <= int(token) <= 63:
            return None
        bits.add(int(token))
    return bits


def validate_explicit_partition_metadata(
    plan: MultiFormatPlan,
    payload: str,
    partitions: Sequence[str],
) -> None:
    """Validate sfdisk's post-write report against exact frozen geometry."""
    validate_multi_plan(plan)
    if plan.logical_sector_size is None:
        raise FormatValidationError("Exact metadata validation requires explicit geometry")
    if len(partitions) != len(plan.partitions):
        raise FormatValidationError("The reported partition count changed")
    try:
        table = json.loads(payload).get("partitiontable")
    except (AttributeError, TypeError, json.JSONDecodeError) as error:
        raise FormattingError("sfdisk returned invalid partition metadata") from error
    expected_label = "dos" if plan.partition_table is PartitionTable.MBR else "gpt"
    if not isinstance(table, dict) or (
        table.get("label") != expected_label
        or table.get("device") != plan.device_path
        or table.get("unit") != "sectors"
        or table.get("sectorsize") != plan.logical_sector_size
    ):
        raise FormattingError(
            "The partition table identity, type, unit, or logical sector size is unexpected"
        )
    reported = table.get("partitions")
    if not isinstance(reported, list) or len(reported) != len(plan.partitions):
        raise FormattingError("The partition table contains an unexpected child count")
    for index, (spec, expected_path, entry) in enumerate(
        zip(plan.partitions, partitions, reported, strict=True), start=1,
    ):
        if not isinstance(entry, dict):
            raise FormattingError(f"Partition {index} metadata is invalid")
        expected_type = _partition_type(spec, plan.partition_table)
        type_matches = (
            str(entry.get("type") or "").casefold() == expected_type.casefold()
            if plan.partition_table is PartitionTable.GPT
            else _normalized_mbr_type(entry.get("type"))
            == _normalized_mbr_type(expected_type)
        )
        if not (
            entry.get("node") == expected_path
            and entry.get("start") == spec.start_sector
            and entry.get("size") == spec.sector_count
            and type_matches
        ):
            raise FormattingError(
                f"Partition {index} path, geometry, or type differs from the frozen layout"
            )
        if plan.partition_table is PartitionTable.GPT:
            bits = _gpt_attribute_bits(entry.get("attrs"))
            expected_bits = {63} if spec.role is PartitionRole.UEFI_NTFS else set()
            if entry.get("name") != _PARTITION_NAMES[spec.role] or bits != expected_bits:
                raise FormattingError(
                    f"Partition {index} GPT name or attributes differ from the frozen layout"
                )
        elif bool(entry.get("bootable")) is not spec.bootable:
            raise FormattingError(
                f"Partition {index} MBR boot flag differs from the frozen layout"
            )


def validate_single_partition_metadata(
    plan: FormatPlan,
    payload: str,
    partition: str,
    expected_logical_sector_size: int | None = None,
) -> int:
    """Validate the exact full-capacity layout created by ``partition_script``.

    A single-partition restore deliberately has no caller-selectable geometry:
    it starts at LBA 2048 and consumes every usable sector.  Binding that exact
    result prevents a stale or concurrently replaced partition table from being
    accepted merely because one plausible child pathname appeared.
    """

    validate_plan(plan)
    if (
        not isinstance(partition, str)
        or not _BLOCK_PATH.fullmatch(partition)
        or not _partition_belongs_to_device(plan.device_path, partition)
    ):
        raise FormatValidationError("Exact metadata validation requires a safe partition path")
    try:
        table = json.loads(payload).get("partitiontable")
    except (AttributeError, TypeError, json.JSONDecodeError) as error:
        raise FormattingError("sfdisk returned invalid single-partition metadata") from error
    expected_label = "dos" if plan.partition_table is PartitionTable.MBR else "gpt"
    if not isinstance(table, dict) or (
        table.get("label") != expected_label
        or table.get("device") != plan.device_path
        or table.get("unit") != "sectors"
    ):
        raise FormattingError(
            "The partition table identity, type, or unit is unexpected"
        )
    sector_size = table.get("sectorsize")
    if (
        not isinstance(sector_size, int)
        or isinstance(sector_size, bool)
        or sector_size < 256
        or sector_size > 65_536
        or sector_size & (sector_size - 1)
    ):
        raise FormattingError("The partition table reports an invalid logical sector size")
    if (
        expected_logical_sector_size is not None
        and sector_size != expected_logical_sector_size
    ):
        raise DeviceChangedError(
            "The partition table logical sector size differs from the preflight value"
        )
    device_size = plan.device_identity[1]
    if device_size % sector_size:
        raise FormattingError("The target capacity is not an exact logical-sector multiple")
    total_sectors = device_size // sector_size
    start_sector, expected_size = _single_partition_geometry(plan, sector_size)
    trailing_sectors = total_sectors - start_sector - expected_size

    reported = table.get("partitions")
    if not isinstance(reported, list) or len(reported) != 1:
        raise FormattingError("The partition table does not contain exactly one partition")
    entry = reported[0]
    expected_type = (
        _MBR_TYPES if plan.partition_table is PartitionTable.MBR else _GPT_TYPES
    )[plan.filesystem]
    if not isinstance(entry, dict):
        raise FormattingError("The partition metadata is invalid")
    type_matches = (
        str(entry.get("type") or "").casefold() == expected_type.casefold()
        if plan.partition_table is PartitionTable.GPT
        else _normalized_mbr_type(entry.get("type"))
        == _normalized_mbr_type(expected_type)
    )
    if not (
        entry.get("node") == partition
        and entry.get("start") == start_sector
        and entry.get("size") == expected_size
        and type_matches
    ):
        raise FormattingError(
            "The single partition path, start, size, or type differs from the frozen layout"
        )
    if plan.partition_table is PartitionTable.GPT:
        expected_last_lba = total_sectors - trailing_sectors - 1
        reported_last_lba = table.get("lastlba")
        if reported_last_lba is not None and reported_last_lba != expected_last_lba:
            raise FormattingError("The GPT usable-sector boundary is unexpected")
    return sector_size


def _read_bounded_probe_output(
    stream: object,
    sink: bytearray,
    limit: int,
    overflow: threading.Event,
) -> None:
    """Drain one child pipe while retaining no more than ``limit + 1`` bytes."""

    try:
        while True:
            block = stream.read(16 * 1024)  # type: ignore[attr-defined]
            if not block:
                return
            remaining = max(0, limit + 1 - len(sink))
            if remaining:
                sink.extend(block[:remaining])
            if len(sink) > limit:
                overflow.set()
    finally:
        stream.close()  # type: ignore[attr-defined]


def _stop_bounded_probe(
    process: subprocess.Popen[bytes],
    grace_seconds: float,
) -> None:
    if process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            return
    try:
        process.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        process.kill()
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired as error:
        raise FormattingError(
            "The mkudffs capability inspection did not stop after termination and kill"
        ) from error


def _capture_mkudffs_help(
    mkudffs: str,
    *,
    popen: Callable[..., subprocess.Popen[bytes]],
    cancel_event: threading.Event,
    timeout_seconds: float,
    max_output: int = _MKUDFFS_PREFLIGHT_MAX_OUTPUT,
) -> tuple[int, bytes]:
    """Return bounded ``mkudffs --help`` output without touching a device."""

    normalized = os.path.normpath(mkudffs) if isinstance(mkudffs, str) else ""
    if (
        not isinstance(mkudffs, str)
        or not os.path.isabs(mkudffs)
        or normalized != mkudffs
        or os.path.dirname(mkudffs) not in _TRUSTED_TOOL_DIRECTORIES
        or os.path.basename(mkudffs) != "mkudffs"
    ):
        raise MissingFormatToolError(f"Refusing untrusted mkudffs path: {mkudffs!r}")
    if cancel_event.is_set():
        raise FormatCancelled("Formatting was cancelled")
    try:
        process = popen(
            [mkudffs, "--help"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
        )
    except OSError as error:
        raise MissingFormatToolError(
            "Could not start mkudffs capability inspection"
        ) from error
    if process.stdout is None:
        _stop_bounded_probe(process, _PROCESS_STOP_GRACE_SECONDS)
        raise FormattingError("Could not capture mkudffs capability output")

    output = bytearray()
    overflow = threading.Event()
    reader = threading.Thread(
        target=_read_bounded_probe_output,
        args=(process.stdout, output, max_output, overflow),
        daemon=True,
    )
    reader.start()
    deadline = time.monotonic() + timeout_seconds
    failure: FormattingError | None = None
    while process.poll() is None:
        if cancel_event.is_set():
            failure = FormatCancelled("Formatting was cancelled")
            break
        if overflow.is_set():
            failure = FormattingError(
                "mkudffs capability inspection produced too much output"
            )
            break
        if time.monotonic() >= deadline:
            failure = FormattingError("mkudffs capability inspection timed out")
            break
        cancel_event.wait(0.01)

    if failure is not None:
        _stop_bounded_probe(process, _PROCESS_STOP_GRACE_SECONDS)
    reader.join(timeout=_PROCESS_STOP_GRACE_SECONDS)
    if reader.is_alive():
        _stop_bounded_probe(process, _PROCESS_STOP_GRACE_SECONDS)
        raise FormattingError("Could not finish reading mkudffs capability output")
    if overflow.is_set() and failure is None:
        failure = FormattingError(
            "mkudffs capability inspection produced too much output"
        )
    if cancel_event.is_set():
        failure = FormatCancelled("Formatting was cancelled")
    if failure is not None:
        raise failure
    return process.returncode or 0, bytes(output)


def _validate_mkudffs_help(returncode: int, payload: bytes) -> tuple[int, int]:
    """Require the upstream version whose label and sector defaults we use."""

    # Upstream mkudffs intentionally returns 1 for --help; some downstream
    # builds use the more conventional 0.  No other status is accepted.
    if returncode not in {0, 1}:
        raise MissingFormatToolError("mkudffs capability inspection failed")
    matches = _MKUDFFS_VERSION_LINE.findall(payload)
    if len(matches) != 1 or b"--label=" not in payload:
        raise MissingFormatToolError(
            "Could not verify mkudffs version and --label support"
        )
    version = tuple(int(value) for value in matches[0])
    if version < _MINIMUM_MKUDFFS_VERSION:
        raise MissingFormatToolError(
            "UDF restore requires mkudffs 1.1 or newer for --label and "
            "logical-sector block-size detection"
        )
    return version


class FormatExecutor:
    """Execute a FormatPlan without ever passing user data through a shell."""

    def __init__(
        self,
        *,
        device_lookup: DeviceLookup | None = None,
        which: Callable[[str], str | None] = _trusted_which,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        preflight_popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        lstat_func: Callable[[str], os.stat_result] = os.lstat,
        sleep: Callable[[float], None] = time.sleep,
        discovery_attempts: int = 20,
        discovery_interval: float = 0.25,
        process_timeout: float = _PROCESS_TIMEOUT_SECONDS,
        stop_grace: float = _PROCESS_STOP_GRACE_SECONDS,
        mkudffs_preflight_timeout: float = _MKUDFFS_PREFLIGHT_TIMEOUT_SECONDS,
    ) -> None:
        if (
            isinstance(mkudffs_preflight_timeout, bool)
            or not isinstance(mkudffs_preflight_timeout, (int, float))
            or not 0 < mkudffs_preflight_timeout <= 60
        ):
            raise FormatValidationError(
                "The mkudffs preflight timeout must be between 0 and 60 seconds"
            )
        self._device_lookup = device_lookup
        self._which = which
        self._popen = popen
        self._preflight_popen = preflight_popen
        self._runner = runner
        self._lstat = lstat_func
        self._sleep = sleep
        self._discovery_attempts = max(1, discovery_attempts)
        self._discovery_interval = max(0.0, discovery_interval)
        self._process_timeout = max(0.01, process_timeout)
        self._stop_grace = max(0.1, stop_grace)
        self._mkudffs_preflight_timeout = float(mkudffs_preflight_timeout)
        self._cancelled = threading.Event()
        self._process: subprocess.Popen[bytes] | None = None

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        self._cancelled.set()
        process = self._process
        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass

    def _check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise FormatCancelled("Formatting was cancelled")

    def _run_probe(
        self,
        argv: Sequence[str],
        *,
        purpose: str,
        timeout: float = _PROBE_TIMEOUT_SECONDS,
    ) -> subprocess.CompletedProcess[str]:
        """Run a bounded, non-streaming probe and normalize timeout/cancel."""

        self._check_cancelled()
        try:
            result = self._runner(
                list(argv), capture_output=True, text=True,
                timeout=timeout, shell=False,
            )
        except subprocess.TimeoutExpired as error:
            if self._cancelled.is_set():
                raise FormatCancelled("Formatting was cancelled") from error
            raise FormattingError(f"{purpose} timed out") from error
        self._check_cancelled()
        return result

    def _lookup_device(self, path: str, tools: FormatTools) -> Device | None:
        if self._device_lookup is not None:
            return self._device_lookup(path)
        fields = "PATH,SIZE,TYPE,RM,HOTPLUG,TRAN,MODEL,VENDOR,SERIAL,WWN,MAJ:MIN,MOUNTPOINTS,RO"
        result = self._run_probe(
            [tools.lsblk, "--tree", "--bytes", "--json", "--output", fields, path],
            purpose="Target identity inspection",
        )
        if result.returncode:
            return None
        try:
            devices = parse_lsblk(result.stdout, include_usb_hdds=True)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None
        return next((device for device in devices if device.path == path), None)

    def _assert_identity(self, plan: FormatPlan, tools: FormatTools) -> Device:
        self._check_cancelled()
        current = self._lookup_device(plan.device_path, tools)
        if current is None:
            raise DeviceChangedError("The selected drive is no longer connected")
        validate_device(current)
        if current.identity != plan.device_identity:
            raise DeviceChangedError(
                "The drive at the selected path changed; formatting was stopped"
            )
        return current

    def _assert_restore_filesystem_geometry(
        self,
        plan: FormatPlan,
        tools: FormatTools,
        expected_logical_sector_size: int | None = None,
    ) -> int:
        """Bind geometry needed by constrained restore filesystem plans."""
        self._check_cancelled()
        result = self._run_probe(
            [
                tools.lsblk, "--bytes", "--json", "--nodeps", "--output",
                "PATH,TYPE,LOG-SEC", plan.device_path,
            ],
            purpose="Target logical-sector inspection",
        )
        if result.returncode:
            message = ((result.stdout or "") + (result.stderr or "")).strip()
            raise FormattingError(
                message or "Could not read the target logical sector size"
            )
        observed = parse_logical_sector_size(result.stdout, plan.device_path)
        if expected_logical_sector_size is not None and (
            observed != expected_logical_sector_size
        ):
            raise DeviceChangedError(
                "The target logical sector size changed during formatting"
            )
        if plan.filesystem in {Filesystem.FAT12, Filesystem.FAT16}:
            if observed not in {512, 4096}:
                raise FormatValidationError(
                    "FAT12/16 restore formatting supports only 512- or "
                    "4096-byte logical sectors"
                )
        elif observed not in _SUPPORTED_ALLOCATION_LOGICAL_SECTORS:
            if plan.filesystem is Filesystem.UDF:
                raise FormatValidationError(
                    "UDF requires a power-of-two logical sector size from 512 "
                    "through 4096 bytes"
                )
            raise FormatValidationError(
                f"{plan.filesystem.value.upper()} restore formatting supports "
                "logical sector sizes "
                "from 512 through 4096 bytes"
            )
        _validate_plan_allocation_geometry(plan, observed)
        return observed

    def _preflight_udf_formatter(
        self,
        plan: FormatPlan,
        tools: FormatTools,
    ) -> None:
        if plan.filesystem is not Filesystem.UDF:
            return
        returncode, payload = _capture_mkudffs_help(
            tools.mkfs,
            popen=self._preflight_popen,
            cancel_event=self._cancelled,
            timeout_seconds=self._mkudffs_preflight_timeout,
        )
        self._check_cancelled()
        _validate_mkudffs_help(returncode, payload)

    def _stop_process(self, process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            try:
                process.terminate()
            except ProcessLookupError:
                return
        try:
            process.communicate(timeout=self._stop_grace)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            process.kill()
        except ProcessLookupError:
            return
        try:
            process.communicate(timeout=self._stop_grace)
        except subprocess.TimeoutExpired as error:
            raise FormattingError(
                "A formatting child did not stop after termination and kill"
            ) from error

    def _run_process(self, argv: Sequence[str], input_data: bytes | None = None) -> None:
        self._check_cancelled()
        process = self._popen(
            list(argv), stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
        )
        self._process = process
        first = True
        deadline = time.monotonic() + self._process_timeout
        try:
            while True:
                try:
                    _stdout, stderr = process.communicate(
                        input=input_data if first else None, timeout=0.2,
                    )
                    break
                except subprocess.TimeoutExpired:
                    first = False
                    if self._cancelled.is_set():
                        self._stop_process(process)
                        raise FormatCancelled("Formatting was cancelled")
                    if time.monotonic() >= deadline:
                        self._stop_process(process)
                        raise FormattingError("A formatting child timed out")
            self._check_cancelled()
            if process.returncode:
                message = stderr.decode(errors="replace").strip()
                fallback = message or f"Command failed: {argv[1]}"
                if is_cooperative_lock_command(argv):
                    fallback = lock_conflict_message(process.returncode, fallback)
                raise FormattingError(
                    fallback
                )
        finally:
            self._process = None
        self._check_cancelled()

    def _resolve_flock(self) -> str:
        try:
            return resolve_flock(self._which)
        except CooperativeLockError as error:
            raise MissingFormatToolError(str(error)) from error

    @staticmethod
    def _locked_format_command(
        command: Sequence[str],
        tools: FormatTools | MultiFormatTools,
        flock: str,
        whole_device: str,
    ) -> list[str]:
        if not command or command[0] != tools.pkexec:
            raise FormattingError("The filesystem command lost its privilege binding")
        try:
            return cooperative_lock_command(
                tools.pkexec, flock, whole_device, command[1:],
            )
        except CooperativeLockError as error:
            raise FormattingError(str(error)) from error

    def _observe_partition_nodes(
        self,
        plan: FormatPlan | MultiFormatPlan,
        tools: FormatTools | MultiFormatTools,
        partitions: Sequence[str],
    ) -> tuple[tuple[str, str], ...]:
        """Bind direct child paths to both kernel and device-node identities."""

        result = self._run_probe(
            [
                tools.lsblk, "--json", "--paths", "--tree", "--output",
                "PATH,TYPE,PKNAME,MAJ:MIN", plan.device_path,
            ],
            purpose="Partition identity inspection",
        )
        if result.returncode:
            message = ((result.stdout or "") + (result.stderr or "")).strip()
            raise FormattingError(
                message or "Could not bind the new partition device identities"
            )
        observed = parse_partition_identities(result.stdout, plan.device_path)
        if tuple(path for path, _identity in observed) != tuple(partitions):
            raise DeviceChangedError("The partition device paths changed after discovery")
        for path, major_minor in observed:
            try:
                info = self._lstat(path)
            except OSError as error:
                raise DeviceChangedError(
                    f"The partition device node disappeared: {path}"
                ) from error
            if (
                not stat.S_ISBLK(info.st_mode)
                or f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}" != major_minor
            ):
                raise DeviceChangedError(
                    f"The partition device node identity changed: {path}"
                )
        return observed

    def _verify_partition_nodes(
        self,
        plan: FormatPlan | MultiFormatPlan,
        tools: FormatTools | MultiFormatTools,
        partitions: Sequence[str],
        expected: tuple[tuple[str, str], ...],
    ) -> None:
        if self._observe_partition_nodes(plan, tools, partitions) != expected:
            raise DeviceChangedError(
                "A partition device identity changed before filesystem creation"
            )

    def _verify_single_geometry(
        self,
        plan: FormatPlan,
        tools: FormatTools,
        partition: str,
        expected_logical_sector_size: int | None,
    ) -> int:
        result = self._run_probe(
            [tools.pkexec, tools.sfdisk, "--json", plan.device_path],
            purpose="Exact single-partition geometry validation",
        )
        if result.returncode:
            message = ((result.stdout or "") + (result.stderr or "")).strip()
            raise FormattingError(
                message or "Could not validate the exact partition geometry"
            )
        return validate_single_partition_metadata(
            plan, result.stdout, partition, expected_logical_sector_size,
        )

    def _unmount(self, device: Device, tools: FormatTools) -> bool:
        normalized_nonzero = False
        targets = device.partitions or ((device.path,) if device.mountpoints else ())
        for target in targets:
            self._check_cancelled()
            try:
                result = self._run_probe(
                    [tools.udisksctl, "unmount", "--block-device", target],
                    purpose=f"Unmounting {target}",
                    timeout=_UNMOUNT_TIMEOUT_SECONDS,
                )
            except FormatCancelled:
                raise
            except (FormattingError, OSError, subprocess.SubprocessError) as error:
                raise FormattingError(
                    str(error or f"Could not unmount {target}")
                    + conflict_diagnostic_suffix(target)
                ) from error
            combined = ((result.stdout or "") + (result.stderr or "")).strip()
            if result.returncode:
                if not unmount_response_is_inactive(combined):
                    message = combined or f"Could not unmount {target}"
                    raise FormattingError(
                        message + conflict_diagnostic_suffix(target)
                    )
                normalized_nonzero = True
        return normalized_nonzero

    def _discover_partition(self, plan: FormatPlan, tools: FormatTools) -> str:
        for attempt in range(self._discovery_attempts):
            self._check_cancelled()
            result = self._run_probe(
                [
                    tools.lsblk, "--json", "--paths", "--tree", "--output",
                    "PATH,TYPE",
                    plan.device_path,
                ],
                purpose="New partition discovery",
            )
            if result.returncode:
                message = ((result.stdout or "") + (result.stderr or "")).strip()
                raise FormattingError(message or "Could not inspect the new partition")
            partitions = parse_partitions(result.stdout, plan.device_path)
            if len(partitions) == 1:
                return partitions[0]
            if len(partitions) > 1:
                raise FormattingError(
                    "Partitioning returned more than one partition; refusing to choose a target"
                )
            if attempt + 1 < self._discovery_attempts:
                self._sleep(self._discovery_interval)
        raise FormattingError("The new partition did not appear")

    def execute(
        self,
        device: Device,
        plan: FormatPlan,
        stage: StageCallback | None = None,
    ) -> str:
        """Restore a drive to one empty partition and return its partition path."""
        validate_device(device)
        validate_plan(plan)
        if device.path != plan.device_path or device.identity != plan.device_identity:
            raise DeviceChangedError("The format plan does not belong to the selected drive")
        validate_label(plan.filesystem, plan.label)
        tools = resolve_tools(plan, self._which)  # Preflight before touching the drive.
        flock = self._resolve_flock()
        self._preflight_udf_formatter(plan, tools)
        report = stage or (lambda _message: None)

        current = self._assert_identity(plan, tools)
        logical_sector_size = self._assert_restore_filesystem_geometry(plan, tools)
        report("Unmounting")
        normalized_unmount = self._unmount(current, tools)
        current = self._assert_identity(plan, tools)
        if normalized_unmount and current.mountpoints:
            raise FormattingError(
                "The target still reports mounted filesystems after unmounting"
            )
        self._assert_restore_filesystem_geometry(
            plan, tools, logical_sector_size,
        )

        report("Creating partition table")
        self._run_process(
            partition_command(plan, tools),
            partition_script(plan, logical_sector_size),
        )
        self._run_process([tools.pkexec, tools.partprobe, plan.device_path])
        self._run_process([tools.udevadm, "settle"])

        report("Waiting for partition")
        partition = self._discover_partition(plan, tools)
        self._assert_identity(plan, tools)
        self._assert_restore_filesystem_geometry(
            plan, tools, logical_sector_size,
        )
        bound_table_sector_size = self._verify_single_geometry(
            plan, tools, partition, logical_sector_size,
        )
        partition_identities = self._observe_partition_nodes(
            plan, tools, (partition,),
        )

        report("Creating filesystem")
        self._assert_identity(plan, tools)
        self._assert_restore_filesystem_geometry(
            plan, tools, logical_sector_size,
        )
        self._verify_single_geometry(
            plan, tools, partition, bound_table_sector_size,
        )
        self._assert_identity(plan, tools)
        self._verify_partition_nodes(
            plan, tools, (partition,), partition_identities,
        )
        self._run_process(self._locked_format_command(
            format_command(
                plan, tools, partition, bound_table_sector_size,
            ), tools, flock, plan.device_path,
        ))
        self._run_process([tools.udevadm, "settle"])
        self._assert_identity(plan, tools)
        self._verify_single_geometry(
            plan, tools, partition, bound_table_sector_size,
        )
        self._verify_partition_nodes(
            plan, tools, (partition,), partition_identities,
        )
        report("Complete")
        return partition


class MultiFormatExecutor(FormatExecutor):
    """Execute an immutable multi-partition layout without guessing children."""

    def _discover_partitions(
        self,
        plan: MultiFormatPlan,
        tools: MultiFormatTools,
    ) -> tuple[str, ...]:
        expected_count = len(plan.partitions)
        for attempt in range(self._discovery_attempts):
            result = self._run_probe(
                [
                    tools.lsblk, "--json", "--paths", "--tree", "--output",
                    "PATH,TYPE",
                    plan.device_path,
                ],
                purpose="New partition discovery",
            )
            if result.returncode:
                message = ((result.stdout or "") + (result.stderr or "")).strip()
                raise FormattingError(message or "Could not inspect the new partitions")
            partitions = parse_partitions(result.stdout, plan.device_path)
            if len(partitions) == expected_count:
                return partitions
            if len(partitions) > expected_count:
                raise FormattingError(
                    "Partitioning returned more children than the frozen layout"
                )
            if attempt + 1 < self._discovery_attempts:
                self._sleep(self._discovery_interval)
        raise FormattingError(
            f"Expected {expected_count} new partitions, but they did not all appear"
        )

    def _verify_explicit_geometry(
        self,
        plan: MultiFormatPlan,
        tools: MultiFormatTools,
        partitions: Sequence[str],
    ) -> None:
        if plan.logical_sector_size is None:
            return
        result = self._run_probe(
            [tools.pkexec, tools.sfdisk, "--json", plan.device_path],
            purpose="Exact partition geometry validation",
        )
        if result.returncode:
            message = ((result.stdout or "") + (result.stderr or "")).strip()
            raise FormattingError(
                message or "Could not validate the exact partition geometry"
            )
        validate_explicit_partition_metadata(plan, result.stdout, partitions)

    def _assert_logical_sector_size(
        self,
        plan: MultiFormatPlan,
        tools: MultiFormatTools,
    ) -> None:
        if plan.logical_sector_size is None:
            return
        result = self._run_probe(
            [
                tools.lsblk, "--bytes", "--json", "--nodeps", "--output",
                "PATH,TYPE,LOG-SEC", plan.device_path,
            ],
            purpose="Target logical-sector inspection",
        )
        if result.returncode:
            message = ((result.stdout or "") + (result.stderr or "")).strip()
            raise FormattingError(
                message or "Could not read the target logical sector size"
            )
        observed = parse_logical_sector_size(result.stdout, plan.device_path)
        if observed != plan.logical_sector_size:
            raise DeviceChangedError(
                f"The target uses {observed}-byte logical sectors, but the frozen "
                f"layout requires {plan.logical_sector_size}-byte sectors"
            )

    def execute_multi(
        self,
        device: Device,
        plan: MultiFormatPlan,
        stage: StageCallback | None = None,
    ) -> tuple[str, ...]:
        """Create, format, and return every partition in canonical number order."""
        validate_device(device)
        validate_multi_plan(plan)
        if device.path != plan.device_path or device.identity != plan.device_identity:
            raise DeviceChangedError(
                "The multi-partition plan does not belong to the selected drive"
            )
        tools = resolve_multi_tools(plan, self._which)  # Preflight before device access.
        flock = self._resolve_flock()
        report = stage or (lambda _message: None)

        current = self._assert_identity(plan, tools)  # type: ignore[arg-type]
        # util-linux can rescale an sfdisk script whose declared sector size
        # differs from the kernel device. Observe and bind it before unmounting.
        self._assert_logical_sector_size(plan, tools)
        report("Unmounting")
        normalized_unmount = self._unmount(current, tools)  # type: ignore[arg-type]
        current = self._assert_identity(plan, tools)  # type: ignore[arg-type]
        if normalized_unmount and current.mountpoints:
            raise FormattingError(
                "The target still reports mounted filesystems after unmounting"
            )
        self._assert_logical_sector_size(plan, tools)

        report("Creating partition table")
        self._run_process(
            multi_partition_command(plan, tools), multi_partition_script(plan),
        )
        self._run_process([tools.pkexec, tools.partprobe, plan.device_path])
        self._run_process([tools.udevadm, "settle"])

        report("Waiting for partitions")
        partitions = self._discover_partitions(plan, tools)
        self._assert_identity(plan, tools)  # type: ignore[arg-type]
        self._verify_explicit_geometry(plan, tools, partitions)
        self._assert_identity(plan, tools)  # type: ignore[arg-type]
        partition_identities = self._observe_partition_nodes(
            plan, tools, partitions,
        )

        commands = multi_format_commands(plan, tools, partitions)
        if commands:
            report("Creating filesystems")
        for command in commands:
            self._assert_identity(plan, tools)  # type: ignore[arg-type]
            self._verify_explicit_geometry(plan, tools, partitions)
            self._verify_partition_nodes(
                plan, tools, partitions, partition_identities,
            )
            self._run_process(self._locked_format_command(
                command, tools, flock, plan.device_path,
            ))
        self._run_process([tools.udevadm, "settle"])
        self._assert_identity(plan, tools)  # type: ignore[arg-type]
        self._verify_explicit_geometry(plan, tools, partitions)
        self._verify_partition_nodes(
            plan, tools, partitions, partition_identities,
        )
        report("Complete")
        return partitions
