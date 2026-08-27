from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bounded, read-only MBR and GPT inspection.

The parser never searches arbitrary offsets.  It considers only 512- and
4096-byte logical sectors, caps GPT metadata, and reads through one caller-
owned descriptor (or a bounded prefix/tail capture for streamed sources).
"""

import os
import stat
import struct
import zlib
from dataclasses import dataclass
from typing import Protocol


LOGICAL_SECTOR_SIZES = (512, 4096)
MAX_GPT_ENTRIES = 16_384
MAX_GPT_ENTRY_SIZE = 4096
MAX_GPT_ARRAY_BYTES = 16 * 1024 * 1024
MIN_GPT_ARRAY_RESERVATION_BYTES = 16 * 1024
MAX_EBR_PARTITIONS = 256
# Enough for a header, a maximally accepted entry array, and alignment at
# either supported logical-sector size.
PARTITION_TABLE_CAPTURE_BYTES = MAX_GPT_ARRAY_BYTES + (3 * max(LOGICAL_SECTOR_SIZES))

_GPT_SIGNATURE = b"EFI PART"
_GPT_REVISION_1_0 = 0x00010000
_GPT_HEADER = struct.Struct("<8sIIIIQQQQ16sQIII")
_MBR_ENTRY = struct.Struct("<B3sB3sII")
_UINT32_MAX = (1 << 32) - 1
_EXTENDED_MBR_TYPES = frozenset({0x05, 0x0F, 0x85})
_GPT_UNDEFINED_ATTRIBUTE_MASK = ((1 << 48) - 1) & ~0x7
_CHS_HEADS = 255
_CHS_SECTORS = 63
_MAX_CHS_LBA = (1024 * _CHS_HEADS * _CHS_SECTORS) - 1

FileIdentity = tuple[int, int, int, int]


class PartitionTableError(RuntimeError):
    """The image could not be read consistently for partition inspection."""


class _UnavailableRange(PartitionTableError):
    pass


class _Reader(Protocol):
    size: int

    def read_at(self, offset: int, length: int) -> bytes: ...


@dataclass(frozen=True)
class PartitionTableInspection:
    has_mbr: bool
    has_gpt: bool
    valid: bool
    malformed: bool
    kind: str
    sector_size: int
    mbr_kind: str
    mbr_boot_code: str
    issues: tuple[str, ...]
    complete: bool = True


@dataclass(frozen=True)
class _MbrInspection:
    valid: bool
    kind: str
    boot_code: str
    entries: tuple[tuple[int, int, int, int], ...]
    issues: tuple[str, ...]


@dataclass(frozen=True)
class _GptHeader:
    revision: int
    header_size: int
    current_lba: int
    backup_lba: int
    first_usable_lba: int
    last_usable_lba: int
    disk_guid: bytes
    entry_lba: int
    entry_count: int
    entry_size: int
    entry_crc32: int


@dataclass(frozen=True)
class _GptCandidate:
    valid: bool
    sector_size: int
    mbr: _MbrInspection
    issues: tuple[str, ...]


class _FdReader:
    def __init__(self, descriptor: int, size: int) -> None:
        self._descriptor = descriptor
        self.size = size

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset > self.size or length > self.size - offset:
            return b""
        try:
            return os.pread(self._descriptor, length, offset)
        except OSError as error:
            raise PartitionTableError(
                "Could not read partition-table metadata"
            ) from error


class _CapturedReader:
    def __init__(self, prefix: bytes, tail: bytes, size: int) -> None:
        self._prefix = prefix
        self._tail = tail
        self.size = size
        self._tail_start = size - len(tail)

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset > self.size or length > self.size - offset:
            return b""
        end = offset + length
        if end <= len(self._prefix):
            return self._prefix[offset:end]
        if offset >= self._tail_start:
            start = offset - self._tail_start
            return self._tail[start:start + length]
        raise _UnavailableRange(
            "Partition metadata lies outside the bounded streamed-image capture"
        )


def _identity(status: os.stat_result) -> FileIdentity:
    return status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns


def _bound_identity(status: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        status.st_dev, status.st_ino, status.st_size,
        status.st_mtime_ns, status.st_ctime_ns,
    )


def _read_exact(reader: _Reader, offset: int, length: int, label: str) -> bytes:
    try:
        value = reader.read_at(offset, length)
    except _UnavailableRange as error:
        raise _UnavailableRange(f"{label}: {error}") from error
    if len(value) != length:
        raise PartitionTableError(f"{label} is truncated")
    return value


def _classify_boot_code(sector: bytes) -> str:
    code = sector[:440]
    if not any(code):
        return "empty"
    lowered = code.lower()
    if b"isolinux" in lowered or b"syslinux" in lowered:
        return "syslinux"
    if b"grub" in lowered:
        return "grub"
    if (
        b"invalid partition table" in lowered
        and b"missing operating system" in lowered
    ):
        return "windows"
    return "unrecognized"


def _lba_to_chs(lba: int) -> bytes:
    """Encode an LBA using the conventional 255-head, 63-sector geometry."""

    if lba < 0 or lba > _MAX_CHS_LBA:
        return b"\xff\xff\xff"
    cylinder, track_offset = divmod(lba, _CHS_HEADS * _CHS_SECTORS)
    head, sector_offset = divmod(track_offset, _CHS_SECTORS)
    sector = sector_offset + 1
    return bytes((
        head,
        sector | ((cylinder >> 2) & 0xC0),
        cylinder & 0xFF,
    ))


def _valid_gpt_entry_size(value: int) -> bool:
    if value < 128 or value > MAX_GPT_ENTRY_SIZE or value % 128:
        return False
    factor = value // 128
    return factor & (factor - 1) == 0


def _validate_ebr_chain(
    reader: _Reader,
    sector_size: int,
    container_start: int,
    container_end: int,
) -> tuple[str, ...]:
    """Validate one bounded DOS extended-partition chain."""

    issues: list[str] = []
    visited: set[int] = set()
    ebr_lbas: list[int] = []
    logical: list[tuple[int, int, int]] = []
    current = container_start
    for logical_number in range(1, MAX_EBR_PARTITIONS + 1):
        if current in visited:
            issues.append("The EBR chain contains a loop.")
            break
        if current < container_start or current >= container_end:
            issues.append("An EBR lies outside its extended partition.")
            break
        visited.add(current)
        ebr_lbas.append(current)
        try:
            sector = _read_exact(
                reader, current * sector_size, 512,
                f"Extended partition EBR at LBA {current}",
            )
        except _UnavailableRange as error:
            if issues:
                issues.append(str(error))
                return tuple(issues)
            raise
        except PartitionTableError as error:
            issues.append(str(error))
            break
        if sector[510:512] != b"\x55\xaa":
            issues.append(f"The EBR at LBA {current} has no valid signature.")
            break

        decoded: list[tuple[int, int, int, int]] = []
        for index in range(4):
            status_byte, _start_chs, partition_type, _end_chs, start, count = (
                _MBR_ENTRY.unpack_from(sector, 446 + index * 16)
            )
            number = index + 1
            if status_byte not in {0, 0x80}:
                issues.append(
                    f"EBR entry {number} at LBA {current} has an invalid boot flag."
                )
            if partition_type == 0:
                if status_byte or start or count:
                    issues.append(
                        f"Unused EBR entry {number} at LBA {current} is not empty."
                    )
                decoded.append((number, 0, 0, 0))
                continue
            if start == 0 or count == 0:
                issues.append(
                    f"EBR entry {number} at LBA {current} has empty geometry."
                )
            decoded.append((number, partition_type, start, count))

        _number, data_type, relative_start, count = decoded[0]
        if data_type in _EXTENDED_MBR_TYPES:
            issues.append(f"The logical entry at EBR LBA {current} is itself extended.")
        elif data_type:
            start = current + relative_start
            end = start + count
            if (
                relative_start == 0 or end <= start
                or start < container_start or end > container_end
            ):
                issues.append(
                    f"Logical MBR partition {logical_number} leaves its extended container."
                )
            else:
                logical.append((start, end, logical_number))
        else:
            issues.append(f"The EBR at LBA {current} has no logical data entry.")

        _number, link_type, relative_link, link_count = decoded[1]
        if link_type and link_type not in _EXTENDED_MBR_TYPES:
            issues.append(f"The EBR link at LBA {current} has a non-extended type.")
            break
        if any(kind for _number, kind, _start, _count in decoded[2:]):
            issues.append(f"The EBR at LBA {current} uses forbidden extra entries.")
        if not link_type:
            break
        following = container_start + relative_link
        link_end = following + link_count
        if (
            relative_link == 0 or link_count == 0 or link_end <= following
            or following < container_start or link_end > container_end
        ):
            issues.append("An EBR link leaves its extended partition.")
            break
        current = following
    else:
        issues.append("The EBR chain exceeds the bounded logical-partition limit.")

    if not logical:
        issues.append("The extended MBR partition contains no usable logical partitions.")
    logical.sort()
    for previous, current_range in zip(logical, logical[1:]):
        if current_range[0] < previous[1]:
            issues.append(
                f"Logical MBR partitions {previous[2]} and {current_range[2]} overlap."
            )
    for ebr_lba in ebr_lbas:
        if any(start <= ebr_lba < end for start, end, _number in logical):
            issues.append(f"An EBR at LBA {ebr_lba} overlaps a logical partition.")
    return tuple(issues)


def _parse_mbr(reader: _Reader, sector_size: int) -> _MbrInspection:
    issues: list[str] = []
    if reader.size < 512:
        return _MbrInspection(
            False, "none", "none", (), ("The MBR sector is truncated.",),
        )
    sector = _read_exact(reader, 0, 512, "The MBR sector")
    if sector[510:512] != b"\x55\xaa":
        return _MbrInspection(
            False, "none", _classify_boot_code(sector), (), (),
        )

    if reader.size % sector_size:
        issues.append(
            f"The image size is not aligned to {sector_size}-byte logical sectors."
        )
    total_sectors = reader.size // sector_size
    entries: list[tuple[int, int, int, int]] = []
    protective = 0
    protective_records: list[tuple[int, int, bytes, bytes]] = []
    for index in range(4):
        offset = 446 + (index * _MBR_ENTRY.size)
        status_byte, start_chs, partition_type, end_chs, start, count = (
            _MBR_ENTRY.unpack_from(sector, offset)
        )
        number = index + 1
        if status_byte not in {0, 0x80}:
            issues.append(f"MBR partition {number} has an invalid boot flag.")
        if partition_type == 0:
            if status_byte:
                issues.append(f"Unused MBR partition {number} is marked bootable.")
            if start or count:
                issues.append(
                    f"Unused MBR partition {number} contains nonzero geometry."
                )
            continue
        if start == 0 or count == 0:
            issues.append(f"MBR partition {number} has empty geometry.")
            continue
        end = start + count
        if end <= start or end > total_sectors:
            issues.append(f"MBR partition {number} extends beyond the image.")
        entries.append((number, partition_type, start, end))
        if partition_type == 0xEE:
            protective += 1
            protective_records.append((number, status_byte, start_chs, end_chs))
            expected = min(max(0, total_sectors - 1), _UINT32_MAX)
            if start != 1 or count != expected:
                issues.append(
                    "The protective MBR partition does not cover the GPT disk."
                )

    if not entries:
        issues.append("The MBR signature has no usable partition entries.")
    if protective > 1:
        issues.append("The MBR contains multiple protective GPT partitions.")
    # A protective entry intentionally overlaps hybrid entries.  Other primary
    # partitions must not overlap one another.
    ordinary = sorted(
        (start, end, number) for number, kind, start, end in entries if kind != 0xEE
    )
    for previous, current in zip(ordinary, ordinary[1:]):
        if current[0] < previous[1]:
            issues.append(
                f"MBR partitions {previous[2]} and {current[2]} overlap."
            )

    extended = tuple(
        item for item in entries if item[1] in _EXTENDED_MBR_TYPES
    )
    if len(extended) > 1:
        issues.append("The MBR contains multiple extended primary partitions.")
    elif extended:
        _number, _kind, container_start, container_end = extended[0]
        if protective:
            issues.append("A hybrid MBR may not contain an extended partition chain.")
        elif not issues:
            # If primary metadata is already conclusively malformed, do not let
            # an uncaptured middle EBR downgrade that evidence to "incomplete."
            issues.extend(_validate_ebr_chain(
                reader, sector_size, container_start, container_end,
            ))

    kind = (
        "protective" if protective and len(entries) == 1
        else "hybrid" if protective
        else "mbr"
    )
    if protective:
        expected_end_chs = _lba_to_chs(max(0, total_sectors - 1))
        for number, status_byte, start_chs, end_chs in protective_records:
            if status_byte != 0:
                issues.append(
                    f"Protective MBR partition {number} is marked bootable."
                )
            if start_chs != _lba_to_chs(1):
                issues.append(
                    f"Protective MBR partition {number} has an invalid starting CHS address."
                )
            # UEFI explicitly permits FF:FF:FF when a protective entry's CHS
            # endpoint is not represented.  GNU Parted uses that sentinel even
            # for small images whose endpoint could be encoded, so accept both
            # the exact conventional geometry and the standard sentinel.
            if end_chs not in {expected_end_chs, b"\xff\xff\xff"}:
                issues.append(
                    f"Protective MBR partition {number} has an invalid ending CHS address."
                )
    if kind == "protective":
        if sector[440:444] != b"\0" * 4:
            issues.append("The protective MBR disk signature is nonzero.")
        if sector[444:446] != b"\0" * 2:
            issues.append("The protective MBR reserved field is nonzero.")
        for index in range(4):
            offset = 446 + (index * _MBR_ENTRY.size)
            if sector[offset + 4] == 0 and any(sector[offset:offset + _MBR_ENTRY.size]):
                issues.append(
                    f"Unused protective MBR partition record {index + 1} is not zero."
                )
        if sector_size > 512:
            reserved_tail = _read_exact(
                reader, 512, sector_size - 512,
                "The protective MBR reserved logical-block tail",
            )
            if any(reserved_tail):
                issues.append(
                    "The protective MBR reserved logical-block tail is nonzero."
                )
    return _MbrInspection(
        not issues, kind, _classify_boot_code(sector), tuple(entries),
        tuple(issues),
    )


def _parse_gpt_header(
    reader: _Reader,
    sector_size: int,
    lba: int,
    expected_current_lba: int,
    label: str,
) -> tuple[_GptHeader | None, tuple[str, ...]]:
    issues: list[str] = []
    try:
        sector = _read_exact(
            reader, lba * sector_size, sector_size, f"The {label} GPT header",
        )
    except _UnavailableRange:
        raise
    except PartitionTableError as error:
        return None, (str(error),)
    if sector[:8] != _GPT_SIGNATURE:
        return None, (f"The {label} GPT header signature is missing.",)
    try:
        (
            _signature, revision, header_size, header_crc32, reserved,
            current_lba, backup_lba, first_usable_lba, last_usable_lba,
            disk_guid, entry_lba, entry_count, entry_size, entry_crc32,
        ) = _GPT_HEADER.unpack_from(sector)
    except struct.error:
        return None, (f"The {label} GPT header is truncated.",)

    if revision != _GPT_REVISION_1_0:
        issues.append(f"The {label} GPT header revision is unsupported.")
    if header_size < _GPT_HEADER.size or header_size > sector_size:
        issues.append(f"The {label} GPT header size is invalid.")
    else:
        check = bytearray(sector[:header_size])
        check[16:20] = b"\0\0\0\0"
        if zlib.crc32(check) & _UINT32_MAX != header_crc32:
            issues.append(f"The {label} GPT header CRC32 does not match.")
    if any(sector[_GPT_HEADER.size:]):
        issues.append(f"The {label} GPT header reserved padding is nonzero.")
    if reserved != 0:
        issues.append(f"The {label} GPT header reserved field is nonzero.")
    if current_lba != expected_current_lba:
        issues.append(f"The {label} GPT header is stored at the wrong LBA.")
    if not any(disk_guid):
        issues.append("The GPT disk GUID is zero.")
    if entry_count <= 0 or entry_count > MAX_GPT_ENTRIES:
        issues.append(f"The {label} GPT entry count is outside the bounded limit.")
    if not _valid_gpt_entry_size(entry_size):
        issues.append(f"The {label} GPT entry size is invalid.")
    if (
        entry_count > 0 and entry_size > 0
        and entry_count * entry_size > MAX_GPT_ARRAY_BYTES
    ):
        issues.append(f"The {label} GPT entry array exceeds the bounded limit.")

    return _GptHeader(
        revision, header_size, current_lba, backup_lba,
        first_usable_lba, last_usable_lba, disk_guid, entry_lba,
        entry_count, entry_size, entry_crc32,
    ), tuple(issues)


def _read_gpt_array(
    reader: _Reader,
    header: _GptHeader,
    sector_size: int,
    total_sectors: int,
    label: str,
) -> tuple[bytes | None, tuple[str, ...]]:
    issues: list[str] = []
    if (
        header.entry_count <= 0 or header.entry_count > MAX_GPT_ENTRIES
        or not _valid_gpt_entry_size(header.entry_size)
    ):
        return None, ()
    length = header.entry_count * header.entry_size
    if length > MAX_GPT_ARRAY_BYTES:
        return None, ()
    sectors = (length + sector_size - 1) // sector_size
    if (
        header.entry_lba < 2
        or header.entry_lba >= total_sectors
        or sectors > total_sectors - header.entry_lba
    ):
        return None, (f"The {label} GPT entry array lies outside the image.",)
    if label == "primary":
        if header.entry_lba + sectors > header.first_usable_lba:
            issues.append("The primary GPT entry array overlaps usable sectors.")
    elif (
        header.entry_lba <= header.last_usable_lba
        or header.entry_lba + sectors > header.current_lba
    ):
        issues.append("The backup GPT entry array overlaps usable sectors or its header.")
    try:
        payload = _read_exact(
            reader, header.entry_lba * sector_size, length,
            f"The {label} GPT entry array",
        )
    except _UnavailableRange:
        raise
    except PartitionTableError as error:
        return None, (*issues, str(error))
    if zlib.crc32(payload) & _UINT32_MAX != header.entry_crc32:
        issues.append(f"The {label} GPT entry-array CRC32 does not match.")
    return payload, tuple(issues)


def _validate_gpt_entries(
    payload: bytes,
    header: _GptHeader,
) -> tuple[tuple[str, ...], tuple[tuple[int, int], ...]]:
    issues: list[str] = []
    partitions: list[tuple[int, int, int]] = []
    unique_guids: set[bytes] = set()
    for index in range(header.entry_count):
        offset = index * header.entry_size
        entry = payload[offset:offset + header.entry_size]
        number = index + 1
        attributes = struct.unpack_from("<Q", entry, 48)[0]
        if attributes & _GPT_UNDEFINED_ATTRIBUTE_MASK:
            issues.append(f"GPT partition entry {number} uses undefined attribute bits.")
        if any(entry[128:]):
            issues.append(f"GPT partition entry {number} has nonzero reserved bytes.")
        type_guid = entry[:16]
        if not any(type_guid):
            continue
        name_units = struct.unpack_from("<36H", entry, 56)
        try:
            terminator = name_units.index(0)
        except ValueError:
            issues.append(
                f"GPT partition entry {number} has no null-terminated UTF-16 name."
            )
        else:
            try:
                entry[56:56 + terminator * 2].decode("utf-16-le", errors="strict")
            except UnicodeDecodeError:
                issues.append(
                    f"GPT partition entry {number} has an invalid UTF-16 name."
                )
        unique_guid = entry[16:32]
        first_lba, last_lba = struct.unpack_from("<QQ", entry, 32)
        if not any(unique_guid):
            issues.append(f"GPT partition {number} has a zero unique GUID.")
        elif unique_guid in unique_guids:
            issues.append(f"GPT partition {number} repeats a unique GUID.")
        unique_guids.add(unique_guid)
        if (
            first_lba > last_lba
            or first_lba < header.first_usable_lba
            or last_lba > header.last_usable_lba
        ):
            issues.append(f"GPT partition {number} lies outside usable sectors.")
            continue
        partitions.append((first_lba, last_lba + 1, number))
    partitions.sort()
    for previous, current in zip(partitions, partitions[1:]):
        if current[0] < previous[1]:
            issues.append(
                f"GPT partitions {previous[2]} and {current[2]} overlap."
            )
    return tuple(issues), tuple((start, end) for start, end, _number in partitions)


def _parse_gpt_candidate(reader: _Reader, sector_size: int) -> _GptCandidate:
    prefix = f"GPT ({sector_size}-byte sectors)"
    issues: list[str] = []
    if reader.size % sector_size:
        return _GptCandidate(
            False, sector_size, _parse_mbr(reader, sector_size),
            (f"{prefix}: the image size is not sector-aligned.",),
        )
    total_sectors = reader.size // sector_size
    if total_sectors < 6:
        return _GptCandidate(
            False, sector_size, _parse_mbr(reader, sector_size),
            (f"{prefix}: the image is too small for GPT metadata.",),
        )
    last_lba = total_sectors - 1
    primary, primary_issues = _parse_gpt_header(
        reader, sector_size, 1, 1, "primary",
    )
    backup, backup_issues = _parse_gpt_header(
        reader, sector_size, last_lba, last_lba, "backup",
    )
    issues.extend(primary_issues)
    issues.extend(backup_issues)
    mbr = _parse_mbr(reader, sector_size)
    if not mbr.valid or mbr.kind not in {"protective", "hybrid"}:
        issues.extend(mbr.issues)
        issues.append("GPT requires a valid protective or hybrid MBR.")
    if primary is None or backup is None:
        return _GptCandidate(
            False, sector_size, mbr,
            tuple(f"{prefix}: {issue}" for issue in dict.fromkeys(issues)),
        )

    if primary.backup_lba != last_lba or backup.backup_lba != 1:
        issues.append("The primary and backup GPT headers are not reciprocal.")
    if (
        primary.revision != backup.revision
        or primary.header_size != backup.header_size
        or primary.first_usable_lba != backup.first_usable_lba
        or primary.last_usable_lba != backup.last_usable_lba
        or primary.disk_guid != backup.disk_guid
        or primary.entry_count != backup.entry_count
        or primary.entry_size != backup.entry_size
        or primary.entry_crc32 != backup.entry_crc32
    ):
        issues.append("The primary and backup GPT headers disagree.")
    if (
        primary.first_usable_lba < 2
        or primary.first_usable_lba > primary.last_usable_lba
        or primary.last_usable_lba >= last_lba
    ):
        issues.append("The GPT usable-LBA range is invalid.")
    minimum_array_sectors = (
        MIN_GPT_ARRAY_RESERVATION_BYTES + sector_size - 1
    ) // sector_size
    if (
        primary.first_usable_lba < 2 + minimum_array_sectors
        or primary.last_usable_lba > last_lba - minimum_array_sectors - 1
    ):
        issues.append(
            "The GPT usable-LBA range does not reserve the required 16 KiB "
            "for each partition-entry array."
        )

    if issues:
        unique = tuple(f"{prefix}: {issue}" for issue in dict.fromkeys(issues))
        return _GptCandidate(False, sector_size, mbr, unique)

    primary_array, array_issues = _read_gpt_array(
        reader, primary, sector_size, total_sectors, "primary",
    )
    issues.extend(array_issues)
    gpt_ranges: tuple[tuple[int, int], ...] = ()
    if primary_array is not None:
        entry_issues, gpt_ranges = _validate_gpt_entries(primary_array, primary)
        issues.extend(entry_issues)
        if mbr.kind == "hybrid":
            available = set(gpt_ranges)
            for number, partition_type, start, end in mbr.entries:
                if partition_type == 0xEE:
                    continue
                if (start, end) not in available:
                    issues.append(
                        f"Hybrid MBR partition {number} does not exactly mirror a GPT partition."
                    )
    if issues:
        unique = tuple(f"{prefix}: {issue}" for issue in dict.fromkeys(issues))
        return _GptCandidate(False, sector_size, mbr, unique)

    backup_array, array_issues = _read_gpt_array(
        reader, backup, sector_size, total_sectors, "backup",
    )
    issues.extend(array_issues)
    if primary_array is not None and backup_array is not None:
        if primary_array != backup_array:
            issues.append("The primary and backup GPT entry arrays differ.")

    unique = tuple(f"{prefix}: {issue}" for issue in dict.fromkeys(issues))
    return _GptCandidate(not unique, sector_size, mbr, unique)


def _inspect_available(
    reader: _Reader,
    first: bytes,
    has_mbr: bool,
    signatures: tuple[int, ...],
) -> PartitionTableInspection:
    has_gpt = bool(signatures)

    if has_gpt:
        candidates = tuple(_parse_gpt_candidate(reader, size) for size in signatures)
        valid = tuple(item for item in candidates if item.valid)
        if len(valid) == 1 and len(candidates) == 1:
            chosen = valid[0]
            kind = "hybrid-gpt" if chosen.mbr.kind == "hybrid" else "gpt"
            return PartitionTableInspection(
                has_mbr, True, True, False, kind, chosen.sector_size,
                chosen.mbr.kind, chosen.mbr.boot_code, (),
            )
        issues = [issue for item in candidates for issue in item.issues]
        if len(valid) > 1:
            issues.append(
                "GPT headers are valid at more than one logical-sector size."
            )
        elif valid:
            issues.append(
                "A second conflicting GPT primary signature is present."
            )
        mbr = candidates[0].mbr
        return PartitionTableInspection(
            has_mbr, True, False, True, "malformed", 0,
            mbr.kind, mbr.boot_code, tuple(dict.fromkeys(issues)),
        )

    mbr = _parse_mbr(reader, 512)
    if has_mbr and mbr.valid and mbr.kind == "mbr":
        return PartitionTableInspection(
            True, False, True, False, "mbr", 512,
            mbr.kind, mbr.boot_code, (),
        )
    if has_mbr:
        issues = list(mbr.issues)
        if mbr.valid and mbr.kind in {"protective", "hybrid"}:
            issues.append("A protective MBR has no valid primary GPT header.")
        return PartitionTableInspection(
            True, False, False, True, "malformed", 0,
            mbr.kind, mbr.boot_code, tuple(dict.fromkeys(issues)),
        )
    return PartitionTableInspection(
        False, False, False, False, "none", 0, "none",
        _classify_boot_code(first.ljust(512, b"\0")), (),
    )


def _inspect(reader: _Reader) -> PartitionTableInspection:
    if reader.size < 0:
        raise ValueError("Image size cannot be negative")
    first = b""
    has_mbr = False
    signatures: list[int] = []
    try:
        first = reader.read_at(0, min(512, reader.size))
        has_mbr = len(first) >= 512 and first[510:512] == b"\x55\xaa"
        for sector_size in LOGICAL_SECTOR_SIZES:
            offset = sector_size
            if offset + len(_GPT_SIGNATURE) <= reader.size:
                if reader.read_at(offset, len(_GPT_SIGNATURE)) == _GPT_SIGNATURE:
                    signatures.append(sector_size)
        if len(signatures) > 1:
            # Multiple primary signatures are conclusive corruption on their
            # own.  Do not let an unavailable middle entry array downgrade the
            # already-known conflict to an inconclusive streamed inspection.
            try:
                mbr = _parse_mbr(reader, signatures[0])
                mbr_kind = mbr.kind
                boot_code = mbr.boot_code
            except _UnavailableRange:
                mbr_kind = "unknown" if has_mbr else "none"
                boot_code = _classify_boot_code(first.ljust(512, b"\0"))
            return PartitionTableInspection(
                has_mbr, True, False, True, "malformed", 0,
                mbr_kind, boot_code,
                ("GPT primary signatures conflict at multiple logical-sector sizes.",),
            )
        return _inspect_available(reader, first, has_mbr, tuple(signatures))
    except _UnavailableRange as error:
        return PartitionTableInspection(
            has_mbr, bool(signatures), False, False, "incomplete", 0,
            "unknown" if has_mbr else "none",
            _classify_boot_code(first.ljust(512, b"\0")),
            (str(error),), False,
        )


def inspect_partition_tables_fd(
    descriptor: int,
    *,
    expected_identity: FileIdentity | None = None,
) -> PartitionTableInspection:
    """Inspect one already-open regular file without reopening its pathname."""

    try:
        before = os.fstat(descriptor)
    except OSError as error:
        raise PartitionTableError("The image descriptor is unavailable") from error
    if not stat.S_ISREG(before.st_mode):
        raise PartitionTableError("Partition inspection requires a regular file")
    if expected_identity is not None and _identity(before) != expected_identity:
        raise PartitionTableError("The image changed before partition inspection")
    bound = _bound_identity(before)
    result = _inspect(_FdReader(descriptor, before.st_size))
    try:
        after = os.fstat(descriptor)
    except OSError as error:
        raise PartitionTableError("The image descriptor became unavailable") from error
    if _bound_identity(after) != bound:
        raise PartitionTableError("The image changed during partition inspection")
    return result


def inspect_partition_tables_capture(
    prefix: bytes,
    tail: bytes,
    size: int,
) -> PartitionTableInspection:
    """Inspect bounded regions retained while a compressed image was streamed."""

    if not isinstance(prefix, bytes) or not isinstance(tail, bytes):
        raise TypeError("Partition-table captures must be bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ValueError("Image size must be a non-negative integer")
    if len(prefix) > PARTITION_TABLE_CAPTURE_BYTES or len(tail) > PARTITION_TABLE_CAPTURE_BYTES:
        raise ValueError("Partition-table capture exceeds the bounded limit")
    if len(prefix) > size or len(tail) > size:
        raise ValueError("Partition-table capture exceeds the image size")
    return _inspect(_CapturedReader(prefix, tail, size))
