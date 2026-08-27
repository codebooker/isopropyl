from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Strict, descriptor-bound Ventoy Sparse Image (VTSI) v1 support.

VTSI stores selected 512-byte disk ranges contiguously, followed by a segment
table and a fixed footer.  This module exposes a deterministic expanded view:
bytes outside stored ranges read as zero.  It never trusts a pathname after a
descriptor has been opened and never allocates in proportion to disk size.
"""

import os
import stat
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path


VTSI_SECTOR_BYTES = 512
VTSI_MAX_SEGMENTS = 128
VTSI_MAX_DISK_BYTES = 64 * 1024**4
VTSI_STREAM_CHUNK_BYTES = 4 * 1024**2
VTSI_MAX_READ_BYTES = 32 * 1024**2

_VTSI_MAGIC = b"VENTOY\x00\x00"
_VTSI_FOOTER_BYTES = 512
_VTSI_VERSION_MAJOR = 1
_VTSI_VERSION_MINOR = 0
_FOOTER_FIXED = struct.Struct("<8sHHQIIIIQ")
_SEGMENT = struct.Struct("<QQQ")
_FOOTER_CHECKSUM_OFFSET = 24
_FOOTER_RESERVED_OFFSET = _FOOTER_FIXED.size

CancelCheck = Callable[[], None]


class VtsiError(RuntimeError):
    """A VTSI image could not be inspected or read."""


class VtsiSafetyError(VtsiError):
    """VTSI structure or caller-supplied state failed closed."""


class VtsiChanged(VtsiSafetyError):
    """The descriptor identity changed after it was bound."""


@dataclass(frozen=True)
class VtsiIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int
    link_count: int

    def __post_init__(self) -> None:
        values = (
            self.device,
            self.inode,
            self.size,
            self.modified_ns,
            self.changed_ns,
            self.link_count,
        )
        if any(type(value) is not int for value in values):
            raise ValueError("VTSI identity fields must be exact integers")
        if (
            self.device < 0
            or self.inode <= 0
            or self.size <= 0
            or self.link_count <= 0
        ):
            raise ValueError("VTSI identity fields are outside the valid range")


@dataclass(frozen=True)
class VtsiSegment:
    disk_start_sector: int
    sector_count: int
    data_offset: int

    def __post_init__(self) -> None:
        values = (self.disk_start_sector, self.sector_count, self.data_offset)
        if any(type(value) is not int for value in values):
            raise ValueError("VTSI segment fields must be exact integers")
        if self.disk_start_sector < 0 or self.sector_count <= 0 or self.data_offset < 0:
            raise ValueError("VTSI segment fields are outside the valid range")

    @property
    def disk_offset(self) -> int:
        return self.disk_start_sector * VTSI_SECTOR_BYTES

    @property
    def byte_count(self) -> int:
        return self.sector_count * VTSI_SECTOR_BYTES

    @property
    def disk_end(self) -> int:
        return self.disk_offset + self.byte_count

    @property
    def data_end(self) -> int:
        return self.data_offset + self.byte_count


@dataclass(frozen=True)
class VtsiPlan:
    path: Path
    identity: VtsiIdentity
    version_major: int
    version_minor: int
    disk_size: int
    disk_signature: int
    segment_offset: int
    segments: tuple[VtsiSegment, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise ValueError("VTSI plan paths must be absolute Path values")
        if type(self.identity) is not VtsiIdentity:
            raise ValueError("VTSI plan identity has an invalid type")
        scalar = (
            self.version_major,
            self.version_minor,
            self.disk_size,
            self.disk_signature,
            self.segment_offset,
        )
        if any(type(value) is not int for value in scalar):
            raise ValueError("VTSI plan fields must be exact integers")
        if (self.version_major, self.version_minor) != (
            _VTSI_VERSION_MAJOR,
            _VTSI_VERSION_MINOR,
        ):
            raise ValueError("VTSI plan version is unsupported")
        if (
            self.disk_size < VTSI_SECTOR_BYTES
            or self.disk_size > VTSI_MAX_DISK_BYTES
            or self.disk_size % VTSI_SECTOR_BYTES
        ):
            raise ValueError("VTSI plan disk size is invalid")
        if not 0 <= self.disk_signature <= 0xFFFFFFFF:
            raise ValueError("VTSI plan disk signature is invalid")
        if self.segment_offset <= 0 or self.segment_offset % VTSI_SECTOR_BYTES:
            raise ValueError("VTSI plan segment-table offset is invalid")
        if (
            type(self.segments) is not tuple
            or not 1 <= len(self.segments) <= VTSI_MAX_SEGMENTS
            or any(type(segment) is not VtsiSegment for segment in self.segments)
        ):
            raise ValueError("VTSI plan segments are invalid")


def _check_cancelled(cancel_check: CancelCheck | None) -> None:
    if cancel_check is not None:
        # Cancellation is caller control flow.  Its exact exception type must
        # survive even when it derives from OSError or RuntimeError.
        cancel_check()


def _identity_from_status(status: os.stat_result) -> VtsiIdentity:
    if not stat.S_ISREG(status.st_mode):
        raise VtsiSafetyError("The VTSI source must be a regular file")
    try:
        return VtsiIdentity(
            status.st_dev,
            status.st_ino,
            status.st_size,
            status.st_mtime_ns,
            status.st_ctime_ns,
            status.st_nlink,
        )
    except ValueError as error:
        raise VtsiSafetyError("The VTSI source identity is invalid") from error


def _descriptor_identity(descriptor: int) -> VtsiIdentity:
    if type(descriptor) is not int or descriptor < 0:
        raise VtsiSafetyError("A valid VTSI file descriptor is required")
    try:
        status = os.fstat(descriptor)
    except OSError as error:
        raise VtsiChanged("The VTSI source descriptor is unavailable") from error
    return _identity_from_status(status)


def _require_identity(descriptor: int, expected: VtsiIdentity) -> None:
    if _descriptor_identity(descriptor) != expected:
        raise VtsiChanged("The VTSI source changed while it was being read")


def _pread_exact(
    descriptor: int,
    length: int,
    offset: int,
    identity: VtsiIdentity,
    cancel_check: CancelCheck | None,
    label: str,
) -> bytes:
    if (
        type(length) is not int
        or type(offset) is not int
        or length < 0
        or length > VTSI_MAX_READ_BYTES
        or offset < 0
        or offset > identity.size
        or length > identity.size - offset
    ):
        raise VtsiSafetyError(f"The VTSI {label} range is invalid")
    _check_cancelled(cancel_check)
    _require_identity(descriptor, identity)
    try:
        data = os.pread(descriptor, length, offset)
    except OSError as error:
        raise VtsiSafetyError(f"Could not read the VTSI {label}") from error
    _check_cancelled(cancel_check)
    _require_identity(descriptor, identity)
    if len(data) != length:
        raise VtsiSafetyError(f"The VTSI {label} is truncated")
    return data


def _checksum(data: bytes) -> int:
    return (~sum(data)) & 0xFFFFFFFF


def _normalize_path(path: Path) -> Path:
    try:
        raw = os.fspath(path)
    except TypeError as error:
        raise VtsiSafetyError("The VTSI path is invalid") from error
    if type(raw) is not str or not raw or "\x00" in raw:
        raise VtsiSafetyError("The VTSI path is invalid")
    return Path(os.path.abspath(raw))


def inspect_vtsi_descriptor(
    descriptor: int,
    path: Path,
    *,
    cancel_check: CancelCheck | None = None,
    maximum_disk_size: int = VTSI_MAX_DISK_BYTES,
) -> VtsiPlan:
    """Parse VTSI v1 from an already-open authoritative descriptor."""

    if (
        type(maximum_disk_size) is not int
        or not VTSI_SECTOR_BYTES <= maximum_disk_size <= VTSI_MAX_DISK_BYTES
    ):
        raise ValueError(
            f"maximum_disk_size must be between {VTSI_SECTOR_BYTES} "
            f"and {VTSI_MAX_DISK_BYTES}"
        )
    _check_cancelled(cancel_check)
    normalized_path = _normalize_path(path)
    identity = _descriptor_identity(descriptor)
    if identity.size < 2 * VTSI_SECTOR_BYTES:
        raise VtsiSafetyError("The VTSI source is too small")

    footer = _pread_exact(
        descriptor,
        _VTSI_FOOTER_BYTES,
        identity.size - _VTSI_FOOTER_BYTES,
        identity,
        cancel_check,
        "footer",
    )
    try:
        (
            magic,
            version_major,
            version_minor,
            disk_size,
            disk_signature,
            footer_checksum,
            segment_count,
            segment_checksum,
            segment_offset,
        ) = _FOOTER_FIXED.unpack_from(footer)
    except struct.error as error:
        raise VtsiSafetyError("The VTSI footer is malformed") from error
    if magic != _VTSI_MAGIC:
        raise VtsiSafetyError("The VTSI footer magic is invalid")
    if (version_major, version_minor) != (
        _VTSI_VERSION_MAJOR,
        _VTSI_VERSION_MINOR,
    ):
        raise VtsiSafetyError(
            f"Unsupported VTSI version {version_major}.{version_minor}"
        )
    footer_for_checksum = bytearray(footer)
    footer_for_checksum[
        _FOOTER_CHECKSUM_OFFSET:_FOOTER_CHECKSUM_OFFSET + 4
    ] = b"\x00" * 4
    if _checksum(bytes(footer_for_checksum)) != footer_checksum:
        raise VtsiSafetyError("The VTSI footer checksum is invalid")
    if any(footer[_FOOTER_RESERVED_OFFSET:]):
        raise VtsiSafetyError("The VTSI footer contains unsupported reserved data")
    if (
        disk_size < VTSI_SECTOR_BYTES
        or disk_size > maximum_disk_size
        or disk_size % VTSI_SECTOR_BYTES
    ):
        raise VtsiSafetyError("The VTSI expanded disk size is invalid")
    if not 1 <= segment_count <= VTSI_MAX_SEGMENTS:
        raise VtsiSafetyError("The VTSI segment count is invalid")
    if segment_offset <= 0 or segment_offset % VTSI_SECTOR_BYTES:
        raise VtsiSafetyError("The VTSI segment-table offset is invalid")

    table_size = segment_count * _SEGMENT.size
    padded_table_size = (
        (table_size + VTSI_SECTOR_BYTES - 1) // VTSI_SECTOR_BYTES
    ) * VTSI_SECTOR_BYTES
    expected_file_size = segment_offset + padded_table_size + _VTSI_FOOTER_BYTES
    if expected_file_size != identity.size:
        raise VtsiSafetyError("The VTSI file layout is inconsistent")
    metadata = _pread_exact(
        descriptor,
        padded_table_size,
        segment_offset,
        identity,
        cancel_check,
        "segment metadata",
    )
    table = metadata[:table_size]
    if _checksum(table) != segment_checksum:
        raise VtsiSafetyError("The VTSI segment-table checksum is invalid")
    if any(metadata[table_size:]):
        raise VtsiSafetyError("The VTSI segment-table padding is not zero")

    segments: list[VtsiSegment] = []
    expected_data_offset = 0
    disk_sectors = disk_size // VTSI_SECTOR_BYTES
    for index in range(segment_count):
        _check_cancelled(cancel_check)
        disk_start, sector_count, data_offset = _SEGMENT.unpack_from(
            table, index * _SEGMENT.size,
        )
        try:
            segment = VtsiSegment(disk_start, sector_count, data_offset)
        except ValueError as error:
            raise VtsiSafetyError(f"VTSI segment {index} is invalid") from error
        if data_offset != expected_data_offset:
            raise VtsiSafetyError(
                f"VTSI segment {index} has a non-contiguous data offset"
            )
        if disk_start > disk_sectors or sector_count > disk_sectors - disk_start:
            raise VtsiSafetyError(f"VTSI segment {index} exceeds the expanded disk")
        if segment.data_end > segment_offset:
            raise VtsiSafetyError(f"VTSI segment {index} exceeds the data area")
        segments.append(segment)
        expected_data_offset = segment.data_end
    if expected_data_offset != segment_offset:
        raise VtsiSafetyError("The VTSI data area does not match its segments")
    # Ventoy records filesystem writes in emission order, which is not
    # necessarily disk-LBA order.  Preserve that catalog order because it
    # binds the contiguous source data offsets.  ISOpropyl separately rejects
    # overlapping expanded extents as a fail-closed safety policy; that is not
    # asserted here as part of the VTSI v1 wire-format grammar.
    disk_order = sorted(segments, key=lambda segment: segment.disk_offset)
    previous_disk_end = 0
    for segment in disk_order:
        if segment.disk_offset < previous_disk_end:
            raise VtsiSafetyError("VTSI disk segments overlap")
        previous_disk_end = segment.disk_end

    _check_cancelled(cancel_check)
    plan = VtsiPlan(
        normalized_path,
        identity,
        version_major,
        version_minor,
        disk_size,
        disk_signature,
        segment_offset,
        tuple(segments),
    )
    _require_identity(descriptor, identity)
    return plan


def inspect_vtsi(
    path: Path,
    *,
    cancel_check: CancelCheck | None = None,
    maximum_disk_size: int = VTSI_MAX_DISK_BYTES,
) -> VtsiPlan:
    """Safely open, inspect, and close one VTSI source."""

    normalized = _normalize_path(path)
    _check_cancelled(cancel_check)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(normalized, flags)
    except OSError as error:
        raise VtsiSafetyError("The VTSI source could not be opened safely") from error
    try:
        return inspect_vtsi_descriptor(
            descriptor,
            normalized,
            cancel_check=cancel_check,
            maximum_disk_size=maximum_disk_size,
        )
    finally:
        os.close(descriptor)


def _validate_plan_model(plan: VtsiPlan) -> None:
    if type(plan) is not VtsiPlan:
        raise VtsiSafetyError("The VTSI plan has an invalid type")
    try:
        identity = VtsiIdentity(
            plan.identity.device,
            plan.identity.inode,
            plan.identity.size,
            plan.identity.modified_ns,
            plan.identity.changed_ns,
            plan.identity.link_count,
        )
        segments = tuple(
            VtsiSegment(
                segment.disk_start_sector,
                segment.sector_count,
                segment.data_offset,
            )
            for segment in plan.segments
        )
        rebound = VtsiPlan(
            plan.path,
            identity,
            plan.version_major,
            plan.version_minor,
            plan.disk_size,
            plan.disk_signature,
            plan.segment_offset,
            segments,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise VtsiSafetyError("The VTSI plan model is invalid") from error
    if rebound != plan:
        raise VtsiSafetyError("The VTSI plan model is inconsistent")
    _validate_frozen_plan_invariants(rebound)


def _validate_frozen_plan_invariants(plan: VtsiPlan) -> None:
    """Validate all cross-field facts without reading the source descriptor."""

    table_size = len(plan.segments) * _SEGMENT.size
    padded_table_size = (
        (table_size + VTSI_SECTOR_BYTES - 1) // VTSI_SECTOR_BYTES
    ) * VTSI_SECTOR_BYTES
    expected_file_size = (
        plan.segment_offset + padded_table_size + _VTSI_FOOTER_BYTES
    )
    if expected_file_size != plan.identity.size:
        raise VtsiSafetyError("The VTSI plan file layout is inconsistent")

    expected_data_offset = 0
    disk_sectors = plan.disk_size // VTSI_SECTOR_BYTES
    for index, segment in enumerate(plan.segments):
        if segment.data_offset != expected_data_offset:
            raise VtsiSafetyError(
                f"VTSI plan segment {index} has a non-contiguous data offset"
            )
        if (
            segment.disk_start_sector > disk_sectors
            or segment.sector_count > disk_sectors - segment.disk_start_sector
        ):
            raise VtsiSafetyError(
                f"VTSI plan segment {index} exceeds the expanded disk"
            )
        if segment.data_end > plan.segment_offset:
            raise VtsiSafetyError(
                f"VTSI plan segment {index} exceeds the data area"
            )
        expected_data_offset = segment.data_end
    if expected_data_offset != plan.segment_offset:
        raise VtsiSafetyError(
            "The VTSI plan data area does not match its segments"
        )

    disk_order = sorted(plan.segments, key=lambda segment: segment.disk_offset)
    previous_disk_end = 0
    for segment in disk_order:
        if segment.disk_offset < previous_disk_end:
            raise VtsiSafetyError("VTSI plan disk segments overlap")
        previous_disk_end = segment.disk_end


def validate_vtsi_plan(
    descriptor: int,
    plan: VtsiPlan,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    """Rebuild every format fact and require an exact frozen-plan match."""

    _check_cancelled(cancel_check)
    _validate_plan_model(plan)
    _require_identity(descriptor, plan.identity)
    rebuilt = inspect_vtsi_descriptor(
        descriptor,
        plan.path,
        cancel_check=cancel_check,
        maximum_disk_size=VTSI_MAX_DISK_BYTES,
    )
    if rebuilt != plan:
        raise VtsiChanged("The VTSI source no longer matches its plan")


def read_vtsi_at(
    descriptor: int,
    plan: VtsiPlan,
    offset: int,
    length: int,
    *,
    cancel_check: CancelCheck | None = None,
) -> bytes:
    """Read a bounded range from the deterministic expanded disk view."""

    _check_cancelled(cancel_check)
    _validate_plan_model(plan)
    if (
        type(offset) is not int
        or type(length) is not int
        or offset < 0
        or length < 0
        or length > VTSI_MAX_READ_BYTES
        or offset > plan.disk_size
        or length > plan.disk_size - offset
    ):
        raise VtsiSafetyError("The expanded VTSI read range is invalid")
    _require_identity(descriptor, plan.identity)
    if not length:
        _check_cancelled(cancel_check)
        return b""
    end = offset + length
    output = bytearray(length)
    for segment in plan.segments:
        _check_cancelled(cancel_check)
        if segment.disk_end <= offset:
            continue
        if segment.disk_offset >= end:
            continue
        overlap_start = max(offset, segment.disk_offset)
        overlap_end = min(end, segment.disk_end)
        source_offset = segment.data_offset + overlap_start - segment.disk_offset
        payload = _pread_exact(
            descriptor,
            overlap_end - overlap_start,
            source_offset,
            plan.identity,
            cancel_check,
            "segment data",
        )
        target_start = overlap_start - offset
        output[target_start:target_start + len(payload)] = payload
    _check_cancelled(cancel_check)
    _require_identity(descriptor, plan.identity)
    return bytes(output)


def iter_vtsi_chunks(
    descriptor: int,
    plan: VtsiPlan,
    *,
    chunk_size: int = VTSI_STREAM_CHUNK_BYTES,
    cancel_check: CancelCheck | None = None,
) -> Iterator[bytes]:
    """Yield the complete expanded disk image in bounded sequential chunks."""

    if (
        type(chunk_size) is not int
        or not 1 <= chunk_size <= VTSI_MAX_READ_BYTES
    ):
        raise ValueError(
            f"chunk_size must be between 1 and {VTSI_MAX_READ_BYTES}"
        )
    _check_cancelled(cancel_check)
    _validate_plan_model(plan)
    _require_identity(descriptor, plan.identity)
    expanded_offset = 0
    # Catalog order binds source offsets, but disk order is what a sequential
    # full-device stream needs. The parser has already proved these extents do
    # not overlap, so sorting cannot change their meaning.
    for segment in sorted(plan.segments, key=lambda item: item.disk_offset):
        while expanded_offset < segment.disk_offset:
            _check_cancelled(cancel_check)
            _require_identity(descriptor, plan.identity)
            length = min(chunk_size, segment.disk_offset - expanded_offset)
            yield bytes(length)
            expanded_offset += length
        source_offset = segment.data_offset
        remaining = segment.byte_count
        while remaining:
            _check_cancelled(cancel_check)
            length = min(chunk_size, remaining)
            yield _pread_exact(
                descriptor,
                length,
                source_offset,
                plan.identity,
                cancel_check,
                "segment data",
            )
            source_offset += length
            expanded_offset += length
            remaining -= length
    while expanded_offset < plan.disk_size:
        _check_cancelled(cancel_check)
        _require_identity(descriptor, plan.identity)
        length = min(chunk_size, plan.disk_size - expanded_offset)
        yield bytes(length)
        expanded_offset += length
    _check_cancelled(cancel_check)
    _require_identity(descriptor, plan.identity)
