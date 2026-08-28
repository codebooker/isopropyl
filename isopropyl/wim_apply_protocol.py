# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Candidate wire contract for a future privileged WIM apply.

The first Windows To Go profile must eventually transfer one authenticated,
seekable, read-only WIM snapshot descriptor to a root-owned helper and apply one
exact numeric image to the freshly formatted NTFS child partition. This module
only serializes untrusted claims about that intent. It does not resolve devices,
receive descriptors, issue a readiness capability, execute wimlib, or authorize
media mutation.

SHA-256 values are lowercase hexadecimal at the Python API and raw 32-byte
digests on the wire. UUIDs use canonical RFC byte order on the wire, not GPT's
mixed-endian on-disk representation. The source digest must be recomputed from
the exact inherited descriptor. ``expanded_bytes`` means the selected image's
exact WIM XML ``TOTALBYTES`` value and must also be re-inspected from that
descriptor. Plan and ready digests are correlation receipts, never write
authority: a future helper must independently observe the GPT, partition, NTFS,
source, and WIM metadata before issuing PREPARED.
"""

import os
import re
import struct
import uuid
from dataclasses import dataclass

WIM_APPLY_PROTOCOL_MAGIC = b"ISOPROPYL-WIM001"
WIM_APPLY_PROTOCOL_VERSION = 1
WIM_APPLY_PACKET_REQUEST = 2
WIM_APPLY_PACKET_FLAGS = 0
WIM_APPLY_HELPER_PROFILE = "io.github.codebooker.isopropyl/wim-apply-helper/v1"
WIM_APPLY_OPERATION = "apply-wim-ntfs-v1"
WIM_APPLY_SOURCE_KIND_WIM_CONTAINER = 1
WIM_APPLY_REQUEST_PACKET = struct.Struct(
    "!16sBBH16sIIQQIIIIQQQQII16s16s16sQQ32s32s32s"
)
WIM_APPLY_REQUEST_BYTES = WIM_APPLY_REQUEST_PACKET.size
WIM_APPLY_V1_MIB = 1024 * 1024
WIM_APPLY_V1_GIB = 1024 * WIM_APPLY_V1_MIB
WIM_APPLY_V1_LOGICAL_SECTOR_SIZE = 512
WIM_APPLY_V1_MINIMUM_PARENT_BYTES = 32 * WIM_APPLY_V1_GIB
WIM_APPLY_V1_MINIMUM_FREE_BYTES = 8 * WIM_APPLY_V1_GIB
WIM_APPLY_V1_ESP_BYTES = 260 * WIM_APPLY_V1_MIB
WIM_APPLY_V1_MSR_BYTES = 128 * WIM_APPLY_V1_MIB
WIM_APPLY_MAX_SOURCE_BYTES = 128 * WIM_APPLY_V1_GIB
WIM_APPLY_MAX_PARENT_BYTES = 64 * 1024 * 1024 * 1024 * 1024 * 1024
WIM_APPLY_MAX_IMAGE_INDEX = 2_147_483_647
WIM_APPLY_WINDOWS_PARTITION_NUMBER = 3
WIM_APPLY_WINDOWS_START_BYTES = (
    WIM_APPLY_V1_MIB + WIM_APPLY_V1_ESP_BYTES + WIM_APPLY_V1_MSR_BYTES
)
MICROSOFT_BASIC_DATA_GUID = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")

_UINT64_MAX = 0xFFFFFFFFFFFFFFFF
_GPT_TAIL_SECTORS = 33
_ALIGNMENT_SECTORS = WIM_APPLY_V1_MIB // WIM_APPLY_V1_LOGICAL_SECTOR_SIZE
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class WimApplyProtocolError(ValueError):
    """A WIM-apply request could not be represented exactly."""


@dataclass(frozen=True)
class WimApplyRequest:
    request_id: bytes
    parent_major: int
    parent_minor: int
    parent_disk_sequence: int
    parent_size: int
    logical_sector_size: int
    partition_major: int
    partition_minor: int
    partition_number: int
    partition_start: int
    partition_size: int
    source_size: int
    expanded_bytes: int
    image_index: int
    source_kind: int
    disk_guid: uuid.UUID
    partition_guid: uuid.UUID
    partition_type_guid: uuid.UUID
    partition_attributes: int
    ntfs_volume_serial: int
    source_sha256: str
    plan_sha256: str
    ready_sha256: str
    helper_profile: str = WIM_APPLY_HELPER_PROFILE
    operation: str = WIM_APPLY_OPERATION


def _uint(value: object, maximum: int, label: str, *, nonzero: bool = False) -> int:
    if type(value) is not int or value < int(nonzero) or value > maximum:
        qualifier = "non-zero " if nonzero else ""
        raise WimApplyProtocolError(f"The {label} must be a {qualifier}unsigned integer")
    return value


def _digest(value: object, label: str) -> str:
    if (
        type(value) is not str
        or _SHA256.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise WimApplyProtocolError(f"The {label} must be a non-zero lowercase SHA-256 digest")
    return value


def _guid(value: object, label: str) -> uuid.UUID:
    if type(value) is not uuid.UUID or value.int == 0:
        raise WimApplyProtocolError(f"The {label} must be a non-zero UUID")
    return value


def _device(major: object, minor: object, label: str) -> tuple[int, int]:
    major_number = _uint(major, 0xFFFFFFFF, f"{label} major number", nonzero=True)
    minor_number = _uint(minor, 0xFFFFFFFF, f"{label} minor number")
    try:
        encoded = os.makedev(major_number, minor_number)
    except (OverflowError, ValueError) as error:
        raise WimApplyProtocolError(f"The {label} device number is not representable") from error
    if os.major(encoded) != major_number or os.minor(encoded) != minor_number:
        raise WimApplyProtocolError(f"The {label} device number is not canonical")
    return major_number, minor_number


def validate_wim_apply_request(request: WimApplyRequest) -> None:
    """Validate candidate-v1 structure and its deliberately narrow policy."""

    if type(request) is not WimApplyRequest:
        raise WimApplyProtocolError("A WimApplyRequest is required")
    if (
        type(request.request_id) is not bytes
        or len(request.request_id) != 16
        or request.request_id == b"\0" * 16
    ):
        raise WimApplyProtocolError("The WIM-apply request ID must be 16 non-zero bytes")
    parent_device = _device(request.parent_major, request.parent_minor, "parent")
    partition_device = _device(request.partition_major, request.partition_minor, "partition")
    if parent_device == partition_device:
        raise WimApplyProtocolError("The Windows partition must differ from its parent disk")
    _uint(
        request.parent_disk_sequence,
        _UINT64_MAX,
        "parent disk sequence",
        nonzero=True,
    )
    parent_size = _uint(
        request.parent_size,
        WIM_APPLY_MAX_PARENT_BYTES,
        "parent size",
        nonzero=True,
    )
    if (
        parent_size < WIM_APPLY_V1_MINIMUM_PARENT_BYTES
        or parent_size % WIM_APPLY_V1_LOGICAL_SECTOR_SIZE
    ):
        raise WimApplyProtocolError("The WIM-apply parent size is outside candidate-v1 policy")
    sector_size = _uint(
        request.logical_sector_size,
        0xFFFFFFFF,
        "logical sector size",
        nonzero=True,
    )
    if sector_size != WIM_APPLY_V1_LOGICAL_SECTOR_SIZE:
        raise WimApplyProtocolError("Candidate-v1 requires 512-byte logical sectors")
    partition_number = _uint(
        request.partition_number,
        0xFFFFFFFF,
        "partition number",
        nonzero=True,
    )
    if partition_number != WIM_APPLY_WINDOWS_PARTITION_NUMBER:
        raise WimApplyProtocolError("Candidate-v1 requires the Windows partition to be number 3")
    partition_start = _uint(
        request.partition_start,
        _UINT64_MAX,
        "partition start",
        nonzero=True,
    )
    partition_size = _uint(
        request.partition_size,
        _UINT64_MAX,
        "partition size",
        nonzero=True,
    )
    parent_sectors = parent_size // WIM_APPLY_V1_LOGICAL_SECTOR_SIZE
    aligned_end_sectors = (
        (parent_sectors - _GPT_TAIL_SECTORS) // _ALIGNMENT_SECTORS
    ) * _ALIGNMENT_SECTORS
    expected_partition_size = (
        aligned_end_sectors * WIM_APPLY_V1_LOGICAL_SECTOR_SIZE - partition_start
    )
    if (
        partition_start != WIM_APPLY_WINDOWS_START_BYTES
        or partition_start % WIM_APPLY_V1_MIB
        or partition_size % WIM_APPLY_V1_MIB
        or partition_start > parent_size
        or partition_size > parent_size - partition_start
        or partition_size != expected_partition_size
    ):
        raise WimApplyProtocolError("The Windows partition geometry is outside the frozen layout")
    _uint(
        request.source_size,
        WIM_APPLY_MAX_SOURCE_BYTES,
        "WIM source size",
        nonzero=True,
    )
    expanded_bytes = _uint(
        request.expanded_bytes,
        _UINT64_MAX,
        "expanded image size",
        nonzero=True,
    )
    if (
        expanded_bytes > _UINT64_MAX - WIM_APPLY_V1_MINIMUM_FREE_BYTES
        or expanded_bytes + WIM_APPLY_V1_MINIMUM_FREE_BYTES > partition_size
    ):
        raise WimApplyProtocolError("The Windows partition lacks the required 8 GiB free floor")
    _uint(
        request.image_index,
        WIM_APPLY_MAX_IMAGE_INDEX,
        "WIM image index",
        nonzero=True,
    )
    source_kind = _uint(request.source_kind, 0xFFFFFFFF, "WIM-apply source kind")
    if source_kind != WIM_APPLY_SOURCE_KIND_WIM_CONTAINER:
        raise WimApplyProtocolError("The WIM-apply source kind is unsupported")
    disk_guid = _guid(request.disk_guid, "GPT disk GUID")
    partition_guid = _guid(request.partition_guid, "GPT partition GUID")
    if disk_guid == partition_guid:
        raise WimApplyProtocolError("The GPT disk and partition GUIDs must differ")
    if _guid(request.partition_type_guid, "GPT partition type GUID") != MICROSOFT_BASIC_DATA_GUID:
        raise WimApplyProtocolError("Candidate-v1 requires a Microsoft basic-data partition")
    partition_attributes = _uint(
        request.partition_attributes,
        _UINT64_MAX,
        "Windows-partition GPT attributes",
    )
    if partition_attributes != 0:
        raise WimApplyProtocolError("Candidate-v1 requires zero Windows-partition GPT attributes")
    _uint(
        request.ntfs_volume_serial,
        _UINT64_MAX,
        "NTFS volume serial",
        nonzero=True,
    )
    _digest(request.source_sha256, "WIM source digest")
    _digest(request.plan_sha256, "WIM-apply plan digest")
    _digest(request.ready_sha256, "WIM-apply ready digest")
    if (
        request.helper_profile != WIM_APPLY_HELPER_PROFILE
        or request.operation != WIM_APPLY_OPERATION
    ):
        raise WimApplyProtocolError("The WIM-apply profile or operation was modified")


def pack_wim_apply_request(request: WimApplyRequest) -> bytes:
    """Pack one exact request without resolving or opening any device."""

    validate_wim_apply_request(request)
    return WIM_APPLY_REQUEST_PACKET.pack(
        WIM_APPLY_PROTOCOL_MAGIC,
        WIM_APPLY_PROTOCOL_VERSION,
        WIM_APPLY_PACKET_REQUEST,
        WIM_APPLY_PACKET_FLAGS,
        request.request_id,
        request.parent_major,
        request.parent_minor,
        request.parent_disk_sequence,
        request.parent_size,
        request.logical_sector_size,
        request.partition_major,
        request.partition_minor,
        request.partition_number,
        request.partition_start,
        request.partition_size,
        request.source_size,
        request.expanded_bytes,
        request.image_index,
        request.source_kind,
        request.disk_guid.bytes,
        request.partition_guid.bytes,
        request.partition_type_guid.bytes,
        request.partition_attributes,
        request.ntfs_volume_serial,
        bytes.fromhex(request.source_sha256),
        bytes.fromhex(request.plan_sha256),
        bytes.fromhex(request.ready_sha256),
    )


def unpack_wim_apply_request(packet: bytes) -> WimApplyRequest:
    """Decode one request; root-side observation remains mandatory future work."""

    if type(packet) is not bytes or len(packet) != WIM_APPLY_REQUEST_BYTES:
        raise WimApplyProtocolError("The WIM-apply request packet has the wrong size")
    fields = WIM_APPLY_REQUEST_PACKET.unpack(packet)
    magic, version, packet_type, packet_flags = fields[:4]
    if (
        magic != WIM_APPLY_PROTOCOL_MAGIC
        or version != WIM_APPLY_PROTOCOL_VERSION
        or packet_type != WIM_APPLY_PACKET_REQUEST
        or packet_flags != WIM_APPLY_PACKET_FLAGS
    ):
        raise WimApplyProtocolError("The WIM-apply request packet is unsupported")
    request = WimApplyRequest(
        request_id=fields[4],
        parent_major=fields[5],
        parent_minor=fields[6],
        parent_disk_sequence=fields[7],
        parent_size=fields[8],
        logical_sector_size=fields[9],
        partition_major=fields[10],
        partition_minor=fields[11],
        partition_number=fields[12],
        partition_start=fields[13],
        partition_size=fields[14],
        source_size=fields[15],
        expanded_bytes=fields[16],
        image_index=fields[17],
        source_kind=fields[18],
        disk_guid=uuid.UUID(bytes=fields[19]),
        partition_guid=uuid.UUID(bytes=fields[20]),
        partition_type_guid=uuid.UUID(bytes=fields[21]),
        partition_attributes=fields[22],
        ntfs_volume_serial=fields[23],
        source_sha256=fields[24].hex(),
        plan_sha256=fields[25].hex(),
        ready_sha256=fields[26].hex(),
    )
    validate_wim_apply_request(request)
    if pack_wim_apply_request(request) != packet:
        raise WimApplyProtocolError("The WIM-apply request packet is not canonical")
    return request
