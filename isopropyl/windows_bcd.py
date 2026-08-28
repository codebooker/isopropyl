"""Fixture-gated candidate BCD qualified-partition record serialization.

This is a narrow, deterministic primitive for a future native Linux BCD
transformer.  It does not edit registry hives and does not authorize boot-store
publication.  Windows BCDBoot differential fixtures and QEMU/OVMF certification
remain mandatory before callers may use generated records on physical media.

The internal hive records decoded by DiscUtils and emitted by BCD-SYS use 0 for
GPT and 1 for MBR.  Microsoft's public BcdDeviceQualifiedPartitionData WMI
contract documents the opposite numeric values.  The candidate wire mapping is
therefore deliberately private and must not be confused with the public API.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from enum import Enum

BCD_PARTITION_DEVICE_BYTES = 88
BCD_DEVICE_TYPE_QUALIFIED_PARTITION = 6
BCD_PARTITION_RECORD_BYTES = 0x48
BCD_BOOTMGR_DEVICE_ELEMENT = 0x11000001
BCD_OSLOADER_DEVICE_ELEMENT = 0x11000001
BCD_OSLOADER_OSDEVICE_ELEMENT = 0x21000001
BCD_RECOVERY_ENABLED_ELEMENT = 0x16000009


class BcdError(ValueError):
    pass


class BcdPartitionScheme(Enum):
    GPT = "gpt"
    MBR = "mbr"


_CANDIDATE_HIVE_SCHEME_GPT = 0
_CANDIDATE_HIVE_SCHEME_MBR = 1


@dataclass(frozen=True)
class CandidateBcdQualifiedPartition:
    scheme: BcdPartitionScheme
    disk_guid: uuid.UUID | None = None
    partition_guid: uuid.UUID | None = None
    disk_signature: int | None = None
    partition_offset: int | None = None


def _guid(value: uuid.UUID | str, label: str) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        parsed = value
    else:
        if type(value) is not str:
            raise BcdError(f"The {label} must be a UUID")
        try:
            parsed = uuid.UUID(value)
        except (AttributeError, ValueError) as error:
            raise BcdError(f"The {label} must be a UUID") from error
    if parsed.int == 0:
        raise BcdError(f"The {label} must not be the zero UUID")
    return parsed


def _record(partition_identity: bytes, hive_scheme: int, disk_identity: bytes) -> bytes:
    if len(partition_identity) != 16 or len(disk_identity) != 16:
        raise BcdError("BCD partition identities must occupy exactly 16 bytes")
    payload = bytearray(BCD_PARTITION_DEVICE_BYTES)
    struct.pack_into("<I", payload, 0x10, BCD_DEVICE_TYPE_QUALIFIED_PARTITION)
    struct.pack_into("<I", payload, 0x18, BCD_PARTITION_RECORD_BYTES)
    payload[0x20:0x30] = partition_identity
    if hive_scheme not in (_CANDIDATE_HIVE_SCHEME_GPT, _CANDIDATE_HIVE_SCHEME_MBR):
        raise BcdError("The candidate BCD hive scheme is unsupported")
    struct.pack_into("<I", payload, 0x34, hive_scheme)
    payload[0x38:0x48] = disk_identity
    return bytes(payload)


def encode_candidate_gpt_qualified_partition(
    disk_guid: uuid.UUID | str,
    partition_guid: uuid.UUID | str,
) -> bytes:
    """Encode a fixture-gated type-6 GPT record in EFI GUID byte order."""

    disk = _guid(disk_guid, "GPT disk GUID")
    partition = _guid(partition_guid, "GPT partition GUID")
    return _record(partition.bytes_le, _CANDIDATE_HIVE_SCHEME_GPT, disk.bytes_le)


def encode_candidate_mbr_qualified_partition(
    disk_signature: int,
    partition_offset: int,
) -> bytes:
    """Encode a fixture-gated type-6 MBR record without device discovery."""

    if (
        type(disk_signature) is not int
        or isinstance(disk_signature, bool)
        or not 0 < disk_signature <= 0xFFFFFFFF
    ):
        raise BcdError("The MBR disk signature must be a non-zero 32-bit integer")
    if (
        type(partition_offset) is not int
        or isinstance(partition_offset, bool)
        or partition_offset <= 0
        or partition_offset > 0xFFFFFFFFFFFFFFFF
        or partition_offset % 512
    ):
        raise BcdError("The MBR partition offset must be a positive sector-aligned byte offset")
    partition = partition_offset.to_bytes(16, "little")
    disk = disk_signature.to_bytes(4, "little") + b"\0" * 12
    return _record(partition, _CANDIDATE_HIVE_SCHEME_MBR, disk)


def decode_candidate_qualified_partition(
    payload: bytes,
) -> CandidateBcdQualifiedPartition:
    """Parse one candidate internal qualified-partition record."""

    if type(payload) is not bytes or len(payload) != BCD_PARTITION_DEVICE_BYTES:
        raise BcdError("A BCD partition device must be exactly 88 bytes")
    if (
        any(payload[0x00:0x10])
        or struct.unpack_from("<I", payload, 0x10)[0]
        != BCD_DEVICE_TYPE_QUALIFIED_PARTITION
        or any(payload[0x14:0x18])
        or struct.unpack_from("<I", payload, 0x18)[0] != BCD_PARTITION_RECORD_BYTES
        or any(payload[0x1C:0x20])
        or any(payload[0x30:0x34])
        or any(payload[0x48:0x58])
    ):
        raise BcdError("The BCD partition device header or reserved bytes are invalid")
    hive_scheme = struct.unpack_from("<I", payload, 0x34)[0]
    if hive_scheme == _CANDIDATE_HIVE_SCHEME_GPT:
        scheme = BcdPartitionScheme.GPT
    elif hive_scheme == _CANDIDATE_HIVE_SCHEME_MBR:
        scheme = BcdPartitionScheme.MBR
    else:
        raise BcdError("The candidate BCD hive scheme is unsupported")
    partition_identity = payload[0x20:0x30]
    disk_identity = payload[0x38:0x48]
    if scheme is BcdPartitionScheme.GPT:
        partition = uuid.UUID(bytes_le=partition_identity)
        disk = uuid.UUID(bytes_le=disk_identity)
        if partition.int == 0 or disk.int == 0:
            raise BcdError("GPT BCD device GUIDs must not be zero")
        return CandidateBcdQualifiedPartition(scheme, disk, partition)
    if any(partition_identity[8:]) or any(disk_identity[4:]):
        raise BcdError("The MBR BCD device contains non-zero reserved identity bytes")
    offset = int.from_bytes(partition_identity[:8], "little")
    signature = int.from_bytes(disk_identity[:4], "little")
    if not offset or offset % 512 or not signature:
        raise BcdError("The MBR BCD partition identity is invalid")
    return CandidateBcdQualifiedPartition(
        scheme,
        disk_signature=signature,
        partition_offset=offset,
    )
