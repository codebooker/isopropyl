# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import dataclasses
import struct
import unittest
import uuid

from isopropyl.wim_apply_protocol import (
    MICROSOFT_BASIC_DATA_GUID,
    WIM_APPLY_MAX_IMAGE_INDEX,
    WIM_APPLY_PACKET_REQUEST,
    WIM_APPLY_PROTOCOL_MAGIC,
    WIM_APPLY_PROTOCOL_VERSION,
    WIM_APPLY_REQUEST_BYTES,
    WIM_APPLY_SOURCE_KIND_WIM_CONTAINER,
    WIM_APPLY_WINDOWS_START_BYTES,
    WimApplyProtocolError,
    WimApplyRequest,
    pack_wim_apply_request,
    unpack_wim_apply_request,
    validate_wim_apply_request,
)
from isopropyl.windows_to_go import (
    MINIMUM_FREE_BYTES,
    MINIMUM_TARGET_BYTES,
    RUFUS_ESP_BYTES,
    RUFUS_MSR_BYTES,
    SUPPORTED_LOGICAL_SECTOR_SIZE,
)


GIB = 1024**3
MIB = 1024**2
DISK_GUID = uuid.UUID("01234567-89ab-cdef-8123-456789abcdef")
PARTITION_GUID = uuid.UUID("fedcba98-7654-3210-8fed-cba987654321")


def request(**changes: object) -> WimApplyRequest:
    base = WimApplyRequest(
        request_id=bytes.fromhex("00112233445566778899aabbccddeeff"),
        parent_major=8,
        parent_minor=16,
        parent_disk_sequence=41,
        parent_size=64 * GIB,
        logical_sector_size=512,
        partition_major=8,
        partition_minor=19,
        partition_number=3,
        partition_start=WIM_APPLY_WINDOWS_START_BYTES,
        partition_size=64 * GIB - 390 * MIB,
        source_size=6 * GIB,
        expanded_bytes=20 * GIB,
        image_index=3,
        source_kind=WIM_APPLY_SOURCE_KIND_WIM_CONTAINER,
        disk_guid=DISK_GUID,
        partition_guid=PARTITION_GUID,
        partition_type_guid=MICROSOFT_BASIC_DATA_GUID,
        partition_attributes=0,
        ntfs_volume_serial=0x0123456789ABCDEF,
        source_sha256="11" * 32,
        plan_sha256="22" * 32,
        ready_sha256="33" * 32,
    )
    return dataclasses.replace(base, **changes)


class WimApplyProtocolTests(unittest.TestCase):
    def test_exact_packet_layout_and_round_trip(self):
        value = request()
        packet = pack_wim_apply_request(value)
        self.assertEqual(len(packet), WIM_APPLY_REQUEST_BYTES)
        self.assertEqual(WIM_APPLY_REQUEST_BYTES, 276)
        self.assertEqual(packet[:16], WIM_APPLY_PROTOCOL_MAGIC)
        self.assertEqual(packet[16], WIM_APPLY_PROTOCOL_VERSION)
        self.assertEqual(packet[17], WIM_APPLY_PACKET_REQUEST)
        self.assertEqual(packet[18:20], b"\0\0")
        self.assertEqual(packet[20:36], value.request_id)
        self.assertEqual(struct.unpack_from("!II", packet, 36), (8, 16))
        self.assertEqual(struct.unpack_from("!QQ", packet, 44), (41, 64 * GIB))
        self.assertEqual(struct.unpack_from("!IIII", packet, 60), (512, 8, 19, 3))
        self.assertEqual(
            struct.unpack_from("!QQQQII", packet, 76),
            (
                WIM_APPLY_WINDOWS_START_BYTES,
                64 * GIB - 390 * MIB,
                6 * GIB,
                20 * GIB,
                3,
                WIM_APPLY_SOURCE_KIND_WIM_CONTAINER,
            ),
        )
        self.assertEqual(packet[116:132], DISK_GUID.bytes)
        self.assertEqual(packet[132:148], PARTITION_GUID.bytes)
        self.assertEqual(packet[148:164], MICROSOFT_BASIC_DATA_GUID.bytes)
        self.assertEqual(struct.unpack_from("!QQ", packet, 164), (0, 0x0123456789ABCDEF))
        self.assertEqual(packet[180:212], b"\x11" * 32)
        self.assertEqual(packet[212:244], b"\x22" * 32)
        self.assertEqual(packet[244:276], b"\x33" * 32)
        self.assertEqual(unpack_wim_apply_request(packet), value)

    def test_v1_literals_match_the_current_planner_and_parser_profiles(self):
        self.assertEqual(WIM_APPLY_MAX_IMAGE_INDEX, 2_147_483_647)
        validate_wim_apply_request(request(image_index=2_147_483_647))
        self.assertEqual(
            WIM_APPLY_WINDOWS_START_BYTES,
            MIB + RUFUS_ESP_BYTES + RUFUS_MSR_BYTES,
        )
        self.assertEqual(MINIMUM_TARGET_BYTES, 32 * GIB)
        self.assertEqual(MINIMUM_FREE_BYTES, 8 * GIB)
        self.assertEqual(SUPPORTED_LOGICAL_SECTOR_SIZE, 512)
        self.assertEqual(
            DISK_GUID.bytes,
            bytes.fromhex("0123456789abcdef8123456789abcdef"),
        )
        self.assertEqual(
            PARTITION_GUID.bytes,
            bytes.fromhex("fedcba98765432108fedcba987654321"),
        )

    def test_v1_floor_is_on_parent_and_selected_image_has_eight_gib_free(self):
        minimum = request(
            parent_size=32 * GIB,
            partition_size=32 * GIB - 390 * MIB,
            expanded_bytes=20 * GIB,
        )
        validate_wim_apply_request(minimum)
        self.assertEqual(
            unpack_wim_apply_request(pack_wim_apply_request(minimum)),
            minimum,
        )

    def test_rejects_identity_geometry_capacity_and_selection_confusion(self):
        invalid = (
            {"request_id": b"\0" * 16},
            {"request_id": b"short"},
            {"parent_major": True},
            {"parent_major": 0x1_0000_0000},
            {"parent_disk_sequence": 0},
            {"parent_size": 31 * GIB},
            {"parent_size": 64 * GIB + 1},
            {"logical_sector_size": 4096},
            {"partition_minor": 16},
            {"partition_number": 2},
            {"partition_number": 3.0},
            {"partition_start": WIM_APPLY_WINDOWS_START_BYTES + MIB},
            {"partition_size": 63 * GIB},
            {"partition_size": 63 * GIB + 1},
            {"partition_size": 64 * GIB},
            {"source_size": 0},
            {"source_size": 129 * GIB},
            {"expanded_bytes": 0},
            {"expanded_bytes": 56 * GIB},
            {"image_index": 0},
            {"image_index": 2_147_483_648},
            {"image_index": True},
            {"source_kind": 2},
            {"source_kind": True},
            {"disk_guid": uuid.UUID(int=0)},
            {"partition_guid": DISK_GUID},
            {"partition_type_guid": PARTITION_GUID},
            {"partition_attributes": 1},
            {"partition_attributes": False},
            {"ntfs_volume_serial": 0},
            {"source_sha256": "0" * 64},
            {"source_sha256": "AA" * 32},
            {"plan_sha256": "2" * 63},
            {"ready_sha256": "g" * 64},
            {"helper_profile": "changed"},
            {"operation": "changed"},
        )
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(WimApplyProtocolError):
                validate_wim_apply_request(request(**changes))

    def test_unpack_rejects_header_and_length_mutations(self):
        valid = pack_wim_apply_request(request())
        mutations = []
        for offset in (0, 16, 17, 18, 19):
            changed = bytearray(valid)
            changed[offset] ^= 0x01
            mutations.append(bytes(changed))
        mutations.extend((b"", valid[:-1], valid + b"\0"))
        for packet in mutations:
            with self.subTest(packet=packet.hex()), self.assertRaises(WimApplyProtocolError):
                unpack_wim_apply_request(packet)

    def test_unpack_revalidates_semantic_fields_and_nonzero_digests(self):
        valid = pack_wim_apply_request(request())
        mutations = (
            (20, b"\0" * 16),
            (44, (0).to_bytes(8, "big")),
            (60, (4096).to_bytes(4, "big")),
            (68, (16).to_bytes(4, "big")),
            (72, (2).to_bytes(4, "big")),
            (76, (390 * MIB).to_bytes(8, "big")),
            (108, (0).to_bytes(4, "big")),
            (112, (2).to_bytes(4, "big")),
            (116, b"\0" * 16),
            (148, PARTITION_GUID.bytes),
            (164, (1).to_bytes(8, "big")),
            (172, b"\0" * 8),
            (180, b"\0" * 32),
        )
        for offset, replacement in mutations:
            changed = bytearray(valid)
            changed[offset : offset + len(replacement)] = replacement
            with self.subTest(offset=offset), self.assertRaises(WimApplyProtocolError):
                unpack_wim_apply_request(bytes(changed))


if __name__ == "__main__":
    unittest.main()
