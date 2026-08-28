# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import struct
import unittest
import uuid

from isopropyl.windows_bcd import (
    BCD_PARTITION_DEVICE_BYTES,
    BcdError,
    BcdPartitionScheme,
    decode_candidate_qualified_partition,
    encode_candidate_gpt_qualified_partition,
    encode_candidate_mbr_qualified_partition,
)


DISK_GUID = uuid.UUID("01234567-89ab-cdef-8123-456789abcdef")
PARTITION_GUID = uuid.UUID("fedcba98-7654-3210-8fed-cba987654321")


class WindowsBcdQualifiedPartitionCandidateTests(unittest.TestCase):
    def test_gpt_encoding_matches_the_open_source_candidate_wire_offsets(self):
        payload = encode_candidate_gpt_qualified_partition(DISK_GUID, PARTITION_GUID)
        self.assertEqual(len(payload), BCD_PARTITION_DEVICE_BYTES)
        expected = bytearray(88)
        expected[0x10:0x14] = (6).to_bytes(4, "little")
        expected[0x18:0x1C] = (0x48).to_bytes(4, "little")
        expected[0x20:0x30] = bytes.fromhex(
            "98badcfe547610328fedcba987654321"
        )
        expected[0x34:0x38] = (0).to_bytes(4, "little")
        expected[0x38:0x48] = bytes.fromhex(
            "67452301ab89efcd8123456789abcdef"
        )
        self.assertEqual(payload, bytes(expected))
        decoded = decode_candidate_qualified_partition(payload)
        self.assertEqual(decoded.scheme, BcdPartitionScheme.GPT)
        self.assertEqual(decoded.disk_guid, DISK_GUID)
        self.assertEqual(decoded.partition_guid, PARTITION_GUID)
        self.assertIsNone(decoded.disk_signature)

    def test_mbr_encoding_uses_offset_and_signature_with_zero_extended_slots(self):
        payload = encode_candidate_mbr_qualified_partition(0xA1B2C3D4, 2048 * 512)
        self.assertEqual(payload[0x20:0x28], (1048576).to_bytes(8, "little"))
        self.assertEqual(payload[0x28:0x30], b"\0" * 8)
        self.assertEqual(struct.unpack_from("<I", payload, 0x34)[0], 1)
        self.assertEqual(payload[0x38:0x3C], bytes.fromhex("d4c3b2a1"))
        self.assertEqual(payload[0x3C:0x48], b"\0" * 12)
        decoded = decode_candidate_qualified_partition(payload)
        self.assertEqual(decoded.scheme, BcdPartitionScheme.MBR)
        self.assertEqual(decoded.disk_signature, 0xA1B2C3D4)
        self.assertEqual(decoded.partition_offset, 1048576)
        self.assertIsNone(decoded.disk_guid)

    def test_rejects_invalid_inputs_without_truncation_or_normalization(self):
        for disk, partition in (
            (uuid.UUID(int=0), PARTITION_GUID),
            (DISK_GUID, uuid.UUID(int=0)),
            ("not-a-guid", str(PARTITION_GUID)),
        ):
            with self.subTest(disk=disk, partition=partition), self.assertRaises(BcdError):
                encode_candidate_gpt_qualified_partition(disk, partition)
        for signature, offset in (
            (0, 1048576),
            (0x1_0000_0000, 1048576),
            (True, 1048576),
            (1, 0),
            (1, 513),
            (1, True),
        ):
            with self.subTest(signature=signature, offset=offset), self.assertRaises(BcdError):
                encode_candidate_mbr_qualified_partition(signature, offset)

    def test_parser_rejects_header_reserved_style_and_identity_corruption(self):
        valid_gpt = encode_candidate_gpt_qualified_partition(DISK_GUID, PARTITION_GUID)
        corruptions = []
        for offset in (0x00, 0x14, 0x1C, 0x30, 0x48, 0x57):
            changed = bytearray(valid_gpt)
            changed[offset] = 1
            corruptions.append(bytes(changed))
        for offset, value in ((0x10, 5), (0x18, 0x47), (0x34, 2)):
            changed = bytearray(valid_gpt)
            struct.pack_into("<I", changed, offset, value)
            corruptions.append(bytes(changed))
        corruptions.extend((b"", valid_gpt[:-1], valid_gpt + b"\0"))
        for payload in corruptions:
            with self.subTest(payload=payload.hex()), self.assertRaises(BcdError):
                decode_candidate_qualified_partition(payload)

        for identity_slice in (slice(0x20, 0x30), slice(0x38, 0x48)):
            changed = bytearray(valid_gpt)
            changed[identity_slice] = b"\0" * 16
            with self.assertRaises(BcdError):
                decode_candidate_qualified_partition(bytes(changed))

        valid_mbr = encode_candidate_mbr_qualified_partition(1, 1048576)
        for offset in (0x28, 0x3C):
            changed = bytearray(valid_mbr)
            changed[offset] = 1
            with self.assertRaises(BcdError):
                decode_candidate_qualified_partition(bytes(changed))

        for identity_slice, replacement in (
            (slice(0x20, 0x28), b"\0" * 8),
            (slice(0x20, 0x28), (513).to_bytes(8, "little")),
            (slice(0x38, 0x3C), b"\0" * 4),
        ):
            changed = bytearray(valid_mbr)
            changed[identity_slice] = replacement
            with self.assertRaises(BcdError):
                decode_candidate_qualified_partition(bytes(changed))


if __name__ == "__main__":
    unittest.main()
