from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from isopropyl.partition_tables import (
    PARTITION_TABLE_CAPTURE_BYTES,
    PartitionTableError,
    inspect_partition_tables_capture,
    inspect_partition_tables_fd,
)


GPT_HEADER = struct.Struct("<8sIIIIQQQQ16sQIII")
MBR_ENTRY = struct.Struct("<B3sB3sII")


def _chs(lba: int) -> bytes:
    maximum = (1024 * 255 * 63) - 1
    if lba < 0 or lba > maximum:
        return b"\xff\xff\xff"
    cylinder, track_offset = divmod(lba, 255 * 63)
    head, sector_offset = divmod(track_offset, 63)
    return bytes((
        head,
        sector_offset + 1 | ((cylinder >> 2) & 0xC0),
        cylinder & 0xFF,
    ))


def mbr_image(
    *,
    sectors: int = 128,
    sector_size: int = 512,
    partitions: tuple[tuple[int, int, int], ...] = ((0x0C, 1, 127),),
    boot_marker: bytes = b"",
) -> bytearray:
    data = bytearray(sectors * sector_size)
    data[:len(boot_marker)] = boot_marker
    ordinary_bootable = False
    for index, (partition_type, start, count) in enumerate(partitions):
        status = 0
        if partition_type != 0xEE and not ordinary_bootable:
            status = 0x80
            ordinary_bootable = True
        MBR_ENTRY.pack_into(
            data, 446 + index * 16, status,
            _chs(start), partition_type, _chs(start + count - 1), start, count,
        )
    data[510:512] = b"\x55\xaa"
    return data


def _gpt_header(
    sector_size: int,
    *,
    current_lba: int,
    backup_lba: int,
    first_usable: int,
    last_usable: int,
    disk_guid: bytes,
    entry_lba: int,
    entry_count: int,
    entry_size: int,
    entry_crc: int,
) -> bytes:
    sector = bytearray(sector_size)
    GPT_HEADER.pack_into(
        sector, 0, b"EFI PART", 0x00010000, GPT_HEADER.size, 0, 0,
        current_lba, backup_lba, first_usable, last_usable, disk_guid,
        entry_lba, entry_count, entry_size, entry_crc,
    )
    crc = zlib.crc32(sector[:GPT_HEADER.size]) & 0xFFFFFFFF
    struct.pack_into("<I", sector, 16, crc)
    return bytes(sector)


def gpt_image(
    sector_size: int = 512,
    *,
    total_sectors: int = 256,
    hybrid: bool = False,
    overlapping: bool = False,
    entry_count: int = 128,
    entry_size: int = 128,
    primary_entry_lba: int = 2,
    backup_entry_lba: int | None = None,
) -> bytearray:
    array = bytearray(entry_count * entry_size)
    array_sectors = (len(array) + sector_size - 1) // sector_size
    first_usable = primary_entry_lba + array_sectors
    if backup_entry_lba is None:
        backup_entry_lba = total_sectors - 1 - array_sectors
    last_usable = backup_entry_lba - 1
    first_end = first_usable + 7
    array[0:16] = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")
    array[16:32] = bytes.fromhex("00112233445566778899aabbccddeeff")
    struct.pack_into("<QQ", array, 32, first_usable, first_end)
    if overlapping:
        offset = entry_size
        array[offset:offset + 16] = bytes.fromhex("af3dc60f838472478e793d69d8477de4")
        array[offset + 16:offset + 32] = bytes.fromhex(
            "102132435465768798a9bacbdcedfe0f"
        )
        struct.pack_into("<QQ", array, offset + 32, first_end, first_end + 4)
    entry_crc = zlib.crc32(array) & 0xFFFFFFFF
    disk_guid = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    hybrid_entries = ((0x83, first_usable, 8),) if hybrid else ()
    data = mbr_image(
        sectors=total_sectors,
        sector_size=sector_size,
        partitions=(
            (0xEE, 1, min(total_sectors - 1, 0xFFFFFFFF)),
            *hybrid_entries,
        ),
    )
    primary = _gpt_header(
        sector_size, current_lba=1, backup_lba=total_sectors - 1,
        first_usable=first_usable, last_usable=last_usable,
        disk_guid=disk_guid, entry_lba=primary_entry_lba, entry_count=entry_count,
        entry_size=entry_size, entry_crc=entry_crc,
    )
    backup = _gpt_header(
        sector_size, current_lba=total_sectors - 1, backup_lba=1,
        first_usable=first_usable, last_usable=last_usable,
        disk_guid=disk_guid, entry_lba=backup_entry_lba,
        entry_count=entry_count, entry_size=entry_size, entry_crc=entry_crc,
    )
    data[sector_size:2 * sector_size] = primary
    start = primary_entry_lba * sector_size
    data[start:start + len(array)] = array
    start = backup_entry_lba * sector_size
    data[start:start + len(array)] = array
    start = (total_sectors - 1) * sector_size
    data[start:start + sector_size] = backup
    return data


def refresh_gpt_crcs(payload: bytearray, sector_size: int = 512) -> None:
    total_sectors = len(payload) // sector_size
    for header_lba in (1, total_sectors - 1):
        header_offset = header_lba * sector_size
        header = bytearray(payload[header_offset:header_offset + sector_size])
        entry_lba, entry_count, entry_size = struct.unpack_from("<QII", header, 72)
        array_offset = entry_lba * sector_size
        array_length = entry_count * entry_size
        array_crc = zlib.crc32(
            payload[array_offset:array_offset + array_length]
        ) & 0xFFFFFFFF
        struct.pack_into("<I", header, 88, array_crc)
        struct.pack_into("<I", header, 16, 0)
        header_size = struct.unpack_from("<I", header, 12)[0]
        struct.pack_into(
            "<I", header, 16,
            zlib.crc32(header[:header_size]) & 0xFFFFFFFF,
        )
        payload[header_offset:header_offset + sector_size] = header


def inspect_bytes(payload: bytes):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "disk.img"
        path.write_bytes(payload)
        descriptor = os.open(path, os.O_RDONLY)
        try:
            return inspect_partition_tables_fd(descriptor)
        finally:
            os.close(descriptor)


class PartitionTableTests(unittest.TestCase):
    def test_valid_mbr_and_boot_code_are_classified(self):
        marker = b"SYSLINUX boot code"
        result = inspect_bytes(mbr_image(boot_marker=marker))
        self.assertTrue(result.has_mbr)
        self.assertFalse(result.has_gpt)
        self.assertTrue(result.valid)
        self.assertEqual(result.kind, "mbr")
        self.assertEqual(result.sector_size, 512)
        self.assertEqual(result.mbr_boot_code, "syslinux")

    def test_signature_only_and_overlapping_mbr_are_malformed(self):
        signature_only = bytearray(4096)
        signature_only[510:512] = b"\x55\xaa"
        result = inspect_bytes(signature_only)
        self.assertTrue(result.malformed)
        self.assertIn("no usable partition", " ".join(result.issues))

        overlapping = mbr_image(
            partitions=((0x83, 1, 40), (0x0C, 20, 40)),
        )
        result = inspect_bytes(overlapping)
        self.assertTrue(result.malformed)
        self.assertIn("overlap", " ".join(result.issues))

    def test_extended_mbr_chain_is_bounded_and_structurally_validated(self):
        payload = mbr_image(partitions=((0x0F, 1, 100),))
        # First EBR: one logical partition and a link, relative to the extended
        # base, to the second EBR.
        first_ebr = 1 * 512
        MBR_ENTRY.pack_into(
            payload, first_ebr + 446, 0, b"\0\0\0", 0x83,
            b"\0\0\0", 1, 10,
        )
        MBR_ENTRY.pack_into(
            payload, first_ebr + 462, 0, b"\0\0\0", 0x0F,
            b"\0\0\0", 20, 80,
        )
        payload[first_ebr + 510:first_ebr + 512] = b"\x55\xaa"
        second_ebr = 21 * 512
        MBR_ENTRY.pack_into(
            payload, second_ebr + 446, 0, b"\0\0\0", 0x83,
            b"\0\0\0", 1, 10,
        )
        payload[second_ebr + 510:second_ebr + 512] = b"\x55\xaa"
        result = inspect_bytes(payload)
        self.assertTrue(result.valid, result.issues)

        # Make the second EBR point to itself. The bounded parser must identify
        # the loop instead of following it indefinitely.
        MBR_ENTRY.pack_into(
            payload, second_ebr + 462, 0, b"\0\0\0", 0x0F,
            b"\0\0\0", 20, 80,
        )
        result = inspect_bytes(payload)
        self.assertTrue(result.malformed)
        self.assertIn("loop", " ".join(result.issues))

    def test_protective_mbr_without_gpt_is_malformed(self):
        result = inspect_bytes(mbr_image(partitions=((0xEE, 1, 127),)))
        self.assertTrue(result.malformed)
        self.assertEqual(result.mbr_kind, "protective")
        self.assertIn("no valid primary GPT", " ".join(result.issues))

    def test_valid_primary_and_backup_gpt_for_512_and_4096_sectors(self):
        for sector_size in (512, 4096):
            with self.subTest(sector_size=sector_size):
                result = inspect_bytes(gpt_image(sector_size))
                self.assertTrue(result.has_mbr)
                self.assertTrue(result.has_gpt)
                self.assertTrue(result.valid, result.issues)
                self.assertFalse(result.malformed)
                self.assertTrue(result.complete)
                self.assertEqual(result.kind, "gpt")
                self.assertEqual(result.sector_size, sector_size)

    def test_gpt_revision_and_reserved_header_padding_are_mandatory(self):
        bad_revision = gpt_image()
        for header_lba in (1, 255):
            struct.pack_into("<I", bad_revision, header_lba * 512 + 8, 0x00010001)
        refresh_gpt_crcs(bad_revision)
        result = inspect_bytes(bad_revision)
        self.assertTrue(result.malformed)
        self.assertIn("revision", " ".join(result.issues))

        bad_padding = gpt_image()
        bad_padding[512 + GPT_HEADER.size] = 0xA5
        bad_padding[255 * 512 + GPT_HEADER.size] = 0x5A
        # Reserved header padding is outside HeaderSize and therefore outside
        # the header CRC.  This proves the zero check is independent of CRC.
        result = inspect_bytes(bad_padding)
        self.assertTrue(result.malformed)
        self.assertIn("reserved padding", " ".join(result.issues))

    def test_gpt_entry_size_reserved_bytes_and_attributes_are_validated(self):
        bad_size = gpt_image(entry_size=136)
        result = inspect_bytes(bad_size)
        self.assertTrue(result.malformed)
        self.assertIn("entry size", " ".join(result.issues))

        bad_reserved = gpt_image(entry_size=256)
        primary_entry_lba = struct.unpack_from("<Q", bad_reserved, 512 + 72)[0]
        backup_entry_lba = struct.unpack_from("<Q", bad_reserved, 255 * 512 + 72)[0]
        for entry_lba in (primary_entry_lba, backup_entry_lba):
            bad_reserved[entry_lba * 512 + 128] = 1
        refresh_gpt_crcs(bad_reserved)
        result = inspect_bytes(bad_reserved)
        self.assertTrue(result.malformed)
        self.assertIn("reserved bytes", " ".join(result.issues))

        bad_attributes = gpt_image()
        primary_entry_lba = struct.unpack_from("<Q", bad_attributes, 512 + 72)[0]
        backup_entry_lba = struct.unpack_from("<Q", bad_attributes, 255 * 512 + 72)[0]
        for entry_lba in (primary_entry_lba, backup_entry_lba):
            # Bits 0-2 are defined by UEFI; bits 3-47 are undefined and zero.
            struct.pack_into("<Q", bad_attributes, entry_lba * 512 + 48, 1 << 3)
        refresh_gpt_crcs(bad_attributes)
        result = inspect_bytes(bad_attributes)
        self.assertTrue(result.malformed)
        self.assertIn("undefined attribute", " ".join(result.issues))

        unterminated_name = gpt_image()
        primary_entry_lba = struct.unpack_from(
            "<Q", unterminated_name, 512 + 72,
        )[0]
        backup_entry_lba = struct.unpack_from(
            "<Q", unterminated_name, 255 * 512 + 72,
        )[0]
        for entry_lba in (primary_entry_lba, backup_entry_lba):
            unterminated_name[
                entry_lba * 512 + 56:entry_lba * 512 + 128
            ] = b"A\0" * 36
        refresh_gpt_crcs(unterminated_name)
        result = inspect_bytes(unterminated_name)
        self.assertTrue(result.malformed)
        self.assertIn("null-terminated UTF-16", " ".join(result.issues))

    def test_gpt_reserves_minimum_entry_array_space_at_both_ends(self):
        for sector_size in (512, 4096):
            with self.subTest(sector_size=sector_size):
                payload = gpt_image(
                    sector_size, entry_count=1, entry_size=128,
                )
                result = inspect_bytes(payload)
                self.assertTrue(result.malformed)
                self.assertIn("required 16 KiB", " ".join(result.issues))

    def test_protective_mbr_mandatory_fields_are_validated(self):
        mutations = {
            "bootable": lambda payload: payload.__setitem__(446, 0x80),
            "disk signature": lambda payload: payload.__setitem__(440, 1),
            "reserved field": lambda payload: payload.__setitem__(444, 1),
            "starting CHS": lambda payload: payload.__setitem__(447, 1),
            "ending CHS": lambda payload: payload.__setitem__(451, 1),
            "unused record": lambda payload: payload.__setitem__(463, 1),
            "signature": lambda payload: payload.__setitem__(510, 0),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                payload = gpt_image()
                mutate(payload)
                result = inspect_bytes(payload)
                self.assertTrue(result.malformed, (label, result))

        reserved_tail = gpt_image(4096)
        reserved_tail[512] = 1
        result = inspect_bytes(reserved_tail)
        self.assertTrue(result.malformed)
        self.assertIn("reserved logical-block tail", " ".join(result.issues))

    def test_standard_protective_ending_chs_sentinel_is_accepted(self):
        payload = gpt_image()
        payload[451:454] = b"\xff\xff\xff"

        result = inspect_bytes(payload)

        self.assertTrue(result.valid, result.issues)

    def test_gnu_parted_gpt_is_accepted_when_available(self):
        parted = shutil.which("parted")
        if not parted:
            self.skipTest("GNU Parted is not installed")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "parted-gpt.img"
            with path.open("wb") as stream:
                stream.truncate(64 * 1024**2)
            subprocess.run(
                [parted, "-s", str(path), "mklabel", "gpt"],
                check=True, capture_output=True, timeout=15,
            )
            descriptor = os.open(path, os.O_RDONLY)
            try:
                result = inspect_partition_tables_fd(descriptor)
            finally:
                os.close(descriptor)

        self.assertTrue(result.valid, result.issues)

    def test_hybrid_mbr_can_retain_legacy_disk_signature_semantics(self):
        payload = gpt_image(hybrid=True)
        payload[440:444] = b"\x12\x34\x56\x78"
        result = inspect_bytes(payload)
        self.assertTrue(result.valid, result.issues)
        self.assertEqual(result.kind, "hybrid-gpt")

    def test_hybrid_gpt_is_distinguished(self):
        result = inspect_bytes(gpt_image(hybrid=True))
        self.assertTrue(result.valid, result.issues)
        self.assertEqual(result.kind, "hybrid-gpt")
        self.assertEqual(result.mbr_kind, "hybrid")

    def test_hybrid_mbr_entry_must_exactly_mirror_a_gpt_partition(self):
        payload = gpt_image(hybrid=True)
        # The second MBR entry starts at byte 462; its start LBA is at +8.
        start = struct.unpack_from("<I", payload, 462 + 8)[0]
        struct.pack_into("<I", payload, 462 + 8, start + 1)
        result = inspect_bytes(payload)
        self.assertTrue(result.malformed)
        self.assertIn("exactly mirror", " ".join(result.issues))

    def test_bad_header_crc_and_different_backup_array_are_rejected(self):
        bad_crc = gpt_image()
        bad_crc[512 + 20] ^= 1
        result = inspect_bytes(bad_crc)
        self.assertTrue(result.malformed)
        self.assertIn("header CRC32", " ".join(result.issues))

        different = gpt_image()
        backup_array = (256 - 1 - 32) * 512
        different[backup_array + 64] ^= 1
        result = inspect_bytes(different)
        self.assertTrue(result.malformed)
        self.assertIn("entry-array CRC32", " ".join(result.issues))
        self.assertIn("entry arrays differ", " ".join(result.issues))

    def test_out_of_bounds_and_overlapping_gpt_partitions_are_rejected(self):
        result = inspect_bytes(gpt_image(overlapping=True))
        self.assertTrue(result.malformed)
        self.assertIn("overlap", " ".join(result.issues))

        payload = gpt_image()
        # Move the first partition beyond LastUsableLBA and update both arrays'
        # CRCs and both headers, proving the range check is independent of CRC.
        for array_lba in (2, 223):
            struct.pack_into("<QQ", payload, array_lba * 512 + 32, 400, 401)
        array = bytes(payload[2 * 512:34 * 512])
        crc = zlib.crc32(array) & 0xFFFFFFFF
        for header_lba in (1, 255):
            header = bytearray(payload[header_lba * 512:(header_lba + 1) * 512])
            struct.pack_into("<I", header, 88, crc)
            struct.pack_into("<I", header, 16, 0)
            struct.pack_into(
                "<I", header, 16,
                zlib.crc32(header[:GPT_HEADER.size]) & 0xFFFFFFFF,
            )
            payload[header_lba * 512:(header_lba + 1) * 512] = header
        result = inspect_bytes(payload)
        self.assertTrue(result.malformed)
        self.assertIn("outside usable sectors", " ".join(result.issues))

    def test_stream_capture_validates_gpt_without_unbounded_storage(self):
        payload = bytes(gpt_image())
        limit = PARTITION_TABLE_CAPTURE_BYTES
        result = inspect_partition_tables_capture(
            payload[:limit], payload[-limit:], len(payload),
        )
        self.assertTrue(result.valid, result.issues)
        self.assertTrue(result.complete)

    def test_stream_capture_reports_uncaptured_legal_gpt_and_ebr_as_incomplete(self):
        limit = PARTITION_TABLE_CAPTURE_BYTES
        total_sectors = 70_000

        relocated_gpt = gpt_image(
            total_sectors=total_sectors,
            primary_entry_lba=34_000,
            backup_entry_lba=35_000,
        )
        full = inspect_bytes(relocated_gpt)
        self.assertTrue(full.valid, full.issues)
        captured = inspect_partition_tables_capture(
            bytes(relocated_gpt[:limit]),
            bytes(relocated_gpt[-limit:]),
            len(relocated_gpt),
        )
        self.assertTrue(captured.has_gpt)
        self.assertFalse(captured.valid)
        self.assertFalse(captured.malformed)
        self.assertFalse(captured.complete)
        self.assertEqual(captured.kind, "incomplete")
        self.assertIn("outside", " ".join(captured.issues))

        middle_ebr_lba = 34_000
        relocated_ebr = mbr_image(
            sectors=total_sectors,
            partitions=((0x0F, middle_ebr_lba, 100),),
        )
        ebr_offset = middle_ebr_lba * 512
        MBR_ENTRY.pack_into(
            relocated_ebr, ebr_offset + 446, 0,
            _chs(1), 0x83, _chs(10), 1, 10,
        )
        relocated_ebr[ebr_offset + 510:ebr_offset + 512] = b"\x55\xaa"
        full = inspect_bytes(relocated_ebr)
        self.assertTrue(full.valid, full.issues)
        captured = inspect_partition_tables_capture(
            bytes(relocated_ebr[:limit]),
            bytes(relocated_ebr[-limit:]),
            len(relocated_ebr),
        )
        self.assertTrue(captured.has_mbr)
        self.assertFalse(captured.has_gpt)
        self.assertFalse(captured.valid)
        self.assertFalse(captured.malformed)
        self.assertFalse(captured.complete)
        self.assertEqual(captured.kind, "incomplete")
        self.assertIn("outside", " ".join(captured.issues))

    def test_known_malformed_capture_is_not_downgraded_by_uncaptured_metadata(self):
        limit = PARTITION_TABLE_CAPTURE_BYTES
        total_sectors = 70_000
        relocated_gpt = gpt_image(
            total_sectors=total_sectors,
            primary_entry_lba=34_000,
            backup_entry_lba=35_000,
        )
        struct.pack_into("<I", relocated_gpt, 512 + 8, 0x00010001)
        struct.pack_into(
            "<I", relocated_gpt, (total_sectors - 1) * 512 + 8, 0x00010001,
        )
        refresh_gpt_crcs(relocated_gpt)

        gpt_result = inspect_partition_tables_capture(
            bytes(relocated_gpt[:limit]),
            bytes(relocated_gpt[-limit:]),
            len(relocated_gpt),
        )

        self.assertTrue(gpt_result.malformed)
        self.assertTrue(gpt_result.complete)
        self.assertIn("revision", " ".join(gpt_result.issues))

        conflicting_gpt = gpt_image(
            total_sectors=total_sectors,
            primary_entry_lba=34_000,
            backup_entry_lba=35_000,
        )
        conflicting_gpt[4096:4096 + len(b"EFI PART")] = b"EFI PART"
        conflict_result = inspect_partition_tables_capture(
            bytes(conflicting_gpt[:limit]),
            bytes(conflicting_gpt[-limit:]),
            len(conflicting_gpt),
        )

        self.assertTrue(conflict_result.malformed)
        self.assertTrue(conflict_result.complete)
        self.assertIn("multiple logical-sector sizes", " ".join(conflict_result.issues))

        middle_ebr_lba = 34_000
        relocated_ebr = mbr_image(
            sectors=total_sectors,
            partitions=((0x0F, middle_ebr_lba, 100),),
        )
        relocated_ebr[446] = 0x7F

        mbr_result = inspect_partition_tables_capture(
            bytes(relocated_ebr[:limit]),
            bytes(relocated_ebr[-limit:]),
            len(relocated_ebr),
        )

        self.assertTrue(mbr_result.malformed)
        self.assertTrue(mbr_result.complete)
        self.assertIn("boot flag", " ".join(mbr_result.issues))

    def test_descriptor_must_match_expected_identity_and_remain_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img"
            path.write_bytes(mbr_image())
            descriptor = os.open(path, os.O_RDONLY)
            try:
                status = os.fstat(descriptor)
                wrong = (
                    status.st_dev, status.st_ino, status.st_size + 1,
                    status.st_mtime_ns,
                )
                with self.assertRaisesRegex(PartitionTableError, "changed before"):
                    inspect_partition_tables_fd(descriptor, expected_identity=wrong)

                changed = SimpleNamespace(
                    st_mode=stat.S_IFREG, st_dev=status.st_dev,
                    st_ino=status.st_ino, st_size=status.st_size,
                    st_mtime_ns=status.st_mtime_ns + 1,
                    st_ctime_ns=status.st_ctime_ns + 1,
                )
                with patch(
                    "isopropyl.partition_tables.os.fstat",
                    side_effect=(status, changed),
                ):
                    with self.assertRaisesRegex(PartitionTableError, "changed during"):
                        inspect_partition_tables_fd(descriptor)
            finally:
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
