# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from isopropyl.eltorito import (
    BootPlatform, ElToritoError, ElToritoNotFound, EmulationType, IsoChanged,
    inspect_eltorito_bytes, inspect_eltorito_file,
)

BLOCK = 2048
CATALOG_LBA = 20


def validation_entry(platform: int = 0, identifier: bytes = b"ISOPROPYL") -> bytes:
    entry = bytearray(32)
    entry[0] = 1
    entry[1] = platform
    entry[4:28] = identifier.ljust(24, b"\0")
    entry[30:32] = b"\x55\xaa"
    words = struct.unpack("<16H", entry)
    struct.pack_into("<H", entry, 28, (-sum(words)) & 0xFFFF)
    return bytes(entry)


def boot_entry(
    *, bootable: bool = True, emulation: int = 0, segment: int = 0,
    count: int = 4, image_lba: int = 24, system_type: int = 0,
    selection_type: int = 0, selection: bytes = b"",
) -> bytes:
    entry = bytearray(32)
    entry[0] = 0x88 if bootable else 0
    entry[1] = emulation
    struct.pack_into("<H", entry, 2, segment)
    entry[4] = system_type
    entry[5] = selection_type
    struct.pack_into("<H", entry, 6, count)
    struct.pack_into("<I", entry, 8, image_lba)
    entry[12:12 + min(20, len(selection))] = selection[:20]
    return bytes(entry)


def section_header(
    *, final: bool, platform: int, count: int, identifier: bytes = b"SECTION",
) -> bytes:
    entry = bytearray(32)
    entry[0] = 0x91 if final else 0x90
    entry[1] = platform
    struct.pack_into("<H", entry, 2, count)
    entry[4:32] = identifier.ljust(28, b"\0")
    return bytes(entry)


def make_iso(
    *, validation: bytes | None = None, default: bytes | None = None,
    extra_catalog: tuple[bytes, ...] = (), catalog_lba: int = CATALOG_LBA,
    second_boot_record: bool = False, sectors: int = 32,
) -> bytes:
    image = bytearray(sectors * BLOCK)

    def descriptor(lba: int, kind: int) -> memoryview:
        view = memoryview(image)[lba * BLOCK:(lba + 1) * BLOCK]
        view[0] = kind
        view[1:6] = b"CD001"
        view[6] = 1
        return view

    boot = descriptor(16, 0)
    boot[7:39] = b"EL TORITO SPECIFICATION".ljust(32, b" ")
    struct.pack_into("<I", boot, 71, catalog_lba)
    if second_boot_record:
        duplicate = descriptor(17, 0)
        duplicate[7:39] = b"EL TORITO SPECIFICATION".ljust(32, b" ")
        struct.pack_into("<I", duplicate, 71, catalog_lba)
        primary = descriptor(18, 1)
        struct.pack_into("<I", primary, 80, sectors)
        struct.pack_into(">I", primary, 84, sectors)
        descriptor(19, 255)
    else:
        primary = descriptor(17, 1)
        struct.pack_into("<I", primary, 80, sectors)
        struct.pack_into(">I", primary, 84, sectors)
        descriptor(18, 255)

    last_descriptor = 19 if second_boot_record else 18
    if last_descriptor < catalog_lba < sectors:
        catalog = catalog_lba * BLOCK
        contents = (
            validation or validation_entry(),
            default or boot_entry(),
            *extra_catalog,
        )
        for index, entry in enumerate(contents):
            image[catalog + index * 32:catalog + (index + 1) * 32] = entry
    return bytes(image)


class ElToritoTests(unittest.TestCase):
    def test_parses_default_bios_entry_and_minimum_load_extent(self):
        result = inspect_eltorito_bytes(make_iso())
        self.assertEqual(result.catalog_lba, CATALOG_LBA)
        self.assertEqual(result.catalog_size, 64)
        self.assertEqual(result.validation.platform, BootPlatform.BIOS_X86)
        entry = result.entries[0]
        self.assertTrue(entry.is_default)
        self.assertTrue(entry.bootable)
        self.assertEqual(entry.emulation, EmulationType.NO_EMULATION)
        self.assertEqual(entry.effective_load_segment, 0x07C0)
        self.assertEqual(entry.load_size, 2048)
        self.assertEqual(entry.image_offset, 24 * BLOCK)
        self.assertEqual(entry.extent_end, 25 * BLOCK)
        self.assertEqual(entry.load_extent, (24 * BLOCK, 25 * BLOCK))
        self.assertEqual(result.bootable_platforms, (BootPlatform.BIOS_X86,))

    def test_parses_final_efi_section_and_selection_metadata(self):
        efi = boot_entry(
            image_lba=25, count=8, selection_type=1, selection=b"criteria"
        )
        result = inspect_eltorito_bytes(make_iso(extra_catalog=(
            section_header(final=True, platform=0xEF, count=1, identifier=b"UEFI x64"),
            efi,
        )))
        self.assertEqual(len(result.entries), 2)
        entry = result.entries[1]
        self.assertEqual(entry.platform, BootPlatform.EFI)
        self.assertEqual(entry.section_identifier, "UEFI x64")
        self.assertEqual(entry.selection_criteria_type, 1)
        self.assertTrue(entry.selection_criteria.startswith(b"criteria"))
        self.assertEqual(
            result.bootable_platforms, (BootPlatform.BIOS_X86, BootPlatform.EFI)
        )

    def test_nonbootable_default_entry_can_have_no_image_extent(self):
        result = inspect_eltorito_bytes(make_iso(
            default=boot_entry(bootable=False, count=0, image_lba=0)
        ))
        entry = result.entries[0]
        self.assertFalse(entry.bootable)
        self.assertIsNone(entry.image_offset)
        self.assertEqual(result.bootable_platforms, ())

    def test_zero_sector_count_is_limited_to_efi_no_emulation(self):
        result = inspect_eltorito_bytes(make_iso(
            validation=validation_entry(platform=0xEF),
            default=boot_entry(count=0, image_lba=24),
        ))
        entry = result.entries[0]
        self.assertEqual(entry.platform, BootPlatform.EFI)
        self.assertEqual(entry.load_size, 0)
        self.assertEqual(entry.load_extent, (24 * BLOCK, 24 * BLOCK))
        with self.assertRaisesRegex(ElToritoError, "zero sector count"):
            inspect_eltorito_bytes(make_iso(
                default=boot_entry(count=0, image_lba=24),
            ))

    def test_reports_emulation_and_explicit_load_segment(self):
        result = inspect_eltorito_bytes(make_iso(default=boot_entry(
            emulation=4, segment=0x9000, image_lba=24, count=1,
        )))
        entry = result.entries[0]
        self.assertEqual(entry.emulation, EmulationType.HARD_DISK)
        self.assertEqual(entry.effective_load_segment, 0x9000)

    def test_rejects_bad_validation_signature_checksum_and_platform(self):
        invalid_entries = []
        bad_signature = bytearray(validation_entry())
        bad_signature[30] = 0
        invalid_entries.append(bad_signature)
        bad_checksum = bytearray(validation_entry())
        bad_checksum[4] ^= 1
        invalid_entries.append(bad_checksum)
        invalid_entries.append(bytearray(validation_entry(platform=0x7F)))
        for entry in invalid_entries:
            with self.subTest(entry=bytes(entry)):
                with self.assertRaises(ElToritoError):
                    inspect_eltorito_bytes(make_iso(validation=bytes(entry)))

    def test_rejects_multiple_boot_records_and_catalog_overlap(self):
        with self.assertRaisesRegex(ElToritoError, "Multiple"):
            inspect_eltorito_bytes(make_iso(second_boot_record=True))
        with self.assertRaisesRegex(ElToritoError, "overlaps"):
            inspect_eltorito_bytes(make_iso(catalog_lba=18))

    def test_rejects_out_of_range_catalog_and_boot_image(self):
        with self.assertRaisesRegex(ElToritoError, "outside"):
            inspect_eltorito_bytes(make_iso(catalog_lba=99))
        with self.assertRaisesRegex(ElToritoError, "outside"):
            inspect_eltorito_bytes(make_iso(default=boot_entry(image_lba=31, count=8)))

    def test_rejects_invalid_entry_indicator_media_and_reserved_data(self):
        bad_indicator = bytearray(boot_entry())
        bad_indicator[0] = 0x87
        bad_media = bytearray(boot_entry())
        bad_media[1] = 0x7F
        bad_reserved = bytearray(boot_entry())
        bad_reserved[12] = 1
        for entry in (bad_indicator, bad_media, bad_reserved):
            with self.subTest(entry=bytes(entry)):
                with self.assertRaises(ElToritoError):
                    inspect_eltorito_bytes(make_iso(default=bytes(entry)))

    def test_rejects_unfinished_empty_or_extension_sections(self):
        unfinished = make_iso(extra_catalog=(
            section_header(final=False, platform=0xEF, count=1), boot_entry(image_lba=25),
        ))
        with self.assertRaisesRegex(ElToritoError, "section header"):
            inspect_eltorito_bytes(unfinished)
        empty = make_iso(extra_catalog=(section_header(final=True, platform=0, count=0),))
        with self.assertRaisesRegex(ElToritoError, "no entries"):
            inspect_eltorito_bytes(empty)
        extension = bytearray(boot_entry())
        extension[0] = 0x44
        with self.assertRaisesRegex(ElToritoError, "extensions"):
            inspect_eltorito_bytes(make_iso(extra_catalog=(
                section_header(final=True, platform=0, count=1), bytes(extension),
            )))

    def test_rejects_catalog_or_volume_descriptor_image_overlap(self):
        with self.assertRaisesRegex(ElToritoError, "boot catalog"):
            inspect_eltorito_bytes(make_iso(default=boot_entry(image_lba=CATALOG_LBA)))
        # Catalog remains after the descriptor set, but its entry targets LBA 17.
        with self.assertRaisesRegex(ElToritoError, "volume descriptors"):
            inspect_eltorito_bytes(make_iso(default=boot_entry(image_lba=17)))

    def test_missing_boot_record_and_truncated_descriptors_are_rejected(self):
        image = bytearray(make_iso())
        image[16 * BLOCK + 7:16 * BLOCK + 39] = b"OTHER BOOT SYSTEM".ljust(32)
        with self.assertRaises(ElToritoNotFound):
            inspect_eltorito_bytes(bytes(image))
        with self.assertRaisesRegex(ElToritoError, "outside"):
            inspect_eltorito_bytes(make_iso()[:17 * BLOCK])

    def test_regular_file_identity_is_bound_and_changes_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "linux.iso"
            payload = make_iso()
            path.write_bytes(payload)
            before = path.stat()
            result = inspect_eltorito_file(path)
            after = path.stat()
            self.assertIsNotNone(result.source_identity)
            self.assertEqual(
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns),
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            )
            assert result.source_identity is not None
            self.assertEqual(result.source_identity.changed_ns, before.st_ctime_ns)

            real_fstat = os.fstat
            calls = 0

            def changing_fstat(descriptor: int):
                nonlocal calls
                calls += 1
                if calls == 2:
                    path.write_bytes(payload + b"changed")
                return real_fstat(descriptor)

            with patch("isopropyl.eltorito.os.fstat", side_effect=changing_fstat):
                with self.assertRaises(IsoChanged):
                    inspect_eltorito_file(path)


if __name__ == "__main__":
    unittest.main()
