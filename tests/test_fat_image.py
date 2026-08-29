# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import isopropyl.fat_image as fat_image_module
from isopropyl.eltorito import (
    BootEntry,
    BootPlatform,
    ElToritoInspection,
    EmulationType,
    ValidationEntry,
    inspect_eltorito_file,
)
from isopropyl.fat_image import (
    FatImageError,
    FatType,
    inspect_uefi_eltorito_fat,
    inspect_uefi_eltorito_fats,
    materialize_embedded_fat,
    read_embedded_fat_file,
    validate_uefi_eltorito_fats,
)

BLOCK = 2_048
IMAGE_LBA = 24
IMAGE_OFFSET = IMAGE_LBA * BLOCK


def _set_fat_entry(table: bytearray, kind: FatType, cluster: int, value: int) -> None:
    if kind is FatType.FAT12:
        offset = cluster + cluster // 2
        pair = table[offset] | (table[offset + 1] << 8)
        if cluster & 1:
            pair = (pair & 0x000F) | ((value & 0x0FFF) << 4)
        else:
            pair = (pair & 0xF000) | (value & 0x0FFF)
        table[offset] = pair & 0xFF
        table[offset + 1] = (pair >> 8) & 0xFF
    elif kind is FatType.FAT16:
        struct.pack_into("<H", table, cluster * 2, value)
    else:
        struct.pack_into("<I", table, cluster * 4, value)


def _short_entry(
    name: bytes,
    *,
    directory: bool,
    cluster: int,
    size: int = 0,
) -> bytes:
    assert len(name) == 11
    raw = bytearray(32)
    raw[:11] = name
    raw[11] = 0x10 if directory else 0x20
    struct.pack_into("<H", raw, 20, (cluster >> 16) & 0xFFFF)
    struct.pack_into("<H", raw, 26, cluster & 0xFFFF)
    struct.pack_into("<I", raw, 28, size)
    return bytes(raw)


def _lfn_entry(name: str, short_name: bytes, *, bad_checksum: bool = False) -> bytes:
    encoded = name.encode("utf-16-le")
    units = list(struct.unpack(f"<{len(encoded) // 2}H", encoded))
    units.append(0)
    units.extend([0xFFFF] * (13 - len(units)))
    raw = bytearray(32)
    raw[0] = 0x41
    raw[11] = 0x0F
    checksum = 0
    for byte in short_name:
        checksum = (((checksum & 1) << 7) | (checksum >> 1)) + byte
        checksum &= 0xFF
    raw[13] = checksum ^ (1 if bad_checksum else 0)
    name_bytes = struct.pack("<13H", *units)
    raw[1:11] = name_bytes[:10]
    raw[14:26] = name_bytes[10:22]
    raw[28:32] = name_bytes[22:]
    return bytes(raw)


def make_fat(
    kind: FatType,
    *,
    corrupt_second_fat: bool = False,
    loop: bool = False,
    payload: bytes = b"MZ!",
    long_name: bool = False,
    bad_lfn_checksum: bool = False,
    fat12_max_geometry: bool = False,
    loader_clusters: tuple[int, ...] = (5,),
    loader_name: bytes = b"BOOTX64 EFI",
) -> bytes:
    if (
        not payload
        or not loader_clusters
        or len(payload) > 512 * len(loader_clusters)
        or len(payload) <= 512 * (len(loader_clusters) - 1)
        or len(loader_name) != 11
        or (long_name and loader_name != b"BOOTX64 EFI")
    ):
        raise ValueError("The FAT fixture payload or loader name is invalid")
    if kind is FatType.FAT12:
        reserved, root_entries = 1, 16
        if fat12_max_geometry:
            fat_sectors, clusters = 12, 4_084
        else:
            fat_sectors, clusters = 1, 60
    elif kind is FatType.FAT16:
        reserved, fat_sectors, root_entries, clusters = 1, 17, 16, 4_085
    else:
        reserved, fat_sectors, root_entries, clusters = 32, 512, 0, 65_525
    bytes_per_sector = 512
    fat_count = 2
    root_sectors = (root_entries * 32 + 511) // 512
    total_sectors = reserved + fat_count * fat_sectors + root_sectors + clusters
    image = bytearray(total_sectors * bytes_per_sector)
    image[0:3] = b"\xeb\x3c\x90"
    image[3:11] = b"ISOPROPY"
    struct.pack_into("<H", image, 11, bytes_per_sector)
    image[13] = 1
    struct.pack_into("<H", image, 14, reserved)
    image[16] = fat_count
    struct.pack_into("<H", image, 17, root_entries)
    if total_sectors <= 0xFFFF:
        struct.pack_into("<H", image, 19, total_sectors)
    else:
        struct.pack_into("<I", image, 32, total_sectors)
    image[21] = 0xF8
    if kind is FatType.FAT32:
        struct.pack_into("<I", image, 36, fat_sectors)
        struct.pack_into("<I", image, 44, 2)
        image[82:90] = b"FAT32   "
    else:
        struct.pack_into("<H", image, 22, fat_sectors)
        # A realistic FAT12/16 extended BPB starts at offset 36.  Those bytes
        # are not the FAT32 sectors-per-FAT field.
        image[36] = 0x80
        image[38] = 0x29
        struct.pack_into("<I", image, 39, 0x12345678)
        image[54:62] = (b"FAT12   " if kind is FatType.FAT12 else b"FAT16   ")
    image[510:512] = b"\x55\xaa"

    fat = bytearray(fat_sectors * bytes_per_sector)
    if kind is FatType.FAT12:
        _set_fat_entry(fat, kind, 0, 0xFF8)
        _set_fat_entry(fat, kind, 1, 0xFFF)
        eoc = 0xFFF
    elif kind is FatType.FAT16:
        _set_fat_entry(fat, kind, 0, 0xFFF8)
        _set_fat_entry(fat, kind, 1, 0xFFFF)
        eoc = 0xFFFF
    else:
        _set_fat_entry(fat, kind, 0, 0x0FFFFFF8)
        _set_fat_entry(fat, kind, 1, 0x0FFFFFFF)
        eoc = 0x0FFFFFFF
    for cluster in (2, 3, 4):
        _set_fat_entry(fat, kind, cluster, eoc)
    for index, cluster in enumerate(loader_clusters):
        following = (
            loader_clusters[index + 1]
            if index + 1 < len(loader_clusters)
            else (cluster if loop else eoc)
        )
        _set_fat_entry(fat, kind, cluster, following)
    fat_start = reserved * bytes_per_sector
    image[fat_start:fat_start + len(fat)] = fat
    second = bytearray(fat)
    if corrupt_second_fat:
        second[-1] ^= 1
    image[fat_start + len(fat):fat_start + 2 * len(fat)] = second

    root_offset = (reserved + fat_count * fat_sectors) * bytes_per_sector
    data_offset = root_offset + root_sectors * bytes_per_sector

    def cluster_offset(cluster: int) -> int:
        return data_offset + (cluster - 2) * bytes_per_sector

    root = cluster_offset(2) if kind is FatType.FAT32 else root_offset
    image[root:root + 32] = _short_entry(
        b"EFI        ", directory=True, cluster=3,
    )
    efi = cluster_offset(3)
    image[efi:efi + 32] = _short_entry(
        b"BOOT       ", directory=True, cluster=4,
    )
    boot = cluster_offset(4)
    short_name = b"BOOTX6~1EFI" if long_name else loader_name
    if long_name:
        image[boot:boot + 32] = _lfn_entry(
            "bootx64.efi",
            short_name,
            bad_checksum=bad_lfn_checksum,
        )
        boot += 32
    image[boot:boot + 32] = _short_entry(
        short_name, directory=False, cluster=loader_clusters[0], size=len(payload),
    )
    for index, cluster in enumerate(loader_clusters):
        chunk = payload[index * 512:(index + 1) * 512]
        start = cluster_offset(cluster)
        image[start:start + len(chunk)] = chunk
    return bytes(image)


def inspection(source_size: int, *, image_offset: int = IMAGE_OFFSET) -> ElToritoInspection:
    entry = BootEntry(
        1,
        True,
        BootPlatform.EFI,
        "UEFI",
        True,
        EmulationType.NO_EMULATION,
        0,
        0,
        1,
        image_offset // BLOCK,
        image_offset,
        512,
        image_offset + 512,
        0,
        b"",
    )
    return ElToritoInspection(
        source_size,
        20,
        20 * BLOCK,
        64,
        3,
        ValidationEntry(BootPlatform.EFI, "UEFI", 0),
        (entry,),
        logical_volume_size=source_size,
    )


def write_container(path: Path, fat: bytes, *, wrapped: bool = False) -> ElToritoInspection:
    partition_prefix = 4 * 512 if wrapped else 0
    size = IMAGE_OFFSET + partition_prefix + len(fat)
    size = ((size + BLOCK - 1) // BLOCK) * BLOCK
    with path.open("wb") as stream:
        stream.truncate(size)
        descriptor = bytearray(BLOCK)
        descriptor[0] = 0
        descriptor[1:6] = b"CD001"
        descriptor[6] = 1
        descriptor[7:39] = b"EL TORITO SPECIFICATION".ljust(32, b" ")
        struct.pack_into("<I", descriptor, 71, 20)
        stream.seek(16 * BLOCK)
        stream.write(descriptor)
        primary = bytearray(BLOCK)
        primary[0] = 1
        primary[1:6] = b"CD001"
        primary[6] = 1
        logical_blocks = size // BLOCK
        struct.pack_into("<I", primary, 80, logical_blocks)
        struct.pack_into(">I", primary, 84, logical_blocks)
        stream.write(primary)
        terminator = bytearray(BLOCK)
        terminator[0] = 255
        terminator[1:6] = b"CD001"
        terminator[6] = 1
        stream.write(terminator)
        validation = bytearray(32)
        validation[0] = 1
        validation[1] = 0xEF
        validation[4:28] = b"ISOPROPYL".ljust(24, b"\0")
        validation[30:32] = b"\x55\xaa"
        struct.pack_into(
            "<H",
            validation,
            28,
            (-sum(struct.unpack("<16H", validation))) & 0xFFFF,
        )
        catalog_entry = bytearray(32)
        catalog_entry[0] = 0x88
        struct.pack_into("<H", catalog_entry, 6, 1)
        struct.pack_into("<I", catalog_entry, 8, IMAGE_LBA)
        stream.seek(20 * BLOCK)
        stream.write(validation)
        stream.write(catalog_entry)
        if wrapped:
            mbr = bytearray(512)
            mbr[446] = 0x80
            mbr[450] = 0x0C
            struct.pack_into("<II", mbr, 454, 4, len(fat) // 512)
            mbr[510:512] = b"\x55\xaa"
            stream.seek(IMAGE_OFFSET)
            stream.write(mbr)
        stream.seek(IMAGE_OFFSET + partition_prefix)
        stream.write(fat)
    return inspection(size)


def write_plural_container(
    path: Path,
    first_fat: bytes,
    second_fat: bytes,
) -> tuple[ElToritoInspection, int]:
    base = write_container(path, first_fat)
    second_offset = IMAGE_OFFSET + (
        (len(first_fat) + BLOCK - 1) // BLOCK
    ) * BLOCK
    size = second_offset + len(second_fat)
    size = ((size + BLOCK - 1) // BLOCK) * BLOCK
    with path.open("r+b") as stream:
        stream.truncate(size)
        stream.seek(16 * BLOCK + 80)
        logical_blocks = size // BLOCK
        stream.write(struct.pack("<I", logical_blocks))
        stream.write(struct.pack(">I", logical_blocks))
        stream.seek(second_offset)
        stream.write(second_fat)
    second = replace(
        base.entries[0],
        catalog_index=2,
        is_default=False,
        image_lba=second_offset // BLOCK,
        image_offset=second_offset,
        extent_end=second_offset + 512,
    )
    return (
        replace(
            base,
            source_size=size,
            entries=(second, base.entries[0]),
            logical_volume_size=size,
        ),
        second_offset,
    )


class EmbeddedFatImageTests(unittest.TestCase):
    def test_plural_parser_is_deterministic_validates_and_rechecks_each_image(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plural.iso"
            catalog, second_offset = write_plural_container(
                path,
                make_fat(FatType.FAT12, payload=b"MZ-first"),
                make_fat(FatType.FAT12, payload=b"MZ-second"),
            )
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with mock.patch.object(
                    fat_image_module.os,
                    "fstat",
                    wraps=os.fstat,
                ) as checked:
                    results = inspect_uefi_eltorito_fats(descriptor, catalog)
                self.assertEqual(
                    tuple(result.image_offset for result in results),
                    (IMAGE_OFFSET, second_offset),
                )
                self.assertEqual(len(results), 2)
                self.assertGreaterEqual(checked.call_count, 3)
                validate_uefi_eltorito_fats(descriptor, catalog, results)
                with self.assertRaisesRegex(FatImageError, "ambiguous"):
                    inspect_uefi_eltorito_fat(descriptor, catalog)
            finally:
                os.close(descriptor)

    def test_plural_parser_rejects_duplicate_eligible_offsets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.iso"
            base = write_container(path, make_fat(FatType.FAT12))
            duplicate = replace(
                base.entries[0],
                catalog_index=2,
                is_default=False,
            )
            catalog = replace(base, entries=(base.entries[0], duplicate))
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with self.assertRaisesRegex(FatImageError, "duplicate offsets"):
                    inspect_uefi_eltorito_fats(descriptor, catalog)
            finally:
                os.close(descriptor)

    def test_plural_parser_rejects_more_than_eight_images(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "too-many.iso"
            base = write_container(path, make_fat(FatType.FAT12))
            entries = tuple(
                replace(
                    base.entries[0],
                    catalog_index=index + 1,
                    is_default=index == 0,
                    image_lba=IMAGE_LBA + index,
                    image_offset=IMAGE_OFFSET + index * BLOCK,
                    extent_end=IMAGE_OFFSET + index * BLOCK + 512,
                )
                for index in range(fat_image_module.MAX_EMBEDDED_IMAGES + 1)
            )
            catalog = replace(base, entries=entries)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with self.assertRaisesRegex(FatImageError, "too many"):
                    inspect_uefi_eltorito_fats(descriptor, catalog)
            finally:
                os.close(descriptor)

    def test_plural_parser_bounds_each_image_by_the_next_image(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "overlap.iso"
            catalog, _ = write_plural_container(
                path,
                make_fat(FatType.FAT12),
                make_fat(FatType.FAT12),
            )
            intruding = replace(
                catalog.entries[0],
                image_lba=(IMAGE_OFFSET + BLOCK) // BLOCK,
                image_offset=IMAGE_OFFSET + BLOCK,
                extent_end=IMAGE_OFFSET + BLOCK + 512,
            )
            bounded = replace(catalog, entries=(catalog.entries[1], intruding))
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with self.assertRaisesRegex(FatImageError, "bounded image extent"):
                    inspect_uefi_eltorito_fats(descriptor, bounded)
            finally:
                os.close(descriptor)

    def test_plural_parser_applies_aggregate_tree_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "aggregate.iso"
            fat = make_fat(FatType.FAT12)
            catalog, _ = write_plural_container(path, fat, fat)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with mock.patch.object(fat_image_module, "MAX_ENTRIES", 5):
                    with self.assertRaisesRegex(FatImageError, "too many entries"):
                        inspect_uefi_eltorito_fats(descriptor, catalog)
                with mock.patch.object(fat_image_module, "MAX_DIRECTORIES", 3):
                    with self.assertRaisesRegex(FatImageError, "too many directories"):
                        inspect_uefi_eltorito_fats(descriptor, catalog)
                with mock.patch.object(
                    fat_image_module,
                    "MAX_FILESYSTEM_BYTES",
                    len(fat) * 2 - 1,
                ):
                    with self.assertRaises(FatImageError):
                        inspect_uefi_eltorito_fats(descriptor, catalog)
            finally:
                os.close(descriptor)

    def test_parses_direct_fat12_fat16_and_fat32(self):
        for kind in FatType:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "image.iso"
                catalog = write_container(path, make_fat(kind))
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    result = inspect_uefi_eltorito_fat(descriptor, catalog)
                    assert result is not None
                    self.assertEqual(result.fat_type, kind)
                    self.assertEqual(
                        tuple(entry.path for entry in result.entries),
                        ("EFI", "EFI/BOOT", "EFI/BOOT/BOOTX64.EFI"),
                    )
                    self.assertEqual(len(result.fallback_loaders), 1)
                    self.assertEqual(
                        read_embedded_fat_file(
                            descriptor, result, "EFI/BOOT/BOOTX64.EFI",
                        ),
                        b"MZ!",
                    )
                finally:
                    os.close(descriptor)

    def test_parses_first_active_mbr_wrapped_fat(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrapped.iso"
            catalog = write_container(path, make_fat(FatType.FAT12), wrapped=True)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                result = inspect_uefi_eltorito_fat(descriptor, catalog)
            finally:
                os.close(descriptor)
            assert result is not None
            self.assertEqual(result.partition_start_lba, 4)
            self.assertEqual(result.partition_sectors, len(make_fat(FatType.FAT12)) // 512)

    def test_zero_catalog_sector_count_expands_from_valid_fat_geometry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "zero-count.iso"
            base = write_container(path, make_fat(FatType.FAT12))
            entry = replace(
                base.entries[0],
                sector_count=0,
                load_size=0,
                extent_end=base.entries[0].image_offset,
            )
            catalog = replace(base, entries=(entry,))
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                result = inspect_uefi_eltorito_fat(descriptor, catalog)
            finally:
                os.close(descriptor)
            assert result is not None
            self.assertEqual(result.filesystem_size, len(make_fat(FatType.FAT12)))

    def test_validates_and_uses_vfat_long_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lfn.iso"
            catalog = write_container(
                path,
                make_fat(FatType.FAT12, long_name=True),
            )
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                result = inspect_uefi_eltorito_fat(descriptor, catalog)
                assert result is not None
                self.assertEqual(
                    result.fallback_loaders[0].path,
                    "EFI/BOOT/bootx64.efi",
                )
            finally:
                os.close(descriptor)

            bad = Path(directory) / "bad-lfn.iso"
            bad_catalog = write_container(
                bad,
                make_fat(
                    FatType.FAT12,
                    long_name=True,
                    bad_lfn_checksum=True,
                ),
            )
            descriptor = os.open(bad, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with self.assertRaisesRegex(FatImageError, "does not match"):
                    inspect_uefi_eltorito_fat(descriptor, bad_catalog)
            finally:
                os.close(descriptor)

    def test_rejects_disagreeing_fats_and_cluster_loops(self):
        variants = (
            (make_fat(FatType.FAT12, corrupt_second_fat=True), "copies disagree"),
            (make_fat(FatType.FAT12, loop=True), "loop"),
        )
        for fat, message in variants:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "bad.iso"
                catalog = write_container(path, fat)
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    with self.assertRaisesRegex(FatImageError, message):
                        inspect_uefi_eltorito_fat(descriptor, catalog)
                finally:
                    os.close(descriptor)

    def test_accepts_volume_valid_fat12_link_near_type_cutover(self):
        payload = b"x" * 513
        fat = make_fat(
            FatType.FAT12,
            payload=payload,
            fat12_max_geometry=True,
            loader_clusters=(5, 0xFF0),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "near-cutover.iso"
            catalog = write_container(path, fat)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                result = inspect_uefi_eltorito_fat(descriptor, catalog)
                assert result is not None
                self.assertEqual(
                    read_embedded_fat_file(
                        descriptor,
                        result,
                        "EFI/BOOT/BOOTX64.EFI",
                    ),
                    payload,
                )
            finally:
                os.close(descriptor)

    def test_rejects_orphan_long_name_at_exact_directory_end(self):
        fat = bytearray(make_fat(FatType.FAT12))
        data_offset = 4 * 512
        boot_directory = data_offset + (4 - 2) * 512
        for slot in range(1, 15):
            fat[boot_directory + slot * 32] = 0xE5
        fat[boot_directory + 15 * 32:boot_directory + 16 * 32] = _lfn_entry(
            "orphan.efi",
            b"ORPHAN~1EFI",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "orphan-lfn.iso"
            catalog = write_container(path, bytes(fat))
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with self.assertRaisesRegex(FatImageError, "orphan long name"):
                    inspect_uefi_eltorito_fat(descriptor, catalog)
            finally:
                os.close(descriptor)

    def test_zero_count_mbr_image_start_cannot_overlap_boot_catalog(self):
        fat = make_fat(FatType.FAT12)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog-overlap.iso"
            base = write_container(path, fat)
            image_offset = base.catalog_offset
            with path.open("r+b") as stream:
                stream.seek(image_offset + 446)
                partition = bytearray(16)
                partition[0] = 0x80
                partition[4] = 0x0C
                struct.pack_into("<II", partition, 8, 4, len(fat) // 512)
                stream.write(partition)
                stream.seek(image_offset + 510)
                stream.write(b"\x55\xaa")
                stream.seek(image_offset + 4 * 512)
                stream.write(fat)
            overlapping_entry = replace(
                base.entries[0],
                sector_count=0,
                image_lba=image_offset // BLOCK,
                image_offset=image_offset,
                load_size=0,
                extent_end=image_offset,
            )
            catalog = replace(base, entries=(overlapping_entry,))
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with self.assertRaisesRegex(FatImageError, "El Torito catalog"):
                    inspect_uefi_eltorito_fat(descriptor, catalog)
            finally:
                os.close(descriptor)

    def test_catalog_identity_uses_ctime_when_mtime_is_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ctime.iso"
            write_container(path, make_fat(FatType.FAT12))
            catalog = inspect_eltorito_file(path)
            original = path.stat()
            with path.open("r+b") as stream:
                stream.seek(-1, os.SEEK_END)
                stream.write(b"x")
            os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
            self.assertNotEqual(path.stat().st_ctime_ns, catalog.source_identity.changed_ns)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with self.assertRaisesRegex(FatImageError, "different ISO identity"):
                    inspect_uefi_eltorito_fat(descriptor, catalog)
            finally:
                os.close(descriptor)

    def test_catalog_count_over_one_bounds_the_complete_fat_extent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bounded.iso"
            catalog = write_container(path, make_fat(FatType.FAT12))
            entry = catalog.entries[0]
            bounded = ElToritoInspection(
                catalog.source_size,
                catalog.catalog_lba,
                catalog.catalog_offset,
                catalog.catalog_size,
                catalog.descriptors_scanned,
                catalog.validation,
                (
                    BootEntry(
                        entry.catalog_index,
                        entry.is_default,
                        entry.platform,
                        entry.section_identifier,
                        entry.bootable,
                        entry.emulation,
                        entry.load_segment,
                        entry.system_type,
                        2,
                        entry.image_lba,
                        entry.image_offset,
                        1_024,
                        (entry.image_offset or 0) + 1_024,
                        entry.selection_criteria_type,
                        entry.selection_criteria,
                    ),
                ),
                logical_volume_size=catalog.logical_volume_size,
            )
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with self.assertRaisesRegex(FatImageError, "bounded image extent"):
                    inspect_uefi_eltorito_fat(descriptor, bounded)
            finally:
                os.close(descriptor)

    def test_materializes_additively_and_refuses_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "image.iso"
            catalog = write_container(path, make_fat(FatType.FAT12))
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                plan = inspect_uefi_eltorito_fat(descriptor, catalog)
                assert plan is not None
                target = root / "tree"
                target.mkdir()
                written = materialize_embedded_fat(
                    descriptor,
                    catalog,
                    plan,
                    target,
                    tuple(entry.path for entry in plan.entries),
                )
                self.assertEqual(written, 3)
                self.assertEqual((target / "EFI/BOOT/BOOTX64.EFI").read_bytes(), b"MZ!")

                second = root / "second"
                (second / "EFI/BOOT").mkdir(parents=True)
                (second / "EFI/BOOT/BOOTX64.EFI").write_bytes(b"occupied")
                with self.assertRaisesRegex(FatImageError, "replace staged path"):
                    materialize_embedded_fat(
                        descriptor,
                        catalog,
                        plan,
                        second,
                        tuple(entry.path for entry in plan.entries),
                    )
            finally:
                os.close(descriptor)

    def test_source_mutation_invalidates_bound_file_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.iso"
            catalog = write_container(path, make_fat(FatType.FAT12))
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                plan = inspect_uefi_eltorito_fat(descriptor, catalog)
                assert plan is not None
                with path.open("r+b") as stream:
                    stream.seek(-1, os.SEEK_END)
                    stream.write(b"x")
                with self.assertRaisesRegex(FatImageError, "no longer matches"):
                    read_embedded_fat_file(
                        descriptor, plan, "EFI/BOOT/BOOTX64.EFI",
                    )
            finally:
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
