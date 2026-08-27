from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import os
import struct
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from isopropyl.bootloaders import BoundBootArtifact, BoundBootBundle
from isopropyl.syslinux import (
    LDLINUX_MAGIC,
    SyslinuxPatchError,
    make_empty_adv,
    merge_fat32_boot_sector,
    patch_ldlinux,
)
from isopropyl.syslinux_fat import (
    map_root_ldlinux,
    prepare_syslinux_patch_from_map,
    prepare_syslinux_regular_file_plan,
)


TOTAL_SECTORS = 70_000
RESERVED = 32
FAT_SECTORS = 600
DATA_START = RESERVED + 2 * FAT_SECTORS
FILE_BYTES = bytes((index * 29) & 0xFF for index in range(3_072))


def _vbr(*, hidden_sectors: int = 0) -> bytes:
    sector = bytearray(512)
    sector[:3] = b"\xeb\x58\x90"
    sector[3:11] = b"mkfs.fat"
    struct.pack_into("<H", sector, 11, 512)
    sector[13] = 1
    struct.pack_into("<H", sector, 14, RESERVED)
    sector[16] = 2
    sector[21] = 0xF8
    struct.pack_into("<I", sector, 28, hidden_sectors)
    struct.pack_into("<I", sector, 32, TOTAL_SECTORS)
    struct.pack_into("<I", sector, 36, FAT_SECTORS)
    struct.pack_into("<I", sector, 44, 2)
    struct.pack_into("<H", sector, 48, 1)
    struct.pack_into("<H", sector, 50, 6)
    sector[64] = 0x80
    sector[66] = 0x29
    sector[71:82] = b"ISOPROPYL  "
    sector[82:90] = b"FAT32   "
    sector[510:512] = b"\x55\xaa"
    return bytes(sector)


def _fsinfo() -> bytes:
    sector = bytearray(512)
    struct.pack_into("<I", sector, 0, 0x41615252)
    struct.pack_into("<I", sector, 484, 0x61417272)
    sector[510:512] = b"\x55\xaa"
    return bytes(sector)


def make_image(
    descriptor: int,
    *,
    chain=(3, 5, 4, 8, 6, 7),
    file_bytes: bytes = FILE_BYTES,
    volume_offset_sectors: int = 0,
) -> None:
    volume_offset = volume_offset_sectors * 512
    os.ftruncate(descriptor, volume_offset + TOTAL_SECTORS * 512)
    boot = _vbr(hidden_sectors=volume_offset_sectors)
    os.pwrite(descriptor, boot, volume_offset)
    os.pwrite(descriptor, _fsinfo(), volume_offset + 512)
    os.pwrite(descriptor, boot, volume_offset + 6 * 512)
    fat = bytearray(FAT_SECTORS * 512)
    struct.pack_into("<I", fat, 0, 0x0FFFFFF8)
    struct.pack_into("<I", fat, 4, 0x0FFFFFFF)
    struct.pack_into("<I", fat, 8, 0x0FFFFFFF)
    for current, following in zip(chain, chain[1:]):
        struct.pack_into("<I", fat, current * 4, following)
    struct.pack_into("<I", fat, chain[-1] * 4, 0x0FFFFFFF)
    for index in range(2):
        os.pwrite(
            descriptor, fat,
            volume_offset + (RESERVED + index * FAT_SECTORS) * 512,
        )
    root = bytearray(512)
    root[:11] = b"LDLINUX SYS"
    root[11] = 0x07
    struct.pack_into("<H", root, 26, chain[0])
    struct.pack_into("<I", root, 28, len(file_bytes))
    os.pwrite(descriptor, root, volume_offset + DATA_START * 512)
    for index, cluster in enumerate(chain):
        sector = DATA_START + cluster - 2
        os.pwrite(
            descriptor, file_bytes[index * 512:(index + 1) * 512],
            volume_offset + sector * 512,
        )


def patch_payloads() -> tuple[bytes, bytes]:
    image = bytearray(2_048)
    struct.pack_into(
        "<IIHHIIHH", image, 24,
        LDLINUX_MAGIC, 0x12345678, 0, 0, 0, 0, 127, 100,
    )
    struct.pack_into(
        "<10H", image, 100,
        180, 220, 32, 260, 16, 300, 8, 100, 104, 108,
    )
    boot = bytearray(512)
    boot[:11] = b"\xeb\x58\x90SYSLINUX"
    boot[90:510] = bytes((index * 17) & 0xFF for index in range(420))
    boot[510:512] = b"\x55\xaa"
    return bytes(image), bytes(boot)


def disk_mbr(*, partition_start: int = 2_048) -> bytes:
    sector = bytearray(512)
    sector[440:444] = b"\x12\x34\x56\x78"
    entry = bytearray(16)
    entry[0] = 0x80
    entry[4] = 0x0C
    struct.pack_into("<I", entry, 8, partition_start)
    struct.pack_into("<I", entry, 12, TOTAL_SECTORS)
    sector[446:462] = entry
    sector[510:512] = b"\x55\xaa"
    return bytes(sector)


class Fat32MapTests(unittest.TestCase):
    def test_maps_and_hashes_fragmented_root_file(self):
        with tempfile.TemporaryFile() as image:
            make_image(image.fileno())
            result = map_root_ldlinux(
                image.fileno(), volume_offset=0,
                volume_size=TOTAL_SECTORS * 512, expected_file=FILE_BYTES,
            )
        self.assertEqual(result.clusters, (3, 5, 4, 8, 6, 7))
        self.assertEqual(
            result.sectors,
            tuple(DATA_START + cluster - 2 for cluster in result.clusters),
        )
        self.assertEqual(result.backup_boot_sector, 6)

    def test_binds_nonzero_partition_offset_to_hidden_sectors(self):
        partition_start = 2_048
        with tempfile.TemporaryFile() as image:
            make_image(image.fileno(), volume_offset_sectors=partition_start)
            result = map_root_ldlinux(
                image.fileno(), volume_offset=partition_start * 512,
                volume_size=TOTAL_SECTORS * 512, expected_file=FILE_BYTES,
            )
            wrong = _vbr(hidden_sectors=0)
            os.pwrite(image.fileno(), wrong, partition_start * 512)
            os.pwrite(image.fileno(), wrong, (partition_start + 6) * 512)
            with self.assertRaisesRegex(SyslinuxPatchError, "hidden-sector"):
                map_root_ldlinux(
                    image.fileno(), volume_offset=partition_start * 512,
                    volume_size=TOTAL_SECTORS * 512, expected_file=FILE_BYTES,
                )
        self.assertEqual(result.volume_offset, partition_start * 512)
        self.assertEqual(result.sectors[0], DATA_START + 1)

    def test_complete_regular_file_patch_and_readback_vector(self):
        base, boot_code = patch_payloads()
        unpatched = base + make_empty_adv()
        with tempfile.TemporaryFile() as image:
            make_image(image.fileno(), file_bytes=unpatched)
            before = map_root_ldlinux(
                image.fileno(), volume_offset=0,
                volume_size=TOTAL_SECTORS * 512, expected_file=unpatched,
            )
            patched, patched_bss, _offset, _extents, sectors = patch_ldlinux(
                base, boot_code, list(before.sectors), directory="/isolinux",
            )
            patched_vbr, backup_sector = merge_fat32_boot_sector(
                before.boot_sector, patched_bss,
            )
            for index, sector in enumerate(sectors):
                chunk = patched[index * 512:(index + 1) * 512]
                os.pwrite(image.fileno(), chunk, sector * 512)
            os.pwrite(image.fileno(), patched_vbr, 0)
            os.pwrite(image.fileno(), patched_vbr, backup_sector * 512)
            os.fsync(image.fileno())
            after = map_root_ldlinux(
                image.fileno(), volume_offset=0,
                volume_size=TOTAL_SECTORS * 512, expected_file=patched,
            )
        self.assertEqual(after.sectors, before.sectors)
        self.assertEqual(after.boot_sector, patched_vbr)

    def test_exact_bundle_can_only_patch_its_descriptor_derived_map(self):
        base, boot_code = patch_payloads()
        unpatched = base + make_empty_adv()
        pins = {
            "ldlinux.bss": (len(boot_code), hashlib.sha256(boot_code).hexdigest()),
            "ldlinux.sys": (len(base), hashlib.sha256(base).hexdigest()),
        }
        bundle = BoundBootBundle(
            "syslinux", "fixture", "matched-bios-payloads",
            (
                BoundBootArtifact("ldlinux.bss", boot_code, pins["ldlinux.bss"][1]),
                BoundBootArtifact("ldlinux.sys", base, pins["ldlinux.sys"][1]),
            ),
            "GPL-2.0-or-later", "https://example.invalid/source",
        )
        with tempfile.TemporaryFile() as image:
            make_image(image.fileno(), file_bytes=unpatched)
            mapping = map_root_ldlinux(
                image.fileno(), volume_offset=0,
                volume_size=TOTAL_SECTORS * 512, expected_file=unpatched,
            )
            with patch(
                "isopropyl.syslinux.PINNED_SYSLINUX_PAYLOADS", {"fixture": pins},
            ), patch(
                "isopropyl.syslinux.PINNED_SYSLINUX_PROVENANCE",
                {"fixture": "https://example.invalid/source"},
            ):
                result = prepare_syslinux_patch_from_map(
                    bundle, image.fileno(), mapping, directory="/isolinux",
                )
                forged = replace(
                    mapping,
                    sectors=tuple(range(2_000, 2_000 + len(mapping.sectors))),
                )
                with self.assertRaisesRegex(SyslinuxPatchError, "changed since inspection"):
                    prepare_syslinux_patch_from_map(
                        bundle, image.fileno(), forged, directory="/isolinux",
                    )
        self.assertEqual(result.sector_map, mapping.sectors)
        self.assertNotEqual(result.ldlinux_file, unpatched)

    def test_complete_regular_disk_plan_binds_mbr_partition_and_live_fat_map(self):
        base, boot_code = patch_payloads()
        unpatched = base + make_empty_adv()
        pins = {
            "ldlinux.bss": (len(boot_code), hashlib.sha256(boot_code).hexdigest()),
            "ldlinux.sys": (len(base), hashlib.sha256(base).hexdigest()),
        }
        bundle = BoundBootBundle(
            "syslinux", "fixture", "matched-bios-payloads",
            (
                BoundBootArtifact("ldlinux.bss", boot_code, pins["ldlinux.bss"][1]),
                BoundBootArtifact("ldlinux.sys", base, pins["ldlinux.sys"][1]),
            ),
            "GPL-2.0-or-later", "https://example.invalid/source",
        )
        with tempfile.TemporaryFile() as image:
            make_image(
                image.fileno(), file_bytes=unpatched,
                volume_offset_sectors=2_048,
            )
            formatted_mbr = disk_mbr()
            os.pwrite(image.fileno(), formatted_mbr, 0)
            mapping = map_root_ldlinux(
                image.fileno(), volume_offset=2_048 * 512,
                volume_size=TOTAL_SECTORS * 512, expected_file=unpatched,
            )
            with patch(
                "isopropyl.syslinux.PINNED_SYSLINUX_PAYLOADS", {"fixture": pins},
            ), patch(
                "isopropyl.syslinux.PINNED_SYSLINUX_PROVENANCE",
                {"fixture": "https://example.invalid/source"},
            ):
                plan = prepare_syslinux_regular_file_plan(
                    bundle, image.fileno(), mapping, directory="/isolinux",
                )
        self.assertEqual(plan.mapping, mapping)
        self.assertEqual(plan.mbr.mbr[440:], formatted_mbr[440:])
        self.assertEqual(plan.mbr.partition_sector_count, TOTAL_SECTORS)
        self.assertEqual(plan.syslinux.sector_map, mapping.sectors)

    def test_rejects_disagreeing_fat_copies(self):
        with tempfile.TemporaryFile() as image:
            make_image(image.fileno())
            os.pwrite(
                image.fileno(), struct.pack("<I", 0x0FFFFFFF),
                (RESERVED + FAT_SECTORS) * 512 + 3 * 4,
            )
            with self.assertRaisesRegex(SyslinuxPatchError, "copies disagree"):
                map_root_ldlinux(
                    image.fileno(), volume_offset=0,
                    volume_size=TOTAL_SECTORS * 512, expected_file=FILE_BYTES,
                )

    def test_rejects_source_bytes_or_directory_alias_changes(self):
        with tempfile.TemporaryFile() as image:
            make_image(image.fileno())
            first_file_sector = DATA_START + 1
            os.pwrite(image.fileno(), b"changed", first_file_sector * 512)
            with self.assertRaisesRegex(SyslinuxPatchError, "bytes changed"):
                map_root_ldlinux(
                    image.fileno(), volume_offset=0,
                    volume_size=TOTAL_SECTORS * 512, expected_file=FILE_BYTES,
                )
        with tempfile.TemporaryFile() as image:
            make_image(image.fileno())
            lfn = bytearray(32)
            lfn[0] = 0x41
            lfn[11] = 0x0F
            checksum = 0
            for byte in b"LDLINUX SYS":
                checksum = (((checksum & 1) << 7) | (checksum >> 1)) + byte
                checksum &= 0xFF
            lfn[13] = checksum
            units = [ord(character) for character in "ldlinux.sys"] + [0, 0xFFFF]
            encoded = struct.pack("<13H", *units)
            lfn[1:11] = encoded[:10]
            lfn[14:26] = encoded[10:22]
            lfn[28:32] = encoded[22:]
            os.pwrite(image.fileno(), lfn, DATA_START * 512)
            entry = bytearray(32)
            entry[:11] = b"LDLINUX SYS"
            entry[11] = 0x07
            struct.pack_into("<H", entry, 26, 3)
            struct.pack_into("<I", entry, 28, len(FILE_BYTES))
            os.pwrite(image.fileno(), entry, DATA_START * 512 + 32)
            with self.assertRaisesRegex(SyslinuxPatchError, "long-name alias"):
                map_root_ldlinux(
                    image.fileno(), volume_offset=0,
                    volume_size=TOTAL_SECTORS * 512, expected_file=FILE_BYTES,
                )

    def test_rejects_bad_bounds_backup_and_cluster_loop(self):
        with tempfile.TemporaryFile() as image:
            make_image(image.fileno())
            for size in (TOTAL_SECTORS * 512 - 512, TOTAL_SECTORS * 512 + 512):
                with self.subTest(size=size), self.assertRaises(SyslinuxPatchError):
                    map_root_ldlinux(
                        image.fileno(), volume_offset=0,
                        volume_size=size, expected_file=FILE_BYTES,
                    )
            os.pwrite(image.fileno(), b"X", 6 * 512)
            with self.assertRaisesRegex(SyslinuxPatchError, "VBRs disagree"):
                map_root_ldlinux(
                    image.fileno(), volume_offset=0,
                    volume_size=TOTAL_SECTORS * 512, expected_file=FILE_BYTES,
                )
        with tempfile.TemporaryFile() as image:
            make_image(image.fileno())
            one_fat = bytearray(_vbr())
            one_fat[16] = 1
            os.pwrite(image.fileno(), one_fat, 0)
            os.pwrite(image.fileno(), one_fat, 6 * 512)
            with self.assertRaisesRegex(SyslinuxPatchError, "supported FAT32 profile"):
                map_root_ldlinux(
                    image.fileno(), volume_offset=0,
                    volume_size=TOTAL_SECTORS * 512, expected_file=FILE_BYTES,
                )
        with tempfile.TemporaryFile() as image:
            make_image(image.fileno(), chain=(3, 4, 5, 6, 7, 8))
            for index in range(2):
                os.pwrite(
                    image.fileno(), struct.pack("<I", 3),
                    (RESERVED + index * FAT_SECTORS) * 512 + 8 * 4,
                )
            with self.assertRaisesRegex(SyslinuxPatchError, "cluster loop|cluster limit"):
                map_root_ldlinux(
                    image.fileno(), volume_offset=0,
                    volume_size=TOTAL_SECTORS * 512, expected_file=FILE_BYTES,
                )


if __name__ == "__main__":
    unittest.main()
