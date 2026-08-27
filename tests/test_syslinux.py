from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import os
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

from isopropyl.bootloaders import BoundBootArtifact, BoundBootBundle
from isopropyl.syslinux import (
    ADV_MAGIC1,
    ADV_MAGIC2,
    ADV_MAGIC3,
    LDLINUX_MAGIC,
    PINNED_SYSLINUX_PAYLOADS,
    PINNED_SYSLINUX_PROVENANCE,
    SYSLINUX_MBR_602,
    SYSLINUX_MBR_602_SHA256,
    SectorExtent,
    SyslinuxPatchError,
    bind_syslinux_bundle,
    make_empty_adv,
    merge_fat32_boot_sector,
    patch_ldlinux,
    prepare_syslinux_mbr,
    prepare_syslinux_patch,
)


def payloads(*, extent_count: int = 8, directory_length: int = 32):
    image = bytearray(2_048)
    patch_offset = 24
    epa_offset = 100
    struct.pack_into(
        "<IIHHIIHH", image, patch_offset,
        LDLINUX_MAGIC, 0x12345678, 0, 0, 0, 0, 127, epa_offset,
    )
    struct.pack_into(
        "<10H", image, epa_offset,
        180, 220, directory_length, 260, 16, 300, extent_count,
        100, 104, 108,
    )
    boot = bytearray(512)
    boot[0:11] = b"\xeb\x58\x90SYSLINUX"
    boot[90:510] = bytes((index * 17) & 0xFF for index in range(420))
    boot[510:512] = b"\x55\xaa"
    return bytes(image), bytes(boot)


def vbr(**changes) -> bytes:
    sector = bytearray(512)
    sector[0:3] = b"\xeb\x58\x90"
    sector[3:11] = b"mkfs.fat"
    struct.pack_into("<H", sector, 11, changes.get("bytes_per_sector", 512))
    sector[13] = changes.get("sectors_per_cluster", 1)
    struct.pack_into("<H", sector, 14, changes.get("reserved", 32))
    sector[16] = changes.get("fat_count", 2)
    struct.pack_into("<H", sector, 17, changes.get("root_entries", 0))
    struct.pack_into("<H", sector, 19, changes.get("total16", 0))
    sector[21] = changes.get("media", 0xF8)
    struct.pack_into("<H", sector, 22, changes.get("fat16_size", 0))
    struct.pack_into("<I", sector, 32, changes.get("total_sectors", 200_000))
    struct.pack_into("<I", sector, 36, changes.get("fat_size", 2_000))
    struct.pack_into("<H", sector, 42, changes.get("filesystem_version", 0))
    struct.pack_into("<I", sector, 44, changes.get("root_cluster", 2))
    struct.pack_into("<H", sector, 48, changes.get("fsinfo", 1))
    struct.pack_into("<H", sector, 50, changes.get("backup", 6))
    sector[64] = 0x80
    sector[66] = changes.get("boot_signature", 0x29)
    sector[71:82] = b"ISOPROPYL  "
    sector[82:90] = changes.get("filesystem_type", b"FAT32   ")
    sector[510:512] = changes.get("signature", b"\x55\xaa")
    return bytes(sector)


def mbr(**changes) -> bytes:
    sector = bytearray(512)
    sector[440:444] = changes.get("disk_signature", b"\x12\x34\x56\x78")
    sector[444:446] = changes.get("reserved", b"\0\0")
    entry = bytearray(16)
    entry[0] = changes.get("bootable", 0x80)
    entry[1:4] = b"\x00\x02\x00"
    entry[4] = changes.get("partition_type", 0x0C)
    entry[5:8] = b"\xfe\xff\xff"
    struct.pack_into("<I", entry, 8, changes.get("start", 2_048))
    struct.pack_into("<I", entry, 12, changes.get("count", 100_000))
    sector[446:462] = entry
    sector[510:512] = changes.get("signature", b"\x55\xaa")
    if changes.get("extra_partition", False):
        sector[462:478] = entry
    return bytes(sector)


class AdvTests(unittest.TestCase):
    def test_empty_adv_has_two_identical_valid_copies(self):
        adv = make_empty_adv()
        self.assertEqual(len(adv), 1_024)
        self.assertEqual(adv[:512], adv[512:])
        self.assertEqual(struct.unpack_from("<I", adv, 0)[0], ADV_MAGIC1)
        self.assertEqual(struct.unpack_from("<I", adv, 4)[0], ADV_MAGIC2)
        self.assertEqual(struct.unpack_from("<I", adv, 508)[0], ADV_MAGIC3)
        values = struct.unpack("<126I", adv[4:508])
        self.assertEqual(sum(values) & 0xFFFFFFFF, ADV_MAGIC2)


class MbrTests(unittest.TestCase):
    def test_pinned_bootstrap_has_expected_length_and_digest(self):
        self.assertEqual(len(SYSLINUX_MBR_602), 440)
        self.assertEqual(
            hashlib.sha256(SYSLINUX_MBR_602).hexdigest(),
            SYSLINUX_MBR_602_SHA256,
        )

    def test_merges_only_bootstrap_and_preserves_all_mbr_metadata(self):
        original = mbr()
        result = prepare_syslinux_mbr(
            original,
            partition_start_sector=2_048,
            partition_sector_count=100_000,
        )
        self.assertEqual(result.mbr[:440], SYSLINUX_MBR_602)
        self.assertEqual(result.mbr[440:], original[440:])
        self.assertEqual(result.partition_start_sector, 2_048)
        self.assertEqual(result.partition_sector_count, 100_000)

    def test_rejects_unpinned_bootstrap_and_nonexact_mbr_profiles(self):
        changed = bytearray(SYSLINUX_MBR_602)
        changed[0] ^= 1
        cases = (
            (mbr(), {"bootstrap": bytes(changed)}),
            (mbr(bootable=0), {}),
            (mbr(partition_type=0x0B), {}),
            (mbr(start=4_096), {}),
            (mbr(count=99_999), {}),
            (mbr(extra_partition=True), {}),
            (mbr(reserved=b"\x01\0"), {}),
            (mbr(signature=b"\0\0"), {}),
        )
        for formatted, extra in cases:
            with self.subTest(extra=extra), self.assertRaises(SyslinuxPatchError):
                prepare_syslinux_mbr(
                    formatted,
                    partition_start_sector=2_048,
                    partition_sector_count=100_000,
                    **extra,
                )

    def test_rejects_unaddressable_or_empty_partition_plans(self):
        for start, count in (
            (0, 100_000),
            (2_048, 0),
            (2_048, -1),
            (2_048, 0xFFFFFFFF),
            (True, 100_000),
        ):
            with self.subTest(start=start, count=count), self.assertRaises(
                SyslinuxPatchError,
            ):
                prepare_syslinux_mbr(
                    mbr(start=int(start), count=max(0, min(int(count), 0xFFFFFFFF))),
                    partition_start_sector=start,
                    partition_sector_count=count,
                )


class PatchTests(unittest.TestCase):
    def test_matches_independent_field_and_checksum_vector(self):
        image, boot = payloads()
        result, patched_boot, offset, extents, sector_map = patch_ldlinux(
            image, boot, [100, 101, 102, 104, 200, 201], directory="/isolinux",
        )
        self.assertEqual(offset, 24)
        self.assertEqual(sector_map, (100, 101, 102, 104, 200, 201))
        self.assertEqual(extents, (SectorExtent(101, 2), SectorExtent(104, 1)))
        self.assertEqual(len(result), 3_072)
        self.assertEqual(result[2_048:], make_empty_adv())
        self.assertEqual(struct.unpack_from("<I", patched_boot, 100)[0], 100)
        self.assertEqual(struct.unpack_from("<I", patched_boot, 104)[0], 0)
        self.assertEqual(struct.unpack_from("<HHI", result, 32), (4, 2, 512))
        self.assertEqual(struct.unpack_from("<Q", result, 180)[0], 200)
        self.assertEqual(struct.unpack_from("<Q", result, 188)[0], 201)
        self.assertEqual(result[220:230], b"/isolinux\0")
        self.assertEqual(struct.unpack_from("<QH", result, 300), (101, 2))
        self.assertEqual(struct.unpack_from("<QH", result, 310), (104, 1))
        self.assertEqual(result[320:380], b"\0" * 60)
        dwords = len(image) // 4
        self.assertEqual(
            sum(struct.unpack_from(f"<{dwords}I", result)) & 0xFFFFFFFF,
            LDLINUX_MAGIC,
        )

    def test_breaks_contiguous_extents_at_real_mode_boundaries(self):
        image, boot = payloads(extent_count=4)
        image = bytearray(image)
        # Enlarge the image so its exact sector map includes 130 data sectors,
        # plus the boot-sector pointer and two ADVs.
        image.extend(b"\0" * (131 * 512 - len(image)))
        sectors = list(range(1_000, 1_133))
        result = patch_ldlinux(bytes(image), boot, sectors)
        self.assertEqual(result[3], (SectorExtent(1_001, 127), SectorExtent(1_128, 3)))

    def test_rejects_extent_table_overflow(self):
        image, boot = payloads(extent_count=1)
        with self.assertRaisesRegex(SyslinuxPatchError, "extent table"):
            patch_ldlinux(image, boot, [100, 101, 103, 104, 200, 201])

    def test_rejects_duplicate_or_wrong_length_sector_maps(self):
        image, boot = payloads()
        for sectors in ([100] * 6, [100] * 5, [100, 101, 102, 103, 104, True]):
            with self.subTest(sectors=sectors), self.assertRaises(SyslinuxPatchError):
                patch_ldlinux(image, boot, sectors)

    def test_rejects_payload_above_the_bounded_patch_size(self):
        _image, boot = payloads()
        with self.assertRaisesRegex(SyslinuxPatchError, "invalid size"):
            patch_ldlinux(b"\0" * (16 * 1024 * 1024 + 1), boot, [])

    def test_rejects_multiple_patch_magics(self):
        image, boot = payloads()
        changed = bytearray(image)
        struct.pack_into("<I", changed, 600, LDLINUX_MAGIC)
        with self.assertRaisesRegex(SyslinuxPatchError, "one aligned patch area"):
            patch_ldlinux(bytes(changed), boot, [100, 101, 102, 103, 200, 201])

    def test_rejects_out_of_bounds_patch_regions(self):
        image, boot = payloads()
        changed = bytearray(image)
        struct.pack_into("<H", changed, 24 + 22, len(changed) - 10)
        with self.assertRaisesRegex(SyslinuxPatchError, "extended patch area"):
            patch_ldlinux(bytes(changed), boot, [100, 101, 102, 103, 200, 201])

    def test_rejects_boot_pointer_outside_copied_fat32_code(self):
        image, boot = payloads()
        changed = bytearray(image)
        struct.pack_into("<H", changed, 100 + 14, 507)
        with self.assertRaisesRegex(SyslinuxPatchError, "outside FAT32 boot code"):
            patch_ldlinux(bytes(changed), boot, [100, 101, 102, 103, 200, 201])

    def test_rejects_overlapping_patch_regions(self):
        image, boot = payloads()
        changed = bytearray(image)
        # Move the extent table over the patch area's magic and metadata.
        struct.pack_into("<H", changed, 100 + 10, 24)
        with self.assertRaisesRegex(SyslinuxPatchError, "overlaps"):
            patch_ldlinux(bytes(changed), boot, [100, 101, 102, 103, 200, 201])

    def test_rejects_noncanonical_or_oversized_directory(self):
        image, boot = payloads(directory_length=5)
        for directory in ("relative", "/a/../b", "/trail/", "/é", "/long"):
            with self.subTest(directory=directory), self.assertRaises(SyslinuxPatchError):
                patch_ldlinux(
                    image, boot, [100, 101, 102, 103, 200, 201],
                    directory=directory,
                )


class VbrTests(unittest.TestCase):
    def test_merges_only_jump_oem_and_fat32_code(self):
        _image, boot = payloads()
        original = vbr()
        merged, backup = merge_fat32_boot_sector(original, boot)
        self.assertEqual(backup, 6)
        self.assertEqual(merged[:11], boot[:11])
        self.assertEqual(merged[11:90], original[11:90])
        self.assertEqual(merged[90:510], boot[90:510])
        self.assertEqual(merged[510:512], b"\x55\xaa")

    def test_rejects_non_fat32_and_invalid_reserved_metadata(self):
        _image, boot = payloads()
        invalid = (
            vbr(bytes_per_sector=4096),
            vbr(fat_count=1),
            vbr(filesystem_type=b"FAT16   "),
            vbr(total_sectors=0xFFFFFFFF, fat_size=2_100_000),
            vbr(total_sectors=2_000),
            vbr(root_cluster=300_000),
            vbr(fsinfo=6),
            vbr(backup=32),
            vbr(signature=b"\0\0"),
        )
        for sector in invalid:
            with self.subTest(hash=hashlib.sha256(sector).hexdigest()), self.assertRaises(
                SyslinuxPatchError,
            ):
                merge_fat32_boot_sector(sector, boot)


class BundleTests(unittest.TestCase):
    def test_independently_rejects_catalog_metadata_without_matching_bytes(self):
        artifacts = tuple(
            BoundBootArtifact(name, b"x" * size, digest)
            for name, (size, digest) in PINNED_SYSLINUX_PAYLOADS["6.03-2014-10-06"].items()
        )
        bundle = BoundBootBundle(
            "syslinux", "6.03-2014-10-06", "matched-bios-payloads",
            artifacts, "GPL-2.0-or-later",
            PINNED_SYSLINUX_PROVENANCE["6.03-2014-10-06"],
        )
        with self.assertRaisesRegex(SyslinuxPatchError, "pinned payload"):
            bind_syslinux_bundle(bundle)

    def test_accepts_complete_exact_bundle_at_the_consumer_boundary(self):
        fixture = {"ldlinux.bss": b"bss", "ldlinux.sys": b"sys"}
        pins = {
            name: (len(data), hashlib.sha256(data).hexdigest())
            for name, data in fixture.items()
        }
        artifacts = tuple(
            BoundBootArtifact(name, fixture[name], pins[name][1]) for name in pins
        )
        bundle = BoundBootBundle(
            "syslinux", "fixture", "matched-bios-payloads", artifacts,
            "GPL-2.0-or-later", "https://example.invalid/source",
        )
        with patch("isopropyl.syslinux.PINNED_SYSLINUX_PAYLOADS", {"fixture": pins}):
            with patch(
                "isopropyl.syslinux.PINNED_SYSLINUX_PROVENANCE",
                {"fixture": "https://example.invalid/source"},
            ):
                bound = bind_syslinux_bundle(bundle)
        self.assertEqual(bound.version, "fixture")
        self.assertEqual(bound.ldlinux_sys, b"sys")
        self.assertEqual(bound.ldlinux_bss, b"bss")


_REAL_FIXTURE_DIRECTORY = os.environ.get("ISOPROPYL_SYSLINUX_FIXTURES", "")


@unittest.skipUnless(
    _REAL_FIXTURE_DIRECTORY,
    "set ISOPROPYL_SYSLINUX_FIXTURES for offline pinned-payload golden tests",
)
class RealPayloadGoldenTests(unittest.TestCase):
    """Compare real pinned bytes with frozen outputs from the upstream algorithm.

    The fixture directory contains a version-named directory for each cataloged
    release, each with ``ldlinux.bss`` and ``ldlinux.sys``.  Normal CI never
    downloads executable boot payloads implicitly.
    """

    def test_pinned_603_and_604_vectors(self):
        expected_outputs = {
            "6.03-2014-10-06": (
                "aa4b2f0804a1e56032ff264b9cd1ede87e02552e55f5fb52c25208e3091dc77a",
                "b57cc19153d30c0966648284a9c4489d71c022da729bf8b2acc5241321dc75e0",
            ),
            "6.04-pre1": (
                "5afd390ded15fb24ae6f06bdc9d4e388d4eb505147dd3e3b453e712e1b136c38",
                "a714a4a8f70ffa59fb82019884ae85c06a2df952670ec60d19d880cbee3278b5",
            ),
        }
        root = Path(_REAL_FIXTURE_DIRECTORY)
        for version, expected in expected_outputs.items():
            with self.subTest(version=version):
                directory = root / version
                bss = (directory / "ldlinux.bss").read_bytes()
                system = (directory / "ldlinux.sys").read_bytes()
                bundle = BoundBootBundle(
                    "syslinux", version, "matched-bios-payloads",
                    (
                        BoundBootArtifact(
                            "ldlinux.bss", bss, hashlib.sha256(bss).hexdigest(),
                        ),
                        BoundBootArtifact(
                            "ldlinux.sys", system, hashlib.sha256(system).hexdigest(),
                        ),
                    ),
                    "GPL-2.0-or-later", PINNED_SYSLINUX_PROVENANCE[version],
                )
                sector_count = (len(system) + 1_024 + 511) // 512
                result = prepare_syslinux_patch(
                    bundle,
                    vbr(),
                    list(range(4_096, 4_096 + sector_count)),
                    volume_offset=0,
                    directory="/isolinux",
                )
                self.assertEqual(result.ldlinux_sha256, expected[0])
                self.assertEqual(result.boot_sector_sha256, expected[1])


if __name__ == "__main__":
    unittest.main()
