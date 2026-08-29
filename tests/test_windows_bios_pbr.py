from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import isopropyl.windows_bios_pbr as windows_bios_pbr
from isopropyl.windows_bios_pbr import (
    MODERN_BOOTMGR_ENTRY_STUB,
    MODERN_BOOTMGR_MAX_SIZE,
    MODERN_BOOTMGR_MIN_SIZE,
    SECTOR_SIZE,
    STAGE_SECTOR,
    STAGE_SIZE,
    WindowsBiosPbrError,
    WindowsBootmgrBiosProfile,
    attest_fat32_bootmgr_pbr,
    classify_windows_bootmgr_bios,
    load_boot_code_artifacts,
    plan_fat32_bootmgr_pbr,
    verify_reproducible_boot_code,
)


ROOT = Path(__file__).resolve().parents[1]
TOTAL_SECTORS = 70_000
FAT_SECTORS = 600
RESERVED_SECTORS = 32
DATA_START = RESERVED_SECTORS + 2 * FAT_SECTORS
VOLUME_SIZE = TOTAL_SECTORS * SECTOR_SIZE
VOLUME_OFFSET = 2_048 * SECTOR_SIZE
IMAGE_SIZE = VOLUME_OFFSET + VOLUME_SIZE
REAL_LIKE_BOOTMGR_SIZE = 473_364


def boot_sector() -> bytes:
    value = bytearray(SECTOR_SIZE)
    value[:3] = b"\xeb\x58\x90"
    value[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", value, 11, SECTOR_SIZE)
    value[13] = 1
    struct.pack_into("<H", value, 14, RESERVED_SECTORS)
    value[16] = 2
    struct.pack_into("<H", value, 17, 0)
    struct.pack_into("<H", value, 19, 0)
    value[21] = 0xF8
    struct.pack_into("<H", value, 22, 0)
    struct.pack_into("<I", value, 28, VOLUME_OFFSET // SECTOR_SIZE)
    struct.pack_into("<I", value, 32, TOTAL_SECTORS)
    struct.pack_into("<I", value, 36, FAT_SECTORS)
    struct.pack_into("<H", value, 40, 0)
    struct.pack_into("<H", value, 42, 0)
    struct.pack_into("<I", value, 44, 2)
    struct.pack_into("<H", value, 48, 1)
    struct.pack_into("<H", value, 50, 6)
    value[64] = 0x80
    value[66] = 0x29
    value[67:71] = b"TEST"
    value[71:82] = b"ISOPROPYL  "
    value[82:90] = b"FAT32   "
    value[90:510] = bytes((index * 17 + 3) & 0xFF for index in range(420))
    value[510:512] = b"\x55\xaa"
    return bytes(value)


def fsinfo_sector() -> bytes:
    value = bytearray((index * 29 + 7) & 0xFF for index in range(SECTOR_SIZE))
    value[:4] = b"RRaA"
    value[484:488] = b"rrAa"
    value[508:512] = b"\0\0\x55\xaa"
    return bytes(value)


def make_image(path: Path) -> int:
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    os.ftruncate(descriptor, IMAGE_SIZE)
    mbr = bytearray(SECTOR_SIZE)
    mbr[440:444] = b"ISOP"
    mbr[446] = 0x80
    mbr[450] = 0x0C
    struct.pack_into("<I", mbr, 454, VOLUME_OFFSET // SECTOR_SIZE)
    struct.pack_into("<I", mbr, 458, TOTAL_SECTORS)
    mbr[510:512] = b"\x55\xaa"
    os.pwrite(descriptor, mbr, 0)
    boot = boot_sector()
    fsinfo = fsinfo_sector()
    os.pwrite(descriptor, boot, VOLUME_OFFSET)
    os.pwrite(descriptor, fsinfo, VOLUME_OFFSET + SECTOR_SIZE)
    os.pwrite(descriptor, boot, VOLUME_OFFSET + 6 * SECTOR_SIZE)
    os.pwrite(descriptor, fsinfo, VOLUME_OFFSET + 7 * SECTOR_SIZE)
    return descriptor


def apply_plan(descriptor: int, plan) -> None:
    for write in plan.writes:
        os.pwrite(descriptor, write.data, write.offset)
    os.fsync(descriptor)


class WindowsBiosPbrTests(unittest.TestCase):
    def test_modern_bootmgr_classifier_is_exact_and_bounded(self) -> None:
        self.assertIs(
            classify_windows_bootmgr_bios(
                MODERN_BOOTMGR_ENTRY_STUB,
                file_size=REAL_LIKE_BOOTMGR_SIZE,
            ),
            WindowsBootmgrBiosProfile.MODERN_ENTRY_ZERO,
        )
        self.assertIs(
            classify_windows_bootmgr_bios(
                MODERN_BOOTMGR_ENTRY_STUB,
                file_size=MODERN_BOOTMGR_MAX_SIZE,
            ),
            WindowsBootmgrBiosProfile.MODERN_ENTRY_ZERO,
        )
        for header, size in (
            (b"MZ\0\0\0\0", REAL_LIKE_BOOTMGR_SIZE),
            (MODERN_BOOTMGR_ENTRY_STUB, MODERN_BOOTMGR_MIN_SIZE - 1),
            (MODERN_BOOTMGR_ENTRY_STUB, MODERN_BOOTMGR_MAX_SIZE + 1),
        ):
            with self.subTest(header=header, size=size):
                with self.assertRaises(WindowsBiosPbrError):
                    classify_windows_bootmgr_bios(header, file_size=size)

    def test_sources_reproduce_pinned_project_artifacts(self) -> None:
        if not Path("/usr/bin/as").is_file() or not Path("/usr/bin/ld").is_file():
            self.skipTest("GNU binutils are unavailable")
        artifacts = verify_reproducible_boot_code(ROOT)
        self.assertEqual(len(artifacts.stage0), SECTOR_SIZE)
        self.assertEqual(len(artifacts.stage2), STAGE_SIZE)
        self.assertEqual(artifacts.stage0[3:90], bytes(87))
        self.assertIn(b"BOOTMGR    ", artifacts.stage2)
        # push 0x2000; push 0; retf is the stage's encoded far transfer to
        # 2000:0000.  The runtime marker cannot distinguish entry zero from a
        # loader that skipped directly to the header's near-jump destination.
        self.assertEqual(artifacts.stage2.count(bytes.fromhex("6800206a00cb")), 1)

    def test_plan_preserves_bpb_fsinfo_signatures_and_orders_activation_last(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fat32.img"
            descriptor = make_image(path)
            try:
                before = os.pread(
                    descriptor, VOLUME_OFFSET + RESERVED_SECTORS * SECTOR_SIZE, 0,
                )
                plan = plan_fat32_bootmgr_pbr(
                    descriptor, volume_offset=VOLUME_OFFSET, volume_size=VOLUME_SIZE,
                )
                self.assertEqual(
                    tuple(write.role for write in plan.writes),
                    ("stage", "backup-vbr", "primary-vbr", "mbr"),
                )
                self.assertEqual(
                    plan.stage_offset, VOLUME_OFFSET + STAGE_SECTOR * SECTOR_SIZE,
                )
                self.assertEqual(plan.writes[1].data, plan.writes[2].data)
                self.assertEqual(
                    plan.writes[2].data[3:90],
                    before[VOLUME_OFFSET + 3:VOLUME_OFFSET + 90],
                )
                self.assertEqual(plan.writes[2].data[510:512], b"\x55\xaa")
                apply_plan(descriptor, plan)
                attest_fat32_bootmgr_pbr(descriptor, plan)
                after = os.pread(
                    descriptor, VOLUME_OFFSET + RESERVED_SECTORS * SECTOR_SIZE, 0,
                )
            finally:
                os.close(descriptor)

            allowed = set(range(440))
            allowed |= set(range(VOLUME_OFFSET, VOLUME_OFFSET + 3))
            allowed |= set(range(VOLUME_OFFSET + 90, VOLUME_OFFSET + 510))
            allowed |= set(range(VOLUME_OFFSET + 6 * SECTOR_SIZE, VOLUME_OFFSET + 6 * SECTOR_SIZE + 3))
            allowed |= set(range(VOLUME_OFFSET + 6 * SECTOR_SIZE + 90, VOLUME_OFFSET + 7 * SECTOR_SIZE - 2))
            allowed |= set(range(
                VOLUME_OFFSET + STAGE_SECTOR * SECTOR_SIZE,
                VOLUME_OFFSET + STAGE_SECTOR * SECTOR_SIZE + STAGE_SIZE,
            ))
            changed = {index for index, pair in enumerate(zip(before, after)) if pair[0] != pair[1]}
            self.assertTrue(changed)
            self.assertTrue(changed <= allowed)
            self.assertEqual(
                after[VOLUME_OFFSET + SECTOR_SIZE:VOLUME_OFFSET + 2 * SECTOR_SIZE],
                fsinfo_sector(),
            )
            self.assertEqual(
                after[VOLUME_OFFSET + 7 * SECTOR_SIZE:VOLUME_OFFSET + 8 * SECTOR_SIZE],
                fsinfo_sector(),
            )

    def test_nonempty_stage_and_post_patch_tampering_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fat32.img"
            descriptor = make_image(path)
            try:
                os.pwrite(descriptor, b"x", VOLUME_OFFSET + STAGE_SECTOR * SECTOR_SIZE)
                with self.assertRaisesRegex(WindowsBiosPbrError, "not empty"):
                    plan_fat32_bootmgr_pbr(
                        descriptor, volume_offset=VOLUME_OFFSET, volume_size=VOLUME_SIZE,
                    )
                os.pwrite(descriptor, b"\0", VOLUME_OFFSET + STAGE_SECTOR * SECTOR_SIZE)
                plan = plan_fat32_bootmgr_pbr(
                    descriptor, volume_offset=VOLUME_OFFSET, volume_size=VOLUME_SIZE,
                )
                apply_plan(descriptor, plan)
                os.pwrite(descriptor, b"x", plan.fsinfo_offset + 100)
                with self.assertRaisesRegex(WindowsBiosPbrError, "FSInfo changed"):
                    attest_fat32_bootmgr_pbr(descriptor, plan)
            finally:
                os.close(descriptor)

    def test_rejects_non_regular_descriptors_and_inconsistent_artifacts(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            with self.assertRaisesRegex(WindowsBiosPbrError, "regular-file"):
                plan_fat32_bootmgr_pbr(read_fd, volume_offset=0, volume_size=SECTOR_SIZE)
        finally:
            os.close(read_fd)
            os.close(write_fd)
        artifacts = load_boot_code_artifacts()
        self.assertEqual(artifacts.stage0_sha256, artifacts.stage0_sha256.lower())
        with tempfile.TemporaryDirectory() as directory:
            descriptor = make_image(Path(directory) / "fat32.img")
            try:
                altered = replace(
                    artifacts,
                    stage2=artifacts.stage2[:-1] + bytes([artifacts.stage2[-1] ^ 1]),
                )
                with self.assertRaisesRegex(WindowsBiosPbrError, "not self-consistent"):
                    plan_fat32_bootmgr_pbr(
                        descriptor,
                        volume_offset=VOLUME_OFFSET,
                        volume_size=VOLUME_SIZE,
                        artifacts=altered,
                    )
            finally:
                os.close(descriptor)

    def test_short_reads_and_eintr_are_completed(self) -> None:
        with mock.patch.object(
            windows_bios_pbr.os,
            "pread",
            side_effect=(InterruptedError(), b"ab", b"c"),
        ) as pread:
            self.assertEqual(
                windows_bios_pbr._pread_exact(9, 100, 3, "fixture"),
                b"abc",
            )
        self.assertEqual(
            pread.call_args_list,
            [mock.call(9, 3, 100), mock.call(9, 3, 100), mock.call(9, 1, 102)],
        )

    def test_attestation_rejects_rehashed_malformed_witness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            descriptor = make_image(Path(directory) / "fat32.img")
            try:
                plan = plan_fat32_bootmgr_pbr(
                    descriptor,
                    volume_offset=VOLUME_OFFSET,
                    volume_size=VOLUME_SIZE,
                )
                apply_plan(descriptor, plan)
                forged = replace(plan, stage_offset=plan.stage_offset + SECTOR_SIZE)
                forged = replace(
                    forged,
                    plan_sha256=windows_bios_pbr._plan_digest(forged),
                )
                with self.assertRaisesRegex(WindowsBiosPbrError, "malformed"):
                    attest_fat32_bootmgr_pbr(descriptor, forged)
            finally:
                os.close(descriptor)

    def test_rejects_128_sector_clusters_consistently_with_stage2(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            descriptor = make_image(Path(directory) / "fat32.img")
            try:
                primary = bytearray(os.pread(descriptor, SECTOR_SIZE, VOLUME_OFFSET))
                primary[13] = 128
                os.pwrite(descriptor, primary, VOLUME_OFFSET)
                os.pwrite(descriptor, primary, VOLUME_OFFSET + 6 * SECTOR_SIZE)
                with self.assertRaisesRegex(WindowsBiosPbrError, "supported FAT32"):
                    plan_fat32_bootmgr_pbr(
                        descriptor,
                        volume_offset=VOLUME_OFFSET,
                        volume_size=VOLUME_SIZE,
                    )
            finally:
                os.close(descriptor)

    @unittest.skipUnless(
        Path("/usr/bin/qemu-system-i386").is_file(),
        "QEMU/SeaBIOS is unavailable",
    )
    def test_fragmented_root_and_473364_byte_modern_marker_reaches_header_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boot.img"
            descriptor = make_image(path)
            try:
                # Root directory deliberately spans cluster 2 -> cluster 5.
                entries = bytearray(SECTOR_SIZE)
                for offset in range(0, SECTOR_SIZE, 32):
                    entries[offset] = 0xE5
                os.pwrite(
                    descriptor, entries, VOLUME_OFFSET + (DATA_START + 0) * SECTOR_SIZE,
                )
                root = bytearray(SECTOR_SIZE)
                root[:11] = b"BOOTMGR    "
                root[11] = 0x20
                first_file_cluster = 10
                struct.pack_into("<H", root, 20, first_file_cluster >> 16)
                struct.pack_into("<H", root, 26, first_file_cluster & 0xFFFF)
                struct.pack_into("<I", root, 28, REAL_LIKE_BOOTMGR_SIZE)
                os.pwrite(
                    descriptor, root, VOLUME_OFFSET + (DATA_START + 3) * SECTOR_SIZE,
                )

                cluster_count = (REAL_LIKE_BOOTMGR_SIZE + SECTOR_SIZE - 1) // SECTOR_SIZE
                file_clusters = tuple(first_file_cluster + index * 2 for index in range(cluster_count))
                fat = bytearray(FAT_SECTORS * SECTOR_SIZE)
                struct.pack_into("<I", fat, 0, 0x0FFFFFF8)
                struct.pack_into("<I", fat, 4, 0x0FFFFFFF)
                struct.pack_into("<I", fat, 2 * 4, 5)
                struct.pack_into("<I", fat, 5 * 4, 0x0FFFFFFF)
                for index, cluster in enumerate(file_clusters):
                    successor = file_clusters[index + 1] if index + 1 < len(file_clusters) else 0x0FFFFFFF
                    struct.pack_into("<I", fat, cluster * 4, successor)
                os.pwrite(descriptor, fat, VOLUME_OFFSET + RESERVED_SECTORS * SECTOR_SIZE)
                os.pwrite(
                    descriptor, fat,
                    VOLUME_OFFSET + (RESERVED_SECTORS + FAT_SECTORS) * SECTOR_SIZE,
                )

                marker = bytearray(REAL_LIKE_BOOTMGR_SIZE)
                # Match the modern LTSC BOOTMGR entry stub and keep its initial
                # near jump live.  The reproducible-artifact assertion above,
                # rather than this marker alone, binds the transfer to offset 0.
                marker[:6] = MODERN_BOOTMGR_ENTRY_STUB
                marker_code = bytes.fromhex(
                    "81fa80007518"
                    "bae900b049eeb04feeb04beeb021eebaf400b010eef4ebfd"
                )
                marker[0x1D8:0x1D8 + len(marker_code)] = marker_code
                for index, cluster in enumerate(file_clusters):
                    block = marker[index * SECTOR_SIZE:(index + 1) * SECTOR_SIZE]
                    os.pwrite(
                        descriptor, block.ljust(SECTOR_SIZE, b"\0"),
                        VOLUME_OFFSET + (DATA_START + cluster - 2) * SECTOR_SIZE,
                    )
                plan = plan_fat32_bootmgr_pbr(
                    descriptor, volume_offset=VOLUME_OFFSET, volume_size=VOLUME_SIZE,
                )
                apply_plan(descriptor, plan)
                attest_fat32_bootmgr_pbr(descriptor, plan)
            finally:
                os.close(descriptor)

            completed = subprocess.run(
                [
                    "/usr/bin/qemu-system-i386", "-nodefaults", "-machine", "pc,accel=tcg",
                    "-m", "16", "-drive", f"file={path},format=raw,if=ide",
                    "-nographic", "-monitor", "none", "-serial", "none",
                    "-debugcon", "stdio", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                    "-no-reboot",
                ],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=20, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            )
            self.assertIn(b"IOK!", completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
