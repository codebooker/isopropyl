from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

import isopropyl.syslinux_device_helper as helper
import tests.test_syslinux_device_helper as syslinux_fixtures
from isopropyl.syslinux_device_helper import (
    HelperRequest,
    HelperRequestError,
    HelperSourceError,
    WINDOWS_HELPER_PROFILE,
    pack_windows_helper_control,
    pack_windows_helper_request,
    unpack_helper_request,
    unpack_windows_helper_request,
    unpack_windows_server_packet,
)
from isopropyl.windows_iso_fat32 import prepare_windows_iso_fat32
from tests.test_windows_iso_fat32 import WindowsIsoFat32Tests


REQUEST_ID = bytes(range(16))
DISK_SEQUENCE = 9_881_337


class WindowsDeviceHelperTests(unittest.TestCase):
    def _plan(self, directory: str):
        plan, _workspace = WindowsIsoFat32Tests().build_plan(directory)
        return plan

    def test_request_and_control_use_a_distinct_fixed_binary_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sys_root = Path(directory)
            block = sys_root / "dev" / "block" / "8:240"
            block.mkdir(parents=True)
            (block / "uevent").write_text("DEVNAME=sdz\n", encoding="ascii")
            packet = pack_windows_helper_request(
                REQUEST_ID, 8, 240, DISK_SEQUENCE, 40 * 1024 * 1024, 512,
                0x12345678, 0x87654321, "ab" * 32,
            )
            request = unpack_windows_helper_request(packet, sys_root=sys_root)
            self.assertEqual(request.profile, WINDOWS_HELPER_PROFILE)
            self.assertEqual(request.target_path, "/dev/sdz")
            self.assertEqual(request.expected_sha256, "ab" * 32)
            self.assertNotIn(b"/dev/", packet)
            with self.assertRaises(HelperRequestError):
                unpack_helper_request(packet, sys_root=sys_root)

            control = pack_windows_helper_control(REQUEST_ID, commit=True)
            self.assertEqual(
                control[:len(helper.WINDOWS_PROTOCOL_MAGIC)],
                helper.WINDOWS_PROTOCOL_MAGIC,
            )
            with self.assertRaises(HelperRequestError):
                helper.unpack_server_packet(control)
            ready = helper._HEADER.pack(
                helper.WINDOWS_PROTOCOL_MAGIC,
                helper.PROTOCOL_VERSION,
                helper.PACKET_READY,
                0,
            )
            self.assertEqual(unpack_windows_server_packet(ready), ("ready",))

    def test_root_layout_validator_accepts_only_the_composed_windows_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan = self._plan(directory)
            with prepare_windows_iso_fat32(plan) as prepared:
                result = prepared.result
                with tempfile.TemporaryFile() as image:
                    digest = hashlib.sha256()
                    for chunk in prepared.chunks():
                        image.write(chunk)
                        digest.update(chunk)
                    image.flush()
                    request = HelperRequest(
                        REQUEST_ID,
                        WINDOWS_HELPER_PROFILE,
                        "/dev/sdz",
                        "8:240",
                        DISK_SEQUENCE,
                        result.image_size,
                        512,
                        result.disk_signature,
                        result.volume_id,
                        digest.hexdigest(),
                    )
                    observed_mbr = helper._validate_windows_image_layout(
                        image.fileno(), request, read_at=os.pread,
                    )
                    self.assertEqual(observed_mbr[510:512], b"\x55\xaa")
                    volume = helper.PARTITION_START_SECTOR * helper.SECTOR_SIZE
                    stage = volume + 12 * helper.SECTOR_SIZE
                    byte = os.pread(image.fileno(), 1, stage)
                    os.pwrite(image.fileno(), bytes([byte[0] ^ 1]), stage)
                    with self.assertRaisesRegex(HelperSourceError, "BIOS stage"):
                        helper._validate_windows_image_layout(
                            image.fileno(), request, read_at=os.pread,
                        )

    def test_modern_bootmgr_entry_is_checked_independently_of_whole_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan = self._plan(directory)
            with prepare_windows_iso_fat32(plan) as prepared:
                result = prepared.result
                with tempfile.TemporaryFile() as image:
                    for chunk in prepared.chunks():
                        image.write(chunk)
                    image.flush()
                    request = HelperRequest(
                        REQUEST_ID, WINDOWS_HELPER_PROFILE, "/dev/sdz", "8:240",
                        DISK_SEQUENCE, result.image_size, 512,
                        result.disk_signature, result.volume_id,
                        result.final_image_sha256,
                    )
                    bootmgr = plan.private_plan.geometry.volume_offset
                    # Locate the root entry and derive its data offset through
                    # the same bounded FAT facts, then corrupt only its stub.
                    primary = os.pread(image.fileno(), 512, bootmgr)
                    sectors_per_cluster = primary[13]
                    sectors_per_fat = int.from_bytes(primary[36:40], "little")
                    data_start = 32 + 2 * sectors_per_fat
                    attr, cluster, _size = helper._fat32_short_entry(
                        image.fileno(), volume_offset=bootmgr,
                        data_start=data_start, fat_start=32,
                        sectors_per_cluster=sectors_per_cluster,
                        cluster_end=(result.image_size - bootmgr) // 512 + 2,
                        directory_cluster=2, short_name=b"BOOTMGR    ",
                        read_at=os.pread,
                    )
                    self.assertFalse(attr & 0x18)
                    offset = bootmgr + (
                        data_start + (cluster - 2) * sectors_per_cluster
                    ) * 512
                    os.pwrite(image.fileno(), b"X", offset)
                    with self.assertRaisesRegex(HelperSourceError, "entry stub"):
                        helper._validate_windows_image_layout(
                            image.fileno(), request, read_at=os.pread,
                        )

    def test_windows_profile_reuses_same_fd_mbr_last_full_readback_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan = self._plan(directory)
            with prepare_windows_iso_fat32(plan) as prepared:
                result = prepared.result
                image = b"".join(prepared.chunks())
            request = HelperRequest(
                REQUEST_ID, WINDOWS_HELPER_PROFILE, "/dev/sdz", "8:240",
                syslinux_fixtures.DISK_SEQUENCE, len(image), 512,
                result.disk_signature, result.volume_id,
                hashlib.sha256(image).hexdigest(),
            )
            harness = syslinux_fixtures.TransactionHarness(image)
            self.addCleanup(harness.close)
            mutations: list[bool] = []
            receipt = helper.execute_helper_transaction(
                request,
                source_descriptor=harness.source.fileno(),
                invoking_uid=os.geteuid(),
                operations=harness.operations(),
                progress=lambda phase, done, total: harness.progress.append(
                    (phase, done, total),
                ),
                mutation_started=lambda: mutations.append(True),
            )
            self.assertEqual(receipt.profile, WINDOWS_HELPER_PROFILE)
            self.assertEqual(receipt.readback_sha256, request.expected_sha256)
            self.assertEqual(mutations, [True])
            self.assertEqual(harness.write_calls[-1][2], 0)
            self.assertEqual(harness.write_calls[-1][1], image[:512])
            self.assertEqual(os.pread(harness.target.fileno(), len(image), 0), image)
            terminal = {
                phase: done
                for phase, done, total in harness.progress
                if done == total
            }
            self.assertEqual(set(terminal), set(helper.PHASE_CODES))


if __name__ == "__main__":
    unittest.main()
