from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import fcntl
import hashlib
import os
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import isopropyl.private_fat32 as private_fat32
from isopropyl.fat_image import inspect_regular_fat32_image
from isopropyl.private_fat32 import (
    PrivateFat32BuildProfile,
    PrivateFat32Builder,
    PrivateFat32Error,
    PrivateFat32State,
    build_generic_private_fat32_plan,
    validate_private_fat32_plan,
)


IMAGE_SIZE = 36_888_576
FIXED_MTIME_NS = 1_700_000_000_000_000_000


def _set_fixed_times(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        os.utime(path, ns=(FIXED_MTIME_NS, FIXED_MTIME_NS), follow_symlinks=False)
    os.utime(root, ns=(FIXED_MTIME_NS, FIXED_MTIME_NS), follow_symlinks=False)


class GenericPrivateFat32Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.source_tmp = tempfile.TemporaryDirectory()
        self.workspace_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.source_tmp.cleanup)
        self.addCleanup(self.workspace_tmp.cleanup)
        self.source = Path(self.source_tmp.name)
        self.workspace = Path(self.workspace_tmp.name)
        (self.source / "EFI" / "BOOT").mkdir(parents=True)
        (self.source / "EFI" / "BOOT" / "BOOTX64.EFI").write_bytes(b"MZ generic")
        (self.source / "README.txt").write_text("generic image\n", encoding="utf-8")
        (self.source / "empty.bin").write_bytes(b"")
        (self.source / "Long Name").mkdir()
        (self.source / "Long Name" / "café.txt").write_bytes(b"coffee")
        _set_fixed_times(self.source)

    def plan(self):
        return build_generic_private_fat32_plan(
            self.source,
            self.workspace,
            image_size=IMAGE_SIZE,
        )

    def test_generic_profile_has_no_ldlinux_dependency_and_is_digest_bound(self) -> None:
        with patch.dict(sys.modules, {"isopropyl.syslinux_transaction": None}):
            plan = self.plan()
            validate_private_fat32_plan(plan)
            with PrivateFat32Builder().execute(plan) as image:
                self.assertEqual(image.state, PrivateFat32State.GENERIC_ATTESTED)
                self.assertEqual(
                    hashlib.sha256(b"".join(image.chunks(64 * 1024))).hexdigest(),
                    image.result.image_sha256,
                )
        self.assertIs(plan.profile, PrivateFat32BuildProfile.GENERIC)
        self.assertIsNone(plan.root_ldlinux_size)
        self.assertIsNone(plan.root_ldlinux_sha256)
        self.assertNotIn(("ldlinux.sys",), tuple(item.source.parts for item in plan.files))

        forged = replace(plan, profile=PrivateFat32BuildProfile.SYSLINUX)
        forged = replace(forged, plan_sha256=private_fat32._plan_digest(forged))
        with self.assertRaises(PrivateFat32Error):
            validate_private_fat32_plan(forged)

    def test_syslinux_plan_cannot_be_recast_as_a_generic_plan(self) -> None:
        (self.source / "ldlinux.sys").write_bytes(b"unpatched loader")
        _set_fixed_times(self.source)
        syslinux = private_fat32.build_private_fat32_plan(
            self.source,
            self.workspace,
            image_size=IMAGE_SIZE,
            expected_root_ldlinux=b"unpatched loader",
        )
        forged = replace(
            syslinux,
            profile=PrivateFat32BuildProfile.GENERIC,
            root_ldlinux_size=None,
            root_ldlinux_sha256=None,
        )
        forged = replace(forged, plan_sha256=private_fat32._plan_digest(forged))
        with self.assertRaisesRegex(
            PrivateFat32Error,
            "profile does not match its construction",
        ):
            validate_private_fat32_plan(forged)

    def test_generic_profile_treats_a_file_named_ldlinux_as_ordinary_data(self) -> None:
        (self.source / "ldlinux.sys").write_bytes(b"ordinary data")
        _set_fixed_times(self.source)
        plan = self.plan()
        loader = next(
            item for item in plan.files if item.source.parts == ("ldlinux.sys",)
        )
        self.assertNotEqual(loader.first_cluster, 3)
        root = private_fat32._directory_content(plan, plan.directories[0])
        record = next(
            root[offset:offset + 32]
            for offset in range(0, len(root), 32)
            if root[offset:offset + 11] == b"LDLINUX SYS"
        )
        self.assertEqual(record[11], 0x20)
        with PrivateFat32Builder().execute(plan) as image:
            self.assertIn("ldlinux.sys", tuple(
                entry.path for entry in image.inspection.entries
            ))

    def test_generic_build_is_preallocated_deterministic_and_independently_parsed(self) -> None:
        plans = []
        digests: list[str] = []
        for _index in range(2):
            plan = self.plan()
            plans.append(plan)
            with PrivateFat32Builder().execute(plan) as image:
                descriptor = image._owned_descriptor()
                status = os.fstat(descriptor)
                self.assertTrue(stat.S_ISREG(status.st_mode))
                self.assertEqual(status.st_nlink, 0)
                self.assertEqual(stat.S_IMODE(status.st_mode), 0o600)
                self.assertEqual(status.st_size, IMAGE_SIZE)
                self.assertGreaterEqual(status.st_blocks * 512, IMAGE_SIZE)
                self.assertTrue(
                    fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
                )

                inspection = inspect_regular_fat32_image(descriptor)
                self.assertEqual(
                    tuple(entry.path for entry in inspection.entries),
                    (
                        "EFI",
                        "EFI/BOOT",
                        "EFI/BOOT/BOOTX64.EFI",
                        "empty.bin",
                        "Long Name",
                        "Long Name/café.txt",
                        "README.txt",
                    ),
                )
                self.assertEqual(
                    inspection.filesystem_offset,
                    private_fat32.PARTITION_START_SECTOR * private_fat32.SECTOR_SIZE,
                )
                self.assertEqual(inspection.filesystem_size, plan.geometry.volume_size)
                self.assertEqual(
                    inspection.sectors_per_cluster,
                    plan.geometry.sectors_per_cluster,
                )
                self.assertEqual(inspection.allocated_clusters, plan.allocated_clusters)
                self.assertEqual(inspection.manifest_sha256, image.result.manifest_sha256)
                self.assertEqual(inspection.entries, image.inspection.entries)
                digests.append(image.result.image_sha256)
        self.assertEqual(plans[0].plan_sha256, plans[1].plan_sha256)
        self.assertEqual(plans[0].disk_signature, plans[1].disk_signature)
        self.assertEqual(plans[0].volume_id, plans[1].volume_id)
        self.assertEqual(digests[0], digests[1])
        self.assertEqual(os.listdir(self.workspace), [])

    def test_generic_image_is_poisoned_if_attestation_fails_before_streaming(self) -> None:
        image = PrivateFat32Builder().execute(self.plan())
        self.addCleanup(image.close)
        os.pwrite(image._owned_descriptor(), b"X", 0)
        with self.assertRaisesRegex(PrivateFat32Error, "changed before streaming"):
            next(image.chunks(4096))
        self.assertEqual(image.state, PrivateFat32State.POISONED)
        with self.assertRaisesRegex(PrivateFat32Error, "closed"):
            image._owned_descriptor()


if __name__ == "__main__":
    unittest.main()
