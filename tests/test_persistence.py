from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest

from isopropyl.images import ImageInspection, ImageMember
from isopropyl.persistence import (
    MIB, PersistenceError, build_persistence_plan, detect_persistence_profile,
)


def image(label, paths):
    return ImageInspection(
        100, "Optical ISO", label, True, False, True, False,
        ("BIOS", "UEFI"), ("x64",), "GRUB", False, True,
        members=tuple(ImageMember(path, 1, "file") for path in paths),
    )


class PersistenceTests(unittest.TestCase):
    def test_modern_and_legacy_casper_labels_are_not_confused(self):
        modern = detect_persistence_profile(image(
            "Ubuntu 24.04 LTS", ("casper/vmlinuz", "casper/filesystem.squashfs"),
        ))
        legacy = detect_persistence_profile(image(
            "Ubuntu 18.04 LTS", ("casper/vmlinuz", "casper/filesystem.squashfs"),
        ))
        self.assertEqual(modern.label, "writable")
        self.assertEqual(legacy.label, "casper-rw")
        self.assertEqual(modern.boot_parameter, "persistent")

    def test_debian_live_boot_profile_has_exact_config(self):
        profile = detect_persistence_profile(image(
            "Debian Live 13", ("live/vmlinuz", "live/filesystem.squashfs"),
        ))
        self.assertEqual(profile.label, "persistence")
        self.assertEqual(profile.configuration_path, "persistence.conf")
        self.assertEqual(profile.configuration_contents, "/ union\n")

    def test_tails_and_unknown_images_fail_closed(self):
        self.assertIsNone(detect_persistence_profile(image(
            "Tails 7", ("live/vmlinuz", "live/filesystem.squashfs"),
        )))
        self.assertIsNone(detect_persistence_profile(image("CUSTOM", ("boot/kernel",))))

    def test_plan_validates_minimum_and_alignment_but_stays_nonexecutable(self):
        inspection = image(
            "Kali Live", ("live/vmlinuz", "live/filesystem.squashfs"),
        )
        plan = build_persistence_plan(inspection, 1024 * MIB)
        self.assertFalse(plan.executable)
        self.assertIn("per-release", plan.blocker)
        for size in (255 * MIB, 300 * MIB + 1):
            with self.subTest(size=size), self.assertRaises(PersistenceError):
                build_persistence_plan(inspection, size)


if __name__ == "__main__":
    unittest.main()
