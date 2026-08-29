from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "data/io.github.codebooker.isopropyl.grub-rescue-write.policy"


class GrubRescuePolicyTests(unittest.TestCase):
    def test_policy_authorizes_only_the_exact_rescue_operation(self) -> None:
        root = ET.parse(POLICY).getroot()
        self.assertEqual(root.tag, "policyconfig")
        actions = root.findall("action")
        self.assertEqual(len(actions), 1)
        action = actions[0]
        self.assertEqual(
            action.attrib,
            {"id": "io.github.codebooker.isopropyl.write-grub-rescue-image"},
        )
        self.assertEqual(
            (action.findtext("description") or "").strip(),
            "Write exact GRUB 2.14 blank BIOS rescue media",
        )
        message = (action.findtext("message") or "").strip()
        self.assertIn("overwrite the selected removable drive", message)
        self.assertIn("exact GRUB 2.14 blank BIOS rescue media", message)
        defaults = action.findall("defaults")
        self.assertEqual(len(defaults), 1)
        self.assertEqual(
            {child.tag: (child.text or "").strip() for child in defaults[0]},
            {
                "allow_any": "no",
                "allow_inactive": "no",
                "allow_active": "auth_admin",
            },
        )
        self.assertEqual(
            {
                node.get("key"): (node.text or "").strip()
                for node in action.findall("annotate")
            },
            {
                "org.freedesktop.policykit.exec.path":
                "/usr/libexec/isopropyl-device-helper",
                "org.freedesktop.policykit.exec.argv1":
                "write-grub-2.14-rescue-image-v1",
            },
        )

    def test_policy_is_only_in_the_explicit_host_install(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        ordinary = makefile.split("\ninstall:\n", 1)[1].split(
            "\nuninstall:\n", 1,
        )[0]
        host_install = makefile.split(
            "\ninstall-host-helper:\n", 1,
        )[1].split("\nuninstall-host-helper:\n", 1)[0]
        host_uninstall = makefile.split("\nuninstall-host-helper:\n", 1)[1]
        name = "io.github.codebooker.isopropyl.grub-rescue-write.policy"
        self.assertNotIn(name, ordinary)
        self.assertIn(f"data/{name}", host_install)
        self.assertIn(f"polkit-1/actions/{name}", host_install)
        self.assertIn(f"polkit-1/actions/{name}", host_uninstall)


if __name__ == "__main__":
    unittest.main()
