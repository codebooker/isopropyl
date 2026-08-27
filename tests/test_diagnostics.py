from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import tempfile
import unittest
from pathlib import Path

from isopropyl.devices import Device
from isopropyl.diagnostics import build_diagnostics, write_diagnostics
from isopropyl.images import ImageInspection, ImageMember


def device() -> Device:
    return Device(
        "/dev/sdb", 1_000_000, "Stick", "Acme", "usb", "SECRET-SERIAL",
        "SECRET-WWN", "8:16", True, True, False, ("/media/alice/SECRET",),
        ("/dev/sdb1",),
    )


def inspection() -> ImageInspection:
    return ImageInspection(
        100, "Optical ISO", "TEST", True, False, True, False,
        ("UEFI",), ("x64",), "GRUB", False, True,
        members=(ImageMember("customer/private-name", 10, "file"),),
    )


class DiagnosticTests(unittest.TestCase):
    def test_default_report_omits_sensitive_fields(self):
        report = build_diagnostics(
            [device()], inspection(), log_text="/home/alice/private.iso",
            tool_probe=lambda: {},
        )
        rendered = json.dumps(report)
        for secret in (
            "SECRET-SERIAL", "SECRET-WWN", "/media/alice", "private-name", "/home/alice",
        ):
            self.assertNotIn(secret, rendered)
        self.assertFalse(report["privacy"]["identifiers_included"])
        self.assertEqual(report["selected_image_inspection"]["member_count"], 1)

    def test_explicit_opt_in_includes_identifiers_and_log(self):
        report = build_diagnostics(
            [device()], None, include_identifiers=True, log_text="chosen image path",
            tool_probe=lambda: {},
        )
        self.assertEqual(report["devices"][0]["serial"], "SECRET-SERIAL")
        self.assertEqual(report["activity_log"], "chosen image path")
        self.assertTrue(report["privacy"]["log_included"])

    def test_atomic_json_export(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "isopropyl-diagnostics.json"
            write_diagnostics(destination, {"schema": 1, "ok": True})
            self.assertEqual(json.loads(destination.read_text()), {"schema": 1, "ok": True})
            self.assertEqual(list(Path(directory).glob("*.partial")), [])


if __name__ == "__main__":
    unittest.main()
