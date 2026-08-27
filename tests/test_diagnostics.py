from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from isopropyl.devices import Device
from isopropyl.diagnostics import build_diagnostics, write_diagnostics
from isopropyl.eltorito import (
    BootEntry, BootPlatform, ElToritoInspection, EmulationType, ValidationEntry,
)
from isopropyl.images import ImageInspection, ImageMember
from isopropyl.uefi import ImageUefiPayload, SbatState, SignatureTableState


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
        private_inspection = replace(
            inspection(),
            volume_label="SECRET-VOLUME",
            bootloader_issues=("EFI/customer-secret/grub.cfg: issue",),
            uefi_payloads=(ImageUefiPayload(
                "EFI/customer-secret/loader.efi", "x64", "EFI application",
                True, SignatureTableState.PRESENT_UNVERIFIED,
                SbatState.PRESENT, (),
            ),),
            uefi_analysis_issues=("EFI/another-secret/loader.efi: issue",),
        )
        report = build_diagnostics(
            [device()], private_inspection, log_text="/home/alice/private.iso",
            tool_probe=lambda: {},
        )
        rendered = json.dumps(report)
        for secret in (
            "SECRET-SERIAL", "SECRET-WWN", "/media/alice", "private-name",
            "/home/alice", "SECRET-VOLUME", "customer-secret", "another-secret",
        ):
            self.assertNotIn(secret, rendered)
        self.assertFalse(report["privacy"]["identifiers_included"])
        image = report["selected_image_inspection"]
        self.assertEqual(image["member_count"], 1)
        self.assertEqual(image["bootloader_issue_count"], 1)
        self.assertEqual(image["uefi_payload_count"], 1)
        self.assertEqual(image["uefi_analysis_issue_count"], 1)
        self.assertTrue(image["volume_label_present"])

    def test_eltorito_diagnostics_are_json_safe_and_omit_image_text(self):
        eltorito = ElToritoInspection(
            source_size=100_000,
            catalog_lba=20,
            catalog_offset=40_960,
            catalog_size=64,
            descriptors_scanned=2,
            validation=ValidationEntry(
                BootPlatform.EFI, "SECRET-VALIDATION", 0,
            ),
            entries=(BootEntry(
                1, True, BootPlatform.EFI, "SECRET-SECTION", True,
                EmulationType.NO_EMULATION, 0, 0, 4, 24, 49_152,
                2_048, 51_200, 1, b"SECRET-CRITERIA",
            ),),
        )
        report = build_diagnostics(
            [], replace(inspection(), eltorito=eltorito), tool_probe=lambda: {},
        )
        rendered = json.dumps(report)
        self.assertNotIn("SECRET", rendered)
        summary = report["selected_image_inspection"]["eltorito"]
        self.assertEqual(summary["entry_count"], 1)
        self.assertEqual(summary["bootable_platforms"], [BootPlatform.EFI.value])

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
