from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from isopropyl.devices import Device
from isopropyl.dbx import DbxAssessment, DbxState
from isopropyl.diagnostics import build_diagnostics, write_diagnostics
from isopropyl.eltorito import (
    BootEntry, BootPlatform, ElToritoInspection, EmulationType, ValidationEntry,
)
from isopropyl.images import ImageInspection, ImageMember
from isopropyl.fat_image import (
    EmbeddedFatImage, FatImageEntry, FatSourceIdentity, FatType,
)
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
                SbatState.PRESENT, (), dbx=DbxAssessment(
                    DbxState.MATCHED_UNFLAGGED, "x64", "a" * 64,
                ),
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
            "a" * 64,
        ):
            self.assertNotIn(secret, rendered)
        self.assertFalse(report["privacy"]["identifiers_included"])
        image = report["selected_image_inspection"]
        self.assertEqual(image["member_count"], 1)
        self.assertEqual(image["bootloader_issue_count"], 1)
        self.assertEqual(image["uefi_payload_count"], 1)
        self.assertEqual(image["uefi_analysis_issue_count"], 1)
        self.assertEqual(
            image["dbx_advisor"]["counts"][DbxState.MATCHED_UNFLAGGED.value], 1,
        )
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

    def test_embedded_fat_diagnostics_export_counts_not_paths_or_hashes(self):
        boot = BootEntry(
            1, True, BootPlatform.EFI, "SECRET-SECTION", True,
            EmulationType.NO_EMULATION, 0, 0, 1, 24, 49_152,
            512, 49_664, 0, b"",
        )
        embedded = EmbeddedFatImage(
            FatSourceIdentity(1, 2, 100_000, 3, 4),
            boot,
            49_152,
            100_000,
            49_152,
            4_096,
            None,
            None,
            FatType.FAT12,
            512,
            1,
            (FatImageEntry(
                "EFI/SECRET-CUSTOMER/BOOTX64.EFI",
                8,
                False,
                2,
                (2,),
                "b" * 64,
            ),),
            "c" * 64,
        )
        report = build_diagnostics(
            [],
            replace(
                inspection(),
                embedded_uefi_fat=embedded,
                embedded_uefi_issues=("SECRET-ISSUE",),
            ),
            tool_probe=lambda: {},
        )
        rendered = json.dumps(report)
        self.assertNotIn("SECRET", rendered)
        self.assertNotIn("b" * 64, rendered)
        self.assertNotIn("c" * 64, rendered)
        summary = report["selected_image_inspection"]["embedded_uefi_fat"]
        self.assertEqual(summary["entry_count"], 1)
        self.assertEqual(summary["file_count"], 1)
        self.assertEqual(summary["content_bytes"], 8)
        self.assertEqual(
            report["selected_image_inspection"]["embedded_uefi_fat_count"],
            1,
        )
        self.assertEqual(
            report["selected_image_inspection"]["embedded_uefi_fats"],
            [summary],
        )
        self.assertEqual(
            report["selected_image_inspection"]["embedded_uefi_issue_count"],
            1,
        )

    def test_plural_embedded_fat_diagnostics_are_bounded_and_path_free(self):
        boot = BootEntry(
            1, True, BootPlatform.EFI, "SECRET-SECTION", True,
            EmulationType.NO_EMULATION, 0, 0, 1, 24, 49_152,
            512, 49_664, 0, b"",
        )
        embedded = EmbeddedFatImage(
            FatSourceIdentity(1, 2, 100_000, 3, 4),
            boot,
            49_152,
            100_000,
            49_152,
            4_096,
            None,
            None,
            FatType.FAT12,
            512,
            1,
            (FatImageEntry(
                "EFI/SECRET-CUSTOMER/BOOTX64.EFI",
                8,
                False,
                2,
                (2,),
                "b" * 64,
            ),),
            "c" * 64,
        )
        fats = tuple(
            replace(
                embedded,
                boot_entry=replace(boot, catalog_index=index + 1),
            )
            for index in range(33)
        )
        report = build_diagnostics(
            [],
            replace(inspection(), embedded_uefi_fats=fats),
            tool_probe=lambda: {},
        )
        image = report["selected_image_inspection"]
        rendered = json.dumps(image)
        self.assertEqual(image["embedded_uefi_fat_count"], 33)
        self.assertEqual(len(image["embedded_uefi_fats"]), 32)
        self.assertFalse(image["embedded_uefi_fat_summaries_complete"])
        self.assertNotIn("embedded_uefi_fat", image)
        self.assertNotIn("SECRET", rendered)
        self.assertNotIn("b" * 64, rendered)
        self.assertNotIn("c" * 64, rendered)

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
