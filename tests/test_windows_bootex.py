# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import os
import stat
import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import isopropyl.windows_bootex as bootex
from isopropyl.windows_bootex import (
    BootExProfile, BootExProvenanceError, BootExRequest, BootExSafetyError,
    TRUST_BASIS, WindowsBootExOptions, apply_bootex_plan,
    available_bootex_profiles, bind_bootex_source, build_bootex_plan,
    profile_for_official_iso, validate_bootex_plan,
    validate_bootex_result, validate_bootex_source_binding,
)


def signed_efi(machine: int = 0x8664, subsystem: int = 10) -> bytes:
    pe_offset = 0x80
    optional_size = 0xF0
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into("<HH", data, coff, machine, 0)
    struct.pack_into("<H", data, coff + 16, optional_size)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<H", data, optional + 68, subsystem)
    struct.pack_into("<I", data, optional + 108, 16)
    certificate = struct.pack("<IHH", 16, 0x0200, 0x0002) + b"12345678"
    certificate_offset = (len(data) + 7) & ~7
    data.extend(b"\0" * (certificate_offset - len(data)))
    data.extend(certificate)
    struct.pack_into(
        "<II", data, optional + 112 + 4 * 8,
        certificate_offset, len(certificate),
    )
    return bytes(data)


def unsigned_efi(machine: int = 0x8664) -> bytes:
    blob = bytearray(signed_efi(machine))
    optional = 0x80 + 4 + 20
    struct.pack_into("<II", blob, optional + 112 + 4 * 8, 0, 0)
    return bytes(blob[:0x200])


class BootExTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.iso = self.root / "windows.iso"
        self.iso.write_bytes(b"official fixture iso")
        self.profile = BootExProfile(
            "fixture-windows-11-25h2-x64", "Windows 11", "25H2", "English",
            "x64", "fixture.iso", self.iso.stat().st_size,
            hashlib.sha256(self.iso.read_bytes()).hexdigest(),
            "https://www.microsoft.com/software-download/windows11",
            "efi/boot/bootx64.efi",
        )
        self.extracted = self.root / "extracted"
        (self.extracted / "EFI_EX").mkdir(parents=True)
        (self.extracted / "Fonts_EX").mkdir()
        (self.extracted / "EFI_EX" / "bootmgfw_EX.efi").write_bytes(signed_efi())
        (self.extracted / "EFI_EX" / "bootmgr_EX.efi").write_bytes(signed_efi())
        (self.extracted / "EFI_EX" / "ignored.p7b").write_bytes(b"ignored")
        (self.extracted / "Fonts_EX" / "segoe_slboot.ttf").write_bytes(b"new font")
        self.staging = self.root / "staging"
        (self.staging / "efi" / "boot").mkdir(parents=True)
        (self.staging / "efi" / "microsoft" / "boot" / "fonts").mkdir(parents=True)
        (self.staging / "efi" / "boot" / "bootx64.efi").write_bytes(b"old fallback")
        (self.staging / "bootmgr.efi").write_bytes(b"old bootmgr")
        (self.staging / "efi" / "microsoft" / "boot" / "fonts" / "segoe_slboot.ttf").write_bytes(b"old font")
        (self.staging / "sentinel.txt").write_bytes(b"untouched")
        self.profile_patch = patch.object(
            bootex, "available_bootex_profiles", return_value=(self.profile,),
        )
        self.profile_patch.start()
        self.addCleanup(self.profile_patch.stop)

    def request(self, **changes) -> BootExRequest:
        values = {
            "source_iso": self.iso,
            "extracted_root": self.extracted,
            "staging_root": self.staging,
            "architecture": "x64",
            "expected_release_id": self.profile.release_id,
        }
        values.update(changes)
        return BootExRequest(**values)

    def test_real_catalog_exposes_exact_reviewed_x64_and_arm64_profiles(self):
        self.profile_patch.stop()
        profiles = available_bootex_profiles()
        self.assertEqual({item.architecture for item in profiles}, {"x64", "arm64"})
        self.assertEqual(
            {item.fallback_path for item in profiles},
            {"efi/boot/bootx64.efi", "efi/boot/bootaa64.efi"},
        )
        self.assertTrue(all(item.trust_basis == TRUST_BASIS for item in profiles))
        self.assertEqual(
            profile_for_official_iso(
                profiles[0].iso_size, profiles[0].iso_sha256,
                architecture=profiles[0].architecture,
            ),
            profiles[0],
        )

    def test_plan_hashes_iso_and_maps_only_fallback_bootmgr_and_direct_fonts(self):
        plan = build_bootex_plan(self.request())
        self.assertRegex(plan.plan_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(plan.source_iso.sha256, self.profile.iso_sha256)
        self.assertEqual(
            {item.destination_path for item in plan.replacements},
            {
                "efi/boot/bootx64.efi", "bootmgr.efi",
                "efi/microsoft/boot/fonts/segoe_slboot.ttf",
            },
        )
        self.assertEqual(plan.ignored_extracted_files, ("EFI_EX/ignored.p7b",))
        pe_entries = tuple(item for item in plan.replacements if item.pe is not None)
        self.assertEqual(len(pe_entries), 2)
        self.assertTrue(all(item.pe.architecture == "x64" for item in pe_entries))
        self.assertTrue(all(not item.pe.signature_trust_evaluated for item in pe_entries))

    def test_planning_source_binding_and_options_are_strict(self):
        binding = bind_bootex_source(
            self.iso,
            architecture="x64",
            expected_release_id=self.profile.release_id,
        )
        validate_bootex_source_binding(binding)
        self.assertEqual(binding.profile, self.profile)
        self.assertEqual(binding.source_iso.sha256, self.profile.iso_sha256)
        self.assertEqual(
            WindowsBootExOptions(True, True),
            WindowsBootExOptions(
                enabled=True,
                acknowledge_firmware_compatibility=True,
            ),
        )
        with self.assertRaisesRegex(ValueError, "requires the feature"):
            WindowsBootExOptions(False, True)

    def test_literal_ex_suffix_is_removed_from_font_destination(self):
        source = self.extracted / "Fonts_EX" / "boot_EX.ttf"
        source.write_bytes(b"new renamed font")
        destination = (
            self.staging / "efi" / "microsoft" / "boot" / "fonts" / "boot.ttf"
        )
        destination.write_bytes(b"old renamed font")
        plan = build_bootex_plan(self.request())
        operation = next(
            item for item in plan.replacements
            if item.source_path == "Fonts_EX/boot_EX.ttf"
        )
        self.assertEqual(
            operation.destination_path,
            "efi/microsoft/boot/fonts/boot.ttf",
        )
        apply_bootex_plan(plan)
        self.assertEqual(destination.read_bytes(), b"new renamed font")

    def test_apply_replaces_intended_files_and_returns_old_new_receipt(self):
        old = {
            item.destination_path: item.old_sha256
            for item in build_bootex_plan(self.request()).replacements
        }
        plan = build_bootex_plan(self.request())
        result = apply_bootex_plan(plan)
        self.assertEqual((self.staging / "sentinel.txt").read_bytes(), b"untouched")
        self.assertEqual(
            (self.staging / "efi" / "boot" / "bootx64.efi").read_bytes(),
            signed_efi(),
        )
        self.assertEqual((self.staging / "bootmgr.efi").read_bytes(), signed_efi())
        self.assertEqual(
            (self.staging / "efi" / "microsoft" / "boot" / "fonts" / "segoe_slboot.ttf").read_bytes(),
            b"new font",
        )
        self.assertRegex(result.receipt_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(result.trust_basis, TRUST_BASIS)
        self.assertFalse(result.signature_trust_evaluated)
        self.assertIn("cannot independently prove", result.extraction_boundary)
        for item in result.replacements:
            self.assertEqual(item.old_sha256, old[item.destination_path])
            target = self.staging.joinpath(*PurePath(item.destination_path).parts)
            self.assertEqual(item.new_sha256, hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertFalse(tuple(self.staging.rglob(".isopropyl-bootex-*.tmp")))

    def test_result_validator_requires_the_complete_exact_plan_and_receipt(self):
        plan = build_bootex_plan(self.request())
        result = apply_bootex_plan(plan)
        validate_bootex_result(plan, result)

        with self.assertRaisesRegex(BootExSafetyError, "complete execution plan"):
            validate_bootex_result(
                plan,
                replace(result, replacements=result.replacements[:-1]),
            )
        with self.assertRaisesRegex(BootExSafetyError, "complete execution plan"):
            validate_bootex_result(
                plan,
                replace(result, receipt_sha256="0" * 64),
            )

    def test_public_validators_reject_malformed_and_case_colliding_evidence(self):
        binding = bind_bootex_source(self.iso, architecture="x64")
        malformed_evidence = replace(binding.source_iso, identity=())
        with self.assertRaises(BootExSafetyError):
            validate_bootex_source_binding(
                replace(binding, source_iso=malformed_evidence),
            )

        plan = build_bootex_plan(self.request())
        font = next(item for item in plan.replacements if item.kind == "boot-font")
        collision = replace(
            font,
            source_path=font.source_path.upper(),
            destination_path=font.destination_path.upper(),
        )
        forged = replace(plan, replacements=(*plan.replacements, collision))
        forged = replace(forged, plan_sha256=bootex._plan_digest(forged))
        with self.assertRaisesRegex(BootExSafetyError, "replacement evidence"):
            validate_bootex_plan(forged)

    def test_wrong_iso_digest_fails_before_tree_transformation(self):
        wrong = replace(self.profile, iso_sha256="0" * 64)
        with (
            patch.object(bootex, "available_bootex_profiles", return_value=(wrong,)),
            self.assertRaisesRegex(BootExProvenanceError, "SHA-256"),
        ):
            build_bootex_plan(self.request())

    def test_architecture_mapping_and_pe_architecture_are_strict(self):
        with self.assertRaisesRegex(BootExProvenanceError, "x64 or arm64"):
            build_bootex_plan(self.request(architecture="amd64"))
        (self.extracted / "EFI_EX" / "bootmgfw_EX.efi").write_bytes(
            signed_efi(machine=0xAA64),
        )
        with self.assertRaisesRegex(BootExSafetyError, "does not match"):
            build_bootex_plan(self.request())

    def test_arm64_maps_only_to_aa64_and_requires_arm64_pe(self):
        arm_profile = replace(
            self.profile, release_id="fixture-windows-11-25h2-arm64",
            architecture="arm64", fallback_path="efi/boot/bootaa64.efi",
        )
        for name in ("bootmgfw_EX.efi", "bootmgr_EX.efi"):
            (self.extracted / "EFI_EX" / name).write_bytes(signed_efi(machine=0xAA64))
        fallback = self.staging / "efi" / "boot" / "bootx64.efi"
        fallback.rename(fallback.with_name("bootaa64.efi"))
        with patch.object(bootex, "available_bootex_profiles", return_value=(arm_profile,)):
            plan = build_bootex_plan(self.request(
                architecture="ARM64", expected_release_id=arm_profile.release_id,
            ))
        self.assertEqual(plan.profile.architecture, "arm64")
        self.assertEqual(plan.replacements[0].destination_path, "efi/boot/bootaa64.efi")
        self.assertEqual(plan.replacements[0].pe.architecture, "ARM64")

    def test_unsigned_or_non_application_pe_is_rejected(self):
        target = self.extracted / "EFI_EX" / "bootmgr_EX.efi"
        target.write_bytes(unsigned_efi())
        with self.assertRaisesRegex(BootExSafetyError, "signature table"):
            build_bootex_plan(self.request())
        target.write_bytes(signed_efi(subsystem=11))
        with self.assertRaisesRegex(BootExSafetyError, "EFI application"):
            build_bootex_plan(self.request())

    def test_extracted_tree_rejects_symlinks_hardlinks_specials_and_nesting(self):
        cases = []
        symlink = self.extracted / "EFI_EX" / "alias.efi"
        symlink.symlink_to("bootmgfw_EX.efi")
        cases.append((symlink, "regular"))
        for path, message in cases:
            with self.subTest(kind=path.name):
                with self.assertRaisesRegex(BootExSafetyError, message):
                    build_bootex_plan(self.request())
                path.unlink()

        hardlink = self.extracted / "EFI_EX" / "hard.p7b"
        os.link(self.extracted / "EFI_EX" / "ignored.p7b", hardlink)
        with self.assertRaisesRegex(BootExSafetyError, "regular"):
            build_bootex_plan(self.request())
        hardlink.unlink()
        # The original now has one link again.

        fifo = self.extracted / "EFI_EX" / "pipe"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(BootExSafetyError, "regular"):
            build_bootex_plan(self.request())
        fifo.unlink()

        nested = self.extracted / "Fonts_EX" / "nested"
        nested.mkdir()
        with self.assertRaisesRegex(BootExSafetyError, "nested"):
            build_bootex_plan(self.request())

    def test_extracted_root_directories_cannot_be_links(self):
        fonts = self.extracted / "Fonts_EX"
        real_fonts = self.root / "real-fonts"
        fonts.rename(real_fonts)
        fonts.symlink_to(real_fonts, target_is_directory=True)
        with self.assertRaisesRegex(BootExSafetyError, "no-follow directory"):
            build_bootex_plan(self.request())

    def test_extracted_tree_rejects_casefold_collisions_and_unsafe_fonts(self):
        collision = self.extracted / "Fonts_EX" / "SEGOE_SLBOOT.TTF"
        collision.write_bytes(b"collision")
        with self.assertRaisesRegex(BootExSafetyError, "collision"):
            build_bootex_plan(self.request())
        collision.unlink()
        bad = self.extracted / "Fonts_EX" / "font.otf"
        bad.write_bytes(b"bad")
        with self.assertRaisesRegex(BootExSafetyError, "direct .ttf"):
            build_bootex_plan(self.request())

    def test_extracted_tree_bounds_are_enforced(self):
        extra = self.extracted / "EFI_EX" / "large.bin"
        extra.write_bytes(b"1234")
        with (
            patch.object(bootex, "MAX_EXTRACTED_FILE_BYTES", 3),
            self.assertRaisesRegex(BootExSafetyError, "size limit"),
        ):
            build_bootex_plan(self.request())

    def test_missing_or_case_mismatched_destination_fails_closed(self):
        target = self.staging / "efi" / "boot" / "bootx64.efi"
        target.rename(target.with_name("BOOTX64.EFI"))
        with self.assertRaisesRegex(BootExSafetyError, "unexpected case"):
            build_bootex_plan(self.request())

    def test_stale_source_destination_iso_and_forged_plan_are_rejected(self):
        plan = build_bootex_plan(self.request())
        forged = replace(plan, plan_sha256="0" * 64)
        with self.assertRaisesRegex(BootExSafetyError, "digest"):
            validate_bootex_plan(forged)
        forged_operation = replace(
            plan.replacements[0], destination_path="sentinel.txt",
        )
        semantic_forgery = replace(
            plan, replacements=(forged_operation, *plan.replacements[1:]),
        )
        semantic_forgery = replace(
            semantic_forgery, plan_sha256=bootex._plan_digest(semantic_forgery),
        )
        with self.assertRaisesRegex(BootExSafetyError, "fallback-loader"):
            validate_bootex_plan(semantic_forgery)

        source = self.extracted / "Fonts_EX" / "segoe_slboot.ttf"
        source.write_bytes(b"changed!")
        with self.assertRaisesRegex(BootExSafetyError, "changed"):
            apply_bootex_plan(plan)
        source.write_bytes(b"new font")

        plan = build_bootex_plan(self.request())
        destination = self.staging / "bootmgr.efi"
        destination.write_bytes(b"destination changed")
        with self.assertRaisesRegex(BootExSafetyError, "changed"):
            apply_bootex_plan(plan)

        destination.write_bytes(b"old bootmgr")
        plan = build_bootex_plan(self.request())
        self.iso.write_bytes(b"different fixture iso")
        with self.assertRaisesRegex(BootExSafetyError, "source ISO changed"):
            apply_bootex_plan(plan)

    def test_staging_links_are_rejected_and_failed_commit_cleans_temporaries(self):
        font = self.staging / "efi" / "microsoft" / "boot" / "fonts" / "segoe_slboot.ttf"
        font.unlink()
        font.symlink_to(self.staging / "sentinel.txt")
        with self.assertRaisesRegex(BootExSafetyError, "regular"):
            build_bootex_plan(self.request())
        font.unlink()
        font.write_bytes(b"old font")
        plan = build_bootex_plan(self.request())
        with (
            patch.object(bootex.os, "replace", side_effect=OSError("fixture failure")),
            self.assertRaisesRegex(BootExSafetyError, "commit"),
        ):
            apply_bootex_plan(plan)
        self.assertFalse(tuple(self.staging.rglob(".isopropyl-bootex-*.tmp")))
        self.assertEqual((self.staging / "bootmgr.efi").read_bytes(), b"old bootmgr")


class PurePath:
    """Small platform-independent adapter for result path lookup in tests."""

    def __init__(self, value: str) -> None:
        self.parts = tuple(value.split("/"))


if __name__ == "__main__":
    unittest.main()
