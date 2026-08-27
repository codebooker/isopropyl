# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest
from dataclasses import FrozenInstanceError, replace

from isopropyl.authenticode import AuthenticodeIntegrityState, AuthenticodeResult
from isopropyl.images import ImageInspection
from isopropyl.uefi import ImageUefiPayload, SbatState, SignatureTableState
from isopropyl.iso import (
    FAT32_MAX_FILE_SIZE,
    ArchiveEntry,
    BootStrategy,
    EntryKind,
    FileSystem,
    FirmwareTarget,
    PartitionTable,
    PlanError,
    RequirementSource,
    Transformation,
    UnsafeArchiveError,
    WriteMode,
    build_write_plan,
    recommend_write_method,
    validate_extraction_entries,
)
from isopropyl.timestamps import (
    MAX_PORTABLE_ARCHIVE_MTIME_NS, MIN_PORTABLE_ARCHIVE_MTIME_NS,
)


def inspection(
    *, iso: bool = True, boot_modes: tuple[str, ...] = ("BIOS", "UEFI"),
    bootloader: str = "GRUB", windows: bool = False,
    architectures: tuple[str, ...] = ("x64",),
    hybrid: bool = True,
) -> ImageInspection:
    payloads = (
        ImageUefiPayload(
            "EFI/BOOT/BOOTX64.EFI", "x64", "EFI application", True,
            SignatureTableState.ABSENT, SbatState.ABSENT, (),
        ),
    ) if architectures else ()
    return ImageInspection(
        size=1024, kind="Optical ISO" if iso else "Raw image", volume_label="TEST",
        has_mbr=iso and hybrid, has_gpt=False, is_iso9660=iso, looks_windows=windows,
        boot_modes=boot_modes, architectures=architectures, bootloader=bootloader,
        has_windows_installer=windows, contents_scanned=True,
        uefi_payloads=payloads,
    )


class PlanTests(unittest.TestCase):
    def test_authenticode_analysis_is_presentation_only_for_write_planning(self):
        image = inspection()
        entries = [ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 32)]
        baseline = build_write_plan(image, entries)
        for state in AuthenticodeIntegrityState:
            result = (
                AuthenticodeResult(state, "sha256", "CN=Claim", "a" * 64, 1)
                if state is AuthenticodeIntegrityState.VALID_UNTRUSTED
                else AuthenticodeResult(state, error="fixture")
            )
            payload = replace(image.uefi_payloads[0], authenticode=result)
            with self.subTest(state=state):
                self.assertEqual(
                    build_write_plan(replace(image, uefi_payloads=(payload,)), entries),
                    baseline,
                )

    def test_auto_selects_dd_for_raw_image(self):
        plan = build_write_plan(inspection(iso=False))
        self.assertEqual(plan.mode, WriteMode.DD)
        self.assertIsNone(plan.layout)
        self.assertEqual(plan.minimum_content_bytes, 1024)

    def test_auto_selects_extracted_fat32_mbr_for_hybrid_iso(self):
        plan = build_write_plan(
            inspection(), [ArchiveEntry("boot/grub/grub.cfg", 20)]
        )
        self.assertEqual(plan.mode, WriteMode.EXTRACTED_ISO)
        self.assertEqual(plan.layout.main_filesystem, FileSystem.FAT32)
        self.assertEqual(plan.layout.partition_table, PartitionTable.MBR)
        keys = {requirement.key for requirement in plan.requirements}
        self.assertIn("matching-grub-i386-pc", keys)
        self.assertIn("efi-removable-loader-x64", keys)
        self.assertFalse(plan.executable)
        self.assertTrue(any("exact GRUB" in item for item in plan.blockers))

    def test_uefi_only_image_uses_gpt(self):
        plan = build_write_plan(
            inspection(boot_modes=("UEFI",)), [ArchiveEntry("EFI/BOOT/BOOTX64.EFI")]
        )
        self.assertEqual(plan.layout.partition_table, PartitionTable.GPT)
        self.assertFalse(plan.layout.bios_bootable)
        self.assertTrue(plan.layout.uefi_bootable)

    def test_explicit_uefi_only_profile_drops_bios_requirement_and_is_executable(self):
        image = inspection()
        plan = build_write_plan(
            image,
            [ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 10)],
            firmware_target=FirmwareTarget.UEFI_ONLY,
        )
        self.assertFalse(plan.layout.bios_bootable)
        self.assertTrue(plan.layout.uefi_bootable)
        self.assertEqual(plan.firmware_target, FirmwareTarget.UEFI_ONLY)
        self.assertTrue(plan.executable)
        self.assertNotIn("matching-grub-i386-pc", {item.key for item in plan.requirements})

    def test_uefi_execution_requires_a_recognized_fallback_loader(self):
        plan = build_write_plan(
            inspection(boot_modes=("UEFI",), architectures=()),
            [ArchiveEntry("efi/vendor/loader.efi", 10)],
            firmware_target=FirmwareTarget.UEFI_ONLY,
        )
        self.assertFalse(plan.executable)
        self.assertTrue(any("fallback loader" in item for item in plan.blockers))

    def test_uefi_execution_requires_structurally_valid_fallback_payload(self):
        image = inspection(boot_modes=("UEFI",))
        image = ImageInspection(**{**image.__dict__, "uefi_payloads": ()})
        plan = build_write_plan(
            image,
            [ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 10)],
            firmware_target=FirmwareTarget.UEFI_ONLY,
        )
        self.assertFalse(plan.executable)
        self.assertTrue(any("EFI application" in item for item in plan.blockers))

    def test_firmware_profile_must_exist_in_image(self):
        with self.assertRaisesRegex(PlanError, "no detected UEFI"):
            build_write_plan(
                inspection(boot_modes=("BIOS",)),
                [ArchiveEntry("isolinux/isolinux.bin")],
                firmware_target=FirmwareTarget.UEFI_ONLY,
            )

    def test_syslinux_bios_requirement_must_match_image_version(self):
        plan = build_write_plan(
            inspection(boot_modes=("BIOS",), bootloader="Syslinux/Isolinux"),
            [ArchiveEntry("isolinux/isolinux.bin")],
        )
        dependency = next(
            item for item in plan.requirements if item.key == "matching-syslinux-bios"
        )
        self.assertEqual(dependency.version_constraint, "match-image-version")
        self.assertEqual(dependency.source, RequirementSource.SYSTEM_OR_VERIFIED_DOWNLOAD)

    def test_write_plan_is_immutable(self):
        plan = build_write_plan(inspection(iso=False))
        with self.assertRaises(FrozenInstanceError):
            plan.mode = WriteMode.EXTRACTED_ISO  # type: ignore[misc]

    def test_large_windows_wim_is_split_for_fat32(self):
        plan = build_write_plan(inspection(windows=True, bootloader="Windows Boot Manager"), [
            ArchiveEntry("sources/install.wim", FAT32_MAX_FILE_SIZE + 1),
            ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 10),
        ])
        self.assertEqual(plan.layout.main_filesystem, FileSystem.FAT32)
        self.assertTrue(plan.needs_wim_split)
        self.assertIn(Transformation.SPLIT_WINDOWS_WIM, plan.transformations)
        self.assertIn("wim-splitter", {item.key for item in plan.requirements})
        self.assertIn("windows-bios-boot-code", {item.key for item in plan.requirements})

    def test_fat32_exact_max_file_size_does_not_split(self):
        plan = build_write_plan(inspection(windows=True), [
            ArchiveEntry("sources/install.wim", FAT32_MAX_FILE_SIZE),
        ])
        self.assertFalse(plan.needs_wim_split)

    def test_explicit_ntfs_does_not_split_windows_wim(self):
        plan = build_write_plan(
            inspection(windows=True),
            [ArchiveEntry("sources/install.wim", FAT32_MAX_FILE_SIZE + 1)],
            requested_filesystem=FileSystem.NTFS,
        )
        self.assertFalse(plan.needs_wim_split)
        self.assertEqual(plan.layout.main_filesystem, FileSystem.NTFS)

    def test_single_nested_oversized_windows_wim_is_preserved_on_ntfs(self):
        plan = build_write_plan(
            inspection(windows=True, boot_modes=("UEFI",)),
            [
                ArchiveEntry("x64/sources/install.wim", FAT32_MAX_FILE_SIZE + 1),
                ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 10),
            ],
            firmware_target=FirmwareTarget.UEFI_ONLY,
        )
        self.assertEqual(plan.layout.main_filesystem, FileSystem.NTFS)
        self.assertFalse(plan.needs_wim_split)
        with self.assertRaisesRegex(PlanError, "FAT32 cannot hold"):
            build_write_plan(
                inspection(windows=True, boot_modes=("UEFI",)),
                [
                    ArchiveEntry(
                        "x64/sources/install.wim", FAT32_MAX_FILE_SIZE + 1,
                    ),
                    ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 10),
                ],
                firmware_target=FirmwareTarget.UEFI_ONLY,
                requested_filesystem=FileSystem.FAT32,
            )

    def test_multiple_small_windows_wims_remain_fat32_without_splitting(self):
        plan = build_write_plan(
            inspection(windows=True, boot_modes=("UEFI",)),
            [
                ArchiveEntry("x64/sources/install.wim", 1024),
                ArchiveEntry("x86/sources/install.wim", 2048),
                ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 10),
            ],
            firmware_target=FirmwareTarget.UEFI_ONLY,
        )
        self.assertEqual(plan.layout.main_filesystem, FileSystem.FAT32)
        self.assertFalse(plan.needs_wim_split)

    def test_multiple_windows_wims_with_one_large_source_use_ntfs(self):
        entries = [
            ArchiveEntry("x64/sources/install.wim", FAT32_MAX_FILE_SIZE + 1),
            ArchiveEntry("x86/sources/install.wim", 2048),
            ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 10),
        ]
        plan = build_write_plan(
            inspection(windows=True, boot_modes=("UEFI",)), entries,
            firmware_target=FirmwareTarget.UEFI_ONLY,
        )
        self.assertEqual(plan.layout.main_filesystem, FileSystem.NTFS)
        self.assertEqual(plan.layout.boot_strategy, BootStrategy.UEFI_NTFS)
        self.assertFalse(plan.needs_wim_split)
        with self.assertRaisesRegex(PlanError, "FAT32 cannot hold"):
            build_write_plan(
                inspection(windows=True, boot_modes=("UEFI",)), entries,
                firmware_target=FirmwareTarget.UEFI_ONLY,
                requested_filesystem=FileSystem.FAT32,
            )

    def test_large_canonical_wim_with_esd_source_is_preserved_on_ntfs(self):
        entries = [
            ArchiveEntry("sources/install.wim", FAT32_MAX_FILE_SIZE + 1),
            ArchiveEntry("sources/install.esd", 2048),
            ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 10),
        ]
        plan = build_write_plan(
            inspection(windows=True, boot_modes=("UEFI",)), entries,
            firmware_target=FirmwareTarget.UEFI_ONLY,
        )
        self.assertEqual(plan.layout.main_filesystem, FileSystem.NTFS)
        self.assertFalse(plan.needs_wim_split)

    def test_non_wim_over_fat32_limit_uses_ntfs_and_uefi_boot_partition(self):
        plan = build_write_plan(inspection(), [
            ArchiveEntry("live/filesystem.squashfs", FAT32_MAX_FILE_SIZE + 1),
        ])
        self.assertEqual(plan.layout.main_filesystem, FileSystem.NTFS)
        self.assertEqual(plan.layout.partition_count, 2)
        self.assertIsNone(plan.layout.boot_partition_filesystem)
        self.assertEqual(plan.layout.boot_strategy, BootStrategy.UEFI_NTFS)
        uefi_ntfs = next(item for item in plan.requirements if item.key == "uefi-ntfs")
        self.assertEqual(uefi_ntfs.source, RequirementSource.VERIFIED_DOWNLOAD)

    def test_uefi_only_ntfs_plan_is_executable_for_supported_architecture(self):
        plan = build_write_plan(
            inspection(boot_modes=("UEFI",)),
            [
                ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 10),
                ArchiveEntry("huge.bin", FAT32_MAX_FILE_SIZE + 1),
            ],
            firmware_target=FirmwareTarget.UEFI_ONLY,
        )
        self.assertTrue(plan.executable, plan.blockers)
        self.assertEqual(plan.layout.boot_strategy, BootStrategy.UEFI_NTFS)
        self.assertFalse(plan.needs_wim_split)

    def test_uefi_ntfs_blocks_incomplete_or_unknown_architectures(self):
        for architecture, message in (
            ("LoongArch64", "no complete"),
            ("MIPS64", "not enabled"),
        ):
            fallback_name = {
                "LoongArch64": "BOOTLOONGARCH64.EFI",
                "MIPS64": "BOOTMIPS64.EFI",
            }[architecture]
            image = inspection(
                boot_modes=("UEFI",), architectures=(architecture,),
            )
            image = ImageInspection(**{
                **image.__dict__,
                "uefi_payloads": (
                    ImageUefiPayload(
                        f"EFI/BOOT/{fallback_name}", architecture,
                        "EFI application", True, SignatureTableState.ABSENT,
                        SbatState.ABSENT, (),
                    ),
                ),
            })
            entries = [
                ArchiveEntry(f"EFI/BOOT/{fallback_name}", 10),
                ArchiveEntry("huge.bin", FAT32_MAX_FILE_SIZE + 1),
            ]
            with self.subTest(architecture=architecture):
                plan = build_write_plan(
                    image, entries, firmware_target=FirmwareTarget.UEFI_ONLY,
                )
                self.assertFalse(plan.executable)
                self.assertTrue(any(message in item for item in plan.blockers))

    def test_uefi_ntfs_allows_explicitly_confirmed_unsigned_architectures(self):
        for architecture, fallback_name in (
            ("ARM", "BOOTARM.EFI"),
            ("RISC-V64", "BOOTRISCV64.EFI"),
        ):
            image = inspection(
                boot_modes=("UEFI",), architectures=(architecture,),
            )
            image = ImageInspection(**{
                **image.__dict__,
                "uefi_payloads": (
                    ImageUefiPayload(
                        f"EFI/BOOT/{fallback_name}", architecture,
                        "EFI application", True, SignatureTableState.ABSENT,
                        SbatState.ABSENT, (),
                    ),
                ),
            })
            plan = build_write_plan(
                image,
                [
                    ArchiveEntry(f"EFI/BOOT/{fallback_name}", 10),
                    ArchiveEntry("huge.bin", FAT32_MAX_FILE_SIZE + 1),
                ],
                firmware_target=FirmwareTarget.UEFI_ONLY,
            )
            with self.subTest(architecture=architecture):
                self.assertTrue(plan.executable, plan.blockers)
                self.assertTrue(any("unsigned" in item for item in plan.warnings))

    def test_fallback_filename_must_match_the_pe_machine_architecture(self):
        image = inspection(boot_modes=("UEFI",), architectures=("x64",))
        image = ImageInspection(**{
            **image.__dict__,
            "uefi_payloads": (
                ImageUefiPayload(
                    "EFI/BOOT/BOOTX64.EFI", "ARM64", "EFI application", True,
                    SignatureTableState.ABSENT, SbatState.ABSENT, (),
                ),
            ),
        })
        plan = build_write_plan(
            image,
            [
                ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 10),
                ArchiveEntry("huge.bin", FAT32_MAX_FILE_SIZE + 1),
            ],
            firmware_target=FirmwareTarget.UEFI_ONLY,
        )
        self.assertFalse(plan.executable)
        self.assertTrue(any("does not match" in item for item in plan.blockers))

    def test_explicit_fat32_rejects_unsplittable_large_file(self):
        with self.assertRaisesRegex(PlanError, "cannot hold"):
            build_write_plan(
                inspection(), [ArchiveEntry("huge.bin", FAT32_MAX_FILE_SIZE + 1)],
                requested_filesystem=FileSystem.FAT32,
            )

    def test_explicit_dd_allows_optical_iso_but_warns_if_not_hybrid(self):
        image = inspection()
        image = ImageInspection(
            **{**image.__dict__, "has_mbr": False, "has_gpt": False}
        )
        plan = build_write_plan(image, requested_mode=WriteMode.DD)
        self.assertTrue(plan.warnings)

    def test_explicit_dd_allows_malformed_partition_metadata_with_warning(self):
        image = inspection()
        image = ImageInspection(**{
            **image.__dict__,
            "partition_table_valid": False,
            "partition_table_kind": "malformed",
            "partition_table_issues": ("The MBR partition is out of bounds.",),
        })
        plan = build_write_plan(image, requested_mode=WriteMode.DD)
        self.assertTrue(plan.executable)
        self.assertTrue(any("malformed" in item for item in plan.warnings))

    def test_explicit_dd_warns_when_target_sector_size_differs(self):
        image = inspection(iso=False)
        image = ImageInspection(**{
            **image.__dict__,
            "has_mbr": True,
            "partition_table_valid": True,
            "partition_table_kind": "gpt",
            "partition_table_sector_size": 4096,
        })

        plan = build_write_plan(
            image,
            requested_mode=WriteMode.DD,
            target_logical_sector_size=512,
        )

        self.assertTrue(plan.executable)
        self.assertTrue(any("different logical" in item for item in plan.warnings))

    def test_target_capacity_is_checked_without_touching_target(self):
        with self.assertRaisesRegex(PlanError, "smaller"):
            build_write_plan(inspection(iso=False), target_size=100)

    def test_extracted_mode_rejects_a_raw_image(self):
        with self.assertRaisesRegex(PlanError, "requires an ISO"):
            build_write_plan(inspection(iso=False), requested_mode=WriteMode.EXTRACTED_ISO)

    def test_missing_entry_catalog_marks_constraints_unchecked(self):
        plan = build_write_plan(inspection())
        self.assertFalse(plan.content_constraints_checked)
        self.assertTrue(any("rescan" in warning for warning in plan.warnings))
        self.assertTrue(any("catalog" in blocker for blocker in plan.blockers))

    def test_extracted_capacity_includes_filesystem_overhead(self):
        with self.assertRaisesRegex(PlanError, "metadata"):
            build_write_plan(
                inspection(boot_modes=("UEFI",)), [ArchiveEntry("file", 100)],
                target_size=100,
            )


class WriteMethodRecommendationTests(unittest.TestCase):
    @staticmethod
    def uefi_entries():
        return (
            ArchiveEntry("EFI", kind=EntryKind.DIRECTORY),
            ArchiveEntry("EFI/BOOT", kind=EntryKind.DIRECTORY),
            ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 8),
            ArchiveEntry("casper/filesystem.squashfs", 512),
        )

    def test_raw_images_offer_only_dd(self):
        result = recommend_write_method(inspection(iso=False))
        self.assertEqual(result.available_modes, (WriteMode.DD,))
        self.assertEqual(result.recommended_mode, WriteMode.DD)
        self.assertIsNone(result.iso_plan)

    def test_optical_only_uefi_iso_recommends_iso_mode(self):
        result = recommend_write_method(
            inspection(hybrid=False, boot_modes=("UEFI",)), self.uefi_entries(),
        )
        self.assertEqual(result.recommended_mode, WriteMode.EXTRACTED_ISO)
        self.assertIn(WriteMode.EXTRACTED_ISO, result.available_modes)
        self.assertIn("optical-only", result.reason)

    def test_windows_installer_recommends_iso_even_when_hybrid(self):
        result = recommend_write_method(
            inspection(windows=True), self.uefi_entries(),
        )
        self.assertEqual(result.recommended_mode, WriteMode.EXTRACTED_ISO)
        self.assertIn("Windows installer", result.reason)

    def test_hybrid_linux_iso_recommends_dd_but_exposes_iso(self):
        result = recommend_write_method(inspection(), self.uefi_entries())
        self.assertEqual(result.recommended_mode, WriteMode.DD)
        self.assertEqual(
            result.available_modes,
            (WriteMode.DD, WriteMode.EXTRACTED_ISO),
        )
        self.assertIn("native BIOS/UEFI", result.reason)

    def test_blocked_iso_exposes_reason_without_silent_fallback(self):
        result = recommend_write_method(
            inspection(boot_modes=("UEFI",)),
            (ArchiveEntry("README", 1),),
        )
        self.assertEqual(result.available_modes, (WriteMode.DD,))
        self.assertEqual(result.recommended_mode, WriteMode.DD)
        self.assertIn("fallback loader", result.iso_unavailable_reason)

    def test_malformed_table_keeps_dd_available_without_recommending_it(self):
        image = inspection()
        image = ImageInspection(**{
            **image.__dict__,
            "partition_table_valid": False,
            "partition_table_kind": "malformed",
            "partition_table_issues": ("The GPT header CRC32 does not match.",),
        })
        blocked_iso = recommend_write_method(image, ())
        self.assertEqual(blocked_iso.available_modes, (WriteMode.DD,))
        self.assertIsNone(blocked_iso.recommended_mode)
        self.assertIn("explicit", blocked_iso.reason)
        self.assertTrue(blocked_iso.dd_plan.warnings)

        executable_iso = recommend_write_method(image, self.uefi_entries())
        self.assertEqual(
            executable_iso.recommended_mode, WriteMode.EXTRACTED_ISO,
        )
        self.assertEqual(
            executable_iso.available_modes,
            (WriteMode.DD, WriteMode.EXTRACTED_ISO),
        )

    def test_malformed_raw_image_keeps_only_explicit_dd_available(self):
        image = inspection(iso=False)
        image = ImageInspection(**{
            **image.__dict__, "has_mbr": True,
            "partition_table_valid": False,
            "partition_table_kind": "malformed",
        })
        result = recommend_write_method(image)
        self.assertEqual(result.available_modes, (WriteMode.DD,))
        self.assertIsNone(result.recommended_mode)
        self.assertIn("not recommended", result.reason)

    def test_incomplete_compressed_table_is_unverified_not_malformed(self):
        image = inspection(iso=False)
        image = ImageInspection(**{
            **image.__dict__,
            "has_mbr": True,
            "compression": "gzip",
            "partition_table_valid": None,
            "partition_table_kind": "incomplete",
            "partition_table_inspection_complete": False,
        })

        result = recommend_write_method(image)

        self.assertEqual(result.available_modes, (WriteMode.DD,))
        self.assertIsNone(result.recommended_mode)
        self.assertIn("could not be fully inspected", result.reason)
        self.assertTrue(any("fully inspected" in item for item in result.dd_plan.warnings))

    def test_sector_mismatch_is_never_silently_recommended_for_dd(self):
        raw = inspection(iso=False)
        raw = ImageInspection(**{
            **raw.__dict__,
            "has_mbr": True,
            "partition_table_valid": True,
            "partition_table_kind": "gpt",
            "partition_table_sector_size": 4096,
        })
        raw_result = recommend_write_method(
            raw, target_logical_sector_size=512,
        )
        self.assertEqual(raw_result.available_modes, (WriteMode.DD,))
        self.assertIsNone(raw_result.recommended_mode)
        self.assertIn("different logical sector sizes", raw_result.reason)

        hybrid = inspection(boot_modes=("UEFI",))
        hybrid = ImageInspection(**{
            **hybrid.__dict__,
            "partition_table_valid": True,
            "partition_table_kind": "gpt",
            "partition_table_sector_size": 4096,
        })
        iso_result = recommend_write_method(
            hybrid,
            self.uefi_entries(),
            target_logical_sector_size=512,
        )
        self.assertEqual(iso_result.recommended_mode, WriteMode.EXTRACTED_ISO)
        self.assertIn("different logical sector sizes", iso_result.reason)

    def test_unknown_selected_target_sector_keeps_structured_dd_explicit(self):
        raw = inspection(iso=False)
        raw = ImageInspection(**{
            **raw.__dict__,
            "has_mbr": True,
            "partition_table_valid": True,
            "partition_table_kind": "gpt",
            "partition_table_sector_size": 4096,
        })

        provisional = recommend_write_method(raw)
        selected = recommend_write_method(raw, target_logical_sector_size=0)

        self.assertEqual(provisional.recommended_mode, WriteMode.DD)
        self.assertIsNone(selected.recommended_mode)
        self.assertIn("did not report", selected.reason)
        self.assertTrue(any("did not report" in item for item in selected.dd_plan.warnings))

    def test_target_capacity_is_method_specific(self):
        result = recommend_write_method(
            inspection(hybrid=False, boot_modes=("UEFI",)),
            self.uefi_entries(),
            target_size=100,
        )
        self.assertEqual(result.available_modes, ())
        self.assertIsNone(result.recommended_mode)
        self.assertIn("too small", result.reason)


class ExtractionSafetyTests(unittest.TestCase):
    def assert_unsafe(self, *entries: ArchiveEntry) -> None:
        with self.assertRaises(UnsafeArchiveError):
            validate_extraction_entries(entries)

    def test_normalizes_safe_paths(self):
        modified_ns = 1_709_210_096_123_456_789
        result = validate_extraction_entries([
            ArchiveEntry("EFI\\BOOT\\BOOTX64.EFI", modified_ns=modified_ns),
            ArchiveEntry("boot", kind=EntryKind.DIRECTORY),
            ArchiveEntry("boot/current", kind=EntryKind.SYMLINK, link_target="grub"),
        ])
        self.assertEqual(result[0].path, "EFI/BOOT/BOOTX64.EFI")
        self.assertEqual(result[0].modified_ns, modified_ns)

    def test_rejects_invalid_or_link_modification_times(self):
        for value in (
            True, 1.5, -1, 0,
            MIN_PORTABLE_ARCHIVE_MTIME_NS - 1,
            MAX_PORTABLE_ARCHIVE_MTIME_NS + 1,
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ArchiveEntry("file", modified_ns=value)  # type: ignore[arg-type]
        for value in (
            MIN_PORTABLE_ARCHIVE_MTIME_NS,
            MAX_PORTABLE_ARCHIVE_MTIME_NS,
        ):
            self.assertEqual(ArchiveEntry("file", modified_ns=value).modified_ns, value)
        with self.assertRaisesRegex(ValueError, "files and directories"):
            ArchiveEntry(
                "link", kind=EntryKind.SYMLINK, link_target="file",
                modified_ns=1_709_210_096_000_000_000,
            )

    def test_rejects_absolute_unc_drive_and_parent_paths(self):
        for path in ("/etc/passwd", "C:\\Windows\\file", "\\\\server\\share", "a/../b"):
            with self.subTest(path=path):
                self.assert_unsafe(ArchiveEntry(path))

    def test_rejects_special_entries_and_reserved_device_names(self):
        self.assert_unsafe(ArchiveEntry("dev/sda", kind=EntryKind.BLOCK_DEVICE))
        self.assert_unsafe(ArchiveEntry("boot/CON.txt"))

    def test_rejects_symlink_escape(self):
        self.assert_unsafe(ArchiveEntry(
            "boot/link", kind=EntryKind.SYMLINK, link_target="../../outside",
        ))

    def test_rejects_member_written_through_symlink(self):
        self.assert_unsafe(
            ArchiveEntry("boot/link", kind=EntryKind.SYMLINK, link_target="grub"),
            ArchiveEntry("boot/link/evil.cfg"),
        )

    def test_rejects_case_and_unicode_collisions(self):
        self.assert_unsafe(ArchiveEntry("EFI/BOOT/file"), ArchiveEntry("efi/boot/FILE"))
        self.assert_unsafe(ArchiveEntry("caf\N{LATIN SMALL LETTER E WITH ACUTE}"), ArchiveEntry("cafe\N{COMBINING ACUTE ACCENT}"))

    def test_rejects_file_used_as_directory(self):
        self.assert_unsafe(ArchiveEntry("boot"), ArchiveEntry("boot/grub.cfg"))


if __name__ == "__main__":
    unittest.main()
