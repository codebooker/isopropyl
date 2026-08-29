from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import fcntl
import os
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from isopropyl.iso import (
    ArchiveEntry,
    BootStrategy,
    DependencyRequirement,
    FileSystem,
    FirmwareTarget,
    PartitionTable,
    RequirementSource,
    TargetLayout,
    Transformation,
    WriteMode,
    WritePlan,
    build_write_plan,
)
from isopropyl.images import ImageInspection
from isopropyl.iso_staging import (
    IsoStagingExecutor,
    IsoStagingSafetyError,
    build_iso_staging_plan,
    validate_iso_staging_plan,
)
from isopropyl.private_fat32 import (
    PrivateFat32Builder,
    PrivateFat32Error,
    PrivateFat32State,
)
from isopropyl.windows_bios_pbr import MODERN_BOOTMGR_ENTRY_STUB, STAGE_SECTOR
from isopropyl.uefi import ImageUefiPayload, SbatState, SignatureTableState
from isopropyl.windows_iso_fat32 import (
    WindowsIsoFat32Builder,
    WindowsIsoFat32Error,
    build_windows_iso_fat32_plan,
    prepare_windows_iso_fat32,
    validate_windows_iso_fat32_plan,
)
from tests.test_iso_staging import (
    FakeExtractor,
    FakeSplitter,
    SEVEN_ZIP,
    fake_catalog_scanner,
    fake_split_plan,
)


IMAGE_SIZE = 40 * 1024 * 1024
LARGE_TEMP_PARENT = Path(__file__).resolve().parents[1]


def requirement(
    key: str,
    source: RequirementSource,
    version: str | None = None,
) -> DependencyRequirement:
    return DependencyRequirement(key, (key,), source, key, version)


def windows_write_plan(total_bytes: int) -> WritePlan:
    return WritePlan(
        WriteMode.EXTRACTED_ISO,
        FirmwareTarget.BOTH,
        TargetLayout(
            PartitionTable.MBR,
            FileSystem.FAT32,
            1,
            None,
            True,
            True,
            BootStrategy.WINDOWS_BOOTMGR_FAT32,
            True,
        ),
        (
            requirement("iso-extractor", RequirementSource.SYSTEM),
            requirement("partitioner", RequirementSource.SYSTEM),
            requirement("formatter-fat32", RequirementSource.SYSTEM),
            requirement("windows-bios-boot-files", RequirementSource.IMAGE),
            requirement(
                "isopropyl-windows-bios-loader",
                RequirementSource.BUNDLED,
                "project-source-reproducible-v1",
            ),
            requirement("efi-removable-loader-x64", RequirementSource.IMAGE),
        ),
        (),
        (),
        total_bytes,
        36 * 1024 * 1024,
        True,
        ("BIOS construction is not enabled; choose UEFI-only or use DD mode.",),
    )


def populate_extracted_tree(root: Path) -> None:
    bootmgr = root / "bootmgr"
    if bootmgr.exists():
        payload = bytearray(bootmgr.stat().st_size)
        payload[:len(MODERN_BOOTMGR_ENTRY_STUB)] = MODERN_BOOTMGR_ENTRY_STUB
        bootmgr.write_bytes(payload)
    payloads = {
        "Boot/BCD": b"regf" + b"bcd" * 32,
        "EFI/BOOT/BOOTX64.EFI": b"MZ" + b"efi" * 32,
        "sources/boot.wim": b"wim" * 1024,
    }
    for relative, payload in payloads.items():
        path = root / relative
        if path.exists():
            if len(payload) != path.stat().st_size:
                raise AssertionError("fixture size mismatch")
            path.write_bytes(payload)


class WindowsIsoFat32Tests(unittest.TestCase):
    def publish(
        self,
        directory: str,
        entries: tuple[ArchiveEntry, ...],
        write_plan: WritePlan,
        *,
        mutate=populate_extracted_tree,
        splitter=None,
    ):
        root = Path(directory)
        workspace = Path(directory) / "workspace"
        workspace.mkdir()
        image = root / "source.iso"
        image.write_bytes(b"ISO placeholder")
        with patch(
            "isopropyl.iso_staging.scan_image_contents",
            fake_catalog_scanner(entries),
        ):
            iso_plan = build_iso_staging_plan(
                image,
                root / "staging",
                entries,
                write_plan,
                seven_zip=SEVEN_ZIP,
            )
        staging_result = IsoStagingExecutor(
            extractor=FakeExtractor(
                mutate=lambda destination, _image: mutate(destination),
            ),
            wim_splitter=splitter,
            split_plan_builder=fake_split_plan,
        ).execute(iso_plan)
        self.assertIsNotNone(staging_result.tree_manifest)
        return iso_plan, staging_result, workspace

    def build_plan(
        self,
        directory: str,
        *,
        write_plan: WritePlan | None = None,
        image_size: int = IMAGE_SIZE,
    ):
        entries = (
            ArchiveEntry("bootmgr", 0x400),
            ArchiveEntry("Boot/BCD", 100),
            ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 98),
            ArchiveEntry("sources/boot.wim", 3 * 1024),
        )
        selected_write_plan = write_plan or windows_write_plan(
            sum(item.size for item in entries),
        )
        iso_plan, staging_result, workspace = self.publish(
            directory,
            entries,
            selected_write_plan,
        )
        plan = build_windows_iso_fat32_plan(
            iso_plan,
            staging_result,
            workspace,
            image_size=image_size,
        )
        return plan, workspace

    def test_builds_patches_and_re_attests_only_anonymous_final_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan, workspace = self.build_plan(directory)
            validate_windows_iso_fat32_plan(plan)
            with prepare_windows_iso_fat32(plan) as prepared:
                readonly, readonly_size = prepared._duplicate_attested_readonly_descriptor()
                try:
                    self.assertEqual(readonly_size, IMAGE_SIZE)
                    self.assertEqual(
                        fcntl.fcntl(readonly, fcntl.F_GETFL) & os.O_ACCMODE,
                        os.O_RDONLY,
                    )
                    with self.assertRaises(OSError):
                        os.write(readonly, b"x")
                finally:
                    os.close(readonly)
                digest = hashlib.sha256()
                prefix = bytearray()
                for block in prepared.chunks(1024 * 1024):
                    digest.update(block)
                    if len(prefix) < plan.private_plan.geometry.volume_offset + 14 * 512:
                        prefix.extend(block)
                result = prepared.result
                self.assertEqual(digest.hexdigest(), result.final_image_sha256)
                self.assertNotEqual(
                    result.unpatched_image_sha256,
                    result.final_image_sha256,
                )
                self.assertEqual(
                    result.source_manifest_sha256,
                    plan.source_manifest_sha256,
                )
                self.assertRegex(result.final_fat_manifest_sha256, r"^[0-9a-f]{64}$")
                self.assertEqual(prefix[510:512], b"\x55\xaa")
                volume = plan.private_plan.geometry.volume_offset
                self.assertEqual(prefix[volume + 510:volume + 512], b"\x55\xaa")
                self.assertTrue(any(
                    prefix[
                        volume + STAGE_SECTOR * 512:
                        volume + (STAGE_SECTOR + 2) * 512
                    ]
                ))
            self.assertEqual(tuple(workspace.iterdir()), ())

    def test_composes_the_strict_planner_output_without_enabling_device_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            entries = (
                ArchiveEntry("bootmgr", 0x400),
                ArchiveEntry("Boot/BCD", 100),
                ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 98),
                ArchiveEntry("sources/boot.wim", 3 * 1024),
            )
            payload = ImageUefiPayload(
                "EFI/BOOT/BOOTX64.EFI",
                "x64",
                "EFI application",
                True,
                SignatureTableState.ABSENT,
                SbatState.ABSENT,
                (),
            )
            write_plan = build_write_plan(
                ImageInspection(
                    size=1024,
                    kind="Optical ISO",
                    volume_label="WINDOWS",
                    has_mbr=False,
                    has_gpt=False,
                    is_iso9660=True,
                    looks_windows=True,
                    boot_modes=("BIOS", "UEFI"),
                    architectures=("x64",),
                    bootloader="Windows Boot Manager",
                    has_windows_installer=True,
                    contents_scanned=True,
                    uefi_payloads=(payload,),
                ),
                entries,
                firmware_target=FirmwareTarget.BOTH,
            )
            self.assertFalse(write_plan.executable)
            plan, _workspace = self.build_plan(
                directory,
                write_plan=write_plan,
                image_size=68 * 1024 * 1024,
            )
            validate_windows_iso_fat32_plan(plan)

    def test_unpatched_windows_profile_cannot_cross_consumer_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan, _workspace = self.build_plan(directory)
            image = PrivateFat32Builder().execute(plan.private_plan)
            try:
                self.assertIs(image.state, PrivateFat32State.UNPATCHED_ATTESTED)
                with self.assertRaisesRegex(PrivateFat32Error, "patched, attested"):
                    next(image.chunks(512))
            finally:
                image.close()

    def test_prepared_owner_streams_and_closes_from_another_thread(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan, _workspace = self.build_plan(directory)
            prepared = prepare_windows_iso_fat32(plan)
            observations = []
            errors = []

            def consume() -> None:
                try:
                    observations.append(sum(len(block) for block in prepared.chunks()))
                    prepared.close()
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=consume, daemon=True)
            thread.start()
            thread.join(10)
            if thread.is_alive():
                prepared.close()
            self.assertFalse(thread.is_alive(), "the image lifecycle lock leaked")
            self.assertEqual(errors, [])
            self.assertEqual(observations, [IMAGE_SIZE])

    def test_readonly_bridge_survives_source_duplicate_close_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan, _workspace = self.build_plan(directory)
            with prepare_windows_iso_fat32(plan) as prepared:
                real_close = os.close

                def close_then_raise(descriptor: int) -> None:
                    real_close(descriptor)
                    raise OSError("synthetic close diagnostic")

                with patch(
                    "isopropyl.private_fat32.os.close",
                    side_effect=close_then_raise,
                ):
                    readonly, size = prepared._duplicate_attested_readonly_descriptor()
                try:
                    self.assertEqual(size, IMAGE_SIZE)
                    self.assertEqual(os.fstat(readonly).st_size, IMAGE_SIZE)
                    self.assertEqual(
                        fcntl.fcntl(readonly, fcntl.F_GETFL) & os.O_ACCMODE,
                        os.O_RDONLY,
                    )
                finally:
                    real_close(readonly)

    def test_rejects_missing_required_file_and_plan_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            entries = (
                ArchiveEntry("bootmgr", 0x400),
                ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 98),
                ArchiveEntry("sources/boot.wim", 3 * 1024),
            )
            iso_plan, staging_result, workspace = self.publish(
                directory,
                entries,
                windows_write_plan(sum(item.size for item in entries)),
            )
            with self.assertRaisesRegex(WindowsIsoFat32Error, "boot/bcd"):
                build_windows_iso_fat32_plan(
                    iso_plan,
                    staging_result,
                    workspace,
                    image_size=IMAGE_SIZE,
                )
        with tempfile.TemporaryDirectory() as directory:
            plan, workspace = self.build_plan(directory)
            forged = replace(plan, bootmgr_sha256="0" * 64)
            with self.assertRaisesRegex(WindowsIsoFat32Error, "receipt"):
                validate_windows_iso_fat32_plan(forged)
            replaced_result = replace(plan.staging_result)
            with self.assertRaisesRegex(WindowsIsoFat32Error, "authentic result"):
                build_windows_iso_fat32_plan(
                    plan.iso_plan,
                    replaced_result,
                    workspace,
                    image_size=IMAGE_SIZE,
                )

    def test_transitional_windows_staging_rejects_unreviewed_composition(self) -> None:
        entries = (
            ArchiveEntry("bootmgr", 0x400),
            ArchiveEntry("Boot/BCD", 100),
            ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 98),
            ArchiveEntry("sources/boot.wim", 3 * 1024),
        )
        write_plan = windows_write_plan(sum(item.size for item in entries))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "source.iso"
            image.write_bytes(b"ISO placeholder")
            for field in (
                "overlay", "embedded_fat", "windows_customization", "windows_bootex",
            ):
                with self.subTest(field=field), patch(
                    "isopropyl.iso_staging.scan_image_contents",
                    fake_catalog_scanner(entries),
                ):
                    with self.assertRaisesRegex(
                        IsoStagingSafetyError,
                        "transitional Windows BIOS\\+UEFI profile",
                    ):
                        build_iso_staging_plan(
                            image,
                            root / f"staging-{field}",
                            entries,
                            write_plan,
                            seven_zip=SEVEN_ZIP,
                            **{field: object()},
                        )

            with patch(
                "isopropyl.iso_staging.scan_image_contents",
                fake_catalog_scanner(entries),
            ):
                clean = build_iso_staging_plan(
                    image,
                    root / "staging-clean",
                    entries,
                    write_plan,
                    seven_zip=SEVEN_ZIP,
                )
            forged = replace(clean, overlay=object())
            with self.assertRaisesRegex(
                IsoStagingSafetyError,
                "transitional Windows BIOS\\+UEFI profile",
            ):
                validate_iso_staging_plan(forged)

    def test_witnessed_split_tree_may_be_smaller_than_original_catalog(self) -> None:
        with tempfile.TemporaryDirectory(dir=LARGE_TEMP_PARENT) as directory:
            entries = (
                ArchiveEntry("bootmgr", 0x400),
                ArchiveEntry("Boot/BCD", 100),
                ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 98),
                ArchiveEntry("sources/install.wim", (4 * 1024**3)),
            )
            write_plan = windows_write_plan(sum(item.size for item in entries))
            write_plan = replace(
                write_plan,
                requirements=write_plan.requirements + (
                    requirement("wim-splitter", RequirementSource.SYSTEM),
                ),
                transformations=(Transformation.SPLIT_WINDOWS_WIM,),
            )
            iso_plan, staging_result, workspace = self.publish(
                directory,
                entries,
                write_plan,
                splitter=FakeSplitter(),
            )
            self.assertLess(staging_result.bytes_staged, write_plan.minimum_content_bytes)
            image_size = (write_plan.minimum_target_bytes + 511) // 512 * 512
            plan = build_windows_iso_fat32_plan(
                iso_plan,
                staging_result,
                workspace,
                image_size=image_size,
            )
            self.assertEqual(
                plan.source_manifest_sha256,
                staging_result.tree_manifest.manifest_sha256,
            )

    def test_rejects_bootmgr_that_the_bios_stage_cannot_transfer(self) -> None:
        for payload in (
            MODERN_BOOTMGR_ENTRY_STUB + b"x" * 64,
            b"MZ" + bytes(0x3FE),
        ):
            with self.subTest(size=len(payload)):
                with tempfile.TemporaryDirectory() as directory:
                    entries = (
                        ArchiveEntry("bootmgr", len(payload)),
                        ArchiveEntry("Boot/BCD", 100),
                        ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 98),
                        ArchiveEntry("sources/boot.wim", 3 * 1024),
                    )

                    def write_invalid(destination: Path) -> None:
                        populate_extracted_tree(destination)
                        (destination / "bootmgr").write_bytes(payload)

                    iso_plan, staging_result, workspace = self.publish(
                        directory,
                        entries,
                        windows_write_plan(sum(item.size for item in entries)),
                        mutate=write_invalid,
                    )
                    with self.assertRaisesRegex(WindowsIsoFat32Error, "BOOTMGR"):
                        build_windows_iso_fat32_plan(
                            iso_plan,
                            staging_result,
                            workspace,
                            image_size=IMAGE_SIZE,
                        )

    def test_preimage_change_poisons_the_anonymous_image_before_mbr_activation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan, workspace = self.build_plan(directory)
            captured = []
            calls = 0
            real_execute = PrivateFat32Builder.execute
            real_pwrite = os.pwrite

            def capture_execute(builder, *args, **kwargs):
                image = real_execute(builder, *args, **kwargs)
                captured.append(image)
                return image

            def malicious_write(descriptor: int, data: bytes, offset: int) -> int:
                nonlocal calls
                count = real_pwrite(descriptor, data, offset)
                calls += 1
                if calls == 1:
                    real_pwrite(
                        descriptor,
                        b"X",
                        plan.private_plan.geometry.volume_offset + 6 * 512 + 100,
                    )
                return count

            with patch.object(PrivateFat32Builder, "execute", capture_execute), patch(
                "isopropyl.windows_iso_fat32.os.pwrite",
                side_effect=malicious_write,
            ), self.assertRaisesRegex(WindowsIsoFat32Error, "preimage changed"):
                WindowsIsoFat32Builder().execute(plan)
            self.assertEqual(len(captured), 1)
            self.assertIs(captured[0].state, PrivateFat32State.POISONED)
            self.assertEqual(tuple(workspace.iterdir()), ())

    def test_unplanned_reserved_sector_write_fails_complete_image_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan, _workspace = self.build_plan(directory)
            captured = []
            calls = 0
            real_execute = PrivateFat32Builder.execute
            real_pwrite = os.pwrite

            def capture_execute(builder, *args, **kwargs):
                image = real_execute(builder, *args, **kwargs)
                captured.append(image)
                return image

            def malicious_write(descriptor: int, data: bytes, offset: int) -> int:
                nonlocal calls
                count = real_pwrite(descriptor, data, offset)
                calls += 1
                if calls == 4:
                    real_pwrite(
                        descriptor,
                        b"X",
                        plan.private_plan.geometry.volume_offset + 20 * 512,
                    )
                return count

            with patch.object(PrivateFat32Builder, "execute", capture_execute), patch(
                "isopropyl.windows_iso_fat32.os.pwrite",
                side_effect=malicious_write,
            ), self.assertRaisesRegex(WindowsIsoFat32Error, "hash is inconsistent"):
                WindowsIsoFat32Builder().execute(plan)
            self.assertEqual(len(captured), 1)
            self.assertIs(captured[0].state, PrivateFat32State.POISONED)

    def test_cleanup_releases_patch_lock_even_when_descriptor_close_raises(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan, _workspace = self.build_plan(directory)
            captured = []
            target_descriptor = []
            calls = 0
            real_execute = PrivateFat32Builder.execute
            real_pwrite = os.pwrite
            real_close = os.close

            def capture_execute(builder, *args, **kwargs):
                image = real_execute(builder, *args, **kwargs)
                captured.append(image)
                target_descriptor.append(image._descriptor)
                return image

            def malicious_write(descriptor: int, data: bytes, offset: int) -> int:
                nonlocal calls
                count = real_pwrite(descriptor, data, offset)
                calls += 1
                if calls == 1:
                    real_pwrite(
                        descriptor,
                        b"X",
                        plan.private_plan.geometry.volume_offset + 6 * 512 + 100,
                    )
                return count

            def failing_close(descriptor: int) -> None:
                real_close(descriptor)
                if target_descriptor and descriptor == target_descriptor[0]:
                    raise OSError("injected anonymous-image close failure")

            with patch.object(PrivateFat32Builder, "execute", capture_execute), patch(
                "isopropyl.windows_iso_fat32.os.pwrite",
                side_effect=malicious_write,
            ), patch(
                "isopropyl.private_fat32.os.close",
                side_effect=failing_close,
            ), self.assertRaisesRegex(OSError, "injected anonymous-image close failure"):
                WindowsIsoFat32Builder().execute(plan)
            self.assertEqual(len(captured), 1)
            self.assertIs(captured[0].state, PrivateFat32State.POISONED)
            thread = threading.Thread(target=captured[0].close, daemon=True)
            thread.start()
            thread.join(2)
            self.assertFalse(thread.is_alive(), "failure cleanup leaked the patch lock")


if __name__ == "__main__":
    unittest.main()
