from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import (
    QApplication, QComboBox, QDialog, QMessageBox, QPlainTextEdit, QPushButton,
)

from isopropyl.app import PendingIsoWrite, Window
from isopropyl.bootloaders import (
    BootloaderCacheDeletionResult, BootloaderCacheInventory, CacheDeletion,
    CachedBootloaderArtifact,
)
from isopropyl.casper_media import supported_casper_profile
from isopropyl.devices import Device
from isopropyl.formatting import Filesystem as FormatFilesystem
from isopropyl.images import ImageInspection, ImageMember
from isopropyl.iso import WriteMode
from isopropyl.persistence import ALIGNMENT_BYTES, MIN_PERSISTENCE_BYTES
from isopropyl.uefi import ImageUefiPayload, SbatState, SignatureTableState


def device(size: int = 8 * 1024**3) -> Device:
    return Device(
        "/dev/sdz", size, "Test Drive", "ISOpropyl", "usb", "SERIAL",
        "", "65:144", True, True, False, (), (),
    )


def optical_windows_inspection(*, hybrid: bool = False) -> ImageInspection:
    return ImageInspection(
        size=1024,
        kind="Optical ISO",
        volume_label="WINDOWS",
        has_mbr=hybrid,
        has_gpt=False,
        is_iso9660=True,
        looks_windows=True,
        boot_modes=("UEFI",),
        architectures=("x64",),
        bootloader="Windows Boot Manager",
        has_windows_installer=True,
        contents_scanned=True,
        uefi_payloads=(
            ImageUefiPayload(
                "EFI/BOOT/BOOTX64.EFI", "x64", "EFI application", True,
                SignatureTableState.ABSENT, SbatState.ABSENT, (),
            ),
        ),
        members=(
            ImageMember("EFI", 0, "directory"),
            ImageMember("EFI/BOOT", 0, "directory"),
            ImageMember("EFI/BOOT/BOOTX64.EFI", 8, "file"),
            ImageMember("sources", 0, "directory"),
            ImageMember("sources/install.esd", 16, "file"),
        ),
    )


def ubuntu_casper_inspection() -> ImageInspection:
    members = tuple(
        ImageMember(path, size, "file") for path, size in (
            (".disk/info", 32),
            ("casper/vmlinuz", 16),
            ("casper/initrd", 16),
            ("casper/filesystem.squashfs", 1024),
            ("EFI/BOOT/BOOTX64.EFI", 8),
            ("boot/grub/grub.cfg", 128),
        )
    )
    return ImageInspection(
        size=2048,
        kind="Optical ISO",
        volume_label="Ubuntu 24.04.3 LTS amd64",
        has_mbr=True,
        has_gpt=False,
        is_iso9660=True,
        looks_windows=False,
        boot_modes=("BIOS", "UEFI"),
        architectures=("x64",),
        bootloader="GRUB",
        has_windows_installer=False,
        contents_scanned=True,
        members=members,
        uefi_payloads=(
            ImageUefiPayload(
                "EFI/BOOT/BOOTX64.EFI", "x64", "EFI application", True,
                SignatureTableState.ABSENT, SbatState.ABSENT, (),
            ),
        ),
    )


class ImmediateThread:
    """Run a Window background closure synchronously in headless tests."""

    def __init__(self, *, target, daemon: bool = False) -> None:
        self.target = target
        self.daemon = daemon

    def start(self) -> None:
        self.target()


class RestoreFilesystemDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        with patch("isopropyl.app.list_devices", return_value=[]):
            self.window = Window()
        self.window.device_refresh_generation += 1
        self.window.device_refresh_busy = False
        self.window.devices = [device()]
        self.window.device_combo.clear()
        self.window.device_combo.addItem(self.window.devices[0].label)

    def tearDown(self) -> None:
        self.window.close()
        self.window.deleteLater()
        self.application.processEvents()

    def test_restore_selector_exposes_ext2_ext3_and_ext4(self):
        observed = []

        def inspect_dialog(dialog) -> int:
            combo = next(
                candidate for candidate in dialog.findChildren(QComboBox)
                if any(
                    candidate.itemData(index) is FormatFilesystem.EXT2
                    for index in range(candidate.count())
                )
            )
            observed.extend(combo.itemData(index) for index in range(combo.count()))
            return QDialog.DialogCode.Rejected

        with patch("isopropyl.app.QDialog.exec", new=inspect_dialog):
            self.window.format_drive()
        self.assertEqual(
            observed,
            [
                FormatFilesystem.FAT32, FormatFilesystem.EXFAT,
                FormatFilesystem.NTFS, FormatFilesystem.EXT2,
                FormatFilesystem.EXT3, FormatFilesystem.EXT4,
            ],
        )


class BootloaderCacheDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        with patch("isopropyl.app.list_devices", return_value=[]):
            self.window = Window()
        self.window.device_refresh_generation += 1
        self.window.device_refresh_busy = False

    def tearDown(self) -> None:
        self.window.close()
        self.window.deleteLater()
        self.application.processEvents()

    def test_cache_dialog_deletes_only_inventory_entries_marked_safe(self):
        safe = CachedBootloaderArtifact(
            "uefi-ntfs", "2.8", "uefi-ntfs.img", 1024, True, True,
        )
        unsafe = CachedBootloaderArtifact(
            "grub", "2.12", "core.img", 2048, False, False,
            "The path is a symbolic link",
        )
        populated = BootloaderCacheInventory((safe, unsafe), 3072, 1024)
        empty = BootloaderCacheInventory((), 0, 0)
        deletion = BootloaderCacheDeletionResult(
            (CacheDeletion("uefi-ntfs", "2.8", "uefi-ntfs.img", 1024),),
            (), 1024,
        )
        observed: dict[str, str] = {}

        def exercise(dialog) -> int:
            observed["details"] = "\n".join(
                widget.toPlainText()
                for widget in dialog.findChildren(QPlainTextEdit)
            )
            delete_buttons = [
                button for button in dialog.findChildren(QPushButton)
                if button.text() == "Delete safe cached helpers…"
            ]
            self.assertEqual(len(delete_buttons), 1)
            self.assertTrue(delete_buttons[0].isEnabled())
            delete_buttons[0].click()
            return 0

        with (
            patch(
                "isopropyl.app.inventory_cache", side_effect=(populated, empty),
            ),
            patch("isopropyl.app.delete_cached_artifacts", return_value=deletion) as delete,
            patch(
                "isopropyl.app.QMessageBox.question",
                return_value=QMessageBox.StandardButton.Yes,
            ),
            patch("isopropyl.app.QMessageBox.information") as information,
            patch("isopropyl.app.QDialog.exec", new=exercise),
        ):
            self.window.show_bootloader_cache()

        self.assertIn("uefi-ntfs 2.8", observed["details"])
        self.assertIn("Verified", observed["details"])
        self.assertIn("Unsafe entry", observed["details"])
        delete.assert_called_once_with((("uefi-ntfs", "2.8", "uefi-ntfs.img"),))
        information.assert_called_once()


class WindowWriteMethodTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.settings_home = tempfile.TemporaryDirectory()
        with patch("isopropyl.app.list_devices", return_value=[]):
            self.window = Window()
        # Any queued result from the constructor's worker is now deliberately stale.
        self.window.device_refresh_generation += 1
        self.window.device_refresh_busy = False
        self.window.image = Path(self.settings_home.name) / "windows.iso"
        self.window.image.write_bytes(b"fixture")
        self.window.inspection = optical_windows_inspection()
        self.window.inspection_identity = (1, 2, 3, 4)
        self.window.devices = [device()]
        self.window.device_combo.clear()
        self.window.device_combo.addItem(self.window.devices[0].label)

    def tearDown(self) -> None:
        self.window.close()
        self.window.deleteLater()
        self.application.processEvents()
        self.settings_home.cleanup()

    def test_windows_iso_is_recommended_and_verification_is_mandatory(self):
        self.window.verify.setChecked(False)
        self.window.rebuild_write_recommendation(preserve_selection=False)

        modes = tuple(
            WriteMode(self.window.write_method.itemData(index))
            for index in range(self.window.write_method.count())
        )
        self.assertEqual(modes, (WriteMode.DD, WriteMode.EXTRACTED_ISO))
        self.assertEqual(self.window.selected_write_mode(), WriteMode.EXTRACTED_ISO)
        self.assertTrue(self.window.verify.isChecked())
        self.assertFalse(self.window.verify.isEnabled())
        self.assertEqual(self.window.write_button.text(), "Write in ISO mode")
        self.assertTrue(self.window.write_button.isEnabled())

    def test_image_chooser_advertises_raw_aliases_not_structured_apply_formats(self):
        with patch(
            "isopropyl.app.QFileDialog.getOpenFileName", return_value=("", ""),
        ) as chooser:
            self.window.choose_image()

        image_filter = chooser.call_args.args[3]
        for pattern in ("*.img", "*.raw", "*.usb", "*.wic"):
            self.assertIn(pattern, image_filter)
        for pattern in ("*.wim", "*.esd", "*.ffu", "*.vtsi"):
            self.assertNotIn(pattern, image_filter)

    def test_explicit_dd_selection_remains_visible_and_changes_dispatch_label(self):
        self.window.rebuild_write_recommendation(preserve_selection=False)
        self.window.write_method.setCurrentIndex(
            self.window.write_method.findData(WriteMode.DD.value)
        )

        self.assertEqual(self.window.selected_write_mode(), WriteMode.DD)
        self.assertTrue(self.window.verify.isEnabled())
        self.assertEqual(self.window.write_button.text(), "Write in DD mode")

    def test_iso_dispatch_rebuilds_a_fresh_target_sized_plan(self):
        self.window.rebuild_write_recommendation(preserve_selection=False)
        starter = Mock()
        self.window.start_constructed_iso_write = starter

        with (
            patch("isopropyl.app.image_identity", return_value=(1, 2, 3, 4)),
            patch("isopropyl.app.QMessageBox.warning") as warning,
            patch("isopropyl.app.QMessageBox.critical") as critical,
        ):
            self.window.confirm_iso_write(self.window.devices[0])

        warning.assert_not_called()
        critical.assert_not_called()
        starter.assert_called_once()
        entries, plan = starter.call_args.args
        self.assertTrue(entries)
        self.assertEqual(plan.mode, WriteMode.EXTRACTED_ISO)
        self.assertTrue(plan.executable)
        self.assertLessEqual(plan.minimum_target_bytes, self.window.devices[0].size)

    def test_stale_device_refresh_cannot_replace_newer_target_state(self):
        original = self.window.devices[0]
        self.window.device_refresh_generation = 9
        replacement = Device(
            "/dev/sdy", original.size, "Other", "ISOpropyl", "usb", "OTHER",
            "", "65:143", True, True, False, (), (),
        )

        self.window.on_devices_refreshed(8, (replacement,))

        self.assertEqual(self.window.devices, [original])

    def test_current_device_refresh_replaces_targets_and_clears_busy_state(self):
        self.window.device_refresh_generation = 4
        self.window.device_refresh_busy = True
        replacement = Device(
            "/dev/sdy", 16 * 1024**3, "Other", "ISOpropyl", "usb", "OTHER",
            "", "65:143", True, True, False, (), (),
        )

        self.window.on_devices_refreshed(4, (replacement,))

        self.assertEqual(self.window.devices, [replacement])
        self.assertFalse(self.window.device_refresh_busy)
        self.assertTrue(self.window.device_combo.isEnabled())
        self.assertEqual(self.window.selected_device(), replacement)


class WindowPersistenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.settings_home = tempfile.TemporaryDirectory()
        with patch("isopropyl.app.list_devices", return_value=[]):
            self.window = Window()
        self.window.device_refresh_generation += 1
        self.window.device_refresh_busy = False
        self.window.image = Path(self.settings_home.name) / "ubuntu.iso"
        self.window.image.write_bytes(b"fixture")
        self.window.inspection_identity = (1, 2, 3, 4)
        self.window.devices = [device()]
        self.window.device_combo.clear()
        self.window.device_combo.addItem(self.window.devices[0].label)
        self.window.show()
        self.application.processEvents()
        inspection = ubuntu_casper_inspection()
        with patch("isopropyl.app.image_identity", return_value=(1, 2, 3, 4)):
            self.window.on_inspection_finished((1, 2, 3, 4), inspection)
        self.window.write_method.setCurrentIndex(
            self.window.write_method.findData(WriteMode.EXTRACTED_ISO.value)
        )
        self.application.processEvents()
        self.assertIsNotNone(self.window.persistence_profile)

    def tearDown(self) -> None:
        self.window.close()
        self.window.deleteLater()
        self.application.processEvents()
        self.settings_home.cleanup()

    def replace_target(self, size: int) -> Device:
        target = device(size)
        self.window.device_combo.blockSignals(True)
        self.window.devices = [target]
        self.window.device_combo.clear()
        self.window.device_combo.addItem(target.label)
        self.window.device_combo.blockSignals(False)
        self.window.on_device_changed()
        self.application.processEvents()
        return target

    def pending_write(self) -> tuple[PendingIsoWrite, Mock]:
        recommendation = self.window.write_recommendation
        assert recommendation is not None and recommendation.iso_plan is not None
        workspace = Mock()
        pending = PendingIsoWrite(
            image=self.window.image,
            inspection=self.window.inspection,
            device=self.window.devices[0],
            write_plan=recommendation.iso_plan,
            workspace=workspace,
            staging_plan=Mock(),
            persistence_profile=self.window.persistence_profile,
            persistence_bytes=MIN_PERSISTENCE_BYTES,
        )
        return pending, workspace

    def test_detected_profile_controls_are_visible_only_in_iso_mode(self):
        self.assertEqual(
            self.window.persistence_profile,
            supported_casper_profile(ubuntu_casper_inspection()),
        )
        self.assertEqual(self.window.selected_write_mode(), WriteMode.EXTRACTED_ISO)
        self.assertTrue(self.window.persistence_controls.isVisible())

        self.window.persistence_checkbox.setChecked(True)
        self.window.write_method.setCurrentIndex(
            self.window.write_method.findData(WriteMode.DD.value)
        )
        self.assertFalse(self.window.persistence_controls.isVisible())
        self.assertFalse(self.window.persistence_checkbox.isChecked())

        self.window.write_method.setCurrentIndex(
            self.window.write_method.findData(WriteMode.EXTRACTED_ISO.value)
        )
        self.assertTrue(self.window.persistence_controls.isVisible())

        with patch("isopropyl.app.image_identity", return_value=(1, 2, 3, 4)):
            self.window.on_inspection_finished(
                (1, 2, 3, 4), optical_windows_inspection(),
            )
        self.assertIsNone(self.window.persistence_profile)
        self.assertFalse(self.window.persistence_controls.isVisible())

    def test_target_capacity_bounds_and_disables_persistence(self):
        recommendation = self.window.write_recommendation
        assert recommendation is not None and recommendation.iso_plan is not None
        minimum = recommendation.iso_plan.minimum_target_bytes
        too_small = minimum + MIN_PERSISTENCE_BYTES + 2 * ALIGNMENT_BYTES - 1

        self.replace_target(too_small)

        self.assertTrue(self.window.persistence_controls.isVisible())
        self.assertFalse(self.window.persistence_checkbox.isEnabled())
        self.assertFalse(self.window.persistence_checkbox.isChecked())
        self.assertEqual(
            self.window.persistence_slider.maximum(),
            MIN_PERSISTENCE_BYTES // ALIGNMENT_BYTES,
        )

        requested_mib = 512
        self.replace_target(
            minimum + requested_mib * ALIGNMENT_BYTES + 2 * ALIGNMENT_BYTES
        )
        self.assertTrue(self.window.persistence_checkbox.isEnabled())
        self.assertEqual(self.window.persistence_slider.maximum(), requested_mib)

    def test_selected_persistence_size_contributes_to_readiness(self):
        recommendation = self.window.write_recommendation
        assert recommendation is not None and recommendation.iso_plan is not None
        minimum = recommendation.iso_plan.minimum_target_bytes
        self.replace_target(minimum + 514 * ALIGNMENT_BYTES)
        self.window.persistence_slider.setValue(512)
        self.window.persistence_checkbox.setChecked(True)
        selected = 512 * ALIGNMENT_BYTES

        self.assertEqual(self.window.selected_persistence_bytes(), selected)
        self.assertTrue(self.window.write_button.isEnabled())

        # Keep the already-bound plan but make the selected target one byte too
        # small for the extra partition.  update_ready must include the slider.
        self.window.devices[0] = device(minimum + selected - 1)
        self.window.update_ready()
        self.assertFalse(self.window.write_button.isEnabled())
        self.assertIn("too small", self.window.status.text())

        self.window.persistence_checkbox.setChecked(False)
        self.assertEqual(self.window.selected_persistence_bytes(), 0)
        self.assertTrue(self.window.write_button.isEnabled())

    def test_preconsent_casper_probe_dispatches_fresh_sector_size(self):
        pending, workspace = self.pending_write()
        confirmer = Mock()
        self.window.confirm_and_start_iso_write = confirmer

        with (
            patch("isopropyl.app.threading.Thread", ImmediateThread),
            patch(
                "isopropyl.app.probe_casper_logical_sector_size",
                return_value=4096,
            ) as probe,
        ):
            self.window.start_casper_preparation(pending)

        probe.assert_called_once_with(pending.device)
        confirmer.assert_called_once_with(pending, None, 4096)
        workspace.cleanup.assert_not_called()
        self.assertIsNone(self.window.pending_iso_write)
        self.assertIsNone(self.window.casper_preparer)

    def test_preconsent_casper_probe_cancellation_discards_workspace(self):
        pending, workspace = self.pending_write()
        confirmer = Mock()
        self.window.confirm_and_start_iso_write = confirmer

        def cancel_during_probe(_target: Device) -> int:
            assert self.window.casper_preparer is not None
            self.window.casper_preparer.cancel()
            return 512

        with (
            patch("isopropyl.app.threading.Thread", ImmediateThread),
            patch(
                "isopropyl.app.probe_casper_logical_sector_size",
                side_effect=cancel_during_probe,
            ),
            patch("isopropyl.app.QMessageBox.warning") as warning,
        ):
            self.window.start_casper_preparation(pending)

        workspace.cleanup.assert_called_once_with()
        confirmer.assert_not_called()
        warning.assert_not_called()
        self.assertIn("cancelled", self.window.status.text().casefold())
        self.assertFalse(self.window.operation_active)

    def test_preconsent_casper_probe_rejects_invalid_sector_result(self):
        pending, workspace = self.pending_write()
        confirmer = Mock()
        self.window.confirm_and_start_iso_write = confirmer

        with (
            patch("isopropyl.app.threading.Thread", ImmediateThread),
            patch(
                "isopropyl.app.probe_casper_logical_sector_size",
                return_value=2048,
            ),
            patch("isopropyl.app.QMessageBox.warning") as warning,
        ):
            self.window.start_casper_preparation(pending)

        workspace.cleanup.assert_called_once_with()
        confirmer.assert_not_called()
        warning.assert_called_once()
        self.assertIn("unsupported logical sector size", warning.call_args.args[2])
        self.assertFalse(self.window.operation_active)

    def test_constructed_iso_dispatch_snapshots_persistence_request(self):
        self.window.persistence_slider.setValue(
            MIN_PERSISTENCE_BYTES // ALIGNMENT_BYTES
        )
        self.window.persistence_checkbox.setChecked(True)
        recommendation = self.window.write_recommendation
        assert recommendation is not None and recommendation.iso_plan is not None
        workspace = Mock()
        workspace.name = str(Path(self.settings_home.name) / "private-workspace")
        staging_plan = Mock()
        starter = Mock()
        self.window.start_casper_preparation = starter

        with (
            patch("isopropyl.app.image_is_on_device", return_value=False),
            patch(
                "isopropyl.app.QFileDialog.getExistingDirectory",
                return_value=self.settings_home.name,
            ),
            patch("isopropyl.app.tempfile.TemporaryDirectory", return_value=workspace),
            patch("isopropyl.app.build_iso_staging_plan", return_value=staging_plan),
            patch("isopropyl.app.QMessageBox.warning") as warning,
        ):
            self.window.start_constructed_iso_write(
                list(self.window.archive_entries()), recommendation.iso_plan,
            )

        warning.assert_not_called()
        starter.assert_called_once()
        pending = starter.call_args.args[0]
        self.assertIsInstance(pending, PendingIsoWrite)
        self.assertEqual(pending.image, self.window.image)
        self.assertEqual(pending.inspection, self.window.inspection)
        self.assertEqual(pending.device, self.window.devices[0])
        self.assertIs(pending.write_plan, recommendation.iso_plan)
        self.assertIs(pending.workspace, workspace)
        self.assertIs(pending.staging_plan, staging_plan)
        self.assertEqual(pending.persistence_profile, self.window.persistence_profile)
        self.assertEqual(pending.persistence_bytes, MIN_PERSISTENCE_BYTES)


if __name__ == "__main__":
    unittest.main()
