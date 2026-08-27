from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

from isopropyl.app import Window
from isopropyl.devices import Device
from isopropyl.images import ImageInspection, ImageMember
from isopropyl.iso import WriteMode
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


class WindowWriteMethodTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.settings_home = tempfile.TemporaryDirectory()
        with patch("isopropyl.app.list_devices", return_value=[]):
            self.window = Window()
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


if __name__ == "__main__":
    unittest.main()
