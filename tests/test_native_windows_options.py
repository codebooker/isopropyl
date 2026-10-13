# SPDX-License-Identifier: AGPL-3.0-or-later
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication

from isopropyl.mac_windows_iso import WindowsSourceMetadata
from isopropyl.native_windows_options import WindowsOptionsDialog
from isopropyl.native_writer import file_identity
from isopropyl.wim import WimEdition, WimSelection
from isopropyl.windows import WindowsCustomization
from isopropyl.windows_bootex import WindowsBootExOptions


class NativeWindowsOptionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name) / "installer.iso"
        self.source.write_bytes(bytes(512))
        self.edition = WimEdition(
            1, "Windows 11 Pro", "Pro", "Professional", "amd64", 10, 0, 26100, 1
        )
        self.metadata = WindowsSourceMetadata(
            file_identity(self.source.stat()),
            "amd64",
            "sources/install.wim",
            4096,
            (self.edition,),
            "a" * 64,
            False,
        )
        with patch("isopropyl.native_windows_options.QTimer.singleShot"):
            self.dialog = WindowsOptionsDialog(
                self.source, WindowsCustomization(), WindowsBootExOptions()
            )
        self.addCleanup(self.dialog.close)
        self.dialog.inspected(self.metadata, "")

    def test_supported_options_require_selection_and_acknowledgment(self):
        control = self.dialog.controls["bypass_online_account_requirement"]
        self.assertFalse(control.isEnabled())
        self.dialog.edition.setCurrentIndex(1)
        self.assertTrue(control.isEnabled())
        control.setChecked(True)
        with self.assertRaisesRegex(ValueError, "Acknowledge"):
            self.dialog.xml()
        self.dialog.controls["acknowledge_online_account_limitations"].setChecked(True)
        self.assertIn("BypassNRO", self.dialog.xml())
        self.assertFalse(
            self.dialog.controls["apply_secure_boot_revocation_policy"].isEnabled()
        )
        self.assertFalse(self.dialog.bootex_check.isEnabled())

    def test_settings_and_region_reach_shared_answer_file(self):
        self.dialog.controls["bypass_hardware_requirements"].setChecked(True)
        self.dialog.controls["disable_fast_startup"].setChecked(True)
        self.dialog.controls["system_locale"].setText("en-US")
        self.dialog.username.setText("installer")
        xml = self.dialog.xml()
        for value in ["BypassTPMCheck", "HiberbootEnabled", "en-US", "installer"]:
            self.assertIn(value, xml)
        self.dialog.save()
        self.assertTrue(self.dialog.options.enabled)
        self.assertEqual(self.dialog.options.local_username, "installer")

    def test_source_change_blocks_saving_inspected_settings(self):
        self.source.write_bytes(b"changed")
        with patch("isopropyl.native_windows_options.QMessageBox.warning") as warning:
            self.dialog.save()
        warning.assert_called_once()
        self.assertFalse(self.dialog.options.enabled)

    def test_reopening_preserves_compatible_settings_and_acknowledgments(self):
        options = WindowsCustomization(
            install_image=WimSelection('sources/install.wim',4096,(self.edition,),1),
            bypass_online_account_requirement=True,
            acknowledge_online_account_limitations=True,
            quality_of_life=True,acknowledge_quality_of_life_limitations=True)
        with patch('isopropyl.native_windows_options.QTimer.singleShot'):
            reopened = WindowsOptionsDialog(self.source,options,WindowsBootExOptions())
        try:
            reopened.inspected(self.metadata,'')
            self.assertEqual(reopened.selected(),options)
            self.assertIn('BypassNRO',reopened.xml())
        finally:
            reopened.close()

    def test_source_combo_changes_bound_member_and_emits_nested_setup_path(self):
        from dataclasses import replace
        from isopropyl.mac_windows_iso import WindowsInstallCandidate
        candidates=(WindowsInstallCandidate('sources/install.wim',4096),WindowsInstallCandidate('alternate/sources/install.wim',2048))
        initial=replace(self.metadata,install_candidates=candidates,install_source_count=2)
        alternate=replace(initial,install_path=candidates[1].path,install_size=2048)
        self.dialog.inspected(initial,'')
        self.dialog.metadata_cache[alternate.install_path]=alternate
        self.dialog.source_combo.setCurrentIndex(1)
        self.assertEqual(self.dialog.metadata.install_path,alternate.install_path)
        self.dialog.edition.setCurrentIndex(1)
        options=self.dialog.selected()
        self.assertEqual(options.install_image.source_name,alternate.install_path)
        self.assertEqual(options.install_image.source_size,2048)
        self.assertEqual(options.install_image_path,alternate.install_path)
        self.assertIn('alternate\\sources\\install.wim',self.dialog.xml())
        self.dialog.source_combo.setCurrentIndex(0)
        self.dialog.edition.setCurrentIndex(1)
        self.assertEqual(self.dialog.selected().install_image_path,'sources/install.wim')

    def test_reopening_preserves_nested_source_selection(self):
        from dataclasses import replace
        from isopropyl.mac_windows_iso import WindowsInstallCandidate
        candidates=(WindowsInstallCandidate('sources/install.wim',4096),WindowsInstallCandidate('nested/sources/install.wim',2048))
        metadata=replace(self.metadata,install_path=candidates[1].path,install_size=2048,install_candidates=candidates,install_source_count=2)
        selection=WimSelection(metadata.install_path,metadata.install_size,metadata.editions,1)
        options=WindowsCustomization(install_image=selection,install_image_path=metadata.install_path)
        with patch('isopropyl.native_windows_options.QTimer.singleShot'):
            dialog=WindowsOptionsDialog(self.source,options,WindowsBootExOptions())
        try:
            dialog.inspected(metadata,'')
            self.assertEqual(dialog.source_combo.currentData(),metadata.install_path)
            self.assertEqual(dialog.selected(),options)
        finally:dialog.close()
