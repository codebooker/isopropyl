from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QMessageBox,
    QLabel, QPlainTextEdit, QPushButton,
)

from isopropyl.app import (
    BackgroundPreparation, ChecksumToken, PendingIsoWrite, Window,
    WindowsMetadataToken,
)
from isopropyl.backup import VHD_MAX_SIZE
from isopropyl.bootloaders import (
    BootloaderCacheDeletionResult, BootloaderCacheInventory, CacheDeletion,
    CachedBootloaderArtifact,
)
from isopropyl.casper_media import supported_casper_profile
from isopropyl.devices import Device, SizeUnitMode
from isopropyl.formatting import (
    Filesystem as FormatFilesystem, PartitionTable as FormatPartitionTable,
)
from isopropyl.images import ChecksumCancelled, ImageInspection, ImageMember
from isopropyl.iso import ArchiveEntry, WriteMode
from isopropyl.extraction import SafeIsoExtractor
from isopropyl.persistence import ALIGNMENT_BYTES, MIN_PERSISTENCE_BYTES
from isopropyl.uefi import ImageUefiPayload, SbatState, SignatureTableState
from isopropyl.wim import WimEdition, WimInfo, WimSelection
from isopropyl.windows import WindowsCustomization


def device(size: int = 8 * 1024**3) -> Device:
    return Device(
        "/dev/sdz", size, "Test Drive", "ISOpropyl", "usb", "SERIAL",
        "", "65:144", True, True, False, (), (), 512,
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
        self.settings_home = tempfile.TemporaryDirectory()
        settings = QSettings(
            str(Path(self.settings_home.name) / "settings.ini"),
            QSettings.Format.IniFormat,
        )
        with (
            patch("isopropyl.app.QSettings", return_value=settings),
            patch("isopropyl.app.list_devices", return_value=[]),
        ):
            self.window = Window()
        self.window.size_unit_mode = SizeUnitMode.SI
        self.window.device_refresh_generation += 1
        self.window.device_refresh_busy = False
        self.window.devices = [device()]
        self.window.device_combo.clear()
        self.window.device_combo.addItem(self.window.devices[0].label)

    def tearDown(self) -> None:
        self.window.close()
        self.window.deleteLater()
        self.application.processEvents()
        self.settings_home.cleanup()

    def test_restore_selector_filters_by_capacity_and_keeps_safe_defaults(self):
        observed = []
        defaults = []
        notes = []

        def inspect_dialog(dialog) -> int:
            combo = next(
                candidate for candidate in dialog.findChildren(QComboBox)
                if any(
                    candidate.itemData(index) is FormatFilesystem.EXT2
                    for index in range(candidate.count())
                )
            )
            observed.extend(combo.itemData(index) for index in range(combo.count()))
            tables = next(
                candidate for candidate in dialog.findChildren(QComboBox)
                if candidate.findData(FormatPartitionTable.MBR) >= 0
            )
            defaults.extend((combo.currentData(), tables.currentData()))
            notes.extend(label.text() for label in dialog.findChildren(QLabel))
            return QDialog.DialogCode.Rejected

        with patch("isopropyl.app.QDialog.exec", new=inspect_dialog):
            self.window.format_drive()
        self.assertEqual(
            observed,
            [
                FormatFilesystem.FAT32, FormatFilesystem.EXFAT,
                FormatFilesystem.NTFS, FormatFilesystem.UDF,
                FormatFilesystem.EXT2, FormatFilesystem.EXT3,
                FormatFilesystem.EXT4,
            ],
        )
        self.assertEqual(
            defaults,
            [FormatFilesystem.FAT32, FormatPartitionTable.MBR],
        )
        self.assertIn("not mounted automatically by macOS", " ".join(notes))

    def test_restore_capacity_envelopes_hide_only_incompatible_formats(self):
        cases = (
            (64 * 1024**2, {FormatFilesystem.FAT12}, {FormatFilesystem.FAT16}),
            (
                200 * 1024**2,
                {FormatFilesystem.FAT12, FormatFilesystem.FAT16},
                set(),
            ),
            (
                3 * 1024**4,
                set(),
                {FormatFilesystem.FAT32, FormatFilesystem.UDF},
            ),
        )
        for size, present, absent in cases:
            with self.subTest(size=size):
                self.window.devices = [device(size)]
                observed = set()

                def inspect_dialog(dialog) -> int:
                    combo = next(
                        candidate for candidate in dialog.findChildren(QComboBox)
                        if candidate.findData(FormatFilesystem.EXT4) >= 0
                    )
                    observed.update(
                        combo.itemData(index) for index in range(combo.count())
                    )
                    return QDialog.DialogCode.Rejected

                with patch("isopropyl.app.QDialog.exec", new=inspect_dialog):
                    self.window.format_drive()
                self.assertTrue(present <= observed)
                self.assertFalse(absent & observed)

    def test_restore_selector_filters_known_sector_and_formatter_dead_ends(self):
        cases = (
            (
                replace(device(200 * 1024**2), logical_sector_size=1024),
                {FormatFilesystem.FAT32, FormatFilesystem.EXT4},
                {FormatFilesystem.FAT12, FormatFilesystem.FAT16},
            ),
            (
                replace(device(64 * 1024**2), logical_sector_size=4096),
                {FormatFilesystem.FAT12, FormatFilesystem.EXT4},
                {FormatFilesystem.FAT16, FormatFilesystem.FAT32},
            ),
            (
                replace(device(20 * 1024**4), logical_sector_size=512),
                {FormatFilesystem.EXT4},
                {
                    FormatFilesystem.FAT32,
                    FormatFilesystem.UDF,
                    FormatFilesystem.EXT2,
                    FormatFilesystem.EXT3,
                },
            ),
        )
        for target, present, absent in cases:
            with self.subTest(size=target.size, sector=target.logical_sector_size):
                self.window.devices = [target]
                observed = set()

                def inspect_dialog(dialog) -> int:
                    combo = dialog.findChild(QComboBox, "restoreFilesystem")
                    self.assertIsNotNone(combo)
                    observed.update(
                        combo.itemData(index) for index in range(combo.count())
                    )
                    return QDialog.DialogCode.Rejected

                with patch("isopropyl.app.QDialog.exec", new=inspect_dialog):
                    self.window.format_drive()
                self.assertTrue(present <= observed)
                self.assertFalse(absent & observed)

    def test_restore_selector_disables_review_when_sector_is_unsupported(self):
        self.window.devices = [
            replace(device(), logical_sector_size=8192),
        ]
        observed = {}

        def inspect_dialog(dialog) -> int:
            filesystem = dialog.findChild(QComboBox, "restoreFilesystem")
            buttons = dialog.findChild(QDialogButtonBox)
            self.assertIsNotNone(filesystem)
            self.assertIsNotNone(buttons)
            observed["count"] = filesystem.count()
            observed["review"] = buttons.button(
                QDialogButtonBox.StandardButton.Ok
            ).isEnabled()
            observed["text"] = " ".join(
                label.text() for label in dialog.findChildren(QLabel)
            )
            return QDialog.DialogCode.Rejected

        with patch("isopropyl.app.QDialog.exec", new=inspect_dialog):
            self.window.format_drive()

        self.assertEqual(observed["count"], 0)
        self.assertFalse(observed["review"])
        self.assertIn("will not repartition", observed["text"])

    def test_restore_selector_refilters_when_partition_table_changes(self):
        self.window.devices = [
            replace(device(36_170_240), logical_sector_size=512),
        ]
        observed: dict[str, object] = {}

        def inspect_dialog(dialog) -> int:
            filesystem = dialog.findChild(QComboBox, "restoreFilesystem")
            table = dialog.findChild(QComboBox, "restorePartitionTable")
            buttons = dialog.findChild(QDialogButtonBox)
            self.assertIsNotNone(filesystem)
            self.assertIsNotNone(table)
            self.assertIsNotNone(buttons)
            observed["mbr_fat32"] = filesystem.findData(
                FormatFilesystem.FAT32,
            ) >= 0
            table.setCurrentIndex(table.findData(FormatPartitionTable.GPT))
            observed["gpt_fat32"] = filesystem.findData(
                FormatFilesystem.FAT32,
            ) >= 0
            observed["selected"] = filesystem.currentData()
            observed["review"] = buttons.button(
                QDialogButtonBox.StandardButton.Ok,
            ).isEnabled()
            return QDialog.DialogCode.Rejected

        with patch("isopropyl.app.QDialog.exec", new=inspect_dialog):
            self.window.format_drive()

        self.assertTrue(observed["mbr_fat32"])
        self.assertFalse(observed["gpt_fat32"])
        self.assertIsNot(observed["selected"], FormatFilesystem.FAT32)
        self.assertTrue(observed["review"])

    def test_restore_selector_defaults_to_gpt_beyond_mbr_addressability(self):
        self.window.devices = [
            replace(device(3 * 1024**4), logical_sector_size=512),
        ]
        observed: dict[str, object] = {}

        def inspect_dialog(dialog) -> int:
            filesystem = dialog.findChild(QComboBox, "restoreFilesystem")
            table = dialog.findChild(QComboBox, "restorePartitionTable")
            buttons = dialog.findChild(QDialogButtonBox)
            observed["table"] = table.currentData()
            observed["filesystems"] = filesystem.count()
            observed["review"] = buttons.button(
                QDialogButtonBox.StandardButton.Ok,
            ).isEnabled()
            return QDialog.DialogCode.Rejected

        with patch("isopropyl.app.QDialog.exec", new=inspect_dialog):
            self.window.format_drive()

        self.assertIs(observed["table"], FormatPartitionTable.GPT)
        self.assertGreater(observed["filesystems"], 0)
        self.assertTrue(observed["review"])

    def test_restore_selector_filters_and_labels_allocation_units(self):
        observed: dict[str, object] = {}

        def inspect_dialog(dialog) -> int:
            combos = dialog.findChildren(QComboBox)
            filesystem = next(
                candidate for candidate in combos
                if candidate.findData(FormatFilesystem.EXT4) >= 0
            )
            allocation = next(
                candidate for candidate in combos
                if any(
                    isinstance(candidate.itemData(index), int)
                    and not isinstance(candidate.itemData(index), bool)
                    for index in range(candidate.count())
                )
            )

            filesystem.setCurrentIndex(filesystem.findData(FormatFilesystem.NTFS))
            observed["ntfs"] = tuple(
                allocation.itemData(index) for index in range(allocation.count())
            )
            observed["ntfs_note"] = " ".join(
                label.text() for label in dialog.findChildren(QLabel)
            )

            filesystem.setCurrentIndex(filesystem.findData(FormatFilesystem.UDF))
            observed["udf"] = tuple(
                allocation.itemData(index) for index in range(allocation.count())
            )
            observed["udf_enabled"] = allocation.isEnabled()

            filesystem.setCurrentIndex(filesystem.findData(FormatFilesystem.EXT4))
            observed["ext"] = tuple(
                allocation.itemData(index) for index in range(allocation.count())
            )
            observed["labels"] = tuple(
                label.text() for label in dialog.findChildren(QLabel)
            )
            return QDialog.DialogCode.Rejected

        with patch("isopropyl.app.QDialog.exec", new=inspect_dialog):
            self.window.format_drive()

        self.assertEqual(observed["ntfs"][0], None)
        self.assertIn(4096, observed["ntfs"])
        self.assertIn(65536, observed["ntfs"])
        self.assertIn(2 * 1024**2, observed["ntfs"])
        self.assertIn("above 64 KiB", observed["ntfs_note"])
        self.assertEqual(observed["udf"], (None,))
        self.assertFalse(observed["udf_enabled"])
        self.assertEqual(observed["ext"], (None, 1024, 2048, 4096))
        self.assertIn("Filesystem block size", observed["labels"])


class BootloaderCacheDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.settings_home = tempfile.TemporaryDirectory()
        settings = QSettings(
            str(Path(self.settings_home.name) / "settings.ini"),
            QSettings.Format.IniFormat,
        )
        with (
            patch("isopropyl.app.QSettings", return_value=settings),
            patch("isopropyl.app.list_devices", return_value=[]),
        ):
            self.window = Window()
        self.window.device_refresh_generation += 1
        self.window.device_refresh_busy = False

    def tearDown(self) -> None:
        self.window.close()
        self.window.deleteLater()
        self.application.processEvents()
        self.settings_home.cleanup()

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
        settings = QSettings(
            str(Path(self.settings_home.name) / "settings.ini"),
            QSettings.Format.IniFormat,
        )
        with (
            patch("isopropyl.app.QSettings", return_value=settings),
            patch("isopropyl.app.list_devices", return_value=[]),
        ):
            self.window = Window()
        self.window.size_unit_mode = SizeUnitMode.SI
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

    def test_image_inspection_oserror_leaves_the_window_ready(self):
        failed_image = Path(self.settings_home.name) / "unreadable.iso"
        failed_image.write_bytes(b"fixture")

        with (
            patch(
                "isopropyl.app.inspect_image",
                side_effect=OSError("fixture inspection failure"),
            ),
            patch("isopropyl.app.threading.Thread", ImmediateThread),
            patch.object(self.window.logger, "warning") as warning,
        ):
            self.window.load_image(failed_image)

        self.assertIsNone(self.window.inspection)
        self.assertIsNone(self.window.inspection_identity)
        self.assertFalse(self.window.write_method.isEnabled())
        self.assertEqual(
            self.window.write_method_reason.text(),
            "Image inspection did not complete.",
        )
        self.assertIn("fixture inspection failure", self.window.image_detail.text())
        warning.assert_called_once()

    def test_stale_inspection_generation_cannot_replace_current_state(self):
        current = self.window.inspection
        self.window.inspection_generation = 3
        status = self.window.image.stat()
        identity = (
            status.st_dev, status.st_ino, status.st_size,
            status.st_mtime_ns, status.st_ctime_ns,
        )

        self.window.on_inspection_finished(
            identity, optical_windows_inspection(hybrid=True), 2,
        )

        self.assertIs(self.window.inspection, current)

    def test_selecting_an_image_cancels_the_previous_inspection(self):
        image = Path(self.settings_home.name) / "replacement.iso"
        image.write_bytes(b"fixture")
        previous = self.window.inspection_cancel_event

        class DeferredThread:
            def __init__(self, *, target, daemon=False):
                self.target = target

            def start(self):
                pass

        with patch("isopropyl.app.threading.Thread", DeferredThread):
            self.window.load_image(image)

        self.assertTrue(previous.is_set())
        self.assertFalse(self.window.inspection_cancel_event.is_set())
        self.assertTrue(self.window.inspection_busy)

        self.window.cancel()

        self.assertTrue(self.window.inspection_cancel_event.is_set())
        self.assertFalse(self.window.inspection_busy)
        self.assertEqual(self.window.image_detail.text(), "Image inspection cancelled")

    def test_selecting_an_image_cancels_and_invalidates_checksum_worker(self):
        image = Path(self.settings_home.name) / "replacement.iso"
        image.write_bytes(b"fixture")
        operation = BackgroundPreparation()
        self.window.checksum_preparer = operation
        self.window.checksum_generation = 4
        self.window.checksum_busy = True

        class DeferredThread:
            def __init__(self, *, target, daemon=False):
                self.target = target

            def start(self):
                pass

        with patch("isopropyl.app.threading.Thread", DeferredThread):
            self.window.load_image(image)

        self.assertTrue(operation.cancelled)
        self.assertIsNone(self.window.checksum_preparer)
        self.assertEqual(self.window.checksum_generation, 5)
        self.assertFalse(self.window.checksum_busy)

    def test_stale_checksum_completion_cannot_clear_a_newer_operation(self):
        old = BackgroundPreparation()
        current = BackgroundPreparation()
        self.window.checksum_generation = 2
        self.window.checksum_preparer = current
        self.window.checksum_busy = True
        token = ChecksumToken(1, self.window.inspection_identity, old)

        with patch("isopropyl.app.QMessageBox.critical") as critical:
            self.window.on_checksums_finished(token, RuntimeError("stale fixture"))

        self.assertIs(self.window.checksum_preparer, current)
        self.assertTrue(self.window.checksum_busy)
        critical.assert_not_called()
        self.window.checksum_preparer = None
        self.window.checksum_busy = False

    def test_wrong_checksum_generation_cannot_clear_current_operation(self):
        current = BackgroundPreparation()
        self.window.checksum_generation = 2
        self.window.checksum_preparer = current
        self.window.checksum_busy = True
        token = ChecksumToken(1, self.window.inspection_identity, current)

        self.window.on_checksums_finished(token, RuntimeError("stale fixture"))

        self.assertIs(self.window.checksum_preparer, current)
        self.assertTrue(self.window.checksum_busy)
        self.window.checksum_preparer = None
        self.window.checksum_busy = False

    def test_stale_checksum_progress_cannot_replace_current_status(self):
        old = BackgroundPreparation()
        current = BackgroundPreparation()
        self.window.checksum_generation = 2
        self.window.checksum_preparer = current
        self.window.status.setText("Current operation")
        self.window.progress.setValue(321)
        token = ChecksumToken(1, self.window.inspection_identity, old)

        self.window.on_checksum_progress(token, 8, 16)

        self.assertEqual(self.window.status.text(), "Current operation")
        self.assertEqual(self.window.progress.value(), 321)
        self.window.checksum_preparer = None

    def test_checksum_cancellation_clears_worker_without_error_dialog(self):
        status = self.window.image.stat()
        identity = (
            status.st_dev, status.st_ino, status.st_size,
            status.st_mtime_ns, status.st_ctime_ns,
        )
        operation = BackgroundPreparation()
        self.window.inspection_identity = identity
        self.window.checksum_generation = 1
        self.window.checksum_preparer = operation
        self.window.checksum_busy = True
        token = ChecksumToken(1, identity, operation)

        with (
            patch("isopropyl.app.QMessageBox.critical") as critical,
            patch("isopropyl.app.QDialog.exec") as dialog,
        ):
            self.window.on_checksums_finished(
                token, ChecksumCancelled("cancelled fixture"),
            )

        self.assertIsNone(self.window.checksum_preparer)
        self.assertFalse(self.window.checksum_busy)
        self.assertIn("cancelled", self.window.status.text().casefold())
        critical.assert_not_called()
        dialog.assert_not_called()

    def test_late_checksum_cancellation_suppresses_success_dialog(self):
        status = self.window.image.stat()
        identity = (
            status.st_dev, status.st_ino, status.st_size,
            status.st_mtime_ns, status.st_ctime_ns,
        )
        operation = BackgroundPreparation()
        operation.cancel()
        self.window.inspection_identity = identity
        self.window.checksum_generation = 1
        self.window.checksum_preparer = operation
        self.window.checksum_busy = True
        token = ChecksumToken(1, identity, operation)
        result = {
            "MD5": "1" * 32,
            "SHA-1": "2" * 40,
            "SHA-256": "3" * 64,
            "SHA-512": "4" * 128,
        }

        with (
            patch("isopropyl.app.QMessageBox.critical") as critical,
            patch("isopropyl.app.QDialog.exec") as dialog,
        ):
            self.window.on_checksums_finished(token, result)

        self.assertIsNone(self.window.checksum_preparer)
        self.assertFalse(self.window.checksum_busy)
        self.assertIn("cancelled", self.window.status.text().casefold())
        critical.assert_not_called()
        dialog.assert_not_called()

    def test_cancel_stops_active_checksum_worker(self):
        operation = BackgroundPreparation()
        self.window.checksum_preparer = operation
        self.window.checksum_busy = True

        self.window.cancel()

        self.assertTrue(operation.cancelled)
        self.assertEqual(self.window.status.text(), "Stopping…")
        self.window.checksum_preparer = None
        self.window.checksum_busy = False

    def test_checksum_worker_is_bound_to_inspected_identity(self):
        status = self.window.image.stat()
        identity = (
            status.st_dev, status.st_ino, status.st_size,
            status.st_mtime_ns, status.st_ctime_ns,
        )
        self.window.inspection_identity = identity
        result = {
            "MD5": "1" * 32,
            "SHA-1": "2" * 40,
            "SHA-256": "3" * 64,
            "SHA-512": "4" * 128,
        }

        with (
            patch("isopropyl.app.threading.Thread", ImmediateThread),
            patch(
                "isopropyl.app.calculate_checksums", return_value=result,
            ) as calculate,
            patch(
                "isopropyl.app.QDialog.exec",
                return_value=QDialog.DialogCode.Rejected,
            ),
        ):
            self.window.calculate_image_checksums()

        calculate.assert_called_once()
        self.assertEqual(calculate.call_args.args[0], self.window.image)
        self.assertTrue(callable(calculate.call_args.args[1]))
        self.assertEqual(calculate.call_args.kwargs["expected_identity"], identity)
        self.assertTrue(callable(calculate.call_args.kwargs["cancel_check"]))
        self.assertIsNone(self.window.checksum_preparer)
        self.assertFalse(self.window.checksum_busy)

    def test_image_tooltip_surfaces_partition_structure_and_issues(self):
        inspection = replace(
            optical_windows_inspection(hybrid=True),
            partition_table_valid=False,
            partition_table_kind="malformed",
            partition_table_issues=("primary: GPT header CRC32 is invalid.",),
            mbr_kind="protective",
            mbr_boot_code="grub",
        )

        with patch("isopropyl.app.image_identity", return_value=(1, 2, 3, 4)):
            self.window.on_inspection_finished((1, 2, 3, 4), inspection)

        tooltip = self.window.image_detail.toolTip()
        self.assertIn("Partition structure: Malformed", tooltip)
        self.assertIn("MBR boot code: GRUB", tooltip)
        self.assertIn("primary: GPT header CRC32 is invalid.", tooltip)

    def test_image_tooltip_marks_plain_mbr_sector_size_as_assumed(self):
        inspection = replace(
            optical_windows_inspection(hybrid=True),
            partition_table_valid=True,
            partition_table_kind="mbr",
            partition_table_sector_size=512,
            mbr_kind="mbr",
            mbr_boot_code="syslinux",
        )

        with patch("isopropyl.app.image_identity", return_value=(1, 2, 3, 4)):
            self.window.on_inspection_finished((1, 2, 3, 4), inspection)

        tooltip = self.window.image_detail.toolTip()
        self.assertIn("MBR · valid · 512-byte sectors assumed", tooltip)
        self.assertIn("MBR boot code: Syslinux", tooltip)

    def test_image_tooltip_reports_exact_cataloged_syslinux_bundle(self):
        inspection = replace(
            optical_windows_inspection(hybrid=True),
            bootloader="Syslinux/Isolinux",
            bootloader_version="6.04",
            bootloader_build="6.04-pre1",
            bootloader_dependency="syslinux:6.04-pre1",
        )

        with patch("isopropyl.app.image_identity", return_value=(1, 2, 3, 4)):
            self.window.on_inspection_finished((1, 2, 3, 4), inspection)

        tooltip = self.window.image_detail.toolTip()
        self.assertIn("Exact boot payload: 6.04-pre1", tooltip)
        self.assertIn("hash-pinned matching payload bundle is cataloged", tooltip)
        self.assertIn("BIOS installation remains disabled", tooltip)

    def test_multi_source_windows_iso_requires_an_explicit_source_choice(self):
        inspection = replace(
            optical_windows_inspection(),
            members=(
                ImageMember("EFI/BOOT/BOOTX64.EFI", 8, "file"),
                ImageMember("x64/sources/install.wim", 16, "file"),
                ImageMember("x86/sources/install.wim", 12, "file"),
            ),
        )
        with patch("isopropyl.app.image_identity", return_value=(1, 2, 3, 4)):
            self.window.on_inspection_finished((1, 2, 3, 4), inspection)

        self.assertEqual(
            tuple(item.path for item in self.window.windows_wim_candidates),
            ("x64/sources/install.wim", "x86/sources/install.wim"),
        )
        self.assertIsNone(self.window.windows_wim_member)
        self.assertIn("Choose one of 2", self.window.windows_button.toolTip())

        def choose_second_source(dialog) -> int:
            source = dialog.findChild(QComboBox, "windowsSourceCombo")
            self.assertIsNotNone(source)
            assert source is not None
            source.setCurrentIndex(source.findData("x86/sources/install.wim"))
            buttons = dialog.findChildren(QDialogButtonBox)
            buttons[-1].button(QDialogButtonBox.StandardButton.Save).click()
            return QDialog.DialogCode.Accepted

        with patch("isopropyl.app.QDialog.exec", new=choose_second_source):
            self.window.configure_windows()
        self.assertEqual(
            self.window.windows_wim_member,
            ArchiveEntry("x86/sources/install.wim", 12),
        )

    def test_canonical_wim_path_binding_tracks_whether_source_is_sole(self):
        source = ArchiveEntry("sources/install.wim", 16)
        edition = WimEdition(
            1, "Windows 11 Pro", "", "Professional", "amd64",
            10, 0, 26100, 0,
        )
        self.window.windows_wim_candidates = (source,)
        self.window.windows_install_source_count = 1
        self.window.windows_wim_member = source
        self.window.windows_wim_editions = (edition,)

        def choose_edition(dialog) -> int:
            combo = dialog.findChild(QComboBox, "windowsEditionCombo")
            assert combo is not None
            combo.setCurrentIndex(combo.findData(edition.index))
            buttons = dialog.findChildren(QDialogButtonBox)
            buttons[-1].button(QDialogButtonBox.StandardButton.Save).click()
            return QDialog.DialogCode.Accepted

        with patch("isopropyl.app.QDialog.exec", new=choose_edition):
            self.window.configure_windows()
        self.assertIsNotNone(self.window.windows_options.install_image)
        self.assertEqual(self.window.windows_options.install_image_path, "")

        self.window.windows_install_source_count = 2
        with patch("isopropyl.app.QDialog.exec", new=choose_edition):
            self.window.configure_windows()
        self.assertEqual(
            self.window.windows_options.install_image_path, source.path,
        )

    def test_online_account_bypass_requires_and_persists_compatible_edition(self):
        source = ArchiveEntry("sources/install.wim", 16)
        edition = WimEdition(
            1, "Windows 11 Pro", "", "Professional", "amd64",
            10, 0, 26100, 0,
        )
        self.window.windows_wim_candidates = (source,)
        self.window.windows_install_source_count = 1
        self.window.windows_wim_member = source
        self.window.windows_wim_editions = (edition,)

        def enable_and_save(dialog) -> int:
            checkbox = dialog.findChild(
                QCheckBox, "windowsBypassOnlineRequirementCheckBox",
            )
            acknowledgment = dialog.findChild(
                QCheckBox, "windowsBypassOnlineRequirementAcknowledgment",
            )
            combo = dialog.findChild(QComboBox, "windowsEditionCombo")
            assert checkbox is not None and acknowledgment is not None
            assert combo is not None
            self.assertFalse(checkbox.isEnabled())
            self.assertFalse(acknowledgment.isEnabled())
            combo.setCurrentIndex(combo.findData(edition.index))
            self.assertTrue(checkbox.isEnabled())
            self.assertIn("BypassNRO", checkbox.toolTip())
            checkbox.setChecked(True)
            self.assertTrue(acknowledgment.isEnabled())
            acknowledgment.setChecked(True)
            buttons = dialog.findChildren(QDialogButtonBox)
            buttons[-1].button(QDialogButtonBox.StandardButton.Save).click()
            return QDialog.DialogCode.Accepted

        with patch("isopropyl.app.QDialog.exec", new=enable_and_save):
            self.window.configure_windows()

        self.assertTrue(
            self.window.windows_options.bypass_online_account_requirement,
        )
        self.assertTrue(
            self.window.windows_options.acknowledge_online_account_limitations,
        )
        self.assertEqual(self.window.windows_options.install_image.edition, edition)

        def verify_reopened(dialog) -> int:
            checkbox = dialog.findChild(
                QCheckBox, "windowsBypassOnlineRequirementCheckBox",
            )
            acknowledgment = dialog.findChild(
                QCheckBox, "windowsBypassOnlineRequirementAcknowledgment",
            )
            assert checkbox is not None and acknowledgment is not None
            self.assertTrue(checkbox.isEnabled())
            self.assertTrue(checkbox.isChecked())
            self.assertTrue(acknowledgment.isEnabled())
            self.assertTrue(acknowledgment.isChecked())
            return QDialog.DialogCode.Rejected

        with patch("isopropyl.app.QDialog.exec", new=verify_reopened):
            self.window.configure_windows()

    def test_online_account_bypass_disables_unknown_later_build(self):
        source = ArchiveEntry("sources/install.wim", 16)
        edition = WimEdition(
            1, "Windows 11 Pro", "", "Professional", "amd64",
            10, 0, 26200, 0,
        )
        self.window.windows_wim_candidates = (source,)
        self.window.windows_wim_member = source
        self.window.windows_wim_editions = (edition,)

        def inspect_disabled_control(dialog) -> int:
            checkbox = dialog.findChild(
                QCheckBox, "windowsBypassOnlineRequirementCheckBox",
            )
            acknowledgment = dialog.findChild(
                QCheckBox, "windowsBypassOnlineRequirementAcknowledgment",
            )
            combo = dialog.findChild(QComboBox, "windowsEditionCombo")
            assert checkbox is not None and acknowledgment is not None
            assert combo is not None
            combo.setCurrentIndex(combo.findData(edition.index))
            self.assertFalse(checkbox.isEnabled())
            self.assertFalse(checkbox.isChecked())
            self.assertFalse(acknowledgment.isEnabled())
            self.assertFalse(acknowledgment.isChecked())
            self.assertIn("21H2–24H2", checkbox.toolTip())
            return QDialog.DialogCode.Rejected

        with patch("isopropyl.app.QDialog.exec", new=inspect_disabled_control):
            self.window.configure_windows()

    def test_changing_windows_source_clears_selection_bound_account_bypass(self):
        first = ArchiveEntry("x64/sources/install.wim", 16)
        second = ArchiveEntry("arm64/sources/install.wim", 18)
        edition = WimEdition(
            1, "Windows 11 Pro", "", "Professional", "amd64",
            10, 0, 26100, 0,
        )
        selection = WimSelection(first.path, first.size, (edition,), 1)
        self.window.windows_wim_candidates = (first, second)
        self.window.windows_wim_member = first
        self.window.windows_options = WindowsCustomization(
            install_image=selection,
            install_image_path=first.path,
            bypass_online_account_requirement=True,
            acknowledge_online_account_limitations=True,
        )

        self.window.select_windows_wim_source(second)

        self.assertIsNone(self.window.windows_options.install_image)
        self.assertEqual(self.window.windows_options.install_image_path, "")
        self.assertFalse(
            self.window.windows_options.bypass_online_account_requirement,
        )
        self.assertFalse(
            self.window.windows_options.acknowledge_online_account_limitations,
        )

    def test_nested_wim_edition_records_its_exact_source_path(self):
        source = ArchiveEntry("x64/sources/install.wim", 16)
        edition = WimEdition(
            1, "Windows 11 Pro", "", "Professional", "amd64",
            10, 0, 26100, 0,
        )
        self.window.windows_wim_candidates = (source,)
        self.window.windows_install_source_count = 1
        self.window.windows_wim_member = source
        self.window.windows_wim_editions = (edition,)

        def choose_edition(dialog) -> int:
            combo = dialog.findChild(QComboBox, "windowsEditionCombo")
            assert combo is not None
            combo.setCurrentIndex(combo.findData(edition.index))
            buttons = dialog.findChildren(QDialogButtonBox)
            buttons[-1].button(QDialogButtonBox.StandardButton.Save).click()
            return QDialog.DialogCode.Accepted

        with patch("isopropyl.app.QDialog.exec", new=choose_edition):
            self.window.configure_windows()
        self.assertIsNotNone(self.window.windows_options.install_image)
        self.assertEqual(
            self.window.windows_options.install_image_path, source.path,
        )

    def test_stale_windows_metadata_cannot_clear_a_newer_operation(self):
        source = ArchiveEntry("x64/sources/install.wim", 16)
        self.window.windows_wim_candidates = (source,)
        self.window.windows_wim_member = source
        self.window.windows_metadata_generation = 2
        old = SafeIsoExtractor()
        current = SafeIsoExtractor()
        self.window.windows_wim_extractor = current
        token = WindowsMetadataToken(1, (1, 2, 3, 4), source, old)

        self.window.on_windows_metadata_finished(
            token, source.path, RuntimeError("stale fixture"),
        )

        self.assertIs(self.window.windows_wim_extractor, current)
        self.assertEqual(self.window.windows_wim_error, "")
        self.window.windows_wim_extractor = None

    def test_stale_windows_metadata_progress_cannot_overwrite_current_status(self):
        source = ArchiveEntry("x64/sources/install.wim", 16)
        self.window.windows_wim_candidates = (source,)
        self.window.windows_wim_member = source
        self.window.windows_metadata_generation = 2
        old = SafeIsoExtractor()
        current = SafeIsoExtractor()
        self.window.windows_wim_extractor = current
        token = WindowsMetadataToken(1, (1, 2, 3, 4), source, old)
        self.window.status.setText("Current operation")
        self.window.progress.setValue(321)

        self.window.on_windows_metadata_progress(token, 8, 16)

        self.assertEqual(self.window.status.text(), "Current operation")
        self.assertEqual(self.window.progress.value(), 321)
        self.window.windows_wim_extractor = None

    def test_windows_metadata_result_is_bound_to_the_source_size(self):
        source = ArchiveEntry("x64/sources/install.wim", 16)
        self.window.windows_wim_candidates = (source,)
        self.window.windows_wim_member = source
        self.window.windows_metadata_generation = 1
        extractor = SafeIsoExtractor()
        self.window.windows_wim_extractor = extractor
        token = WindowsMetadataToken(
            1, (1, 2, 3, 4), source, extractor,
        )
        edition = WimEdition(
            1, "Windows 11 Pro", "", "Professional", "amd64",
            10, 0, 26100, 0,
        )
        selection = WimSelection(source.path, source.size, (edition,), 1)
        self.window.windows_options = WindowsCustomization(
            install_image=selection, install_image_path=source.path,
            bypass_online_account_requirement=True,
            acknowledge_online_account_limitations=True,
        )
        info = WimInfo("/tmp/install.wim", 17, (edition,), (1, 2, 17, 4, 5, 1))

        with patch("isopropyl.app.image_identity", return_value=(1, 2, 3, 4)):
            self.window.on_windows_metadata_finished(token, source.path, info)

        self.assertEqual(self.window.windows_wim_editions, ())
        self.assertIn("different catalog size", self.window.windows_wim_error)
        self.assertIsNone(self.window.windows_options.install_image)
        self.assertEqual(self.window.windows_options.install_image_path, "")
        self.assertFalse(
            self.window.windows_options.bypass_online_account_requirement,
        )
        self.assertFalse(
            self.window.windows_options.acknowledge_online_account_limitations,
        )

    def test_settings_persist_binary_units_and_refresh_device_label(self):
        self.window.size_unit_mode = SizeUnitMode.SI
        self.window.refresh_size_labels()
        self.assertIn("8.6 GB", self.window.device_combo.itemText(0))

        def choose_binary(dialog) -> int:
            unit_combos = [
                combo for combo in dialog.findChildren(QComboBox)
                if combo.findData(SizeUnitMode.IEC.value) >= 0
            ]
            self.assertEqual(len(unit_combos), 1)
            combo = unit_combos[0]
            combo.setCurrentIndex(combo.findData(SizeUnitMode.IEC.value))
            boxes = dialog.findChildren(QDialogButtonBox)
            self.assertEqual(len(boxes), 1)
            boxes[0].button(QDialogButtonBox.StandardButton.Save).click()
            return 0

        with patch("isopropyl.app.QDialog.exec", new=choose_binary):
            self.window.show_settings()

        self.assertEqual(self.window.size_unit_mode, SizeUnitMode.IEC)
        self.assertEqual(
            self.window.settings.value("size_units"), SizeUnitMode.IEC.value,
        )
        self.assertIn("8.0 GiB", self.window.device_combo.itemText(0))

    def test_settings_cannot_change_display_units_during_an_operation(self):
        self.window.set_busy(True)

        self.assertFalse(self.window.settings_button.isEnabled())

        self.window.set_busy(False)
        self.assertTrue(self.window.settings_button.isEnabled())

    def test_ignored_drive_description_is_independent_of_display_units(self):
        self.window.size_unit_mode = SizeUnitMode.IEC
        with (
            patch(
                "isopropyl.app.QMessageBox.question",
                return_value=QMessageBox.StandardButton.Yes,
            ),
            patch.object(self.window, "refresh_devices"),
        ):
            self.window.ignore_drive(self.window.devices[0])

        description = self.window.ignored_devices()["serial:usb:serial"]
        self.assertEqual(description, "ISOpropyl Test Drive · /dev/sdz")
        self.assertNotIn("GiB", description)

    def test_drive_backup_filter_selects_raw_vhd_or_vhdx_backend_and_suffix(self):
        invocations = []

        class FakeRawImager:
            def cancel(self) -> None:
                pass

            def backup(self, source, destination, progress, *, sparse=False) -> None:
                invocations.append(("raw", source, destination, sparse))
                progress(source.size, source.size)

        class FakeVirtualImager:
            def cancel(self) -> None:
                pass

            def backup(self, source, destination, progress) -> None:
                invocations.append(("virtual", source, destination, None))
                progress(source.size * 3, source.size * 3)

        cases = (
            ("Raw disk image (*.img)", "chosen.vhdx", "chosen.img", "raw"),
            ("Virtual PC disk (*.vhd)", "chosen.img", "chosen.vhd", "virtual"),
            ("Hyper-V virtual disk (*.vhdx)", "chosen.backup", "chosen.backup.vhdx", "virtual"),
        )
        for selected_filter, entered_name, expected_name, backend in cases:
            with self.subTest(selected_filter=selected_filter):
                invocations.clear()
                entered = Path(self.settings_home.name) / entered_name
                with (
                    patch(
                        "isopropyl.app.QFileDialog.getSaveFileName",
                        return_value=(str(entered), selected_filter),
                    ),
                    patch("isopropyl.app.path_is_on_device", return_value=False),
                    patch("isopropyl.app.shutil.disk_usage", return_value=Mock(free=10**15)),
                    patch(
                        "isopropyl.app.QMessageBox.question",
                        return_value=QMessageBox.StandardButton.Yes,
                    ),
                    patch("isopropyl.app.QMessageBox.information"),
                    patch("isopropyl.app.QMessageBox.critical") as critical,
                    patch("isopropyl.app.list_devices", return_value=self.window.devices),
                    patch("isopropyl.app.DriveImager", FakeRawImager),
                    patch("isopropyl.app.VirtualDriveImager", FakeVirtualImager),
                    patch("isopropyl.app.threading.Thread", ImmediateThread),
                ):
                    self.window.save_drive()

                critical.assert_not_called()
                self.assertEqual(len(invocations), 1)
                self.assertEqual(invocations[0][0], backend)
                self.assertEqual(invocations[0][2].name, expected_name)
                self.assertIs(invocations[0][1], self.window.devices[0])
                self.assertEqual(invocations[0][3], False if backend == "raw" else None)

    def test_drive_backup_rechecks_destination_against_refreshed_device(self):
        backend = Mock()

        class FakeRawImager:
            def cancel(self) -> None:
                pass

            def backup(self, *args, **kwargs) -> None:
                backend(*args, **kwargs)

        selected = self.window.devices[0]
        refreshed = Device(
            selected.path, selected.size, selected.model, selected.vendor,
            selected.transport, selected.serial, selected.wwn,
            selected.major_minor, selected.removable, selected.hotplug,
            selected.read_only, ("/media/new",), ("/dev/sdz1",),
        )
        destination = Path(self.settings_home.name) / "backup.img"
        with (
            patch(
                "isopropyl.app.QFileDialog.getSaveFileName",
                return_value=(str(destination), "Raw disk image (*.img)"),
            ),
            patch("isopropyl.app.path_is_on_device", side_effect=(False, True)),
            patch("isopropyl.app.shutil.disk_usage", return_value=Mock(free=10**15)),
            patch(
                "isopropyl.app.QMessageBox.question",
                return_value=QMessageBox.StandardButton.Yes,
            ),
            patch("isopropyl.app.QMessageBox.information"),
            patch("isopropyl.app.QMessageBox.critical") as critical,
            patch("isopropyl.app.list_devices", return_value=[refreshed]),
            patch("isopropyl.app.DriveImager", FakeRawImager),
            patch("isopropyl.app.threading.Thread", ImmediateThread),
            patch.object(self.window.logger, "exception"),
        ):
            self.window.save_drive()

        backend.assert_not_called()
        self.assertTrue(critical.called)
        self.assertIn("destination moved onto", critical.call_args.args[2])

    def test_oversized_vhd_is_rejected_before_space_check_or_confirmation(self):
        self.window.devices = [device(VHD_MAX_SIZE + 512)]
        destination = Path(self.settings_home.name) / "too-large.vhd"
        with (
            patch(
                "isopropyl.app.QFileDialog.getSaveFileName",
                return_value=(str(destination), "Virtual PC disk (*.vhd)"),
            ),
            patch("isopropyl.app.shutil.disk_usage") as disk_usage,
            patch("isopropyl.app.QMessageBox.question") as question,
            patch("isopropyl.app.QMessageBox.warning") as warning,
        ):
            self.window.save_drive()

        disk_usage.assert_not_called()
        question.assert_not_called()
        warning.assert_called_once()
        self.assertIn("too large for VHD", warning.call_args.args[2])

    def test_explicit_dd_selection_remains_visible_and_changes_dispatch_label(self):
        self.window.rebuild_write_recommendation(preserve_selection=False)
        self.window.write_method.setCurrentIndex(
            self.window.write_method.findData(WriteMode.DD.value)
        )

        self.assertEqual(self.window.selected_write_mode(), WriteMode.DD)
        self.assertTrue(self.window.verify.isEnabled())
        self.assertEqual(self.window.write_button.text(), "Write in DD mode")

    def test_malformed_raw_layout_requires_explicit_dd_selection_and_warning(self):
        self.window.inspection = replace(
            optical_windows_inspection(hybrid=True),
            kind="Raw disk image",
            is_iso9660=False,
            looks_windows=False,
            has_windows_installer=False,
            partition_table_valid=False,
            partition_table_kind="malformed",
            partition_table_issues=("primary: GPT header CRC32 is invalid.",),
        )

        self.window.rebuild_write_recommendation(preserve_selection=False)

        self.assertEqual(self.window.write_method.currentIndex(), -1)
        self.assertEqual(self.window.write_button.text(), "Choose write method")
        self.assertFalse(self.window.write_button.isEnabled())

        self.window.write_method.setCurrentIndex(
            self.window.write_method.findData(WriteMode.DD.value)
        )
        self.assertTrue(self.window.write_button.isEnabled())
        with (
            patch("isopropyl.app.image_identity", return_value=(1, 2, 3, 4)),
            patch(
                "isopropyl.app.QMessageBox.warning",
                return_value=QMessageBox.StandardButton.Cancel,
            ) as warning,
            patch.object(self.window, "start_write") as start_write,
        ):
            self.window.confirm_write()

        start_write.assert_not_called()
        self.assertEqual(warning.call_args.args[1], "Image may not be USB bootable")
        self.assertIn("malformed MBR or GPT", warning.call_args.args[2])

    def test_incomplete_compressed_layout_requires_explicit_dd_and_clear_warning(self):
        self.window.inspection = replace(
            optical_windows_inspection(hybrid=True),
            kind="Raw disk image",
            is_iso9660=False,
            looks_windows=False,
            has_windows_installer=False,
            compression="gzip",
            partition_table_valid=None,
            partition_table_kind="incomplete",
            partition_table_inspection_complete=False,
            partition_table_issues=("Partition metadata is outside the capture.",),
        )
        self.window.rebuild_write_recommendation(preserve_selection=False)
        self.assertEqual(self.window.write_method.currentIndex(), -1)

        self.window.write_method.setCurrentIndex(
            self.window.write_method.findData(WriteMode.DD.value)
        )
        with (
            patch("isopropyl.app.image_identity", return_value=(1, 2, 3, 4)),
            patch(
                "isopropyl.app.QMessageBox.warning",
                return_value=QMessageBox.StandardButton.Cancel,
            ) as warning,
            patch.object(self.window, "start_write") as start_write,
        ):
            self.window.confirm_write()

        start_write.assert_not_called()
        self.assertIn("not known to be damaged", warning.call_args.args[2])

    def test_dd_confirmation_rejects_an_image_changed_after_inspection(self):
        self.window.rebuild_write_recommendation(preserve_selection=False)
        self.window.write_method.setCurrentIndex(
            self.window.write_method.findData(WriteMode.DD.value)
        )
        with (
            patch("isopropyl.app.image_identity", return_value=(9, 9, 9, 9)),
            patch("isopropyl.app.QMessageBox.warning") as warning,
            patch.object(self.window, "start_write") as start_write,
        ):
            self.window.confirm_write()

        start_write.assert_not_called()
        warning.assert_called_once()
        self.assertEqual(warning.call_args.args[1], "Image changed")

    def test_sector_mismatch_keeps_dd_explicit_and_warned(self):
        self.window.inspection = replace(
            optical_windows_inspection(hybrid=True),
            kind="Raw disk image",
            is_iso9660=False,
            looks_windows=False,
            has_windows_installer=False,
            partition_table_valid=True,
            partition_table_kind="gpt",
            partition_table_sector_size=4096,
        )

        self.window.rebuild_write_recommendation(preserve_selection=False)

        self.assertEqual(self.window.write_method.currentIndex(), -1)
        self.assertIn("different logical sector sizes", self.window.write_method_reason.text())
        self.window.write_method.setCurrentIndex(
            self.window.write_method.findData(WriteMode.DD.value)
        )
        with (
            patch("isopropyl.app.image_identity", return_value=(1, 2, 3, 4)),
            patch(
                "isopropyl.app.QMessageBox.warning",
                return_value=QMessageBox.StandardButton.Cancel,
            ) as warning,
            patch.object(self.window, "start_write") as start_write,
        ):
            self.window.confirm_write()

        start_write.assert_not_called()
        self.assertIn("wrong target LBAs", warning.call_args.args[2])

    def test_target_change_clears_preserved_dd_when_it_becomes_explicit_only(self):
        self.window.inspection = replace(
            optical_windows_inspection(hybrid=True),
            kind="Raw disk image",
            is_iso9660=False,
            looks_windows=False,
            has_windows_installer=False,
            partition_table_valid=True,
            partition_table_kind="gpt",
            partition_table_sector_size=512,
        )
        self.window.rebuild_write_recommendation(preserve_selection=False)
        self.assertEqual(self.window.selected_write_mode(), WriteMode.DD)

        self.window.devices = [replace(device(), logical_sector_size=4096)]
        self.window.on_device_changed()

        self.assertIsNone(self.window.selected_write_mode())
        self.assertFalse(self.window.write_button.isEnabled())
        self.assertIn("No method is recommended", self.window.write_method_reason.text())
        self.assertIn("different logical sector sizes", self.window.write_method_reason.text())

    def test_unknown_target_sector_keeps_structured_dd_explicit_and_warned(self):
        self.window.inspection = replace(
            optical_windows_inspection(hybrid=True),
            kind="Raw disk image",
            is_iso9660=False,
            looks_windows=False,
            has_windows_installer=False,
            partition_table_valid=True,
            partition_table_kind="gpt",
            partition_table_sector_size=4096,
        )
        self.window.devices = [replace(device(), logical_sector_size=0)]
        self.window.rebuild_write_recommendation(preserve_selection=False)
        self.assertIsNone(self.window.selected_write_mode())
        self.assertIn("did not report", self.window.write_method_reason.text())

        self.window.write_method.setCurrentIndex(
            self.window.write_method.findData(WriteMode.DD.value)
        )
        with (
            patch("isopropyl.app.image_identity", return_value=(1, 2, 3, 4)),
            patch(
                "isopropyl.app.QMessageBox.warning",
                return_value=QMessageBox.StandardButton.Cancel,
            ) as warning,
            patch.object(self.window, "start_write") as start_write,
        ):
            self.window.confirm_write()

        start_write.assert_not_called()
        self.assertIn("did not report", warning.call_args.args[2])

    def test_confirmation_rechecks_image_after_final_consent(self):
        self.window.inspection = replace(
            optical_windows_inspection(hybrid=True),
            kind="Raw disk image",
            is_iso9660=False,
            looks_windows=False,
            has_windows_installer=False,
        )
        status = self.window.image.stat()
        selected_identity = (
            status.st_dev, status.st_ino, status.st_size,
            status.st_mtime_ns, status.st_ctime_ns,
        )
        self.window.inspection_identity = selected_identity
        self.window.rebuild_write_recommendation(preserve_selection=False)
        changed = False

        def consent(*args, **kwargs):
            nonlocal changed
            if args[1] == "Erase removable drive?":
                self.window.image.write_bytes(b"changed")
                os.utime(
                    self.window.image,
                    ns=(status.st_atime_ns, status.st_mtime_ns),
                )
                changed = True
                return QMessageBox.StandardButton.Yes
            return QMessageBox.StandardButton.Cancel

        with (
            patch("isopropyl.app.QMessageBox.warning", side_effect=consent) as warning,
            patch.object(self.window, "start_write") as start_write,
        ):
            self.window.confirm_write()

        self.assertTrue(changed)
        start_write.assert_not_called()
        self.assertEqual(warning.call_args.args[1], "Image changed")

    def test_start_write_rejects_fresh_target_sector_change(self):
        status = self.window.image.stat()
        identity = (
            status.st_dev, status.st_ino, status.st_size,
            status.st_mtime_ns, status.st_ctime_ns,
        )
        backend = Mock()
        backend.cancelled = False
        refreshed = replace(device(), logical_sector_size=4096)
        with (
            patch("isopropyl.app.ImageWriter", return_value=backend),
            patch("isopropyl.app.list_devices", return_value=[refreshed]),
            patch("isopropyl.app.threading.Thread", ImmediateThread),
            patch("isopropyl.app.QMessageBox.critical") as critical,
            patch.object(self.window.logger, "exception"),
        ):
            self.window.start_write(
                self.window.image, device(), False, identity,
            )

        backend.write.assert_not_called()
        self.assertTrue(critical.called)
        self.assertIn("logical sector size changed", critical.call_args.args[2])

    def test_virtual_write_binds_reopened_container_to_consent_identity(self):
        status = self.window.image.stat()
        identity = (
            status.st_dev, status.st_ino, status.st_size,
            status.st_mtime_ns, status.st_ctime_ns,
        )
        self.window.inspection = replace(
            optical_windows_inspection(), virtual_format="VHDX",
        )
        backend = Mock()
        backend.cancelled = False
        virtual_info = Mock()
        virtual_info.identity.device = identity[0]
        virtual_info.identity.inode = identity[1] + 1
        virtual_info.identity.size = identity[2]
        virtual_info.identity.modified_ns = identity[3]
        virtual_info.identity.changed_ns = identity[4]
        with (
            patch("isopropyl.app.ImageWriter", return_value=backend),
            patch("isopropyl.app.list_devices", return_value=[device()]),
            patch("isopropyl.app.inspect_virtual_disk", return_value=virtual_info),
            patch("isopropyl.app.threading.Thread", ImmediateThread),
            patch("isopropyl.app.QMessageBox.critical") as critical,
            patch.object(self.window.logger, "exception"),
        ):
            self.window.start_write(
                self.window.image, device(), False, identity,
            )

        backend.write.assert_not_called()
        self.assertTrue(critical.called)
        self.assertIn("virtual disk changed", critical.call_args.args[2])

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
        settings = QSettings(
            str(Path(self.settings_home.name) / "settings.ini"),
            QSettings.Format.IniFormat,
        )
        with (
            patch("isopropyl.app.QSettings", return_value=settings),
            patch("isopropyl.app.list_devices", return_value=[]),
        ):
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
