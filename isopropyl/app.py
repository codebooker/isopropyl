from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import sys
import threading
import logging
import shutil
import json
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

from PyQt6.QtCore import QObject, QSettings, QTimer, pyqtSignal
from PyQt6.QtGui import (
    QCloseEvent, QDragEnterEvent, QDropEvent, QIcon, QKeySequence, QShortcut,
    QTextCursor,
)
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QTabWidget, QVBoxLayout, QWidget,
)

from .backup import DriveImager
from .constructed import (
    ConstructedMediaCancelled, ConstructedMediaExecutor,
    build_constructed_media_plan,
)
from .devices import (
    Device, format_size, image_is_on_device, list_devices, path_is_on_device,
)
from .diagnostics import build_diagnostics, write_diagnostics
from .erase import EraseCancelled, EraseMode, EraseRunner, build_erase_plan
from .extraction import (
    ExtractionCancelled, SafeIsoExtractor, build_extraction_plan,
)
from .formatting import (
    Filesystem as FormatFilesystem, FormatCancelled, FormatExecutor,
    PartitionTable as FormatPartitionTable, create_format_plan,
)
from .images import (
    ImageInspection, calculate_checksums, compare_expected_checksum, inspect_image,
)
from .iso import (
    ArchiveEntry, BootStrategy, EntryKind, FirmwareTarget, WriteMode, WritePlan,
    WriteMethodRecommendation, build_write_plan, recommend_write_method,
)
from .iso_staging import (
    IsoStagingCancelled, IsoStagingExecutor, IsoStagingPlan,
    build_iso_staging_plan,
)
from .logging_setup import read_log, setup_logging
from .media_test import (
    MediaTestCancelled, MediaTestMode, MediaTestResult, MediaTestRunner,
    build_media_test_plan,
)
from .optical import (
    OpticalCancelled, OpticalCaptureRunner, build_optical_capture_plan,
    list_optical_devices,
)
from .progress import ProgressEstimator, format_duration
from .writer import ImageWriter, WriteCancelled
from .virtual import VirtualConversionCancelled, VirtualDiskStager, inspect_virtual_disk
from .uefi_ntfs import (
    BoundArtifact, UefiNtfsCancelled, UefiNtfsExecutor,
    build_uefi_ntfs_media_plan, prepare_uefi_ntfs_artifact,
    probe_uefi_ntfs_logical_sector_size,
)
from .wim import WimEdition, WimInfo, WimSelection, inspect_wim
from .windows import (
    WindowsCustomization, generate_autounattend, windows_architecture,
)


class BackgroundPreparation:
    """Small cancellable operation token for pre-consent background work."""

    def __init__(self) -> None:
        self.cancel_event = threading.Event()

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def cancel(self) -> None:
        self.cancel_event.set()


@dataclass(frozen=True)
class PendingIsoWrite:
    image: Path
    inspection: ImageInspection
    device: Device
    write_plan: WritePlan
    workspace: tempfile.TemporaryDirectory[str]
    staging_plan: IsoStagingPlan


class Bridge(QObject):
    # PyQt's plain `int` maps to a signed 32-bit C++ int. Disk images routinely
    # exceed that, so keep byte counters as Python objects across threads.
    progress = pyqtSignal(object, object, str)
    finished = pyqtSignal(bool, str)
    inspection_finished = pyqtSignal(object, object)
    checksums_finished = pyqtSignal(object, object)
    status_changed = pyqtSignal(str)
    media_progress = pyqtSignal(object)
    media_finished = pyqtSignal(object)
    windows_metadata_finished = pyqtSignal(object, object, object)
    uefi_preparation_finished = pyqtSignal(object, object, object)
    device_refresh_finished = pyqtSignal(object, object)


class Window(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.image: Path | None = None
        self.inspection: ImageInspection | None = None
        self.inspection_identity: object | None = None
        self.write_recommendation: WriteMethodRecommendation | None = None
        self.device_refresh_generation = 0
        self.device_refresh_busy = False
        self.checksum_busy = False
        self.devices: list[Device] = []
        self.writer: ImageWriter | None = None
        self.imager: DriveImager | None = None
        self.formatter: FormatExecutor | None = None
        self.media_runner: MediaTestRunner | None = None
        self.eraser: EraseRunner | None = None
        self.optical_runner: OpticalCaptureRunner | None = None
        self.extractor: SafeIsoExtractor | None = None
        self.virtual_stager: VirtualDiskStager | None = None
        self.iso_stager: IsoStagingExecutor | None = None
        self.windows_wim_extractor: SafeIsoExtractor | None = None
        self.constructed_writer: ConstructedMediaExecutor | None = None
        self.uefi_ntfs_writer: UefiNtfsExecutor | None = None
        self.uefi_preparer: BackgroundPreparation | None = None
        self.pending_iso_write: PendingIsoWrite | None = None
        self.iso_workspace: tempfile.TemporaryDirectory[str] | None = None
        self.windows_options = WindowsCustomization()
        self.windows_wim_member: ArchiveEntry | None = None
        self.windows_wim_editions: tuple[WimEdition, ...] = ()
        self.windows_wim_error = ""
        self.settings = QSettings("codebooker", "ISOpropyl")
        self.progress_estimator = ProgressEstimator()
        self.logger = logging.getLogger("isopropyl")
        self.bridge = Bridge()
        self.bridge.progress.connect(self.on_progress)
        self.bridge.finished.connect(self.on_finished)
        self.bridge.inspection_finished.connect(self.on_inspection_finished)
        self.bridge.checksums_finished.connect(self.on_checksums_finished)
        self.setWindowTitle("ISOpropyl")
        self.setMinimumSize(720, 700)
        self.setAcceptDrops(True)
        self.build_ui()
        self.bridge.status_changed.connect(self.status.setText)
        self.bridge.media_progress.connect(self.on_media_progress)
        self.bridge.media_finished.connect(self.on_media_finished)
        self.bridge.windows_metadata_finished.connect(
            self.on_windows_metadata_finished
        )
        self.bridge.uefi_preparation_finished.connect(
            self.on_uefi_preparation_finished
        )
        self.bridge.device_refresh_finished.connect(self.on_devices_refreshed)
        QShortcut(QKeySequence.StandardKey.Open, self, activated=self.choose_image)
        QShortcut(QKeySequence("Ctrl+R"), self, activated=self.refresh_devices)
        QShortcut(QKeySequence("Ctrl+L"), self, activated=self.show_log)
        QShortcut(QKeySequence.StandardKey.Cancel, self, activated=self.cancel)
        self.refresh_devices()

    def build_ui(self) -> None:
        root = QWidget(objectName="root")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(10)

        eyebrow = QLabel("ISOPROPYL")
        eyebrow.setObjectName("eyebrow")
        title = QLabel("Make a bootable USB")
        title.setObjectName("title")
        subtitle = QLabel("Choose an image and a removable drive. ISOpropyl handles the rest.")
        subtitle.setObjectName("subtitle")
        layout.addWidget(eyebrow)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        self.source_card = self.card("1", "Disk image", "Choose a Linux ISO or raw disk image")
        source_row = QHBoxLayout()
        self.image_label = QLabel("No image selected")
        self.image_label.setObjectName("muted")
        choose = QPushButton("Choose image…")
        choose.clicked.connect(self.choose_image)
        source_row.addWidget(self.image_label, 1)
        source_row.addWidget(choose)
        self.source_card.layout().addLayout(source_row)
        image_tools = QHBoxLayout()
        self.image_detail = QLabel("DD mode · Image type and boot layout will appear here")
        self.image_detail.setObjectName("muted")
        self.source_card.layout().addWidget(self.image_detail)
        method_row = QHBoxLayout()
        method_label = QLabel("Write method")
        method_label.setObjectName("muted")
        self.write_method = QComboBox()
        self.write_method.setEnabled(False)
        self.write_method.currentIndexChanged.connect(
            self.on_write_method_changed
        )
        method_row.addWidget(method_label)
        method_row.addWidget(self.write_method, 1)
        self.source_card.layout().addLayout(method_row)
        self.write_method_reason = QLabel(
            "ISOpropyl will recommend a method after inspecting the image."
        )
        self.write_method_reason.setObjectName("muted")
        self.write_method_reason.setWordWrap(True)
        self.source_card.layout().addWidget(self.write_method_reason)
        self.checksum_button = QPushButton("Checksums…")
        self.checksum_button.setEnabled(False)
        self.checksum_button.clicked.connect(self.calculate_image_checksums)
        self.windows_button = QPushButton("Windows options…")
        self.windows_button.setEnabled(False)
        self.windows_button.clicked.connect(self.configure_windows)
        image_tools.addStretch()
        self.iso_plan_button = QPushButton("Plan details…")
        self.iso_plan_button.setToolTip(
            "Preview or write an ISO through a filesystem-aware UEFI/FAT32 workflow."
        )
        self.iso_plan_button.setEnabled(False)
        self.iso_plan_button.clicked.connect(self.preview_iso_plan)
        image_tools.addWidget(self.iso_plan_button)
        image_tools.addWidget(self.windows_button)
        image_tools.addWidget(self.checksum_button)
        self.source_card.layout().addLayout(image_tools)
        layout.addWidget(self.source_card)

        self.target_card = self.card("2", "Destination", "Only removable USB and SD media are shown")
        target_row = QHBoxLayout()
        self.device_combo = QComboBox()
        self.device_combo.currentIndexChanged.connect(self.on_device_changed)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh_devices)
        target_row.addWidget(self.device_combo, 1)
        target_row.addWidget(refresh)
        self.target_card.layout().addLayout(target_row)
        self.device_detail = QLabel("Connect a removable drive, then refresh")
        self.device_detail.setObjectName("muted")
        self.target_card.layout().addWidget(self.device_detail)
        layout.addWidget(self.target_card)

        options = QVBoxLayout()
        write_options = QHBoxLayout()
        self.verify = QCheckBox("Verify after writing")
        self.verify.setChecked(True)
        self.show_external = QCheckBox("Show USB hard drives/SSDs")
        self.show_external.setToolTip(
            "External fixed disks are hidden by default to protect backup drives."
        )
        self.show_external.toggled.connect(self.refresh_devices)
        write_options.addWidget(self.verify)
        write_options.addWidget(self.show_external)
        write_options.addStretch()
        options.addLayout(write_options)
        utility_options = QHBoxLayout()
        utility_options.addStretch()
        log_button = QPushButton("View log")
        log_button.clicked.connect(self.show_log)
        self.tools_button = QPushButton("Drive tools…")
        self.tools_button.clicked.connect(self.show_drive_tools)
        utility_options.addWidget(self.tools_button)
        self.optical_button = QPushButton("Save optical disc…")
        self.optical_button.clicked.connect(self.save_optical_disc)
        utility_options.addWidget(self.optical_button)
        settings_button = QPushButton("Settings…")
        settings_button.clicked.connect(self.show_settings)
        utility_options.addWidget(settings_button)
        utility_options.addWidget(log_button)
        options.addLayout(utility_options)
        layout.addLayout(options)

        self.status = QLabel("Ready when you are")
        self.status.setObjectName("status")
        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        layout.addWidget(self.status)
        layout.addWidget(self.progress)

        actions = QHBoxLayout()
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setVisible(False)
        self.cancel_button.clicked.connect(self.cancel)
        self.write_button = QPushButton("Write image")
        self.write_button.setObjectName("primary")
        self.write_button.clicked.connect(self.confirm_write)
        actions.addWidget(self.cancel_button)
        actions.addStretch()
        actions.addWidget(self.write_button)
        layout.addLayout(actions)
        self.setCentralWidget(root)

    def card(self, number: str, title: str, text: str) -> QFrame:
        frame = QFrame(objectName="card")
        box = QVBoxLayout(frame)
        heading = QLabel(f"{number}   {title}")
        heading.setObjectName("cardTitle")
        detail = QLabel(text)
        detail.setObjectName("muted")
        box.addWidget(heading)
        box.addWidget(detail)
        return frame

    def choose_image(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self, "Choose a disk image", str(Path.home()),
            "Disk images (*.iso *.img *.vhd *.vhdx *.qcow *.qcow2 *.gz *.gzip *.bz2 *.bzip2 *.xz *.lzma *.zst *.zstd *.Z *.z *.zip);;All files (*)",
        )
        if filename:
            self.load_image(Path(filename))

    def load_image(self, path: Path) -> None:
        try:
            identity = image_identity(path)
        except OSError as error:
            QMessageBox.critical(self, "Image unavailable", str(error))
            return
        self.image = path.resolve()
        path = self.image
        self.logger.info("Selected image %s", path)
        self.inspection = None
        self.inspection_identity = None
        self.write_recommendation = None
        self.windows_options = WindowsCustomization()
        self.windows_wim_member = None
        self.windows_wim_editions = ()
        self.windows_wim_error = ""
        self.windows_button.setText("Windows options…")
        self.windows_button.setToolTip("")
        self.windows_button.setEnabled(False)
        self.iso_plan_button.setEnabled(False)
        self.write_method.blockSignals(True)
        self.write_method.clear()
        self.write_method.blockSignals(False)
        self.write_method.setEnabled(False)
        self.write_method_reason.setText(
            "ISOpropyl will recommend a method after inspecting the image."
        )
        self.image_label.setText(f"{path.name}  ·  {format_size(path.stat().st_size)}")
        self.image_label.setToolTip(str(path))
        self.image_detail.setText("DD mode · Inspecting image layout…")
        self.checksum_button.setEnabled(False)
        self.on_device_changed()

        def work() -> None:
            try:
                result: object = inspect_image(path)
            except Exception as error:
                result = error
            self.bridge.inspection_finished.emit(identity, result)

        threading.Thread(target=work, daemon=True).start()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        urls = event.mimeData().urls()
        if len(urls) == 1 and urls[0].isLocalFile() and not self.operation_active:
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        urls = event.mimeData().urls()
        if len(urls) == 1 and urls[0].isLocalFile() and not self.operation_active:
            self.load_image(Path(urls[0].toLocalFile()))
            event.acceptProposedAction()

    def refresh_devices(self, _checked: bool = False) -> None:
        if self.operation_active:
            return
        self.device_refresh_generation += 1
        generation = self.device_refresh_generation
        include_external = self.show_external.isChecked()
        ignored = self.ignored_devices()
        self.device_refresh_busy = True
        self.device_combo.setEnabled(False)
        self.update_ready()
        self.status.setText("Scanning removable drives…")

        def work() -> None:
            try:
                result: object = tuple(
                    device for device in list_devices(include_external)
                    if not device.read_only and device.stable_id not in ignored
                )
            except Exception as error:
                result = error
            self.bridge.device_refresh_finished.emit(generation, result)

        threading.Thread(target=work, daemon=True).start()

    def on_devices_refreshed(self, generation: object, result: object) -> None:
        if generation != self.device_refresh_generation:
            return
        previous = self.selected_device()
        previous_key = (
            (previous.stable_id or previous.path) if previous is not None else None
        )
        self.device_refresh_busy = False
        self.device_combo.blockSignals(True)
        self.device_combo.clear()
        error_message = ""
        if isinstance(result, Exception):
            self.logger.warning("Drive discovery failed: %s", result)
            self.devices = []
            self.device_combo.addItem("Could not inspect drives")
            error_message = str(result)
        elif isinstance(result, tuple) and all(
            isinstance(item, Device) for item in result
        ):
            self.devices = list(result)
            self.logger.info(
                "Detected removable targets: %s",
                ", ".join(device.path for device in self.devices) or "none",
            )
            for device in self.devices:
                self.device_combo.addItem(device.label)
            if not self.devices:
                self.device_combo.addItem("No removable drives found")
            elif previous_key is not None:
                for index, device in enumerate(self.devices):
                    if (device.stable_id or device.path) == previous_key:
                        self.device_combo.setCurrentIndex(index)
                        break
        else:
            self.logger.error("Drive discovery returned an invalid internal result")
            self.devices = []
            self.device_combo.addItem("Could not inspect drives")
            error_message = "Drive discovery returned an invalid result"
        self.device_combo.blockSignals(False)
        self.device_combo.setEnabled(bool(self.devices))
        self.on_device_changed()
        if error_message:
            self.status.setText(error_message)

    def selected_device(self) -> Device | None:
        index = self.device_combo.currentIndex()
        return self.devices[index] if 0 <= index < len(self.devices) else None

    def archive_entries(self) -> tuple[ArchiveEntry, ...]:
        if self.inspection is None:
            return ()
        kinds = {
            "file": EntryKind.FILE,
            "directory": EntryKind.DIRECTORY,
            "symlink": EntryKind.SYMLINK,
            "hardlink": EntryKind.HARDLINK,
        }
        return tuple(
            ArchiveEntry(
                member.path,
                member.size,
                kinds.get(member.kind, EntryKind.FILE),
                member.link_target or None,
            )
            for member in self.inspection.members
        )

    def selected_write_mode(self) -> WriteMode | None:
        value = self.write_method.currentData()
        try:
            return WriteMode(value) if value is not None else None
        except ValueError:
            return None

    def rebuild_write_recommendation(self, *, preserve_selection: bool = True) -> None:
        inspection = self.inspection
        if inspection is None:
            self.write_recommendation = None
            self.write_method.setEnabled(False)
            return
        previous = self.selected_write_mode() if preserve_selection else None
        device = self.selected_device()
        try:
            recommendation = recommend_write_method(
                inspection,
                self.archive_entries(),
                target_size=device.size if device is not None else None,
            )
        except ValueError as error:
            self.write_recommendation = None
            self.write_method.blockSignals(True)
            self.write_method.clear()
            self.write_method.blockSignals(False)
            self.write_method.setEnabled(False)
            self.write_method_reason.setText(
                f"No safe write method could be planned: {error}"
            )
            return
        self.write_recommendation = recommendation
        selected = (
            previous
            if previous in recommendation.available_modes else
            recommendation.recommended_mode
        )
        labels = {
            WriteMode.DD: "DD mode — exact byte-for-byte copy",
            WriteMode.EXTRACTED_ISO: "ISO mode — filesystem-aware, UEFI-only",
        }
        self.write_method.blockSignals(True)
        self.write_method.clear()
        for mode in recommendation.available_modes:
            self.write_method.addItem(labels[mode], mode.value)
        if selected is not None:
            index = self.write_method.findData(selected.value)
            self.write_method.setCurrentIndex(index)
        self.write_method.blockSignals(False)
        self.write_method.setEnabled(bool(recommendation.available_modes))
        prefix = (
            "Recommended: ISO mode. "
            if recommendation.recommended_mode is WriteMode.EXTRACTED_ISO else
            "Recommended: DD mode. "
            if recommendation.recommended_mode is WriteMode.DD else
            "No write method is currently available. "
        )
        detail = prefix + recommendation.reason
        if (
            inspection.is_iso9660
            and WriteMode.EXTRACTED_ISO not in recommendation.available_modes
            and recommendation.iso_unavailable_reason
        ):
            detail += " ISO mode unavailable: " + recommendation.iso_unavailable_reason
        self.write_method_reason.setText(detail)
        self.on_write_method_changed()

    def on_device_changed(self) -> None:
        self.rebuild_write_recommendation()
        self.update_ready()

    def on_write_method_changed(self) -> None:
        mode = self.selected_write_mode()
        if self.inspection is not None:
            label = "ISO mode" if mode is WriteMode.EXTRACTED_ISO else "DD mode"
            self.image_detail.setText(f"{label} · {self.inspection.summary}")
        iso_mode = mode is WriteMode.EXTRACTED_ISO
        self.verify.setChecked(True if iso_mode else self.verify.isChecked())
        self.verify.setEnabled(not self.operation_active and not iso_mode)
        self.write_button.setText(
            "Write in ISO mode" if iso_mode else "Write in DD mode"
        )
        self.update_ready()

    def update_ready(self) -> None:
        device = self.selected_device()
        mode = self.selected_write_mode()
        recommendation = self.write_recommendation
        plan = None
        if recommendation is not None:
            plan = (
                recommendation.iso_plan
                if mode is WriteMode.EXTRACTED_ISO else
                recommendation.dd_plan
                if mode is WriteMode.DD else None
            )
        enough_space = bool(
            self.image and device and plan
            and mode in recommendation.available_modes  # type: ignore[union-attr]
            and plan.minimum_target_bytes <= device.size
        )
        self.write_button.setEnabled(
            enough_space and not self.operation_active and self.inspection is not None
            and not self.checksum_busy and not self.device_refresh_busy
        )
        self.tools_button.setEnabled(
            bool(device) and not self.operation_active and not self.device_refresh_busy
        )
        if device:
            serial = device.serial or device.wwn or "not reported"
            media_type = "Removable media" if device.removable else "External fixed disk"
            self.device_detail.setText(
                f"Serial: {serial}  ·  {media_type}  ·  Transport: {device.transport.upper()}"
            )
        else:
            self.device_detail.setText("Connect a removable drive, then refresh")
        if self.image and device and plan is not None and not enough_space:
            self.status.setText(
                "The selected target is too small for this write method"
            )
        elif not self.operation_active:
            self.status.setText("Ready when you are")

    @property
    def operation_active(self) -> bool:
        return any((
            self.writer, self.imager, self.formatter, self.media_runner, self.eraser,
            self.optical_runner,
            self.extractor,
            self.virtual_stager,
            self.iso_stager,
            self.windows_wim_extractor,
            self.constructed_writer,
            self.uefi_ntfs_writer,
            self.uefi_preparer,
        ))

    def confirm_write(self) -> None:
        device = self.selected_device()
        if not self.image or not device or not self.inspection:
            return
        mode = self.selected_write_mode()
        if mode is WriteMode.EXTRACTED_ISO:
            self.confirm_iso_write(device)
            return
        if mode is not WriteMode.DD:
            QMessageBox.warning(
                self, "No write method selected",
                "Choose an available write method before continuing.",
            )
            return
        compatibility_warning = None
        if self.inspection.has_windows_installer:
            compatibility_warning = (
                "Most Windows ISOs need the filesystem-aware "
                "workflow, so a byte-for-byte copy may not boot from USB.\n\n"
                "Use ISO mode for supported UEFI Windows media unless you know this "
                "image supports raw USB writing."
            )
        elif not self.inspection.raw_compatible:
            compatibility_warning = (
                "This appears to be an optical-only ISO without an MBR or GPT disk "
                "layout. Raw-writing it may produce a USB that cannot boot."
            )
        if compatibility_warning:
            warning = QMessageBox.warning(
                self, "Image may not be USB bootable",
                compatibility_warning + "\n\nWrite it anyway?",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if warning != QMessageBox.StandardButton.Yes:
                return
        if self.windows_options.enabled:
            warning = QMessageBox.warning(
                self, "Windows profile cannot be applied in DD mode",
                "A Windows customization profile is selected, but DD mode copies "
                "the ISO byte-for-byte and cannot add autounattend.xml. The profile "
                "will not be applied to this USB.\n\nContinue without the profile?",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if warning != QMessageBox.StandardButton.Yes:
                return
        if not device.removable:
            warning = QMessageBox.warning(
                self, "External hard drive or SSD selected",
                "This device reports itself as a fixed disk. Confirm that it is not a "
                "backup drive or another disk containing important data.\n\nContinue?",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if warning != QMessageBox.StandardButton.Yes:
                return
        answer = QMessageBox.warning(
            self, "Erase removable drive?",
            f"Everything on {device.label} will be permanently erased.\n\n"
            f"Image: {self.image.name}\nMethod: DD mode · exact byte-for-byte copy\n"
            f"Layout: {self.inspection.layout}\n"
            f"Target: {device.path}\nSerial: {device.serial or device.wwn or 'not reported'}\n\n"
            "Check the target carefully before continuing.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.logger.info("Confirmed write: image=%s target=%s identity=%s", self.image, device.path, device.identity)
            self.start_write(self.image, device, self.verify.isChecked())

    def confirm_iso_write(self, device: Device) -> None:
        image = self.image
        inspection = self.inspection
        if image is None or inspection is None:
            return
        try:
            current_identity = image_identity(image)
        except OSError as error:
            QMessageBox.critical(self, "Image unavailable", str(error))
            return
        if current_identity != self.inspection_identity:
            QMessageBox.warning(
                self,
                "Image changed",
                "The image changed after inspection. Select it again before writing.",
            )
            return
        entries = self.archive_entries()
        try:
            recommendation = recommend_write_method(
                inspection, entries, target_size=device.size,
            )
        except ValueError as error:
            QMessageBox.warning(self, "ISO mode unavailable", str(error))
            return
        plan = recommendation.iso_plan
        if (
            plan is None
            or not plan.executable
            or WriteMode.EXTRACTED_ISO not in recommendation.available_modes
        ):
            QMessageBox.warning(
                self,
                "ISO mode unavailable",
                recommendation.iso_unavailable_reason
                or "This image no longer has an executable ISO-mode plan.",
            )
            self.rebuild_write_recommendation()
            return
        self.logger.info(
            "Dispatching fresh ISO-mode plan: image=%s target=%s identity=%s",
            image, device.path, device.identity,
        )
        self.start_constructed_iso_write(list(entries), plan)

    def start_write(self, image: Path, device: Device, should_verify: bool) -> None:
        try:
            source_identity = image_identity(image)
        except OSError as error:
            QMessageBox.critical(self, "Image unavailable", str(error))
            return
        self.writer = ImageWriter()
        self.virtual_stager = VirtualDiskStager() if self.inspection and self.inspection.virtual_format else None
        self.set_busy(True)
        self.progress.setValue(0)
        self.status.setText("Preparing drive…")

        def work() -> None:
            try:
                assert self.writer is not None
                matches = [
                    d for d in list_devices(include_usb_hdds=not device.removable)
                    if d.path == device.path
                ]
                if not matches or matches[0].identity != device.identity:
                    raise RuntimeError("The selected drive changed or was disconnected. Refresh and select it again.")
                if image_is_on_device(str(image), device):
                    raise RuntimeError(
                        "The selected image is stored on the target drive. Move it to another disk before writing."
                    )
                if image_identity(image) != source_identity:
                    raise RuntimeError("The selected image changed after confirmation. Choose it again before writing.")
                staged = None
                write_source = image
                if self.virtual_stager is not None:
                    info = inspect_virtual_disk(image)
                    staged = self.virtual_stager.stage(
                        info,
                        lambda d, t: self.bridge.progress.emit(d, t, "Converting virtual disk"),
                    )
                    write_source = staged.path
                try:
                    self.writer.write(
                        write_source, device,
                        lambda d, t: self.bridge.progress.emit(d, t, "Writing"),
                    )
                    if should_verify:
                        self.bridge.progress.emit(0, write_source.stat().st_size * 2, "Verifying")
                        if not self.writer.verify(
                            write_source, device.path,
                            lambda d, t: self.bridge.progress.emit(d, t, "Verifying"),
                        ):
                            raise RuntimeError(
                                "Verification failed: the written data does not match the image"
                            )
                finally:
                    if staged is not None:
                        staged.close()
                if self.writer.cancelled:
                    raise WriteCancelled("Writing was cancelled")
                if self.writer.power_off(device):
                    message = "Your bootable USB is ready and safely powered off. You can remove it."
                else:
                    message = "Your bootable USB is ready. Eject it with your desktop before removing it."
                self.bridge.finished.emit(True, message)
            except WriteCancelled as error:
                self.logger.info("Operation cancelled: %s", error)
                self.bridge.finished.emit(False, str(error))
            except VirtualConversionCancelled as error:
                self.logger.info("Operation cancelled: %s", error)
                self.bridge.finished.emit(False, str(error))
            except Exception as error:
                self.logger.exception("Write operation failed")
                self.bridge.finished.emit(False, str(error))

        threading.Thread(target=work, daemon=True).start()

    def on_progress(self, done: int, total: int, stage: str) -> None:
        snapshot = self.progress_estimator.update(done, total, stage)
        self.progress.setValue(round(snapshot.fraction * 1000))
        details = (
            f"{stage}… {snapshot.fraction:.0%}  ·  "
            f"{format_size(snapshot.done)} of {format_size(snapshot.total)}"
        )
        if snapshot.bytes_per_second:
            details += f"  ·  {format_size(snapshot.bytes_per_second)}/s"
        if snapshot.eta_seconds is not None:
            details += f"  ·  {format_duration(snapshot.eta_seconds)} remaining"
        self.status.setText(details)

    def on_finished(self, success: bool, message: str) -> None:
        self.writer = None
        self.imager = None
        self.formatter = None
        self.media_runner = None
        self.eraser = None
        self.optical_runner = None
        self.extractor = None
        self.virtual_stager = None
        self.iso_stager = None
        self.windows_wim_extractor = None
        self.constructed_writer = None
        self.uefi_ntfs_writer = None
        self.uefi_preparer = None
        self.pending_iso_write = None
        if self.iso_workspace is not None:
            try:
                self.iso_workspace.cleanup()
            except OSError as error:
                self.logger.warning("Could not remove ISO workspace: %s", error)
                message += " Temporary workspace cleanup was incomplete."
            self.iso_workspace = None
        self.progress.setRange(0, 1000)
        self.set_busy(False)
        self.status.setText(message)
        if success:
            self.progress.setValue(1000)
            QMessageBox.information(self, "Operation complete", message)
        else:
            QMessageBox.critical(self, "Operation did not complete", message)
        self.refresh_devices()

    def set_busy(self, busy: bool) -> None:
        if busy:
            self.progress_estimator.reset()
        self.source_card.setEnabled(not busy)
        self.target_card.setEnabled(not busy)
        self.verify.setEnabled(
            not busy and self.selected_write_mode() is not WriteMode.EXTRACTED_ISO
        )
        self.show_external.setEnabled(not busy)
        self.tools_button.setEnabled(not busy and self.selected_device() is not None)
        self.optical_button.setEnabled(not busy)
        self.checksum_button.setEnabled(not busy and self.inspection is not None)
        self.windows_button.setEnabled(
            not busy and bool(self.inspection and self.inspection.has_windows_installer)
        )
        self.iso_plan_button.setEnabled(
            not busy and bool(self.inspection and self.inspection.is_iso9660)
        )
        self.write_button.setEnabled(not busy)
        self.cancel_button.setVisible(busy)
        self.cancel_button.setEnabled(busy)

    def cancel(self) -> None:
        active = tuple(filter(None, (
            self.writer, self.imager, self.formatter, self.media_runner, self.eraser,
            self.optical_runner, self.extractor, self.virtual_stager,
            self.iso_stager, self.constructed_writer,
            self.uefi_ntfs_writer,
            self.uefi_preparer,
            self.windows_wim_extractor,
        )))
        if active:
            self.status.setText("Stopping…")
            self.cancel_button.setEnabled(False)
            for operation in active:
                operation.cancel()

    def closeEvent(self, event: QCloseEvent) -> None:
        if not self.operation_active:
            event.accept()
            return
        answer = QMessageBox.warning(
            self, "An operation is still in progress",
            "Closing now will cancel the operation and may leave an incomplete result. "
            "Keep the drive connected until ISOpropyl confirms it has stopped.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.cancel()
        event.ignore()

    def save_drive(self) -> None:
        device = self.selected_device()
        if not device or self.operation_active:
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save removable drive as an image", f"{Path.home() / 'drive-backup.img'}",
            "Raw disk image (*.img);;All files (*)",
        )
        if not filename:
            return
        destination = Path(filename)
        if path_is_on_device(str(destination), device):
            QMessageBox.critical(
                self, "Choose another destination",
                "The backup cannot be saved onto the drive being imaged. Choose a "
                "folder on another disk.",
            )
            return
        try:
            free = shutil.disk_usage(destination.parent).free
        except OSError as error:
            QMessageBox.critical(self, "Destination unavailable", str(error))
            return
        if free < device.size:
            QMessageBox.critical(
                self, "Not enough free space",
                f"A complete image needs {format_size(device.size)}, but the destination "
                f"has only {format_size(free)} available.",
            )
            return
        answer = QMessageBox.question(
            self, "Save complete drive image?",
            f"ISOpropyl will unmount and read all {format_size(device.size)} from:\n"
            f"{device.label}\n\nand save a raw image to:\n{destination}\n\n"
            "The source drive will not be modified.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        identity = device.identity
        self.imager = DriveImager()
        self.set_busy(True)
        self.progress.setValue(0)
        self.status.setText("Preparing drive backup…")

        def work() -> None:
            try:
                matches = [
                    item for item in list_devices(include_usb_hdds=not device.removable)
                    if item.path == device.path
                ]
                if not matches or matches[0].identity != identity:
                    raise RuntimeError(
                        "The selected drive changed or was disconnected. Refresh and try again."
                    )
                assert self.imager is not None
                self.imager.backup(
                    device, destination,
                    lambda done, total: self.bridge.progress.emit(done, total, "Saving drive"),
                    sparse=False,
                )
                self.bridge.finished.emit(True, f"Drive image saved to {destination}")
            except WriteCancelled as error:
                self.bridge.finished.emit(False, str(error))
            except Exception as error:
                self.logger.exception("Drive backup failed")
                self.bridge.finished.emit(False, str(error))

        threading.Thread(target=work, daemon=True).start()

    def show_drive_tools(self) -> None:
        device = self.selected_device()
        if not device or self.operation_active:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Drive tools")
        dialog.setMinimumWidth(500)
        layout = QVBoxLayout(dialog)
        title = QLabel(device.label)
        title.setObjectName("cardTitle")
        layout.addWidget(title)
        save = QPushButton("Save complete drive as a raw image…")
        save.setToolTip("Read-only backup; the source drive is not modified")
        restore = QPushButton("Restore as an empty data drive…")
        restore.setToolTip("Erases the drive and creates one new filesystem")
        media_test = QPushButton("Test for bad blocks or fake capacity…")
        media_test.setEnabled(device.removable)
        media_test.setToolTip(
            "Destructive full-media validation is restricted to drives marked removable"
        )
        erase = QPushButton("Erase drive with zeros…")
        erase.setEnabled(device.removable)
        erase.setToolTip(
            "Logical zero overwrite; this is not a hardware secure erase"
            if device.removable else "Erase is restricted to drives marked removable"
        )
        ignore = QPushButton("Hide this drive from ISOpropyl…")
        ignore.setEnabled(device.stable_id is not None)
        ignore.setToolTip(
            "Adds this serial/WWN to the persistent safety denylist"
            if device.stable_id else "This drive reports no stable serial or WWN"
        )
        layout.addWidget(save)
        layout.addWidget(restore)
        layout.addWidget(erase)
        layout.addWidget(media_test)
        layout.addWidget(ignore)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        def choose(action) -> None:
            dialog.accept()
            QTimer.singleShot(0, action)

        save.clicked.connect(lambda: choose(self.save_drive))
        restore.clicked.connect(lambda: choose(self.format_drive))
        erase.clicked.connect(lambda: choose(self.erase_drive))
        media_test.clicked.connect(lambda: choose(self.test_media))
        ignore.clicked.connect(lambda: choose(lambda: self.ignore_drive(device)))
        dialog.exec()

    def save_optical_disc(self) -> None:
        if self.operation_active:
            return
        try:
            devices = list_optical_devices()
        except Exception as error:
            QMessageBox.warning(self, "Optical capture unavailable", str(error))
            return
        if not devices:
            QMessageBox.information(
                self,
                "No readable optical disc",
                "ISOpropyl did not find a supported /dev/sr* optical drive with readable media.",
            )
            return

        choose = QDialog(self)
        choose.setWindowTitle("Save optical disc as ISO")
        choose.setMinimumWidth(620)
        choose_layout = QVBoxLayout(choose)
        note = QLabel(
            "This is a read-only capture. ISOpropyl reads complete 2048-byte data sectors "
            "from the optical disc and does not modify it."
        )
        note.setWordWrap(True)
        choose_layout.addWidget(note)
        source = QComboBox()
        for device in devices:
            name = " ".join(item for item in (device.vendor, device.model) if item).strip()
            label = device.label or "unlabelled disc"
            source.addItem(
                f"{name or 'Optical drive'} · {device.path} · {label} · "
                f"{format_size(device.size)}",
                device,
            )
        choose_layout.addWidget(source)
        choose_buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        choose_buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Choose destination…")
        choose_buttons.accepted.connect(choose.accept)
        choose_buttons.rejected.connect(choose.reject)
        choose_layout.addWidget(choose_buttons)
        if choose.exec() != QDialog.DialogCode.Accepted:
            return
        device = source.currentData()
        default_name = f"{device.label or 'optical-disc'}.iso"
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save optical disc as ISO", default_name, "ISO images (*.iso)"
        )
        if not filename:
            return
        destination = Path(filename)
        if destination.suffix.casefold() != ".iso":
            destination = destination.with_suffix(".iso")
        try:
            plan = build_optical_capture_plan(device, destination)
        except Exception as error:
            QMessageBox.warning(self, "Optical capture unavailable", str(error))
            return
        answer = QMessageBox.question(
            self,
            "Capture this optical disc?",
            f"Read {format_size(plan.readable_bytes)} from {device.path}\n"
            f"Label: {device.label or 'not reported'}\n\n"
            f"Save a new ISO to:\n{plan.destination}\n\n"
            "The disc is not modified, and ISOpropyl will not overwrite an existing file.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        self.optical_runner = OpticalCaptureRunner()
        self.set_busy(True)
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        self.status.setText("Preparing optical capture…")

        def work() -> None:
            try:
                assert self.optical_runner is not None
                result = self.optical_runner.run(
                    plan,
                    lambda update: self.bridge.progress.emit(
                        update.bytes_done, update.total_bytes, "Saving optical disc"
                    ),
                )
                self.logger.info(
                    "Optical capture complete: source=%s destination=%s bytes=%s",
                    device.path, result.destination, result.bytes_written,
                )
                self.bridge.finished.emit(
                    True, f"Optical disc saved to {result.destination}"
                )
            except OpticalCancelled as error:
                self.bridge.finished.emit(False, str(error))
            except Exception as error:
                self.logger.exception("Optical capture failed")
                self.bridge.finished.emit(False, str(error))

        threading.Thread(target=work, daemon=True).start()

    def ignored_devices(self) -> dict[str, str]:
        raw = self.settings.value("ignored_devices", "{}")
        try:
            parsed = json.loads(str(raw))
        except (TypeError, json.JSONDecodeError):
            return {}
        return {
            str(key): str(value) for key, value in parsed.items()
            if isinstance(key, str) and isinstance(value, str)
        } if isinstance(parsed, dict) else {}

    def ignore_drive(self, device: Device) -> None:
        if not device.stable_id:
            return
        answer = QMessageBox.question(
            self, "Hide this drive?",
            f"Hide {device.label} from ISOpropyl's destination list on future connections?\n\n"
            "You can clear the ignored-drive list under Settings.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        ignored = self.ignored_devices()
        ignored[device.stable_id] = device.label
        self.settings.setValue("ignored_devices", json.dumps(ignored, sort_keys=True))
        self.logger.info("Added device to safety denylist: %s", device.stable_id)
        self.refresh_devices()

    def format_drive(self) -> None:
        device = self.selected_device()
        if not device or self.operation_active:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Restore drive")
        dialog.setMinimumWidth(520)
        layout = QVBoxLayout(dialog)
        notice = QLabel(
            "Create one empty, full-capacity data partition. This removes every "
            "existing partition and all files on the selected drive."
        )
        notice.setWordWrap(True)
        layout.addWidget(notice)
        layout.addWidget(QLabel("Filesystem"))
        filesystem = QComboBox()
        filesystem.addItem("FAT32 — widest device compatibility", FormatFilesystem.FAT32)
        filesystem.addItem("exFAT — large files and cross-platform use", FormatFilesystem.EXFAT)
        filesystem.addItem("NTFS — Windows-focused", FormatFilesystem.NTFS)
        filesystem.addItem("ext4 — Linux-focused", FormatFilesystem.EXT4)
        layout.addWidget(filesystem)
        layout.addWidget(QLabel("Partition table"))
        table = QComboBox()
        table.addItem("MBR — widest legacy compatibility", FormatPartitionTable.MBR)
        table.addItem("GPT — modern systems", FormatPartitionTable.GPT)
        layout.addWidget(table)
        layout.addWidget(QLabel("Volume label (optional)"))
        label = QLineEdit("USB")
        layout.addWidget(label)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Review erase…")
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            plan = create_format_plan(
                device, filesystem.currentData(), table.currentData(), label.text()
            )
        except ValueError as error:
            QMessageBox.warning(self, "Invalid format options", str(error))
            return
        if not device.removable:
            fixed = QMessageBox.warning(
                self, "External hard drive or SSD selected",
                "This target reports itself as a fixed disk. Make certain it is not "
                "a backup drive before continuing.",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if fixed != QMessageBox.StandardButton.Yes:
                return
        answer = QMessageBox.warning(
            self, "Erase and restore this drive?",
            f"ALL DATA WILL BE ERASED\n\n{device.label}\n"
            f"Serial: {device.serial or device.wwn or 'not reported'}\n"
            f"New layout: {plan.partition_table.value.upper()}, "
            f"{plan.filesystem.value.upper()}, label {plan.label or '(none)'}\n\n"
            "Check the device path, model, size, and serial before continuing.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.formatter = FormatExecutor()
        self.set_busy(True)
        self.progress.setRange(0, 0)
        self.status.setText("Preflighting format tools…")

        def work() -> None:
            try:
                assert self.formatter is not None
                partition = self.formatter.execute(
                    device, plan,
                    lambda stage: self.bridge.status_changed.emit(f"Formatting · {stage}"),
                )
                self.logger.info(
                    "Drive restored: device=%s partition=%s filesystem=%s table=%s",
                    device.path, partition, plan.filesystem.value, plan.partition_table.value,
                )
                self.bridge.finished.emit(
                    True,
                    f"The drive was restored as {plan.filesystem.value.upper()} on {partition}. "
                    "Eject it with your desktop before unplugging it.",
                )
            except FormatCancelled as error:
                self.bridge.finished.emit(False, str(error))
            except Exception as error:
                self.logger.exception("Drive restore failed")
                self.bridge.finished.emit(False, str(error))

        threading.Thread(target=work, daemon=True).start()

    def erase_drive(self) -> None:
        device = self.selected_device()
        if not device or self.operation_active:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Erase drive with zeros")
        dialog.setMinimumWidth(600)
        layout = QVBoxLayout(dialog)
        warning = QLabel(
            "Both choices destroy data. They perform logical writes only and are not "
            "hardware secure erase or sanitization commands."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet("color: #ff8a80; font-weight: 650;")
        layout.addWidget(warning)
        mode = QComboBox()
        mode.addItem(
            f"Full zero pass — overwrite all {format_size(device.size)}",
            EraseMode.FULL_ZERO,
        )
        mode.addItem(
            "Quick boundary zero — first and last 16 MiB only",
            EraseMode.QUICK_BOUNDARY_ZERO,
        )
        layout.addWidget(mode)
        scope = QLabel(
            "Full mode writes one pass across the advertised logical address space. "
            "Quick mode only removes common partition, boot, and filesystem metadata; "
            "middle data remains recoverable."
        )
        scope.setWordWrap(True)
        scope.setObjectName("muted")
        layout.addWidget(scope)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Review erase…")
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            plan = build_erase_plan(device, mode.currentData())
        except Exception as error:
            QMessageBox.warning(self, "Drive erase unavailable", str(error))
            return

        confirm = QDialog(self)
        confirm.setWindowTitle("Final drive-erase confirmation")
        confirm.setMinimumWidth(680)
        confirm_layout = QVBoxLayout(confirm)
        for text in plan.warnings:
            line = QLabel(text)
            line.setWordWrap(True)
            confirm_layout.addWidget(line)
        phrase = QLineEdit()
        phrase.setPlaceholderText(plan.confirmation_phrase)
        confirm_layout.addWidget(phrase)
        confirm_buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        start_button = confirm_buttons.button(QDialogButtonBox.StandardButton.Ok)
        start_button.setText("Erase drive")
        start_button.setEnabled(False)
        phrase.textChanged.connect(
            lambda value: start_button.setEnabled(value == plan.confirmation_phrase)
        )
        confirm_buttons.accepted.connect(confirm.accept)
        confirm_buttons.rejected.connect(confirm.reject)
        confirm_layout.addWidget(confirm_buttons)
        if confirm.exec() != QDialog.DialogCode.Accepted:
            return
        authorization = phrase.text()

        self.eraser = EraseRunner()
        self.set_busy(True)
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        self.status.setText("Preparing drive erase…")

        def work() -> None:
            try:
                assert self.eraser is not None
                stage = (
                    "Zeroing drive"
                    if plan.mode is EraseMode.FULL_ZERO
                    else "Zeroing drive boundaries"
                )
                result = self.eraser.run(
                    plan,
                    authorization,
                    lambda update: self.bridge.progress.emit(
                        update.bytes_done, update.total_bytes, stage
                    ),
                )
                self.logger.info(
                    "Logical erase complete: device=%s mode=%s bytes=%s",
                    device.path, result.mode.value, result.bytes_written,
                )
                if plan.mode is EraseMode.FULL_ZERO:
                    description = "one logical zero pass across the advertised drive size"
                else:
                    description = "the first and last 16 MiB boundaries"
                self.bridge.finished.emit(
                    True,
                    f"ISOpropyl zeroed {description}. This was not a hardware secure erase. "
                    "Use Drive tools → Restore to create a new filesystem.",
                )
            except EraseCancelled as error:
                self.bridge.finished.emit(False, str(error))
            except Exception as error:
                self.logger.exception("Drive erase failed")
                self.bridge.finished.emit(False, str(error))

        threading.Thread(target=work, daemon=True).start()

    def test_media(self) -> None:
        device = self.selected_device()
        if not device or self.operation_active:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Destructive media test")
        dialog.setMinimumWidth(600)
        layout = QVBoxLayout(dialog)
        warning = QLabel(
            "This test overwrites the entire drive. It is intended to find damaged "
            "blocks and fraudulent capacity, and can take many hours."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet("color: #ff8a80; font-weight: 650;")
        layout.addWidget(warning)
        layout.addWidget(QLabel("Test mode"))
        mode = QComboBox()
        mode.addItem("Full surface — write and compare every block", MediaTestMode.FULL_SURFACE)
        mode.addItem("Quick fake-capacity probe — requires f3probe", MediaTestMode.FAKE_CAPACITY)
        mode.addItem("Complete — fake-capacity probe plus full surface", MediaTestMode.COMPLETE)
        layout.addWidget(mode)
        layout.addWidget(QLabel("Full-surface pattern passes"))
        passes = QComboBox()
        for count in range(1, 5):
            passes.addItem(f"{count} pass{'es' if count != 1 else ''}", count)
        layout.addWidget(passes)
        mode.currentIndexChanged.connect(
            lambda: passes.setEnabled(mode.currentData() is not MediaTestMode.FAKE_CAPACITY)
        )
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Review destructive test…")
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            plan = build_media_test_plan(
                device, mode.currentData(), passes=int(passes.currentData())
            )
        except Exception as error:
            QMessageBox.warning(self, "Media test unavailable", str(error))
            return

        confirm = QDialog(self)
        confirm.setWindowTitle("Final destructive-test confirmation")
        confirm.setMinimumWidth(650)
        confirm_layout = QVBoxLayout(confirm)
        for text in plan.warnings:
            line = QLabel(text)
            line.setWordWrap(True)
            confirm_layout.addWidget(line)
        phrase = QLineEdit()
        phrase.setPlaceholderText(plan.confirmation_phrase)
        confirm_layout.addWidget(phrase)
        confirm_buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        start_button = confirm_buttons.button(QDialogButtonBox.StandardButton.Ok)
        start_button.setText("Erase and test")
        start_button.setEnabled(False)
        phrase.textChanged.connect(
            lambda value: start_button.setEnabled(value == plan.confirmation_phrase)
        )
        confirm_buttons.accepted.connect(confirm.accept)
        confirm_buttons.rejected.connect(confirm.reject)
        confirm_layout.addWidget(confirm_buttons)
        if confirm.exec() != QDialog.DialogCode.Accepted:
            return

        self.media_runner = MediaTestRunner()
        self.set_busy(True)
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        self.status.setText("Preparing destructive media test…")

        def work() -> None:
            try:
                assert self.media_runner is not None
                result = self.media_runner.run(
                    plan, phrase.text(), self.bridge.media_progress.emit
                )
                self.bridge.media_finished.emit(result)
            except MediaTestCancelled as error:
                self.bridge.finished.emit(False, str(error))
            except Exception as error:
                self.logger.exception("Media validation failed")
                self.bridge.finished.emit(False, str(error))

        threading.Thread(target=work, daemon=True).start()

    def on_media_progress(self, update: object) -> None:
        fraction = float(update.fraction)  # type: ignore[attr-defined]
        phase = str(update.phase_name)  # type: ignore[attr-defined]
        self.progress.setValue(round(fraction * 1000))
        self.status.setText(f"Testing media · {phase} · {fraction:.0%}")

    def on_media_finished(self, result: object) -> None:
        report: MediaTestResult = result  # type: ignore[assignment]
        self.media_runner = None
        self.set_busy(False)
        self.progress.setRange(0, 1000)
        self.progress.setValue(1000)
        capacity = report.capacity_status.value.replace("_", " ")
        bad_blocks = ", ".join(str(item) for item in report.bad_blocks[:20])
        if len(report.bad_blocks) > 20:
            bad_blocks += f" … and {len(report.bad_blocks) - 20} more"
        details = (
            f"Capacity result: {capacity}\n"
            f"Bad blocks: {bad_blocks or 'none reported'}\n\n"
            "The test erased the drive. Use Drive tools → Restore to create a new filesystem."
        )
        if report.passed:
            self.status.setText("Media test passed")
            QMessageBox.information(self, "Media test passed", details)
        else:
            self.status.setText("Media test found a problem")
            QMessageBox.warning(self, "Media test found a problem", details)
        self.refresh_devices()

    def on_inspection_finished(self, identity: object, result: object) -> None:
        if not self.image:
            return
        try:
            current_identity = image_identity(self.image)
        except OSError:
            return
        if identity != current_identity:
            return
        if isinstance(result, Exception):
            self.logger.warning("Image inspection failed: %s", result)
            self.inspection = None
            self.inspection_identity = None
            self.write_recommendation = None
            self.write_method.clear()
            self.write_method.setEnabled(False)
            self.write_method_reason.setText("Image inspection did not complete.")
            self.image_detail.setText(f"Could not inspect image: {result}")
        else:
            self.inspection = result  # type: ignore[assignment]
            self.inspection_identity = identity
            self.logger.info("Image inspection: %s", self.inspection.summary)
            if self.inspection.compression != "none":
                self.image_label.setText(
                    f"{self.image.name}  ·  {format_size(self.inspection.size)} expanded"
                )
            elif self.inspection.virtual_format:
                self.image_label.setText(
                    f"{self.image.name}  ·  {format_size(self.inspection.size)} virtual "
                    f"({format_size(self.inspection.container_size)} container)"
                )
            self.image_detail.setText(f"DD mode · {self.inspection.summary}")
            detail_lines = [
                f"Layout: {self.inspection.layout}",
                f"Boot modes: {', '.join(self.inspection.boot_modes) or 'not detected'}",
                f"Architectures: {', '.join(self.inspection.architectures) or 'not detected'}",
                f"Bootloader: {self.inspection.bootloader}",
            ]
            if self.inspection.bootloader_build:
                detail_lines.append(
                    f"Exact boot payload: {self.inspection.bootloader_build} "
                    f"({self.inspection.bootloader_dependency})"
                )
            elif self.inspection.bootloader_identity_ambiguous:
                detail_lines.append("Bootloader identity conflicts across image members")
            elif self.inspection.bootloader_version:
                detail_lines.append(
                    f"Bootloader version {self.inspection.bootloader_version}; exact build unknown"
                )
            if self.inspection.has_windows_installer:
                detail_lines.append("Windows installer image detected")
                candidates = tuple(
                    member for member in self.inspection.members
                    if member.kind == "file" and member.path.casefold() in {
                        "sources/install.wim", "sources/install.esd",
                    }
                )
                if len(candidates) == 1:
                    member = candidates[0]
                    self.windows_wim_member = ArchiveEntry(member.path, member.size)
                    self.windows_wim_error = ""
                    self.windows_button.setToolTip(
                        f"Inspect {member.path} to list its Windows image indexes"
                    )
                else:
                    self.windows_wim_member = None
                    self.windows_wim_error = (
                        "The ISO catalog does not contain exactly one "
                        "sources/install.wim or sources/install.esd."
                    )
                    self.windows_button.setToolTip(self.windows_wim_error)
            if self.inspection.eltorito is not None:
                platforms = ", ".join(
                    platform.display_name
                    for platform in self.inspection.eltorito.bootable_platforms
                ) or "no bootable entries"
                detail_lines.append(
                    f"El Torito catalog: LBA {self.inspection.eltorito.catalog_lba}; "
                    f"{platforms}"
                )
            if self.inspection.eltorito_issues:
                detail_lines.append(
                    "El Torito catalog issue: "
                    + "; ".join(self.inspection.eltorito_issues)
                )
            if self.inspection.uefi_payloads:
                detail_lines.append("UEFI payload structure (signatures are not trust-validated):")
                detail_lines.extend(
                    f"  {payload.path}: {payload.architecture}, "
                    f"certificate {payload.signature_state.value}, SBAT {payload.sbat_state.value}"
                    for payload in self.inspection.uefi_payloads[:8]
                )
            if self.inspection.uefi_analysis_issues:
                detail_lines.append(
                    f"UEFI inspection issues: {len(self.inspection.uefi_analysis_issues)}"
                )
            if not self.inspection.contents_scanned:
                detail_lines.append("Install 7-Zip for deeper content inspection")
            self.image_detail.setToolTip("\n".join(detail_lines))
            self.windows_button.setEnabled(self.inspection.has_windows_installer)
            self.iso_plan_button.setEnabled(self.inspection.is_iso9660)
            self.checksum_button.setEnabled(True)
            self.rebuild_write_recommendation(preserve_selection=False)
        self.update_ready()

    def start_windows_wim_inspection(self) -> None:
        image = self.image
        member = self.windows_wim_member
        if image is None or member is None or self.operation_active:
            return
        try:
            identity = image_identity(image)
        except OSError as error:
            self.windows_wim_error = str(error)
            return
        self.windows_wim_extractor = SafeIsoExtractor()
        self.set_busy(True)
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        self.status.setText(f"Inspecting Windows editions in {member.path}…")
        self.windows_button.setText("Inspecting Windows editions…")

        def work() -> None:
            result: object
            try:
                with tempfile.TemporaryDirectory(prefix=".isopropyl-wim-info-") as directory:
                    destination = Path(directory) / "image"
                    plan = build_extraction_plan(image, destination, (member,))
                    assert self.windows_wim_extractor is not None
                    self.windows_wim_extractor.execute(
                        plan,
                        lambda update: self.bridge.progress.emit(
                            update.bytes_done, update.total_bytes,
                            "Extracting Windows image metadata source",
                        ),
                    )
                    source = destination.joinpath(*Path(member.path).parts)
                    info = inspect_wim(
                        source,
                        cancel_event=self.windows_wim_extractor.cancel_event,
                    )
                    if info.size != member.size:
                        raise RuntimeError(
                            "The extracted WIM/ESD size does not match the ISO catalog"
                        )
                    if image_identity(image) != identity:
                        raise RuntimeError("The ISO changed while Windows editions were inspected")
                    result = info
            except Exception as error:
                result = error
            self.bridge.windows_metadata_finished.emit(identity, member.path, result)

        threading.Thread(target=work, daemon=True).start()

    def on_windows_metadata_finished(
        self, identity: object, source_name: object, result: object,
    ) -> None:
        self.windows_wim_extractor = None
        self.windows_button.setText("Windows options…")
        self.progress.setValue(0)
        self.set_busy(False)
        self.update_ready()
        if self.image is None or self.windows_wim_member is None:
            return
        try:
            current_identity = image_identity(self.image)
        except OSError:
            return
        if (
            identity != current_identity
            or source_name != self.windows_wim_member.path
        ):
            return
        if isinstance(result, Exception) or not isinstance(result, WimInfo):
            self.windows_wim_editions = ()
            if self.windows_options.install_image is not None:
                self.windows_options = replace(
                    self.windows_options, install_image=None,
                )
            self.windows_wim_error = (
                str(result) if isinstance(result, Exception)
                else "The WIM inspector returned invalid metadata"
            )
            self.windows_button.setToolTip(
                f"Windows edition metadata unavailable: {self.windows_wim_error}"
            )
            self.status.setText(
                f"Windows edition inspection failed: {self.windows_wim_error}"
            )
            return
        info = result
        self.windows_wim_editions = info.editions
        self.windows_wim_error = ""
        current_selection = self.windows_options.install_image
        if current_selection is not None and (
            current_selection.source_name != self.windows_wim_member.path
            or current_selection.source_size != self.windows_wim_member.size
            or current_selection.editions != info.editions
        ):
            self.windows_options = replace(self.windows_options, install_image=None)
        labels = "\n".join(edition.display_label for edition in info.editions)
        self.windows_button.setToolTip(labels)
        self.status.setText(
            f"Found {len(info.editions)} Windows installation image"
            f"{'s' if len(info.editions) != 1 else ''}"
        )

    def calculate_image_checksums(self) -> None:
        if not self.image or self.checksum_busy:
            return
        path = self.image
        identity = image_identity(path)
        self.checksum_busy = True
        self.checksum_button.setText("Calculating…")
        self.checksum_button.setEnabled(False)
        self.progress.setValue(0)
        self.update_ready()

        def work() -> None:
            try:
                result: object = calculate_checksums(
                    path, lambda done, total: self.bridge.progress.emit(done, total, "Checksumming")
                )
            except Exception as error:
                result = error
            self.bridge.checksums_finished.emit(identity, result)

        threading.Thread(target=work, daemon=True).start()

    def on_checksums_finished(self, identity: object, result: object) -> None:
        self.checksum_busy = False
        self.checksum_button.setText("Checksums…")
        self.progress.setValue(0)
        self.update_ready()
        if not self.image:
            return
        try:
            if identity != image_identity(self.image):
                return
        except OSError:
            return
        if isinstance(result, Exception):
            QMessageBox.critical(self, "Checksum calculation failed", str(result))
            return
        checksums: dict[str, str] = result  # type: ignore[assignment]
        dialog = QDialog(self)
        dialog.setWindowTitle("Image checksums")
        dialog.resize(700, 480)
        layout = QVBoxLayout(dialog)
        title = QLabel(f"Checksums for {self.image.name}")
        title.setObjectName("cardTitle")
        layout.addWidget(title)
        details = QPlainTextEdit()
        details.setReadOnly(True)
        details.setPlainText("\n\n".join(
            f"{name}\n{value}" for name, value in checksums.items()
        ))
        layout.addWidget(details)
        prompt = QLabel("Paste the checksum published by the image provider")
        prompt.setObjectName("muted")
        layout.addWidget(prompt)
        expected = QLineEdit()
        expected.setPlaceholderText("MD5, SHA-1, SHA-256, or SHA-512")
        layout.addWidget(expected)
        comparison = QLabel("Waiting for a checksum")
        comparison.setObjectName("muted")
        layout.addWidget(comparison)

        def compare() -> None:
            if not expected.text().strip():
                comparison.setText("Waiting for a checksum")
                comparison.setStyleSheet("")
                return
            try:
                algorithm, matches = compare_expected_checksum(checksums, expected.text())
            except ValueError as error:
                comparison.setText(str(error))
                comparison.setStyleSheet("color: #ffb86c;")
                return
            if matches:
                comparison.setText(f"✓ {algorithm} matches the selected image")
                comparison.setStyleSheet("color: #63d79b; font-weight: 650;")
            else:
                comparison.setText(
                    f"✗ {algorithm} does not match — do not write this image"
                )
                comparison.setStyleSheet("color: #ff6b6b; font-weight: 650;")

        expected.textChanged.connect(compare)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        copy_button = buttons.addButton("Copy all", QDialogButtonBox.ButtonRole.ActionRole)
        copy_button.clicked.connect(
            lambda: QApplication.clipboard().setText(details.toPlainText())
        )
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()

    def preview_iso_plan(self) -> None:
        if not self.inspection or not self.inspection.is_iso9660:
            return
        kind = {
            "file": EntryKind.FILE,
            "directory": EntryKind.DIRECTORY,
            "symlink": EntryKind.SYMLINK,
        }
        entries = [
            ArchiveEntry(
                member.path, member.size, kind.get(member.kind, EntryKind.FILE),
                member.link_target or None,
            )
            for member in self.inspection.members
        ]
        try:
            plan = build_write_plan(
                self.inspection, entries, requested_mode=WriteMode.EXTRACTED_ISO,
                firmware_target=FirmwareTarget.UEFI_ONLY,
                target_size=self.selected_device().size if self.selected_device() else None,
            )
        except ValueError as error:
            QMessageBox.warning(self, "ISO plan could not be built", str(error))
            return
        assert plan.layout is not None
        lines = [
            "Filesystem-aware UEFI ISO mode", "",
            f"Partition table: {plan.layout.partition_table.value.upper()}",
            f"Main filesystem: {plan.layout.main_filesystem.value.upper()}",
            f"Partitions: {plan.layout.partition_count}",
            f"Firmware: {'BIOS ' if plan.layout.bios_bootable else ''}"
            f"{'UEFI' if plan.layout.uefi_bootable else ''}".strip(),
            f"Cataloged files: {len(entries)}",
            f"File content: {format_size(plan.minimum_content_bytes)}",
            f"Conservative target minimum: {format_size(plan.minimum_target_bytes)}",
        ]
        if plan.needs_wim_split:
            lines.append("Transformation: split sources/install.wim for FAT32")
        if self.windows_options.install_image is not None:
            lines.append(
                f"Windows image: {self.windows_options.install_image.display_label}"
            )
        lines.extend(("", "Dependencies:"))
        lines.extend(
            f"• {requirement.key}: {', '.join(requirement.alternatives)}"
            for requirement in plan.requirements
        )
        lines.extend(("", "Execution blockers:"))
        lines.extend(f"• {blocker}" for blocker in plan.blockers)
        dialog = QDialog(self)
        dialog.setWindowTitle("Extracted ISO plan")
        dialog.resize(720, 560)
        layout = QVBoxLayout(dialog)
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setPlainText("\n".join(lines))
        layout.addWidget(text)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        copy_button = buttons.addButton("Copy", QDialogButtonBox.ButtonRole.ActionRole)
        copy_button.clicked.connect(lambda: QApplication.clipboard().setText(text.toPlainText()))
        extract_button = buttons.addButton(
            "Extract safely…", QDialogButtonBox.ButtonRole.ActionRole
        )

        def extract() -> None:
            assert self.image is not None
            parent = QFileDialog.getExistingDirectory(
                dialog, "Choose a parent folder for extracted ISO files", str(Path.home())
            )
            if not parent:
                return
            destination = Path(parent) / f"{self.image.stem}-extracted"
            dialog.accept()
            QTimer.singleShot(
                0, lambda: self.start_iso_extraction(entries, destination)
            )

        extract_button.clicked.connect(extract)
        write_iso_button = buttons.addButton(
            "Write USB in ISO mode…", QDialogButtonBox.ButtonRole.ActionRole
        )
        write_iso_button.setEnabled(
            plan.executable and self.selected_device() is not None
        )
        if plan.executable:
            if plan.layout.boot_strategy is BootStrategy.UEFI_NTFS:
                write_iso_button.setToolTip(
                    "Stage the ISO privately, then create and verify an NTFS USB "
                    "with a pinned UEFI:NTFS boot bridge."
                )
            else:
                write_iso_button.setToolTip(
                    "Stage the ISO privately, then create and verify a UEFI/FAT32 USB."
                )
        else:
            write_iso_button.setToolTip(
                "This image does not yet have an executable ISO-mode plan."
            )

        def write_iso() -> None:
            dialog.accept()
            QTimer.singleShot(
                0, lambda: self.start_constructed_iso_write(entries, plan)
            )

        write_iso_button.clicked.connect(write_iso)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()

    def start_constructed_iso_write(
        self, entries: list[ArchiveEntry], write_plan: WritePlan,
    ) -> None:
        image = self.image
        inspection = self.inspection
        device = self.selected_device()
        if (
            image is None or inspection is None or device is None
            or self.operation_active or not write_plan.executable
        ):
            return
        if image_is_on_device(str(image), device):
            QMessageBox.critical(
                self, "Move the ISO first",
                "The selected ISO is stored on the target drive and would be erased. "
                "Move it to another disk before using ISO mode.",
            )
            return
        if not device.removable:
            warning = QMessageBox.warning(
                self, "External hard drive or SSD selected",
                "This target reports itself as a fixed disk. Confirm that it is not "
                "a backup drive or another disk containing important data.\n\nContinue?",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if warning != QMessageBox.StandardButton.Yes:
                return
        working_parent = QFileDialog.getExistingDirectory(
            self,
            "Choose temporary working space for ISO mode",
            str(Path.home()),
        )
        if not working_parent:
            return
        workspace: tempfile.TemporaryDirectory[str] | None = None
        try:
            workspace = tempfile.TemporaryDirectory(
                prefix=".isopropyl-iso-", dir=working_parent,
            )
            staging_destination = Path(workspace.name) / "ready-media"
            staging_plan = build_iso_staging_plan(
                image,
                staging_destination,
                entries,
                write_plan,
                windows_customization=self.windows_options,
                windows_architecture=(
                    self.windows_options.install_image.edition.architecture
                    if self.windows_options.install_image is not None else
                    windows_architecture(inspection.architectures)
                ),
            )
        except Exception as error:
            if workspace is not None:
                try:
                    workspace.cleanup()
                except OSError as cleanup_error:
                    self.logger.warning(
                        "Could not remove rejected ISO workspace: %s", cleanup_error,
                    )
            QMessageBox.warning(self, "ISO mode unavailable", str(error))
            return

        assert write_plan.layout is not None
        strategy = write_plan.layout.boot_strategy
        pending = PendingIsoWrite(
            image, inspection, device, write_plan, workspace, staging_plan,
        )
        if strategy is BootStrategy.UEFI_NTFS:
            helper_answer = QMessageBox.question(
                self,
                "Prepare the verified UEFI:NTFS boot helper?",
                "This image needs NTFS because it contains a file larger than FAT32 "
                "can store. ISOpropyl will obtain the 1 MiB UEFI:NTFS v2.8 helper "
                "from a release-pinned Rufus source URL (or use its verified cache), "
                "then check its exact size and SHA-256 before asking to erase the "
                "drive.\n\n"
                "The x64, x86, and ARM64 payloads are signed through Microsoft UEFI "
                "CA 2011. Secure Boot can still reject them on systems that disable "
                "third-party trust or revoke that certificate.\n\nContinue?",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Yes,
            )
            if helper_answer != QMessageBox.StandardButton.Yes:
                try:
                    workspace.cleanup()
                except OSError as error:
                    self.logger.warning("Could not remove ISO workspace: %s", error)
                return
            self.start_uefi_preparation(pending)
            return
        self.confirm_and_start_iso_write(pending, None, None)

    def start_uefi_preparation(self, pending: PendingIsoWrite) -> None:
        preparer = BackgroundPreparation()
        self.pending_iso_write = pending
        self.uefi_preparer = preparer
        self.set_busy(True)
        self.progress.setRange(0, 0)
        self.status.setText(
            "Checking the target and obtaining the verified UEFI:NTFS helper…"
        )

        def work() -> None:
            try:
                logical_sector_size = probe_uefi_ntfs_logical_sector_size(
                    pending.device
                )
                if preparer.cancelled:
                    raise UefiNtfsCancelled(
                        "UEFI:NTFS helper preparation was cancelled"
                    )
                artifact = prepare_uefi_ntfs_artifact(
                    cancel_event=preparer.cancel_event
                )
                if preparer.cancelled:
                    raise UefiNtfsCancelled(
                        "UEFI:NTFS helper preparation was cancelled"
                    )
                self.bridge.uefi_preparation_finished.emit(
                    preparer, (artifact, logical_sector_size), None,
                )
            except Exception as error:
                self.bridge.uefi_preparation_finished.emit(
                    preparer, None, error,
                )

        threading.Thread(target=work, daemon=True).start()

    def on_uefi_preparation_finished(
        self,
        preparer: BackgroundPreparation,
        result: object,
        error: object,
    ) -> None:
        if preparer is not self.uefi_preparer:
            return
        pending = self.pending_iso_write
        self.uefi_preparer = None
        self.pending_iso_write = None
        self.progress.setRange(0, 1000)
        if pending is None:
            self.set_busy(False)
            return
        if error is not None or preparer.cancelled:
            try:
                pending.workspace.cleanup()
            except OSError as cleanup_error:
                self.logger.warning(
                    "Could not remove cancelled ISO workspace: %s", cleanup_error,
                )
            self.set_busy(False)
            if preparer.cancelled:
                message = "UEFI:NTFS helper preparation was cancelled"
                self.logger.info(message)
                self.status.setText(message)
            else:
                message = str(error)
                self.logger.warning("UEFI:NTFS preparation failed: %s", message)
                self.status.setText("ISO mode is not active")
                QMessageBox.warning(
                    self, "Verified boot helper unavailable", message,
                )
            return
        if (
            not isinstance(result, tuple)
            or len(result) != 2
            or not isinstance(result[0], BoundArtifact)
            or result[1] != 512
        ):
            try:
                pending.workspace.cleanup()
            except OSError as cleanup_error:
                self.logger.warning(
                    "Could not remove rejected ISO workspace: %s", cleanup_error,
                )
            self.set_busy(False)
            self.status.setText("ISO mode is not active")
            QMessageBox.warning(
                self,
                "Verified boot helper unavailable",
                "The background safety check returned an invalid result.",
            )
            return
        artifact, logical_sector_size = result
        self.status.setText("Verified UEFI:NTFS boot helper is ready")
        self.confirm_and_start_iso_write(
            pending, artifact, logical_sector_size,
        )

    def confirm_and_start_iso_write(
        self,
        pending: PendingIsoWrite,
        artifact: BoundArtifact | None,
        logical_sector_size: int | None,
    ) -> None:
        image = pending.image
        inspection = pending.inspection
        device = pending.device
        write_plan = pending.write_plan
        workspace = pending.workspace
        staging_plan = pending.staging_plan
        assert write_plan.layout is not None
        strategy = write_plan.layout.boot_strategy
        if strategy is BootStrategy.UEFI_NTFS and (
            artifact is None or logical_sector_size != 512
        ):
            try:
                workspace.cleanup()
            except OSError as error:
                self.logger.warning("Could not remove ISO workspace: %s", error)
            self.set_busy(False)
            QMessageBox.warning(
                self,
                "Verified boot helper unavailable",
                "UEFI:NTFS requires a verified helper and a freshly observed "
                "512-byte logical sector size.",
            )
            return

        customization = (
            "\nWindows customization: autounattend.xml will be added."
            if self.windows_options.enabled else ""
        )
        if self.windows_options.install_image is not None:
            customization += (
                "\nWindows image: "
                f"{self.windows_options.install_image.display_label}."
            )
        if strategy is BootStrategy.UEFI_NTFS:
            mode_description = (
                "UEFI-only · GPT · NTFS + verified UEFI:NTFS bridge · "
                "full file and bridge read-back verification"
            )
            customization += (
                "\nSecure Boot note: the bridge depends on Microsoft UEFI CA 2011 "
                "third-party trust."
            )
        else:
            mode_description = (
                "UEFI-only · GPT · FAT32 · full file read-back verification"
            )
        answer = QMessageBox.warning(
            self,
            "Erase drive and write in ISO mode?",
            f"Everything on {device.label} will be permanently erased.\n\n"
            f"Image: {image.name}\n"
            f"Mode: {mode_description}\n"
            f"Target: {device.path}\n"
            f"Serial: {device.serial or device.wwn or 'not reported'}\n"
            f"Temporary space required: {format_size(staging_plan.required_free_bytes)}"
            f"{customization}\n\n"
            "Keep the image, working disk, and target connected until completion.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            try:
                workspace.cleanup()
            except OSError as error:
                self.logger.warning("Could not remove ISO workspace: %s", error)
            self.set_busy(False)
            self.status.setText("ISO mode is not active")
            return

        self.iso_workspace = workspace
        self.iso_stager = IsoStagingExecutor()
        if strategy is BootStrategy.UEFI_NTFS:
            self.uefi_ntfs_writer = UefiNtfsExecutor()
        else:
            self.constructed_writer = ConstructedMediaExecutor()
        self.set_busy(True)
        self.progress.setValue(0)
        self.status.setText("Preparing ISO-mode staging…")
        self.logger.info(
            "Confirmed ISO-mode write: image=%s target=%s identity=%s",
            image, device.path, device.identity,
        )

        def work() -> None:
            success = False
            message = "ISO-mode operation did not complete"
            try:
                assert self.iso_stager is not None
                staged = self.iso_stager.execute(
                    staging_plan,
                    lambda update: self.bridge.progress.emit(
                        update.bytes_done, update.total_bytes, update.stage,
                    ),
                )
                partition_table = FormatPartitionTable(
                    write_plan.layout.partition_table.value  # type: ignore[union-attr]
                )
                if strategy is BootStrategy.UEFI_NTFS:
                    assert artifact is not None
                    assert self.uefi_ntfs_writer is not None
                    target_plan = build_uefi_ntfs_media_plan(
                        staged.destination,
                        device,
                        partition_table,
                        inspection.architectures,
                        artifact,
                        volume_label="ISOPROPYL",
                        logical_sector_size=logical_sector_size,
                    )
                    result = self.uefi_ntfs_writer.execute(
                        target_plan,
                        lambda update: self.bridge.progress.emit(
                            update.bytes_done, update.total_bytes,
                            update.stage + (
                                f" · {update.relative_path}"
                                if update.relative_path else ""
                            ),
                        ),
                    )
                else:
                    assert self.constructed_writer is not None
                    target_plan = build_constructed_media_plan(
                        staged.destination,
                        device,
                        partition_table,
                        volume_label="ISOPROPYL",
                    )
                    result = self.constructed_writer.execute(
                        target_plan,
                        lambda update: self.bridge.progress.emit(
                            update.bytes_done, update.total_bytes,
                            update.stage + (
                                f" · {update.relative_path}"
                                if update.relative_path else ""
                            ),
                        ),
                    )
                message = (
                    "Your UEFI bootable USB is ready and safely powered off. "
                    "You can remove it."
                    if result.powered_off else
                    "Your UEFI bootable USB is ready. Eject it with your desktop "
                    "before removing it."
                )
                success = True
            except (
                IsoStagingCancelled, ConstructedMediaCancelled, UefiNtfsCancelled,
            ) as error:
                self.logger.info("ISO-mode operation cancelled: %s", error)
                message = str(error)
            except Exception as error:
                self.logger.exception("ISO-mode write failed")
                message = str(error)
            finally:
                try:
                    workspace.cleanup()
                except OSError as error:
                    self.logger.warning("Could not remove ISO workspace: %s", error)
                    message += " Temporary workspace cleanup was incomplete."
                self.bridge.finished.emit(success, message)

        threading.Thread(target=work, daemon=True).start()

    def start_iso_extraction(
        self, entries: list[ArchiveEntry], destination: Path,
    ) -> None:
        if not self.image or self.operation_active:
            return
        try:
            plan = build_extraction_plan(self.image, destination, entries)
        except Exception as error:
            QMessageBox.warning(self, "ISO extraction unavailable", str(error))
            return
        answer = QMessageBox.question(
            self,
            "Extract ISO files?",
            f"Safely extract {len(plan.entries)} cataloged members "
            f"({format_size(plan.content_bytes)} of file data) to:\n\n"
            f"{plan.destination}\n\n"
            "The source ISO and removable drives will not be modified. The destination "
            "must remain absent until extraction completes. Windows options are applied "
            "only by the private, atomically published ISO-to-USB staging workflow.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.extractor = SafeIsoExtractor()
        self.set_busy(True)
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        self.status.setText("Preparing safe ISO extraction…")

        def work() -> None:
            try:
                assert self.extractor is not None
                result = self.extractor.execute(
                    plan,
                    lambda update: self.bridge.progress.emit(
                        update.bytes_done, update.total_bytes, "Extracting ISO"
                    ),
                )
                self.logger.info(
                    "ISO extraction complete: image=%s destination=%s files=%s bytes=%s",
                    plan.image, result.destination, result.files, result.bytes_written,
                )
                self.bridge.finished.emit(
                    True,
                    f"ISO files safely extracted to {result.destination}",
                )
            except ExtractionCancelled as error:
                self.bridge.finished.emit(False, str(error))
            except Exception as error:
                self.logger.exception("ISO extraction failed")
                self.bridge.finished.emit(False, str(error))

        threading.Thread(target=work, daemon=True).start()

    def show_log(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("ISOpropyl activity log")
        dialog.resize(760, 460)
        layout = QVBoxLayout(dialog)
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setPlainText(read_log())
        text.moveCursor(QTextCursor.MoveOperation.End)
        layout.addWidget(text)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        copy_button = buttons.addButton("Copy", QDialogButtonBox.ButtonRole.ActionRole)
        copy_button.clicked.connect(lambda: QApplication.clipboard().setText(text.toPlainText()))
        export_button = buttons.addButton(
            "Export diagnostics…", QDialogButtonBox.ButtonRole.ActionRole
        )

        def export_diagnostics() -> None:
            privacy = QMessageBox.question(
                dialog,
                "Include identifying details?",
                "By default ISOpropyl omits serial numbers, WWNs, mount paths, ISO member "
                "names, and log contents. Include device identifiers and the visible "
                "activity log in this report?",
                QMessageBox.StandardButton.No | QMessageBox.StandardButton.Yes |
                QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.No,
            )
            if privacy == QMessageBox.StandardButton.Cancel:
                return
            filename, _ = QFileDialog.getSaveFileName(
                dialog, "Export ISOpropyl diagnostics", "isopropyl-diagnostics.json",
                "JSON files (*.json)",
            )
            if not filename:
                return
            try:
                include = privacy == QMessageBox.StandardButton.Yes
                report = build_diagnostics(
                    self.devices, self.inspection, include_identifiers=include,
                    log_text=text.toPlainText() if include else None,
                )
                write_diagnostics(Path(filename), report)
            except Exception as error:
                QMessageBox.critical(dialog, "Diagnostics export failed", str(error))
                return
            QMessageBox.information(dialog, "Diagnostics exported", f"Saved {filename}")

        export_button.clicked.connect(export_diagnostics)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()

    def show_settings(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("ISOpropyl settings")
        dialog.setMinimumWidth(440)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("Appearance"))
        theme = QComboBox()
        theme.addItem("Dark", "dark")
        theme.addItem("Light", "light")
        current = str(self.settings.value("appearance", "dark"))
        theme.setCurrentIndex(max(0, theme.findData(current)))
        layout.addWidget(theme)
        layout.addWidget(QLabel("Ignored drives"))
        ignored = self.ignored_devices()
        ignored_text = QPlainTextEdit()
        ignored_text.setReadOnly(True)
        ignored_text.setMaximumHeight(100)
        ignored_text.setPlainText("\n".join(ignored.values()) or "No drives are hidden")
        layout.addWidget(ignored_text)
        clear_ignored = QPushButton("Clear ignored-drive list")
        clear_ignored.setEnabled(bool(ignored))
        layout.addWidget(clear_ignored)
        reset_all = QPushButton("Reset all ISOpropyl settings")
        layout.addWidget(reset_all)
        clear_requested = False
        reset_requested = False

        def clear() -> None:
            nonlocal clear_requested
            clear_requested = True
            ignored_text.setPlainText("Ignored-drive list will be cleared when saved")
            clear_ignored.setEnabled(False)

        clear_ignored.clicked.connect(clear)

        def reset() -> None:
            nonlocal reset_requested, clear_requested
            answer = QMessageBox.question(
                dialog,
                "Reset all settings?",
                "Reset appearance and the ignored-drive list when you save? "
                "No images, logs, or drive contents are removed.",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            reset_requested = True
            clear_requested = True
            theme.setCurrentIndex(max(0, theme.findData("dark")))
            ignored_text.setPlainText("All settings will be reset when saved")
            clear_ignored.setEnabled(False)
            reset_all.setEnabled(False)

        reset_all.clicked.connect(reset)
        note = QLabel(
            "Drive visibility and destructive confirmations are deliberately not saved."
        )
        note.setWordWrap(True)
        note.setObjectName("muted")
        layout.addWidget(note)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel
        )
        layout.addWidget(buttons)

        def save() -> None:
            selected = str(theme.currentData())
            if reset_requested:
                self.settings.clear()
                selected = "dark"
            else:
                self.settings.setValue("appearance", selected)
            if clear_requested and not reset_requested:
                self.settings.remove("ignored_devices")
            QApplication.instance().setStyleSheet(THEMES[selected])
            dialog.accept()
            if clear_requested:
                self.refresh_devices()

        buttons.accepted.connect(save)
        buttons.rejected.connect(dialog.reject)
        dialog.exec()

    def configure_windows(self) -> None:
        if not self.inspection or not self.inspection.has_windows_installer:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Windows installation options")
        dialog.resize(700, 650)
        layout = QVBoxLayout(dialog)
        notice = QLabel(
            "These options generate an auditable autounattend.xml profile. "
            "ISOpropyl does not apply it in raw-write mode yet; export it for inspection "
            "or use it with filesystem-aware Windows media."
        )
        notice.setWordWrap(True)
        notice.setObjectName("muted")
        layout.addWidget(notice)
        tabs = QTabWidget()
        setup_tab = QWidget()
        setup_layout = QVBoxLayout(setup_tab)
        regional_tab = QWidget()
        regional_form = QFormLayout(regional_tab)
        tabs.addTab(setup_tab, "Setup and account")
        tabs.addTab(regional_tab, "Region and keyboard")
        layout.addWidget(tabs)

        image_heading = QLabel("Windows edition")
        image_heading.setObjectName("cardTitle")
        image_combo = QComboBox()
        image_combo.addItem("Ask during Windows Setup (no preselection)", None)
        current = self.windows_options
        available_editions = self.windows_wim_editions
        if (
            not available_editions and current.install_image is not None
            and self.windows_wim_member is not None
            and current.install_image.source_name == self.windows_wim_member.path
            and current.install_image.source_size == self.windows_wim_member.size
        ):
            available_editions = current.install_image.editions
        for edition in available_editions:
            image_combo.addItem(edition.display_label, edition.index)
        image_combo.setEnabled(bool(available_editions))
        if current.install_image is not None:
            selected_row = image_combo.findData(current.install_image.selected_index)
            image_combo.setCurrentIndex(max(0, selected_row))
        image_detail = QLabel()
        image_detail.setWordWrap(True)
        image_detail.setObjectName("muted")

        def update_image_detail() -> None:
            index = image_combo.currentData()
            edition = next(
                (item for item in available_editions if item.index == index), None,
            )
            if edition is not None:
                image_detail.setText(
                    f"Edition ID: {edition.edition_id} · architecture: "
                    f"{edition.architecture.upper()} · Windows "
                    f"{edition.major_version}.{edition.minor_version} · "
                    f"build {edition.version}"
                    + (f"\n{edition.description}" if edition.description else "")
                )
            elif self.windows_wim_error:
                image_detail.setText(
                    f"Edition metadata is unavailable: {self.windows_wim_error}"
                )
            elif self.windows_wim_member is not None and not available_editions:
                image_detail.setText(
                    f"Inspecting editions temporarily extracts "
                    f"{format_size(self.windows_wim_member.size)} from the ISO. "
                    "The private copy is deleted immediately afterward."
                )
            else:
                image_detail.setText(
                    "No edition is preselected; Windows Setup will ask when applicable."
                )

        image_combo.currentIndexChanged.connect(update_image_detail)
        inspect_editions = QPushButton(
            "Refresh edition metadata…" if available_editions
            else "Inspect WIM/ESD editions…"
        )
        inspect_editions.setEnabled(self.windows_wim_member is not None)
        if self.windows_wim_member is not None:
            inspect_editions.setToolTip(
                f"Temporarily extract {format_size(self.windows_wim_member.size)} from "
                "the ISO, inspect it with trusted wimlib-imagex, then delete the copy."
            )
        elif self.windows_wim_error:
            inspect_editions.setToolTip(self.windows_wim_error)
        setup_layout.addWidget(image_heading)
        setup_layout.addWidget(image_combo)
        setup_layout.addWidget(image_detail)
        setup_layout.addWidget(inspect_editions)
        update_image_detail()

        bypass = QCheckBox("Remove Windows 11 RAM, Secure Boot, and TPM 2.0 setup checks")
        online = QCheckBox("Hide the online Microsoft account screen")
        privacy = QCheckBox("Reduce setup data collection (skip Express privacy settings)")
        bitlocker = QCheckBox("Prevent automatic BitLocker device encryption")
        local = QCheckBox("Create a local administrator account")
        username = QLineEdit()
        username.setPlaceholderText("Local account name")
        password_change = QCheckBox(
            "Mandatory: require the local user to set a password after setup"
        )
        password_never_expires = QCheckBox("Do not expire that replacement password")

        def set_local_controls(enabled: bool) -> None:
            username.setEnabled(enabled)
            password_change.setChecked(True)
            password_change.setEnabled(False)
            password_never_expires.setEnabled(enabled)

        local.toggled.connect(set_local_controls)
        for checkbox in (bypass, online, privacy, bitlocker, local):
            setup_layout.addWidget(checkbox)
        setup_layout.addWidget(username)
        setup_layout.addWidget(password_change)
        setup_layout.addWidget(password_never_expires)
        account_note = QLabel(
            "ISOpropyl exports no secret. The local account starts with a blank password; "
            "a mandatory first-logon command marks it for replacement after setup. "
            "Do not use this option for Windows S mode, where first-logon commands do "
            "not run. Review the generated XML before use."
        )
        account_note.setWordWrap(True)
        account_note.setObjectName("muted")
        setup_layout.addWidget(account_note)
        setup_layout.addStretch()

        input_locale = QLineEdit()
        input_locale.setPlaceholderText("For example: 0409:00000409 or en-US")
        system_locale = QLineEdit()
        system_locale.setPlaceholderText("For example: en-US")
        ui_language = QLineEdit()
        ui_language.setPlaceholderText("For example: en-US")
        user_locale = QLineEdit()
        user_locale.setPlaceholderText("For example: en-US")
        timezone = QLineEdit()
        timezone.setPlaceholderText("For example: Eastern Standard Time")
        regional_form.addRow("Keyboard/input locale", input_locale)
        regional_form.addRow("System locale", system_locale)
        regional_form.addRow("UI language", ui_language)
        regional_form.addRow("User locale", user_locale)
        regional_form.addRow("Windows time zone", timezone)
        regional_note = QLabel(
            "Leave a field blank to let Windows Setup choose it. Time-zone names use "
            "Windows terminology, not Linux IANA names."
        )
        regional_note.setWordWrap(True)
        regional_note.setObjectName("muted")
        regional_form.addRow(regional_note)
        bypass.setChecked(current.bypass_hardware_requirements)
        online.setChecked(current.hide_online_account)
        privacy.setChecked(current.reduce_data_collection)
        bitlocker.setChecked(current.disable_automatic_bitlocker)
        local.setChecked(bool(current.local_username))
        username.setText(current.local_username)
        password_change.setChecked(current.require_local_password_change)
        password_never_expires.setChecked(current.local_password_never_expires)
        input_locale.setText(current.input_locale)
        system_locale.setText(current.system_locale)
        ui_language.setText(current.ui_language)
        user_locale.setText(current.user_locale)
        timezone.setText(current.timezone)
        set_local_controls(local.isChecked())
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel
        )
        export_button = buttons.addButton("Export XML…", QDialogButtonBox.ButtonRole.ActionRole)
        layout.addWidget(buttons)

        def selected() -> WindowsCustomization:
            install_image = None
            selected_index = image_combo.currentData()
            if selected_index is not None:
                if self.windows_wim_member is None or not available_editions:
                    raise ValueError("Windows edition metadata is no longer available")
                install_image = WimSelection(
                    self.windows_wim_member.path,
                    self.windows_wim_member.size,
                    available_editions,
                    int(selected_index),
                )
            return WindowsCustomization(
                bypass_hardware_requirements=bypass.isChecked(),
                hide_online_account=online.isChecked(),
                local_username=username.text() if local.isChecked() else "",
                reduce_data_collection=privacy.isChecked(),
                disable_automatic_bitlocker=bitlocker.isChecked(),
                input_locale=input_locale.text(),
                system_locale=system_locale.text(),
                ui_language=ui_language.text(),
                user_locale=user_locale.text(),
                timezone=timezone.text(),
                require_local_password_change=password_change.isChecked(),
                local_password_never_expires=password_never_expires.isChecked(),
                install_image=install_image,
            )

        def profile_architecture(options: WindowsCustomization) -> str:
            if options.install_image is not None:
                return options.install_image.edition.architecture
            return windows_architecture(self.inspection.architectures)

        def export_xml() -> None:
            try:
                options = selected()
                xml = generate_autounattend(
                    options, profile_architecture(options)
                )
            except ValueError as error:
                QMessageBox.warning(dialog, "Invalid Windows options", str(error))
                return
            filename, _ = QFileDialog.getSaveFileName(
                dialog, "Export Windows answer file", "autounattend.xml", "XML files (*.xml)"
            )
            if filename:
                try:
                    Path(filename).write_text(xml, encoding="utf-8")
                except OSError as error:
                    QMessageBox.warning(
                        dialog, "Profile could not be saved", str(error),
                    )
                    return
                QMessageBox.information(dialog, "Profile exported", f"Saved {filename}")

        def confirm_local_account(options: WindowsCustomization) -> bool:
            if options.local_username:
                account_answer = QMessageBox.warning(
                    dialog,
                    "Confirm blank-password account workflow",
                    "The local administrator is created with a blank initial password. "
                    "A first-logon command marks it for mandatory replacement, but that "
                    "command does not run in Windows S mode and can be affected by "
                    "Windows setup policy.\n\nContinue with this account option?",
                    QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                    QMessageBox.StandardButton.Cancel,
                )
                if account_answer != QMessageBox.StandardButton.Yes:
                    return False
            return True

        def accept() -> None:
            try:
                options = selected()
                generate_autounattend(
                    options, profile_architecture(options)
                )
            except ValueError as error:
                QMessageBox.warning(dialog, "Invalid Windows options", str(error))
                return
            if not confirm_local_account(options):
                return
            self.windows_options = options
            self.logger.info("Windows customization profile updated: %s", options)
            dialog.accept()

        def inspect_metadata() -> None:
            try:
                options = selected()
                generate_autounattend(options, profile_architecture(options))
            except ValueError as error:
                QMessageBox.warning(dialog, "Invalid Windows options", str(error))
                return
            if not confirm_local_account(options):
                return
            self.windows_options = options
            dialog.accept()
            QTimer.singleShot(0, self.start_windows_wim_inspection)

        export_button.clicked.connect(export_xml)
        inspect_editions.clicked.connect(inspect_metadata)
        buttons.accepted.connect(accept)
        buttons.rejected.connect(dialog.reject)
        dialog.exec()


STYLE = """
QWidget { color: #f5f6f8; font-size: 14px; }
#root { background: #111318; color: #f5f6f8; }
QLabel#eyebrow { color: #ff9f43; font-size: 13px; font-weight: 800; letter-spacing: 3px; }
QLabel#title { font-size: 34px; font-weight: 750; }
QLabel#subtitle, QLabel#muted { color: #a9adb7; font-size: 14px; }
QLabel#cardTitle { font-size: 17px; font-weight: 650; }
QLabel#status { color: #c8cbd2; font-size: 13px; }
QFrame#card { background: #1b1e25; border: 1px solid #2d313b; border-radius: 14px; padding: 13px; }
QPushButton, QComboBox, QLineEdit, QPlainTextEdit { background: #272b34; color: #f5f6f8; border: 1px solid #3a3f4b; border-radius: 8px; padding: 9px 14px; }
QFrame#card QPushButton, QFrame#card QComboBox { color: #f5f6f8; padding: 5px 10px; }
QPushButton:hover { background: #323743; }
QPushButton#primary { background: #f28c28; color: #16120d; border: none; font-weight: 750; padding: 11px 24px; }
QPushButton#primary:hover { background: #ffa347; }
QPushButton:disabled { color: #70747d; background: #20232a; }
QFrame#card QPushButton:disabled, QFrame#card QComboBox:disabled { color: #a9adb7; border-color: #343945; }
QPushButton#primary:disabled { color: #777b83; background: #292c32; }
QProgressBar { border: none; background: #292d35; border-radius: 4px; height: 8px; }
QProgressBar::chunk { background: #f28c28; border-radius: 4px; }
QCheckBox { color: #d9dbe0; spacing: 9px; }
"""

LIGHT_STYLE = """
QWidget { color: #20242b; font-size: 14px; }
#root { background: #f5f6f8; color: #20242b; }
QLabel#eyebrow { color: #bd5f08; font-size: 13px; font-weight: 800; letter-spacing: 3px; }
QLabel#title { font-size: 34px; font-weight: 750; }
QLabel#subtitle, QLabel#muted { color: #626975; font-size: 14px; }
QLabel#cardTitle { font-size: 17px; font-weight: 650; }
QLabel#status { color: #515864; font-size: 13px; }
QFrame#card { background: #ffffff; border: 1px solid #d8dce3; border-radius: 14px; padding: 13px; }
QPushButton, QComboBox, QLineEdit, QPlainTextEdit { background: #ffffff; color: #20242b; border: 1px solid #c7ccd5; border-radius: 8px; padding: 9px 14px; }
QFrame#card QPushButton, QFrame#card QComboBox { color: #20242b; padding: 5px 10px; }
QPushButton:hover { background: #eef0f4; }
QPushButton#primary { background: #e97f16; color: #1d1208; border: none; font-weight: 750; padding: 11px 24px; }
QPushButton#primary:hover { background: #f28c28; }
QPushButton:disabled { color: #969ca6; background: #eceef2; }
QFrame#card QPushButton:disabled, QFrame#card QComboBox:disabled { color: #9298a2; border-color: #d8dce3; }
QPushButton#primary:disabled { color: #9298a2; background: #dfe2e7; }
QProgressBar { border: none; background: #dfe2e7; border-radius: 4px; height: 8px; }
QProgressBar::chunk { background: #e97f16; border-radius: 4px; }
QCheckBox { color: #303640; spacing: 9px; }
"""

THEMES = {"dark": STYLE, "light": LIGHT_STYLE}


def main() -> int:
    setup_logging()
    app = QApplication(sys.argv)
    app.setApplicationName("ISOpropyl")
    app.setOrganizationName("codebooker")
    app.setDesktopFileName("io.github.codebooker.isopropyl")
    icon = QIcon.fromTheme("io.github.codebooker.isopropyl")
    if icon.isNull():
        source_icon = (
            Path(__file__).resolve().parent.parent
            / "data" / "io.github.codebooker.isopropyl.svg"
        )
        if source_icon.is_file():
            icon = QIcon(str(source_icon))
    if not icon.isNull():
        app.setWindowIcon(icon)
    selected_theme = str(QSettings("codebooker", "ISOpropyl").value("appearance", "dark"))
    app.setStyleSheet(THEMES.get(selected_theme, STYLE))
    window = Window()
    window.show()
    positional = [Path(argument) for argument in app.arguments()[1:] if not argument.startswith("-")]
    if positional:
        QTimer.singleShot(0, lambda: window.load_image(positional[0]))
    return app.exec()


def image_identity(path: Path) -> tuple[int, int, int, int]:
    info = path.stat()
    if not path.is_file():
        raise OSError("The selected image is not a regular file")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def looks_like_windows_image(path: Path) -> bool:
    name = path.name.casefold()
    return path.suffix.casefold() == ".iso" and any(
        marker in name for marker in ("windows", "win10", "win11", "win_10", "win_11")
    )
