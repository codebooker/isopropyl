from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import sys
import threading
import logging
import shutil
import json
import stat
import tempfile
from dataclasses import dataclass, replace
from importlib.resources import files
from pathlib import Path

from PyQt6.QtCore import QObject, QSettings, QTimer, Qt, pyqtSignal
from PyQt6.QtGui import (
    QCloseEvent, QDragEnterEvent, QDropEvent, QIcon, QKeySequence, QShortcut,
    QTextCursor,
)
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QSlider, QTabWidget, QVBoxLayout,
    QWidget,
)

from .backup import (
    DriveImager, VirtualDriveImager, validate_virtual_backup_destination,
    virtual_backup_required_space,
)
from .authenticode import AuthenticodeIntegrityState
from .bootloaders import (
    CatalogError, bundle_for_dependency, delete_cached_artifacts, inventory_cache,
)
from .casper_media import (
    CasperMediaCancelled, CasperMediaExecutor, CasperStagingExecutor,
    build_casper_media_plan, build_casper_staging_plan,
    probe_casper_logical_sector_size, supported_casper_profile,
)
from .constructed import (
    ConstructedMediaCancelled, ConstructedMediaExecutor, ConstructedMediaPlan,
    build_constructed_media_plan, validate_constructed_media_plan,
)
from .distro_policies import DistroPolicyError, match_distro_iso_exclusion
from .devices import (
    Device, SizeUnitMode, format_size, image_is_on_device, list_devices,
    path_is_on_device,
)
from .diagnostics import build_diagnostics, write_diagnostics
from .erase import (
    QUICK_BOUNDARY_BYTES, EraseCancelled, EraseMode, EraseRunner,
    build_erase_plan,
)
from .extraction import (
    ExtractionCancelled, SafeIsoExtractor, build_extraction_plan,
)
from .formatting import (
    Filesystem as FormatFilesystem, FormatCancelled, FormatExecutor,
    PartitionTable as FormatPartitionTable, create_format_plan,
    restore_allocation_unit_sizes, restore_filesystem_geometry_supported,
)
from .images import (
    ChecksumCancelled, ImageInspection, ImageInspectionCancelled,
    calculate_checksums, classify_windows_installer_members,
    compare_expected_checksum, inspect_image,
)
from .iso import (
    AdditiveOverlayMerge, ArchiveEntry, BootStrategy, EntryKind, FirmwareTarget,
    WriteMode, WritePlan, WriteMethodRecommendation, build_write_plan,
    merge_additive_overlay_entries, partition_sector_mismatch,
    partition_sector_unverified, recommend_write_method,
)
from .iso_staging import (
    IsoStagingCancelled, IsoStagingExecutor, IsoStagingPlan,
    build_iso_staging_plan,
)
from .logging_setup import read_log, setup_logging
from .linux_downloads import (
    DownloadedLinuxImage, LinuxDownloadCancelled, LinuxImageRelease,
    LinuxIsoDownloader, available_linux_images,
)
from .media_test import (
    MediaTestCancelled, MediaTestMode, MediaTestResult, MediaTestRunner,
    build_media_test_plan,
)
from .optical import (
    OpticalCancelled, OpticalCaptureRunner, build_optical_capture_plan,
    list_optical_devices,
)
from .progress import ProgressEstimator, format_duration
from .persistence import (
    ALIGNMENT_BYTES, MIN_PERSISTENCE_BYTES, CasperCompatibilityProfile,
)
from .runtime_validation import (
    RUNTIME_VALIDATION_ARTIFACTS, RUNTIME_VALIDATION_VERSION,
    PreparedRuntimeValidation, RuntimeValidationCancelled,
    RuntimeValidationError,
    apply_runtime_validation, prepare_runtime_validation,
    validate_prepared_runtime_validation, validate_runtime_validation_stage,
)
from .settings import (
    SettingsStore, application_settings, parse_application_arguments,
    portable_settings_path, settings_sync_error, settings_sync_was_committed,
)
from .writer import ImageWriter, WriteCancelled
from .virtual import (
    CompressedVirtualDiskPreparer, VirtualConversionCancelled,
    VirtualDiskStager, inspect_virtual_disk,
)
from .uefi import SignatureTableState
from .uefi_ntfs import (
    UEFI_NTFS_SIZE, BoundArtifact, UefiNtfsCancelled, UefiNtfsExecutor,
    build_uefi_ntfs_media_plan, prepare_uefi_ntfs_artifact,
    probe_uefi_ntfs_logical_sector_size,
)
from .uefi_shell import (
    UEFI_SHELL_PROVENANCE_URL, UEFI_SHELL_VERSION,
    UefiShellCancelled, UefiShellStage, prepare_uefi_shell,
    stage_uefi_shell, validate_uefi_shell_stage,
)
from .wim import (
    WimEdition, WimInfo, WimSelection, inspect_wim, validate_wim_editions,
)
from .windows import (
    WindowsCustomization, generate_autounattend,
    online_account_bypass_compatibility, windows_architecture,
)
from .zip_overlay import (
    ZipOverlayPlan, build_zip_overlay_plan,
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
    allow_unsigned_payloads: bool = False
    persistence_profile: CasperCompatibilityProfile | None = None
    persistence_bytes: int = 0
    runtime_validation: PreparedRuntimeValidation | None = None


@dataclass(frozen=True)
class WindowsMetadataToken:
    generation: int
    image_identity: object
    source: ArchiveEntry
    extractor: SafeIsoExtractor


@dataclass(frozen=True)
class ChecksumToken:
    generation: int
    image_identity: object
    operation: BackgroundPreparation


@dataclass(frozen=True)
class ZipOverlayPlanningToken:
    generation: int
    inspection_generation: int
    image_identity: object
    archive: Path
    base_entries: tuple[ArchiveEntry, ...]
    operation: BackgroundPreparation


@dataclass(frozen=True)
class IsoStagingPreparationRequest:
    image: Path
    image_identity: object
    inspection: ImageInspection
    device: Device
    base_entries: tuple[ArchiveEntry, ...]
    write_plan: WritePlan
    overlay: ZipOverlayPlan | None
    workspace: tempfile.TemporaryDirectory[str]
    windows_customization: WindowsCustomization
    windows_architecture: str
    persistence_profile: CasperCompatibilityProfile | None
    persistence_bytes: int
    runtime_validation_requested: bool = False


@dataclass(frozen=True)
class IsoStagingPreparationToken:
    generation: int
    operation: BackgroundPreparation
    request: IsoStagingPreparationRequest


@dataclass(frozen=True)
class PendingUefiShell:
    device: Device
    workspace: tempfile.TemporaryDirectory[str]


@dataclass(frozen=True)
class UefiShellPreparationToken:
    operation: BackgroundPreparation
    pending: PendingUefiShell


@dataclass(frozen=True)
class LinuxDownloadToken:
    generation: int
    operation: LinuxIsoDownloader
    release: LinuxImageRelease
    destination: Path


class Bridge(QObject):
    # PyQt's plain `int` maps to a signed 32-bit C++ int. Disk images routinely
    # exceed that, so keep byte counters as Python objects across threads.
    progress = pyqtSignal(object, object, str)
    finished = pyqtSignal(bool, str)
    inspection_finished = pyqtSignal(object, object, object)
    inspection_worker_finished = pyqtSignal()
    checksum_progress = pyqtSignal(object, object, object)
    checksums_finished = pyqtSignal(object, object)
    zip_overlay_finished = pyqtSignal(object, object)
    iso_staging_preparation_finished = pyqtSignal(object, object)
    status_changed = pyqtSignal(str)
    media_progress = pyqtSignal(object)
    media_finished = pyqtSignal(object)
    windows_metadata_progress = pyqtSignal(object, object, object)
    windows_metadata_finished = pyqtSignal(object, object, object)
    uefi_preparation_finished = pyqtSignal(object, object, object)
    uefi_shell_preparation_finished = pyqtSignal(object, object, object)
    casper_preparation_finished = pyqtSignal(object, object, object)
    device_refresh_finished = pyqtSignal(object, object)
    linux_download_finished = pyqtSignal(object, object, object)


class Window(QMainWindow):
    def __init__(self, settings: SettingsStore | None = None) -> None:
        super().__init__()
        self.image: Path | None = None
        self.inspection: ImageInspection | None = None
        self.inspection_identity: object | None = None
        self.inspection_cancel_event = threading.Event()
        self.inspection_generation = 0
        self.inspection_busy = False
        self.inspection_worker_count = 0
        self.close_after_inspection = False
        self.write_recommendation: WriteMethodRecommendation | None = None
        self._distro_policy_inspection: ImageInspection | None = None
        self._distro_policy_exclusion_reason = ""
        self.device_refresh_generation = 0
        self.device_refresh_busy = False
        self.persistence_profile: CasperCompatibilityProfile | None = None
        self.checksum_busy = False
        self.checksum_generation = 0
        self.checksum_preparer: BackgroundPreparation | None = None
        self.linux_download_generation = 0
        self.linux_downloader: LinuxIsoDownloader | None = None
        self.linux_download_token: LinuxDownloadToken | None = None
        self.zip_overlay_plan: ZipOverlayPlan | None = None
        self.zip_overlay_merge: AdditiveOverlayMerge | None = None
        self.zip_overlay_generation = 0
        self.zip_overlay_preparer: BackgroundPreparation | None = None
        self.zip_overlay_token: ZipOverlayPlanningToken | None = None
        self.iso_staging_preparation_generation = 0
        self.iso_staging_preparer: BackgroundPreparation | None = None
        self.iso_staging_token: IsoStagingPreparationToken | None = None
        self.devices: list[Device] = []
        self.writer: ImageWriter | None = None
        self.imager: DriveImager | VirtualDriveImager | None = None
        self.formatter: FormatExecutor | None = None
        self.media_runner: MediaTestRunner | None = None
        self.eraser: EraseRunner | None = None
        self.optical_runner: OpticalCaptureRunner | None = None
        self.extractor: SafeIsoExtractor | None = None
        self.virtual_stager: VirtualDiskStager | None = None
        self.compressed_virtual_preparer: CompressedVirtualDiskPreparer | None = None
        self.iso_stager: IsoStagingExecutor | None = None
        self.windows_wim_extractor: SafeIsoExtractor | None = None
        self.constructed_writer: ConstructedMediaExecutor | None = None
        self.uefi_ntfs_writer: UefiNtfsExecutor | None = None
        self.uefi_preparer: BackgroundPreparation | None = None
        self.uefi_shell_preparer: BackgroundPreparation | None = None
        self.uefi_shell_token: UefiShellPreparationToken | None = None
        self.uefi_shell_workspace: tempfile.TemporaryDirectory[str] | None = None
        self.casper_preparer: BackgroundPreparation | None = None
        self.casper_stager: CasperStagingExecutor | None = None
        self.casper_writer: CasperMediaExecutor | None = None
        self.pending_iso_write: PendingIsoWrite | None = None
        self.iso_workspace: tempfile.TemporaryDirectory[str] | None = None
        self.runtime_validation_cancel_event = threading.Event()
        self.windows_options = WindowsCustomization()
        self.windows_wim_candidates: tuple[ArchiveEntry, ...] = ()
        self.windows_install_source_count = 0
        self.windows_wim_member: ArchiveEntry | None = None
        self.windows_wim_editions: tuple[WimEdition, ...] = ()
        self.windows_wim_error = ""
        self.windows_metadata_generation = 0
        self.settings = settings if settings is not None else QSettings(
            "codebooker", "ISOpropyl"
        )
        try:
            self.size_unit_mode = SizeUnitMode(
                str(self.settings.value("size_units", SizeUnitMode.SI.value))
            )
        except ValueError:
            self.size_unit_mode = SizeUnitMode.SI
        self.progress_estimator = ProgressEstimator()
        self.logger = logging.getLogger("isopropyl")
        self.bridge = Bridge()
        self.bridge.progress.connect(self.on_progress)
        self.bridge.finished.connect(self.on_finished)
        self.bridge.inspection_finished.connect(self.on_inspection_finished)
        self.bridge.inspection_worker_finished.connect(
            self.on_inspection_worker_finished
        )
        self.bridge.checksum_progress.connect(self.on_checksum_progress)
        self.bridge.checksums_finished.connect(self.on_checksums_finished)
        self.bridge.zip_overlay_finished.connect(self.on_zip_overlay_finished)
        self.bridge.iso_staging_preparation_finished.connect(
            self.on_iso_staging_preparation_finished
        )
        self.setWindowTitle("ISOpropyl")
        self.setMinimumSize(720, 700)
        self.setAcceptDrops(True)
        self.build_ui()
        self.bridge.status_changed.connect(self.status.setText)
        self.bridge.media_progress.connect(self.on_media_progress)
        self.bridge.media_finished.connect(self.on_media_finished)
        self.bridge.windows_metadata_progress.connect(
            self.on_windows_metadata_progress
        )
        self.bridge.windows_metadata_finished.connect(
            self.on_windows_metadata_finished
        )
        self.bridge.uefi_preparation_finished.connect(
            self.on_uefi_preparation_finished
        )
        self.bridge.uefi_shell_preparation_finished.connect(
            self.on_uefi_shell_preparation_finished
        )
        self.bridge.casper_preparation_finished.connect(
            self.on_casper_preparation_finished
        )
        self.bridge.device_refresh_finished.connect(self.on_devices_refreshed)
        self.bridge.linux_download_finished.connect(
            self.on_linux_download_finished
        )
        QShortcut(QKeySequence.StandardKey.Open, self, activated=self.choose_image)
        QShortcut(QKeySequence("Ctrl+R"), self, activated=self.refresh_devices)
        QShortcut(QKeySequence("Ctrl+L"), self, activated=self.show_log)
        QShortcut(QKeySequence.StandardKey.Cancel, self, activated=self.cancel)
        self.refresh_devices()

    def display_size(self, size: int | float) -> str:
        return format_size(size, self.size_unit_mode)

    def display_device(self, device: Device) -> str:
        return device.display_label(self.size_unit_mode)

    def refresh_size_labels(self) -> None:
        for index, device in enumerate(self.devices):
            self.device_combo.setItemText(index, self.display_device(device))
        if self.image is not None:
            try:
                if (
                    self.inspection is not None
                    and self.inspection.sparse_format == "VTSI"
                ):
                    text = (
                        f"{self.image.name}  ·  "
                        f"{self.display_size(self.inspection.size)} expanded disk "
                        f"({self.display_size(self.inspection.container_size)} sparse file)"
                    )
                elif (
                    self.inspection is not None
                    and self.inspection.virtual_format
                    and self.inspection.compression != "none"
                ):
                    text = (
                        f"{self.image.name}  ·  "
                        f"{self.display_size(self.inspection.size)} virtual disk "
                        f"({self.display_size(self.inspection.decoded_container_size)} "
                        f"decoded · {self.display_size(self.inspection.container_size)} "
                        f"{self.inspection.compression.upper()})"
                    )
                elif self.inspection is not None and self.inspection.compression != "none":
                    text = (
                        f"{self.image.name}  ·  "
                        f"{self.display_size(self.inspection.size)} expanded"
                    )
                elif self.inspection is not None and self.inspection.virtual_format:
                    text = (
                        f"{self.image.name}  ·  "
                        f"{self.display_size(self.inspection.size)} virtual "
                        f"({self.display_size(self.inspection.container_size)} container)"
                    )
                else:
                    text = f"{self.image.name}  ·  {self.display_size(self.image.stat().st_size)}"
                self.image_label.setText(text)
            except OSError:
                pass
        self.on_persistence_changed()

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
        self.linux_download_button = QPushButton("Download Linux…")
        self.linux_download_button.setToolTip(
            "Explicitly download an ISO from ISOpropyl's small signed Linux catalog."
        )
        self.linux_download_button.clicked.connect(self.download_linux_image)
        source_row.addWidget(self.image_label, 1)
        source_row.addWidget(self.linux_download_button)
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
        self.persistence_controls = QWidget()
        persistence_layout = QHBoxLayout(self.persistence_controls)
        persistence_layout.setContentsMargins(0, 0, 0, 0)
        self.persistence_checkbox = QCheckBox("Persistent storage")
        self.persistence_checkbox.setToolTip(
            "Reserve ext4 writable storage for a candidate Ubuntu remaster; "
            "private staging must still validate an eligible UEFI GRUB boot line."
        )
        self.persistence_slider = QSlider(Qt.Orientation.Horizontal)
        self.persistence_slider.setMinimum(MIN_PERSISTENCE_BYTES // ALIGNMENT_BYTES)
        self.persistence_slider.setMaximum(4 * 1024)
        self.persistence_slider.setValue(4 * 1024)
        self.persistence_slider.setSingleStep(256)
        self.persistence_slider.setPageStep(1024)
        self.persistence_size_label = QLabel(self.display_size(4 * 1024**3))
        self.persistence_size_label.setObjectName("muted")
        self.persistence_size_label.setMinimumWidth(72)
        persistence_layout.addWidget(self.persistence_checkbox)
        persistence_layout.addWidget(self.persistence_slider, 1)
        persistence_layout.addWidget(self.persistence_size_label)
        self.persistence_controls.setVisible(False)
        self.persistence_checkbox.toggled.connect(self.on_persistence_changed)
        self.persistence_slider.valueChanged.connect(self.on_persistence_changed)
        self.source_card.layout().addWidget(self.persistence_controls)
        self.zip_overlay_controls = QWidget()
        overlay_layout = QHBoxLayout(self.zip_overlay_controls)
        overlay_layout.setContentsMargins(0, 0, 0, 0)
        overlay_title = QLabel("Additional files")
        overlay_title.setObjectName("muted")
        self.zip_overlay_label = QLabel("No ZIP overlay selected")
        self.zip_overlay_label.setObjectName("muted")
        self.zip_overlay_label.setWordWrap(True)
        self.zip_overlay_choose_button = QPushButton("Add ZIP…")
        self.zip_overlay_choose_button.setObjectName("zipOverlayChooseButton")
        self.zip_overlay_choose_button.setToolTip(
            "Add files from a bounded ZIP archive in filesystem-aware ISO mode. "
            "Existing ISO files, fallback loaders, and canonical Windows install "
            "payloads cannot be replaced."
        )
        self.zip_overlay_choose_button.clicked.connect(self.choose_zip_overlay)
        self.zip_overlay_choose_button.setEnabled(False)
        self.zip_overlay_clear_button = QPushButton("Clear")
        self.zip_overlay_clear_button.setObjectName("zipOverlayClearButton")
        self.zip_overlay_clear_button.clicked.connect(self.clear_zip_overlay)
        self.zip_overlay_clear_button.setEnabled(False)
        overlay_layout.addWidget(overlay_title)
        overlay_layout.addWidget(self.zip_overlay_label, 1)
        overlay_layout.addWidget(self.zip_overlay_choose_button)
        overlay_layout.addWidget(self.zip_overlay_clear_button)
        self.source_card.layout().addWidget(self.zip_overlay_controls)
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
        self.runtime_validation = QCheckBox(
            "Boot-time corruption check (MD5)"
        )
        self.runtime_validation.setObjectName("runtimeValidationCheckBox")
        self.runtime_validation.setChecked(False)
        self.runtime_validation.setToolTip(
            "Optional accidental-corruption check on later boots. The unsigned "
            "MD5 manifest does not authenticate the image, can be replaced with "
            "the USB contents, and is bypassable/fail-open. It adds boot time."
        )
        self.show_external = QCheckBox("Show USB hard drives/SSDs")
        self.show_external.setToolTip(
            "External fixed disks are hidden by default to protect backup drives."
        )
        self.show_external.toggled.connect(self.refresh_devices)
        write_options.addWidget(self.verify)
        write_options.addWidget(self.runtime_validation)
        write_options.addWidget(self.show_external)
        write_options.addStretch()
        options.addLayout(write_options)
        utility_options = QHBoxLayout()
        utility_options.addStretch()
        log_button = QPushButton("View log")
        log_button.clicked.connect(self.show_log)
        self.uefi_shell_button = QPushButton("Create UEFI Shell…")
        self.uefi_shell_button.setToolTip(
            "Download hash-pinned upstream UEFI Shell applications and create "
            "multi-architecture GPT/FAT32 boot media."
        )
        self.uefi_shell_button.clicked.connect(self.create_uefi_shell_media)
        utility_options.addWidget(self.uefi_shell_button)
        self.tools_button = QPushButton("Drive tools…")
        self.tools_button.clicked.connect(self.show_drive_tools)
        utility_options.addWidget(self.tools_button)
        self.optical_button = QPushButton("Save optical disc…")
        self.optical_button.clicked.connect(self.save_optical_disc)
        utility_options.addWidget(self.optical_button)
        self.settings_button = QPushButton("Settings…")
        self.settings_button.clicked.connect(self.show_settings)
        utility_options.addWidget(self.settings_button)
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
            "Disk images (*.iso *.img *.raw *.usb *.wic *.vtsi *.vhd *.vhdx *.qcow *.qcow2 *.gz *.gzip *.bz2 *.bzip2 *.xz *.lzma *.zst *.zstd *.Z *.z *.zip);;All files (*)",
        )
        if filename:
            self.load_image(Path(filename))

    def download_linux_image(self) -> None:
        if self.operation_active or self.inspection_busy:
            return
        try:
            releases = available_linux_images()
        except Exception as error:
            QMessageBox.critical(self, "Linux catalog unavailable", str(error))
            return
        if not releases:
            QMessageBox.warning(
                self, "Linux catalog unavailable", "No curated Linux images are available."
            )
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Download a verified Linux ISO")
        dialog.setMinimumWidth(560)
        layout = QVBoxLayout(dialog)
        notice = QLabel(
            "Choose an image from the bundled catalog. Networking starts only after "
            "you confirm a destination. ISOpropyl authenticates the distribution's "
            "signed checksum metadata and verifies the complete ISO before publishing it."
        )
        notice.setWordWrap(True)
        layout.addWidget(notice)
        choices = QComboBox()
        choices.setObjectName("linuxDownloadRelease")
        for release in releases:
            choices.addItem(
                f"{release.distribution} {release.release} · {release.edition} "
                f"{release.architecture} · {self.display_size(release.size)}",
                release,
            )
        layout.addWidget(choices)
        details = QLabel()
        details.setObjectName("muted")
        details.setWordWrap(True)
        layout.addWidget(details)

        def update_details() -> None:
            release = choices.currentData()
            if isinstance(release, LinuxImageRelease):
                details.setText(
                    f"Official filename: {release.filename}\n"
                    f"Signed SHA-256: {release.sha256}\n"
                    f"Source: {release.provenance_url}"
                )

        choices.currentIndexChanged.connect(update_details)
        update_details()
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Choose destination…")
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        release = choices.currentData()
        if not isinstance(release, LinuxImageRelease) or release not in releases:
            QMessageBox.critical(
                self, "Linux catalog unavailable", "The selected catalog entry is invalid."
            )
            return

        downloads = Path.home() / "Downloads"
        starting_directory = downloads if downloads.is_dir() else Path.home()
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save verified Linux ISO",
            str(starting_directory / release.filename),
            "ISO images (*.iso)",
        )
        if not filename:
            return
        destination = Path(filename)
        if destination.name != release.filename:
            QMessageBox.warning(
                self,
                "Keep the official filename",
                f"This catalog entry must be saved as {release.filename}. Choose the "
                "destination again without renaming it.",
            )
            return
        if not destination.is_absolute():
            QMessageBox.warning(
                self, "Choose an absolute destination", "Choose a normal local folder."
            )
            return
        confirmation = QMessageBox.question(
            self,
            "Download and verify Linux ISO?",
            f"Download {release.distribution} {release.release} {release.edition} "
            f"({release.architecture}) from:\n{release.provenance_url}\n\n"
            f"Size: {self.display_size(release.size)}\n"
            f"Destination: {destination}\n\n"
            "A cancelled transfer remains in a private resumable directory beside "
            "the destination. Downloaded bytes are never executed on Linux.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if confirmation != QMessageBox.StandardButton.Yes:
            return

        downloader = LinuxIsoDownloader()
        self.linux_download_generation += 1
        token = LinuxDownloadToken(
            self.linux_download_generation, downloader, release, destination,
        )
        self.linux_downloader = downloader
        self.linux_download_token = token
        self.set_busy(True)
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        self.status.setText("Authenticating signed Linux download metadata…")
        self.logger.info(
            "Confirmed Linux ISO download: release=%s destination=%s",
            release.id, destination,
        )

        def work() -> None:
            try:
                result: object = downloader.download(
                    release,
                    destination,
                    lambda done, total: self.bridge.progress.emit(
                        done, total, f"Downloading {release.distribution} ISO",
                    ),
                )
                error: object = None
            except Exception as caught:
                result = None
                error = caught
            self.bridge.linux_download_finished.emit(token, result, error)

        threading.Thread(target=work, daemon=True).start()

    def on_linux_download_finished(
        self, token: LinuxDownloadToken, result: object, error: object,
    ) -> None:
        if (
            token is not self.linux_download_token
            or token.operation is not self.linux_downloader
            or token.generation != self.linux_download_generation
        ):
            return
        self.linux_downloader = None
        self.linux_download_token = None
        self.set_busy(False)
        if error is not None:
            if isinstance(error, LinuxDownloadCancelled) or token.operation.cancelled:
                message = (
                    "Linux ISO download cancelled. Choose the same destination later "
                    "to authenticate the metadata again and resume safely."
                )
                self.logger.info(message)
                self.status.setText(message)
            else:
                self.logger.warning("Linux ISO download failed: %s", error)
                self.status.setText("Linux ISO download did not complete")
                QMessageBox.critical(self, "Linux download failed", str(error))
            return
        if (
            not isinstance(result, DownloadedLinuxImage)
            or result.path != token.destination
            or result.release_id != token.release.id
            or result.size != token.release.size
            or result.sha256 != token.release.sha256
        ):
            self.status.setText("Linux ISO download returned an invalid result")
            QMessageBox.critical(
                self,
                "Linux download failed",
                "The background downloader returned an invalid bound result.",
            )
            return
        self.progress.setValue(1000)
        self.status.setText("Verified Linux ISO downloaded")
        self.logger.info(
            "Verified Linux ISO downloaded: release=%s destination=%s sha256=%s",
            result.release_id, result.path, result.sha256,
        )
        QMessageBox.information(
            self,
            "Linux ISO ready",
            f"Downloaded and verified {token.release.distribution} "
            f"{token.release.release}.\n\n{result.path}",
        )
        self.load_image(result.path)

    def load_image(self, path: Path) -> None:
        try:
            identity = image_identity(path)
        except OSError as error:
            QMessageBox.critical(self, "Image unavailable", str(error))
            return
        self._reset_zip_overlay(rebuild=False)
        checksum_was_active = self.checksum_preparer is not None
        if self.checksum_preparer is not None:
            self.checksum_preparer.cancel()
        self.checksum_generation += 1
        self.checksum_preparer = None
        self.checksum_busy = False
        self.checksum_button.setText("Checksums…")
        if checksum_was_active and not self.operation_active:
            self.set_busy(False)
        self.image = path.resolve()
        path = self.image
        self.inspection_cancel_event.set()
        inspection_cancel_event = threading.Event()
        self.inspection_cancel_event = inspection_cancel_event
        self.inspection_generation += 1
        inspection_generation = self.inspection_generation
        self.inspection_busy = True
        self.logger.info("Selected image %s", path)
        self.inspection = None
        self.inspection_identity = None
        self._distro_policy_inspection = None
        self._distro_policy_exclusion_reason = ""
        self.write_recommendation = None
        self.persistence_profile = None
        self.persistence_checkbox.blockSignals(True)
        self.persistence_checkbox.setChecked(False)
        self.persistence_checkbox.blockSignals(False)
        self.persistence_controls.setVisible(False)
        self.runtime_validation.blockSignals(True)
        self.runtime_validation.setChecked(False)
        self.runtime_validation.blockSignals(False)
        self.windows_options = WindowsCustomization()
        if self.windows_wim_extractor is not None:
            self.windows_wim_extractor.cancel()
        self.windows_metadata_generation += 1
        self.windows_wim_candidates = ()
        self.windows_install_source_count = 0
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
        self.image_label.setText(
            f"{path.name}  ·  {self.display_size(path.stat().st_size)}"
        )
        self.image_label.setToolTip(str(path))
        self.image_detail.setText("DD mode · Inspecting image layout…")
        self.checksum_button.setEnabled(False)
        self.on_device_changed()

        def work() -> None:
            def check_cancelled() -> None:
                if inspection_cancel_event.is_set():
                    raise ImageInspectionCancelled("Image inspection was cancelled")

            try:
                try:
                    result: object = inspect_image(
                        path,
                        expected_identity=identity,
                        cancel_check=check_cancelled,
                    )
                except ImageInspectionCancelled:
                    return
                except Exception as error:
                    result = error
                if inspection_cancel_event.is_set():
                    return
                self.bridge.inspection_finished.emit(
                    identity, result, inspection_generation,
                )
            finally:
                self.bridge.inspection_worker_finished.emit()

        self.inspection_worker_count += 1
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
                self.device_combo.addItem(self.display_device(device))
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
                member.modified_ns,
            )
            for member in self.inspection.members
        )

    def effective_archive_entries(self) -> tuple[ArchiveEntry, ...]:
        base_entries = self.archive_entries()
        if self.zip_overlay_plan is None:
            return base_entries
        merged = self.zip_overlay_merge
        if merged is None or merged.base_entries != base_entries:
            raise ValueError("The ZIP overlay no longer matches the inspected ISO catalog")
        return merged.merged_entries

    @staticmethod
    def runtime_validation_architectures(
        entries: tuple[ArchiveEntry, ...],
    ) -> tuple[str, ...]:
        files = {
            entry.path.casefold()
            for entry in entries
            if entry.kind is EntryKind.FILE
        }
        return tuple(
            profile.architecture
            for profile in RUNTIME_VALIDATION_ARTIFACTS
            if profile.fallback_path.casefold() in files
        )

    def runtime_validation_exclusion_reason(self) -> str:
        if self.selected_write_mode() is not WriteMode.EXTRACTED_ISO:
            return "Choose filesystem-aware ISO mode."
        recommendation = self.write_recommendation
        plan = recommendation.iso_plan if recommendation is not None else None
        if (
            plan is None or not plan.executable or plan.layout is None
            or plan.layout.boot_strategy is not BootStrategy.IMAGE_NATIVE
            or plan.layout.main_filesystem.value != "fat32"
        ):
            return "The first supported path is native UEFI/FAT32 ISO mode."
        if self.selected_persistence_bytes():
            return "Boot-time validation is not yet certified with persistence."
        try:
            entries = self.effective_archive_entries()
        except ValueError:
            return "The effective ISO catalog is no longer valid."
        if any(
            entry.path.split("/", 1)[0].casefold() == "casper"
            for entry in entries
        ):
            return (
                "Casper/Ubuntu media are temporarily excluded pending installer "
                "compatibility testing."
            )
        if any(
            "/" not in entry.path
            and entry.path.casefold() == "md5sum.txt"
            and entry.path != "md5sum.txt"
            for entry in entries
        ):
            return "A root case alias conflicts with the required md5sum.txt manifest."
        reserved_originals = {
            profile.original_path.casefold()
            for profile in RUNTIME_VALIDATION_ARTIFACTS
        }
        if any(entry.path.casefold() in reserved_originals for entry in entries):
            return "A reserved boot*_original.efi chainload path already exists."
        overlay = self.zip_overlay_plan
        if overlay is not None and any(
            member.entry.path.casefold() == "md5sum.txt"
            for member in overlay.members
        ):
            return "The ZIP overlay supplies the manifest name that must be regenerated."
        if not self.runtime_validation_architectures(entries):
            return "No supported removable-media UEFI fallback loader was found."
        return ""

    def update_runtime_validation_control(self) -> None:
        reason = self.runtime_validation_exclusion_reason()
        if reason:
            self.runtime_validation.blockSignals(True)
            self.runtime_validation.setChecked(False)
            self.runtime_validation.blockSignals(False)
        self.runtime_validation.setEnabled(not reason and not self.operation_active)
        limitations = (
            "The unsigned MD5 manifest detects accidental corruption only; it "
            "does not authenticate the image, is replaceable with the USB files, "
            "and can be bypassed or fail open. Validation adds boot time."
        )
        self.runtime_validation.setToolTip(
            f"Unavailable: {reason}\n\n{limitations}" if reason else limitations
        )

    def _zip_overlay_is_on_target(self, device: Device | None = None) -> bool:
        plan = self.zip_overlay_plan
        target = device if device is not None else self.selected_device()
        if plan is None or target is None:
            return False
        try:
            return path_is_on_device(str(plan.archive), target)
        except OSError:
            return True

    def _distro_iso_exclusion_reason(self) -> str:
        inspection = self.inspection
        if inspection is self._distro_policy_inspection:
            return self._distro_policy_exclusion_reason
        reason = ""
        if (
            inspection is not None
            and (inspection.is_iso9660 or inspection.kind == "Optical ISO")
            and inspection.contents_scanned is True
        ):
            try:
                matched = match_distro_iso_exclusion(inspection)
            except DistroPolicyError as error:
                reason = f"ISO-mode compatibility evidence is unsafe: {error}"
            else:
                if matched is not None:
                    reason = matched.reason
        self._distro_policy_inspection = inspection
        self._distro_policy_exclusion_reason = reason
        return reason

    def update_zip_overlay_controls(self) -> None:
        eligible = bool(
            self.inspection is not None
            and self.inspection.is_iso9660
            and self.inspection.contents_scanned
        )
        iso_exclusion = self._distro_iso_exclusion_reason() if eligible else ""
        planning = self.zip_overlay_preparer is not None
        self.zip_overlay_choose_button.setEnabled(
            eligible and not iso_exclusion and not planning
            and not self.operation_active
        )
        self.zip_overlay_choose_button.setToolTip(
            iso_exclusion
            or "Add one bounded ZIP archive to ISO mode without replacing any "
            "file already present in the image."
        )
        self.zip_overlay_clear_button.setEnabled(
            (planning or self.zip_overlay_plan is not None) and not self.operation_active
        )
        self.iso_plan_button.setEnabled(
            eligible and not planning and not self.operation_active
        )
        if planning and self.zip_overlay_token is not None:
            self.zip_overlay_label.setText(
                f"Inspecting {self.zip_overlay_token.archive.name}…"
            )
        elif self.zip_overlay_plan is not None:
            warning = (
                " · stored on selected target — move it first"
                if self._zip_overlay_is_on_target() else ""
            )
            if self.selected_write_mode() is WriteMode.DD:
                warning += " · not applied in DD mode"
            self.zip_overlay_label.setText(
                f"{self.zip_overlay_plan.archive.name} · "
                f"{self.display_size(self.zip_overlay_plan.content_bytes)} expanded"
                f"{warning}"
            )
            self.zip_overlay_label.setToolTip(
                f"{self.zip_overlay_plan.archive}\n"
                f"SHA-256: {self.zip_overlay_plan.archive_sha256}"
            )
        else:
            self.zip_overlay_label.setText("No ZIP overlay selected")
            self.zip_overlay_label.setToolTip("")

    def _reset_zip_overlay(self, *, rebuild: bool) -> None:
        if self.zip_overlay_preparer is not None:
            self.zip_overlay_preparer.cancel()
        self.zip_overlay_generation += 1
        self.zip_overlay_preparer = None
        self.zip_overlay_token = None
        self.zip_overlay_plan = None
        self.zip_overlay_merge = None
        self.update_zip_overlay_controls()
        if rebuild and self.inspection is not None:
            self.rebuild_write_recommendation()
        else:
            self.update_ready()

    def clear_zip_overlay(self, _checked: bool = False) -> None:
        self._reset_zip_overlay(rebuild=True)

    def choose_zip_overlay(self) -> None:
        if not (
            self.inspection is not None
            and self.inspection.is_iso9660
            and self.inspection.contents_scanned
            and self.image is not None
            and self.inspection_identity is not None
            and not self.operation_active
        ):
            return
        if self._distro_iso_exclusion_reason():
            return
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Choose an additive ZIP overlay",
            str(Path.home()),
            "ZIP archives (*.zip);;All files (*)",
        )
        if not filename:
            return
        archive = Path(filename).absolute()
        device = self.selected_device()
        if device is not None:
            try:
                on_target = path_is_on_device(str(archive), device)
            except OSError:
                on_target = True
            if on_target:
                QMessageBox.warning(
                    self,
                    "Move the ZIP overlay first",
                    "The selected ZIP overlay is stored on the target drive. "
                    "Move it to another disk before using it in ISO mode.",
                )
                return

        if self.zip_overlay_preparer is not None:
            self.zip_overlay_preparer.cancel()
        self.zip_overlay_generation += 1
        operation = BackgroundPreparation()
        token = ZipOverlayPlanningToken(
            self.zip_overlay_generation,
            self.inspection_generation,
            self.inspection_identity,
            archive,
            self.archive_entries(),
            operation,
        )
        self.zip_overlay_plan = None
        self.zip_overlay_merge = None
        self.zip_overlay_preparer = operation
        self.zip_overlay_token = token
        self.update_zip_overlay_controls()
        self.update_ready()
        self.status.setText("Inspecting the ZIP overlay safely…")

        def work() -> None:
            def check_cancelled() -> None:
                if operation.cancelled:
                    raise IsoStagingCancelled("ZIP overlay inspection was cancelled")

            try:
                plan = build_zip_overlay_plan(
                    archive, cancel_check=check_cancelled,
                )
                merged = merge_additive_overlay_entries(
                    token.base_entries,
                    (member.entry for member in plan.members),
                )
                result: object = (plan, merged)
            except Exception as error:
                result = error
            self.bridge.zip_overlay_finished.emit(token, result)

        threading.Thread(target=work, daemon=True).start()

    def on_zip_overlay_finished(self, token: object, result: object) -> None:
        if not isinstance(token, ZipOverlayPlanningToken):
            return
        if (
            token is not self.zip_overlay_token
            or token.operation is not self.zip_overlay_preparer
            or token.generation != self.zip_overlay_generation
        ):
            return
        self.zip_overlay_preparer = None
        self.zip_overlay_token = None
        current = False
        try:
            current = bool(
                self.image is not None
                and token.inspection_generation == self.inspection_generation
                and token.image_identity == self.inspection_identity
                and token.image_identity == image_identity(self.image)
                and token.base_entries == self.archive_entries()
            )
        except OSError:
            current = False
        if not current:
            self.update_zip_overlay_controls()
            self.update_ready()
            return
        if token.operation.cancelled or isinstance(result, IsoStagingCancelled):
            self.status.setText("ZIP overlay inspection cancelled")
            self.update_zip_overlay_controls()
            self.update_ready()
            return
        if isinstance(result, Exception):
            self.status.setText("ZIP overlay was not selected")
            self.update_zip_overlay_controls()
            self.update_ready()
            QMessageBox.warning(self, "ZIP overlay unavailable", str(result))
            return
        if (
            not isinstance(result, tuple)
            or len(result) != 2
            or not isinstance(result[0], ZipOverlayPlan)
            or not isinstance(result[1], AdditiveOverlayMerge)
            or result[0].archive != token.archive
        ):
            self.status.setText("ZIP overlay was not selected")
            self.update_zip_overlay_controls()
            self.update_ready()
            QMessageBox.warning(
                self,
                "ZIP overlay unavailable",
                "The background ZIP inspection returned an invalid result.",
            )
            return
        plan, merged = result
        if (
            merged.base_entries != token.base_entries
            or len(merged.overlay_targets) != len(plan.members)
        ):
            QMessageBox.warning(
                self,
                "ZIP overlay unavailable",
                "The background ZIP merge returned inconsistent catalog data.",
            )
            self.update_zip_overlay_controls()
            self.update_ready()
            return
        self.zip_overlay_plan = plan
        self.zip_overlay_merge = merged
        if self._zip_overlay_is_on_target():
            self.status.setText("Move the ZIP overlay off the selected target drive")
        else:
            self.status.setText("ZIP overlay selected; ISO plans now include its files")
        self.update_zip_overlay_controls()
        self.rebuild_write_recommendation()

    def selected_write_mode(self) -> WriteMode | None:
        value = self.write_method.currentData()
        try:
            return WriteMode(value) if value is not None else None
        except ValueError:
            return None

    def verification_is_mandatory(self) -> bool:
        mode = self.selected_write_mode()
        return bool(
            mode is WriteMode.EXTRACTED_ISO
            or (
                mode is WriteMode.DD
                and self.inspection is not None
                and self.inspection.sparse_format == "VTSI"
            )
        )

    def selected_persistence_bytes(self) -> int:
        if (
            self.persistence_profile is not None
            and not self.persistence_controls.isHidden()
            and self.persistence_checkbox.isChecked()
            and self.selected_write_mode() is WriteMode.EXTRACTED_ISO
        ):
            return self.persistence_slider.value() * ALIGNMENT_BYTES
        return 0

    def update_persistence_controls(self) -> None:
        recommendation = self.write_recommendation
        iso_plan = recommendation.iso_plan if recommendation is not None else None
        eligible = bool(
            self.persistence_profile is not None
            and self.selected_write_mode() is WriteMode.EXTRACTED_ISO
            and iso_plan is not None
            and iso_plan.executable
            and iso_plan.layout is not None
            and iso_plan.layout.main_filesystem.value == "fat32"
        )
        self.persistence_controls.setVisible(eligible)
        if not eligible:
            self.persistence_checkbox.blockSignals(True)
            self.persistence_checkbox.setChecked(False)
            self.persistence_checkbox.blockSignals(False)
            return
        device = self.selected_device()
        maximum_mib = 0
        if device is not None and iso_plan is not None:
            remaining = max(
                0,
                device.size - iso_plan.minimum_target_bytes - 2 * ALIGNMENT_BYTES,
            )
            maximum_mib = remaining // ALIGNMENT_BYTES
        minimum_mib = MIN_PERSISTENCE_BYTES // ALIGNMENT_BYTES
        available = maximum_mib >= minimum_mib
        self.persistence_checkbox.setEnabled(available and not self.operation_active)
        self.persistence_slider.blockSignals(True)
        self.persistence_slider.setMinimum(minimum_mib)
        self.persistence_slider.setMaximum(max(minimum_mib, maximum_mib))
        if self.persistence_slider.value() < minimum_mib:
            self.persistence_slider.setValue(minimum_mib)
        self.persistence_slider.blockSignals(False)
        if not available:
            self.persistence_checkbox.blockSignals(True)
            self.persistence_checkbox.setChecked(False)
            self.persistence_checkbox.blockSignals(False)
        self.persistence_slider.setEnabled(
            available and self.persistence_checkbox.isChecked()
            and not self.operation_active
        )
        self.on_persistence_changed()

    def on_persistence_changed(self, _value: object = None) -> None:
        value_mib = self.persistence_slider.value()
        self.persistence_size_label.setText(
            self.display_size(value_mib * ALIGNMENT_BYTES)
        )
        self.persistence_slider.setEnabled(
            not self.persistence_controls.isHidden()
            and self.persistence_checkbox.isEnabled()
            and self.persistence_checkbox.isChecked()
            and not self.operation_active
        )
        self.update_runtime_validation_control()
        self.update_ready()

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
                self.effective_archive_entries(),
                target_size=device.size if device is not None else None,
                target_logical_sector_size=(
                    device.logical_sector_size if device is not None else None
                ),
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
        self._distro_policy_inspection = inspection
        self._distro_policy_exclusion_reason = (
            recommendation.distro_iso_exclusion_reason
        )
        self.write_recommendation = recommendation
        selected = (
            previous
            if (
                recommendation.recommended_mode is not None
                and previous in recommendation.available_modes
            )
            else recommendation.recommended_mode
        )
        labels = {
            WriteMode.DD: (
                "VTSI restore — expand sparse disk image"
                if inspection.sparse_format == "VTSI" else
                "Virtual disk restore — decode/convert to raw disk"
                if inspection.virtual_format else
                "DD mode — exact byte-for-byte copy"
            ),
            WriteMode.EXTRACTED_ISO: "ISO mode — filesystem-aware, UEFI-only",
        }
        self.write_method.blockSignals(True)
        self.write_method.clear()
        for mode in recommendation.available_modes:
            self.write_method.addItem(labels[mode], mode.value)
        if selected is not None:
            index = self.write_method.findData(selected.value)
            self.write_method.setCurrentIndex(index)
        else:
            # A method that remains available only as an explicit expert choice
            # must not become selected merely because it is the combo's first item.
            self.write_method.setCurrentIndex(-1)
        self.write_method.blockSignals(False)
        self.write_method.setEnabled(bool(recommendation.available_modes))
        prefix = (
            "Recommended: ISO mode. "
            if recommendation.recommended_mode is WriteMode.EXTRACTED_ISO else
            "Recommended: virtual disk restore. "
            if (
                recommendation.recommended_mode is WriteMode.DD
                and bool(inspection.virtual_format)
            ) else
            "Recommended: DD mode. "
            if recommendation.recommended_mode is WriteMode.DD else
            "No method is recommended. "
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
            label = (
                "ISO mode" if mode is WriteMode.EXTRACTED_ISO else
                "VTSI restore" if (
                    mode is WriteMode.DD
                    and self.inspection.sparse_format == "VTSI"
                ) else
                "Virtual disk restore" if (
                    mode is WriteMode.DD
                    and bool(self.inspection.virtual_format)
                ) else
                "DD mode" if mode is WriteMode.DD else
                "Choose a write method"
            )
            self.image_detail.setText(f"{label} · {self.inspection.summary}")
        iso_mode = mode is WriteMode.EXTRACTED_ISO
        vtsi_mode = bool(
            mode is WriteMode.DD
            and self.inspection is not None
            and self.inspection.sparse_format == "VTSI"
        )
        virtual_mode = bool(
            mode is WriteMode.DD
            and self.inspection is not None
            and self.inspection.virtual_format
        )
        mandatory_verification = self.verification_is_mandatory()
        self.verify.setChecked(
            True if mandatory_verification else self.verify.isChecked()
        )
        self.verify.setEnabled(
            not self.operation_active and not mandatory_verification
        )
        self.update_runtime_validation_control()
        self.write_button.setText(
            "Write in ISO mode" if iso_mode else
            "Restore VTSI image" if vtsi_mode else
            "Restore virtual disk" if virtual_mode else
            "Write in DD mode (ZIP omitted)"
            if mode is WriteMode.DD and self.zip_overlay_plan is not None else
            "Write in DD mode" if mode is WriteMode.DD else
            "Choose write method"
        )
        self.update_persistence_controls()
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
            and plan.minimum_target_bytes + self.selected_persistence_bytes()
            <= device.size
            and (
                self.inspection is None
                or self.inspection.sparse_format != "VTSI"
                or device.size == self.inspection.size
            )
        )
        overlay_ready = (
            self.zip_overlay_preparer is None
            and (
                mode is WriteMode.DD
                or not self._zip_overlay_is_on_target(device)
            )
        )
        self.write_button.setEnabled(
            enough_space and overlay_ready
            and not self.operation_active and self.inspection is not None
            and not self.checksum_busy and not self.device_refresh_busy
        )
        self.tools_button.setEnabled(
            bool(device) and not self.operation_active and not self.device_refresh_busy
        )
        self.uefi_shell_button.setEnabled(
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
        self.update_zip_overlay_controls()
        if self.zip_overlay_preparer is not None:
            self.status.setText("Inspecting the ZIP overlay safely…")
        elif (
            mode is WriteMode.EXTRACTED_ISO
            and self._zip_overlay_is_on_target(device)
        ):
            self.status.setText("Move the ZIP overlay off the selected target drive")
        elif self.image and device and plan is not None and not enough_space:
            self.status.setText(
                "The selected target is too small for this write method"
            )
        elif (
            self.image and device and self.inspection is not None
            and self.inspection.sparse_format == "VTSI"
            and device.size != self.inspection.size
        ):
            self.status.setText(
                "VTSI restore requires a target with the exact expanded capacity"
            )
        elif (
            self.image and device and self.inspection is not None
            and self.inspection.sparse_format == "VTSI"
            and device.logical_sector_size != 512
        ):
            self.status.setText(
                "VTSI restore requires a drive that reports 512-byte sectors"
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
            self.compressed_virtual_preparer,
            self.iso_stager,
            self.windows_wim_extractor,
            self.constructed_writer,
            self.uefi_ntfs_writer,
            self.uefi_preparer,
            self.uefi_shell_preparer,
            self.casper_preparer,
            self.casper_stager,
            self.casper_writer,
            self.checksum_preparer,
            self.iso_staging_preparer,
            self.linux_downloader,
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
        if self.zip_overlay_plan is not None:
            omission = QMessageBox.warning(
                self,
                "ZIP overlay will not be written",
                f"DD mode copies {self.image.name} byte-for-byte. The selected ZIP "
                f"overlay {self.zip_overlay_plan.archive.name} will not be applied.\n\n"
                "Continue with the base image only?",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if omission != QMessageBox.StandardButton.Yes:
                return
        try:
            current_identity = image_identity(self.image)
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
        compatibility_warning = None
        if self.inspection.partition_table_malformed:
            compatibility_warning = (
                "This image contains malformed MBR or GPT partition metadata. "
                "A byte-for-byte copy preserves that damage and may not boot.\n\n"
                "Only continue if you intentionally need the image's exact bytes."
            )
        elif self.inspection.partition_table_incomplete:
            compatibility_warning = (
                "This compressed image stores partition metadata outside "
                "ISOpropyl's bounded inspection capture. The table is not known to "
                "be damaged, but it could not be fully validated.\n\n"
                "Only continue if you intentionally accept an unverified exact copy."
            )
        elif partition_sector_mismatch(
            self.inspection, device.logical_sector_size,
        ):
            relationship = (
                "Under the conventional assumed 512-byte MBR interpretation, "
                "this image and the selected drive have different logical sector sizes."
                if self.inspection.partition_table_kind == "mbr" else
                "This image and the selected drive use different logical sector sizes."
            )
            compatibility_warning = (
                relationship + " A byte-for-byte copy would place partition metadata "
                "at the wrong target LBAs and is not expected to boot.\n\n"
                "Only continue if you intentionally need the image's exact bytes."
            )
        elif partition_sector_unverified(
            self.inspection, device.logical_sector_size,
        ):
            compatibility_warning = (
                "The selected drive did not report its logical sector size, so "
                "ISOpropyl cannot validate this image's structured partition LBAs "
                "against the target.\n\nOnly continue if you intentionally accept "
                "an unverified exact copy."
            )
        elif self.inspection.has_windows_installer:
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
        method_description = (
            "Ventoy sparse image restore · expanded zero/data stream"
            if self.inspection.sparse_format == "VTSI"
            else (
                "Compressed virtual disk restore · decode and convert "
                "guest-visible bytes to raw disk"
                if self.inspection.compression != "none"
                else "Virtual disk restore · convert guest-visible bytes to raw disk"
            )
            if self.inspection.virtual_format
            else "DD mode · exact byte-for-byte copy"
        )
        virtual_size_details = ""
        if self.inspection.virtual_format:
            if self.inspection.compression != "none":
                virtual_size_details = (
                    f"Compressed file: "
                    f"{self.display_size(self.inspection.container_size)}\n"
                    f"Decoded container: "
                    f"{self.display_size(self.inspection.decoded_container_size)}\n"
                )
            else:
                virtual_size_details = (
                    f"Container: {self.display_size(self.inspection.container_size)}\n"
                )
            virtual_size_details += (
                f"Guest-visible disk: {self.display_size(self.inspection.size)}\n"
            )
        answer = QMessageBox.warning(
            self, "Erase removable drive?",
            f"Everything on {self.display_device(device)} will be permanently erased.\n\n"
            f"Image: {self.image.name}\nMethod: {method_description}\n"
            f"{virtual_size_details}"
            f"Layout: {self.inspection.layout}\n"
            f"Target: {device.path}\nSerial: {device.serial or device.wwn or 'not reported'}\n\n"
            "Check the target carefully before continuing.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer == QMessageBox.StandardButton.Yes:
            try:
                confirmed_identity = image_identity(self.image)
            except OSError as error:
                QMessageBox.critical(self, "Image unavailable", str(error))
                return
            if confirmed_identity != self.inspection_identity:
                QMessageBox.warning(
                    self,
                    "Image changed",
                    "The image changed during confirmation. Select it again "
                    "before writing.",
                )
                return
            self.logger.info("Confirmed write: image=%s target=%s identity=%s", self.image, device.path, device.identity)
            self.start_write(
                self.image, device, self.verify.isChecked(), confirmed_identity,
            )

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
        base_entries = self.archive_entries()
        try:
            entries = self.effective_archive_entries()
            recommendation = recommend_write_method(
                inspection, entries, target_size=device.size,
                target_logical_sector_size=device.logical_sector_size,
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
        self.start_constructed_iso_write(list(base_entries), plan)

    def start_write(
        self,
        image: Path,
        device: Device,
        should_verify: bool,
        expected_source_identity: tuple[int, int, int, int, int],
    ) -> None:
        try:
            source_identity = image_identity(image)
        except OSError as error:
            QMessageBox.critical(self, "Image unavailable", str(error))
            return
        if source_identity != expected_source_identity:
            QMessageBox.warning(
                self,
                "Image changed",
                "The image changed after confirmation. Select it again before writing.",
            )
            return
        self.writer = ImageWriter()
        inspection = self.inspection
        virtual_format = inspection.virtual_format if inspection is not None else ""
        compressed_virtual = bool(
            virtual_format
            and inspection is not None
            and inspection.compression != "none"
        )
        self.virtual_stager = VirtualDiskStager() if virtual_format else None
        self.compressed_virtual_preparer = (
            CompressedVirtualDiskPreparer() if compressed_virtual else None
        )
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
                if matches[0].logical_sector_size != device.logical_sector_size:
                    raise RuntimeError(
                        "The selected drive's logical sector size changed. "
                        "Refresh and select it again."
                    )
                if image_is_on_device(str(image), device):
                    raise RuntimeError(
                        "The selected image is stored on the target drive. Move it to another disk before writing."
                    )
                if image_identity(image) != source_identity:
                    raise RuntimeError("The selected image changed after confirmation. Choose it again before writing.")
                if self.virtual_stager is not None:
                    try:
                        stage_root_on_target = path_is_on_device(
                            tempfile.gettempdir(), device,
                        )
                    except OSError:
                        stage_root_on_target = True
                    if stage_root_on_target:
                        raise RuntimeError(
                            "ISOpropyl's temporary staging directory is on the "
                            "selected target drive. Configure temporary storage "
                            "on another disk before writing."
                        )
                staged = None
                prepared_container = None
                write_source = image
                if self.virtual_stager is not None:
                    if self.compressed_virtual_preparer is not None:
                        expected_format = {
                            "VHD": "vpc",
                            "VHDX": "vhdx",
                            "QCOW": "qcow",
                            "QCOW2": "qcow2",
                        }.get(virtual_format)
                        if expected_format is None or inspection is None:
                            raise RuntimeError(
                                "The confirmed virtual disk format is unsupported"
                            )
                        self.bridge.status_changed.emit(
                            "Decoding compressed virtual disk…"
                        )
                        prepared_container = self.compressed_virtual_preparer.prepare(
                            image,
                            expected_identity=expected_source_identity,
                            expected_format=expected_format,
                            expected_virtual_size=inspection.size,
                        )
                        info = prepared_container.info
                    else:
                        info = inspect_virtual_disk(image)
                        virtual_identity = (
                            info.identity.device, info.identity.inode,
                            info.identity.size, info.identity.modified_ns,
                            info.identity.changed_ns,
                        )
                        if virtual_identity != expected_source_identity:
                            raise RuntimeError(
                                "The selected virtual disk changed after confirmation. "
                                "Choose it again before writing."
                            )
                    try:
                        staged = self.virtual_stager.stage(
                            info,
                            lambda d, t: self.bridge.progress.emit(
                                d, t, "Converting virtual disk",
                            ),
                        )
                    except BaseException:
                        if prepared_container is not None:
                            prepared_container.close()
                            prepared_container = None
                        raise
                    write_source = staged.path
                    if image_is_on_device(str(write_source), device):
                        staged.close()
                        staged = None
                        if prepared_container is not None:
                            prepared_container.close()
                            prepared_container = None
                        raise RuntimeError(
                            "The private virtual-disk stage was created on the "
                            "target drive. Configure temporary storage on another "
                            "disk before writing."
                        )
                try:
                    self.writer.write(
                        write_source, device,
                        lambda d, t: self.bridge.progress.emit(d, t, "Writing"),
                        expected_identity=(
                            expected_source_identity if staged is None else None
                        ),
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
                    if prepared_container is not None:
                        prepared_container.close()
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
            f"{self.display_size(snapshot.done)} of {self.display_size(snapshot.total)}"
        )
        if snapshot.bytes_per_second:
            details += f"  ·  {self.display_size(snapshot.bytes_per_second)}/s"
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
        self.compressed_virtual_preparer = None
        self.iso_stager = None
        self.iso_staging_preparer = None
        self.iso_staging_token = None
        self.windows_wim_extractor = None
        self.constructed_writer = None
        self.uefi_ntfs_writer = None
        self.uefi_preparer = None
        self.uefi_shell_preparer = None
        self.uefi_shell_token = None
        self.casper_preparer = None
        self.casper_stager = None
        self.casper_writer = None
        self.pending_iso_write = None
        self.runtime_validation_cancel_event = threading.Event()
        if self.iso_workspace is not None:
            try:
                self.iso_workspace.cleanup()
            except OSError as error:
                self.logger.warning("Could not remove ISO workspace: %s", error)
                message += " Temporary workspace cleanup was incomplete."
            self.iso_workspace = None
        if self.uefi_shell_workspace is not None:
            try:
                self.uefi_shell_workspace.cleanup()
            except OSError as error:
                self.logger.warning(
                    "Could not remove UEFI Shell workspace: %s", error,
                )
                message += " Temporary UEFI Shell workspace cleanup was incomplete."
            self.uefi_shell_workspace = None
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
        mandatory_verification = self.verification_is_mandatory()
        if mandatory_verification:
            self.verify.setChecked(True)
        self.verify.setEnabled(not busy and not mandatory_verification)
        self.runtime_validation.setEnabled(False)
        self.show_external.setEnabled(not busy)
        self.tools_button.setEnabled(not busy and self.selected_device() is not None)
        self.uefi_shell_button.setEnabled(
            not busy and self.selected_device() is not None
            and not self.device_refresh_busy
        )
        self.optical_button.setEnabled(not busy)
        self.settings_button.setEnabled(not busy)
        self.checksum_button.setEnabled(not busy and self.inspection is not None)
        self.windows_button.setEnabled(
            not busy and bool(self.inspection and self.inspection.has_windows_installer)
        )
        self.iso_plan_button.setEnabled(
            not busy and bool(self.inspection and self.inspection.is_iso9660)
        )
        self.update_zip_overlay_controls()
        self.write_button.setEnabled(not busy)
        self.cancel_button.setVisible(busy)
        self.cancel_button.setEnabled(busy)
        if not busy:
            self.update_persistence_controls()
            self.update_runtime_validation_control()
            self.update_ready()

    def cancel(self) -> None:
        was_inspecting = self.inspection_busy
        was_planning_overlay = self.zip_overlay_preparer is not None
        if self.zip_overlay_preparer is not None:
            self.zip_overlay_preparer.cancel()
            self.zip_overlay_generation += 1
            self.zip_overlay_preparer = None
            self.zip_overlay_token = None
            self.update_zip_overlay_controls()
        self.inspection_cancel_event.set()
        self.runtime_validation_cancel_event.set()
        self.inspection_busy = False
        active = tuple(filter(None, (
            self.writer, self.imager, self.formatter, self.media_runner, self.eraser,
            self.optical_runner, self.extractor, self.virtual_stager,
            self.compressed_virtual_preparer,
            self.iso_stager, self.constructed_writer,
            self.uefi_ntfs_writer,
            self.uefi_preparer,
            self.uefi_shell_preparer,
            self.casper_preparer, self.casper_stager, self.casper_writer,
            self.windows_wim_extractor,
            self.checksum_preparer,
            self.iso_staging_preparer,
            self.linux_downloader,
        )))
        if active:
            self.status.setText("Stopping…")
            self.cancel_button.setEnabled(False)
            for operation in active:
                operation.cancel()
        elif was_inspecting:
            self.status.setText("Image inspection cancelled")
            self.image_detail.setText("Image inspection cancelled")
            self.write_method_reason.setText(
                "Select the image again to restart inspection."
            )
        elif was_planning_overlay:
            self.status.setText("ZIP overlay inspection cancelled")
            self.update_ready()

    def closeEvent(self, event: QCloseEvent) -> None:
        inspection_active = self.inspection_worker_count > 0
        if not self.operation_active and not inspection_active:
            self.inspection_cancel_event.set()
            if self.zip_overlay_preparer is not None:
                self.zip_overlay_preparer.cancel()
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
            if inspection_active and not self.operation_active:
                self.close_after_inspection = True
            self.cancel()
        event.ignore()

    def save_drive(self) -> None:
        device = self.selected_device()
        if not device or self.operation_active:
            return
        raw_filter = "Raw disk image (*.img)"
        vhd_filter = "Virtual PC disk (*.vhd)"
        vhdx_filter = "Hyper-V virtual disk (*.vhdx)"
        filename, selected_filter = QFileDialog.getSaveFileName(
            self, "Save removable drive as an image", f"{Path.home() / 'drive-backup.img'}",
            ";;".join((raw_filter, vhd_filter, vhdx_filter)),
        )
        if not filename:
            return
        destination = Path(filename)
        expected_suffix = {
            raw_filter: ".img", vhd_filter: ".vhd", vhdx_filter: ".vhdx",
        }.get(selected_filter)
        recognized_suffixes = {".img", ".vhd", ".vhdx"}
        if expected_suffix is None:
            expected_suffix = (
                destination.suffix.casefold()
                if destination.suffix.casefold() in recognized_suffixes
                else ".img"
            )
        if destination.suffix.casefold() in recognized_suffixes:
            if destination.suffix.casefold() != expected_suffix:
                destination = destination.with_suffix(expected_suffix)
        else:
            destination = destination.with_name(destination.name + expected_suffix)
        virtual = expected_suffix in {".vhd", ".vhdx"}
        output_name = {
            ".img": "raw disk image", ".vhd": "VHD", ".vhdx": "VHDX",
        }[expected_suffix]
        if virtual:
            try:
                validate_virtual_backup_destination(device.size, destination)
            except Exception as error:
                QMessageBox.warning(self, "Virtual backup unavailable", str(error))
                return
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
        required_space = (
            virtual_backup_required_space(device.size) if virtual else device.size
        )
        if free < required_space:
            QMessageBox.critical(
                self, "Not enough free space",
                f"A safe {output_name} backup needs "
                f"{self.display_size(required_space)}, but the "
                f"destination has only {self.display_size(free)} available.",
            )
            return
        if virtual:
            workflow = (
                "ISOpropyl will first make a private exact raw capture, convert it, "
                "verify the virtual disk's complete guest-visible contents, and only "
                "then publish the result. The temporary capture and conversion can "
                f"need up to {self.display_size(required_space)} of free space."
            )
        else:
            workflow = "ISOpropyl will save an exact raw, sector-for-sector image."
        answer = QMessageBox.question(
            self, "Save complete drive image?",
            f"ISOpropyl will unmount and read all {self.display_size(device.size)} from:\n"
            f"{self.display_device(device)}\n\nand save a {output_name} to:\n"
            f"{destination}\n\n{workflow}\n\nThe source drive will not be modified.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        identity = device.identity
        self.imager = VirtualDriveImager() if virtual else DriveImager()
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
                current_device = matches[0]
                if path_is_on_device(str(destination), current_device):
                    raise RuntimeError(
                        "The backup destination moved onto the drive being imaged. "
                        "Choose a destination on another disk."
                    )
                assert self.imager is not None
                if virtual:
                    self.imager.backup(
                        current_device, destination,
                        lambda done, total: self.bridge.progress.emit(
                            done, total, "Capturing, converting, and verifying drive"
                        ),
                    )
                else:
                    self.imager.backup(
                        current_device, destination,
                        lambda done, total: self.bridge.progress.emit(
                            done, total, "Saving drive"
                        ),
                        sparse=False,
                    )
                self.bridge.finished.emit(
                    True, f"{output_name} backup saved to {destination}"
                )
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
        title = QLabel(self.display_device(device))
        title.setObjectName("cardTitle")
        layout.addWidget(title)
        save = QPushButton("Save complete drive as an image…")
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

    @staticmethod
    def _cleanup_uefi_shell_pending(pending: PendingUefiShell) -> None:
        try:
            pending.workspace.cleanup()
        except OSError:
            logging.getLogger("isopropyl").warning(
                "Could not remove rejected UEFI Shell workspace",
                exc_info=True,
            )

    def create_uefi_shell_media(self) -> None:
        device = self.selected_device()
        if device is None or self.operation_active or self.device_refresh_busy:
            return
        if not device.removable:
            fixed = QMessageBox.warning(
                self,
                "External hard drive or SSD selected",
                "This target reports itself as a fixed disk. Confirm that it is not "
                "a backup drive or another disk containing important data.\n\nContinue?",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if fixed != QMessageBox.StandardButton.Yes:
                return
        consent = QMessageBox.question(
            self,
            "Download verified UEFI Shell applications?",
            f"ISOpropyl will obtain the five upstream UEFI Shell {UEFI_SHELL_VERSION} "
            "applications for x86, x64, ARM64, RISC-V64, and LoongArch64 from:\n"
            f"{UEFI_SHELL_PROVENANCE_URL}\n\n"
            "Every file is pinned by exact size and SHA-256, validated as the "
            "expected EFI application, and cached only after verification. The "
            "downloaded firmware programs are never executed on Linux.\n\n"
            "These applications are unsigned. Secure Boot must be disabled on the "
            "computer that boots this USB. Continue with the network request?",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if consent != QMessageBox.StandardButton.Yes:
            return
        try:
            workspace = tempfile.TemporaryDirectory(prefix=".isopropyl-uefi-shell-")
        except OSError as error:
            QMessageBox.warning(
                self, "UEFI Shell preparation unavailable", str(error),
            )
            return
        preparer = BackgroundPreparation()
        pending = PendingUefiShell(device, workspace)
        token = UefiShellPreparationToken(preparer, pending)
        self.uefi_shell_preparer = preparer
        self.uefi_shell_token = token
        self.set_busy(True)
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        self.status.setText("Obtaining and validating UEFI Shell applications…")

        def work() -> None:
            try:
                prepared = prepare_uefi_shell(
                    cancel_event=preparer.cancel_event,
                    progress=lambda done, total: self.bridge.progress.emit(
                        done, total, "Downloading verified UEFI Shell applications",
                    ),
                )
                if preparer.cancelled:
                    raise UefiShellCancelled("UEFI Shell preparation was cancelled")
                stage = stage_uefi_shell(
                    prepared,
                    Path(workspace.name) / "ready-media",
                    cancel_event=preparer.cancel_event,
                )
                validate_uefi_shell_stage(stage)
                if preparer.cancelled:
                    raise UefiShellCancelled("UEFI Shell preparation was cancelled")
                plan = build_constructed_media_plan(
                    stage.root,
                    device,
                    FormatPartitionTable.GPT,
                    volume_label="UEFI_SHELL",
                )
                self.bridge.uefi_shell_preparation_finished.emit(
                    token, (stage, plan), None,
                )
            except Exception as error:
                self.bridge.uefi_shell_preparation_finished.emit(
                    token, None, error,
                )

        threading.Thread(target=work, daemon=True).start()

    def on_uefi_shell_preparation_finished(
        self,
        token_object: object,
        result: object,
        error: object,
    ) -> None:
        if not isinstance(token_object, UefiShellPreparationToken):
            return
        token = token_object
        if token is not self.uefi_shell_token:
            self._cleanup_uefi_shell_pending(token.pending)
            return
        preparer = token.operation
        pending = token.pending
        self.uefi_shell_preparer = None
        self.uefi_shell_token = None
        self.progress.setRange(0, 1000)
        if error is not None or preparer.cancelled:
            self._cleanup_uefi_shell_pending(pending)
            self.set_busy(False)
            if preparer.cancelled:
                message = "UEFI Shell preparation was cancelled"
                self.logger.info(message)
                self.status.setText(message)
            else:
                message = str(error)
                self.logger.warning("UEFI Shell preparation failed: %s", message)
                self.status.setText("UEFI Shell media is not active")
                QMessageBox.warning(
                    self, "UEFI Shell preparation unavailable", message,
                )
            return
        if (
            not isinstance(result, tuple)
            or len(result) != 2
            or not isinstance(result[0], UefiShellStage)
            or not isinstance(result[1], ConstructedMediaPlan)
        ):
            self._cleanup_uefi_shell_pending(pending)
            self.set_busy(False)
            QMessageBox.warning(
                self,
                "UEFI Shell preparation unavailable",
                "The background safety check returned an invalid result.",
            )
            return
        stage, plan = result
        try:
            validate_uefi_shell_stage(stage)
            validate_constructed_media_plan(plan)
        except Exception as validation_error:
            self._cleanup_uefi_shell_pending(pending)
            self.set_busy(False)
            QMessageBox.warning(
                self, "UEFI Shell preparation unavailable", str(validation_error),
            )
            return
        if (
            stage.root != Path(pending.workspace.name) / "ready-media"
            or stage.root != plan.staging_root
            or plan.device.identity != pending.device.identity
            or plan.partition_table is not FormatPartitionTable.GPT
            or plan.filesystem is not FormatFilesystem.FAT32
            or plan.volume_label != "UEFI_SHELL"
        ):
            self._cleanup_uefi_shell_pending(pending)
            self.set_busy(False)
            QMessageBox.warning(
                self,
                "UEFI Shell preparation unavailable",
                "The prepared media plan no longer matches the selected target.",
            )
            return
        self._confirm_and_write_uefi_shell(pending, stage, plan)

    def _confirm_and_write_uefi_shell(
        self,
        pending: PendingUefiShell,
        stage: UefiShellStage,
        plan: ConstructedMediaPlan,
    ) -> None:
        device = pending.device
        confirmation = QDialog(self)
        confirmation.setObjectName("uefiShellConfirmationDialog")
        confirmation.setWindowTitle("Final UEFI Shell media confirmation")
        confirmation.setMinimumWidth(680)
        layout = QVBoxLayout(confirmation)
        warning = QLabel(
            "ALL DATA ON THIS TARGET WILL BE ERASED\n\n"
            f"{self.display_device(device)}\n"
            f"Path: {device.path}\n"
            f"Serial: {device.serial or device.wwn or 'not reported'}\n\n"
            f"Layout: GPT / FAT32 / UEFI_SHELL\n"
            f"Payloads: {', '.join(stage.architectures)}\n"
            "Read-back verification: every copied file\n"
            "Secure Boot: must be disabled; these upstream applications are unsigned."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet("color: #ff8a80; font-weight: 650;")
        layout.addWidget(warning)
        phrase_text = f"WRITE {device.path}"
        instruction = QLabel(f"Type {phrase_text} to enable the write button.")
        layout.addWidget(instruction)
        phrase = QLineEdit()
        phrase.setObjectName("uefiShellConfirmationPhrase")
        phrase.setPlaceholderText(phrase_text)
        layout.addWidget(phrase)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        start = buttons.addButton(
            "Write UEFI Shell", QDialogButtonBox.ButtonRole.AcceptRole,
        )
        start.setObjectName("uefiShellWriteButton")
        start.setEnabled(False)
        phrase.textChanged.connect(
            lambda value: start.setEnabled(value == phrase_text)
        )
        start.clicked.connect(confirmation.accept)
        buttons.rejected.connect(confirmation.reject)
        layout.addWidget(buttons)
        if confirmation.exec() != QDialog.DialogCode.Accepted:
            self._cleanup_uefi_shell_pending(pending)
            self.set_busy(False)
            self.status.setText("UEFI Shell media is not active")
            return

        self.uefi_shell_workspace = pending.workspace
        self.constructed_writer = ConstructedMediaExecutor()
        self.set_busy(True)
        self.progress.setValue(0)
        self.status.setText("Writing verified UEFI Shell media…")
        self.logger.info(
            "Confirmed UEFI Shell write: target=%s identity=%s architectures=%s",
            device.path, device.identity, stage.architectures,
        )

        def work() -> None:
            try:
                assert self.constructed_writer is not None
                result = self.constructed_writer.execute(
                    plan,
                    lambda update: self.bridge.progress.emit(
                        update.bytes_done,
                        update.total_bytes,
                        update.stage + (
                            f" · {update.relative_path}"
                            if update.relative_path else ""
                        ),
                    ),
                )
                if result.powered_off:
                    message = (
                        "The multi-architecture UEFI Shell USB is ready and safely "
                        "powered off. Disable Secure Boot before using it."
                    )
                elif not result.unmounted:
                    detail = (
                        result.cleanup_diagnostic + " "
                        if result.cleanup_diagnostic else ""
                    )
                    message = (
                        "UEFI Shell media was written but could not be cleanly "
                        f"unmounted. {detail}Eject it with your desktop before removal."
                    )
                else:
                    message = (
                        "The multi-architecture UEFI Shell USB is ready. Eject it "
                        "with your desktop before removal and disable Secure Boot "
                        "before using it."
                    )
                self.bridge.finished.emit(True, message)
            except ConstructedMediaCancelled as operation_error:
                self.logger.info("UEFI Shell write cancelled: %s", operation_error)
                self.bridge.finished.emit(False, str(operation_error))
            except Exception as operation_error:
                self.logger.exception("UEFI Shell write failed")
                self.bridge.finished.emit(False, str(operation_error))

        threading.Thread(target=work, daemon=True).start()

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
                f"{self.display_size(device.size)}",
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
            f"Read {self.display_size(plan.readable_bytes)} from {device.path}\n"
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
            f"Hide {self.display_device(device)} from ISOpropyl's destination list "
            "on future connections?\n\n"
            "You can clear the ignored-drive list under Settings.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        ignored = self.ignored_devices()
        name = " ".join(
            part for part in (device.vendor, device.model) if part
        ).strip() or "USB drive"
        # Persist an identity-oriented description, not a size rendered using
        # the display-unit preference that happened to be active at this time.
        ignored[device.stable_id] = f"{name} · {device.path}"
        previous = str(self.settings.value("ignored_devices", "{}"))
        self.settings.setValue("ignored_devices", json.dumps(ignored, sort_keys=True))
        persistence_error = settings_sync_error(self.settings)
        if persistence_error:
            if settings_sync_was_committed(self.settings):
                QMessageBox.warning(
                    self,
                    "Ignored drive saved with a durability warning",
                    "The drive was added to the persistent ignored-drive list, "
                    "but the settings directory could not confirm durable storage.\n\n"
                    f"{persistence_error}",
                )
                self.logger.warning(
                    "Ignored-drive setting committed with a durability warning: %s",
                    persistence_error,
                )
                self.refresh_devices()
                return
            self.settings.setValue("ignored_devices", previous)
            QMessageBox.warning(
                self,
                "Could not save ignored drive",
                "The drive was not added to the persistent ignored-drive list.\n\n"
                f"{persistence_error}",
            )
            return
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
        filesystem.setObjectName("restoreFilesystem")
        filesystem_choices = (
            (
                "FAT12 — tiny legacy media (up to "
                f"{self.display_size(256 * 1024**2)})",
                FormatFilesystem.FAT12,
            ),
            (
                "FAT16 — legacy media ("
                f"{self.display_size(128 * 1024**2)} to "
                f"{self.display_size(4 * 1024**3)})",
                FormatFilesystem.FAT16,
            ),
            ("FAT32 — widest device compatibility", FormatFilesystem.FAT32),
            ("exFAT — large files and cross-platform use", FormatFilesystem.EXFAT),
            ("NTFS — Windows-focused", FormatFilesystem.NTFS),
            (
                "UDF 2.01 — large cross-platform files (macOS caveat)",
                FormatFilesystem.UDF,
            ),
            ("ext2 — legacy Linux compatibility", FormatFilesystem.EXT2),
            ("ext3 — journaled legacy Linux", FormatFilesystem.EXT3),
            ("ext4 — Linux-focused", FormatFilesystem.EXT4),
        )
        layout.addWidget(filesystem)
        filesystem_note_text = (
            "Only full-capacity formats compatible with this drive's size are listed. "
            "FAT12/FAT16 limits are conservative formatter envelopes, not universal "
            "device-compatibility promises. A partitioned UDF drive works on Linux "
            "and Windows but is generally not mounted automatically by macOS."
        )
        filesystem_note = QLabel(filesystem_note_text)
        filesystem_note.setWordWrap(True)
        filesystem_note.setObjectName("muted")
        layout.addWidget(filesystem_note)
        layout.addWidget(QLabel("Partition table"))
        table = QComboBox()
        table.setObjectName("restorePartitionTable")
        table.addItem("MBR — widest legacy compatibility", FormatPartitionTable.MBR)
        table.addItem("GPT — modern systems", FormatPartitionTable.GPT)
        layout.addWidget(table)
        allocation_label = QLabel("Allocation unit size")
        layout.addWidget(allocation_label)
        allocation = QComboBox()
        allocation.setObjectName("restoreAllocationUnit")
        layout.addWidget(allocation)
        allocation_note = QLabel()
        allocation_note.setWordWrap(True)
        allocation_note.setObjectName("muted")
        layout.addWidget(allocation_note)

        def refresh_allocation_units() -> None:
            selected_filesystem = filesystem.currentData()
            selected_table = table.currentData()
            logical_sector_size = device.logical_sector_size
            allocation.blockSignals(True)
            allocation.clear()
            choices: tuple[int, ...] = ()
            automatic_supported = bool(
                selected_filesystem is not None
                and restore_filesystem_geometry_supported(
                    selected_filesystem,
                    device.size,
                    logical_sector_size,
                    selected_table,
                )
            )
            if automatic_supported:
                allocation.addItem("Automatic — formatter default", None)
            if selected_filesystem is not None:
                choices = restore_allocation_unit_sizes(
                    selected_filesystem,
                    device.size,
                    logical_sector_size,
                    selected_table,
                )
            for size in choices:
                allocation.addItem(
                    f"{self.display_size(size)} · {size:,} bytes", size,
                )
                allocation.setItemData(
                    allocation.count() - 1,
                    f"Exact allocation unit: {size:,} bytes",
                    Qt.ItemDataRole.ToolTipRole,
                )
            allocation.blockSignals(False)
            allocation.setEnabled(allocation.count() > 1)
            review = buttons.button(QDialogButtonBox.StandardButton.Ok)
            review.setEnabled(filesystem.count() > 0 and allocation.count() > 0)
            if selected_filesystem in {
                FormatFilesystem.EXT2,
                FormatFilesystem.EXT3,
                FormatFilesystem.EXT4,
            }:
                allocation_label.setText("Filesystem block size")
                if not logical_sector_size:
                    allocation_note.setText(
                        "The drive did not report a logical sector size, so only "
                        "the host formatter's Automatic choice is available. "
                        "ISOpropyl will verify the geometry before erasing."
                    )
                else:
                    allocation_note.setText(
                        "Explicit ext block-size choices are limited to portable "
                        "1, 2, or 4 KiB values compatible with the reported logical "
                        "sector; Automatic follows the host mke2fs policy."
                    )
            else:
                allocation_label.setText("Allocation unit size")
                if selected_filesystem is FormatFilesystem.UDF:
                    allocation_note.setText(
                        "UDF uses the target's logical sector size automatically; "
                        "overriding it would reduce interoperability."
                    )
                elif not logical_sector_size:
                    allocation_note.setText(
                        "The drive did not report a logical sector size during "
                        "discovery, so only the formatter default is available. "
                        "ISOpropyl will still verify the sector size before erasing."
                    )
                elif selected_filesystem is FormatFilesystem.NTFS:
                    allocation_note.setText(
                        "NTFS values above 4 KiB disable filesystem compression; "
                        "values above 64 KiB also exceed Rufus's compatibility-oriented "
                        "range and may not work on older systems."
                    )
                else:
                    allocation_note.setText(
                        "Only exact sizes compatible with the planned partition, "
                        "filesystem limits, and reported logical sector are shown."
                    )
        layout.addWidget(QLabel("Volume label (optional)"))
        label = QLineEdit("USB")
        layout.addWidget(label)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Review erase…")

        def refresh_restore_geometry() -> None:
            selected_table = table.currentData()
            previous = filesystem.currentData()
            filesystem.blockSignals(True)
            filesystem.clear()
            for text, candidate in filesystem_choices:
                automatic = restore_filesystem_geometry_supported(
                    candidate,
                    device.size,
                    device.logical_sector_size,
                    selected_table,
                )
                explicit = restore_allocation_unit_sizes(
                    candidate,
                    device.size,
                    device.logical_sector_size,
                    selected_table,
                )
                if automatic or explicit:
                    filesystem.addItem(text, candidate)
            preferred_index = filesystem.findData(previous)
            if preferred_index < 0:
                preferred_index = filesystem.findData(FormatFilesystem.FAT32)
            filesystem.setCurrentIndex(preferred_index if preferred_index >= 0 else 0)
            filesystem.blockSignals(False)
            if filesystem.count() == 0:
                filesystem_note.setText(
                    "No restore filesystem supports the drive's reported capacity, "
                    "partition table, and logical sector size. ISOpropyl will not "
                    "repartition it."
                )
            else:
                filesystem_note.setText(filesystem_note_text)
            refresh_allocation_units()

        filesystem.currentIndexChanged.connect(refresh_allocation_units)
        table.currentIndexChanged.connect(refresh_restore_geometry)
        refresh_restore_geometry()
        if filesystem.count() == 0:
            gpt_index = table.findData(FormatPartitionTable.GPT)
            if gpt_index >= 0:
                table.setCurrentIndex(gpt_index)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            plan = create_format_plan(
                device, filesystem.currentData(), table.currentData(), label.text(),
                allocation_unit_size=allocation.currentData(),
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
            f"ALL DATA WILL BE ERASED\n\n{self.display_device(device)}\n"
            f"Serial: {device.serial or device.wwn or 'not reported'}\n"
            f"New layout: {plan.partition_table.value.upper()}, "
            f"{plan.filesystem.value.upper()}, label {plan.label or '(none)'}\n"
            + (
                "Filesystem block size: "
                if plan.filesystem in {
                    FormatFilesystem.EXT2,
                    FormatFilesystem.EXT3,
                    FormatFilesystem.EXT4,
                }
                else "Allocation unit size: "
            )
            + (
                "formatter default"
                if plan.allocation_unit_size is None
                else (
                    f"{self.display_size(plan.allocation_unit_size)} "
                    f"({plan.allocation_unit_size:,} bytes)"
                )
            )
            + "\n\n"
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
            f"Full zero pass — overwrite all {self.display_size(device.size)}",
            EraseMode.FULL_ZERO,
        )
        mode.addItem(
            "Quick boundary zero — first and last "
            f"{self.display_size(QUICK_BOUNDARY_BYTES)} only",
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
            plan = build_erase_plan(
                device, mode.currentData(), size_unit_mode=self.size_unit_mode,
            )
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
                    description = (
                        "the first and last "
                        f"{self.display_size(QUICK_BOUNDARY_BYTES)} boundaries"
                    )
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
                device, mode.currentData(), passes=int(passes.currentData()),
                size_unit_mode=self.size_unit_mode,
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

    def on_inspection_finished(
        self,
        identity: object,
        result: object,
        generation: object | None = None,
    ) -> None:
        if generation is not None and generation != self.inspection_generation:
            return
        self.inspection_busy = False
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
            self._distro_policy_inspection = None
            self._distro_policy_exclusion_reason = ""
            self.write_recommendation = None
            self.write_method.clear()
            self.write_method.setEnabled(False)
            self.write_method_reason.setText("Image inspection did not complete.")
            self.image_detail.setText(f"Could not inspect image: {result}")
            self.persistence_profile = None
            self.persistence_controls.setVisible(False)
        else:
            self.inspection = result  # type: ignore[assignment]
            self.inspection_identity = identity
            self.persistence_profile = supported_casper_profile(self.inspection)
            self.logger.info("Image inspection: %s", self.inspection.summary)
            if self.inspection.sparse_format == "VTSI":
                self.image_label.setText(
                    f"{self.image.name}  ·  "
                    f"{self.display_size(self.inspection.size)} expanded disk "
                    f"({self.display_size(self.inspection.container_size)} sparse file)"
                )
            elif (
                self.inspection.virtual_format
                and self.inspection.compression != "none"
            ):
                self.image_label.setText(
                    f"{self.image.name}  ·  "
                    f"{self.display_size(self.inspection.size)} virtual disk "
                    f"({self.display_size(self.inspection.decoded_container_size)} "
                    f"decoded · {self.display_size(self.inspection.container_size)} "
                    f"{self.inspection.compression.upper()})"
                )
            elif self.inspection.compression != "none":
                self.image_label.setText(
                    f"{self.image.name}  ·  "
                    f"{self.display_size(self.inspection.size)} expanded"
                )
            elif self.inspection.virtual_format:
                self.image_label.setText(
                    f"{self.image.name}  ·  "
                    f"{self.display_size(self.inspection.size)} virtual "
                    f"({self.display_size(self.inspection.container_size)} container)"
                )
            self.image_detail.setText(f"DD mode · {self.inspection.summary}")
            detail_lines = [
                f"Layout: {self.inspection.layout}",
                f"Boot modes: {', '.join(self.inspection.boot_modes) or 'not detected'}",
                f"Architectures: {', '.join(self.inspection.architectures) or 'not detected'}",
                f"Bootloader: {self.inspection.bootloader}",
            ]
            if self.inspection.partition_table_incomplete:
                detail_lines.append("Partition structure: Inspection incomplete")
            elif self.inspection.partition_table_valid is not None:
                table_state = (
                    "valid" if self.inspection.partition_table_valid else "malformed"
                )
                table_names = {
                    "gpt": "GPT",
                    "hybrid-gpt": "Hybrid MBR/GPT",
                    "mbr": "MBR",
                    "malformed": "Malformed",
                }
                structure_details = [
                    table_names.get(
                        self.inspection.partition_table_kind,
                        self.inspection.partition_table_kind or "Unknown",
                    ),
                ]
                if table_state.casefold() not in {
                    detail.casefold() for detail in structure_details
                }:
                    structure_details.append(table_state)
                if self.inspection.partition_table_sector_size:
                    assumption = (
                        " assumed"
                        if self.inspection.partition_table_kind == "mbr" else ""
                    )
                    structure_details.append(
                        f"{self.inspection.partition_table_sector_size}-byte sectors"
                        f"{assumption}"
                    )
                detail_lines.append(
                    "Partition structure: " + " · ".join(structure_details)
                )
                boot_code_names = {
                    "grub": "GRUB",
                    "syslinux": "Syslinux",
                    "windows": "Windows",
                    "empty": "Empty",
                    "unrecognized": "Unrecognized",
                }
                detail_lines.append(
                    "MBR boot code: "
                    + boot_code_names.get(
                        self.inspection.mbr_boot_code,
                        self.inspection.mbr_boot_code or "Not detected",
                    )
                )
            if self.inspection.partition_table_issues:
                detail_lines.append("Partition-table issues:")
                detail_lines.extend(
                    f"  {issue}"
                    for issue in self.inspection.partition_table_issues[:8]
                )
                if len(self.inspection.partition_table_issues) > 8:
                    detail_lines.append(
                        "  … "
                        f"{len(self.inspection.partition_table_issues) - 8} more"
                    )
            if self.inspection.bootloader_build:
                detail_lines.append(
                    f"Exact boot payload: {self.inspection.bootloader_build} "
                    f"({self.inspection.bootloader_dependency})"
                )
                try:
                    matching_bundle = bundle_for_dependency(
                        self.inspection.bootloader_dependency,
                    )
                except CatalogError as error:
                    matching_bundle = None
                    self.logger.warning("Boot-helper catalog is unavailable: %s", error)
                if matching_bundle is not None:
                    detail_lines.append(
                        "A hash-pinned matching payload bundle is cataloged; "
                        "BIOS installation remains disabled until its media executor is audited"
                    )
            elif self.inspection.bootloader_identity_ambiguous:
                detail_lines.append(
                    "Bootloader identity inspection is incomplete or conflicting"
                )
            elif self.inspection.bootloader_version:
                detail_lines.append(
                    f"Bootloader version {self.inspection.bootloader_version}; exact build unknown"
                )
            if self.inspection.has_windows_installer:
                detail_lines.append("Windows installer image detected")
                classified = classify_windows_installer_members(
                    self.inspection.members,
                )
                selected_paths = (
                    classified.wim_paths
                    if classified.wim_paths else (
                        (classified.esd_path,) if classified.esd_path else ()
                    )
                ) if classified.valid else ()
                self.windows_install_source_count = (
                    len(classified.wim_paths)
                    + (1 if classified.esd_path is not None else 0)
                    if classified.valid else 0
                )
                by_path = {member.path: member for member in self.inspection.members}
                candidates = tuple(
                    ArchiveEntry(path, by_path[path].size)
                    for path in selected_paths if path in by_path
                )
                self.windows_wim_candidates = candidates
                if len(candidates) == 1:
                    member = candidates[0]
                    self.windows_wim_member = member
                    self.windows_wim_error = ""
                    self.windows_button.setToolTip(
                        f"Inspect {member.path} to list its Windows image indexes"
                    )
                elif candidates:
                    self.windows_wim_member = None
                    self.windows_wim_error = ""
                    self.windows_button.setToolTip(
                        f"Choose one of {len(candidates)} install.wim sources to inspect"
                    )
                else:
                    self.windows_wim_candidates = ()
                    self.windows_wim_member = None
                    self.windows_wim_error = (
                        "The ISO catalog does not contain a safe, bounded Windows "
                        "install.wim source or one canonical sources/install.esd."
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
                detail_lines.append(
                    "UEFI payload signatures — integrity only; signer identity, "
                    "certificate trust/revocation, timestamps, and Secure Boot "
                    "acceptance are not evaluated:"
                )
                for payload in self.inspection.uefi_payloads[:8]:
                    if payload.authenticode is not None:
                        auth_state = {
                            AuthenticodeIntegrityState.VALID_UNTRUSTED: (
                                "Authenticode integrity passed (signer trust not evaluated)"
                            ),
                            AuthenticodeIntegrityState.INVALID: "Authenticode check failed",
                            AuthenticodeIntegrityState.MALFORMED: "Authenticode data malformed",
                            AuthenticodeIntegrityState.UNSUPPORTED: "Authenticode check unsupported",
                            AuthenticodeIntegrityState.INDETERMINATE: (
                                "Authenticode result indeterminate"
                            ),
                        }[payload.authenticode.state]
                    elif payload.signature_state is SignatureTableState.ABSENT:
                        auth_state = "Authenticode absent"
                    else:
                        auth_state = "Authenticode not checked"
                    detail_lines.append(
                        f"  {payload.path}: {payload.architecture}, certificate "
                        f"{payload.signature_state.value}, {auth_state}, "
                        f"SBAT {payload.sbat_state.value}"
                    )
            if self.inspection.uefi_analysis_issues:
                detail_lines.append(
                    f"UEFI inspection issues: {len(self.inspection.uefi_analysis_issues)}"
                )
            if not self.inspection.contents_scanned:
                detail_lines.append("Install 7-Zip for deeper content inspection")
            if self.persistence_profile is not None:
                detail_lines.append(
                    "Persistent live storage candidate: Ubuntu "
                    f"{self.persistence_profile.ubuntu_release} LTS amd64; "
                    "private staging performs final GRUB validation"
                )
            self.image_detail.setToolTip("\n".join(detail_lines))
            self.windows_button.setEnabled(self.inspection.has_windows_installer)
            self.iso_plan_button.setEnabled(self.inspection.is_iso9660)
            self.checksum_button.setEnabled(True)
        self.rebuild_write_recommendation(preserve_selection=False)
        self.update_ready()

    def on_inspection_worker_finished(self) -> None:
        if self.inspection_worker_count > 0:
            self.inspection_worker_count -= 1
        if self.inspection_worker_count == 0 and self.close_after_inspection:
            self.close_after_inspection = False
            self.close()

    def select_windows_wim_source(self, member: ArchiveEntry | None) -> None:
        if member is not None and member not in self.windows_wim_candidates:
            raise ValueError("The selected Windows image source is not in this ISO catalog")
        if member == self.windows_wim_member:
            return
        self.windows_metadata_generation += 1
        self.windows_wim_member = member
        self.windows_wim_editions = ()
        self.windows_wim_error = ""
        if (
            self.windows_options.install_image is not None
            or self.windows_options.install_image_path
            or self.windows_options.bypass_online_account_requirement
            or self.windows_options.acknowledge_online_account_limitations
        ):
            self.windows_options = replace(
                self.windows_options, install_image=None, install_image_path="",
                bypass_online_account_requirement=False,
                acknowledge_online_account_limitations=False,
            )

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
        extractor = SafeIsoExtractor()
        self.windows_wim_extractor = extractor
        self.windows_metadata_generation += 1
        token = WindowsMetadataToken(
            self.windows_metadata_generation, identity, member, extractor,
        )
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
                    extractor.execute(
                        plan,
                        lambda update: self.bridge.windows_metadata_progress.emit(
                            token, update.bytes_done, update.total_bytes,
                        ),
                    )
                    source = destination.joinpath(*Path(member.path).parts)
                    info = inspect_wim(
                        source,
                        cancel_event=extractor.cancel_event,
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
            self.bridge.windows_metadata_finished.emit(token, member.path, result)

        threading.Thread(target=work, daemon=True).start()

    def on_windows_metadata_progress(
        self, token_object: object, done: object, total: object,
    ) -> None:
        if not isinstance(token_object, WindowsMetadataToken):
            return
        token = token_object
        if (
            token.extractor is not self.windows_wim_extractor
            or token.generation != self.windows_metadata_generation
            or token.source != self.windows_wim_member
            or type(done) is not int
            or type(total) is not int
        ):
            return
        self.on_progress(done, total, "Extracting Windows image metadata source")

    def on_windows_metadata_finished(
        self, token_object: object, source_name: object, result: object,
    ) -> None:
        if not isinstance(token_object, WindowsMetadataToken):
            return
        token = token_object
        if token.extractor is not self.windows_wim_extractor:
            return
        current = False
        if self.image is not None:
            try:
                current_identity = image_identity(self.image)
            except OSError:
                current_identity = None
            current = (
                token.generation == self.windows_metadata_generation
                and token.image_identity == current_identity
                and token.source == self.windows_wim_member
                and source_name == token.source.path
            )
        self.windows_wim_extractor = None
        self.windows_button.setText("Windows options…")
        self.progress.setValue(0)
        if not self.inspection_busy and not self.operation_active:
            self.set_busy(False)
            self.update_ready()
        if not current or self.image is None or self.windows_wim_member is None:
            return
        if isinstance(result, Exception) or not isinstance(result, WimInfo):
            self.windows_wim_editions = ()
            if (
                self.windows_options.install_image is not None
                or self.windows_options.install_image_path
                or self.windows_options.bypass_online_account_requirement
                or self.windows_options.acknowledge_online_account_limitations
            ):
                self.windows_options = replace(
                    self.windows_options, install_image=None, install_image_path="",
                    bypass_online_account_requirement=False,
                    acknowledge_online_account_limitations=False,
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
        try:
            validate_wim_editions(info.editions)
        except Exception as error:
            self.windows_wim_editions = ()
            if (
                self.windows_options.install_image is not None
                or self.windows_options.install_image_path
                or self.windows_options.bypass_online_account_requirement
                or self.windows_options.acknowledge_online_account_limitations
            ):
                self.windows_options = replace(
                    self.windows_options, install_image=None, install_image_path="",
                    bypass_online_account_requirement=False,
                    acknowledge_online_account_limitations=False,
                )
            self.windows_wim_error = str(error)
            self.windows_button.setToolTip(
                f"Windows edition metadata unavailable: {self.windows_wim_error}"
            )
            return
        if info.size != token.source.size:
            self.windows_wim_editions = ()
            if (
                self.windows_options.install_image is not None
                or self.windows_options.install_image_path
                or self.windows_options.bypass_online_account_requirement
                or self.windows_options.acknowledge_online_account_limitations
            ):
                self.windows_options = replace(
                    self.windows_options, install_image=None, install_image_path="",
                    bypass_online_account_requirement=False,
                    acknowledge_online_account_limitations=False,
                )
            self.windows_wim_error = (
                "The WIM inspector returned metadata for a different catalog size"
            )
            self.windows_button.setToolTip(
                f"Windows edition metadata unavailable: {self.windows_wim_error}"
            )
            return
        self.windows_wim_editions = info.editions
        self.windows_wim_error = ""
        current_selection = self.windows_options.install_image
        selection_is_stale = current_selection is not None and (
            current_selection.source_name != self.windows_wim_member.path
            or current_selection.source_size != self.windows_wim_member.size
            or current_selection.editions != info.editions
        )
        selection_is_missing = current_selection is None and (
            bool(self.windows_options.install_image_path)
            or self.windows_options.bypass_online_account_requirement
            or self.windows_options.acknowledge_online_account_limitations
        )
        if selection_is_stale or selection_is_missing:
            self.windows_options = replace(
                self.windows_options, install_image=None, install_image_path="",
                bypass_online_account_requirement=False,
                acknowledge_online_account_limitations=False,
            )
        labels = "\n".join(edition.display_label for edition in info.editions)
        self.windows_button.setToolTip(labels)
        self.status.setText(
            f"Found {len(info.editions)} Windows installation image"
            f"{'s' if len(info.editions) != 1 else ''}"
        )

    def calculate_image_checksums(self) -> None:
        if (
            not self.image or self.inspection_identity is None
            or self.checksum_busy or self.operation_active
        ):
            return
        path = self.image
        try:
            identity = image_identity(path)
        except OSError as error:
            QMessageBox.critical(self, "Checksum calculation failed", str(error))
            return
        if identity != self.inspection_identity:
            QMessageBox.critical(
                self, "Image changed",
                "The selected image changed after inspection. Select it again before "
                "calculating checksums.",
            )
            return
        operation = BackgroundPreparation()
        self.checksum_generation += 1
        token = ChecksumToken(self.checksum_generation, identity, operation)
        self.checksum_preparer = operation
        self.checksum_busy = True
        self.checksum_button.setText("Calculating…")
        self.set_busy(True)
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        self.status.setText("Calculating image checksums…")

        def work() -> None:
            def check_cancelled() -> None:
                if operation.cancelled:
                    raise ChecksumCancelled("Checksum calculation was cancelled")

            try:
                result: object = calculate_checksums(
                    path,
                    lambda done, total: self.bridge.checksum_progress.emit(
                        token, done, total,
                    ),
                    expected_identity=identity,
                    cancel_check=check_cancelled,
                )
            except Exception as error:
                result = error
            self.bridge.checksums_finished.emit(token, result)

        threading.Thread(target=work, daemon=True).start()

    def on_checksum_progress(
        self, token: object, done: object, total: object,
    ) -> None:
        if (
            not isinstance(token, ChecksumToken)
            or token.operation is not self.checksum_preparer
            or token.generation != self.checksum_generation
            or token.image_identity != self.inspection_identity
            or type(done) is not int or type(total) is not int
            or done < 0 or total < 0 or done > total
        ):
            return
        self.on_progress(done, total, "Checksumming")

    def on_checksums_finished(self, token: object, result: object) -> None:
        if (
            not isinstance(token, ChecksumToken)
            or token.operation is not self.checksum_preparer
            or token.generation != self.checksum_generation
        ):
            return
        current = bool(
            self.image is not None
            and token.image_identity == self.inspection_identity
        )
        if current:
            try:
                current = token.image_identity == image_identity(self.image)  # type: ignore[arg-type]
            except OSError:
                current = False
        self.checksum_preparer = None
        self.checksum_busy = False
        self.checksum_button.setText("Checksums…")
        self.progress.setValue(0)
        self.set_busy(False)
        if token.operation.cancelled or isinstance(result, ChecksumCancelled):
            self.status.setText("Checksum calculation cancelled")
            return
        if not current or not self.image:
            self.status.setText(
                "Checksum result discarded because the selected image changed"
            )
            return
        if isinstance(result, Exception):
            QMessageBox.critical(self, "Checksum calculation failed", str(result))
            return
        if not (
            isinstance(result, dict)
            and set(result) == {"MD5", "SHA-1", "SHA-256", "SHA-512"}
            and all(isinstance(value, str) for value in result.values())
        ):
            QMessageBox.critical(
                self, "Checksum calculation failed",
                "The checksum worker returned an invalid result.",
            )
            return
        checksums: dict[str, str] = result
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
        base_entries = self.archive_entries()
        try:
            entries = self.effective_archive_entries()
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
            f"Catalog entries: {len(entries)}",
            f"File content: {self.display_size(plan.minimum_content_bytes)}",
            f"Conservative target minimum: {self.display_size(plan.minimum_target_bytes)}",
        ]
        if self.zip_overlay_plan is not None:
            merge = self.zip_overlay_merge
            added = merge.overlay_entries if merge is not None else ()
            lines.extend((
                "",
                f"ZIP overlay: {self.zip_overlay_plan.archive.name}",
                f"ZIP SHA-256: {self.zip_overlay_plan.archive_sha256}",
                f"ZIP expanded content: "
                f"{self.display_size(self.zip_overlay_plan.content_bytes)}",
                f"Overlay catalog: {len(self.zip_overlay_plan.members)} members · "
                f"{len(added)} new paths",
                f"Final catalog: {len(base_entries)} base entries → "
                f"{len(entries)} effective entries",
                "Merge policy: additive only; existing ISO files are never replaced.",
            ))
        if plan.needs_wim_split:
            lines.append("Transformation: split sources/install.wim for FAT32")
        if self.windows_options.install_image is not None:
            lines.append(
                f"Windows image: {self.windows_options.install_image.display_label} · "
                f"{self.windows_options.install_image.source_name}"
            )
        lines.extend(("", "Dependencies:"))
        lines.extend(
            f"• {requirement.key}: {', '.join(requirement.alternatives)}"
            for requirement in plan.requirements
        )
        lines.extend(("", "Execution blockers:"))
        lines.extend(f"• {blocker}" for blocker in plan.blockers)
        dialog = QDialog(self)
        dialog.setWindowTitle("Filesystem-aware ISO-mode plan")
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
            "Extract original ISO…", QDialogButtonBox.ButtonRole.ActionRole
        )
        extract_button.setToolTip(
            "Extract only the selected ISO. ZIP overlay files are included only by "
            "the private ISO-mode staging and USB-writing workflow."
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
                0, lambda: self.start_iso_extraction(
                    list(base_entries), destination,
                )
            )

        extract_button.clicked.connect(extract)
        write_iso_button = buttons.addButton(
            "Write USB in ISO mode…", QDialogButtonBox.ButtonRole.ActionRole
        )
        write_iso_button.setEnabled(
            plan.executable and self.selected_device() is not None
            and not self._zip_overlay_is_on_target()
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
                0, lambda: self.start_constructed_iso_write(
                    list(base_entries), plan,
                )
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
            or self.operation_active or type(write_plan) is not WritePlan
            or not write_plan.executable
        ):
            return
        base_entries = self.archive_entries()
        if tuple(entries) != base_entries:
            QMessageBox.warning(
                self,
                "ISO mode unavailable",
                "The ISO catalog or write plan changed. Review the current plan "
                "before trying again.",
            )
            self.rebuild_write_recommendation()
            return
        try:
            effective_entries = self.effective_archive_entries()
            recommendation = recommend_write_method(
                inspection,
                effective_entries,
                target_size=device.size,
                target_logical_sector_size=device.logical_sector_size,
            )
        except ValueError as error:
            QMessageBox.warning(self, "ISO mode unavailable", str(error))
            self.rebuild_write_recommendation()
            return
        fresh_plan = recommendation.iso_plan
        if (
            fresh_plan is None
            or not fresh_plan.executable
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
        if fresh_plan != write_plan:
            QMessageBox.warning(
                self,
                "ISO mode unavailable",
                "The ISO-mode plan changed. Review the refreshed plan before "
                "starting the write.",
            )
            self.rebuild_write_recommendation()
            return
        write_plan = fresh_plan
        if image_is_on_device(str(image), device):
            QMessageBox.critical(
                self, "Move the ISO first",
                "The selected ISO is stored on the target drive and would be erased. "
                "Move it to another disk before using ISO mode.",
            )
            return
        overlay = self.zip_overlay_plan
        if overlay is not None:
            try:
                overlay_on_target = path_is_on_device(str(overlay.archive), device)
            except OSError:
                overlay_on_target = True
            if overlay_on_target:
                QMessageBox.critical(
                    self,
                    "Move the ZIP overlay first",
                    "The selected ZIP overlay is stored on the target drive and "
                    "cannot be used for this write.",
                )
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
        runtime_validation_requested = self.runtime_validation.isChecked()
        if runtime_validation_requested:
            runtime_reason = self.runtime_validation_exclusion_reason()
            if runtime_reason:
                self.runtime_validation.setChecked(False)
                QMessageBox.warning(
                    self,
                    "Boot-time corruption check unavailable",
                    runtime_reason,
                )
                return
            architectures = self.runtime_validation_architectures(effective_entries)
            unsigned_architectures = tuple(
                profile.architecture
                for profile in RUNTIME_VALIDATION_ARTIFACTS
                if (
                    profile.architecture in architectures
                    and profile.signature_state is SignatureTableState.ABSENT
                )
            )
            secure_boot_note = (
                "\n\nThe " + ", ".join(unsigned_architectures)
                + " wrapper(s) are unsigned and require Secure Boot disabled."
                if unsigned_architectures else
                "\n\nThe signed x64/x86/ARM64 wrappers still depend on firmware "
                "trust in Microsoft UEFI CA 2011 and current DBX policy."
            )
            answer = QMessageBox.question(
                self,
                "Prepare the boot-time corruption check?",
                f"ISOpropyl will obtain the exact, release-pinned uefi-md5sum "
                f"v{RUNTIME_VALIDATION_VERSION} EFI wrappers (or use their verified "
                "cache), then verify size, SHA-256, PE architecture, and signature "
                "table state before use.\n\n"
                "At boot, they check an unsigned MD5 manifest for accidental media "
                "damage. This is not image authentication: anyone able to rewrite "
                "the USB can replace both files and manifest, and missing, malformed, "
                "cancelled, or failed validation can chainload the original bootloader. "
                "The check also adds boot time."
                f"{secure_boot_note}\n\nContinue?",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        working_parent = QFileDialog.getExistingDirectory(
            self,
            "Choose temporary working space for ISO mode",
            str(Path.home()),
        )
        if not working_parent:
            return
        try:
            working_on_target = path_is_on_device(working_parent, device)
        except OSError:
            working_on_target = True
        if working_on_target:
            QMessageBox.warning(
                self,
                "Choose working space on another disk",
                "ISOpropyl cannot stage the ISO on the target drive that will be erased.",
            )
            return
        persistence_bytes = self.selected_persistence_bytes()
        persistence_profile = (
            supported_casper_profile(inspection) if persistence_bytes else None
        )
        assert write_plan.layout is not None
        strategy = write_plan.layout.boot_strategy
        if persistence_bytes and (
            persistence_profile is None
            or strategy is not BootStrategy.IMAGE_NATIVE
            or write_plan.layout.main_filesystem.value != "fat32"
            or write_plan.minimum_target_bytes + persistence_bytes > device.size
        ):
            QMessageBox.warning(
                self,
                "Persistent storage unavailable",
                "The image, write plan, or selected target no longer supports the "
                "requested persistent-storage layout. Review the image and target "
                "selection before trying again.",
            )
            return
        try:
            workspace = tempfile.TemporaryDirectory(
                prefix=".isopropyl-iso-", dir=working_parent,
            )
        except OSError as error:
            QMessageBox.warning(self, "ISO mode unavailable", str(error))
            return
        customization = self.windows_options
        architecture = (
            customization.install_image.edition.architecture
            if customization.install_image is not None else
            windows_architecture(inspection.architectures)
        )
        request = IsoStagingPreparationRequest(
            image,
            current_identity,
            inspection,
            device,
            base_entries,
            write_plan,
            overlay,
            workspace,
            customization,
            architecture,
            persistence_profile=persistence_profile,
            persistence_bytes=persistence_bytes,
            runtime_validation_requested=runtime_validation_requested,
        )
        self.iso_staging_preparation_generation += 1
        operation = BackgroundPreparation()
        token = IsoStagingPreparationToken(
            self.iso_staging_preparation_generation, operation, request,
        )
        self.iso_staging_preparer = operation
        self.iso_staging_token = token
        self.set_busy(True)
        self.progress.setRange(0, 0)
        self.status.setText("Validating the ISO and ZIP overlay plan…")

        def work() -> None:
            def check_cancelled() -> None:
                if operation.cancelled:
                    raise IsoStagingCancelled("ISO staging-plan preparation was cancelled")

            try:
                staging_plan = build_iso_staging_plan(
                    request.image,
                    Path(request.workspace.name) / "ready-media",
                    request.base_entries,
                    request.write_plan,
                    overlay=request.overlay,
                    cancel_check=check_cancelled,
                    windows_customization=request.windows_customization,
                    windows_architecture=request.windows_architecture,
                )
                if request.runtime_validation_requested:
                    prepared = prepare_runtime_validation(
                        cancel_event=operation.cancel_event,
                        progress=lambda done, total: self.bridge.progress.emit(
                            done, total,
                            f"Obtaining verified uefi-md5sum v{RUNTIME_VALIDATION_VERSION}",
                        ),
                    )
                    result: object = (staging_plan, prepared)
                else:
                    result = staging_plan
            except Exception as error:
                result = error
            self.bridge.iso_staging_preparation_finished.emit(token, result)

        threading.Thread(target=work, daemon=True).start()

    def on_iso_staging_preparation_finished(
        self, token: object, result: object,
    ) -> None:
        if not isinstance(token, IsoStagingPreparationToken):
            return
        request = token.request
        if (
            token is not self.iso_staging_token
            or token.operation is not self.iso_staging_preparer
            or token.generation != self.iso_staging_preparation_generation
        ):
            workspace_is_owned = (
                self.pending_iso_write is not None
                and self.pending_iso_write.workspace is request.workspace
            ) or self.iso_workspace is request.workspace
            if not workspace_is_owned:
                try:
                    request.workspace.cleanup()
                except OSError as error:
                    self.logger.warning("Could not remove stale ISO workspace: %s", error)
            return
        self.iso_staging_preparer = None
        self.iso_staging_token = None
        self.progress.setRange(0, 1000)
        prepared_runtime_validation: PreparedRuntimeValidation | None = None
        if request.runtime_validation_requested:
            if (
                isinstance(result, tuple) and len(result) == 2
                and type(result[0]) is IsoStagingPlan
                and type(result[1]) is PreparedRuntimeValidation
            ):
                result, prepared_runtime_validation = result
                try:
                    validate_prepared_runtime_validation(
                        prepared_runtime_validation
                    )
                except RuntimeValidationError as error:
                    prepared_runtime_validation = None
                    result = error
        current = False
        try:
            current = bool(
                self.image == request.image
                and self.inspection == request.inspection
                and self.selected_device() == request.device
                and self.zip_overlay_plan == request.overlay
                and self.archive_entries() == request.base_entries
                and image_identity(request.image) == request.image_identity
                and not path_is_on_device(request.workspace.name, request.device)
                and (
                    not request.runtime_validation_requested
                    or not self.runtime_validation_exclusion_reason()
                )
            )
        except OSError:
            current = False
        if token.operation.cancelled or isinstance(result, IsoStagingCancelled):
            try:
                request.workspace.cleanup()
            except OSError as error:
                self.logger.warning("Could not remove cancelled ISO workspace: %s", error)
            self.set_busy(False)
            self.status.setText("ISO staging-plan preparation cancelled")
            return
        if (
            not current or type(result) is not IsoStagingPlan
            or (
                request.runtime_validation_requested
                and prepared_runtime_validation is None
            )
        ):
            try:
                request.workspace.cleanup()
            except OSError as error:
                self.logger.warning("Could not remove rejected ISO workspace: %s", error)
            self.set_busy(False)
            message = (
                str(result) if isinstance(result, Exception) else
                "The image, target, or ZIP overlay changed during preparation."
                if not current else
                "The background staging planner returned an invalid result."
            )
            self.status.setText("ISO mode is not active")
            QMessageBox.warning(self, "ISO mode unavailable", message)
            return
        expected_destination = Path(request.workspace.name) / "ready-media"
        if (
            result.image != request.image
            or result.destination != expected_destination
            or result.entries != request.base_entries
            or result.write_plan != request.write_plan
            or result.overlay != request.overlay
            or result.windows_customization != (
                request.windows_customization
                if request.windows_customization.enabled else None
            )
            or result.windows_architecture != (
                request.windows_architecture
                if request.windows_customization.enabled else None
            )
            or result.wim_selection != request.windows_customization.install_image
        ):
            try:
                request.workspace.cleanup()
            except OSError as error:
                self.logger.warning("Could not remove rejected ISO workspace: %s", error)
            self.set_busy(False)
            self.status.setText("ISO mode is not active")
            QMessageBox.warning(
                self,
                "ISO mode unavailable",
                "The background staging plan does not match the selected inputs.",
            )
            return
        pending = PendingIsoWrite(
            image=request.image,
            inspection=request.inspection,
            device=request.device,
            write_plan=request.write_plan,
            workspace=request.workspace,
            staging_plan=result,
            persistence_profile=request.persistence_profile,
            persistence_bytes=request.persistence_bytes,
            runtime_validation=prepared_runtime_validation,
        )
        self.set_busy(False)
        self._continue_prepared_iso_write(pending)

    def _continue_prepared_iso_write(self, pending: PendingIsoWrite) -> None:
        inspection = pending.inspection
        write_plan = pending.write_plan
        workspace = pending.workspace
        assert write_plan.layout is not None
        strategy = write_plan.layout.boot_strategy
        persistence_profile = pending.persistence_profile
        if persistence_profile is not None:
            self.start_casper_preparation(pending)
            return
        if strategy is BootStrategy.UEFI_NTFS:
            unsigned_architectures = tuple(
                architecture for architecture in inspection.architectures
                if architecture.casefold() in {"arm", "risc-v64"}
            )
            if unsigned_architectures:
                helper_detail = (
                    "This image needs NTFS and uses the unsigned "
                    + ", ".join(unsigned_architectures)
                    + " UEFI:NTFS bridge. It will not boot while Secure Boot is "
                    "enabled. ISOpropyl will still verify the helper's exact size "
                    "and SHA-256.\n\nExplicitly allow these unsigned boot payloads?"
                )
                helper_default = QMessageBox.StandardButton.Cancel
            else:
                helper_detail = (
                    "This image needs NTFS because it contains a file larger than FAT32 "
                    "can store. ISOpropyl will obtain the "
                    f"{self.display_size(UEFI_NTFS_SIZE)} UEFI:NTFS v2.8 helper "
                    "from a release-pinned Rufus source URL (or use its verified cache), "
                    "then check its exact size and SHA-256 before asking to erase the "
                    "drive.\n\n"
                    "The x64, x86, and ARM64 payloads are signed through Microsoft UEFI "
                    "CA 2011. Secure Boot can still reject them on systems that disable "
                    "third-party trust or revoke that certificate.\n\nContinue?"
                )
                helper_default = QMessageBox.StandardButton.Yes
            helper_answer = QMessageBox.question(
                self,
                "Prepare the verified UEFI:NTFS boot helper?",
                helper_detail,
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                helper_default,
            )
            if helper_answer != QMessageBox.StandardButton.Yes:
                try:
                    workspace.cleanup()
                except OSError as error:
                    self.logger.warning("Could not remove ISO workspace: %s", error)
                return
            if unsigned_architectures:
                pending = replace(pending, allow_unsigned_payloads=True)
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

    def start_casper_preparation(self, pending: PendingIsoWrite) -> None:
        preparer = BackgroundPreparation()
        self.pending_iso_write = pending
        self.casper_preparer = preparer
        self.set_busy(True)
        self.progress.setRange(0, 0)
        self.status.setText(
            "Revalidating the target and reading its logical sector size…"
        )

        def work() -> None:
            try:
                logical_sector_size = probe_casper_logical_sector_size(
                    pending.device
                )
                if preparer.cancelled:
                    raise CasperMediaCancelled(
                        "Persistent-media preparation was cancelled"
                    )
                self.bridge.casper_preparation_finished.emit(
                    preparer, logical_sector_size, None,
                )
            except Exception as error:
                self.bridge.casper_preparation_finished.emit(
                    preparer, None, error,
                )

        threading.Thread(target=work, daemon=True).start()

    def on_casper_preparation_finished(
        self,
        preparer: BackgroundPreparation,
        result: object,
        error: object,
    ) -> None:
        if preparer is not self.casper_preparer:
            return
        pending = self.pending_iso_write
        self.casper_preparer = None
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
                message = "Persistent-media preparation was cancelled"
                self.logger.info(message)
                self.status.setText(message)
            else:
                message = str(error)
                self.logger.warning("Persistent-media preparation failed: %s", message)
                self.status.setText("ISO mode is not active")
                QMessageBox.warning(
                    self, "Persistent storage unavailable", message,
                )
            return
        if type(result) is not int or result not in (512, 4096):
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
                "Persistent storage unavailable",
                "The background target check returned an unsupported logical "
                "sector size.",
            )
            return
        self.status.setText("Persistent-media target geometry is ready")
        self.confirm_and_start_iso_write(pending, None, result)

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
        persistence_enabled = pending.persistence_profile is not None
        runtime_validation_enabled = pending.runtime_validation is not None
        runtime_architectures = self.runtime_validation_architectures(
            staging_plan.effective_entries
        )
        runtime_overlay_conflict = bool(
            staging_plan.overlay is not None
            and any(
                member.entry.path.casefold() == "md5sum.txt"
                for member in staging_plan.overlay.members
            )
        )
        runtime_casper_conflict = any(
            entry.path.split("/", 1)[0].casefold() == "casper"
            for entry in staging_plan.effective_entries
        )
        runtime_reserved_originals = {
            profile.original_path.casefold()
            for profile in RUNTIME_VALIDATION_ARTIFACTS
        }
        runtime_reserved_conflict = any(
            (
                "/" not in entry.path
                and entry.path.casefold() == "md5sum.txt"
                and entry.path != "md5sum.txt"
            )
            or entry.path.casefold() in runtime_reserved_originals
            for entry in staging_plan.effective_entries
        )
        if runtime_validation_enabled:
            try:
                assert pending.runtime_validation is not None
                validate_prepared_runtime_validation(pending.runtime_validation)
            except (AssertionError, RuntimeValidationError) as error:
                try:
                    workspace.cleanup()
                except OSError as cleanup_error:
                    self.logger.warning(
                        "Could not remove ISO workspace: %s", cleanup_error,
                    )
                self.set_busy(False)
                QMessageBox.warning(
                    self,
                    "Boot-time corruption check unavailable",
                    f"The prepared uefi-md5sum payload set is invalid: {error}",
                )
                return
        if runtime_validation_enabled and (
            strategy is not BootStrategy.IMAGE_NATIVE
            or write_plan.layout.main_filesystem.value != "fat32"
            or persistence_enabled
            or runtime_overlay_conflict
            or runtime_casper_conflict
            or runtime_reserved_conflict
            or not runtime_architectures
        ):
            try:
                workspace.cleanup()
            except OSError as error:
                self.logger.warning("Could not remove ISO workspace: %s", error)
            self.set_busy(False)
            QMessageBox.warning(
                self,
                "Boot-time corruption check unavailable",
                "The frozen ISO-mode plan is no longer eligible for the first "
                "native UEFI/FAT32 runtime-validation profile.",
            )
            return
        try:
            workspace_on_target = path_is_on_device(workspace.name, device)
        except OSError:
            workspace_on_target = True
        if workspace_on_target:
            try:
                workspace.cleanup()
            except OSError as error:
                self.logger.warning("Could not remove ISO workspace: %s", error)
            self.set_busy(False)
            QMessageBox.warning(
                self,
                "Choose working space on another disk",
                "The private ISO staging workspace is now on the target drive.",
            )
            return
        if staging_plan.overlay is not None:
            try:
                overlay_on_target = path_is_on_device(
                    str(staging_plan.overlay.archive), device,
                )
            except OSError:
                overlay_on_target = True
            if overlay_on_target:
                try:
                    workspace.cleanup()
                except OSError as error:
                    self.logger.warning("Could not remove ISO workspace: %s", error)
                self.set_busy(False)
                QMessageBox.warning(
                    self,
                    "Move the ZIP overlay first",
                    "The ZIP overlay is now stored on the target drive. Move it "
                    "elsewhere and prepare the ISO-mode write again.",
                )
                return
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
        if persistence_enabled and (
            pending.persistence_profile != supported_casper_profile(inspection)
            or strategy is not BootStrategy.IMAGE_NATIVE
            or write_plan.layout.main_filesystem.value != "fat32"
            or type(logical_sector_size) is not int
            or logical_sector_size not in (512, 4096)
            or pending.persistence_bytes < MIN_PERSISTENCE_BYTES
            or pending.persistence_bytes % ALIGNMENT_BYTES
        ):
            try:
                workspace.cleanup()
            except OSError as error:
                self.logger.warning("Could not remove ISO workspace: %s", error)
            self.set_busy(False)
            QMessageBox.warning(
                self,
                "Persistent storage unavailable",
                "The persistent-media profile or freshly observed target geometry "
                "is no longer valid.",
            )
            return

        customization = (
            "\nWindows customization: autounattend.xml will be added."
            if staging_plan.windows_customization is not None else ""
        )
        if staging_plan.wim_selection is not None:
            customization += (
                "\nWindows image: "
                f"{staging_plan.wim_selection.display_label} from "
                f"{staging_plan.wim_selection.source_name}."
            )
        if staging_plan.overlay is not None:
            final_files = sum(
                entry.kind is EntryKind.FILE
                for entry in staging_plan.effective_entries
            )
            customization += (
                f"\nZIP overlay: {staging_plan.overlay.archive.name} · "
                f"{self.display_size(staging_plan.overlay.content_bytes)} expanded."
                f"\nZIP SHA-256: {staging_plan.overlay.archive_sha256}."
                f"\nEffective input catalog: {final_files} files · "
                f"{self.display_size(staging_plan.content_bytes)} of ISO/overlay file data."
                "\nOverlay policy: additive only; no existing ISO file is replaced."
            )
        if persistence_enabled:
            assert pending.persistence_profile is not None
            mode_description = (
                "UEFI-only · GPT · FAT32 + ext4 writable persistence · "
                "full file read-back verification"
            )
            customization += (
                "\nPersistent storage: "
                f"{self.display_size(pending.persistence_bytes)} for Ubuntu "
                f"{pending.persistence_profile.ubuntu_release} LTS amd64."
            )
        elif strategy is BootStrategy.UEFI_NTFS:
            mode_description = (
                "UEFI-only · GPT · NTFS + verified UEFI:NTFS bridge · "
                "full file and bridge read-back verification"
            )
            customization += (
                "\nSecure Boot note: the bridge depends on Microsoft UEFI CA 2011 "
                "third-party trust."
            )
            if pending.allow_unsigned_payloads:
                customization += (
                    "\nUnsigned-payload warning: Secure Boot must be disabled."
                )
        else:
            mode_description = (
                "UEFI-only · GPT · FAT32 · full file read-back verification"
            )
        if runtime_validation_enabled:
            unsigned_architectures = tuple(
                profile.architecture
                for profile in RUNTIME_VALIDATION_ARTIFACTS
                if (
                    profile.architecture in runtime_architectures
                    and profile.signature_state is SignatureTableState.ABSENT
                )
            )
            customization += (
                "\nBoot-time check: uefi-md5sum "
                f"v{RUNTIME_VALIDATION_VERSION} for "
                f"{', '.join(runtime_architectures)}."
                "\nIntegrity limit: unsigned MD5 accidental-corruption detection "
                "only; not image authentication; missing, malformed, cancelled, "
                "or failed validation can chainload the original loader."
            )
            if unsigned_architectures:
                customization += (
                    "\nSecure Boot: disabled is required for the unsigned "
                    f"{', '.join(unsigned_architectures)} wrapper(s)."
                )
            else:
                customization += (
                    "\nSecure Boot: signed wrappers still depend on Microsoft UEFI "
                    "CA 2011 third-party trust and current DBX policy."
                )
        answer = QMessageBox.warning(
            self,
            "Erase drive and write in ISO mode?",
            f"Everything on {self.display_device(device)} will be permanently erased.\n\n"
            f"Image: {image.name}\n"
            f"Mode: {mode_description}\n"
            f"Target: {device.path}\n"
            f"Serial: {device.serial or device.wwn or 'not reported'}\n"
            f"Temporary space required: "
            f"{self.display_size(staging_plan.required_free_bytes)}"
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

        try:
            workspace_on_target = path_is_on_device(workspace.name, device)
        except OSError:
            workspace_on_target = True
        if workspace_on_target:
            try:
                workspace.cleanup()
            except OSError as error:
                self.logger.warning("Could not remove ISO workspace: %s", error)
            self.set_busy(False)
            self.status.setText("ISO mode is not active")
            QMessageBox.warning(
                self,
                "Choose working space on another disk",
                "The private ISO staging workspace moved onto the target drive "
                "during confirmation. No staging or device write was started.",
            )
            return

        if staging_plan.overlay is not None:
            try:
                overlay_on_target = path_is_on_device(
                    str(staging_plan.overlay.archive), device,
                )
            except OSError:
                overlay_on_target = True
            if overlay_on_target:
                try:
                    workspace.cleanup()
                except OSError as error:
                    self.logger.warning("Could not remove ISO workspace: %s", error)
                self.set_busy(False)
                self.status.setText("ISO mode is not active")
                QMessageBox.warning(
                    self,
                    "Move the ZIP overlay first",
                    "The ZIP overlay moved onto the target drive during confirmation. "
                    "No staging or device write was started.",
                )
                return

        self.iso_workspace = workspace
        self.iso_stager = IsoStagingExecutor()
        runtime_validation_cancel_event = threading.Event()
        self.runtime_validation_cancel_event = runtime_validation_cancel_event
        if persistence_enabled:
            self.casper_stager = CasperStagingExecutor()
            self.casper_writer = CasperMediaExecutor()
        elif strategy is BootStrategy.UEFI_NTFS:
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
                if persistence_enabled:
                    assert pending.persistence_profile is not None
                    assert self.casper_stager is not None
                    assert self.casper_writer is not None
                    self.bridge.progress.emit(
                        staged.bytes_staged,
                        staged.bytes_staged,
                        "Enabling verified persistent boot configuration",
                    )
                    casper_staging_plan = build_casper_staging_plan(
                        staged.destination, pending.persistence_profile,
                    )
                    casper_staging = self.casper_stager.execute(
                        casper_staging_plan
                    )
                    if runtime_validation_enabled:
                        raise RuntimeError(
                            "Runtime validation is not enabled for persistent media"
                        )
                    target_plan = build_casper_media_plan(
                        staged.destination,
                        casper_staging,
                        device,
                        pending.persistence_bytes,
                        logical_sector_size,
                    )
                    result = self.casper_writer.execute(
                        target_plan,
                        lambda update: self.bridge.progress.emit(
                            update.bytes_done,
                            update.total_bytes,
                            update.stage + (
                                f" · {update.relative_path}"
                                if update.relative_path else ""
                            ),
                        ),
                    )
                elif strategy is BootStrategy.UEFI_NTFS:
                    if runtime_validation_enabled:
                        raise RuntimeError(
                            "Runtime validation is not enabled for UEFI:NTFS media"
                        )
                    assert artifact is not None
                    assert self.uefi_ntfs_writer is not None
                    partition_table = FormatPartitionTable(
                        write_plan.layout.partition_table.value
                    )
                    target_plan = build_uefi_ntfs_media_plan(
                        staged.destination,
                        device,
                        partition_table,
                        inspection.architectures,
                        artifact,
                        volume_label="ISOPROPYL",
                        allow_unsigned_payloads=pending.allow_unsigned_payloads,
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
                    if runtime_validation_enabled:
                        assert pending.runtime_validation is not None
                        self.bridge.progress.emit(
                            staged.bytes_staged,
                            staged.bytes_staged,
                            "Generating the boot-time corruption manifest",
                        )
                        runtime_stage = apply_runtime_validation(
                            pending.runtime_validation,
                            staged.destination,
                            cancel_event=runtime_validation_cancel_event,
                        )
                        validate_runtime_validation_stage(
                            runtime_stage,
                            cancel_event=runtime_validation_cancel_event,
                        )
                    partition_table = FormatPartitionTable(
                        write_plan.layout.partition_table.value
                    )
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
                runtime_suffix = (
                    " Boot-time corruption checking is enabled."
                    if runtime_validation_enabled else ""
                )
                if result.powered_off:
                    message = (
                        "Your UEFI bootable USB is ready and safely powered off. "
                        f"You can remove it.{runtime_suffix}"
                    )
                elif not result.unmounted:
                    detail = (
                        result.cleanup_diagnostic + " "
                        if result.cleanup_diagnostic else ""
                    )
                    message = (
                        "The bootable USB was written, but it could not be cleanly "
                        f"unmounted. {detail}Close files using it, then eject it "
                        f"with your desktop.{runtime_suffix}"
                    )
                else:
                    message = (
                        "Your UEFI bootable USB is ready. Eject it with your desktop "
                        f"before removing it.{runtime_suffix}"
                    )
                success = True
            except (
                IsoStagingCancelled, ConstructedMediaCancelled, UefiNtfsCancelled,
                CasperMediaCancelled, RuntimeValidationCancelled,
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
            f"({self.display_size(plan.content_bytes)} of file data) to:\n\n"
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
        layout.addWidget(QLabel("Display units"))
        units = QComboBox()
        units.addItem("Decimal — MB, GB, TB", SizeUnitMode.SI.value)
        units.addItem("Binary — MiB, GiB, TiB", SizeUnitMode.IEC.value)
        units.setCurrentIndex(max(0, units.findData(self.size_unit_mode.value)))
        layout.addWidget(units)
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
        layout.addWidget(QLabel("Downloaded boot helpers"))
        manage_cache = QPushButton("Manage downloaded boot helpers…")
        manage_cache.clicked.connect(lambda: self.show_bootloader_cache(dialog))
        layout.addWidget(manage_cache)
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
                "Reset appearance, display units, and the ignored-drive list when you save? "
                "No images, logs, or drive contents are removed.",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            reset_requested = True
            clear_requested = True
            theme.setCurrentIndex(max(0, theme.findData("dark")))
            units.setCurrentIndex(max(0, units.findData(SizeUnitMode.SI.value)))
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
            selected_units = SizeUnitMode(str(units.currentData()))
            previous = {
                "appearance": str(self.settings.value("appearance", "dark")),
                "size_units": str(self.settings.value(
                    "size_units", SizeUnitMode.SI.value,
                )),
                "ignored_devices": str(self.settings.value("ignored_devices", "{}")),
            }
            if reset_requested:
                self.settings.clear()
                selected = "dark"
                selected_units = SizeUnitMode.SI
            else:
                self.settings.setValue("appearance", selected)
                self.settings.setValue("size_units", selected_units.value)
            if clear_requested and not reset_requested:
                self.settings.remove("ignored_devices")
            persistence_error = settings_sync_error(self.settings)
            if persistence_error:
                if settings_sync_was_committed(self.settings):
                    QMessageBox.warning(
                        dialog,
                        "Settings saved with a durability warning",
                        "The new settings are active and were atomically published, "
                        "but the settings directory could not confirm durable "
                        "storage.\n\n"
                        f"{persistence_error}",
                    )
                else:
                    for key, value in previous.items():
                        self.settings.setValue(key, value)
                    QMessageBox.warning(
                        dialog,
                        "Settings were not saved",
                        "ISOpropyl kept the previous settings for this session.\n\n"
                        f"{persistence_error}",
                    )
                    return
            self.size_unit_mode = selected_units
            QApplication.instance().setStyleSheet(THEMES[selected])
            dialog.accept()
            self.refresh_size_labels()
            if clear_requested:
                self.refresh_devices()

        buttons.accepted.connect(save)
        buttons.rejected.connect(dialog.reject)
        dialog.exec()

    def show_bootloader_cache(self, parent: QWidget | None = None) -> None:
        dialog = QDialog(parent or self)
        dialog.setWindowTitle("Downloaded boot helpers")
        dialog.setMinimumWidth(560)
        layout = QVBoxLayout(dialog)
        summary = QLabel()
        summary.setWordWrap(True)
        layout.addWidget(summary)
        details = QPlainTextEdit()
        details.setReadOnly(True)
        details.setMaximumHeight(190)
        layout.addWidget(details)
        note = QLabel(
            "Only exact paths named by ISOpropyl's bundled, hash-pinned catalog are "
            "shown or removed. Unknown files, links, and unsafe entries are left untouched."
        )
        note.setWordWrap(True)
        note.setObjectName("muted")
        layout.addWidget(note)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        delete_button = buttons.addButton(
            "Delete safe cached helpers…", QDialogButtonBox.ButtonRole.DestructiveRole,
        )
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        current = None

        def refresh() -> bool:
            nonlocal current
            try:
                current = inventory_cache()
            except Exception as error:
                summary.setText("The boot-helper cache could not be inspected.")
                details.setPlainText(str(error))
                delete_button.setEnabled(False)
                return False
            count = len(current.artifacts)
            if count:
                noun = "helper" if count == 1 else "helpers"
                summary.setText(
                    f"{count} cataloged {noun} · "
                    f"{self.display_size(current.total_size)} cached · "
                    f"{self.display_size(current.deletable_size)} safe to delete"
                )
                lines = []
                for artifact in current.artifacts:
                    status = "Verified" if artifact.hash_valid else "Invalid or incomplete"
                    if not artifact.deletion_safe:
                        status = "Unsafe entry — will not be deleted"
                    if artifact.issue:
                        status = f"{status}: {artifact.issue}"
                    lines.append(
                        f"{artifact.family} {artifact.version} · {artifact.name} · "
                        f"{self.display_size(artifact.size)} · {status}"
                    )
                if current.issues:
                    lines.extend(f"Cache notice: {issue}" for issue in current.issues)
                details.setPlainText("\n".join(lines))
            else:
                summary.setText("No cataloged boot helpers are cached.")
                details.setPlainText(
                    "A verified helper may be downloaded later only after explicit consent."
                )
            delete_button.setEnabled(any(
                artifact.deletion_safe for artifact in current.artifacts
            ))
            return True

        def delete_cache() -> None:
            if current is None:
                return
            keys = tuple(
                (artifact.family, artifact.version, artifact.name)
                for artifact in current.artifacts if artifact.deletion_safe
            )
            if not keys:
                return
            answer = QMessageBox.question(
                dialog,
                "Delete downloaded boot helpers?",
                f"Delete {len(keys)} cataloged cached helper(s) representing "
                f"{self.display_size(current.deletable_size)} of logical file data?\n\n"
                "ISOpropyl will ask before downloading a required helper again. "
                "Unknown or unsafe cache entries will not be touched.",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            try:
                result = delete_cached_artifacts(keys)
            except Exception as error:
                QMessageBox.critical(dialog, "Cache deletion failed", str(error))
                return
            skipped = len(result.skipped)
            message = (
                f"Deleted {len(result.deleted)} helper(s), representing "
                f"{self.display_size(result.bytes_deleted)} of logical file data."
            )
            if skipped or result.issues:
                reasons = [item.reason for item in result.skipped]
                reasons.extend(result.issues)
                QMessageBox.warning(
                    dialog,
                    "Boot-helper cache partially cleared",
                    message + "\n\n" + "\n".join(reasons),
                )
            else:
                QMessageBox.information(dialog, "Boot-helper cache cleared", message)
            refresh()

        delete_button.clicked.connect(delete_cache)
        refresh()
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

        current = self.windows_options
        source_heading = QLabel("Windows image source")
        source_heading.setObjectName("cardTitle")
        source_combo = QComboBox()
        source_combo.setObjectName("windowsSourceCombo")
        if len(self.windows_wim_candidates) != 1:
            source_combo.addItem("Choose an install.wim source…", None)
        for candidate in self.windows_wim_candidates:
            source_combo.addItem(
                f"{candidate.path} · {self.display_size(candidate.size)}",
                candidate.path,
            )
        preferred_source = (
            current.install_image.source_name
            if current.install_image is not None else (
                self.windows_wim_member.path
                if self.windows_wim_member is not None else None
            )
        )
        if preferred_source is not None:
            row = source_combo.findData(preferred_source)
            if row >= 0:
                source_combo.setCurrentIndex(row)

        image_heading = QLabel("Windows edition")
        image_heading.setObjectName("cardTitle")
        image_combo = QComboBox()
        image_combo.setObjectName("windowsEditionCombo")
        image_detail = QLabel()
        image_detail.setWordWrap(True)
        image_detail.setObjectName("muted")
        inspect_editions = QPushButton("Inspect WIM/ESD editions…")
        available_editions: tuple[WimEdition, ...] = ()

        def selected_source() -> ArchiveEntry | None:
            path = source_combo.currentData()
            return next(
                (
                    candidate for candidate in self.windows_wim_candidates
                    if candidate.path == path
                ),
                None,
            )

        def update_image_detail() -> None:
            member = selected_source()
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
            elif member == self.windows_wim_member and self.windows_wim_error:
                image_detail.setText(
                    f"Edition metadata is unavailable: {self.windows_wim_error}"
                )
            elif member is not None and not available_editions:
                image_detail.setText(
                    f"Inspecting editions temporarily extracts "
                    f"{self.display_size(member.size)} from {member.path}. "
                    "The private copy is deleted immediately afterward."
                )
            else:
                image_detail.setText(
                    "No edition is preselected; Windows Setup will ask when applicable."
                )

        def rebuild_editions() -> None:
            nonlocal available_editions
            member = selected_source()
            available_editions = ()
            selected_index = None
            if member is not None and member == self.windows_wim_member:
                available_editions = self.windows_wim_editions
            if (
                current.install_image is not None
                and member is not None
                and current.install_image.source_name == member.path
                and current.install_image.source_size == member.size
            ):
                if not available_editions:
                    available_editions = current.install_image.editions
                selected_index = current.install_image.selected_index
            image_combo.blockSignals(True)
            image_combo.clear()
            image_combo.addItem("Ask during Windows Setup (no preselection)", None)
            for edition in available_editions:
                image_combo.addItem(edition.display_label, edition.index)
            image_combo.setEnabled(bool(available_editions))
            if selected_index is not None:
                selected_row = image_combo.findData(selected_index)
                image_combo.setCurrentIndex(max(0, selected_row))
            image_combo.blockSignals(False)
            inspect_editions.setEnabled(member is not None)
            inspect_editions.setText(
                "Refresh edition metadata…" if available_editions
                else "Inspect WIM/ESD editions…"
            )
            if member is not None:
                inspect_editions.setToolTip(
                    f"Temporarily extract {self.display_size(member.size)} from "
                    f"{member.path}, inspect it with trusted wimlib-imagex, then "
                    "delete the private copy."
                )
            elif self.windows_wim_error:
                inspect_editions.setToolTip(self.windows_wim_error)
            else:
                inspect_editions.setToolTip("Choose a Windows image source first")
            update_image_detail()

        source_combo.currentIndexChanged.connect(rebuild_editions)
        image_combo.currentIndexChanged.connect(update_image_detail)
        setup_layout.addWidget(source_heading)
        setup_layout.addWidget(source_combo)
        setup_layout.addWidget(image_heading)
        setup_layout.addWidget(image_combo)
        setup_layout.addWidget(image_detail)
        setup_layout.addWidget(inspect_editions)
        rebuild_editions()

        bypass = QCheckBox("Remove Windows 11 RAM, Secure Boot, and TPM 2.0 setup checks")
        online = QCheckBox("Hide the online Microsoft account screen")
        offline_account = QCheckBox(
            "Enable the Windows 11 offline-account path (known 21H2–24H2 builds)"
        )
        offline_account.setObjectName("windowsBypassOnlineRequirementCheckBox")
        offline_account_acknowledgment = QCheckBox(
            "I understand WIM metadata cannot prove S mode is absent and this "
            "Setup workaround may stop working"
        )
        offline_account_acknowledgment.setObjectName(
            "windowsBypassOnlineRequirementAcknowledgment",
        )
        privacy = QCheckBox("Reduce setup data collection (skip Express privacy settings)")
        bitlocker = QCheckBox("Prevent automatic BitLocker device encryption")
        fast_startup = QCheckBox(
            "Disable Windows Fast Startup (use full shutdowns; startup may be slower)"
        )
        fast_startup.setObjectName("windowsDisableFastStartupCheckBox")
        fast_startup.setToolTip(
            "Writes the fixed HiberbootEnabled=0 machine setting during Windows "
            "Setup. This avoids hybrid shutdown but may make startup slower."
        )
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
        for checkbox in (
            bypass, online, offline_account, privacy, bitlocker, fast_startup, local,
        ):
            setup_layout.addWidget(checkbox)
        offline_account_note = QLabel()
        offline_account_note.setWordWrap(True)
        offline_account_note.setObjectName("muted")
        setup_layout.addWidget(offline_account_note)
        setup_layout.addWidget(offline_account_acknowledgment)
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
        offline_account.setChecked(current.bypass_online_account_requirement)
        offline_account_acknowledgment.setChecked(
            current.acknowledge_online_account_limitations,
        )
        privacy.setChecked(current.reduce_data_collection)
        bitlocker.setChecked(current.disable_automatic_bitlocker)
        fast_startup.setChecked(current.disable_fast_startup)
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

        def selected_bypass_image() -> WimSelection | None:
            member = selected_source()
            selected_index = image_combo.currentData()
            if member is None or selected_index is None or not available_editions:
                return None
            return WimSelection(
                member.path, member.size, available_editions, int(selected_index),
            )

        def update_offline_account_control() -> None:
            supported, reason = online_account_bypass_compatibility(
                selected_bypass_image(),
            )
            offline_account.setEnabled(supported)
            offline_account.setToolTip(reason)
            offline_account_note.setText(reason)
            if not supported:
                offline_account.setChecked(False)

        def update_offline_account_acknowledgment() -> None:
            enabled = offline_account.isEnabled() and offline_account.isChecked()
            offline_account_acknowledgment.setEnabled(enabled)
            if not enabled:
                offline_account_acknowledgment.setChecked(False)

        source_combo.currentIndexChanged.connect(update_offline_account_control)
        image_combo.currentIndexChanged.connect(update_offline_account_control)
        offline_account.toggled.connect(update_offline_account_acknowledgment)
        update_offline_account_control()
        update_offline_account_acknowledgment()
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel
        )
        export_button = buttons.addButton("Export XML…", QDialogButtonBox.ButtonRole.ActionRole)
        layout.addWidget(buttons)

        def selected() -> WindowsCustomization:
            install_image = None
            install_image_path = ""
            member = selected_source()
            selected_index = image_combo.currentData()
            if selected_index is not None:
                if member is None or not available_editions:
                    raise ValueError("Windows edition metadata is no longer available")
                install_image = WimSelection(
                    member.path,
                    member.size,
                    available_editions,
                    int(selected_index),
                )
                if (
                    member.path.casefold().endswith("/sources/install.wim")
                    or (
                        member.path.casefold() == "sources/install.wim"
                        and self.windows_install_source_count > 1
                    )
                ):
                    install_image_path = member.path
            return WindowsCustomization(
                bypass_hardware_requirements=bypass.isChecked(),
                hide_online_account=online.isChecked(),
                bypass_online_account_requirement=offline_account.isChecked(),
                acknowledge_online_account_limitations=(
                    offline_account_acknowledgment.isChecked()
                ),
                local_username=username.text() if local.isChecked() else "",
                reduce_data_collection=privacy.isChecked(),
                disable_automatic_bitlocker=bitlocker.isChecked(),
                disable_fast_startup=fast_startup.isChecked(),
                input_locale=input_locale.text(),
                system_locale=system_locale.text(),
                ui_language=ui_language.text(),
                user_locale=user_locale.text(),
                timezone=timezone.text(),
                require_local_password_change=password_change.isChecked(),
                local_password_never_expires=password_never_expires.isChecked(),
                install_image=install_image,
                install_image_path=install_image_path,
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
            self.select_windows_wim_source(selected_source())
            self.windows_options = options
            self.logger.info("Windows customization profile updated: %s", options)
            dialog.accept()

        def inspect_metadata() -> None:
            member = selected_source()
            if member is None:
                QMessageBox.warning(
                    dialog, "Choose a Windows image source",
                    "Choose the install.wim or install.esd source to inspect.",
                )
                return
            try:
                options = selected()
                generate_autounattend(options, profile_architecture(options))
            except ValueError as error:
                QMessageBox.warning(dialog, "Invalid Windows options", str(error))
                return
            if not confirm_local_account(options):
                return
            self.select_windows_wim_source(member)
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
        source_icon = files("isopropyl").joinpath(
            "data/io.github.codebooker.isopropyl.svg"
        )
        if source_icon.is_file():
            icon = QIcon(str(source_icon))
    if not icon.isNull():
        app.setWindowIcon(icon)
    try:
        parsed_arguments = parse_application_arguments(app.arguments())
        settings = application_settings(app.arguments())
    except ValueError as error:
        QMessageBox.critical(None, "Could not start ISOpropyl", str(error))
        return 2
    selected_theme = str(settings.value("appearance", "dark"))
    app.setStyleSheet(THEMES.get(selected_theme, STYLE))
    window = Window(settings=settings)
    window.show()
    if parsed_arguments.image is not None:
        QTimer.singleShot(0, lambda: window.load_image(parsed_arguments.image))
    return app.exec()


def image_identity(path: Path) -> tuple[int, int, int, int, int]:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise OSError("The selected image is not a regular file")
    return (
        info.st_dev, info.st_ino, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns,
    )


def looks_like_windows_image(path: Path) -> bool:
    name = path.name.casefold()
    return path.suffix.casefold() == ".iso" and any(
        marker in name for marker in ("windows", "win10", "win11", "win_10", "win_11")
    )
