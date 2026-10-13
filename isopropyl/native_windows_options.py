"""Native Windows installer options using the shared Linux profile generator."""

# SPDX-License-Identifier: AGPL-3.0-or-later
import sys
from dataclasses import fields
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .mac_windows_iso import inspect_windows_source
from .native_style import WINDOWS_OPTIONS_SIZE
from .native_writer import NativeWriter, path_file_identity
from .wim import WimSelection
from .windows import (
    WindowsBootExOptions,
    WindowsCustomization,
    generate_autounattend,
    online_account_bypass_compatibility,
    quality_of_life_compatibility,
    secure_boot_revocation_policy_compatibility,
)


class InstallerInspection(QThread):
    result = pyqtSignal(object, str)

    def __init__(self, source, parent, selected_member=None):
        super().__init__(parent)
        self.source = source
        self.selected_member=selected_member
        self.writer = NativeWriter()

    def run(self):
        try:
            if sys.platform == "win32":
                from .windows_media import inspect_windows_source as inspect_windows
                metadata = inspect_windows(self.source,self.writer,selected_member=self.selected_member)
            else:
                metadata = inspect_windows_source(self.source,self.writer,selected_member=self.selected_member)
            self.result.emit(metadata, "")
        except Exception as error:
            self.result.emit(None, str(error))


class WindowsOptionsDialog(QDialog):
    def __init__(self, source, options, bootex, parent=None):
        super().__init__(parent)
        self.source = Path(source).absolute()
        self.options, self.bootex = options, bootex
        self.metadata = None
        self.job = None
        self.closing = False
        self.metadata_cache={}
        self.edition_choices={}
        self.initial_inspection=True
        self.setWindowTitle("Windows installer settings")
        self.resize(*WINDOWS_OPTIONS_SIZE)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        heading = QLabel("Customize Windows")
        heading.setObjectName("sectionTitle")
        layout.addWidget(heading)
        self.detail = QLabel("Inspecting editions and installer compatibility…")
        self.detail.setWordWrap(True)
        layout.addWidget(self.detail)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.controls = {}
        setup = self.page("Setup")
        setup.addWidget(QLabel("Windows image source"))
        self.source_combo=QComboBox()
        self.source_combo.setObjectName('windowsSourceCombo')
        self.source_combo.setEnabled(False)
        setup.addWidget(self.source_combo)
        setup.addWidget(QLabel("Windows edition"))
        self.edition = QComboBox()
        self.edition.addItem("Let Windows Setup choose", None)
        setup.addWidget(self.edition)
        self.check(
            setup,
            "bypass_hardware_requirements",
            "Skip Windows 11 TPM, RAM and Secure Boot setup checks",
        )
        self.check(setup, "hide_online_account", "Hide the Microsoft account screen")
        self.check(
            setup,
            "bypass_online_account_requirement",
            "Enable the Windows 11 offline-account setup path",
        )
        self.check(
            setup,
            "acknowledge_online_account_limitations",
            "I understand S mode cannot be ruled out and this workaround may stop working",
        )
        setup.addWidget(QLabel("Local administrator account"))
        self.username = QLineEdit(options.local_username)
        self.username.setPlaceholderText("Optional account name")
        setup.addWidget(self.username)
        note = QLabel(
            "The account starts with a blank password. Windows must request a replacement after setup. Do not use this for Windows S mode, where first-logon commands do not run."
        )
        note.setWordWrap(True)
        setup.addWidget(note)
        self.check(
            setup,
            "local_password_never_expires",
            "Do not expire the replacement password",
        )
        regional = self.page("Region")
        form = QFormLayout()
        regional.addLayout(form)
        for name, label, placeholder in [
            ("input_locale", "Keyboard", "0409:00000409 or en-US"),
            ("system_locale", "System locale", "en-US"),
            ("ui_language", "Display language", "en-US"),
            ("user_locale", "User locale", "en-US"),
            ("timezone", "Windows time zone", "Eastern Standard Time"),
        ]:
            control = QLineEdit(getattr(options, name))
            control.setPlaceholderText(placeholder)
            self.controls[name] = control
            form.addRow(label, control)
        regional.addWidget(QLabel("Leave fields blank to use Windows Setup defaults."))
        experience = self.page("Privacy")
        for name, label in [
            ("reduce_data_collection", "Skip Express privacy settings"),
            (
                "disable_automatic_bitlocker",
                "Prevent automatic BitLocker device encryption",
            ),
            ("disable_fast_startup", "Disable Fast Startup and use full shutdowns"),
            ("quality_of_life", "Apply the Windows 11 quality-of-life bundle"),
            (
                "acknowledge_quality_of_life_limitations",
                "I understand package removals and policies may change or partially fail",
            ),
        ]:
            self.check(experience, name, label)
        note = QLabel(
            "The quality-of-life bundle disables OneDrive synchronization, removes OneDrive setup programs and Outlook / Teams packages, and applies Windows 11 policies. Startup can be slower with Fast Startup disabled."
        )
        note.setWordWrap(True)
        experience.addWidget(note)
        security = self.page("Boot security")
        self.check(
            security,
            "apply_secure_boot_revocation_policy",
            "Apply the installed Windows Secure Boot revocation policy (25H2 / 26H1)",
        )
        acknowledgment = self.check(
            security,
            "acknowledge_secure_boot_revocation_risk",
            "I have updated installation and recovery media and accept the revocation risk",
        )
        acknowledgment.setToolTip(
            "My ISO has current updates. I have recovery media and any BitLocker recovery key. Older boot or recovery media may stop working."
        )
        self.bootex_check = QCheckBox(
            "Use Windows 2023-generation installer boot files (25H2 v2)"
        )
        self.bootex_check.setChecked(bootex.enabled)
        security.addWidget(self.bootex_check)
        self.bootex_ack = QCheckBox("My target firmware trusts Windows UEFI CA 2023")
        self.bootex_ack.setToolTip(
            "Firmware that only trusts Windows UEFI CA 2011 may not boot this USB."
        )
        self.bootex_ack.setChecked(bootex.acknowledge_firmware_compatibility)
        security.addWidget(self.bootex_ack)
        self.boot_note = QLabel(
            "Boot-file replacement requires an exact supported Microsoft ISO. The installed-system revocation policy is a separate setting."
        )
        self.boot_note.setWordWrap(True)
        security.addWidget(self.boot_note)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.tabs.addTab(self.preview, "Answer file")
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )
        self.save_button = buttons.button(QDialogButtonBox.StandardButton.Save)
        self.export = buttons.addButton(
            "Export XML…", QDialogButtonBox.ButtonRole.ActionRole
        )
        self.export.clicked.connect(self.export_xml)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        for field in fields(options):
            if field.name in self.controls and isinstance(
                self.controls[field.name], QCheckBox
            ):
                self.controls[field.name].setChecked(getattr(options, field.name))
        self.source_combo.currentIndexChanged.connect(self.source_changed)
        self.edition.currentIndexChanged.connect(self.update_controls)
        self.tabs.currentChanged.connect(lambda *_: self.update_preview())
        for control in self.controls.values():
            if isinstance(control, QCheckBox):
                control.toggled.connect(self.update_controls)
            else:
                control.textChanged.connect(self.update_preview)
        self.username.textChanged.connect(self.update_preview)
        self.bootex_check.toggled.connect(self.update_controls)
        self.update_controls()

        QTimer.singleShot(0, self.inspect)

    def page(self, title):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setSpacing(10)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        scroll.setWidget(body)
        self.tabs.addTab(scroll, title)
        return layout

    def check(self, layout, name, label):
        control = QCheckBox(label)
        self.controls[name] = control
        layout.addWidget(control)
        control.setToolTip(label)
        return control

    def inspect(self, selected_member=None):
        if self.closing:
            return
        if self.job:return
        if selected_member is None and self.options.install_image:
            selected_member=self.options.install_image.source_name
        self.job = InstallerInspection(self.source, self, selected_member)
        self.job.result.connect(self.inspected)
        self.job.finished.connect(self.inspection_finished)
        self.save_button.setEnabled(False)
        self.export.setEnabled(False)
        self.source_combo.setEnabled(False)
        self.edition.setEnabled(False)
        self.job.start()

    def inspected(self, metadata, error):
        self.metadata = metadata
        self.detail.setText(
            error
            or f"{self.source.name} · {metadata.architecture.upper()} · {len(metadata.editions)} edition(s)"
        )
        if metadata:
            self.metadata_cache[metadata.install_path]=metadata
            from .mac_windows_iso import WindowsInstallCandidate
            candidates=metadata.install_candidates or (WindowsInstallCandidate(metadata.install_path,metadata.install_size),)
            self.source_combo.blockSignals(True);self.source_combo.clear()
            for candidate in candidates:self.source_combo.addItem(f'{candidate.path} · {candidate.size:,} bytes',candidate.path)
            self.source_combo.setCurrentIndex(self.source_combo.findData(metadata.install_path));self.source_combo.blockSignals(False)
            self.edition.blockSignals(True);self.edition.clear();self.edition.addItem('Let Windows Setup choose',None)
            preferred=self.edition_choices.get(metadata.install_path)
            if preferred is None and self.options.install_image and self.options.install_image.source_name==metadata.install_path:
                preferred=self.options.install_image.selected_index
            for edition in metadata.editions:
                self.edition.addItem(edition.display_label,edition.index)
                if edition.index==preferred:self.edition.setCurrentIndex(self.edition.count()-1)
            self.edition.blockSignals(False)
        self.update_controls()
        if metadata and self.initial_inspection:
            self.initial_inspection=False
            for name in (
                "bypass_online_account_requirement",
                "quality_of_life",
                "apply_secure_boot_revocation_policy",
                "acknowledge_online_account_limitations",
                "acknowledge_quality_of_life_limitations",
                "acknowledge_secure_boot_revocation_risk",
            ):
                if self.controls[name].isEnabled():
                    self.controls[name].setChecked(getattr(self.options, name))
            if self.bootex_check.isEnabled():
                self.bootex_check.setChecked(self.bootex.enabled)
                self.bootex_ack.setChecked(
                    self.bootex.acknowledge_firmware_compatibility
                )

    def source_changed(self,*_):
        if self.job or self.closing:return
        path=self.source_combo.currentData()
        if not path or self.metadata and path==self.metadata.install_path:return
        if self.metadata:self.edition_choices[self.metadata.install_path]=self.edition.currentData()
        cached=self.metadata_cache.get(path)
        if cached and path_file_identity(self.source)==cached.source_identity:
            self.inspected(cached,'');return
        self.metadata=None
        self.edition.blockSignals(True);self.edition.clear();self.edition.addItem('Let Windows Setup choose',None);self.edition.blockSignals(False)
        self.detail.setText('Inspecting the selected install-image source…')
        self.update_controls();self.inspect(path)

    def inspection_finished(self):
        self.job.deleteLater()
        self.job = None
        self.update_controls()
        if self.closing:
            super().reject()

    def selection(self):
        index = self.edition.currentData()
        if self.metadata and index is not None:
            return WimSelection(
                self.metadata.install_path,
                self.metadata.install_size,
                self.metadata.editions,
                index,
            )
        return None

    def selected(self):
        values = {
            name: control.isChecked()
            if isinstance(control, QCheckBox)
            else control.text().strip()
            for name, control in self.controls.items()
        }
        selection=self.selection()
        explicit_path=selection.source_name if selection and selection.source_name.casefold().endswith('/install.wim') and (
            self.metadata.install_source_count>1 or selection.source_name.casefold()!='sources/install.wim') else ''
        return WindowsCustomization(
            **values,
            local_username=self.username.text().strip(),
            require_local_password_change=True,
            install_image=selection,
            install_image_path=explicit_path,
        )

    def update_controls(self, *_):
        for name, ack, check in [
            (
                "bypass_online_account_requirement",
                "acknowledge_online_account_limitations",
                online_account_bypass_compatibility,
            ),
            (
                "quality_of_life",
                "acknowledge_quality_of_life_limitations",
                quality_of_life_compatibility,
            ),
            (
                "apply_secure_boot_revocation_policy",
                "acknowledge_secure_boot_revocation_risk",
                secure_boot_revocation_policy_compatibility,
            ),
        ]:
            supported, reason = check(self.selection())
            control = self.controls[name]
            control.setEnabled(supported)
            control.setToolTip(reason)
            if not supported:
                control.blockSignals(True)
                control.setChecked(False)
                control.blockSignals(False)
            acknowledgment = self.controls[ack]
            acknowledgment.setEnabled(supported and control.isChecked())
            if not acknowledgment.isEnabled():
                acknowledgment.setChecked(False)
        supported = self.metadata is not None and self.metadata.bootex_supported
        self.bootex_check.setEnabled(supported)
        if not supported:
            self.bootex_check.setChecked(False)
        self.bootex_ack.setEnabled(supported and self.bootex_check.isChecked())
        if not self.bootex_ack.isEnabled():
            self.bootex_ack.setChecked(False)
        self.bootex_check.setToolTip(
            "Requires an exact Microsoft-published Windows 11 25H2 v2 ISO from the reviewed catalog"
        )
        _, policy_reason = secure_boot_revocation_policy_compatibility(self.selection())
        self.boot_note.setText(
            policy_reason
            + (
                "\nWindows 2023 boot-file replacement requires an exact reviewed Microsoft 25H2 v2 ISO."
                if not supported
                else "\nWindows 2023 boot-file replacement is available for this verified ISO. Older firmware may not boot it."
            )
        )
        self.source_combo.setEnabled(self.job is None and bool(self.source_combo.count()))
        self.edition.setEnabled(self.job is None and self.metadata is not None)
        self.save_button.setEnabled(self.metadata is not None and self.job is None)
        self.export.setEnabled(self.metadata is not None and self.job is None)
        self.update_preview()

    def xml(self):
        return generate_autounattend(
            self.selected(), self.metadata.architecture if self.metadata else "amd64"
        )

    def update_preview(self, *_):
        try:
            self.preview.setPlainText(self.xml())
        except ValueError as error:
            self.preview.setPlainText(str(error))

    def save(self):
        if self.job:
            return
        try:
            if (
                not self.metadata
                or path_file_identity(self.source) != self.metadata.source_identity
            ):
                raise ValueError(
                    "The ISO changed. Reopen settings to inspect it again."
                )
            self.xml()
            if self.bootex_check.isChecked() and not self.bootex_ack.isChecked():
                raise ValueError(
                    "Confirm the firmware requirement for Windows 2023 boot files"
                )
            self.options = self.selected()
            self.bootex = WindowsBootExOptions(
                self.bootex_check.isChecked(), self.bootex_ack.isChecked()
            )
        except (ValueError, OSError) as error:
            QMessageBox.warning(self, "Check installer settings", str(error))
            return
        self.accept()

    def export_xml(self):
        try:
            xml = self.xml()
        except ValueError as error:
            QMessageBox.warning(self, "Check installer settings", str(error))
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Windows answer file", "autounattend.xml", "XML files (*.xml)"
        )
        if filename:
            try:
                Path(filename).write_text(xml, encoding="utf-8")
            except OSError as error:
                QMessageBox.warning(self, "Cannot export", str(error))

    def reject(self):
        self.closing = True
        if self.job:
            self.job.writer.cancel()
            self.detail.setText("Closing installer inspection…")
        else:
            super().reject()

    def closeEvent(self, event):
        if self.job:
            event.ignore()
            self.reject()
        else:
            event.accept()
