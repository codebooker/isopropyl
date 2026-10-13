"""Native Qt raw writer. Linux's advanced interface lives in app.py."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import argparse
import os
import sys
from importlib.resources import files

from PyQt6.QtCore import QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from .mac_windows_iso import WindowsIsoPlan, build_windows_plan, run_windows_iso
from .mac_write import run_macos_write
from .native_devices import discover
from .native_elevation import report_gui_ready, request_write_access
from .native_style import MAIN_SIZE, MINIMUM_SIZE, STYLE, LIGHT_STYLE
from .native_writer import NativeWriteError, NativeWriter, build_plan
from .native_inputs import PreparedImagePlan, run_prepared_image
from .native_tools import NativeToolPlan, build_tool_plan, run_tool
from .windows import WindowsBootExOptions, WindowsCustomization
from .native_media import NativeMediaOptions, NativeMediaPlan, build_media_plan, run_media
from dataclasses import replace


class Discovery(QThread):
    ready = pyqtSignal(object, str)

    def __init__(self, include_fixed, parent):
        super().__init__(parent)
        self.include_fixed = include_fixed

    def run(self):
        try:
            self.ready.emit(discover(self.include_fixed), "")
        except Exception as error:  # noqa: BLE001 - an escaping Qt worker exception can abort the process
            self.ready.emit([], str(error))


class WriteJob(QThread):
    progress = pyqtSignal(str, int)
    result = pyqtSignal(bool, str)

    def __init__(self, plan, confirmation, parent):
        super().__init__(parent)
        self.plan, self.confirmation = plan, confirmation
        self.writer = NativeWriter()

    def run(self):
        import logging
        logger=logging.getLogger("isopropyl")
        logger.info("Starting %s on %s",getattr(self.plan,"operation","write"),getattr(getattr(self.plan,"target",None),"device",None))
        try:
            progress = lambda stage, done, total: self.progress.emit(stage, done * 100 // total)
            if getattr(self,'prepared_boot',False):
                raw=build_plan(self.plan.source,self.plan.target,include_fixed=self.plan.include_fixed)
                self.writer.final_verification=self.plan.options.final_verification
                if sys.platform=='darwin' and os.geteuid()!=0:
                    checksum=run_macos_write(raw,self.confirmation,self.writer,progress=progress,prepared_private=True)
                else:
                    self.writer._worker_private_source=True
                    checksum=self.writer.run(raw,self.confirmation,progress=progress)
                self.result.emit(True,f'Boot media verified.\nSHA-256: {checksum}');return
            if isinstance(self.plan, NativeMediaPlan):
                checksum = run_media(self.plan,self.confirmation,self.writer,progress=progress)
                self.result.emit(True,f'Write verified.\nPrepared image SHA-256: {checksum}\nEject the drive before unplugging it.')
                return
            if isinstance(self.plan, NativeToolPlan):
                if sys.platform == 'darwin':
                    from .host_platform import validate_host
                    self.writer.privilege_check = lambda host: validate_host(host=host)
                result = run_tool(self.plan, self.confirmation, self.writer, progress=progress)
                message = (f'Backup verified.\n{self.plan.destination}\nDrive data SHA-256: {result}'
                           if self.plan.operation == 'backup' else result)
                self.result.emit(True, message)
                return
            if isinstance(self.plan, PreparedImagePlan):
                checksum = run_prepared_image(self.plan,self.confirmation,self.writer,progress=progress)
            elif isinstance(self.plan, WindowsIsoPlan):
                if sys.platform == 'win32':
                    from .windows_media import run_windows_iso as run_windows_installer
                    checksum = run_windows_installer(self.plan,self.confirmation,self.writer,progress=progress)
                else:
                    checksum = run_windows_iso(self.plan,self.confirmation,self.writer,progress=progress)
            elif sys.platform == 'darwin' and os.geteuid() != 0:
                checksum = run_macos_write(self.plan, self.confirmation, self.writer, progress=progress)
            else:
                checksum = self.writer.run(self.plan, self.confirmation, progress=progress)
            checksum_label = 'Prepared USB image SHA-256' if isinstance(self.plan,WindowsIsoPlan) else 'Image SHA-256'
            self.result.emit(True, f"Write verified.\n{checksum_label}: {checksum}\nEject the drive before unplugging it.")
        except Exception as error:  # noqa: BLE001 - report every worker failure before releasing UI controls
            logger.exception("Disk operation failed; write_started=%s",self.writer.write_started)
            detail = str(error)
            if self.writer.write_started:
                detail += "\nThe target may be incomplete. Rewrite it before use."
            self.result.emit(False, detail)


class AccessJob(QThread):
    result = pyqtSignal(bool, str)

    def __init__(self, image, checksum, target, include_fixed, parent, session_state="",portable=False):
        super().__init__(parent)
        self.arguments = (image, checksum, target, include_fixed)
        self.session_state=session_state;self.portable=portable

    def run(self):
        try:
            request_write_access(*self.arguments,session_state=self.session_state,portable=self.portable)
            self.result.emit(True, "")
        except Exception as error:  # noqa: BLE001 - never let a worker exception abort the Qt process
            self.result.emit(False, str(error))


class InspectionJob(QThread):
    progress = pyqtSignal(str, int)
    result = pyqtSignal(bool, str)

    def __init__(self, image, parent):
        super().__init__(parent)
        self.image = image
        self.writer = NativeWriter()

    def run(self):
        from .native_inspection import inspect_source
        try:
            details = inspect_source(self.image,self.writer,
                lambda stage,done,total:self.progress.emit(stage,done*100//total))
            self.result.emit(True,details)
        except Exception as error:
            self.result.emit(False,str(error))


class DownloadJob(QThread):
    progress = pyqtSignal(str,int)
    result = pyqtSignal(bool,object)

    def __init__(self,family,release,destination,source_url,parent):
        super().__init__(parent)
        self.family,self.release,self.destination,self.source_url = family,release,destination,source_url
        self.writer = NativeWriter()

    def run(self):
        try:
            progress = lambda done,total:self.progress.emit('Downloading and verifying image',done*100//total)
            if self.family == 'Windows':
                from .windows_downloads import WindowsIsoDownloader
                result = WindowsIsoDownloader(self.writer.cancelled).download(self.release,self.destination,
                    progress,source_url=self.source_url,cancel_check=self.writer.check_cancelled)
            elif self.family == 'Ubuntu':
                from .linux_downloads import LinuxIsoDownloader
                result = LinuxIsoDownloader(self.writer.cancelled).download(self.release,self.destination,
                    progress,cancel_check=self.writer.check_cancelled)
            else:
                from .freedos_downloads import FreeDosUsbDownloader
                result = FreeDosUsbDownloader(self.writer.cancelled).download(self.release,self.destination,
                    progress,cancel_check=self.writer.check_cancelled)
            self.result.emit(True,result)
        except Exception as error:
            self.result.emit(False,str(error))


class TaskJob(QThread):
    progress=pyqtSignal(str,int)
    result=pyqtSignal(bool,object)
    def __init__(self,task,parent):
        super().__init__(parent);self.task=task;self.writer=NativeWriter()
    def run(self):
        try:self.result.emit(True,self.task(self.writer,lambda stage,done,total:self.progress.emit(stage,done*100//max(1,total))))
        except Exception as error:self.result.emit(False,str(error))


class PreparationJob(QThread):
    progress=pyqtSignal(str,int)
    result=pyqtSignal(bool,object)
    def __init__(self,kind,target,parent,architectures=None):
        super().__init__(parent);self.kind=kind;self.target=target;self.architectures=architectures;self.writer=NativeWriter()
    def run(self):
        import tempfile
        from pathlib import Path
        from .native_boot import prepare_boot_media
        try:
            self.workspace=tempfile.TemporaryDirectory(prefix='isopropyl-boot-')
            image=prepare_boot_media(self.kind,self.target,Path(self.workspace.name),self.writer,
                lambda stage,done,total:self.progress.emit(stage,done*100//max(total,1)),architectures=self.architectures)
            self.result.emit(True,image)
        except Exception as error:
            if hasattr(self,'workspace'):self.workspace.cleanup()
            self.result.emit(False,str(error))


class NativeWindow(QMainWindow):
    def __init__(self, initial=None):
        super().__init__()
        self.setWindowTitle("ISOpropyl Writer")
        self.resize(*MAIN_SIZE)
        self.setMinimumSize(*MINIMUM_SIZE)
        self.setStyleSheet(STYLE)
        self.windows_options = WindowsCustomization()
        self.windows_bootex = WindowsBootExOptions()
        self.media_options = NativeMediaOptions()
        self.portable=getattr(initial,"portable",False)
        self.scan = None
        self.job = None
        self.access_job = None
        self.access_result = None
        self.initial_target = getattr(initial, "target", None)
        self.pending_result = None
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        body = QWidget(); body.setObjectName('canvas'); scroll.setWidget(body)
        self.setCentralWidget(scroll)
        layout = QVBoxLayout(body); layout.setContentsMargins(16,14,16,14); layout.setSpacing(10)
        brand_row=QHBoxLayout();brand=QLabel('ISOpropyl');brand.setObjectName('eyebrow');brand_row.addWidget(brand);brand_row.addStretch();self.settings_button=QPushButton('Settings…');self.settings_button.clicked.connect(self.configure_settings);brand_row.addWidget(self.settings_button);self.utilities_button=QPushButton('Utilities…');utilities=QMenu(self.utilities_button);utilities.addAction('Capture optical disc…').triggered.connect(self.capture_optical);utilities.addAction('Extract ISO files…').triggered.connect(self.extract_files);self.utilities_button.setMenu(utilities);brand_row.addWidget(self.utilities_button);layout.addLayout(brand_row)
        heading = QLabel('Create a bootable USB'); heading.setObjectName('title'); layout.addWidget(heading)
        note = QLabel('Choose an image, configure your installer, and write with automatic verification.')
        note.setObjectName('muted'); note.setWordWrap(True); layout.addWidget(note)
        def card(number,title):
            frame = QFrame(); frame.setObjectName('card')
            content = QVBoxLayout(frame); content.setContentsMargins(14,12,14,12); content.setSpacing(8)
            label = QLabel(f'{number}  /  {title}'); label.setObjectName('sectionTitle'); content.addWidget(label)
            layout.addWidget(frame); return content
        source = card('01','Choose your image')
        self.image = QLineEdit(); self.image.setPlaceholderText('Select an ISO or disk image')
        self.browse = QPushButton('Browse…'); self.browse.clicked.connect(self.choose_image)
        self.download_button = QPushButton('Download…'); self.download_button.clicked.connect(self.download_image)
        image_row = QHBoxLayout(); image_row.addWidget(self.image,1); image_row.addWidget(self.browse); image_row.addWidget(self.download_button); source.addLayout(image_row)
        self.checksum = QLineEdit(); self.checksum.setPlaceholderText('Optional expected SHA-256 checksum')
        source.addWidget(self.checksum)
        self.inspect_button = QPushButton('Inspect image & checksums…')
        self.inspect_button.clicked.connect(self.inspect_image)
        self.windows_button = QPushButton('Customize Windows…'); self.windows_button.clicked.connect(self.configure_windows)
        self.windows_button.setVisible(sys.platform in {'darwin','win32'})
        self.options_summary = QLabel('Standard Windows setup · UEFI / FAT32')
        self.options_summary.setObjectName('muted'); self.options_summary.setWordWrap(True)
        self.options_summary.setVisible(sys.platform in {'darwin','win32'})
        source.addWidget(self.options_summary)
        self.media_button = QPushButton('Media options…'); self.media_button.clicked.connect(self.configure_media)
        self.plan_button=QPushButton('Plan details…');self.plan_button.clicked.connect(self.inspect_plan)
        image_actions = QHBoxLayout(); image_actions.addWidget(self.inspect_button); image_actions.addWidget(self.windows_button); image_actions.addWidget(self.media_button)
        source.addLayout(image_actions)
        self.inspect_button.setMenu(QMenu(self.inspect_button));self.inspect_button.menu().addAction("Inspect image & checksums").triggered.connect(self.inspect_image);self.inspect_button.menu().addAction("Plan details…").triggered.connect(self.inspect_plan)
        target_card = card('02','Select the USB drive')
        self.targets = QComboBox()
        self.targets.currentIndexChanged.connect(self.target_changed)
        self.refresh_button = QPushButton('Refresh'); self.refresh_button.clicked.connect(self.refresh)
        target_row = QHBoxLayout(); target_row.addWidget(self.targets,1); target_row.addWidget(self.refresh_button); target_card.addLayout(target_row)
        self.tools_button = QPushButton('Drive tools…')
        tools = QMenu(self.tools_button)
        for title, operation in [('Back up drive…', 'backup'), ('Restore / format drive…', 'restore'), ('Zero entire drive…', 'zero'), ('Fast zero drive…', 'fast_zero'), ('Quick capacity test…', 'capacity'), ('Full surface test…', 'surface')]:
            action = tools.addAction(title)
            action.triggered.connect(lambda checked=False, operation=operation: self.start_tool(operation))
        tools.addAction("Hide this drive").triggered.connect(self.hide_drive)
        tools.addSeparator()
        for title,kind in [('Create UEFI Shell…','uefi-shell'),('Create GRUB rescue (experimental)…','grub-rescue')]:
            action=tools.addAction(title);action.triggered.connect(lambda checked=False,kind=kind:self.start_boot(kind))
        self.tools_button.setMenu(tools)
        target_row.addWidget(self.tools_button)
        warning = QLabel('All existing data on the selected drive will be erased. You’ll confirm the exact drive before writing.')
        warning.setObjectName('muted'); warning.setWordWrap(True); target_card.addWidget(warning)
        self.fixed = QCheckBox('Also show fixed USB hard drives and SSDs'); self.fixed.toggled.connect(self.refresh); target_card.addWidget(self.fixed)
        output = card('03','Write & verify')
        self.status = QLabel('Ready when you are'); self.status.setWordWrap(True); output.addWidget(self.status)
        self.progress = QProgressBar(); self.progress.setTextVisible(False); self.progress.setValue(0); output.addWidget(self.progress)
        actions = QHBoxLayout(); output.addLayout(actions)
        self.access_button = QPushButton('Enable writing…'); self.access_button.clicked.connect(self.enable_writing)
        self.access_button.setVisible(self.needs_write_access()); actions.addWidget(self.access_button)
        actions.addStretch()
        self.cancel_button = QPushButton('Cancel'); self.cancel_button.clicked.connect(self.cancel); self.cancel_button.setEnabled(False); actions.addWidget(self.cancel_button)
        self.write_button = QPushButton('Write and verify'); self.write_button.setObjectName('primary'); self.write_button.clicked.connect(self.start_write); actions.addWidget(self.write_button)
        layout.addStretch()
        self.image.textChanged.connect(self.image_changed)
        if initial is not None:
            self.image.setText(initial.image or "")
            self.checksum.setText(initial.sha256 or "")
            self.fixed.blockSignals(True)
            self.fixed.setChecked(initial.include_usb_hard_drives)
            self.fixed.blockSignals(False)
        from .native_settings import settings,decode_state
        self.settings=settings(getattr(initial,'portable',False))
        self.fixed.blockSignals(True)
        self.fixed.setChecked(bool(getattr(initial,'include_usb_hard_drives',False)) or self.settings.value('include_fixed',False,type=bool))
        self.fixed.blockSignals(False)
        self.setStyleSheet(LIGHT_STYLE if self.settings.value('theme','dark')=='light' else STYLE)
        self.ignored=set(self.settings.value('ignored',[],type=list))
        if getattr(initial,'session_state_file',None):
            from .native_settings import load_state_file
            self.media_options,self.windows_options,self.windows_bootex=load_state_file(initial.session_state_file,initial.session_state_sha256)
        elif getattr(initial,'session_state',None):
            self.media_options,self.windows_options,self.windows_bootex=decode_state(initial.session_state)
        self.update_options_summary()
        self.refresh()

    def image_changed(self):
        self.windows_options = WindowsCustomization()
        self.windows_bootex = WindowsBootExOptions()
        self.update_options_summary()

    def update_options_summary(self):
        o=self.media_options
        custom=' · customized Windows setup' if self.windows_options.enabled or self.windows_bootex.enabled else ''
        self.options_summary.setText(f'{o.mode.upper()} · {o.partition_table.upper()} · {o.filesystem.upper()} · {o.firmware.upper()}{custom}')

    def configure_media(self):
        from .native_options import MediaOptionsDialog
        if self.job or self.scan or self.access_job:return
        dialog=MediaOptionsDialog(self.media_options,self)
        if dialog.exec():
            self.media_options=dialog.options
            self.update_options_summary()

    def configure_windows(self):
        from .native_windows_options import WindowsOptionsDialog
        if self.job or self.scan or self.access_job:
            return
        if not self.image.text() or not self.image.text().lower().endswith('.iso'):
            QMessageBox.information(self,'Choose a Windows ISO','Select a Windows installer ISO before customizing it.')
            return
        dialog = WindowsOptionsDialog(self.image.text(),self.windows_options,self.windows_bootex,self)
        if dialog.exec():
            self.windows_options, self.windows_bootex = dialog.options, dialog.bootex
            self.update_options_summary()

    def needs_write_access(self):
        if sys.platform != "win32":
            return False
        try:
            NativeWriter().privilege_check(sys.platform)
            return False
        except PermissionError:
            return True

    def enable_writing(self):
        if self.access_job is not None or self.scan is not None or self.job is not None:
            return
        target = self.targets.currentData()
        self.access_job = AccessJob(self.image.text(), self.checksum.text(),
            target.device.path if target else "", self.fixed.isChecked(), self,
            __import__("isopropyl.native_settings",fromlist=["encode_state"]).encode_state(self.media_options,self.windows_options,self.windows_bootex),self.portable)
        self.access_result = None
        self.set_busy(True)
        self.status.setText("Waiting for administrator authorization…")
        self.access_job.result.connect(lambda ok, message: setattr(self, "access_result", (ok, message)))
        self.access_job.finished.connect(self.access_finished)
        self.access_job.start()

    def access_finished(self):
        self.access_job.deleteLater()
        self.access_job = None
        ok, message = self.access_result or (False, "Authorization ended without a result")
        if ok:
            self.close()
        else:
            self.set_busy(False)
            self.status.setText(message)
            QMessageBox.information(self, "Write access", message)

    def choose_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a disk image", "", "Disk images (*.iso *.img *.raw *.usb *.wic *.gz *.gzip *.bz2 *.bzip2 *.xz *.lzma *.zip *.zst *.zstd *.Z *.vtsi *.vhd *.vhdx *.qcow *.qcow2)")
        if path:
            self.image.setText(path)

    def set_busy(self, busy):
        for control in (self.image, self.browse, self.checksum, self.targets, self.fixed,
                        self.refresh_button, self.write_button, self.access_button, self.windows_button, self.plan_button, self.utilities_button, self.settings_button, self.media_button, self.tools_button, self.inspect_button, self.download_button):
            control.setEnabled(not busy)
        self.cancel_button.setEnabled(busy and self.job is not None)
        if not busy:self.target_changed()

    def refresh(self):
        if self.scan is not None or self.job is not None or self.access_job is not None:
            return
        self.scan = Discovery(self.fixed.isChecked(), self)
        self.set_busy(True)
        self.status.setText("Discovering removable drives…")
        self.scan.ready.connect(self.discovered)
        self.scan.finished.connect(self.scan_finished)
        self.scan.start()

    def discovered(self, targets, error):
        previous = self.targets.currentData()
        preferred = self.initial_target or (previous.device.path if previous else None)
        self.targets.clear()
        for target in targets:
            if target.device.path not in getattr(self,"ignored",set()) and target.device.stable_id not in getattr(self,"ignored",set()):
                self.targets.addItem(target.device.display_label("iec" if self.settings.value("binary_units",False,type=bool) else "si")+(" [read-only]" if target.device.read_only else ""), target)
                if target.device.path == preferred:
                    self.targets.setCurrentIndex(self.targets.count() - 1)
        self.initial_target = None
        self.status.setText(error or ("Ready" if self.targets.count() else "No supported removable drives found"))

    def target_changed(self):
        target=self.targets.currentData()
        if hasattr(self,'write_button'):
            self.write_button.setEnabled(bool(target and not target.device.read_only and target.device.logical_sector_size==512) and not(self.job or self.scan or self.access_job))

    def scan_finished(self):
        self.scan.deleteLater()
        self.scan = None
        self.set_busy(False)
        self.target_changed()

    def start_write(self):
        target = self.targets.currentData()
        if target is None:
            return
        try:
            options=replace(self.media_options,customization=self.windows_options,bootex=self.windows_bootex)
            plan=build_media_plan(self.image.text(),target,options,include_fixed=self.fixed.isChecked(),
                                  expected_sha256=self.checksum.text().strip() or None)
        except (OSError, ValueError, RuntimeError) as error:
            QMessageBox.critical(self, "Cannot write image", str(error))
            return
        try:
            if sys.platform != 'darwin':
                NativeWriter().privilege_check(sys.platform)
        except PermissionError:
            self.enable_writing()
            return
        answer = QMessageBox.warning(
            self, "Erase this drive?", f"ALL data on {target.device.label} will be erased.\n"
            + f"Image: {plan.source.name}\nMedia options: {plan.details}.\n"
            + ("Custom Windows settings will be included in the installer.\n" if plan.customization.enabled or plan.bootex.enabled else "")
            + ("The answer file accepts the Windows Setup license terms.\n" if plan.customization.install_image or plan.customization.bypass_hardware_requirements else "")
            + (f"Local administrator '{plan.customization.local_username}' starts with a blank password and requires replacement after setup.\n" if plan.customization.local_username else "")
            + "Are you sure you want to erase this drive and continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.job = WriteJob(plan, plan.confirmation, self)
        self.job.prepared_boot=bool(getattr(self,"boot_workspace",None))
        self.pending_result = None
        self.set_busy(True)
        self.progress.setValue(0)
        self.job.progress.connect(self.update_progress)
        self.job.result.connect(lambda ok, message: setattr(self, "pending_result", (ok, message)))
        self.job.finished.connect(self.write_finished)
        self.job.start()

    def start_tool(self, operation):
        if self.job or self.scan or self.access_job:
            return
        target = self.targets.currentData()
        if target is None:
            QMessageBox.information(self, 'Choose a drive', 'Select a USB drive first.')
            return
        if self.needs_write_access():
            self.enable_writing()
            return
        destination = None
        if operation == 'backup':
            destination, _ = QFileDialog.getSaveFileName(self, 'Save full-drive backup', '', 'Raw disk image (*.img);;VHD (*.vhd);;VHDX (*.vhdx)')
            if not destination:
                return
        options={}
        if operation=='surface':
            from .native_test_options import TestOptionsDialog
            dialog=TestOptionsDialog(self)
            if not dialog.exec():return
            options=dialog.options
        if operation=='backup':options['sparse']=self.settings.value('sparse_backup',True,type=bool)
        if operation=='restore':
            from .native_restore_options import RestoreOptionsDialog
            dialog=RestoreOptionsDialog(self,target.device.size,target.device.logical_sector_size)
            if not dialog.exec():return
            options=dialog.options
        try:
            plan = build_tool_plan(operation, target, include_fixed=self.fixed.isChecked(), destination=destination,**options)
        except (OSError, ValueError, RuntimeError) as error:
            QMessageBox.critical(self, 'Cannot run drive tool', str(error))
            return
        text = (f'Back up every byte of {target.device.label}?\nThe source is opened read-only and checked again before publishing the backup.'
                if operation == 'backup' else
                f'ALL data on {target.device.label} will be erased.\n'
                + ('Create a blank FAT32 partition and verify the entire drive? This overwrites all advertised bytes and can take a while.'
                   if operation == 'format_fat32' else
                   f'Restore {options.get("filesystem","fat32").upper()} using {options.get("partition_table","mbr").upper()}?' if operation=='restore' else
                   'Scan the complete drive, overwrite nonzero chunks, and verify every byte as zero?' if operation=='fast_zero' else
                   'Run a sampled destructive capacity check? A full surface test checks every byte.' if operation=='capacity' else
                   'Write and verify zeroes across the entire drive? This is a logical overwrite, not hardware Secure Erase.'
                   if operation == 'zero' else
                   'Run the selected full-drive write/read passes, including an address-specific capacity check? This can take hours. The drive will need reformatting afterward.'))
        if QMessageBox.warning(self, 'Confirm drive operation', text,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel) != QMessageBox.StandardButton.Yes:
            return
        self.job = WriteJob(plan, plan.confirmation, self)
        self.pending_result = None
        self.set_busy(True); self.progress.setValue(0)
        self.job.progress.connect(self.update_progress)
        self.job.result.connect(lambda ok, message: setattr(self, 'pending_result', (ok, message)))
        self.job.finished.connect(self.write_finished)
        self.job.start()

    def start_task(self,task,finished):
        self.job=TaskJob(task,self);self.pending_result=None;self.set_busy(True);self.progress.setValue(0)
        self.job.progress.connect(self.update_progress);self.job.result.connect(lambda ok,result:setattr(self,'pending_result',(ok,result)))
        self.job.finished.connect(finished);self.job.start()

    def capture_optical(self):
        if self.job or self.scan or self.access_job:return
        from .native_optical import discover_optical
        self.start_task(lambda writer,progress:discover_optical(),self.optical_discovered)

    def optical_discovered(self):
        self.job.deleteLater();self.job=None;self.set_busy(False)
        ok,sources=self.pending_result or (False,'Discovery ended without a result')
        if not ok:QMessageBox.critical(self,'Cannot discover optical media',str(sources));return
        if not sources:QMessageBox.information(self,'Optical capture','No loaded data discs found.');return
        names=[f'{s.label} · {s.path}' for s in sources]
        name,accepted=QInputDialog.getItem(self,'Capture optical disc','Read-only source:',names,0,False)
        if not accepted:return
        path,_=QFileDialog.getSaveFileName(self,'Save optical image','','Optical image (*.iso)')
        if not path:return
        from .native_optical import build_optical_plan,run_optical
        try:plan=build_optical_plan(sources[names.index(name)],path)
        except (OSError,ValueError,RuntimeError) as error:QMessageBox.critical(self,'Cannot capture disc',str(error));return
        self.start_task(lambda writer,progress:f'Optical image verified.\n{plan.destination}\nISO file SHA-256: {run_optical(plan,writer,progress=progress)}',self.utility_finished)

    def extract_files(self):
        if self.job or self.scan or self.access_job:return
        folder=QFileDialog.getExistingDirectory(self,'Choose parent folder for extracted ISO')
        if not folder:return
        from pathlib import Path
        import tempfile,shutil
        from .native_extract import extract_iso,snapshot_file
        from .native_writer import path_file_identity
        source=Path(self.image.text()).absolute();destination=Path(folder)/'ISOpropyl-extracted'
        if destination.exists():QMessageBox.critical(self,'Cannot extract ISO','ISOpropyl-extracted already exists in that folder.');return
        def extract(writer,progress):
            with tempfile.TemporaryDirectory(prefix='.isopropyl-extract-',dir=folder) as workspace:
                snapshot=Path(workspace)/'input.iso';snapshot_file(source,path_file_identity(source),snapshot,writer,progress)
                tree=Path(workspace)/'files';extract_iso(snapshot,tree,writer,progress)
                # Publish by directory rename: no existing destination is intentionally replaced.
                if destination.exists():raise FileExistsError(str(destination))
                tree.rename(destination)
            return f'Extracted ISO files: {destination}'
        self.start_task(extract,self.utility_finished)

    def utility_finished(self):
        self.job.deleteLater();self.job=None;self.set_busy(False)
        ok,result=self.pending_result or (False,'Operation ended without a result')
        self.status.setText('Complete' if ok else 'Stopped')
        (QMessageBox.information if ok else QMessageBox.critical)(self,'ISOpropyl',str(result))

    def start_boot(self,kind):
        if self.job or self.scan or self.access_job:return
        if self.needs_write_access():self.enable_writing();return
        target=self.targets.currentData()
        if not target:return
        architectures=None
        if kind=='uefi-shell':
            dialog=QDialog(self);dialog.setWindowTitle('UEFI Shell architectures');layout=QVBoxLayout(dialog)
            controls=[]
            from .uefi_shell import UEFI_SHELL_ARTIFACTS
            for name in (item.architecture for item in UEFI_SHELL_ARTIFACTS):
                control=QCheckBox(name);control.setChecked(name in {'x64','ARM64'});controls.append(control);layout.addWidget(control)
            buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Ok|QDialogButtonBox.StandardButton.Cancel);buttons.accepted.connect(dialog.accept);buttons.rejected.connect(dialog.reject);layout.addWidget(buttons)
            if not dialog.exec():return
            architectures=tuple(c.text() for c in controls if c.isChecked())
            if not architectures:QMessageBox.information(self,'Choose architectures','Select at least one architecture.');return
        self.job=PreparationJob(kind,target,self,architectures);self.pending_result=None
        self.set_busy(True);self.progress.setValue(0)
        self.job.progress.connect(self.update_progress)
        self.job.result.connect(lambda ok,result:setattr(self,'pending_result',(ok,result)))
        self.job.finished.connect(self.boot_prepared);self.job.start()

    def boot_prepared(self):
        job=self.job;self.job=None;self.set_busy(False)
        ok,result=self.pending_result or (False,'Preparation ended without a result')
        if not ok:
            QMessageBox.critical(self,'Cannot prepare boot media',str(result));job.deleteLater();return
        self.boot_workspace=job.workspace;job.deleteLater()
        self.image.setText(str(result));self.media_options=NativeMediaOptions(mode='dd')
        self.start_write()
        if self.job is None:self.boot_workspace.cleanup();self.boot_workspace=None

    def hide_drive(self):
        if self.job or self.scan or self.access_job:return
        target=self.targets.currentData()
        if not target:return
        self.ignored.add(target.device.stable_id or target.device.path)
        self.settings.setValue('ignored',sorted(self.ignored));self.settings.sync();self.refresh()

    def configure_settings(self):
        from .native_preferences import PreferencesDialog
        dialog=PreferencesDialog(self.settings,self)
        if dialog.exec():
            self.setStyleSheet(LIGHT_STYLE if self.settings.value('theme','dark')=='light' else STYLE)
            self.ignored=set(self.settings.value('ignored',[],type=list));self.refresh()

    def inspect_plan(self):
        if self.job or self.scan or self.access_job:return
        target=self.targets.currentData()
        if not target:QMessageBox.information(self,'Plan details','Choose a target drive first.');return
        from .native_media import describe_media_plan
        try:plan=build_media_plan(self.image.text(),target,replace(self.media_options,customization=self.windows_options,bootex=self.windows_bootex),include_fixed=self.fixed.isChecked(),expected_sha256=self.checksum.text().strip() or None)
        except (OSError,ValueError,RuntimeError) as error:QMessageBox.critical(self,'Cannot plan media',str(error));return
        self.start_task(lambda writer,progress:describe_media_plan(plan,writer,progress),self.inspection_finished)

    def inspect_image(self):
        if self.job or self.scan or self.access_job:
            return
        self.job = InspectionJob(self.image.text(),self)
        self.pending_result = None
        self.set_busy(True); self.progress.setValue(0)
        self.job.progress.connect(self.update_progress)
        self.job.result.connect(lambda ok,message:setattr(self,'pending_result',(ok,message)))
        self.job.finished.connect(self.inspection_finished)
        self.job.start()

    def inspection_finished(self):
        self.job.deleteLater(); self.job = None
        self.set_busy(False)
        ok, detail = self.pending_result or (False,'Inspection ended without a result')
        self.status.setText('Inspection complete' if ok else 'Inspection stopped')
        if not ok:
            QMessageBox.critical(self,'Cannot inspect image',detail)
            return
        dialog = QDialog(self); dialog.setWindowTitle('Image inspection'); dialog.resize(600,440)
        dialog.setStyleSheet(self.styleSheet())
        layout = QVBoxLayout(dialog)
        text = QPlainTextEdit(detail); text.setReadOnly(True); layout.addWidget(text)
        copy = QPushButton('Copy results'); copy.clicked.connect(lambda:QApplication.clipboard().setText(detail)); layout.addWidget(copy)
        close = QPushButton('Close'); close.clicked.connect(dialog.accept); layout.addWidget(close)
        dialog.exec()

    def download_image(self):
        from pathlib import Path
        if self.job or self.scan or self.access_job:
            return
        try:
            from .windows_downloads import available_windows_images
            from .linux_downloads import available_linux_images
            from .freedos_downloads import available_freedos_images
            choices = [(family,item) for family,items in [('Windows',available_windows_images()),
                ('Ubuntu',available_linux_images()),('FreeDOS',available_freedos_images())] for item in items]
            names = [f'{family} · {item.release} · {item.edition} · {item.architecture}' for family,item in choices]
            selection,accepted = QInputDialog.getItem(self,'Download official image','Choose an image:',names,0,False)
            if not accepted:
                return
            family,release = choices[names.index(selection)]
            source_url = None
            if family == 'Windows' and not release.direct_resolver_supported:
                source_url,accepted = QInputDialog.getText(self,'Microsoft download link',
                    f'Create the English {release.architecture} download link on {release.provenance_url}, then paste it here:')
                if not accepted or not source_url.strip():
                    return
                source_url = source_url.strip()
            folder = QFileDialog.getExistingDirectory(self,'Choose download folder')
            if not folder:
                return
            destination = Path(folder).resolve()/(release.image_filename if family == 'FreeDOS' else release.filename)
        except (OSError,ValueError,RuntimeError) as error:
            QMessageBox.critical(self,'Cannot prepare download',str(error))
            return
        self.job = DownloadJob(family,release,destination,source_url,self)
        self.pending_result = None
        self.set_busy(True); self.progress.setValue(0)
        self.job.progress.connect(self.update_progress)
        self.job.result.connect(lambda ok,result:setattr(self,'pending_result',(ok,result)))
        self.job.finished.connect(self.download_finished)
        self.job.start()

    def download_finished(self):
        self.job.deleteLater(); self.job = None; self.set_busy(False)
        ok,result = self.pending_result or (False,'Download ended without a result')
        if not ok:
            self.status.setText('Download stopped'); QMessageBox.critical(self,'Download stopped',str(result))
            return
        self.image.setText(str(result.path)); self.checksum.setText(result.sha256)
        self.status.setText('Download verified. Select a drive when ready.')

    def update_progress(self, stage, percent):
        self.status.setText(stage)
        self.progress.setValue(percent)

    def write_finished(self):
        self.job.deleteLater()
        self.job = None
        self.set_busy(False)
        ok, message = self.pending_result or (False, "Writer ended without a result")
        if getattr(self,"boot_workspace",None):
            self.boot_workspace.cleanup();self.boot_workspace=None
        self.status.setText("Verified" if ok else "Write stopped")
        (QMessageBox.information if ok else QMessageBox.critical)(self, "ISOpropyl", message)
        self.refresh()

    def cancel(self):
        if self.job:
            self.job.writer.cancel()
            self.cancel_button.setEnabled(False)
            self.status.setText("Cancelling…")

    def closeEvent(self, event):
        if self.job is not None or self.scan is not None or self.access_job is not None:
            event.ignore()
            if self.job:
                self.cancel()
        else:
            self.settings.setValue("include_fixed",self.fixed.isChecked())
            self.settings.sync()
            event.accept()


def main() -> int:
    parser = argparse.ArgumentParser(description="ISOpropyl native GUI")
    parser.add_argument("--portable",action="store_true")
    parser.add_argument("--session-state",help=argparse.SUPPRESS)
    parser.add_argument("--session-state-file",help=argparse.SUPPRESS)
    parser.add_argument("--session-state-sha256",help=argparse.SUPPRESS)
    parser.add_argument("--image")
    parser.add_argument("--sha256")
    parser.add_argument("--target")
    parser.add_argument("--include-usb-hard-drives", action="store_true")
    parser.add_argument("--startup-report", help=argparse.SUPPRESS)
    parser.add_argument("--check-disk-access", help=argparse.SUPPRESS)
    parser.add_argument("--check-disk-write-access", help=argparse.SUPPRESS)
    initial = parser.parse_args(sys.argv[1:])
    if initial.check_disk_access or initial.check_disk_write_access:
        import json
        import stat
        import tempfile
        from pathlib import Path

        from .native_disk_io import authorized_mac_open, open_disk
        try:
            if sys.platform != 'darwin':
                raise ValueError('Disk access probe requires macOS')
            path = initial.check_disk_access or initial.check_disk_write_access
            targets = [item for item in discover(False) if item.device.path == path]
            if len(targets) != 1:
                raise ValueError('Probe target must be a currently eligible removable disk')
            if initial.check_disk_write_access:
                with tempfile.TemporaryDirectory(prefix='isopropyl-access-check-') as directory:
                    source = Path(directory)/'probe.img'
                    source.write_bytes(bytes(512))
                    plan = build_plan(source, targets[0])
                    checker = NativeWriter(host='darwin')
                    checker.revalidate(plan)
                    with open_disk(targets[0], 'darwin') as disk:
                        data = disk.read(512)
                        current = checker.revalidate(plan, locked=True)
                        locked = [current]
                print(json.dumps({'ok':len(data) == 512, 'bytes_read':len(data), 'write_started':False,
                                  'before':targets[0].__dict__ | {'device':targets[0].device.__dict__},
                                  'locked':[item.__dict__ | {'device':item.device.__dict__} for item in locked]}), flush=True)
                return 0
            raw = '/dev/r' + targets[0].device.path.removeprefix('/dev/')
            descriptor = authorized_mac_open(raw, os.O_RDONLY | os.O_NONBLOCK)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISCHR(info.st_mode) or info.st_rdev != os.stat(raw).st_rdev:
                    raise ValueError('Probe descriptor identity changed')
                data = os.read(descriptor, 512)
                if len(data) != 512:
                    raise ValueError('Probe could not read a complete sector')
                locked = [item for item in discover(False) if item.device.path == path]
            finally:
                os.close(descriptor)
            print(json.dumps({'ok':True, 'bytes_read':len(data), 'write_started':False,
                              'before':targets[0].__dict__ | {'device':targets[0].device.__dict__},
                              'locked':[item.__dict__ | {'device':item.device.__dict__} for item in locked]}), flush=True)
            return 0
        except Exception as error:
            print(json.dumps({'ok':False, 'error':str(error), 'write_started':False}), flush=True)
            return 1
    from .logging_setup import setup_logging
    setup_logging()
    app = QApplication(sys.argv)
    app.setApplicationName("ISOpropyl")
    app.setOrganizationName("codebooker")
    app.setWindowIcon(QIcon(str(files("isopropyl").joinpath("data/io.github.codebooker.isopropyl.svg"))))
    window = NativeWindow(initial)
    window.show()
    if initial.startup_report:
        def ready():
            try:
                report_gui_ready(initial.startup_report)
            except OSError as error:
                print(f"Could not report GUI startup: {error}", file=sys.stderr)
        QTimer.singleShot(0, ready)
    return app.exec()
