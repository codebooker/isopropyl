"""Shared, asynchronous update controls for both Qt interfaces."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import tempfile
import threading
import time
from pathlib import Path

from PyQt6.QtCore import QObject, QThread, QTimer, Qt, pyqtSignal
from PyQt6.QtWidgets import (QCheckBox, QDialog, QHBoxLayout, QLabel,
    QPlainTextEdit, QProgressBar, QPushButton, QVBoxLayout)

from .updates import current_version, check_for_update, download_update, UpdateCancelled


class UpdateJob(QThread):
    result = pyqtSignal(object)
    failed = pyqtSignal(str)
    progress = pyqtSignal(object, object)
    phase = pyqtSignal(str)

    def __init__(self, task, *, cancellable=True):
        super().__init__()
        self.task = task
        self.cancellable = cancellable
        self.cancel_event = threading.Event()

    def check_cancelled(self):
        if self.cancel_event.is_set():
            raise UpdateCancelled('Update cancelled')

    def run(self):
        try:
            value = self.task(self.check_cancelled, self.progress.emit)
            if self.cancellable:
                self.check_cancelled()
            self.result.emit(value)
        except Exception as error:
            self.failed.emit(str(error))


def _enabled(value):
    return value is True or str(value).lower() in {'1', 'true', 'yes'}


class UpdateDialog(QDialog):
    def reject(self):
        if not self.parent().updater.committing:
            super().reject()


class UpdateController(QObject):
    """Never replace application files while the GUI or a disk job is running."""
    def __init__(self, window, settings, busy):
        super().__init__(window)
        self.window, self.settings, self.busy = window, settings, busy
        self.job = None
        self.release = None
        self.dialog = None
        self.actions = []
        self.workspace = None
        self.closing = False
        self.handoff = False
        self.committing = False
        self.cancel_requested = False
        self.stage_ready = False
        self.startup = QTimer(self)
        self.startup.setSingleShot(True)
        self.startup.timeout.connect(self.automatic_check)
        self.startup.start(2500)
        self.daily = QTimer(self)
        self.daily.setInterval(3600000)
        self.daily.timeout.connect(self.automatic_check)
        self.daily.start()
        self.result_timer = QTimer(self)
        self.result_timer.setSingleShot(True)
        self.result_timer.timeout.connect(self._startup_result)
        self.result_timer.start(500)
        QTimer.singleShot(0, self._notify_ready)

    def _notify_ready(self):
        from .update_install import notify_update_ready
        try:
            notify_update_ready()
        except Exception:
            import logging
            logging.getLogger(__name__).exception("Could not confirm updated application startup")
            self.startup.stop()
            self.daily.stop()
            self.result_timer.stop()
            self.window.setEnabled(False)
            self._close_failed_startup()

    def _close_failed_startup(self):
        # A helper may roll this startup attempt back; never allow disk work.
        if self.busy():
            QTimer.singleShot(50, self._close_failed_startup)
        else:
            self.window.close()

    def _previous_status(self, target):
        from .update_install import read_update_status
        try:
            return read_update_status(target)
        except (OSError, ValueError):
            return None

    def _startup_result(self):
        previous = self._previous_status(self._target())
        if not previous or previous.get('state') not in {'failed', 'rolled-back'}:
            return
        stamp = str(previous.get('time', ''))
        if stamp == str(self.settings.value('updates/seen_result', '')):
            return
        if self.busy() or self.dialog is not None:
            self.result_timer.start(1000)
            return
        self.settings.setValue('updates/seen_result', stamp)
        self.settings.sync()
        self.show()

    def add_action(self, action):
        self.actions.append(action)
        signal = getattr(action, 'triggered', None) or action.clicked
        signal.connect(self.show)

    def automatic_check(self):
        if not _enabled(self.settings.value('updates/automatic', True)):
            return
        try:
            last = float(self.settings.value('updates/last_check', 0))
        except (ValueError, TypeError):
            last = 0
        if time.time() - last >= 86400:
            self.check(silent=True)

    def _target(self):
        from .update_install import detect_installation
        return detect_installation()

    def _start(self, task, result, *, silent=False, cancellable=True):
        if self.job is not None:
            return
        job = UpdateJob(task, cancellable=cancellable)
        self.job = job
        job.result.connect(result)
        job.failed.connect(lambda message: self._error(message, silent))
        job.progress.connect(self._progress)
        job.phase.connect(self._status)
        job.finished.connect(lambda: self._finished(job))
        self._controls(True)
        job.start()

    def _finished(self, job):
        if self.job is job:
            self.job = None
        job.deleteLater()
        self._controls(False)
        if self.closing:
            QTimer.singleShot(0, self.window.close)

    def _controls(self, active):
        if self.dialog is not None:
            self.check_button.setEnabled(not active and not self.stage_ready)
            self.install_button.setEnabled(not active and not self.stage_ready and self.release is not None and self.target.supported)
            self.close_button.setText('Cancel' if active else 'Close')
            self.close_button.setEnabled(not self.committing)

    def _status(self, message):
        if self.dialog is not None:
            self.status.setText(message)

    def _error(self, message, silent=False):
        self.committing = False
        if not silent:
            self._status(message)
        if self.workspace is not None and not self.handoff:
            self.workspace.cleanup()
            self.workspace = None

    def _progress(self, done, total):
        if self.dialog is not None:
            if total > 0:
                self.progress.setRange(0, 1000)
                self.progress.setValue(min(1000, int(done * 1000 / total)))
            else:
                self.progress.setRange(0, 0)

    def check(self, _checked=False, *, silent=False):
        if self.job is not None:
            return
        target = self._target()
        self.settings.setValue('updates/last_check', time.time())
        self.settings.sync()
        self._status('Checking GitHub for a newer release…')
        self._start(lambda cancel, progress: check_for_update(kind=target.kind, cancel_check=cancel),
                    self._checked, silent=silent)

    def _checked(self, release):
        self.release = release
        for action in self.actions:
            action.setText(f'Update available: {release.version}…' if release else 'Check for updates…')
        if self.dialog is not None:
            if release:
                self._status(f'ISOpropyl {release.version} is available.')
                self.notes.setPlainText(release.notes or 'No release notes were provided.')
            else:
                self._status('You’re up to date. No newer compatible release is available.')
                self.notes.clear()

    def show(self, _checked=False):
        if self.dialog is not None:
            self.dialog.raise_()
            self.dialog.activateWindow()
            return
        if self.busy():
            return
        self.target = self._target()
        dialog = UpdateDialog(self.window)
        self.dialog = dialog
        dialog.setWindowTitle('ISOpropyl updates')
        dialog.resize(480, 380)
        dialog.setWindowModality(Qt.WindowModality.WindowModal)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel(f'Installed version: {current_version()}'))
        automatic = QCheckBox('Check automatically once a day')
        automatic.setChecked(_enabled(self.settings.value('updates/automatic', True)))
        def preference(checked):
            self.settings.setValue('updates/automatic', checked)
            self.settings.sync()
        automatic.toggled.connect(preference)
        layout.addWidget(automatic)
        self.status = QLabel('Check for the latest release on GitHub.')
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status)
        if not self.target.supported:
            reason = QLabel(self.target.reason)
            reason.setWordWrap(True)
            reason.setTextFormat(Qt.TextFormat.PlainText)
            layout.addWidget(reason)
        self.notes = QPlainTextEdit()
        self.notes.setReadOnly(True)
        self.notes.setPlaceholderText('Release notes')
        previous = self._previous_status(self.target)
        if previous and previous.get('state') in {'failed', 'rolled-back'}:
            last_status = QLabel('Previous update: ' + str(previous.get('message') or previous.get('state')))
            last_status.setWordWrap(True)
            last_status.setTextFormat(Qt.TextFormat.PlainText)
            layout.addWidget(last_status)
        layout.addWidget(self.notes)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        layout.addWidget(self.progress)
        row = QHBoxLayout()
        self.check_button = QPushButton('Check now')
        self.check_button.clicked.connect(self.check)
        self.install_button = QPushButton('Update and restart')
        self.install_button.setObjectName('primary')
        self.install_button.clicked.connect(self.install)
        self.close_button = QPushButton('Close')
        self.close_button.clicked.connect(self.close_dialog)
        for button in (self.check_button, self.install_button, self.close_button):
            row.addWidget(button)
        layout.addLayout(row)
        # Escape/window close cancels a transfer without destroying its QThread.
        dialog.rejected.connect(self._dialog_closed)
        dialog.finished.connect(self._dialog_closed)
        self._controls(self.job is not None)
        if self.release is not None:
            self._checked(self.release)
        dialog.open()
        if self.job is None and self.release is None:
            self.check()

    def _dialog_closed(self, *_):
        if self.job is not None and not self.handoff:
            self.cancel_requested = True
            self.job.cancel_event.set()
        dialog, self.dialog = self.dialog, None
        if dialog is not None:
            dialog.deleteLater()

    def close_dialog(self):
        if self.committing:
            return
        if self.job is not None:
            self.cancel_requested = True
            self.job.cancel_event.set()
            self._status('Cancelling…')
        elif self.dialog is not None:
            self.dialog.reject()

    def install(self):
        if self.job is not None or self.stage_ready or self.release is None or self.busy():
            return
        self.target = self._target()
        if not self.target.supported:
            self._status(self.target.reason)
            return
        release, target = self.release, self.target
        self.cancel_requested = False
        self.workspace = tempfile.TemporaryDirectory(prefix='isopropyl-update-download-')
        self._status(f'Downloading and verifying ISOpropyl {release.version}…')
        def stage(cancel, progress):
            from .update_install import prepare_update
            payload = download_update(release, Path(self.workspace.name), progress=progress, cancel_check=cancel)
            cancel()
            self.job.phase.emit('Preparing the updated application…')
            plan = prepare_update(release, payload, target,
                progress=lambda stage, done, total: (self.job.phase.emit(stage), progress(done, total)))
            try:
                cancel()
            except BaseException:
                from .update_install import discard_update
                discard_update(plan)
                raise
            return plan
        self._start(stage, self._prepared, cancellable=False)

    def _prepared(self, plan):
        # QThread.finished follows result; start handoff only after that signal.
        self.plan = plan
        self.stage_ready = True
        QTimer.singleShot(0, self._handoff)

    def _handoff(self):
        if self.job is not None:
            QTimer.singleShot(10, self._handoff)
            return
        if self.busy() or self.dialog is None or self.closing or self.cancel_requested:
            from .update_install import discard_update
            discard_update(self.plan)
            self.stage_ready = False
            self._error('Update cancelled.' if self.cancel_requested else
                        'The update was paused. Finish the current operation and try again.')
            return
        self.stage_ready = False
        self.committing = True
        self.close_button.setEnabled(False)
        self._status('Preparing to restart. ISOpropyl will reopen after the update…')
        def launch(cancel, progress):
            from .update_install import launch_install
            cancel()
            return launch_install(self.plan, busy=self.busy())
        self._start(launch, self._launched, cancellable=False)

    def _launched(self, launch):
        self.handoff = True
        self.settings.setValue('updates/status_path', str(launch.status_path))
        self.settings.sync()
        self.closing = True
        # The external helper owns the verified stage from this point onward.
        if self.workspace is not None:
            self.workspace.cleanup()
            self.workspace = None

    def can_close(self):
        self.startup.stop()
        self.daily.stop()
        self.result_timer.stop()
        if self.job is None:
            return True
        self.closing = True
        if not self.handoff and not self.committing:
            self.cancel_requested = True
            self.job.cancel_event.set()
        return False


def operation_in_progress(window):
    """Shared guard for background discovery, inspection and destructive work."""
    flags = ('_update_operation_busy', 'operation_active', 'inspection_busy', 'inspection_worker_count',
             'checksum_busy', 'device_refresh_busy')
    jobs = ('job', 'scan', 'access_job')
    return any(bool(getattr(window, name, False)) for name in flags) or any(
        getattr(window, name, None) is not None for name in jobs)
