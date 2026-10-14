# SPDX-License-Identifier: AGPL-3.0-or-later
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton
from isopropyl.update_ui import UpdateController, operation_in_progress


class MemorySettings:
    def __init__(self): self.data = {'updates/automatic': False}
    def value(self, key, default=None): return self.data.get(key, default)
    def setValue(self, key, value): self.data[key] = value
    def sync(self): pass


class UpdateUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.settings = MemorySettings()
        self.window = QMainWindow()
        self.busy = False
        self.target = SimpleNamespace(kind='portable-zip', supported=True, reason='')
        self.patches = [patch('isopropyl.update_install.detect_installation', return_value=self.target),
                        patch('isopropyl.update_install.read_update_status', return_value=None),
                        patch('isopropyl.update_install.notify_update_ready')]
        for item in self.patches: item.start(); self.addCleanup(item.stop)
        self.controller = UpdateController(self.window, self.settings, lambda: self.busy)
        self.window.updater = self.controller
        self.controller.startup.stop()
        self.button = QPushButton()
        self.controller.add_action(self.button)
        self.release = SimpleNamespace(version='0.2.0', notes='<b>Release notes</b>', asset=SimpleNamespace(kind='portable-zip'))
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.controller.job:
            self.controller.job.cancel_event.set()
            self.wait_idle()
        if self.controller.dialog: self.controller.dialog.reject()
        self.window.deleteLater()
        self.app.processEvents()

    def wait_idle(self):
        deadline = time.monotonic() + 3
        while self.controller.job is not None and time.monotonic() < deadline:
            self.app.processEvents(); time.sleep(.001)
        self.assertIsNone(self.controller.job)

    def show_available(self):
        self.controller.release = self.release
        self.controller.show()

    def test_manual_check_offers_matching_release_and_plaintext_notes(self):
        with patch('isopropyl.update_ui.check_for_update', return_value=self.release) as check:
            self.controller.show(); self.wait_idle()
        check.assert_called_once()
        self.assertIn('0.2.0', self.button.text())
        self.assertEqual(self.controller.notes.toPlainText(), '<b>Release notes</b>')
        self.assertTrue(self.controller.install_button.isEnabled())
        self.assertIn('updates/last_check', self.settings.data)

    def test_automatic_checks_are_optional_and_daily(self):
        with patch.object(self.controller, 'check') as check:
            self.controller.automatic_check(); check.assert_not_called()
            self.settings.data['updates/automatic'] = True
            self.settings.data['updates/last_check'] = time.time()
            self.controller.automatic_check(); check.assert_not_called()
            self.settings.data['updates/last_check'] = 0
            self.controller.automatic_check(); check.assert_called_once_with(silent=True)

    def test_active_disk_work_prevents_show_and_install(self):
        self.busy = True
        self.controller.show()
        self.assertIsNone(self.controller.dialog)
        self.controller.release = self.release
        with patch('isopropyl.update_ui.download_update') as download:
            self.controller.install()
        download.assert_not_called()

    def test_check_failure_allows_retry_without_install(self):
        with patch('isopropyl.update_ui.check_for_update', side_effect=RuntimeError('Network unavailable')):
            self.controller.show(); self.wait_idle()
        self.assertEqual(self.controller.status.text(), 'Network unavailable')
        self.assertTrue(self.controller.check_button.isEnabled())
        self.assertFalse(self.controller.install_button.isEnabled())

    def test_unsupported_install_can_check_but_not_replace_files(self):
        self.target.supported = False
        self.target.reason = 'This is a development checkout.'
        self.show_available()
        self.assertFalse(self.controller.install_button.isEnabled())
        with patch('isopropyl.update_ui.download_update') as download: self.controller.install()
        download.assert_not_called()

    def test_close_waits_for_check_to_finish_and_requests_cancellation(self):
        import threading
        entered = threading.Event()
        def check(**kwargs):
            entered.set()
            while True:
                kwargs['cancel_check'](); time.sleep(.001)
        with patch('isopropyl.update_ui.check_for_update', side_effect=check):
            self.controller.check(silent=True)
            self.assertTrue(entered.wait(1))
            self.assertFalse(self.controller.can_close())
            self.wait_idle()
        self.assertTrue(self.controller.can_close())

    def test_failed_handoff_keeps_current_app_open(self):
        self.show_available()
        self.controller.plan = object()
        with patch('isopropyl.update_install.launch_install', side_effect=RuntimeError('Helper could not start')):
            self.controller._handoff(); self.wait_idle()
        self.assertFalse(self.controller.handoff)
        self.assertFalse(self.controller.closing)
        self.assertIn('Helper could not start', self.controller.status.text())
        self.assertTrue(self.controller.close_button.isEnabled())

    def test_successful_handoff_records_status_and_closes_after_worker_finishes(self):
        self.show_available()
        self.controller.plan = object()
        launch = SimpleNamespace(status_path='/private/update-status.json')
        with patch('isopropyl.update_install.launch_install', return_value=launch):
            self.controller._handoff(); self.wait_idle()
        self.assertTrue(self.controller.handoff)
        self.assertTrue(self.controller.closing)
        self.assertEqual(self.settings.data['updates/status_path'], '/private/update-status.json')

    def test_busy_guard_covers_discovery_inspection_and_writer(self):
        self.assertFalse(operation_in_progress(SimpleNamespace()))
        for name in ('operation_active', 'inspection_busy', 'checksum_busy', 'device_refresh_busy'):
            self.assertTrue(operation_in_progress(SimpleNamespace(**{name: True})))
        for name in ('job', 'scan', 'access_job'):
            self.assertTrue(operation_in_progress(SimpleNamespace(**{name: object()})))

    def test_cancel_after_download_prevents_handoff_and_discards_plan(self):
        self.show_available()
        self.controller.plan = object()
        self.controller.cancel_requested = True
        with patch('isopropyl.update_install.discard_update') as discard, \
             patch('isopropyl.update_install.launch_install') as launch:
            self.controller._handoff()
        discard.assert_called_once_with(self.controller.plan)
        launch.assert_not_called()
        self.assertEqual(self.controller.status.text(), 'Update cancelled.')

    def test_single_click_downloads_prepares_then_hands_off(self):
        self.show_available()
        plan = object()
        with patch('isopropyl.update_ui.download_update', return_value=Path('/verified/update.zip')) as download, \
             patch('isopropyl.update_install.prepare_update', return_value=plan) as prepare, \
             patch('isopropyl.update_install.launch_install', return_value=SimpleNamespace(status_path='/state/status.json')) as launch:
            self.controller.install()
            deadline = time.monotonic() + 3
            while not self.controller.handoff and time.monotonic() < deadline:
                self.app.processEvents(); time.sleep(.001)
            self.wait_idle()
        download.assert_called_once()
        self.assertEqual(prepare.call_args.args, (self.release, Path('/verified/update.zip'), self.target))
        self.assertTrue(callable(prepare.call_args.kwargs['progress']))
        launch.assert_called_once_with(plan, busy=False)
        self.assertTrue(self.controller.handoff)

    def test_failed_startup_handshake_disables_new_window_before_rollback(self):
        self.busy = True
        with patch('isopropyl.update_install.notify_update_ready', side_effect=RuntimeError('bad token')), \
             self.assertLogs('isopropyl.update_ui', level='ERROR'):
            self.controller._notify_ready()
        self.assertFalse(self.window.isEnabled())
        self.assertFalse(self.controller.startup.isActive())
        self.assertFalse(self.controller.daily.isActive())
        self.busy = False
