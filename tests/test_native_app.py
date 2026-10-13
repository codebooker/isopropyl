# SPDX-License-Identifier: AGPL-3.0-or-later
import os

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import time
import unittest
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication

from isopropyl.native_app import NativeWindow, WriteJob


class AppTests(unittest.TestCase):
    def test_click_confirmation_passes_bound_plan_without_text_entry(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import Mock

        from PyQt6.QtWidgets import QMessageBox

        from isopropyl.devices import Device
        from isopropyl.native_devices import NativeDevice
        target = NativeDevice(Device('/dev/disk8',4096,'TEST','','usb','123','','disk8',
                                     True,True,False,(),(),512))
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'image.img';source.write_bytes(bytes(512))
            window=self.ready_window(target);window.image.setText(str(source))
            worker=Mock()
            with patch('isopropyl.native_app.QMessageBox.warning',return_value=QMessageBox.StandardButton.Yes) as confirm, \
                    patch('isopropyl.native_app.WriteJob',return_value=worker) as job, \
                    patch('isopropyl.native_app.NativeWriter',return_value=Mock()):
                window.start_write()
            self.assertEqual(confirm.call_args.args[-1],QMessageBox.StandardButton.Cancel)
            self.assertIn(target.device.path,confirm.call_args.args[2])
            self.assertNotIn('Type ',confirm.call_args.args[2])
            self.assertEqual(job.call_args.args[1],job.call_args.args[0].confirmation)
            worker.start.assert_called_once()
            window.job=None;window.close()

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        import tempfile
        from PyQt6.QtCore import QSettings
        cls.settings_directory=tempfile.TemporaryDirectory()
        cls.settings_patch=patch('isopropyl.native_settings.settings',side_effect=lambda *args:QSettings(cls.settings_directory.name+'/test.ini',QSettings.Format.IniFormat))
        cls.settings_patch.start()
        cls.addClassCleanup(cls.settings_patch.stop);cls.addClassCleanup(cls.settings_directory.cleanup)

    def test_startup_discovery_keeps_ui_thread_responsive(self):
        with patch('isopropyl.native_app.discover', return_value=[]):
            window = NativeWindow()
            deadline = time.monotonic() + 5
            while window.scan is not None and time.monotonic() < deadline:
                self.app.processEvents()
                time.sleep(.001)
            self.assertIsNone(window.scan)
            self.assertIn('No supported', window.status.text())
            self.assertFalse(window.write_button.isEnabled())
            self.assertFalse(window.cancel_button.isEnabled())
            window.close()

    def test_discovery_error_is_visible_and_controls_recover(self):
        with patch('isopropyl.native_app.discover', side_effect=RuntimeError('native discovery failed')):
            window = NativeWindow()
            deadline = time.monotonic() + 5
            while window.scan is not None and time.monotonic() < deadline:
                self.app.processEvents()
                time.sleep(.001)
            self.assertIsNone(window.scan)
            self.assertEqual(window.status.text(), 'native discovery failed')
            self.assertTrue(window.refresh_button.isEnabled())
            window.close()

    def test_worker_reports_incomplete_target_on_failure(self):
        worker = WriteJob(None, '', None)
        messages = []
        worker.result.connect(lambda ok, detail: messages.append((ok, detail)))
        worker.writer.write_started = True
        with patch.object(worker.writer, 'run', side_effect=OSError('device disconnected')),patch('isopropyl.native_app.run_macos_write',side_effect=OSError('device disconnected')):
            worker.run()
        self.assertFalse(messages[0][0])
        self.assertIn('incomplete', messages[0][1])

    def ready_window(self, target=None, initial=None):
        with patch('isopropyl.native_app.discover', return_value=[target] if target else []):
            window = NativeWindow(initial)
            deadline = time.monotonic() + 5
            while window.scan is not None and time.monotonic() < deadline:
                self.app.processEvents()
                time.sleep(.001)
            self.assertIsNone(window.scan)
            return window

    def test_initial_selection_restored_without_starting_a_write(self):
        from types import SimpleNamespace

        from isopropyl.devices import Device
        from isopropyl.native_devices import NativeDevice
        target = NativeDevice(Device('/dev/disk8', 4096, 'Flash', '', 'usb', '123', '',
                                     'disk8', True, True, False, (), (), 512))
        initial = SimpleNamespace(image='/Images/test.img', sha256='a'*64, target='/dev/disk8',
                                  include_usb_hard_drives=True)
        window = self.ready_window(target, initial)
        self.assertEqual(window.image.text(), '/Images/test.img')
        self.assertEqual(window.checksum.text(), 'a'*64)
        self.assertEqual(window.targets.currentData().device.path, '/dev/disk8')
        self.assertTrue(window.fixed.isChecked())
        self.assertIsNone(window.job)
        self.assertIsNone(window.access_job)
        window.close()

    def test_access_uses_operating_system_authorization_without_extra_prompt(self):
        from unittest.mock import Mock
        window=self.ready_window()
        worker=Mock()
        with patch('isopropyl.native_app.QMessageBox.question') as question, patch('isopropyl.native_app.AccessJob',return_value=worker):
            window.enable_writing()
        question.assert_not_called();worker.start.assert_called_once()
        self.assertIsNone(window.job)
        window.access_job=None;window.close()

    def test_access_worker_cancel_recovers_controls(self):
        from unittest.mock import Mock
        window = self.ready_window()
        window.access_job = Mock()
        window.access_result = (False, 'Authorization cancelled. No write was started.')
        window.set_busy(True)
        with patch('isopropyl.native_app.QMessageBox.information'):
            window.access_finished()
        self.assertTrue(window.refresh_button.isEnabled())
        self.assertIn('cancelled', window.status.text())
        self.assertIsNone(window.job)
        window.close()

    def test_failed_relaunch_keeps_original_window_visible(self):
        from unittest.mock import Mock
        window = self.ready_window()
        window.show()
        window.access_job = Mock()
        window.access_result = (False, 'Replacement did not report successful startup')
        with patch('isopropyl.native_app.QMessageBox.information'):
            window.access_finished()
        self.assertTrue(window.isVisible())
        self.assertTrue(window.refresh_button.isEnabled())
        self.assertIsNone(window.job)
        window.close()

    def test_access_worker_startup_exception_is_reported_without_aborting(self):
        from isopropyl.native_app import AccessJob
        worker = AccessJob('', '', '', False, None)
        messages = []
        worker.result.connect(lambda ok, message: messages.append((ok, message)))
        with patch('isopropyl.native_app.request_write_access', side_effect=RuntimeError('startup failed')):
            worker.run()
        self.assertEqual(messages, [(False, 'startup failed')])

    def test_image_permission_error_does_not_request_more_administrator_access(self):
        from isopropyl.devices import Device
        from isopropyl.native_devices import NativeDevice
        target = NativeDevice(Device('/dev/disk8', 4096, 'Flash', '', 'usb', '123', '',
                                     'disk8', True, True, False, (), (), 512))
        window = self.ready_window(target)
        with patch('isopropyl.native_app.build_media_plan', side_effect=PermissionError('Cannot read image')), \
                patch.object(window, 'enable_writing') as enable, \
                patch('isopropyl.native_app.QMessageBox.critical') as error:
            window.start_write()
        enable.assert_not_called()
        error.assert_called_once()
        self.assertIsNone(window.job)
        window.close()

    @unittest.skipUnless(__import__('sys').platform == 'darwin', 'macOS Windows installer mode')
    def test_optical_windows_iso_uses_uefi_confirmation_without_requesting_access(self):
        import tempfile
        from pathlib import Path

        from isopropyl.devices import Device
        from isopropyl.native_devices import NativeDevice
        target = NativeDevice(Device('/dev/disk8', 1024**3, 'Flash', '', 'usb', '123', '',
                                     'disk8', True, True, False, (), (), 512))
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory)/'windows.iso'
            image.write_bytes(bytes(512))
            window = self.ready_window(target)
            window.image.setText(str(image))
            with patch('isopropyl.native_app.QMessageBox.warning',return_value=__import__('PyQt6.QtWidgets',fromlist=['QMessageBox']).QMessageBox.StandardButton.Cancel) as confirm, \
                    patch.object(window,'enable_writing') as enable:
                window.start_write()
            self.assertIn('FAT32 • UEFI',confirm.call_args.args[2])
            enable.assert_not_called()
            self.assertIsNone(window.job)
            window.close()

    def test_windows_installer_job_uses_windows_preparation_not_hdiutil(self):
        import tempfile
        from pathlib import Path

        from isopropyl.devices import Device
        from isopropyl.mac_windows_iso import build_windows_plan
        from isopropyl.native_devices import NativeDevice
        target = NativeDevice(Device(r'\\.\PhysicalDrive2',1024**3,'TEST','','usb','123','','2',
                                     True,True,False,(),(),512))
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'windows.iso';source.write_bytes(bytes(512))
            job=WriteJob(build_windows_plan(source,target),'ERASE '+target.device.path,None)
            messages=[];job.result.connect(lambda *args:messages.append(args))
            with patch('isopropyl.native_app.sys.platform','win32'), \
                    patch('isopropyl.windows_media.run_windows_iso',return_value='a'*64) as windows, \
                    patch('isopropyl.native_app.run_windows_iso') as mac:
                job.run()
            windows.assert_called_once()
            mac.assert_not_called()
            self.assertTrue(messages[0][0])

    def test_drive_tool_cancel_keeps_disk_untouched_and_yes_uses_bound_plan(self):
        from unittest.mock import Mock
        from PyQt6.QtWidgets import QMessageBox
        from isopropyl.devices import Device
        from isopropyl.native_devices import NativeDevice
        target=NativeDevice(Device('/dev/disk8',4096,'Flash','','usb','123','','disk8',True,True,False,(),(),512))
        window=self.ready_window(target)
        with patch.object(window,'needs_write_access',return_value=False), \
             patch('isopropyl.native_app.QMessageBox.warning',return_value=QMessageBox.StandardButton.Cancel), \
             patch('isopropyl.native_app.WriteJob') as job:
            window.start_tool('zero')
        job.assert_not_called()
        with patch.object(window,'needs_write_access',return_value=False), \
             patch('isopropyl.native_app.QMessageBox.warning',return_value=QMessageBox.StandardButton.Yes), \
             patch('isopropyl.native_app.WriteJob',return_value=Mock()) as job, \
             patch('isopropyl.native_test_options.TestOptionsDialog',return_value=Mock(exec=Mock(return_value=True),options=dict(passes=4,capacity_first=False))):
            window.start_tool('surface')
        self.assertEqual(job.call_args.args[1],job.call_args.args[0].confirmation)
        self.assertEqual(job.call_args.args[0].operation,'surface')
        self.assertFalse(window.tools_button.isEnabled())
        window.job=None;window.close()

    def test_compressed_write_worker_uses_preparation_before_disk_worker(self):
        import gzip,tempfile
        from pathlib import Path
        from unittest.mock import Mock
        from isopropyl.devices import Device
        from isopropyl.native_devices import NativeDevice
        from isopropyl.native_writer import build_plan
        target=NativeDevice(Device('/dev/disk8',4096,'Flash','','usb','123','','disk8',True,True,False,(),(),512))
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'disk.img.gz';source.write_bytes(gzip.compress(bytes(512)))
            plan=build_plan(source,target);job=WriteJob(plan,plan.confirmation,None)
            with patch('isopropyl.native_app.run_prepared_image',return_value='a'*64) as prepared, \
                 patch('isopropyl.native_app.run_macos_write') as raw:
                job.run()
            prepared.assert_called_once();raw.assert_not_called()
