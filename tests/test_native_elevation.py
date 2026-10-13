# SPDX-License-Identifier: AGPL-3.0-or-later
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from isopropyl.native_elevation import (
    MAC_AUTH_SCRIPT,
    MAC_DETACHED_LAUNCHER,
    mac_launch_command,
    process_alive,
    report_gui_ready,
    request_write_access,
    wait_for_ready,
)


class ElevationTests(unittest.TestCase):
    def test_windows_process_check_queries_without_sending_a_signal(self):
        kernel = Mock()
        kernel.OpenProcess.return_value = 1 << 40
        def query(handle, output):
            output._obj.value = 259
            return 1
        kernel.GetExitCodeProcess.side_effect = query
        with patch('isopropyl.native_elevation.sys.platform', 'win32'), \
                patch('ctypes.WinDLL', return_value=kernel, create=True), \
                patch('isopropyl.native_elevation.os.kill') as signal:
            self.assertTrue(process_alive(123))
        signal.assert_not_called()
        kernel.OpenProcess.assert_called_once_with(0x1000, False, 123)
        kernel.CloseHandle.assert_called_once_with(1 << 40)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS AppleScript launcher regression')
    def test_detached_launch_from_real_nonterminal_apple_script(self):
        probe = Path(self.directory.name)/'probe.txt'
        arguments = [sys.executable, '-I', '-c',
                     "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('ready')", str(probe)]
        command = mac_launch_command(arguments, self.log)
        result = subprocess.run(['/usr/bin/osascript', '-e',
            'on run argv\n do shell script (item 1 of argv)\nend run', command],
            check=True, capture_output=True, text=True, timeout=15)
        self.assertTrue(result.stdout.strip().isdigit())
        deadline = time.monotonic() + 5
        while not probe.exists() and time.monotonic() < deadline:
            time.sleep(.05)
        self.assertEqual(probe.read_text(), 'ready')

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.log = Path(self.directory.name)/'launch.log'
        self.log.write_text('startup diagnostic')
        self.path_patch = patch('isopropyl.native_elevation.launch_log_path', return_value=self.log)
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)

    def test_mac_auth_uses_fixed_script_and_quotes_every_argument(self):
        image = "/Images/My image's $(touch forbidden).iso"
        with patch('isopropyl.native_elevation.subprocess.run', return_value=
                   subprocess.CompletedProcess([], 0, '', '')) as run, \
                patch('isopropyl.native_elevation.wait_for_ready') as wait:
            request_write_access(image, 'a'*64, '/dev/disk8', True, host='darwin')
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ['/usr/bin/osascript', '-e', MAC_AUTH_SCRIPT])
        command = argv[3]
        arguments = shlex.split(command)
        self.assertEqual(arguments[3], MAC_DETACHED_LAUNCHER)
        self.assertNotIn('/usr/bin/nohup', arguments)
        self.assertEqual(arguments[arguments.index('--image')+1], image)
        self.assertEqual(arguments[arguments.index('--target')+1], '/dev/disk8')
        self.assertIn('--startup-report', arguments)
        self.assertFalse(run.call_args.kwargs['shell'])
        self.assertNotIn(' write ', command)
        wait.assert_called_once()

    def test_cancelled_authorization_reports_no_write(self):
        with patch('isopropyl.native_elevation.subprocess.run', return_value=
                   subprocess.CompletedProcess([], 1, '', 'User canceled. (-128)')):
            with self.assertRaisesRegex(PermissionError, 'cancelled.*No write'):
                request_write_access(host='darwin')

    def test_failed_authorization_is_reported(self):
        with patch('isopropyl.native_elevation.subprocess.run', return_value=
                   subprocess.CompletedProcess([], 1, '', 'Not authorized')):
            with self.assertRaisesRegex(PermissionError, 'Not authorized'):
                request_write_access(host='darwin')

    def test_unsupported_host_never_runs_auth_command(self):
        with patch('isopropyl.native_elevation.subprocess.run') as run:
            with self.assertRaises(ValueError):
                request_write_access(host='linux')
            run.assert_not_called()

    def test_successful_launcher_without_ready_window_is_failure(self):
        with patch('isopropyl.native_elevation.subprocess.run', return_value=
                   subprocess.CompletedProcess([], 0, '', '')), \
                patch('isopropyl.native_elevation.wait_for_ready', side_effect=RuntimeError('replacement failed')):
            with self.assertRaisesRegex(RuntimeError, 'replacement failed'):
                request_write_access(host='darwin')

    def test_startup_failure_keeps_log_and_reports_error(self):
        report = Path(self.directory.name)/'absent.json'
        with self.assertRaisesRegex(RuntimeError, 'startup diagnostic'):
            wait_for_ready(report, self.log, timeout=0)
        self.assertTrue(self.log.exists())

    def test_unprivileged_replacement_is_not_accepted(self):
        report = Path(self.directory.name)/'ready.json'
        report.write_text(json.dumps({'state':'ready', 'elevated':False, 'pid':os.getpid()}))
        with self.assertRaisesRegex(PermissionError, 'without administrator access'):
            wait_for_ready(report, self.log, timeout=1)

    def test_report_is_exclusive_and_readable_by_desktop_owner(self):
        report = Path(self.directory.name)/'ready.json'
        with patch('isopropyl.native_disk_io.require_privileges'):
            report_gui_ready(str(report))
        self.assertTrue(json.loads(report.read_text())['elevated'])
        if os.name == 'posix':
            self.assertEqual(report.stat().st_mode & 0o777, 0o644)
        with self.assertRaises(FileExistsError):
            report_gui_ready(str(report))
        wait_for_ready(report, self.log, timeout=1)

    def test_dead_replacement_cannot_close_original_window(self):
        report = Path(self.directory.name)/'ready.json'
        report.write_text(json.dumps({'state':'ready', 'elevated':True, 'pid':12345}))
        with patch('isopropyl.native_elevation.os.kill', side_effect=ProcessLookupError()):
            with self.assertRaisesRegex(RuntimeError, 'current window has been kept open'):
                wait_for_ready(report, self.log, timeout=1)
