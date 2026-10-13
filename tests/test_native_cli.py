# SPDX-License-Identifier: AGPL-3.0-or-later
import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from isopropyl.devices import Device
from isopropyl.native_cli import main
from isopropyl.native_devices import NativeDevice


class CliTests(unittest.TestCase):
    def setUp(self):
        self.target = NativeDevice(Device('/dev/disk2', 4096, 'Flash', '', 'usb',
            '123', '', 'disk2', True, True, False, (), (), 512))
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name)/'image.img'
        self.source.write_bytes(b'A'*2048)

    def test_native_cli_import_does_not_load_qt_or_linux_helpers(self):
        result = subprocess.run([sys.executable, '-c',
            "import sys; import isopropyl.native_cli; assert 'PyQt6' not in sys.modules; assert 'isopropyl.raw_workflow' not in sys.modules; assert 'isopropyl.raw_snapshot' not in sys.modules"],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_list_requires_no_privilege_check(self):
        writer = Mock()
        with patch('isopropyl.native_cli.NativeWriter', return_value=writer), \
                patch('isopropyl.native_cli.discover', return_value=[self.target]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(['list']), 0)
        self.assertIn('/dev/disk2', output.getvalue())
        writer.privilege_check.assert_not_called()
        writer.run.assert_not_called()

    def test_unlisted_target_fails_before_confirmation(self):
        writer = Mock(write_started=False)
        with patch('isopropyl.native_cli.NativeWriter', return_value=writer), \
                patch('isopropyl.native_cli.discover', return_value=[self.target]), \
                patch('builtins.input') as confirmation, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['write', str(self.source), '--target', '/dev/disk0']), 4)
        confirmation.assert_not_called()
        writer.run.assert_not_called()

    def test_noninteractive_write_fails_closed(self):
        writer = Mock(write_started=False)
        with patch('isopropyl.native_cli.NativeWriter', return_value=writer), \
                patch('isopropyl.native_cli.discover', return_value=[self.target]), \
                patch('sys.stdin.isatty', return_value=False), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['write', str(self.source), '--target', '/dev/disk2']), 4)
        writer.run.assert_not_called()

    def test_write_passes_exact_confirmation_and_expected_hash(self):
        writer = Mock(write_started=False)
        writer.run.return_value = 'a'*64
        with patch('isopropyl.native_cli.NativeWriter', return_value=writer), \
                patch('isopropyl.native_cli.discover', return_value=[self.target]), \
                patch('sys.stdin.isatty', return_value=True), \
                patch('builtins.input', return_value='yes'), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(['write', str(self.source), '--target', '/dev/disk2', '--sha256', 'A'*64]), 0)
        self.assertEqual(writer.run.call_args.args[1], 'ERASE /dev/disk2')
        self.assertEqual(writer.run.call_args.args[0].expected_sha256, 'a'*64)
        self.assertIn('Write verified', output.getvalue())

    def test_permission_failure_never_prompts_or_runs(self):
        writer = Mock(write_started=False)
        writer.privilege_check.side_effect = PermissionError('requires elevation')
        with patch('isopropyl.native_cli.NativeWriter', return_value=writer), \
                patch('isopropyl.native_cli.discover', return_value=[self.target]), \
                patch('builtins.input') as confirmation, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['write', str(self.source), '--target', '/dev/disk2']), 4)
        confirmation.assert_not_called()
        writer.run.assert_not_called()
