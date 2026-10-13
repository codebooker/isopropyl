# SPDX-License-Identifier: AGPL-3.0-or-later
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from isopropyl import entrypoints
from isopropyl.host_platform import validate_host, x86_binutil


class PlatformTests(unittest.TestCase):
    def test_arm_linux_uses_x86_cross_tools_for_bios_code(self):
        for machine, prefix in [('aarch64', 'x86_64-linux-gnu-'), ('x86_64', '')]:
            with patch('isopropyl.host_platform.platform.machine', return_value=machine):
                self.assertEqual(x86_binutil('as').as_posix(), f'/usr/bin/{prefix}as')

    def test_exact_supported_matrix(self):
        for host, machine in [('linux', 'x86_64'), ('linux', 'aarch64'),
                              ('win32', 'AMD64'), ('win32', 'ARM64'), ('darwin', 'arm64')]:
            with self.subTest(host=host, machine=machine):
                self.assertIn(validate_host(host, machine, 64)[1], {'x86_64', 'arm64'})
        for host, machine, bits in [('darwin', 'x86_64', 64), ('linux', 'i686', 32),
                                    ('win32', 'ARM64', 32), ('freebsd', 'amd64', 64)]:
            with self.subTest(host=host, machine=machine):
                with self.assertRaisesRegex(RuntimeError, 'Unsupported host'):
                    validate_host(host, machine, bits)

    def test_dispatch_before_linux_imports(self):
        for host, module in [('linux', 'isopropyl.cli'), ('darwin', 'isopropyl.native_cli'),
                             ('win32', 'isopropyl.native_cli')]:
            main = unittest.mock.Mock(return_value=7)
            with patch.object(entrypoints, '_supported', return_value=True), \
                    patch.object(sys, 'platform', host), \
                    patch.dict(sys.modules, {module: SimpleNamespace(main=main)}):
                self.assertEqual(entrypoints.cli(), 7)
                main.assert_called_once_with()

    def test_unsupported_host_does_not_load_frontend(self):
        with patch.object(entrypoints, '_supported', return_value=False):
            self.assertEqual(entrypoints.gui(), 2)
            self.assertEqual(entrypoints.cli(), 2)
