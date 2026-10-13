# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from isopropyl.native_inspection import inspect_source
from isopropyl.native_writer import NativeCancelled,NativeWriteError,NativeWriter


class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.path=Path(self.directory.name)/'image.img';self.path.write_bytes(b'A'*2048)
        self.writer=NativeWriter(opener=Mock(side_effect=AssertionError('No disk access in inspection')))

    def test_all_checksums_identify_source_without_disk_access(self):
        details=inspect_source(self.path,self.writer)
        self.assertIn(hashlib.sha256(self.path.read_bytes()).hexdigest(),details)
        self.assertIn('SHA-512:',details);self.assertIn('MD5:',details)
        self.assertIn('Partition map:',details)
        self.writer.opener.assert_not_called()

    def test_changed_source_and_cancellation_do_not_publish_result(self):
        def progress(*args):self.path.write_bytes(b'B'*2048)
        with self.assertRaisesRegex(NativeWriteError,'changed'):inspect_source(self.path,self.writer,progress)
        self.writer.cancel()
        with self.assertRaises(NativeCancelled):inspect_source(self.path,self.writer)
