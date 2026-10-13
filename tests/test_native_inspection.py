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
        # Change size too so this generic mutation guard does not rely on the
        # filesystem's timestamp tick on a fast Windows runner.
        def progress(*args):self.path.write_bytes(b'B'*4096)
        with self.assertRaisesRegex(NativeWriteError,'changed'):inspect_source(self.path,self.writer,progress)
        self.writer.cancel()
        with self.assertRaises(NativeCancelled):inspect_source(self.path,self.writer)

    def test_mutation_between_checksum_and_catalog_is_normalized(self):
        def progress(stage,*args):
            if stage=='Inspecting boot records, filesystems and signatures':self.path.write_bytes(b'B'*4096)
        with self.assertRaisesRegex(NativeWriteError,'changed'):inspect_source(self.path,self.writer,progress)
        self.writer.opener.assert_not_called()

    def test_disappearance_between_checksum_and_catalog_is_normalized(self):
        import gzip
        for suffix in ('.img','.img.gz'):
            with self.subTest(suffix=suffix):
                path=self.path.with_suffix(suffix)
                path.write_bytes(gzip.compress(b'A'*2048) if suffix.endswith('.gz') else b'A'*2048)
                def progress(stage,done,total):
                    if stage=='Inspecting boot records, filesystems and signatures' and done==0:path.unlink()
                with self.assertRaisesRegex(NativeWriteError,'changed'):inspect_source(path,self.writer,progress)
                self.writer.opener.assert_not_called()

    def test_mutation_after_catalog_does_not_publish_stale_checksums(self):
        def progress(stage,done,total):
            if stage=='Inspecting boot records, filesystems and signatures' and done==total:self.path.write_bytes(b'B'*4096)
        with self.assertRaisesRegex(NativeWriteError,'changed'):inspect_source(self.path,self.writer,progress)
        self.writer.opener.assert_not_called()
