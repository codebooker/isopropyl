# SPDX-License-Identifier: AGPL-3.0-or-later
import bz2
import gzip
import hashlib
import io
import lzma
import os
import tempfile
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from isopropyl.devices import Device
from isopropyl.native_devices import NativeDevice
from isopropyl.native_inputs import PreparedImagePlan, prepare_image
from isopropyl.native_writer import NativeWriteError, NativeWriter, build_plan
from isopropyl.portable_io import pread


class InputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.target = NativeDevice(Device('/dev/disk2',4096,'Flash','','usb','SERIAL','','disk2',True,True,False,(),(),512))
        self.disk = io.BytesIO(bytes(4096)); self.opened = 0
        @contextmanager
        def opener(*args):
            self.opened += 1
            yield self.disk
        self.writer = NativeWriter(host='win32', discovery=lambda *args,**kwargs:[self.target],
                                   opener=opener, privilege_check=lambda host:None)
        self.data = b'A'*2048

    def source(self, suffix, data):
        path = self.root/('test.img'+suffix); path.write_bytes(data)
        return path

    def test_gzip_bzip_xz_and_zip_write_expanded_bytes(self):
        for suffix, compress in [('.gz',gzip.compress),('.bz2',bz2.compress),('.xz',lzma.compress)]:
            with self.subTest(suffix=suffix):
                path=self.source(suffix,compress(self.data))
                plan=build_plan(path,self.target)
                self.assertIsInstance(plan,PreparedImagePlan)
                workspace=self.root/suffix[1:];workspace.mkdir()
                decoded=prepare_image(plan,workspace,self.writer,lambda *args:None)
                self.assertEqual(decoded.source.read_bytes(),self.data)
        archive=self.root/'test.zip'
        with zipfile.ZipFile(archive,'w') as output:output.writestr('image.img',self.data)
        workspace=self.root/'zip';workspace.mkdir()
        decoded=prepare_image(build_plan(archive,self.target),workspace,self.writer,lambda *args:None)
        self.assertEqual(decoded.source.read_bytes(),self.data)
        self.assertEqual(self.opened,0)

    def test_container_checksum_is_checked_and_raw_readback_hash_returned(self):
        path=self.source('.gz',gzip.compress(self.data))
        plan=build_plan(path,self.target,expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(self.writer.run(plan,plan.confirmation),hashlib.sha256(self.data).hexdigest())
        self.assertEqual(self.disk.getvalue(),self.data+bytes(2048))

    def test_too_large_expansion_and_bad_checksum_never_open_disk(self):
        for data, checksum in [(gzip.compress(bytes(8192)),None),(gzip.compress(self.data),'0'*64)]:
            path=self.source('.gz',data);plan=build_plan(path,self.target,expected_sha256=checksum)
            with self.assertRaises(NativeWriteError):self.writer.run(plan,plan.confirmation)
        self.assertEqual(self.opened,0)

    def test_source_replacement_after_confirmation_never_opens_disk(self):
        path=self.source('.gz',gzip.compress(self.data));plan=build_plan(path,self.target)
        path.write_bytes(gzip.compress(b'B'*2048))
        with self.assertRaisesRegex(NativeWriteError,'changed'):self.writer.run(plan,plan.confirmation)
        self.assertEqual(self.opened,0)

    def test_zip_ambiguity_and_optical_iso_are_rejected_before_disk_access(self):
        for names in [('a.img','b.img'),('optical.iso',)]:
            archive=self.root/'images.zip'
            with zipfile.ZipFile(archive,'w') as output:
                for name in names:output.writestr(name,bytes(2048))
            plan=build_plan(archive,self.target)
            with self.assertRaises(RuntimeError):self.writer.run(plan,plan.confirmation)
        self.assertEqual(self.opened,0)

    def test_windows_positioned_read_preserves_offset_and_compressed_decoding(self):
        path=self.source('.gz',gzip.compress(self.data))
        with path.open('rb',buffering=0) as stream:
            stream.seek(2)
            with patch('isopropyl.portable_io.os.pread',None,create=True):
                self.assertEqual(pread(stream.fileno(),2,0),b'\x1f\x8b')
            self.assertEqual(stream.tell(),2)
        work=self.root/'fallback';work.mkdir()
        with patch('isopropyl.portable_io.os.pread',None,create=True):
            decoded=prepare_image(build_plan(path,self.target),work,self.writer,lambda *args:None)
        self.assertEqual(decoded.source.read_bytes(),self.data)

    def test_zstandard_uses_in_process_decoder_without_external_commands(self):
        try:
            import zstandard
        except ImportError:
            self.skipTest('optional zstandard runtime')
        path=self.source('.zst',zstandard.ZstdCompressor().compress(self.data))
        workspace=self.root/'zstd';workspace.mkdir()
        decoded=prepare_image(build_plan(path,self.target),workspace,self.writer,lambda *args:None)
        self.assertEqual(decoded.source.read_bytes(),self.data)
