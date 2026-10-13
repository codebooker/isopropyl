# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from isopropyl.helper_tools import helper
from isopropyl.native_writer import NativeWriteError

class HelperIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);(self.root/'data').mkdir()
        self.directory=self.root/'helpers/windows-arm64';self.directory.mkdir(parents=True)
        (self.directory/'tool.exe').write_bytes(b'helper executable')
        (self.directory/'dependency.dll').write_bytes(b'helper dependency')
        self.provenance={'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.directory.iterdir()}}
        self.write()
        self.addCleanup(mock.patch.stopall)
        mock.patch('isopropyl.helper_tools.files',return_value=self.root).start()
        mock.patch('isopropyl.helper_tools.validate_host',return_value=('win32','arm64')).start()
    def write(self):
        (self.directory/'PROVENANCE.json').write_text(json.dumps(self.provenance))
        (self.root/'data/native-tools-v1.json').write_text(json.dumps({'version':1,'platforms':{'windows-arm64':{'test-tool':{'file':'tool.exe','sha256':self.provenance['files']['tool.exe']}}}}))
    def test_resolves_integrity_checked_platform_bundle(self):
        self.assertEqual(helper('test-tool'),str(self.directory/'tool.exe'))
    def test_rejects_modified_dependency_before_executing_helper(self):
        (self.directory/'dependency.dll').write_bytes(b'changed')
        with self.assertRaisesRegex(NativeWriteError,'integrity'):helper('test-tool')
    def test_rejects_missing_dependency(self):
        (self.directory/'dependency.dll').unlink()
        with self.assertRaisesRegex(NativeWriteError,'integrity'):helper('test-tool')
    def test_rejects_malformed_manifest(self):
        (self.root/'data/native-tools-v1.json').write_text('null')
        with self.assertRaisesRegex(NativeWriteError,'integrity'):helper('test-tool')
    def test_rejects_dependency_escape(self):
        self.provenance['files']['../../other.dll']='0'*64;self.write()
        with self.assertRaisesRegex(NativeWriteError,'integrity'):helper('test-tool')

class HelperBundlePublicationTests(unittest.TestCase):
    def test_failed_import_preserves_existing_runtime_bundle(self):
        from tools.bundle_native_helpers import bundle
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);existing=root/'isopropyl/helpers/windows-arm64';existing.mkdir(parents=True)
            (existing/'known-good.exe').write_bytes(b'previous complete bundle')
            (root/'isopropyl/data').mkdir()
            manifest=root/'isopropyl/data/native-tools-v1.json';manifest.write_text('{"version":1,"platforms":{}}')
            invalid=root/'invalid.exe';invalid.write_bytes(b'not a Windows executable')
            spec={'platform':'windows-arm64','tools':{'test':str(invalid)},'licenses':{},'sources':{}}
            with self.assertRaisesRegex(ValueError,'not PE'):bundle(spec,root)
            self.assertEqual((existing/'known-good.exe').read_bytes(),b'previous complete bundle')
            self.assertEqual(manifest.read_text(),'{"version":1,"platforms":{}}')
            self.assertFalse(any(p.name.startswith('.helper-stage') for p in existing.parent.iterdir()))
