# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from isopropyl.devices import Device
from isopropyl.mac_worker import execute, load_request
from isopropyl.mac_write import authorize_request, run_macos_write
from isopropyl.native_devices import NativeDevice
from isopropyl.native_writer import NativeWriteError, NativeWriter, build_plan


@unittest.skipUnless(os.name == 'posix', 'macOS worker validates POSIX permissions')
class MacWorkerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.parent = Path(self.directory.name)
        self.source = self.parent/'source.img'
        self.source.write_bytes(bytes(512))
        self.source.chmod(0o600)
        self.request = self.parent/'request.json'
        self.request.write_text(json.dumps({'version':1, 'operation':'probe', 'source_name':'source.img'}))
        self.request.chmod(0o600)

    def test_probe_never_discovers_or_opens_a_device(self):
        with patch('isopropyl.host_platform.validate_host'), patch('isopropyl.mac_worker.discover') as discovery:
            result = execute(self.request)
        self.assertTrue(result['ok'])
        self.assertFalse(result['write_started'])
        discovery.assert_not_called()

    def test_request_cannot_reference_original_or_arbitrary_user_paths(self):
        for name in ['/Users/user/Downloads/image.img', '../image.img', 'request.json']:
            self.request.write_text(json.dumps({'version':1,'operation':'probe','source_name':name}))
            with self.assertRaises(ValueError):
                load_request(self.request)

    def test_shared_writable_directory_is_rejected(self):
        self.parent.chmod(0o777)
        with self.assertRaises(ValueError):
            load_request(self.request)

    def test_worker_is_direct_child_and_never_uses_elevated_shell(self):
        process = Mock(returncode=0)
        process.communicate.return_value = (json.dumps({'ok':True, 'write_started':False}), '')
        with patch('isopropyl.mac_write.worker_python', return_value='/runtime/bin/python'), \
                patch('isopropyl.mac_write.subprocess.Popen', return_value=process) as launch:
            result = authorize_request(self.request)
        self.assertTrue(result['ok'])
        self.assertEqual(launch.call_args.args[0], ['/runtime/bin/python', '-I', '-m',
                        'isopropyl.mac_worker', '--request', str(self.request)])
        self.assertFalse(launch.call_args.kwargs['shell'])

    def test_changed_target_fails_without_entering_writer(self):
        self.request.write_text(json.dumps({'version':1,'operation':'write','source_name':'source.img',
                                           'target_identity':['wrong'], 'sha256':'0'*64}))
        with patch('isopropyl.host_platform.validate_host'), patch('isopropyl.mac_worker.discover', return_value=[]), \
                patch('isopropyl.mac_worker.NativeWriter') as writer:
            result = execute(self.request)
        self.assertFalse(result['ok'])
        writer.return_value.run.assert_not_called()

    def test_worker_rejects_untyped_verification_choice(self):
        payload={'version':1,'operation':'probe','source_name':'source.img','final_verification':'yes'}
        self.request.write_text(json.dumps(payload))
        with self.assertRaisesRegex(ValueError,'final-verification'):
            load_request(self.request)


class MacStagingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)/'test.img'
        self.content = b'A'*2048
        self.path.write_bytes(self.content)
        self.target = NativeDevice(Device('/dev/disk2', 4096, 'Flash', '', 'usb', '123', '',
                                         'disk2', True, True, False, (), (), 512))
        self.writer = NativeWriter(host='darwin')
        self.plan = build_plan(self.path, self.target)
    def test_desktop_source_is_staged_before_authorization(self):
        def authorize(request, **kwargs):
            payload = json.loads(request.read_text())
            staged = request.parent/payload['source_name']
            self.assertEqual(staged.read_bytes(), self.content)
            self.assertNotIn(str(self.path), request.read_text())
            self.assertEqual(payload['confirmation'], self.plan.confirmation)
            return {'ok':True,'write_started':True,'sha256':payload['sha256']}
        with patch('isopropyl.mac_write.authorize_request', side_effect=authorize):
            checksum = run_macos_write(self.plan, self.plan.confirmation, self.writer)
        self.assertEqual(checksum, hashlib.sha256(self.content).hexdigest())

    def test_bad_source_hash_never_requests_authorization(self):
        plan = build_plan(self.path, self.target, expected_sha256='0'*64)
        with patch('isopropyl.mac_write.authorize_request') as authorize:
            with self.assertRaises(NativeWriteError):
                run_macos_write(plan, plan.confirmation, self.writer)
        authorize.assert_not_called()

    def test_prepared_private_image_is_moved_without_copying(self):
        self.path.chmod(0o600)
        self.plan=build_plan(self.path,self.target)
        inode=self.path.stat().st_ino
        def authorize(request,**kwargs):
            payload=json.loads(request.read_text());staged=request.parent/payload['source_name']
            self.assertEqual(staged.stat().st_ino,inode)
            self.assertEqual(staged.read_bytes(),self.content)
            self.assertFalse(self.path.exists())
            return {'ok':True,'write_started':True,'sha256':payload['sha256']}
        with patch('isopropyl.mac_write.authorize_request',side_effect=authorize):
            result=run_macos_write(self.plan,self.plan.confirmation,self.writer,prepared_private=True)
        self.assertEqual(result,hashlib.sha256(self.content).hexdigest())

    def test_final_verification_preference_is_sent_to_worker(self):
        self.writer.final_verification=True
        def authorize(request,**kwargs):
            payload=json.loads(request.read_text());self.assertIs(payload['final_verification'],True)
            return {'ok':True,'write_started':True,'sha256':payload['sha256']}
        with patch('isopropyl.mac_write.authorize_request',side_effect=authorize):
            run_macos_write(self.plan,self.plan.confirmation,self.writer)
