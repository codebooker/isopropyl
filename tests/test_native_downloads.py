# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import io
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from isopropyl import verified_download as verified
from isopropyl.native_downloads import execute_windows_download


class Response(io.BytesIO):
    status=200
    def __init__(self,body,url,headers):
        super().__init__(body);self.url=url;self.headers=headers
    def geturl(self):return self.url


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name)
        self.body=b'Pinned image bytes'*128
        self.artifact=SimpleNamespace(id='image-v1',filename='image.iso',size=len(self.body),sha256=hashlib.sha256(self.body).hexdigest())
        self.url='https://official.example/image.iso'
        self.authorize=Mock(return_value=verified.ResolvedDownloadSource(self.url))
        self.cancelled=threading.Event()

    def run_download(self,opener=None,progress=None):
        return execute_windows_download(self.artifact,self.root/self.artifact.filename,self.authorize,progress,
            cancel_event=self.cancelled,cancel_check=None,overall_timeout=30,
            opener=opener or (lambda *args,**kwargs:Response(self.body,self.url,{'Content-Length':str(len(self.body))})),
            policy=verified.DEFAULT_ERROR_POLICY)

    def test_complete_verified_image_is_published_and_workspace_removed(self):
        result=self.run_download()
        self.assertEqual(result.path.read_bytes(),self.body)
        self.assertEqual([path.resolve() for path in self.root.iterdir()],[result.path])
        self.authorize.assert_called_once()

    def test_cancel_keeps_only_partial_then_safely_resumes(self):
        def progress(*args):self.cancelled.set()
        with self.assertRaises(verified.VerifiedDownloadCancelled):self.run_download(progress=progress)
        self.assertFalse((self.root/'image.iso').exists())
        self.cancelled.clear()
        self.assertEqual(self.run_download().path.read_bytes(),self.body)

    def test_existing_destination_and_redirect_never_publish(self):
        output=self.root/'image.iso';output.write_bytes(b'keep')
        with self.assertRaises(verified.VerifiedDownloadError):self.run_download()
        self.assertEqual(output.read_bytes(),b'keep');output.unlink()
        with self.assertRaises(verified.VerifiedDownloadError):
            self.run_download(opener=lambda *args,**kwargs:Response(self.body,'https://other.example/image',{'Content-Length':str(len(self.body))}))
        self.assertFalse(output.exists())

    def test_corrupted_download_and_partial_replacement_are_rejected(self):
        with self.assertRaises(verified.VerifiedDownloadError):
            self.run_download(opener=lambda *args,**kwargs:Response(b'X'*len(self.body),self.url,{'Content-Length':str(len(self.body))}))
        self.assertFalse((self.root/'image.iso').exists())
        partial=next(self.root.iterdir())/'partial';partial.unlink(missing_ok=True);partial.symlink_to(self.root/'outside')
        with self.assertRaises(verified.VerifiedDownloadError):self.run_download()

    def test_bad_checksum_does_not_poison_the_next_download_attempt(self):
        with self.assertRaises(verified.VerifiedDownloadError):
            self.run_download(opener=lambda *args,**kwargs:Response(b'X'*len(self.body),self.url,{'Content-Length':str(len(self.body))}))
        self.assertEqual(self.run_download().path.read_bytes(),self.body)

    def test_exact_range_resume_rehashes_preexisting_bytes(self):
        stage=self.root/verified.resume_stage_name(self.artifact);stage.mkdir(mode=0o700)
        count=512;(stage/'partial').write_bytes(self.body[:count])
        def opener(request,**kwargs):
            self.assertEqual(request.get_header('Range'),f'bytes={count}-')
            response=Response(self.body[count:],self.url,{'Content-Length':str(len(self.body)-count),'Content-Range':f'bytes {count}-{len(self.body)-1}/{len(self.body)}'})
            response.status=206
            return response
        self.assertEqual(self.run_download(opener=opener).path.read_bytes(),self.body)

    def test_native_freedos_extracts_only_reviewed_image_and_checks_structure(self):
        from tests.test_freedos_downloads import fixture_release,opener_for
        from isopropyl.native_downloads import download_freedos
        release,archive=fixture_release()
        result=download_freedos(release,self.root/release.image_filename,None,
            cancel_event=self.cancelled,cancel_check=None,overall_timeout=30,
            opener=opener_for(release,archive,[]))
        self.assertEqual(hashlib.sha256(result.path.read_bytes()).hexdigest(),release.image_sha256)
        self.assertEqual([p.name for p in self.root.iterdir()],[release.image_filename])

    def test_freedos_completed_archive_survives_cancel_and_is_reused(self):
        from tests.test_freedos_downloads import fixture_release,opener_for
        from isopropyl.native_downloads import download_freedos
        from isopropyl.freedos_downloads import _private_stage_name
        release,archive=fixture_release();calls=[]
        def progress(done,total):
            if done>release.archive_size:self.cancelled.set()
        with self.assertRaises(verified.VerifiedDownloadCancelled):
            download_freedos(release,self.root/release.image_filename,progress,
                cancel_event=self.cancelled,cancel_check=None,overall_timeout=30,
                opener=opener_for(release,archive,calls))
        stage=self.root/_private_stage_name(release)
        self.assertEqual((stage/release.archive_filename).read_bytes(),archive)
        self.assertFalse((self.root/release.image_filename).exists())
        self.cancelled.clear()
        def no_network(*args,**kwargs):raise AssertionError('Verified cached archive should be reused')
        result=download_freedos(release,self.root/release.image_filename,None,
            cancel_event=self.cancelled,cancel_check=None,overall_timeout=30,opener=no_network)
        self.assertEqual(hashlib.sha256(result.path.read_bytes()).hexdigest(),release.image_sha256)
        self.assertFalse(stage.exists())

    def test_signature_fingerprint_is_required_even_when_tool_exits_successfully(self):
        from unittest.mock import patch
        from isopropyl.native_downloads import verify_native_manifest
        result=SimpleNamespace(stdout=b'[GNUPG:] VALIDSIG WRONG 1 2 3\n')
        with patch.object(Path,'is_file',return_value=True), \
             patch('isopropyl.native_downloads.path_file_identity',return_value=(1,2,3,4,5)), \
             patch('isopropyl.native_virtual.run_native_command',return_value=result):
            with self.assertRaisesRegex(verified.VerifiedDownloadError,'pinned key'):
                import time
                verify_native_manifest(b'manifest',b'signature',b'key','EXPECTED',time.monotonic()+30,
                    self.cancelled,None,verified.DEFAULT_ERROR_POLICY)
