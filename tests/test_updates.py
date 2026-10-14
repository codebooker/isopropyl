# SPDX-License-Identifier: AGPL-3.0-or-later
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

from isopropyl import updates as u


class Response(io.BytesIO):
    def __init__(self, data, url, headers=None):
        super().__init__(data); self.url=url; self.headers=headers or {}
    def geturl(self): return self.url
    def getcode(self): return 200


def fixture():
    data=b'verified update bytes'
    entry={'os':'windows','arch':'arm64','kind':'portable-zip','name':'ISOpropyl-arm64.zip',
           'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    row={'name':entry['name'],'size':entry['size'],'digest':'sha256:'+entry['sha256'],
         'browser_download_url':u.REPOSITORY+'/releases/download/v0.2.0/'+entry['name']}
    payload={'tag_name':'v0.2.0','draft':False,'prerelease':False,'name':'Release 0.2',
             'body':'Plain text notes','html_url':u.REPOSITORY+'/releases/tag/v0.2.0','assets':[row]}
    manifest={'schema':1,'version':'0.2.0','assets':[entry]}
    return data,payload,manifest


class UpdateTests(unittest.TestCase):
    def parse(self,payload,manifest,**kwargs):
        return u.parse_release(payload,manifest,version='0.1.0',host='windows',arch='arm64',kind='portable-zip',**kwargs)

    def test_selects_newer_exact_platform(self):
        _,p,m=fixture(); release=self.parse(p,m)
        self.assertEqual(release.version,'0.2.0');self.assertEqual(release.asset.arch,'arm64')
        self.assertEqual(release.notes,'Plain text notes')

    def test_no_downgrade_or_reinstall(self):
        _,p,m=fixture()
        for version in ('0.2.0','1.0.0'):
            self.assertIsNone(u.parse_release(p,m,version=version))

    def test_stable_semver_only(self):
        for tag in ('v1.0.0rc1','v1.0.0-beta','v01.2.3','v1.2','v1.2.3+build','v1.2.3/evil'):
            _,p,m=fixture();p['tag_name']=tag
            with self.subTest(tag=tag),self.assertRaises(u.UpdateError):self.parse(p,m)

    def test_prerelease_and_draft_ignored(self):
        for field in ('prerelease','draft'):
            _,p,m=fixture();p[field]=True;self.assertIsNone(self.parse(p,m))

    def test_manifest_authority_failures(self):
        changes=[lambda p,m:m.update(version='0.3.0'),lambda p,m:m.update(schema=True),
                 lambda p,m:m['assets'][0].update(sha256=''),
                 lambda p,m:m['assets'][0].update(size=True),
                 lambda p,m:p['assets'][0].update(digest='sha256:'+'0'*64),
                 lambda p,m:p['assets'][0].update(browser_download_url='https://evil.example/file.zip'),
                 lambda p,m:m['assets'].append(copy.deepcopy(m['assets'][0])),
                 lambda p,m:m['assets'][0].update(name='../evil.zip')]
        for index,change in enumerate(changes):
            _,p,m=fixture();change(p,m)
            with self.subTest(index=index),self.assertRaises(u.UpdateError):self.parse(p,m)

    def test_missing_platform_rejected(self):
        _,p,m=fixture()
        with self.assertRaises(u.UpdateError):u.parse_release(p,m,version='0.1.0',host='linux',arch='arm64',kind='deb')

    def test_current_version_available(self):
        self.assertIsInstance(u.current_version(),str)

    def test_redirect_hosts_and_credentials(self):
        for url in ('http://github.com/file','https://github.com.evil/file','https://user@github.com/file',
                    'https://github.com:8443/file','file:///tmp/update','https://github.com/file#fragment'):
            with self.subTest(url=url),self.assertRaises(u.UpdateError):u._https(url)
        u._https('https://release-assets.githubusercontent.com/asset?token=value')

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(u.UpdateError):u._json(b'{"schema":1,"schema":2}')

    def test_discovery_checks_manifest_and_api_digest(self):
        _,p,m=fixture(); manifest=json.dumps(m).encode()
        p['assets'].append({'name':u.MANIFEST_NAME,'size':len(manifest),'digest':'sha256:'+hashlib.sha256(manifest).hexdigest(),
                            'browser_download_url':u.REPOSITORY+'/releases/download/v0.2.0/'+u.MANIFEST_NAME})
        def opener(req,**kwargs):
            return Response(json.dumps(p).encode() if req.full_url==u.LATEST_URL else manifest,req.full_url)
        release=u.check_for_update(version='0.1.0',host='win32',arch='aarch64',opener=opener)
        self.assertEqual(release.asset.name,'ISOpropyl-arm64.zip')

    def test_404_means_no_release(self):
        def opener(req,**kwargs):raise urllib.error.HTTPError(req.full_url,404,'none',{},None)
        self.assertIsNone(u.check_for_update(opener=opener))

    def test_metadata_bounded(self):
        def opener(req,**kwargs):return Response(b'x'*(u.MAX_METADATA_SIZE+1),req.full_url)
        with self.assertRaises(u.UpdateError):u.check_for_update(opener=opener)

    def test_download_verifies_private_staged_bytes(self):
        data,p,m=fixture();release=self.parse(p,m);progress=[]
        with tempfile.TemporaryDirectory() as root:
            path=u.download_update(release,root,lambda done,total:progress.append((done,total)),
                opener=lambda req,**kw:Response(data,req.full_url,{'Content-Length':str(len(data))}))
            self.assertEqual(path.read_bytes(),data);self.assertEqual(progress[-1],(len(data),len(data)))
            self.assertEqual(path.parent.parent,Path(root).resolve())

    def test_corrupt_truncated_oversize_and_cancel_cleanup(self):
        data,p,m=fixture();release=self.parse(p,m)
        for value,cancel in ((b'wrong',None),(data[:-1],None),(data+b'x',None),(data,lambda:True)):
            with self.subTest(value=value,cancel=bool(cancel)),tempfile.TemporaryDirectory() as root:
                with self.assertRaises(u.UpdateError):
                    u.download_update(release,root,cancel_check=cancel,opener=lambda req,**kw:Response(value,req.full_url))
                self.assertEqual(list(Path(root).iterdir()),[])

    def test_postdownload_readback_detects_mutation(self):
        data,p,m=fixture();release=self.parse(p,m)
        with tempfile.TemporaryDirectory() as root:
            def progress(done,total):
                path=next(Path(root).glob('*/*'))
                with path.open('r+b') as stream:stream.write(b'X')
            with self.assertRaises(u.UpdateError):u.download_update(release,root,progress,opener=lambda req,**kw:Response(data,req.full_url))
            self.assertEqual(list(Path(root).iterdir()),[])


if __name__=='__main__':unittest.main()
