# SPDX-License-Identifier: AGPL-3.0-or-later
import ctypes as c
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from isopropyl import portable_fs as fs

class Call:
    def __init__(self,action):self.action=action;self.calls=[]
    def __call__(self,*args):self.calls.append(args);return self.action(*args)

W=SimpleNamespace(DWORD=c.c_uint32,HANDLE=c.c_void_p,BOOL=c.c_int)

def kernel(extended=True,identifier=7,serial=11,legacy=7):
    def query(handle,kind,pointer,size):
        assert kind==18 and size==24
        pointer._obj.Serial=serial
        for index,value in enumerate(identifier.to_bytes(16,'little')):pointer._obj.Identifier[index]=value
        return extended
    def old(handle,pointer):
        pointer._obj.Serial=serial;pointer._obj.IndexHigh=legacy>>32;pointer._obj.IndexLow=legacy&0xffffffff
        return True
    return SimpleNamespace(GetFileInformationByHandleEx=Call(query),GetFileInformationByHandle=Call(old))

class WindowsIdentityTests(unittest.TestCase):
    def test_full_128_bit_refs_identifier_is_retained(self):
        identity=(1<<112)|0x12345678;api=kernel(identifier=identity,serial=1<<40)
        with patch.object(fs,'_api',return_value=(c,W,api,None)):
            self.assertEqual(fs._handle_id(9,(1<<40,identity)),(1<<40,identity))
        self.assertFalse(api.GetFileInformationByHandle.calls)
    def test_ntfs_extended_identity_is_compatible_with_named_stat(self):
        api=kernel(identifier=0x123456789abcdef)
        with patch.object(fs,'_api',return_value=(c,W,api,None)):
            self.assertEqual(fs._handle_id(9,(11,0x123456789abcdef)),(11,0x123456789abcdef))
    def test_legacy_fallback_requires_complete_named_identity_match(self):
        api=kernel(extended=False,legacy=7)
        with patch.object(fs,'_api',return_value=(c,W,api,None)):
            self.assertEqual(fs._handle_id(9,(11,7)),(11,7))
            with self.assertRaisesRegex(OSError,'Legacy directory identity'):
                fs._handle_id(9,(11,(1<<100)|7))
    def test_absent_extended_api_uses_only_consistent_legacy_identity(self):
        api=kernel();del api.GetFileInformationByHandleEx
        with patch.object(fs,'_api',return_value=(c,W,api,None)):
            self.assertEqual(fs._handle_id(9,(11,7)),(11,7))
    def test_zero_extended_identifier_uses_bound_legacy_fallback(self):
        api=kernel(identifier=0)
        with patch.object(fs,'_api',return_value=(c,W,api,None)):
            self.assertEqual(fs._handle_id(9,(11,7)),(11,7))
    def test_open_directory_closes_handle_when_identity_query_fails(self):
        from pathlib import Path
        api=SimpleNamespace(CreateFileW=Call(lambda *a:9),CloseHandle=Call(lambda *a:True))
        status=SimpleNamespace(st_mode=0o40700,st_dev=11,st_ino=7,st_file_attributes=0)
        with patch.object(fs,'_api',return_value=(c,W,api,None)),patch.object(Path,'lstat',return_value=status),patch.object(fs,'_handle_id',side_effect=OSError('query failed')):
            with self.assertRaises(OSError):fs._open_directory('/private')
        self.assertEqual(api.CloseHandle.calls,[(9,)])

    def test_owner_sddl_alias_is_canonicalized_without_accepting_other_users(self):
        sid='S-1-5-21-100-200-300-500'
        strings=[]
        def security_info(handle,kind,flags,owner,group,dacl,sacl,descriptor):
            owner._obj.value=123;descriptor._obj.value=456;return 0
        def as_sddl(descriptor,revision,flags,text,length):
            text._obj.value=strings[-1];return True
        def owner_string(owner,text):text._obj.value=sid;return True
        security=SimpleNamespace(GetSecurityInfo=Call(security_info),ConvertSecurityDescriptorToStringSecurityDescriptorW=Call(as_sddl),ConvertSidToStringSidW=Call(owner_string))
        api=SimpleNamespace(LocalFree=Call(lambda *a:None))
        types=SimpleNamespace(LPWSTR=c.c_wchar_p,DWORD=c.c_uint32,BOOL=c.c_int)
        with patch.object(fs,'_api',return_value=(c,types,api,security)),patch.object(fs,'_current_sid',return_value=sid):
            strings.append('O:LAD:P(A;OICI;FA;;;LA)(A;OICI;FA;;;SY)')
            self.assertEqual(fs._security(9),(sid,True))
            strings.append('O:LAD:P(A;OICI;FA;;;LA)(A;OICIIO;FA;;;WD)')
            self.assertEqual(fs._security(9),(sid,False))

    def test_status_of_already_open_file_does_not_reopen_delete_on_close_path(self):
        from pathlib import Path
        import stat
        info=SimpleNamespace(st_dev=11,st_ino=7,st_mode=stat.S_IFREG|0o600,st_size=512,st_file_attributes=0,st_ctime_ns=123,st_mtime_ns=100)
        api=SimpleNamespace(CloseHandle=Call(lambda *a:True))
        with patch.object(fs,'_api',return_value=(c,W,api,None)),patch.object(Path,'lstat',return_value=info),patch.object(Path,'open',side_effect=AssertionError('must not reopen')),patch.object(fs,'_handle_id',return_value=(11,7)),patch.object(fs,'_security',return_value=('S-1-5-18',True)),patch.object(fs,'_current_sid',return_value='S-1-5-18'):
            result=fs._status(Path('/temporary'),9,opened_info=info)
        self.assertEqual(result.st_uid,0);self.assertEqual(stat.S_IMODE(result.st_mode),0o600)
        self.assertEqual(result.st_ctime_ns,123);self.assertFalse(api.CloseHandle.calls)

    def test_private_mkdir_assigns_creator_owner_and_protected_dacl(self):
        import tempfile
        from pathlib import Path
        captured=[]
        def descriptor(text,revision,pointer,size):captured.append(text);pointer._obj.value=123;return True
        security=SimpleNamespace(ConvertStringSecurityDescriptorToSecurityDescriptorW=Call(descriptor),SetFileSecurityW=Call(lambda *a:True))
        api=SimpleNamespace(LocalFree=Call(lambda *a:None))
        types=SimpleNamespace(LPCWSTR=c.c_wchar_p,DWORD=c.c_uint32,BOOL=c.c_int)
        with tempfile.TemporaryDirectory() as directory,patch.object(fs,'_api',return_value=(c,types,api,security)),patch.object(fs,'_current_sid',return_value='S-1-5-18'):
            target=Path(directory)/'private';fs.WindowsOS().mkdir(target,0o700)
            self.assertTrue(target.is_dir())
        self.assertTrue(captured[0].startswith('O:S-1-5-18D:P'))
        self.assertEqual(security.SetFileSecurityW.calls[0][1],1|4|0x80000000)
        self.assertNotIn(';;;WD)',captured[0]);self.assertNotIn(';;;AU)',captured[0])
