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
