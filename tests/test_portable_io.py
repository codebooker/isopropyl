# SPDX-License-Identifier: AGPL-3.0-or-later
import ctypes
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch

from isopropyl.portable_io import descriptor_status,regular_status,_windows_handle_metadata


class ChangeTimeTests(unittest.TestCase):
    def test_windows_basic_info_uses_change_time_and_held_handle(self):
        # Birth/mtime deliberately differ from ChangeTime. API class 0 must
        # read the fourth LARGE_INTEGER, in 100ns ticks since 1601.
        query=Mock()
        def fill(handle,information_class,buffer,size):
            self.assertEqual(handle,123);self.assertEqual(information_class,0)
            self.assertEqual(size,40)
            times=ctypes.cast(buffer,ctypes.POINTER(ctypes.c_int64))
            times[0]=116444736000000000+11;times[2]=116444736000000000+22
            times[3]=116444736000000000+123456789
            return 1
        query.side_effect=fill
        with patch.object(ctypes,'WinDLL',return_value=SimpleNamespace(GetFileInformationByHandleEx=query),create=True):
            changed,attributes=_windows_handle_metadata(123)
        self.assertEqual(changed,12345678900);self.assertEqual(attributes,0)

    def test_descriptor_status_preserves_fields_and_replaces_birth_time(self):
        info=SimpleNamespace(st_dev=8,st_ino=7,st_size=6,st_mtime_ns=5,st_ctime_ns=4,st_nlink=1,st_file_attributes=None)
        with patch('isopropyl.portable_io.sys.platform','win32'),patch('isopropyl.portable_io.os.fstat',return_value=info), \
             patch.dict('sys.modules',{'msvcrt':SimpleNamespace(get_osfhandle=lambda fd:123)}), \
             patch('isopropyl.portable_io._windows_handle_metadata',return_value=(987654321,0x20)) as query:
            result=descriptor_status(9)
        query.assert_called_once_with(123)
        self.assertEqual((result.st_dev,result.st_ino,result.st_size,result.st_mtime_ns,result.st_nlink),(8,7,6,5,1))
        self.assertEqual(result.st_ctime_ns,987654321);self.assertEqual(result.st_file_attributes,0x20)

    def test_failed_windows_change_time_query_cannot_fall_back_to_creation_time(self):
        with patch('isopropyl.portable_io.sys.platform','win32'),patch('isopropyl.portable_io.os.fstat',return_value=SimpleNamespace()), \
             patch.dict('sys.modules',{'msvcrt':SimpleNamespace(get_osfhandle=lambda fd:123)}), \
             patch('isopropyl.portable_io._windows_handle_metadata',side_effect=OSError('API failed')):
            with self.assertRaisesRegex(OSError,'API failed'):descriptor_status(9)

    def test_held_descriptor_and_path_detect_rewrite_with_restored_mtime(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'source.img';path.write_bytes(b'A'*4096)
            with path.open('rb') as source:
                before=descriptor_status(source.fileno());original=path.stat()
                path.write_bytes(b'B'*4096);os.utime(path,ns=(original.st_atime_ns,original.st_mtime_ns))
                after=descriptor_status(source.fileno());named=regular_status(path)
            self.assertEqual(before.st_mtime_ns,after.st_mtime_ns)
            self.assertNotEqual(before.st_ctime_ns,after.st_ctime_ns)
            self.assertEqual(after.st_ctime_ns,named.st_ctime_ns)

    def test_native_tree_rejects_same_size_rewrite_with_restored_mtime(self):
        from isopropyl.native_tree import scan_tree,consume
        from isopropyl.native_writer import NativeWriteError
        writer=SimpleNamespace(check_cancelled=lambda:None)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'payload.bin';path.write_bytes(b'A'*4096)
            original=path.stat();_,files=scan_tree(root,writer)
            path.write_bytes(b'B'*4096);os.utime(path,ns=(original.st_atime_ns,original.st_mtime_ns))
            with self.assertRaisesRegex(NativeWriteError,'staged source file changed'):consume(root,files[0],writer)
