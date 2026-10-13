"""Positioned regular-file reads on POSIX and Windows.

The Windows fallback serializes and restores descriptor offsets. Consumers of
these descriptors must use positioned reads rather than concurrent stream I/O.
"""
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import threading
import stat
import sys

_position_lock = threading.RLock()


class _ChangeTimeStatus:
    """Stat fields with Windows metadata-change time instead of birth time."""
    def __init__(self,status,changed_ns,attributes):
        self._status=status
        self.st_ctime_ns=changed_ns
        self.st_ctime=changed_ns/1_000_000_000
        self.st_file_attributes=attributes

    def __getattr__(self,name):return getattr(self._status,name)

    def __dir__(self):return sorted(set(dir(self._status))|set(object.__dir__(self)))


def _windows_handle_metadata(handle):
    import ctypes
    from ctypes import wintypes
    class FILE_BASIC_INFO(ctypes.Structure):
        _fields_=[('CreationTime',ctypes.c_int64),('LastAccessTime',ctypes.c_int64),
                  ('LastWriteTime',ctypes.c_int64),('ChangeTime',ctypes.c_int64),
                  ('FileAttributes',wintypes.DWORD)]
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    query=kernel.GetFileInformationByHandleEx
    query.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
    query.restype=wintypes.BOOL
    basic=FILE_BASIC_INFO()
    if not query(handle,0,ctypes.byref(basic),ctypes.sizeof(basic)):
        raise ctypes.WinError(ctypes.get_last_error())
    return (basic.ChangeTime-116444736000000000)*100,basic.FileAttributes


def descriptor_status(descriptor):
    """Read identity metadata from the held descriptor; Windows fails closed."""
    info=os.fstat(descriptor)
    if sys.platform!='win32':return info
    import msvcrt
    return _ChangeTimeStatus(info,*_windows_handle_metadata(msvcrt.get_osfhandle(descriptor)))


def path_status(path):
    """Non-following path metadata, with actual Windows handle ChangeTime."""
    named=path.lstat()
    if sys.platform!='win32':return named
    if getattr(named,'st_file_attributes',0)&0x400 or stat.S_ISLNK(named.st_mode):
        raise OSError('Expected an ordinary filesystem object')
    if not stat.S_ISDIR(named.st_mode):
        with path.open('rb') as stream:info=descriptor_status(stream.fileno())
        if (info.st_dev,info.st_ino)!=(named.st_dev,named.st_ino):raise OSError('File changed while opening')
        return info
    import ctypes
    from ctypes import wintypes
    class HANDLE_INFO(ctypes.Structure):
        _fields_=[('attributes',wintypes.DWORD),('creation',wintypes.FILETIME),
                  ('access',wintypes.FILETIME),('write',wintypes.FILETIME),
                  ('volume',wintypes.DWORD),('size_high',wintypes.DWORD),
                  ('size_low',wintypes.DWORD),('links',wintypes.DWORD),
                  ('index_high',wintypes.DWORD),('index_low',wintypes.DWORD)]
    class FILE_ID_INFO(ctypes.Structure):
        _fields_=[('volume',ctypes.c_uint64),('identifier',ctypes.c_ubyte*16)]
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,
                                wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype=wintypes.HANDLE
    kernel.GetFileInformationByHandle.argtypes=[wintypes.HANDLE,ctypes.POINTER(HANDLE_INFO)]
    kernel.GetFileInformationByHandle.restype=wintypes.BOOL
    kernel.GetFileInformationByHandleEx.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
    kernel.GetFileInformationByHandleEx.restype=wintypes.BOOL
    kernel.CloseHandle.argtypes=[wintypes.HANDLE];kernel.CloseHandle.restype=wintypes.BOOL
    handle=kernel.CreateFileW(str(path),0x80,7,None,3,0x02200000,None)
    if handle==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
    try:
        info=HANDLE_INFO()
        if not kernel.GetFileInformationByHandle(handle,ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        identity=(info.volume,(info.index_high<<32)|info.index_low)
        extended=FILE_ID_INFO()
        if kernel.GetFileInformationByHandleEx(handle,18,ctypes.byref(extended),ctypes.sizeof(extended)):
            # Python 3.12 path stat uses the full 128-bit ID on filesystems
            # supporting FileIdInfo; FAT filesystems retain the legacy ID.
            identity=(extended.volume,int.from_bytes(bytes(extended.identifier),'little'))
        if info.attributes&0x400 or identity!=(named.st_dev,named.st_ino):
            raise OSError('Directory changed while opening')
        return _ChangeTimeStatus(named,*_windows_handle_metadata(handle))
    finally:kernel.CloseHandle(handle)


def regular_status(path):
    """Use handle change-times on Windows, preserving normal POSIX metadata."""
    if sys.platform!='win32':return path.stat()
    named=path.lstat()
    if not stat.S_ISREG(named.st_mode) or getattr(named,'st_file_attributes',0)&0x400:
        raise OSError('Expected an ordinary regular file')
    with path.open('rb') as stream:
        info=descriptor_status(stream.fileno())
    if (info.st_dev,info.st_ino)!=(named.st_dev,named.st_ino):raise OSError('File changed while opening')
    return info


def pread(descriptor: int, size: int, offset: int) -> bytes:
    if callable(getattr(os, 'pread', None)):
        return os.pread(descriptor, size, offset)
    with _position_lock:
        previous = os.lseek(descriptor, 0, os.SEEK_CUR)
        try:
            os.lseek(descriptor, offset, os.SEEK_SET)
            return os.read(descriptor, size)
        finally:
            os.lseek(descriptor, previous, os.SEEK_SET)
