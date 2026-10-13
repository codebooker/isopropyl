"""Directory-relative regular-file operations on Windows and POSIX.

Windows directory references retain a kernel handle and verify the named file
ID before every relative operation. This adapter is for private source/cache
trees only; native whole-disk I/O continues to use native_disk_io.
"""
# SPDX-License-Identifier: AGPL-3.0-or-later
import os as real_os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from functools import lru_cache

_DIR=0x20000000
_NOFOLLOW=0x10000000
_frames={}
_next=1_000_000
_token_sid=None


class Directory(int):
    pass


@lru_cache(maxsize=1)
def _api():
    import ctypes as c
    from ctypes import wintypes as w
    kernel=c.WinDLL('kernel32',use_last_error=True);security=c.WinDLL('advapi32',use_last_error=True)
    kernel.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE];kernel.CreateFileW.restype=w.HANDLE
    kernel.CloseHandle.argtypes=[w.HANDLE];kernel.CloseHandle.restype=w.BOOL
    kernel.GetCurrentProcess.restype=w.HANDLE
    security.GetSecurityInfo.argtypes=[w.HANDLE,c.c_int,w.DWORD,c.POINTER(c.c_void_p),c.c_void_p,c.POINTER(c.c_void_p),c.c_void_p,c.POINTER(c.c_void_p)]
    security.GetSecurityInfo.restype=w.DWORD
    security.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes=[c.c_void_p,w.DWORD,w.DWORD,c.POINTER(w.LPWSTR),c.c_void_p]
    security.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype=w.BOOL
    kernel.LocalFree.argtypes=[c.c_void_p];kernel.LocalFree.restype=c.c_void_p
    return c,w,kernel,security


def _handle_id(handle,named_identity):
    c,w,kernel,security=_api()
    class FileIdInfo(c.Structure):
        _fields_=[('Serial',c.c_ulonglong),('Identifier',c.c_ubyte*16)]
    query=getattr(kernel,'GetFileInformationByHandleEx',None)
    if query is not None:
        query.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD];query.restype=w.BOOL
        extended=FileIdInfo()
        if query(handle,18,c.byref(extended),c.sizeof(extended)):
            identifier=int.from_bytes(bytes(extended.Identifier),'little')
            if identifier:return extended.Serial,identifier
    # Older filesystems may reject FileIdInfo. A legacy 64-bit ID is only
    # usable when it matches Python's named identity in full, without truncation.
    class FileTime(c.Structure):_fields_=[('Low',w.DWORD),('High',w.DWORD)]
    class Info(c.Structure):
        _fields_=[('Attributes',w.DWORD),('Created',FileTime),('Accessed',FileTime),('Written',FileTime),
                  ('Serial',w.DWORD),('SizeHigh',w.DWORD),('SizeLow',w.DWORD),('Links',w.DWORD),
                  ('IndexHigh',w.DWORD),('IndexLow',w.DWORD)]
    kernel.GetFileInformationByHandle.argtypes=[w.HANDLE,c.c_void_p];kernel.GetFileInformationByHandle.restype=w.BOOL
    info=Info()
    if not kernel.GetFileInformationByHandle(handle,c.byref(info)):raise OSError('Could not bind directory handle identity')
    identity=info.Serial,(info.IndexHigh<<32)|info.IndexLow
    if identity!=named_identity:raise OSError('Legacy directory identity differs from the named file ID')
    return identity


def _security(handle):
    """Return actual owner and whether the DACL excludes ordinary other users."""
    c,w,kernel,security=_api();owner=c.c_void_p();dacl=c.c_void_p();descriptor=c.c_void_p()
    if security.GetSecurityInfo(handle,1,5,c.byref(owner),None,c.byref(dacl),None,c.byref(descriptor)):
        raise OSError('Could not inspect private-directory ownership')
    text=w.LPWSTR()
    try:
        if not security.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor,1,5,c.byref(text),None):
            raise OSError('Could not inspect private-directory permissions')
        value=text.value
        import re
        own=re.search(r'O:(.*?)(?=G:|D:|S:|$)',value)
        owner_sid=own.group(1) if own else ''
        allowed={owner_sid,'OW','SY','BA',_current_sid()}
        aces=re.findall(r'\(([^()]+)\)',value)
        private=bool(aces) and all(ace.split(';')[-1] in allowed or 'IO' in ace.split(';')[1] for ace in aces)
        return owner_sid,private
    finally:
        if text:kernel.LocalFree(c.cast(text,c.c_void_p))
        if descriptor:kernel.LocalFree(descriptor)


def _current_sid():
    global _token_sid
    if _token_sid is not None:return _token_sid
    c,w,kernel,security=_api()
    security.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,c.POINTER(w.HANDLE)];security.OpenProcessToken.restype=w.BOOL
    security.GetTokenInformation.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD,c.POINTER(w.DWORD)];security.GetTokenInformation.restype=w.BOOL
    security.ConvertSidToStringSidW.argtypes=[c.c_void_p,c.POINTER(w.LPWSTR)];security.ConvertSidToStringSidW.restype=w.BOOL
    token=w.HANDLE();size=w.DWORD()
    if not security.OpenProcessToken(kernel.GetCurrentProcess(),8,c.byref(token)):raise OSError('Cannot identify the current user')
    try:
        security.GetTokenInformation(token,1,None,0,c.byref(size));data=c.create_string_buffer(size.value)
        if not security.GetTokenInformation(token,1,data,size,c.byref(size)):raise OSError('Cannot identify token owner')
        sid=c.cast(data,c.POINTER(c.c_void_p))[0];text=w.LPWSTR()
        if not security.ConvertSidToStringSidW(sid,c.byref(text)):raise OSError('Cannot encode token owner')
        try:_token_sid=text.value
        finally:kernel.LocalFree(c.cast(text,c.c_void_p))
    finally:kernel.CloseHandle(token)
    return _token_sid


def _open_directory(path):
    global _next
    c,w,kernel,security=_api();path=Path(path).absolute()
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
        raise OSError('Directory reference cannot traverse a reparse point')
    handle=kernel.CreateFileW(str(path),0x80000000,7,None,3,0x02000000|0x00200000,None)
    if handle==c.c_void_p(-1).value:raise c.WinError(c.get_last_error())
    try:
        if _handle_id(handle,(info.st_dev,info.st_ino))!=(info.st_dev,info.st_ino):
            raise OSError('Directory changed while opening')
    except BaseException:
        kernel.CloseHandle(handle);raise
    frame=Directory(_next);_next+=1
    _frames[frame]=(path,handle,(info.st_dev,info.st_ino))
    return frame


def _path(path,dir_fd=None):
    if dir_fd is not None:
        root,handle,identity=_frames[dir_fd]
        current=root.lstat()
        if (current.st_dev,current.st_ino)!=identity or getattr(current,'st_file_attributes',0)&0x400:
            raise OSError('Bound directory was renamed or replaced')
        child=Path(path)
        if child.is_absolute() or any(part=='..' for part in child.parts):raise OSError('Invalid directory-relative path')
        return root/child
    return Path(path)


def _status(path,handle=None):
    named=path.lstat()
    if getattr(named,'st_file_attributes',0)&0x400:return named
    own_handle=None
    c,w,kernel,security=_api()
    if handle is None:
        own_handle=kernel.CreateFileW(str(path),0x80000000,7,None,3,0x02000000,None)
        if own_handle==c.c_void_p(-1).value:raise c.WinError(c.get_last_error())
        handle=own_handle
    try:
        named_identity=(named.st_dev,named.st_ino)
        if _handle_id(handle,named_identity)!=named_identity:
            raise OSError('Metadata handle differs from its named file identity')
        owner,private=_security(handle)
        if stat.S_ISREG(named.st_mode):
            with path.open('rb') as stream:info=real_os.fstat(stream.fileno())
            if (info.st_dev,info.st_ino)!=named_identity:
                raise OSError('Regular file changed while binding its metadata')
        else:info=named
        values={name:getattr(info,name) for name in dir(info) if name.startswith('st_')}
        import ctypes
        values['st_uid']=0 if owner==_current_sid() or owner=='BA' and ctypes.windll.shell32.IsUserAnAdmin() else 1
        values['st_gid']=0
        mode=0o700 if stat.S_ISDIR(info.st_mode) else (0o400 if getattr(info,'st_file_attributes',0)&1 else 0o600)
        if not private:mode |= 0o055 if stat.S_ISDIR(info.st_mode) else 0o044
        values['st_mode']=stat.S_IFMT(info.st_mode)|mode
        return SimpleNamespace(**values)
    finally:
        if own_handle is not None:kernel.CloseHandle(own_handle)


class WindowsOS:
    O_DIRECTORY=_DIR
    O_NOFOLLOW=_NOFOLLOW
    O_CLOEXEC=0
    O_NONBLOCK=0

    def __getattr__(self,name):return getattr(real_os,name)
    def geteuid(self):return 0
    def getuid(self):return 0
    def open(self,path,flags,mode=0o777,*,dir_fd=None):
        path=_path(path,dir_fd)
        if flags&_DIR:return _open_directory(path)
        nofollow=bool(flags&_NOFOLLOW);flags &= ~(_DIR|_NOFOLLOW)
        if nofollow and path.exists():
            info=path.lstat()
            if getattr(info,'st_file_attributes',0)&0x400 or not stat.S_ISREG(info.st_mode):raise OSError('Expected a no-follow regular file')
        fd=real_os.open(path,flags|getattr(real_os,'O_BINARY',0),mode)
        if nofollow:
            named=path.lstat();opened=real_os.fstat(fd)
            if (named.st_dev,named.st_ino)!=(opened.st_dev,opened.st_ino) or getattr(named,'st_file_attributes',0)&0x400:
                real_os.close(fd);raise OSError('File changed while opening')
        return fd
    def close(self,fd):
        if fd in _frames:
            c,w,kernel,security=_api();kernel.CloseHandle(_frames.pop(fd)[1])
        else:real_os.close(fd)
    def dup(self,fd):
        return _open_directory(_frames[fd][0]) if fd in _frames else real_os.dup(fd)
    def fstat(self,fd):
        if fd in _frames:
            path=_path('.',fd);return _status(path,_frames[fd][1])
        info=real_os.fstat(fd);path=self._fdpath(fd);named=path.lstat()
        if (info.st_dev,info.st_ino)!=(named.st_dev,named.st_ino):raise OSError('Bound regular file pathname changed')
        result=_status(path)
        for name in dir(info):
            if name.startswith('st_') and name not in {'st_uid','st_gid','st_mode'}:setattr(result,name,getattr(info,name))
        return result
    def stat(self,path,*,dir_fd=None,follow_symlinks=True):return _status(_path(path,dir_fd))
    def lstat(self,path,*,dir_fd=None):return _status(_path(path,dir_fd))
    def listdir(self,path):return real_os.listdir(_path('.',path) if path in _frames else path) if isinstance(path,int) else real_os.listdir(path)
    def mkdir(self,path,mode=0o777,*,dir_fd=None):
        path=_path(path,dir_fd)
        real_os.mkdir(path,mode)
        if mode&0o077==0:
            # Restrict new private directories to the creator and SYSTEM.
            c,w,kernel,security=_api();descriptor=c.c_void_p()
            security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[w.LPCWSTR,w.DWORD,c.POINTER(c.c_void_p),c.c_void_p]
            security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=w.BOOL
            security.SetFileSecurityW.argtypes=[w.LPCWSTR,w.DWORD,c.c_void_p];security.SetFileSecurityW.restype=w.BOOL
            sddl=f'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{_current_sid()})'
            if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,c.byref(descriptor),None):raise OSError('Cannot construct private-directory ACL')
            try:
                if not security.SetFileSecurityW(str(path),4|0x80000000,descriptor):raise OSError('Cannot restrict private-directory ACL')
            finally:kernel.LocalFree(descriptor)
    def unlink(self,path,*,dir_fd=None):return real_os.unlink(_path(path,dir_fd))
    def rmdir(self,path,*,dir_fd=None):return real_os.rmdir(_path(path,dir_fd))
    def rename(self,src,dst,*,src_dir_fd=None,dst_dir_fd=None):return real_os.rename(_path(src,src_dir_fd),_path(dst,dst_dir_fd))
    def replace(self,src,dst,*,src_dir_fd=None,dst_dir_fd=None):return real_os.replace(_path(src,src_dir_fd),_path(dst,dst_dir_fd))
    def link(self,src,dst,*,src_dir_fd=None,dst_dir_fd=None,follow_symlinks=True):
        source=_path(src,src_dir_fd)
        if not follow_symlinks and getattr(source.lstat(),'st_file_attributes',0)&0x400:raise OSError('Cannot hardlink a reparse point')
        return real_os.link(source,_path(dst,dst_dir_fd))
    def fsync(self,fd):
        if fd not in _frames:return real_os.fsync(fd)
        # Windows does not expose POSIX directory fsync. Named references are
        # rebound after commit; file flushes remain mandatory.
        _path('.',fd)
    def _fdpath(self,fd):
        import msvcrt
        c,w,kernel,security=_api();buffer=c.create_unicode_buffer(32768)
        kernel.GetFinalPathNameByHandleW.argtypes=[w.HANDLE,w.LPWSTR,w.DWORD,w.DWORD];kernel.GetFinalPathNameByHandleW.restype=w.DWORD
        length=kernel.GetFinalPathNameByHandleW(msvcrt.get_osfhandle(fd),buffer,len(buffer),0)
        if not 0<length<len(buffer):raise OSError('Cannot resolve the bound regular file')
        return Path(buffer.value)
    def fchmod(self,fd,mode):real_os.chmod(self._fdpath(fd),mode)
    def utime(self,path,*args,dir_fd=None,**kwargs):
        if isinstance(path,int):path=self._fdpath(path)
        return real_os.utime(_path(path,dir_fd),*args,**kwargs)
    def fstatvfs(self,fd):
        import shutil
        path=_path('.',fd) if fd in _frames else self._fdpath(fd)
        free=shutil.disk_usage(path).free
        return SimpleNamespace(f_bavail=free,f_frsize=1)
    def pread(self,fd,size,offset):
        from .portable_io import pread
        return pread(fd,size,offset)


os=WindowsOS() if sys.platform=='win32' else real_os
