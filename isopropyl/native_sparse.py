"""Bounded allocated-range discovery for private sparse regular images."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import errno
import os
import stat


def merge_ranges(ranges, size):
    result=[]
    for offset,length in sorted(ranges,key=lambda value:value[0]):
        if length<=0:continue
        end=min(size,offset+length);offset=max(0,offset)
        if offset>=end:continue
        if result and offset<=sum(result[-1]):
            previous,count=result[-1];result[-1]=(previous,max(previous+count,end)-previous)
        else:result.append((offset,end-offset))
    return tuple(result)


def iter_allocated_ranges(descriptor, *, start=0, length=None, cancel_check=lambda:None):
    info=os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):raise ValueError('Sparse range queries require a regular image')
    end=info.st_size if length is None else min(info.st_size,start+length)
    if not 0<=start<=end:raise ValueError('Invalid sparse image range')
    if os.name=='nt':
        import ctypes as c
        import msvcrt
        from ctypes import wintypes as w
        class Range(c.Structure):_fields_=[('offset',c.c_longlong),('length',c.c_longlong)]
        kernel=c.WinDLL('kernel32',use_last_error=True)
        kernel.DeviceIoControl.argtypes=[w.HANDLE,w.DWORD,c.c_void_p,w.DWORD,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p]
        kernel.DeviceIoControl.restype=w.BOOL
        position=start;handle=msvcrt.get_osfhandle(descriptor)
        while position<end:
            cancel_check();request=Range(position,end-position);output=(Range*256)();count=w.DWORD()
            success=kernel.DeviceIoControl(handle,0x940CF,c.byref(request),c.sizeof(request),output,c.sizeof(output),c.byref(count),None)
            error=c.get_last_error() if not success else 0
            if error not in {0,234}:  # unsupported filesystem: conservative full range
                yield start,end-start;return
            if count.value%c.sizeof(Range):raise OSError('Allocated-range query returned truncated metadata')
            values=count.value//c.sizeof(Range)
            if not values:return
            previous=position
            for item in output[:values]:
                offset=max(start,item.offset);right=min(end,item.offset+item.length)
                if item.length<=0 or item.offset<position or right<=offset:raise OSError('Allocated-range query made invalid progress')
                yield offset,right-offset;position=right
            if position<=previous:raise OSError('Allocated-range query did not advance')
            if success:return
    elif hasattr(os,'SEEK_DATA') and hasattr(os,'SEEK_HOLE'):
        position=start
        try:
            while position<end:
                cancel_check()
                try:data=os.lseek(descriptor,position,os.SEEK_DATA)
                except OSError as error:
                    if error.errno==errno.ENXIO:return
                    raise
                if data>=end:return
                hole=min(end,os.lseek(descriptor,data,os.SEEK_HOLE))
                if hole<=data:raise OSError('Sparse range query did not advance')
                yield data,hole-data;position=hole
        except OSError as error:
            if error.errno not in {errno.EINVAL,errno.ENOTSUP,errno.ENOSYS}:raise
            yield start,end-start
    else:yield start,end-start
