"""Native isolated Authenticode transport and Windows worker resource bounds."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import hashlib
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

_jobs=[]


def limit_current_process(memory,seconds):
    """Bound worker memory, CPU and descendants with a retained Windows job."""
    import ctypes as c
    from ctypes import wintypes as w
    class Basic(c.Structure):
        _fields_=[('ProcessTime',c.c_longlong),('JobTime',c.c_longlong),('Flags',w.DWORD),
                  ('MinWorking',c.c_size_t),('MaxWorking',c.c_size_t),('Active',w.DWORD),
                  ('Affinity',c.c_size_t),('Priority',w.DWORD),('Scheduling',w.DWORD)]
    class Counters(c.Structure):
        _fields_=[(name,c.c_ulonglong) for name in ('ReadOps','WriteOps','OtherOps','ReadBytes','WriteBytes','OtherBytes')]
    class Extended(c.Structure):
        _fields_=[('Basic',Basic),('Io',Counters),('ProcessMemory',c.c_size_t),('JobMemory',c.c_size_t),
                  ('PeakProcess',c.c_size_t),('PeakJob',c.c_size_t)]
    kernel=c.WinDLL('kernel32',use_last_error=True)
    kernel.CreateJobObjectW.argtypes=[c.c_void_p,w.LPCWSTR];kernel.CreateJobObjectW.restype=w.HANDLE
    kernel.SetInformationJobObject.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD];kernel.SetInformationJobObject.restype=w.BOOL
    kernel.GetCurrentProcess.restype=w.HANDLE
    kernel.AssignProcessToJobObject.argtypes=[w.HANDLE,w.HANDLE];kernel.AssignProcessToJobObject.restype=w.BOOL
    kernel.CloseHandle.argtypes=[w.HANDLE];kernel.CloseHandle.restype=w.BOOL
    kernel.QueryInformationJobObject.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD,c.c_void_p]
    kernel.QueryInformationJobObject.restype=w.BOOL
    job=kernel.CreateJobObjectW(None,None)
    limits=Extended();limits.Basic.Flags=0x100|0x8|0x2;limits.Basic.Active=1
    limits.Basic.ProcessTime=seconds*10_000_000;limits.ProcessMemory=memory
    if not job:raise OSError(c.get_last_error(),'Could not create Authenticode worker limits job')
    try:
        if not kernel.SetInformationJobObject(job,9,c.byref(limits),c.sizeof(limits)):
            raise OSError(c.get_last_error(),'Could not configure Authenticode worker limits job')
        # Windows 10 supports nested jobs, including an inherited CI runner job.
        # Do not use breakaway flags or relax limits when assignment is refused.
        if not kernel.AssignProcessToJobObject(job,kernel.GetCurrentProcess()):
            raise OSError(c.get_last_error(),'Could not assign Authenticode worker to bounded job (including nested jobs)')
        observed=Extended()
        if not kernel.QueryInformationJobObject(job,9,c.byref(observed),c.sizeof(observed),None):
            raise OSError(c.get_last_error(),'Could not verify Authenticode worker job limits')
        if (observed.Basic.Flags&limits.Basic.Flags!=limits.Basic.Flags or observed.Basic.Active!=1
                or not 0<observed.Basic.ProcessTime<=limits.Basic.ProcessTime
                or not 0<observed.ProcessMemory<=memory):
            raise OSError('Authenticode worker job limits differ from the required bounds')
    except BaseException:
        kernel.CloseHandle(job);raise
    _jobs.append(job)


def _darwin_resident_bytes(pid):
    import ctypes
    import struct
    library=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True)
    library.proc_pidinfo.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_ulonglong,ctypes.c_void_p,ctypes.c_int]
    library.proc_pidinfo.restype=ctypes.c_int
    buffer=ctypes.create_string_buffer(96)
    if library.proc_pidinfo(pid,4,0,buffer,len(buffer))!=96:
        raise OSError('Could not inspect isolated worker resident memory')
    return struct.unpack_from('=Q',buffer.raw,8)[0]

def run_worker(blob,facts,*,timeout,cancel_check=None,popen=None):
    from .authenticode import (_WORKER_BOOTSTRAP,_WorkerFailure,MAX_WORKER_OUTPUT,
                               _stop_worker,_check_worker_cancellation)
    entry=facts.entries[0]
    with tempfile.TemporaryDirectory(prefix='isopropyl-authenticode-') as directory:
        payload=Path(directory)/'payload.bin';payload.write_bytes(blob);payload.chmod(0o400)
        parent=str(Path(__file__).resolve().parent.parent)
        arguments=[sys.executable,'-I','-c',_WORKER_BOOTSTRAP,parent,'--source-file',str(payload),hashlib.sha256(blob).hexdigest(),
                   str(len(blob)),str(facts.file_offset),str(facts.size),str(entry.length),
                   str(entry.revision),str(entry.certificate_type)]
        options={'creationflags':subprocess.CREATE_NO_WINDOW} if sys.platform=='win32' else {}
        process=(popen or subprocess.Popen)(arguments,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,close_fds=True,shell=False,**options)
        messages=queue.Queue(maxsize=4);stop=threading.Event()
        def read():
            try:
                while not stop.is_set():
                    data=os.read(process.stdout.fileno(),4096)
                    while not stop.is_set():
                        try:messages.put(data,timeout=.05);break
                        except queue.Full:pass
                    if not data:return
            except OSError:
                pass
        reader=threading.Thread(target=read,daemon=True);reader.start()
        output=bytearray();deadline=time.monotonic()+timeout
        try:
            while True:
                _check_worker_cancellation(cancel_check)
                if sys.platform=='darwin' and process.poll() is None:
                    from .authenticode_worker import _ADDRESS_SPACE_LIMIT
                    try:resident=_darwin_resident_bytes(process.pid)
                    except OSError as error:
                        if process.poll() is None:raise _WorkerFailure(str(error)) from error
                        resident=0
                    if resident>_ADDRESS_SPACE_LIMIT:raise _WorkerFailure('Authenticode worker exceeded its resident-memory bound')
                if time.monotonic()>deadline:raise _WorkerFailure('Authenticode worker timed out')
                try:data=messages.get(timeout=.05)
                except queue.Empty:continue
                if not data:break
                output.extend(data)
                if len(output)>MAX_WORKER_OUTPUT:raise _WorkerFailure('Authenticode worker output exceeds its bound')
            if process.wait(timeout=max(.001,deadline-time.monotonic())):
                raise _WorkerFailure('Authenticode worker failed')
            return bytes(output)
        finally:
            stop.set()
            if process.poll() is None:_stop_worker(process)
            process.stdout.close();reader.join(timeout=.5)
            payload.chmod(0o600)
