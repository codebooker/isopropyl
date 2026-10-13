"""Advisory exclusive lock released by the OS on process exit."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import os,sys
from contextlib import contextmanager
@contextmanager
def exclusive_file_lock(path):
    flags=os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0)
    descriptor=os.open(path,flags,0o600)
    try:
        import stat
        status=os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink!=1:raise OSError('Unsafe workspace lock')
        if sys.platform=='win32':
            import msvcrt
            if not status.st_size:os.write(descriptor,b'0')
            os.lseek(descriptor,0,os.SEEK_SET);msvcrt.locking(descriptor,msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:os.close(descriptor)
