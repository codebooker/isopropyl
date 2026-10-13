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


def regular_status(path):
    """Use handle change-times on Windows, preserving normal POSIX metadata."""
    if sys.platform!='win32':return path.stat()
    named=path.lstat()
    if not stat.S_ISREG(named.st_mode) or getattr(named,'st_file_attributes',0)&0x400:
        raise OSError('Expected an ordinary regular file')
    with path.open('rb') as stream:
        info=os.fstat(stream.fileno())
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
