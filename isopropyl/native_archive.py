"""Bounded native archive commands; archive names never become destinations."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from .native_virtual import run_native_command
from .portable_io import descriptor_status
from .native_writer import NativeWriteError,file_identity,path_file_identity


def seven_zip():
    from .helper_tools import helper
    return helper('7z')


@contextmanager
def bound_archive(path,descriptor):
    path=Path(path).absolute()
    if not stat.S_ISREG(path.lstat().st_mode):raise NativeWriteError('Archive source must be a regular file')
    identity=path_file_identity(path)
    if descriptor is not None and file_identity(descriptor_status(descriptor))!=identity:
        raise NativeWriteError('Archive pathname differs from its bound source')
    yield str(path)
    if path_file_identity(path)!=identity or descriptor is not None and file_identity(descriptor_status(descriptor))!=identity:
        raise NativeWriteError('The archive source changed during the command')


def run_archive(arguments,path,descriptor,cancel_check,*,timeout,limit):
    writer=SimpleNamespace(check_cancelled=cancel_check or (lambda:None))
    with bound_archive(path,descriptor) as source:
        executable=seven_zip()
        if not executable:raise NativeWriteError('7-Zip is required for filesystem-aware image inspection and extraction')
        return run_native_command([executable,*arguments,source],writer,timeout=timeout,limit=limit)


def catalog(path,descriptor,namespace,cancel_check):
    from .images import parse_7z_listing,MAX_7Z_CATALOG_BYTES
    flags=[] if namespace is None else ['-t'+namespace.value]
    try:
        result=run_archive(['l','-slt','-sccUTF-8',*flags,'--'],path,descriptor,cancel_check,
                           timeout=20,limit=MAX_7Z_CATALOG_BYTES)
        members=parse_7z_listing(result.stdout.decode('utf-8',errors='strict'))
        return (members,'complete') if members else ([],'unavailable')
    except NativeWriteError as error:
        if 'source changed' in str(error) or 'bound source' in str(error):raise
        return [],'unavailable'


def read_member(executable,path,member,descriptor,cancel_check,*,timeout,max_bytes,archive_type):
    flags=[] if archive_type is None else ['-t'+archive_type]
    writer=SimpleNamespace(check_cancelled=cancel_check or (lambda:None))
    with bound_archive(path,descriptor) as source:
        result=run_native_command([executable,'x','-so','-spd','-y',*flags,'--',source,member],
                                  writer,timeout=timeout,limit=max_bytes+65536)
        if len(result.stdout)>max_bytes:raise NativeWriteError('Archive member exceeds its inspection bound')
        return result.stdout
