"""Bounded, cancellation-aware subprocess output to a new regular file."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import subprocess
import sys
import tempfile
import time

from .native_writer import NativeWriteError


def command_to_file(arguments,path,size,writer,*,timeout=1800):
    options={'creationflags':subprocess.CREATE_NO_WINDOW} if sys.platform=='win32' else {}
    with path.open('xb') as output,tempfile.TemporaryFile() as errors:
        path.chmod(0o600)
        process=subprocess.Popen(arguments,stdin=subprocess.DEVNULL,stdout=output,stderr=errors,shell=False,**options)
        deadline=time.monotonic()+timeout
        try:
            while process.poll() is None:
                writer.check_cancelled()
                if time.monotonic()>deadline or os.fstat(output.fileno()).st_size>size or os.fstat(errors.fileno()).st_size>65536:
                    raise NativeWriteError('File preparation exceeded its time or size bound')
                try:process.wait(timeout=.1)
                except subprocess.TimeoutExpired:pass
            writer.check_cancelled();output.flush();os.fsync(output.fileno())
            if process.returncode or os.fstat(output.fileno()).st_size!=size:
                errors.seek(0);detail=errors.read(2048).decode(errors='replace')
                raise NativeWriteError(detail or 'Prepared file has the wrong size')
        finally:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=2)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=2)
