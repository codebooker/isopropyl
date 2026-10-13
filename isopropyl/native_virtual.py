"""Private native QEMU conversion; a container is never sent to a raw disk."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import astuple
from pathlib import Path

from .native_writer import BLOCK, NativeWriteError, path_file_identity
from .virtual import FileIdentity, ToolIdentity, _parse_virtual_info

FORMATS = {'.vhd':'vpc', '.vhdx':'vhdx', '.qcow':'qcow', '.qcow2':'qcow2'}


def qemu_tool(host=None):
    from .helper_tools import helper
    try:resolved=Path(helper('qemu-img')).resolve(strict=True)
    except NativeWriteError as error:raise NativeWriteError('QEMU image support is missing from this build: '+str(error)) from error
    return ToolIdentity(resolved,FileIdentity(*path_file_identity(resolved)))


def run_native_command(arguments, writer, *, timeout=1800, limit=1024*1024):
    """Cancellation-aware subprocess with bounded diagnostics and no console."""
    options = {'creationflags':subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {}
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=errors, shell=False, **options)
        deadline = time.monotonic()+timeout
        try:
            while process.poll() is None:
                writer.check_cancelled()
                if time.monotonic() > deadline:
                    raise NativeWriteError('Image preparation tool timed out')
                if os.fstat(output.fileno()).st_size + os.fstat(errors.fileno()).st_size > limit:
                    raise NativeWriteError('Image preparation tool produced excessive output')
                try:
                    process.wait(timeout=.1)
                except subprocess.TimeoutExpired:
                    pass
            writer.check_cancelled()
            output.seek(0); errors.seek(0)
            stdout, stderr = output.read(limit+1), errors.read(limit+1)
            if len(stdout)+len(stderr) > limit:
                raise NativeWriteError('Image preparation tool produced excessive output')
            if process.returncode:
                raise NativeWriteError(stderr.decode('utf-8',errors='replace')[-2048:] or 'Image preparation tool failed')
            return subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=2)


def _require_tool(tool):
    if FileIdentity(*path_file_identity(tool.path)) != tool.identity:
        raise NativeWriteError('The image conversion tool changed during preparation')


def convert_private_container(container, workspace, writer, target_size, progress):
    """Only caller-created snapshots in a private workspace are accepted."""
    if container.parent != workspace or container.is_symlink() or container.suffix.lower() not in FORMATS:
        raise NativeWriteError('Virtual conversion requires a private container snapshot')
    tool = qemu_tool(writer.host)
    identity = FileIdentity(*path_file_identity(container))
    image_format = FORMATS[container.suffix.lower()]
    _require_tool(tool)
    result = run_native_command([str(tool.path),'info','--output=json','-f',image_format,str(container)], writer, timeout=30)
    info = _parse_virtual_info(container, identity, tool, result, target_size)
    if info.format != image_format or info.has_snapshots:
        raise NativeWriteError('Virtual image format differs from its suffix or contains snapshots')
    if shutil.disk_usage(workspace).free < info.virtual_size*3 + BLOCK:
        raise NativeWriteError('Not enough temporary space to convert and stage the virtual disk')
    _require_tool(tool); writer.check_cancelled()
    image = workspace/'converted.img'
    progress('Converting virtual disk', 0, 1)
    run_native_command([str(tool.path),'convert','-f',image_format,'-O','raw',str(container),str(image)],writer)
    _require_tool(tool)
    progress('Verifying virtual-disk conversion', 0, 1)
    run_native_command([str(tool.path),'compare','-q','-f',image_format,'-F','raw',str(container),str(image)],writer)
    _require_tool(tool)
    if path_file_identity(container) != astuple(identity):
        raise NativeWriteError('The private virtual image changed during conversion')
    if image.is_symlink() or image.stat().st_size != info.virtual_size:
        raise NativeWriteError('Converted virtual image has an unexpected size')
    image.chmod(0o600)
    progress('Verifying virtual-disk conversion', 1, 1)
    return image
