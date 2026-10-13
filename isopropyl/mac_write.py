"""Stage images and run a desktop-user worker with authorized disk descriptors."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .native_writer import BLOCK, NativeCancelled, NativeWriteError, file_identity


def worker_python() -> str:
    runtime = Path.home() / 'Library/Application Support/ISOpropyl/runtime/bin/python'
    if runtime.is_file():
        return str(runtime)
    executable = Path(sys.executable).absolute()
    protected = (Path.home()/name for name in ('Documents', 'Desktop', 'Downloads'))
    if any(executable.is_relative_to(directory) for directory in protected):
        raise NativeWriteError('Install the macOS runtime in Application Support before writing. See CROSS_PLATFORM.md.')
    return str(executable)


def authorize_request(request: Path, *, writer=None, progress=lambda stage, done, total: None):
    command = [worker_python(), '-I', '-m', 'isopropyl.mac_worker', '--request', str(request)]
    process = subprocess.Popen(command,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)
    last = None
    while True:
        if writer and writer.cancelled.is_set():
            (request.parent/'cancel').touch(exist_ok=True)
        try:
            with (request.parent/'progress.json').open(encoding='utf-8') as stream:
                status = json.loads(stream.read(4096))
            if writer:
                writer.write_started = status.get('write_started') is True
            state = (status.get('stage'), status.get('done'), status.get('total'))
            if state != last and isinstance(state[0], str) and type(state[1]) is int and type(state[2]) is int and state[2] > 0:
                progress(*state)
                last = state
        except (OSError, ValueError, TypeError):
            pass
        try:
            output, error = process.communicate(timeout=.1)
            break
        except subprocess.TimeoutExpired:
            continue
    if process.returncode:
        if '-128' in error:
            raise NativeCancelled('Authorization cancelled. No write was started.')
        if writer:
            writer.write_started = True  # No authoritative result: do not imply the target is safe.
        raise NativeWriteError(error.strip()[-2048:] or 'The device worker did not return a result')
    try:
        result = json.loads(output)
        if type(result.get('write_started')) is not bool or type(result.get('ok')) is not bool:
            raise ValueError('Invalid worker result')
    except (ValueError, TypeError, AttributeError) as error:
        if writer:
            writer.write_started = True
        raise NativeWriteError('The device worker returned invalid completion data') from error
    if writer:
        writer.write_started = result['write_started']
    if not result['ok']:
        raise NativeWriteError(str(result.get('error') or 'Device write failed'))
    return result


def run_macos_write(plan, confirmation, writer, *, progress=lambda stage, done, total: None, prepared_private=False):
    if confirmation != plan.confirmation:
        raise NativeWriteError('The exact erase confirmation was not supplied')
    with tempfile.TemporaryDirectory(prefix='isopropyl-write-') as directory:
        parent = Path(directory)
        source_path = parent/('source' + plan.source.suffix.lower())
        digest = hashlib.sha256()
        if prepared_private:
            info=plan.source.lstat();parent_info=plan.source.parent.lstat()
            if (info.st_mode&0o077 or info.st_nlink!=1 or parent_info.st_mode&0o077
                    or file_identity(info)!=plan.source_identity):
                raise NativeWriteError('Prepared source is not a bound private image')
            plan.source.replace(source_path)
        staged_identity=file_identity(source_path.lstat()) if prepared_private else plan.source_identity
        with source_path.open('rb') if prepared_private else plan.source.open('rb') as source, (source_path.open('rb') if prepared_private else source_path.open('xb')) as staged:
            if not prepared_private:source_path.chmod(0o600)
            if file_identity(os.fstat(source.fileno())) != staged_identity:
                raise NativeWriteError('The source changed after confirmation')
            done = 0
            while done < plan.size:
                writer.check_cancelled()
                data = source.read(min(BLOCK, plan.size-done))
                if not data:
                    raise NativeWriteError('The source image ended unexpectedly')
                if not prepared_private:staged.write(data)
                digest.update(data)
                done += len(data)
                progress('Staging image', done, plan.size)
            if source.read(1) or file_identity(os.fstat(source.fileno())) != staged_identity or file_identity((source_path if prepared_private else plan.source).lstat()) != staged_identity:
                raise NativeWriteError('The source changed during staging')
        checksum = digest.hexdigest()
        if plan.expected_sha256 and plan.expected_sha256 != checksum:
            raise NativeWriteError('Image SHA-256 does not match the expected checksum')
        writer.check_cancelled()
        request = parent/'request.json'
        request.write_text(json.dumps({'version':1, 'operation':'write', 'source_name':source_path.name,
            'sha256':checksum, 'target_identity':list(plan.target.identity),
            'include_fixed':plan.include_fixed, 'confirmation':confirmation,
            'final_verification':writer.final_verification}), encoding='utf-8')
        request.chmod(0o600)
        progress('Starting disk-access worker', 0, 1)
        result = authorize_request(request, writer=writer, progress=progress)
        if result.get('sha256') != checksum:
            raise NativeWriteError('The device worker returned a mismatched verification checksum')
        return checksum
