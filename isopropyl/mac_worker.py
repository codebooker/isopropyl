"""macOS device worker: no Qt, no access to the original user's image folder."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import threading
from pathlib import Path

from .native_devices import discover
from .native_writer import NativeWriter, build_plan

SOURCE_NAMES = {f'source{suffix}' for suffix in ('.iso', '.img', '.raw', '.usb', '.wic')}


def load_request(path: Path):
    parent = path.parent.lstat()
    info = path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077
            or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != parent.st_uid or info.st_mode & 0o022 or info.st_size > 16384):
        raise ValueError('Unsafe worker request directory or file')
    with path.open(encoding='utf-8') as stream:
        request = json.loads(stream.read(16385))
    if request.get('version') != 1 or request.get('operation') not in {'write', 'probe'}:
        raise ValueError('Unsupported worker request')
    if type(request.get('final_verification',False)) is not bool:
        raise ValueError('Invalid final-verification choice')
    name = request.get('source_name')
    if name not in SOURCE_NAMES:
        raise ValueError('Invalid staged source name')
    source = path.parent / name
    source_info = source.lstat()
    if (not stat.S_ISREG(source_info.st_mode) or source_info.st_nlink != 1
            or source_info.st_uid != parent.st_uid or source_info.st_mode & 0o022):
        raise ValueError('Unsafe staged image')
    return request, source


def execute(request_path: Path) -> dict:
    from .host_platform import validate_host
    validate_host(host='darwin')
    request, source = load_request(request_path)
    if request['operation'] == 'probe':
        if source.stat().st_size > 4096:
            raise ValueError('Probe data exceeds its bound')
        return {'ok': True, 'elevated': os.geteuid() == 0, 'sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'write_started': False}
    # The signed authopen service authorizes the descriptor; Python stays a
    # child of the desktop app so TCC can attribute disk access correctly.
    writer = NativeWriter(host='darwin', privilege_check=lambda host: validate_host(host=host),
                          temp_directory=str(request_path.parent))
    writer._worker_private_source = True
    writer.final_verification=request.get("final_verification",False)
    stopped = threading.Event()
    cancel_file = request_path.parent / 'cancel'
    progress_file = request_path.parent / 'progress.json'
    def watch():
        while not stopped.wait(.05):
            if cancel_file.exists():
                writer.cancel()
                return
    watcher = threading.Thread(target=watch, daemon=True)
    descriptor = os.open(progress_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    os.fchmod(descriptor, 0o644)
    watcher.start()
    try:
        candidates = [item for item in discover(request.get('include_fixed') is True, host='darwin')
                      if list(item.identity) == request.get('target_identity')]
        if len(candidates) != 1:
            raise ValueError('The confirmed target identity changed before authorization')
        plan = build_plan(source, candidates[0], include_fixed=request.get('include_fixed') is True,
                          expected_sha256=request['sha256'])
        if cancel_file.exists():
            writer.cancel()
        def progress(stage, done, total):
            data = json.dumps({'stage':stage, 'done':done, 'total':total,
                               'write_started':writer.write_started}).encode('utf-8')
            os.lseek(descriptor, 0, os.SEEK_SET)
            done_bytes = 0
            while done_bytes < len(data):
                count = os.write(descriptor, data[done_bytes:])
                if count <= 0:
                    raise OSError('Could not report device progress')
                done_bytes += count
            os.ftruncate(descriptor, len(data))
        checksum = writer.run(plan, request['confirmation'], progress=progress)
        return {'ok':True, 'sha256':checksum, 'write_started':writer.write_started}
    except Exception as error:
        return {'ok':False, 'error':str(error)[:2048], 'write_started':writer.write_started}
    finally:
        stopped.set()
        watcher.join()
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--request', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = execute(args.request)
    except Exception as error:
        result = {'ok':False, 'error':str(error)[:2048], 'write_started':False}
    print(json.dumps(result), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
