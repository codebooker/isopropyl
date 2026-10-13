"""Prepare compressed and sparse sources before a native disk transaction."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .native_writer import (
    BLOCK, NativeWriteError, NativeWritePlan, build_plan, file_identity,
    path_file_identity,
)
from .sources import open_image_source
from .native_virtual import FORMATS, convert_private_container

COMPRESSED = {'.gz', '.gzip', '.bz2', '.bzip2', '.xz', '.lzma', '.zip', '.zst', '.zstd', '.z'}
PREPARED_SUFFIXES = COMPRESSED | {'.vtsi'} | set(FORMATS)


@dataclass(frozen=True)
class PreparedImagePlan(NativeWritePlan):
    """The confirmed original input; expanded size is checked before disk access."""


def build_prepared_plan(path, target, *, include_fixed=False, expected_sha256=None):
    from .native_tools import validate_target
    import re
    validate_target(target, include_fixed)
    if path.suffix.lower() not in PREPARED_SUFFIXES:
        raise NativeWriteError('Choose a supported disk image, compressed image, or VTSI sparse image')
    identity = path_file_identity(path)
    if identity[2] == 0:
        raise NativeWriteError('The selected image is empty')
    if expected_sha256 is not None:
        if not re.fullmatch(r'[0-9a-fA-F]{64}', expected_sha256):
            raise NativeWriteError('Expected SHA-256 must contain exactly 64 hexadecimal characters')
        expected_sha256 = expected_sha256.lower()
    return PreparedImagePlan(path, identity, target, include_fixed, expected_sha256)


def prepare_image(plan, workspace, writer, progress, *, return_source=False):
    """Decode once into a private file; no target handle exists during this phase."""
    if path_file_identity(plan.source) != plan.source_identity:
        raise NativeWriteError('The source image changed after confirmation')
    allowed = {'.img', '.raw', '.usb', '.wic', '.iso'} | set(FORMATS)
    suffix = plan.source.suffix.lower() if plan.source.suffix.lower() in FORMATS else Path(plan.source.stem).suffix.lower()
    if plan.source.suffix.lower() in COMPRESSED and suffix and suffix not in allowed:
        raise NativeWriteError('Compressed input must contain one raw image, ISO, or supported virtual disk; nested compression and apply-format containers are unsupported')
    if suffix not in allowed:
        suffix = '.img'
    output = workspace / ('expanded' + suffix)
    with open_image_source(plan.source, cancel_check=writer.check_cancelled,
                           maximum_sparse_bytes=plan.target.device.size) as source:
        if file_identity(os.fstat(source.fileno())) != plan.source_identity:
            raise NativeWriteError('The source image changed after confirmation')
        if source.requires_exact_target_size:
            size = source.measure(maximum=plan.target.device.size, cancel_check=writer.check_cancelled)
            if size != plan.target.device.size:
                raise NativeWriteError('VTSI requires a target matching its exact advertised disk size')
        if source.compression == 'zip':
            import zipfile
            with source._open_bound_stream(cancel_check=writer.check_cancelled) as stream:
                with zipfile.ZipFile(stream) as archive:
                    member = source._single_zip_member(archive)
                    member_suffix = Path(member.filename).suffix.lower()
                    if member_suffix not in allowed:
                        raise NativeWriteError('ZIP must contain one supported raw image or ISO')
                    output = workspace / ('expanded' + member_suffix)
        # Expected checksums refer to the file selected by the user, including
        # its compression container. Read-back refers to the expanded bytes.
        if plan.expected_sha256:
            from .portable_io import pread
            digest = hashlib.sha256()
            done = 0
            while done < plan.size:
                writer.check_cancelled()
                data = pread(source.fileno(), min(BLOCK, plan.size-done), done)
                if not data:
                    raise NativeWriteError('Source checksum read ended unexpectedly')
                digest.update(data); done += len(data)
                progress('Checking source checksum', done, plan.size)
            if digest.hexdigest() != plan.expected_sha256:
                raise NativeWriteError('Image SHA-256 does not match the expected checksum')
        done = 0
        with output.open('xb') as expanded:
            output.chmod(0o600)
            for data in source.chunks(cancel_check=writer.check_cancelled):
                done += len(data)
                # Container allocation metadata can be larger than the guest
                # disk (notably a tiny VHDX). Bound that overhead separately;
                # QEMU's inspected virtual size must still fit the USB exactly.
                maximum = plan.target.device.size + 64*1024*1024 if output.suffix.lower() in FORMATS else plan.target.device.size
                if done > maximum:
                    raise NativeWriteError('The expanded image is larger than the target')
                if shutil.disk_usage(workspace).free < len(data) + BLOCK:
                    raise NativeWriteError('Not enough temporary space to expand the image')
                expanded.write(data)
                progress('Expanding image', done, max(done, plan.target.device.size))
            expanded.flush(); os.fsync(expanded.fileno())
        if path_file_identity(plan.source) != plan.source_identity:
            raise NativeWriteError('The source image changed during expansion')
    if output.suffix.lower() in FORMATS:
        output = convert_private_container(output, workspace, writer, plan.target.device.size, progress)
    if return_source:return output
    # This also checks sector alignment and the decoded ISO partition map.
    return build_plan(output, plan.target, include_fixed=plan.include_fixed)


def run_prepared_image(plan, confirmation, writer, *, progress=lambda *args: None):
    if writer.used:
        raise NativeWriteError('Each writer can run only once')
    if confirmation != plan.confirmation:
        raise NativeWriteError('The exact erase confirmation was not supplied')
    writer.check_cancelled()
    writer.revalidate(plan)
    with tempfile.TemporaryDirectory(prefix='isopropyl-expand-', dir=writer.temp_directory) as directory:
        expanded = prepare_image(plan, Path(directory), writer, progress)
        if writer.host == 'darwin' and os.geteuid() != 0:
            from .mac_write import run_macos_write
            return run_macos_write(expanded, expanded.confirmation, writer, progress=progress)
        return writer.run(expanded, expanded.confirmation, progress=progress)
