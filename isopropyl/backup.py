from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import logging
import os
import subprocess
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from .devices import Device
from .writer import (
    MAX_DIAGNOSTIC_BYTES,
    DeviceLookup,
    WriteCancelled,
    WriterError,
    WriterSafetyError,
    _bounded_message,
    _trusted_which,
    revalidate_device,
    resolve_writer_tools,
    unmount_device,
    validate_device_selection,
)

Progress = Callable[[int, int], None]
logger = logging.getLogger("isopropyl")
BLOCK_SIZE = 4 * 1024 * 1024


def copy_exact(
    source: BinaryIO,
    destination: BinaryIO,
    total: int,
    progress: Progress,
    *,
    sparse: bool = False,
    cancelled: Callable[[], bool] = lambda: False,
) -> None:
    """Copy exactly total bytes, optionally representing zero blocks as holes."""

    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise ValueError("Copy length must be a non-negative integer")
    done = 0
    while done < total:
        if cancelled():
            raise WriteCancelled("Drive backup was cancelled")
        block = source.read(min(BLOCK_SIZE, total - done))
        if not block:
            raise OSError(f"The drive ended after {done} of {total} bytes")
        if sparse and not any(block):
            destination.seek(len(block), os.SEEK_CUR)
        else:
            destination.write(block)
        done += len(block)
        progress(done, total)
    destination.truncate(total)


class DriveImager:
    """Create an identity-bound raw image from removable/external media."""

    def __init__(
        self,
        *,
        which: Callable[[str], str | None] = _trusted_which,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
        popen: Callable[..., subprocess.Popen[bytes]] | None = None,
        device_lookup: DeviceLookup | None = None,
        block_stat: Callable[[str], os.stat_result] = os.stat,
    ) -> None:
        self._which = which
        self._runner = runner
        self._popen = popen
        self._device_lookup = device_lookup
        self._block_stat = block_stat
        self._process: subprocess.Popen[bytes] | None = None
        self._process_lock = threading.Lock()
        self._cancelled = threading.Event()
        self._used = False

    def _run(self, *args, **kwargs):
        return (self._runner or subprocess.run)(*args, **kwargs)

    def _spawn(self, *args, **kwargs):
        return (self._popen or subprocess.Popen)(*args, **kwargs)

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    @staticmethod
    def _terminate_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        except OSError:
            pass

    def cancel(self) -> None:
        self._cancelled.set()
        with self._process_lock:
            process = self._process
        if process is not None:
            self._terminate_process(process)

    def _check_cancelled(self) -> None:
        if self.cancelled:
            raise WriteCancelled("Drive backup was cancelled")

    def _revalidate(self, device: Device, tools) -> Device:
        self._check_cancelled()
        return revalidate_device(
            device, writable=False, tools=tools, runner=self._run,
            stat_func=self._block_stat, device_lookup=self._device_lookup,
        )

    def unmount(self, device: Device) -> None:
        tools = resolve_writer_tools(self._which)
        unmount_device(
            device, writable=False, tools=tools, runner=self._run,
            stat_func=self._block_stat, device_lookup=self._device_lookup,
            cancel_check=self._check_cancelled,
        )

    @staticmethod
    def _commit_without_overwrite(temporary: Path, destination: Path) -> None:
        """Atomically publish a same-filesystem temporary file without clobbering."""

        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError as error:
            raise WriterSafetyError("The backup destination already exists") from error
        except OSError as error:
            raise WriterError(
                _bounded_message(error, "Could not atomically publish the backup image")
            ) from error
        temporary.unlink()
        descriptor = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def backup(
        self,
        device: Device,
        destination: Path,
        progress: Progress,
        *,
        sparse: bool = False,
    ) -> None:
        if self._used:
            raise WriterSafetyError("A drive backup worker cannot be reused")
        self._used = True
        self._check_cancelled()
        validate_device_selection(device, writable=False)
        tools = resolve_writer_tools(self._which)

        destination = Path(destination).expanduser()
        if destination.name in {"", ".", ".."}:
            raise WriterSafetyError("A backup destination file is required")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination = destination.parent.resolve(strict=True) / destination.name
        if destination.exists() or destination.is_symlink():
            raise WriterSafetyError("The backup destination already exists")

        # Revalidation occurs outside the overridable unmount method as well as
        # inside the default implementation.
        self._revalidate(device, tools)
        self.unmount(device)
        self._revalidate(device, tools)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".partial", dir=destination.parent,
        )
        temporary = Path(temporary_name)
        descriptor_open = True
        logger.info(
            "Starting raw backup of %s to %s (%d bytes, sparse=%s)",
            device.path, destination, device.size, sparse,
        )
        try:
            self._revalidate(device, tools)
            command = [
                tools.pkexec, tools.dd, f"if={device.path}", "bs=4M",
                f"count={device.size}", "iflag=fullblock,count_bytes", "status=none",
            ]
            try:
                process = self._spawn(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, shell=False,
                )
            except OSError as error:
                raise WriterError(
                    _bounded_message(error, "Could not start the privileged drive reader")
                ) from error
            with self._process_lock:
                self._process = process
            if process.stdout is None or process.stderr is None:
                self._terminate_process(process)
                raise WriterError("Could not capture privileged drive data")
            output_file = os.fdopen(descriptor, "w+b")
            descriptor_open = False
            diagnostic = b""
            code = -1
            try:
                with output_file as output:
                    copy_exact(
                        process.stdout, output, device.size, progress,
                        sparse=sparse, cancelled=lambda: self.cancelled,
                    )
                    output.flush()
                    os.fsync(output.fileno())
                extra = process.stdout.read(1)
                diagnostic = process.stderr.read(MAX_DIAGNOSTIC_BYTES + 1)
                code = process.wait()
            finally:
                self._terminate_process(process)
                with self._process_lock:
                    if self._process is process:
                        self._process = None
            self._check_cancelled()
            if len(diagnostic) > MAX_DIAGNOSTIC_BYTES:
                raise WriterError("Drive reader produced too much diagnostic output")
            if code:
                raise WriterError(
                    diagnostic.decode(errors="replace").replace("\x00", "").strip()
                    or "Could not read the drive"
                )
            if extra:
                raise WriterError("The privileged reader returned more than the bound drive size")
            # Refuse to publish data if the path now names different media.
            self._revalidate(device, tools)
            self._check_cancelled()
            self._commit_without_overwrite(temporary, destination)
            logger.info("Raw backup completed: %s", destination)
        finally:
            if descriptor_open:
                os.close(descriptor)
            with self._process_lock:
                process = self._process
                self._process = None
            if process is not None:
                self._terminate_process(process)
            temporary.unlink(missing_ok=True)
