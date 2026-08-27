from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import logging
import os
import secrets
import shutil
import stat
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from .devices import Device, path_is_on_device
from .locking import (
    CooperativeLockError, cooperative_lock_command, lock_conflict_message,
    resolve_flock,
)
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
from .virtual import (
    MAX_DIAGNOSTIC as MAX_QEMU_DIAGNOSTIC,
    PROGRESS_PATTERN,
    FileIdentity,
    ProcessFactory,
    ProcessLike,
    ToolIdentity,
    VirtualDiskError,
    inspect_virtual_disk,
    resolve_qemu_img,
)

Progress = Callable[[int, int], None]
logger = logging.getLogger("isopropyl")
BLOCK_SIZE = 4 * 1024 * 1024
VIRTUAL_BACKUP_HEADROOM = 64 * 1024 * 1024
# QEMU's VPC/VHD driver uses VHD_MAX_SECTORS (0xff000000), a 2040 GiB
# ceiling that is lower than the format's commonly rounded "2 TB" label.
VHD_MAX_SIZE = 0xFF000000 * 512
VHDX_MAX_SIZE = 64 * 1024**4
PROCESS_STOP_TIMEOUT_SECONDS = 2.0
DirectoryIdentity = tuple[int, int]


def _open_bound_directory(path: Path, label: str) -> tuple[int, DirectoryIdentity]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        named = path.lstat()
    except OSError as error:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise WriterSafetyError(f"{label} is not a stable directory: {error}") from error
    identity = (opened.st_dev, opened.st_ino)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or identity != (named.st_dev, named.st_ino)
    ):
        os.close(descriptor)
        raise WriterSafetyError(f"{label} changed while it was being opened")
    return descriptor, identity


def _require_bound_directory(
    path: Path, expected: DirectoryIdentity, label: str,
) -> None:
    try:
        current = path.lstat()
    except OSError as error:
        raise WriterSafetyError(f"{label} moved or became unavailable") from error
    if (
        not stat.S_ISDIR(current.st_mode)
        or (current.st_dev, current.st_ino) != expected
    ):
        raise WriterSafetyError(f"{label} was renamed or replaced during the backup")


def _require_directory_descriptor(
    descriptor: int, expected: DirectoryIdentity, label: str,
) -> None:
    """Require an open descriptor to keep naming the bound directory."""

    try:
        current = os.fstat(descriptor)
    except OSError as error:
        raise WriterSafetyError(f"{label} descriptor became unavailable") from error
    if (
        not stat.S_ISDIR(current.st_mode)
        or (current.st_dev, current.st_ino) != expected
    ):
        raise WriterSafetyError(f"{label} descriptor changed during the backup")


def _create_private_file_at(
    directory: int, *, prefix: str, suffix: str,
) -> tuple[int, str]:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    for _attempt in range(128):
        name = f"{prefix}{secrets.token_hex(12)}{suffix}"
        try:
            return os.open(name, flags, 0o600, dir_fd=directory), name
        except FileExistsError:
            continue
        except OSError as error:
            raise WriterError(
                _bounded_message(error, "Could not create a private backup file")
            ) from error
    raise WriterError("Could not allocate a unique private backup file")


def _create_private_directory_at(
    parent: int, *, prefix: str, suffix: str,
) -> str:
    for _attempt in range(128):
        name = f"{prefix}{secrets.token_hex(12)}{suffix}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            return name
        except FileExistsError:
            continue
        except OSError as error:
            raise VirtualBackupError(
                _bounded_message(error, "Could not create a private backup workspace")
            ) from error
    raise VirtualBackupError("Could not allocate a unique private backup workspace")


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


def _terminate_process_bounded(process: ProcessLike) -> bool:
    """Best-effort terminate/kill/reap without ever escaping cleanup paths."""

    if process.poll() is not None:
        return True
    try:
        process.terminate()
    except OSError:
        return process.poll() is not None
    try:
        process.wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
        return True
    except subprocess.TimeoutExpired:
        pass
    except OSError:
        return process.poll() is not None
    try:
        process.kill()
    except OSError:
        return process.poll() is not None
    try:
        process.wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
    except (subprocess.TimeoutExpired, OSError):
        return process.poll() is not None
    return True


class BackupPublishError(WriterError):
    """A destination link exists, but publication durability is uncertain."""

    def __init__(self, message: str, *, published: bool) -> None:
        super().__init__(message)
        self.published = published


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
        destination_on_device: Callable[[str, Device], bool] = path_is_on_device,
    ) -> None:
        self._which = which
        self._runner = runner
        self._popen = popen
        self._device_lookup = device_lookup
        self._block_stat = block_stat
        self._destination_on_device = destination_on_device
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
    def _terminate_process(process: subprocess.Popen[bytes]) -> bool:
        return _terminate_process_bounded(process)

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
        try:
            temporary.unlink()
        except OSError as error:
            raise BackupPublishError(
                f"The backup was published to {destination}, but its private "
                "temporary link could not be removed; cleanup is incomplete",
                published=True,
            ) from error
        try:
            descriptor = os.open(
                destination.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
        except OSError as error:
            raise BackupPublishError(
                f"The backup was published to {destination}, but publication "
                "durability could not be confirmed",
                published=True,
            ) from error
        try:
            try:
                os.fsync(descriptor)
            except OSError as error:
                raise BackupPublishError(
                    f"The backup was published to {destination}, but its parent "
                    "directory could not be synchronized",
                    published=True,
                ) from error
        finally:
            os.close(descriptor)

    @staticmethod
    def _commit_without_overwrite_at(
        source_directory: int,
        source_name: str,
        destination_directory: int,
        destination_name: str,
        destination: Path,
    ) -> None:
        """Publish through already-bound directory descriptors."""

        try:
            os.link(
                source_name, destination_name,
                src_dir_fd=source_directory,
                dst_dir_fd=destination_directory,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise WriterSafetyError("The backup destination already exists") from error
        except OSError as error:
            raise WriterError(
                _bounded_message(error, "Could not atomically publish the backup image")
            ) from error
        try:
            os.unlink(source_name, dir_fd=source_directory)
        except OSError as error:
            raise BackupPublishError(
                f"The backup was published to {destination}, but its private "
                "temporary link could not be removed; cleanup is incomplete",
                published=True,
            ) from error
        try:
            os.fsync(source_directory)
            if destination_directory != source_directory:
                os.fsync(destination_directory)
        except OSError as error:
            raise BackupPublishError(
                f"The backup was published to {destination}, but its directory "
                "metadata could not be synchronized",
                published=True,
            ) from error

    def _capture_bound(
        self,
        device: Device,
        destination: Path,
        destination_directory: int,
        destination_identity: DirectoryIdentity,
        progress: Progress,
        *,
        sparse: bool,
        tools,
        flock: str,
        binding_check: Callable[[], None],
    ) -> None:
        """Capture and publish through one already-bound directory descriptor."""

        binding_check()
        _require_directory_descriptor(
            destination_directory, destination_identity,
            "The backup destination directory",
        )
        try:
            os.stat(
                destination.name, dir_fd=destination_directory,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as error:
            raise WriterSafetyError(
                _bounded_message(error, "Could not inspect the backup destination")
            ) from error
        else:
            raise WriterSafetyError("The backup destination already exists")
        descriptor, temporary_name = _create_private_file_at(
            destination_directory,
            prefix=f".{destination.name}.", suffix=".partial",
        )
        descriptor_open = True
        published = False
        logger.info(
            "Starting raw backup of %s to %s (%d bytes, sparse=%s)",
            device.path, destination, device.size, sparse,
        )
        try:
            self._revalidate(device, tools)
            command = cooperative_lock_command(
                tools.pkexec, flock, device.path,
                [
                    tools.dd, f"if={device.path}", "bs=4M",
                    f"count={device.size}", "iflag=fullblock,count_bytes",
                    "status=none",
                ],
            )
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
                process_stopped = self._terminate_process(process)
                with self._process_lock:
                    if self._process is process:
                        self._process = None
                if not process_stopped:
                    raise WriterError(
                        "The privileged drive reader could not be reaped after "
                        "terminate and kill"
                    )
            self._check_cancelled()
            if len(diagnostic) > MAX_DIAGNOSTIC_BYTES:
                raise WriterError("Drive reader produced too much diagnostic output")
            if code:
                message = (
                    diagnostic.decode(errors="replace").replace("\x00", "").strip()
                    or "Could not read the drive"
                )
                raise WriterError(lock_conflict_message(code, message))
            if extra:
                raise WriterError("The privileged reader returned more than the bound drive size")
            # Refuse to publish data if the path now names different media.
            self._revalidate(device, tools)
            self._check_cancelled()
            binding_check()
            _require_directory_descriptor(
                destination_directory, destination_identity,
                "The backup destination directory",
            )
            try:
                self._commit_without_overwrite_at(
                    destination_directory, temporary_name,
                    destination_directory, destination.name, destination,
                )
                published = True
            except BackupPublishError as error:
                published = error.published
                raise
            logger.info("Raw backup completed: %s", destination)
        finally:
            if descriptor_open:
                os.close(descriptor)
            with self._process_lock:
                process = self._process
                self._process = None
            if process is not None:
                if not self._terminate_process(process):
                    logger.error(
                        "Privileged drive reader could not be reaped during cleanup"
                    )
            cleanup_error: OSError | None = None
            try:
                os.unlink(temporary_name, dir_fd=destination_directory)
            except FileNotFoundError:
                pass
            except OSError as error:
                cleanup_error = error
            if cleanup_error is not None:
                outcome = (
                    f"The backup was published to {destination}, but"
                    if published else "The backup did not complete, and"
                )
                raise BackupPublishError(
                    f"{outcome} its sensitive private raw file could not be "
                    f"removed: {_bounded_message(cleanup_error, 'cleanup failed')}",
                    published=published,
                ) from cleanup_error

    def _backup_to_bound_directory(
        self,
        device: Device,
        destination: Path,
        destination_directory: int,
        destination_identity: DirectoryIdentity,
        progress: Progress,
        *,
        sparse: bool = False,
        binding_check: Callable[[], None] = lambda: None,
    ) -> None:
        """Internal capture path for a caller-owned, already-bound directory."""

        if self._used:
            raise WriterSafetyError("A drive backup worker cannot be reused")
        self._used = True
        self._check_cancelled()
        validate_device_selection(device, writable=False)
        tools = resolve_writer_tools(self._which)
        try:
            flock = resolve_flock(self._which)
        except CooperativeLockError as error:
            raise WriterError(str(error)) from error
        destination = Path(destination)
        if (
            destination.name in {"", ".", ".."}
            or "/" in destination.name
            or "\x00" in destination.name
        ):
            raise WriterSafetyError("A backup destination file is required")
        current = self._revalidate(device, tools)
        if self._destination_on_device(str(destination), current):
            raise WriterSafetyError(
                "The backup destination is on the drive being imaged"
            )
        binding_check()
        _require_directory_descriptor(
            destination_directory, destination_identity,
            "The backup destination directory",
        )
        self.unmount(device)
        current = self._revalidate(device, tools)
        if self._destination_on_device(str(destination), current):
            raise WriterSafetyError(
                "The backup destination moved onto the drive being imaged"
            )
        binding_check()
        _require_directory_descriptor(
            destination_directory, destination_identity,
            "The backup destination directory",
        )
        self._capture_bound(
            device, destination, destination_directory, destination_identity,
            progress, sparse=sparse, tools=tools, flock=flock,
            binding_check=binding_check,
        )

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
        try:
            flock = resolve_flock(self._which)
        except CooperativeLockError as error:
            raise WriterError(str(error)) from error

        destination = Path(destination).expanduser()
        if destination.name in {"", ".", ".."}:
            raise WriterSafetyError("A backup destination file is required")
        current = self._revalidate(device, tools)
        if self._destination_on_device(str(destination), current):
            raise WriterSafetyError(
                "The backup destination is on the drive being imaged"
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination = destination.parent.resolve(strict=True) / destination.name
        if destination.exists() or destination.is_symlink():
            raise WriterSafetyError("The backup destination already exists")
        if self._destination_on_device(str(destination), current):
            raise WriterSafetyError(
                "The backup destination is on the drive being imaged"
            )
        parent_descriptor, parent_identity = _open_bound_directory(
            destination.parent, "The backup destination directory",
        )

        # Revalidation occurs outside the overridable unmount method as well as
        # inside the default implementation.
        try:
            self.unmount(device)
            current = self._revalidate(device, tools)
            if self._destination_on_device(str(destination), current):
                raise WriterSafetyError(
                    "The backup destination moved onto the drive being imaged"
                )
            _require_bound_directory(
                destination.parent, parent_identity,
                "The backup destination directory",
            )
            self._capture_bound(
                device, destination, parent_descriptor, parent_identity,
                progress, sparse=sparse, tools=tools, flock=flock,
                binding_check=lambda: _require_bound_directory(
                    destination.parent, parent_identity,
                    "The backup destination directory",
                ),
            )
        finally:
            os.close(parent_descriptor)


class VirtualBackupError(WriterError):
    """A raw capture could not be safely converted into a virtual disk."""


class VirtualBackupCleanupError(VirtualBackupError):
    """A virtual backup left private, potentially sensitive data behind."""


def virtual_backup_required_space(size: int) -> int:
    """Return conservative destination space for raw capture plus conversion.

    The final term covers VHD block bitmaps, VHDX metadata/BAT allocation, and
    filesystem rounding without relying on qemu-img producing sparse output.
    """

    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ValueError("Virtual backup size must be a positive integer")
    return size + _virtual_container_required_space(size)


def _virtual_container_required_space(size: int) -> int:
    return size + max(VIRTUAL_BACKUP_HEADROOM, (size + 127) // 128)


def _virtual_backup_format(destination: Path) -> str:
    suffix = destination.suffix.casefold()
    if suffix == ".vhd":
        return "vpc"
    if suffix == ".vhdx":
        return "vhdx"
    raise WriterSafetyError("A virtual backup destination must end in .vhd or .vhdx")


def validate_virtual_backup_destination(size: int, destination: Path) -> str:
    """Validate a requested virtual format/size before any UI confirmation."""

    image_format = _virtual_backup_format(Path(destination))
    VirtualDriveImager._validate_size(image_format, size)
    return image_format


def _private_file_identity(path: Path, expected_size: int, label: str) -> FileIdentity:
    try:
        status = path.lstat()
    except OSError as error:
        message = _bounded_message(error, f"{label} is unavailable")
        raise VirtualBackupError(f"{label} is unavailable: {message}") from error
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
        raise VirtualBackupError(f"{label} is not a private regular file")
    if status.st_size != expected_size:
        raise VirtualBackupError(
            f"{label} has {status.st_size} bytes; expected exactly {expected_size}"
        )
    return FileIdentity(
        status.st_dev, status.st_ino, status.st_size,
        status.st_mtime_ns, status.st_ctime_ns,
    )


def _require_unchanged_private_file(
    path: Path, expected: FileIdentity, expected_size: int, label: str,
) -> None:
    if _private_file_identity(path, expected_size, label) != expected:
        raise VirtualBackupError(f"{label} changed during virtual-disk conversion")


def _cleanup_virtual_backup(
    directory: Path, raw: Path, output: Path,
    *,
    private_descriptor: int | None = None,
    parent_descriptor: int | None = None,
    directory_name: str | None = None,
) -> tuple[str, ...]:
    """Remove only transaction-owned names and report every cleanup failure."""

    issues: list[str] = []
    for path in (raw, output):
        try:
            if private_descriptor is None:
                path.unlink(missing_ok=True)
            else:
                try:
                    os.unlink(path.name, dir_fd=private_descriptor)
                except FileNotFoundError:
                    pass
        except OSError as error:
            issues.append(
                f"could not remove {path.name}: "
                f"{_bounded_message(error, 'filesystem cleanup failed')}"
            )
    try:
        if parent_descriptor is None or directory_name is None:
            directory.rmdir()
        else:
            os.rmdir(directory_name, dir_fd=parent_descriptor)
    except OSError as error:
        issues.append(
            "could not remove the private directory: "
            f"{_bounded_message(error, 'filesystem cleanup failed')}"
        )
    return tuple(issues)


class VirtualDriveImager:
    """Capture a drive exactly, then privately convert and publish VHD/VHDX.

    The destination suffix selects the output format. Instances are single-use,
    matching :class:`DriveImager`; ``cancel()`` covers both capture and qemu-img.
    """

    def __init__(
        self,
        *,
        raw_imager: DriveImager | None = None,
        qemu_img: Path | None = None,
        qemu_runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
        qemu_popen: ProcessFactory = subprocess.Popen,
        disk_usage: Callable[[os.PathLike[str] | str], shutil._ntuple_diskusage] = shutil.disk_usage,
        destination_on_device: Callable[[str, Device], bool] = path_is_on_device,
    ) -> None:
        self._raw_imager = raw_imager or DriveImager()
        self._qemu_img = qemu_img
        self._qemu_runner = qemu_runner
        self._qemu_popen = qemu_popen
        self._disk_usage = disk_usage
        self._destination_on_device = destination_on_device
        self._process: ProcessLike | None = None
        self._process_lock = threading.Lock()
        self._cancelled = threading.Event()
        self._used = False
        self._workspace_path: Path | None = None
        self._workspace_identity: DirectoryIdentity | None = None
        self._parent_path: Path | None = None
        self._parent_identity: DirectoryIdentity | None = None

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    @staticmethod
    def _terminate_process(process: ProcessLike) -> bool:
        return _terminate_process_bounded(process)

    def cancel(self) -> None:
        self._cancelled.set()
        self._raw_imager.cancel()
        with self._process_lock:
            process = self._process
        if process is not None:
            self._terminate_process(process)

    def _check_cancelled(self) -> None:
        if self.cancelled:
            raise WriteCancelled("Drive backup was cancelled")

    def _require_workspace_unchanged(self) -> None:
        if (
            self._workspace_path is None
            or self._workspace_identity is None
            or self._parent_path is None
            or self._parent_identity is None
        ):
            raise VirtualBackupError("The private backup workspace is not bound")
        _require_bound_directory(
            self._parent_path, self._parent_identity,
            "The backup destination directory",
        )
        _require_bound_directory(
            self._workspace_path, self._workspace_identity,
            "The private backup workspace",
        )

    @staticmethod
    def _require_tool(tool: ToolIdentity) -> None:
        try:
            current = resolve_qemu_img(tool.path)
        except VirtualDiskError as error:
            raise VirtualBackupError(str(error)) from error
        if current != tool:
            raise VirtualBackupError("qemu-img changed during the drive backup")

    @staticmethod
    def _validate_size(image_format: str, size: int) -> None:
        if size <= 0 or size % 512:
            raise WriterSafetyError(
                "Virtual drive backups require a positive whole-sector source size"
            )
        maximum = VHD_MAX_SIZE if image_format == "vpc" else VHDX_MAX_SIZE
        if size > maximum:
            display = "VHD" if image_format == "vpc" else "VHDX"
            raise WriterSafetyError(f"The source drive is too large for {display} output")

    def _run_qemu(
        self,
        command: list[str],
        operation: str,
        size: int,
        progress: Progress,
    ) -> tuple[int, bytes]:
        """Run one cancellable qemu-img phase with bounded pipe retention."""

        self._check_cancelled()
        try:
            process = self._qemu_popen(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, shell=False,
            )
        except OSError as error:
            raise VirtualBackupError(
                _bounded_message(error, f"Could not start qemu-img {operation}")
            ) from error
        with self._process_lock:
            self._process = process
        if self.cancelled:
            self._terminate_process(process)
        if process.stdout is None or process.stderr is None:
            self._terminate_process(process)
            raise VirtualBackupError(f"qemu-img {operation} pipes were not available")

        stdout_tail = bytearray()
        stderr_tail = bytearray()
        reader_errors: list[BaseException] = []
        latest_done = 0
        progress_lock = threading.Lock()

        def append_bounded(buffer: bytearray, block: bytes) -> None:
            buffer.extend(block)
            if len(buffer) > MAX_QEMU_DIAGNOSTIC:
                del buffer[:len(buffer) - MAX_QEMU_DIAGNOSTIC]

        def read_stdout() -> None:
            nonlocal latest_done
            scan_tail = b""
            try:
                while block := process.stdout.read(4096):
                    append_bounded(stdout_tail, block)
                    searchable = scan_tail + block
                    for match in PROGRESS_PATTERN.finditer(searchable):
                        percentage = min(100.0, float(match.group(1)))
                        done = min(size, int(size * percentage / 100.0))
                        with progress_lock:
                            if done > latest_done:
                                latest_done = done
                                progress(done, size)
                    scan_tail = searchable[-128:]
            except BaseException as error:
                reader_errors.append(error)
                self._terminate_process(process)

        def read_stderr() -> None:
            try:
                while block := process.stderr.read(4096):
                    append_bounded(stderr_tail, block)
            except BaseException as error:
                reader_errors.append(error)
                self._terminate_process(process)

        threads = (
            threading.Thread(target=read_stdout, daemon=True),
            threading.Thread(target=read_stderr, daemon=True),
        )
        try:
            for thread in threads:
                thread.start()
            while process.poll() is None:
                if self.cancelled or reader_errors:
                    self._terminate_process(process)
                    break
                time.sleep(0.05)
            try:
                code = process.wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired as error:
                self._terminate_process(process)
                raise VirtualBackupError(
                    f"qemu-img {operation} did not stop after cancellation"
                ) from error
            for thread in threads:
                thread.join(timeout=2)
            if any(thread.is_alive() for thread in threads):
                raise VirtualBackupError(f"qemu-img {operation} pipes did not close")
            self._check_cancelled()
            if reader_errors:
                raise reader_errors[0]
            if code == 0:
                with progress_lock:
                    if latest_done < size:
                        progress(size, size)
            return code, bytes(stderr_tail)
        finally:
            self._terminate_process(process)
            with self._process_lock:
                if self._process is process:
                    self._process = None

    def _convert(
        self,
        raw: Path,
        raw_identity: FileIdentity,
        output: Path,
        image_format: str,
        size: int,
        maximum_container_size: int,
        tool: ToolIdentity,
        progress: Progress,
        compare_progress: Progress,
    ) -> FileIdentity:
        self._check_cancelled()
        self._require_workspace_unchanged()
        _require_unchanged_private_file(raw, raw_identity, size, "The private raw capture")
        self._require_tool(tool)
        if output.exists() or output.is_symlink():
            raise VirtualBackupError("The private virtual-disk output already exists")

        command = [
            str(tool.path), "convert", "-p", "-f", "raw", "-T", "none",
            "-O", image_format,
        ]
        if image_format == "vpc":
            command.extend(("-o", "force_size=on"))
        command.extend((str(raw), str(output)))
        code, diagnostic = self._run_qemu(command, "conversion", size, progress)
        if code:
            message = diagnostic.decode(errors="replace").replace("\x00", "").strip()
            raise VirtualBackupError(message or "qemu-img could not convert the drive image")

        self._check_cancelled()
        self._require_workspace_unchanged()
        _require_unchanged_private_file(raw, raw_identity, size, "The private raw capture")
        self._require_tool(tool)
        try:
            output_status = output.lstat()
        except OSError as error:
            raise VirtualBackupError(f"qemu-img did not create its output: {error}") from error
        allocated_size = output_status.st_blocks * 512
        if not stat.S_ISREG(output_status.st_mode) or output_status.st_nlink != 1:
            raise VirtualBackupError("qemu-img output is not a private regular file")
        if (
            output_status.st_size < 512
            or output_status.st_size > maximum_container_size
            or allocated_size > maximum_container_size
        ):
            raise VirtualBackupError("qemu-img output exceeded the bounded container size")
        output.chmod(0o600)
        try:
            with output.open("rb", buffering=0) as stream:
                os.fsync(stream.fileno())
            info = inspect_virtual_disk(
                output, qemu_img=tool.path, runner=self._qemu_runner,
                maximum_virtual_size=size,
            )
        except VirtualDiskError as error:
            raise VirtualBackupError(str(error)) from error
        self._check_cancelled()
        self._require_workspace_unchanged()
        if info.format != image_format or info.virtual_size != size:
            raise VirtualBackupError("qemu-img output has an unexpected format or virtual size")
        if info.has_snapshots:
            raise VirtualBackupError("qemu-img output unexpectedly contains snapshots")
        if info.actual_size is not None and info.actual_size > maximum_container_size:
            raise VirtualBackupError("qemu-img reported an oversized container allocation")
        final_status = output.lstat()
        final_identity = FileIdentity(
            final_status.st_dev, final_status.st_ino,
            final_status.st_size, final_status.st_mtime_ns,
            final_status.st_ctime_ns,
        )
        if (
            not stat.S_ISREG(final_status.st_mode)
            or final_status.st_nlink != 1
            or final_status.st_size > maximum_container_size
            or final_status.st_blocks * 512 > maximum_container_size
            or final_identity != info.identity
        ):
            raise VirtualBackupError("The converted virtual disk changed during validation")
        self._compare(
            raw, raw_identity, output, info.identity, image_format,
            size, maximum_container_size, tool, compare_progress,
        )
        return info.identity

    def _compare(
        self,
        raw: Path,
        raw_identity: FileIdentity,
        output: Path,
        output_identity: FileIdentity,
        image_format: str,
        size: int,
        maximum_container_size: int,
        tool: ToolIdentity,
        progress: Progress,
    ) -> None:
        """Compare guest-visible contents after separately binding exact size."""

        self._check_cancelled()
        self._require_workspace_unchanged()
        _require_unchanged_private_file(raw, raw_identity, size, "The private raw capture")
        self._require_tool(tool)
        before = output.lstat()
        before_identity = FileIdentity(
            before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > maximum_container_size
            or before.st_blocks * 512 > maximum_container_size
            or before_identity != output_identity
        ):
            raise VirtualBackupError("The converted virtual disk changed before comparison")
        command = [
            str(tool.path), "compare", "-p", "-f", "raw", "-F", image_format,
            "-T", "none", str(raw), str(output),
        ]
        code, diagnostic = self._run_qemu(command, "comparison", size, progress)
        self._check_cancelled()
        self._require_workspace_unchanged()
        _require_unchanged_private_file(raw, raw_identity, size, "The private raw capture")
        self._require_tool(tool)
        after = output.lstat()
        after_identity = FileIdentity(
            after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns,
        )
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or after.st_size > maximum_container_size
            or after.st_blocks * 512 > maximum_container_size
            or after_identity != output_identity
        ):
            raise VirtualBackupError("The converted virtual disk changed during comparison")
        if code:
            message = diagnostic.decode(errors="replace").replace("\x00", "").strip()
            if code == 1:
                raise VirtualBackupError(
                    message or "The converted virtual disk does not match the raw capture"
                )
            raise VirtualBackupError(message or "qemu-img could not compare the drive image")

    def backup(self, device: Device, destination: Path, progress: Progress) -> None:
        """Create a non-overwriting VHD/VHDX backup selected by destination suffix."""

        if self._used:
            raise WriterSafetyError("A virtual drive backup worker cannot be reused")
        self._used = True
        self._check_cancelled()
        destination = Path(destination).expanduser()
        if destination.name in {"", ".", ".."}:
            raise WriterSafetyError("A backup destination file is required")
        image_format = validate_virtual_backup_destination(device.size, destination)
        if self._destination_on_device(str(destination), device):
            raise WriterSafetyError(
                "The virtual backup destination is on the drive being imaged"
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination = destination.parent.resolve(strict=True) / destination.name
        if destination.exists() or destination.is_symlink():
            raise WriterSafetyError("The backup destination already exists")
        if self._destination_on_device(str(destination), device):
            raise WriterSafetyError(
                "The virtual backup destination is on the drive being imaged"
            )
        try:
            tool = resolve_qemu_img(self._qemu_img)
        except VirtualDiskError as error:
            raise VirtualBackupError(str(error)) from error
        required = virtual_backup_required_space(device.size)
        try:
            free = self._disk_usage(destination.parent).free
        except OSError as error:
            raise VirtualBackupError(
                _bounded_message(error, "Could not determine backup destination free space")
            ) from error
        if free < required:
            raise VirtualBackupError(
                f"A safe virtual backup needs {required} free bytes for its private raw "
                f"capture and conversion; only {free} bytes are available"
            )

        parent_descriptor, parent_identity = _open_bound_directory(
            destination.parent, "The backup destination directory",
        )
        directory_name = ""
        private_descriptor = -1
        try:
            directory_name = _create_private_directory_at(
                parent_descriptor,
                prefix=f".{destination.name}.", suffix=".private",
            )
            directory = destination.parent / directory_name
            private_descriptor, private_identity = _open_bound_directory(
                directory, "The private backup workspace",
            )
        except BaseException:
            if private_descriptor >= 0:
                os.close(private_descriptor)
            if directory_name:
                try:
                    os.rmdir(directory_name, dir_fd=parent_descriptor)
                except OSError:
                    pass
            os.close(parent_descriptor)
            raise
        self._parent_path = destination.parent
        self._parent_identity = parent_identity
        self._workspace_path = directory
        self._workspace_identity = private_identity
        raw = directory / "capture.raw"
        output = directory / f"converted{destination.suffix.casefold()}"
        total_progress = device.size * 3
        failure: Exception | None = None
        published = False
        cleanup_issues: tuple[str, ...] = ()
        try:
            try:
                self._require_workspace_unchanged()
                self._raw_imager._backup_to_bound_directory(
                    device, raw, private_descriptor, private_identity,
                    lambda done, _total: progress(done, total_progress),
                    sparse=False, binding_check=self._require_workspace_unchanged,
                )
                self._check_cancelled()
                self._require_workspace_unchanged()
                raw_identity = _private_file_identity(
                    raw, device.size, "The private raw capture",
                )
                container_required = _virtual_container_required_space(device.size)
                try:
                    free = self._disk_usage(directory).free
                except OSError as error:
                    raise VirtualBackupError(
                        _bounded_message(error, "Could not recheck conversion free space")
                    ) from error
                if free < container_required:
                    raise VirtualBackupError(
                        "Destination free space changed before virtual-disk conversion"
                    )
                output_identity = self._convert(
                    raw, raw_identity, output, image_format, device.size,
                    container_required, tool,
                    lambda done, _total: progress(device.size + done, total_progress),
                    lambda done, _total: progress(device.size * 2 + done, total_progress),
                )
                self._check_cancelled()
                self._require_workspace_unchanged()
                output_status = output.lstat()
                current_output_identity = FileIdentity(
                    output_status.st_dev, output_status.st_ino,
                    output_status.st_size, output_status.st_mtime_ns,
                    output_status.st_ctime_ns,
                )
                if (
                    not stat.S_ISREG(output_status.st_mode)
                    or output_status.st_nlink != 1
                    or current_output_identity != output_identity
                    or output_status.st_size > container_required
                    or output_status.st_blocks * 512 > container_required
                ):
                    raise VirtualBackupError(
                        "The converted virtual disk changed immediately before publication"
                    )
                try:
                    DriveImager._commit_without_overwrite_at(
                        private_descriptor, output.name,
                        parent_descriptor, destination.name, destination,
                    )
                    published = True
                except BackupPublishError as error:
                    published = error.published
                    raise
                logger.info("Virtual drive backup completed: %s", destination)
            except Exception as error:
                failure = error
        finally:
            with self._process_lock:
                process = self._process
                self._process = None
            process_stopped = (
                process is None or self._terminate_process(process)
            )
            cleanup_issues = _cleanup_virtual_backup(
                directory, raw, output,
                private_descriptor=private_descriptor,
                parent_descriptor=parent_descriptor,
                directory_name=directory_name,
            )
            os.close(private_descriptor)
            os.close(parent_descriptor)
            self._workspace_path = None
            self._workspace_identity = None
            self._parent_path = None
            self._parent_identity = None
            if not process_stopped:
                cleanup_issues += (
                    "a qemu-img child could not be reaped after terminate and kill",
                )
        if cleanup_issues:
            outcome = (
                f"The backup was safely published to {destination}, but"
                if published
                else "The backup did not complete, and"
            )
            original = (
                "; original operation: "
                + _bounded_message(failure, "backup failed")
                if failure is not None else ""
            )
            raise VirtualBackupCleanupError(
                f"{outcome} ISOpropyl could not remove its private workspace at "
                f"{directory}. A sensitive exact raw drive capture may remain there. "
                f"Remove that directory manually after checking the published result. "
                f"Cleanup details: {'; '.join(cleanup_issues)}{original}"
            ) from failure
        if failure is not None:
            raise failure
