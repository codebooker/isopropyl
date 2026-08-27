from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .devices import Device, parse_lsblk
from .conflicts import conflict_diagnostic_suffix
from .locking import (
    CooperativeLockError,
    cooperative_lock_command,
    lock_conflict_message,
    resolve_flock,
)
from .sources import (
    ImageSource,
    ImageSourceError,
    SourceIdentity,
    open_image_source,
    sha256_source,
)

Progress = Callable[[int, int], None]
DeviceLookup = Callable[[str], Device | None]
logger = logging.getLogger("isopropyl")

BLOCK_SIZE = 4 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 16 * 1024
MAX_LSBLK_OUTPUT = 1024 * 1024
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_TRUSTED_TOOL_DIRECTORIES = frozenset(_TRUSTED_TOOL_PATH.split(":"))
_WHOLE_DISK = re.compile(
    r"/dev/(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|mmcblk\d+|ubd[a-z]+)"
)
_BLOCK_PATH = re.compile(r"/dev/[A-Za-z0-9._+:-]+")
_MAJOR_MINOR = re.compile(r"\d+:\d+")
_LSBLK_FIELDS = (
    "PATH,SIZE,TYPE,RM,HOTPLUG,TRAN,MODEL,VENDOR,SERIAL,WWN,"
    "MAJ:MIN,MOUNTPOINTS,RO,LOG-SEC"
)


class WriterError(RuntimeError):
    pass


class WriterSafetyError(WriterError):
    pass


class WriterToolUnavailable(WriterError):
    pass


class WriteCancelled(WriterError):
    pass


@dataclass(frozen=True)
class WriterTools:
    pkexec: str
    dd: str
    udisksctl: str
    lsblk: str


def _bounded_message(value: object, fallback: str) -> str:
    rendered = str(value or "").replace("\x00", "").strip()
    return rendered[-MAX_DIAGNOSTIC_BYTES:] if rendered else fallback


def _trusted_which(name: str) -> str | None:
    return shutil.which(name, path=_TRUSTED_TOOL_PATH)


def _validate_tool_path(name: str, value: str | None) -> str:
    if not isinstance(value, str) or not value:
        raise WriterToolUnavailable(f"{name} is required but was not found")
    normalized = os.path.normpath(value)
    if (
        not os.path.isabs(value)
        or normalized != value
        or os.path.dirname(normalized) not in _TRUSTED_TOOL_DIRECTORIES
        or os.path.basename(normalized) != name
    ):
        raise WriterToolUnavailable(f"Refusing untrusted {name} path: {value!r}")
    return normalized


def resolve_writer_tools(
    which: Callable[[str], str | None] = _trusted_which,
) -> WriterTools:
    return WriterTools(**{
        name: _validate_tool_path(name, which(name))
        for name in ("pkexec", "dd", "udisksctl", "lsblk")
    })


def _resolve_writer_flock(
    which: Callable[[str], str | None],
) -> str:
    try:
        return resolve_flock(which)
    except CooperativeLockError as error:
        raise WriterToolUnavailable(str(error)) from error


def _partition_belongs_to_device(device_path: str, partition_path: str) -> bool:
    separator = "p" if device_path[-1].isdigit() else ""
    return re.fullmatch(re.escape(device_path) + separator + r"\d+", partition_path) is not None


def validate_device_selection(device: Device, *, writable: bool) -> None:
    """Validate ISOpropyl's removable/external whole-device safety model."""

    if not isinstance(device, Device):
        raise WriterSafetyError("A discovered removable Device is required")
    if (
        not isinstance(device.path, str)
        or not isinstance(device.size, int)
        or isinstance(device.size, bool)
        or not all(
            isinstance(value, str)
            for value in (
                device.model, device.vendor, device.transport, device.serial,
                device.wwn, device.major_minor,
            )
        )
        or not all(
            isinstance(value, bool)
            for value in (device.removable, device.hotplug, device.read_only)
        )
        or not isinstance(device.mountpoints, tuple)
        or not all(isinstance(value, str) for value in device.mountpoints)
        or not isinstance(device.partitions, tuple)
        or not all(isinstance(value, str) for value in device.partitions)
        or isinstance(device.logical_sector_size, bool)
        or not isinstance(device.logical_sector_size, int)
        or device.logical_sector_size < 0
    ):
        raise WriterSafetyError("The discovered drive information is malformed")
    if not _WHOLE_DISK.fullmatch(device.path):
        raise WriterSafetyError("The target must be a supported whole-disk path under /dev")
    if not _MAJOR_MINOR.fullmatch(device.major_minor):
        raise WriterSafetyError("The drive has no stable kernel major:minor identity")
    if device.size <= 0:
        raise WriterSafetyError("The selected drive has an invalid capacity")
    if writable and device.read_only:
        raise WriterSafetyError("The selected drive is read-only")
    if device.transport not in {"usb", "mmc"}:
        raise WriterSafetyError("Only USB and SD/MMC drives are supported")
    if not device.removable and not (
        device.transport == "usb" and device.hotplug
    ):
        raise WriterSafetyError("The selected drive is not removable or hot-pluggable")
    if "/" in device.mountpoints:
        raise WriterSafetyError("The drive backing the running system is forbidden")
    for partition in device.partitions:
        if (
            not _BLOCK_PATH.fullmatch(partition)
            or not _partition_belongs_to_device(device.path, partition)
        ):
            raise WriterSafetyError(f"Unsafe partition path reported for drive: {partition!r}")


def _run_checked(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    argv: Sequence[str],
    *,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(
            list(argv), capture_output=True, text=True, timeout=timeout, shell=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WriterError(_bounded_message(error, f"Could not run {argv[0]}")) from error
    if len(result.stdout or "") + len(result.stderr or "") > MAX_LSBLK_OUTPUT:
        raise WriterError(f"{Path(argv[0]).name} produced too much output")
    return result


def lookup_device(
    path: str,
    tools: WriterTools,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> Device | None:
    result = _run_checked(
        runner,
        [
            tools.lsblk, "--tree", "--bytes", "--json", "--output",
            _LSBLK_FIELDS, path,
        ],
        timeout=15,
    )
    if result.returncode:
        combined = (result.stdout or "") + (result.stderr or "")
        raise WriterSafetyError(_bounded_message(combined, "lsblk could not inspect the drive"))
    try:
        matches = [
            item for item in parse_lsblk(result.stdout, include_usb_hdds=True)
            if item.path == path
        ]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise WriterSafetyError("lsblk returned invalid drive information") from error
    if len(matches) > 1:
        raise WriterSafetyError("lsblk returned an ambiguous drive identity")
    return matches[0] if matches else None


def revalidate_device(
    expected: Device,
    *,
    writable: bool,
    tools: WriterTools,
    runner: Callable[..., subprocess.CompletedProcess[str]],
    stat_func: Callable[[str], os.stat_result],
    device_lookup: DeviceLookup | None = None,
) -> Device:
    validate_device_selection(expected, writable=writable)
    try:
        current = (
            device_lookup(expected.path) if device_lookup is not None
            else lookup_device(expected.path, tools, runner)
        )
    except WriterError:
        raise
    except (OSError, ValueError) as error:
        raise WriterSafetyError(
            _bounded_message(error, "Could not revalidate the selected drive")
        ) from error
    if current is None or current.identity != expected.identity:
        raise WriterSafetyError(
            "The selected drive disappeared or its identity changed; rescan and select it again"
        )
    if current.logical_sector_size != expected.logical_sector_size:
        raise WriterSafetyError(
            "The selected drive's logical sector size changed; rescan and select it again"
        )
    validate_device_selection(current, writable=writable)
    try:
        status = stat_func(expected.path)
    except OSError as error:
        raise WriterSafetyError(
            _bounded_message(error, "The selected drive is no longer available")
        ) from error
    if not stat.S_ISBLK(status.st_mode):
        raise WriterSafetyError("The selected drive path is not a block device")
    actual = f"{os.major(status.st_rdev)}:{os.minor(status.st_rdev)}"
    if actual != expected.major_minor:
        raise WriterSafetyError(
            "The selected drive's kernel device number changed; rescan and select it again"
        )
    return current


def unmount_device(
    expected: Device,
    *,
    writable: bool,
    tools: WriterTools,
    runner: Callable[..., subprocess.CompletedProcess[str]],
    stat_func: Callable[[str], os.stat_result],
    device_lookup: DeviceLookup | None = None,
    cancel_check: Callable[[], None] = lambda: None,
) -> None:
    current = revalidate_device(
        expected, writable=writable, tools=tools, runner=runner,
        stat_func=stat_func, device_lookup=device_lookup,
    )
    targets = current.partitions or ((current.path,) if current.mountpoints else ())
    for target in targets:
        cancel_check()
        try:
            result = _run_checked(
                runner,
                [tools.udisksctl, "unmount", "--block-device", target],
                timeout=30,
            )
        except WriterError as error:
            raise WriterError(
                str(error) + conflict_diagnostic_suffix(target)
            ) from error
        combined = (result.stdout or "") + (result.stderr or "")
        if result.returncode and not any(
            marker in combined.casefold()
            for marker in ("not mounted", "not a mounted filesystem")
        ):
            message = _bounded_message(combined, f"Could not unmount {target}")
            raise WriterError(message + conflict_diagnostic_suffix(target))
    revalidate_device(
        expected, writable=writable, tools=tools, runner=runner,
        stat_func=stat_func, device_lookup=device_lookup,
    )


class ImageWriter:
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
        self._prepared_identity: SourceIdentity | None = None
        self._prepared_size: int | None = None
        self._prepared_device: Device | None = None

    def _run(self, *args, **kwargs):
        return (self._runner or subprocess.run)(*args, **kwargs)

    def _spawn(self, *args, **kwargs):
        return (self._popen or subprocess.Popen)(*args, **kwargs)

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

    def _set_process(self, process: subprocess.Popen[bytes] | None) -> None:
        with self._process_lock:
            self._process = process

    def cancel(self) -> None:
        self._cancelled.set()
        with self._process_lock:
            process = self._process
        if process is not None:
            self._terminate_process(process)

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def _check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise WriteCancelled("Writing was cancelled")

    def _revalidate(self, device: Device, tools: WriterTools, *, writable: bool) -> Device:
        self._check_cancelled()
        return revalidate_device(
            device, writable=writable, tools=tools, runner=self._run,
            stat_func=self._block_stat, device_lookup=self._device_lookup,
        )

    def unmount(self, device: Device) -> None:
        tools = resolve_writer_tools(self._which)
        unmount_device(
            device, writable=True, tools=tools, runner=self._run,
            stat_func=self._block_stat, device_lookup=self._device_lookup,
            cancel_check=self._check_cancelled,
        )

    @staticmethod
    def _assert_source_bound(source: ImageSource, identity: SourceIdentity, total: int) -> None:
        try:
            current = open_image_source(source.path)
        except (OSError, ImageSourceError) as error:
            raise WriterSafetyError("The selected image is no longer available") from error
        try:
            if current.identity != identity:
                raise WriterSafetyError("The selected image changed after it was measured")
            if not current.compressed and current.identity.size != total:
                raise WriterSafetyError("The selected image size changed after it was measured")
        finally:
            current.close()

    def write(
        self,
        image: Path,
        device: Device,
        progress: Progress,
        *,
        expected_identity: tuple[int, int, int, int, int] | None = None,
    ) -> None:
        self._check_cancelled()
        validate_device_selection(device, writable=True)
        tools = resolve_writer_tools(self._which)
        # Resolve and bind the cooperative lock helper before unmounting or
        # otherwise changing device state.  A missing or forged helper must
        # fail while the selected drive is still untouched.
        flock = _resolve_writer_flock(self._which)
        source = open_image_source(image)
        try:
            observed_identity = (
                source.identity.device, source.identity.inode,
                source.identity.size, source.identity.modified_ns,
                source.identity.changed_ns,
            )
            if expected_identity is not None and observed_identity != expected_identity:
                raise WriterSafetyError(
                    "The selected image changed after confirmation"
                )
            total = source.measure(
                maximum=device.size, cancel_check=self._check_cancelled,
            )
            source_identity = source.identity
            self._prepared_identity = source_identity
            self._prepared_size = total
            self._prepared_device = device
            self._check_cancelled()

            # Revalidate on both sides of unmounting.  This remains outside the
            # overridable unmount method so subclasses cannot bypass the guard.
            self._revalidate(device, tools, writable=True)
            self.unmount(device)
            self._revalidate(device, tools, writable=True)
            self._assert_source_bound(source, source_identity, total)
            self._check_cancelled()
            # Every source is streamed from its one O_NOFOLLOW-bound descriptor.
            # Passing a pathname to privileged dd would reintroduce a
            # check-to-open race after the target has already been unmounted.
            self._write_stream(source, device, tools, flock, total, progress)
        finally:
            source.close()

    def _write_stream(
        self,
        source: ImageSource,
        device: Device,
        tools: WriterTools,
        flock: str,
        total: int,
        progress: Progress,
    ) -> None:
        self._assert_source_bound(source, source.identity, total)
        self._revalidate(device, tools, writable=True)
        command = cooperative_lock_command(
            tools.pkexec,
            flock,
            device.path,
            [
                tools.dd, f"of={device.path}", "bs=4M",
                "conv=fsync", "status=none",
            ],
        )
        logger.info(
            "Starting descriptor-bound %s write to %s (%d bytes)",
            source.compression if source.compressed else "raw",
            device.path, total,
        )
        try:
            process = self._spawn(
                command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, shell=False,
            )
        except OSError as error:
            raise WriterError(_bounded_message(error, "Could not start the privileged writer")) from error
        self._set_process(process)
        if process.stdin is None or process.stderr is None:
            self._terminate_process(process)
            self._set_process(None)
            raise WriterError("Could not open privileged writer pipes")
        done = 0
        code = -1
        diagnostic = b""
        try:
            for block in source.chunks(
                expected_size=total, cancel_check=self._check_cancelled,
            ):
                process.stdin.write(block)
                done += len(block)
                progress(done, total)
            process.stdin.close()
            diagnostic = process.stderr.read(MAX_DIAGNOSTIC_BYTES + 1)
            code = process.wait()
        except BrokenPipeError:
            diagnostic = process.stderr.read(MAX_DIAGNOSTIC_BYTES + 1)
            code = process.wait()
        finally:
            self._terminate_process(process)
            self._set_process(None)
        self._check_cancelled()
        if len(diagnostic) > MAX_DIAGNOSTIC_BYTES:
            raise WriterError("The privileged writer produced too much diagnostic output")
        if code:
            raise WriterError(
                lock_conflict_message(
                    code,
                    diagnostic.decode(errors="replace").replace("\x00", "").strip()
                    or "The privileged writer failed",
                )
            )
        if done != total:
            raise OSError(f"Could only write {done} of {total} decompressed bytes")
        self._assert_source_bound(source, source.identity, total)
        progress(total, total)
        logger.info("Descriptor-bound write completed for %s", device.path)

    def verify(self, image: Path, device_path: str, progress: Progress) -> bool:
        source = open_image_source(image)
        try:
            return self._verify_source(source, device_path, progress)
        finally:
            source.close()

    def _verify_source(
        self,
        source: ImageSource,
        device_path: str,
        progress: Progress,
    ) -> bool:
        self._check_cancelled()

        def checked_progress(done: int, total: int) -> None:
            if self._cancelled.is_set():
                raise WriteCancelled("Verification was cancelled")
            progress(done, total)

        try:
            target_status = self._block_stat(device_path)
        except OSError as error:
            raise WriterSafetyError("The verification target is unavailable") from error
        is_block = stat.S_ISBLK(target_status.st_mode)
        if is_block:
            if (
                self._prepared_device is None
                or self._prepared_device.path != device_path
                or self._prepared_identity is None
                or self._prepared_size is None
            ):
                raise WriterSafetyError(
                    "Block-device verification requires the ImageWriter that performed the write"
                )
            if source.identity != self._prepared_identity:
                raise WriterSafetyError("The selected image changed after it was written")
            size = self._prepared_size
            device = self._prepared_device
        else:
            size = source.measure(cancel_check=self._check_cancelled)
            device = None

        logger.info("Starting SHA-256 read-back verification of %s", device_path)
        verify_total = size * 2
        source_hash = sha256_source(
            source, size,
            lambda done, _total: checked_progress(done, verify_total),
            self._check_cancelled,
        )
        self._check_cancelled()
        if device is None:
            target_hash = sha256_file(
                Path(device_path),
                lambda done, _total: checked_progress(size + done, verify_total),
                size,
            )
            matches = source_hash == target_hash
            logger.info("Read-back verification result for %s: %s", device_path, matches)
            return matches

        tools = resolve_writer_tools(self._which)
        # Verification is read-only, but it still requires a stable snapshot:
        # otherwise a second cooperative writer could change bytes midway
        # through hashing and produce a meaningless result.  Use the same
        # exclusive whole-disk lock for the bounded read-back command.
        flock = _resolve_writer_flock(self._which)
        self._revalidate(device, tools, writable=False)
        command = cooperative_lock_command(
            tools.pkexec,
            flock,
            device.path,
            [
                tools.dd, f"if={device_path}", "bs=4M", f"count={size}",
                "iflag=count_bytes", "status=none",
            ],
        )
        try:
            process = self._spawn(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, shell=False,
            )
        except OSError as error:
            raise WriterError(_bounded_message(error, "Could not start read-back verification")) from error
        self._set_process(process)
        if process.stdout is None or process.stderr is None:
            self._terminate_process(process)
            self._set_process(None)
            raise WriterError("Could not capture verification data")
        digest = hashlib.sha256()
        done = 0
        diagnostic = b""
        code = -1
        try:
            while done < size:
                self._check_cancelled()
                block = process.stdout.read(min(BLOCK_SIZE, size - done))
                if not block:
                    break
                digest.update(block)
                done += len(block)
                checked_progress(size + done, verify_total)
            diagnostic = process.stderr.read(MAX_DIAGNOSTIC_BYTES + 1)
            code = process.wait()
        finally:
            self._terminate_process(process)
            self._set_process(None)
        self._check_cancelled()
        if len(diagnostic) > MAX_DIAGNOSTIC_BYTES:
            raise WriterError("Verification produced too much diagnostic output")
        if code:
            raise WriterError(
                lock_conflict_message(
                    code,
                    diagnostic.decode(errors="replace").replace("\x00", "").strip()
                    or "Could not read the drive for verification",
                )
            )
        if done != size:
            raise OSError(f"Could only verify {done} of {size} bytes")
        matches = source_hash == digest.hexdigest()
        logger.info("Read-back verification result for %s: %s", device_path, matches)
        return matches

    def power_off(self, device: Device) -> bool:
        self._check_cancelled()
        tools = resolve_writer_tools(self._which)
        self._revalidate(device, tools, writable=False)
        result = _run_checked(
            self._run,
            [tools.udisksctl, "power-off", "--block-device", device.path],
            timeout=30,
        )
        success = result.returncode == 0
        logger.info("Power-off result for %s: %s", device.path, success)
        return success


def sha256_file(path: Path, progress: Progress | None = None, limit: int | None = None) -> str:
    total = limit if limit is not None else path.stat().st_size
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise ValueError("Hash length must be a non-negative integer")
    digest = hashlib.sha256()
    done = 0
    with path.open("rb", buffering=0) as stream:
        while done < total:
            block = stream.read(min(BLOCK_SIZE, total - done))
            if not block:
                raise OSError(f"Unexpected end of data after {done} bytes")
            digest.update(block)
            done += len(block)
            if progress:
                progress(done, total)
    return digest.hexdigest()


def verify_image(image: Path, device_path: str, progress: Progress) -> bool:
    """Verify regular-file targets; block devices require an identity-bound writer."""

    with open_image_source(image) as source:
        size = source.measure()
        target = Path(device_path)
        status = target.stat()
        if stat.S_ISBLK(status.st_mode):
            raise WriterSafetyError(
                "Use ImageWriter.verify after ImageWriter.write for a raw block device"
            )
        source_hash = sha256_source(source, size)
        target_hash = sha256_file(target, progress, size)
        return source_hash == target_hash
