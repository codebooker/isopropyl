# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Descriptor-only WIM apply backend for device-free certification.

This module proves the exact wimlib invocation against a regular NTFS image.
It intentionally rejects block devices and is not imported by the GUI,
PolicyKit runner, or privileged helper.  Promoting the backend to block media
still requires root-side topology/mount re-attestation, PREPARED -> COMMIT,
contamination recovery, QEMU/OVMF, and physical certification.
"""

import ctypes
import fcntl
import hashlib
import hmac
import os
import re
import signal
import stat
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .wim import (
    MAX_COMMAND_OUTPUT,
    WimCancelled,
    WimCommandError,
    WimValidationError,
    run_bounded_command,
)

WIMLIB_IMAGEX_PATH = "/usr/bin/wimlib-imagex"
WIM_APPLY_TIMEOUT_SECONDS = 8 * 60 * 60
WIM_HEADER_MAGIC = b"MSWIM\0\0\0"
NTFS_OEM_ID = b"NTFS    "
NTFS_BOOT_BYTES = 512
NTFS_MEDIA_FIXED = 0xF8
NTFS_BOOT_SIGNATURE = b"\x55\xaa"
COPY_BYTES = 4 * 1024 * 1024
MAX_WIM_SOURCE_BYTES = 128 * 1024**3
MAX_NTFS_TARGET_BYTES = 64 * 1024**4
WIM_ATTESTATION_TIMEOUT_SECONDS = 30 * 60
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39


class WimApplyBackendError(RuntimeError):
    """The descriptor-only certification backend failed closed."""


class WimApplyTargetContaminated(WimApplyBackendError):
    """wimlib started and the NTFS image must be reformatted before reuse."""


def _prctl(option: int, argument: int = 0) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(option, argument, 0, 0, 0)
    if result < 0:
        error = ctypes.get_errno()
        raise WimApplyBackendError("The WIM certification process could not be isolated") from OSError(
            error,
            os.strerror(error),
        )
    return int(result)


def lock_down_wim_apply_process() -> None:
    """Deny same-UID access to this process's inherited descriptor table."""

    _prctl(_PR_SET_NO_NEW_PRIVS, 1)
    if _prctl(_PR_GET_NO_NEW_PRIVS) != 1:
        raise WimApplyBackendError("The WIM certification process could gain privileges")
    _prctl(_PR_SET_DUMPABLE, 0)
    if _prctl(_PR_GET_DUMPABLE) != 0:
        raise WimApplyBackendError("The WIM certification process remained dumpable")


def _require_locked_down_process() -> None:
    if _prctl(_PR_GET_DUMPABLE) != 0:
        raise WimApplyBackendError(
            "WIM apply requires a non-dumpable descriptor-owner process",
        )


@dataclass(frozen=True)
class NtfsDescriptorIdentity:
    size: int
    bytes_per_sector: int
    sectors_per_cluster: int
    partition_start_sector: int
    total_sectors: int
    mft_cluster: int
    mft_mirror_cluster: int
    file_record_bytes: int
    index_record_bytes: int
    volume_serial: int
    primary_boot: bytes
    backup_boot: bytes


@dataclass(frozen=True)
class WimApplyCertificationPlan:
    source_size: int
    source_sha256: str
    image_index: int
    target_size: int
    fresh_target_sha256: str
    partition_start_sector: int
    ntfs_volume_serial: int
    temporary_directory: str
    wimlib_imagex: str = WIMLIB_IMAGEX_PATH


@dataclass(frozen=True)
class WimApplyCertificationResult:
    source_size: int
    source_sha256: str
    image_index: int
    target_size: int
    ntfs_volume_serial: int
    missing_integrity_table: bool
    source_read_lease: bool = True
    anonymous_target: bool = True
    target_advisory_lock: bool = True
    descriptor_only: bool = True
    block_devices_supported: bool = False


def _uint(value: object, maximum: int, label: str, *, nonzero: bool = False) -> int:
    if type(value) is not int or value < int(nonzero) or value > maximum:
        qualifier = "non-zero " if nonzero else ""
        raise WimApplyBackendError(f"The {label} must be a {qualifier}unsigned integer")
    return value


def _descriptor_flags(descriptor: int) -> int:
    try:
        return fcntl.fcntl(descriptor, fcntl.F_GETFL)
    except OSError as error:
        raise WimApplyBackendError("A WIM-apply descriptor is unavailable") from error


def _descriptor_status(descriptor: int) -> os.stat_result:
    if type(descriptor) is not int or descriptor < 0:
        raise WimApplyBackendError("A WIM-apply descriptor is invalid")
    try:
        return os.fstat(descriptor)
    except OSError as error:
        raise WimApplyBackendError("A WIM-apply descriptor is unavailable") from error


def _stable_regular_identity(
    status: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_nlink,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _read_exact(descriptor: int, offset: int, size: int) -> bytes:
    payload = bytearray()
    while len(payload) < size:
        try:
            block = os.pread(descriptor, size - len(payload), offset + len(payload))
        except OSError as error:
            raise WimApplyBackendError("A WIM-apply descriptor could not be read") from error
        if not block:
            raise WimApplyBackendError("A WIM-apply descriptor ended unexpectedly")
        payload.extend(block)
    return bytes(payload)


def _check_attestation_budget(
    cancel_event: threading.Event | None,
    deadline: float | None,
) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise WimCancelled("WIM operation was cancelled")
    if deadline is not None and time.monotonic() >= deadline:
        raise WimApplyBackendError("WIM descriptor attestation timed out")


def _hash_descriptor(
    descriptor: int,
    size: int,
    *,
    cancel_event: threading.Event | None = None,
    deadline: float | None = None,
) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        _check_attestation_budget(cancel_event, deadline)
        block = _read_exact(descriptor, offset, min(COPY_BYTES, size - offset))
        digest.update(block)
        offset += len(block)
    _check_attestation_budget(cancel_event, deadline)
    return digest.hexdigest()


def validate_wim_apply_certification_plan(plan: WimApplyCertificationPlan) -> None:
    if type(plan) is not WimApplyCertificationPlan:
        raise WimApplyBackendError("A WimApplyCertificationPlan is required")
    _uint(plan.source_size, MAX_WIM_SOURCE_BYTES, "WIM source size", nonzero=True)
    if (
        type(plan.source_sha256) is not str
        or _SHA256.fullmatch(plan.source_sha256) is None
        or plan.source_sha256 == "0" * 64
    ):
        raise WimApplyBackendError("The WIM source digest is invalid")
    _uint(plan.image_index, 2_147_483_647, "WIM image index", nonzero=True)
    _uint(plan.target_size, MAX_NTFS_TARGET_BYTES, "NTFS target size", nonzero=True)
    if (
        type(plan.fresh_target_sha256) is not str
        or _SHA256.fullmatch(plan.fresh_target_sha256) is None
        or plan.fresh_target_sha256 == "0" * 64
    ):
        raise WimApplyBackendError("The fresh NTFS target digest is invalid")
    _uint(
        plan.partition_start_sector,
        0xFFFFFFFF,
        "NTFS partition start sector",
        nonzero=True,
    )
    _uint(plan.ntfs_volume_serial, 0xFFFFFFFFFFFFFFFF, "NTFS serial", nonzero=True)
    if (
        plan.wimlib_imagex != WIMLIB_IMAGEX_PATH
        or type(plan.temporary_directory) is not str
        or not os.path.isabs(plan.temporary_directory)
        or os.path.normpath(plan.temporary_directory) != plan.temporary_directory
    ):
        raise WimApplyBackendError("The WIM-apply tool or temporary directory is invalid")
    try:
        temporary = os.stat(plan.temporary_directory, follow_symlinks=False)
    except OSError as error:
        raise WimApplyBackendError("The WIM-apply temporary directory is unavailable") from error
    if not stat.S_ISDIR(temporary.st_mode) or temporary.st_mode & 0o077:
        raise WimApplyBackendError("The WIM-apply temporary directory must be private")


def inspect_wim_source_descriptor(
    descriptor: int,
    *,
    expected_size: int,
    expected_sha256: str,
    cancel_event: threading.Event | None = None,
    deadline: float | None = None,
) -> str:
    """Hash and re-attest one seekable, read-only regular WIM descriptor."""

    status = _descriptor_status(descriptor)
    flags = _descriptor_flags(descriptor)
    before = _stable_regular_identity(status)
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or status.st_size != expected_size
        or flags & os.O_ACCMODE != os.O_RDONLY
        or flags & os.O_APPEND
        or _read_exact(descriptor, 0, len(WIM_HEADER_MAGIC)) != WIM_HEADER_MAGIC
    ):
        raise WimApplyBackendError("The inherited WIM descriptor is invalid")
    digest = _hash_descriptor(
        descriptor,
        expected_size,
        cancel_event=cancel_event,
        deadline=deadline,
    )
    after = _stable_regular_identity(_descriptor_status(descriptor))
    if before != after or not hmac.compare_digest(digest, expected_sha256):
        raise WimApplyBackendError("The inherited WIM descriptor changed or has the wrong digest")
    return digest


def inspect_ntfs_target_descriptor(
    descriptor: int,
    *,
    expected_size: int,
    expected_start_sector: int,
    expected_volume_serial: int,
) -> NtfsDescriptorIdentity:
    """Validate a regular NTFS image; block devices are deliberately rejected."""

    status = _descriptor_status(descriptor)
    flags = _descriptor_flags(descriptor)
    if stat.S_ISBLK(status.st_mode):
        raise WimApplyBackendError("Block-device WIM apply is not certified")
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 0
        or status.st_uid != os.geteuid()
        or stat.S_IMODE(status.st_mode) != 0o600
        or status.st_size != expected_size
        or flags & os.O_ACCMODE != os.O_RDWR
        or flags & os.O_APPEND
    ):
        raise WimApplyBackendError(
            "The NTFS certification target must be a private, anonymous descriptor",
        )
    boot = _read_exact(descriptor, 0, NTFS_BOOT_BYTES)
    bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
    sectors_per_cluster = boot[13]
    partition_start_sector = struct.unpack_from("<I", boot, 28)[0]
    total_sectors = struct.unpack_from("<Q", boot, 40)[0]
    mft_cluster = struct.unpack_from("<Q", boot, 48)[0]
    mft_mirror_cluster = struct.unpack_from("<Q", boot, 56)[0]
    volume_serial = struct.unpack_from("<Q", boot, 72)[0]
    cluster_count = total_sectors // sectors_per_cluster if sectors_per_cluster else 0
    cluster_bytes = bytes_per_sector * sectors_per_cluster

    def record_bytes(offset: int) -> int:
        encoded = struct.unpack_from("b", boot, offset)[0]
        if encoded == 0:
            return 0
        value = 1 << -encoded if encoded < 0 else encoded * cluster_bytes
        return value if 512 <= value <= 64 * 1024 and value & (value - 1) == 0 else 0

    file_record_bytes = record_bytes(64)
    index_record_bytes = record_bytes(68)
    backup_boot = (
        _read_exact(descriptor, total_sectors * bytes_per_sector, NTFS_BOOT_BYTES)
        if total_sectors and bytes_per_sector
        else b""
    )
    if (
        boot[:3] not in {b"\xebR\x90", b"\xeb[\x90"}
        or boot[3:11] != NTFS_OEM_ID
        or bytes_per_sector != NTFS_BOOT_BYTES
        or sectors_per_cluster not in {1, 2, 4, 8, 16, 32, 64, 128}
        or boot[14:16] != b"\0\0"
        or boot[16] != 0
        or boot[17:21] != b"\0" * 4
        or boot[21] != NTFS_MEDIA_FIXED
        or boot[22:24] != b"\0\0"
        or partition_start_sector != expected_start_sector
        or total_sectors == 0
        or (total_sectors + 1) * bytes_per_sector != expected_size
        or mft_cluster >= cluster_count
        or mft_mirror_cluster >= cluster_count
        or mft_cluster == mft_mirror_cluster
        or not file_record_bytes
        or not index_record_bytes
        or volume_serial != expected_volume_serial
        or boot[510:512] != NTFS_BOOT_SIGNATURE
        or backup_boot != boot
    ):
        raise WimApplyBackendError("The NTFS certification target BPB is invalid")
    return NtfsDescriptorIdentity(
        status.st_size,
        bytes_per_sector,
        sectors_per_cluster,
        partition_start_sector,
        total_sectors,
        mft_cluster,
        mft_mirror_cluster,
        file_record_bytes,
        index_record_bytes,
        volume_serial,
        boot,
        backup_boot,
    )


def wimlib_apply_command(
    plan: WimApplyCertificationPlan,
    source_descriptor: int,
    target_descriptor: int,
) -> tuple[str, ...]:
    validate_wim_apply_certification_plan(plan)
    _descriptor_status(source_descriptor)
    _descriptor_status(target_descriptor)
    if source_descriptor < 3 or target_descriptor < 3 or source_descriptor == target_descriptor:
        raise WimApplyBackendError("WIM apply requires two distinct inherited descriptors")
    if not (
        os.path.exists(f"/proc/self/fd/{source_descriptor}")
        and os.path.exists(f"/proc/self/fd/{target_descriptor}")
    ):
        raise WimApplyBackendError("Linux proc-fd access is unavailable")
    return (
        plan.wimlib_imagex,
        "apply",
        "--check",
        "--norpfix",
        "--strict-acls",
        "--quiet",
        "--",
        f"/proc/self/fd/{source_descriptor}",
        str(plan.image_index),
        f"/proc/self/fd/{target_descriptor}",
    )


def _trusted_wimlib() -> None:
    try:
        status = os.lstat(WIMLIB_IMAGEX_PATH)
    except OSError as error:
        raise WimApplyBackendError("The fixed wimlib-imagex binary is unavailable") from error
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != 0
        or status.st_mode & 0o022
        or not status.st_mode & 0o111
        or os.path.realpath(WIMLIB_IMAGEX_PATH) != WIMLIB_IMAGEX_PATH
    ):
        raise WimApplyBackendError("The fixed wimlib-imagex binary is not trusted")


def _acquire_target_lock(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        raise WimApplyBackendError(
            "The anonymous NTFS target could not be exclusively locked",
        ) from error


def _release_target_lock(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError as error:
        raise WimApplyBackendError(
            "The anonymous NTFS target lock could not be released",
        ) from error


def _acquire_source_read_lease(
    descriptor: int,
) -> tuple[threading.Event, object]:
    broken = threading.Event()
    try:
        previous = signal.getsignal(signal.SIGIO)
        signal.signal(signal.SIGIO, lambda _signum, _frame: broken.set())
    except (ValueError, OSError) as error:
        raise WimApplyBackendError("A source read lease requires the main helper thread") from error
    try:
        fcntl.fcntl(descriptor, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        if fcntl.fcntl(descriptor, fcntl.F_GETLEASE) != fcntl.F_RDLCK:
            raise OSError("read lease was not retained")
    except OSError as error:
        signal.signal(signal.SIGIO, previous)
        raise WimApplyBackendError("The WIM source could not be write-excluded") from error
    return broken, previous


def _release_source_read_lease(descriptor: int, previous_handler: object) -> None:
    try:
        fcntl.fcntl(descriptor, fcntl.F_SETLEASE, fcntl.F_UNLCK)
    except OSError as error:
        raise WimApplyBackendError("The WIM source read lease could not be released") from error
    finally:
        signal.signal(signal.SIGIO, previous_handler)


def _apply_wim_under_source_lease(
    plan: WimApplyCertificationPlan,
    source_descriptor: int,
    target_descriptor: int,
    *,
    lease_broken: threading.Event,
    cancel_event: threading.Event | None = None,
    popen: type[subprocess.Popen[bytes]] | object = subprocess.Popen,
) -> WimApplyCertificationResult:
    """Apply once to a regular NTFS image, never to a block device."""

    validate_wim_apply_certification_plan(plan)
    if lease_broken.is_set():
        raise WimApplyBackendError("The WIM source read lease was broken before apply")
    _trusted_wimlib()
    preflight_deadline = time.monotonic() + WIM_ATTESTATION_TIMEOUT_SECONDS
    try:
        source_digest = inspect_wim_source_descriptor(
            source_descriptor,
            expected_size=plan.source_size,
            expected_sha256=plan.source_sha256,
            cancel_event=cancel_event,
            deadline=preflight_deadline,
        )
        before = inspect_ntfs_target_descriptor(
            target_descriptor,
            expected_size=plan.target_size,
            expected_start_sector=plan.partition_start_sector,
            expected_volume_serial=plan.ntfs_volume_serial,
        )
        target_digest = _hash_descriptor(
            target_descriptor,
            plan.target_size,
            cancel_event=cancel_event,
            deadline=preflight_deadline,
        )
    except WimCancelled as error:
        raise WimApplyBackendError(str(error)) from error
    if not hmac.compare_digest(target_digest, plan.fresh_target_sha256):
        raise WimApplyBackendError(
            "The NTFS target does not match the fresh-format receipt",
        )
    source_status = _descriptor_status(source_descriptor)
    target_status = _descriptor_status(target_descriptor)
    if (
        source_descriptor == target_descriptor
        or _stable_regular_identity(source_status)
        == _stable_regular_identity(target_status)
    ):
        raise WimApplyBackendError("The WIM source and NTFS target must be distinct")
    command = wimlib_apply_command(plan, source_descriptor, target_descriptor)
    started = False

    def process_started(_process: subprocess.Popen[bytes]) -> None:
        nonlocal started
        started = True

    environment = {
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "TMPDIR": plan.temporary_directory,
    }
    try:
        result = run_bounded_command(
            command,
            timeout_seconds=WIM_APPLY_TIMEOUT_SECONDS,
            max_output=MAX_COMMAND_OUTPUT,
            cancel_event=cancel_event,
            popen=popen,  # type: ignore[arg-type]
            process_started=process_started,
            pass_fds=(source_descriptor, target_descriptor),
            environment=environment,
            working_directory="/",
            new_session=True,
        )
    except (WimCancelled, WimCommandError, WimValidationError) as error:
        if started:
            raise WimApplyTargetContaminated(
                "The WIM apply did not complete; reformat the NTFS target before reuse",
            ) from error
        raise WimApplyBackendError(str(error)) from error
    warning = (
        b'\r[WARNING] "'
        + f"/proc/self/fd/{source_descriptor}".encode("ascii")
        + b'" does not contain integrity information.  Skipping integrity check.\n'
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").replace("\0", "").strip()
        raise WimApplyTargetContaminated(
            detail[:1000] or "wimlib-imagex failed after target access began",
        )
    if result.stdout or result.stderr not in {b"", warning}:
        raise WimApplyTargetContaminated(
            "wimlib-imagex produced an unexpected success diagnostic",
        )
    try:
        os.fsync(target_descriptor)
    except OSError as error:
        raise WimApplyTargetContaminated("The applied NTFS image could not be synced") from error
    if lease_broken.is_set():
        raise WimApplyTargetContaminated("The WIM source read lease broke during apply")
    try:
        validation_deadline = time.monotonic() + WIM_ATTESTATION_TIMEOUT_SECONDS
        source_after = inspect_wim_source_descriptor(
            source_descriptor,
            expected_size=plan.source_size,
            expected_sha256=plan.source_sha256,
            cancel_event=cancel_event,
            deadline=validation_deadline,
        )
        after = inspect_ntfs_target_descriptor(
            target_descriptor,
            expected_size=plan.target_size,
            expected_start_sector=plan.partition_start_sector,
            expected_volume_serial=plan.ntfs_volume_serial,
        )
    except (WimApplyBackendError, WimCancelled) as error:
        raise WimApplyTargetContaminated(
            "Descriptor identity validation failed after WIM apply",
        ) from error
    if source_after != source_digest:
        raise WimApplyTargetContaminated("The WIM source changed during apply")
    if before != after:
        raise WimApplyTargetContaminated("The NTFS target identity changed during apply")
    if lease_broken.is_set():
        raise WimApplyTargetContaminated("The WIM source read lease broke during validation")
    return WimApplyCertificationResult(
        plan.source_size,
        source_digest,
        plan.image_index,
        plan.target_size,
        after.volume_serial,
        result.stderr == warning,
    )


def apply_wim_to_certification_image(
    plan: WimApplyCertificationPlan,
    source_descriptor: int,
    target_descriptor: int,
    *,
    cancel_event: threading.Event | None = None,
    popen: type[subprocess.Popen[bytes]] | object = subprocess.Popen,
) -> WimApplyCertificationResult:
    """Apply to one anonymous image under source and target coordination locks."""

    _require_locked_down_process()
    _acquire_target_lock(target_descriptor)
    try:
        lease_broken, previous_handler = _acquire_source_read_lease(source_descriptor)
        try:
            result = _apply_wim_under_source_lease(
                plan,
                source_descriptor,
                target_descriptor,
                lease_broken=lease_broken,
                cancel_event=cancel_event,
                popen=popen,
            )
        except BaseException:
            try:
                _release_source_read_lease(source_descriptor, previous_handler)
            except WimApplyBackendError:
                pass
            raise
        try:
            _release_source_read_lease(source_descriptor, previous_handler)
        except WimApplyBackendError as error:
            raise WimApplyTargetContaminated(
                "The WIM apply completed but its source lease could not be released",
            ) from error
    except BaseException:
        try:
            _release_target_lock(target_descriptor)
        except WimApplyBackendError:
            pass
        raise
    try:
        _release_target_lock(target_descriptor)
    except WimApplyBackendError as error:
        raise WimApplyTargetContaminated(
            "The WIM apply completed but its target lock could not be released",
        ) from error
    return result
