from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Root-side versioned device transactions.

This module is the narrow privileged half of the Syslinux, generic raw/DD, and
target-only fast-zero pipelines.  It does not trust unprivileged plans or their
serialized target observations.  Image-writing callers transfer one already
prepared anonymous regular file; fast-zero accepts no source descriptor at all.
The selected exact protocol derives safety properties from the opened block
descriptor and kernel sysfs, retains one Linux exclusive block-device claim and
one BSD lock through mutation, durability, cache invalidation, and required
read-back, and reports a bounded machine-readable result.

The command-line entry point is only suitable when imported by the installed,
root-owned, isolated launcher.  Source-checkout and user-writable console
scripts are deliberately not accepted by the unprivileged runner.
"""

import array
import errno
import fcntl
import hashlib
import os
import re
import select
import signal
import socket
import stat
import struct
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


HELPER_PROFILE = "io.github.codebooker.isopropyl/syslinux-device-helper/v1"
WINDOWS_HELPER_PROFILE = "io.github.codebooker.isopropyl/windows-device-helper/v1"
RAW_HELPER_PROFILE = "io.github.codebooker.isopropyl/raw-device-helper/v1"
FAST_ZERO_HELPER_PROFILE = "io.github.codebooker.isopropyl/fast-zero-device-helper/v1"
SECTOR_SIZE = 512
COPY_BYTES = 4 * 1024 * 1024
MAX_IMAGE_BYTES = 128 * 1024 * 1024 * 1024
MAX_RAW_SOURCE_BYTES = 64 * 1024 * 1024 * 1024 * 1024
MAX_RAW_TARGET_BYTES = 64 * 1024 * 1024 * 1024 * 1024 * 1024
RAW_FRONT_GUARD_BYTES = 1024 * 1024
FAST_ZERO_BOUNDARY_BYTES = 16 * 1024 * 1024
FAST_ZERO_DEFAULT_CHUNK_BYTES = 32 * 1024 * 1024
MAX_TOPOLOGY_NODES = 4_096
MAX_DIAGNOSTIC_BYTES = 4_096
CONTROL_TIMEOUT_SECONDS = 30.0
SYSLINUX_MBR_602_SHA256 = (
    "4746f74bc9b9d3d579c41988a4a29bb7ac932ad1c70470ea779ea161eb799b64"
)
WINDOWS_STAGE0_SHA256 = (
    "852ac6b9a78d3ed2a092d051ef1674e76f1c0b319d7eb4d7f684067b5951072d"
)
WINDOWS_STAGE2_SHA256 = (
    "127a6e7eda4545ba329c43af810ae9e85587302a9a588fafa05c06b8d6dd3a60"
)
WINDOWS_BOOTMGR_ENTRY_STUB = b"\xe9\xd5\x01\xeb\x04\x90"
WINDOWS_BOOTMGR_MIN_SIZE = 0x1D9
WINDOWS_BOOTMGR_MAX_SIZE = 0x7E000
# SHA-256 of each accepted ldlinux.bss boot sector after zeroing the FAT32 BPB
# (bytes 11..89) and the two installer-patched first-sector pointers.  This
# preserves the independently pinned immutable Syslinux 6.03/6.04-pre1 code
# without teaching the privileged helper how to download or patch payloads.
SYSLINUX_VBR_MASKED_SHA256 = frozenset({
    "80625f5d85eb6ae40ad578620890a84c2b7215fa5f0d6b8c5b13c3f43d39ae93",
    "87bbccd533ebd005132d424fb62fd1427eb41aa6d7a5d7016ccb6b1741476cbe",
})
SYSLINUX_SECTOR1_LOW_OFFSET = 282
SYSLINUX_SECTOR1_HIGH_OFFSET = 288
PARTITION_START_SECTOR = 2_048
RESERVED_SECTORS = 32
FAT_COUNT = 2
MIN_FAT32_CLUSTERS = 65_525

PROTOCOL_MAGIC = b"ISOPROPYL-SYSLX1"
WINDOWS_PROTOCOL_MAGIC = b"ISOPROPYL-WIN001"
RAW_PROTOCOL_MAGIC = b"ISOPROPYL-RAW001"
FAST_ZERO_PROTOCOL_MAGIC = b"ISOPROPYL-ZERO01"
PROTOCOL_VERSION = 1
PACKET_READY = 1
PACKET_REQUEST = 2
PACKET_PROGRESS = 3
PACKET_SUCCESS = 4
PACKET_PREPARED = 5
PACKET_COMMIT = 6
PACKET_CANCEL = 7
PACKET_MUTATION_STARTED = 8
PACKET_PARTIAL_CANCEL = 9
PACKET_PARTIAL_FAILURE = 10
OPERATION = "write-image-v1"
WINDOWS_OPERATION = "write-windows-image-v1"
RAW_OPERATION = "write-raw-image-v1"
FAST_ZERO_OPERATION = "fast-zero-drive-v1"
FAST_ZERO_FAILURE_NONE = 0
FAST_ZERO_FAILURE_CANCELLED = 1
FAST_ZERO_FAILURE_REQUEST = 2
FAST_ZERO_FAILURE_TARGET = 3
FAST_ZERO_FAILURE_VERIFICATION = 4
FAST_ZERO_FAILURE_IO = 5
FAST_ZERO_FAILURE_UNEXPECTED = 255
PHASE_CODES = {
    "source-validation": 1,
    "writing": 2,
    "preactivation-readback": 3,
    "readback": 4,
}
PHASE_NAMES = {value: key for key, value in PHASE_CODES.items()}
FAST_ZERO_PHASE_CODES = {
    "scanning": 1,
    "readback": 2,
    "cleanup": 3,
}
FAST_ZERO_PHASE_NAMES = {
    value: key for key, value in FAST_ZERO_PHASE_CODES.items()
}
_HEADER = struct.Struct("!16sBBH")
_REQUEST_PACKET = struct.Struct("!16sBBH16sIIQQIII32s")
_PROGRESS_PACKET = struct.Struct("!16sBBH16sB3xQQ")
_CONTROL_PACKET = struct.Struct("!16sBBH16s")
_MUTATION_PACKET = _CONTROL_PACKET
_SUCCESS_PACKET = struct.Struct("!16sBBH16sIIQQIII32s32s32s")
_RAW_REQUEST_PACKET = struct.Struct("!16sBBH16sIIQQIQB7s32s")
_RAW_SUCCESS_PACKET = struct.Struct("!16sBBH16sIIQQIQIBB2s32s32s32s")
_FAST_ZERO_REQUEST_PACKET = struct.Struct("!16sBBH16sIIQQII32s32s8s")
_FAST_ZERO_RESULT_PACKET = struct.Struct(
    "!16sBBH16sIIQQIIQQQQQQQQHBBBBB5s"
)
MAX_PROTOCOL_PACKET = max(
    _REQUEST_PACKET.size,
    _RAW_REQUEST_PACKET.size,
    _PROGRESS_PACKET.size,
    _CONTROL_PACKET.size,
    _SUCCESS_PACKET.size,
    _RAW_SUCCESS_PACKET.size,
    _FAST_ZERO_REQUEST_PACKET.size,
    _FAST_ZERO_RESULT_PACKET.size,
)
INSTALLED_HELPER_SCRIPT = "/usr/libexec/isopropyl/syslinux_device_helper.py"

# Linux UAPI values from include/uapi/linux/fs.h.  ISOpropyl currently supports
# only the 64-bit Linux userspace used by its desktop dependencies.
BLKROGET = 0x125E
BLKFLSBUF = 0x1261
BLKSSZGET = 0x1268
BLKGETSIZE64 = 0x80081272
BLKGETDISKSEQ = 0x80081280

_TARGET_PATH = re.compile(
    r"/dev/(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|mmcblk\d+|ubd[a-z]+)\Z",
)
_MAJOR_MINOR = re.compile(r"(?:0|[1-9]\d*):(?:0|[1-9]\d*)\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class HelperError(RuntimeError):
    """A privileged transaction failed closed."""

    exit_code = 5


class HelperRequestError(HelperError):
    exit_code = 2


class HelperSourceError(HelperError):
    exit_code = 3


class HelperTargetError(HelperError):
    exit_code = 4


class HelperVerificationError(HelperError):
    exit_code = 6


class HelperCancelled(HelperError):
    exit_code = 7


@dataclass(frozen=True)
class HelperRequest:
    request_id: bytes
    profile: str
    target_path: str
    expected_major_minor: str
    expected_disk_sequence: int
    expected_size: int
    expected_sector_size: int
    expected_disk_signature: int
    expected_volume_id: int
    expected_sha256: str


@dataclass(frozen=True)
class KernelTargetObservation:
    device_number: int
    related_device_numbers: frozenset[int]
    transport: str
    removable: bool
    read_only: bool
    logical_sector_size: int
    has_holders: bool
    disk_sequence: int


@dataclass(frozen=True)
class HelperResult:
    request_id: bytes
    profile: str
    target_path: str
    major_minor: str
    disk_sequence: int
    bytes_written: int
    source_sha256: str
    written_sha256: str
    readback_sha256: str
    logical_sector_size: int
    disk_signature: int
    volume_id: int
    exclusive_open: bool
    cache_invalidated: bool


@dataclass(frozen=True)
class RawHelperRequest:
    request_id: bytes
    profile: str
    target_path: str
    expected_major_minor: str
    expected_disk_sequence: int
    expected_target_size: int
    expected_sector_size: int
    source_size: int
    source_sha256: str
    final_verification: bool


@dataclass(frozen=True)
class RawHelperResult:
    request_id: bytes
    profile: str
    target_path: str
    major_minor: str
    disk_sequence: int
    target_size: int
    bytes_written: int
    source_sha256: str
    written_sha256: str
    readback_sha256: str
    logical_sector_size: int
    front_guard_bytes: int
    target_tail_sanitized: bool
    final_verification: bool
    exclusive_open: bool
    cache_invalidated: bool


@dataclass(frozen=True)
class FastZeroHelperRequest:
    request_id: bytes
    profile: str
    target_path: str
    expected_major_minor: str
    expected_disk_sequence: int
    expected_target_size: int
    expected_sector_size: int
    chunk_size: int
    plan_sha256: str
    ready_sha256: str


@dataclass(frozen=True)
class FastZeroHelperResult:
    request_id: bytes
    profile: str
    target_path: str
    major_minor: str
    disk_sequence: int
    target_size: int
    logical_sector_size: int
    chunk_size: int
    scanned_bytes: int
    written_bytes: int
    skipped_bytes: int
    verified_bytes: int
    scanned_chunks: int
    written_chunks: int
    skipped_chunks: int
    boundary_cleanup_bytes: int
    failure_code: int
    outcome: str
    exclusive_open: bool
    cache_invalidated: bool
    complete: bool
    cleanup_verified: bool
    durable: bool


Progress = Callable[[str, int, int], None]


@dataclass(frozen=True)
class HelperOperations:
    """Injectable syscall boundary used by non-privileged unit tests."""

    lstat: Callable[[str], os.stat_result] = os.lstat
    stat: Callable[[str], os.stat_result] = os.stat
    fstat: Callable[[int], os.stat_result] = os.fstat
    open: Callable[[str, int], int] = os.open
    close: Callable[[int], None] = os.close
    pread: Callable[[int, int, int], bytes] = os.pread
    pwrite: Callable[[int, bytes, int], int] = os.pwrite
    fsync: Callable[[int], None] = os.fsync
    flock: Callable[[int, int], None] = fcntl.flock
    get_flags: Callable[[int], int] = lambda descriptor: fcntl.fcntl(
        descriptor,
        fcntl.F_GETFL,
    )
    ioctl_uint: Callable[[int, int], int] = lambda descriptor, request: _ioctl_uint(
        descriptor,
        request,
    )
    ioctl_u64: Callable[[int, int], int] = lambda descriptor, request: _ioctl_u64(
        descriptor,
        request,
    )
    ioctl_void: Callable[[int, int], None] = lambda descriptor, request: _ioctl_void(
        descriptor,
        request,
    )
    inspect_target: Callable[[int], KernelTargetObservation] = lambda device_number: (
        inspect_kernel_target(device_number)
    )
    active_devices: Callable[[], frozenset[int]] = lambda: active_kernel_devices()
    inspect_raw_target: Callable[[int], KernelTargetObservation] = lambda device_number: (
        inspect_kernel_target(device_number, allow_fixed_usb=True)
    )


def _bounded(value: object, fallback: str) -> str:
    rendered = str(value or "").replace("\x00", "").strip()
    if not rendered:
        return fallback
    return rendered[-MAX_DIAGNOSTIC_BYTES:]


def _retry(call: Callable[[], object], label: str) -> object:
    while True:
        try:
            return call()
        except InterruptedError:
            continue
        except OSError as error:
            if error.errno == errno.EINTR:
                continue
            raise HelperError(_bounded(error, label)) from error


def _ioctl_uint(descriptor: int, request: int) -> int:
    value = array.array("I", [0])
    while True:
        try:
            fcntl.ioctl(descriptor, request, value, True)
            return int(value[0])
        except InterruptedError:
            continue


def _ioctl_u64(descriptor: int, request: int) -> int:
    value = array.array("Q", [0])
    while True:
        try:
            fcntl.ioctl(descriptor, request, value, True)
            return int(value[0])
        except InterruptedError:
            continue


def _ioctl_void(descriptor: int, request: int) -> None:
    while True:
        try:
            fcntl.ioctl(descriptor, request)
            return
        except InterruptedError:
            continue


def _dev_text(device_number: int) -> str:
    return f"{os.major(device_number)}:{os.minor(device_number)}"


def _target_path_from_kernel(
    device_number: int,
    *,
    sys_root: Path = Path("/sys"),
) -> str:
    uevent = _read_small(
        sys_root / "dev" / "block" / _dev_text(device_number) / "uevent",
        "device uevent",
        maximum=16 * 1024,
    )
    names = [
        line.removeprefix("DEVNAME=")
        for line in uevent.splitlines()
        if line.startswith("DEVNAME=")
    ]
    if len(names) != 1:
        raise HelperTargetError("Kernel target identity has no unambiguous device name")
    path = f"/dev/{names[0]}"
    if _TARGET_PATH.fullmatch(path) is None:
        raise HelperTargetError("Kernel target identity resolved to an unsafe device path")
    return path


def _parse_dev(value: str) -> int:
    rendered = value.strip()
    if _MAJOR_MINOR.fullmatch(rendered) is None:
        raise HelperTargetError("Kernel block topology contains an invalid device number")
    major, minor = (int(part) for part in rendered.split(":", 1))
    try:
        return os.makedev(major, minor)
    except (OverflowError, ValueError) as error:
        raise HelperTargetError("Kernel block topology contains an invalid device number") from error


def _read_small(path: Path, label: str, *, maximum: int = 256) -> str:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise HelperTargetError(_bounded(error, f"Could not read {label}")) from error
    if not data or len(data) > maximum or b"\x00" in data:
        raise HelperTargetError(f"Kernel {label} is malformed")
    try:
        return data.decode("ascii").strip()
    except UnicodeError as error:
        raise HelperTargetError(f"Kernel {label} is malformed") from error


def _resolved_sysfs_node(device_number: int, sys_root: Path) -> Path:
    root = (sys_root / "devices").resolve()
    link = sys_root / "dev" / "block" / _dev_text(device_number)
    try:
        node = link.resolve(strict=True)
        node.relative_to(root)
    except (OSError, RuntimeError, ValueError) as error:
        raise HelperTargetError("The opened target has no trusted kernel sysfs identity") from error
    if _parse_dev(_read_small(node / "dev", "device identity")) != device_number:
        raise HelperTargetError("The opened descriptor and kernel sysfs identity disagree")
    return node


def _related_sysfs_devices(
    start: Path,
    sys_root: Path,
) -> tuple[frozenset[int], bool]:
    devices_root = (sys_root / "devices").resolve()
    pending = [start]
    seen_paths: set[Path] = set()
    numbers: set[int] = set()
    has_holders = False
    while pending:
        node = pending.pop()
        try:
            node = node.resolve(strict=True)
            node.relative_to(devices_root)
        except (OSError, RuntimeError, ValueError) as error:
            raise HelperTargetError("Kernel target topology escaped trusted sysfs") from error
        if node in seen_paths:
            continue
        seen_paths.add(node)
        if len(seen_paths) > MAX_TOPOLOGY_NODES:
            raise HelperTargetError("Kernel target topology is too large")
        numbers.add(_parse_dev(_read_small(node / "dev", "device identity")))
        try:
            children = tuple(node.iterdir())
        except OSError as error:
            raise HelperTargetError("Could not inspect kernel target topology") from error
        for child in children:
            if child.is_dir() and (child / "partition").is_file() and (child / "dev").is_file():
                pending.append(child)
        holders = node / "holders"
        try:
            if holders.is_dir():
                holder_entries = tuple(holders.iterdir())
                has_holders = has_holders or bool(holder_entries)
                pending.extend(holder_entries)
        except OSError as error:
            raise HelperTargetError("Could not inspect kernel target holders") from error
    return frozenset(numbers), has_holders


def _transport_for_node(node: Path, sys_root: Path) -> str:
    devices_root = (sys_root / "devices").resolve()
    current = node
    while True:
        subsystem = current / "subsystem"
        try:
            if subsystem.exists() or subsystem.is_symlink():
                name = subsystem.resolve(strict=True).name
                if name in {"usb", "mmc"}:
                    return name
        except (OSError, RuntimeError):
            raise HelperTargetError("Could not inspect the target transport")
        if current == devices_root:
            break
        parent = current.parent
        if parent == current:
            break
        current = parent
    return ""


def inspect_kernel_target(
    device_number: int,
    *,
    sys_root: Path = Path("/sys"),
    allow_fixed_usb: bool = False,
) -> KernelTargetObservation:
    """Derive whole-disk and transport safety from root-owned kernel sysfs."""

    if type(allow_fixed_usb) is not bool:
        raise HelperTargetError("The fixed-USB target policy is invalid")

    node = _resolved_sysfs_node(device_number, sys_root)
    if (node / "partition").exists():
        raise HelperTargetError("The privileged target must be a whole disk, not a partition")
    removable_text = _read_small(node / "removable", "removable flag")
    read_only_text = _read_small(node / "ro", "read-only flag")
    sector_text = _read_small(
        node / "queue" / "logical_block_size",
        "logical sector size",
    )
    disk_sequence_text = _read_small(node / "diskseq", "disk sequence")
    if removable_text not in {"0", "1"} or read_only_text not in {"0", "1"}:
        raise HelperTargetError("Kernel target flags are malformed")
    try:
        logical_sector_size = int(sector_text, 10)
        disk_sequence = int(disk_sequence_text, 10)
    except ValueError as error:
        raise HelperTargetError("Kernel target geometry or disk sequence is malformed") from error
    if not 0 < disk_sequence <= 0xFFFFFFFFFFFFFFFF:
        raise HelperTargetError("Kernel disk sequence is outside the supported range")
    transport = _transport_for_node(node, sys_root)
    removable = removable_text == "1"
    if transport == "usb" and (removable or allow_fixed_usb):
        pass
    elif transport == "mmc" and removable:
        pass
    else:
        raise HelperTargetError(
            "The privileged target is not an independently verified removable USB or SD/MMC disk",
        )
    related, has_holders = _related_sysfs_devices(node, sys_root)
    return KernelTargetObservation(
        device_number,
        related,
        transport,
        removable,
        read_only_text == "1",
        logical_sector_size,
        has_holders,
        disk_sequence,
    )


def active_kernel_devices(
    *,
    proc_root: Path = Path("/proc"),
    stat_func: Callable[[str], os.stat_result] = os.stat,
) -> frozenset[int]:
    """Return mounted and active-swap device numbers from kernel interfaces."""

    found: set[int] = set()
    try:
        mount_data = (proc_root / "self" / "mountinfo").read_text(
            encoding="utf-8",
            errors="strict",
        )
    except (OSError, UnicodeError) as error:
        raise HelperTargetError("Could not inspect active mounts") from error
    if len(mount_data.encode("utf-8")) > 8 * 1024 * 1024:
        raise HelperTargetError("The active mount table is too large")
    for line in mount_data.splitlines():
        fields = line.split()
        if len(fields) < 6 or "-" not in fields:
            raise HelperTargetError("The active mount table is malformed")
        found.add(_parse_dev(fields[2]))
    try:
        swap_data = (proc_root / "swaps").read_text(
            encoding="utf-8",
            errors="strict",
        )
    except (OSError, UnicodeError) as error:
        raise HelperTargetError("Could not inspect active swap devices") from error
    if len(swap_data.encode("utf-8")) > 1024 * 1024:
        raise HelperTargetError("The active swap table is too large")
    lines = swap_data.splitlines()
    if not lines or not lines[0].startswith("Filename"):
        raise HelperTargetError("The active swap table is malformed")
    for line in lines[1:]:
        fields = line.split()
        if not fields:
            continue
        try:
            status = stat_func(fields[0])
        except OSError as error:
            raise HelperTargetError("An active swap device could not be identified") from error
        if stat.S_ISBLK(status.st_mode):
            found.add(status.st_rdev)
        elif stat.S_ISREG(status.st_mode):
            found.add(status.st_dev)
        else:
            raise HelperTargetError("An active swap source has an unsupported file type")
    return frozenset(found)


def validate_helper_request(request: HelperRequest) -> None:
    if type(request) is not HelperRequest:
        raise HelperRequestError("An exact privileged-helper request is required")
    if type(request.request_id) is not bytes or len(request.request_id) != 16:
        raise HelperRequestError("The privileged request identifier is invalid")
    if request.profile not in {HELPER_PROFILE, WINDOWS_HELPER_PROFILE}:
        raise HelperRequestError("The privileged-helper profile is unsupported")
    if type(request.target_path) is not str or _TARGET_PATH.fullmatch(request.target_path) is None:
        raise HelperRequestError("The privileged target path is invalid")
    if (
        type(request.expected_major_minor) is not str
        or _MAJOR_MINOR.fullmatch(request.expected_major_minor) is None
    ):
        raise HelperRequestError("The expected kernel target identity is invalid")
    if (
        type(request.expected_disk_sequence) is not int
        or isinstance(request.expected_disk_sequence, bool)
        or not 0 < request.expected_disk_sequence <= 0xFFFFFFFFFFFFFFFF
    ):
        raise HelperRequestError("The expected kernel disk sequence is invalid")
    if (
        type(request.expected_size) is not int
        or isinstance(request.expected_size, bool)
        or not SECTOR_SIZE <= request.expected_size <= MAX_IMAGE_BYTES
        or request.expected_size % SECTOR_SIZE
    ):
        raise HelperRequestError("The expected target capacity is invalid")
    if request.expected_sector_size != SECTOR_SIZE:
        raise HelperRequestError("This helper profile requires 512-byte logical sectors")
    if (
        type(request.expected_disk_signature) is not int
        or isinstance(request.expected_disk_signature, bool)
        or not 0 < request.expected_disk_signature < 0xFFFFFFFF
        or type(request.expected_volume_id) is not int
        or isinstance(request.expected_volume_id, bool)
        or not 0 < request.expected_volume_id < 0xFFFFFFFF
        or request.expected_volume_id == request.expected_disk_signature
    ):
        raise HelperRequestError("The expected image media identifiers are invalid")
    if type(request.expected_sha256) is not str or _SHA256.fullmatch(request.expected_sha256) is None:
        raise HelperRequestError("The expected image digest is invalid")


def validate_raw_helper_request(request: RawHelperRequest) -> None:
    if type(request) is not RawHelperRequest:
        raise HelperRequestError("An exact raw-device helper request is required")
    if type(request.request_id) is not bytes or len(request.request_id) != 16:
        raise HelperRequestError("The raw-device request identifier is invalid")
    if request.profile != RAW_HELPER_PROFILE:
        raise HelperRequestError("The raw-device helper profile is unsupported")
    if type(request.target_path) is not str or _TARGET_PATH.fullmatch(request.target_path) is None:
        raise HelperRequestError("The raw-device target path is invalid")
    if (
        type(request.expected_major_minor) is not str
        or _MAJOR_MINOR.fullmatch(request.expected_major_minor) is None
    ):
        raise HelperRequestError("The expected raw-device kernel identity is invalid")
    if (
        type(request.expected_disk_sequence) is not int
        or isinstance(request.expected_disk_sequence, bool)
        or not 0 < request.expected_disk_sequence <= 0xFFFFFFFFFFFFFFFF
    ):
        raise HelperRequestError("The expected raw-device disk sequence is invalid")
    if (
        type(request.expected_target_size) is not int
        or isinstance(request.expected_target_size, bool)
        or not 2 * SECTOR_SIZE
        <= request.expected_target_size
        <= MAX_RAW_TARGET_BYTES
        or request.expected_target_size % SECTOR_SIZE
        or type(request.source_size) is not int
        or isinstance(request.source_size, bool)
        or not 2 * SECTOR_SIZE
        <= request.source_size
        <= min(request.expected_target_size, MAX_RAW_SOURCE_BYTES)
        or request.source_size % SECTOR_SIZE
    ):
        raise HelperRequestError("The raw source or target size is invalid")
    if request.expected_sector_size != SECTOR_SIZE:
        raise HelperRequestError("The raw-device helper requires 512-byte logical sectors")
    if (
        type(request.source_sha256) is not str
        or _SHA256.fullmatch(request.source_sha256) is None
    ):
        raise HelperRequestError("The raw source digest is invalid")
    if type(request.final_verification) is not bool:
        raise HelperRequestError("The raw-device verification policy is invalid")


def validate_fast_zero_helper_request(request: FastZeroHelperRequest) -> None:
    """Validate the one fixed, target-only logical-zero profile."""

    if type(request) is not FastZeroHelperRequest:
        raise HelperRequestError("An exact fast-zero helper request is required")
    if type(request.request_id) is not bytes or len(request.request_id) != 16:
        raise HelperRequestError("The fast-zero request identifier is invalid")
    if request.profile != FAST_ZERO_HELPER_PROFILE:
        raise HelperRequestError("The fast-zero helper profile is unsupported")
    if type(request.target_path) is not str or _TARGET_PATH.fullmatch(request.target_path) is None:
        raise HelperRequestError("The fast-zero target path is invalid")
    if (
        type(request.expected_major_minor) is not str
        or _MAJOR_MINOR.fullmatch(request.expected_major_minor) is None
    ):
        raise HelperRequestError("The expected fast-zero kernel identity is invalid")
    if (
        type(request.expected_disk_sequence) is not int
        or isinstance(request.expected_disk_sequence, bool)
        or not 0 < request.expected_disk_sequence <= 0xFFFFFFFFFFFFFFFF
    ):
        raise HelperRequestError("The expected fast-zero disk sequence is invalid")
    sector = request.expected_sector_size
    if (
        type(sector) is not int
        or isinstance(sector, bool)
        or not 512 <= sector <= 4096
        or sector & (sector - 1)
        or type(request.expected_target_size) is not int
        or isinstance(request.expected_target_size, bool)
        or not sector <= request.expected_target_size <= MAX_RAW_TARGET_BYTES
        or request.expected_target_size % sector
    ):
        raise HelperRequestError("The fast-zero target geometry is invalid")
    if request.chunk_size != FAST_ZERO_DEFAULT_CHUNK_BYTES:
        raise HelperRequestError("The fast-zero chunk profile is unsupported")
    if request.chunk_size % sector:
        raise HelperRequestError("The fast-zero chunk is not sector aligned")
    if (
        type(request.plan_sha256) is not str
        or _SHA256.fullmatch(request.plan_sha256) is None
        or type(request.ready_sha256) is not str
        or _SHA256.fullmatch(request.ready_sha256) is None
    ):
        raise HelperRequestError("The fast-zero authorization receipts are invalid")


def _status_snapshot(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_nlink,
        status.st_uid,
        status.st_gid,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _validate_source_status(
    status: os.stat_result,
    request: HelperRequest,
    invoking_uid: int,
) -> None:
    if not stat.S_ISREG(status.st_mode):
        raise HelperSourceError("Standard input is not the anonymous regular-file image")
    if status.st_nlink != 0:
        raise HelperSourceError("The privileged source image must have no filesystem name")
    if stat.S_IMODE(status.st_mode) != 0o600:
        raise HelperSourceError("The privileged source image must have mode 0600")
    if status.st_uid != invoking_uid:
        raise HelperSourceError("The privileged source image is not owned by the invoking user")
    if status.st_size != request.expected_size:
        raise HelperSourceError("The privileged source size does not match the target capacity")


def _validate_raw_source_status(
    status: os.stat_result,
    request: RawHelperRequest,
    invoking_uid: int,
) -> None:
    if not stat.S_ISREG(status.st_mode):
        raise HelperSourceError("Standard input is not the anonymous raw image")
    if status.st_nlink != 0:
        raise HelperSourceError("The privileged raw source must have no filesystem name")
    if stat.S_IMODE(status.st_mode) != 0o600:
        raise HelperSourceError("The privileged raw source must have mode 0600")
    if status.st_uid != invoking_uid:
        raise HelperSourceError("The privileged raw source is not owned by the invoking user")
    if status.st_size != request.source_size:
        raise HelperSourceError("The privileged raw source size changed")


def _read_exact_at(
    descriptor: int,
    offset: int,
    size: int,
    *,
    read_at: Callable[[int, int, int], bytes],
    label: str,
) -> bytes:
    blocks: list[bytes] = []
    consumed = 0
    while consumed < size:
        try:
            block = read_at(descriptor, size - consumed, offset + consumed)
        except InterruptedError:
            continue
        except OSError as error:
            raise HelperSourceError(_bounded(error, f"Could not read {label}")) from error
        if type(block) is not bytes or not block or len(block) > size - consumed:
            raise HelperSourceError(f"The {label} made invalid read progress")
        blocks.append(block)
        consumed += len(block)
    return b"".join(blocks)


def _canonical_fat32_geometry(image_size: int) -> tuple[int, int, int, int]:
    """Independently derive the private builder's exact FAT32 geometry."""

    image_sectors = image_size // SECTOR_SIZE
    partition_sectors = image_sectors - PARTITION_START_SECTOR
    if partition_sectors <= RESERVED_SECTORS or partition_sectors > 0xFFFFFFFF:
        raise HelperSourceError("The Syslinux image has invalid partition geometry")
    if partition_sectors < 532_480:
        sectors_per_cluster = 1
    elif partition_sectors < 16_777_216:
        sectors_per_cluster = 8
    elif partition_sectors < 33_554_432:
        sectors_per_cluster = 16
    elif partition_sectors < 67_108_864:
        sectors_per_cluster = 32
    else:
        sectors_per_cluster = 64
    sectors_per_fat = max(
        1,
        ((partition_sectors - RESERVED_SECTORS) // sectors_per_cluster + 2)
        * 4
        // SECTOR_SIZE,
    )
    seen: set[int] = set()
    while True:
        data_sectors = partition_sectors - RESERVED_SECTORS - FAT_COUNT * sectors_per_fat
        if data_sectors <= 0:
            raise HelperSourceError("The FAT32 metadata consumes the Syslinux image")
        cluster_count = data_sectors // sectors_per_cluster
        required = (cluster_count + 2) * 4
        required = (required + SECTOR_SIZE - 1) // SECTOR_SIZE
        if required == sectors_per_fat:
            break
        if required in seen:
            sectors_per_fat = max(sectors_per_fat, required)
            break
        seen.add(sectors_per_fat)
        sectors_per_fat = required
    data_start = RESERVED_SECTORS + FAT_COUNT * sectors_per_fat
    cluster_count = (partition_sectors - data_start) // sectors_per_cluster
    if (
        cluster_count < MIN_FAT32_CLUSTERS
        or cluster_count + 2 > 0x0FFFFFF0
        or cluster_count + 2 > sectors_per_fat * SECTOR_SIZE // 4
    ):
        raise HelperSourceError("The image does not have canonical FAT32 geometry")
    return partition_sectors, sectors_per_cluster, sectors_per_fat, cluster_count


def _masked_syslinux_vbr_sha256(boot_sector: bytes) -> str:
    masked = bytearray(boot_sector)
    masked[11:90] = b"\0" * 79
    masked[SYSLINUX_SECTOR1_LOW_OFFSET:SYSLINUX_SECTOR1_LOW_OFFSET + 4] = b"\0" * 4
    masked[SYSLINUX_SECTOR1_HIGH_OFFSET:SYSLINUX_SECTOR1_HIGH_OFFSET + 4] = b"\0" * 4
    return hashlib.sha256(masked).hexdigest()


def _validate_syslinux_image_layout(
    descriptor: int,
    request: HelperRequest,
    *,
    read_at: Callable[[int, int, int], bytes],
) -> bytes:
    """Require the canonical private MBR/FAT32 geometry before target mutation."""

    mbr = _read_exact_at(
        descriptor,
        0,
        SECTOR_SIZE,
        read_at=read_at,
        label="Syslinux MBR",
    )
    volume_offset = PARTITION_START_SECTOR * SECTOR_SIZE
    (
        partition_sectors,
        sectors_per_cluster,
        sectors_per_fat,
        cluster_count,
    ) = _canonical_fat32_geometry(request.expected_size)
    expected_partition = bytearray(16)
    expected_partition[:8] = b"\x80\x20\x21\x00\x0c\xfe\xff\xff"
    struct.pack_into("<I", expected_partition, 8, PARTITION_START_SECTOR)
    struct.pack_into("<I", expected_partition, 12, partition_sectors)
    if (
        mbr[510:512] != b"\x55\xaa"
        or hashlib.sha256(mbr[:440]).hexdigest() != SYSLINUX_MBR_602_SHA256
        or struct.unpack_from("<I", mbr, 440)[0] != request.expected_disk_signature
        or mbr[444:446] != b"\x00\x00"
        or mbr[446:462] != expected_partition
        or any(mbr[462:510])
    ):
        raise HelperSourceError("The anonymous source is not the bound single-partition Syslinux image")
    primary = _read_exact_at(
        descriptor,
        volume_offset,
        SECTOR_SIZE,
        read_at=read_at,
        label="primary FAT32 boot sector",
    )
    backup = _read_exact_at(
        descriptor,
        volume_offset + 6 * SECTOR_SIZE,
        SECTOR_SIZE,
        read_at=read_at,
        label="backup FAT32 boot sector",
    )
    for label, boot in (("primary", primary), ("backup", backup)):
        if (
            boot[510:512] != b"\x55\xaa"
            or boot[:11] != b"\xeb\x58\x90SYSLINUX"
            or struct.unpack_from("<H", boot, 11)[0] != SECTOR_SIZE
            or boot[13] != sectors_per_cluster
            or struct.unpack_from("<H", boot, 14)[0] != RESERVED_SECTORS
            or boot[16] != FAT_COUNT
            or struct.unpack_from("<H", boot, 17)[0] != 0
            or struct.unpack_from("<H", boot, 19)[0] != 0
            or boot[21] != 0xF8
            or struct.unpack_from("<H", boot, 22)[0] != 0
            or struct.unpack_from("<H", boot, 24)[0] != 63
            or struct.unpack_from("<H", boot, 26)[0] != 255
            or struct.unpack_from("<I", boot, 28)[0] != PARTITION_START_SECTOR
            or struct.unpack_from("<I", boot, 32)[0] != partition_sectors
            or struct.unpack_from("<I", boot, 36)[0] != sectors_per_fat
            or struct.unpack_from("<H", boot, 40)[0] != 0
            or struct.unpack_from("<H", boot, 42)[0] != 0
            or struct.unpack_from("<I", boot, 44)[0] != 2
            or struct.unpack_from("<H", boot, 48)[0] != 1
            or struct.unpack_from("<H", boot, 50)[0] != 6
            or any(boot[52:64])
            or boot[64] != 0x80
            or boot[65] != 0
            or boot[66] != 0x29
            or struct.unpack_from("<I", boot, 67)[0] != request.expected_volume_id
            or boot[71:82] != b"ISOPROPYL  "
            or boot[82:90] != b"FAT32   "
        ):
            raise HelperSourceError(f"The {label} FAT32 boot sector is not canonical")
    if primary != backup:
        raise HelperSourceError("The primary and backup Syslinux boot sectors disagree")
    first_loader_sector = struct.unpack_from(
        "<I", primary, SYSLINUX_SECTOR1_LOW_OFFSET,
    )[0]
    first_loader_sector_high = struct.unpack_from(
        "<I", primary, SYSLINUX_SECTOR1_HIGH_OFFSET,
    )[0]
    data_start = RESERVED_SECTORS + FAT_COUNT * sectors_per_fat
    if (
        _masked_syslinux_vbr_sha256(primary) not in SYSLINUX_VBR_MASKED_SHA256
        or first_loader_sector_high != 0
        or not data_start <= first_loader_sector < partition_sectors
    ):
        raise HelperSourceError("The FAT32 VBR is not an exact pinned Syslinux profile")
    fsinfo = _read_exact_at(
        descriptor,
        volume_offset + SECTOR_SIZE,
        SECTOR_SIZE,
        read_at=read_at,
        label="FAT32 FSInfo",
    )
    backup_fsinfo = _read_exact_at(
        descriptor,
        volume_offset + 7 * SECTOR_SIZE,
        SECTOR_SIZE,
        read_at=read_at,
        label="backup FAT32 FSInfo",
    )
    free_clusters = struct.unpack_from("<I", fsinfo, 488)[0]
    next_free = struct.unpack_from("<I", fsinfo, 492)[0]
    expected_next_free = (
        0xFFFFFFFF if free_clusters == 0 else 2 + cluster_count - free_clusters
    )
    canonical_fsinfo = bytearray(SECTOR_SIZE)
    struct.pack_into("<I", canonical_fsinfo, 0, 0x41615252)
    struct.pack_into("<I", canonical_fsinfo, 484, 0x61417272)
    struct.pack_into("<I", canonical_fsinfo, 488, free_clusters)
    struct.pack_into("<I", canonical_fsinfo, 492, next_free)
    struct.pack_into("<I", canonical_fsinfo, 508, 0xAA550000)
    if (
        fsinfo != backup_fsinfo
        or fsinfo != bytes(canonical_fsinfo)
        or free_clusters > cluster_count
        or next_free != expected_next_free
    ):
        raise HelperSourceError("The FAT32 allocation metadata is not canonical")
    return mbr


def _fat32_short_entry(
    descriptor: int,
    *,
    volume_offset: int,
    data_start: int,
    fat_start: int,
    sectors_per_cluster: int,
    cluster_end: int,
    directory_cluster: int,
    short_name: bytes,
    long_name: str | None = None,
    read_at: Callable[[int, int, int], bytes],
) -> tuple[int, int, int]:
    """Find one exact short/LFN entry while bounding every FAT traversal."""

    if len(short_name) != 11 or (long_name is not None and not long_name.isascii()):
        raise HelperSourceError("The Windows FAT lookup name is invalid")

    def short_checksum(value: bytes) -> int:
        checksum = 0
        for byte in value:
            checksum = ((checksum & 1) << 7) + (checksum >> 1) + byte
            checksum &= 0xFF
        return checksum

    def decode_lfn(entries: list[bytes], following_short: bytes) -> str | None:
        if not entries:
            return None
        expected_count = entries[0][0] & 0x1F
        if (
            not entries[0][0] & 0x40
            or expected_count == 0
            or len(entries) != expected_count
        ):
            return None
        checksum = short_checksum(following_short)
        parts: dict[int, bytes] = {}
        for index, entry in enumerate(entries):
            ordinal = entry[0] & 0x1F
            if (
                ordinal != expected_count - index
                or entry[11] != 0x0F
                or entry[12] != 0
                or entry[13] != checksum
                or entry[26:28] != b"\0\0"
            ):
                return None
            parts[ordinal] = entry[1:11] + entry[14:26] + entry[28:32]
        raw = b"".join(parts[index] for index in range(1, expected_count + 1))
        units = [raw[index:index + 2] for index in range(0, len(raw), 2)]
        rendered: list[bytes] = []
        terminated = False
        for unit in units:
            if unit == b"\0\0":
                terminated = True
                continue
            if unit == b"\xff\xff" and terminated:
                continue
            if terminated or unit == b"\xff\xff":
                return None
            rendered.append(unit)
        try:
            return b"".join(rendered).decode("utf-16le", errors="strict")
        except UnicodeDecodeError:
            return None

    visited: set[int] = set()
    cluster = directory_cluster
    pending_lfn: list[bytes] = []
    while True:
        if not 2 <= cluster < cluster_end or cluster in visited:
            raise HelperSourceError("The Windows FAT directory chain is invalid")
        visited.add(cluster)
        if len(visited) > cluster_end - 2:
            raise HelperSourceError("The Windows FAT directory traversal is too large")
        lba = data_start + (cluster - 2) * sectors_per_cluster
        content = _read_exact_at(
            descriptor,
            volume_offset + lba * SECTOR_SIZE,
            sectors_per_cluster * SECTOR_SIZE,
            read_at=read_at,
            label="Windows FAT directory",
        )
        for offset in range(0, len(content), 32):
            entry = content[offset:offset + 32]
            if entry[0] == 0:
                raise HelperSourceError("The required Windows FAT entry is absent")
            if entry[0] == 0xE5:
                pending_lfn.clear()
                continue
            if entry[11] == 0x0F:
                pending_lfn.append(entry)
                continue
            observed_lfn = decode_lfn(pending_lfn, entry[:11])
            pending_lfn.clear()
            if entry[11] & 0x08:
                continue
            if entry[:11] == short_name or (
                long_name is not None and observed_lfn == long_name
            ):
                first_cluster = (
                    struct.unpack_from("<H", entry, 20)[0] << 16
                    | struct.unpack_from("<H", entry, 26)[0]
                )
                return entry[11], first_cluster, struct.unpack_from("<I", entry, 28)[0]
        fat_offset = cluster * 4
        successor = _read_exact_at(
            descriptor,
            volume_offset + fat_start * SECTOR_SIZE + fat_offset,
            4,
            read_at=read_at,
            label="Windows FAT successor",
        )
        cluster = struct.unpack("<I", successor)[0] & 0x0FFFFFFF
        if cluster >= 0x0FFFFFF8:
            raise HelperSourceError("The required Windows FAT entry is absent")


def _validate_windows_image_layout(
    descriptor: int,
    request: HelperRequest,
    *,
    read_at: Callable[[int, int, int], bytes],
) -> bytes:
    """Require the exact project Windows FAT32/BIOS image before mutation."""

    mbr = _read_exact_at(descriptor, 0, SECTOR_SIZE, read_at=read_at, label="Windows MBR")
    volume_offset = PARTITION_START_SECTOR * SECTOR_SIZE
    partition_sectors, sectors_per_cluster, sectors_per_fat, cluster_count = (
        _canonical_fat32_geometry(request.expected_size)
    )
    expected_partition = bytearray(16)
    expected_partition[:8] = b"\x80\x20\x21\x00\x0c\xfe\xff\xff"
    struct.pack_into("<I", expected_partition, 8, PARTITION_START_SECTOR)
    struct.pack_into("<I", expected_partition, 12, partition_sectors)
    if (
        mbr[510:512] != b"\x55\xaa"
        or hashlib.sha256(mbr[:440]).hexdigest() != SYSLINUX_MBR_602_SHA256
        or struct.unpack_from("<I", mbr, 440)[0] != request.expected_disk_signature
        or mbr[444:446] != b"\0\0"
        or mbr[446:462] != expected_partition
        or any(mbr[462:510])
    ):
        raise HelperSourceError("The anonymous source is not the bound Windows MBR image")

    primary = _read_exact_at(
        descriptor, volume_offset, SECTOR_SIZE,
        read_at=read_at, label="primary Windows FAT32 boot sector",
    )
    backup = _read_exact_at(
        descriptor, volume_offset + 6 * SECTOR_SIZE, SECTOR_SIZE,
        read_at=read_at, label="backup Windows FAT32 boot sector",
    )
    template = bytearray(primary)
    template[3:90] = b"\0" * 87
    if (
        primary != backup
        or hashlib.sha256(template).hexdigest() != WINDOWS_STAGE0_SHA256
        or primary[:11] != b"\xeb\x58\x90ISOPROPY"
        or struct.unpack_from("<H", primary, 11)[0] != SECTOR_SIZE
        or primary[13] != sectors_per_cluster
        or struct.unpack_from("<H", primary, 14)[0] != RESERVED_SECTORS
        or primary[16] != FAT_COUNT
        or struct.unpack_from("<H", primary, 17)[0] != 0
        or struct.unpack_from("<H", primary, 19)[0] != 0
        or primary[21] != 0xF8
        or struct.unpack_from("<H", primary, 22)[0] != 0
        or struct.unpack_from("<H", primary, 24)[0] != 63
        or struct.unpack_from("<H", primary, 26)[0] != 255
        or struct.unpack_from("<I", primary, 28)[0] != PARTITION_START_SECTOR
        or struct.unpack_from("<I", primary, 32)[0] != partition_sectors
        or struct.unpack_from("<I", primary, 36)[0] != sectors_per_fat
        or struct.unpack_from("<H", primary, 40)[0] != 0
        or struct.unpack_from("<H", primary, 42)[0] != 0
        or struct.unpack_from("<I", primary, 44)[0] != 2
        or struct.unpack_from("<H", primary, 48)[0] != 1
        or struct.unpack_from("<H", primary, 50)[0] != 6
        or any(primary[52:64])
        or primary[64:67] != b"\x80\0\x29"
        or struct.unpack_from("<I", primary, 67)[0] != request.expected_volume_id
        or primary[71:82] != b"ISOPROPYL  "
        or primary[82:90] != b"FAT32   "
        or primary[510:512] != b"\x55\xaa"
    ):
        raise HelperSourceError("The Windows FAT32 VBR is not the pinned project profile")
    stage = _read_exact_at(
        descriptor, volume_offset + 12 * SECTOR_SIZE, 2 * SECTOR_SIZE,
        read_at=read_at, label="Windows BIOS stage",
    )
    if hashlib.sha256(stage).hexdigest() != WINDOWS_STAGE2_SHA256:
        raise HelperSourceError("The Windows FAT32 BIOS stage does not match its pin")

    fsinfo = _read_exact_at(
        descriptor, volume_offset + SECTOR_SIZE, SECTOR_SIZE,
        read_at=read_at, label="Windows FAT32 FSInfo",
    )
    backup_fsinfo = _read_exact_at(
        descriptor, volume_offset + 7 * SECTOR_SIZE, SECTOR_SIZE,
        read_at=read_at, label="backup Windows FAT32 FSInfo",
    )
    free_clusters = struct.unpack_from("<I", fsinfo, 488)[0]
    next_free = struct.unpack_from("<I", fsinfo, 492)[0]
    expected_next_free = 0xFFFFFFFF if free_clusters == 0 else 2 + cluster_count - free_clusters
    canonical_fsinfo = bytearray(SECTOR_SIZE)
    struct.pack_into("<I", canonical_fsinfo, 0, 0x41615252)
    struct.pack_into("<I", canonical_fsinfo, 484, 0x61417272)
    struct.pack_into("<I", canonical_fsinfo, 488, free_clusters)
    struct.pack_into("<I", canonical_fsinfo, 492, next_free)
    struct.pack_into("<I", canonical_fsinfo, 508, 0xAA550000)
    if (
        fsinfo != backup_fsinfo
        or fsinfo != bytes(canonical_fsinfo)
        or free_clusters > cluster_count
        or next_free != expected_next_free
    ):
        raise HelperSourceError("The Windows FAT32 allocation metadata is not canonical")

    data_start = RESERVED_SECTORS + FAT_COUNT * sectors_per_fat
    cluster_end = cluster_count + 2
    lookup = lambda directory, name, long_name=None: _fat32_short_entry(
        descriptor,
        volume_offset=volume_offset,
        data_start=data_start,
        fat_start=RESERVED_SECTORS,
        sectors_per_cluster=sectors_per_cluster,
        cluster_end=cluster_end,
        directory_cluster=directory,
        short_name=name,
        long_name=long_name,
        read_at=read_at,
    )
    bootmgr_attr, bootmgr_cluster, bootmgr_size = lookup(2, b"BOOTMGR    ")
    boot_attr, boot_cluster, _ = lookup(2, b"BOOT       ", "Boot")
    efi_attr, efi_cluster, _ = lookup(2, b"EFI        ")
    bcd_attr, bcd_cluster, bcd_size = lookup(boot_cluster, b"BCD        ")
    efi_boot_attr, efi_boot_cluster, _ = lookup(efi_cluster, b"BOOT       ")
    bootx64_attr, bootx64_cluster, bootx64_size = lookup(
        efi_boot_cluster, b"BOOTX64 EFI",
    )
    if (
        bootmgr_attr & 0x18
        or not WINDOWS_BOOTMGR_MIN_SIZE <= bootmgr_size <= WINDOWS_BOOTMGR_MAX_SIZE
        or not 2 <= bootmgr_cluster < cluster_end
        or not boot_attr & 0x10
        or not efi_attr & 0x10
        or bcd_attr & 0x18
        or bcd_size == 0
        or not 2 <= bcd_cluster < cluster_end
        or not efi_boot_attr & 0x10
        or bootx64_attr & 0x18
        or bootx64_size == 0
        or not 2 <= bootx64_cluster < cluster_end
    ):
        raise HelperSourceError("The required Windows BIOS/UEFI files are invalid")
    bootmgr_offset = volume_offset + (
        data_start + (bootmgr_cluster - 2) * sectors_per_cluster
    ) * SECTOR_SIZE
    if _read_exact_at(
        descriptor, bootmgr_offset, len(WINDOWS_BOOTMGR_ENTRY_STUB),
        read_at=read_at, label="Windows BOOTMGR entry stub",
    ) != WINDOWS_BOOTMGR_ENTRY_STUB:
        raise HelperSourceError("The Windows BOOTMGR entry stub is unsupported")
    return mbr


def _hash_descriptor(
    descriptor: int,
    size: int,
    *,
    read_at: Callable[[int, int, int], bytes],
    progress: Progress,
    phase: str,
) -> str:
    digest = hashlib.sha256()
    offset = 0
    progress(phase, 0, size)
    while offset < size:
        wanted = min(COPY_BYTES, size - offset)
        try:
            block = read_at(descriptor, wanted, offset)
        except InterruptedError:
            continue
        except OSError as error:
            raise HelperError(_bounded(error, f"Could not read during {phase}")) from error
        if type(block) is not bytes or not block or len(block) > wanted:
            raise HelperError(f"{phase} made invalid read progress")
        digest.update(block)
        offset += len(block)
        progress(phase, offset, size)
    return digest.hexdigest()


def _write_exact(
    descriptor: int,
    data: bytes,
    offset: int,
    *,
    write_at: Callable[[int, bytes, int], int],
) -> None:
    written = 0
    while written < len(data):
        try:
            count = write_at(descriptor, data[written:], offset + written)
        except InterruptedError:
            continue
        except OSError as error:
            raise HelperError(_bounded(error, "The target write failed")) from error
        if (
            type(count) is not int
            or count <= 0
            or count > len(data) - written
        ):
            raise HelperError("The target write made invalid progress")
        written += count


def _validate_target_observation(
    observation: KernelTargetObservation,
    request: HelperRequest,
    device_number: int,
    active: frozenset[int],
    source_device: int,
) -> None:
    if type(observation) is not KernelTargetObservation:
        raise HelperTargetError("Kernel target inspection returned invalid evidence")
    if (
        observation.device_number != device_number
        or device_number not in observation.related_device_numbers
        or observation.transport not in {"usb", "mmc"}
        or not observation.removable
        or observation.read_only
        or observation.logical_sector_size != request.expected_sector_size
        or observation.has_holders
        or observation.disk_sequence != request.expected_disk_sequence
    ):
        raise HelperTargetError("Kernel target safety properties do not match this request")
    if observation.related_device_numbers & active:
        raise HelperTargetError("The selected target or one of its dependants is mounted or active swap")
    if source_device in observation.related_device_numbers:
        raise HelperTargetError("The anonymous source image resides on the selected target")


def _require_opened_target_identity(
    descriptor: int,
    request: HelperRequest,
    device_number: int,
    operations: HelperOperations,
    *,
    verification: bool,
) -> None:
    error_type = HelperVerificationError if verification else HelperTargetError
    try:
        status = operations.fstat(descriptor)
        size = operations.ioctl_u64(descriptor, BLKGETSIZE64)
        disk_sequence = operations.ioctl_u64(descriptor, BLKGETDISKSEQ)
        sector_size = operations.ioctl_uint(descriptor, BLKSSZGET)
        read_only = operations.ioctl_uint(descriptor, BLKROGET)
    except OSError as error:
        raise error_type("Could not revalidate the opened target identity") from error
    if (
        not stat.S_ISBLK(status.st_mode)
        or status.st_rdev != device_number
        or size != request.expected_size
        or disk_sequence != request.expected_disk_sequence
        or sector_size != request.expected_sector_size
        or read_only != 0
    ):
        raise error_type("The opened target is no longer the authorized disk generation")


def execute_helper_transaction(
    request: HelperRequest,
    *,
    source_descriptor: int = 0,
    invoking_uid: int,
    operations: HelperOperations = HelperOperations(),
    progress: Progress = lambda _phase, _done, _total: None,
    mutation_started: Callable[[], None] = lambda: None,
) -> HelperResult:
    """Execute one fail-closed, same-target-descriptor disk transaction."""

    validate_helper_request(request)
    if type(source_descriptor) is not int or isinstance(source_descriptor, bool) or source_descriptor < 0:
        raise HelperSourceError("The privileged source descriptor is invalid")
    if type(invoking_uid) is not int or isinstance(invoking_uid, bool) or invoking_uid < 0:
        raise HelperRequestError("The invoking user identity is invalid")
    try:
        source_before = operations.fstat(source_descriptor)
        source_flags = operations.get_flags(source_descriptor)
    except OSError as error:
        raise HelperSourceError(_bounded(error, "Could not inspect the anonymous source image")) from error
    _validate_source_status(source_before, request, invoking_uid)
    if source_flags & os.O_ACCMODE != os.O_RDWR or source_flags & os.O_APPEND:
        raise HelperSourceError("The anonymous source descriptor has unsafe access flags")
    try:
        operations.flock(source_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        raise HelperSourceError("The anonymous source image is not exclusively owned") from error
    source_mbr = (
        _validate_windows_image_layout(
            source_descriptor,
            request,
            read_at=operations.pread,
        )
        if request.profile == WINDOWS_HELPER_PROFILE
        else _validate_syslinux_image_layout(
            source_descriptor,
            request,
            read_at=operations.pread,
        )
    )
    source_sha256 = _hash_descriptor(
        source_descriptor,
        request.expected_size,
        read_at=operations.pread,
        progress=progress,
        phase="source-validation",
    )
    if source_sha256 != request.expected_sha256:
        raise HelperSourceError("The anonymous source image failed its bound SHA-256")
    try:
        source_after_hash = operations.fstat(source_descriptor)
    except OSError as error:
        raise HelperSourceError("The anonymous source image disappeared") from error
    if _status_snapshot(source_after_hash) != _status_snapshot(source_before):
        raise HelperSourceError("The anonymous source image changed during validation")

    try:
        path_status = operations.lstat(request.target_path)
    except OSError as error:
        raise HelperTargetError(_bounded(error, "The selected target is unavailable")) from error
    if not stat.S_ISBLK(path_status.st_mode):
        raise HelperTargetError("The privileged target path is not a block device")
    expected_device_number = _parse_dev(request.expected_major_minor)
    if path_status.st_rdev != expected_device_number:
        raise HelperTargetError("The privileged target path changed kernel identity")
    pre_observation = operations.inspect_target(expected_device_number)
    _validate_target_observation(
        pre_observation,
        request,
        expected_device_number,
        operations.active_devices(),
        source_before.st_dev,
    )

    flags = (
        os.O_RDWR
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    target_descriptor = -1
    activation_attempted = False
    try:
        try:
            target_descriptor = operations.open(request.target_path, flags)
        except OSError as error:
            if error.errno == errno.EBUSY:
                raise HelperTargetError(
                    "The target is mounted, claimed, or busy",
                ) from error
            raise HelperTargetError(_bounded(error, "Could not exclusively open the target")) from error
        try:
            operations.flock(target_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise HelperTargetError("Another lock-aware process is using the target") from error
        try:
            opened_status = operations.fstat(target_descriptor)
            target_size = operations.ioctl_u64(target_descriptor, BLKGETSIZE64)
            disk_sequence = operations.ioctl_u64(target_descriptor, BLKGETDISKSEQ)
            sector_size = operations.ioctl_uint(target_descriptor, BLKSSZGET)
            read_only = operations.ioctl_uint(target_descriptor, BLKROGET)
        except OSError as error:
            raise HelperTargetError(_bounded(error, "Could not inspect the opened target")) from error
        if not stat.S_ISBLK(opened_status.st_mode):
            raise HelperTargetError("The exclusively opened target is not a block device")
        if opened_status.st_rdev != expected_device_number:
            raise HelperTargetError("The exclusively opened target has the wrong kernel identity")
        if target_size != request.expected_size:
            raise HelperTargetError("The opened target capacity changed or does not match the image")
        if disk_sequence != request.expected_disk_sequence:
            raise HelperTargetError("The opened target is not the authorized disk generation")
        if sector_size != request.expected_sector_size:
            raise HelperTargetError("The opened target logical sector size changed")
        if read_only != 0:
            raise HelperTargetError("The opened target is read-only")
        live_observation = operations.inspect_target(opened_status.st_rdev)
        _validate_target_observation(
            live_observation,
            request,
            opened_status.st_rdev,
            operations.active_devices(),
            source_before.st_dev,
        )
        try:
            current_path = operations.lstat(request.target_path)
        except OSError as error:
            raise HelperTargetError("The target path disappeared after exclusive open") from error
        if current_path.st_rdev != opened_status.st_rdev or not stat.S_ISBLK(current_path.st_mode):
            raise HelperTargetError("The target path was replaced during exclusive open")
        try:
            source_before_write = operations.fstat(source_descriptor)
        except OSError as error:
            raise HelperSourceError("The anonymous source image disappeared before writing") from error
        if _status_snapshot(source_before_write) != _status_snapshot(source_before):
            raise HelperSourceError("The anonymous source image changed before writing")

        # From this point ordinary cancellation is deferred until durability
        # and verification complete.  SIGKILL or hardware removal can still
        # interrupt the transaction, so sector-zero-last remains essential.
        mutation_started()
        _require_opened_target_identity(
            target_descriptor,
            request,
            expected_device_number,
            operations,
            verification=False,
        )
        try:
            committed_path = operations.lstat(request.target_path)
        except OSError as error:
            raise HelperTargetError("The target path disappeared before mutation") from error
        if (
            not stat.S_ISBLK(committed_path.st_mode)
            or committed_path.st_rdev != expected_device_number
        ):
            raise HelperTargetError("The target path changed before mutation")
        committed_observation = operations.inspect_target(expected_device_number)
        _validate_target_observation(
            committed_observation,
            request,
            expected_device_number,
            operations.active_devices(),
            source_before.st_dev,
        )
        try:
            source_after_commit = operations.fstat(source_descriptor)
        except OSError as error:
            raise HelperSourceError("The anonymous source disappeared during commit") from error
        if _status_snapshot(source_after_commit) != _status_snapshot(source_before):
            raise HelperSourceError("The anonymous source changed during the commit lease")
        # First deactivate only the primary metadata roots. If the next step
        # fails, an old GPT remains recoverable from its untouched backup and
        # no bulk partition data has changed.
        _write_exact(
            target_descriptor,
            b"\x00" * (2 * SECTOR_SIZE),
            0,
            write_at=operations.pwrite,
        )
        _retry(
            lambda: operations.fsync(target_descriptor),
            "Could not durably deactivate the primary boot metadata",
        )
        # Then remove the standard secondary GPT header at the final LBA. The
        # preceding entry array is inert without either primary or backup
        # header, so a broad tail wipe is unnecessary and could touch old data.
        _write_exact(
            target_descriptor,
            b"\x00" * SECTOR_SIZE,
            request.expected_size - SECTOR_SIZE,
            write_at=operations.pwrite,
        )
        _retry(
            lambda: operations.fsync(target_descriptor),
            "Could not durably deactivate the backup GPT header",
        )

        written_digest = hashlib.sha256(source_mbr)
        offset = SECTOR_SIZE
        progress("writing", 0, request.expected_size)
        while offset < request.expected_size:
            wanted = min(COPY_BYTES, request.expected_size - offset)
            try:
                block = operations.pread(source_descriptor, wanted, offset)
            except InterruptedError:
                continue
            except OSError as error:
                raise HelperSourceError(_bounded(error, "Could not read the anonymous source")) from error
            if type(block) is not bytes or not block or len(block) > wanted:
                raise HelperSourceError("The anonymous source made invalid read progress")
            written_digest.update(block)
            _write_exact(
                target_descriptor,
                block,
                offset,
                write_at=operations.pwrite,
            )
            offset += len(block)
            progress("writing", offset, request.expected_size)
        written_sha256 = written_digest.hexdigest()
        if written_sha256 != request.expected_sha256:
            raise HelperSourceError("The source changed while the target was being written")
        try:
            source_after_write = operations.fstat(source_descriptor)
        except OSError as error:
            raise HelperSourceError("The anonymous source disappeared after writing") from error
        if _status_snapshot(source_after_write) != _status_snapshot(source_before):
            raise HelperSourceError("The anonymous source changed while the target was being written")

        try:
            _retry(lambda: operations.fsync(target_descriptor), "Could not make the target durable")
            operations.ioctl_void(target_descriptor, BLKFLSBUF)
        except HelperError:
            raise
        except OSError as error:
            raise HelperVerificationError(
                _bounded(error, "Could not flush and invalidate the target cache"),
            ) from error

        # Verify every non-activation byte while sector zero remains blank.
        # The expected MBR participates in this logical digest, but is not
        # written until all later bytes have survived a cache-invalidated read.
        preactivation_digest = hashlib.sha256(source_mbr)
        offset = SECTOR_SIZE
        remaining = request.expected_size - SECTOR_SIZE
        progress("preactivation-readback", 0, remaining)
        while offset < request.expected_size:
            wanted = min(COPY_BYTES, request.expected_size - offset)
            try:
                block = operations.pread(target_descriptor, wanted, offset)
            except InterruptedError:
                continue
            except OSError as error:
                raise HelperVerificationError(
                    _bounded(error, "The pre-activation target read-back failed"),
                ) from error
            if type(block) is not bytes or not block or len(block) > wanted:
                raise HelperVerificationError(
                    "The pre-activation target read-back made invalid progress",
                )
            preactivation_digest.update(block)
            offset += len(block)
            progress("preactivation-readback", offset - SECTOR_SIZE, remaining)
        if preactivation_digest.hexdigest() != request.expected_sha256:
            raise HelperVerificationError(
                "The target failed verification before MBR activation",
            )

        _require_opened_target_identity(
            target_descriptor,
            request,
            expected_device_number,
            operations,
            verification=True,
        )

        # Sector zero is the commit marker.  It is written only after the rest
        # of the image is durable and verified.  Prove that cache invalidation
        # did not expose stale activation metadata before writing the marker.
        # From this proof onward, every failure takes the durable emergency
        # deactivation path because sector zero must be treated as potentially
        # active even when the proof itself fails.
        activation_attempted = True
        inactive_mbr = bytearray()
        while len(inactive_mbr) < SECTOR_SIZE:
            wanted = SECTOR_SIZE - len(inactive_mbr)
            try:
                block = operations.pread(
                    target_descriptor,
                    wanted,
                    len(inactive_mbr),
                )
            except InterruptedError:
                continue
            except OSError as error:
                raise HelperVerificationError(
                    _bounded(error, "The inactive target MBR read-back failed"),
                ) from error
            if type(block) is not bytes or not block or len(block) > wanted:
                raise HelperVerificationError(
                    "The inactive target MBR read-back made invalid progress",
                )
            inactive_mbr.extend(block)
        if any(inactive_mbr):
            raise HelperVerificationError(
                "The target sector zero is not inactive before MBR activation",
            )

        # After activation, durability/cache eviction and a complete
        # physical-path read-back are required again.
        _write_exact(
            target_descriptor,
            source_mbr,
            0,
            write_at=operations.pwrite,
        )
        try:
            _retry(lambda: operations.fsync(target_descriptor), "Could not durably activate the target")
            operations.ioctl_void(target_descriptor, BLKFLSBUF)
        except HelperError:
            raise
        except OSError as error:
            raise HelperVerificationError(
                _bounded(error, "Could not flush the activated target cache"),
            ) from error
        readback_sha256 = _hash_descriptor(
            target_descriptor,
            request.expected_size,
            read_at=operations.pread,
            progress=progress,
            phase="readback",
        )
        if readback_sha256 != request.expected_sha256:
            raise HelperVerificationError("The complete target read-back SHA-256 does not match")
        try:
            final_status = operations.fstat(target_descriptor)
            final_size = operations.ioctl_u64(target_descriptor, BLKGETSIZE64)
            final_disk_sequence = operations.ioctl_u64(target_descriptor, BLKGETDISKSEQ)
            final_sector = operations.ioctl_uint(target_descriptor, BLKSSZGET)
            final_read_only = operations.ioctl_uint(target_descriptor, BLKROGET)
            final_path = operations.lstat(request.target_path)
        except OSError as error:
            raise HelperVerificationError("The target identity changed after verification") from error
        if (
            final_status.st_rdev != opened_status.st_rdev
            or final_path.st_rdev != opened_status.st_rdev
            or not stat.S_ISBLK(final_path.st_mode)
            or final_size != request.expected_size
            or final_disk_sequence != request.expected_disk_sequence
            or final_sector != request.expected_sector_size
            or final_read_only != 0
        ):
            raise HelperVerificationError("The target identity or geometry changed after verification")
        return HelperResult(
            request.request_id,
            request.profile,
            request.target_path,
            request.expected_major_minor,
            request.expected_disk_sequence,
            request.expected_size,
            source_sha256,
            written_sha256,
            readback_sha256,
            request.expected_sector_size,
            request.expected_disk_signature,
            request.expected_volume_id,
            True,
            True,
        )
    except BaseException as error:
        if activation_attempted and target_descriptor >= 0:
            try:
                _require_opened_target_identity(
                    target_descriptor,
                    request,
                    expected_device_number,
                    operations,
                    verification=True,
                )
            except BaseException as identity_error:
                original = _bounded(error, "Post-activation verification failed")
                identity = _bounded(
                    identity_error,
                    "target identity could not be re-established",
                )
                raise HelperVerificationError(
                    f"{original}; emergency MBR deactivation was skipped because {identity}",
                ) from error
            try:
                _write_exact(
                    target_descriptor,
                    b"\x00" * SECTOR_SIZE,
                    0,
                    write_at=operations.pwrite,
                )
                _retry(
                    lambda: operations.fsync(target_descriptor),
                    "Could not durably deactivate the failed target",
                )
                operations.ioctl_void(target_descriptor, BLKFLSBUF)
            except BaseException as deactivation_error:
                original = _bounded(error, "Post-activation verification failed")
                deactivation = _bounded(
                    deactivation_error,
                    "emergency MBR deactivation failed",
                )
                raise HelperVerificationError(
                    f"{original}; emergency MBR deactivation also failed: {deactivation}",
                ) from error
        raise
    finally:
        if target_descriptor >= 0:
            try:
                operations.close(target_descriptor)
            except OSError:
                pass


def _raw_front_guard_size(request: RawHelperRequest) -> int:
    return min(RAW_FRONT_GUARD_BYTES, request.source_size - SECTOR_SIZE)


def _validate_raw_target_observation(
    observation: KernelTargetObservation,
    request: RawHelperRequest,
    device_number: int,
    active: frozenset[int],
    source_device: int,
) -> None:
    if type(observation) is not KernelTargetObservation:
        raise HelperTargetError("Kernel raw-target inspection returned invalid evidence")
    transport_ok = (
        observation.transport == "usb"
        or (observation.transport == "mmc" and observation.removable)
    )
    if (
        observation.device_number != device_number
        or device_number not in observation.related_device_numbers
        or not transport_ok
        or observation.read_only
        or observation.logical_sector_size != request.expected_sector_size
        or observation.has_holders
        or observation.disk_sequence != request.expected_disk_sequence
    ):
        raise HelperTargetError("Kernel raw-target safety properties do not match this request")
    if observation.related_device_numbers & active:
        raise HelperTargetError(
            "The selected raw target or one of its dependants is mounted or active swap",
        )
    if source_device in observation.related_device_numbers:
        raise HelperTargetError("The anonymous raw source resides on the selected target")


def _require_raw_opened_target_identity(
    descriptor: int,
    request: RawHelperRequest,
    device_number: int,
    operations: HelperOperations,
    *,
    verification: bool,
) -> None:
    error_type = HelperVerificationError if verification else HelperTargetError
    try:
        status = operations.fstat(descriptor)
        size = operations.ioctl_u64(descriptor, BLKGETSIZE64)
        disk_sequence = operations.ioctl_u64(descriptor, BLKGETDISKSEQ)
        sector_size = operations.ioctl_uint(descriptor, BLKSSZGET)
        read_only = operations.ioctl_uint(descriptor, BLKROGET)
    except OSError as error:
        raise error_type("Could not revalidate the opened raw target identity") from error
    if (
        not stat.S_ISBLK(status.st_mode)
        or status.st_rdev != device_number
        or size != request.expected_target_size
        or disk_sequence != request.expected_disk_sequence
        or sector_size != request.expected_sector_size
        or read_only != 0
    ):
        raise error_type("The opened raw target is no longer the authorized disk generation")


def _read_raw_target_exact(
    descriptor: int,
    offset: int,
    size: int,
    *,
    operations: HelperOperations,
    label: str,
) -> bytes:
    blocks: list[bytes] = []
    consumed = 0
    while consumed < size:
        try:
            block = operations.pread(descriptor, size - consumed, offset + consumed)
        except InterruptedError:
            continue
        except OSError as error:
            raise HelperVerificationError(_bounded(error, f"Could not read {label}")) from error
        if type(block) is not bytes or not block or len(block) > size - consumed:
            raise HelperVerificationError(f"The {label} made invalid read progress")
        blocks.append(block)
        consumed += len(block)
    return b"".join(blocks)


def _raw_deactivation_regions(request: RawHelperRequest) -> tuple[tuple[int, int], ...]:
    guard = _raw_front_guard_size(request)
    candidates = (
        (0, guard),
        (request.source_size - SECTOR_SIZE, SECTOR_SIZE),
        (request.expected_target_size - SECTOR_SIZE, SECTOR_SIZE),
    )
    unique: list[tuple[int, int]] = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    return tuple(unique)


def _zero_raw_regions(
    descriptor: int,
    request: RawHelperRequest,
    operations: HelperOperations,
) -> None:
    for offset, size in _raw_deactivation_regions(request):
        _write_exact(
            descriptor,
            b"\0" * size,
            offset,
            write_at=operations.pwrite,
        )


def execute_raw_helper_transaction(
    request: RawHelperRequest,
    *,
    source_descriptor: int = 0,
    invoking_uid: int,
    operations: HelperOperations = HelperOperations(),
    progress: Progress = lambda _phase, _done, _total: None,
    mutation_started: Callable[[], None] = lambda: None,
) -> RawHelperResult:
    """Write one anonymous raw snapshot under a same-FD disk-generation lease."""

    validate_raw_helper_request(request)
    if (
        type(source_descriptor) is not int
        or isinstance(source_descriptor, bool)
        or source_descriptor < 0
    ):
        raise HelperSourceError("The privileged raw source descriptor is invalid")
    if type(invoking_uid) is not int or isinstance(invoking_uid, bool) or invoking_uid < 0:
        raise HelperRequestError("The invoking user identity is invalid")
    try:
        source_before = operations.fstat(source_descriptor)
        source_flags = operations.get_flags(source_descriptor)
    except OSError as error:
        raise HelperSourceError(
            _bounded(error, "Could not inspect the anonymous raw source"),
        ) from error
    _validate_raw_source_status(source_before, request, invoking_uid)
    if source_flags & os.O_ACCMODE != os.O_RDWR or source_flags & os.O_APPEND:
        raise HelperSourceError("The anonymous raw source has unsafe access flags")
    try:
        operations.flock(source_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        raise HelperSourceError("The anonymous raw source is not exclusively owned") from error

    source_sha256 = _hash_descriptor(
        source_descriptor,
        request.source_size,
        read_at=operations.pread,
        progress=progress,
        phase="source-validation",
    )
    if source_sha256 != request.source_sha256:
        raise HelperSourceError("The anonymous raw source failed its bound SHA-256")
    try:
        source_after_hash = operations.fstat(source_descriptor)
    except OSError as error:
        raise HelperSourceError("The anonymous raw source disappeared") from error
    if _status_snapshot(source_after_hash) != _status_snapshot(source_before):
        raise HelperSourceError("The anonymous raw source changed during validation")

    guard_size = _raw_front_guard_size(request)
    source_tail_offset = request.source_size - SECTOR_SIZE
    target_tail_offset = request.expected_target_size - SECTOR_SIZE
    source_front = _read_exact_at(
        source_descriptor,
        0,
        guard_size,
        read_at=operations.pread,
        label="raw activation guard",
    )
    source_tail = _read_exact_at(
        source_descriptor,
        source_tail_offset,
        SECTOR_SIZE,
        read_at=operations.pread,
        label="raw source tail sector",
    )

    try:
        path_status = operations.lstat(request.target_path)
    except OSError as error:
        raise HelperTargetError(_bounded(error, "The selected raw target is unavailable")) from error
    if not stat.S_ISBLK(path_status.st_mode):
        raise HelperTargetError("The privileged raw target path is not a block device")
    expected_device_number = _parse_dev(request.expected_major_minor)
    if path_status.st_rdev != expected_device_number:
        raise HelperTargetError("The privileged raw target path changed kernel identity")
    pre_observation = operations.inspect_raw_target(expected_device_number)
    _validate_raw_target_observation(
        pre_observation,
        request,
        expected_device_number,
        operations.active_devices(),
        source_before.st_dev,
    )

    flags = (
        os.O_RDWR
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    target_descriptor = -1
    mutation_attempted = False
    try:
        try:
            target_descriptor = operations.open(request.target_path, flags)
        except OSError as error:
            if error.errno == errno.EBUSY:
                raise HelperTargetError("The raw target is mounted, claimed, or busy") from error
            raise HelperTargetError(
                _bounded(error, "Could not exclusively open the raw target"),
            ) from error
        try:
            operations.flock(target_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise HelperTargetError("Another lock-aware process is using the raw target") from error
        _require_raw_opened_target_identity(
            target_descriptor,
            request,
            expected_device_number,
            operations,
            verification=False,
        )
        live_observation = operations.inspect_raw_target(expected_device_number)
        _validate_raw_target_observation(
            live_observation,
            request,
            expected_device_number,
            operations.active_devices(),
            source_before.st_dev,
        )
        try:
            current_path = operations.lstat(request.target_path)
        except OSError as error:
            raise HelperTargetError("The raw target path disappeared after exclusive open") from error
        if (
            not stat.S_ISBLK(current_path.st_mode)
            or current_path.st_rdev != expected_device_number
        ):
            raise HelperTargetError("The raw target path was replaced during exclusive open")
        try:
            source_before_commit = operations.fstat(source_descriptor)
        except OSError as error:
            raise HelperSourceError("The anonymous raw source disappeared before commit") from error
        if _status_snapshot(source_before_commit) != _status_snapshot(source_before):
            raise HelperSourceError("The anonymous raw source changed before commit")

        mutation_started()
        _require_raw_opened_target_identity(
            target_descriptor,
            request,
            expected_device_number,
            operations,
            verification=False,
        )
        try:
            committed_path = operations.lstat(request.target_path)
        except OSError as error:
            raise HelperTargetError("The raw target path disappeared before mutation") from error
        if (
            not stat.S_ISBLK(committed_path.st_mode)
            or committed_path.st_rdev != expected_device_number
        ):
            raise HelperTargetError("The raw target path changed before mutation")
        committed_observation = operations.inspect_raw_target(expected_device_number)
        _validate_raw_target_observation(
            committed_observation,
            request,
            expected_device_number,
            operations.active_devices(),
            source_before.st_dev,
        )
        try:
            source_after_commit = operations.fstat(source_descriptor)
        except OSError as error:
            raise HelperSourceError("The anonymous raw source disappeared during commit") from error
        if _status_snapshot(source_after_commit) != _status_snapshot(source_before):
            raise HelperSourceError("The anonymous raw source changed during the commit lease")

        # Deactivate the complete primary metadata envelope first and make it
        # durable before touching bulk data. Then clear both the source-end and
        # physical target-end sectors so stale backup GPT headers cannot remain
        # active on either an equal-size or larger destination.
        mutation_attempted = True
        _write_exact(
            target_descriptor,
            b"\0" * guard_size,
            0,
            write_at=operations.pwrite,
        )
        _retry(
            lambda: operations.fsync(target_descriptor),
            "Could not durably deactivate the raw target front guard",
        )
        for offset in dict.fromkeys((source_tail_offset, target_tail_offset)):
            _write_exact(
                target_descriptor,
                b"\0" * SECTOR_SIZE,
                offset,
                write_at=operations.pwrite,
            )
        _retry(
            lambda: operations.fsync(target_descriptor),
            "Could not durably sanitize the raw target tail metadata",
        )

        written_digest = hashlib.sha256(source_front)
        offset = guard_size
        progress("writing", 0, request.source_size)
        while offset < source_tail_offset:
            wanted = min(COPY_BYTES, source_tail_offset - offset)
            try:
                block = operations.pread(source_descriptor, wanted, offset)
            except InterruptedError:
                continue
            except OSError as error:
                raise HelperSourceError(_bounded(error, "Could not read the raw source")) from error
            if type(block) is not bytes or not block or len(block) > wanted:
                raise HelperSourceError("The anonymous raw source made invalid read progress")
            written_digest.update(block)
            _write_exact(
                target_descriptor,
                block,
                offset,
                write_at=operations.pwrite,
            )
            offset += len(block)
            progress("writing", offset, request.source_size)
        written_digest.update(source_tail)
        written_sha256 = written_digest.hexdigest()
        if written_sha256 != request.source_sha256:
            raise HelperSourceError("The raw source changed while the target was being written")
        try:
            source_after_write = operations.fstat(source_descriptor)
        except OSError as error:
            raise HelperSourceError("The anonymous raw source disappeared after writing") from error
        if _status_snapshot(source_after_write) != _status_snapshot(source_before):
            raise HelperSourceError("The anonymous raw source changed while writing")

        try:
            _retry(
                lambda: operations.fsync(target_descriptor),
                "Could not make the raw target bulk data durable",
            )
            operations.ioctl_void(target_descriptor, BLKFLSBUF)
        except HelperError:
            raise
        except OSError as error:
            raise HelperVerificationError(
                _bounded(error, "Could not flush and invalidate the raw target cache"),
            ) from error

        preactivation_digest = hashlib.sha256(source_front)
        offset = guard_size
        middle_size = source_tail_offset - guard_size
        progress("preactivation-readback", 0, middle_size)
        while offset < source_tail_offset:
            wanted = min(COPY_BYTES, source_tail_offset - offset)
            block = _read_raw_target_exact(
                target_descriptor,
                offset,
                wanted,
                operations=operations,
                label="raw pre-activation read-back",
            )
            preactivation_digest.update(block)
            offset += len(block)
            progress("preactivation-readback", offset - guard_size, middle_size)
        preactivation_digest.update(source_tail)
        if preactivation_digest.hexdigest() != request.source_sha256:
            raise HelperVerificationError(
                "The raw target failed verification before activation",
            )
        if _read_raw_target_exact(
            target_descriptor,
            0,
            guard_size,
            operations=operations,
            label="inactive raw front guard",
        ) != b"\0" * guard_size:
            raise HelperVerificationError(
                "The raw front guard activation region is not inactive",
            )
        if _read_raw_target_exact(
            target_descriptor,
            source_tail_offset,
            SECTOR_SIZE,
            operations=operations,
            label="inactive raw source tail",
        ) != b"\0" * SECTOR_SIZE:
            raise HelperVerificationError("The raw source-tail activation sector is not inactive")
        if target_tail_offset != source_tail_offset and _read_raw_target_exact(
            target_descriptor,
            target_tail_offset,
            SECTOR_SIZE,
            operations=operations,
            label="sanitized physical target tail",
        ) != b"\0" * SECTOR_SIZE:
            raise HelperVerificationError("The stale physical target tail was not sanitized")

        _require_raw_opened_target_identity(
            target_descriptor,
            request,
            expected_device_number,
            operations,
            verification=True,
        )
        _write_exact(
            target_descriptor,
            source_tail,
            source_tail_offset,
            write_at=operations.pwrite,
        )
        _retry(
            lambda: operations.fsync(target_descriptor),
            "Could not durably write the raw source tail",
        )
        _write_exact(
            target_descriptor,
            source_front,
            0,
            write_at=operations.pwrite,
        )
        try:
            _retry(
                lambda: operations.fsync(target_descriptor),
                "Could not durably activate the raw target",
            )
            operations.ioctl_void(target_descriptor, BLKFLSBUF)
        except HelperError:
            raise
        except OSError as error:
            raise HelperVerificationError(
                _bounded(error, "Could not flush the activated raw target cache"),
            ) from error
        progress("writing", request.source_size, request.source_size)

        if _read_raw_target_exact(
            target_descriptor,
            0,
            guard_size,
            operations=operations,
            label="activated raw front guard",
        ) != source_front:
            raise HelperVerificationError("The activated raw front guard failed read-back")
        if _read_raw_target_exact(
            target_descriptor,
            source_tail_offset,
            SECTOR_SIZE,
            operations=operations,
            label="activated raw source tail",
        ) != source_tail:
            raise HelperVerificationError("The activated raw source tail failed read-back")
        if target_tail_offset != source_tail_offset and _read_raw_target_exact(
            target_descriptor,
            target_tail_offset,
            SECTOR_SIZE,
            operations=operations,
            label="final sanitized physical target tail",
        ) != b"\0" * SECTOR_SIZE:
            raise HelperVerificationError("The physical target tail sanitation did not persist")

        readback_sha256 = ""
        if request.final_verification:
            readback_sha256 = _hash_descriptor(
                target_descriptor,
                request.source_size,
                read_at=operations.pread,
                progress=progress,
                phase="readback",
            )
            if readback_sha256 != request.source_sha256:
                raise HelperVerificationError("The complete raw target read-back does not match")

        _require_raw_opened_target_identity(
            target_descriptor,
            request,
            expected_device_number,
            operations,
            verification=True,
        )
        try:
            final_path = operations.lstat(request.target_path)
            final_source = operations.fstat(source_descriptor)
        except OSError as error:
            raise HelperVerificationError("The raw transaction identity changed at completion") from error
        if (
            not stat.S_ISBLK(final_path.st_mode)
            or final_path.st_rdev != expected_device_number
            or _status_snapshot(final_source) != _status_snapshot(source_before)
        ):
            raise HelperVerificationError("The raw source or target identity changed at completion")
        final_observation = operations.inspect_raw_target(expected_device_number)
        _validate_raw_target_observation(
            final_observation,
            request,
            expected_device_number,
            operations.active_devices(),
            source_before.st_dev,
        )
        return RawHelperResult(
            request.request_id,
            RAW_HELPER_PROFILE,
            request.target_path,
            request.expected_major_minor,
            request.expected_disk_sequence,
            request.expected_target_size,
            request.source_size,
            source_sha256,
            written_sha256,
            readback_sha256,
            request.expected_sector_size,
            guard_size,
            target_tail_offset != source_tail_offset,
            request.final_verification,
            True,
            True,
        )
    except BaseException as error:
        if mutation_attempted and target_descriptor >= 0:
            try:
                _require_raw_opened_target_identity(
                    target_descriptor,
                    request,
                    expected_device_number,
                    operations,
                    verification=True,
                )
            except BaseException as identity_error:
                original = _bounded(error, "The committed raw transaction failed")
                identity = _bounded(identity_error, "target identity could not be re-established")
                raise HelperVerificationError(
                    f"{original}; emergency raw deactivation was skipped because {identity}",
                ) from error
            try:
                _zero_raw_regions(target_descriptor, request, operations)
                _retry(
                    lambda: operations.fsync(target_descriptor),
                    "Could not durably deactivate the failed raw target",
                )
                operations.ioctl_void(target_descriptor, BLKFLSBUF)
            except BaseException as deactivation_error:
                original = _bounded(error, "The committed raw transaction failed")
                deactivation = _bounded(
                    deactivation_error,
                    "emergency raw deactivation failed",
                )
                raise HelperVerificationError(
                    f"{original}; emergency raw deactivation also failed: {deactivation}",
                ) from error
        raise
    finally:
        if target_descriptor >= 0:
            try:
                operations.close(target_descriptor)
            except OSError:
                pass


def _validate_fast_zero_target_observation(
    observation: KernelTargetObservation,
    request: FastZeroHelperRequest,
    device_number: int,
    active: frozenset[int],
) -> None:
    if type(observation) is not KernelTargetObservation:
        raise HelperTargetError("Kernel fast-zero target inspection returned invalid evidence")
    if (
        observation.device_number != device_number
        or device_number not in observation.related_device_numbers
        or observation.transport not in {"usb", "mmc"}
        or not observation.removable
        or observation.read_only
        or observation.logical_sector_size != request.expected_sector_size
        or observation.has_holders
        or observation.disk_sequence != request.expected_disk_sequence
    ):
        raise HelperTargetError("Kernel fast-zero target safety properties do not match this request")
    if observation.related_device_numbers & active:
        raise HelperTargetError(
            "The selected fast-zero target or one of its dependants is mounted or active swap",
        )


def _require_fast_zero_opened_target_identity(
    descriptor: int,
    request: FastZeroHelperRequest,
    device_number: int,
    operations: HelperOperations,
    *,
    verification: bool,
) -> None:
    error_type = HelperVerificationError if verification else HelperTargetError
    try:
        status = operations.fstat(descriptor)
        size = operations.ioctl_u64(descriptor, BLKGETSIZE64)
        disk_sequence = operations.ioctl_u64(descriptor, BLKGETDISKSEQ)
        sector_size = operations.ioctl_uint(descriptor, BLKSSZGET)
        read_only = operations.ioctl_uint(descriptor, BLKROGET)
    except OSError as error:
        raise error_type("Could not revalidate the opened fast-zero target identity") from error
    if (
        not stat.S_ISBLK(status.st_mode)
        or status.st_rdev != device_number
        or size != request.expected_target_size
        or disk_sequence != request.expected_disk_sequence
        or sector_size != request.expected_sector_size
        or read_only != 0
    ):
        raise error_type("The opened fast-zero target is no longer the authorized disk generation")


def _fast_zero_boundary_regions(size: int) -> tuple[tuple[int, int], ...]:
    boundary = min(FAST_ZERO_BOUNDARY_BYTES, size)
    if size <= 2 * boundary:
        return ((0, size),)
    return ((0, boundary), (size - boundary, boundary))


def _fast_zero_failure_code(error: BaseException) -> int:
    if isinstance(error, HelperCancelled):
        return FAST_ZERO_FAILURE_CANCELLED
    if isinstance(error, HelperRequestError):
        return FAST_ZERO_FAILURE_REQUEST
    if isinstance(error, HelperTargetError):
        return FAST_ZERO_FAILURE_TARGET
    if isinstance(error, HelperVerificationError):
        return FAST_ZERO_FAILURE_VERIFICATION
    if isinstance(error, HelperError):
        return FAST_ZERO_FAILURE_IO
    return FAST_ZERO_FAILURE_UNEXPECTED


def _invalidate_fast_zero_cache(
    descriptor: int,
    operations: HelperOperations,
    label: str,
) -> None:
    try:
        _retry(lambda: operations.ioctl_void(descriptor, BLKFLSBUF), label)
    except HelperError as error:
        raise HelperVerificationError(_bounded(error, label)) from error


def _require_fast_zero_cleanup_identity(
    descriptor: int,
    request: FastZeroHelperRequest,
    device_number: int,
    operations: HelperOperations,
) -> None:
    _require_fast_zero_opened_target_identity(
        descriptor,
        request,
        device_number,
        operations,
        verification=True,
    )
    try:
        current_path = operations.lstat(request.target_path)
    except OSError as error:
        raise HelperVerificationError(
            "The fast-zero target path disappeared during boundary cleanup",
        ) from error
    if not stat.S_ISBLK(current_path.st_mode) or current_path.st_rdev != device_number:
        raise HelperVerificationError(
            "The fast-zero target path changed during boundary cleanup",
        )
    try:
        _validate_fast_zero_target_observation(
            operations.inspect_target(device_number),
            request,
            device_number,
            operations.active_devices(),
        )
    except HelperTargetError as error:
        raise HelperVerificationError(
            "The fast-zero target topology changed during boundary cleanup",
        ) from error


def _fast_zero_result(
    request: FastZeroHelperRequest,
    *,
    outcome: str,
    scanned_bytes: int,
    written_bytes: int,
    skipped_bytes: int,
    verified_bytes: int,
    scanned_chunks: int,
    written_chunks: int,
    skipped_chunks: int,
    cleanup_bytes: int = 0,
    failure_code: int = FAST_ZERO_FAILURE_NONE,
) -> FastZeroHelperResult:
    return FastZeroHelperResult(
        request.request_id,
        FAST_ZERO_HELPER_PROFILE,
        request.target_path,
        request.expected_major_minor,
        request.expected_disk_sequence,
        request.expected_target_size,
        request.expected_sector_size,
        request.chunk_size,
        scanned_bytes,
        written_bytes,
        skipped_bytes,
        verified_bytes,
        scanned_chunks,
        written_chunks,
        skipped_chunks,
        cleanup_bytes,
        failure_code,
        outcome,
        True,
        True,
        outcome == "success",
        outcome != "success",
        True,
    )


def _cleanup_fast_zero_boundaries(
    descriptor: int,
    request: FastZeroHelperRequest,
    device_number: int,
    operations: HelperOperations,
    progress: Progress,
) -> int:
    _require_fast_zero_cleanup_identity(
        descriptor,
        request,
        device_number,
        operations,
    )
    regions = _fast_zero_boundary_regions(request.expected_target_size)
    total = sum(size for _offset, size in regions)
    progress("cleanup", 0, total)
    zeros = b"\0" * min(FAST_ZERO_BOUNDARY_BYTES, request.expected_target_size)
    for offset, size in regions:
        _write_exact(descriptor, zeros[:size], offset, write_at=operations.pwrite)
    _retry(
        lambda: operations.fsync(descriptor),
        "Could not make fast-zero boundary cleanup durable",
    )
    _invalidate_fast_zero_cache(
        descriptor,
        operations,
        "Could not invalidate the fast-zero target cache after cleanup",
    )
    verified = 0
    for offset, size in regions:
        if _read_raw_target_exact(
            descriptor,
            offset,
            size,
            operations=operations,
            label="fast-zero boundary cleanup read-back",
        ) != zeros[:size]:
            raise HelperVerificationError("The fast-zero boundary cleanup failed read-back")
        verified += size
        progress("cleanup", verified, total)
    _require_fast_zero_cleanup_identity(
        descriptor,
        request,
        device_number,
        operations,
    )
    return total


def execute_fast_zero_helper_transaction(
    request: FastZeroHelperRequest,
    *,
    operations: HelperOperations = HelperOperations(),
    progress: Progress = lambda _phase, _done, _total: None,
    mutation_started: Callable[[], None] = lambda: None,
    postcommit_cancel: Callable[[], None] = lambda: None,
) -> FastZeroHelperResult:
    """Scan and logically zero one exact removable disk under a same-FD lease."""

    validate_fast_zero_helper_request(request)
    try:
        path_status = operations.lstat(request.target_path)
    except OSError as error:
        raise HelperTargetError(_bounded(error, "The selected fast-zero target is unavailable")) from error
    if not stat.S_ISBLK(path_status.st_mode):
        raise HelperTargetError("The fast-zero target path is not a block device")
    expected_device_number = _parse_dev(request.expected_major_minor)
    if path_status.st_rdev != expected_device_number:
        raise HelperTargetError("The fast-zero target path changed kernel identity")
    _validate_fast_zero_target_observation(
        operations.inspect_target(expected_device_number),
        request,
        expected_device_number,
        operations.active_devices(),
    )

    flags = (
        os.O_RDWR
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    target_descriptor = -1
    committed = False
    scanned_bytes = written_bytes = skipped_bytes = verified_bytes = 0
    scanned_chunks = written_chunks = skipped_chunks = 0
    try:
        try:
            target_descriptor = operations.open(request.target_path, flags)
        except OSError as error:
            if error.errno == errno.EBUSY:
                raise HelperTargetError("The fast-zero target is mounted, claimed, or busy") from error
            raise HelperTargetError(
                _bounded(error, "Could not exclusively open the fast-zero target"),
            ) from error
        try:
            operations.flock(target_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise HelperTargetError("Another lock-aware process is using the fast-zero target") from error
        _require_fast_zero_opened_target_identity(
            target_descriptor,
            request,
            expected_device_number,
            operations,
            verification=False,
        )
        _validate_fast_zero_target_observation(
            operations.inspect_target(expected_device_number),
            request,
            expected_device_number,
            operations.active_devices(),
        )
        current_path = operations.lstat(request.target_path)
        if not stat.S_ISBLK(current_path.st_mode) or current_path.st_rdev != expected_device_number:
            raise HelperTargetError("The fast-zero target path was replaced after exclusive open")

        mutation_started()
        committed = True
        _require_fast_zero_opened_target_identity(
            target_descriptor,
            request,
            expected_device_number,
            operations,
            verification=False,
        )
        committed_path = operations.lstat(request.target_path)
        if not stat.S_ISBLK(committed_path.st_mode) or committed_path.st_rdev != expected_device_number:
            raise HelperTargetError("The fast-zero target path changed before mutation")
        _validate_fast_zero_target_observation(
            operations.inspect_target(expected_device_number),
            request,
            expected_device_number,
            operations.active_devices(),
        )

        zeros = b"\0" * request.chunk_size
        progress("scanning", 0, request.expected_target_size)
        offset = 0
        while offset < request.expected_target_size:
            postcommit_cancel()
            wanted = min(request.chunk_size, request.expected_target_size - offset)
            block = _read_raw_target_exact(
                target_descriptor,
                offset,
                wanted,
                operations=operations,
                label="fast-zero target scan",
            )
            if block == zeros[:wanted]:
                skipped_bytes += wanted
                skipped_chunks += 1
            else:
                _require_fast_zero_opened_target_identity(
                    target_descriptor,
                    request,
                    expected_device_number,
                    operations,
                    verification=False,
                )
                _write_exact(target_descriptor, zeros[:wanted], offset, write_at=operations.pwrite)
                written_bytes += wanted
                written_chunks += 1
            scanned_bytes += wanted
            scanned_chunks += 1
            offset += wanted
            progress("scanning", offset, request.expected_target_size)
        postcommit_cancel()
        _retry(lambda: operations.fsync(target_descriptor), "Could not make fast-zero writes durable")
        _invalidate_fast_zero_cache(
            target_descriptor,
            operations,
            "Could not invalidate the fast-zero target cache",
        )

        progress("readback", 0, request.expected_target_size)
        offset = 0
        while offset < request.expected_target_size:
            postcommit_cancel()
            wanted = min(request.chunk_size, request.expected_target_size - offset)
            block = _read_raw_target_exact(
                target_descriptor,
                offset,
                wanted,
                operations=operations,
                label="fast-zero full read-back",
            )
            if block != zeros[:wanted]:
                raise HelperVerificationError("The fast-zero target failed full zero read-back")
            offset += wanted
            verified_bytes += wanted
            progress("readback", offset, request.expected_target_size)
        postcommit_cancel()
        _require_fast_zero_opened_target_identity(
            target_descriptor,
            request,
            expected_device_number,
            operations,
            verification=True,
        )
        _validate_fast_zero_target_observation(
            operations.inspect_target(expected_device_number),
            request,
            expected_device_number,
            operations.active_devices(),
        )
        return _fast_zero_result(
            request,
            outcome="success",
            scanned_bytes=scanned_bytes,
            written_bytes=written_bytes,
            skipped_bytes=skipped_bytes,
            verified_bytes=verified_bytes,
            scanned_chunks=scanned_chunks,
            written_chunks=written_chunks,
            skipped_chunks=skipped_chunks,
        )
    except BaseException as error:
        if not committed or target_descriptor < 0:
            raise
        try:
            cleanup_bytes = _cleanup_fast_zero_boundaries(
                target_descriptor,
                request,
                expected_device_number,
                operations,
                progress,
            )
        except BaseException as cleanup_error:
            original = _bounded(error, "The committed fast-zero transaction failed")
            cleanup = _bounded(cleanup_error, "boundary cleanup could not be verified")
            raise HelperVerificationError(
                f"{original}; fast-zero boundary cleanup also failed: {cleanup}",
            ) from error
        return _fast_zero_result(
            request,
            outcome=("partial-cancel" if isinstance(error, HelperCancelled) else "partial-failure"),
            scanned_bytes=scanned_bytes,
            written_bytes=written_bytes,
            skipped_bytes=skipped_bytes,
            verified_bytes=verified_bytes,
            scanned_chunks=scanned_chunks,
            written_chunks=written_chunks,
            skipped_chunks=skipped_chunks,
            cleanup_bytes=cleanup_bytes,
            failure_code=_fast_zero_failure_code(error),
        )
    finally:
        if target_descriptor >= 0:
            try:
                operations.close(target_descriptor)
            except OSError:
                pass


def pack_helper_request(
    request_id: bytes,
    major_number: int,
    minor_number: int,
    disk_sequence: int,
    size: int,
    sector_size: int,
    disk_signature: int,
    volume_id: int,
    sha256_hex: str,
) -> bytes:
    """Pack the only accepted client request; all fields remain untrusted."""

    if (
        type(request_id) is not bytes
        or len(request_id) != 16
        or type(major_number) is not int
        or type(minor_number) is not int
        or not 0 <= major_number <= 0xFFFFFFFF
        or not 0 <= minor_number <= 0xFFFFFFFF
        or type(disk_sequence) is not int
        or isinstance(disk_sequence, bool)
        or not 0 < disk_sequence <= 0xFFFFFFFFFFFFFFFF
        or type(size) is not int
        or isinstance(size, bool)
        or not 0 <= size <= 0xFFFFFFFFFFFFFFFF
        or type(sector_size) is not int
        or isinstance(sector_size, bool)
        or not 0 <= sector_size <= 0xFFFFFFFF
        or type(disk_signature) is not int
        or isinstance(disk_signature, bool)
        or not 0 <= disk_signature <= 0xFFFFFFFF
        or type(volume_id) is not int
        or isinstance(volume_id, bool)
        or not 0 <= volume_id <= 0xFFFFFFFF
        or type(sha256_hex) is not str
        or _SHA256.fullmatch(sha256_hex) is None
    ):
        raise HelperRequestError("The privileged request cannot be encoded")
    return _REQUEST_PACKET.pack(
        PROTOCOL_MAGIC,
        PROTOCOL_VERSION,
        PACKET_REQUEST,
        0,
        request_id,
        major_number,
        minor_number,
        disk_sequence,
        size,
        sector_size,
        disk_signature,
        volume_id,
        bytes.fromhex(sha256_hex),
    )


def unpack_helper_request(
    packet: bytes,
    *,
    sys_root: Path = Path("/sys"),
) -> HelperRequest:
    if type(packet) is not bytes or len(packet) != _REQUEST_PACKET.size:
        raise HelperRequestError("The privileged request packet has the wrong size")
    (
        magic,
        version,
        packet_type,
        reserved,
        request_id,
        major_number,
        minor_number,
        disk_sequence,
        size,
        sector_size,
        disk_signature,
        volume_id,
        digest,
    ) = _REQUEST_PACKET.unpack(packet)
    if (
        magic != PROTOCOL_MAGIC
        or version != PROTOCOL_VERSION
        or packet_type != PACKET_REQUEST
        or reserved != 0
    ):
        raise HelperRequestError("The privileged request packet is unsupported")
    try:
        device_number = os.makedev(major_number, minor_number)
    except (OverflowError, ValueError) as error:
        raise HelperRequestError("The privileged request has an invalid device number") from error
    request = HelperRequest(
        request_id,
        HELPER_PROFILE,
        _target_path_from_kernel(device_number, sys_root=sys_root),
        f"{major_number}:{minor_number}",
        disk_sequence,
        size,
        sector_size,
        disk_signature,
        volume_id,
        digest.hex(),
    )
    validate_helper_request(request)
    return request


def pack_windows_helper_request(
    request_id: bytes,
    major_number: int,
    minor_number: int,
    disk_sequence: int,
    size: int,
    sector_size: int,
    disk_signature: int,
    volume_id: int,
    sha256_hex: str,
) -> bytes:
    packet = pack_helper_request(
        request_id, major_number, minor_number, disk_sequence, size,
        sector_size, disk_signature, volume_id, sha256_hex,
    )
    return WINDOWS_PROTOCOL_MAGIC + packet[len(PROTOCOL_MAGIC):]


def unpack_windows_helper_request(
    packet: bytes,
    *,
    sys_root: Path = Path("/sys"),
) -> HelperRequest:
    if type(packet) is not bytes or len(packet) != _REQUEST_PACKET.size:
        raise HelperRequestError("The Windows request packet has the wrong size")
    if packet[:len(WINDOWS_PROTOCOL_MAGIC)] != WINDOWS_PROTOCOL_MAGIC:
        raise HelperRequestError("The Windows request packet is unsupported")
    generic = unpack_helper_request(
        PROTOCOL_MAGIC + packet[len(WINDOWS_PROTOCOL_MAGIC):],
        sys_root=sys_root,
    )
    request = HelperRequest(
        generic.request_id,
        WINDOWS_HELPER_PROFILE,
        generic.target_path,
        generic.expected_major_minor,
        generic.expected_disk_sequence,
        generic.expected_size,
        generic.expected_sector_size,
        generic.expected_disk_signature,
        generic.expected_volume_id,
        generic.expected_sha256,
    )
    validate_helper_request(request)
    return request


def pack_raw_helper_request(
    request_id: bytes,
    major_number: int,
    minor_number: int,
    disk_sequence: int,
    target_size: int,
    sector_size: int,
    source_size: int,
    sha256_hex: str,
    *,
    final_verification: bool,
) -> bytes:
    """Pack the exact raw-device request; every root-side field is untrusted."""

    if (
        type(request_id) is not bytes
        or len(request_id) != 16
        or type(major_number) is not int
        or type(minor_number) is not int
        or not 0 <= major_number <= 0xFFFFFFFF
        or not 0 <= minor_number <= 0xFFFFFFFF
        or type(disk_sequence) is not int
        or isinstance(disk_sequence, bool)
        or not 0 < disk_sequence <= 0xFFFFFFFFFFFFFFFF
        or type(target_size) is not int
        or isinstance(target_size, bool)
        or not 0 <= target_size <= 0xFFFFFFFFFFFFFFFF
        or type(sector_size) is not int
        or isinstance(sector_size, bool)
        or not 0 <= sector_size <= 0xFFFFFFFF
        or type(source_size) is not int
        or isinstance(source_size, bool)
        or not 0 <= source_size <= 0xFFFFFFFFFFFFFFFF
        or type(sha256_hex) is not str
        or _SHA256.fullmatch(sha256_hex) is None
        or type(final_verification) is not bool
    ):
        raise HelperRequestError("The privileged raw request cannot be encoded")
    return _RAW_REQUEST_PACKET.pack(
        RAW_PROTOCOL_MAGIC,
        PROTOCOL_VERSION,
        PACKET_REQUEST,
        0,
        request_id,
        major_number,
        minor_number,
        disk_sequence,
        target_size,
        sector_size,
        source_size,
        int(final_verification),
        b"\0" * 7,
        bytes.fromhex(sha256_hex),
    )


def unpack_raw_helper_request(
    packet: bytes,
    *,
    sys_root: Path = Path("/sys"),
) -> RawHelperRequest:
    if type(packet) is not bytes or len(packet) != _RAW_REQUEST_PACKET.size:
        raise HelperRequestError("The privileged raw request has the wrong size")
    (
        magic,
        version,
        packet_type,
        reserved,
        request_id,
        major_number,
        minor_number,
        disk_sequence,
        target_size,
        sector_size,
        source_size,
        final_verification,
        trailing_reserved,
        digest,
    ) = _RAW_REQUEST_PACKET.unpack(packet)
    if (
        magic != RAW_PROTOCOL_MAGIC
        or version != PROTOCOL_VERSION
        or packet_type != PACKET_REQUEST
        or reserved != 0
        or final_verification not in {0, 1}
        or trailing_reserved != b"\0" * 7
    ):
        raise HelperRequestError("The privileged raw request is unsupported")
    try:
        device_number = os.makedev(major_number, minor_number)
    except (OverflowError, ValueError) as error:
        raise HelperRequestError("The raw request has an invalid device number") from error
    request = RawHelperRequest(
        request_id,
        RAW_HELPER_PROFILE,
        _target_path_from_kernel(device_number, sys_root=sys_root),
        f"{major_number}:{minor_number}",
        disk_sequence,
        target_size,
        sector_size,
        source_size,
        digest.hex(),
        bool(final_verification),
    )
    validate_raw_helper_request(request)
    return request


def pack_fast_zero_helper_request(
    request_id: bytes,
    major_number: int,
    minor_number: int,
    disk_sequence: int,
    target_size: int,
    sector_size: int,
    chunk_size: int,
    plan_sha256: str,
    ready_sha256: str,
) -> bytes:
    """Pack the fixed target-only fast-zero request (never with SCM_RIGHTS)."""

    if (
        type(request_id) is not bytes
        or len(request_id) != 16
        or type(major_number) is not int
        or isinstance(major_number, bool)
        or not 0 <= major_number <= 0xFFFFFFFF
        or type(minor_number) is not int
        or isinstance(minor_number, bool)
        or not 0 <= minor_number <= 0xFFFFFFFF
        or type(disk_sequence) is not int
        or isinstance(disk_sequence, bool)
        or not 0 < disk_sequence <= 0xFFFFFFFFFFFFFFFF
        or type(target_size) is not int
        or isinstance(target_size, bool)
        or not 0 <= target_size <= 0xFFFFFFFFFFFFFFFF
        or type(sector_size) is not int
        or isinstance(sector_size, bool)
        or not 0 <= sector_size <= 0xFFFFFFFF
        or type(chunk_size) is not int
        or isinstance(chunk_size, bool)
        or not 0 <= chunk_size <= 0xFFFFFFFF
        or type(plan_sha256) is not str
        or _SHA256.fullmatch(plan_sha256) is None
        or type(ready_sha256) is not str
        or _SHA256.fullmatch(ready_sha256) is None
    ):
        raise HelperRequestError("The fast-zero request cannot be encoded")
    return _FAST_ZERO_REQUEST_PACKET.pack(
        FAST_ZERO_PROTOCOL_MAGIC,
        PROTOCOL_VERSION,
        PACKET_REQUEST,
        0,
        request_id,
        major_number,
        minor_number,
        disk_sequence,
        target_size,
        sector_size,
        chunk_size,
        bytes.fromhex(plan_sha256),
        bytes.fromhex(ready_sha256),
        b"\0" * 8,
    )


def unpack_fast_zero_helper_request(
    packet: bytes,
    *,
    sys_root: Path = Path("/sys"),
) -> FastZeroHelperRequest:
    if type(packet) is not bytes or len(packet) != _FAST_ZERO_REQUEST_PACKET.size:
        raise HelperRequestError("The fast-zero request has the wrong size")
    (
        magic,
        version,
        packet_type,
        reserved,
        request_id,
        major_number,
        minor_number,
        disk_sequence,
        target_size,
        sector_size,
        chunk_size,
        plan_digest,
        ready_digest,
        trailing_reserved,
    ) = _FAST_ZERO_REQUEST_PACKET.unpack(packet)
    if (
        magic != FAST_ZERO_PROTOCOL_MAGIC
        or version != PROTOCOL_VERSION
        or packet_type != PACKET_REQUEST
        or reserved != 0
        or trailing_reserved != b"\0" * 8
    ):
        raise HelperRequestError("The fast-zero request is unsupported")
    try:
        device_number = os.makedev(major_number, minor_number)
    except (OverflowError, ValueError) as error:
        raise HelperRequestError("The fast-zero request has an invalid device number") from error
    request = FastZeroHelperRequest(
        request_id,
        FAST_ZERO_HELPER_PROFILE,
        _target_path_from_kernel(device_number, sys_root=sys_root),
        f"{major_number}:{minor_number}",
        disk_sequence,
        target_size,
        sector_size,
        chunk_size,
        plan_digest.hex(),
        ready_digest.hex(),
    )
    validate_fast_zero_helper_request(request)
    return request


def unpack_server_packet(packet: bytes) -> tuple[object, ...]:
    """Strictly decode one trusted-helper packet for the GUI-side runner."""

    if type(packet) is not bytes or len(packet) < _HEADER.size:
        raise HelperRequestError("The helper response packet is truncated")
    magic, version, packet_type, reserved = _HEADER.unpack(packet[:_HEADER.size])
    if magic != PROTOCOL_MAGIC or version != PROTOCOL_VERSION or reserved != 0:
        raise HelperRequestError("The helper response packet is unsupported")
    if packet_type == PACKET_READY and len(packet) == _HEADER.size:
        return ("ready",)
    if packet_type == PACKET_PREPARED and len(packet) == _CONTROL_PACKET.size:
        _, _, _, _, request_id = _CONTROL_PACKET.unpack(packet)
        return ("prepared", request_id)
    if packet_type == PACKET_PROGRESS and len(packet) == _PROGRESS_PACKET.size:
        _, _, _, _, request_id, phase_code, done, total = _PROGRESS_PACKET.unpack(packet)
        phase = PHASE_NAMES.get(phase_code)
        if phase is None or done > total:
            raise HelperRequestError("The helper progress packet is invalid")
        return ("progress", request_id, phase, done, total)
    if packet_type == PACKET_MUTATION_STARTED and len(packet) == _MUTATION_PACKET.size:
        _, _, _, _, request_id = _MUTATION_PACKET.unpack(packet)
        return ("mutation-started", request_id)
    if packet_type == PACKET_SUCCESS and len(packet) == _SUCCESS_PACKET.size:
        (
            _,
            _,
            _,
            _,
            request_id,
            major_number,
            minor_number,
            disk_sequence,
            size,
            sector_size,
            disk_signature,
            volume_id,
            source_digest,
            written_digest,
            readback_digest,
        ) = _SUCCESS_PACKET.unpack(packet)
        return (
            "success",
            request_id,
            major_number,
            minor_number,
            disk_sequence,
            size,
            sector_size,
            disk_signature,
            volume_id,
            source_digest.hex(),
            written_digest.hex(),
            readback_digest.hex(),
        )
    raise HelperRequestError("The helper response packet has an invalid type or size")


def unpack_windows_server_packet(packet: bytes) -> tuple[object, ...]:
    """Strictly decode one Windows-profile helper packet."""

    if type(packet) is not bytes or len(packet) < _HEADER.size:
        raise HelperRequestError("The Windows helper response is truncated")
    if packet[:len(WINDOWS_PROTOCOL_MAGIC)] != WINDOWS_PROTOCOL_MAGIC:
        raise HelperRequestError("The Windows helper response is unsupported")
    return unpack_server_packet(
        PROTOCOL_MAGIC + packet[len(WINDOWS_PROTOCOL_MAGIC):],
    )


def unpack_raw_server_packet(packet: bytes) -> tuple[object, ...]:
    """Strictly decode one raw-device helper packet for its runner."""

    if type(packet) is not bytes or len(packet) < _HEADER.size:
        raise HelperRequestError("The raw helper response is truncated")
    magic, version, packet_type, reserved = _HEADER.unpack(packet[:_HEADER.size])
    if magic != RAW_PROTOCOL_MAGIC or version != PROTOCOL_VERSION or reserved != 0:
        raise HelperRequestError("The raw helper response is unsupported")
    if packet_type == PACKET_READY and len(packet) == _HEADER.size:
        return ("ready",)
    if packet_type == PACKET_PREPARED and len(packet) == _CONTROL_PACKET.size:
        _, _, _, _, request_id = _CONTROL_PACKET.unpack(packet)
        return ("prepared", request_id)
    if packet_type == PACKET_PROGRESS and len(packet) == _PROGRESS_PACKET.size:
        _, _, _, _, request_id, phase_code, done, total = _PROGRESS_PACKET.unpack(packet)
        phase = PHASE_NAMES.get(phase_code)
        if phase is None or done > total:
            raise HelperRequestError("The raw helper progress packet is invalid")
        return ("progress", request_id, phase, done, total)
    if packet_type == PACKET_MUTATION_STARTED and len(packet) == _MUTATION_PACKET.size:
        _, _, _, _, request_id = _MUTATION_PACKET.unpack(packet)
        return ("mutation-started", request_id)
    if packet_type == PACKET_SUCCESS and len(packet) == _RAW_SUCCESS_PACKET.size:
        (
            _,
            _,
            _,
            _,
            request_id,
            major_number,
            minor_number,
            disk_sequence,
            target_size,
            sector_size,
            source_size,
            guard_size,
            target_tail_sanitized,
            final_verification,
            trailing_reserved,
            source_digest,
            written_digest,
            readback_digest,
        ) = _RAW_SUCCESS_PACKET.unpack(packet)
        if (
            target_tail_sanitized not in {0, 1}
            or final_verification not in {0, 1}
            or trailing_reserved != b"\0" * 2
        ):
            raise HelperRequestError("The raw helper result flags are invalid")
        if not final_verification and any(readback_digest):
            raise HelperRequestError("The raw helper returned an unexpected read-back digest")
        return (
            "success",
            request_id,
            major_number,
            minor_number,
            disk_sequence,
            target_size,
            sector_size,
            source_size,
            guard_size,
            bool(target_tail_sanitized),
            bool(final_verification),
            source_digest.hex(),
            written_digest.hex(),
            readback_digest.hex() if final_verification else "",
        )
    raise HelperRequestError("The raw helper response has an invalid type or size")


def _pack_fast_zero_result(result: FastZeroHelperResult) -> bytes:
    if type(result) is not FastZeroHelperResult:
        raise HelperError("The fast-zero helper result type is invalid")
    packet_type = {
        "success": PACKET_SUCCESS,
        "partial-cancel": PACKET_PARTIAL_CANCEL,
        "partial-failure": PACKET_PARTIAL_FAILURE,
    }.get(result.outcome)
    if packet_type is None:
        raise HelperError("The fast-zero helper result outcome is invalid")
    major_number, minor_number = (int(part) for part in result.major_minor.split(":", 1))
    values = (
        result.disk_sequence,
        result.target_size,
        result.logical_sector_size,
        result.chunk_size,
        result.scanned_bytes,
        result.written_bytes,
        result.skipped_bytes,
        result.verified_bytes,
        result.scanned_chunks,
        result.written_chunks,
        result.skipped_chunks,
        result.boundary_cleanup_bytes,
        result.failure_code,
    )
    if any(type(value) is not int or isinstance(value, bool) or value < 0 for value in values):
        raise HelperError("The fast-zero helper result counters are invalid")
    return _FAST_ZERO_RESULT_PACKET.pack(
        FAST_ZERO_PROTOCOL_MAGIC,
        PROTOCOL_VERSION,
        packet_type,
        0,
        result.request_id,
        major_number,
        minor_number,
        result.disk_sequence,
        result.target_size,
        result.logical_sector_size,
        result.chunk_size,
        result.scanned_bytes,
        result.written_bytes,
        result.skipped_bytes,
        result.verified_bytes,
        result.scanned_chunks,
        result.written_chunks,
        result.skipped_chunks,
        result.boundary_cleanup_bytes,
        result.failure_code,
        int(result.exclusive_open),
        int(result.cache_invalidated),
        int(result.complete),
        int(result.cleanup_verified),
        int(result.durable),
        b"\0" * 5,
    )


def unpack_fast_zero_server_packet(packet: bytes) -> tuple[object, ...]:
    """Strictly decode one target-only fast-zero helper packet."""

    if type(packet) is not bytes or len(packet) < _HEADER.size:
        raise HelperRequestError("The fast-zero helper response is truncated")
    magic, version, packet_type, reserved = _HEADER.unpack(packet[:_HEADER.size])
    if magic != FAST_ZERO_PROTOCOL_MAGIC or version != PROTOCOL_VERSION or reserved != 0:
        raise HelperRequestError("The fast-zero helper response is unsupported")
    if packet_type == PACKET_READY and len(packet) == _HEADER.size:
        return ("ready",)
    if packet_type == PACKET_PREPARED and len(packet) == _CONTROL_PACKET.size:
        _, _, _, _, request_id = _CONTROL_PACKET.unpack(packet)
        return ("prepared", request_id)
    if packet_type == PACKET_PROGRESS and len(packet) == _PROGRESS_PACKET.size:
        _, _, _, _, request_id, phase_code, done, total = _PROGRESS_PACKET.unpack(packet)
        phase = FAST_ZERO_PHASE_NAMES.get(phase_code)
        if phase is None or done > total:
            raise HelperRequestError("The fast-zero helper progress packet is invalid")
        return ("progress", request_id, phase, done, total)
    if packet_type == PACKET_MUTATION_STARTED and len(packet) == _MUTATION_PACKET.size:
        _, _, _, _, request_id = _MUTATION_PACKET.unpack(packet)
        return ("mutation-started", request_id)
    if packet_type not in {PACKET_SUCCESS, PACKET_PARTIAL_CANCEL, PACKET_PARTIAL_FAILURE}:
        raise HelperRequestError("The fast-zero helper response has an invalid type")
    if len(packet) != _FAST_ZERO_RESULT_PACKET.size:
        raise HelperRequestError("The fast-zero helper result has the wrong size")
    unpacked = _FAST_ZERO_RESULT_PACKET.unpack(packet)
    (
        _, _, _, _, request_id, major_number, minor_number, disk_sequence,
        target_size, sector_size, chunk_size, scanned_bytes, written_bytes,
        skipped_bytes, verified_bytes, scanned_chunks, written_chunks,
        skipped_chunks, cleanup_bytes, failure_code, exclusive_open,
        cache_invalidated, complete, cleanup_verified, durable, trailing_reserved,
    ) = unpacked
    if (
        any(flag not in {0, 1} for flag in (
            exclusive_open, cache_invalidated, complete, cleanup_verified, durable,
        ))
        or trailing_reserved != b"\0" * 5
        or scanned_bytes != written_bytes + skipped_bytes
        or scanned_chunks != written_chunks + skipped_chunks
        or scanned_bytes > target_size
        or verified_bytes > target_size
        or not exclusive_open
        or not cache_invalidated
        or not durable
    ):
        raise HelperRequestError("The fast-zero helper result accounting is invalid")
    outcome = {
        PACKET_SUCCESS: "success",
        PACKET_PARTIAL_CANCEL: "partial-cancel",
        PACKET_PARTIAL_FAILURE: "partial-failure",
    }[packet_type]
    if outcome == "success":
        valid = (
            complete
            and not cleanup_verified
            and cleanup_bytes == 0
            and failure_code == FAST_ZERO_FAILURE_NONE
            and scanned_bytes == target_size
            and verified_bytes == target_size
        )
    else:
        valid = (
            not complete
            and cleanup_verified
            and 0 < cleanup_bytes <= target_size
            and failure_code != FAST_ZERO_FAILURE_NONE
            and (outcome != "partial-cancel" or failure_code == FAST_ZERO_FAILURE_CANCELLED)
            and (outcome != "partial-failure" or failure_code != FAST_ZERO_FAILURE_CANCELLED)
        )
    if not valid:
        raise HelperRequestError("The fast-zero helper result state is invalid")
    return (
        outcome,
        request_id,
        major_number,
        minor_number,
        disk_sequence,
        target_size,
        sector_size,
        chunk_size,
        scanned_bytes,
        written_bytes,
        skipped_bytes,
        verified_bytes,
        scanned_chunks,
        written_chunks,
        skipped_chunks,
        cleanup_bytes,
        failure_code,
        bool(exclusive_open),
        bool(cache_invalidated),
        bool(complete),
        bool(cleanup_verified),
        bool(durable),
    )


def pack_helper_control(request_id: bytes, *, commit: bool) -> bytes:
    """Encode the only two client decisions accepted after root preflight."""

    if type(request_id) is not bytes or len(request_id) != 16 or type(commit) is not bool:
        raise HelperRequestError("The privileged control decision cannot be encoded")
    return _CONTROL_PACKET.pack(
        PROTOCOL_MAGIC,
        PROTOCOL_VERSION,
        PACKET_COMMIT if commit else PACKET_CANCEL,
        0,
        request_id,
    )


def pack_windows_helper_control(request_id: bytes, *, commit: bool) -> bytes:
    packet = pack_helper_control(request_id, commit=commit)
    return WINDOWS_PROTOCOL_MAGIC + packet[len(PROTOCOL_MAGIC):]


def pack_raw_helper_control(request_id: bytes, *, commit: bool) -> bytes:
    if type(request_id) is not bytes or len(request_id) != 16 or type(commit) is not bool:
        raise HelperRequestError("The privileged raw control decision cannot be encoded")
    return _CONTROL_PACKET.pack(
        RAW_PROTOCOL_MAGIC,
        PROTOCOL_VERSION,
        PACKET_COMMIT if commit else PACKET_CANCEL,
        0,
        request_id,
    )


def pack_fast_zero_helper_control(request_id: bytes, *, commit: bool) -> bytes:
    if type(request_id) is not bytes or len(request_id) != 16 or type(commit) is not bool:
        raise HelperRequestError("The fast-zero control decision cannot be encoded")
    return _CONTROL_PACKET.pack(
        FAST_ZERO_PROTOCOL_MAGIC,
        PROTOCOL_VERSION,
        PACKET_COMMIT if commit else PACKET_CANCEL,
        0,
        request_id,
    )


def _send_packet(channel: socket.socket, packet: bytes) -> None:
    try:
        count = channel.send(packet, socket.MSG_DONTWAIT)
    except OSError as error:
        raise HelperError("The privileged protocol peer disconnected") from error
    if count != len(packet):
        raise HelperError("The privileged protocol packet was not sent atomically")


class _ProtocolProgress:
    def __init__(
        self,
        channel: socket.socket,
        request_id: bytes,
        expected_uid: int,
        protocol_magic: bytes = PROTOCOL_MAGIC,
    ) -> None:
        if protocol_magic not in {
            PROTOCOL_MAGIC,
            WINDOWS_PROTOCOL_MAGIC,
            RAW_PROTOCOL_MAGIC,
            FAST_ZERO_PROTOCOL_MAGIC,
        }:
            raise HelperRequestError("The privileged protocol profile is invalid")
        self._channel = channel
        self._request_id = request_id
        self._expected_uid = expected_uid
        self._protocol_magic = protocol_magic
        self._connected = True
        self._mutation_started = False

    def prepare_mutation(self) -> None:
        if self._mutation_started:
            raise HelperError("The privileged mutation boundary was repeated")
        _poll_cancel(
            self._channel,
            expected_uid=self._expected_uid,
            request_id=self._request_id,
            protocol_magic=self._protocol_magic,
        )
        _send_packet(
            self._channel,
            _CONTROL_PACKET.pack(
                self._protocol_magic,
                PROTOCOL_VERSION,
                PACKET_PREPARED,
                0,
                self._request_id,
            ),
        )

    def begin_mutation(self) -> None:
        if self._mutation_started:
            raise HelperError("The privileged mutation boundary was repeated")
        # COMMIT is irreversible. Once accepted, loss of the UI cannot make
        # the helper abandon partially written media.
        self._mutation_started = True
        try:
            _send_packet(
                self._channel,
                _MUTATION_PACKET.pack(
                    self._protocol_magic,
                    PROTOCOL_VERSION,
                    PACKET_MUTATION_STARTED,
                    0,
                    self._request_id,
                ),
            )
        except HelperError:
            self._connected = False

    def __call__(self, phase: str, done: int, total: int) -> None:
        phase_codes = (
            FAST_ZERO_PHASE_CODES
            if self._protocol_magic == FAST_ZERO_PROTOCOL_MAGIC
            else PHASE_CODES
        )
        phase_code = phase_codes.get(phase)
        if phase_code is None or type(done) is not int or type(total) is not int:
            raise HelperError("The privileged transaction emitted invalid progress")
        if not self._mutation_started:
            _poll_cancel(
                self._channel,
                expected_uid=self._expected_uid,
                request_id=self._request_id,
                protocol_magic=self._protocol_magic,
            )
        if self._connected:
            try:
                _send_packet(
                    self._channel,
                    _PROGRESS_PACKET.pack(
                        self._protocol_magic,
                        PROTOCOL_VERSION,
                        PACKET_PROGRESS,
                        0,
                        self._request_id,
                        phase_code,
                        done,
                        total,
                    ),
                )
            except HelperError:
                if not self._mutation_started:
                    raise
                self._connected = False


def _receive_request(
    channel: socket.socket,
    *,
    expected_uid: int,
) -> tuple[bytes, int]:
    credentials_size = struct.calcsize("3i")
    descriptor_size = array.array("i").itemsize
    try:
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        packet, ancillary, flags, _address = channel.recvmsg(
            MAX_PROTOCOL_PACKET,
            socket.CMSG_SPACE(credentials_size) + socket.CMSG_SPACE(descriptor_size),
        )
    except OSError as error:
        raise HelperRequestError("Could not receive the privileged request") from error
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise HelperRequestError("The privileged request or descriptor list was truncated")
    received_fds: list[int] = []
    credentials: list[tuple[int, int, int]] = []
    try:
        for level, kind, value in ancillary:
            if level != socket.SOL_SOCKET:
                raise HelperRequestError("The privileged request contains unknown ancillary data")
            if kind == socket.SCM_RIGHTS:
                if len(value) % descriptor_size:
                    raise HelperRequestError("The privileged source descriptor is malformed")
                descriptors = array.array("i")
                descriptors.frombytes(value)
                received_fds.extend(int(item) for item in descriptors)
            elif kind == socket.SCM_CREDENTIALS:
                if len(value) != credentials_size:
                    raise HelperRequestError("The privileged peer credentials are malformed")
                credentials.append(struct.unpack("3i", value))
            else:
                raise HelperRequestError("The privileged request contains unknown ancillary data")
        if len(received_fds) != 1 or len(credentials) != 1:
            raise HelperRequestError(
                "The privileged request must contain one source descriptor and one credential record",
            )
        _pid, uid, _gid = credentials[0]
        if uid != expected_uid:
            raise HelperRequestError("The privileged message credentials do not match pkexec")
        descriptor = received_fds.pop()
        try:
            os.set_inheritable(descriptor, False)
        except OSError as error:
            os.close(descriptor)
            raise HelperRequestError("Could not secure the privileged source descriptor") from error
        return packet, descriptor
    finally:
        for descriptor in received_fds:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _receive_target_only_request(
    channel: socket.socket,
    *,
    expected_uid: int,
) -> bytes:
    """Receive one credential-bound request and reject every transferred FD."""

    credentials_size = struct.calcsize("3i")
    descriptor_size = array.array("i").itemsize
    try:
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        packet, ancillary, flags, _address = channel.recvmsg(
            MAX_PROTOCOL_PACKET,
            socket.CMSG_SPACE(credentials_size) + socket.CMSG_SPACE(descriptor_size),
        )
    except OSError as error:
        raise HelperRequestError("Could not receive the fast-zero request") from error
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise HelperRequestError("The fast-zero request or ancillary data was truncated")
    credentials: list[tuple[int, int, int]] = []
    received_fds: list[int] = []
    try:
        for level, kind, value in ancillary:
            if level != socket.SOL_SOCKET:
                raise HelperRequestError("The fast-zero request contains unknown ancillary data")
            if kind == socket.SCM_RIGHTS:
                if len(value) % descriptor_size:
                    raise HelperRequestError("The fast-zero descriptor list is malformed")
                descriptors = array.array("i")
                descriptors.frombytes(value)
                received_fds.extend(int(item) for item in descriptors)
            elif kind == socket.SCM_CREDENTIALS and len(value) == credentials_size:
                credentials.append(struct.unpack("3i", value))
            else:
                raise HelperRequestError("The fast-zero request has invalid credentials")
        if received_fds:
            raise HelperRequestError("The target-only fast-zero request must not transfer descriptors")
        if len(credentials) != 1 or credentials[0][1] != expected_uid:
            raise HelperRequestError("The fast-zero request credentials do not match pkexec")
        return packet
    finally:
        for descriptor in received_fds:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _receive_control(
    channel: socket.socket,
    *,
    expected_uid: int,
    request_id: bytes,
    timeout: float = CONTROL_TIMEOUT_SECONDS,
    protocol_magic: bytes = PROTOCOL_MAGIC,
) -> bool:
    """Receive one authenticated COMMIT/CANCEL packet after target preflight."""

    credentials_size = struct.calcsize("3i")
    try:
        readable, _, _ = select.select(
            [channel],
            [],
            [],
            timeout,
        )
    except OSError as error:
        raise HelperRequestError("Could not wait for the privileged commit decision") from error
    if not readable:
        raise HelperRequestError("The privileged commit decision timed out")
    try:
        packet, ancillary, flags, _address = channel.recvmsg(
            MAX_PROTOCOL_PACKET,
            socket.CMSG_SPACE(credentials_size),
        )
    except OSError as error:
        raise HelperRequestError("Could not receive the privileged commit decision") from error
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise HelperRequestError("The privileged commit decision was truncated")
    credentials: list[tuple[int, int, int]] = []
    for level, kind, value in ancillary:
        if (
            level != socket.SOL_SOCKET
            or kind != socket.SCM_CREDENTIALS
            or len(value) != credentials_size
        ):
            raise HelperRequestError("The privileged commit decision has invalid credentials")
        credentials.append(struct.unpack("3i", value))
    if len(credentials) != 1 or credentials[0][1] != expected_uid:
        raise HelperRequestError("The privileged commit decision does not match pkexec")
    if type(packet) is not bytes or len(packet) != _CONTROL_PACKET.size:
        raise HelperRequestError("The privileged commit decision has the wrong size")
    magic, version, packet_type, reserved, observed_id = _CONTROL_PACKET.unpack(packet)
    if (
        magic != protocol_magic
        or version != PROTOCOL_VERSION
        or packet_type not in {PACKET_COMMIT, PACKET_CANCEL}
        or reserved != 0
        or observed_id != request_id
    ):
        raise HelperRequestError("The privileged commit decision is invalid")
    return packet_type == PACKET_COMMIT


def _poll_cancel(
    channel: socket.socket,
    *,
    expected_uid: int,
    request_id: bytes,
    protocol_magic: bytes = PROTOCOL_MAGIC,
) -> None:
    """Consume an in-band CANCEL promptly while root preflight is still safe."""

    try:
        readable, _, _ = select.select([channel], [], [], 0)
    except OSError as error:
        raise HelperRequestError("Could not poll the privileged cancellation channel") from error
    if not readable:
        return
    if _receive_control(
        channel,
        expected_uid=expected_uid,
        request_id=request_id,
        timeout=0,
        protocol_magic=protocol_magic,
    ):
        raise HelperRequestError("COMMIT arrived before the privileged helper was prepared")
    raise HelperCancelled("The device transaction was cancelled before mutation")


def _poll_fast_zero_postcommit_cancel(
    channel: socket.socket,
    *,
    expected_uid: int,
    request_id: bytes,
) -> None:
    """Poll one authenticated post-commit CANCEL only at chunk boundaries."""

    try:
        readable, _, _ = select.select([channel], [], [], 0)
    except OSError as error:
        raise HelperRequestError("Could not poll fast-zero cancellation") from error
    if not readable:
        return
    if _receive_control(
        channel,
        expected_uid=expected_uid,
        request_id=request_id,
        timeout=0,
        protocol_magic=FAST_ZERO_PROTOCOL_MAGIC,
    ):
        raise HelperRequestError("The fast-zero COMMIT decision was repeated")
    raise HelperCancelled("The fast-zero transaction was cancelled after commit")


def _protocol_channel(expected_uid: int) -> socket.socket:
    try:
        channel = socket.socket(fileno=0)
        if channel.family != socket.AF_UNIX or channel.type & 0xF != socket.SOCK_SEQPACKET:
            raise HelperRequestError("Standard input is not the required local packet channel")
        peer_pid, peer_uid, _peer_gid = struct.unpack(
            "3i",
            channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
        )
    except HelperRequestError:
        raise
    except OSError as error:
        raise HelperRequestError("Could not authenticate the privileged protocol channel") from error
    if peer_pid <= 0 or peer_uid != expected_uid:
        raise HelperRequestError("The privileged protocol peer does not match pkexec")
    try:
        # Enable credentials before READY so an eager peer cannot enqueue the
        # descriptor packet before Linux starts attaching SCM_CREDENTIALS.
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    except OSError as error:
        raise HelperRequestError("Could not enable privileged peer credentials") from error
    return channel


def _invoking_uid() -> int:
    value = os.environ.get("PKEXEC_UID")
    if value is None or not value.isascii() or not value.isdecimal():
        raise HelperRequestError("The helper was not launched by pkexec")
    uid = int(value, 10)
    if uid < 0:
        raise HelperRequestError("The invoking user identity is invalid")
    return uid


def _require_initial_namespaces() -> None:
    """Reject caller-controlled mount/user namespaces before touching /dev."""

    for namespace in ("mnt", "user"):
        try:
            ours = os.stat(f"/proc/self/ns/{namespace}")
            initial = os.stat(f"/proc/1/ns/{namespace}")
        except OSError as error:
            raise HelperRequestError("Could not verify the helper namespaces") from error
        if (ours.st_dev, ours.st_ino) != (initial.st_dev, initial.st_ino):
            raise HelperRequestError(
                "The helper is not running in the initial trusted host namespaces",
            )


def _require_root_owned_file(path: str, *, executable: bool) -> None:
    try:
        status = os.lstat(path)
    except OSError as error:
        raise HelperRequestError("The installed privileged helper is unavailable") from error
    required = 0o500 if executable else 0o400
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != 0
        or status.st_mode & 0o022
        or stat.S_IMODE(status.st_mode) & required != required
    ):
        raise HelperRequestError("The installed privileged helper has unsafe ownership or mode")


def _verify_installed_helper() -> None:
    try:
        actual = os.path.realpath(__file__)
    except (OSError, TypeError) as error:
        raise HelperRequestError("The privileged helper location is invalid") from error
    if actual != INSTALLED_HELPER_SCRIPT or os.path.normpath(__file__) != __file__:
        raise HelperRequestError("The privileged helper is not running from its fixed installation path")
    _require_root_owned_file(INSTALLED_HELPER_SCRIPT, executable=False)
    for parent in (
        "/usr/libexec/isopropyl",
        "/usr/libexec",
        "/usr",
    ):
        try:
            status = os.lstat(parent)
        except OSError as error:
            raise HelperRequestError("The privileged helper parent directory is unavailable") from error
        if (
            not stat.S_ISDIR(status.st_mode)
            or status.st_uid != 0
            or status.st_mode & 0o022
        ):
            raise HelperRequestError("The privileged helper parent directory is unsafe")


def _harden_process(invoking_uid: int) -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, OSError, ValueError) as error:
        raise HelperRequestError("Could not disable privileged core dumps") from error
    try:
        unexpected = tuple(int(name) for name in os.listdir("/proc/self/fd"))
    except (OSError, ValueError) as error:
        raise HelperRequestError("Could not enumerate privileged descriptors") from error
    for descriptor in unexpected:
        if descriptor > 2:
            try:
                os.close(descriptor)
            except OSError:
                pass
    os.umask(0o077)
    try:
        os.chdir("/")
    except OSError as error:
        raise HelperRequestError("Could not enter the privileged working directory") from error
    # No operation in the helper executes another program or needs locale,
    # configuration, a home directory, or a network proxy.
    os.environ.clear()
    os.environ["PKEXEC_UID"] = str(invoking_uid)
    os.environ["LANG"] = "C"


def _defer_ordinary_termination() -> None:
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
        signal.signal(signum, signal.SIG_IGN)


def _reset_ordinary_termination() -> None:
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
        signal.signal(signum, signal.SIG_DFL)
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_SETMASK, set())


def main(argv: list[str] | None = None) -> int:
    _reset_ordinary_termination()
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    source_descriptor = -1
    channel: socket.socket | None = None
    try:
        if os.geteuid() != 0:
            raise HelperRequestError("The device helper must run as root")
        if struct.calcsize("P") != 8:
            raise HelperRequestError("The device helper requires 64-bit Linux userspace")
        _verify_installed_helper()
        arguments = sys.argv[1:] if argv is None else argv
        if len(arguments) != 1 or arguments[0] not in {
            OPERATION,
            WINDOWS_OPERATION,
            RAW_OPERATION,
            FAST_ZERO_OPERATION,
        }:
            raise HelperRequestError("The privileged helper operation is unsupported")
        operation = arguments[0]
        protocol_magic = {
            OPERATION: PROTOCOL_MAGIC,
            WINDOWS_OPERATION: WINDOWS_PROTOCOL_MAGIC,
            RAW_OPERATION: RAW_PROTOCOL_MAGIC,
            FAST_ZERO_OPERATION: FAST_ZERO_PROTOCOL_MAGIC,
        }[operation]
        invoking_uid = _invoking_uid()
        _require_initial_namespaces()
        _harden_process(invoking_uid)
        channel = _protocol_channel(invoking_uid)
        _send_packet(
            channel,
            _HEADER.pack(protocol_magic, PROTOCOL_VERSION, PACKET_READY, 0),
        )
        if operation == FAST_ZERO_OPERATION:
            packet = _receive_target_only_request(channel, expected_uid=invoking_uid)
            request: HelperRequest | RawHelperRequest | FastZeroHelperRequest = (
                unpack_fast_zero_helper_request(packet)
            )
        else:
            packet, source_descriptor = _receive_request(
                channel,
                expected_uid=invoking_uid,
            )
            request = (
                unpack_helper_request(packet)
                if operation == OPERATION
                else unpack_windows_helper_request(packet)
                if operation == WINDOWS_OPERATION
                else unpack_raw_helper_request(packet)
            )
        progress = _ProtocolProgress(
            channel,
            request.request_id,
            invoking_uid,
            protocol_magic,
        )

        def begin_mutation() -> None:
            # All root-side source/target checks and the exclusive open have
            # completed. The authenticated peer now chooses the exact commit
            # boundary; HUP or CANCEL before COMMIT cannot touch the disk.
            progress.prepare_mutation()
            if not _receive_control(
                channel,
                expected_uid=invoking_uid,
                request_id=request.request_id,
                protocol_magic=protocol_magic,
            ):
                raise HelperCancelled("The device transaction was cancelled before mutation")
            _defer_ordinary_termination()
            progress.begin_mutation()

        result: HelperResult | RawHelperResult | FastZeroHelperResult
        if type(request) is HelperRequest:
            result = execute_helper_transaction(
                request,
                source_descriptor=source_descriptor,
                invoking_uid=invoking_uid,
                progress=progress,
                mutation_started=begin_mutation,
            )
        elif type(request) is RawHelperRequest:
            result = execute_raw_helper_transaction(
                request,
                source_descriptor=source_descriptor,
                invoking_uid=invoking_uid,
                progress=progress,
                mutation_started=begin_mutation,
            )
        elif type(request) is FastZeroHelperRequest:
            result = execute_fast_zero_helper_transaction(
                request,
                progress=progress,
                mutation_started=begin_mutation,
                postcommit_cancel=lambda: _poll_fast_zero_postcommit_cancel(
                    channel,
                    expected_uid=invoking_uid,
                    request_id=request.request_id,
                ),
            )
        else:
            raise HelperRequestError("The privileged helper request type is unsupported")
        major_number, minor_number = (
            int(part) for part in result.major_minor.split(":", 1)
        )
        try:
            if type(result) is HelperResult:
                response = _SUCCESS_PACKET.pack(
                    (
                        WINDOWS_PROTOCOL_MAGIC
                        if result.profile == WINDOWS_HELPER_PROFILE
                        else PROTOCOL_MAGIC
                    ),
                    PROTOCOL_VERSION,
                    PACKET_SUCCESS,
                    0,
                    result.request_id,
                    major_number,
                    minor_number,
                    result.disk_sequence,
                    result.bytes_written,
                    result.logical_sector_size,
                    result.disk_signature,
                    result.volume_id,
                    bytes.fromhex(result.source_sha256),
                    bytes.fromhex(result.written_sha256),
                    bytes.fromhex(result.readback_sha256),
                )
            elif type(result) is RawHelperResult:
                response = _RAW_SUCCESS_PACKET.pack(
                    RAW_PROTOCOL_MAGIC,
                    PROTOCOL_VERSION,
                    PACKET_SUCCESS,
                    0,
                    result.request_id,
                    major_number,
                    minor_number,
                    result.disk_sequence,
                    result.target_size,
                    result.logical_sector_size,
                    result.bytes_written,
                    result.front_guard_bytes,
                    int(result.target_tail_sanitized),
                    int(result.final_verification),
                    b"\0" * 2,
                    bytes.fromhex(result.source_sha256),
                    bytes.fromhex(result.written_sha256),
                    (
                        bytes.fromhex(result.readback_sha256)
                        if result.final_verification
                        else b"\0" * 32
                    ),
                )
            elif type(result) is FastZeroHelperResult:
                response = _pack_fast_zero_result(result)
            else:
                raise HelperError("The privileged helper result type is unsupported")
            _send_packet(channel, response)
        except HelperError:
            # The disk has already passed durability and complete read-back.
            # A vanished GUI cannot turn that verified outcome into a failed
            # storage transaction, though the GUI will report it as unknown.
            pass
        return 0
    except HelperCancelled:
        return HelperCancelled.exit_code
    except HelperError as error:
        sys.stderr.write(_bounded(error, "The privileged transaction failed") + "\n")
        return error.exit_code
    except SystemExit:
        raise
    except BaseException:
        sys.stderr.write("The privileged transaction failed unexpectedly\n")
        return 5
    finally:
        if source_descriptor >= 0:
            try:
                os.close(source_descriptor)
            except OSError:
                pass
        if channel is not None:
            try:
                channel.close()
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
