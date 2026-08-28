from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Root-side versioned device transactions.

This module is the narrow privileged half of the Syslinux and generic raw/DD
image pipelines.  It does not trust the unprivileged plans or their serialized
target observations.  The caller transfers one already prepared anonymous
regular file; the selected exact protocol validates and hashes that seekable
descriptor before opening a target.  The helper then derives safety properties
from the opened block descriptor and kernel sysfs, retains one Linux exclusive
block-device claim and one BSD lock through writing, durability, cache
invalidation, and required read-back, and reports a bounded machine-readable
result.

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
RAW_HELPER_PROFILE = "io.github.codebooker.isopropyl/raw-device-helper/v1"
SECTOR_SIZE = 512
COPY_BYTES = 4 * 1024 * 1024
MAX_IMAGE_BYTES = 128 * 1024 * 1024 * 1024
MAX_RAW_SOURCE_BYTES = 64 * 1024 * 1024 * 1024 * 1024
MAX_RAW_TARGET_BYTES = 64 * 1024 * 1024 * 1024 * 1024 * 1024
RAW_FRONT_GUARD_BYTES = 1024 * 1024
MAX_TOPOLOGY_NODES = 4_096
MAX_DIAGNOSTIC_BYTES = 4_096
CONTROL_TIMEOUT_SECONDS = 30.0
SYSLINUX_MBR_602_SHA256 = (
    "4746f74bc9b9d3d579c41988a4a29bb7ac932ad1c70470ea779ea161eb799b64"
)
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
RAW_PROTOCOL_MAGIC = b"ISOPROPYL-RAW001"
PROTOCOL_VERSION = 1
PACKET_READY = 1
PACKET_REQUEST = 2
PACKET_PROGRESS = 3
PACKET_SUCCESS = 4
PACKET_PREPARED = 5
PACKET_COMMIT = 6
PACKET_CANCEL = 7
PACKET_MUTATION_STARTED = 8
OPERATION = "write-image-v1"
RAW_OPERATION = "write-raw-image-v1"
PHASE_CODES = {
    "source-validation": 1,
    "writing": 2,
    "preactivation-readback": 3,
    "readback": 4,
}
PHASE_NAMES = {value: key for key, value in PHASE_CODES.items()}
_HEADER = struct.Struct("!16sBBH")
_REQUEST_PACKET = struct.Struct("!16sBBH16sIIQQIII32s")
_PROGRESS_PACKET = struct.Struct("!16sBBH16sB3xQQ")
_CONTROL_PACKET = struct.Struct("!16sBBH16s")
_MUTATION_PACKET = _CONTROL_PACKET
_SUCCESS_PACKET = struct.Struct("!16sBBH16sIIQQIII32s32s32s")
_RAW_REQUEST_PACKET = struct.Struct("!16sBBH16sIIQQIQB7s32s")
_RAW_SUCCESS_PACKET = struct.Struct("!16sBBH16sIIQQIQIBB2s32s32s32s")
MAX_PROTOCOL_PACKET = max(
    _REQUEST_PACKET.size,
    _RAW_REQUEST_PACKET.size,
    _PROGRESS_PACKET.size,
    _CONTROL_PACKET.size,
    _SUCCESS_PACKET.size,
    _RAW_SUCCESS_PACKET.size,
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
    if request.profile != HELPER_PROFILE:
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
        raise HelperRequestError("The expected Syslinux media identifiers are invalid")
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
    source_mbr = _validate_syslinux_image_layout(
        source_descriptor,
        request,
        read_at=operations.pread,
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
        # of the image is durable and verified, then durability/cache eviction
        # and a complete physical-path read-back are required again.
        activation_attempted = True
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
            HELPER_PROFILE,
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
        if protocol_magic not in {PROTOCOL_MAGIC, RAW_PROTOCOL_MAGIC}:
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
        phase_code = PHASE_CODES.get(phase)
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
        if len(arguments) != 1 or arguments[0] not in {OPERATION, RAW_OPERATION}:
            raise HelperRequestError("The privileged helper operation is unsupported")
        operation = arguments[0]
        protocol_magic = (
            PROTOCOL_MAGIC if operation == OPERATION else RAW_PROTOCOL_MAGIC
        )
        invoking_uid = _invoking_uid()
        _require_initial_namespaces()
        _harden_process(invoking_uid)
        channel = _protocol_channel(invoking_uid)
        _send_packet(
            channel,
            _HEADER.pack(protocol_magic, PROTOCOL_VERSION, PACKET_READY, 0),
        )
        packet, source_descriptor = _receive_request(
            channel,
            expected_uid=invoking_uid,
        )
        request: HelperRequest | RawHelperRequest = (
            unpack_helper_request(packet)
            if operation == OPERATION
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

        result: HelperResult | RawHelperResult
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
        else:
            raise HelperRequestError("The privileged helper request type is unsupported")
        major_number, minor_number = (
            int(part) for part in result.major_minor.split(":", 1)
        )
        try:
            if type(result) is HelperResult:
                response = _SUCCESS_PACKET.pack(
                    PROTOCOL_MAGIC,
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
