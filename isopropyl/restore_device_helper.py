from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""One-lease privileged full-format transaction.

This module is the root side of the desktop application's isolated Verified
full overwrite + format PolicyKit path.  One whole-disk descriptor is
authenticated, locked, and retained from PREPARED through a verified full zero,
deterministic partition creation, filesystem creation, and final attestations.
No command is executed through a shell.
"""

import array
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import resource
import signal
import stat
import subprocess
import select
import socket
import struct
import sys
import time
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


BLKRRPART = 0x125F
BLKROGET = 0x125E
BLKFLSBUF = 0x1261
BLKSSZGET = 0x1268
BLKGETSIZE64 = 0x80081272
BLKGETDISKSEQ = 0x80081280
RESTORE_DEVICE_PROFILE = "io.github.codebooker.isopropyl/restore-device/v2"
RESTORE_DEVICE_OPERATION = "restore-device-v2"
FILESYSTEM_RECEIPT_PROFILE = (
    "io.github.codebooker.isopropyl/restore-device/post-format-receipt/v1"
)
INSTALLED_SCRIPT_PATH = "/usr/libexec/isopropyl/restore_device_helper.py"
DEFAULT_CHUNK_BYTES = 8 * 1024 * 1024
MAX_CHILD_OUTPUT = 64 * 1024
CHILD_TIMEOUT_SECONDS = 300.0
_CHILD_TERM_GRACE_SECONDS = 0.5
_CHILD_KILL_GRACE_SECONDS = 2.0
_MAX_CHILD_DESCENDANTS = 4096
_MAX_CHILDREN_FILE_BYTES = 64 * 1024
_ORDINARY_TERMINATION_SIGNALS = (
    signal.SIGINT,
    signal.SIGHUP,
    signal.SIGTERM,
    signal.SIGQUIT,
)

_SFDISK = "/usr/sbin/sfdisk"
_UDEVADM = "/usr/bin/udevadm"
_WHOLE_DISK = re.compile(
    r"/dev/(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|mmcblk\d+|ubd[a-z]+)\Z",
)
_MAJOR_MINOR = re.compile(r"(?:0|[1-9]\d*):(?:0|[1-9]\d*)\Z")
_FAT_FORBIDDEN = frozenset('"*/:<>?\\|+,.;=[]')
_WINDOWS_FORBIDDEN = frozenset('"*/:<>?\\|')
_GPT_DATA_TYPE = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
_MINIMUM_CAPACITY = 16 * 1024 * 1024
_MAXIMUM_CAPACITY = 64 * 1024**4
_MAX_TOPOLOGY_NODES = 4096
_WIRE_MAGIC = b"ISOPROPYL-RST02!"
_WIRE_VERSION = 2
PACKET_REQUEST = 1
PACKET_READY = 2
PACKET_PREPARED = 3
PACKET_COMMIT = 4
PACKET_CANCEL = 5
PACKET_PROGRESS = 6
PACKET_RESULT = 7
PACKET_ERROR = 8
_HEADER = struct.Struct("!16sBBH")
_REQUEST = struct.Struct("!16sBBH16sIIQQIQQIBBQH128s32s")
_CONTROL = struct.Struct("!16sBBH16s32s")
_PROGRESS = struct.Struct("!16sBBH16sB7xQQ")
_RESULT = struct.Struct("!16sBBH16sIIQQQQQQIIQQ32sBBHII128s32s32s")
_ERROR = struct.Struct("!16sBBH16sI512s")
MAX_PROTOCOL_PACKET = max(
    _REQUEST.size, _CONTROL.size, _PROGRESS.size, _RESULT.size, _ERROR.size,
)


class Filesystem(str, Enum):
    FAT32 = "fat32"
    NTFS = "ntfs"


class PartitionTable(str, Enum):
    MBR = "mbr"
    GPT = "gpt"


_FILESYSTEM_CODE = {Filesystem.FAT32: 1, Filesystem.NTFS: 2}
_FILESYSTEM_FROM_CODE = {value: key for key, value in _FILESYSTEM_CODE.items()}
_TABLE_CODE = {PartitionTable.MBR: 1, PartitionTable.GPT: 2}
_TABLE_FROM_CODE = {value: key for key, value in _TABLE_CODE.items()}
_PHASE_CODE = {"zero-scan": 1, "zero-readback": 2}


@dataclass(frozen=True)
class FormatPlan:
    device_path: str
    device_identity: tuple[str, int, str, str, str, str]
    filesystem: Filesystem
    partition_table: PartitionTable
    label: str = ""
    allocation_unit_size: int | None = None


class HelperError(RuntimeError):
    pass


class HelperTargetError(HelperError):
    pass


class HelperVerificationError(HelperError):
    pass


class HelperCancelled(HelperError):
    pass


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


def _coerce_plan(value: object) -> FormatPlan:
    try:
        source_identity = value.device_identity
        identity = (
            value.device_path,
            source_identity[1],
            "",
            "",
            "",
            source_identity[5],
        )
        filesystem = Filesystem(value.filesystem.value)
        table = PartitionTable(value.partition_table.value)
        plan = FormatPlan(
            value.device_path,
            identity,
            filesystem,
            table,
            value.label,
            value.allocation_unit_size,
        )
    except (AttributeError, IndexError, TypeError, ValueError) as error:
        raise HelperTargetError("The restore format plan is malformed") from error
    validate_plan(plan)
    return plan


def validate_plan(plan: FormatPlan) -> None:
    if type(plan) is not FormatPlan:
        raise HelperTargetError("An exact restore format plan is required")
    if _WHOLE_DISK.fullmatch(plan.device_path) is None:
        raise HelperTargetError("The restore target path is unsafe")
    if (
        type(plan.device_identity) is not tuple
        or len(plan.device_identity) != 6
        or plan.device_identity[0] != plan.device_path
        or type(plan.device_identity[1]) is not int
        or not _MINIMUM_CAPACITY <= plan.device_identity[1] <= _MAXIMUM_CAPACITY
        or type(plan.device_identity[5]) is not str
        or _MAJOR_MINOR.fullmatch(plan.device_identity[5]) is None
    ):
        raise HelperTargetError("The restore device identity is malformed")
    if type(plan.filesystem) is not Filesystem or type(plan.partition_table) is not PartitionTable:
        raise HelperTargetError("The restore filesystem or partition table is unsupported")
    if type(plan.label) is not str or plan.label != plan.label.strip():
        raise HelperTargetError("The restore label is malformed")
    try:
        utf16_units = len(plan.label.encode("utf-16-le")) // 2
    except UnicodeEncodeError as error:
        raise HelperTargetError("The restore label is malformed") from error
    if any(ord(character) < 32 or ord(character) == 127 for character in plan.label):
        raise HelperTargetError("The restore label contains control characters")
    if plan.filesystem is Filesystem.FAT32:
        if (
            not plan.label.isascii()
            or len(plan.label) > 11
            or any(character in _FAT_FORBIDDEN for character in plan.label)
        ):
            raise HelperTargetError("The FAT32 label is unsupported")
    elif (
        utf16_units > 32
        or any(character in _WINDOWS_FORBIDDEN for character in plan.label)
    ):
        raise HelperTargetError("The NTFS label is unsupported")
    allocation = plan.allocation_unit_size
    if allocation is not None and (
        type(allocation) is not int
        or allocation < 512
        or allocation > 2 * 1024 * 1024
        or allocation & (allocation - 1)
    ):
        raise HelperTargetError("The allocation unit is unsupported")


def _single_partition_geometry(plan: FormatPlan, sector: int) -> tuple[int, int]:
    total = plan.device_identity[1] // sector
    trailing = 1 + (128 * 128 + sector - 1) // sector if plan.partition_table is PartitionTable.GPT else 0
    count = total - 2048 - trailing
    if count <= 0 or (plan.partition_table is PartitionTable.MBR and count > 0xFFFFFFFF):
        raise HelperTargetError("The device cannot hold the frozen partition geometry")
    return 2048, count


def partition_script(plan: FormatPlan, sector: int) -> bytes:
    validate_plan(plan)
    start, count = _single_partition_geometry(plan, sector)
    label = "dos" if plan.partition_table is PartitionTable.MBR else "gpt"
    type_value = (
        _GPT_DATA_TYPE
        if plan.partition_table is PartitionTable.GPT
        else ("c" if plan.filesystem is Filesystem.FAT32 else "7")
    )
    return (
        f"label: {label}\nunit: sectors\n\n"
        f"start={start}, size={count}, type={type_value}\n"
    ).encode("ascii")
_MKFS = {
    Filesystem.FAT32: "/usr/sbin/mkfs.fat",
    Filesystem.NTFS: "/usr/sbin/mkntfs",
}
_ALLOWED_TOOLS = frozenset({_SFDISK, _UDEVADM, *_MKFS.values()})
_TARGET_PREFIXES = ("/dev/sd", "/dev/vd", "/dev/xvd", "/dev/nvme", "/dev/mmcblk")


Progress = Callable[[str, int, int], None]


@dataclass(frozen=True)
class RestoreDeviceRequest:
    request_id: bytes
    profile: str
    plan: FormatPlan
    expected_major_minor: str
    expected_disk_sequence: int
    expected_capacity: int
    logical_sector_size: int
    partition_start_sector: int
    partition_sector_count: int
    chunk_size: int = DEFAULT_CHUNK_BYTES
    plan_sha256: bytes = b""


@dataclass(frozen=True)
class FilesystemReceipt:
    filesystem: Filesystem
    partition_major_minor: str
    partition_start_sector: int
    partition_sector_count: int
    logical_sector_size: int
    sectors_per_cluster: int
    cluster_size: int
    normalized_label: str
    metadata_sha256: bytes
    receipt_sha256: bytes


@dataclass(frozen=True)
class PartitionObservation:
    path: str
    device_number: int
    parent_device_number: int
    number: int
    start_sector: int
    sector_count: int


@dataclass(frozen=True)
class ChildResult:
    argv: tuple[str, ...]
    output: bytes


@dataclass(frozen=True)
class RestoreDeviceResult:
    request_id: bytes
    profile: str
    target_path: str
    expected_major_minor: str
    disk_sequence: int
    capacity: int
    logical_sector_size: int
    partition: PartitionObservation
    scanned_bytes: int
    written_bytes: int
    skipped_bytes: int
    verified_bytes: int
    filesystem: Filesystem
    filesystem_receipt: FilesystemReceipt
    durable: bool
    cache_invalidated: bool


def _dev_text(device_number: int) -> str:
    return f"{os.major(device_number)}:{os.minor(device_number)}"


def _read_small(path: Path, label: str, maximum: int = 256) -> str:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise HelperTargetError(f"Could not read kernel {label}") from error
    if not payload or len(payload) > maximum or b"\0" in payload:
        raise HelperTargetError(f"Kernel {label} is malformed")
    try:
        return payload.decode("ascii").strip()
    except UnicodeError as error:
        raise HelperTargetError(f"Kernel {label} is malformed") from error


def _resolved_sysfs_node(device_number: int, sys_root: Path) -> Path:
    devices = (sys_root / "devices").resolve()
    try:
        node = (sys_root / "dev" / "block" / _dev_text(device_number)).resolve(strict=True)
        node.relative_to(devices)
    except (OSError, RuntimeError, ValueError) as error:
        raise HelperTargetError("The target has no trusted sysfs identity") from error
    if _parse_major_minor(_read_small(node / "dev", "device identity")) != device_number:
        raise HelperTargetError("The descriptor and sysfs device identities disagree")
    return node


def _transport_for_node(node: Path, sys_root: Path) -> str:
    devices = (sys_root / "devices").resolve()
    current = node
    while True:
        subsystem = current / "subsystem"
        try:
            if subsystem.exists() or subsystem.is_symlink():
                name = subsystem.resolve(strict=True).name
                if name in {"usb", "mmc"}:
                    return name
        except (OSError, RuntimeError) as error:
            raise HelperTargetError("Could not inspect target transport") from error
        if current == devices or current.parent == current:
            return ""
        current = current.parent


def _related_devices(start: Path, sys_root: Path) -> tuple[frozenset[int], bool]:
    devices = (sys_root / "devices").resolve()
    pending = [start]
    seen: set[Path] = set()
    numbers: set[int] = set()
    has_holders = False
    while pending:
        try:
            node = pending.pop().resolve(strict=True)
            node.relative_to(devices)
        except (OSError, RuntimeError, ValueError) as error:
            raise HelperTargetError("Target topology escaped trusted sysfs") from error
        if node in seen:
            continue
        seen.add(node)
        if len(seen) > _MAX_TOPOLOGY_NODES:
            raise HelperTargetError("Target topology is too large")
        numbers.add(_parse_major_minor(_read_small(node / "dev", "device identity")))
        try:
            children = tuple(node.iterdir())
            holders = tuple((node / "holders").iterdir()) if (node / "holders").is_dir() else ()
        except OSError as error:
            raise HelperTargetError("Could not inspect target topology") from error
        pending.extend(
            child for child in children
            if child.is_dir() and (child / "partition").is_file() and (child / "dev").is_file()
        )
        has_holders = has_holders or bool(holders)
        pending.extend(holders)
    return frozenset(numbers), has_holders


def inspect_kernel_target(
    device_number: int,
    *,
    sys_root: Path = Path("/sys"),
) -> KernelTargetObservation:
    node = _resolved_sysfs_node(device_number, sys_root)
    if (node / "partition").exists():
        raise HelperTargetError("The target must be a whole disk")
    removable_text = _read_small(node / "removable", "removable flag")
    read_only_text = _read_small(node / "ro", "read-only flag")
    sector_text = _read_small(node / "queue/logical_block_size", "logical sector")
    diskseq_text = _read_small(node / "diskseq", "disk sequence")
    if removable_text not in {"0", "1"} or read_only_text not in {"0", "1"}:
        raise HelperTargetError("Kernel target flags are malformed")
    try:
        sector = int(sector_text)
        diskseq = int(diskseq_text)
    except ValueError as error:
        raise HelperTargetError("Kernel target geometry is malformed") from error
    transport = _transport_for_node(node, sys_root)
    removable = removable_text == "1"
    if not removable or transport not in {"usb", "mmc"}:
        raise HelperTargetError("The target is not a removable USB or SD/MMC whole disk")
    related, holders = _related_devices(node, sys_root)
    return KernelTargetObservation(
        device_number,
        related,
        transport,
        removable,
        read_only_text == "1",
        sector,
        holders,
        diskseq,
    )


def active_kernel_devices(
    *,
    proc_root: Path = Path("/proc"),
    stat_func: Callable[[str], os.stat_result] = os.stat,
) -> frozenset[int]:
    try:
        mounts = (proc_root / "self/mountinfo").read_bytes()
        swaps = (proc_root / "swaps").read_bytes()
    except OSError as error:
        raise HelperTargetError("Could not inspect mounted filesystems and swap") from error
    if len(mounts) > 8 * 1024 * 1024 or len(swaps) > 1024 * 1024 or b"\0" in mounts + swaps:
        raise HelperTargetError("Mounted filesystem or swap evidence is malformed")
    try:
        mount_lines = mounts.decode("utf-8").splitlines()
        swap_lines = swaps.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise HelperTargetError("Mounted filesystem or swap evidence is malformed") from error
    found: set[int] = set()
    for line in mount_lines:
        fields = line.split()
        if len(fields) < 6 or "-" not in fields:
            raise HelperTargetError("The active mount table is malformed")
        found.add(_parse_major_minor(fields[2]))
    if not swap_lines or not swap_lines[0].startswith("Filename"):
        raise HelperTargetError("The active swap table is malformed")
    for line in swap_lines[1:]:
        fields = line.split()
        if not fields:
            continue
        try:
            status = stat_func(fields[0])
        except OSError as error:
            raise HelperTargetError("An active swap source could not be identified") from error
        if stat.S_ISBLK(status.st_mode):
            found.add(status.st_rdev)
        elif stat.S_ISREG(status.st_mode):
            found.add(status.st_dev)
        else:
            raise HelperTargetError("An active swap source has an unsupported type")
    return frozenset(found)


def _ioctl_uint(descriptor: int, operation: int) -> int:
    value = array.array("I", [0])
    fcntl.ioctl(descriptor, operation, value, True)
    return int(value[0])


def _ioctl_u64(descriptor: int, operation: int) -> int:
    value = array.array("Q", [0])
    fcntl.ioctl(descriptor, operation, value, True)
    return int(value[0])


def _ioctl_void(descriptor: int, operation: int) -> None:
    fcntl.ioctl(descriptor, operation)


def _read_number(path: Path, label: str) -> int:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise HelperTargetError(f"Could not read partition {label}") from error
    if not raw or len(raw) > 32 or not raw.rstrip(b"\n").isdigit():
        raise HelperTargetError(f"Kernel partition {label} is malformed")
    return int(raw)


def _read_dev(path: Path) -> int:
    try:
        raw = path.read_text(encoding="ascii").strip()
        major_text, minor_text = raw.split(":", 1)
        if not major_text.isdigit() or not minor_text.isdigit():
            raise ValueError
        device_number = os.makedev(int(major_text), int(minor_text))
        if f"{os.major(device_number)}:{os.minor(device_number)}" != raw:
            raise ValueError
        return device_number
    except (OSError, UnicodeError, ValueError) as error:
        raise HelperTargetError("Kernel partition device number is malformed") from error


def _devname(path: Path) -> str:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise HelperTargetError("Could not read partition uevent") from error
    names = [line[8:] for line in lines if line.startswith("DEVNAME=")]
    if len(names) != 1 or not names[0] or "/" in names[0] or "\x00" in names[0]:
        raise HelperTargetError("Kernel partition name is ambiguous")
    candidate = "/dev/" + names[0]
    if not candidate.startswith(_TARGET_PREFIXES):
        raise HelperTargetError("Kernel partition path is outside the fixed allowlist")
    return candidate


def discover_single_partition(
    parent_device_number: int,
    _number: int = 1,
    *,
    sys_root: Path = Path("/sys"),
) -> PartitionObservation:
    """Resolve exactly one direct child using sysfs, without trusting a name."""

    link = sys_root / "dev" / "block" / (
        f"{os.major(parent_device_number)}:{os.minor(parent_device_number)}"
    )
    try:
        parent = link.resolve(strict=True)
        children = tuple(
            child for child in parent.iterdir()
            if child.is_dir() and (child / "partition").is_file()
        )
    except OSError as error:
        raise HelperTargetError("Could not enumerate the retained disk's partitions") from error
    if len(children) != 1:
        raise HelperTargetError("The retained disk does not have exactly one partition")
    child = children[0]
    number = _read_number(child / "partition", "number")
    if number != 1:
        raise HelperTargetError("The retained disk's only partition is not partition 1")
    return PartitionObservation(
        _devname(child / "uevent"),
        _read_dev(child / "dev"),
        parent_device_number,
        number,
        _read_number(child / "start", "start"),
        _read_number(child / "size", "size"),
    )


def _trusted_tool(path: str) -> None:
    if path not in _ALLOWED_TOOLS:
        raise HelperError("The requested child tool is not allowlisted")
    try:
        status = os.lstat(path)
    except OSError as error:
        raise HelperError(f"Required trusted tool is unavailable: {path}") from error
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != 0
        or status.st_mode & 0o022
        or stat.S_IMODE(status.st_mode) & 0o500 != 0o500
        or os.path.realpath(path) != path
    ):
        raise HelperError(f"Required child tool has unsafe ownership or mode: {path}")
    parent = os.path.dirname(path)
    while parent != "/":
        parent_status = os.stat(parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_status.st_mode)
            or parent_status.st_uid != 0
            or parent_status.st_mode & 0o022
        ):
            raise HelperError(f"Trusted child tool has an unsafe parent: {parent}")
        parent = os.path.dirname(parent)


def _child_subreaper_enabled() -> bool:
    libc = ctypes.CDLL(None, use_errno=True)
    enabled = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(enabled), 0, 0, 0) != 0:  # PR_GET_CHILD_SUBREAPER
        raise HelperError("Could not inspect trusted-child descendant reaping")
    if enabled.value not in {0, 1}:
        raise HelperError("The trusted-child descendant reaper state is invalid")
    return bool(enabled.value)


def _enable_child_subreaper() -> bool:
    previous = _child_subreaper_enabled()
    if previous:
        return True
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise HelperError("Could not enable trusted-child descendant reaping")
    if not _child_subreaper_enabled():
        raise HelperError("Trusted-child descendant reaping was not enabled")
    return False


def _restore_child_subreaper(previous: bool) -> None:
    if type(previous) is not bool:
        raise HelperError("The prior descendant reaper state is invalid")
    current = _child_subreaper_enabled()
    if current == previous:
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, int(previous), 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise HelperError("Could not restore trusted-child descendant reaping")
    if _child_subreaper_enabled() != previous:
        raise HelperError("Trusted-child descendant reaping was not restored")


def _read_process_children(process_id: int) -> tuple[int, ...]:
    if type(process_id) is not int or process_id <= 0:
        raise HelperError("The trusted child process identity is invalid")
    path = (
        f"/proc/self/task/{process_id}/children"
        if process_id == os.getpid()
        else f"/proc/{process_id}/task/{process_id}/children"
    )
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        payload = os.read(descriptor, _MAX_CHILDREN_FILE_BYTES + 1)
    except FileNotFoundError:
        if process_id == os.getpid():
            raise HelperError("The helper child inventory is unavailable")
        return ()
    except OSError as error:
        raise HelperError("Could not inspect trusted child descendants") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > _MAX_CHILDREN_FILE_BYTES:
        raise HelperError("The trusted child descendant inventory is excessive")
    try:
        text = payload.decode("ascii")
    except UnicodeError as error:
        raise HelperError("The trusted child descendant inventory is malformed") from error
    if not text.strip():
        return ()
    values = text.split()
    if len(values) > _MAX_CHILD_DESCENDANTS:
        raise HelperError("The trusted child descendant inventory is excessive")
    children: list[int] = []
    for value in values:
        if not value.isdecimal() or value.startswith("0"):
            raise HelperError("The trusted child descendant inventory is malformed")
        child = int(value)
        if child <= 0 or child in children:
            raise HelperError("The trusted child descendant inventory is malformed")
        children.append(child)
    return tuple(children)


def _descendant_processes() -> frozenset[int]:
    pending = list(_read_process_children(os.getpid()))
    descendants: set[int] = set()
    while pending:
        process_id = pending.pop()
        if process_id in descendants:
            continue
        descendants.add(process_id)
        if len(descendants) > _MAX_CHILD_DESCENDANTS:
            raise HelperError("The trusted child descendant inventory is excessive")
        pending.extend(_read_process_children(process_id))
    return frozenset(descendants)


def _reap_adopted_children() -> None:
    while True:
        try:
            child, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        except InterruptedError:
            continue
        if child == 0:
            return


def _signal_descendants(signum: int) -> bool:
    descendants = _descendant_processes()
    for process_id in descendants:
        try:
            os.kill(process_id, signum)
        except ProcessLookupError:
            pass
        except PermissionError as error:
            raise HelperError("Could not signal a trusted child descendant") from error
    return bool(descendants)


def _wait_for_descendant_absence(timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        _reap_adopted_children()
        if not _descendant_processes():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def _terminate_and_reap_descendants() -> bool:
    """Return whether any adopted descendant existed; prove final absence."""

    existed = _signal_descendants(signal.SIGTERM)
    if not _wait_for_descendant_absence(_CHILD_TERM_GRACE_SECONDS):
        _signal_descendants(signal.SIGKILL)
    if not _wait_for_descendant_absence(_CHILD_KILL_GRACE_SECONDS):
        raise HelperError("Trusted child descendants could not be proven absent")
    return existed


def _process_group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError as error:
        raise HelperError("Could not attest the trusted child process group") from error


def _reap_process_group_children(group: int) -> None:
    while True:
        try:
            child, _status = os.waitpid(-group, os.WNOHANG)
        except ChildProcessError:
            return
        except InterruptedError:
            continue
        if child == 0:
            return


def _wait_for_process_group_absence(group: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        _reap_process_group_children(group)
        if not _process_group_exists(group):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def _terminate_and_reap_process_group(process: subprocess.Popen[bytes]) -> bool:
    """Return whether a live group remained; always prove final absence."""

    group = process.pid
    process.poll()
    if process.returncode is not None:
        _reap_process_group_children(group)
    existed = _process_group_exists(group)
    if existed:
        try:
            os.killpg(group, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=_CHILD_TERM_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=_CHILD_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise HelperError("The trusted child leader could not be reaped") from error
    if not _wait_for_process_group_absence(group, _CHILD_TERM_GRACE_SECONDS):
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if not _wait_for_process_group_absence(group, _CHILD_KILL_GRACE_SECONDS):
        raise HelperError("The trusted child process group could not be proven absent")
    process.wait()
    descendants_existed = _terminate_and_reap_descendants()
    return existed or descendants_existed


def _cleanup_failed_child(
    process: subprocess.Popen[bytes],
    original: BaseException,
) -> None:
    try:
        _terminate_and_reap_process_group(process)
    except BaseException as cleanup_error:
        raise HelperError(
            f"The trusted child failed and its process group was not safely reaped: {cleanup_error}",
        ) from original


def run_exact_child(
    argv: tuple[str, ...],
    stdin: bytes | None,
    pass_fds: tuple[int, ...],
    timeout: float = CHILD_TIMEOUT_SECONDS,
) -> ChildResult:
    """Run, retain, terminate if needed, and reap one exact native child."""

    if not argv or any(type(item) is not str or not item or "\x00" in item for item in argv):
        raise HelperError("The child argv is malformed")
    _trusted_tool(argv[0])
    previous_subreaper = _enable_child_subreaper()
    try:
        if _descendant_processes():
            raise HelperError("The helper already owns an unexpected child process")
        return _run_exact_child_as_subreaper(argv, stdin, pass_fds, timeout)
    finally:
        _restore_child_subreaper(previous_subreaper)


def _run_exact_child_as_subreaper(
    argv: tuple[str, ...],
    stdin: bytes | None,
    pass_fds: tuple[int, ...],
    timeout: float,
) -> ChildResult:
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/root",
    }
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            close_fds=True,
            pass_fds=pass_fds,
            start_new_session=True,
            bufsize=0,
        )
    except OSError as error:
        raise HelperError(f"Could not execute trusted child: {argv[0]}") from error
    captured = bytearray()
    deadline = time.monotonic() + timeout
    try:
        if process.stdin is not None:
            try:
                process.stdin.write(stdin or b"")
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        assert process.stdout is not None
        output_fd = process.stdout.fileno()
        os.set_blocking(output_fd, False)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            readable, _, _ = select.select((output_fd,), (), (), min(0.1, remaining))
            if readable:
                try:
                    block = os.read(output_fd, 8192)
                except BlockingIOError:
                    continue
                if block:
                    captured.extend(block)
                    if len(captured) > MAX_CHILD_OUTPUT:
                        raise OverflowError
                elif process.poll() is not None:
                    break
            elif process.poll() is not None:
                # Drain bytes already queued between poll and process exit.
                while True:
                    try:
                        block = os.read(output_fd, 8192)
                    except BlockingIOError:
                        break
                    if not block:
                        break
                    captured.extend(block)
                    if len(captured) > MAX_CHILD_OUTPUT:
                        raise OverflowError
                break
        process.wait()
    except (TimeoutError, OverflowError) as error:
        _cleanup_failed_child(process, error)
        label = "timed out" if isinstance(error, TimeoutError) else "produced excessive output"
        raise HelperError(f"Trusted child {label}: {argv[0]}") from error
    except BaseException as error:
        _cleanup_failed_child(process, error)
        raise
    finally:
        if process.stdout is not None:
            process.stdout.close()
    if _terminate_and_reap_process_group(process):
        raise HelperError("The trusted child left a lingering process-group member")
    if process.returncode != 0:
        rendered = bytes(captured).decode("utf-8", "replace").strip()[-4096:]
        raise HelperError(f"Trusted child failed ({process.returncode}): {rendered}")
    return ChildResult(argv, bytes(captured))


@dataclass(frozen=True)
class RestoreOperations:
    lstat: Callable[[str], os.stat_result] = os.lstat
    fstat: Callable[[int], os.stat_result] = os.fstat
    open: Callable[[str, int], int] = os.open
    close: Callable[[int], None] = os.close
    pread: Callable[[int, int, int], bytes] = os.pread
    pwrite: Callable[[int, bytes, int], int] = os.pwrite
    fsync: Callable[[int], None] = os.fsync
    flock: Callable[[int, int], None] = fcntl.flock
    ioctl_uint: Callable[[int, int], int] = _ioctl_uint
    ioctl_u64: Callable[[int, int], int] = _ioctl_u64
    ioctl_void: Callable[[int, int], None] = _ioctl_void
    inspect_target: Callable[[int], KernelTargetObservation] = inspect_kernel_target
    active_devices: Callable[[], frozenset[int]] = active_kernel_devices
    discover_partition: Callable[[int, int], PartitionObservation] = discover_single_partition
    run_child: Callable[[tuple[str, ...], bytes | None, tuple[int, ...], float], ChildResult] = run_exact_child
    monotonic: Callable[[], float] = time.monotonic


def _parse_major_minor(value: str) -> int:
    try:
        major_text, minor_text = value.split(":", 1)
        if not major_text.isdigit() or not minor_text.isdigit():
            raise ValueError
        device_number = os.makedev(int(major_text), int(minor_text))
        if f"{os.major(device_number)}:{os.minor(device_number)}" != value:
            raise ValueError
        return device_number
    except (ValueError, OverflowError) as error:
        raise HelperTargetError("The expected device number is malformed") from error


def _expected_geometry(plan: FormatPlan, sector: int) -> tuple[int, int]:
    script = partition_script(plan, sector).decode("ascii")
    geometry = next(line for line in script.splitlines() if line.startswith("start="))
    fields = dict(item.strip().split("=", 1) for item in geometry.split(",")[:2])
    return int(fields["start"]), int(fields["size"])


def _request_digest(
    plan: FormatPlan,
    disk_sequence: int,
    capacity: int,
    sector: int,
    start: int,
    count: int,
    chunk: int,
) -> bytes:
    label = plan.label.encode("utf-8")
    major, minor = (int(part) for part in plan.device_identity[5].split(":", 1))
    canonical = struct.pack(
        "!IIQQIQQIBBQH128s",
        major,
        minor,
        disk_sequence,
        capacity,
        sector,
        start,
        count,
        chunk,
        _FILESYSTEM_CODE[plan.filesystem],
        _TABLE_CODE[plan.partition_table],
        plan.allocation_unit_size or 0,
        len(label),
        label.ljust(128, b"\0"),
    )
    return hashlib.sha256(RESTORE_DEVICE_PROFILE.encode("ascii") + b"\0" + canonical).digest()


def build_restore_device_request(
    plan: object,
    *,
    request_id: bytes,
    disk_sequence: int,
    logical_sector_size: int,
    chunk_size: int = DEFAULT_CHUNK_BYTES,
) -> RestoreDeviceRequest:
    frozen = _coerce_plan(plan)
    try:
        start, count = _expected_geometry(frozen, logical_sector_size)
        digest = _request_digest(
            frozen,
            disk_sequence,
            frozen.device_identity[1],
            logical_sector_size,
            start,
            count,
            chunk_size,
        )
    except (OverflowError, struct.error, ValueError, ZeroDivisionError) as error:
        raise HelperTargetError("The restore request fields are outside protocol bounds") from error
    request = RestoreDeviceRequest(
        request_id,
        RESTORE_DEVICE_PROFILE,
        frozen,
        frozen.device_identity[5],
        disk_sequence,
        frozen.device_identity[1],
        logical_sector_size,
        start,
        count,
        chunk_size,
        digest,
    )
    validate_restore_device_request(request)
    return request


def validate_restore_device_request(request: RestoreDeviceRequest) -> None:
    if type(request) is not RestoreDeviceRequest:
        raise HelperTargetError("The restore request has an invalid type")
    validate_plan(request.plan)
    if (
        request.profile != RESTORE_DEVICE_PROFILE
        or type(request.request_id) is not bytes
        or len(request.request_id) != 16
    ):
        raise HelperTargetError("The restore request profile or identifier is invalid")
    if (
        request.plan.device_identity[1] != request.expected_capacity
        or request.plan.device_identity[5] != request.expected_major_minor
    ):
        raise HelperTargetError("The restore request is not bound to its format plan")
    if (
        type(request.expected_disk_sequence) is not int
        or not 0 < request.expected_disk_sequence <= 0xFFFFFFFFFFFFFFFF
    ):
        raise HelperTargetError("The restore request has no disk generation")
    if type(request.logical_sector_size) is not int or request.logical_sector_size not in {
        512, 1024, 2048, 4096,
    }:
        raise HelperTargetError("The restore request logical sector is unsupported")
    if request.plan.filesystem not in _MKFS:
        raise HelperTargetError("This helper version supports only FAT32 and NTFS")
    if (
        type(request.expected_capacity) is not int
        or not _MINIMUM_CAPACITY <= request.expected_capacity <= _MAXIMUM_CAPACITY
        or request.expected_capacity % request.logical_sector_size
    ):
        raise HelperTargetError("The restore capacity is not sector aligned")
    if type(request.chunk_size) is not int or request.chunk_size < request.logical_sector_size or (
        request.chunk_size > 64 * 1024 * 1024
        or request.chunk_size % request.logical_sector_size
    ):
        raise HelperTargetError("The zero chunk size is invalid")
    if request.plan.allocation_unit_size is not None and (
        request.plan.allocation_unit_size < request.logical_sector_size
        or request.plan.allocation_unit_size % request.logical_sector_size
    ):
        raise HelperTargetError("The allocation unit is not sector aligned")
    if _expected_geometry(request.plan, request.logical_sector_size) != (
        request.partition_start_sector,
        request.partition_sector_count,
    ):
        raise HelperTargetError("The partition geometry differs from the frozen plan")
    if (
        type(request.plan_sha256) is not bytes
        or len(request.plan_sha256) != 32
        or request.plan_sha256 != _request_digest(
            request.plan,
            request.expected_disk_sequence,
            request.expected_capacity,
            request.logical_sector_size,
            request.partition_start_sector,
            request.partition_sector_count,
            request.chunk_size,
        )
    ):
        raise HelperTargetError("The restore request digest is invalid")


def _require_target(
    descriptor: int,
    request: RestoreDeviceRequest,
    device_number: int,
    operations: RestoreOperations,
    *,
    verification: bool,
) -> None:
    error_type = HelperVerificationError if verification else HelperTargetError
    try:
        status = operations.fstat(descriptor)
        size = operations.ioctl_u64(descriptor, BLKGETSIZE64)
        diskseq = operations.ioctl_u64(descriptor, BLKGETDISKSEQ)
        sector = operations.ioctl_uint(descriptor, BLKSSZGET)
        read_only = operations.ioctl_uint(descriptor, BLKROGET)
    except OSError as error:
        raise error_type("Could not attest the retained whole-disk descriptor") from error
    if (
        not stat.S_ISBLK(status.st_mode)
        or status.st_rdev != device_number
        or size != request.expected_capacity
        or diskseq != request.expected_disk_sequence
        or sector != request.logical_sector_size
        or read_only != 0
    ):
        raise error_type("The retained descriptor is not the authorized disk generation")


def _require_topology(
    request: RestoreDeviceRequest,
    device_number: int,
    operations: RestoreOperations,
) -> None:
    evidence = operations.inspect_target(device_number)
    if (
        type(evidence) is not KernelTargetObservation
        or evidence.device_number != device_number
        or device_number not in evidence.related_device_numbers
        or evidence.transport not in {"usb", "mmc"}
        or not evidence.removable
        or evidence.read_only
        or evidence.logical_sector_size != request.logical_sector_size
        or evidence.disk_sequence != request.expected_disk_sequence
        or evidence.has_holders
        or evidence.related_device_numbers & operations.active_devices()
    ):
        raise HelperTargetError("The restore target topology is unsafe or changed")


def _read_exact(
    descriptor: int,
    size: int,
    offset: int,
    operations: RestoreOperations,
) -> bytes:
    chunks: list[bytes] = []
    consumed = 0
    while consumed < size:
        try:
            chunk = operations.pread(descriptor, size - consumed, offset + consumed)
        except InterruptedError:
            continue
        except OSError as error:
            raise HelperVerificationError("The retained target read failed") from error
        if type(chunk) is not bytes or not chunk or len(chunk) > size - consumed:
            raise HelperVerificationError("The retained target made invalid read progress")
        chunks.append(chunk)
        consumed += len(chunk)
    return b"".join(chunks)


def _write_exact(
    descriptor: int,
    data: bytes,
    offset: int,
    operations: RestoreOperations,
) -> None:
    written = 0
    while written < len(data):
        try:
            count = operations.pwrite(descriptor, data[written:], offset + written)
        except InterruptedError:
            continue
        except OSError as error:
            raise HelperError("The retained target write failed") from error
        if type(count) is not int or count <= 0 or count > len(data) - written:
            raise HelperError("The retained target made invalid write progress")
        written += count


def _power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _partition_readback(
    whole: int,
    partition: int,
    request: RestoreDeviceRequest,
    offset: int,
    size: int,
    operations: RestoreOperations,
) -> bytes:
    partition_bytes = request.partition_sector_count * request.logical_sector_size
    if (
        type(offset) is not int
        or type(size) is not int
        or offset < 0
        or size <= 0
        or offset > partition_bytes
        or size > partition_bytes - offset
    ):
        raise HelperVerificationError("Filesystem metadata lies outside the frozen partition")
    child = _read_exact(partition, size, offset, operations)
    parent_offset = request.partition_start_sector * request.logical_sector_size + offset
    parent = _read_exact(whole, size, parent_offset, operations)
    if child != parent:
        raise HelperVerificationError(
            "Parent and child descriptors disagree about filesystem metadata",
        )
    return child


def _filesystem_receipt_digest(
    request: RestoreDeviceRequest,
    filesystem: Filesystem,
    partition_major_minor: str,
    sectors_per_cluster: int,
    normalized_label: str,
    metadata_sha256: bytes,
) -> bytes:
    try:
        label = normalized_label.encode("utf-8", "strict")
        partition_device = _parse_major_minor(partition_major_minor)
        canonical = struct.pack(
            "!B3xIIQQIIH128s32s",
            _FILESYSTEM_CODE[filesystem],
            os.major(partition_device),
            os.minor(partition_device),
            request.partition_start_sector,
            request.partition_sector_count,
            request.logical_sector_size,
            sectors_per_cluster,
            len(label),
            label.ljust(128, b"\0"),
            metadata_sha256,
        )
    except (HelperTargetError, UnicodeError, OverflowError, struct.error) as error:
        raise HelperVerificationError("The filesystem receipt fields are invalid") from error
    return hashlib.sha256(
        FILESYSTEM_RECEIPT_PROFILE.encode("ascii")
        + b"\0"
        + request.plan_sha256
        + canonical
    ).digest()


def validate_filesystem_receipt(
    request: RestoreDeviceRequest,
    receipt: FilesystemReceipt,
) -> None:
    validate_restore_device_request(request)
    if type(receipt) is not FilesystemReceipt:
        raise HelperVerificationError("An exact post-format filesystem receipt is required")
    try:
        encoded_label = receipt.normalized_label.encode("utf-8", "strict")
    except UnicodeError as error:
        raise HelperVerificationError("The filesystem receipt label is invalid") from error
    if (
        type(receipt.filesystem) is not Filesystem
        or receipt.filesystem is not request.plan.filesystem
        or type(receipt.partition_major_minor) is not str
        or _MAJOR_MINOR.fullmatch(receipt.partition_major_minor) is None
        or receipt.partition_major_minor == request.expected_major_minor
        or receipt.partition_start_sector != request.partition_start_sector
        or receipt.partition_sector_count != request.partition_sector_count
        or receipt.logical_sector_size != request.logical_sector_size
        or type(receipt.sectors_per_cluster) is not int
        or not _power_of_two(receipt.sectors_per_cluster)
        or receipt.sectors_per_cluster > 128
        or receipt.cluster_size
        != receipt.logical_sector_size * receipt.sectors_per_cluster
        or not _power_of_two(receipt.cluster_size)
        or receipt.cluster_size > 2 * 1024 * 1024
        or request.plan.allocation_unit_size is not None
        and receipt.cluster_size != request.plan.allocation_unit_size
        or len(encoded_label) > 128
        or receipt.normalized_label != unicodedata.normalize(
            "NFC", request.plan.label,
        )
        or type(receipt.metadata_sha256) is not bytes
        or len(receipt.metadata_sha256) != 32
        or type(receipt.receipt_sha256) is not bytes
        or len(receipt.receipt_sha256) != 32
        or receipt.receipt_sha256 != _filesystem_receipt_digest(
            request,
            receipt.filesystem,
            receipt.partition_major_minor,
            receipt.sectors_per_cluster,
            receipt.normalized_label,
            receipt.metadata_sha256,
        )
    ):
        raise HelperVerificationError("The post-format filesystem receipt is inconsistent")


def _receipt(
    request: RestoreDeviceRequest,
    filesystem: Filesystem,
    partition_device_number: int,
    sectors_per_cluster: int,
    normalized_label: str,
    metadata: bytes,
) -> FilesystemReceipt:
    metadata_sha256 = hashlib.sha256(metadata).digest()
    result = FilesystemReceipt(
        filesystem,
        _dev_text(partition_device_number),
        request.partition_start_sector,
        request.partition_sector_count,
        request.logical_sector_size,
        sectors_per_cluster,
        request.logical_sector_size * sectors_per_cluster,
        normalized_label,
        metadata_sha256,
        _filesystem_receipt_digest(
            request,
            filesystem,
            _dev_text(partition_device_number),
            sectors_per_cluster,
            normalized_label,
            metadata_sha256,
        ),
    )
    validate_filesystem_receipt(request, result)
    return result


def _fat32_receipt(
    whole: int,
    partition: int,
    request: RestoreDeviceRequest,
    partition_device_number: int,
    operations: RestoreOperations,
) -> FilesystemReceipt:
    sector = request.logical_sector_size
    boot = _partition_readback(whole, partition, request, 0, sector, operations)
    bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
    sectors_per_cluster = boot[13]
    reserved_sectors = struct.unpack_from("<H", boot, 14)[0]
    fat_count = boot[16]
    root_entries = struct.unpack_from("<H", boot, 17)[0]
    total_16 = struct.unpack_from("<H", boot, 19)[0]
    sectors_per_fat_16 = struct.unpack_from("<H", boot, 22)[0]
    hidden_sectors = struct.unpack_from("<I", boot, 28)[0]
    total_32 = struct.unpack_from("<I", boot, 32)[0]
    sectors_per_fat = struct.unpack_from("<I", boot, 36)[0]
    filesystem_version = struct.unpack_from("<H", boot, 42)[0]
    root_cluster = struct.unpack_from("<I", boot, 44)[0]
    fsinfo_sector = struct.unpack_from("<H", boot, 48)[0]
    backup_sector = struct.unpack_from("<H", boot, 50)[0]
    total_sectors = total_16 or total_32
    data_start = reserved_sectors + fat_count * sectors_per_fat
    data_sectors = total_sectors - data_start
    cluster_count = (
        data_sectors // sectors_per_cluster if sectors_per_cluster else 0
    )
    fat_entries = sectors_per_fat * bytes_per_sector // 4 if bytes_per_sector else 0
    cluster_size = bytes_per_sector * sectors_per_cluster
    expected_label_field = (
        request.plan.label.encode("ascii") if request.plan.label else b"NO NAME"
    ).ljust(11, b" ")
    if (
        boot[:3] not in {b"\xebX\x90", b"\xe9\0\0"}
        or bytes_per_sector != sector
        or not _power_of_two(sectors_per_cluster)
        or sectors_per_cluster > 128
        or not _power_of_two(cluster_size)
        or cluster_size > 64 * 1024
        or request.plan.allocation_unit_size is not None
        and cluster_size != request.plan.allocation_unit_size
        or reserved_sectors < 8
        or fat_count not in {1, 2}
        or root_entries != 0
        or total_16 != 0
        or boot[21] not in {0xF0, 0xF8}
        or sectors_per_fat_16 != 0
        or hidden_sectors != request.partition_start_sector
        or total_32 != request.partition_sector_count
        or total_sectors <= data_start
        or cluster_count <= 0
        or cluster_count > 0x0FFFFFF5
        or fat_entries < cluster_count + 2
        or sectors_per_fat == 0
        or filesystem_version != 0
        or root_cluster < 2
        or root_cluster >= cluster_count + 2
        or fsinfo_sector <= 0
        or fsinfo_sector >= reserved_sectors
        or backup_sector <= 0
        or backup_sector >= reserved_sectors
        or backup_sector + fsinfo_sector >= reserved_sectors
        or boot[65] != 0
        or boot[66] != 0x29
        or boot[71:82] != expected_label_field
        or boot[82:90] != b"FAT32   "
        or boot[510:512] != b"\x55\xaa"
    ):
        raise HelperVerificationError("The created FAT32 boot metadata is invalid")

    backup = _partition_readback(
        whole, partition, request, backup_sector * sector, sector, operations,
    )
    fsinfo = _partition_readback(
        whole, partition, request, fsinfo_sector * sector, sector, operations,
    )
    backup_fsinfo = _partition_readback(
        whole,
        partition,
        request,
        (backup_sector + fsinfo_sector) * sector,
        sector,
        operations,
    )
    free_cluster_count = struct.unpack_from("<I", fsinfo, 488)[0]
    next_free_cluster = struct.unpack_from("<I", fsinfo, 492)[0]
    if (
        backup != boot
        or fsinfo != backup_fsinfo
        or fsinfo[:4] != b"RRaA"
        or fsinfo[484:488] != b"rrAa"
        or fsinfo[510:512] != b"\x55\xaa"
        or free_cluster_count != 0xFFFFFFFF
        and free_cluster_count > cluster_count
        or (
            next_free_cluster != 0xFFFFFFFF
            and not 2 <= next_free_cluster < cluster_count + 2
        )
    ):
        raise HelperVerificationError("The created FAT32 backup metadata is invalid")

    root_offset = (
        data_start + (root_cluster - 2) * sectors_per_cluster
    ) * sector
    root = _partition_readback(
        whole, partition, request, root_offset, cluster_size, operations,
    )
    labels: list[bytes] = []
    for offset in range(0, len(root), 32):
        entry = root[offset:offset + 32]
        if entry[0] == 0:
            break
        if entry[0] == 0xE5 or entry[11] == 0x0F:
            continue
        if entry[11] & 0x08:
            if entry[11] != 0x08:
                raise HelperVerificationError("The created FAT32 root metadata is invalid")
            labels.append(entry[:11])
    expected_labels = [expected_label_field] if request.plan.label else []
    if labels != expected_labels:
        raise HelperVerificationError("The created FAT32 volume label is invalid")
    return _receipt(
        request,
        Filesystem.FAT32,
        partition_device_number,
        sectors_per_cluster,
        unicodedata.normalize("NFC", request.plan.label),
        boot + backup + fsinfo + backup_fsinfo + root,
    )


def _ntfs_record_size(encoded: int, cluster_size: int) -> int:
    if encoded == 0:
        return 0
    size = 1 << -encoded if encoded < 0 else encoded * cluster_size
    return size if 512 <= size <= 64 * 1024 and _power_of_two(size) else 0


def _ntfs_volume_label(
    raw_record: bytes,
    bytes_per_sector: int,
    expected_label: str,
) -> str:
    record = bytearray(raw_record)
    if len(record) < 64 or record[:4] != b"FILE":
        raise HelperVerificationError("The NTFS volume record is invalid")
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    expected_usa_count = len(record) // bytes_per_sector + 1
    if (
        len(record) % bytes_per_sector
        or usa_count != expected_usa_count
        or usa_offset < 8
        or usa_offset + usa_count * 2 > len(record)
    ):
        raise HelperVerificationError("The NTFS volume-record fixup is invalid")
    sequence = bytes(record[usa_offset:usa_offset + 2])
    for index in range(1, usa_count):
        end = index * bytes_per_sector
        if bytes(record[end - 2:end]) != sequence:
            raise HelperVerificationError("The NTFS volume-record fixup does not match")
        replacement = record[usa_offset + index * 2:usa_offset + index * 2 + 2]
        record[end - 2:end] = replacement

    first_attribute = struct.unpack_from("<H", record, 20)[0]
    flags = struct.unpack_from("<H", record, 22)[0]
    used_bytes = struct.unpack_from("<I", record, 24)[0]
    allocated_bytes = struct.unpack_from("<I", record, 28)[0]
    record_number = struct.unpack_from("<I", record, 44)[0]
    if (
        not flags & 1
        or allocated_bytes != len(record)
        or used_bytes > allocated_bytes
        or first_attribute < 48
        or first_attribute & 7
        or first_attribute >= used_bytes
        or usa_offset + usa_count * 2 > first_attribute
        or record_number != 3
    ):
        raise HelperVerificationError("The NTFS volume record header is invalid")

    volume_names: list[bytes] = []
    offset = first_attribute
    ended = False
    while offset + 8 <= used_bytes:
        attribute_type, length = struct.unpack_from("<II", record, offset)
        if attribute_type == 0xFFFFFFFF:
            ended = True
            break
        if length < 24 or length & 7 or length > used_bytes - offset:
            raise HelperVerificationError("The NTFS volume attribute list is invalid")
        nonresident = record[offset + 8]
        name_length = record[offset + 9]
        if attribute_type == 0x60:
            value_length = struct.unpack_from("<I", record, offset + 16)[0]
            value_offset = struct.unpack_from("<H", record, offset + 20)[0]
            if (
                nonresident != 0
                or name_length != 0
                or value_length > 128
                or value_length & 1
                or value_offset < 24
                or value_offset > length
                or value_length > length - value_offset
            ):
                raise HelperVerificationError("The NTFS volume-name attribute is invalid")
            volume_names.append(bytes(
                record[offset + value_offset:offset + value_offset + value_length]
            ))
        offset += length
    expected = expected_label.encode("utf-16-le", "strict")
    if not ended or volume_names != [expected]:
        raise HelperVerificationError("The created NTFS volume label is invalid")
    try:
        decoded = volume_names[0].decode("utf-16-le", "strict")
    except UnicodeError as error:
        raise HelperVerificationError("The created NTFS volume label is invalid") from error
    return unicodedata.normalize("NFC", decoded)


def _ntfs_receipt(
    whole: int,
    partition: int,
    request: RestoreDeviceRequest,
    partition_device_number: int,
    operations: RestoreOperations,
) -> FilesystemReceipt:
    sector = request.logical_sector_size
    boot = _partition_readback(whole, partition, request, 0, sector, operations)
    bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
    sectors_per_cluster = boot[13]
    hidden_sectors = struct.unpack_from("<I", boot, 28)[0]
    total_sectors = struct.unpack_from("<Q", boot, 40)[0]
    mft_cluster = struct.unpack_from("<Q", boot, 48)[0]
    mft_mirror_cluster = struct.unpack_from("<Q", boot, 56)[0]
    cluster_size = bytes_per_sector * sectors_per_cluster
    cluster_count = (
        (total_sectors + 1) // sectors_per_cluster if sectors_per_cluster else 0
    )
    file_record_size = _ntfs_record_size(
        struct.unpack_from("b", boot, 64)[0], cluster_size,
    )
    index_record_size = _ntfs_record_size(
        struct.unpack_from("b", boot, 68)[0], cluster_size,
    )
    if (
        boot[:3] not in {b"\xebR\x90", b"\xeb[\x90"}
        or boot[3:11] != b"NTFS    "
        or bytes_per_sector != sector
        or not _power_of_two(sectors_per_cluster)
        or sectors_per_cluster > 128
        or not _power_of_two(cluster_size)
        or cluster_size > 2 * 1024 * 1024
        or request.plan.allocation_unit_size is not None
        and cluster_size != request.plan.allocation_unit_size
        or boot[14:21] != b"\0" * 7
        or boot[21] != 0xF8
        or boot[22:24] != b"\0\0"
        or hidden_sectors != request.partition_start_sector
        or total_sectors + 1 != request.partition_sector_count
        or cluster_count <= 0
        or mft_cluster >= cluster_count
        or mft_mirror_cluster >= cluster_count
        or mft_cluster == mft_mirror_cluster
        or not file_record_size
        or not index_record_size
        or boot[510:512] != b"\x55\xaa"
    ):
        raise HelperVerificationError("The created NTFS boot metadata is invalid")
    backup = _partition_readback(
        whole,
        partition,
        request,
        total_sectors * sector,
        sector,
        operations,
    )
    if backup != boot:
        raise HelperVerificationError("The created NTFS backup boot sector is invalid")
    volume_record_offset = mft_cluster * cluster_size + 3 * file_record_size
    raw_volume_record = _partition_readback(
        whole,
        partition,
        request,
        volume_record_offset,
        file_record_size,
        operations,
    )
    normalized_label = _ntfs_volume_label(
        raw_volume_record,
        bytes_per_sector,
        request.plan.label,
    )
    return _receipt(
        request,
        Filesystem.NTFS,
        partition_device_number,
        sectors_per_cluster,
        normalized_label,
        boot + backup + raw_volume_record,
    )


def _post_format_receipt(
    whole: int,
    partition: int,
    request: RestoreDeviceRequest,
    partition_device_number: int,
    operations: RestoreOperations,
) -> FilesystemReceipt:
    if request.plan.filesystem is Filesystem.FAT32:
        return _fat32_receipt(
            whole, partition, request, partition_device_number, operations,
        )
    if request.plan.filesystem is Filesystem.NTFS:
        return _ntfs_receipt(
            whole, partition, request, partition_device_number, operations,
        )
    raise HelperVerificationError("The post-format filesystem is unsupported")


def _zero_and_verify(
    descriptor: int,
    request: RestoreDeviceRequest,
    operations: RestoreOperations,
    progress: Progress,
) -> tuple[int, int, int, int]:
    zeros = b"\0" * request.chunk_size
    scanned = written = skipped = 0
    progress("zero-scan", 0, request.expected_capacity)
    for offset in range(0, request.expected_capacity, request.chunk_size):
        wanted = min(request.chunk_size, request.expected_capacity - offset)
        block = _read_exact(descriptor, wanted, offset, operations)
        scanned += wanted
        if block == zeros[:wanted]:
            skipped += wanted
        else:
            _write_exact(descriptor, zeros[:wanted], offset, operations)
            written += wanted
        progress("zero-scan", scanned, request.expected_capacity)
    operations.fsync(descriptor)
    operations.ioctl_void(descriptor, BLKFLSBUF)
    verified = 0
    progress("zero-readback", 0, request.expected_capacity)
    for offset in range(0, request.expected_capacity, request.chunk_size):
        wanted = min(request.chunk_size, request.expected_capacity - offset)
        if _read_exact(descriptor, wanted, offset, operations) != zeros[:wanted]:
            raise HelperVerificationError("The full zero read-back failed")
        verified += wanted
        progress("zero-readback", verified, request.expected_capacity)
    return scanned, written, skipped, verified


def _formatter_argv(
    request: RestoreDeviceRequest,
    partition_descriptor: int,
) -> tuple[str, ...]:
    plan = request.plan
    filesystem = plan.filesystem
    argv = [_MKFS[filesystem]]
    if filesystem is Filesystem.FAT32:
        argv += [
            "-F", filesystem.value.removeprefix("fat"),
            "-S", str(request.logical_sector_size),
            "-h", str(request.partition_start_sector),
        ]
        if plan.allocation_unit_size is not None:
            argv += ["-s", str(plan.allocation_unit_size // request.logical_sector_size)]
        if plan.label:
            argv += ["-n", plan.label]
    else:
        argv += [
            "-f",
            "-s", str(request.logical_sector_size),
            "-p", str(request.partition_start_sector),
        ]
        if plan.allocation_unit_size is not None:
            argv += ["-c", str(plan.allocation_unit_size)]
        if plan.label:
            argv += ["-L", plan.label]
    argv.append(f"/proc/self/fd/{partition_descriptor}")
    return tuple(argv)


def _validate_partition(
    observation: PartitionObservation,
    request: RestoreDeviceRequest,
    parent_device_number: int,
) -> None:
    if (
        type(observation) is not PartitionObservation
        or observation.parent_device_number != parent_device_number
        or observation.number != 1
        or observation.start_sector != request.partition_start_sector
        or observation.sector_count != request.partition_sector_count
        or observation.device_number == parent_device_number
    ):
        raise HelperVerificationError("The discovered partition differs from frozen geometry")


def _validate_partition_descriptor(
    descriptor: int,
    observation: PartitionObservation,
    request: RestoreDeviceRequest,
    operations: RestoreOperations,
) -> None:
    try:
        status = operations.fstat(descriptor)
        size = operations.ioctl_u64(descriptor, BLKGETSIZE64)
        sector = operations.ioctl_uint(descriptor, BLKSSZGET)
        read_only = operations.ioctl_uint(descriptor, BLKROGET)
    except OSError as error:
        raise HelperVerificationError("Could not attest the partition descriptor") from error
    if (
        not stat.S_ISBLK(status.st_mode)
        or status.st_rdev != observation.device_number
        or size != request.partition_sector_count * request.logical_sector_size
        or sector != request.logical_sector_size
        or read_only != 0
    ):
        raise HelperVerificationError("The partition descriptor geometry is not authorized")


def _validate_sfdisk_json(payload: bytes, request: RestoreDeviceRequest) -> None:
    try:
        table = json.loads(payload).get("partitiontable")
    except (AttributeError, UnicodeError, json.JSONDecodeError) as error:
        raise HelperVerificationError("sfdisk returned malformed partition evidence") from error
    expected_label = "dos" if request.plan.partition_table is PartitionTable.MBR else "gpt"
    entries = table.get("partitions") if isinstance(table, dict) else None
    if (
        not isinstance(table, dict)
        or table.get("label") != expected_label
        or table.get("unit") != "sectors"
        or table.get("sectorsize") != request.logical_sector_size
        or not isinstance(entries, list)
        or len(entries) != 1
        or not isinstance(entries[0], dict)
    ):
        raise HelperVerificationError("The partition table metadata is not the frozen layout")
    expected_type = next(
        item.split("=", 1)[1]
        for item in partition_script(request.plan, request.logical_sector_size)
        .decode("ascii").splitlines()[-1].split(", ")
        if item.startswith("type=")
    )
    entry = entries[0]
    actual_type = str(entry.get("type", ""))
    if request.plan.partition_table is PartitionTable.MBR:
        expected_type = expected_type.removeprefix("0x").lstrip("0") or "0"
        actual_type = actual_type.removeprefix("0x").lstrip("0") or "0"
    if (
        entry.get("start") != request.partition_start_sector
        or entry.get("size") != request.partition_sector_count
        or actual_type.casefold() != expected_type.casefold()
    ):
        raise HelperVerificationError("The partition geometry or type is not the frozen layout")


def execute_restore_device_transaction(
    request: RestoreDeviceRequest,
    *,
    await_commit: Callable[[], bool],
    prepared: Callable[[], None] = lambda: None,
    progress: Progress = lambda _phase, _done, _total: None,
    operations: RestoreOperations = RestoreOperations(),
    require_root: bool = True,
) -> RestoreDeviceResult:
    """Execute a one-descriptor PREPARED -> COMMIT restore transaction."""

    validate_restore_device_request(request)
    if require_root and (os.getuid() != 0 or os.geteuid() != 0):
        raise HelperTargetError("The restore helper must run as real and effective root")
    device_number = _parse_major_minor(request.expected_major_minor)
    path_status = operations.lstat(request.plan.device_path)
    if not stat.S_ISBLK(path_status.st_mode) or path_status.st_rdev != device_number:
        raise HelperTargetError("The restore path is not the authorized block device")
    _require_topology(request, device_number, operations)
    whole = partition = -1
    committed = False
    try:
        flags = (
            os.O_RDWR
            | os.O_EXCL
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        whole = operations.open(request.plan.device_path, flags)
        operations.flock(whole, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _require_target(whole, request, device_number, operations, verification=False)
        _require_topology(request, device_number, operations)
        current_path = operations.lstat(request.plan.device_path)
        if not stat.S_ISBLK(current_path.st_mode) or current_path.st_rdev != device_number:
            raise HelperTargetError("The restore path changed after descriptor acquisition")
        prepared()
        if await_commit() is not True:
            raise HelperCancelled("The restore transaction was cancelled before COMMIT")
        committed = True
        _require_target(whole, request, device_number, operations, verification=False)
        _require_topology(request, device_number, operations)

        scanned, written, skipped, verified = _zero_and_verify(
            whole, request, operations, progress,
        )
        _require_target(whole, request, device_number, operations, verification=True)
        _require_topology(request, device_number, operations)

        disk_procfd = f"/proc/self/fd/{whole}"
        operations.run_child(
            (_SFDISK, "--wipe", "always", disk_procfd),
            partition_script(request.plan, request.logical_sector_size),
            (whole,),
            CHILD_TIMEOUT_SECONDS,
        )
        operations.fsync(whole)
        operations.ioctl_void(whole, BLKRRPART)
        operations.run_child(
            (_UDEVADM, "settle", "--timeout=30"), None, (), 35.0,
        )
        _require_target(whole, request, device_number, operations, verification=True)
        _require_topology(request, device_number, operations)
        _validate_sfdisk_json(
            operations.run_child(
                (_SFDISK, "--json", disk_procfd), None, (whole,), CHILD_TIMEOUT_SECONDS,
            ).output,
            request,
        )

        observed = operations.discover_partition(device_number, 1)
        _validate_partition(observed, request, device_number)
        partition = operations.open(
            observed.path,
            os.O_RDWR
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        _validate_partition_descriptor(partition, observed, request, operations)
        _require_target(whole, request, device_number, operations, verification=True)
        if operations.discover_partition(device_number, 1) != observed:
            raise HelperVerificationError("The partition changed before filesystem creation")

        operations.run_child(
            _formatter_argv(request, partition), None, (partition,), CHILD_TIMEOUT_SECONDS,
        )
        operations.fsync(partition)
        operations.ioctl_void(partition, BLKFLSBUF)
        operations.fsync(whole)
        operations.ioctl_void(whole, BLKFLSBUF)
        _require_target(whole, request, device_number, operations, verification=True)
        _require_topology(request, device_number, operations)
        if operations.discover_partition(device_number, 1) != observed:
            raise HelperVerificationError("The partition changed after filesystem creation")
        _validate_partition_descriptor(partition, observed, request, operations)
        _validate_sfdisk_json(
            operations.run_child(
                (_SFDISK, "--json", disk_procfd), None, (whole,), CHILD_TIMEOUT_SECONDS,
            ).output,
            request,
        )
        filesystem_receipt = _post_format_receipt(
            whole, partition, request, observed.device_number, operations,
        )
        validate_filesystem_receipt(request, filesystem_receipt)
        return RestoreDeviceResult(
            request.request_id,
            RESTORE_DEVICE_PROFILE,
            request.plan.device_path,
            request.expected_major_minor,
            request.expected_disk_sequence,
            request.expected_capacity,
            request.logical_sector_size,
            observed,
            scanned,
            written,
            skipped,
            verified,
            request.plan.filesystem,
            filesystem_receipt,
            True,
            True,
        )
    except BaseException:
        if committed and whole >= 0:
            try:
                if partition >= 0:
                    operations.close(partition)
                    partition = -1
                # A failed post-COMMIT transaction must not leave bootable
                # boundary metadata.  Re-attest before this emergency write.
                _require_target(whole, request, device_number, operations, verification=True)
                boundary = min(16 * 1024 * 1024, request.expected_capacity)
                zeros = b"\0" * min(request.chunk_size, boundary)
                for start in {0, request.expected_capacity - boundary}:
                    offset = 0
                    while offset < boundary:
                        block = zeros[: min(len(zeros), boundary - offset)]
                        _write_exact(whole, block, start + offset, operations)
                        offset += len(block)
                operations.fsync(whole)
                operations.ioctl_void(whole, BLKFLSBUF)
                for start in {0, request.expected_capacity - boundary}:
                    if _read_exact(whole, boundary, start, operations) != b"\0" * boundary:
                        raise HelperVerificationError("Emergency boundary cleanup failed")
                operations.ioctl_void(whole, BLKRRPART)
            except BaseException as cleanup_error:
                raise HelperVerificationError(
                    f"The restore failed and emergency boundary cleanup was not verified: {cleanup_error}",
                ) from cleanup_error
        raise
    finally:
        for descriptor in (partition, whole):
            if descriptor >= 0:
                try:
                    operations.close(descriptor)
                except OSError:
                    pass


def pack_restore_device_request(request: RestoreDeviceRequest) -> bytes:
    validate_restore_device_request(request)
    major, minor = (int(part) for part in request.expected_major_minor.split(":", 1))
    label = request.plan.label.encode("utf-8")
    return _REQUEST.pack(
        _WIRE_MAGIC,
        _WIRE_VERSION,
        PACKET_REQUEST,
        0,
        request.request_id,
        major,
        minor,
        request.expected_disk_sequence,
        request.expected_capacity,
        request.logical_sector_size,
        request.partition_start_sector,
        request.partition_sector_count,
        request.chunk_size,
        _FILESYSTEM_CODE[request.plan.filesystem],
        _TABLE_CODE[request.plan.partition_table],
        request.plan.allocation_unit_size or 0,
        len(label),
        label.ljust(128, b"\0"),
        request.plan_sha256,
    )


def pack_restore_device_result(
    request: RestoreDeviceRequest,
    result: RestoreDeviceResult,
) -> bytes:
    validate_restore_device_request(request)
    if type(result) is not RestoreDeviceResult:
        raise HelperVerificationError("An exact restore result is required")
    validate_filesystem_receipt(request, result.filesystem_receipt)
    receipt = result.filesystem_receipt
    if (
        result.request_id != request.request_id
        or result.profile != RESTORE_DEVICE_PROFILE
        or result.target_path != request.plan.device_path
        or result.expected_major_minor != request.expected_major_minor
        or result.disk_sequence != request.expected_disk_sequence
        or result.capacity != request.expected_capacity
        or result.logical_sector_size != request.logical_sector_size
        or type(result.partition) is not PartitionObservation
        or _dev_text(result.partition.parent_device_number)
        != request.expected_major_minor
        or result.partition.start_sector != request.partition_start_sector
        or result.partition.sector_count != request.partition_sector_count
        or result.scanned_bytes != request.expected_capacity
        or result.written_bytes + result.skipped_bytes != request.expected_capacity
        or result.verified_bytes != request.expected_capacity
        or result.filesystem is not request.plan.filesystem
        or receipt.filesystem is not result.filesystem
        or receipt.partition_major_minor
        != _dev_text(result.partition.device_number)
        or result.durable is not True
        or result.cache_invalidated is not True
    ):
        raise HelperVerificationError("The restore result is incomplete or inconsistent")
    label = receipt.normalized_label.encode("utf-8", "strict")
    return _RESULT.pack(
        _WIRE_MAGIC,
        _WIRE_VERSION,
        PACKET_RESULT,
        0,
        result.request_id,
        os.major(result.partition.parent_device_number),
        os.minor(result.partition.parent_device_number),
        result.disk_sequence,
        result.capacity,
        result.scanned_bytes,
        result.written_bytes,
        result.skipped_bytes,
        result.verified_bytes,
        os.major(result.partition.device_number),
        os.minor(result.partition.device_number),
        result.partition.start_sector,
        result.partition.sector_count,
        request.plan_sha256,
        _FILESYSTEM_CODE[result.filesystem],
        1,
        len(label),
        receipt.logical_sector_size,
        receipt.sectors_per_cluster,
        label.ljust(128, b"\0"),
        receipt.metadata_sha256,
        receipt.receipt_sha256,
    )


def _target_path_from_kernel(device_number: int, *, sys_root: Path = Path("/sys")) -> str:
    node = _resolved_sysfs_node(device_number, sys_root)
    lines = _read_small(node / "uevent", "device uevent", 16 * 1024).splitlines()
    names = [line[8:] for line in lines if line.startswith("DEVNAME=")]
    path = "/dev/" + names[0] if len(names) == 1 else ""
    if _WHOLE_DISK.fullmatch(path) is None:
        raise HelperTargetError("The target has no unambiguous whole-disk path")
    return path


def unpack_restore_device_request(
    packet: bytes,
    *,
    target_path: Callable[[int], str] = _target_path_from_kernel,
) -> RestoreDeviceRequest:
    if type(packet) is not bytes or len(packet) != _REQUEST.size:
        raise HelperTargetError("The restore wire request has an invalid size")
    (
        magic, version, packet_type, flags, request_id, major, minor, diskseq,
        capacity, sector, start, count, chunk, filesystem_code, table_code,
        allocation, label_size, label_field, digest,
    ) = _REQUEST.unpack(packet)
    if (
        magic != _WIRE_MAGIC
        or version != _WIRE_VERSION
        or packet_type != PACKET_REQUEST
        or flags != 0
        or filesystem_code not in _FILESYSTEM_FROM_CODE
        or table_code not in _TABLE_FROM_CODE
        or label_size > len(label_field)
        or any(label_field[label_size:])
    ):
        raise HelperTargetError("The restore wire request header is invalid")
    try:
        label = label_field[:label_size].decode("utf-8", "strict")
        device_number = os.makedev(major, minor)
        path = target_path(device_number)
    except (UnicodeError, OverflowError, ValueError) as error:
        raise HelperTargetError("The restore wire request payload is invalid") from error
    plan = FormatPlan(
        path,
        (path, capacity, "", "", "", f"{major}:{minor}"),
        _FILESYSTEM_FROM_CODE[filesystem_code],
        _TABLE_FROM_CODE[table_code],
        label,
        allocation or None,
    )
    request = RestoreDeviceRequest(
        request_id,
        RESTORE_DEVICE_PROFILE,
        plan,
        f"{major}:{minor}",
        diskseq,
        capacity,
        sector,
        start,
        count,
        chunk,
        digest,
    )
    validate_restore_device_request(request)
    return request


def _validate_control_binding(request_id: bytes, plan_sha256: bytes) -> None:
    if (
        type(request_id) is not bytes
        or len(request_id) != 16
        or type(plan_sha256) is not bytes
        or len(plan_sha256) != 32
    ):
        raise HelperTargetError("The restore control binding is invalid")


def pack_restore_control(
    request_id: bytes,
    plan_sha256: bytes,
    *,
    commit: bool,
) -> bytes:
    _validate_control_binding(request_id, plan_sha256)
    if type(commit) is not bool:
        raise HelperTargetError("The restore control decision is invalid")
    return _CONTROL.pack(
        _WIRE_MAGIC,
        _WIRE_VERSION,
        PACKET_COMMIT if commit else PACKET_CANCEL,
        0,
        request_id,
        plan_sha256,
    )


def unpack_restore_control(
    packet: bytes,
    *,
    request_id: bytes,
    plan_sha256: bytes,
) -> bool:
    _validate_control_binding(request_id, plan_sha256)
    if type(packet) is not bytes or len(packet) != _CONTROL.size:
        raise HelperTargetError("The restore decision packet is invalid")
    magic, version, packet_type, flags, received_id, received_digest = _CONTROL.unpack(packet)
    if (
        magic != _WIRE_MAGIC
        or version != _WIRE_VERSION
        or flags != 0
        or received_id != request_id
        or received_digest != plan_sha256
        or packet_type not in {PACKET_COMMIT, PACKET_CANCEL}
    ):
        raise HelperTargetError("The restore decision packet is invalid")
    return packet_type == PACKET_COMMIT


def unpack_restore_server_packet(packet: bytes) -> tuple[object, ...]:
    if type(packet) is not bytes or len(packet) < _HEADER.size:
        raise HelperTargetError("The restore server packet is truncated")
    magic, version, packet_type, flags = _HEADER.unpack_from(packet)
    if magic != _WIRE_MAGIC or version != _WIRE_VERSION or flags != 0:
        raise HelperTargetError("The restore server packet header is invalid")
    if packet_type == PACKET_READY and packet == _HEADER.pack(
        _WIRE_MAGIC, _WIRE_VERSION, PACKET_READY, 0,
    ):
        return ("ready",)
    if packet_type == PACKET_PREPARED and len(packet) == _CONTROL.size:
        fields = _CONTROL.unpack(packet)
        return ("prepared", fields[4], fields[5])
    if packet_type == PACKET_PROGRESS and len(packet) == _PROGRESS.size:
        fields = _PROGRESS.unpack(packet)
        phase = next((key for key, value in _PHASE_CODE.items() if value == fields[5]), None)
        if phase is None or fields[6] > fields[7]:
            raise HelperTargetError("The restore progress packet is invalid")
        return ("progress", fields[4], phase, fields[6], fields[7])
    if packet_type == PACKET_RESULT and len(packet) == _RESULT.size:
        fields = _RESULT.unpack(packet)
        filesystem_code = fields[18]
        label_size = fields[20]
        label_field = fields[23]
        if (
            filesystem_code not in _FILESYSTEM_FROM_CODE
            or fields[19] != 1
            or label_size > len(label_field)
            or any(label_field[label_size:])
        ):
            raise HelperTargetError("The restore result receipt header is invalid")
        try:
            label = label_field[:label_size].decode("utf-8", "strict")
        except UnicodeError as error:
            raise HelperTargetError("The restore result receipt label is invalid") from error
        return (
            "result",
            *fields[4:18],
            _FILESYSTEM_FROM_CODE[filesystem_code],
            fields[21],
            fields[22],
            label,
            fields[24],
            fields[25],
        )
    if packet_type == PACKET_ERROR and len(packet) == _ERROR.size:
        fields = _ERROR.unpack(packet)
        message = fields[6].split(b"\0", 1)[0].decode("utf-8", "replace")
        return ("error", fields[4], fields[5], message)
    raise HelperTargetError("The restore server packet shape is invalid")


def _send_packet(channel: socket.socket, packet: bytes) -> None:
    if channel.send(packet) != len(packet):
        raise HelperError("The restore protocol made a partial packet write")


def _receive_packet(channel: socket.socket) -> bytes:
    packet, ancillary, flags, _address = channel.recvmsg(
        MAX_PROTOCOL_PACKET + 1,
        socket.CMSG_SPACE(struct.calcsize("i")),
    )
    if ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or not packet:
        raise HelperTargetError("The restore protocol received an invalid packet")
    return packet


def _peer_uid(channel: socket.socket) -> int:
    credentials = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", credentials)
    return uid


def _invoking_uid() -> int:
    raw = os.environ.get("PKEXEC_UID", "")
    if not raw.isascii() or not raw.isdecimal():
        raise HelperTargetError("PolicyKit did not provide an invoking UID")
    uid = int(raw)
    if uid <= 0 or uid > 0xFFFFFFFF:
        raise HelperTargetError("The invoking UID is outside the supported range")
    return uid


def _reset_inherited_signal_state() -> None:
    for signum in _ORDINARY_TERMINATION_SIGNALS:
        signal.signal(signum, signal.SIG_DFL)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    signal.pthread_sigmask(
        signal.SIG_UNBLOCK,
        {*_ORDINARY_TERMINATION_SIGNALS, signal.SIGPIPE},
    )


def _defer_ordinary_termination() -> None:
    for signum in _ORDINARY_TERMINATION_SIGNALS:
        signal.signal(signum, signal.SIG_IGN)


def _verify_installed_script() -> None:
    if __file__ != INSTALLED_SCRIPT_PATH or sys.argv[0] != INSTALLED_SCRIPT_PATH:
        raise HelperTargetError("The restore helper script path is invalid")
    try:
        script_status = os.lstat(INSTALLED_SCRIPT_PATH)
    except OSError as error:
        raise HelperTargetError("Could not attest the installed restore helper") from error
    if (
        not stat.S_ISREG(script_status.st_mode)
        or script_status.st_uid != 0
        or stat.S_IMODE(script_status.st_mode) != 0o644
    ):
        raise HelperTargetError("The installed restore helper has unsafe ownership or mode")
    for parent in (
        "/usr/libexec/isopropyl",
        "/usr/libexec",
        "/usr",
    ):
        try:
            parent_status = os.lstat(parent)
        except OSError as error:
            raise HelperTargetError("Could not attest a restore-helper parent") from error
        if (
            not stat.S_ISDIR(parent_status.st_mode)
            or parent_status.st_uid != 0
            or parent_status.st_mode & 0o022
        ):
            raise HelperTargetError("The installed restore helper has an unsafe parent")


def _close_unexpected_descriptors(channel: socket.socket) -> None:
    channel_descriptor = channel.fileno()
    if type(channel_descriptor) is not int or channel_descriptor < 0:
        raise HelperTargetError("The restore helper channel descriptor is invalid")
    keep = {0, 1, 2, channel_descriptor}
    try:
        names = os.listdir("/proc/self/fd")
    except OSError as error:
        raise HelperTargetError("Could not inventory restore-helper descriptors") from error
    descriptors: set[int] = set()
    for name in names:
        if (
            not name.isascii()
            or not name.isdecimal()
            or (name.startswith("0") and name != "0")
        ):
            raise HelperTargetError("The restore-helper descriptor inventory is malformed")
        descriptor = int(name)
        if descriptor not in keep:
            descriptors.add(descriptor)
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:  # /proc enumeration's own descriptor already closed.
                raise HelperTargetError("Could not close an inherited restore-helper descriptor") from error
    try:
        for descriptor in keep:
            os.fstat(descriptor)
        os.set_inheritable(channel_descriptor, False)
    except OSError as error:
        raise HelperTargetError("Could not retain the required restore-helper descriptors") from error


def _harden_root_process(invoking_uid: int, channel: socket.socket) -> None:
    if os.getuid() != 0 or os.geteuid() != 0 or _peer_uid(channel) != invoking_uid:
        raise HelperTargetError("The restore helper identity or peer is invalid")
    for namespace in ("mnt", "user"):
        try:
            if os.readlink(f"/proc/self/ns/{namespace}") != os.readlink(f"/proc/1/ns/{namespace}"):
                raise HelperTargetError("The restore helper is in an unexpected namespace")
        except OSError as error:
            raise HelperTargetError("Could not attest the restore helper namespace") from error
    _close_unexpected_descriptors(channel)
    os.umask(0o077)
    os.chdir("/")
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
            raise HelperTargetError("Could not disable restore-helper core files")
    except (OSError, ValueError) as error:
        raise HelperTargetError("Could not disable restore-helper core files") from error
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
        raise HelperTargetError("Could not disable restore-helper core dumps")
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise HelperTargetError("Could not disable restore-helper privilege gains")
    if libc.prctl(39, 0, 0, 0, 0) != 1:  # PR_GET_NO_NEW_PRIVS
        raise HelperTargetError("Restore-helper privilege gains were not disabled")
    os.environ.clear()
    os.environ.update({"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})


def serve_restore_device_channel(channel: socket.socket, *, invoking_uid: int) -> int:
    request_id = b"\0" * 16
    try:
        _harden_root_process(invoking_uid, channel)
        _send_packet(channel, _HEADER.pack(_WIRE_MAGIC, _WIRE_VERSION, PACKET_READY, 0))
        request = unpack_restore_device_request(_receive_packet(channel))
        request_id = request.request_id

        def prepared() -> None:
            _send_packet(channel, _CONTROL.pack(
                _WIRE_MAGIC, _WIRE_VERSION, PACKET_PREPARED, 0, request.request_id,
                request.plan_sha256,
            ))

        def await_commit() -> bool:
            packet = _receive_packet(channel)
            if unpack_restore_control(
                packet,
                request_id=request.request_id,
                plan_sha256=request.plan_sha256,
            ):
                _defer_ordinary_termination()
                return True
            return False

        def progress(phase: str, done: int, total: int) -> None:
            _send_packet(channel, _PROGRESS.pack(
                _WIRE_MAGIC,
                _WIRE_VERSION,
                PACKET_PROGRESS,
                0,
                request.request_id,
                _PHASE_CODE[phase],
                done,
                total,
            ))

        result = execute_restore_device_transaction(
            request,
            await_commit=await_commit,
            prepared=prepared,
            progress=progress,
        )
        _send_packet(channel, pack_restore_device_result(request, result))
        return 0
    except BaseException as error:
        message = str(error).replace("\0", "").encode("utf-8", "replace")[:512]
        try:
            _send_packet(channel, _ERROR.pack(
                _WIRE_MAGIC,
                _WIRE_VERSION,
                PACKET_ERROR,
                0,
                request_id,
                1,
                message.ljust(512, b"\0"),
            ))
        except BaseException:
            pass
        return 1


def main(argv: list[str] | None = None) -> int:
    try:
        _reset_inherited_signal_state()
    except BaseException:
        return 2
    arguments = sys.argv[1:] if argv is None else argv
    if arguments != [RESTORE_DEVICE_OPERATION]:
        return 2
    try:
        _verify_installed_script()
        invoking_uid = _invoking_uid()
        channel = socket.fromfd(0, socket.AF_UNIX, socket.SOCK_SEQPACKET)
        if channel.family != socket.AF_UNIX or channel.type & 0xF != socket.SOCK_SEQPACKET:
            raise HelperTargetError("The restore helper requires a local sequenced-packet channel")
        try:
            return serve_restore_device_channel(channel, invoking_uid=invoking_uid)
        finally:
            channel.close()
    except BaseException:
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
