from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import os
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum

from .devices import Device, parse_lsblk


class FormattingError(RuntimeError):
    """Base class for safe-formatting failures."""


class FormatValidationError(FormattingError, ValueError):
    pass


class MissingFormatToolError(FormattingError):
    pass


class DeviceChangedError(FormattingError):
    pass


class FormatCancelled(FormattingError):
    pass


class Filesystem(str, Enum):
    FAT32 = "fat32"
    EXFAT = "exfat"
    NTFS = "ntfs"
    EXT4 = "ext4"


class PartitionTable(str, Enum):
    MBR = "mbr"
    GPT = "gpt"


class PartitionRole(str, Enum):
    """Semantic partition roles used by constructed-media workflows."""

    DATA = "data"
    EFI_SYSTEM = "efi-system"
    PERSISTENCE = "persistence"
    MICROSOFT_RESERVED = "microsoft-reserved"


DeviceIdentity = tuple[str, int, str, str, str, str]
StageCallback = Callable[[str], None]
DeviceLookup = Callable[[str], Device | None]


@dataclass(frozen=True)
class FormatPlan:
    """A validated intent bound to the drive selected by the user."""

    device_path: str
    device_identity: DeviceIdentity
    filesystem: Filesystem
    partition_table: PartitionTable
    label: str = ""


@dataclass(frozen=True)
class PartitionSpec:
    """One ordered partition in a multi-partition layout.

    ``size_mib=None`` means consume the remaining device space and is accepted
    only for the final partition.  Partitions such as the Microsoft Reserved
    Partition deliberately have no filesystem and are not formatted.
    """

    role: PartitionRole
    filesystem: Filesystem | None
    label: str = ""
    size_mib: int | None = None
    bootable: bool = False


@dataclass(frozen=True)
class MultiFormatPlan:
    """A complete ordered partitioning intent bound to one selected drive."""

    device_path: str
    device_identity: DeviceIdentity
    partition_table: PartitionTable
    partitions: tuple[PartitionSpec, ...]


@dataclass(frozen=True)
class FormatTools:
    pkexec: str
    udisksctl: str
    sfdisk: str
    partprobe: str
    udevadm: str
    lsblk: str
    mkfs: str


@dataclass(frozen=True)
class MultiFormatTools:
    pkexec: str
    udisksctl: str
    sfdisk: str
    partprobe: str
    udevadm: str
    lsblk: str
    mkfs_tools: tuple[tuple[Filesystem, str], ...]

    def mkfs_for(self, filesystem: Filesystem) -> str:
        for candidate, path in self.mkfs_tools:
            if candidate is filesystem:
                return path
        raise MissingFormatToolError(
            f"The multi-partition plan has no formatter for {filesystem.value}"
        )


_WHOLE_DISK = re.compile(
    r"/dev/(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|mmcblk\d+|ubd[a-z]+)"
)
_BLOCK_PATH = re.compile(r"/dev/[A-Za-z0-9._+:-]+")
_MAJOR_MINOR = re.compile(r"\d+:\d+")
_WINDOWS_FORBIDDEN = frozenset('"*/:<>?\\|')
_FAT_FORBIDDEN = _WINDOWS_FORBIDDEN | frozenset("+,.;=[]")
_MINIMUM_DEVICE_SIZE = 16 * 1024 * 1024
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"

_MKFS_NAMES: Mapping[Filesystem, str] = {
    Filesystem.FAT32: "mkfs.vfat",
    Filesystem.EXFAT: "mkfs.exfat",
    Filesystem.NTFS: "mkfs.ntfs",
    Filesystem.EXT4: "mkfs.ext4",
}

_MBR_TYPES: Mapping[Filesystem, str] = {
    Filesystem.FAT32: "c",
    Filesystem.EXFAT: "7",
    Filesystem.NTFS: "7",
    Filesystem.EXT4: "83",
}

_GPT_TYPES: Mapping[Filesystem, str] = {
    Filesystem.FAT32: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    Filesystem.EXFAT: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    Filesystem.NTFS: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    Filesystem.EXT4: "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
}

_MBR_ROLE_TYPES: Mapping[PartitionRole, str] = {
    PartitionRole.EFI_SYSTEM: "ef",
    PartitionRole.PERSISTENCE: "83",
}

_GPT_ROLE_TYPES: Mapping[PartitionRole, str] = {
    PartitionRole.DATA: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    PartitionRole.EFI_SYSTEM: "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
    PartitionRole.PERSISTENCE: "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
    PartitionRole.MICROSOFT_RESERVED: "E3C9E316-0B5C-4DB8-817D-F92DF00215AE",
}

_PARTITION_NAMES: Mapping[PartitionRole, str] = {
    PartitionRole.DATA: "ISOpropyl data",
    PartitionRole.EFI_SYSTEM: "ISOpropyl boot",
    PartitionRole.PERSISTENCE: "ISOpropyl persistence",
    PartitionRole.MICROSOFT_RESERVED: "Microsoft reserved",
}

_MINIMUM_PARTITION_MIB = 1
_MAXIMUM_GPT_PARTITIONS = 128
_MAXIMUM_MBR_PARTITIONS = 4


def _partition_belongs_to_device(device_path: str, partition_path: str) -> bool:
    separator = "p" if device_path[-1].isdigit() else ""
    return re.fullmatch(re.escape(device_path) + separator + r"\d+", partition_path) is not None


def _coerce_filesystem(value: Filesystem | str) -> Filesystem:
    try:
        return Filesystem(value)
    except ValueError as error:
        choices = ", ".join(item.value for item in Filesystem)
        raise FormatValidationError(
            f"Unsupported filesystem {value!r}; choose {choices}"
        ) from error


def _coerce_table(value: PartitionTable | str) -> PartitionTable:
    try:
        return PartitionTable(value)
    except ValueError as error:
        choices = ", ".join(item.value for item in PartitionTable)
        raise FormatValidationError(
            f"Unsupported partition table {value!r}; choose {choices}"
        ) from error


def validate_device(device: Device) -> None:
    """Reject anything outside ISOpropyl's removable/external whole-disk model."""
    if not _WHOLE_DISK.fullmatch(device.path):
        raise FormatValidationError(f"Unsafe or unsupported whole-disk path: {device.path!r}")
    if not _MAJOR_MINOR.fullmatch(device.major_minor):
        raise FormatValidationError("The drive has no stable kernel major:minor identity")
    if device.size < _MINIMUM_DEVICE_SIZE:
        raise FormatValidationError("The drive is too small to create a safe aligned partition")
    if device.read_only:
        raise FormatValidationError("The selected drive is read-only")
    if device.transport not in {"usb", "mmc"}:
        raise FormatValidationError("Only USB and SD/MMC drives can be formatted")
    if not device.removable and not (device.transport == "usb" and device.hotplug):
        raise FormatValidationError("The selected drive is not removable or hot-pluggable")
    for path in device.partitions:
        if not _BLOCK_PATH.fullmatch(path) or not _partition_belongs_to_device(device.path, path):
            raise FormatValidationError(f"Unsafe partition path reported for drive: {path!r}")


def validate_label(filesystem: Filesystem | str, label: str) -> str:
    fs = _coerce_filesystem(filesystem)
    if not isinstance(label, str):
        raise FormatValidationError("The volume label must be text")
    if label != label.strip():
        raise FormatValidationError("The volume label cannot start or end with whitespace")
    if any(ord(character) < 32 or ord(character) == 127 for character in label):
        raise FormatValidationError("The volume label cannot contain control characters")
    if fs is Filesystem.FAT32:
        if len(label.encode("utf-8")) > 11:
            raise FormatValidationError("FAT32 labels can be at most 11 UTF-8 bytes")
        if any(character in _FAT_FORBIDDEN for character in label):
            raise FormatValidationError("The FAT32 label contains an unsupported character")
    elif fs is Filesystem.EXFAT:
        if len(label.encode("utf-16-le")) // 2 > 15:
            raise FormatValidationError("exFAT labels can be at most 15 UTF-16 characters")
        if any(character in _WINDOWS_FORBIDDEN for character in label):
            raise FormatValidationError("The exFAT label contains an unsupported character")
    elif fs is Filesystem.NTFS:
        if len(label.encode("utf-16-le")) // 2 > 32:
            raise FormatValidationError("NTFS labels can be at most 32 UTF-16 characters")
        if any(character in _WINDOWS_FORBIDDEN for character in label):
            raise FormatValidationError("The NTFS label contains an unsupported character")
    else:
        if len(label.encode("utf-8")) > 16:
            raise FormatValidationError("ext4 labels can be at most 16 UTF-8 bytes")
        if "/" in label:
            raise FormatValidationError("The ext4 label cannot contain a slash")
    return label


def create_format_plan(
    device: Device,
    filesystem: Filesystem | str,
    partition_table: PartitionTable | str,
    label: str = "",
) -> FormatPlan:
    validate_device(device)
    fs = _coerce_filesystem(filesystem)
    table = _coerce_table(partition_table)
    return FormatPlan(device.path, device.identity, fs, table, validate_label(fs, label))


def _validate_partition_spec(
    spec: PartitionSpec,
    table: PartitionTable,
    index: int,
    count: int,
) -> None:
    if not isinstance(spec, PartitionSpec):
        raise FormatValidationError("Every partition must be a PartitionSpec")
    if not isinstance(spec.role, PartitionRole):
        raise FormatValidationError("A partition contains an invalid semantic role")
    if spec.filesystem is not None and not isinstance(spec.filesystem, Filesystem):
        raise FormatValidationError("A partition contains an invalid filesystem")
    if spec.size_mib is not None and (
        isinstance(spec.size_mib, bool)
        or not isinstance(spec.size_mib, int)
        or spec.size_mib < _MINIMUM_PARTITION_MIB
    ):
        raise FormatValidationError(
            f"Partition {index + 1} must be at least {_MINIMUM_PARTITION_MIB} MiB"
        )
    if spec.size_mib is None and index != count - 1:
        raise FormatValidationError(
            "Only the final partition may consume the remaining device space"
        )
    if spec.filesystem is None:
        if spec.label:
            raise FormatValidationError("An unformatted partition cannot have a volume label")
    else:
        validate_label(spec.filesystem, spec.label)
    if spec.role is PartitionRole.DATA and spec.filesystem is None:
        raise FormatValidationError("A data partition requires a filesystem")
    if spec.role is PartitionRole.EFI_SYSTEM and spec.filesystem is not Filesystem.FAT32:
        raise FormatValidationError("An EFI System Partition must use FAT32")
    if spec.role is PartitionRole.PERSISTENCE and spec.filesystem is not Filesystem.EXT4:
        raise FormatValidationError("A persistence partition must use ext4")
    if spec.role is PartitionRole.MICROSOFT_RESERVED:
        if table is not PartitionTable.GPT or spec.filesystem is not None:
            raise FormatValidationError(
                "A Microsoft Reserved Partition must be unformatted and use GPT"
            )
    if spec.bootable and table is not PartitionTable.MBR:
        raise FormatValidationError("The legacy bootable flag is valid only for MBR")


def validate_multi_plan(plan: MultiFormatPlan) -> None:
    if not isinstance(plan, MultiFormatPlan):
        raise FormatValidationError("A MultiFormatPlan is required")
    if not isinstance(plan.partition_table, PartitionTable):
        raise FormatValidationError("The multi-partition plan has an invalid partition table")
    if not _WHOLE_DISK.fullmatch(plan.device_path):
        raise FormatValidationError("The multi-partition plan has an unsafe device path")
    limit = (
        _MAXIMUM_MBR_PARTITIONS
        if plan.partition_table is PartitionTable.MBR
        else _MAXIMUM_GPT_PARTITIONS
    )
    if not plan.partitions or len(plan.partitions) > limit:
        raise FormatValidationError(
            f"A {plan.partition_table.value.upper()} plan requires 1 to {limit} partitions"
        )
    seen_singletons: set[PartitionRole] = set()
    for index, spec in enumerate(plan.partitions):
        _validate_partition_spec(spec, plan.partition_table, index, len(plan.partitions))
        if spec.role in {PartitionRole.EFI_SYSTEM, PartitionRole.MICROSOFT_RESERVED}:
            if spec.role in seen_singletons:
                raise FormatValidationError(
                    f"The plan contains more than one {spec.role.value} partition"
                )
            seen_singletons.add(spec.role)
    fixed_bytes = sum(
        spec.size_mib * 1024 * 1024
        for spec in plan.partitions
        if spec.size_mib is not None
    )
    # Device size is part of the frozen identity tuple.  Reserve one MiB for
    # the partition-table header/alignment and one MiB between each partition.
    device_size = plan.device_identity[1]
    alignment_reserve = (len(plan.partitions) + 1) * 1024 * 1024
    if fixed_bytes + alignment_reserve > device_size:
        raise FormatValidationError("The fixed partitions do not fit on the selected drive")


def create_multi_format_plan(
    device: Device,
    partition_table: PartitionTable | str,
    partitions: Sequence[PartitionSpec],
) -> MultiFormatPlan:
    validate_device(device)
    table = _coerce_table(partition_table)
    frozen = tuple(partitions)
    plan = MultiFormatPlan(device.path, device.identity, table, frozen)
    validate_multi_plan(plan)
    return plan


def validate_plan(plan: FormatPlan) -> None:
    if not isinstance(plan, FormatPlan):
        raise FormatValidationError("A FormatPlan is required")
    if not isinstance(plan.filesystem, Filesystem):
        raise FormatValidationError("The format plan contains an invalid filesystem")
    if not isinstance(plan.partition_table, PartitionTable):
        raise FormatValidationError("The format plan contains an invalid partition table")
    if not _WHOLE_DISK.fullmatch(plan.device_path):
        raise FormatValidationError("The format plan contains an unsafe device path")
    validate_label(plan.filesystem, plan.label)


def required_tool_names(plan: FormatPlan) -> tuple[str, ...]:
    validate_plan(plan)
    return (
        "pkexec", "udisksctl", "sfdisk", "partprobe", "udevadm", "lsblk",
        _MKFS_NAMES[plan.filesystem],
    )


def _trusted_which(name: str) -> str | None:
    """Never elevate a binary found through the calling user's mutable PATH."""
    return shutil.which(name, path=_TRUSTED_TOOL_PATH)


def resolve_tools(
    plan: FormatPlan,
    which: Callable[[str], str | None] = _trusted_which,
) -> FormatTools:
    resolved: dict[str, str] = {}
    missing: list[str] = []
    for name in required_tool_names(plan):
        path = which(name)
        if not path:
            missing.append(name)
        else:
            resolved[name] = os.path.abspath(path)
    if missing:
        raise MissingFormatToolError(
            "Formatting requires missing system tool" + ("s" if len(missing) != 1 else "")
            + ": " + ", ".join(missing)
        )
    return FormatTools(
        pkexec=resolved["pkexec"], udisksctl=resolved["udisksctl"],
        sfdisk=resolved["sfdisk"], partprobe=resolved["partprobe"],
        udevadm=resolved["udevadm"], lsblk=resolved["lsblk"],
        mkfs=resolved[_MKFS_NAMES[plan.filesystem]],
    )


def required_multi_tool_names(plan: MultiFormatPlan) -> tuple[str, ...]:
    validate_multi_plan(plan)
    base = ("pkexec", "udisksctl", "sfdisk", "partprobe", "udevadm", "lsblk")
    formatters = tuple(dict.fromkeys(
        _MKFS_NAMES[spec.filesystem]
        for spec in plan.partitions
        if spec.filesystem is not None
    ))
    return base + formatters


def resolve_multi_tools(
    plan: MultiFormatPlan,
    which: Callable[[str], str | None] = _trusted_which,
) -> MultiFormatTools:
    resolved: dict[str, str] = {}
    missing: list[str] = []
    for name in required_multi_tool_names(plan):
        path = which(name)
        if not path:
            missing.append(name)
        else:
            resolved[name] = os.path.abspath(path)
    if missing:
        raise MissingFormatToolError(
            "Multi-partition formatting requires missing system tool"
            + ("s" if len(missing) != 1 else "") + ": " + ", ".join(missing)
        )
    filesystems = tuple(dict.fromkeys(
        spec.filesystem for spec in plan.partitions if spec.filesystem is not None
    ))
    return MultiFormatTools(
        pkexec=resolved["pkexec"], udisksctl=resolved["udisksctl"],
        sfdisk=resolved["sfdisk"], partprobe=resolved["partprobe"],
        udevadm=resolved["udevadm"], lsblk=resolved["lsblk"],
        mkfs_tools=tuple((filesystem, resolved[_MKFS_NAMES[filesystem]]) for filesystem in filesystems),
    )


def partition_script(plan: FormatPlan) -> bytes:
    label = "dos" if plan.partition_table is PartitionTable.MBR else "gpt"
    types = _MBR_TYPES if plan.partition_table is PartitionTable.MBR else _GPT_TYPES
    # A single 1 MiB-aligned partition consumes the remaining space.
    return (
        f"label: {label}\nunit: sectors\n\nstart=2048, type={types[plan.filesystem]}\n"
    ).encode("ascii")


def _partition_type(spec: PartitionSpec, table: PartitionTable) -> str:
    if table is PartitionTable.GPT:
        if spec.role is PartitionRole.DATA:
            assert spec.filesystem is not None
            return _GPT_TYPES[spec.filesystem]
        return _GPT_ROLE_TYPES[spec.role]
    if spec.role is PartitionRole.DATA:
        assert spec.filesystem is not None
        return _MBR_TYPES[spec.filesystem]
    try:
        return _MBR_ROLE_TYPES[spec.role]
    except KeyError as error:
        raise FormatValidationError(
            f"Partition role {spec.role.value!r} is not supported with MBR"
        ) from error


def multi_partition_script(plan: MultiFormatPlan) -> bytes:
    """Return a complete deterministic sfdisk script for a frozen layout."""
    validate_multi_plan(plan)
    label = "dos" if plan.partition_table is PartitionTable.MBR else "gpt"
    lines = [f"label: {label}", ""]
    for spec in plan.partitions:
        fields: list[str] = []
        if spec.size_mib is not None:
            fields.append(f"size={spec.size_mib}MiB")
        fields.append(f"type={_partition_type(spec, plan.partition_table)}")
        if plan.partition_table is PartitionTable.GPT:
            fields.append(f'name="{_PARTITION_NAMES[spec.role]}"')
        elif spec.bootable:
            fields.append("bootable")
        lines.append(", ".join(fields))
    return ("\n".join(lines) + "\n").encode("ascii")


def partition_command(plan: FormatPlan, tools: FormatTools) -> list[str]:
    return [
        tools.pkexec, tools.sfdisk, "--lock=yes", "--wipe", "always",
        "--wipe-partitions", "always", plan.device_path,
    ]


def multi_partition_command(
    plan: MultiFormatPlan, tools: MultiFormatTools,
) -> list[str]:
    validate_multi_plan(plan)
    return [
        tools.pkexec, tools.sfdisk, "--lock=yes", "--wipe", "always",
        "--wipe-partitions", "always", plan.device_path,
    ]


def _format_command(
    filesystem: Filesystem,
    label: str,
    mkfs: str,
    partition: str,
) -> list[str]:
    command = [mkfs]
    if filesystem is Filesystem.FAT32:
        command.extend(["-F", "32"])
        if label:
            command.extend(["-n", label])
    elif filesystem is Filesystem.EXFAT:
        if label:
            command.extend(["-L", label])
    elif filesystem is Filesystem.NTFS:
        command.append("-f")
        if label:
            command.extend(["-L", label])
    else:
        command.append("-F")
        if label:
            command.extend(["-L", label])
    command.append(partition)
    return command


def format_command(plan: FormatPlan, tools: FormatTools, partition: str) -> list[str]:
    if (
        not _BLOCK_PATH.fullmatch(partition)
        or not _partition_belongs_to_device(plan.device_path, partition)
    ):
        raise FormatValidationError(f"Unsafe partition path: {partition!r}")
    return [tools.pkexec, *_format_command(
        plan.filesystem, plan.label, tools.mkfs, partition,
    )]


def multi_format_commands(
    plan: MultiFormatPlan,
    tools: MultiFormatTools,
    partitions: Sequence[str],
) -> tuple[list[str], ...]:
    validate_multi_plan(plan)
    if len(partitions) != len(plan.partitions):
        raise FormatValidationError(
            "The discovered partition count does not match the frozen layout"
        )
    commands: list[list[str]] = []
    for spec, partition in zip(plan.partitions, partitions, strict=True):
        if (
            not _BLOCK_PATH.fullmatch(partition)
            or not _partition_belongs_to_device(plan.device_path, partition)
        ):
            raise FormatValidationError(f"Unsafe partition path: {partition!r}")
        if spec.filesystem is None:
            continue
        commands.append([tools.pkexec, *_format_command(
            spec.filesystem, spec.label, tools.mkfs_for(spec.filesystem), partition,
        )])
    return tuple(commands)


def parse_partitions(payload: str, device_path: str) -> tuple[str, ...]:
    """Extract partitions descended from a specific whole disk in lsblk JSON."""
    if not _WHOLE_DISK.fullmatch(device_path):
        raise FormatValidationError(f"Unsafe whole-disk path: {device_path!r}")
    try:
        nodes = json.loads(payload).get("blockdevices", [])
    except (AttributeError, TypeError, json.JSONDecodeError) as error:
        raise FormattingError("lsblk returned invalid partition data") from error
    found: list[str] = []

    def visit(node: object, below_target: bool = False) -> None:
        if not isinstance(node, dict):
            return
        path = str(node.get("path") or "")
        is_target = path == device_path and node.get("type") == "disk"
        below = below_target or is_target
        if (
            below and node.get("type") == "part" and _BLOCK_PATH.fullmatch(path)
            and _partition_belongs_to_device(device_path, path)
        ):
            found.append(path)
        for child in node.get("children") or []:
            visit(child, below)

    for node in nodes:
        visit(node)
    prefix = device_path + ("p" if device_path[-1].isdigit() else "")
    unique = dict.fromkeys(found)
    return tuple(sorted(unique, key=lambda path: int(path.removeprefix(prefix))))


class FormatExecutor:
    """Execute a FormatPlan without ever passing user data through a shell."""

    def __init__(
        self,
        *,
        device_lookup: DeviceLookup | None = None,
        which: Callable[[str], str | None] = _trusted_which,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        sleep: Callable[[float], None] = time.sleep,
        discovery_attempts: int = 20,
        discovery_interval: float = 0.25,
    ) -> None:
        self._device_lookup = device_lookup
        self._which = which
        self._popen = popen
        self._runner = runner
        self._sleep = sleep
        self._discovery_attempts = max(1, discovery_attempts)
        self._discovery_interval = max(0.0, discovery_interval)
        self._cancelled = threading.Event()
        self._process: subprocess.Popen[bytes] | None = None

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        self._cancelled.set()
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()

    def _check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise FormatCancelled("Formatting was cancelled")

    def _lookup_device(self, path: str, tools: FormatTools) -> Device | None:
        if self._device_lookup is not None:
            return self._device_lookup(path)
        fields = "PATH,SIZE,TYPE,RM,HOTPLUG,TRAN,MODEL,VENDOR,SERIAL,WWN,MAJ:MIN,MOUNTPOINTS,RO"
        result = self._runner(
            [tools.lsblk, "--tree", "--bytes", "--json", "--output", fields, path],
            capture_output=True, text=True, shell=False,
        )
        if result.returncode:
            return None
        try:
            devices = parse_lsblk(result.stdout, include_usb_hdds=True)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None
        return next((device for device in devices if device.path == path), None)

    def _assert_identity(self, plan: FormatPlan, tools: FormatTools) -> Device:
        self._check_cancelled()
        current = self._lookup_device(plan.device_path, tools)
        if current is None:
            raise DeviceChangedError("The selected drive is no longer connected")
        validate_device(current)
        if current.identity != plan.device_identity:
            raise DeviceChangedError(
                "The drive at the selected path changed; formatting was stopped"
            )
        return current

    def _run_process(self, argv: Sequence[str], input_data: bytes | None = None) -> None:
        self._check_cancelled()
        process = self._popen(
            list(argv), stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
        )
        self._process = process
        first = True
        try:
            while True:
                try:
                    _stdout, stderr = process.communicate(
                        input=input_data if first else None, timeout=0.2,
                    )
                    break
                except subprocess.TimeoutExpired:
                    first = False
                    if self._cancelled.is_set():
                        process.terminate()
                        process.communicate()
                        raise FormatCancelled("Formatting was cancelled")
            if process.returncode:
                message = stderr.decode(errors="replace").strip()
                raise FormattingError(message or f"Command failed: {argv[1]}")
        finally:
            self._process = None
        self._check_cancelled()

    def _unmount(self, device: Device, tools: FormatTools) -> None:
        targets = device.partitions or ((device.path,) if device.mountpoints else ())
        for target in targets:
            self._check_cancelled()
            result = self._runner(
                [tools.udisksctl, "unmount", "--block-device", target],
                capture_output=True, text=True, shell=False,
            )
            combined = ((result.stdout or "") + (result.stderr or "")).strip()
            if result.returncode and not any(
                text in combined.casefold()
                for text in ("not mounted", "not a mounted filesystem")
            ):
                raise FormattingError(combined or f"Could not unmount {target}")

    def _discover_partition(self, plan: FormatPlan, tools: FormatTools) -> str:
        for attempt in range(self._discovery_attempts):
            self._check_cancelled()
            result = self._runner(
                [
                    tools.lsblk, "--json", "--paths", "--output", "PATH,TYPE",
                    plan.device_path,
                ],
                capture_output=True, text=True, shell=False,
            )
            if result.returncode:
                message = ((result.stdout or "") + (result.stderr or "")).strip()
                raise FormattingError(message or "Could not inspect the new partition")
            partitions = parse_partitions(result.stdout, plan.device_path)
            if len(partitions) == 1:
                return partitions[0]
            if len(partitions) > 1:
                raise FormattingError(
                    "Partitioning returned more than one partition; refusing to choose a target"
                )
            if attempt + 1 < self._discovery_attempts:
                self._sleep(self._discovery_interval)
        raise FormattingError("The new partition did not appear")

    def execute(
        self,
        device: Device,
        plan: FormatPlan,
        stage: StageCallback | None = None,
    ) -> str:
        """Restore a drive to one empty partition and return its partition path."""
        validate_device(device)
        validate_plan(plan)
        if device.path != plan.device_path or device.identity != plan.device_identity:
            raise DeviceChangedError("The format plan does not belong to the selected drive")
        validate_label(plan.filesystem, plan.label)
        tools = resolve_tools(plan, self._which)  # Preflight before touching the drive.
        report = stage or (lambda _message: None)

        current = self._assert_identity(plan, tools)
        report("Unmounting")
        self._unmount(current, tools)
        self._assert_identity(plan, tools)

        report("Creating partition table")
        self._run_process(partition_command(plan, tools), partition_script(plan))
        self._run_process([tools.pkexec, tools.partprobe, plan.device_path])
        self._run_process([tools.udevadm, "settle"])

        report("Waiting for partition")
        partition = self._discover_partition(plan, tools)
        self._assert_identity(plan, tools)

        report("Creating filesystem")
        self._run_process(format_command(plan, tools, partition))
        self._run_process([tools.udevadm, "settle"])
        report("Complete")
        return partition


class MultiFormatExecutor(FormatExecutor):
    """Execute an immutable multi-partition layout without guessing children."""

    def _discover_partitions(
        self,
        plan: MultiFormatPlan,
        tools: MultiFormatTools,
    ) -> tuple[str, ...]:
        expected_count = len(plan.partitions)
        for attempt in range(self._discovery_attempts):
            self._check_cancelled()
            result = self._runner(
                [
                    tools.lsblk, "--json", "--paths", "--output", "PATH,TYPE",
                    plan.device_path,
                ],
                capture_output=True, text=True, shell=False,
            )
            if result.returncode:
                message = ((result.stdout or "") + (result.stderr or "")).strip()
                raise FormattingError(message or "Could not inspect the new partitions")
            partitions = parse_partitions(result.stdout, plan.device_path)
            if len(partitions) == expected_count:
                return partitions
            if len(partitions) > expected_count:
                raise FormattingError(
                    "Partitioning returned more children than the frozen layout"
                )
            if attempt + 1 < self._discovery_attempts:
                self._sleep(self._discovery_interval)
        raise FormattingError(
            f"Expected {expected_count} new partitions, but they did not all appear"
        )

    def execute_multi(
        self,
        device: Device,
        plan: MultiFormatPlan,
        stage: StageCallback | None = None,
    ) -> tuple[str, ...]:
        """Create, format, and return every partition in canonical number order."""
        validate_device(device)
        validate_multi_plan(plan)
        if device.path != plan.device_path or device.identity != plan.device_identity:
            raise DeviceChangedError(
                "The multi-partition plan does not belong to the selected drive"
            )
        tools = resolve_multi_tools(plan, self._which)  # Preflight before device access.
        report = stage or (lambda _message: None)

        current = self._assert_identity(plan, tools)  # type: ignore[arg-type]
        report("Unmounting")
        self._unmount(current, tools)  # type: ignore[arg-type]
        self._assert_identity(plan, tools)  # type: ignore[arg-type]

        report("Creating partition table")
        self._run_process(
            multi_partition_command(plan, tools), multi_partition_script(plan),
        )
        self._run_process([tools.pkexec, tools.partprobe, plan.device_path])
        self._run_process([tools.udevadm, "settle"])

        report("Waiting for partitions")
        partitions = self._discover_partitions(plan, tools)
        self._assert_identity(plan, tools)  # type: ignore[arg-type]

        commands = multi_format_commands(plan, tools, partitions)
        if commands:
            report("Creating filesystems")
        for command in commands:
            self._assert_identity(plan, tools)  # type: ignore[arg-type]
            self._run_process(command)
        self._run_process([tools.udevadm, "settle"])
        self._assert_identity(plan, tools)  # type: ignore[arg-type]
        report("Complete")
        return partitions
