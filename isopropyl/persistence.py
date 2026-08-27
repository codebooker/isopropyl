from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Conservative persistence detection, planning, and narrow execution.

Broad Ubuntu/Mint/Debian/Kali recognition remains planning-only. A separate
fail-closed executor supports explicit Ubuntu amd64 LTS 20.04, 22.04, and 24.04
Casper profiles when the existing media layout already reserves a contiguous
tail; it never shrinks or moves a partition.
"""

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import threading
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from collections.abc import Callable, Sequence

from .devices import Device, parse_lsblk
from .formatting import PartitionTable, FormattingError, validate_device
from .images import ImageInspection
from .locking import (
    CooperativeLockError,
    add_native_sfdisk_lock,
    cooperative_lock_command,
    is_cooperative_lock_command,
    lock_conflict_message,
    resolve_flock,
)

MIB = 1024 * 1024
MIN_PERSISTENCE_BYTES = 256 * MIB
ALIGNMENT_BYTES = MIB


class PersistenceError(ValueError):
    pass


@dataclass(frozen=True)
class PersistenceProfile:
    family: str
    filesystem: str
    label: str
    boot_parameter: str
    configuration_path: str = ""
    configuration_contents: str = ""
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class PersistencePlan:
    profile: PersistenceProfile
    partition_bytes: int
    minimum_bytes: int
    blocker: str

    @property
    def executable(self) -> bool:
        return False


def _paths(inspection: ImageInspection) -> set[str]:
    return {
        member.path.replace("\\", "/").casefold().lstrip("/")
        for member in inspection.members
    }


def detect_persistence_profile(
    inspection: ImageInspection,
) -> PersistenceProfile | None:
    paths = _paths(inspection)
    label = inspection.volume_label.casefold()
    if "tails" in label:
        # Tails deliberately manages encrypted persistence inside the running
        # OS. A generic writer must not substitute an unencrypted partition.
        return None
    has_casper = any(path.startswith("casper/") for path in paths) and any(
        path.startswith("casper/vmlinuz") for path in paths
    )
    if has_casper and any(name in label for name in ("ubuntu", "mint", "pop_os", "pop-os")):
        old_release = bool(re.search(r"(?:^|[^0-9])1[468]\.\d{2}(?:[^0-9]|$)", label))
        persistent_label = "casper-rw" if old_release else "writable"
        return PersistenceProfile(
            family="casper",
            filesystem="ext4",
            label=persistent_label,
            boot_parameter="persistent",
            evidence=("casper kernel tree", f"volume label {inspection.volume_label!r}"),
        )
    has_live_boot = (
        any(path.startswith("live/vmlinuz") for path in paths)
        and any(path.startswith("live/filesystem.squashfs") for path in paths)
    )
    if has_live_boot and any(name in label for name in ("debian", "kali")):
        return PersistenceProfile(
            family="debian-live-boot",
            filesystem="ext4",
            label="persistence",
            boot_parameter="persistence",
            configuration_path="persistence.conf",
            configuration_contents="/ union\n",
            evidence=("Debian live-boot tree", f"volume label {inspection.volume_label!r}"),
        )
    return None


def build_persistence_plan(
    inspection: ImageInspection,
    partition_bytes: int,
) -> PersistencePlan:
    profile = detect_persistence_profile(inspection)
    if profile is None:
        raise PersistenceError(
            "This image is not in ISOpropyl's conservative Ubuntu/Mint/Debian/Kali persistence matrix"
        )
    if not isinstance(partition_bytes, int) or isinstance(partition_bytes, bool):
        raise PersistenceError("Persistence size must be an integer number of bytes")
    if partition_bytes < MIN_PERSISTENCE_BYTES:
        raise PersistenceError("Persistence partitions must be at least 256 MiB")
    if partition_bytes % ALIGNMENT_BYTES:
        raise PersistenceError("Persistence size must be aligned to 1 MiB")
    return PersistencePlan(
        profile,
        partition_bytes,
        MIN_PERSISTENCE_BYTES,
        "Persistence execution awaits per-release boot-config and partition-layout testing.",
    )


# ---------------------------------------------------------------------------
# Executable Ubuntu/Casper backend
# ---------------------------------------------------------------------------

SECTOR_BYTES = 512
SECTORS_PER_MIB = MIB // SECTOR_BYTES
MAX_BOOT_CONFIG_BYTES = 2 * MIB
MAX_EVIDENCE_HASH_BYTES = 64 * MIB
MAX_COMMAND_OUTPUT = 64 * 1024
COMMAND_TIMEOUT_SECONDS = 5 * 60
COMMAND_TERMINATE_GRACE_SECONDS = 2.0
COMMAND_KILL_GRACE_SECONDS = 2.0
CASPER_RELEASES = ("20.04", "22.04", "24.04")
LINUX_FILESYSTEM_GUID = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
MICROSOFT_BASIC_DATA_GUID = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_TRUSTED_TOOL_DIRECTORIES = frozenset(_TRUSTED_TOOL_PATH.split(":"))
_WHOLE_DISK = re.compile(
    r"/dev/(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|mmcblk\d+|ubd[a-z]+)"
)
_BLOCK_PATH = re.compile(r"/dev/[A-Za-z0-9._+:-]+")
_MAJOR_MINOR = re.compile(r"\d+:\d+")
_GRUB_COMMAND = frozenset(("linux", "linuxefi"))
_SYSLINUX_KERNEL = frozenset(("kernel", "linux"))
_GRUB_CONFIG_PATHS = (
    "boot/grub/grub.cfg",
    "boot/grub/loopback.cfg",
    "EFI/BOOT/grub.cfg",
)
_SYSLINUX_CONFIG_PATHS = (
    "isolinux/isolinux.cfg",
    "isolinux/menu.cfg",
    "isolinux/txt.cfg",
    "syslinux/syslinux.cfg",
    "syslinux/menu.cfg",
    "syslinux/txt.cfg",
)
_DIR_FLAGS = (
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


class PersistenceBackendError(RuntimeError):
    pass


class PersistenceBackendUnavailable(PersistenceBackendError):
    pass


class PersistenceBackendSafetyError(PersistenceBackendError):
    pass


class PersistenceBackendCancelled(PersistenceBackendError):
    pass


@dataclass(frozen=True)
class CasperCompatibilityProfile:
    """One release-specific compatibility promise, rather than a heuristic."""

    profile_id: str
    ubuntu_release: str
    architecture: str
    filesystem: str
    partition_label: str
    boot_parameter: str
    configuration_path: str = ""
    configuration_contents: bytes = b""


def ubuntu_casper_profile(
    ubuntu_release: str,
    architecture: str = "amd64",
) -> CasperCompatibilityProfile:
    if ubuntu_release not in CASPER_RELEASES:
        supported = ", ".join(CASPER_RELEASES)
        raise PersistenceBackendSafetyError(
            f"Executable Casper persistence is limited to Ubuntu LTS {supported}"
        )
    if architecture != "amd64":
        raise PersistenceBackendSafetyError(
            "The first executable Casper profile is limited to Ubuntu amd64 media"
        )
    return CasperCompatibilityProfile(
        profile_id="ubuntu-casper-writable-v1",
        ubuntu_release=ubuntu_release,
        architecture=architecture,
        filesystem="ext4",
        partition_label="writable",
        boot_parameter="persistent",
    )


@dataclass(frozen=True)
class PartitionLayout:
    number: int
    path: str
    start_sector: int
    sector_count: int
    partition_type: str
    filesystem: str
    label: str
    mountpoints: tuple[str, ...]
    major_minor: str

    @property
    def end_sector(self) -> int:
        return self.start_sector + self.sector_count


@dataclass(frozen=True)
class MediaLayout:
    partition_table: PartitionTable
    sector_size: int
    partitions: tuple[PartitionLayout, ...]


@dataclass(frozen=True)
class PersistenceTools:
    pkexec: str
    flock: str
    sfdisk: str
    partprobe: str
    udevadm: str
    lsblk: str
    mkfs_ext4: str


FileIdentity = tuple[int, int, int, int, int]
RootIdentity = tuple[int, int, int, int]


@dataclass(frozen=True)
class SourceFileBinding:
    relative_path: str
    identity: FileIdentity
    sha256: str


@dataclass(frozen=True)
class BootConfigBinding:
    relative_path: str
    bootloader: str
    identity: FileIdentity
    mode: int
    original_sha256: str
    transformed_sha256: str
    original_contents: bytes
    transformed_contents: bytes
    eligible_lines: int
    changed_lines: int


@dataclass(frozen=True)
class CasperPersistencePlan:
    profile: CasperCompatibilityProfile
    media_root: Path
    media_root_identity: RootIdentity
    device: Device
    layout: MediaLayout
    evidence: tuple[SourceFileBinding, ...]
    boot_configs: tuple[BootConfigBinding, ...]
    partition_bytes: int
    partition_start_sector: int
    partition_sector_count: int
    partition_path: str
    tools: PersistenceTools

    @property
    def executable(self) -> bool:
        return True


@dataclass(frozen=True)
class PersistenceExecutionProgress:
    stage: str
    step: int
    total_steps: int

    @property
    def fraction(self) -> float:
        if self.total_steps <= 0:
            return 0.0
        return min(1.0, max(0.0, self.step / self.total_steps))


@dataclass(frozen=True)
class PersistenceExecutionResult:
    device_identity: tuple[str, int, str, str, str, str]
    partition_path: str
    partition_bytes: int
    partition_label: str
    boot_configs_updated: tuple[str, ...]
    persistence_token: str


@dataclass(frozen=True)
class BootConfigTransform:
    contents: bytes
    eligible_lines: int
    changed_lines: int


DeviceLookup = Callable[[str], Device | None]
LayoutReader = Callable[[Device, Path, PersistenceTools], MediaLayout]
Progress = Callable[[PersistenceExecutionProgress], None]


def _validate_profile(profile: CasperCompatibilityProfile) -> None:
    if not isinstance(profile, CasperCompatibilityProfile):
        raise PersistenceBackendSafetyError("A CasperCompatibilityProfile is required")
    expected = ubuntu_casper_profile(profile.ubuntu_release, profile.architecture)
    if profile != expected:
        raise PersistenceBackendSafetyError("The Casper compatibility profile was modified")


def _trusted_which(name: str) -> str | None:
    return shutil.which(name, path=_TRUSTED_TOOL_PATH)


def _trusted_tool(name: str, finder: Callable[[str], str | None]) -> str:
    value = finder(name)
    if not value:
        raise PersistenceBackendUnavailable(f"Persistence requires missing tool: {name}")
    normalized = os.path.normpath(value)
    if (
        not os.path.isabs(value)
        or normalized != value
        or os.path.dirname(value) not in _TRUSTED_TOOL_DIRECTORIES
        or os.path.basename(value) != name
    ):
        raise PersistenceBackendUnavailable(f"Refusing untrusted tool path: {value!r}")
    return value


def resolve_persistence_tools(
    finder: Callable[[str], str | None] = _trusted_which,
) -> PersistenceTools:
    try:
        flock = resolve_flock(finder)
    except CooperativeLockError as error:
        raise PersistenceBackendUnavailable(str(error)) from error
    return PersistenceTools(
        pkexec=_trusted_tool("pkexec", finder),
        flock=flock,
        sfdisk=_trusted_tool("sfdisk", finder),
        partprobe=_trusted_tool("partprobe", finder),
        udevadm=_trusted_tool("udevadm", finder),
        lsblk=_trusted_tool("lsblk", finder),
        mkfs_ext4=_trusted_tool("mkfs.ext4", finder),
    )


def _validate_tools(tools: PersistenceTools) -> None:
    if not isinstance(tools, PersistenceTools):
        raise PersistenceBackendSafetyError("The plan contains invalid persistence tools")
    for name, value in (
        ("pkexec", tools.pkexec),
        ("sfdisk", tools.sfdisk),
        ("partprobe", tools.partprobe),
        ("udevadm", tools.udevadm),
        ("lsblk", tools.lsblk),
        ("mkfs.ext4", tools.mkfs_ext4),
    ):
        try:
            resolved = _trusted_tool(name, lambda requested, n=name, v=value: (
                v if requested == n else None
            ))
        except PersistenceBackendUnavailable as error:
            raise PersistenceBackendSafetyError(str(error)) from error
        if resolved != value:
            raise PersistenceBackendSafetyError("The plan contains inconsistent tool paths")
    try:
        resolved_flock = resolve_flock(
            lambda name: tools.flock if name == "flock" else None
        )
    except CooperativeLockError as error:
        raise PersistenceBackendSafetyError(str(error)) from error
    if resolved_flock != tools.flock:
        raise PersistenceBackendSafetyError("The plan contains inconsistent tool paths")


def _partition_path(device_path: str, number: int) -> str:
    if not _WHOLE_DISK.fullmatch(device_path) or number <= 0:
        raise PersistenceBackendSafetyError("Unsafe partition path request")
    separator = "p" if device_path[-1].isdigit() else ""
    return f"{device_path}{separator}{number}"


def _normal_type(value: str) -> str:
    return value.strip().upper().removeprefix("0X")


def _parse_partition_number(device_path: str, partition_path: str) -> int:
    prefix = device_path + ("p" if device_path[-1].isdigit() else "")
    if not partition_path.startswith(prefix):
        raise PersistenceBackendSafetyError("A partition does not belong to the selected drive")
    suffix = partition_path.removeprefix(prefix)
    if not suffix.isascii() or not suffix.isdecimal() or int(suffix) <= 0:
        raise PersistenceBackendSafetyError("A partition has an invalid number")
    return int(suffix)


def _validate_layout(layout: MediaLayout, device: Device, media_root: Path) -> None:
    if not isinstance(layout, MediaLayout):
        raise PersistenceBackendSafetyError("The media layout is invalid")
    if layout.partition_table not in {PartitionTable.GPT, PartitionTable.MBR}:
        raise PersistenceBackendSafetyError("Only GPT and MBR constructed media are supported")
    if layout.sector_size != SECTOR_BYTES:
        raise PersistenceBackendSafetyError("Persistence requires 512-byte logical sectors")
    seen: set[int] = set()
    for partition in layout.partitions:
        if not isinstance(partition, PartitionLayout):
            raise PersistenceBackendSafetyError("The media layout contains an invalid partition")
        if partition.number in seen or partition.number <= 0:
            raise PersistenceBackendSafetyError("The media layout has duplicate partition numbers")
        seen.add(partition.number)
        if partition.path != _partition_path(device.path, partition.number):
            raise PersistenceBackendSafetyError("The media layout contains an unexpected path")
        if (
            partition.start_sector < SECTORS_PER_MIB
            or partition.sector_count <= 0
            or partition.end_sector > device.size // SECTOR_BYTES
        ):
            raise PersistenceBackendSafetyError("The media layout contains invalid geometry")
        if not _MAJOR_MINOR.fullmatch(partition.major_minor):
            raise PersistenceBackendSafetyError("A partition lacks a kernel major:minor identity")
        if any(not os.path.isabs(path) for path in partition.mountpoints):
            raise PersistenceBackendSafetyError("The media layout contains a relative mountpoint")
    ordered = tuple(sorted(layout.partitions, key=lambda item: item.number))
    if layout.partitions != ordered:
        raise PersistenceBackendSafetyError("The media layout is not in partition-number order")
    if len(layout.partitions) == 1:
        first = layout.partitions[0]
        if first.number != 1 or first.path != _partition_path(device.path, 1):
            raise PersistenceBackendSafetyError("Constructed media must have exactly partition 1")
        if first.filesystem.casefold() not in {"vfat", "fat", "fat32"}:
            raise PersistenceBackendSafetyError("The constructed media partition is not FAT32")
        if first.label.casefold() != "isopropyl":
            raise PersistenceBackendSafetyError(
                "The FAT32 media label is not ISOpropyl's constructed-media label"
            )
        mounted = {Path(path).resolve(strict=False) for path in first.mountpoints}
        if mounted != {media_root}:
            raise PersistenceBackendSafetyError(
                "The supplied media root is not the sole mount of partition 1"
            )
        kind = _normal_type(first.partition_type)
        allowed = (
            {MICROSOFT_BASIC_DATA_GUID}
            if layout.partition_table is PartitionTable.GPT
            else {"B", "C", "0B", "0C"}
        )
        if kind not in allowed:
            raise PersistenceBackendSafetyError(
                "Partition 1 does not have a recognized FAT32 partition type"
            )


def _completed_or_error(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    argv: Sequence[str],
) -> subprocess.CompletedProcess[str]:
    result = runner(
        list(argv), capture_output=True, text=True, shell=False,
        timeout=30,
    )
    if result.returncode:
        detail = ((result.stdout or "") + (result.stderr or "")).strip()
        raise PersistenceBackendError(detail[-2048:] or f"Command failed: {argv[-1]}")
    if len(result.stdout or "") > 4 * MIB or len(result.stderr or "") > MAX_COMMAND_OUTPUT:
        raise PersistenceBackendError("A layout inspection command produced too much output")
    return result


def read_media_layout(
    device: Device,
    media_root: Path,
    tools: PersistenceTools,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> MediaLayout:
    """Read sfdisk geometry and merge it with lsblk filesystem identities."""

    _validate_tools(tools)
    try:
        table_result = _completed_or_error(
            runner, [tools.pkexec, tools.sfdisk, "--json", device.path],
        )
        block_result = _completed_or_error(
            runner,
            [
                tools.lsblk, "--bytes", "--json", "--paths", "--output",
                "PATH,TYPE,FSTYPE,LABEL,MAJ:MIN,MOUNTPOINTS,RO", device.path,
            ],
        )
        table_data = json.loads(table_result.stdout)
        block_data = json.loads(block_result.stdout)
    except (json.JSONDecodeError, TypeError, AttributeError, KeyError) as error:
        raise PersistenceBackendSafetyError("Could not parse the media partition layout") from error

    table = table_data.get("partitiontable")
    if not isinstance(table, dict) or table.get("device") != device.path:
        raise PersistenceBackendSafetyError("sfdisk returned a layout for another device")
    label = str(table.get("label") or "").casefold()
    try:
        partition_table = {"gpt": PartitionTable.GPT, "dos": PartitionTable.MBR}[label]
        sector_size = int(table.get("sectorsize"))
    except (KeyError, TypeError, ValueError) as error:
        raise PersistenceBackendSafetyError("sfdisk returned an unsupported partition table") from error
    if str(table.get("unit") or "").casefold() != "sectors":
        raise PersistenceBackendSafetyError("sfdisk did not report sector-based geometry")

    block_nodes: dict[str, dict] = {}

    def visit(value: object) -> None:
        if not isinstance(value, dict):
            return
        path = str(value.get("path") or "")
        if path:
            block_nodes[path] = value
        for child in value.get("children") or ():
            visit(child)

    for node in block_data.get("blockdevices") or ():
        visit(node)

    partitions: list[PartitionLayout] = []
    for raw in table.get("partitions") or ():
        if not isinstance(raw, dict):
            raise PersistenceBackendSafetyError("sfdisk returned an invalid partition entry")
        path = str(raw.get("node") or "")
        node = block_nodes.get(path)
        if node is None or node.get("type") != "part" or bool(node.get("ro")):
            raise PersistenceBackendSafetyError("lsblk did not confirm a writable partition")
        mountpoints = tuple(str(item) for item in (node.get("mountpoints") or ()) if item)
        try:
            partitions.append(PartitionLayout(
                number=_parse_partition_number(device.path, path),
                path=path,
                start_sector=int(raw.get("start")),
                sector_count=int(raw.get("size")),
                partition_type=str(raw.get("type") or ""),
                filesystem=str(node.get("fstype") or ""),
                label=str(node.get("label") or ""),
                mountpoints=mountpoints,
                major_minor=str(node.get("maj:min") or ""),
            ))
        except (TypeError, ValueError) as error:
            raise PersistenceBackendSafetyError("A partition has invalid geometry") from error
    result = MediaLayout(
        partition_table, sector_size,
        tuple(sorted(partitions, key=lambda item: item.number)),
    )
    _validate_layout(result, device, media_root)
    return result


def _lookup_device(
    path: str,
    tools: PersistenceTools,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> Device | None:
    fields = "PATH,SIZE,TYPE,RM,HOTPLUG,TRAN,MODEL,VENDOR,SERIAL,WWN,MAJ:MIN,MOUNTPOINTS,RO"
    try:
        result = _completed_or_error(
            runner,
            [tools.lsblk, "--tree", "--bytes", "--json", "--output", fields, path],
        )
        devices = parse_lsblk(result.stdout, include_usb_hdds=True)
    except (PersistenceBackendError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return next((device for device in devices if device.path == path), None)


def _decode_config(payload: bytes) -> tuple[list[str], str]:
    if not payload or len(payload) > MAX_BOOT_CONFIG_BYTES or b"\x00" in payload:
        raise PersistenceBackendSafetyError("A boot configuration is empty, too large, or binary")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PersistenceBackendSafetyError("Boot configurations must be valid UTF-8") from error
    if "\r" in text.replace("\r\n", ""):
        raise PersistenceBackendSafetyError("A boot configuration has unsupported line endings")
    newline = "\r\n" if "\r\n" in text else "\n"
    if "\r\n" in text and "\n" in text.replace("\r\n", ""):
        raise PersistenceBackendSafetyError("A boot configuration mixes line endings")
    return text.splitlines(keepends=True), newline


def _line_parts(line: str) -> tuple[str, str, str]:
    ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
    body = line[:-len(ending)] if ending else line
    indentation = body[:len(body) - len(body.lstrip(" \t"))]
    return indentation, body[len(indentation):], ending


def _safe_kernel_tokens(text: str, context: str) -> list[str]:
    if any(character in text for character in ('"', "'", "\\", ";", "`")):
        raise PersistenceBackendSafetyError(f"Unsupported quoting or command syntax in {context}")
    tokens = text.split()
    if any(token.startswith("#") for token in tokens):
        raise PersistenceBackendSafetyError(f"Inline comments are unsupported in {context}")
    return tokens


def _add_token(tokens: list[str], token: str, context: str) -> tuple[list[str], bool]:
    if tokens.count(token) > 1:
        raise PersistenceBackendSafetyError(f"Duplicate {token!r} token in {context}")
    if "nopersistent" in tokens:
        raise PersistenceBackendSafetyError(f"Conflicting nopersistent token in {context}")
    if token in tokens:
        return tokens, False
    try:
        position = tokens.index("---")
    except ValueError:
        position = len(tokens)
    return tokens[:position] + [token] + tokens[position:], True


def _insert_token_preserving_line(body: str, token: str) -> str:
    separator = re.search(r"(?<!\S)---(?=\s|$)", body)
    if separator is not None:
        return body[:separator.start()] + token + " " + body[separator.start():]
    core = body.rstrip(" \t")
    trailing = body[len(core):]
    return core + " " + token + trailing


def transform_grub_config(payload: bytes, token: str = "persistent") -> BootConfigTransform:
    if token != "persistent":
        raise PersistenceBackendSafetyError("The Casper boot token must be exactly 'persistent'")
    lines, _newline = _decode_config(payload)
    output: list[str] = []
    eligible = changed = 0
    for number, line in enumerate(lines, 1):
        indentation, body, ending = _line_parts(line)
        stripped = body.strip()
        if not stripped or stripped.startswith("#"):
            output.append(line)
            continue
        first = stripped.split(None, 1)[0]
        if first not in _GRUB_COMMAND:
            if first.casefold() in _GRUB_COMMAND or (
                first.startswith("linux") and "casper" in stripped.casefold()
            ):
                raise PersistenceBackendSafetyError(
                    f"Unknown GRUB kernel command syntax on line {number}"
                )
            output.append(line)
            continue
        tokens = _safe_kernel_tokens(stripped, f"GRUB line {number}")
        if len(tokens) < 2:
            raise PersistenceBackendSafetyError(f"Incomplete GRUB kernel line {number}")
        kernel = tokens[1]
        if "/casper/" in kernel.casefold() and not re.fullmatch(
            r"(?:\([^()\s]+\))?/casper/vmlinuz(?:[A-Za-z0-9._+-]*)", kernel,
            re.IGNORECASE,
        ):
            raise PersistenceBackendSafetyError(
                f"Unknown Casper kernel path on GRUB line {number}"
            )
        if not re.fullmatch(
            r"(?:\([^()\s]+\))?/casper/vmlinuz(?:[A-Za-z0-9._+-]*)", kernel,
            re.IGNORECASE,
        ):
            output.append(line)
            continue
        eligible += 1
        _arguments, modified = _add_token(tokens[2:], token, f"GRUB line {number}")
        changed += int(modified)
        output.append(
            indentation + _insert_token_preserving_line(body, token) + ending
            if modified else line
        )
    return BootConfigTransform("".join(output).encode("utf-8"), eligible, changed)


def transform_syslinux_config(payload: bytes, token: str = "persistent") -> BootConfigTransform:
    if token != "persistent":
        raise PersistenceBackendSafetyError("The Casper boot token must be exactly 'persistent'")
    lines, _newline = _decode_config(payload)
    labels = [
        index for index, line in enumerate(lines)
        if _line_parts(line)[1].strip().split(None, 1)[0:1]
        and _line_parts(line)[1].strip().split(None, 1)[0].casefold() == "label"
    ]
    boundaries = labels + [len(lines)]
    output = list(lines)
    eligible = changed = 0
    covered: set[int] = set()
    for label_index, end in zip(labels, boundaries[1:], strict=True):
        covered.update(range(label_index, end))
        kernel_lines: list[tuple[int, list[str]]] = []
        append_lines: list[tuple[int, list[str], str, str]] = []
        for index in range(label_index + 1, end):
            indentation, body, ending = _line_parts(lines[index])
            stripped = body.strip()
            if not stripped or stripped.startswith("#"):
                continue
            first = stripped.split(None, 1)[0]
            directive = first.casefold()
            if directive in _SYSLINUX_KERNEL:
                if first not in {"kernel", "linux", "KERNEL", "LINUX"}:
                    raise PersistenceBackendSafetyError(
                        f"Unknown Syslinux kernel directive on line {index + 1}"
                    )
                kernel_lines.append((index, _safe_kernel_tokens(
                    stripped, f"Syslinux line {index + 1}",
                )))
            elif directive == "append":
                append_lines.append((
                    index,
                    _safe_kernel_tokens(stripped, f"Syslinux line {index + 1}"),
                    indentation,
                    ending,
                ))
        casper_kernels = [
            item for item in kernel_lines
            if len(item[1]) >= 2 and re.fullmatch(
                r"/casper/vmlinuz(?:[A-Za-z0-9._+-]*)", item[1][1], re.IGNORECASE,
            )
        ]
        if not casper_kernels:
            if any(
                len(item[1]) >= 2 and "/casper/" in item[1][1].casefold()
                for item in kernel_lines
            ):
                raise PersistenceBackendSafetyError("Unknown Syslinux Casper kernel path")
            continue
        if len(casper_kernels) != 1 or len(kernel_lines) != 1 or len(append_lines) != 1:
            raise PersistenceBackendSafetyError(
                "Each Casper Syslinux label must have one kernel and one APPEND line"
            )
        eligible += 1
        index, tokens, indentation, ending = append_lines[0]
        suppresses_global = tokens[1:] == ["-"]
        arguments = [] if suppresses_global else tokens[1:]
        _arguments, modified = _add_token(
            arguments, token, f"Syslinux line {index + 1}",
        )
        changed += int(modified)
        if modified:
            body = _line_parts(lines[index])[1]
            if suppresses_global:
                prefix, separator, suffix = body.rpartition("-")
                if not separator or suffix.strip():
                    raise PersistenceBackendSafetyError(
                        f"Unknown Syslinux APPEND suppression on line {index + 1}"
                    )
                body = prefix + token + suffix
            else:
                body = _insert_token_preserving_line(body, token)
            output[index] = indentation + body + ending
    for index, line in enumerate(lines):
        if index in covered:
            continue
        stripped = _line_parts(line)[1].strip()
        if not stripped or stripped.startswith("#"):
            continue
        tokens = stripped.split()
        directive = tokens[0].casefold()
        if (
            directive in _SYSLINUX_KERNEL
            and any("/casper/" in token.casefold() for token in tokens[1:])
        ) or (
            directive == "append"
            and any(token.casefold() == "boot=casper" for token in tokens[1:])
        ):
            raise PersistenceBackendSafetyError(
                f"Casper Syslinux directives outside a LABEL block on line {index + 1}"
            )
    return BootConfigTransform("".join(output).encode("utf-8"), eligible, changed)


def _root_identity(info: os.stat_result) -> RootIdentity:
    return info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns


def _file_identity(info: os.stat_result) -> FileIdentity:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _open_parent(root_fd: int, relative_path: str) -> tuple[int, str]:
    parts = PurePosixPath(relative_path).parts
    if not parts or PurePosixPath(relative_path).is_absolute() or ".." in parts:
        raise PersistenceBackendSafetyError("Unsafe media-relative path")
    current = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            following = os.open(component, _DIR_FLAGS, dir_fd=current)
            os.close(current)
            current = following
        return current, parts[-1]
    except BaseException:
        os.close(current)
        raise


def _read_file_from_root(
    root_fd: int,
    relative_path: str,
    *,
    maximum: int,
) -> tuple[bytes, os.stat_result]:
    parent_fd, name = _open_parent(root_fd, relative_path)
    try:
        descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
    except BaseException:
        os.close(parent_fd)
        raise
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PersistenceBackendSafetyError(
                f"Media file must be a single-link regular file: {relative_path}"
            )
        if info.st_size <= 0 or info.st_size > maximum:
            raise PersistenceBackendSafetyError(
                f"Media file has an unsafe size: {relative_path}"
            )
        payload = bytearray()
        while len(payload) <= maximum:
            block = os.read(descriptor, min(256 * 1024, maximum + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        if _file_identity(after) != _file_identity(info) or len(payload) != info.st_size:
            raise PersistenceBackendSafetyError(
                f"Media file changed while reading: {relative_path}"
            )
        return bytes(payload), after
    finally:
        os.close(descriptor)
        os.close(parent_fd)


def _binding(root_fd: int, relative_path: str, maximum: int) -> SourceFileBinding:
    parent_fd, name = _open_parent(root_fd, relative_path)
    try:
        descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
    except BaseException:
        os.close(parent_fd)
        raise
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > maximum
        ):
            raise PersistenceBackendSafetyError(
                f"Media evidence has an unsafe type or size: {relative_path}"
            )
        digest = ""
        if info.st_size <= MAX_EVIDENCE_HASH_BYTES:
            hasher = hashlib.sha256()
            remaining = info.st_size
            while remaining:
                block = os.read(descriptor, min(256 * 1024, remaining))
                if not block:
                    raise PersistenceBackendSafetyError(
                        f"Media evidence ended early: {relative_path}"
                    )
                hasher.update(block)
                remaining -= len(block)
            digest = hasher.hexdigest()
        after = os.fstat(descriptor)
        if _file_identity(after) != _file_identity(info):
            raise PersistenceBackendSafetyError(
                f"Media evidence changed while binding: {relative_path}"
            )
        return SourceFileBinding(relative_path, _file_identity(after), digest)
    finally:
        os.close(descriptor)
        os.close(parent_fd)


def _bind_boot_config(
    root_fd: int,
    relative_path: str,
    bootloader: str,
    profile: CasperCompatibilityProfile,
) -> BootConfigBinding | None:
    payload, info = _read_file_from_root(
        root_fd, relative_path, maximum=MAX_BOOT_CONFIG_BYTES,
    )
    transform = (
        transform_grub_config(payload, profile.boot_parameter)
        if bootloader == "grub"
        else transform_syslinux_config(payload, profile.boot_parameter)
    )
    if transform.eligible_lines == 0:
        return None
    return BootConfigBinding(
        relative_path=relative_path,
        bootloader=bootloader,
        identity=_file_identity(info),
        mode=stat.S_IMODE(info.st_mode),
        original_sha256=hashlib.sha256(payload).hexdigest(),
        transformed_sha256=hashlib.sha256(transform.contents).hexdigest(),
        original_contents=payload,
        transformed_contents=transform.contents,
        eligible_lines=transform.eligible_lines,
        changed_lines=transform.changed_lines,
    )


def _path_exists(root_fd: int, relative_path: str) -> bool:
    try:
        parent_fd, name = _open_parent(root_fd, relative_path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False
    finally:
        os.close(parent_fd)


def _validate_release_info(payload: bytes, profile: CasperCompatibilityProfile) -> None:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PersistenceBackendSafetyError(".disk/info is not valid UTF-8") from error
    release = re.escape(profile.ubuntu_release)
    if not re.search(rf"\bUbuntu\s+{release}(?:\.\d+)?\s+LTS\b", text, re.IGNORECASE):
        raise PersistenceBackendSafetyError(
            ".disk/info does not match the explicitly selected Ubuntu LTS release"
        )
    if not re.search(rf"\b{re.escape(profile.architecture)}\b", text, re.IGNORECASE):
        raise PersistenceBackendSafetyError(
            ".disk/info does not match the explicitly selected architecture"
        )


def _align_up(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


def build_casper_persistence_backend_plan(
    media_root: Path,
    device: Device,
    partition_bytes: int,
    profile: CasperCompatibilityProfile,
    *,
    finder: Callable[[str], str | None] = _trusted_which,
    device_lookup: DeviceLookup | None = None,
    layout_reader: LayoutReader | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> CasperPersistencePlan:
    """Plan persistence only in pre-reserved space; never shrink existing data."""

    _validate_profile(profile)
    if (
        not isinstance(partition_bytes, int)
        or isinstance(partition_bytes, bool)
        or partition_bytes < MIN_PERSISTENCE_BYTES
        or partition_bytes % ALIGNMENT_BYTES
    ):
        raise PersistenceBackendSafetyError(
            "Persistence size must be at least 256 MiB and aligned to 1 MiB"
        )
    try:
        validate_device(device)
    except (FormattingError, ValueError) as error:
        raise PersistenceBackendSafetyError(str(error)) from error
    tools = resolve_persistence_tools(finder)
    lookup = device_lookup or (lambda path: _lookup_device(path, tools, runner))
    current = lookup(device.path)
    if current is None or current.identity != device.identity:
        raise PersistenceBackendSafetyError("The selected removable device changed")
    try:
        validate_device(current)
    except (FormattingError, ValueError) as error:
        raise PersistenceBackendSafetyError(str(error)) from error

    raw_root = Path(media_root)
    if not raw_root.is_absolute():
        raise PersistenceBackendSafetyError("The constructed-media root must be absolute")
    raw_root = Path(os.path.normpath(raw_root))
    try:
        root_lstat = os.lstat(raw_root)
    except OSError as error:
        raise PersistenceBackendSafetyError("The constructed-media root is unavailable") from error
    if stat.S_ISLNK(root_lstat.st_mode) or not stat.S_ISDIR(root_lstat.st_mode):
        raise PersistenceBackendSafetyError("The constructed-media root must be a real directory")
    root = raw_root.resolve(strict=True)
    root_info = root.stat()
    if (root_info.st_dev, root_info.st_ino) != (root_lstat.st_dev, root_lstat.st_ino):
        raise PersistenceBackendSafetyError("The constructed-media root changed while opening")

    reader = layout_reader or (
        lambda selected, mount, resolved: read_media_layout(
            selected, mount, resolved, runner=runner,
        )
    )
    layout = reader(current, root, tools)
    _validate_layout(layout, current, root)
    if len(layout.partitions) != 1 or current.partitions != (layout.partitions[0].path,):
        raise PersistenceBackendSafetyError(
            "Persistence requires exactly one existing constructed-media partition"
        )
    first = layout.partitions[0]
    start = _align_up(first.end_sector, SECTORS_PER_MIB)
    sectors = partition_bytes // SECTOR_BYTES
    disk_sectors = current.size // SECTOR_BYTES
    table_reserve = 34 if layout.partition_table is PartitionTable.GPT else 1
    if start + sectors > disk_sectors - table_reserve:
        raise PersistenceBackendSafetyError(
            "The device has no pre-reserved contiguous tail space for persistence; "
            "ISOpropyl will not shrink the existing filesystem"
        )

    root_fd = os.open(root, _DIR_FLAGS)
    try:
        evidence_paths = [
            ".disk/info",
            "casper/vmlinuz",
            "casper/filesystem.squashfs",
            "EFI/BOOT/BOOTX64.EFI",
        ]
        initrd_candidates = ("casper/initrd", "casper/initrd.lz", "casper/initrd.gz")
        initrd = next((path for path in initrd_candidates if _path_exists(root_fd, path)), None)
        if initrd is None:
            raise PersistenceBackendSafetyError("The media has no recognized Casper initrd")
        evidence_paths.append(initrd)
        evidence: list[SourceFileBinding] = []
        for relative_path in evidence_paths:
            maximum = 4 * MIB if relative_path == ".disk/info" else current.size
            evidence.append(_binding(root_fd, relative_path, maximum))
        info_payload, _info = _read_file_from_root(
            root_fd, ".disk/info", maximum=4 * MIB,
        )
        _validate_release_info(info_payload, profile)

        configs: list[BootConfigBinding] = []
        for bootloader, paths in (
            ("grub", _GRUB_CONFIG_PATHS),
            ("syslinux", _SYSLINUX_CONFIG_PATHS),
        ):
            for relative_path in paths:
                if not _path_exists(root_fd, relative_path):
                    continue
                binding = _bind_boot_config(root_fd, relative_path, bootloader, profile)
                if binding is not None:
                    configs.append(binding)
        if not configs or sum(item.eligible_lines for item in configs) <= 0:
            raise PersistenceBackendSafetyError(
                "No recognized Casper GRUB or Syslinux kernel command lines were found"
            )
    except OSError as error:
        raise PersistenceBackendSafetyError("Could not safely inspect constructed media") from error
    finally:
        os.close(root_fd)

    configs.sort(key=lambda item: unicodedata.normalize("NFC", item.relative_path).casefold())
    return CasperPersistencePlan(
        profile=profile,
        media_root=root,
        media_root_identity=_root_identity(root_info),
        device=current,
        layout=layout,
        evidence=tuple(evidence),
        boot_configs=tuple(configs),
        partition_bytes=partition_bytes,
        partition_start_sector=start,
        partition_sector_count=sectors,
        partition_path=_partition_path(current.path, 2),
        tools=tools,
    )


def validate_casper_persistence_backend_plan(plan: CasperPersistencePlan) -> None:
    if not isinstance(plan, CasperPersistencePlan):
        raise PersistenceBackendSafetyError("A CasperPersistencePlan is required")
    _validate_profile(plan.profile)
    _validate_tools(plan.tools)
    try:
        validate_device(plan.device)
    except (FormattingError, ValueError) as error:
        raise PersistenceBackendSafetyError(str(error)) from error
    if not plan.media_root.is_absolute() or plan.media_root != Path(os.path.normpath(plan.media_root)):
        raise PersistenceBackendSafetyError("The plan contains an unsafe media root")
    if (
        len(plan.media_root_identity) != 4
        or any(
            not isinstance(value, int) or value < 0
            for value in plan.media_root_identity
        )
    ):
        raise PersistenceBackendSafetyError("The plan contains an invalid media-root identity")
    _validate_layout(plan.layout, plan.device, plan.media_root)
    if len(plan.layout.partitions) != 1:
        raise PersistenceBackendSafetyError("The plan is not bound to a one-partition layout")
    first = plan.layout.partitions[0]
    expected_start = _align_up(first.end_sector, SECTORS_PER_MIB)
    if (
        plan.partition_bytes < MIN_PERSISTENCE_BYTES
        or plan.partition_bytes % ALIGNMENT_BYTES
        or plan.partition_sector_count != plan.partition_bytes // SECTOR_BYTES
        or plan.partition_start_sector != expected_start
        or plan.partition_path != _partition_path(plan.device.path, 2)
    ):
        raise PersistenceBackendSafetyError("The plan contains invalid persistence geometry")
    reserve = 34 if plan.layout.partition_table is PartitionTable.GPT else 1
    if plan.partition_start_sector + plan.partition_sector_count > (
        plan.device.size // SECTOR_BYTES - reserve
    ):
        raise PersistenceBackendSafetyError("The planned persistence partition does not fit")
    if not plan.evidence or not plan.boot_configs:
        raise PersistenceBackendSafetyError("The plan has no bound media evidence or boot config")
    if any(not isinstance(item, SourceFileBinding) for item in plan.evidence):
        raise PersistenceBackendSafetyError("The plan contains an invalid evidence binding")
    evidence_paths = tuple(item.relative_path for item in plan.evidence)
    required_evidence = {
        ".disk/info",
        "casper/vmlinuz",
        "casper/filesystem.squashfs",
        "EFI/BOOT/BOOTX64.EFI",
    }
    if (
        not required_evidence.issubset(evidence_paths)
        or sum(path in {"casper/initrd", "casper/initrd.lz", "casper/initrd.gz"}
               for path in evidence_paths) != 1
        or len(evidence_paths) != len(set(evidence_paths))
    ):
        raise PersistenceBackendSafetyError("The plan has incomplete Casper media evidence")
    for binding in plan.evidence:
        if (
            not isinstance(binding, SourceFileBinding)
            or len(binding.identity) != 5
            or any(not isinstance(value, int) or value < 0 for value in binding.identity)
            or (
                binding.sha256
                and not re.fullmatch(r"[0-9a-f]{64}", binding.sha256)
            )
        ):
            raise PersistenceBackendSafetyError("The plan contains an invalid evidence binding")
    known_paths = set(_GRUB_CONFIG_PATHS) | set(_SYSLINUX_CONFIG_PATHS)
    previous = ""
    for binding in plan.boot_configs:
        if not isinstance(binding, BootConfigBinding) or (
            len(binding.identity) != 5
            or any(not isinstance(value, int) or value < 0 for value in binding.identity)
            or binding.eligible_lines <= 0
            or binding.changed_lines < 0
            or binding.changed_lines > binding.eligible_lines
        ):
            raise PersistenceBackendSafetyError("The plan contains an invalid boot binding")
        if binding.relative_path not in known_paths:
            raise PersistenceBackendSafetyError("The plan contains an unknown boot-config path")
        if binding.relative_path.casefold() <= previous:
            raise PersistenceBackendSafetyError("Boot configurations are not canonically ordered")
        previous = binding.relative_path.casefold()
        transform = (
            transform_grub_config(binding.original_contents, plan.profile.boot_parameter)
            if binding.bootloader == "grub"
            else transform_syslinux_config(binding.original_contents, plan.profile.boot_parameter)
            if binding.bootloader == "syslinux"
            else None
        )
        if transform is None or (
            transform.contents != binding.transformed_contents
            or transform.eligible_lines != binding.eligible_lines
            or transform.changed_lines != binding.changed_lines
            or hashlib.sha256(binding.original_contents).hexdigest()
            != binding.original_sha256
            or hashlib.sha256(binding.transformed_contents).hexdigest()
            != binding.transformed_sha256
        ):
            raise PersistenceBackendSafetyError("A boot-config transformation binding is invalid")


def persistence_partition_script(plan: CasperPersistencePlan) -> bytes:
    validate_casper_persistence_backend_plan(plan)
    partition_type = (
        LINUX_FILESYSTEM_GUID
        if plan.layout.partition_table is PartitionTable.GPT
        else "83"
    )
    name = ', name="ISOpropyl persistence"' if plan.layout.partition_table is PartitionTable.GPT else ""
    return (
        f"start={plan.partition_start_sector}, size={plan.partition_sector_count}, "
        f"type={partition_type}{name}\n"
    ).encode("ascii")


def persistence_partition_command(plan: CasperPersistencePlan) -> list[str]:
    validate_casper_persistence_backend_plan(plan)
    return add_native_sfdisk_lock([
        plan.tools.pkexec,
        plan.tools.sfdisk,
        "--no-reread",
        "--append",
        plan.device.path,
    ], plan.tools.sfdisk)


def persistence_format_command(plan: CasperPersistencePlan) -> list[str]:
    validate_casper_persistence_backend_plan(plan)
    return cooperative_lock_command(
        plan.tools.pkexec,
        plan.tools.flock,
        plan.device.path,
        [
            plan.tools.mkfs_ext4,
            "-F",
            "-L",
            plan.profile.partition_label,
            plan.partition_path,
        ],
    )


def _geometry_matches(
    partition: PartitionLayout,
    plan: CasperPersistencePlan,
    *,
    formatted: bool,
) -> bool:
    expected_type = (
        LINUX_FILESYSTEM_GUID
        if plan.layout.partition_table is PartitionTable.GPT
        else "83"
    )
    if (
        partition.number != 2
        or partition.path != plan.partition_path
        or partition.start_sector != plan.partition_start_sector
        or partition.sector_count != plan.partition_sector_count
        or _normal_type(partition.partition_type) != _normal_type(expected_type)
        or partition.mountpoints
        or not _MAJOR_MINOR.fullmatch(partition.major_minor)
    ):
        return False
    if formatted:
        return (
            partition.filesystem.casefold() == "ext4"
            and partition.label == plan.profile.partition_label
        )
    return not partition.filesystem and not partition.label


class CasperPersistenceExecutor:
    def __init__(
        self,
        *,
        device_lookup: DeviceLookup | None = None,
        layout_reader: LayoutReader | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        block_stat: Callable[[str], os.stat_result] = os.stat,
    ) -> None:
        self._device_lookup = device_lookup
        self._layout_reader = layout_reader
        self._runner = runner
        self._popen = popen
        self._block_stat = block_stat
        self._cancelled = threading.Event()
        self._process: subprocess.Popen[bytes] | None = None
        self._lock = threading.Lock()
        self._used = False

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        self._cancelled.set()
        with self._lock:
            process = self._process
        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                # The execution thread owns bounded escalation and reaping.
                # Cancellation callers must never be stranded with a signal
                # delivery race from an already-exiting child.
                pass

    def _check_cancelled(self) -> None:
        if self.cancelled:
            raise PersistenceBackendCancelled("Persistence creation was cancelled")

    def _lookup(self, plan: CasperPersistencePlan) -> Device | None:
        if self._device_lookup is not None:
            return self._device_lookup(plan.device.path)
        return _lookup_device(plan.device.path, plan.tools, self._runner)

    def _read_layout(self, plan: CasperPersistencePlan, current: Device) -> MediaLayout:
        if self._layout_reader is not None:
            result = self._layout_reader(current, plan.media_root, plan.tools)
        else:
            result = read_media_layout(
                current, plan.media_root, plan.tools, runner=self._runner,
            )
        _validate_layout(result, current, plan.media_root)
        return result

    def _assert_device(self, plan: CasperPersistencePlan) -> Device:
        self._check_cancelled()
        current = self._lookup(plan)
        if current is None or current.identity != plan.device.identity:
            raise PersistenceBackendSafetyError("The selected device changed or disconnected")
        try:
            validate_device(current)
        except (FormattingError, ValueError) as error:
            raise PersistenceBackendSafetyError(str(error)) from error
        return current

    def _assert_media_root(self, plan: CasperPersistencePlan) -> int:
        try:
            initial = os.lstat(plan.media_root)
        except OSError as error:
            raise PersistenceBackendSafetyError("The constructed-media root disappeared") from error
        if stat.S_ISLNK(initial.st_mode) or not stat.S_ISDIR(initial.st_mode):
            raise PersistenceBackendSafetyError("The constructed-media root changed type")
        root_fd = os.open(plan.media_root, _DIR_FLAGS)
        opened = os.fstat(root_fd)
        if _root_identity(opened) != plan.media_root_identity:
            os.close(root_fd)
            raise PersistenceBackendSafetyError("The constructed-media root changed")
        return root_fd

    def _assert_binding(self, root_fd: int, binding: SourceFileBinding) -> None:
        try:
            current = _binding(
                root_fd, binding.relative_path, maximum=max(binding.identity[2], 1),
            )
        except (OSError, PersistenceBackendSafetyError) as error:
            raise PersistenceBackendSafetyError(
                f"Bound media file changed: {binding.relative_path}"
            ) from error
        if current != binding:
            raise PersistenceBackendSafetyError(
                f"Bound media file changed: {binding.relative_path}"
            )

    def _assert_boot_binding(self, root_fd: int, binding: BootConfigBinding) -> None:
        payload, info = _read_file_from_root(
            root_fd, binding.relative_path, maximum=MAX_BOOT_CONFIG_BYTES,
        )
        if (
            _file_identity(info) != binding.identity
            or hashlib.sha256(payload).hexdigest() != binding.original_sha256
            or payload != binding.original_contents
        ):
            raise PersistenceBackendSafetyError(
                f"Boot configuration changed: {binding.relative_path}"
            )

    def _assert_activated_boot_binding(
        self,
        root_fd: int,
        binding: BootConfigBinding,
    ) -> None:
        payload, info = _read_file_from_root(
            root_fd, binding.relative_path, maximum=MAX_BOOT_CONFIG_BYTES,
        )
        if (
            payload != binding.transformed_contents
            or hashlib.sha256(payload).hexdigest() != binding.transformed_sha256
            or (
                binding.changed_lines == 0
                and _file_identity(info) != binding.identity
            )
        ):
            raise PersistenceBackendSafetyError(
                f"Activated boot configuration could not be verified: {binding.relative_path}"
            )

    def _assert_persistence_partition(
        self,
        plan: CasperPersistencePlan,
        *,
        formatted: bool,
    ) -> MediaLayout:
        current = self._assert_device(plan)
        layout = self._read_layout(plan, current)
        if (
            len(layout.partitions) != 2
            or layout.partitions[0] != plan.layout.partitions[0]
            or not _geometry_matches(layout.partitions[1], plan, formatted=formatted)
        ):
            detail = (
                "The persistence filesystem identity could not be verified"
                if formatted
                else "The new partition does not match the frozen geometry"
            )
            raise PersistenceBackendSafetyError(detail)
        try:
            block_info = self._block_stat(plan.partition_path)
        except OSError as error:
            raise PersistenceBackendSafetyError(
                "The new partition node is unavailable"
            ) from error
        if not stat.S_ISBLK(block_info.st_mode):
            raise PersistenceBackendSafetyError(
                "The new persistence target is not a block device"
            )
        major_minor = layout.partitions[1].major_minor
        expected_rdev = os.makedev(*(int(value) for value in major_minor.split(":")))
        if block_info.st_rdev != expected_rdev:
            raise PersistenceBackendSafetyError(
                "The new partition node identity changed"
            )
        return layout

    @staticmethod
    def _terminate_and_reap(
        process: subprocess.Popen[bytes],
    ) -> tuple[bytes, bytes]:
        if process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass
        try:
            return process.communicate(timeout=COMMAND_TERMINATE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                return process.communicate(timeout=COMMAND_KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired as error:
                raise PersistenceBackendError(
                    "A persistence command could not be stopped and reaped"
                ) from error

    def _run_process(
        self,
        argv: Sequence[str],
        input_data: bytes | None = None,
        *,
        cleanup: bool = False,
    ) -> None:
        if not cleanup:
            self._check_cancelled()
        process = self._popen(
            list(argv),
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        with self._lock:
            self._process = process
        first = True
        deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
        try:
            while True:
                try:
                    stdout, stderr = process.communicate(
                        input=input_data if first else None, timeout=0.2,
                    )
                    break
                except subprocess.TimeoutExpired:
                    first = False
                    if (self.cancelled and not cleanup) or time.monotonic() >= deadline:
                        stdout, stderr = self._terminate_and_reap(process)
                        if self.cancelled and not cleanup:
                            raise PersistenceBackendCancelled(
                                "Persistence creation was cancelled"
                            )
                        raise PersistenceBackendError("A persistence command timed out")
            if len(stdout) > MAX_COMMAND_OUTPUT or len(stderr) > MAX_COMMAND_OUTPUT:
                raise PersistenceBackendError("A persistence command produced too much output")
            if self.cancelled and not cleanup:
                raise PersistenceBackendCancelled("Persistence creation was cancelled")
            if process.returncode:
                detail = stderr.decode("utf-8", errors="replace").strip()
                fallback = (
                    detail[-2048:]
                    or f"Persistence command failed: {argv[-1]}"
                )
                if is_cooperative_lock_command(argv):
                    fallback = lock_conflict_message(process.returncode, fallback)
                raise PersistenceBackendError(
                    fallback
                )
        finally:
            with self._lock:
                if self._process is process:
                    self._process = None
        if not cleanup:
            self._check_cancelled()

    def _atomic_replace(
        self,
        root_fd: int,
        binding: BootConfigBinding,
        payload: bytes,
        expected_sha256: str,
        expected_identity: FileIdentity | None = None,
    ) -> None:
        parent_fd, name = _open_parent(root_fd, binding.relative_path)
        temporary = f".{name}.isopropyl-{secrets.token_hex(8)}.tmp"
        descriptor: int | None = None
        try:
            current_fd = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
            try:
                current = os.fstat(current_fd)
                current_payload_buffer = bytearray()
                while len(current_payload_buffer) <= MAX_BOOT_CONFIG_BYTES:
                    block = os.read(
                        current_fd,
                        min(
                            256 * 1024,
                            MAX_BOOT_CONFIG_BYTES + 1 - len(current_payload_buffer),
                        ),
                    )
                    if not block:
                        break
                    current_payload_buffer.extend(block)
                current_after = os.fstat(current_fd)
            finally:
                os.close(current_fd)
            current_payload = bytes(current_payload_buffer)
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or _file_identity(current_after) != _file_identity(current)
                or (
                    expected_identity is not None
                    and _file_identity(current) != expected_identity
                )
                or hashlib.sha256(current_payload).hexdigest() != expected_sha256
            ):
                raise PersistenceBackendSafetyError(
                    f"Boot configuration changed before replacement: {binding.relative_path}"
                )
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
            written = 0
            while written < len(payload):
                block = os.write(descriptor, payload[written:])
                if block <= 0:
                    raise PersistenceBackendError("Could not write a boot-config replacement")
                written += block
            os.fchmod(descriptor, binding.mode)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            os.close(parent_fd)

    def _rollback_configs(
        self,
        root_fd: int,
        bindings: Sequence[BootConfigBinding],
    ) -> list[str]:
        errors: list[str] = []
        for binding in reversed(bindings):
            try:
                parent_fd, name = _open_parent(root_fd, binding.relative_path)
                try:
                    descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
                    try:
                        info = os.fstat(descriptor)
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                            raise PersistenceBackendSafetyError(
                                "boot configuration changed type during rollback"
                            )
                        payload = bytearray()
                        while len(payload) <= MAX_BOOT_CONFIG_BYTES:
                            block = os.read(
                                descriptor,
                                min(256 * 1024, MAX_BOOT_CONFIG_BYTES + 1 - len(payload)),
                            )
                            if not block:
                                break
                            payload.extend(block)
                    finally:
                        os.close(descriptor)
                finally:
                    os.close(parent_fd)
                digest = hashlib.sha256(payload).hexdigest()
                if digest == binding.original_sha256:
                    continue
                if digest != binding.transformed_sha256:
                    raise PersistenceBackendSafetyError(
                        "boot configuration changed during rollback"
                    )
                self._atomic_replace(
                    root_fd,
                    binding,
                    binding.original_contents,
                    binding.transformed_sha256,
                )
            except Exception as error:  # best-effort recovery, retained for the final diagnostic
                errors.append(f"{binding.relative_path}: {error}")
        return errors

    def _cleanup_partition(self, plan: CasperPersistencePlan) -> list[str]:
        errors: list[str] = []
        try:
            current = self._lookup(plan)
            if current is None or current.identity != plan.device.identity:
                return ["device changed before persistence-partition cleanup"]
            layout = self._read_layout(plan, current)
            if layout == plan.layout:
                return []
            if (
                len(layout.partitions) != 2
                or layout.partitions[0] != plan.layout.partitions[0]
                or not _geometry_matches(layout.partitions[1], plan, formatted=bool(
                    layout.partitions[1].filesystem
                ))
            ):
                return ["partition layout changed; refusing to guess a cleanup target"]
            self._run_process(add_native_sfdisk_lock(
                [
                    plan.tools.pkexec,
                    plan.tools.sfdisk,
                    "--no-reread",
                    "--delete",
                    plan.device.path,
                    "2",
                ],
                plan.tools.sfdisk,
            ), cleanup=True)
            self._run_process(
                [plan.tools.pkexec, plan.tools.partprobe, plan.device.path], cleanup=True,
            )
            self._run_process([plan.tools.udevadm, "settle"], cleanup=True)
            current = self._lookup(plan)
            if current is None or self._read_layout(plan, current) != plan.layout:
                errors.append("persistence partition cleanup could not be verified")
        except Exception as error:
            errors.append(str(error))
        return errors

    def execute(
        self,
        plan: CasperPersistencePlan,
        progress: Progress = lambda _update: None,
    ) -> PersistenceExecutionResult:
        if self._used:
            raise PersistenceBackendSafetyError(
                "A Casper persistence executor can only be used once"
            )
        self._used = True
        validate_casper_persistence_backend_plan(plan)
        self._check_cancelled()
        root_fd = self._assert_media_root(plan)
        partition_attempted = False
        activated = False
        updated: list[BootConfigBinding] = []
        touched: list[BootConfigBinding] = []
        total_steps = 5 + sum(item.changed_lines > 0 for item in plan.boot_configs)
        try:
            current = self._assert_device(plan)
            if self._read_layout(plan, current) != plan.layout:
                raise PersistenceBackendSafetyError("The partition layout changed after planning")
            for binding in plan.evidence:
                self._assert_binding(root_fd, binding)
            for binding in plan.boot_configs:
                self._assert_boot_binding(root_fd, binding)

            progress(PersistenceExecutionProgress("Creating persistence partition", 1, total_steps))
            partition_attempted = True
            self._run_process(
                persistence_partition_command(plan), persistence_partition_script(plan),
            )
            self._run_process([plan.tools.pkexec, plan.tools.partprobe, plan.device.path])
            self._run_process([plan.tools.udevadm, "settle"])

            progress(PersistenceExecutionProgress("Verifying partition geometry", 2, total_steps))
            self._assert_persistence_partition(plan, formatted=False)

            progress(PersistenceExecutionProgress("Creating ext4 persistence filesystem", 3, total_steps))
            # The callback above is outside our trust boundary. Rebind both the
            # exact geometry and kernel block-node identity immediately before
            # the destructive formatter is launched.
            self._assert_persistence_partition(plan, formatted=False)
            self._run_process(persistence_format_command(plan))
            self._run_process([plan.tools.udevadm, "settle"])
            self._assert_persistence_partition(plan, formatted=True)

            progress(PersistenceExecutionProgress("Revalidating boot media", 4, total_steps))
            for binding in plan.evidence:
                self._assert_binding(root_fd, binding)
            for binding in plan.boot_configs:
                self._assert_boot_binding(root_fd, binding)

            step = 4
            for binding in plan.boot_configs:
                if binding.changed_lines == 0:
                    continue
                self._check_cancelled()
                step += 1
                progress(PersistenceExecutionProgress(
                    f"Updating {binding.bootloader.upper()} boot configuration",
                    step,
                    total_steps,
                ))
                self._check_cancelled()
                self._assert_persistence_partition(plan, formatted=True)
                touched.append(binding)
                self._atomic_replace(
                    root_fd,
                    binding,
                    binding.transformed_contents,
                    binding.original_sha256,
                    binding.identity,
                )
                updated.append(binding)

            # Activation remains rollbackable until every target and media
            # binding has been rechecked after the final replacement. In
            # particular, a cancellation or device swap racing the last config
            # write must not be mistaken for a successful commit.
            self._check_cancelled()
            self._assert_persistence_partition(plan, formatted=True)
            for binding in plan.evidence:
                self._assert_binding(root_fd, binding)
            for binding in plan.boot_configs:
                self._assert_activated_boot_binding(root_fd, binding)
            self._check_cancelled()
            self._assert_persistence_partition(plan, formatted=True)
            self._check_cancelled()
            activated = True
            result = PersistenceExecutionResult(
                device_identity=plan.device.identity,
                partition_path=plan.partition_path,
                partition_bytes=plan.partition_bytes,
                partition_label=plan.profile.partition_label,
                boot_configs_updated=tuple(item.relative_path for item in updated),
                persistence_token=plan.profile.boot_parameter,
            )
            try:
                progress(PersistenceExecutionProgress("Complete", total_steps, total_steps))
            except Exception:
                pass
            return result
        except PersistenceBackendCancelled:
            raise
        except OSError as error:
            raise PersistenceBackendError(
                "A filesystem operation failed while enabling persistence"
            ) from error
        finally:
            cleanup_errors: list[str] = []
            if not activated:
                rollback_errors = self._rollback_configs(root_fd, touched)
                cleanup_errors.extend(rollback_errors)
                if partition_attempted and not rollback_errors:
                    cleanup_errors.extend(self._cleanup_partition(plan))
                elif partition_attempted:
                    cleanup_errors.append(
                        "persistence partition retained because boot-config rollback was incomplete"
                    )
            os.close(root_fd)
            if cleanup_errors:
                # Raising from finally intentionally supersedes the first error:
                # callers must know that automatic recovery was incomplete.
                raise PersistenceBackendError(
                    "Persistence failed and cleanup was incomplete: "
                    + "; ".join(cleanup_errors)
                )
