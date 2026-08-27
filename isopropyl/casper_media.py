from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Immutable, up-front Ubuntu Casper persistence media construction.

This module intentionally does not append a partition to completed media.  It
first transforms boot configuration inside a caller-owned unpublished staging
tree, then creates and formats the complete FAT32 + ext4 layout before any
staged file is copied to the target.
"""

import hashlib
import json
import math
import os
import re
import secrets
import shutil
import stat
import subprocess
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .constructed import (
    ConstructedMediaCancelled,
    ConstructedMediaError,
    ConstructedMediaExecutor,
    ConstructedMediaPlan,
    ConstructedMediaResult,
    ConstructedMediaSafetyError,
    ConstructedProgress,
    build_constructed_media_plan,
    validate_constructed_media_plan,
)
from .devices import Device, parse_lsblk, path_is_on_device
from .formatting import (
    DeviceChangedError,
    Filesystem,
    FormatCancelled,
    FormattingError,
    MultiFormatExecutor,
    MultiFormatPlan,
    MultiFormatTools,
    PartitionRole,
    PartitionSpec,
    PartitionTable,
    create_multi_format_plan,
    multi_format_commands,
    multi_partition_command,
    multi_partition_script,
    parse_logical_sector_size,
    resolve_multi_tools,
    validate_device,
    validate_explicit_partition_metadata,
    validate_multi_plan,
)
from .images import ImageInspection
from .persistence import (
    ALIGNMENT_BYTES,
    MAX_BOOT_CONFIG_BYTES,
    MIN_PERSISTENCE_BYTES,
    BootConfigBinding,
    CasperCompatibilityProfile,
    PersistenceBackendSafetyError,
    SourceFileBinding,
    _DIR_FLAGS,
    _GRUB_CONFIG_PATHS,
    _READ_FLAGS,
    _SYSLINUX_CONFIG_PATHS,
    _bind_boot_config,
    _binding,
    _file_identity,
    _open_parent,
    _path_exists,
    _read_file_from_root,
    _root_identity,
    _validate_release_info,
    transform_grub_config,
    transform_syslinux_config,
    ubuntu_casper_profile,
)


_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_TRUSTED_DIRECTORIES = frozenset(_TRUSTED_TOOL_PATH.split(":"))
_BLOCK_PATH = re.compile(r"/dev/[A-Za-z0-9._+:-]+")
_MAJOR_MINOR = re.compile(r"\d+:\d+")
_MAX_ERROR = 2048
_MAX_EVIDENCE_FILE_BYTES = (1 << 63) - 1
_GPT_ENTRY_ARRAY_BYTES = 128 * 128
_SUPPORTED_SECTOR_SIZES = frozenset((512, 4096))
_PARTITION_LABEL = "writable"
_DATA_LABEL = "ISOPROPYL"


class CasperMediaError(RuntimeError):
    pass


class CasperMediaUnavailable(CasperMediaError):
    pass


class CasperMediaSafetyError(CasperMediaError):
    pass


class CasperMediaCancelled(CasperMediaError):
    pass


FileIdentity = tuple[int, int, int, int, int]
RootIdentity = tuple[int, int, int, int]
PublishedRootIdentity = tuple[int, int]
Progress = Callable[["CasperMediaProgress"], None]
DeviceLister = Callable[[], Sequence[Device]]
RunCommand = Callable[..., subprocess.CompletedProcess[str]]
StagingReplacer = Callable[[int, BootConfigBinding, bytes, str, FileIdentity], None]


@dataclass(frozen=True)
class CasperStagingPlan:
    root: Path
    root_identity: RootIdentity
    profile: CasperCompatibilityProfile
    evidence: tuple[SourceFileBinding, ...]
    boot_configs: tuple[BootConfigBinding, ...]


@dataclass(frozen=True)
class StagedBootConfig:
    relative_path: str
    bootloader: str
    identity: FileIdentity
    mode: int
    sha256: str
    eligible_lines: int


@dataclass(frozen=True)
class CasperStagingResult:
    # Rename publication legitimately changes a directory's ctime.  Device and
    # inode remain stable across that commit and are rebound to full source-file
    # identities and hashes before media planning.
    root_identity: PublishedRootIdentity
    profile: CasperCompatibilityProfile
    evidence: tuple[SourceFileBinding, ...]
    boot_configs: tuple[StagedBootConfig, ...]


@dataclass(frozen=True)
class CasperMediaTools:
    pkexec: str
    sfdisk: str
    lsblk: str
    udisksctl: str


@dataclass(frozen=True)
class CasperMediaPlan:
    device: Device
    profile: CasperCompatibilityProfile
    staging: CasperStagingResult
    layout: MultiFormatPlan
    content: ConstructedMediaPlan
    persistence_bytes: int
    data_capacity: int
    tools: CasperMediaTools


@dataclass(frozen=True)
class CasperMediaProgress:
    stage: str
    relative_path: str = ""
    bytes_done: int = 0
    total_bytes: int = 0

    @property
    def fraction(self) -> float:
        if self.total_bytes <= 0:
            return 1.0 if self.stage == "Complete" else 0.0
        return min(1.0, max(0.0, self.bytes_done / self.total_bytes))


@dataclass(frozen=True)
class CasperMediaResult:
    device_identity: tuple[str, int, str, str, str, str]
    data_partition: str
    persistence_partition: str
    persistence_bytes: int
    persistence_label: str
    content: ConstructedMediaResult
    powered_off: bool


def _bounded(value: object, fallback: str) -> str:
    rendered = str(value or "").strip()
    return rendered[-_MAX_ERROR:] if rendered else fallback


def _canonical_profile(profile: CasperCompatibilityProfile) -> CasperCompatibilityProfile:
    if not isinstance(profile, CasperCompatibilityProfile):
        raise CasperMediaSafetyError("A Casper compatibility profile is required")
    try:
        expected = ubuntu_casper_profile(profile.ubuntu_release, profile.architecture)
    except PersistenceBackendSafetyError as error:
        raise CasperMediaSafetyError(str(error)) from error
    if profile != expected or (
        profile.profile_id != "ubuntu-casper-writable-v1"
        or profile.architecture != "amd64"
        or profile.filesystem != "ext4"
        or profile.partition_label != _PARTITION_LABEL
        or profile.boot_parameter != "persistent"
        or profile.configuration_path
        or profile.configuration_contents
    ):
        raise CasperMediaSafetyError("The Casper compatibility profile was modified")
    return expected


def supported_casper_profile(
    inspection: ImageInspection,
) -> CasperCompatibilityProfile | None:
    """Return a narrow UI candidate; private staging performs final validation."""
    if (
        not isinstance(inspection, ImageInspection)
        or not inspection.is_iso9660
        or not inspection.contents_scanned
        or inspection.has_windows_installer
        or "x64" not in inspection.architectures
    ):
        return None
    paths = {
        member.path.replace("\\", "/").casefold().lstrip("/")
        for member in inspection.members
        if member.kind == "file" and member.size > 0
    }
    required = {
        ".disk/info",
        "casper/vmlinuz",
        "casper/filesystem.squashfs",
        "efi/boot/bootx64.efi",
    }
    initrds = paths & {
        "casper/initrd", "casper/initrd.lz", "casper/initrd.gz",
    }
    grub_configs = paths & {
        path.casefold() for path in _GRUB_CONFIG_PATHS
    }
    if (
        not required.issubset(paths)
        or len(initrds) != 1
        or not grub_configs
    ):
        return None
    match = re.search(
        r"\bubuntu\b.*?\b(20\.04|22\.04|24\.04)(?:\.\d+)?\b.*?\b(?:amd64|x86_64)\b",
        inspection.volume_label,
        re.IGNORECASE,
    )
    if match is None:
        return None
    try:
        return ubuntu_casper_profile(match.group(1), "amd64")
    except PersistenceBackendSafetyError:
        return None


def _normalized_root(root: Path | str) -> tuple[Path, os.stat_result]:
    candidate = Path(root)
    if not candidate.is_absolute():
        raise CasperMediaSafetyError("The private staging root must be absolute")
    candidate = Path(os.path.normpath(candidate))
    try:
        before = os.lstat(candidate)
    except OSError as error:
        raise CasperMediaSafetyError("The private staging root is unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise CasperMediaSafetyError("The private staging root must be a real directory")
    try:
        root_fd = os.open(candidate, _DIR_FLAGS)
    except OSError as error:
        raise CasperMediaSafetyError("Could not safely open the private staging root") from error
    try:
        opened = os.fstat(root_fd)
    finally:
        os.close(root_fd)
    if _root_identity(opened) != _root_identity(before):
        raise CasperMediaSafetyError("The private staging root changed while opening")
    return candidate, opened


def _evidence_and_configs(
    root_fd: int,
    profile: CasperCompatibilityProfile,
) -> tuple[tuple[SourceFileBinding, ...], tuple[BootConfigBinding, ...]]:
    initrds = tuple(
        path for path in ("casper/initrd", "casper/initrd.lz", "casper/initrd.gz")
        if _path_exists(root_fd, path)
    )
    if len(initrds) != 1:
        raise CasperMediaSafetyError(
            "The staging tree must contain exactly one recognized Casper initrd"
        )
    evidence_paths = (
        ".disk/info",
        "casper/vmlinuz",
        "casper/filesystem.squashfs",
        "EFI/BOOT/BOOTX64.EFI",
        initrds[0],
    )
    try:
        evidence = tuple(
            _binding(root_fd, path, _MAX_EVIDENCE_FILE_BYTES)
            for path in evidence_paths
        )
        info, _ = _read_file_from_root(root_fd, ".disk/info", maximum=4 * 1024 * 1024)
        _validate_release_info(info, profile)
    except (OSError, PersistenceBackendSafetyError) as error:
        raise CasperMediaSafetyError(str(error)) from error

    configs: list[BootConfigBinding] = []
    try:
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
    except (OSError, PersistenceBackendSafetyError) as error:
        raise CasperMediaSafetyError(str(error)) from error
    configs.sort(key=lambda item: item.relative_path.casefold())
    if not configs or sum(item.eligible_lines for item in configs) <= 0:
        raise CasperMediaSafetyError(
            "No recognized Casper GRUB or Syslinux kernel command lines were found"
        )
    if sum(
        item.eligible_lines for item in configs if item.bootloader == "grub"
    ) <= 0:
        raise CasperMediaSafetyError(
            "UEFI-only persistence requires a recognized GRUB kernel command line"
        )
    return evidence, tuple(configs)


def build_casper_staging_plan(
    private_root: Path | str,
    profile: CasperCompatibilityProfile,
) -> CasperStagingPlan:
    """Bind an extracted, unpublished tree before changing any boot config."""

    canonical = _canonical_profile(profile)
    root, root_info = _normalized_root(private_root)
    root_fd = os.open(root, _DIR_FLAGS)
    try:
        evidence, configs = _evidence_and_configs(root_fd, canonical)
    finally:
        os.close(root_fd)
    return CasperStagingPlan(
        root, _root_identity(root_info), canonical, evidence, configs,
    )


def validate_casper_staging_plan(plan: CasperStagingPlan) -> None:
    if not isinstance(plan, CasperStagingPlan):
        raise CasperMediaSafetyError("A CasperStagingPlan is required")
    canonical = _canonical_profile(plan.profile)
    rebuilt = build_casper_staging_plan(plan.root, canonical)
    if rebuilt != plan:
        raise CasperMediaSafetyError("The private Casper staging tree changed after planning")


def _atomic_replace_config(
    root_fd: int,
    binding: BootConfigBinding,
    payload: bytes,
    expected_sha256: str,
    expected_identity: FileIdentity,
) -> None:
    parent_fd, name = _open_parent(root_fd, binding.relative_path)
    temporary = f".{name}.isopropyl-{secrets.token_hex(8)}.tmp"
    descriptor = -1
    try:
        current_fd = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
        try:
            before = os.fstat(current_fd)
            current = bytearray()
            while len(current) <= MAX_BOOT_CONFIG_BYTES:
                block = os.read(
                    current_fd,
                    min(256 * 1024, MAX_BOOT_CONFIG_BYTES + 1 - len(current)),
                )
                if not block:
                    break
                current.extend(block)
            after = os.fstat(current_fd)
        finally:
            os.close(current_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _file_identity(before) != expected_identity
            or _file_identity(after) != expected_identity
            or hashlib.sha256(current).hexdigest() != expected_sha256
        ):
            raise CasperMediaSafetyError(
                f"Boot configuration changed before transformation: {binding.relative_path}"
            )
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise CasperMediaError("A boot-config transformation made no write progress")
            offset += written
        os.fchmod(descriptor, binding.mode)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as error:
        raise CasperMediaError(
            _bounded(error, f"Could not transform {binding.relative_path}")
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def _post_transform_config(
    root_fd: int,
    binding: BootConfigBinding,
) -> StagedBootConfig:
    try:
        payload, info = _read_file_from_root(
            root_fd, binding.relative_path, maximum=MAX_BOOT_CONFIG_BYTES,
        )
        transform = (
            transform_grub_config(payload, "persistent")
            if binding.bootloader == "grub"
            else transform_syslinux_config(payload, "persistent")
        )
    except (OSError, PersistenceBackendSafetyError) as error:
        raise CasperMediaSafetyError(str(error)) from error
    digest = hashlib.sha256(payload).hexdigest()
    if (
        payload != binding.transformed_contents
        or digest != binding.transformed_sha256
        or transform.contents != payload
        or transform.changed_lines != 0
        or transform.eligible_lines != binding.eligible_lines
    ):
        raise CasperMediaSafetyError(
            f"Transformed boot configuration could not be verified: {binding.relative_path}"
        )
    return StagedBootConfig(
        binding.relative_path,
        binding.bootloader,
        _file_identity(info),
        stat.S_IMODE(info.st_mode),
        digest,
        transform.eligible_lines,
    )


class CasperStagingExecutor:
    """Transform one private tree; publication remains the caller's responsibility."""

    def __init__(self, *, replacer: StagingReplacer = _atomic_replace_config) -> None:
        self._replacer = replacer
        self._cancelled = threading.Event()
        self._used = False

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        self._cancelled.set()

    def _check_cancelled(self) -> None:
        if self.cancelled:
            raise CasperMediaCancelled(
                "Casper staging was cancelled; discard the unpublished tree"
            )

    def execute(self, plan: CasperStagingPlan) -> CasperStagingResult:
        if self._used:
            raise CasperMediaSafetyError("A Casper staging executor can only be used once")
        self._used = True
        validate_casper_staging_plan(plan)
        self._check_cancelled()
        root_fd = os.open(plan.root, _DIR_FLAGS)
        try:
            if _root_identity(os.fstat(root_fd)) != plan.root_identity:
                raise CasperMediaSafetyError("The private staging root changed")
            for binding in plan.boot_configs:
                self._check_cancelled()
                if binding.changed_lines:
                    self._replacer(
                        root_fd,
                        binding,
                        binding.transformed_contents,
                        binding.original_sha256,
                        binding.identity,
                    )
                self._check_cancelled()

            for evidence in plan.evidence:
                try:
                    current = _binding(
                        root_fd, evidence.relative_path, _MAX_EVIDENCE_FILE_BYTES,
                    )
                except (OSError, PersistenceBackendSafetyError) as error:
                    raise CasperMediaSafetyError(str(error)) from error
                if current != evidence:
                    raise CasperMediaSafetyError(
                        f"Casper evidence changed: {evidence.relative_path}"
                    )
            configs = tuple(
                _post_transform_config(root_fd, binding)
                for binding in plan.boot_configs
            )
            self._check_cancelled()
            if _root_identity(os.fstat(root_fd)) != plan.root_identity:
                raise CasperMediaSafetyError("The private staging root changed")
            return CasperStagingResult(
                plan.root_identity[:2], plan.profile, plan.evidence, configs,
            )
        finally:
            os.close(root_fd)


def _validate_staging_result(
    staging_root: Path | str,
    result: CasperStagingResult,
) -> Path:
    if not isinstance(result, CasperStagingResult):
        raise CasperMediaSafetyError("A verified Casper staging result is required")
    profile = _canonical_profile(result.profile)
    root, root_info = _normalized_root(staging_root)
    if (
        len(result.root_identity) != 2
        or any(not isinstance(value, int) or value < 0 for value in result.root_identity)
        or result.root_identity != _root_identity(root_info)[:2]
    ):
        raise CasperMediaSafetyError("The published staging root has the wrong identity")
    if not result.evidence or not result.boot_configs:
        raise CasperMediaSafetyError("The staged Casper manifest is incomplete")
    root_fd = os.open(root, _DIR_FLAGS)
    try:
        expected_evidence, current_configs = _evidence_and_configs(root_fd, profile)
        if expected_evidence != result.evidence:
            raise CasperMediaSafetyError("The staged Casper evidence changed")
        by_path = {item.relative_path: item for item in result.boot_configs}
        if len(by_path) != len(result.boot_configs) or tuple(by_path) != tuple(
            item.relative_path for item in result.boot_configs
        ):
            raise CasperMediaSafetyError("The staged boot manifest is not canonical")
        if tuple(item.relative_path for item in current_configs) != tuple(by_path):
            raise CasperMediaSafetyError("The staged boot-config set changed")
        for current in current_configs:
            manifest = by_path[current.relative_path]
            payload, info = _read_file_from_root(
                root_fd, current.relative_path, maximum=MAX_BOOT_CONFIG_BYTES,
            )
            transform = (
                transform_grub_config(payload, "persistent")
                if current.bootloader == "grub"
                else transform_syslinux_config(payload, "persistent")
            )
            if (
                manifest.bootloader != current.bootloader
                or manifest.identity != _file_identity(info)
                or manifest.mode != stat.S_IMODE(info.st_mode)
                or manifest.sha256 != hashlib.sha256(payload).hexdigest()
                or manifest.eligible_lines != transform.eligible_lines
                or transform.changed_lines != 0
                or transform.contents != payload
            ):
                raise CasperMediaSafetyError(
                    f"Staged boot configuration changed: {current.relative_path}"
                )
    except (OSError, PersistenceBackendSafetyError) as error:
        raise CasperMediaSafetyError(str(error)) from error
    finally:
        os.close(root_fd)
    return root


def _trusted_which(name: str) -> str | None:
    return shutil.which(name, path=_TRUSTED_TOOL_PATH)


def _trusted_tool(name: str, finder: Callable[[str], str | None]) -> str:
    value = finder(name)
    if not value:
        raise CasperMediaUnavailable(f"Casper media requires missing tool: {name}")
    normalized = os.path.normpath(value)
    if (
        not os.path.isabs(value)
        or normalized != value
        or os.path.dirname(value) not in _TRUSTED_DIRECTORIES
        or os.path.basename(value) != name
    ):
        raise CasperMediaUnavailable(f"Refusing untrusted tool path: {value!r}")
    return value


def probe_casper_logical_sector_size(
    device: Device,
    *,
    finder: Callable[[str], str | None] = _trusted_which,
    runner: RunCommand = subprocess.run,
) -> int:
    """Bind the target identity and sector size before destructive consent."""

    try:
        validate_device(device)
    except (FormattingError, ValueError) as error:
        raise CasperMediaSafetyError(str(error)) from error
    lsblk = _trusted_tool("lsblk", finder)
    fields = (
        "PATH,SIZE,TYPE,RM,HOTPLUG,TRAN,MODEL,VENDOR,SERIAL,WWN,"
        "MAJ:MIN,MOUNTPOINTS,RO,LOG-SEC"
    )
    try:
        result = runner(
            [
                lsblk, "--bytes", "--json", "--nodeps", "--output", fields,
                device.path,
            ],
            capture_output=True, text=True, timeout=15, shell=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CasperMediaUnavailable(
            _bounded(error, "Could not inspect the target logical sector size")
        ) from error
    if result.returncode:
        raise CasperMediaUnavailable(
            _bounded(
                (result.stdout or "") + (result.stderr or ""),
                "Could not inspect the target logical sector size",
            )
        )
    try:
        matching = [
            current for current in parse_lsblk(result.stdout, include_usb_hdds=True)
            if current.path == device.path
        ]
        sector_size = parse_logical_sector_size(result.stdout, device.path)
    except (FormattingError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise CasperMediaSafetyError(str(error)) from error
    if len(matching) != 1 or matching[0].identity != device.identity:
        raise CasperMediaSafetyError(
            "The target changed while its logical sector size was inspected"
        )
    if sector_size not in _SUPPORTED_SECTOR_SIZES:
        raise CasperMediaUnavailable(
            "Casper media supports only 512-byte or 4096-byte logical sectors; "
            f"this target reports {sector_size}"
        )
    return sector_size


def _geometry(
    device: Device,
    persistence_bytes: int,
    logical_sector_size: int,
) -> tuple[int, int, int, int]:
    if logical_sector_size not in _SUPPORTED_SECTOR_SIZES:
        raise CasperMediaSafetyError(
            "Casper media supports only 512-byte or 4096-byte logical sectors"
        )
    if (
        not isinstance(persistence_bytes, int)
        or isinstance(persistence_bytes, bool)
        or persistence_bytes < MIN_PERSISTENCE_BYTES
        or persistence_bytes % ALIGNMENT_BYTES
    ):
        raise CasperMediaSafetyError(
            "Persistence must be at least 256 MiB and aligned to 1 MiB"
        )
    alignment = ALIGNMENT_BYTES // logical_sector_size
    total = device.size // logical_sector_size
    gpt_tail = math.ceil(_GPT_ENTRY_ARRAY_BYTES / logical_sector_size) + 1
    aligned_end = ((total - gpt_tail) // alignment) * alignment
    persistence_count = persistence_bytes // logical_sector_size
    persistence_start = aligned_end - persistence_count
    data_start = alignment
    data_count = persistence_start - data_start
    if data_count <= 0 or persistence_start < data_start:
        raise CasperMediaSafetyError("The target is too small for the persistence layout")
    return data_start, data_count, persistence_start, persistence_count


def _layout_for(
    device: Device,
    persistence_bytes: int,
    logical_sector_size: int,
) -> MultiFormatPlan:
    data_start, data_count, persistence_start, persistence_count = _geometry(
        device, persistence_bytes, logical_sector_size,
    )
    try:
        return create_multi_format_plan(
            device,
            PartitionTable.GPT,
            (
                PartitionSpec(
                    PartitionRole.DATA,
                    Filesystem.FAT32,
                    _DATA_LABEL,
                    start_sector=data_start,
                    sector_count=data_count,
                ),
                PartitionSpec(
                    PartitionRole.PERSISTENCE,
                    Filesystem.EXT4,
                    _PARTITION_LABEL,
                    start_sector=persistence_start,
                    sector_count=persistence_count,
                ),
            ),
            logical_sector_size=logical_sector_size,
        )
    except (FormattingError, ValueError) as error:
        raise CasperMediaSafetyError(str(error)) from error


def build_casper_media_plan(
    staging_root: Path | str,
    staging: CasperStagingResult,
    device: Device,
    persistence_bytes: int,
    logical_sector_size: int,
    *,
    finder: Callable[[str], str | None] = _trusted_which,
    source_on_device: Callable[[str, Device], bool] = path_is_on_device,
) -> CasperMediaPlan:
    root = _validate_staging_result(staging_root, staging)
    profile = _canonical_profile(staging.profile)
    try:
        validate_device(device)
        layout = _layout_for(device, persistence_bytes, logical_sector_size)
        multi_tools = resolve_multi_tools(layout, finder)
        content = build_constructed_media_plan(
            root,
            device,
            PartitionTable.GPT,
            volume_label=_DATA_LABEL,
            filesystem=Filesystem.FAT32,
            finder=finder,
            source_on_device=source_on_device,
        )
    except (FormattingError, ConstructedMediaError, ValueError) as error:
        raise CasperMediaSafetyError(str(error)) from error
    data_spec = layout.partitions[0]
    assert data_spec.sector_count is not None
    data_capacity = data_spec.sector_count * logical_sector_size
    if content.required_capacity > data_capacity:
        raise CasperMediaSafetyError(
            "The transformed ISO does not fit in the exact FAT32 data partition"
        )
    tools = CasperMediaTools(
        multi_tools.pkexec,
        multi_tools.sfdisk,
        multi_tools.lsblk,
        content.tools.udisksctl,
    )
    plan = CasperMediaPlan(
        device,
        profile,
        staging,
        layout,
        content,
        persistence_bytes,
        data_capacity,
        tools,
    )
    validate_casper_media_plan(plan)
    return plan


def validate_casper_media_plan(plan: CasperMediaPlan) -> None:
    if not isinstance(plan, CasperMediaPlan):
        raise CasperMediaSafetyError("A CasperMediaPlan is required")
    profile = _canonical_profile(plan.profile)
    if plan.staging.profile != profile:
        raise CasperMediaSafetyError("The staged and target Casper profiles disagree")
    try:
        validate_device(plan.device)
        validate_multi_plan(plan.layout)
        validate_constructed_media_plan(plan.content)
    except (FormattingError, ConstructedMediaError, ValueError) as error:
        raise CasperMediaSafetyError(str(error)) from error
    _validate_staging_result(plan.content.staging_root, plan.staging)
    expected_layout = _layout_for(
        plan.device, plan.persistence_bytes, plan.layout.logical_sector_size or 0,
    )
    if plan.layout != expected_layout:
        raise CasperMediaSafetyError("The Casper partition layout is not canonical")
    if (
        plan.layout.device_identity != plan.device.identity
        or plan.content.device.identity != plan.device.identity
        or plan.content.partition_table is not PartitionTable.GPT
        or plan.content.filesystem is not Filesystem.FAT32
        or plan.content.volume_label != _DATA_LABEL
        or len(plan.layout.partitions) != 2
    ):
        raise CasperMediaSafetyError("The Casper media plan components disagree")
    data = plan.layout.partitions[0]
    persistence = plan.layout.partitions[1]
    assert data.sector_count is not None and persistence.sector_count is not None
    sector = plan.layout.logical_sector_size
    assert sector is not None
    if (
        data.role is not PartitionRole.DATA
        or data.filesystem is not Filesystem.FAT32
        or data.label != _DATA_LABEL
        or persistence.role is not PartitionRole.PERSISTENCE
        or persistence.filesystem is not Filesystem.EXT4
        or persistence.label != _PARTITION_LABEL
        or persistence.sector_count * sector != plan.persistence_bytes
        or plan.data_capacity != data.sector_count * sector
        or plan.content.required_capacity > plan.data_capacity
    ):
        raise CasperMediaSafetyError("The Casper layout or capacity binding is invalid")
    if not isinstance(plan.tools, CasperMediaTools):
        raise CasperMediaSafetyError("The Casper media tools are invalid")
    for name, path in (
        ("pkexec", plan.tools.pkexec),
        ("sfdisk", plan.tools.sfdisk),
        ("lsblk", plan.tools.lsblk),
        ("udisksctl", plan.tools.udisksctl),
    ):
        try:
            resolved = _trusted_tool(
                name, lambda requested, n=name, p=path: p if requested == n else None,
            )
        except CasperMediaUnavailable as error:
            raise CasperMediaSafetyError(str(error)) from error
        if resolved != path:
            raise CasperMediaSafetyError("The Casper media tool binding changed")


def _partition_path(device_path: str, number: int) -> str:
    if not _BLOCK_PATH.fullmatch(device_path) or number <= 0:
        raise CasperMediaSafetyError("Unsafe partition path request")
    separator = "p" if device_path[-1].isdigit() else ""
    return f"{device_path}{separator}{number}"


class CasperLayoutExecutor(MultiFormatExecutor):
    """MultiFormatExecutor with an exact node check before every mkfs."""

    def __init__(
        self,
        *,
        boundary_validator: Callable[[tuple[str, ...]], None],
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._boundary_validator = boundary_validator

    def execute_multi(
        self,
        device: Device,
        plan: MultiFormatPlan,
        stage: Callable[[str], None] | None = None,
    ) -> tuple[str, ...]:
        validate_device(device)
        validate_multi_plan(plan)
        if device.path != plan.device_path or device.identity != plan.device_identity:
            raise DeviceChangedError("The layout does not belong to the selected drive")
        tools: MultiFormatTools = resolve_multi_tools(plan, self._which)
        report = stage or (lambda _message: None)

        current = self._assert_identity(plan, tools)  # type: ignore[arg-type]
        self._assert_logical_sector_size(plan, tools)
        report("Unmounting")
        self._check_cancelled()
        self._unmount(current, tools)  # type: ignore[arg-type]
        self._assert_identity(plan, tools)  # type: ignore[arg-type]
        self._assert_logical_sector_size(plan, tools)

        self._check_cancelled()
        self._assert_identity(plan, tools)  # type: ignore[arg-type]
        self._assert_logical_sector_size(plan, tools)
        # This report is the exact hand-off boundary: all non-destructive
        # target/tool checks have passed and the partitioning command follows.
        report("Creating partition table")
        self._run_process(
            multi_partition_command(plan, tools), multi_partition_script(plan),
        )
        self._run_process([tools.pkexec, tools.partprobe, plan.device_path])
        self._run_process([tools.udevadm, "settle"])

        report("Waiting for partitions")
        self._check_cancelled()
        partitions = self._discover_partitions(plan, tools)
        self._assert_identity(plan, tools)  # type: ignore[arg-type]
        self._verify_explicit_geometry(plan, tools, partitions)
        self._assert_logical_sector_size(plan, tools)
        partition_identities = self._observe_partition_nodes(
            plan, tools, partitions,
        )

        commands = multi_format_commands(plan, tools, partitions)
        if len(commands) != 2:
            raise FormattingError("Casper media requires exactly two formatted partitions")
        report("Creating filesystems")
        for command in commands:
            self._check_cancelled()
            self._assert_identity(plan, tools)  # type: ignore[arg-type]
            self._assert_logical_sector_size(plan, tools)
            self._verify_explicit_geometry(plan, tools, partitions)
            self._verify_partition_nodes(
                plan, tools, partitions, partition_identities,
            )
            self._boundary_validator(partitions)
            self._check_cancelled()
            self._assert_identity(plan, tools)  # type: ignore[arg-type]
            self._assert_logical_sector_size(plan, tools)
            self._verify_explicit_geometry(plan, tools, partitions)
            self._verify_partition_nodes(
                plan, tools, partitions, partition_identities,
            )
            self._run_process(command)
        self._run_process([tools.udevadm, "settle"])
        self._assert_identity(plan, tools)  # type: ignore[arg-type]
        self._assert_logical_sector_size(plan, tools)
        self._verify_explicit_geometry(plan, tools, partitions)
        self._verify_partition_nodes(
            plan, tools, partitions, partition_identities,
        )
        report("Complete")
        return partitions


class CasperMediaExecutor:
    def __init__(
        self,
        *,
        layout_executor: MultiFormatExecutor | None = None,
        content_executor: ConstructedMediaExecutor | None = None,
        run_command: RunCommand = subprocess.run,
        device_lister: DeviceLister | None = None,
        stat_func: Callable[[str], os.stat_result] = os.stat,
    ) -> None:
        self._run = run_command
        self._device_lister = device_lister
        self._stat = stat_func
        self._cancelled = threading.Event()
        self._started = False
        self._active_plan: CasperMediaPlan | None = None
        self._layout = layout_executor or CasperLayoutExecutor(
            boundary_validator=self._layout_boundary,
        )
        self._content = content_executor or ConstructedMediaExecutor()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        self._cancelled.set()
        self._layout.cancel()
        self._content.cancel()

    def _check_cancelled(self) -> None:
        if self.cancelled:
            raise CasperMediaCancelled("Casper persistence media creation was cancelled")

    def _devices(self, plan: CasperMediaPlan) -> Sequence[Device]:
        if self._device_lister is not None:
            return self._device_lister()
        fields = "PATH,SIZE,TYPE,RM,HOTPLUG,TRAN,MODEL,VENDOR,SERIAL,WWN,MAJ:MIN,MOUNTPOINTS,RO"
        try:
            result = self._run(
                [
                    plan.tools.lsblk, "--tree", "--bytes", "--json", "--output",
                    fields, plan.device.path,
                ],
                capture_output=True, text=True, timeout=15, shell=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise CasperMediaSafetyError("Could not revalidate the target drive") from error
        if result.returncode:
            raise CasperMediaSafetyError("Could not revalidate the target drive")
        try:
            return parse_lsblk(result.stdout, include_usb_hdds=True)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise CasperMediaSafetyError("lsblk returned invalid target information") from error

    def _verify_device(self, plan: CasperMediaPlan) -> None:
        self._check_cancelled()
        matching = [item for item in self._devices(plan) if item.path == plan.device.path]
        if len(matching) != 1 or matching[0].identity != plan.device.identity:
            raise CasperMediaSafetyError("The target drive disappeared or changed identity")
        try:
            validate_device(matching[0])
            info = self._stat(plan.device.path)
        except (OSError, FormattingError, ValueError) as error:
            raise CasperMediaSafetyError("The target is no longer a safe block device") from error
        if (
            not stat.S_ISBLK(info.st_mode)
            or f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
            != plan.device.major_minor
        ):
            raise CasperMediaSafetyError("The target drive device number changed")

    @staticmethod
    def _block_nodes(payload: str, device_path: str) -> dict[str, dict[str, object]]:
        try:
            roots = json.loads(payload).get("blockdevices", [])
        except (AttributeError, TypeError, json.JSONDecodeError) as error:
            raise CasperMediaSafetyError("lsblk returned invalid partition metadata") from error
        if not isinstance(roots, list) or len(roots) != 1 or not isinstance(roots[0], dict):
            raise CasperMediaSafetyError("lsblk did not uniquely report the target")
        root = roots[0]
        if root.get("path") != device_path or root.get("type") != "disk":
            raise CasperMediaSafetyError("lsblk reported partition metadata for another target")
        nodes: dict[str, dict[str, object]] = {}
        for item in root.get("children") or []:
            if isinstance(item, dict) and item.get("type") == "part":
                path = str(item.get("path") or "")
                if path in nodes:
                    raise CasperMediaSafetyError("lsblk reported a duplicate partition")
                nodes[path] = item
        return nodes

    def _verify_target(
        self,
        plan: CasperMediaPlan,
        partitions: Sequence[str],
        *,
        formatted: bool,
        unmounted: bool,
    ) -> None:
        self._verify_device(plan)
        expected = (
            _partition_path(plan.device.path, 1),
            _partition_path(plan.device.path, 2),
        )
        if tuple(partitions) != expected:
            raise CasperMediaSafetyError("The layout returned unexpected partition paths")
        for partition in expected:
            try:
                info = self._stat(partition)
            except OSError as error:
                raise CasperMediaSafetyError("A target partition is unavailable") from error
            if not stat.S_ISBLK(info.st_mode):
                raise CasperMediaSafetyError("A target partition is not a block device")
        try:
            table = self._run(
                [plan.tools.pkexec, plan.tools.sfdisk, "--json", plan.device.path],
                capture_output=True, text=True, timeout=30, shell=False,
            )
            blocks = self._run(
                [
                    plan.tools.lsblk, "--bytes", "--json", "--paths", "--output",
                    "PATH,TYPE,PKNAME,FSTYPE,LABEL,MAJ:MIN,MOUNTPOINTS,RO",
                    plan.device.path,
                ],
                capture_output=True, text=True, timeout=15, shell=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise CasperMediaSafetyError("Could not validate the target partitions") from error
        if table.returncode or blocks.returncode:
            raise CasperMediaSafetyError("Could not validate the target partitions")
        try:
            validate_explicit_partition_metadata(plan.layout, table.stdout, expected)
        except FormattingError as error:
            raise CasperMediaSafetyError(str(error)) from error
        nodes = self._block_nodes(blocks.stdout, plan.device.path)
        if set(nodes) != set(expected):
            raise CasperMediaSafetyError("The target has an unexpected partition-node set")
        expected_filesystems = (("vfat", _DATA_LABEL), ("ext4", _PARTITION_LABEL))
        for partition, (filesystem, label) in zip(expected, expected_filesystems, strict=True):
            node = nodes[partition]
            parent = str(node.get("pkname") or "")
            if parent and not parent.startswith("/dev/"):
                parent = "/dev/" + parent
            major_minor = str(node.get("maj:min") or "")
            try:
                block_info = self._stat(partition)
                expected_rdev = os.makedev(*(int(value) for value in major_minor.split(":")))
            except (OSError, TypeError, ValueError) as error:
                raise CasperMediaSafetyError("A partition has invalid block identity") from error
            mountpoints = tuple(str(value) for value in (node.get("mountpoints") or ()) if value)
            if (
                parent != plan.device.path
                or not _MAJOR_MINOR.fullmatch(major_minor)
                or block_info.st_rdev != expected_rdev
                or bool(node.get("ro"))
                or (unmounted and mountpoints)
            ):
                raise CasperMediaSafetyError("A target partition changed identity or mount state")
            if formatted and (
                str(node.get("fstype") or "").casefold() != filesystem
                or str(node.get("label") or "") != label
            ):
                raise CasperMediaSafetyError("A target filesystem or label is not exact")

    def _layout_boundary(self, partitions: tuple[str, ...]) -> None:
        plan = self._active_plan
        if plan is None:
            raise CasperMediaSafetyError("No active Casper media plan")
        self._verify_target(plan, partitions, formatted=False, unmounted=False)

    def _unmount_created(
        self,
        plan: CasperMediaPlan,
        partitions: tuple[str, str],
    ) -> None:
        for partition in partitions:
            self._verify_target(plan, partitions, formatted=True, unmounted=False)
            self._check_cancelled()
            result = self._run(
                [
                    plan.tools.udisksctl, "unmount", "--block-device", partition,
                    "--no-user-interaction",
                ],
                capture_output=True, text=True, timeout=30, shell=False,
            )
            combined = ((result.stdout or "") + (result.stderr or "")).casefold()
            if result.returncode and not any(
                text in combined for text in ("not mounted", "not a mounted filesystem")
            ):
                raise CasperMediaError(
                    _bounded(combined, f"Could not unmount {partition}")
                )
        self._verify_target(plan, partitions, formatted=True, unmounted=True)

    def _power_off(
        self,
        plan: CasperMediaPlan,
        partitions: tuple[str, str],
    ) -> bool:
        try:
            self._verify_target(
                plan, partitions, formatted=True, unmounted=True,
            )
            matching = [item for item in self._devices(plan) if item.path == plan.device.path]
            info = self._stat(plan.device.path)
            if (
                len(matching) != 1
                or matching[0].identity != plan.device.identity
                or not stat.S_ISBLK(info.st_mode)
                or f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
                != plan.device.major_minor
            ):
                return False
        except (OSError, CasperMediaError, subprocess.SubprocessError, ValueError):
            return False
        try:
            result = self._run(
                [
                    plan.tools.udisksctl, "power-off", "--block-device",
                    plan.device.path, "--no-user-interaction",
                ],
                capture_output=True, text=True, timeout=30, shell=False,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def execute(
        self,
        plan: CasperMediaPlan,
        progress: Progress = lambda _update: None,
    ) -> CasperMediaResult:
        if self._started:
            raise CasperMediaSafetyError("A Casper media executor can only be used once")
        self._started = True
        validate_casper_media_plan(plan)
        self._check_cancelled()
        self._verify_device(plan)
        attempted = False
        powered_off = False
        pair: tuple[str, str] | None = None
        safe_to_power_off = False
        self._active_plan = plan
        try:
            # The Casper manifest binds only persistence-specific evidence.  The
            # constructed plan binds every staged directory and file, and must be
            # fully rescanned before either filesystem is created.
            self._content.verify_pre_destructive(plan.content)
            progress(CasperMediaProgress("Creating exact FAT32/persistence layout"))
            self._check_cancelled()
            self._verify_device(plan)

            def layout_progress(stage: str) -> None:
                nonlocal attempted
                if stage == "Creating partition table":
                    attempted = True
                progress(CasperMediaProgress(stage))

            partitions = self._layout.execute_multi(
                plan.device, plan.layout, layout_progress,
            )
            if len(partitions) != 2:
                raise CasperMediaSafetyError("Casper media requires exactly two partitions")
            data_partition, persistence_partition = partitions
            pair = (data_partition, persistence_partition)
            self._verify_target(plan, pair, formatted=True, unmounted=False)
            self._unmount_created(plan, pair)

            progress(CasperMediaProgress("Copying verified boot media"))
            self._check_cancelled()
            self._verify_target(plan, pair, formatted=True, unmounted=True)
            safe_to_power_off = False

            def content_progress(update: ConstructedProgress) -> None:
                self._check_cancelled()
                progress(CasperMediaProgress(
                    update.stage,
                    update.relative_path,
                    update.bytes_done,
                    update.total_bytes,
                ))

            content = self._content.populate_existing_partition(
                plan.content,
                data_partition,
                content_progress,
                power_off=False,
            )
            if not content.unmounted:
                raise CasperMediaError(
                    "The FAT32 data partition could not be cleanly unmounted"
                )
            self._check_cancelled()
            self._verify_target(plan, pair, formatted=True, unmounted=True)
            safe_to_power_off = True
            progress(CasperMediaProgress(
                "Complete",
                bytes_done=plan.content.total_bytes,
                total_bytes=plan.content.total_bytes,
            ))
        except (FormatCancelled, ConstructedMediaCancelled) as error:
            suffix = "; media is incomplete" if attempted else ""
            raise CasperMediaCancelled(
                f"Casper persistence media creation was cancelled{suffix}"
            ) from error
        except CasperMediaCancelled as error:
            if attempted:
                raise CasperMediaCancelled(
                    "Casper persistence media creation was cancelled; media is incomplete"
                ) from error
            raise
        except CasperMediaSafetyError as error:
            if attempted:
                raise CasperMediaSafetyError(
                    f"Casper media is incomplete: {error}"
                ) from error
            raise
        except ConstructedMediaSafetyError as error:
            if attempted:
                raise CasperMediaSafetyError(
                    f"Casper media is incomplete: {error}"
                ) from error
            raise CasperMediaSafetyError(str(error)) from error
        except FormattingError as error:
            prefix = "Casper media is incomplete: " if attempted else ""
            raise CasperMediaError(f"{prefix}{error}") from error
        except (ConstructedMediaError, CasperMediaError) as error:
            prefix = "Casper media is incomplete: " if attempted else ""
            raise CasperMediaError(f"{prefix}{error}") from error
        except Exception as error:
            prefix = "Casper media is incomplete: " if attempted else ""
            raise CasperMediaError(
                f"{prefix}{_bounded(error, 'operation failed')}"
            ) from error
        finally:
            self._active_plan = None
            if safe_to_power_off and pair is not None:
                powered_off = self._power_off(plan, pair)
        return CasperMediaResult(
            plan.device.identity,
            data_partition,
            persistence_partition,
            plan.persistence_bytes,
            plan.profile.partition_label,
            content,
            powered_off,
        )
