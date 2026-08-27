from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Fail-closed UEFI:NTFS planning and execution.

The bridge image is downloaded only through ISOpropyl's release-bundled,
hash-pinned catalog.  Its bytes are then opened without following links,
identity-bound, and held in memory.  Privileged ``dd`` receives those bytes on
stdin and never opens a user-controlled cache pathname.
"""

import hashlib
import hmac
import json
import math
import os
import re
import shutil
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .bootloaders import (
    BootloaderResource,
    DownloadResponse,
    default_cache_dir,
    fetch_resource,
    load_catalog,
)
from .constructed import (
    ConstructedMediaCancelled,
    ConstructedMediaError,
    ConstructedMediaExecutor,
    ConstructedMediaPlan,
    ConstructedMediaResult,
    ConstructedProgress,
    build_constructed_media_plan,
    validate_constructed_media_plan,
)
from .devices import Device, parse_lsblk, path_is_on_device
from .formatting import (
    Filesystem,
    FormatCancelled,
    FormattingError,
    MultiFormatExecutor,
    MultiFormatPlan,
    MultiFormatTools,
    PartitionTable,
    create_uefi_ntfs_format_plan,
    parse_logical_sector_size,
    resolve_multi_tools,
    validate_explicit_partition_metadata,
    validate_multi_plan,
)

UEFI_NTFS_FAMILY = "uefi-ntfs"
UEFI_NTFS_VERSION = "2.8-rufus-2368e49a"
UEFI_NTFS_NAME = "uefi-ntfs.img"
UEFI_NTFS_SIZE = 1_048_576
UEFI_NTFS_SHA256 = "72683fa1250eeea772d3399277b434d4e55ba8dd0dc926e52d817e701fc2eb9e"
UEFI_NTFS_URL = (
    "https://raw.githubusercontent.com/pbatard/rufus/"
    "2368e49a82e854d3e702f824648cc723953dbb53/res/uefi/uefi-ntfs.img"
)
UEFI_NTFS_ALLOWED_HOSTS = ("raw.githubusercontent.com",)
_BLOCK_PATH = re.compile(r"/dev/[A-Za-z0-9._+:-]+")
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_TRUSTED_DIRECTORIES = tuple(_TRUSTED_TOOL_PATH.split(":"))
_MAX_ERROR = 2048
_RAW_IO_TIMEOUT_SECONDS = 120.0
_PROCESS_POLL_SECONDS = 0.2
_PROCESS_STOP_SECONDS = 2.0


class UefiNtfsError(RuntimeError):
    pass


class UefiNtfsUnavailable(UefiNtfsError):
    pass


class UefiNtfsSafetyError(UefiNtfsError):
    pass


class UefiNtfsCancelled(UefiNtfsError):
    pass


class PayloadTrust(str, Enum):
    MICROSOFT_UEFI_CA_2011 = "microsoft-uefi-ca-2011"
    UNSIGNED = "unsigned"


@dataclass(frozen=True)
class ArchitecturePayload:
    architecture: str
    suffix: str
    fallback_path: str
    bridge_path: str
    driver_path: str
    trust: PayloadTrust
    warning: str = ""


@dataclass(frozen=True)
class BoundArtifact:
    family: str
    version: str
    name: str
    sha256: str
    data: bytes
    source_device: int
    source_inode: int


@dataclass(frozen=True)
class UefiNtfsTools:
    pkexec: str
    dd: str
    sfdisk: str
    lsblk: str
    udisksctl: str


@dataclass(frozen=True)
class UefiNtfsMediaPlan:
    device: Device
    layout: MultiFormatPlan
    content: ConstructedMediaPlan
    artifact: BoundArtifact
    architectures: tuple[str, ...]
    allow_unsigned_arm: bool
    payloads: tuple[ArchitecturePayload, ...]
    tools: UefiNtfsTools
    data_capacity: int


@dataclass(frozen=True)
class UefiNtfsProgress:
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
class UefiNtfsResult:
    device_identity: tuple[str, int, str, str, str, str]
    data_partition: str
    boot_partition: str
    content: ConstructedMediaResult
    artifact_sha256: str
    powered_off: bool


Progress = Callable[[UefiNtfsProgress], None]
DeviceLister = Callable[[], Sequence[Device]]
RunCommand = Callable[..., subprocess.CompletedProcess[str]]
OpenUrl = Callable[..., DownloadResponse]


_ARCHITECTURES: dict[str, ArchitecturePayload] = {
    "x64": ArchitecturePayload(
        "x64", "x64", "EFI/BOOT/BOOTX64.EFI",
        "EFI/Boot/bootx64.efi", "EFI/Rufus/ntfs_x64.efi",
        PayloadTrust.MICROSOFT_UEFI_CA_2011,
        "Secure Boot also requires Microsoft UEFI CA 2011 third-party trust and no DBX revocation.",
    ),
    "x86": ArchitecturePayload(
        "x86", "ia32", "EFI/BOOT/BOOTIA32.EFI",
        "EFI/Boot/bootia32.efi", "EFI/Rufus/ntfs_ia32.efi",
        PayloadTrust.MICROSOFT_UEFI_CA_2011,
        "Secure Boot also requires Microsoft UEFI CA 2011 third-party trust and no DBX revocation.",
    ),
    "arm64": ArchitecturePayload(
        "ARM64", "aa64", "EFI/BOOT/BOOTAA64.EFI",
        "EFI/Boot/bootaa64.efi", "EFI/Rufus/ntfs_aa64.efi",
        PayloadTrust.MICROSOFT_UEFI_CA_2011,
        "Secure Boot also requires Microsoft UEFI CA 2011 third-party trust and no DBX revocation.",
    ),
    "arm": ArchitecturePayload(
        "ARM", "arm", "EFI/BOOT/BOOTARM.EFI",
        "EFI/Boot/bootarm.efi", "EFI/Rufus/ntfs_arm.efi",
        PayloadTrust.UNSIGNED,
        "The ARM32 bridge and driver are not Secure Boot signed.",
    ),
}


def _bounded(value: object, fallback: str) -> str:
    rendered = str(value or "").strip()
    return rendered[-_MAX_ERROR:] if rendered else fallback


def _trusted_which(name: str) -> str | None:
    return shutil.which(name, path=_TRUSTED_TOOL_PATH)


def _trusted_tool(name: str, finder: Callable[[str], str | None]) -> str:
    value = finder(name)
    if not value:
        raise UefiNtfsUnavailable(f"{name} is required for UEFI:NTFS media")
    normalized = os.path.normpath(value)
    if (
        not os.path.isabs(normalized)
        or os.path.dirname(normalized) not in _TRUSTED_DIRECTORIES
        or os.path.basename(normalized) != name
    ):
        raise UefiNtfsUnavailable(f"Refusing untrusted {name} path: {value!r}")
    return normalized


def probe_uefi_ntfs_logical_sector_size(
    device: Device,
    *,
    finder: Callable[[str], str | None] = _trusted_which,
    runner: RunCommand = subprocess.run,
) -> int:
    """Observe a target's logical sector size before destructive consent."""
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
        raise UefiNtfsUnavailable(
            _bounded(error, "Could not inspect the target logical sector size")
        ) from error
    if result.returncode:
        raise UefiNtfsUnavailable(
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
        raise UefiNtfsSafetyError(str(error)) from error
    if len(matching) != 1 or matching[0].identity != device.identity:
        raise UefiNtfsSafetyError(
            "The target changed while its logical sector size was inspected"
        )
    if sector_size != 512:
        raise UefiNtfsUnavailable(
            "The pinned UEFI:NTFS image currently requires 512-byte logical sectors; "
            f"this target reports {sector_size}"
        )
    return sector_size


def _catalog_resource() -> BootloaderResource:
    resource = load_catalog().find(
        UEFI_NTFS_FAMILY, UEFI_NTFS_VERSION, UEFI_NTFS_NAME,
    )
    if resource is None:
        raise UefiNtfsUnavailable("The release has no pinned UEFI:NTFS artifact")
    if (
        resource.key != (UEFI_NTFS_FAMILY, UEFI_NTFS_VERSION, UEFI_NTFS_NAME)
        or resource.url != UEFI_NTFS_URL
        or resource.allowed_hosts != UEFI_NTFS_ALLOWED_HOSTS
        or resource.size != UEFI_NTFS_SIZE
        or resource.sha256 != UEFI_NTFS_SHA256
    ):
        raise UefiNtfsSafetyError("The bundled UEFI:NTFS catalog entry is inconsistent")
    return resource


def bind_uefi_ntfs_artifact(
    path: Path | str,
    resource: BootloaderResource | None = None,
) -> BoundArtifact:
    expected = resource or _catalog_resource()
    if expected.key != (UEFI_NTFS_FAMILY, UEFI_NTFS_VERSION, UEFI_NTFS_NAME):
        raise UefiNtfsSafetyError("The artifact does not use the supported UEFI:NTFS key")
    if expected.size != UEFI_NTFS_SIZE or expected.sha256 != UEFI_NTFS_SHA256:
        raise UefiNtfsSafetyError("The artifact metadata differs from the supported release")
    candidate = os.fspath(path)
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise UefiNtfsSafetyError(
            _bounded(error, "Could not safely open the UEFI:NTFS artifact")
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != expected.size
        ):
            raise UefiNtfsSafetyError(
                "The UEFI:NTFS artifact must be one regular, singly linked 1 MiB file"
            )
        chunks: list[bytes] = []
        remaining = expected.size + 1
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
        if any(getattr(before, field) != getattr(after, field) for field in identity_fields):
            raise UefiNtfsSafetyError("The UEFI:NTFS artifact changed while it was read")
    finally:
        os.close(descriptor)
    if len(data) != expected.size:
        raise UefiNtfsSafetyError("The UEFI:NTFS artifact has the wrong length")
    digest = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(digest, expected.sha256):
        raise UefiNtfsSafetyError("The UEFI:NTFS artifact failed SHA-256 verification")
    return BoundArtifact(
        expected.family, expected.version, expected.name, digest, data,
        before.st_dev, before.st_ino,
    )


def prepare_uefi_ntfs_artifact(
    *,
    cache_dir: Path | None = None,
    opener: OpenUrl | None = None,
    cancel_event: threading.Event | None = None,
) -> BoundArtifact:
    """Download/cache and bind the pinned artifact before destructive consent."""
    resource = _catalog_resource()
    kwargs: dict[str, object] = {}
    if opener is not None:
        kwargs["opener"] = opener
    path = fetch_resource(
        resource, cache_dir or default_cache_dir(), cancel_event=cancel_event,
        **kwargs,  # type: ignore[arg-type]
    )
    if cancel_event is not None and cancel_event.is_set():
        raise UefiNtfsCancelled("UEFI:NTFS helper preparation was cancelled")
    return bind_uefi_ntfs_artifact(path, resource)


def _payloads_for(
    architectures: Sequence[str],
    fallback_loaders: Sequence[str],
    *,
    allow_unsigned_arm: bool,
) -> tuple[ArchitecturePayload, ...]:
    if not architectures:
        raise UefiNtfsSafetyError("No UEFI architecture was detected")
    available = {path.casefold() for path in fallback_loaders}
    payloads: list[ArchitecturePayload] = []
    for architecture in dict.fromkeys(item.casefold() for item in architectures):
        if architecture == "risc-v64":
            raise UefiNtfsSafetyError(
                "UEFI:NTFS v2.8 has an upstream RISC-V64 suffix mismatch and is blocked"
            )
        if architecture == "loongarch64":
            raise UefiNtfsSafetyError(
                "The pinned UEFI:NTFS image has no complete LoongArch64 payload pair"
            )
        payload = _ARCHITECTURES.get(architecture)
        if payload is None:
            raise UefiNtfsSafetyError(
                f"UEFI:NTFS does not support architecture {architecture!r}"
            )
        if payload.trust is PayloadTrust.UNSIGNED and not allow_unsigned_arm:
            raise UefiNtfsSafetyError(
                "ARM32 UEFI:NTFS requires an explicit unsigned-payload opt-in"
            )
        if payload.fallback_path.casefold() not in available:
            raise UefiNtfsSafetyError(
                f"The staged tree lacks {payload.fallback_path} for {payload.architecture}"
            )
        payloads.append(payload)
    return tuple(payloads)


def build_uefi_ntfs_media_plan(
    staging_root: Path | str,
    device: Device,
    partition_table: PartitionTable,
    architectures: Sequence[str],
    artifact: BoundArtifact,
    *,
    volume_label: str = "ISO_DATA",
    bios_bootable: bool = False,
    allow_unsigned_arm: bool = False,
    logical_sector_size: int | None = None,
    finder: Callable[[str], str | None] = _trusted_which,
    source_on_device: Callable[[str, Device], bool] = path_is_on_device,
) -> UefiNtfsMediaPlan:
    if not isinstance(partition_table, PartitionTable):
        raise UefiNtfsSafetyError("UEFI:NTFS requires an MBR or GPT table")
    if (
        artifact.family != UEFI_NTFS_FAMILY
        or artifact.version != UEFI_NTFS_VERSION
        or artifact.name != UEFI_NTFS_NAME
        or artifact.sha256 != UEFI_NTFS_SHA256
        or len(artifact.data) != UEFI_NTFS_SIZE
        or not hmac.compare_digest(hashlib.sha256(artifact.data).hexdigest(), artifact.sha256)
    ):
        raise UefiNtfsSafetyError("The bound UEFI:NTFS artifact is invalid")
    if logical_sector_size is None:
        raise UefiNtfsSafetyError(
            "UEFI:NTFS planning requires a freshly observed logical sector size"
        )
    try:
        layout = create_uefi_ntfs_format_plan(
            device, partition_table, filesystem=Filesystem.NTFS,
            label=volume_label, bios_bootable=bios_bootable,
            logical_sector_size=logical_sector_size,
        )
        multi_tools = resolve_multi_tools(layout, finder)
        content = build_constructed_media_plan(
            staging_root, device, partition_table,
            volume_label=volume_label, filesystem=Filesystem.NTFS,
            finder=finder, source_on_device=source_on_device,
        )
    except (FormattingError, ConstructedMediaError, ValueError) as error:
        raise UefiNtfsSafetyError(str(error)) from error
    frozen_architectures = tuple(architectures)
    payloads = _payloads_for(
        frozen_architectures, content.fallback_loaders,
        allow_unsigned_arm=allow_unsigned_arm,
    )
    data_spec = layout.partitions[0]
    assert data_spec.sector_count is not None
    data_capacity = data_spec.sector_count * logical_sector_size
    if content.required_capacity > data_capacity:
        raise UefiNtfsSafetyError(
            "The staged tree does not fit in the exact UEFI:NTFS data partition"
        )
    tools = UefiNtfsTools(
        multi_tools.pkexec,
        _trusted_tool("dd", finder),
        multi_tools.sfdisk,
        multi_tools.lsblk,
        content.tools.udisksctl,
    )
    return UefiNtfsMediaPlan(
        device, layout, content, artifact, frozen_architectures,
        allow_unsigned_arm, payloads, tools, data_capacity,
    )


def validate_uefi_ntfs_media_plan(plan: UefiNtfsMediaPlan) -> None:
    if not isinstance(plan, UefiNtfsMediaPlan):
        raise UefiNtfsSafetyError("A UefiNtfsMediaPlan is required")
    validate_multi_plan(plan.layout)
    validate_constructed_media_plan(plan.content)
    if (
        plan.layout.device_identity != plan.device.identity
        or plan.content.device.identity != plan.device.identity
        or plan.content.filesystem is not Filesystem.NTFS
        or plan.layout.logical_sector_size != 512
        or len(plan.layout.partitions) != 2
        or not plan.payloads
    ):
        raise UefiNtfsSafetyError("The UEFI:NTFS plan components disagree")
    if (
        plan.artifact.family != UEFI_NTFS_FAMILY
        or plan.artifact.version != UEFI_NTFS_VERSION
        or plan.artifact.name != UEFI_NTFS_NAME
        or plan.artifact.sha256 != UEFI_NTFS_SHA256
        or len(plan.artifact.data) != UEFI_NTFS_SIZE
        or not hmac.compare_digest(
            hashlib.sha256(plan.artifact.data).hexdigest(), UEFI_NTFS_SHA256,
        )
    ):
        raise UefiNtfsSafetyError("The plan's bound UEFI:NTFS bytes are invalid")
    if (
        not isinstance(plan.architectures, tuple)
        or not plan.architectures
        or any(not isinstance(item, str) or not item for item in plan.architectures)
        or not isinstance(plan.allow_unsigned_arm, bool)
    ):
        raise UefiNtfsSafetyError("The plan has invalid architecture bindings")
    try:
        expected_payloads = _payloads_for(
            plan.architectures,
            plan.content.fallback_loaders,
            allow_unsigned_arm=plan.allow_unsigned_arm,
        )
    except UefiNtfsSafetyError:
        raise
    if plan.payloads != expected_payloads:
        raise UefiNtfsSafetyError(
            "The plan's UEFI:NTFS payload mapping is not canonical"
        )
    data = plan.layout.partitions[0]
    assert data.sector_count is not None
    if (
        plan.data_capacity != data.sector_count * 512
        or plan.content.required_capacity > plan.data_capacity
    ):
        raise UefiNtfsSafetyError("The plan has invalid data-partition capacity")
    for name, path in (
        ("pkexec", plan.tools.pkexec), ("dd", plan.tools.dd),
        ("sfdisk", plan.tools.sfdisk), ("lsblk", plan.tools.lsblk),
        ("udisksctl", plan.tools.udisksctl),
    ):
        try:
            _trusted_tool(name, lambda requested, n=name, p=path: p if requested == n else None)
        except UefiNtfsUnavailable as error:
            raise UefiNtfsSafetyError("The plan contains an untrusted tool path") from error


class UefiNtfsExecutor:
    def __init__(
        self,
        *,
        layout_executor: MultiFormatExecutor | None = None,
        content_executor: ConstructedMediaExecutor | None = None,
        run_command: RunCommand = subprocess.run,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        device_lister: DeviceLister | None = None,
        stat_func: Callable[[str], os.stat_result] = os.stat,
        raw_io_timeout: float = _RAW_IO_TIMEOUT_SECONDS,
        process_stop_timeout: float = _PROCESS_STOP_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            not math.isfinite(raw_io_timeout)
            or not math.isfinite(process_stop_timeout)
            or raw_io_timeout <= 0
            or process_stop_timeout <= 0
        ):
            raise ValueError("Raw I/O and process-stop timeouts must be positive")
        self._layout = layout_executor or MultiFormatExecutor()
        self._content = content_executor or ConstructedMediaExecutor()
        self._run = run_command
        self._popen = popen
        self._device_lister = device_lister
        self._stat = stat_func
        self._raw_io_timeout = float(raw_io_timeout)
        self._process_stop_timeout = float(process_stop_timeout)
        self._monotonic = monotonic
        self._cancelled = threading.Event()
        self._process: subprocess.Popen[bytes] | None = None
        self._process_lock = threading.Lock()
        self._started = False

    def cancel(self) -> None:
        self._cancelled.set()
        self._layout.cancel()
        self._content.cancel()
        with self._process_lock:
            process = self._process
        if process is not None and process.poll() is None:
            try:
                # Keep the GUI-side cancellation request non-blocking.  The
                # worker owns bounded termination, kill fallback, and reaping.
                process.terminate()
            except OSError:
                pass

    def _check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise UefiNtfsCancelled("UEFI:NTFS writing was cancelled")

    def _devices(self, plan: UefiNtfsMediaPlan) -> Sequence[Device]:
        if self._device_lister is not None:
            return self._device_lister()
        fields = "PATH,SIZE,TYPE,RM,HOTPLUG,TRAN,MODEL,VENDOR,SERIAL,WWN,MAJ:MIN,MOUNTPOINTS,RO"
        result = self._run(
            [
                plan.tools.lsblk, "--tree", "--bytes", "--json", "--output",
                fields, plan.device.path,
            ],
            capture_output=True, text=True, timeout=15, shell=False,
        )
        if result.returncode:
            raise UefiNtfsSafetyError("Could not revalidate the target drive")
        try:
            return parse_lsblk(result.stdout, include_usb_hdds=True)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise UefiNtfsSafetyError("lsblk returned invalid target information") from error

    def _verify_target(
        self,
        plan: UefiNtfsMediaPlan,
        partitions: Sequence[str],
    ) -> None:
        self._check_cancelled()
        matching = [item for item in self._devices(plan) if item.path == plan.device.path]
        if len(matching) != 1 or matching[0].identity != plan.device.identity:
            raise UefiNtfsSafetyError("The target drive disappeared or changed identity")
        try:
            whole = self._stat(plan.device.path)
        except OSError as error:
            raise UefiNtfsSafetyError("The target drive path is unavailable") from error
        if (
            not stat.S_ISBLK(whole.st_mode)
            or f"{os.major(whole.st_rdev)}:{os.minor(whole.st_rdev)}"
            != plan.device.major_minor
        ):
            raise UefiNtfsSafetyError("The target drive device number changed")
        for partition in partitions:
            if not _BLOCK_PATH.fullmatch(partition):
                raise UefiNtfsSafetyError("The layout returned an unsafe partition path")
            try:
                info = self._stat(partition)
            except OSError as error:
                raise UefiNtfsSafetyError("A target partition is unavailable") from error
            if not stat.S_ISBLK(info.st_mode):
                raise UefiNtfsSafetyError("A target partition is no longer a block device")
        result = self._run(
            [plan.tools.pkexec, plan.tools.sfdisk, "--json", plan.device.path],
            capture_output=True, text=True, timeout=30, shell=False,
        )
        if result.returncode:
            raise UefiNtfsSafetyError(
                _bounded((result.stdout or "") + (result.stderr or ""),
                         "Could not revalidate partition geometry")
            )
        try:
            validate_explicit_partition_metadata(plan.layout, result.stdout, partitions)
        except FormattingError as error:
            raise UefiNtfsSafetyError(str(error)) from error

    def _set_process(self, process: subprocess.Popen[bytes] | None) -> None:
        with self._process_lock:
            self._process = process

    def _terminate_and_reap(self, process: subprocess.Popen[bytes]) -> None:
        """Stop a raw-I/O child without leaving an unbounded wait or zombie."""
        if process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass
        try:
            process.communicate(timeout=self._process_stop_timeout)
            return
        except subprocess.TimeoutExpired:
            pass
        except OSError:
            if process.poll() is not None:
                return
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.communicate(timeout=self._process_stop_timeout)
        except subprocess.TimeoutExpired as error:
            raise UefiNtfsError(
                "Privileged raw I/O could not be stopped and reaped"
            ) from error
        except OSError as error:
            if process.poll() is None:
                raise UefiNtfsError(
                    "Privileged raw I/O could not be stopped and reaped"
                ) from error

    def _run_dd(self, argv: Sequence[str], input_data: bytes | None) -> bytes:
        self._check_cancelled()
        process = self._popen(
            list(argv),
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        self._set_process(process)
        deadline = self._monotonic() + self._raw_io_timeout
        first = True
        try:
            while True:
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    self._terminate_and_reap(process)
                    raise UefiNtfsError(
                        "Privileged raw I/O exceeded its bounded time limit"
                    )
                try:
                    stdout, stderr = process.communicate(
                        input=input_data if first else None,
                        timeout=min(_PROCESS_POLL_SECONDS, remaining),
                    )
                    break
                except subprocess.TimeoutExpired:
                    first = False
                    if self._cancelled.is_set():
                        self._terminate_and_reap(process)
                        raise UefiNtfsCancelled("UEFI:NTFS writing was cancelled")
            if self._cancelled.is_set():
                raise UefiNtfsCancelled("UEFI:NTFS writing was cancelled")
            if process.returncode:
                raise UefiNtfsError(
                    _bounded(stderr.decode(errors="replace"), "Privileged raw I/O failed")
                )
            return stdout
        except (UefiNtfsError, UefiNtfsCancelled):
            raise
        except BaseException:
            self._terminate_and_reap(process)
            raise
        finally:
            self._set_process(None)

    def _write_and_verify_artifact(
        self,
        plan: UefiNtfsMediaPlan,
        boot_partition: str,
    ) -> None:
        common = ["bs=1048576", "count=1", "iflag=fullblock", "status=none"]
        self._run_dd(
            [
                plan.tools.pkexec, plan.tools.dd, f"of={boot_partition}",
                *common, "conv=fsync,notrunc",
            ],
            plan.artifact.data,
        )
        readback = self._run_dd(
            [
                plan.tools.pkexec, plan.tools.dd, f"if={boot_partition}",
                *common,
            ],
            None,
        )
        if len(readback) != UEFI_NTFS_SIZE or not hmac.compare_digest(
            hashlib.sha256(readback).hexdigest(), plan.artifact.sha256,
        ):
            raise UefiNtfsError("UEFI:NTFS raw read-back verification failed")

    def _power_off(self, plan: UefiNtfsMediaPlan) -> bool:
        # Never act on a path after an identity failure: a replacement device
        # may now occupy the same /dev name.
        try:
            matching = [
                item for item in self._devices(plan)
                if item.path == plan.device.path
            ]
            info = self._stat(plan.device.path)
            if (
                len(matching) != 1
                or matching[0].identity != plan.device.identity
                or not stat.S_ISBLK(info.st_mode)
                or f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
                != plan.device.major_minor
            ):
                return False
        except (OSError, UefiNtfsError, subprocess.SubprocessError, ValueError):
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
        plan: UefiNtfsMediaPlan,
        progress: Progress = lambda _progress: None,
    ) -> UefiNtfsResult:
        if self._started:
            raise UefiNtfsSafetyError("A UEFI:NTFS executor cannot be reused")
        self._started = True
        self._check_cancelled()
        validate_uefi_ntfs_media_plan(plan)
        powered_off = False
        try:
            progress(UefiNtfsProgress("Creating exact NTFS/boot layout"))
            partitions = self._layout.execute_multi(plan.device, plan.layout)
            if len(partitions) != 2:
                raise UefiNtfsSafetyError("UEFI:NTFS requires exactly two partitions")
            data_partition, boot_partition = partitions
            self._verify_target(plan, partitions)

            def content_progress(update: ConstructedProgress) -> None:
                progress(UefiNtfsProgress(
                    update.stage, update.relative_path,
                    update.bytes_done, update.total_bytes,
                ))

            content = self._content.populate_existing_partition(
                plan.content, data_partition, content_progress, power_off=False,
            )
            if not content.unmounted:
                raise UefiNtfsError(
                    "The NTFS data partition could not be cleanly unmounted; "
                    "the boot helper was not written"
                )
            self._verify_target(plan, partitions)
            progress(UefiNtfsProgress("Writing UEFI:NTFS bridge"))
            self._write_and_verify_artifact(plan, boot_partition)
            self._verify_target(plan, partitions)
            progress(UefiNtfsProgress(
                "Complete", bytes_done=plan.content.total_bytes,
                total_bytes=plan.content.total_bytes,
            ))
        except (FormatCancelled, ConstructedMediaCancelled) as error:
            raise UefiNtfsCancelled("UEFI:NTFS writing was cancelled") from error
        except FormattingError as error:
            raise UefiNtfsError(str(error)) from error
        finally:
            powered_off = self._power_off(plan)
        return UefiNtfsResult(
            plan.device.identity, data_partition, boot_partition,
            content, plan.artifact.sha256, powered_off,
        )
