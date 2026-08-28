from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Authenticated target-only orchestration for strict fast zeroing.

The operation scans every logical byte, skips only chunks already containing
all zeroes, overwrites every other chunk with zeroes, and accepts success only
after a cache-invalidated complete read-back.  It has no source descriptor,
``dd`` command, shell, or fallback privileged executor.
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import select
import shutil
import socket
import stat
import struct
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from . import raw_device
from .devices import Device, SizeUnitMode, format_size
from .syslinux_device_helper import (
    FAST_ZERO_DEFAULT_CHUNK_BYTES,
    FAST_ZERO_FAILURE_CANCELLED,
    FAST_ZERO_FAILURE_NONE,
    FAST_ZERO_HELPER_PROFILE,
    FAST_ZERO_OPERATION,
    HelperRequestError,
    MAX_PROTOCOL_PACKET,
    pack_fast_zero_helper_control,
    pack_fast_zero_helper_request,
    unpack_fast_zero_server_packet,
)
from .writer import (
    WriterError,
    WriterSafetyError,
    WriterTools,
    unmount_device,
    validate_device_selection,
)


logger = logging.getLogger("isopropyl")

FAST_ZERO_BOUNDARY_BYTES = 16 * 1024 * 1024
FAST_ZERO_CHUNK_BYTES = FAST_ZERO_DEFAULT_CHUNK_BYTES
FAST_ZERO_PLAN_PROFILE = "io.github.codebooker.isopropyl/fast-zero-plan/v1"
FAST_ZERO_READY_PROFILE = "io.github.codebooker.isopropyl/fast-zero-ready/v1"
FAST_ZERO_EXECUTOR_PROFILE = FAST_ZERO_HELPER_PROFILE
PKEXEC_PATH = "/usr/bin/pkexec"
HELPER_PATH = "/usr/libexec/isopropyl-device-helper"
HELPER_SCRIPT_PATH = "/usr/libexec/isopropyl/syslinux_device_helper.py"
POLICY_PATH = (
    "/usr/share/polkit-1/actions/"
    "io.github.codebooker.isopropyl.fast-zero.policy"
)
POLICY_ACTION = "io.github.codebooker.isopropyl.fast-zero-drive"
POLICY_DESCRIPTION = "Fast-zero a removable USB or SD drive"
POLICY_MESSAGE = (
    "Authentication is required to scan and logically zero the selected "
    "removable USB or SD target"
)
MAX_DIAGNOSTIC_BYTES = 8 * 1024
HELPER_STALL_TIMEOUT_SECONDS = 300.0
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_TRUSTED_TOOL_DIRECTORIES = frozenset(_TRUSTED_TOOL_PATH.split(":"))
_INERT_DD_PATH = "/nonexistent/isopropyl-fast-zero-has-no-dd"
_MAJOR_MINOR = re.compile(r"\d+:\d+\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PLAN_WITNESS = object()
_CONFIRMATION_WITNESS = object()
_READY_WITNESS = object()

FastZeroProgress = Callable[[str, int, int], None]


class FastZeroError(RuntimeError):
    """The fast-zero transaction could not produce its exact result."""


class FastZeroPlanError(FastZeroError):
    """Target planning or an authorization receipt failed closed."""


class FastZeroRunError(FastZeroError):
    """The helper transaction failed or ended in an unknown state."""

    def __init__(
        self,
        message: str,
        *,
        partial: FastZeroPartialFailure | None = None,
    ) -> None:
        super().__init__(message)
        self.partial = partial


class FastZeroCancelled(FastZeroError):
    """Cancellation won before mutation or before complete success."""

    def __init__(
        self,
        message: str,
        *,
        partial: FastZeroPartialResult | None = None,
    ) -> None:
        super().__init__(message)
        self.partial = partial


class FastZeroHelperUnavailable(FastZeroRunError):
    """The exact root-owned fast-zero integration is unavailable."""


class FastZeroState(str, Enum):
    CREATED = "created"
    PREPARING = "preparing"
    PREPARED = "prepared"
    CONFIRMED = "confirmed"
    EXECUTING = "executing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    PARTIAL_CANCELLED = "partial-cancelled"
    FAILED = "failed"
    CLOSED = "closed"


@dataclass(frozen=True)
class FastZeroTargetObservation:
    device: Device
    related_device_numbers: frozenset[int]
    disk_sequence: int


@dataclass(frozen=True)
class _PlanReceipt:
    token: object
    plan: object
    observation: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class _ConfirmationReceipt:
    token: object
    confirmation: object
    plan: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class _ReadyReceipt:
    token: object
    ready: object
    plan: object
    confirmation: object
    observation: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class FastZeroPlan:
    device: Device
    observation: FastZeroTargetObservation = field(repr=False, compare=False)
    disk_sequence: int
    target_capacity: int
    logical_sector_size: int
    chunk_size: int
    boundary_bytes: int
    related_device_numbers: frozenset[int]
    required_executor_profile: str
    size_unit_mode: SizeUnitMode
    warnings: tuple[str, ...]
    confirmation_phrase: str
    plan_sha256: str
    _authorization: _PlanReceipt | None = field(
        init=False,
        default=None,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class ConfirmedFastZero:
    plan: FastZeroPlan = field(repr=False, compare=False)
    plan_sha256: str
    device_identity: tuple[str, int, str, str, str, str]
    disk_sequence: int
    target_capacity: int
    logical_sector_size: int
    chunk_size: int
    confirmation_phrase: str
    _authorization: _ConfirmationReceipt | None = field(
        init=False,
        default=None,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class ReadyFastZero:
    plan: FastZeroPlan = field(repr=False, compare=False)
    confirmation: ConfirmedFastZero = field(repr=False, compare=False)
    observation: FastZeroTargetObservation
    plan_sha256: str
    ready_sha256: str
    _authorization: _ReadyReceipt | None = field(
        init=False,
        default=None,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class FastZeroResult:
    request_id: str
    plan_sha256: str
    ready_sha256: str
    target_path: str
    major_minor: str
    disk_sequence: int
    target_capacity: int
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
    cleanup_verified: bool
    cleanup_durable: bool
    exclusive_open: bool
    cache_invalidated: bool
    complete: bool
    cancellation_deferred: bool


@dataclass(frozen=True)
class FastZeroPartialResult:
    request_id: str
    plan_sha256: str
    ready_sha256: str
    target_path: str
    major_minor: str
    disk_sequence: int
    target_capacity: int
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
    cleanup_verified: bool
    cleanup_durable: bool
    exclusive_open: bool
    cache_invalidated: bool
    complete: bool


@dataclass(frozen=True)
class FastZeroPartialFailure(FastZeroPartialResult):
    failure_code: int


@dataclass(frozen=True)
class FastZeroHelperInstallation:
    pkexec: str
    helper: str
    script: str
    policy: str


def _device_payload(device: Device) -> dict[str, object]:
    return {
        "path": device.path,
        "size": device.size,
        "model": device.model,
        "vendor": device.vendor,
        "transport": device.transport,
        "serial": device.serial,
        "wwn": device.wwn,
        "major_minor": device.major_minor,
        "removable": device.removable,
        "hotplug": device.hotplug,
        "read_only": device.read_only,
        "mountpoints": list(device.mountpoints),
        "partitions": list(device.partitions),
        "logical_sector_size": device.logical_sector_size,
    }


def _validate_device_profile(device: Device) -> None:
    try:
        validate_device_selection(device, writable=True)
    except WriterSafetyError as error:
        raise FastZeroPlanError(str(error)) from error
    if type(device) is not Device or not device.removable:
        raise FastZeroPlanError(
            "Fast zero is restricted to media marked removable"
        )
    sector = device.logical_sector_size
    if (
        type(sector) is not int
        or isinstance(sector, bool)
        or sector < 512
        or sector > 4096
        or sector & (sector - 1)
    ):
        raise FastZeroPlanError(
            "Fast zero requires a 512 to 4096-byte power-of-two logical sector"
        )
    if device.size % sector:
        raise FastZeroPlanError(
            "The fast-zero target capacity is not logically sector aligned"
        )
    if FAST_ZERO_CHUNK_BYTES % sector:
        raise FastZeroPlanError(
            "The fast-zero chunk profile is incompatible with this target"
        )


def _validate_device_number(value: int) -> None:
    if type(value) is not int or value < 0:
        raise FastZeroPlanError("The target topology contains an invalid device number")
    try:
        if os.makedev(os.major(value), os.minor(value)) != value:
            raise ValueError("device number does not round trip")
    except (OverflowError, ValueError) as error:
        raise FastZeroPlanError(
            "The target topology contains an invalid device number"
        ) from error


def _validate_observation(observation: FastZeroTargetObservation) -> None:
    if type(observation) is not FastZeroTargetObservation:
        raise FastZeroPlanError("Exact live fast-zero target evidence is required")
    _validate_device_profile(observation.device)
    if (
        type(observation.related_device_numbers) is not frozenset
        or not observation.related_device_numbers
    ):
        raise FastZeroPlanError("The target topology evidence is empty or malformed")
    for number in observation.related_device_numbers:
        _validate_device_number(number)
    if (
        type(observation.disk_sequence) is not int
        or isinstance(observation.disk_sequence, bool)
        or not 0 < observation.disk_sequence <= 0xFFFFFFFFFFFFFFFF
    ):
        raise FastZeroPlanError("The target disk generation is invalid")
    major, minor = (int(part) for part in observation.device.major_minor.split(":"))
    if os.makedev(major, minor) not in observation.related_device_numbers:
        raise FastZeroPlanError(
            "The selected target is absent from its witnessed topology"
        )


def _default_observe_selected(device: Device) -> FastZeroTargetObservation:
    try:
        target_status = raw_device._validate_target_node(device)
        observed = raw_device._validate_live_target(device, target_status)
        disk_sequence = raw_device._read_disk_sequence(device.major_minor)
        result = FastZeroTargetObservation(
            observed.device,
            observed.related_device_numbers,
            disk_sequence,
        )
    except Exception as error:
        if isinstance(error, FastZeroPlanError):
            raise
        raise FastZeroPlanError(str(error)) from error
    _validate_observation(result)
    return result


def _default_observe_path(path: str) -> FastZeroTargetObservation:
    try:
        observed = raw_device._probe_live_target(path)
        disk_sequence = raw_device._read_disk_sequence(
            observed.device.major_minor,
        )
        result = FastZeroTargetObservation(
            observed.device,
            observed.related_device_numbers,
            disk_sequence,
        )
    except Exception as error:
        if isinstance(error, FastZeroPlanError):
            raise
        raise FastZeroPlanError(str(error)) from error
    _validate_observation(result)
    return result


ObserveSelected = Callable[[Device], FastZeroTargetObservation]
ObservePath = Callable[[str], FastZeroTargetObservation]


def _warnings(device: Device, size_unit_mode: SizeUnitMode) -> tuple[str, ...]:
    return (
        "THIS OPERATION IS DESTRUCTIVE AND CANNOT BE UNDONE.",
        (
            f"Target: {device.display_label(size_unit_mode)}; "
            f"serial {device.serial or 'not reported'}; "
            f"kernel identity {device.major_minor}."
        ),
        (
            "ISOpropyl will scan every logical byte, skip only chunks that are "
            "already all-zero, and overwrite every other chunk with zeroes."
        ),
        (
            "A complete cache-invalidated read-back must verify all "
            f"{format_size(device.size, size_unit_mode)} as zero before success."
        ),
        (
            "This is a logical overwrite, not a hardware secure erase or "
            "sanitization command."
        ),
        (
            "Cancelling after mutation begins leaves a partial erase; ISOpropyl "
            "will attempt to durably clear and verify up to the first and last "
            "16 MiB (counting overlap once, or the entire target when those "
            "regions overlap) only while the exact target identity and topology "
            "can still be revalidated. If that cleanup cannot be verified, the "
            "target state will be reported as unknown."
        ),
        f"To authorize this operation, type exactly: FAST ZERO {device.path} {device.major_minor}",
    )


def _plan_digest(plan: FastZeroPlan) -> str:
    try:
        encoded = json.dumps(
            {
                "profile": FAST_ZERO_PLAN_PROFILE,
                "target": _device_payload(plan.device),
                "disk_sequence": plan.disk_sequence,
                "capacity": plan.target_capacity,
                "logical_sector_size": plan.logical_sector_size,
                "chunk_size": plan.chunk_size,
                "boundary_bytes": plan.boundary_bytes,
                "topology": sorted(plan.related_device_numbers),
                "executor": plan.required_executor_profile,
                "size_unit_mode": plan.size_unit_mode.value,
                "warnings": list(plan.warnings),
                "confirmation_phrase": plan.confirmation_phrase,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return ""
    return hashlib.sha256(encoded).hexdigest()


def _plan_snapshot(plan: FastZeroPlan) -> tuple[object, ...]:
    return (
        plan.device,
        plan.disk_sequence,
        plan.target_capacity,
        plan.logical_sector_size,
        plan.chunk_size,
        plan.boundary_bytes,
        plan.related_device_numbers,
        plan.required_executor_profile,
        plan.size_unit_mode,
        plan.warnings,
        plan.confirmation_phrase,
        plan.plan_sha256,
    )


def _confirmation_snapshot(confirmation: ConfirmedFastZero) -> tuple[object, ...]:
    return (
        confirmation.plan_sha256,
        confirmation.device_identity,
        confirmation.disk_sequence,
        confirmation.target_capacity,
        confirmation.logical_sector_size,
        confirmation.chunk_size,
        confirmation.confirmation_phrase,
    )


def _ready_digest(ready: ReadyFastZero) -> str:
    try:
        encoded = json.dumps(
            {
                "profile": FAST_ZERO_READY_PROFILE,
                "plan_sha256": ready.plan_sha256,
                "disk_sequence": ready.observation.disk_sequence,
                "target": _device_payload(ready.observation.device),
                "topology": sorted(ready.observation.related_device_numbers),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return ""
    return hashlib.sha256(encoded).hexdigest()


def _ready_snapshot(ready: ReadyFastZero) -> tuple[object, ...]:
    return (
        ready.plan_sha256,
        ready.ready_sha256,
        ready.observation,
    )


def _post_unmount_matches(original: Device, current: Device) -> bool:
    return (
        current.mountpoints == ()
        and current.path == original.path
        and current.size == original.size
        and current.model == original.model
        and current.vendor == original.vendor
        and current.transport == original.transport
        and current.serial == original.serial
        and current.wwn == original.wwn
        and current.major_minor == original.major_minor
        and current.removable == original.removable
        and current.hotplug == original.hotplug
        and current.read_only == original.read_only
        and current.partitions == original.partitions
        and current.logical_sector_size == original.logical_sector_size
    )


def build_fast_zero_plan(
    device: Device,
    *,
    size_unit_mode: SizeUnitMode = SizeUnitMode.SI,
    observe: ObserveSelected = _default_observe_selected,
) -> FastZeroPlan:
    if type(device) is not Device:
        raise FastZeroPlanError("An exact discovered Device is required")
    if type(size_unit_mode) is not SizeUnitMode:
        raise FastZeroPlanError("The fast-zero size-unit mode is invalid")
    _validate_device_profile(device)
    observation = observe(device)
    _validate_observation(observation)
    if observation.device != device:
        raise FastZeroPlanError(
            "The selected target changed during fast-zero planning"
        )
    phrase = f"FAST ZERO {device.path} {device.major_minor}"
    warnings = _warnings(device, size_unit_mode)
    candidate = FastZeroPlan(
        device,
        observation,
        observation.disk_sequence,
        device.size,
        device.logical_sector_size,
        FAST_ZERO_CHUNK_BYTES,
        min(FAST_ZERO_BOUNDARY_BYTES, device.size),
        observation.related_device_numbers,
        FAST_ZERO_EXECUTOR_PROFILE,
        size_unit_mode,
        warnings,
        phrase,
        "",
    )
    plan = FastZeroPlan(
        candidate.device,
        candidate.observation,
        candidate.disk_sequence,
        candidate.target_capacity,
        candidate.logical_sector_size,
        candidate.chunk_size,
        candidate.boundary_bytes,
        candidate.related_device_numbers,
        candidate.required_executor_profile,
        candidate.size_unit_mode,
        candidate.warnings,
        candidate.confirmation_phrase,
        _plan_digest(candidate),
    )
    object.__setattr__(
        plan,
        "_authorization",
        _PlanReceipt(_PLAN_WITNESS, plan, observation, _plan_snapshot(plan)),
    )
    validate_fast_zero_plan(plan, observe=observe)
    return plan


def _validate_fast_zero_plan_receipt(plan: FastZeroPlan) -> None:
    if type(plan) is not FastZeroPlan:
        raise FastZeroPlanError("An authentic FastZeroPlan is required")
    receipt = plan._authorization
    if (
        type(receipt) is not _PlanReceipt
        or receipt.token is not _PLAN_WITNESS
        or receipt.plan is not plan
        or receipt.observation is not plan.observation
        or receipt.snapshot != _plan_snapshot(plan)
        or type(plan.observation) is not FastZeroTargetObservation
        or plan.observation.device != plan.device
        or plan.disk_sequence != plan.observation.disk_sequence
        or plan.target_capacity != plan.device.size
        or plan.logical_sector_size != plan.device.logical_sector_size
        or plan.chunk_size != FAST_ZERO_CHUNK_BYTES
        or plan.boundary_bytes != min(FAST_ZERO_BOUNDARY_BYTES, plan.target_capacity)
        or plan.related_device_numbers != plan.observation.related_device_numbers
        or plan.required_executor_profile != FAST_ZERO_EXECUTOR_PROFILE
        or type(plan.size_unit_mode) is not SizeUnitMode
        or plan.warnings != _warnings(plan.device, plan.size_unit_mode)
        or plan.confirmation_phrase
        != f"FAST ZERO {plan.device.path} {plan.device.major_minor}"
        or _SHA256.fullmatch(plan.plan_sha256) is None
        or not hmac.compare_digest(_plan_digest(plan), plan.plan_sha256)
    ):
        raise FastZeroPlanError(
            "The fast-zero plan is forged, cloned, or internally inconsistent"
        )
    _validate_observation(plan.observation)


def validate_fast_zero_plan(
    plan: FastZeroPlan,
    *,
    observe: ObserveSelected = _default_observe_selected,
) -> None:
    _validate_fast_zero_plan_receipt(plan)
    current = observe(plan.device)
    _validate_observation(current)
    if (
        current.device != plan.device
        or current.related_device_numbers != plan.related_device_numbers
        or current.disk_sequence != plan.disk_sequence
    ):
        raise FastZeroPlanError(
            "The selected target or its disk generation changed; rescan it"
        )


def confirm_fast_zero(
    plan: FastZeroPlan,
    phrase: str,
    *,
    observe: ObserveSelected = _default_observe_selected,
) -> ConfirmedFastZero:
    validate_fast_zero_plan(plan, observe=observe)
    if (
        type(phrase) is not str
        or not phrase.isascii()
        or not hmac.compare_digest(
            phrase.encode("ascii"),
            plan.confirmation_phrase.encode("ascii"),
        )
    ):
        raise FastZeroPlanError(
            "The destructive fast-zero confirmation phrase did not match exactly"
        )
    confirmation = ConfirmedFastZero(
        plan,
        plan.plan_sha256,
        plan.device.identity,
        plan.disk_sequence,
        plan.target_capacity,
        plan.logical_sector_size,
        plan.chunk_size,
        phrase,
    )
    object.__setattr__(
        confirmation,
        "_authorization",
        _ConfirmationReceipt(
            _CONFIRMATION_WITNESS,
            confirmation,
            plan,
            _confirmation_snapshot(confirmation),
        ),
    )
    return confirmation


def _validate_confirmation(
    plan: FastZeroPlan,
    confirmation: ConfirmedFastZero,
    *,
    observe: ObserveSelected | None,
) -> None:
    if observe is None:
        _validate_fast_zero_plan_receipt(plan)
    else:
        validate_fast_zero_plan(plan, observe=observe)
    if type(confirmation) is not ConfirmedFastZero:
        raise FastZeroPlanError("An exact fast-zero confirmation is required")
    receipt = confirmation._authorization
    if (
        type(receipt) is not _ConfirmationReceipt
        or receipt.token is not _CONFIRMATION_WITNESS
        or receipt.confirmation is not confirmation
        or receipt.plan is not plan
        or receipt.snapshot != _confirmation_snapshot(confirmation)
        or confirmation.plan is not plan
        or confirmation.plan_sha256 != plan.plan_sha256
        or confirmation.device_identity != plan.device.identity
        or confirmation.disk_sequence != plan.disk_sequence
        or confirmation.target_capacity != plan.target_capacity
        or confirmation.logical_sector_size != plan.logical_sector_size
        or confirmation.chunk_size != plan.chunk_size
        or confirmation.confirmation_phrase != plan.confirmation_phrase
    ):
        raise FastZeroPlanError(
            "The fast-zero confirmation is forged, cloned, or stale"
        )


def authorize_unmounted_fast_zero(
    plan: FastZeroPlan,
    confirmation: ConfirmedFastZero,
    *,
    observe_path: ObservePath = _default_observe_path,
    observe_selected: ObserveSelected = _default_observe_selected,
) -> ReadyFastZero:
    del observe_selected
    _validate_confirmation(plan, confirmation, observe=None)
    current = observe_path(plan.device.path)
    _validate_observation(current)
    if (
        not _post_unmount_matches(plan.device, current.device)
        or current.related_device_numbers != plan.related_device_numbers
        or current.disk_sequence != plan.disk_sequence
    ):
        raise FastZeroPlanError(
            "The target changed during unmounting or remains mounted"
        )
    candidate = ReadyFastZero(
        plan,
        confirmation,
        current,
        plan.plan_sha256,
        "",
    )
    ready = ReadyFastZero(
        candidate.plan,
        candidate.confirmation,
        candidate.observation,
        candidate.plan_sha256,
        _ready_digest(candidate),
    )
    object.__setattr__(
        ready,
        "_authorization",
        _ReadyReceipt(
            _READY_WITNESS,
            ready,
            plan,
            confirmation,
            current,
            _ready_snapshot(ready),
        ),
    )
    validate_ready_fast_zero(
        plan,
        confirmation,
        ready,
        observe_path=observe_path,
    )
    return ready


def validate_ready_fast_zero(
    plan: FastZeroPlan,
    confirmation: ConfirmedFastZero,
    ready: ReadyFastZero,
    *,
    observe_path: ObservePath = _default_observe_path,
    observe_selected: ObserveSelected = _default_observe_selected,
) -> None:
    del observe_selected
    _validate_confirmation(plan, confirmation, observe=None)
    if type(ready) is not ReadyFastZero:
        raise FastZeroPlanError("An exact post-unmount fast-zero receipt is required")
    receipt = ready._authorization
    if (
        type(receipt) is not _ReadyReceipt
        or receipt.token is not _READY_WITNESS
        or receipt.ready is not ready
        or receipt.plan is not plan
        or receipt.confirmation is not confirmation
        or receipt.observation is not ready.observation
        or receipt.snapshot != _ready_snapshot(ready)
        or ready.plan is not plan
        or ready.confirmation is not confirmation
        or ready.plan_sha256 != plan.plan_sha256
        or not hmac.compare_digest(_ready_digest(ready), ready.ready_sha256)
    ):
        raise FastZeroPlanError(
            "The post-unmount fast-zero receipt is forged, cloned, or stale"
        )
    current = observe_path(plan.device.path)
    _validate_observation(current)
    if (
        not _post_unmount_matches(plan.device, current.device)
        or current != ready.observation
        or current.related_device_numbers != plan.related_device_numbers
        or current.disk_sequence != plan.disk_sequence
    ):
        raise FastZeroPlanError(
            "The post-unmount target evidence changed before helper launch"
        )


def _trusted_file(path: str, *, executable: bool, setuid: bool = False) -> None:
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise FastZeroHelperUnavailable("A privileged helper path is not canonical")
    try:
        status = os.lstat(path)
    except OSError as error:
        raise FastZeroHelperUnavailable(
            f"Required fast-zero host integration is not installed: {path}",
        ) from error
    required = 0o500 if executable else 0o400
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != 0
        or status.st_mode & 0o022
        or stat.S_IMODE(status.st_mode) & required != required
        or (setuid and not status.st_mode & stat.S_ISUID)
        or os.path.realpath(path) != path
    ):
        raise FastZeroHelperUnavailable(
            f"Privileged fast-zero host integration has unsafe ownership or mode: {path}",
        )


def _trusted_parents(path: str) -> None:
    parent = os.path.dirname(path)
    while parent != "/":
        try:
            status = os.lstat(parent)
        except OSError as error:
            raise FastZeroHelperUnavailable(
                "A privileged fast-zero parent directory is unavailable",
            ) from error
        if (
            not stat.S_ISDIR(status.st_mode)
            or status.st_uid != 0
            or status.st_mode & 0o022
        ):
            raise FastZeroHelperUnavailable(
                f"A privileged fast-zero parent directory is unsafe: {parent}",
            )
        if parent == "/usr":
            return
        parent = os.path.dirname(parent)
    raise FastZeroHelperUnavailable(
        "Privileged fast-zero integration must be installed beneath /usr",
    )


def _validate_policy() -> None:
    _trusted_file(POLICY_PATH, executable=False)
    _trusted_parents(POLICY_PATH)
    try:
        root = ET.parse(POLICY_PATH).getroot()
    except (OSError, ET.ParseError) as error:
        raise FastZeroHelperUnavailable(
            "The fast-zero PolicyKit action is malformed",
        ) from error
    actions = root.findall("action") if root.tag == "policyconfig" else []
    if len(actions) != 1 or actions[0].attrib != {"id": POLICY_ACTION}:
        raise FastZeroHelperUnavailable(
            "The fast-zero PolicyKit action identity is invalid",
        )
    action = actions[0]
    descriptions = action.findall("description")
    messages = action.findall("message")
    defaults = action.findall("defaults")
    annotations = action.findall("annotate")
    if (
        len(descriptions) != 1
        or len(messages) != 1
        or len(defaults) != 1
        or len(annotations) != 2
        or len(list(action)) != 5
    ):
        raise FastZeroHelperUnavailable(
            "The fast-zero PolicyKit action is ambiguous",
        )
    if (
        descriptions[0].attrib
        or messages[0].attrib
        or list(descriptions[0])
        or list(messages[0])
        or (descriptions[0].text or "").strip() != POLICY_DESCRIPTION
        or (messages[0].text or "").strip() != POLICY_MESSAGE
    ):
        raise FastZeroHelperUnavailable(
            "The fast-zero PolicyKit prompt is misleading or invalid",
        )
    children = list(defaults[0])
    if (
        defaults[0].attrib
        or len(children) != 3
        or len({child.tag for child in children}) != 3
        or any(child.attrib or list(child) for child in children)
    ):
        raise FastZeroHelperUnavailable(
            "The fast-zero PolicyKit defaults are ambiguous",
        )
    values = {child.tag: (child.text or "").strip() for child in children}
    if (
        len({node.get("key") for node in annotations}) != 2
        or any(
            node.attrib != {"key": node.get("key")} or list(node)
            for node in annotations
        )
    ):
        raise FastZeroHelperUnavailable(
            "The fast-zero PolicyKit executable annotations are ambiguous",
        )
    annotation_values = {
        node.get("key"): (node.text or "").strip() for node in annotations
    }
    if (
        values
        != {
            "allow_any": "no",
            "allow_inactive": "no",
            "allow_active": "auth_admin",
        }
        or annotation_values
        != {
            "org.freedesktop.policykit.exec.path": HELPER_PATH,
            "org.freedesktop.policykit.exec.argv1": FAST_ZERO_OPERATION,
        }
    ):
        raise FastZeroHelperUnavailable(
            "The PolicyKit action is broader than the fast-zero protocol",
        )


def resolve_fast_zero_helper_installation() -> FastZeroHelperInstallation:
    """Require the exact root-owned helper and exact PolicyKit action."""

    if struct.calcsize("P") != 8:
        raise FastZeroHelperUnavailable(
            "The fast-zero helper requires 64-bit Linux userspace",
        )
    _trusted_file(PKEXEC_PATH, executable=True, setuid=True)
    _trusted_file(HELPER_PATH, executable=True)
    _trusted_file(HELPER_SCRIPT_PATH, executable=False)
    for path in (PKEXEC_PATH, HELPER_PATH, HELPER_SCRIPT_PATH):
        _trusted_parents(path)
    _validate_policy()
    return FastZeroHelperInstallation(
        PKEXEC_PATH,
        HELPER_PATH,
        HELPER_SCRIPT_PATH,
        POLICY_PATH,
    )


def _resolve_unmount_tools(which: Callable[[str], str | None]) -> WriterTools:
    resolved: dict[str, str] = {}
    for name in ("pkexec", "udisksctl", "lsblk"):
        value = which(name)
        if type(value) is not str:
            raise FastZeroHelperUnavailable(
                f"The fast-zero unmount workflow requires trusted {name}",
            )
        if (
            not os.path.isabs(value)
            or os.path.normpath(value) != value
            or os.path.dirname(value) not in _TRUSTED_TOOL_DIRECTORIES
            or os.path.basename(value) != name
        ):
            raise FastZeroHelperUnavailable(
                f"Refusing untrusted fast-zero tool path: {value!r}",
            )
        resolved[name] = value
    return WriterTools(
        pkexec=resolved["pkexec"],
        dd=_INERT_DD_PATH,
        udisksctl=resolved["udisksctl"],
        lsblk=resolved["lsblk"],
    )


def _bounded_diagnostic(value: bytes) -> str:
    if len(value) > MAX_DIAGNOSTIC_BYTES:
        raise FastZeroRunError(
            "The privileged fast-zero helper produced too much diagnostic output",
        )
    rendered = value.decode("utf-8", errors="replace").replace("\x00", "").strip()
    return rendered[-4_096:] or "The privileged fast-zero helper failed"


class FastZeroRunner:
    """One-shot coordinator for one authenticated target-only transaction."""

    def __init__(
        self,
        *,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        which: Callable[[str], str | None] = lambda name: shutil.which(
            name,
            path=_TRUSTED_TOOL_PATH,
        ),
        block_stat: Callable[[str], os.stat_result] = os.stat,
        request_id: Callable[[int], bytes] = secrets.token_bytes,
        clock: Callable[[], float] = time.monotonic,
        resolve_installation: Callable[[], FastZeroHelperInstallation]
        = resolve_fast_zero_helper_installation,
        observe_selected: ObserveSelected = _default_observe_selected,
        observe_path: ObservePath = _default_observe_path,
    ) -> None:
        self._popen = popen
        self._command_runner = command_runner
        self._which = which
        self._block_stat = block_stat
        self._request_id = request_id
        self._clock = clock
        self._resolve_installation = resolve_installation
        self._observe_selected = observe_selected
        self._observe_path = observe_path
        self._used = False
        self._cancelled = threading.Event()
        self._lock = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self._channel: socket.socket | None = None
        self._request_sent = False
        self._commit_sent = False
        self._cancel_sent = False
        self._request_identifier = b""
        self._control_error: FastZeroRunError | None = None

    def cancel(self) -> None:
        """Request cancellation without killing a possibly committed helper."""

        with self._lock:
            self._cancelled.set()
            process = self._process
            if process is None or process.poll() is not None:
                return
            if not self._request_sent:
                try:
                    process.terminate()
                except OSError:
                    pass
                return
            if self._cancel_sent:
                return
            channel = self._channel
            request_id = self._request_identifier
            if channel is None or len(request_id) != 16:
                return
            try:
                self._send_control(channel, request_id, commit=False)
            except FastZeroRunError as error:
                self._control_error = error
            else:
                self._cancel_sent = True

    def _check_precommit_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise FastZeroCancelled("Fast zero was cancelled before mutation")

    @staticmethod
    def _safe_progress(
        callback: FastZeroProgress,
        phase: str,
        done: int,
        total: int,
    ) -> None:
        try:
            callback(phase, done, total)
        except Exception:
            logger.exception("Ignoring a fast-zero progress callback failure")

    def _stop_and_reap(
        self,
        process: subprocess.Popen[bytes],
        *,
        safe_to_kill: bool,
    ) -> None:
        if process.poll() is not None:
            return
        if not safe_to_kill:
            # A committed helper can still be writing or performing its
            # identity-gated cleanup. Keep the GUI operation owner alive until
            # that privileged process is actually gone; releasing it here would
            # also release the close, refresh, and second-operation interlocks.
            # Continue draining helper-to-client packets as well: abandoning a
            # live SEQPACKET receive queue could block the helper before it can
            # finish and exit.
            channel = self._channel
            while process.poll() is None:
                if channel is not None:
                    try:
                        readable, _, _ = select.select([channel], [], [], 0.25)
                    except (OSError, ValueError):
                        channel = None
                        continue
                    if readable:
                        try:
                            packet, _ancillary, _flags, _address = channel.recvmsg(
                                MAX_PROTOCOL_PACKET + 1,
                                1,
                                socket.MSG_DONTWAIT,
                            )
                        except BlockingIOError:
                            continue
                        except (OSError, ValueError):
                            channel = None
                            continue
                        if not packet:
                            channel = None
                        continue
                try:
                    process.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    continue
                except OSError:
                    if process.poll() is not None:
                        break
                    time.sleep(0.25)
            return
        try:
            process.terminate()
            process.wait(timeout=2)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            process.kill()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            if process.poll() is None:
                threading.Thread(
                    target=process.wait,
                    name="isopropyl-fast-zero-helper-reaper",
                    daemon=True,
                ).start()

    @staticmethod
    def _send_control(
        channel: socket.socket,
        request_id: bytes,
        *,
        commit: bool,
    ) -> None:
        try:
            packet = pack_fast_zero_helper_control(request_id, commit=commit)
            count = channel.send(packet, socket.MSG_DONTWAIT)
        except (HelperRequestError, OSError) as error:
            label = "COMMIT" if commit else "CANCEL"
            raise FastZeroRunError(
                f"Could not send authenticated fast-zero {label}",
            ) from error
        if count != len(packet):
            raise FastZeroRunError(
                "The fast-zero control packet was not sent atomically",
            )

    def _decide_prepared(self, channel: socket.socket, request_id: bytes) -> None:
        with self._lock:
            if self._commit_sent or self._cancel_sent:
                raise FastZeroRunError(
                    "The fast-zero helper requested a repeated decision",
                )
            commit = not self._cancelled.is_set()
            self._send_control(channel, request_id, commit=commit)
            if commit:
                self._commit_sent = True
            else:
                self._cancel_sent = True

    def _receive_packet(
        self,
        channel: socket.socket,
        process: subprocess.Popen[bytes],
        *,
        request_sent: bool,
    ) -> bytes | None:
        deadline = self._clock() + HELPER_STALL_TIMEOUT_SECONDS
        while True:
            with self._lock:
                control_error = self._control_error
                cancelled = self._cancelled.is_set()
                committed = self._commit_sent
                cancel_sent = self._cancel_sent
            if control_error is not None:
                raise control_error
            if cancelled and request_sent and not cancel_sent:
                with self._lock:
                    if not self._cancel_sent and self._channel is not None:
                        self._send_control(
                            self._channel,
                            self._request_identifier,
                            commit=False,
                        )
                        self._cancel_sent = True
            readable, _, _ = select.select([channel], [], [], 0.1)
            if readable:
                packet, ancillary, flags, _address = channel.recvmsg(
                    MAX_PROTOCOL_PACKET + 1,
                    1,
                )
                if ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                    raise FastZeroRunError(
                        "The fast-zero helper returned invalid ancillary data",
                    )
                if len(packet) > MAX_PROTOCOL_PACKET:
                    raise FastZeroRunError(
                        "The fast-zero helper returned an oversized packet",
                    )
                return packet or None
            if process.poll() is not None:
                return None
            if self._clock() >= deadline:
                if not request_sent:
                    self._stop_and_reap(process, safe_to_kill=True)
                    raise FastZeroRunError(
                        "The fast-zero helper handshake timed out",
                    )
                if not committed:
                    if cancelled:
                        raise FastZeroCancelled(
                            "Fast zero was cancelled before mutation",
                        )
                    raise FastZeroRunError(
                        "The helper stopped before COMMIT; no mutation was authorized",
                    )
                raise FastZeroRunError(
                    "The committed helper stopped reporting; target state is unknown",
                )
            if cancelled and not request_sent:
                self._stop_and_reap(process, safe_to_kill=True)

    @staticmethod
    def _decode(packet: bytes) -> tuple[object, ...]:
        try:
            return unpack_fast_zero_server_packet(packet)
        except HelperRequestError as error:
            raise FastZeroRunError(str(error)) from error

    @staticmethod
    def _expected_cleanup_bytes(plan: FastZeroPlan) -> int:
        return min(plan.target_capacity, 2 * FAST_ZERO_BOUNDARY_BYTES)

    @staticmethod
    def _valid_classified_chunk_bytes(
        classified_bytes: int,
        classified_chunks: int,
        *,
        scanned_bytes: int,
        chunk_size: int,
    ) -> bool:
        full_chunks, tail = divmod(scanned_bytes, chunk_size)
        if not tail:
            return classified_bytes == classified_chunks * chunk_size
        without_tail = (
            classified_chunks <= full_chunks
            and classified_bytes == classified_chunks * chunk_size
        )
        with_tail = (
            classified_chunks >= 1
            and classified_chunks - 1 <= full_chunks
            and classified_bytes
            == (classified_chunks - 1) * chunk_size + tail
        )
        return without_tail or with_tail

    @staticmethod
    def _validate_accounting(
        terminal: tuple[object, ...],
        *,
        plan: FastZeroPlan,
        ready: ReadyFastZero,
        request_id: bytes,
        major: int,
        minor: int,
        mutation_started: bool,
        progress: dict[str, int],
    ) -> tuple[str, dict[str, object]]:
        if len(terminal) != 22:
            raise FastZeroRunError("The fast-zero terminal result is malformed")
        (
            outcome,
            observed_id,
            observed_major,
            observed_minor,
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
            exclusive_open,
            cache_invalidated,
            complete,
            cleanup_verified,
            durable,
        ) = terminal
        numeric = (
            scanned_bytes,
            written_bytes,
            skipped_bytes,
            verified_bytes,
            scanned_chunks,
            written_chunks,
            skipped_chunks,
            cleanup_bytes,
            failure_code,
        )
        if (
            type(outcome) is not str
            or observed_id != request_id
            or observed_major != major
            or observed_minor != minor
            or disk_sequence != ready.observation.disk_sequence
            or target_size != plan.target_capacity
            or sector_size != plan.logical_sector_size
            or chunk_size != plan.chunk_size
            or not mutation_started
            or any(type(value) is not int or isinstance(value, bool) for value in numeric)
            or any(value < 0 for value in numeric)
            or scanned_bytes != written_bytes + skipped_bytes
            or scanned_chunks != written_chunks + skipped_chunks
            or scanned_bytes > plan.target_capacity
            or verified_bytes > plan.target_capacity
            or scanned_chunks
            != (
                (scanned_bytes + plan.chunk_size - 1) // plan.chunk_size
                if scanned_bytes
                else 0
            )
            or not FastZeroRunner._valid_classified_chunk_bytes(
                written_bytes,
                written_chunks,
                scanned_bytes=scanned_bytes,
                chunk_size=plan.chunk_size,
            )
            or not FastZeroRunner._valid_classified_chunk_bytes(
                skipped_bytes,
                skipped_chunks,
                scanned_bytes=scanned_bytes,
                chunk_size=plan.chunk_size,
            )
            or progress.get("scanning", 0) != scanned_bytes
            or progress.get("readback", 0) != verified_bytes
            or exclusive_open is not True
            or cache_invalidated is not True
            or durable is not True
        ):
            raise FastZeroRunError(
                "The helper result does not match the authorized target/accounting",
            )
        if outcome == "success":
            if (
                complete is not True
                or cleanup_verified is not False
                or cleanup_bytes != 0
                or failure_code != FAST_ZERO_FAILURE_NONE
                or scanned_bytes != plan.target_capacity
                or verified_bytes != plan.target_capacity
                or progress.get("scanning") != plan.target_capacity
                or progress.get("readback") != plan.target_capacity
                or "cleanup" in progress
            ):
                raise FastZeroRunError(
                    "The helper claimed success without complete zero verification",
                )
        elif outcome in {"partial-cancel", "partial-failure"}:
            if (
                complete is not False
                or cleanup_verified is not True
                or cleanup_bytes != FastZeroRunner._expected_cleanup_bytes(plan)
                or progress.get("cleanup") != cleanup_bytes
                or failure_code == FAST_ZERO_FAILURE_NONE
                or (outcome == "partial-cancel")
                is not (failure_code == FAST_ZERO_FAILURE_CANCELLED)
            ):
                raise FastZeroRunError(
                    "The helper partial result lacks exact durable cleanup evidence",
                )
        else:
            raise FastZeroRunError("The helper terminal outcome is unsupported")
        values = {
            "scanned_bytes": scanned_bytes,
            "written_bytes": written_bytes,
            "skipped_bytes": skipped_bytes,
            "verified_bytes": verified_bytes,
            "scanned_chunks": scanned_chunks,
            "written_chunks": written_chunks,
            "skipped_chunks": skipped_chunks,
            "boundary_cleanup_bytes": cleanup_bytes,
            "failure_code": failure_code,
            "exclusive_open": exclusive_open,
            "cache_invalidated": cache_invalidated,
            "complete": complete,
            "cleanup_verified": cleanup_verified,
            "cleanup_durable": durable,
        }
        return outcome, values

    def _invoke_helper(
        self,
        installation: FastZeroHelperInstallation,
        plan: FastZeroPlan,
        ready: ReadyFastZero,
        progress_callback: FastZeroProgress,
    ) -> FastZeroResult:
        self._check_precommit_cancelled()
        request_id = self._request_id(16)
        if type(request_id) is not bytes or len(request_id) != 16:
            raise FastZeroRunError("The fast-zero request identifier is invalid")
        major, minor = (
            int(part) for part in ready.observation.device.major_minor.split(":", 1)
        )
        try:
            request_packet = pack_fast_zero_helper_request(
                request_id,
                major,
                minor,
                ready.observation.disk_sequence,
                plan.target_capacity,
                plan.logical_sector_size,
                plan.chunk_size,
                plan.plan_sha256,
                ready.ready_sha256,
            )
        except HelperRequestError as error:
            raise FastZeroRunError(str(error)) from error
        parent, child = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET | getattr(socket, "SOCK_CLOEXEC", 0),
        )
        process: subprocess.Popen[bytes] | None = None
        request_sent = False
        prepared_seen = False
        mutation_started = False
        terminal: tuple[object, ...] | None = None
        phase_order = {"scanning": 0, "readback": 1, "cleanup": 2}
        current_phase = -1
        phase_progress: dict[str, int] = {}
        try:
            try:
                process = self._popen(
                    [
                        installation.pkexec,
                        "--disable-internal-agent",
                        installation.helper,
                        FAST_ZERO_OPERATION,
                    ],
                    stdin=child.fileno(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    shell=False,
                )
            except OSError as error:
                raise FastZeroRunError(
                    "Could not start the privileged fast-zero helper",
                ) from error
            with self._lock:
                self._process = process
                self._channel = parent
                self._request_identifier = request_id
            child.close()
            child = None  # type: ignore[assignment]
            first = self._receive_packet(parent, process, request_sent=False)
            if first is None or self._decode(first) != ("ready",):
                if self._cancelled.is_set():
                    raise FastZeroCancelled(
                        "Fast zero was cancelled before mutation",
                    )
                raise FastZeroRunError("The fast-zero helper handshake is invalid")
            with self._lock:
                if self._cancelled.is_set():
                    raise FastZeroCancelled(
                        "Fast zero was cancelled before mutation",
                    )
                try:
                    count = parent.send(request_packet, socket.MSG_DONTWAIT)
                except OSError as error:
                    raise FastZeroRunError(
                        "Could not send the authenticated fast-zero request",
                    ) from error
                if count != len(request_packet):
                    raise FastZeroRunError(
                        "The fast-zero request was not sent atomically",
                    )
                self._request_sent = True
                request_sent = True
            while terminal is None:
                packet = self._receive_packet(parent, process, request_sent=True)
                if packet is None:
                    break
                decoded = self._decode(packet)
                kind = decoded[0] if decoded else None
                if kind == "prepared":
                    if (
                        prepared_seen
                        or mutation_started
                        or decoded != ("prepared", request_id)
                    ):
                        raise FastZeroRunError(
                            "The helper PREPARED boundary is invalid",
                        )
                    prepared_seen = True
                    with self._lock:
                        cancellation_already_sent = self._cancel_sent
                    if not cancellation_already_sent:
                        self._decide_prepared(parent, request_id)
                    continue
                if kind == "mutation-started":
                    if (
                        mutation_started
                        or decoded != ("mutation-started", request_id)
                        or not prepared_seen
                        or not self._commit_sent
                    ):
                        raise FastZeroRunError(
                            "The helper mutation boundary is invalid",
                        )
                    mutation_started = True
                    continue
                if kind == "progress":
                    _, observed_id, phase, done, total = decoded
                    index = phase_order.get(phase) if type(phase) is str else None
                    expected_total = (
                        self._expected_cleanup_bytes(plan)
                        if phase == "cleanup"
                        else plan.target_capacity
                    )
                    if (
                        observed_id != request_id
                        or not mutation_started
                        or index is None
                        or index < current_phase
                        or total != expected_total
                        or type(done) is not int
                        or isinstance(done, bool)
                        or done < 0
                        or done > total
                        or (phase in phase_progress and done <= phase_progress[phase])
                        or (phase == "readback" and phase_progress.get("scanning") != plan.target_capacity)
                        or (phase == "cleanup" and terminal is not None)
                    ):
                        raise FastZeroRunError(
                            "The helper progress sequence is invalid",
                        )
                    current_phase = index
                    phase_progress[phase] = done
                    self._safe_progress(progress_callback, phase, done, total)
                    continue
                if kind not in {"success", "partial-cancel", "partial-failure"}:
                    raise FastZeroRunError(
                        "The fast-zero helper protocol is out of order",
                    )
                terminal = decoded
            try:
                code = process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                with self._lock:
                    committed = self._commit_sent
                self._stop_and_reap(
                    process,
                    safe_to_kill=terminal is not None or not committed,
                )
                raise FastZeroRunError(
                    "The helper did not exit after its terminal result",
                )
            if terminal is not None:
                readable, _, _ = select.select([parent], [], [], 0.5)
                if not readable:
                    raise FastZeroRunError(
                        "The helper left its protocol channel open",
                    )
                trailing, ancillary, flags, _address = parent.recvmsg(
                    MAX_PROTOCOL_PACKET + 1,
                    1,
                )
                if trailing or ancillary or flags:
                    raise FastZeroRunError(
                        "The helper emitted data after its terminal result",
                    )
            diagnostic = b""
            if process.stderr is not None:
                diagnostic = process.stderr.read(MAX_DIAGNOSTIC_BYTES + 1)
            if code or terminal is None:
                if (
                    self._cancelled.is_set()
                    and not self._commit_sent
                    and terminal is None
                    and not diagnostic
                ):
                    raise FastZeroCancelled(
                        "Fast zero was cancelled before mutation",
                    )
                raise FastZeroRunError(_bounded_diagnostic(diagnostic))
            if diagnostic:
                raise FastZeroRunError(
                    "The successful fast-zero protocol emitted diagnostics",
                )
            outcome, values = self._validate_accounting(
                terminal,
                plan=plan,
                ready=ready,
                request_id=request_id,
                major=major,
                minor=minor,
                mutation_started=mutation_started,
                progress=phase_progress,
            )
            common = {
                "request_id": request_id.hex(),
                "plan_sha256": plan.plan_sha256,
                "ready_sha256": ready.ready_sha256,
                "target_path": ready.observation.device.path,
                "major_minor": ready.observation.device.major_minor,
                "disk_sequence": ready.observation.disk_sequence,
                "target_capacity": plan.target_capacity,
                "logical_sector_size": plan.logical_sector_size,
                "chunk_size": plan.chunk_size,
                **values,
            }
            failure_code = common.pop("failure_code")
            if outcome == "success":
                return FastZeroResult(
                    **common,
                    cancellation_deferred=self._cancelled.is_set(),
                )
            partial_values = dict(common)
            partial = FastZeroPartialResult(**partial_values)
            if outcome == "partial-cancel":
                raise FastZeroCancelled(
                    "Fast zero stopped after verified boundary cleanup",
                    partial=partial,
                )
            failed = FastZeroPartialFailure(
                **partial_values,
                failure_code=failure_code,
            )
            raise FastZeroRunError(
                "Fast zero failed after verified boundary cleanup",
                partial=failed,
            )
        finally:
            with self._lock:
                committed = self._commit_sent
            if process is not None and process.poll() is None:
                self._stop_and_reap(
                    process,
                    safe_to_kill=terminal is not None or not committed,
                )
            with self._lock:
                self._process = None
                self._channel = None
            try:
                parent.close()
            except OSError:
                pass
            if child is not None:
                try:
                    child.close()
                except OSError:
                    pass

    def run(
        self,
        plan: FastZeroPlan,
        confirmation: ConfirmedFastZero,
        progress: FastZeroProgress = lambda _stage, _done, _total: None,
    ) -> FastZeroResult:
        """Revalidate, unmount, authorize, and execute exactly once."""

        if self._used:
            raise FastZeroRunError("A fast-zero runner can only be used once")
        self._used = True
        self._check_precommit_cancelled()
        try:
            _validate_confirmation(
                plan,
                confirmation,
                observe=self._observe_selected,
            )
            installation = self._resolve_installation()
            tools = _resolve_unmount_tools(self._which)
            if tools.pkexec != installation.pkexec:
                raise FastZeroHelperUnavailable(
                    "Unmounting and helper launch resolved different pkexec binaries",
                )
            self._check_precommit_cancelled()
            _validate_confirmation(
                plan,
                confirmation,
                observe=self._observe_selected,
            )
            unmount_device(
                plan.device,
                writable=True,
                tools=tools,
                runner=self._command_runner,
                stat_func=self._block_stat,
                cancel_check=self._check_precommit_cancelled,
            )
            ready = authorize_unmounted_fast_zero(
                plan,
                confirmation,
                observe_path=self._observe_path,
            )
            validate_ready_fast_zero(
                plan,
                confirmation,
                ready,
                observe_path=self._observe_path,
            )
            self._check_precommit_cancelled()
            return self._invoke_helper(
                installation,
                plan,
                ready,
                progress,
            )
        except (FastZeroError, FastZeroPlanError):
            raise
        except WriterError as error:
            raise FastZeroRunError(str(error)) from error


@dataclass(frozen=True)
class FastZeroDependencies:
    """Injectable non-GUI system boundary for deterministic workflow tests."""

    resolve_helper: Callable[[], object] = resolve_fast_zero_helper_installation
    build_plan: Callable[..., FastZeroPlan] = build_fast_zero_plan
    confirm_plan: Callable[..., ConfirmedFastZero] = confirm_fast_zero
    runner_factory: Callable[[], FastZeroRunner] = FastZeroRunner


class FastZeroWorkflow:
    """Single lifecycle owner for a strict target-only fast-zero operation."""

    def __init__(
        self,
        device: Device,
        *,
        size_unit_mode: SizeUnitMode = SizeUnitMode.SI,
        dependencies: FastZeroDependencies = FastZeroDependencies(),
    ) -> None:
        if type(device) is not Device:
            raise FastZeroPlanError("An exact discovered Device is required")
        if type(size_unit_mode) is not SizeUnitMode:
            raise FastZeroPlanError("The fast-zero size-unit mode is invalid")
        if type(dependencies) is not FastZeroDependencies:
            raise FastZeroPlanError("Fast-zero workflow dependencies are invalid")
        self.device = device
        self.size_unit_mode = size_unit_mode
        self.dependencies = dependencies
        self._lock = threading.RLock()
        self._cancelled = threading.Event()
        self._state = FastZeroState.CREATED
        self._close_requested = False
        self._plan: FastZeroPlan | None = None
        self._confirmation: ConfirmedFastZero | None = None
        self._runner: FastZeroRunner | None = None
        self._result: FastZeroResult | None = None
        self._partial_result: FastZeroPartialResult | None = None

    @property
    def state(self) -> FastZeroState:
        with self._lock:
            return self._state

    @property
    def plan(self) -> FastZeroPlan | None:
        with self._lock:
            return self._plan

    @property
    def confirmation(self) -> ConfirmedFastZero | None:
        with self._lock:
            return self._confirmation

    @property
    def result(self) -> FastZeroResult | None:
        with self._lock:
            return self._result

    @property
    def partial_result(self) -> FastZeroPartialResult | None:
        with self._lock:
            return self._partial_result

    def _check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise FastZeroCancelled("The fast-zero workflow was cancelled")

    def prepare(self) -> FastZeroPlan:
        with self._lock:
            if self._state is not FastZeroState.CREATED:
                raise FastZeroPlanError(
                    "A fast-zero workflow can only be prepared once",
                )
            self._state = FastZeroState.PREPARING
        try:
            self._check_cancelled()
            # Fail before presenting a confirmation or doing target work when
            # the exact native-host integration is absent or unsafe.
            self.dependencies.resolve_helper()
            self._check_cancelled()
            plan = self.dependencies.build_plan(
                self.device,
                size_unit_mode=self.size_unit_mode,
            )
            self._check_cancelled()
            with self._lock:
                if (
                    self._state is not FastZeroState.PREPARING
                    or self._close_requested
                    or self._cancelled.is_set()
                ):
                    raise FastZeroCancelled(
                        "The fast-zero workflow was closed"
                        if self._close_requested
                        else "The fast-zero workflow was cancelled",
                    )
                self._plan = plan
                self._state = FastZeroState.PREPARED
            return plan
        except BaseException:
            with self._lock:
                self._state = (
                    FastZeroState.CLOSED
                    if self._close_requested
                    else (
                        FastZeroState.CANCELLED
                        if self._cancelled.is_set()
                        else FastZeroState.FAILED
                    )
                )
            raise

    def confirm(self, phrase: str) -> ConfirmedFastZero:
        with self._lock:
            plan = self._plan
            if self._state is not FastZeroState.PREPARED or plan is None:
                raise FastZeroPlanError(
                    "The fast-zero workflow is not ready for confirmation",
                )
            if type(phrase) is not str or phrase != plan.confirmation_phrase:
                raise FastZeroPlanError(
                    "The destructive fast-zero confirmation phrase did not match exactly",
                )
        try:
            self._check_cancelled()
            confirmation = self.dependencies.confirm_plan(plan, phrase)
            self._check_cancelled()
            with self._lock:
                if self._state is not FastZeroState.PREPARED:
                    raise FastZeroCancelled(
                        "The fast-zero workflow was cancelled",
                    )
                self._confirmation = confirmation
                self._state = FastZeroState.CONFIRMED
            return confirmation
        except BaseException:
            with self._lock:
                self._state = (
                    FastZeroState.CLOSED
                    if self._close_requested
                    else (
                        FastZeroState.CANCELLED
                        if self._cancelled.is_set()
                        else FastZeroState.FAILED
                    )
                )
            raise

    def execute(
        self,
        progress: FastZeroProgress = lambda _stage, _done, _total: None,
    ) -> FastZeroResult:
        with self._lock:
            if (
                self._state is not FastZeroState.CONFIRMED
                or self._plan is None
                or self._confirmation is None
            ):
                raise FastZeroPlanError(
                    "Fast zero requires exact confirmation before execution",
                )
            runner = self.dependencies.runner_factory()
            self._runner = runner
            self._state = FastZeroState.EXECUTING
            plan = self._plan
            confirmation = self._confirmation
        try:
            result = runner.run(plan, confirmation, progress)
        except FastZeroCancelled as error:
            with self._lock:
                self._partial_result = error.partial
                self._state = (
                    FastZeroState.CLOSED
                    if self._close_requested
                    else (
                        FastZeroState.PARTIAL_CANCELLED
                        if error.partial is not None
                        else FastZeroState.CANCELLED
                    )
                )
            raise
        except BaseException as error:
            with self._lock:
                if isinstance(error, FastZeroRunError):
                    self._partial_result = error.partial
                self._state = (
                    FastZeroState.CLOSED
                    if self._close_requested
                    else FastZeroState.FAILED
                )
            raise
        with self._lock:
            self._result = result
            self._state = (
                FastZeroState.CLOSED
                if self._close_requested
                else FastZeroState.COMPLETED
            )
        return result

    def cancel(self) -> None:
        self._cancelled.set()
        with self._lock:
            runner = self._runner
            immediate = self._state in {
                FastZeroState.CREATED,
                FastZeroState.PREPARED,
                FastZeroState.CONFIRMED,
            }
            if immediate:
                self._state = (
                    FastZeroState.CLOSED
                    if self._close_requested
                    else FastZeroState.CANCELLED
                )
        if runner is not None:
            try:
                runner.cancel()
            except Exception:
                logger.exception("Could not signal fast-zero cancellation")

    def close(self) -> None:
        with self._lock:
            if self._state is FastZeroState.CLOSED:
                return
            self._close_requested = True
            active = self._state in {
                FastZeroState.PREPARING,
                FastZeroState.EXECUTING,
            }
        if active:
            self.cancel()
            return
        with self._lock:
            self._state = FastZeroState.CLOSED

    def __enter__(self) -> FastZeroWorkflow:
        if self.state is FastZeroState.CLOSED:
            raise FastZeroPlanError("The fast-zero workflow is closed")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
