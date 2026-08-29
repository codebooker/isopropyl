from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""One-shot unprivileged owner for verified-zero restore transactions.

The workflow is the only supported bridge from a normal formatting
``FormatPlan`` to the isolated restore-device PolicyKit endpoint.  It performs
no target I/O itself and deliberately has no ``FormatExecutor`` or shell
fallback.  Process-local receipts prevent callers from cloning or cross-wiring
the prepared intent and typed confirmation before the root helper establishes
its independent PREPARED boundary.
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from . import raw_device
from .devices import Device
from .formatting import (
    Filesystem,
    FormatPlan,
    validate_device,
    validate_plan as validate_format_plan,
)
from .restore_device_helper import (
    FilesystemReceipt,
    RestoreDeviceRequest,
    build_restore_device_request,
    validate_filesystem_receipt,
    validate_restore_device_request,
)
from .restore_device_runner import (
    RestoreDeviceHelperUnavailable,
    RestoreDeviceRunCancelled,
    RestoreDeviceRunError,
    RestoreDeviceRunResult,
    RestoreDeviceRunner,
    resolve_restore_device_installation,
)


RESTORE_WORKFLOW_PROFILE = "io.github.codebooker.isopropyl/restore-workflow/v1"
SUPPORTED_FILESYSTEMS = frozenset({Filesystem.FAT32, Filesystem.NTFS})
SUPPORTED_LOGICAL_SECTORS = frozenset({512, 1024, 2048, 4096})
_PLAN_TOKEN = object()
_CONFIRMATION_TOKEN = object()
_PLAN_DIGEST_BYTES = 32
_REQUEST_ID_BYTES = 16
_MAJOR_MINOR = re.compile(r"(?:0|[1-9]\d*):(?:0|[1-9]\d*)\Z")

logger = logging.getLogger("isopropyl")


class RestoreWorkflowError(RuntimeError):
    """The verified restore workflow could not continue safely."""


class RestoreWorkflowCancelled(RestoreWorkflowError):
    """The verified restore was cancelled before its irreversible boundary."""


class RestoreWorkflowState(str, Enum):
    CREATED = "created"
    PREPARED = "prepared"
    CONFIRMED = "confirmed"
    EXECUTING = "executing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    CLOSED = "closed"


@dataclass(frozen=True)
class RestoreTargetObservation:
    """Fresh unprivileged target evidence derived through ``raw_device``."""

    device: Device
    related_device_numbers: frozenset[int]
    disk_sequence: int


@dataclass(frozen=True)
class _PlanReceipt:
    token: object
    plan: object
    device: object
    format_plan: object
    request: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class _ConfirmationReceipt:
    token: object
    confirmation: object
    plan: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class RestoreWorkflowPlan:
    """Exact non-privileged authorization for one full zero and format."""

    device: Device
    format_plan: FormatPlan
    observation: RestoreTargetObservation
    request: RestoreDeviceRequest
    stable_identity_digest: str
    confirmation_phrase: str
    plan_sha256: str
    _authorization: _PlanReceipt | None = field(
        init=False,
        default=None,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class ConfirmedRestoreWorkflow:
    """Typed consent bound to one authoritative workflow plan."""

    plan: RestoreWorkflowPlan = field(repr=False, compare=False)
    plan_sha256: str
    request_id: bytes
    device_identity: tuple[str, int, str, str, str, str]
    confirmation_phrase: str
    confirmation_sha256: str
    _authorization: _ConfirmationReceipt | None = field(
        init=False,
        default=None,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class RestoreWorkflowResult:
    """Validated terminal receipt returned by the sole privileged runner."""

    plan_sha256: str
    device_identity: tuple[str, int, str, str, str, str]
    request_id: bytes
    target_major_minor: str
    partition_major_minor: str
    disk_sequence: int
    capacity: int
    partition_start_sector: int
    partition_sector_count: int
    scanned_bytes: int
    written_bytes: int
    skipped_bytes: int
    verified_bytes: int
    logical_sector_size: int
    filesystem: str
    sectors_per_cluster: int
    cluster_size: int
    normalized_label: str
    metadata_sha256: bytes
    filesystem_receipt_sha256: bytes
    cancellation_deferred: bool


ObserveTarget = Callable[[Device], RestoreTargetObservation]
Progress = Callable[[str, int, int], None]


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


def _format_payload(plan: FormatPlan) -> dict[str, object]:
    return {
        "device_path": plan.device_path,
        "device_identity": list(plan.device_identity),
        "filesystem": plan.filesystem.value,
        "partition_table": plan.partition_table.value,
        "label": plan.label,
        "allocation_unit_size": plan.allocation_unit_size,
    }


def _stable_identity(device: Device) -> str:
    stable_id = device.stable_id
    if type(stable_id) is not str or not stable_id:
        raise RestoreWorkflowError(
            "Verified zero + format requires a target with a stable serial or WWN",
        )
    return hashlib.sha256(
        (RESTORE_WORKFLOW_PROFILE + "\0" + stable_id).encode("utf-8"),
    ).hexdigest()[:16].upper()


def _confirmation_phrase(device: Device, stable_digest: str) -> str:
    return (
        f"ERASE FORMAT {device.path} {device.size} "
        f"ID-{stable_digest}"
    )


def _observe_target(device: Device) -> RestoreTargetObservation:
    """Reuse the raw broker's bounded block-node/topology/diskseq probes."""

    try:
        status = raw_device._validate_target_node(device)
        live = raw_device._validate_live_target(device, status)
        sequence = raw_device._read_disk_sequence(device.major_minor)
    except raw_device.RawDevicePlanError as error:
        raise RestoreWorkflowError(str(error)) from error
    return RestoreTargetObservation(
        # ``_validate_live_target`` has already proved equality to this exact
        # discovery record.  Preserve the caller-owned object so receipts can
        # reject otherwise equal cross-wired Device clones.
        device,
        live.related_device_numbers,
        sequence,
    )


def _validate_device_and_format(device: Device, plan: FormatPlan) -> None:
    if type(device) is not Device:
        raise RestoreWorkflowError("An exact discovered Device is required")
    if type(plan) is not FormatPlan:
        raise RestoreWorkflowError("An exact formatting FormatPlan is required")
    try:
        validate_device(device)
        validate_format_plan(plan)
    except (TypeError, ValueError) as error:
        raise RestoreWorkflowError(str(error)) from error
    if (
        device.removable is not True
        or device.transport not in {"usb", "mmc"}
        or device.read_only is not False
    ):
        raise RestoreWorkflowError(
            "Verified zero + format is restricted to removable USB or SD/MMC media",
        )
    if device.mountpoints:
        raise RestoreWorkflowError(
            "Unmount every filesystem on the selected target before verified restore",
        )
    if plan.device_path != device.path or plan.device_identity != device.identity:
        raise RestoreWorkflowError(
            "The formatting plan is not bound to the exact selected target",
        )
    if plan.filesystem not in SUPPORTED_FILESYSTEMS:
        raise RestoreWorkflowError(
            "Verified zero + format currently supports only FAT32 and NTFS",
        )
    if device.logical_sector_size not in SUPPORTED_LOGICAL_SECTORS:
        raise RestoreWorkflowError(
            "The selected target has an unsupported or unknown logical sector size",
        )
    if device.size % device.logical_sector_size:
        raise RestoreWorkflowError(
            "The selected target capacity is not logical-sector aligned",
        )
    _stable_identity(device)


def _validate_observation(
    observation: RestoreTargetObservation,
    device: Device,
) -> None:
    try:
        major, minor = (int(item) for item in device.major_minor.split(":", 1))
        device_number = os.makedev(major, minor)
    except (OverflowError, TypeError, ValueError) as error:
        raise RestoreWorkflowError("The target kernel identity is malformed") from error
    if (
        type(observation) is not RestoreTargetObservation
        or observation.device is not device
        or type(observation.related_device_numbers) is not frozenset
        or not observation.related_device_numbers
        or any(type(item) is not int for item in observation.related_device_numbers)
        or any(item < 0 for item in observation.related_device_numbers)
        or device_number not in observation.related_device_numbers
        or type(observation.disk_sequence) is not int
        or isinstance(observation.disk_sequence, bool)
        or not 0 < observation.disk_sequence <= 0xFFFFFFFFFFFFFFFF
    ):
        raise RestoreWorkflowError(
            "Fresh target topology or disk-generation evidence is invalid",
        )


def _plan_digest(plan: RestoreWorkflowPlan) -> str:
    try:
        encoded = json.dumps(
            {
                "profile": RESTORE_WORKFLOW_PROFILE,
                "device": _device_payload(plan.device),
                "format": _format_payload(plan.format_plan),
                "related_device_numbers": sorted(
                    plan.observation.related_device_numbers,
                ),
                "disk_sequence": plan.observation.disk_sequence,
                "request_id": plan.request.request_id.hex(),
                "request_plan_sha256": plan.request.plan_sha256.hex(),
                "partition_start_sector": plan.request.partition_start_sector,
                "partition_sector_count": plan.request.partition_sector_count,
                "stable_identity_digest": plan.stable_identity_digest,
                "confirmation_phrase": plan.confirmation_phrase,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return ""
    return hashlib.sha256(encoded).hexdigest()


def _plan_snapshot(plan: RestoreWorkflowPlan) -> tuple[object, ...]:
    return (
        plan.device,
        plan.format_plan,
        plan.observation,
        plan.request,
        plan.stable_identity_digest,
        plan.confirmation_phrase,
        plan.plan_sha256,
    )


def _confirmation_digest(confirmation: ConfirmedRestoreWorkflow) -> str:
    try:
        encoded = json.dumps(
            {
                "profile": RESTORE_WORKFLOW_PROFILE + "/confirmation",
                "plan_sha256": confirmation.plan_sha256,
                "request_id": confirmation.request_id.hex(),
                "device_identity": list(confirmation.device_identity),
                "confirmation_phrase": confirmation.confirmation_phrase,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return ""
    return hashlib.sha256(encoded).hexdigest()


def _confirmation_snapshot(
    confirmation: ConfirmedRestoreWorkflow,
) -> tuple[object, ...]:
    return (
        confirmation.plan_sha256,
        confirmation.request_id,
        confirmation.device_identity,
        confirmation.confirmation_phrase,
        confirmation.confirmation_sha256,
    )


def _request_matches_plan(
    request: RestoreDeviceRequest,
    device: Device,
    plan: FormatPlan,
    observation: RestoreTargetObservation,
) -> bool:
    try:
        validate_restore_device_request(request)
    except Exception:
        return False
    return (
        request.expected_capacity == device.size
        and request.expected_major_minor == device.major_minor
        and request.expected_disk_sequence == observation.disk_sequence
        and request.logical_sector_size == device.logical_sector_size
        and request.plan.device_path == plan.device_path
        and request.plan.device_identity[0] == device.path
        and request.plan.device_identity[1] == device.size
        and request.plan.device_identity[5] == device.major_minor
        and request.plan.filesystem.value == plan.filesystem.value
        and request.plan.partition_table.value == plan.partition_table.value
        and request.plan.label == plan.label
        and request.plan.allocation_unit_size == plan.allocation_unit_size
    )


def build_restore_workflow_plan(
    device: Device,
    format_plan: FormatPlan,
    *,
    observe_target: ObserveTarget = _observe_target,
    request_id_factory: Callable[[int], bytes] = secrets.token_bytes,
    request_builder: Callable[..., RestoreDeviceRequest] = build_restore_device_request,
) -> RestoreWorkflowPlan:
    """Bind one exact format plan to a fresh live removable-disk generation."""

    _validate_device_and_format(device, format_plan)
    if not callable(observe_target) or not callable(request_id_factory) or not callable(
        request_builder
    ):
        raise RestoreWorkflowError("Restore workflow dependencies are invalid")
    try:
        observation = observe_target(device)
    except RestoreWorkflowError:
        raise
    except Exception as error:
        raise RestoreWorkflowError(
            "Fresh target observation failed",
        ) from error
    _validate_observation(observation, device)
    request_id = request_id_factory(_REQUEST_ID_BYTES)
    if (
        type(request_id) is not bytes
        or len(request_id) != _REQUEST_ID_BYTES
        or request_id == b"\0" * _REQUEST_ID_BYTES
    ):
        raise RestoreWorkflowError("The restore request identifier is invalid")
    try:
        request = request_builder(
            format_plan,
            request_id=request_id,
            disk_sequence=observation.disk_sequence,
            logical_sector_size=device.logical_sector_size,
        )
    except Exception as error:
        raise RestoreWorkflowError(str(error)) from error
    if not _request_matches_plan(request, device, format_plan, observation):
        raise RestoreWorkflowError(
            "The privileged restore request is not bound to the exact plan",
        )
    stable_digest = _stable_identity(device)
    phrase = _confirmation_phrase(device, stable_digest)
    candidate = RestoreWorkflowPlan(
        device,
        format_plan,
        observation,
        request,
        stable_digest,
        phrase,
        "",
    )
    plan = RestoreWorkflowPlan(
        candidate.device,
        candidate.format_plan,
        candidate.observation,
        candidate.request,
        candidate.stable_identity_digest,
        candidate.confirmation_phrase,
        _plan_digest(candidate),
    )
    object.__setattr__(
        plan,
        "_authorization",
        _PlanReceipt(
            _PLAN_TOKEN,
            plan,
            device,
            format_plan,
            request,
            _plan_snapshot(plan),
        ),
    )
    validate_restore_workflow_plan(plan)
    return plan


def validate_restore_workflow_plan(plan: RestoreWorkflowPlan) -> None:
    if type(plan) is not RestoreWorkflowPlan:
        raise RestoreWorkflowError("An exact RestoreWorkflowPlan is required")
    receipt = plan._authorization
    if (
        type(receipt) is not _PlanReceipt
        or receipt.token is not _PLAN_TOKEN
        or receipt.plan is not plan
        or receipt.device is not plan.device
        or receipt.format_plan is not plan.format_plan
        or receipt.request is not plan.request
        or receipt.snapshot != _plan_snapshot(plan)
    ):
        raise RestoreWorkflowError(
            "The restore plan is cloned, forged, or no longer authoritative",
        )
    _validate_device_and_format(plan.device, plan.format_plan)
    _validate_observation(plan.observation, plan.device)
    expected_stable = _stable_identity(plan.device)
    if (
        plan.stable_identity_digest != expected_stable
        or plan.confirmation_phrase
        != _confirmation_phrase(plan.device, expected_stable)
        or type(plan.plan_sha256) is not str
        or len(plan.plan_sha256) != _PLAN_DIGEST_BYTES * 2
        or not hmac.compare_digest(_plan_digest(plan), plan.plan_sha256)
        or not _request_matches_plan(
            plan.request,
            plan.device,
            plan.format_plan,
            plan.observation,
        )
    ):
        raise RestoreWorkflowError(
            "The restore target, format, request, and confirmation bindings disagree",
        )


def _require_same_live_target(
    plan: RestoreWorkflowPlan,
    observe_target: ObserveTarget,
) -> None:
    validate_restore_workflow_plan(plan)
    try:
        current = observe_target(plan.device)
    except RestoreWorkflowError:
        raise
    except Exception as error:
        raise RestoreWorkflowError(
            "Fresh target revalidation failed",
        ) from error
    _validate_observation(current, plan.device)
    if (
        current.device is not plan.device
        or current.related_device_numbers != plan.observation.related_device_numbers
        or current.disk_sequence != plan.observation.disk_sequence
    ):
        raise RestoreWorkflowError(
            "The target topology or disk generation changed after preparation",
        )


def confirm_restore_workflow_plan(
    plan: RestoreWorkflowPlan,
    phrase: str,
    *,
    observe_target: ObserveTarget = _observe_target,
) -> ConfirmedRestoreWorkflow:
    validate_restore_workflow_plan(plan)
    if (
        type(phrase) is not str
        or not phrase.isascii()
        or not hmac.compare_digest(
            phrase.encode("ascii"),
            plan.confirmation_phrase.encode("ascii"),
        )
    ):
        raise RestoreWorkflowError(
            "The destructive restore confirmation phrase did not match exactly",
        )
    _require_same_live_target(plan, observe_target)
    candidate = ConfirmedRestoreWorkflow(
        plan,
        plan.plan_sha256,
        plan.request.request_id,
        plan.device.identity,
        plan.confirmation_phrase,
        "",
    )
    confirmation = ConfirmedRestoreWorkflow(
        candidate.plan,
        candidate.plan_sha256,
        candidate.request_id,
        candidate.device_identity,
        candidate.confirmation_phrase,
        _confirmation_digest(candidate),
    )
    object.__setattr__(
        confirmation,
        "_authorization",
        _ConfirmationReceipt(
            _CONFIRMATION_TOKEN,
            confirmation,
            plan,
            _confirmation_snapshot(confirmation),
        ),
    )
    validate_confirmed_restore_workflow(plan, confirmation)
    return confirmation


def validate_confirmed_restore_workflow(
    plan: RestoreWorkflowPlan,
    confirmation: ConfirmedRestoreWorkflow,
) -> None:
    validate_restore_workflow_plan(plan)
    if type(confirmation) is not ConfirmedRestoreWorkflow:
        raise RestoreWorkflowError("An exact restore confirmation is required")
    receipt = confirmation._authorization
    if (
        type(receipt) is not _ConfirmationReceipt
        or receipt.token is not _CONFIRMATION_TOKEN
        or receipt.confirmation is not confirmation
        or receipt.plan is not plan
        or receipt.snapshot != _confirmation_snapshot(confirmation)
        or confirmation.plan is not plan
        or confirmation.plan_sha256 != plan.plan_sha256
        or confirmation.request_id != plan.request.request_id
        or confirmation.device_identity != plan.device.identity
        or confirmation.confirmation_phrase != plan.confirmation_phrase
        or type(confirmation.confirmation_sha256) is not str
        or len(confirmation.confirmation_sha256) != _PLAN_DIGEST_BYTES * 2
        or not hmac.compare_digest(
            _confirmation_digest(confirmation),
            confirmation.confirmation_sha256,
        )
    ):
        raise RestoreWorkflowError(
            "The restore confirmation is cloned, forged, or cross-wired",
        )


def _validate_runner_result(
    plan: RestoreWorkflowPlan,
    result: RestoreDeviceRunResult,
) -> None:
    request = plan.request
    numeric = (
        result.disk_sequence,
        result.capacity,
        result.partition_start_sector,
        result.partition_sector_count,
        result.scanned_bytes,
        result.written_bytes,
        result.skipped_bytes,
        result.verified_bytes,
        result.logical_sector_size,
        result.sectors_per_cluster,
        result.cluster_size,
    ) if type(result) is RestoreDeviceRunResult else ()
    if type(result) is RestoreDeviceRunResult:
        try:
            filesystem_receipt = FilesystemReceipt(
                result.filesystem,
                result.partition_major_minor,
                result.partition_start_sector,
                result.partition_sector_count,
                result.logical_sector_size,
                result.sectors_per_cluster,
                result.cluster_size,
                result.normalized_label,
                result.metadata_sha256,
                result.filesystem_receipt_sha256,
            )
            validate_filesystem_receipt(request, filesystem_receipt)
        except Exception as error:
            raise RestoreWorkflowError(
                "The privileged restore filesystem receipt is invalid",
            ) from error
    if (
        type(result) is not RestoreDeviceRunResult
        or any(type(value) is not int or value < 0 for value in numeric)
        or result.request_id != request.request_id
        or result.target_major_minor != plan.device.major_minor
        or type(result.partition_major_minor) is not str
        or _MAJOR_MINOR.fullmatch(result.partition_major_minor) is None
        or result.partition_major_minor == plan.device.major_minor
        or result.disk_sequence != plan.observation.disk_sequence
        or result.capacity != plan.device.size
        or result.partition_start_sector != request.partition_start_sector
        or result.partition_sector_count != request.partition_sector_count
        or result.scanned_bytes != plan.device.size
        or result.written_bytes + result.skipped_bytes != plan.device.size
        or result.verified_bytes != plan.device.size
        or result.logical_sector_size != plan.device.logical_sector_size
        or result.filesystem.value != plan.format_plan.filesystem.value
        or result.cluster_size
        != result.logical_sector_size * result.sectors_per_cluster
        or (
            plan.format_plan.allocation_unit_size is not None
            and result.cluster_size != plan.format_plan.allocation_unit_size
        )
        or result.normalized_label
        != unicodedata.normalize("NFC", plan.format_plan.label)
        or type(result.metadata_sha256) is not bytes
        or len(result.metadata_sha256) != 32
        or type(result.filesystem_receipt_sha256) is not bytes
        or len(result.filesystem_receipt_sha256) != 32
    ):
        raise RestoreWorkflowError(
            "The privileged restore result belongs to another or incomplete transaction",
        )


@dataclass(frozen=True)
class RestoreWorkflowDependencies:
    """Injectable system boundary used by the non-Qt lifecycle owner."""

    resolve_helper: Callable[[], object] = resolve_restore_device_installation
    observe_target: ObserveTarget = _observe_target
    request_id_factory: Callable[[int], bytes] = secrets.token_bytes
    request_builder: Callable[..., RestoreDeviceRequest] = build_restore_device_request
    runner_factory: Callable[[], object] = RestoreDeviceRunner


class RestoreWorkflow:
    """Own exactly one verified-zero + format transaction."""

    def __init__(
        self,
        device: Device,
        format_plan: FormatPlan,
        *,
        dependencies: RestoreWorkflowDependencies = RestoreWorkflowDependencies(),
    ) -> None:
        if type(device) is not Device or type(format_plan) is not FormatPlan:
            raise RestoreWorkflowError(
                "An exact Device and formatting FormatPlan are required",
            )
        if type(dependencies) is not RestoreWorkflowDependencies:
            raise RestoreWorkflowError("Restore workflow dependencies are invalid")
        self.device = device
        self.format_plan = format_plan
        self.dependencies = dependencies
        self._lock = threading.RLock()
        self._cancelled = threading.Event()
        self._state = RestoreWorkflowState.CREATED
        self._preparing = False
        self._close_requested = False
        self._plan: RestoreWorkflowPlan | None = None
        self._confirmation: ConfirmedRestoreWorkflow | None = None
        self._runner: object | None = None
        self._result: RestoreWorkflowResult | None = None
        self._cancellation_deferred = False

    @property
    def state(self) -> RestoreWorkflowState:
        with self._lock:
            return self._state

    @property
    def plan(self) -> RestoreWorkflowPlan | None:
        with self._lock:
            return self._plan

    @property
    def confirmation(self) -> ConfirmedRestoreWorkflow | None:
        with self._lock:
            return self._confirmation

    @property
    def result(self) -> RestoreWorkflowResult | None:
        with self._lock:
            return self._result

    @property
    def cancellation_deferred(self) -> bool:
        with self._lock:
            return self._cancellation_deferred

    @property
    def committed(self) -> bool:
        """Report only an exact COMMIT witnessed by the retained runner."""

        with self._lock:
            return getattr(self._runner, "committed", False) is True

    def _check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise RestoreWorkflowCancelled("The verified restore was cancelled")

    def _terminal_failure(self, error: BaseException) -> None:
        with self._lock:
            committed = getattr(self._runner, "committed", False) is True
            if self._close_requested:
                self._state = RestoreWorkflowState.CLOSED
            elif isinstance(error, RestoreWorkflowCancelled) and not committed:
                self._state = RestoreWorkflowState.CANCELLED
            else:
                self._state = RestoreWorkflowState.FAILED

    @staticmethod
    def _translate(error: BaseException) -> RestoreWorkflowError:
        if isinstance(error, RestoreWorkflowError):
            return error
        if isinstance(error, RestoreDeviceRunCancelled):
            return RestoreWorkflowCancelled(str(error) or "Verified restore cancelled")
        if isinstance(
            error,
            (RestoreDeviceRunError, RestoreDeviceHelperUnavailable),
        ):
            return RestoreWorkflowError(str(error))
        return RestoreWorkflowError(str(error) or error.__class__.__name__)

    def prepare(self) -> RestoreWorkflowPlan:
        with self._lock:
            if self._state is not RestoreWorkflowState.CREATED or self._preparing:
                raise RestoreWorkflowError(
                    "A verified restore workflow can only be prepared once",
                )
            self._preparing = True
        try:
            self._check_cancelled()
            self.dependencies.resolve_helper()
            self._check_cancelled()
            plan = build_restore_workflow_plan(
                self.device,
                self.format_plan,
                observe_target=self.dependencies.observe_target,
                request_id_factory=self.dependencies.request_id_factory,
                request_builder=self.dependencies.request_builder,
            )
            self._check_cancelled()
            with self._lock:
                if self._close_requested or self._cancelled.is_set():
                    raise RestoreWorkflowCancelled(
                        "The verified restore workflow was closed"
                        if self._close_requested
                        else "The verified restore was cancelled",
                    )
                self._plan = plan
                self._state = RestoreWorkflowState.PREPARED
            return plan
        except BaseException as original:
            error = self._translate(original)
            self._terminal_failure(error)
            raise error from original if error is not original else None
        finally:
            with self._lock:
                self._preparing = False

    def confirm(self, phrase: str) -> ConfirmedRestoreWorkflow:
        with self._lock:
            plan = self._plan
            if self._state is not RestoreWorkflowState.PREPARED or plan is None:
                raise RestoreWorkflowError(
                    "The verified restore workflow is not ready for confirmation",
                )
            if type(phrase) is not str or phrase != plan.confirmation_phrase:
                raise RestoreWorkflowError(
                    "The destructive restore confirmation phrase did not match exactly",
                )
        try:
            self._check_cancelled()
            confirmation = confirm_restore_workflow_plan(
                plan,
                phrase,
                observe_target=self.dependencies.observe_target,
            )
            self._check_cancelled()
            with self._lock:
                if self._state is not RestoreWorkflowState.PREPARED:
                    raise RestoreWorkflowCancelled(
                        "The verified restore was cancelled",
                    )
                self._confirmation = confirmation
                self._state = RestoreWorkflowState.CONFIRMED
            return confirmation
        except BaseException as original:
            error = self._translate(original)
            self._terminal_failure(error)
            raise error from original if error is not original else None

    def execute(
        self,
        progress: Progress = lambda _phase, _done, _total: None,
    ) -> RestoreWorkflowResult:
        with self._lock:
            plan = self._plan
            confirmation = self._confirmation
            if (
                self._state is not RestoreWorkflowState.CONFIRMED
                or plan is None
                or confirmation is None
            ):
                raise RestoreWorkflowError(
                    "Verified restore requires exact confirmation before execution",
                )
        runner: object | None = None
        try:
            validate_confirmed_restore_workflow(plan, confirmation)
            runner = self.dependencies.runner_factory()
            if not callable(getattr(runner, "run", None)) or not callable(
                getattr(runner, "cancel", None)
            ):
                raise RestoreWorkflowError(
                    "The restore-device runner is not authoritative",
                )
            with self._lock:
                if (
                    self._state is not RestoreWorkflowState.CONFIRMED
                    or self._cancelled.is_set()
                    or self._close_requested
                ):
                    raise RestoreWorkflowCancelled(
                        "The verified restore workflow was cancelled before execution",
                    )
                self._runner = runner
                self._state = RestoreWorkflowState.EXECUTING

            def confirm_commit() -> bool:
                self._check_cancelled()
                validate_confirmed_restore_workflow(plan, confirmation)
                _require_same_live_target(plan, self.dependencies.observe_target)
                self._check_cancelled()
                return True

            raw_result = runner.run(
                plan.request,
                confirm_commit=confirm_commit,
                progress=progress,
            )
            _validate_runner_result(plan, raw_result)
            if getattr(runner, "committed", False) is not True:
                raise RestoreWorkflowError(
                    "The restore runner returned without an authenticated COMMIT",
                )
            with self._lock:
                deferred = self._cancellation_deferred or self._cancelled.is_set()
                result = RestoreWorkflowResult(
                    plan.plan_sha256,
                    plan.device.identity,
                    raw_result.request_id,
                    raw_result.target_major_minor,
                    raw_result.partition_major_minor,
                    raw_result.disk_sequence,
                    raw_result.capacity,
                    raw_result.partition_start_sector,
                    raw_result.partition_sector_count,
                    raw_result.scanned_bytes,
                    raw_result.written_bytes,
                    raw_result.skipped_bytes,
                    raw_result.verified_bytes,
                    raw_result.logical_sector_size,
                    raw_result.filesystem.value,
                    raw_result.sectors_per_cluster,
                    raw_result.cluster_size,
                    raw_result.normalized_label,
                    raw_result.metadata_sha256,
                    raw_result.filesystem_receipt_sha256,
                    deferred,
                )
                self._result = result
                self._state = (
                    RestoreWorkflowState.CLOSED
                    if self._close_requested
                    else RestoreWorkflowState.COMPLETED
                )
            return result
        except BaseException as original:
            error = self._translate(original)
            self._terminal_failure(error)
            raise error from original if error is not original else None

    def cancel(self) -> None:
        with self._lock:
            if self._state in {
                RestoreWorkflowState.COMPLETED,
                RestoreWorkflowState.CANCELLED,
                RestoreWorkflowState.FAILED,
                RestoreWorkflowState.CLOSED,
            }:
                return
            self._cancelled.set()
            runner = self._runner
            committed = getattr(runner, "committed", False) is True
            if committed:
                self._cancellation_deferred = True
            elif self._state in {
                RestoreWorkflowState.CREATED,
                RestoreWorkflowState.PREPARED,
                RestoreWorkflowState.CONFIRMED,
            }:
                self._state = (
                    RestoreWorkflowState.CLOSED
                    if self._close_requested
                    else RestoreWorkflowState.CANCELLED
                )
        if runner is not None:
            try:
                runner.cancel()
            except Exception:
                logger.exception("Could not signal restore-device cancellation")

    def close(self) -> None:
        with self._lock:
            if self._state is RestoreWorkflowState.CLOSED:
                return
            self._close_requested = True
            active = self._preparing or self._state is RestoreWorkflowState.EXECUTING
        if active:
            self.cancel()
            return
        with self._lock:
            self._state = RestoreWorkflowState.CLOSED

    def __enter__(self) -> RestoreWorkflow:
        if self.state is RestoreWorkflowState.CLOSED:
            raise RestoreWorkflowError("The verified restore workflow is closed")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
