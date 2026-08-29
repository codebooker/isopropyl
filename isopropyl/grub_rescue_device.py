from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unprivileged authorization for one exact GRUB 2.14 rescue image.

This module stops before privileged I/O.  It binds the builder-owned rescue
image, its complete result receipt, one kernel-removable USB/MMC whole disk,
the disk generation, and an exact typed confirmation.  A future runner must
consume these process-local receipts; it must not substitute a generic writer.
"""

import hashlib
import hmac
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from . import grub_rescue as _grub_rescue_module
from .devices import Device
from .grub_rescue import (
    GrubRescueError,
    GrubRescuePlan,
    GrubRescueResult,
    PreparedGrubRescueImage,
    validate_grub_rescue_plan,
)
from .private_fat32 import PrivateFat32State
from .syslinux_device import (
    SyslinuxDevicePlanError,
    _LiveTargetObservation,
    _device_payload,
    _post_unmount_device_matches,
    _probe_live_target,
    _read_disk_sequence,
    _validate_live_target,
    _validate_target_node,
)
from .writer import WriterSafetyError, validate_device_selection


SECTOR_SIZE = 512
MAX_TARGET_BYTES = 128 * 1024 * 1024 * 1024
TARGET_PLAN_PROFILE = (
    "io.github.codebooker.isopropyl/grub-rescue-device-plan/v1"
)
READY_TARGET_PROFILE = (
    "io.github.codebooker.isopropyl/grub-rescue-ready-target/v1"
)
REQUIRED_EXECUTOR_PROFILE = (
    "io.github.codebooker.isopropyl/grub-2.14-rescue-device-helper/v1"
)
IMAGE_PROFILE = "grub-2.14/bios/rescue-prompt/fat32-mbr/v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PLAN_TOKEN = object()
_CONFIRM_TOKEN = object()
_READY_TOKEN = object()

CancelCheck = Callable[[], None]


class GrubRescueDevicePlanError(RuntimeError):
    """The exact rescue image could not be bound to a safe target."""


class GrubRescueDevicePlanCancelled(GrubRescueDevicePlanError):
    """Target authorization was cancelled before a receipt was minted."""


@dataclass(frozen=True)
class _PlanReceipt:
    token: object
    owner: object
    rescue_plan: object
    rescue_result: object
    prepared: object
    device: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class _ConfirmationReceipt:
    token: object
    owner: object
    plan: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class _ReadyReceipt:
    token: object
    owner: object
    plan: object
    confirmation: object
    device: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class GrubRescueDeviceWritePlan:
    rescue_plan: GrubRescuePlan = field(repr=False, compare=False)
    rescue_result: GrubRescueResult = field(repr=False, compare=False)
    prepared: PreparedGrubRescueImage = field(repr=False, compare=False)
    device: Device
    disk_sequence: int
    rescue_plan_sha256: str
    private_plan_sha256: str
    final_image_sha256: str
    final_mbr_sha256: str
    final_fat_manifest_sha256: str
    image_size: int
    disk_signature: int
    volume_id: int
    logical_sector_size: int
    image_profile: str
    mandatory_preactivation_readback: bool
    mandatory_final_readback: bool
    required_executor_profile: str
    warnings: tuple[str, ...]
    confirmation_phrase: str
    plan_sha256: str
    _authorization: _PlanReceipt | None = field(
        init=False, default=None, repr=False, compare=False,
    )


@dataclass(frozen=True)
class ConfirmedGrubRescueDeviceWrite:
    plan: GrubRescueDeviceWritePlan = field(repr=False, compare=False)
    plan_sha256: str
    rescue_plan_sha256: str
    final_image_sha256: str
    device_identity: tuple[str, int, str, str, str, str]
    target_capacity: int
    logical_sector_size: int
    confirmation_phrase: str
    _authorization: _ConfirmationReceipt | None = field(
        init=False, default=None, repr=False, compare=False,
    )


@dataclass(frozen=True)
class ReadyGrubRescueDeviceWrite:
    plan: GrubRescueDeviceWritePlan = field(repr=False, compare=False)
    confirmation: ConfirmedGrubRescueDeviceWrite = field(
        repr=False, compare=False,
    )
    device: Device
    disk_sequence: int
    plan_sha256: str
    final_image_sha256: str
    ready_sha256: str
    _authorization: _ReadyReceipt | None = field(
        init=False, default=None, repr=False, compare=False,
    )


def _cancel(cancel_check: CancelCheck | None) -> None:
    if cancel_check is not None:
        cancel_check()


def _phrase_matches(actual: object, expected: str) -> bool:
    return (
        type(actual) is str
        and actual.isascii()
        and hmac.compare_digest(actual.encode("ascii"), expected.encode("ascii"))
    )


def _warnings(device: Device) -> tuple[str, ...]:
    return (
        f"Everything on {device.path} will be permanently erased.",
        "This exact GRUB 2.14 BIOS profile intentionally stops at the rescue prompt.",
        "Secure Boot must be disabled; this is not a UEFI image or operating system.",
        "Execution requires preactivation proof and complete whole-device SHA-256 read-back.",
    )


def _plan_snapshot(plan: GrubRescueDeviceWritePlan) -> tuple[object, ...]:
    return (
        plan.rescue_plan_sha256,
        plan.private_plan_sha256,
        plan.final_image_sha256,
        plan.final_mbr_sha256,
        plan.final_fat_manifest_sha256,
        plan.disk_sequence,
        plan.image_size,
        plan.disk_signature,
        plan.volume_id,
        plan.logical_sector_size,
        plan.image_profile,
        plan.mandatory_preactivation_readback,
        plan.mandatory_final_readback,
        plan.required_executor_profile,
        plan.warnings,
        plan.confirmation_phrase,
        plan.plan_sha256,
    )


def _confirmation_snapshot(
    confirmation: ConfirmedGrubRescueDeviceWrite,
) -> tuple[object, ...]:
    return (
        confirmation.plan_sha256,
        confirmation.rescue_plan_sha256,
        confirmation.final_image_sha256,
        confirmation.device_identity,
        confirmation.target_capacity,
        confirmation.logical_sector_size,
        confirmation.confirmation_phrase,
    )


def _ready_snapshot(ready: ReadyGrubRescueDeviceWrite) -> tuple[object, ...]:
    return (
        ready.plan_sha256,
        ready.final_image_sha256,
        ready.disk_sequence,
        ready.ready_sha256,
        ready.device,
    )


def _plan_digest(plan: GrubRescueDeviceWritePlan) -> str:
    try:
        encoded = json.dumps(
            {
                "profile": TARGET_PLAN_PROFILE,
                "rescue": {
                    "plan": plan.rescue_plan_sha256,
                    "private_plan": plan.private_plan_sha256,
                    "final_image": plan.final_image_sha256,
                    "final_mbr": plan.final_mbr_sha256,
                    "fat_manifest": plan.final_fat_manifest_sha256,
                    "image_size": plan.image_size,
                    "disk_signature": plan.disk_signature,
                    "volume_id": plan.volume_id,
                    "image_profile": plan.image_profile,
                },
                "target": _device_payload(plan.device),
                "disk_sequence": plan.disk_sequence,
                "logical_sector_size": plan.logical_sector_size,
                "mandatory_preactivation_readback": (
                    plan.mandatory_preactivation_readback
                ),
                "mandatory_final_readback": plan.mandatory_final_readback,
                "executor": plan.required_executor_profile,
                "warnings": list(plan.warnings),
                "confirmation": plan.confirmation_phrase,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return ""
    return hashlib.sha256(encoded).hexdigest()


def _ready_digest(ready: ReadyGrubRescueDeviceWrite) -> str:
    try:
        encoded = json.dumps(
            {
                "profile": READY_TARGET_PROFILE,
                "plan": ready.plan_sha256,
                "image": ready.final_image_sha256,
                "disk_sequence": ready.disk_sequence,
                "original": _device_payload(ready.plan.device),
                "unmounted": _device_payload(ready.device),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return ""
    return hashlib.sha256(encoded).hexdigest()


def _target_checks(device: Device) -> tuple[object, _LiveTargetObservation]:
    try:
        status = _validate_target_node(device)
        observation = _validate_live_target(device, status)
    except SyslinuxDevicePlanError as error:
        raise GrubRescueDevicePlanError(str(error)) from error
    return status, observation


def _validate_prepared_binding(
    rescue_plan: GrubRescuePlan,
    rescue_result: GrubRescueResult,
    prepared: PreparedGrubRescueImage,
    cancel_check: CancelCheck | None,
) -> None:
    if type(rescue_plan) is not GrubRescuePlan:
        raise GrubRescueDevicePlanError("An exact GRUB rescue plan is required")
    if type(rescue_result) is not GrubRescueResult:
        raise GrubRescueDevicePlanError("An exact GRUB rescue result is required")
    if type(prepared) is not PreparedGrubRescueImage:
        raise GrubRescueDevicePlanError("An exact prepared GRUB rescue image is required")
    if getattr(prepared, "_witness", None) is not _grub_rescue_module._OWNER_WITNESS:
        raise GrubRescueDevicePlanError(
            "The prepared GRUB rescue image has no authentic owner receipt",
        )
    try:
        validate_grub_rescue_plan(rescue_plan, cancel_check=cancel_check)
        prepared_plan = prepared.plan
        prepared_result = prepared.result
        prepared_state = prepared.state
    except GrubRescueError as error:
        raise GrubRescueDevicePlanError(str(error)) from error
    private = rescue_plan.private_plan
    digests = (
        rescue_result.plan_sha256,
        rescue_result.private_plan_sha256,
        rescue_result.boot_image_sha256,
        rescue_result.bootstrap_sha256,
        rescue_result.final_mbr_sha256,
        rescue_result.core_sha256,
        rescue_result.unpatched_image_sha256,
        rescue_result.final_image_sha256,
        rescue_result.final_fat_manifest_sha256,
    )
    if (
        prepared_plan is not rescue_plan
        or prepared_result is not rescue_result
        or prepared_state is not PrivateFat32State.PATCHED_ATTESTED
        or any(type(item) is not str or _SHA256.fullmatch(item) is None for item in digests)
        or rescue_result.plan_sha256 != rescue_plan.plan_sha256
        or rescue_result.private_plan_sha256 != private.plan_sha256
        or rescue_result.profile != rescue_plan.profile
        or rescue_result.result_semantics != rescue_plan.result_semantics
        or rescue_result.image_size != private.geometry.image_size
        or rescue_result.disk_signature != private.disk_signature
        or rescue_result.volume_id != private.volume_id
        or rescue_result.boot_image_sha256 != rescue_plan.boot_image_sha256
        or rescue_result.bootstrap_sha256 != rescue_plan.bootstrap_sha256
        or rescue_result.core_sha256 != rescue_plan.core_sha256
        or rescue_result.core_offset != rescue_plan.core_offset
        or rescue_result.core_size != rescue_plan.core_size
        or rescue_result.core_padded_size != rescue_plan.core_padded_size
        or rescue_result.embedding_gap_zero_verified is not True
        or hmac.compare_digest(
            rescue_result.unpatched_image_sha256,
            rescue_result.final_image_sha256,
        )
        or rescue_result.files_verified != 0
        or rescue_result.bytes_verified != 0
    ):
        raise GrubRescueDevicePlanError(
            "The GRUB rescue plan, prepared owner, and result receipt disagree",
        )
    _cancel(cancel_check)


def _validate_removable_target(device: Device) -> None:
    if type(device) is not Device:
        raise GrubRescueDevicePlanError("An exact discovered Device is required")
    try:
        validate_device_selection(device, writable=True)
    except WriterSafetyError as error:
        raise GrubRescueDevicePlanError(str(error)) from error
    if device.transport not in {"usb", "mmc"} or device.removable is not True:
        raise GrubRescueDevicePlanError(
            "GRUB rescue writing requires kernel-removable USB or SD/MMC media",
        )
    if device.read_only:
        raise GrubRescueDevicePlanError("The GRUB rescue target is read-only")


def _source_residency(
    plan: GrubRescueDeviceWritePlan,
    status: object,
    observation: _LiveTargetObservation,
) -> None:
    private = plan.rescue_plan.private_plan
    if not private.directories:
        raise GrubRescueDevicePlanError("The witnessed empty staging root is missing")
    source_device = private.directories[0].source.device
    workspace_device = private.workspace_identity.device
    related = observation.related_device_numbers
    if status.st_rdev not in related:
        raise GrubRescueDevicePlanError("The target node and topology disagree")
    if source_device in related or workspace_device in related:
        raise GrubRescueDevicePlanError(
            "The GRUB source or private workspace resides on the target",
        )


def _validate_static(
    plan: GrubRescueDeviceWritePlan,
    cancel_check: CancelCheck | None,
) -> None:
    if type(plan) is not GrubRescueDeviceWritePlan:
        raise GrubRescueDevicePlanError("An exact GRUB target plan is required")
    receipt = plan._authorization
    if (
        type(receipt) is not _PlanReceipt
        or receipt.token is not _PLAN_TOKEN
        or receipt.owner is not plan
        or receipt.rescue_plan is not plan.rescue_plan
        or receipt.rescue_result is not plan.rescue_result
        or receipt.prepared is not plan.prepared
        or receipt.device is not plan.device
        or receipt.snapshot != _plan_snapshot(plan)
    ):
        raise GrubRescueDevicePlanError(
            "The GRUB target authorization is missing, cloned, or stale",
        )
    _validate_prepared_binding(
        plan.rescue_plan, plan.rescue_result, plan.prepared, cancel_check,
    )
    _validate_removable_target(plan.device)
    private = plan.rescue_plan.private_plan
    result = plan.rescue_result
    expected_phrase = (
        f"WRITE GRUB RESCUE {plan.device.path} {plan.device.major_minor}"
    )
    digests = (
        plan.rescue_plan_sha256,
        plan.private_plan_sha256,
        plan.final_image_sha256,
        plan.final_mbr_sha256,
        plan.final_fat_manifest_sha256,
        plan.plan_sha256,
    )
    if (
        any(type(item) is not str or _SHA256.fullmatch(item) is None for item in digests)
        or plan.rescue_plan_sha256 != plan.rescue_plan.plan_sha256
        or plan.private_plan_sha256 != private.plan_sha256
        or plan.final_image_sha256 != result.final_image_sha256
        or plan.final_mbr_sha256 != result.final_mbr_sha256
        or plan.final_fat_manifest_sha256 != result.final_fat_manifest_sha256
        or plan.image_size != result.image_size
        or plan.image_size != private.geometry.image_size
        or plan.image_size != plan.device.size
        or plan.image_size <= 0
        or plan.image_size > MAX_TARGET_BYTES
        or plan.image_size % SECTOR_SIZE
        or plan.disk_signature != result.disk_signature
        or plan.volume_id != result.volume_id
        or type(plan.disk_sequence) is not int
        or isinstance(plan.disk_sequence, bool)
        or not 0 < plan.disk_sequence <= 0xFFFFFFFFFFFFFFFF
        or plan.logical_sector_size != SECTOR_SIZE
        or plan.device.logical_sector_size != SECTOR_SIZE
        or plan.image_profile != IMAGE_PROFILE
        or plan.mandatory_preactivation_readback is not True
        or plan.mandatory_final_readback is not True
        or plan.required_executor_profile != REQUIRED_EXECUTOR_PROFILE
        or plan.warnings != _warnings(plan.device)
        or plan.confirmation_phrase != expected_phrase
        or not hmac.compare_digest(_plan_digest(plan), plan.plan_sha256)
    ):
        raise GrubRescueDevicePlanError(
            "The GRUB image, target geometry, and authorization bindings disagree",
        )
    _cancel(cancel_check)


def _validate_live(
    plan: GrubRescueDeviceWritePlan,
    cancel_check: CancelCheck | None,
) -> None:
    _validate_static(plan, cancel_check)
    status, observation = _target_checks(plan.device)
    _source_residency(plan, status, observation)
    try:
        sequence = _read_disk_sequence(plan.device.major_minor)
    except SyslinuxDevicePlanError as error:
        raise GrubRescueDevicePlanError(str(error)) from error
    if sequence != plan.disk_sequence:
        raise GrubRescueDevicePlanError(
            "The selected GRUB target is a different disk generation",
        )
    _cancel(cancel_check)


def build_grub_rescue_device_write_plan(
    rescue_plan: GrubRescuePlan,
    rescue_result: GrubRescueResult,
    prepared: PreparedGrubRescueImage,
    device: Device,
    *,
    cancel_check: CancelCheck | None = None,
) -> GrubRescueDeviceWritePlan:
    """Bind one builder-owned rescue image to one current removable disk."""

    _validate_prepared_binding(
        rescue_plan, rescue_result, prepared, cancel_check,
    )
    _validate_removable_target(device)
    if device.logical_sector_size != SECTOR_SIZE:
        raise GrubRescueDevicePlanError(
            "GRUB rescue writing requires 512-byte logical sectors",
        )
    if device.size != rescue_result.image_size or device.size % SECTOR_SIZE:
        raise GrubRescueDevicePlanError(
            "The GRUB rescue image must exactly match the target capacity",
        )
    if device.size > MAX_TARGET_BYTES:
        raise GrubRescueDevicePlanError("The GRUB rescue target exceeds 128 GiB")
    status, observation = _target_checks(device)
    try:
        sequence = _read_disk_sequence(device.major_minor)
    except SyslinuxDevicePlanError as error:
        raise GrubRescueDevicePlanError(str(error)) from error
    candidate = GrubRescueDeviceWritePlan(
        rescue_plan=rescue_plan,
        rescue_result=rescue_result,
        prepared=prepared,
        device=device,
        disk_sequence=sequence,
        rescue_plan_sha256=rescue_plan.plan_sha256,
        private_plan_sha256=rescue_plan.private_plan.plan_sha256,
        final_image_sha256=rescue_result.final_image_sha256,
        final_mbr_sha256=rescue_result.final_mbr_sha256,
        final_fat_manifest_sha256=rescue_result.final_fat_manifest_sha256,
        image_size=rescue_result.image_size,
        disk_signature=rescue_result.disk_signature,
        volume_id=rescue_result.volume_id,
        logical_sector_size=device.logical_sector_size,
        image_profile=IMAGE_PROFILE,
        mandatory_preactivation_readback=True,
        mandatory_final_readback=True,
        required_executor_profile=REQUIRED_EXECUTOR_PROFILE,
        warnings=_warnings(device),
        confirmation_phrase=(
            f"WRITE GRUB RESCUE {device.path} {device.major_minor}"
        ),
        plan_sha256="",
    )
    plan = replace(candidate, plan_sha256=_plan_digest(candidate))
    _source_residency(plan, status, observation)
    _cancel(cancel_check)
    object.__setattr__(
        plan,
        "_authorization",
        _PlanReceipt(
            _PLAN_TOKEN,
            plan,
            rescue_plan,
            rescue_result,
            prepared,
            device,
            _plan_snapshot(plan),
        ),
    )
    return plan


def validate_grub_rescue_device_write_plan(
    plan: GrubRescueDeviceWritePlan,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    _validate_live(plan, cancel_check)


def confirm_grub_rescue_device_write(
    plan: GrubRescueDeviceWritePlan,
    phrase: str,
    *,
    cancel_check: CancelCheck | None = None,
) -> ConfirmedGrubRescueDeviceWrite:
    _validate_live(plan, cancel_check)
    if not _phrase_matches(phrase, plan.confirmation_phrase):
        raise GrubRescueDevicePlanError(
            "The GRUB destructive confirmation phrase did not match",
        )
    confirmation = ConfirmedGrubRescueDeviceWrite(
        plan,
        plan.plan_sha256,
        plan.rescue_plan_sha256,
        plan.final_image_sha256,
        plan.device.identity,
        plan.device.size,
        plan.logical_sector_size,
        phrase,
    )
    _cancel(cancel_check)
    object.__setattr__(
        confirmation,
        "_authorization",
        _ConfirmationReceipt(
            _CONFIRM_TOKEN,
            confirmation,
            plan,
            _confirmation_snapshot(confirmation),
        ),
    )
    return confirmation


def _validate_confirmation(
    plan: GrubRescueDeviceWritePlan,
    confirmation: ConfirmedGrubRescueDeviceWrite,
) -> None:
    if type(confirmation) is not ConfirmedGrubRescueDeviceWrite:
        raise GrubRescueDevicePlanError("An exact GRUB confirmation is required")
    receipt = confirmation._authorization
    if (
        type(receipt) is not _ConfirmationReceipt
        or receipt.token is not _CONFIRM_TOKEN
        or receipt.owner is not confirmation
        or receipt.plan is not plan
        or receipt.snapshot != _confirmation_snapshot(confirmation)
        or confirmation.plan is not plan
        or confirmation.plan_sha256 != plan.plan_sha256
        or confirmation.rescue_plan_sha256 != plan.rescue_plan_sha256
        or confirmation.final_image_sha256 != plan.final_image_sha256
        or confirmation.device_identity != plan.device.identity
        or confirmation.target_capacity != plan.device.size
        or confirmation.logical_sector_size != plan.logical_sector_size
        or not _phrase_matches(
            confirmation.confirmation_phrase,
            plan.confirmation_phrase,
        )
    ):
        raise GrubRescueDevicePlanError(
            "The GRUB confirmation is forged, cloned, or cross-wired",
        )


def validate_confirmed_grub_rescue_device_write(
    plan: GrubRescueDeviceWritePlan,
    confirmation: ConfirmedGrubRescueDeviceWrite,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    _validate_live(plan, cancel_check)
    _validate_confirmation(plan, confirmation)
    _cancel(cancel_check)


def authorize_unmounted_grub_rescue_device_write(
    plan: GrubRescueDeviceWritePlan,
    confirmation: ConfirmedGrubRescueDeviceWrite,
    *,
    cancel_check: CancelCheck | None = None,
) -> ReadyGrubRescueDeviceWrite:
    """Mint the sole post-unmount receipt suitable for helper launch."""

    _validate_static(plan, cancel_check)
    _validate_confirmation(plan, confirmation)
    try:
        status = _validate_target_node(plan.device)
        observation = _probe_live_target(plan.device.path)
    except SyslinuxDevicePlanError as error:
        raise GrubRescueDevicePlanError(str(error)) from error
    if type(observation) is not _LiveTargetObservation:
        raise GrubRescueDevicePlanError(
            "Live post-unmount GRUB target evidence is invalid",
        )
    current = observation.device
    if not _post_unmount_device_matches(plan.device, current):
        raise GrubRescueDevicePlanError(
            "The GRUB target changed during unmounting or remains mounted",
        )
    _validate_removable_target(current)
    _source_residency(plan, status, observation)
    try:
        sequence = _read_disk_sequence(current.major_minor)
    except SyslinuxDevicePlanError as error:
        raise GrubRescueDevicePlanError(str(error)) from error
    if sequence != plan.disk_sequence:
        raise GrubRescueDevicePlanError(
            "The GRUB target generation changed during unmount",
        )
    candidate = ReadyGrubRescueDeviceWrite(
        plan,
        confirmation,
        current,
        sequence,
        plan.plan_sha256,
        plan.final_image_sha256,
        "",
    )
    ready = replace(candidate, ready_sha256=_ready_digest(candidate))
    _cancel(cancel_check)
    object.__setattr__(
        ready,
        "_authorization",
        _ReadyReceipt(
            _READY_TOKEN,
            ready,
            plan,
            confirmation,
            current,
            _ready_snapshot(ready),
        ),
    )
    return ready


def validate_ready_grub_rescue_device_write(
    plan: GrubRescueDeviceWritePlan,
    confirmation: ConfirmedGrubRescueDeviceWrite,
    ready: ReadyGrubRescueDeviceWrite,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    _validate_static(plan, cancel_check)
    _validate_confirmation(plan, confirmation)
    if type(ready) is not ReadyGrubRescueDeviceWrite:
        raise GrubRescueDevicePlanError(
            "An exact GRUB post-unmount receipt is required",
        )
    receipt = ready._authorization
    if (
        type(receipt) is not _ReadyReceipt
        or receipt.token is not _READY_TOKEN
        or receipt.owner is not ready
        or receipt.plan is not plan
        or receipt.confirmation is not confirmation
        or receipt.device is not ready.device
        or receipt.snapshot != _ready_snapshot(ready)
        or ready.plan is not plan
        or ready.confirmation is not confirmation
        or ready.plan_sha256 != plan.plan_sha256
        or ready.final_image_sha256 != plan.final_image_sha256
        or ready.disk_sequence != plan.disk_sequence
        or not _post_unmount_device_matches(plan.device, ready.device)
        or not hmac.compare_digest(_ready_digest(ready), ready.ready_sha256)
    ):
        raise GrubRescueDevicePlanError(
            "The GRUB post-unmount receipt is forged, cloned, or stale",
        )
    status, observation = _target_checks(ready.device)
    _validate_removable_target(ready.device)
    _source_residency(plan, status, observation)
    try:
        sequence = _read_disk_sequence(ready.device.major_minor)
    except SyslinuxDevicePlanError as error:
        raise GrubRescueDevicePlanError(str(error)) from error
    if sequence != ready.disk_sequence:
        raise GrubRescueDevicePlanError(
            "The GRUB target generation changed after unmount authorization",
        )
    _cancel(cancel_check)
