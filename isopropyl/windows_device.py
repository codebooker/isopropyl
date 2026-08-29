from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Backend-only authorization for one prepared Windows dual-firmware image."""

import hashlib
import hmac
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from .devices import Device
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
from .windows_iso_fat32 import (
    WindowsIsoFat32Error,
    WindowsIsoFat32Plan,
    validate_windows_iso_fat32_plan,
)
from .writer import WriterSafetyError, validate_device_selection


SECTOR_SIZE = 512
TARGET_PLAN_PROFILE = "io.github.codebooker.isopropyl/windows-device-plan/v1"
REQUIRED_EXECUTOR_PROFILE = "io.github.codebooker.isopropyl/windows-device-helper/v1"
WINDOWS_IMAGE_PROFILE = "windows-11-modern-entry-zero/bios+uefi/fat32-mbr/v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PLAN_TOKEN = object()
_CONFIRM_TOKEN = object()
_READY_TOKEN = object()

CancelCheck = Callable[[], None]


class WindowsDevicePlanError(RuntimeError):
    pass


class WindowsDevicePlanCancelled(WindowsDevicePlanError):
    pass


@dataclass(frozen=True)
class _Receipt:
    token: object
    owner: object
    plan: object
    related: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class WindowsDeviceWritePlan:
    composite_plan: WindowsIsoFat32Plan = field(repr=False, compare=False)
    device: Device
    disk_sequence: int
    composite_plan_sha256: str
    private_plan_sha256: str
    source_manifest_sha256: str
    bootmgr_sha256: str
    bcd_sha256: str
    bootx64_sha256: str
    image_size: int
    disk_signature: int
    volume_id: int
    logical_sector_size: int
    image_profile: str
    mandatory_readback: bool
    required_executor_profile: str
    warnings: tuple[str, ...]
    confirmation_phrase: str
    plan_sha256: str
    _authorization: _Receipt | None = field(init=False, default=None, repr=False, compare=False)


@dataclass(frozen=True)
class ConfirmedWindowsDeviceWrite:
    plan: WindowsDeviceWritePlan = field(repr=False, compare=False)
    plan_sha256: str
    device_identity: tuple[str, int, str, str, str, str]
    confirmation_phrase: str
    _authorization: _Receipt | None = field(init=False, default=None, repr=False, compare=False)


@dataclass(frozen=True)
class ReadyWindowsDeviceWrite:
    plan: WindowsDeviceWritePlan = field(repr=False, compare=False)
    confirmation: ConfirmedWindowsDeviceWrite = field(repr=False, compare=False)
    device: Device
    disk_sequence: int
    plan_sha256: str
    ready_sha256: str
    _authorization: _Receipt | None = field(init=False, default=None, repr=False, compare=False)


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
        "This Windows BIOS+UEFI FAT32 profile has not completed physical-media certification.",
        "The privileged transaction requires MBR-last activation and complete SHA-256 read-back.",
    )


def _snapshot(plan: WindowsDeviceWritePlan) -> tuple[object, ...]:
    return (
        plan.composite_plan_sha256, plan.private_plan_sha256,
        plan.source_manifest_sha256, plan.bootmgr_sha256, plan.bcd_sha256,
        plan.bootx64_sha256, plan.disk_sequence, plan.image_size,
        plan.disk_signature, plan.volume_id, plan.logical_sector_size,
        plan.image_profile, plan.mandatory_readback,
        plan.required_executor_profile, plan.warnings,
        plan.confirmation_phrase, plan.plan_sha256,
    )


def _confirmation_snapshot(value: ConfirmedWindowsDeviceWrite) -> tuple[object, ...]:
    return (value.plan_sha256, value.device_identity, value.confirmation_phrase)


def _ready_snapshot(value: ReadyWindowsDeviceWrite) -> tuple[object, ...]:
    return (value.plan_sha256, value.disk_sequence, value.ready_sha256, value.device)


def _plan_digest(plan: WindowsDeviceWritePlan) -> str:
    try:
        value = json.dumps(
            {
                "profile": TARGET_PLAN_PROFILE,
                "composite": {
                    "plan": plan.composite_plan_sha256,
                    "private": plan.private_plan_sha256,
                    "manifest": plan.source_manifest_sha256,
                    "bootmgr": plan.bootmgr_sha256,
                    "bcd": plan.bcd_sha256,
                    "bootx64": plan.bootx64_sha256,
                },
                "target": _device_payload(plan.device),
                "disk_sequence": plan.disk_sequence,
                "image_size": plan.image_size,
                "disk_signature": plan.disk_signature,
                "volume_id": plan.volume_id,
                "logical_sector_size": plan.logical_sector_size,
                "image_profile": plan.image_profile,
                "mandatory_readback": plan.mandatory_readback,
                "executor": plan.required_executor_profile,
                "warnings": list(plan.warnings),
                "confirmation": plan.confirmation_phrase,
            },
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return ""
    return hashlib.sha256(value).hexdigest()


def _ready_digest(value: ReadyWindowsDeviceWrite) -> str:
    try:
        encoded = json.dumps(
            {
                "profile": "io.github.codebooker.isopropyl/windows-ready-target/v1",
                "plan": value.plan_sha256,
                "disk_sequence": value.disk_sequence,
                "original": _device_payload(value.plan.device),
                "unmounted": _device_payload(value.device),
            },
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return ""
    return hashlib.sha256(encoded).hexdigest()


def _target_checks(device: Device) -> tuple[object, _LiveTargetObservation]:
    try:
        status = _validate_target_node(device)
        observation = _validate_live_target(device, status)
    except SyslinuxDevicePlanError as error:
        raise WindowsDevicePlanError(str(error)) from error
    return status, observation


def _source_residency(plan: WindowsDeviceWritePlan, status: object, observation: _LiveTargetObservation) -> None:
    manifest = plan.composite_plan.staging_result.tree_manifest
    if manifest is None or not manifest.source_directories:
        raise WindowsDevicePlanError("The witnessed Windows staging-root identity is missing")
    related = observation.related_device_numbers
    if status.st_rdev not in related:
        raise WindowsDevicePlanError("The target node and topology disagree")
    if (
        manifest.source_directories[0].device in related
        or plan.composite_plan.private_plan.workspace_identity.device in related
    ):
        raise WindowsDevicePlanError("The Windows source or workspace resides on the target")


def _validate_receipt(plan: WindowsDeviceWritePlan, cancel_check: CancelCheck | None) -> None:
    if type(plan) is not WindowsDeviceWritePlan:
        raise WindowsDevicePlanError("An exact Windows device plan is required")
    receipt = plan._authorization
    if (
        type(receipt) is not _Receipt or receipt.token is not _PLAN_TOKEN
        or receipt.owner is not plan or receipt.plan is not plan.composite_plan
        or receipt.related is not plan.device or receipt.snapshot != _snapshot(plan)
    ):
        raise WindowsDevicePlanError("The Windows target authorization is missing or stale")
    try:
        validate_windows_iso_fat32_plan(plan.composite_plan, cancel_check=cancel_check)
    except WindowsIsoFat32Error as error:
        raise WindowsDevicePlanError(str(error)) from error
    try:
        validate_device_selection(plan.device, writable=True)
    except WriterSafetyError as error:
        raise WindowsDevicePlanError(str(error)) from error
    private = plan.composite_plan.private_plan
    digests = (
        plan.composite_plan_sha256, plan.private_plan_sha256,
        plan.source_manifest_sha256, plan.bootmgr_sha256,
        plan.bcd_sha256, plan.bootx64_sha256, plan.plan_sha256,
    )
    expected_phrase = f"WRITE WINDOWS DUAL {plan.device.path} {plan.device.major_minor}"
    if (
        any(type(item) is not str or _SHA256.fullmatch(item) is None for item in digests)
        or plan.composite_plan_sha256 != plan.composite_plan.plan_sha256
        or plan.private_plan_sha256 != private.plan_sha256
        or plan.source_manifest_sha256 != plan.composite_plan.source_manifest_sha256
        or plan.bootmgr_sha256 != plan.composite_plan.bootmgr_sha256
        or plan.bcd_sha256 != plan.composite_plan.bcd_sha256
        or plan.bootx64_sha256 != plan.composite_plan.bootx64_sha256
        or plan.image_size != private.geometry.image_size
        or plan.device.size != plan.image_size
        or plan.disk_signature != private.disk_signature
        or plan.volume_id != private.volume_id
        or type(plan.disk_sequence) is not int or isinstance(plan.disk_sequence, bool)
        or not 0 < plan.disk_sequence <= 0xFFFFFFFFFFFFFFFF
        or plan.logical_sector_size != SECTOR_SIZE
        or plan.device.logical_sector_size != SECTOR_SIZE
        or not plan.device.removable
        or plan.image_profile != WINDOWS_IMAGE_PROFILE
        or plan.mandatory_readback is not True
        or plan.required_executor_profile != REQUIRED_EXECUTOR_PROFILE
        or plan.warnings != _warnings(plan.device)
        or plan.confirmation_phrase != expected_phrase
        or not hmac.compare_digest(_plan_digest(plan), plan.plan_sha256)
    ):
        raise WindowsDevicePlanError("The Windows image and target bindings disagree")
    _cancel(cancel_check)


def _validate_live(plan: WindowsDeviceWritePlan, cancel_check: CancelCheck | None) -> None:
    _validate_receipt(plan, cancel_check)
    status, observation = _target_checks(plan.device)
    _source_residency(plan, status, observation)
    try:
        sequence = _read_disk_sequence(plan.device.major_minor)
    except SyslinuxDevicePlanError as error:
        raise WindowsDevicePlanError(str(error)) from error
    if sequence != plan.disk_sequence:
        raise WindowsDevicePlanError("The Windows target is a different disk generation")
    _cancel(cancel_check)


def build_windows_device_write_plan(
    composite_plan: WindowsIsoFat32Plan,
    device: Device,
    *,
    cancel_check: CancelCheck | None = None,
) -> WindowsDeviceWritePlan:
    try:
        validate_windows_iso_fat32_plan(composite_plan, cancel_check=cancel_check)
    except WindowsIsoFat32Error as error:
        raise WindowsDevicePlanError(str(error)) from error
    if type(device) is not Device:
        raise WindowsDevicePlanError("A discovered removable Device is required")
    try:
        validate_device_selection(device, writable=True)
    except WriterSafetyError as error:
        raise WindowsDevicePlanError(str(error)) from error
    private = composite_plan.private_plan
    if not device.removable or device.logical_sector_size != SECTOR_SIZE:
        raise WindowsDevicePlanError("Windows device writing requires removable 512-byte media")
    if device.size != private.geometry.image_size or device.size % SECTOR_SIZE:
        raise WindowsDevicePlanError("The target capacity must exactly match the Windows image")
    status, observation = _target_checks(device)
    try:
        sequence = _read_disk_sequence(device.major_minor)
    except SyslinuxDevicePlanError as error:
        raise WindowsDevicePlanError(str(error)) from error
    candidate = WindowsDeviceWritePlan(
        composite_plan, device, sequence, composite_plan.plan_sha256,
        private.plan_sha256, composite_plan.source_manifest_sha256,
        composite_plan.bootmgr_sha256, composite_plan.bcd_sha256,
        composite_plan.bootx64_sha256, private.geometry.image_size,
        private.disk_signature, private.volume_id, device.logical_sector_size,
        WINDOWS_IMAGE_PROFILE, True, REQUIRED_EXECUTOR_PROFILE,
        _warnings(device),
        f"WRITE WINDOWS DUAL {device.path} {device.major_minor}", "",
    )
    plan = replace(candidate, plan_sha256=_plan_digest(candidate))
    _source_residency(plan, status, observation)
    _cancel(cancel_check)
    object.__setattr__(
        plan, "_authorization",
        _Receipt(_PLAN_TOKEN, plan, composite_plan, device, _snapshot(plan)),
    )
    return plan


def validate_windows_device_write_plan(
    plan: WindowsDeviceWritePlan,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    _validate_live(plan, cancel_check)


def confirm_windows_device_write(
    plan: WindowsDeviceWritePlan,
    phrase: str,
    *,
    cancel_check: CancelCheck | None = None,
) -> ConfirmedWindowsDeviceWrite:
    _validate_live(plan, cancel_check)
    if not _phrase_matches(phrase, plan.confirmation_phrase):
        raise WindowsDevicePlanError("The Windows destructive confirmation phrase did not match")
    value = ConfirmedWindowsDeviceWrite(plan, plan.plan_sha256, plan.device.identity, phrase)
    object.__setattr__(
        value, "_authorization",
        _Receipt(_CONFIRM_TOKEN, value, plan, plan.device, _confirmation_snapshot(value)),
    )
    return value


def _validate_confirmation(plan: WindowsDeviceWritePlan, value: ConfirmedWindowsDeviceWrite) -> None:
    if type(value) is not ConfirmedWindowsDeviceWrite:
        raise WindowsDevicePlanError("An exact Windows target confirmation is required")
    receipt = value._authorization
    if (
        type(receipt) is not _Receipt or receipt.token is not _CONFIRM_TOKEN
        or receipt.owner is not value or receipt.plan is not plan
        or receipt.related is not plan.device
        or receipt.snapshot != _confirmation_snapshot(value)
        or value.plan is not plan or value.plan_sha256 != plan.plan_sha256
        or value.device_identity != plan.device.identity
        or not _phrase_matches(value.confirmation_phrase, plan.confirmation_phrase)
    ):
        raise WindowsDevicePlanError("The Windows confirmation is forged, cloned, or stale")


def validate_confirmed_windows_device_write(
    plan: WindowsDeviceWritePlan,
    confirmation: ConfirmedWindowsDeviceWrite,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    _validate_live(plan, cancel_check)
    _validate_confirmation(plan, confirmation)
    _cancel(cancel_check)


def authorize_unmounted_windows_device_write(
    plan: WindowsDeviceWritePlan,
    confirmation: ConfirmedWindowsDeviceWrite,
    *,
    cancel_check: CancelCheck | None = None,
) -> ReadyWindowsDeviceWrite:
    _validate_receipt(plan, cancel_check)
    _validate_confirmation(plan, confirmation)
    try:
        status = _validate_target_node(plan.device)
        observation = _probe_live_target(plan.device.path)
    except SyslinuxDevicePlanError as error:
        raise WindowsDevicePlanError(str(error)) from error
    current = observation.device
    if not _post_unmount_device_matches(plan.device, current):
        raise WindowsDevicePlanError("The Windows target changed or remains mounted")
    try:
        validate_device_selection(current, writable=True)
    except WriterSafetyError as error:
        raise WindowsDevicePlanError(str(error)) from error
    _source_residency(plan, status, observation)
    try:
        sequence = _read_disk_sequence(current.major_minor)
    except SyslinuxDevicePlanError as error:
        raise WindowsDevicePlanError(str(error)) from error
    if sequence != plan.disk_sequence:
        raise WindowsDevicePlanError("The target generation changed during unmount")
    candidate = ReadyWindowsDeviceWrite(plan, confirmation, current, sequence, plan.plan_sha256, "")
    ready = replace(candidate, ready_sha256=_ready_digest(candidate))
    object.__setattr__(
        ready, "_authorization",
        _Receipt(_READY_TOKEN, ready, plan, confirmation, _ready_snapshot(ready)),
    )
    return ready


def validate_ready_windows_device_write(
    plan: WindowsDeviceWritePlan,
    confirmation: ConfirmedWindowsDeviceWrite,
    ready: ReadyWindowsDeviceWrite,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    _validate_receipt(plan, cancel_check)
    _validate_confirmation(plan, confirmation)
    if type(ready) is not ReadyWindowsDeviceWrite:
        raise WindowsDevicePlanError("An exact Windows post-unmount receipt is required")
    receipt = ready._authorization
    if (
        type(receipt) is not _Receipt or receipt.token is not _READY_TOKEN
        or receipt.owner is not ready or receipt.plan is not plan
        or receipt.related is not confirmation
        or receipt.snapshot != _ready_snapshot(ready)
        or ready.plan is not plan or ready.confirmation is not confirmation
        or ready.plan_sha256 != plan.plan_sha256
        or ready.disk_sequence != plan.disk_sequence
        or not _post_unmount_device_matches(plan.device, ready.device)
        or not hmac.compare_digest(_ready_digest(ready), ready.ready_sha256)
    ):
        raise WindowsDevicePlanError("The Windows post-unmount receipt is forged or stale")
    status, observation = _target_checks(ready.device)
    _source_residency(plan, status, observation)
    try:
        sequence = _read_disk_sequence(ready.device.major_minor)
    except SyslinuxDevicePlanError as error:
        raise WindowsDevicePlanError(str(error)) from error
    if sequence != ready.disk_sequence:
        raise WindowsDevicePlanError("The target generation changed after unmount authorization")
    _cancel(cancel_check)
