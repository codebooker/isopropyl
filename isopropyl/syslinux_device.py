from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Witnessed target authorization for the private Syslinux image pipeline.

This module deliberately stops before privileged device I/O.  It binds one
authentic :class:`SyslinuxIsoFat32Plan` to one exact removable whole disk and an
exact typed confirmation.  The process-local receipt prevents accidental or
forged in-process substitutions; it is not cross-process privilege authority.
A future installed, root-owned helper must treat every serialized expectation as
untrusted and independently verify it while keeping one descriptor and one lock
across writing, ``fsync``, and exact read-back.  Separate privileged ``dd``
invocations are not an acceptable substitute for that transaction boundary.
"""

import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field

from .devices import Device, parse_lsblk
from .syslinux_iso_fat32 import (
    SyslinuxIsoFat32Error,
    SyslinuxIsoFat32Plan,
    validate_syslinux_iso_fat32_plan,
)
from .writer import WriterSafetyError, validate_device_selection


SECTOR_SIZE = 512
TARGET_PLAN_PROFILE = "io.github.codebooker.isopropyl/syslinux-device-plan/v1"
REQUIRED_EXECUTOR_PROFILE = (
    "io.github.codebooker.isopropyl/syslinux-device-helper/v1"
)
_PLAN_TOKEN = object()
_CONFIRMATION_TOKEN = object()
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAJOR_MINOR = re.compile(r"\d+:\d+\Z")
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_TRUSTED_TOOL_DIRECTORIES = frozenset(_TRUSTED_TOOL_PATH.split(":"))
_MAX_LSBLK_OUTPUT = 2 * 1024 * 1024
_LSBLK_FIELDS = (
    "PATH,SIZE,TYPE,RM,HOTPLUG,TRAN,MODEL,VENDOR,SERIAL,WWN,"
    "MAJ:MIN,MOUNTPOINTS,RO,LOG-SEC"
)
_lstat = os.lstat
_run = subprocess.run
_which = shutil.which


class SyslinuxDevicePlanError(RuntimeError):
    """A Syslinux image could not be bound to a safe exact target."""


class SyslinuxDevicePlanCancelled(SyslinuxDevicePlanError):
    """Target authorization was cancelled before a receipt was minted."""


CancelCheck = Callable[[], None]


@dataclass(frozen=True)
class _PlanReceipt:
    token: object
    plan: object
    composite_plan: object
    device: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class _ConfirmationReceipt:
    token: object
    confirmation: object
    plan: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class _LiveTargetObservation:
    device: Device
    related_device_numbers: frozenset[int]


@dataclass(frozen=True)
class SyslinuxDeviceWritePlan:
    """One exact composite image plan authorized for one exact whole disk.

    The plan is intentionally not executable in this milestone.  Its receipt
    prevents an ordinary dataclass clone or refreshed equivalent from acquiring
    authority, while its digest makes every public relationship auditable.
    """

    composite_plan: SyslinuxIsoFat32Plan = field(repr=False, compare=False)
    device: Device
    composite_plan_sha256: str
    private_plan_sha256: str
    source_manifest_sha256: str
    image_size: int
    disk_signature: int
    volume_id: int
    logical_sector_size: int
    firmware_profile: str
    mandatory_readback: bool
    required_executor_profile: str
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
class ConfirmedSyslinuxDeviceWrite:
    """Exact typed confirmation for one authentic target plan."""

    plan: SyslinuxDeviceWritePlan = field(repr=False, compare=False)
    plan_sha256: str
    device_identity: tuple[str, int, str, str, str, str]
    logical_sector_size: int
    confirmation_phrase: str
    _authorization: _ConfirmationReceipt | None = field(
        init=False,
        default=None,
        repr=False,
        compare=False,
    )


def _check_cancelled(cancel_check: CancelCheck | None) -> None:
    if cancel_check is not None:
        cancel_check()


def _bounded(value: object, fallback: str) -> str:
    rendered = str(value or "").replace("\x00", "").strip()
    return rendered[-2_048:] if rendered else fallback


def _phrase_matches(value: object, expected: str) -> bool:
    return (
        type(value) is str
        and value.isascii()
        and hmac.compare_digest(value.encode("ascii"), expected.encode("ascii"))
    )


def _trusted_lsblk() -> str:
    value = _which("lsblk", path=_TRUSTED_TOOL_PATH)
    if not isinstance(value, str):
        raise SyslinuxDevicePlanError("Live target authorization requires util-linux lsblk")
    normalized = os.path.normpath(value)
    if (
        not os.path.isabs(value)
        or normalized != value
        or os.path.dirname(value) not in _TRUSTED_TOOL_DIRECTORIES
        or os.path.basename(value) != "lsblk"
    ):
        raise SyslinuxDevicePlanError(f"Refusing untrusted lsblk path: {value!r}")
    return value


def _node_device_number(node: object) -> int:
    if not isinstance(node, dict):
        raise SyslinuxDevicePlanError("lsblk returned an invalid target topology")
    rendered = node.get("maj:min")
    if type(rendered) is not str or _MAJOR_MINOR.fullmatch(rendered) is None:
        raise SyslinuxDevicePlanError(
            "lsblk omitted a kernel identity from the target topology",
        )
    major, minor = (int(part) for part in rendered.split(":", 1))
    try:
        return os.makedev(major, minor)
    except (OverflowError, ValueError) as error:
        raise SyslinuxDevicePlanError(
            "lsblk returned an invalid kernel identity",
        ) from error


def _topology_device_numbers(root: object) -> frozenset[int]:
    pending = [root]
    found: set[int] = set()
    visited = 0
    while pending:
        node = pending.pop()
        visited += 1
        if visited > 4_096:
            raise SyslinuxDevicePlanError("The target dependency topology is too large")
        found.add(_node_device_number(node))
        if not isinstance(node, dict):
            raise SyslinuxDevicePlanError("lsblk returned an invalid target topology")
        children = node.get("children") or []
        if not isinstance(children, list):
            raise SyslinuxDevicePlanError("lsblk returned an invalid target topology")
        pending.extend(children)
    return frozenset(found)


def _probe_live_target(path: str) -> _LiveTargetObservation:
    lsblk = _trusted_lsblk()
    try:
        result = _run(
            [
                lsblk,
                "--tree",
                "--bytes",
                "--json",
                "--output",
                _LSBLK_FIELDS,
                path,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise SyslinuxDevicePlanError(
            _bounded(error, "Could not freshly inspect the selected target"),
        ) from error
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    if len(stdout.encode("utf-8")) + len(stderr.encode("utf-8")) > _MAX_LSBLK_OUTPUT:
        raise SyslinuxDevicePlanError("Live target inspection produced too much output")
    if result.returncode:
        raise SyslinuxDevicePlanError(
            _bounded(stderr or stdout, "Could not freshly inspect the selected target"),
        )
    try:
        payload = json.loads(stdout)
        if not isinstance(payload, dict):
            raise TypeError("top-level value is not an object")
        roots = payload.get("blockdevices")
        if not isinstance(roots, list):
            raise TypeError("missing blockdevices")
        raw_matches = [
            node for node in roots
            if isinstance(node, dict) and node.get("path") == path
        ]
        devices = [
            item for item in parse_lsblk(stdout, include_usb_hdds=True)
            if item.path == path
        ]
    except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise SyslinuxDevicePlanError("lsblk returned invalid live target data") from error
    if len(raw_matches) != 1 or len(devices) != 1:
        raise SyslinuxDevicePlanError(
            "The selected target disappeared, became unsafe, or is ambiguous",
        )
    return _LiveTargetObservation(
        devices[0],
        _topology_device_numbers(raw_matches[0]),
    )


def _firmware_profile(composite_plan: SyslinuxIsoFat32Plan) -> str:
    layout = composite_plan.iso_plan.write_plan.layout
    if layout is None:
        raise SyslinuxDevicePlanError("The source plan has no target layout")
    # The private builder adds the witnessed Syslinux/MBR BIOS path.  A source
    # layout that retained a verified UEFI path therefore becomes dual-firmware.
    return "bios-and-uefi" if layout.uefi_bootable else "bios-only"


def _warnings(device: Device, firmware_profile: str) -> tuple[str, ...]:
    firmware = (
        "BIOS and retained UEFI"
        if firmware_profile == "bios-and-uefi"
        else "BIOS"
    )
    return (
        f"Everything on {device.path} will be permanently erased.",
        f"This {firmware} Syslinux profile is not yet hardware-certified.",
        "Execution requires one privileged descriptor and lock through exact "
        "SHA-256 read-back; no fallback executor is permitted.",
    )


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


def _plan_digest(plan: SyslinuxDeviceWritePlan) -> str:
    try:
        encoded = json.dumps(
            {
                "profile": TARGET_PLAN_PROFILE,
                "composite": {
                    "plan_sha256": plan.composite_plan_sha256,
                    "private_plan_sha256": plan.private_plan_sha256,
                    "source_manifest_sha256": plan.source_manifest_sha256,
                    "version": plan.composite_plan.version,
                    "dependency_key": plan.composite_plan.dependency_key,
                    "config_directory": plan.composite_plan.config_directory,
                    "c32_bundle_sha256": plan.composite_plan.c32_bundle_sha256,
                    "payload_bundle_sha256": plan.composite_plan.payload_bundle_sha256,
                },
                "image": {
                    "size": plan.image_size,
                    "disk_signature": plan.disk_signature,
                    "volume_id": plan.volume_id,
                },
                "target": _device_payload(plan.device),
                "logical_sector_size": plan.logical_sector_size,
                "firmware_profile": plan.firmware_profile,
                "mandatory_readback": plan.mandatory_readback,
                "required_executor_profile": plan.required_executor_profile,
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


def _plan_snapshot(plan: SyslinuxDeviceWritePlan) -> tuple[object, ...]:
    return (
        plan.composite_plan_sha256,
        plan.private_plan_sha256,
        plan.source_manifest_sha256,
        plan.image_size,
        plan.disk_signature,
        plan.volume_id,
        plan.logical_sector_size,
        plan.firmware_profile,
        plan.mandatory_readback,
        plan.required_executor_profile,
        plan.warnings,
        plan.confirmation_phrase,
        plan.plan_sha256,
    )


def _confirmation_snapshot(
    confirmation: ConfirmedSyslinuxDeviceWrite,
) -> tuple[object, ...]:
    return (
        confirmation.plan_sha256,
        confirmation.device_identity,
        confirmation.logical_sector_size,
        confirmation.confirmation_phrase,
    )


def _validate_target_node(device: Device) -> os.stat_result:
    try:
        info = _lstat(device.path)
    except OSError as error:
        raise SyslinuxDevicePlanError(
            _bounded(error, "The selected target is no longer available"),
        ) from error
    if not stat.S_ISBLK(info.st_mode):
        raise SyslinuxDevicePlanError(
            "The selected target path is not a whole-disk block device",
        )
    actual = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    if actual != device.major_minor:
        raise SyslinuxDevicePlanError(
            "The selected target's kernel device number changed",
        )
    return info


def _validate_source_residency(
    plan: SyslinuxDeviceWritePlan,
    target_status: os.stat_result,
    observation: _LiveTargetObservation,
) -> None:
    composite = plan.composite_plan
    manifest = composite.staging_result.tree_manifest
    if manifest is None or not manifest.source_directories:
        raise SyslinuxDevicePlanError("The authenticated staging root identity is missing")
    source_device = manifest.source_directories[0].device
    workspace_device = composite.private_plan.workspace_identity.device
    related = observation.related_device_numbers
    if target_status.st_rdev not in related:
        raise SyslinuxDevicePlanError(
            "The block node and live target topology disagree",
        )
    if source_device in related or workspace_device in related:
        raise SyslinuxDevicePlanError(
            "The staged source or private workspace resides on the target drive",
        )


def _validate_live_target(
    device: Device,
    target_status: os.stat_result,
) -> _LiveTargetObservation:
    observation = _probe_live_target(device.path)
    if type(observation) is not _LiveTargetObservation:
        raise SyslinuxDevicePlanError("Live target inspection returned invalid evidence")
    if observation.device != device:
        raise SyslinuxDevicePlanError(
            "The selected target changed after discovery; refresh and confirm it again",
        )
    if target_status.st_rdev not in observation.related_device_numbers:
        raise SyslinuxDevicePlanError(
            "The selected block node is absent from its live target topology",
        )
    return observation


def _validate_relationships(
    plan: SyslinuxDeviceWritePlan,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    if type(plan) is not SyslinuxDeviceWritePlan:
        raise SyslinuxDevicePlanError("An exact Syslinux device plan is required")
    receipt = plan._authorization
    if (
        type(receipt) is not _PlanReceipt
        or receipt.token is not _PLAN_TOKEN
        or receipt.plan is not plan
        or receipt.composite_plan is not plan.composite_plan
        or receipt.device is not plan.device
        or receipt.snapshot != _plan_snapshot(plan)
    ):
        raise SyslinuxDevicePlanError(
            "The Syslinux target authorization is missing or no longer authoritative",
        )
    if type(plan.composite_plan) is not SyslinuxIsoFat32Plan:
        raise SyslinuxDevicePlanError("The target plan contains no authentic composite plan")
    try:
        validate_syslinux_iso_fat32_plan(
            plan.composite_plan,
            cancel_check=cancel_check,
        )
    except SyslinuxIsoFat32Error as error:
        raise SyslinuxDevicePlanError(str(error)) from error
    _check_cancelled(cancel_check)
    if type(plan.device) is not Device:
        raise SyslinuxDevicePlanError("The target plan contains an invalid device record")
    try:
        validate_device_selection(plan.device, writable=True)
    except WriterSafetyError as error:
        raise SyslinuxDevicePlanError(str(error)) from error
    private = plan.composite_plan.private_plan
    expected_profile = _firmware_profile(plan.composite_plan)
    expected_warnings = _warnings(plan.device, expected_profile)
    expected_phrase = f"WRITE BIOS {plan.device.path} {plan.device.major_minor}"
    for label, value in (
        ("composite plan", plan.composite_plan_sha256),
        ("private plan", plan.private_plan_sha256),
        ("source manifest", plan.source_manifest_sha256),
        ("target plan", plan.plan_sha256),
    ):
        if type(value) is not str or _SHA256.fullmatch(value) is None:
            raise SyslinuxDevicePlanError(f"The {label} digest is invalid")
    if (
        plan.composite_plan_sha256 != plan.composite_plan.plan_sha256
        or plan.private_plan_sha256 != private.plan_sha256
        or plan.source_manifest_sha256 != plan.composite_plan.source_manifest_sha256
        or plan.image_size != private.geometry.image_size
        or plan.disk_signature != private.disk_signature
        or plan.volume_id != private.volume_id
        or plan.device.size != plan.image_size
        or plan.device.size % SECTOR_SIZE
        or plan.logical_sector_size != SECTOR_SIZE
        or plan.device.logical_sector_size != SECTOR_SIZE
        or plan.firmware_profile != expected_profile
        or plan.mandatory_readback is not True
        or plan.required_executor_profile != REQUIRED_EXECUTOR_PROFILE
        or plan.warnings != expected_warnings
        or plan.confirmation_phrase != expected_phrase
        or not hmac.compare_digest(_plan_digest(plan), plan.plan_sha256)
    ):
        raise SyslinuxDevicePlanError(
            "The Syslinux image, target geometry, and authorization bindings disagree",
        )
    target_status = _validate_target_node(plan.device)
    observation = _validate_live_target(plan.device, target_status)
    _validate_source_residency(plan, target_status, observation)
    _check_cancelled(cancel_check)


def build_syslinux_device_write_plan(
    composite_plan: SyslinuxIsoFat32Plan,
    device: Device,
    *,
    cancel_check: CancelCheck | None = None,
) -> SyslinuxDeviceWritePlan:
    """Bind one authentic composite plan to one exact 512-byte-sector target."""

    if type(composite_plan) is not SyslinuxIsoFat32Plan:
        raise SyslinuxDevicePlanError("An authentic Syslinux composite plan is required")
    try:
        validate_syslinux_iso_fat32_plan(
            composite_plan,
            cancel_check=cancel_check,
        )
    except SyslinuxIsoFat32Error as error:
        raise SyslinuxDevicePlanError(str(error)) from error
    if type(device) is not Device:
        raise SyslinuxDevicePlanError("A discovered removable Device is required")
    try:
        validate_device_selection(device, writable=True)
    except WriterSafetyError as error:
        raise SyslinuxDevicePlanError(str(error)) from error
    private = composite_plan.private_plan
    if device.logical_sector_size != SECTOR_SIZE:
        raise SyslinuxDevicePlanError(
            "The initial Syslinux target profile requires 512-byte logical sectors",
        )
    if device.size != private.geometry.image_size:
        raise SyslinuxDevicePlanError(
            "The target capacity must exactly match the witnessed Syslinux image size",
        )
    if device.size % SECTOR_SIZE:
        raise SyslinuxDevicePlanError("The target capacity is not sector aligned")
    target_status = _validate_target_node(device)
    observation = _validate_live_target(device, target_status)
    firmware_profile = _firmware_profile(composite_plan)
    candidate = SyslinuxDeviceWritePlan(
        composite_plan,
        device,
        composite_plan.plan_sha256,
        private.plan_sha256,
        composite_plan.source_manifest_sha256,
        private.geometry.image_size,
        private.disk_signature,
        private.volume_id,
        device.logical_sector_size,
        firmware_profile,
        True,
        REQUIRED_EXECUTOR_PROFILE,
        _warnings(device, firmware_profile),
        f"WRITE BIOS {device.path} {device.major_minor}",
        "",
    )
    plan = SyslinuxDeviceWritePlan(
        candidate.composite_plan,
        candidate.device,
        candidate.composite_plan_sha256,
        candidate.private_plan_sha256,
        candidate.source_manifest_sha256,
        candidate.image_size,
        candidate.disk_signature,
        candidate.volume_id,
        candidate.logical_sector_size,
        candidate.firmware_profile,
        candidate.mandatory_readback,
        candidate.required_executor_profile,
        candidate.warnings,
        candidate.confirmation_phrase,
        _plan_digest(candidate),
    )
    if not hmac.compare_digest(_plan_digest(plan), plan.plan_sha256):
        raise SyslinuxDevicePlanError("The target authorization digest is inconsistent")
    _validate_source_residency(plan, target_status, observation)
    _check_cancelled(cancel_check)
    object.__setattr__(
        plan,
        "_authorization",
        _PlanReceipt(
            _PLAN_TOKEN,
            plan,
            composite_plan,
            device,
            _plan_snapshot(plan),
        ),
    )
    return plan


def validate_syslinux_device_write_plan(
    plan: SyslinuxDeviceWritePlan,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    """Revalidate the live source, exact target node, and every plan binding."""

    _validate_relationships(plan, cancel_check=cancel_check)


def confirm_syslinux_device_write(
    plan: SyslinuxDeviceWritePlan,
    phrase: str,
    *,
    cancel_check: CancelCheck | None = None,
) -> ConfirmedSyslinuxDeviceWrite:
    """Mint a receipt only for an exact, case-sensitive destructive phrase."""

    _validate_relationships(plan, cancel_check=cancel_check)
    if not _phrase_matches(phrase, plan.confirmation_phrase):
        raise SyslinuxDevicePlanError("The destructive confirmation phrase did not match")
    confirmation = ConfirmedSyslinuxDeviceWrite(
        plan,
        plan.plan_sha256,
        plan.device.identity,
        plan.logical_sector_size,
        phrase,
    )
    _check_cancelled(cancel_check)
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
    return confirmation


def validate_confirmed_syslinux_device_write(
    plan: SyslinuxDeviceWritePlan,
    confirmation: ConfirmedSyslinuxDeviceWrite,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    """Validate that a confirmation belongs to this exact authoritative plan."""

    _validate_relationships(plan, cancel_check=cancel_check)
    if type(confirmation) is not ConfirmedSyslinuxDeviceWrite:
        raise SyslinuxDevicePlanError("An exact Syslinux target confirmation is required")
    receipt = confirmation._authorization
    if (
        type(receipt) is not _ConfirmationReceipt
        or receipt.token is not _CONFIRMATION_TOKEN
        or receipt.confirmation is not confirmation
        or receipt.plan is not plan
        or receipt.snapshot != _confirmation_snapshot(confirmation)
        or confirmation.plan is not plan
        or confirmation.plan_sha256 != plan.plan_sha256
        or confirmation.device_identity != plan.device.identity
        or confirmation.logical_sector_size != plan.logical_sector_size
        or not _phrase_matches(
            confirmation.confirmation_phrase,
            plan.confirmation_phrase,
        )
    ):
        raise SyslinuxDevicePlanError(
            "The Syslinux target confirmation is forged, cloned, or belongs to another plan",
        )
    _check_cancelled(cancel_check)
