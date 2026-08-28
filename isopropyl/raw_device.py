from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Witnessed target authorization for generic raw-image transactions.

This module deliberately stops before image preparation, privilege elevation,
or target I/O.  It binds immutable evidence for one selected source snapshot to
one complete live :class:`~isopropyl.devices.Device` observation, its kernel
device number and disk generation, and an exact typed confirmation.  Local
receipts make dataclass clones and cross-wired plans non-authoritative; the
future privileged helper must still establish all kernel evidence itself.
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
from pathlib import Path

from .devices import Device, parse_lsblk
from .raw_snapshot import PreparedRawSnapshot, RawSnapshotResult, RawSnapshotState
from .writer import WriterSafetyError, validate_device_selection


SECTOR_SIZE = 512
MAX_RAW_SOURCE_BYTES = 64 * 1024 * 1024 * 1024 * 1024
MAX_RAW_DEVICE_BYTES = 64 * 1024 * 1024 * 1024 * 1024 * 1024
TARGET_PLAN_PROFILE = "io.github.codebooker.isopropyl/raw-device-plan/v1"
SOURCE_EVIDENCE_PROFILE = (
    "io.github.codebooker.isopropyl/raw-source-evidence/v1"
)
READY_TARGET_PROFILE = (
    "io.github.codebooker.isopropyl/raw-ready-target/v1"
)
REQUIRED_EXECUTOR_PROFILE = (
    "io.github.codebooker.isopropyl/raw-device-helper/v1"
)
_PLAN_TOKEN = object()
_CONFIRMATION_TOKEN = object()
_READY_TOKEN = object()
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAJOR_MINOR = re.compile(r"\d+:\d+\Z")
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_TRUSTED_TOOL_DIRECTORIES = frozenset(_TRUSTED_TOOL_PATH.split(":"))
_MAX_LSBLK_OUTPUT = 2 * 1024 * 1024
_SYSFS_ROOT = Path("/sys")
_LSBLK_FIELDS = (
    "PATH,SIZE,TYPE,RM,HOTPLUG,TRAN,MODEL,VENDOR,SERIAL,WWN,"
    "MAJ:MIN,MOUNTPOINTS,RO,LOG-SEC"
)
_lstat = os.lstat
_run = subprocess.run
_which = shutil.which


class RawDevicePlanError(RuntimeError):
    """A raw source could not be bound to a safe exact target."""


class RawDevicePlanCancelled(RawDevicePlanError):
    """Raw target authorization was cancelled before a receipt was minted."""


CancelCheck = Callable[[], None]


def _is_plain_int(value: object) -> bool:
    return type(value) is int


def _source_evidence_digest(evidence: RawSourceEvidence) -> str:
    try:
        encoded = json.dumps(
            {
                "profile": SOURCE_EVIDENCE_PROFILE,
                "raw_snapshot_plan_sha256": (
                    evidence.raw_snapshot_plan_sha256
                ),
                "source_sha256": evidence.source_sha256,
                "source_size": evidence.source_size,
                "original_identity": {
                    "device": evidence.original_device,
                    "inode": evidence.original_inode,
                    "size": evidence.original_size,
                    "modified_ns": evidence.original_modified_ns,
                    "changed_ns": evidence.original_changed_ns,
                },
                "workspace_device": evidence.workspace_device,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return ""
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class RawSourceEvidence:
    """Minimal immutable evidence produced by a future raw snapshot plan.

    ``source_size`` and ``source_sha256`` describe the exact expanded bytes
    intended for the helper.  The five ``original_*`` values bind the selected
    source's discovery-time stat identity.  ``raw_snapshot_plan_sha256`` binds
    the authentic snapshot plan that produced these bytes, while
    ``snapshot_plan_sha256`` is a derived evidence digest covering every
    public input including the workspace's filesystem device.
    """

    source_sha256: str
    source_size: int
    original_device: int
    original_inode: int
    original_size: int
    original_modified_ns: int
    original_changed_ns: int
    workspace_device: int
    raw_snapshot_plan_sha256: str
    snapshot_plan_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.source_sha256) is not str or _SHA256.fullmatch(
            self.source_sha256,
        ) is None:
            raise RawDevicePlanError("The raw source digest is invalid")
        if (
            type(self.raw_snapshot_plan_sha256) is not str
            or _SHA256.fullmatch(self.raw_snapshot_plan_sha256) is None
        ):
            raise RawDevicePlanError("The raw snapshot plan digest is invalid")
        if not _is_plain_int(self.source_size) or self.source_size <= 0:
            raise RawDevicePlanError("The raw source size is invalid")
        if not _is_plain_int(self.original_size) or self.original_size <= 0:
            raise RawDevicePlanError("The selected source size is invalid")
        for label, value in (
            ("device", self.original_device),
            ("inode", self.original_inode),
            ("modified time", self.original_modified_ns),
            ("changed time", self.original_changed_ns),
            ("workspace device", self.workspace_device),
        ):
            if not _is_plain_int(value) or value < 0:
                raise RawDevicePlanError(
                    f"The selected source {label} is invalid",
                )
        if self.original_inode == 0:
            raise RawDevicePlanError("The selected source inode is invalid")
        object.__setattr__(
            self,
            "snapshot_plan_sha256",
            _source_evidence_digest(self),
        )

    @property
    def original_identity(self) -> tuple[int, int, int, int, int]:
        return (
            self.original_device,
            self.original_inode,
            self.original_size,
            self.original_modified_ns,
            self.original_changed_ns,
        )


def raw_source_evidence_from_snapshot(
    prepared: PreparedRawSnapshot,
) -> RawSourceEvidence:
    """Derive target-plan evidence from one completed anonymous snapshot."""

    if (
        type(prepared) is not PreparedRawSnapshot
        or prepared.state is not RawSnapshotState.READY
        or type(prepared.result) is not RawSnapshotResult
    ):
        raise RawDevicePlanError("An exact ready raw snapshot is required")
    result = prepared.result
    try:
        evidence = RawSourceEvidence(
            source_sha256=result.image_sha256,
            source_size=result.image_size,
            original_device=result.source_identity.device,
            original_inode=result.source_identity.inode,
            original_size=result.source_identity.size,
            original_modified_ns=result.source_identity.modified_ns,
            original_changed_ns=result.source_identity.changed_ns,
            workspace_device=result.workspace_identity.device,
            raw_snapshot_plan_sha256=result.plan_sha256,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise RawDevicePlanError(
            "The completed raw snapshot evidence is malformed",
        ) from error
    return evidence


@dataclass(frozen=True)
class _PlanReceipt:
    token: object
    plan: object
    source_evidence: object
    device: object
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
    device: object
    snapshot: tuple[object, ...]


@dataclass(frozen=True)
class _LiveTargetObservation:
    device: Device
    related_device_numbers: frozenset[int]


@dataclass(frozen=True)
class RawDeviceWritePlan:
    """One exact source snapshot plan authorized for one exact whole disk."""

    source_evidence: RawSourceEvidence = field(repr=False, compare=False)
    device: Device
    disk_sequence: int
    raw_snapshot_plan_sha256: str
    snapshot_plan_sha256: str
    source_sha256: str
    source_size: int
    original_source_identity: tuple[int, int, int, int, int]
    workspace_device: int
    target_capacity: int
    logical_sector_size: int
    mandatory_preactivation_readback: bool
    final_verification_requested: bool
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
class ConfirmedRawDeviceWrite:
    """Exact typed confirmation for one authoritative raw target plan."""

    plan: RawDeviceWritePlan = field(repr=False, compare=False)
    plan_sha256: str
    source_sha256: str
    source_size: int
    device_identity: tuple[str, int, str, str, str, str]
    target_capacity: int
    logical_sector_size: int
    final_verification_requested: bool
    confirmation_phrase: str
    _authorization: _ConfirmationReceipt | None = field(
        init=False,
        default=None,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class ReadyRawDeviceWrite:
    """Fresh post-unmount target evidence for the future raw helper."""

    plan: RawDeviceWritePlan = field(repr=False, compare=False)
    confirmation: ConfirmedRawDeviceWrite = field(repr=False, compare=False)
    device: Device
    disk_sequence: int
    plan_sha256: str
    ready_sha256: str
    _authorization: _ReadyReceipt | None = field(
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
        raise RawDevicePlanError(
            "Live target authorization requires util-linux lsblk",
        )
    normalized = os.path.normpath(value)
    if (
        not os.path.isabs(value)
        or normalized != value
        or os.path.dirname(value) not in _TRUSTED_TOOL_DIRECTORIES
        or os.path.basename(value) != "lsblk"
    ):
        raise RawDevicePlanError(f"Refusing untrusted lsblk path: {value!r}")
    return value


def _node_device_number(node: object) -> int:
    if not isinstance(node, dict):
        raise RawDevicePlanError("lsblk returned an invalid target topology")
    rendered = node.get("maj:min")
    if type(rendered) is not str or _MAJOR_MINOR.fullmatch(rendered) is None:
        raise RawDevicePlanError(
            "lsblk omitted a kernel identity from the target topology",
        )
    major, minor = (int(part) for part in rendered.split(":", 1))
    try:
        return os.makedev(major, minor)
    except (OverflowError, ValueError) as error:
        raise RawDevicePlanError(
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
            raise RawDevicePlanError("The target dependency topology is too large")
        found.add(_node_device_number(node))
        if not isinstance(node, dict):
            raise RawDevicePlanError("lsblk returned an invalid target topology")
        children = node.get("children") or []
        if not isinstance(children, list):
            raise RawDevicePlanError("lsblk returned an invalid target topology")
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
        raise RawDevicePlanError(
            _bounded(error, "Could not freshly inspect the selected target"),
        ) from error
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    if len(stdout.encode("utf-8")) + len(stderr.encode("utf-8")) > (
        _MAX_LSBLK_OUTPUT
    ):
        raise RawDevicePlanError("Live target inspection produced too much output")
    if result.returncode:
        raise RawDevicePlanError(
            _bounded(
                stderr or stdout,
                "Could not freshly inspect the selected target",
            ),
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
    except (
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        raise RawDevicePlanError("lsblk returned invalid live target data") from error
    if len(raw_matches) != 1 or len(devices) != 1:
        raise RawDevicePlanError(
            "The selected target disappeared, became unsafe, or is ambiguous",
        )
    return _LiveTargetObservation(
        devices[0],
        _topology_device_numbers(raw_matches[0]),
    )


def _warnings(
    device: Device,
    final_verification_requested: bool,
) -> tuple[str, ...]:
    final_verification = (
        "A complete final SHA-256 read-back is requested."
        if final_verification_requested
        else "Only the mandatory pre-activation read-back is requested."
    )
    return (
        f"Everything on {device.path} may be permanently overwritten.",
        "The raw profile requires a cache-invalidated pre-activation read-back.",
        final_verification,
        "Execution requires one privileged descriptor and lock; no fallback "
        "executor is permitted.",
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


def _plan_digest(plan: RawDeviceWritePlan) -> str:
    try:
        encoded = json.dumps(
            {
                "profile": TARGET_PLAN_PROFILE,
                "source": {
                    "raw_snapshot_plan_sha256": (
                        plan.raw_snapshot_plan_sha256
                    ),
                    "snapshot_plan_sha256": plan.snapshot_plan_sha256,
                    "source_sha256": plan.source_sha256,
                    "source_size": plan.source_size,
                    "original_identity": list(plan.original_source_identity),
                    "workspace_device": plan.workspace_device,
                },
                "target": _device_payload(plan.device),
                "disk_sequence": plan.disk_sequence,
                "target_capacity": plan.target_capacity,
                "logical_sector_size": plan.logical_sector_size,
                "mandatory_preactivation_readback": (
                    plan.mandatory_preactivation_readback
                ),
                "final_verification_requested": (
                    plan.final_verification_requested
                ),
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


def _plan_snapshot(plan: RawDeviceWritePlan) -> tuple[object, ...]:
    return (
        plan.raw_snapshot_plan_sha256,
        plan.snapshot_plan_sha256,
        plan.source_sha256,
        plan.source_size,
        plan.original_source_identity,
        plan.workspace_device,
        plan.disk_sequence,
        plan.target_capacity,
        plan.logical_sector_size,
        plan.mandatory_preactivation_readback,
        plan.final_verification_requested,
        plan.required_executor_profile,
        plan.warnings,
        plan.confirmation_phrase,
        plan.plan_sha256,
    )


def _confirmation_snapshot(
    confirmation: ConfirmedRawDeviceWrite,
) -> tuple[object, ...]:
    return (
        confirmation.plan_sha256,
        confirmation.source_sha256,
        confirmation.source_size,
        confirmation.device_identity,
        confirmation.target_capacity,
        confirmation.logical_sector_size,
        confirmation.final_verification_requested,
        confirmation.confirmation_phrase,
    )


def _validate_source_evidence(evidence: RawSourceEvidence) -> None:
    if type(evidence) is not RawSourceEvidence:
        raise RawDevicePlanError("Exact raw source snapshot evidence is required")
    try:
        expected = _source_evidence_digest(evidence)
    except (AttributeError, TypeError, ValueError) as error:
        raise RawDevicePlanError("The raw source evidence is malformed") from error
    if (
        type(evidence.snapshot_plan_sha256) is not str
        or _SHA256.fullmatch(evidence.snapshot_plan_sha256) is None
        or not hmac.compare_digest(expected, evidence.snapshot_plan_sha256)
        or type(evidence.raw_snapshot_plan_sha256) is not str
        or _SHA256.fullmatch(evidence.raw_snapshot_plan_sha256) is None
        or type(evidence.source_sha256) is not str
        or _SHA256.fullmatch(evidence.source_sha256) is None
        or not _is_plain_int(evidence.source_size)
        or evidence.source_size <= 0
        or not _is_plain_int(evidence.original_device)
        or evidence.original_device < 0
        or not _is_plain_int(evidence.original_inode)
        or evidence.original_inode <= 0
        or not _is_plain_int(evidence.original_size)
        or evidence.original_size <= 0
        or not _is_plain_int(evidence.original_modified_ns)
        or evidence.original_modified_ns < 0
        or not _is_plain_int(evidence.original_changed_ns)
        or evidence.original_changed_ns < 0
        or not _is_plain_int(evidence.workspace_device)
        or evidence.workspace_device < 0
    ):
        raise RawDevicePlanError("The raw source snapshot evidence is inconsistent")


def _validate_target_node(device: Device) -> os.stat_result:
    try:
        info = _lstat(device.path)
    except OSError as error:
        raise RawDevicePlanError(
            _bounded(error, "The selected target is no longer available"),
        ) from error
    if not stat.S_ISBLK(info.st_mode):
        raise RawDevicePlanError(
            "The selected target path is not a whole-disk block device",
        )
    actual = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    if actual != device.major_minor:
        raise RawDevicePlanError(
            "The selected target's kernel device number changed",
        )
    return info


def _validate_live_target(
    device: Device,
    target_status: os.stat_result,
) -> _LiveTargetObservation:
    observation = _probe_live_target(device.path)
    if type(observation) is not _LiveTargetObservation:
        raise RawDevicePlanError("Live target inspection returned invalid evidence")
    if observation.device != device:
        raise RawDevicePlanError(
            "The selected target changed after discovery; refresh and confirm it again",
        )
    if target_status.st_rdev not in observation.related_device_numbers:
        raise RawDevicePlanError(
            "The selected block node is absent from its live target topology",
        )
    return observation


def _validate_source_residency(
    plan: RawDeviceWritePlan,
    target_status: os.stat_result,
    observation: _LiveTargetObservation,
) -> None:
    related = observation.related_device_numbers
    if target_status.st_rdev not in related:
        raise RawDevicePlanError(
            "The block node and live target topology disagree",
        )
    if (
        plan.source_evidence.original_device in related
        or plan.source_evidence.workspace_device in related
    ):
        raise RawDevicePlanError(
            "The selected source or snapshot workspace resides on the target drive",
        )


def _validate_static_relationships(
    plan: RawDeviceWritePlan,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    if type(plan) is not RawDeviceWritePlan:
        raise RawDevicePlanError("An exact raw device plan is required")
    receipt = plan._authorization
    if (
        type(receipt) is not _PlanReceipt
        or receipt.token is not _PLAN_TOKEN
        or receipt.plan is not plan
        or receipt.source_evidence is not plan.source_evidence
        or receipt.device is not plan.device
        or receipt.snapshot != _plan_snapshot(plan)
    ):
        raise RawDevicePlanError(
            "The raw target authorization is missing or no longer authoritative",
        )
    _validate_source_evidence(plan.source_evidence)
    if type(plan.device) is not Device:
        raise RawDevicePlanError("The target plan contains an invalid device record")
    try:
        validate_device_selection(plan.device, writable=True)
    except WriterSafetyError as error:
        raise RawDevicePlanError(str(error)) from error
    evidence = plan.source_evidence
    expected_warnings = _warnings(
        plan.device,
        plan.final_verification_requested,
    )
    expected_phrase = f"WRITE RAW {plan.device.path} {plan.device.major_minor}"
    for label, value in (
        ("raw snapshot plan", plan.raw_snapshot_plan_sha256),
        ("snapshot plan", plan.snapshot_plan_sha256),
        ("source", plan.source_sha256),
        ("target plan", plan.plan_sha256),
    ):
        if type(value) is not str or _SHA256.fullmatch(value) is None:
            raise RawDevicePlanError(f"The {label} digest is invalid")
    if (
        plan.raw_snapshot_plan_sha256
        != evidence.raw_snapshot_plan_sha256
        or plan.snapshot_plan_sha256 != evidence.snapshot_plan_sha256
        or plan.source_sha256 != evidence.source_sha256
        or plan.source_size != evidence.source_size
        or plan.original_source_identity != evidence.original_identity
        or plan.workspace_device != evidence.workspace_device
        or plan.target_capacity != plan.device.size
        or plan.source_size > plan.target_capacity
        or plan.target_capacity % SECTOR_SIZE
        or not _is_plain_int(plan.disk_sequence)
        or not 0 < plan.disk_sequence <= 0xFFFFFFFFFFFFFFFF
        or plan.logical_sector_size != SECTOR_SIZE
        or plan.device.logical_sector_size != SECTOR_SIZE
        or plan.mandatory_preactivation_readback is not True
        or type(plan.final_verification_requested) is not bool
        or plan.required_executor_profile != REQUIRED_EXECUTOR_PROFILE
        or plan.warnings != expected_warnings
        or plan.confirmation_phrase != expected_phrase
        or not hmac.compare_digest(_plan_digest(plan), plan.plan_sha256)
    ):
        raise RawDevicePlanError(
            "The raw source, target geometry, and authorization bindings disagree",
        )
    _check_cancelled(cancel_check)


def _validate_relationships(
    plan: RawDeviceWritePlan,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    _validate_static_relationships(plan, cancel_check=cancel_check)
    target_status = _validate_target_node(plan.device)
    observation = _validate_live_target(plan.device, target_status)
    _validate_source_residency(plan, target_status, observation)
    if _read_disk_sequence(plan.device.major_minor) != plan.disk_sequence:
        raise RawDevicePlanError(
            "The selected target is a different disk generation; refresh and "
            "confirm it again",
        )
    _check_cancelled(cancel_check)


def build_raw_device_write_plan(
    source_evidence: RawSourceEvidence,
    device: Device,
    *,
    final_verification: bool,
    cancel_check: CancelCheck | None = None,
) -> RawDeviceWritePlan:
    """Bind exact source evidence to one current 512-byte-sector target."""

    _validate_source_evidence(source_evidence)
    if type(device) is not Device:
        raise RawDevicePlanError("A discovered removable Device is required")
    if type(final_verification) is not bool:
        raise RawDevicePlanError("The final verification request must be a boolean")
    try:
        validate_device_selection(device, writable=True)
    except WriterSafetyError as error:
        raise RawDevicePlanError(str(error)) from error
    if device.logical_sector_size != SECTOR_SIZE:
        raise RawDevicePlanError(
            "The initial raw target profile requires 512-byte logical sectors",
        )
    if device.size % SECTOR_SIZE:
        raise RawDevicePlanError("The target capacity is not sector aligned")
    if device.size > MAX_RAW_DEVICE_BYTES:
        raise RawDevicePlanError("The target capacity exceeds the raw helper profile")
    if source_evidence.source_size > device.size:
        raise RawDevicePlanError(
            "The expanded raw source is larger than the selected target capacity",
        )
    if source_evidence.source_size > MAX_RAW_SOURCE_BYTES:
        raise RawDevicePlanError(
            "The expanded raw source exceeds the snapshot/helper profile",
        )
    if (
        source_evidence.source_size < 2 * SECTOR_SIZE
        or source_evidence.source_size % SECTOR_SIZE
    ):
        raise RawDevicePlanError(
            "The initial raw helper profile requires a sector-aligned image "
            "of at least 1024 bytes",
        )
    target_status = _validate_target_node(device)
    observation = _validate_live_target(device, target_status)
    disk_sequence = _read_disk_sequence(device.major_minor)
    warnings = _warnings(device, final_verification)
    candidate = RawDeviceWritePlan(
        source_evidence,
        device,
        disk_sequence,
        source_evidence.raw_snapshot_plan_sha256,
        source_evidence.snapshot_plan_sha256,
        source_evidence.source_sha256,
        source_evidence.source_size,
        source_evidence.original_identity,
        source_evidence.workspace_device,
        device.size,
        device.logical_sector_size,
        True,
        final_verification,
        REQUIRED_EXECUTOR_PROFILE,
        warnings,
        f"WRITE RAW {device.path} {device.major_minor}",
        "",
    )
    plan = RawDeviceWritePlan(
        candidate.source_evidence,
        candidate.device,
        candidate.disk_sequence,
        candidate.raw_snapshot_plan_sha256,
        candidate.snapshot_plan_sha256,
        candidate.source_sha256,
        candidate.source_size,
        candidate.original_source_identity,
        candidate.workspace_device,
        candidate.target_capacity,
        candidate.logical_sector_size,
        candidate.mandatory_preactivation_readback,
        candidate.final_verification_requested,
        candidate.required_executor_profile,
        candidate.warnings,
        candidate.confirmation_phrase,
        _plan_digest(candidate),
    )
    if not hmac.compare_digest(_plan_digest(plan), plan.plan_sha256):
        raise RawDevicePlanError("The raw target authorization digest is inconsistent")
    _validate_source_residency(plan, target_status, observation)
    _check_cancelled(cancel_check)
    object.__setattr__(
        plan,
        "_authorization",
        _PlanReceipt(
            _PLAN_TOKEN,
            plan,
            source_evidence,
            device,
            _plan_snapshot(plan),
        ),
    )
    return plan


def observe_raw_target_device_numbers(
    device: Device,
    *,
    cancel_check: CancelCheck | None = None,
) -> frozenset[int]:
    """Return fresh topology evidence for safe snapshot workspace planning."""

    if type(device) is not Device:
        raise RawDevicePlanError("A discovered removable Device is required")
    try:
        validate_device_selection(device, writable=True)
    except WriterSafetyError as error:
        raise RawDevicePlanError(str(error)) from error
    target_status = _validate_target_node(device)
    observation = _validate_live_target(device, target_status)
    _check_cancelled(cancel_check)
    return observation.related_device_numbers


def validate_raw_device_write_plan(
    plan: RawDeviceWritePlan,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    """Revalidate the complete live target and every source-plan binding."""

    _validate_relationships(plan, cancel_check=cancel_check)


def confirm_raw_device_write(
    plan: RawDeviceWritePlan,
    phrase: str,
    *,
    cancel_check: CancelCheck | None = None,
) -> ConfirmedRawDeviceWrite:
    """Mint a receipt only for the exact case-sensitive destructive phrase."""

    _validate_relationships(plan, cancel_check=cancel_check)
    if not _phrase_matches(phrase, plan.confirmation_phrase):
        raise RawDevicePlanError("The destructive confirmation phrase did not match")
    confirmation = ConfirmedRawDeviceWrite(
        plan,
        plan.plan_sha256,
        plan.source_sha256,
        plan.source_size,
        plan.device.identity,
        plan.target_capacity,
        plan.logical_sector_size,
        plan.final_verification_requested,
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


def _validate_confirmation_receipt(
    plan: RawDeviceWritePlan,
    confirmation: ConfirmedRawDeviceWrite,
) -> None:
    if type(confirmation) is not ConfirmedRawDeviceWrite:
        raise RawDevicePlanError("An exact raw target confirmation is required")
    receipt = confirmation._authorization
    if (
        type(receipt) is not _ConfirmationReceipt
        or receipt.token is not _CONFIRMATION_TOKEN
        or receipt.confirmation is not confirmation
        or receipt.plan is not plan
        or receipt.snapshot != _confirmation_snapshot(confirmation)
        or confirmation.plan is not plan
        or confirmation.plan_sha256 != plan.plan_sha256
        or confirmation.source_sha256 != plan.source_sha256
        or confirmation.source_size != plan.source_size
        or confirmation.device_identity != plan.device.identity
        or confirmation.target_capacity != plan.target_capacity
        or confirmation.logical_sector_size != plan.logical_sector_size
        or confirmation.final_verification_requested
        is not plan.final_verification_requested
        or not _phrase_matches(
            confirmation.confirmation_phrase,
            plan.confirmation_phrase,
        )
    ):
        raise RawDevicePlanError(
            "The raw target confirmation is forged, cloned, or belongs to "
            "another plan",
        )


def validate_confirmed_raw_device_write(
    plan: RawDeviceWritePlan,
    confirmation: ConfirmedRawDeviceWrite,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    """Validate that confirmation belongs to this exact authoritative plan."""

    _validate_relationships(plan, cancel_check=cancel_check)
    _validate_confirmation_receipt(plan, confirmation)
    _check_cancelled(cancel_check)


def _post_unmount_device_matches(original: Device, current: Device) -> bool:
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


def _read_disk_sequence(major_minor: str) -> int:
    """Read the kernel generation number for one whole-disk identity."""

    if type(major_minor) is not str or _MAJOR_MINOR.fullmatch(major_minor) is None:
        raise RawDevicePlanError("The target has no valid kernel identity")
    path = _SYSFS_ROOT / "dev" / "block" / major_minor / "diskseq"
    try:
        data = path.read_bytes()
    except OSError as error:
        raise RawDevicePlanError(
            "The kernel cannot provide a disk generation for this target",
        ) from error
    if not data or len(data) > 32 or b"\x00" in data:
        raise RawDevicePlanError("The kernel disk generation is malformed")
    try:
        rendered = data.decode("ascii").strip()
    except UnicodeError as error:
        raise RawDevicePlanError("The kernel disk generation is malformed") from error
    if not rendered.isdecimal():
        raise RawDevicePlanError("The kernel disk generation is malformed")
    value = int(rendered, 10)
    if not 0 < value <= 0xFFFFFFFFFFFFFFFF:
        raise RawDevicePlanError(
            "The kernel disk generation is outside the supported range",
        )
    return value


def _ready_digest(ready: ReadyRawDeviceWrite) -> str:
    try:
        encoded = json.dumps(
            {
                "profile": READY_TARGET_PROFILE,
                "plan_sha256": ready.plan_sha256,
                "disk_sequence": ready.disk_sequence,
                "original_target": _device_payload(ready.plan.device),
                "unmounted_target": _device_payload(ready.device),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return ""
    return hashlib.sha256(encoded).hexdigest()


def _ready_snapshot(ready: ReadyRawDeviceWrite) -> tuple[object, ...]:
    return (
        ready.plan_sha256,
        ready.disk_sequence,
        ready.ready_sha256,
        ready.device,
    )


def authorize_unmounted_raw_device_write(
    plan: RawDeviceWritePlan,
    confirmation: ConfirmedRawDeviceWrite,
    *,
    cancel_check: CancelCheck | None = None,
) -> ReadyRawDeviceWrite:
    """Witness the sole allowed target transition from mounted to unmounted."""

    _validate_static_relationships(plan, cancel_check=cancel_check)
    _validate_confirmation_receipt(plan, confirmation)
    target_status = _validate_target_node(plan.device)
    observation = _probe_live_target(plan.device.path)
    if type(observation) is not _LiveTargetObservation:
        raise RawDevicePlanError(
            "Live post-unmount inspection returned invalid evidence",
        )
    current = observation.device
    if not _post_unmount_device_matches(plan.device, current):
        raise RawDevicePlanError(
            "The target changed during unmounting or still has a mounted filesystem",
        )
    try:
        validate_device_selection(current, writable=True)
    except WriterSafetyError as error:
        raise RawDevicePlanError(str(error)) from error
    if target_status.st_rdev not in observation.related_device_numbers:
        raise RawDevicePlanError(
            "The post-unmount block node is absent from its live topology",
        )
    _validate_source_residency(plan, target_status, observation)
    disk_sequence = _read_disk_sequence(current.major_minor)
    if disk_sequence != plan.disk_sequence:
        raise RawDevicePlanError(
            "The target is a different disk generation than the confirmed plan",
        )
    candidate = ReadyRawDeviceWrite(
        plan,
        confirmation,
        current,
        disk_sequence,
        plan.plan_sha256,
        "",
    )
    ready = ReadyRawDeviceWrite(
        candidate.plan,
        candidate.confirmation,
        candidate.device,
        candidate.disk_sequence,
        candidate.plan_sha256,
        _ready_digest(candidate),
    )
    _check_cancelled(cancel_check)
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


def validate_ready_raw_device_write(
    plan: RawDeviceWritePlan,
    confirmation: ConfirmedRawDeviceWrite,
    ready: ReadyRawDeviceWrite,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    """Re-probe the exact unmounted target immediately before helper launch."""

    _validate_static_relationships(plan, cancel_check=cancel_check)
    _validate_confirmation_receipt(plan, confirmation)
    if type(ready) is not ReadyRawDeviceWrite:
        raise RawDevicePlanError("An exact post-unmount raw target receipt is required")
    receipt = ready._authorization
    if (
        type(receipt) is not _ReadyReceipt
        or receipt.token is not _READY_TOKEN
        or receipt.ready is not ready
        or receipt.plan is not plan
        or receipt.confirmation is not confirmation
        or receipt.device is not ready.device
        or receipt.snapshot != _ready_snapshot(ready)
        or ready.plan is not plan
        or ready.confirmation is not confirmation
        or ready.plan_sha256 != plan.plan_sha256
        or ready.disk_sequence != plan.disk_sequence
        or not _is_plain_int(ready.disk_sequence)
        or not 0 < ready.disk_sequence <= 0xFFFFFFFFFFFFFFFF
        or not _post_unmount_device_matches(plan.device, ready.device)
        or not hmac.compare_digest(_ready_digest(ready), ready.ready_sha256)
    ):
        raise RawDevicePlanError(
            "The post-unmount raw target receipt is forged, cloned, or stale",
        )
    target_status = _validate_target_node(ready.device)
    observation = _validate_live_target(ready.device, target_status)
    _validate_source_residency(plan, target_status, observation)
    if _read_disk_sequence(ready.device.major_minor) != ready.disk_sequence:
        raise RawDevicePlanError(
            "The target disk generation changed after unmount authorization",
        )
    _check_cancelled(cancel_check)
