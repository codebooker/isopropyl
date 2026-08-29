from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""One-shot orchestration for the narrow Syslinux BIOS + UEFI profile.

The GUI-facing coordinator owns one authenticated ISO staging plan, its exact
selected write plan, one removable target, and the temporary workspace that
contains the unpublished staging destination.  It has no alternate writer:
every successful execution reaches the fixed PolicyKit-backed Syslinux device
runner and its mandatory full-device read-back.

The generic ISO planner intentionally remains UEFI-only.  This module adds a
narrow, later authorization layer without weakening any of that planner's
blockers or making a generic BIOS promise.
"""

import logging
import shutil
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .devices import Device
from .iso import (
    BootStrategy,
    FileSystem,
    FirmwareTarget,
    PartitionTable,
    WriteMode,
    WritePlan,
)
from .iso_staging import (
    IsoStagingCancelled,
    IsoStagingError,
    IsoStagingExecutor,
    IsoStagingPlan,
    IsoStagingProgress,
    IsoStagingResult,
)
from .syslinux_device import (
    ConfirmedSyslinuxDeviceWrite,
    SyslinuxDevicePlanCancelled,
    SyslinuxDevicePlanError,
    SyslinuxDeviceWritePlan,
    build_syslinux_device_write_plan,
    confirm_syslinux_device_write,
)
from .syslinux_device_runner import (
    SyslinuxDeviceRunCancelled,
    SyslinuxDeviceRunError,
    SyslinuxDeviceWriteResult,
    SyslinuxDeviceWriteRunner,
    resolve_syslinux_helper_installation,
)
from .syslinux_iso_fat32 import (
    SyslinuxIsoFat32Cancelled,
    SyslinuxIsoFat32Error,
    SyslinuxIsoFat32Plan,
    build_syslinux_iso_fat32_plan,
)
from .syslinux_transaction import MAX_SYSLINUX_REGULAR_IMAGE_BYTES
from .writer import WriterSafetyError, validate_device_selection


logger = logging.getLogger("isopropyl")

WorkflowProgress = Callable[[str, int, int], None]
WORKSPACE_RESERVE_BYTES = 64 * 1024 * 1024


def _is_lower_hex(value: object, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


class SyslinuxWorkflowError(RuntimeError):
    """The authoritative Syslinux workflow did not complete safely."""


class SyslinuxWorkflowCancelled(SyslinuxWorkflowError):
    """The workflow was cancelled before a completed verified result."""


class SyslinuxWorkflowState(str, Enum):
    CREATED = "created"
    PREPARING = "preparing"
    PREPARED = "prepared"
    CONFIRMED = "confirmed"
    EXECUTING = "executing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    CLOSED = "closed"


@dataclass(frozen=True)
class SyslinuxWorkflowInputs:
    """Exact non-Qt inputs transferred from one pending GUI selection.

    ``workspace`` ownership transfers after successful workflow construction.
    Persistence and runtime validation are represented explicitly so a caller
    cannot silently drop those pending selections while entering this
    deliberately smaller profile.
    """

    write_plan: WritePlan = field(repr=False, compare=False)
    staging_plan: IsoStagingPlan = field(repr=False, compare=False)
    device: Device
    workspace: tempfile.TemporaryDirectory[str] = field(
        repr=False,
        compare=False,
    )
    persistence_profile: object | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    runtime_validation: object | None = field(
        default=None,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class SyslinuxWorkflowDependencies:
    """Injectable host boundaries for deterministic coordinator tests."""

    resolve_helper: Callable[[], object] = resolve_syslinux_helper_installation
    staging_executor_factory: Callable[[], IsoStagingExecutor] = IsoStagingExecutor
    build_composite_plan: Callable[..., SyslinuxIsoFat32Plan] = (
        build_syslinux_iso_fat32_plan
    )
    build_target_plan: Callable[..., SyslinuxDeviceWritePlan] = (
        build_syslinux_device_write_plan
    )
    confirm_target: Callable[..., ConfirmedSyslinuxDeviceWrite] = (
        confirm_syslinux_device_write
    )
    runner_factory: Callable[[], SyslinuxDeviceWriteRunner] = (
        SyslinuxDeviceWriteRunner
    )
    disk_usage: Callable[[Path], object] = shutil.disk_usage


def _require_narrow_profile(inputs: SyslinuxWorkflowInputs) -> Path:
    if type(inputs) is not SyslinuxWorkflowInputs:
        raise SyslinuxWorkflowError("Exact Syslinux workflow inputs are required")
    plan = inputs.staging_plan
    selected = inputs.write_plan
    device = inputs.device
    workspace = inputs.workspace
    if type(plan) is not IsoStagingPlan:
        raise SyslinuxWorkflowError("An exact ISO staging plan is required")
    if type(selected) is not WritePlan or plan.write_plan is not selected:
        raise SyslinuxWorkflowError(
            "The staging plan is not the exact selected write plan"
        )
    if type(device) is not Device:
        raise SyslinuxWorkflowError("An exact discovered target is required")
    if type(workspace) is not tempfile.TemporaryDirectory:
        raise SyslinuxWorkflowError("An owned temporary workspace is required")
    try:
        validate_device_selection(device, writable=True)
    except WriterSafetyError as error:
        raise SyslinuxWorkflowError(str(error)) from error

    layout = selected.layout
    if (
        not selected.executable
        or selected.mode is not WriteMode.EXTRACTED_ISO
        or selected.firmware_target is not FirmwareTarget.UEFI_ONLY
        or layout is None
        or layout.partition_table is not PartitionTable.GPT
        or layout.main_filesystem is not FileSystem.FAT32
        or layout.partition_count != 1
        or layout.boot_partition_filesystem is not None
        or layout.bios_bootable
        or not layout.uefi_bootable
        or layout.boot_strategy is not BootStrategy.IMAGE_NATIVE
        or selected.transformations
    ):
        raise SyslinuxWorkflowError(
            "Syslinux requires the executable native single-partition UEFI/FAT32 source profile"
        )
    if (
        plan.overlay is not None
        or bool(plan.embedded_fats)
        or plan.windows_customization is not None
        or plan.windows_architecture is not None
        or plan.autounattend_xml is not None
        or plan.wim_source is not None
        or plan.wim_selection is not None
        or plan.wimlib_imagex is not None
        or inputs.persistence_profile is not None
        or inputs.runtime_validation is not None
    ):
        raise SyslinuxWorkflowError(
            "The initial Syslinux profile does not permit other ISO transformations"
        )
    if any(
        value is None
        for value in (
            plan.syslinux_analysis,
            plan.syslinux_c32_bundle,
            plan.syslinux_payload_bundle,
            plan.syslinux_staging,
        )
    ):
        raise SyslinuxWorkflowError(
            "The authenticated Syslinux staging bindings are incomplete"
        )
    if (
        not device.removable
        or device.read_only
        or device.logical_sector_size != 512
        or type(device.size) is not int
        or device.size <= 0
        or device.size > MAX_SYSLINUX_REGULAR_IMAGE_BYTES
        or device.size % 512
    ):
        raise SyslinuxWorkflowError(
            "Syslinux requires writable kernel-removable media no larger than "
            "128 GiB with 512-byte logical sectors"
        )

    try:
        root = Path(workspace.name).resolve(strict=True)
    except (OSError, TypeError, ValueError) as error:
        raise SyslinuxWorkflowError("The owned Syslinux workspace is unavailable") from error
    expected_destination = root / "ready-media"
    if (
        not isinstance(plan.destination, Path)
        or not plan.destination.is_absolute()
        or plan.destination != expected_destination
    ):
        raise SyslinuxWorkflowError(
            "The staging destination is outside the exact owned workspace"
        )
    try:
        parent = plan.destination.parent.resolve(strict=True)
    except OSError as error:
        raise SyslinuxWorkflowError(
            "The Syslinux staging destination parent is unavailable"
        ) from error
    if parent != root:
        raise SyslinuxWorkflowError(
            "The staging destination parent changed after selection"
        )
    return root


class SyslinuxWriteWorkflow:
    """Own one staged ISO -> Syslinux composite -> verified device write."""

    def __init__(
        self,
        inputs: SyslinuxWorkflowInputs,
        *,
        dependencies: SyslinuxWorkflowDependencies = SyslinuxWorkflowDependencies(),
    ) -> None:
        if type(dependencies) is not SyslinuxWorkflowDependencies:
            raise SyslinuxWorkflowError("Syslinux workflow dependencies are invalid")
        workspace_root = _require_narrow_profile(inputs)
        self.inputs = inputs
        self.dependencies = dependencies
        self._workspace_root = workspace_root

        self._lock = threading.RLock()
        self._cancelled = threading.Event()
        self._state = SyslinuxWorkflowState.CREATED
        self._close_requested = False
        self._workspace: tempfile.TemporaryDirectory[str] | None = inputs.workspace
        self._stager: IsoStagingExecutor | object | None = None
        self._runner: SyslinuxDeviceWriteRunner | object | None = None
        self._staging_result: IsoStagingResult | None = None
        self._composite_plan: SyslinuxIsoFat32Plan | None = None
        self._plan: SyslinuxDeviceWritePlan | None = None
        self._confirmation: ConfirmedSyslinuxDeviceWrite | None = None
        self._result: SyslinuxDeviceWriteResult | None = None
        self._committed = False

    @property
    def state(self) -> SyslinuxWorkflowState:
        with self._lock:
            return self._state

    @property
    def plan(self) -> SyslinuxDeviceWritePlan | None:
        with self._lock:
            return self._plan

    @property
    def confirmation(self) -> ConfirmedSyslinuxDeviceWrite | None:
        with self._lock:
            return self._confirmation

    @property
    def result(self) -> SyslinuxDeviceWriteResult | None:
        with self._lock:
            return self._result

    @property
    def committed(self) -> bool:
        """Whether execution crossed the helper's irreversible COMMIT boundary."""

        with self._lock:
            runner = self._runner
            return self._committed or bool(
                getattr(runner, "committed", False) if runner is not None else False
            )

    @property
    def confirmation_phrase(self) -> str:
        with self._lock:
            if self._state not in {
                SyslinuxWorkflowState.PREPARED,
                SyslinuxWorkflowState.CONFIRMED,
            } or self._plan is None:
                raise SyslinuxWorkflowError(
                    "A prepared Syslinux target plan is required before confirmation"
                )
            return self._plan.confirmation_phrase

    def _check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise SyslinuxWorkflowCancelled("The Syslinux workflow was cancelled")

    def _set_state(self, state: SyslinuxWorkflowState) -> None:
        with self._lock:
            self._state = state

    @staticmethod
    def _translate(error: BaseException) -> SyslinuxWorkflowError:
        if isinstance(error, SyslinuxWorkflowCancelled):
            return error
        if isinstance(
            error,
            (
                IsoStagingCancelled,
                SyslinuxIsoFat32Cancelled,
                SyslinuxDevicePlanCancelled,
                SyslinuxDeviceRunCancelled,
            ),
        ):
            return SyslinuxWorkflowCancelled(
                str(error) or "The Syslinux workflow was cancelled"
            )
        if isinstance(error, SyslinuxWorkflowError):
            return error
        if isinstance(
            error,
            (
                IsoStagingError,
                SyslinuxIsoFat32Error,
                SyslinuxDevicePlanError,
                SyslinuxDeviceRunError,
                OSError,
                TypeError,
                ValueError,
            ),
        ):
            return SyslinuxWorkflowError(str(error) or "The Syslinux workflow failed")
        return SyslinuxWorkflowError(str(error) or error.__class__.__name__)

    @staticmethod
    def _raise_translated(
        error: BaseException,
        translated: SyslinuxWorkflowError,
    ) -> None:
        if translated is error:
            raise translated
        raise translated from error

    def _cleanup_owned(self, *, clear_authorization: bool) -> None:
        with self._lock:
            workspace = self._workspace
            self._workspace = None
            self._workspace_root = None
            self._stager = None
            self._runner = None
            self._staging_result = None
            self._composite_plan = None
            if clear_authorization:
                self._plan = None
                self._confirmation = None
        if workspace is not None:
            try:
                workspace.cleanup()
            except OSError:
                logger.exception("Could not remove the Syslinux workflow workspace")

    def _fail(self, error: BaseException) -> SyslinuxWorkflowError:
        translated = self._translate(error)
        self._cleanup_owned(clear_authorization=True)
        with self._lock:
            self._state = (
                SyslinuxWorkflowState.CLOSED
                if self._close_requested
                else SyslinuxWorkflowState.CANCELLED
                if isinstance(translated, SyslinuxWorkflowCancelled)
                else SyslinuxWorkflowState.FAILED
            )
        return translated

    def prepare(
        self,
        progress: WorkflowProgress = lambda _stage, _done, _total: None,
    ) -> SyslinuxDeviceWritePlan:
        with self._lock:
            if self._state is not SyslinuxWorkflowState.CREATED:
                raise SyslinuxWorkflowError(
                    "A Syslinux workflow can only be prepared once"
                )
            self._state = SyslinuxWorkflowState.PREPARING
            workspace_root = self._workspace_root
        try:
            if workspace_root is None:
                raise SyslinuxWorkflowError("The owned Syslinux workspace is unavailable")
            self._check_cancelled()
            required_peak = (
                self.inputs.staging_plan.required_free_bytes
                + self.inputs.device.size
            )
            usage = self.dependencies.disk_usage(workspace_root)
            if (
                type(getattr(usage, "free", None)) is not int
                or usage.free < required_peak
            ):
                raise SyslinuxWorkflowError(
                    "The Syslinux developer profile needs temporary space for "
                    "the extracted tree plus a fully allocated target-sized image "
                    f"({required_peak} bytes required)"
                )
            # Refuse an unavailable or unsafe installed helper before doing the
            # comparatively expensive extraction and tree hashing.
            self.dependencies.resolve_helper()
            self._check_cancelled()
            stager = self.dependencies.staging_executor_factory()
            if not callable(getattr(stager, "execute", None)) or not callable(
                getattr(stager, "cancel", None)
            ):
                raise SyslinuxWorkflowError(
                    "The ISO staging executor is not authoritative"
                )
            with self._lock:
                self._stager = stager

            def staging_progress(update: IsoStagingProgress) -> None:
                if type(update) is not IsoStagingProgress:
                    raise SyslinuxWorkflowError(
                        "The ISO staging executor reported invalid progress"
                    )
                progress(update.stage, update.bytes_done, update.total_bytes)

            staged = stager.execute(self.inputs.staging_plan, staging_progress)
            if (
                type(staged) is not IsoStagingResult
                or staged.destination != self.inputs.staging_plan.destination
                or staged.image_identity != self.inputs.staging_plan.image_identity
                or staged.catalog_digest
                != self.inputs.staging_plan.staged_catalog_digest
            ):
                raise SyslinuxWorkflowError(
                    "The published staging result does not match the exact source plan"
                )
            with self._lock:
                self._staging_result = staged
            self._check_cancelled()
            remaining = self.dependencies.disk_usage(workspace_root)
            required_remaining = self.inputs.device.size + WORKSPACE_RESERVE_BYTES
            if (
                type(getattr(remaining, "free", None)) is not int
                or remaining.free < required_remaining
            ):
                raise SyslinuxWorkflowError(
                    "The published Syslinux tree left too little space for the "
                    "fully allocated target-sized private image"
                )
            progress(
                "Binding the private dual-firmware image",
                staged.bytes_staged,
                staged.bytes_staged,
            )
            composite = self.dependencies.build_composite_plan(
                self.inputs.staging_plan,
                staged,
                workspace_root,
                image_size=self.inputs.device.size,
                cancel_check=self._check_cancelled,
            )
            if (
                type(composite) is not SyslinuxIsoFat32Plan
                or composite.iso_plan is not self.inputs.staging_plan
                or composite.staging_result is not staged
                or composite.private_plan.geometry.image_size
                != self.inputs.device.size
            ):
                raise SyslinuxWorkflowError(
                    "The composite plan is not bound to the exact staging result"
                )
            with self._lock:
                self._composite_plan = composite
            target_plan = self.dependencies.build_target_plan(
                composite,
                self.inputs.device,
                cancel_check=self._check_cancelled,
            )
            if (
                type(target_plan) is not SyslinuxDeviceWritePlan
                or target_plan.composite_plan is not composite
                or target_plan.device is not self.inputs.device
                or target_plan.image_size != self.inputs.device.size
                or target_plan.firmware_profile != "bios-and-uefi"
                or target_plan.mandatory_readback is not True
            ):
                raise SyslinuxWorkflowError(
                    "The target plan is not the exact dual-firmware Syslinux authorization"
                )
            self._check_cancelled()
            with self._lock:
                if (
                    self._close_requested
                    or self._cancelled.is_set()
                    or self._state is not SyslinuxWorkflowState.PREPARING
                ):
                    raise SyslinuxWorkflowCancelled(
                        "The Syslinux workflow was closed"
                        if self._close_requested
                        else "The Syslinux workflow was cancelled"
                    )
                self._plan = target_plan
                self._state = SyslinuxWorkflowState.PREPARED
            return target_plan
        except BaseException as error:
            translated = self._fail(error)
            self._raise_translated(error, translated)

    def confirm(self, phrase: str) -> ConfirmedSyslinuxDeviceWrite:
        with self._lock:
            plan = self._plan
            if self._state is not SyslinuxWorkflowState.PREPARED or plan is None:
                raise SyslinuxWorkflowError(
                    "The Syslinux workflow is not ready for confirmation"
                )
            if type(phrase) is not str or phrase != plan.confirmation_phrase:
                raise SyslinuxWorkflowError(
                    "The destructive confirmation phrase did not match exactly"
                )
        try:
            self._check_cancelled()
            confirmation = self.dependencies.confirm_target(
                plan,
                phrase,
                cancel_check=self._check_cancelled,
            )
            if (
                type(confirmation) is not ConfirmedSyslinuxDeviceWrite
                or confirmation.plan is not plan
                or confirmation.plan_sha256 != plan.plan_sha256
                or confirmation.confirmation_phrase != plan.confirmation_phrase
            ):
                raise SyslinuxWorkflowError(
                    "The target confirmation is not bound to the exact prepared plan"
                )
            self._check_cancelled()
            with self._lock:
                if self._state is not SyslinuxWorkflowState.PREPARED:
                    raise SyslinuxWorkflowCancelled(
                        "The Syslinux workflow was cancelled"
                    )
                self._confirmation = confirmation
                self._state = SyslinuxWorkflowState.CONFIRMED
            return confirmation
        except BaseException as error:
            translated = self._fail(error)
            self._raise_translated(error, translated)

    def execute(
        self,
        progress: WorkflowProgress = lambda _stage, _done, _total: None,
    ) -> SyslinuxDeviceWriteResult:
        runner: SyslinuxDeviceWriteRunner | object | None = None
        with self._lock:
            if (
                self._state is not SyslinuxWorkflowState.CONFIRMED
                or self._plan is None
                or self._confirmation is None
                or self._composite_plan is None
                or self._staging_result is None
                or self._workspace is None
            ):
                raise SyslinuxWorkflowError(
                    "The Syslinux workflow requires exact confirmation before execution"
                )
            plan = self._plan
            confirmation = self._confirmation
        try:
            runner = self.dependencies.runner_factory()
            if not callable(getattr(runner, "run", None)) or not callable(
                getattr(runner, "cancel", None)
            ):
                raise SyslinuxWorkflowError(
                    "The Syslinux device runner is not authoritative"
                )
            with self._lock:
                if (
                    self._state is not SyslinuxWorkflowState.CONFIRMED
                    or self._plan is not plan
                    or self._confirmation is not confirmation
                    or self._cancelled.is_set()
                    or self._close_requested
                ):
                    raise SyslinuxWorkflowCancelled(
                        "The Syslinux workflow was closed"
                        if self._close_requested
                        else "The Syslinux workflow was cancelled"
                    )
                self._runner = runner
                self._state = SyslinuxWorkflowState.EXECUTING
            result = runner.run(
                plan,
                confirmation,
                lambda stage, _path, done, total: progress(stage, done, total),
            )
            if (
                type(result) is not SyslinuxDeviceWriteResult
                or result.plan_sha256 != plan.plan_sha256
                or result.target_path != plan.device.path
                or result.major_minor != plan.device.major_minor
                or result.disk_sequence != plan.disk_sequence
                or result.image_size != plan.image_size
                or result.disk_signature != plan.disk_signature
                or result.volume_id != plan.volume_id
                or result.logical_sector_size != plan.logical_sector_size
                or result.helper_profile != plan.required_executor_profile
                or not _is_lower_hex(result.image_sha256, 64)
                or not _is_lower_hex(result.ready_sha256, 64)
                or not _is_lower_hex(result.request_id, 32)
                or result.exclusive_open is not True
                or result.cache_invalidated is not True
                or result.mandatory_readback is not True
                or type(result.cancellation_deferred) is not bool
                or getattr(runner, "committed", False) is not True
            ):
                raise SyslinuxWorkflowError(
                    "The device runner returned a result for another transaction"
                )
            with self._lock:
                self._result = result
                self._committed = True
            self._cleanup_owned(clear_authorization=False)
            with self._lock:
                self._state = (
                    SyslinuxWorkflowState.CLOSED
                    if self._close_requested
                    else SyslinuxWorkflowState.COMPLETED
                )
            return result
        except BaseException as error:
            with self._lock:
                self._committed = bool(
                    getattr(runner, "committed", False)
                    if runner is not None else False
                )
            translated = self._fail(error)
            self._raise_translated(error, translated)

    def cancel(self) -> None:
        self._cancelled.set()
        with self._lock:
            state = self._state
            operations = (self._stager, self._runner)
            immediate = state in {
                SyslinuxWorkflowState.CREATED,
                SyslinuxWorkflowState.PREPARED,
                SyslinuxWorkflowState.CONFIRMED,
            }
        for operation in operations:
            if operation is not None:
                try:
                    operation.cancel()
                except Exception:
                    logger.exception("Could not signal Syslinux workflow cancellation")
        if immediate:
            self._cleanup_owned(clear_authorization=True)
            with self._lock:
                self._state = (
                    SyslinuxWorkflowState.CLOSED
                    if self._close_requested
                    else SyslinuxWorkflowState.CANCELLED
                )

    def close(self) -> None:
        with self._lock:
            self._close_requested = True
            active = self._state in {
                SyslinuxWorkflowState.PREPARING,
                SyslinuxWorkflowState.EXECUTING,
            }
            if self._state is SyslinuxWorkflowState.CLOSED:
                return
        if active:
            self.cancel()
            return
        self._cleanup_owned(clear_authorization=True)
        self._set_state(SyslinuxWorkflowState.CLOSED)

    def __enter__(self) -> SyslinuxWriteWorkflow:
        if self.state is SyslinuxWorkflowState.CLOSED:
            raise SyslinuxWorkflowError("The Syslinux workflow is closed")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
