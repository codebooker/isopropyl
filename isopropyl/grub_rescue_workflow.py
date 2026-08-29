from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Authoritative non-Qt lifecycle for exact GRUB 2.14 rescue media."""

import os
import re
import shutil
import stat
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .bootloaders import BoundBootBundle, prepare_bundle
from .devices import Device
from .grub_rescue import (
    GRUB_FAMILY,
    GRUB_PURPOSE,
    GRUB_VERSION,
    GrubRescueBuilder,
    GrubRescueCancelled,
    GrubRescueError,
    GrubRescuePlan,
    PreparedGrubRescueImage,
    build_grub_rescue_plan,
)
from .grub_rescue_device import (
    IMAGE_PROFILE,
    MAX_TARGET_BYTES,
    REQUIRED_EXECUTOR_PROFILE,
    ConfirmedGrubRescueDeviceWrite,
    GrubRescueDevicePlanCancelled,
    GrubRescueDevicePlanError,
    GrubRescueDeviceWritePlan,
    build_grub_rescue_device_write_plan,
    confirm_grub_rescue_device_write,
    validate_confirmed_grub_rescue_device_write,
    validate_grub_rescue_device_write_plan,
)
from .grub_rescue_device_runner import (
    GrubRescueDeviceHelperUnavailable,
    GrubRescueDeviceRunCancelled,
    GrubRescueDeviceRunError,
    GrubRescueDeviceWriteResult,
    GrubRescueDeviceWriteRunner,
    HelperInstallation,
    resolve_grub_rescue_helper_installation,
)
from .private_fat32 import PrivateFat32State
from .syslinux_device import (
    SyslinuxDevicePlanError,
    _validate_live_target,
    _validate_target_node,
)
from .syslinux_device_helper import GRUB_RESCUE_HELPER_PROFILE
from .writer import WriterSafetyError, validate_device_selection


SECTOR_SIZE = 512
FREE_SPACE_RESERVE = 64 * 1024 * 1024
_REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | os.O_DIRECTORY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)

WorkflowProgress = Callable[[str, int, int], None]


class GrubRescueWorkflowError(RuntimeError):
    """The exact rescue workflow did not produce an authoritative result."""


class GrubRescueWorkflowCancelled(GrubRescueWorkflowError):
    """The workflow was cancelled before a completed result."""


class GrubRescueWorkflowState(str, Enum):
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
class GrubRescueWorkflowDependencies:
    resolve_helper: Callable[[], HelperInstallation] = (
        resolve_grub_rescue_helper_installation
    )
    prepare_exact_bundle: Callable[..., BoundBootBundle] = prepare_bundle
    build_rescue_plan: Callable[..., GrubRescuePlan] = build_grub_rescue_plan
    builder_factory: Callable[[], object] = GrubRescueBuilder
    build_target_plan: Callable[..., GrubRescueDeviceWritePlan] = (
        build_grub_rescue_device_write_plan
    )
    confirm_target: Callable[..., ConfirmedGrubRescueDeviceWrite] = (
        confirm_grub_rescue_device_write
    )
    runner_factory: Callable[[], object] = GrubRescueDeviceWriteRunner
    disk_usage: Callable[[str | os.PathLike[str]], object] = shutil.disk_usage


def _validate_initial_device(device: Device) -> None:
    if type(device) is not Device:
        raise GrubRescueWorkflowError("An exact discovered Device is required")
    try:
        validate_device_selection(device, writable=True)
    except WriterSafetyError as error:
        raise GrubRescueWorkflowError(str(error)) from error
    if device.transport not in {"usb", "mmc"} or device.removable is not True:
        raise GrubRescueWorkflowError(
            "GRUB rescue writing requires kernel-removable USB or SD/MMC media",
        )
    if device.logical_sector_size != SECTOR_SIZE:
        raise GrubRescueWorkflowError(
            "GRUB rescue writing requires 512-byte logical sectors",
        )
    if device.size % SECTOR_SIZE:
        raise GrubRescueWorkflowError("The GRUB rescue target is not sector aligned")
    if device.size > MAX_TARGET_BYTES:
        raise GrubRescueWorkflowError("The GRUB rescue target exceeds 128 GiB")


def _target_topology(device: Device) -> frozenset[int]:
    try:
        status = _validate_target_node(device)
        observation = _validate_live_target(device, status)
    except SyslinuxDevicePlanError as error:
        raise GrubRescueWorkflowError(str(error)) from error
    return observation.related_device_numbers


def _secure_empty_directories(
    owned: tempfile.TemporaryDirectory[str],
) -> tuple[Path, Path, int]:
    if type(owned) is not tempfile.TemporaryDirectory:
        raise GrubRescueWorkflowError(
            "An exact owned TemporaryDirectory is required",
        )
    root = Path(owned.name)
    if not root.is_absolute() or os.path.normpath(os.fspath(root)) != os.fspath(root):
        raise GrubRescueWorkflowError("The owned workspace path is not canonical")
    descriptor = -1
    children: list[int] = []
    try:
        before = os.lstat(root)
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o700
            or os.path.realpath(root) != os.fspath(root)
        ):
            raise GrubRescueWorkflowError("The owned workflow root is unsafe")
        descriptor = os.open(root, _DIRECTORY_FLAGS)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise GrubRescueWorkflowError("The owned workflow root changed")
        if os.listdir(descriptor):
            raise GrubRescueWorkflowError("The owned workflow root must start empty")
        for name in ("staging", "workspace"):
            os.mkdir(name, 0o700, dir_fd=descriptor)
            child = os.open(name, _DIRECTORY_FLAGS, dir_fd=descriptor)
            children.append(child)
            info = os.fstat(child)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or os.listdir(child)
            ):
                raise GrubRescueWorkflowError(
                    "A private GRUB workflow directory is unsafe",
                )
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
            raise GrubRescueWorkflowError("The owned workflow root changed")
        return root / "staging", root / "workspace", opened.st_dev
    except GrubRescueWorkflowError:
        raise
    except OSError as error:
        raise GrubRescueWorkflowError(
            "Could not securely establish the private GRUB workspace",
        ) from error
    finally:
        for child in children:
            try:
                os.close(child)
            except OSError:
                pass
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


class GrubRescueWriteWorkflow:
    """Own one exact prepare, confirmation, and dedicated device transaction."""

    def __init__(
        self,
        device: Device,
        owned_workspace: tempfile.TemporaryDirectory[str],
        *,
        dependencies: GrubRescueWorkflowDependencies = (
            GrubRescueWorkflowDependencies()
        ),
    ) -> None:
        _validate_initial_device(device)
        if type(owned_workspace) is not tempfile.TemporaryDirectory:
            raise GrubRescueWorkflowError(
                "An exact owned TemporaryDirectory is required",
            )
        if type(dependencies) is not GrubRescueWorkflowDependencies:
            raise GrubRescueWorkflowError("GRUB workflow dependencies are invalid")
        self.device = device
        self.dependencies = dependencies
        self._owned_workspace: tempfile.TemporaryDirectory[str] | None = (
            owned_workspace
        )
        self._lock = threading.RLock()
        self._cancelled = threading.Event()
        self._state = GrubRescueWorkflowState.CREATED
        self._close_requested = False
        self._committed = False
        self._prepared: PreparedGrubRescueImage | None = None
        self._plan: GrubRescueDeviceWritePlan | None = None
        self._confirmation: ConfirmedGrubRescueDeviceWrite | None = None
        self._runner: object | None = None
        self._result: GrubRescueDeviceWriteResult | None = None

    @property
    def state(self) -> GrubRescueWorkflowState:
        with self._lock:
            return self._state

    @property
    def plan(self) -> GrubRescueDeviceWritePlan | None:
        with self._lock:
            return self._plan

    @property
    def confirmation(self) -> ConfirmedGrubRescueDeviceWrite | None:
        with self._lock:
            return self._confirmation

    @property
    def result(self) -> GrubRescueDeviceWriteResult | None:
        with self._lock:
            return self._result

    @property
    def committed(self) -> bool:
        with self._lock:
            runner = self._runner
            return self._committed or bool(
                getattr(runner, "committed", False) if runner is not None else False
            )

    @property
    def confirmation_phrase(self) -> str:
        with self._lock:
            if self._plan is None or self._state not in {
                GrubRescueWorkflowState.PREPARED,
                GrubRescueWorkflowState.CONFIRMED,
            }:
                raise GrubRescueWorkflowError(
                    "A prepared GRUB target plan is required",
                )
            return self._plan.confirmation_phrase

    def _check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise GrubRescueWorkflowCancelled("The GRUB rescue workflow was cancelled")

    def _cleanup(self) -> None:
        with self._lock:
            prepared = self._prepared
            owned = self._owned_workspace
            self._prepared = None
            self._owned_workspace = None
        if prepared is not None:
            try:
                prepared.close()
            except Exception:
                pass
        if owned is not None:
            try:
                owned.cleanup()
            except OSError:
                pass

    def _translate(self, error: BaseException) -> GrubRescueWorkflowError:
        if isinstance(error, GrubRescueWorkflowError):
            return error
        if isinstance(
            error,
            (
                GrubRescueCancelled,
                GrubRescueDevicePlanCancelled,
                GrubRescueDeviceRunCancelled,
            ),
        ):
            return GrubRescueWorkflowCancelled(str(error) or "Cancelled")
        if isinstance(
            error,
            (
                GrubRescueError,
                GrubRescueDevicePlanError,
                GrubRescueDeviceRunError,
                GrubRescueDeviceHelperUnavailable,
                OSError,
                ValueError,
            ),
        ):
            return GrubRescueWorkflowError(str(error) or "GRUB workflow failed")
        return GrubRescueWorkflowError(str(error) or error.__class__.__name__)

    def _fail(self, error: BaseException) -> GrubRescueWorkflowError:
        translated = self._translate(error)
        with self._lock:
            runner = self._runner
            self._committed = self._committed or bool(
                getattr(runner, "committed", False) if runner is not None else False
            )
        self._cleanup()
        with self._lock:
            self._state = (
                GrubRescueWorkflowState.CLOSED
                if self._close_requested
                else GrubRescueWorkflowState.CANCELLED
                if isinstance(translated, GrubRescueWorkflowCancelled)
                and not self._committed
                else GrubRescueWorkflowState.FAILED
            )
        return translated

    @staticmethod
    def _raise(error: BaseException, translated: GrubRescueWorkflowError) -> None:
        if translated is error:
            raise translated
        raise translated from error

    def prepare(
        self,
        progress: WorkflowProgress = lambda _stage, _done, _total: None,
    ) -> GrubRescueDeviceWritePlan:
        with self._lock:
            if self._state is not GrubRescueWorkflowState.CREATED:
                raise GrubRescueWorkflowError("A GRUB workflow can only be prepared once")
            self._state = GrubRescueWorkflowState.PREPARING
            owned = self._owned_workspace
        try:
            _validate_initial_device(self.device)
            self._check_cancelled()
            if owned is None:
                raise GrubRescueWorkflowError("The owned workflow root is unavailable")
            staging, workspace, storage_device = _secure_empty_directories(owned)
            topology = _target_topology(self.device)
            if storage_device in topology:
                raise GrubRescueWorkflowError(
                    "The GRUB workspace resides on the selected target",
                )
            usage = self.dependencies.disk_usage(os.fspath(workspace))
            free = getattr(usage, "free", None)
            required = self.device.size + FREE_SPACE_RESERVE
            if type(free) is not int or isinstance(free, bool) or free < required:
                raise GrubRescueWorkflowError(
                    "The private workspace needs the full target size plus a 64 MiB reserve",
                )
            self._check_cancelled()
            installation = self.dependencies.resolve_helper()
            if type(installation) is not HelperInstallation:
                raise GrubRescueWorkflowError(
                    "The exact GRUB helper installation is unavailable",
                )
            self._check_cancelled()
            bundle = self.dependencies.prepare_exact_bundle(
                GRUB_FAMILY,
                GRUB_VERSION,
                GRUB_PURPOSE,
                cancel_event=self._cancelled,
                progress=lambda done, total: progress("download", done, total),
            )
            if type(bundle) is not BoundBootBundle:
                raise GrubRescueWorkflowError("The GRUB bundle result is invalid")
            self._check_cancelled()
            rescue_plan = self.dependencies.build_rescue_plan(
                bundle,
                staging,
                workspace,
                image_size=self.device.size,
                cancel_check=self._check_cancelled,
            )
            if type(rescue_plan) is not GrubRescuePlan:
                raise GrubRescueWorkflowError("The GRUB rescue planner returned an invalid plan")
            builder = self.dependencies.builder_factory()
            prepared = builder.execute(
                rescue_plan,
                cancel_check=self._check_cancelled,
                progress=lambda stage, _path, done, total: progress(
                    stage, done, total,
                ),
            )
            if type(prepared) is not PreparedGrubRescueImage:
                raise GrubRescueWorkflowError("The GRUB builder returned an invalid owner")
            with self._lock:
                self._prepared = prepared
            self._check_cancelled()
            target_plan = self.dependencies.build_target_plan(
                rescue_plan,
                prepared.result,
                prepared,
                self.device,
                cancel_check=self._check_cancelled,
            )
            if type(target_plan) is not GrubRescueDeviceWritePlan:
                raise GrubRescueWorkflowError("The GRUB target planner returned an invalid plan")
            validate_grub_rescue_device_write_plan(
                target_plan,
                cancel_check=self._check_cancelled,
            )
            if (
                target_plan.rescue_plan is not rescue_plan
                or target_plan.rescue_result is not prepared.result
                or target_plan.prepared is not prepared
                or target_plan.device is not self.device
            ):
                raise GrubRescueWorkflowError("The GRUB target plan is cross-wired")
            with self._lock:
                if (
                    self._state is not GrubRescueWorkflowState.PREPARING
                    or self._close_requested
                    or self._cancelled.is_set()
                ):
                    raise GrubRescueWorkflowCancelled(
                        "The GRUB rescue workflow was closed or cancelled",
                    )
                self._plan = target_plan
                self._state = GrubRescueWorkflowState.PREPARED
            return target_plan
        except BaseException as error:
            translated = self._fail(error)
            self._raise(error, translated)

    def confirm(self, phrase: str) -> ConfirmedGrubRescueDeviceWrite:
        with self._lock:
            plan = self._plan
            if self._state is not GrubRescueWorkflowState.PREPARED or plan is None:
                raise GrubRescueWorkflowError("The GRUB workflow is not ready to confirm")
            if type(phrase) is not str or phrase != plan.confirmation_phrase:
                raise GrubRescueWorkflowError(
                    "The GRUB destructive confirmation phrase did not match exactly",
                )
        try:
            self._check_cancelled()
            confirmation = self.dependencies.confirm_target(
                plan,
                phrase,
                cancel_check=self._check_cancelled,
            )
            if type(confirmation) is not ConfirmedGrubRescueDeviceWrite:
                raise GrubRescueWorkflowError("The GRUB confirmation result is invalid")
            validate_confirmed_grub_rescue_device_write(
                plan,
                confirmation,
                cancel_check=self._check_cancelled,
            )
            if confirmation.plan is not plan:
                raise GrubRescueWorkflowError("The GRUB confirmation is cross-wired")
            with self._lock:
                if self._state is not GrubRescueWorkflowState.PREPARED:
                    raise GrubRescueWorkflowCancelled("The GRUB workflow was cancelled")
                self._confirmation = confirmation
                self._state = GrubRescueWorkflowState.CONFIRMED
            return confirmation
        except BaseException as error:
            translated = self._fail(error)
            self._raise(error, translated)

    def _validate_result(
        self,
        plan: GrubRescueDeviceWritePlan,
        result: GrubRescueDeviceWriteResult,
        runner: object,
    ) -> None:
        if type(result) is not GrubRescueDeviceWriteResult:
            raise GrubRescueWorkflowError("The dedicated GRUB runner result is invalid")
        prepared = plan.rescue_result
        if (
            type(result.plan_sha256) is not str
            or _SHA256.fullmatch(result.plan_sha256) is None
            or type(result.ready_sha256) is not str
            or _SHA256.fullmatch(result.ready_sha256) is None
            or type(result.request_id) is not str
            or _REQUEST_ID.fullmatch(result.request_id) is None
            or result.plan_sha256 != plan.plan_sha256
            or result.rescue_plan_sha256 != plan.rescue_plan_sha256
            or result.private_plan_sha256 != plan.private_plan_sha256
            or result.target_path != plan.device.path
            or result.major_minor != plan.device.major_minor
            or result.disk_sequence != plan.disk_sequence
            or result.image_size != plan.image_size
            or result.image_sha256 != plan.final_image_sha256
            or result.final_fat_manifest_sha256
            != plan.final_fat_manifest_sha256
            or result.disk_signature != plan.disk_signature
            or result.volume_id != plan.volume_id
            or result.logical_sector_size != plan.logical_sector_size
            or result.image_profile != prepared.profile
            or result.result_semantics != prepared.result_semantics
            or result.helper_profile != GRUB_RESCUE_HELPER_PROFILE
            or result.exclusive_open is not True
            or result.cache_invalidated is not True
            or result.mandatory_readback is not True
            or type(result.cancellation_deferred) is not bool
            or result.cancellation_deferred is not self._cancelled.is_set()
            or getattr(runner, "committed", False) is not True
            or plan.image_profile != IMAGE_PROFILE
            or plan.required_executor_profile != REQUIRED_EXECUTOR_PROFILE
            or plan.mandatory_preactivation_readback is not True
            or plan.mandatory_final_readback is not True
        ):
            raise GrubRescueWorkflowError(
                "The dedicated GRUB result does not match the confirmed transaction",
            )

    def execute(
        self,
        progress: WorkflowProgress = lambda _stage, _done, _total: None,
    ) -> GrubRescueDeviceWriteResult:
        with self._lock:
            if (
                self._state is not GrubRescueWorkflowState.CONFIRMED
                or self._plan is None
                or self._confirmation is None
                or self._prepared is None
            ):
                raise GrubRescueWorkflowError(
                    "The GRUB workflow requires exact confirmation before execution",
                )
            runner = self.dependencies.runner_factory()
            self._runner = runner
            self._state = GrubRescueWorkflowState.EXECUTING
            plan = self._plan
            confirmation = self._confirmation
        try:
            result = runner.run(
                plan,
                confirmation,
                lambda stage, _path, done, total: progress(stage, done, total),
            )
            self._validate_result(plan, result, runner)
            with self._lock:
                self._committed = True
                self._result = result
            self._cleanup()
            with self._lock:
                self._state = (
                    GrubRescueWorkflowState.CLOSED
                    if self._close_requested
                    else GrubRescueWorkflowState.COMPLETED
                )
            return result
        except BaseException as error:
            translated = self._fail(error)
            self._raise(error, translated)

    def cancel(self) -> None:
        self._cancelled.set()
        with self._lock:
            state = self._state
            runner = self._runner
            committed = self._committed or bool(
                getattr(runner, "committed", False) if runner is not None else False
            )
            self._committed = committed
        if runner is not None:
            try:
                runner.cancel()
            except Exception:
                pass
        if committed or state in {
            GrubRescueWorkflowState.PREPARING,
            GrubRescueWorkflowState.EXECUTING,
        }:
            return
        if state in {
            GrubRescueWorkflowState.CREATED,
            GrubRescueWorkflowState.PREPARED,
            GrubRescueWorkflowState.CONFIRMED,
        }:
            self._cleanup()
            with self._lock:
                self._state = (
                    GrubRescueWorkflowState.CLOSED
                    if self._close_requested
                    else GrubRescueWorkflowState.CANCELLED
                )

    def close(self) -> None:
        with self._lock:
            self._close_requested = True
            active = self._state in {
                GrubRescueWorkflowState.PREPARING,
                GrubRescueWorkflowState.EXECUTING,
            }
            if self._state is GrubRescueWorkflowState.CLOSED:
                return
        if active:
            self.cancel()
            return
        self._cleanup()
        with self._lock:
            self._state = GrubRescueWorkflowState.CLOSED

    def __enter__(self) -> GrubRescueWriteWorkflow:
        if self.state is GrubRescueWorkflowState.CLOSED:
            raise GrubRescueWorkflowError("The GRUB workflow is closed")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
