from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""One-shot, non-Qt orchestration for authenticated raw image writes.

Every raw-capable GUI input reaches the same anonymous snapshot and privileged
device transaction.  This module deliberately has no legacy writer, shell
pipeline, or alternate executor: unavailable host integration and unsupported
geometry fail before source materialization begins.
"""

import logging
import os
import stat
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .devices import Device
from .images import ImageInspection
from .raw_device import (
    ConfirmedRawDeviceWrite,
    RawDevicePlanCancelled,
    RawDevicePlanError,
    RawDeviceWritePlan,
    build_raw_device_write_plan,
    confirm_raw_device_write,
    observe_raw_target_device_numbers,
    raw_source_evidence_from_snapshot,
)
from .raw_device_runner import (
    RawDeviceRunCancelled,
    RawDeviceRunError,
    RawDeviceWriteResult,
    RawDeviceWriteRunner,
    resolve_raw_helper_installation,
)
from .raw_snapshot import (
    PreparedRawSnapshot,
    RawSnapshotBuilder,
    RawSnapshotCancelled,
    RawSnapshotError,
    build_image_source_snapshot_plan,
    build_materialized_snapshot_plan,
)
from .sources import (
    ImageSource,
    ImageSourceError,
    SourceChanged,
    SourceIdentity,
    open_image_source,
)
from .virtual import (
    CompressedVirtualDiskPreparer,
    PreparedCompressedVirtualDisk,
    VirtualConversionCancelled,
    VirtualDiskChanged,
    VirtualDiskError,
    VirtualDiskInfo,
    VirtualDiskStager,
    inspect_virtual_disk,
)


logger = logging.getLogger("isopropyl")

SECTOR_BYTES = 512
MINIMUM_RAW_BYTES = 2 * SECTOR_BYTES
_VIRTUAL_FORMATS = {
    "vhd": "vpc",
    "vhdx": "vhdx",
    "qcow": "qcow",
    "qcow2": "qcow2",
}

WorkflowProgress = Callable[[str, int, int], None]


class RawWorkflowError(RuntimeError):
    """A raw workflow could not produce its exact authenticated result."""


class RawWorkflowCancelled(RawWorkflowError):
    """The raw workflow was cancelled before a completed result."""


class RawWorkflowState(str, Enum):
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
class RawWorkflowDependencies:
    """Injectable system boundary used by deterministic workflow tests."""

    resolve_helper: Callable[[], object] = resolve_raw_helper_installation
    observe_target: Callable[..., frozenset[int]] = observe_raw_target_device_numbers
    open_source: Callable[..., ImageSource] = open_image_source
    build_stream_plan: Callable[..., object] = build_image_source_snapshot_plan
    build_materialized_plan: Callable[..., object] = build_materialized_snapshot_plan
    source_evidence: Callable[..., object] = raw_source_evidence_from_snapshot
    build_target_plan: Callable[..., RawDeviceWritePlan] = build_raw_device_write_plan
    confirm_target: Callable[..., ConfirmedRawDeviceWrite] = confirm_raw_device_write
    inspect_virtual: Callable[..., VirtualDiskInfo] = inspect_virtual_disk
    snapshot_builder_factory: Callable[[], RawSnapshotBuilder] = RawSnapshotBuilder
    virtual_stager_factory: Callable[[], VirtualDiskStager] = VirtualDiskStager
    compressed_virtual_factory: Callable[[], CompressedVirtualDiskPreparer] = (
        CompressedVirtualDiskPreparer
    )
    runner_factory: Callable[[], RawDeviceWriteRunner] = RawDeviceWriteRunner


def _source_identity_tuple(
    identity: SourceIdentity | tuple[int, int, int, int, int],
) -> tuple[int, int, int, int, int]:
    if type(identity) is SourceIdentity:
        values = (
            identity.device,
            identity.inode,
            identity.size,
            identity.modified_ns,
            identity.changed_ns,
        )
    elif type(identity) is tuple and len(identity) == 5:
        values = identity
    else:
        raise RawWorkflowError(
            "An exact five-field selected source identity is required"
        )
    if any(type(value) is not int or value < 0 for value in values):
        raise RawWorkflowError(
            "An exact five-field selected source identity is required"
        )
    if values[1] == 0 or values[2] <= 0:
        raise RawWorkflowError("The selected source identity is invalid")
    return values


def _opened_source_identity(source: ImageSource) -> tuple[int, int, int, int, int]:
    try:
        source.fileno()
        return (
            source.identity.device,
            source.identity.inode,
            source.identity.size,
            source.identity.modified_ns,
            source.identity.changed_ns,
        )
    except (AttributeError, ImageSourceError, OSError) as error:
        raise RawWorkflowError(
            "The descriptor-bound selected source identity is invalid"
        ) from error


def _virtual_identity(info: VirtualDiskInfo) -> tuple[int, int, int, int, int]:
    try:
        return (
            info.identity.device,
            info.identity.inode,
            info.identity.size,
            info.identity.modified_ns,
            info.identity.changed_ns,
        )
    except AttributeError as error:
        raise RawWorkflowError("The virtual-disk identity is malformed") from error


class RawWriteWorkflow:
    """Own one source -> anonymous snapshot -> raw helper transaction."""

    def __init__(
        self,
        source: Path,
        inspection: ImageInspection,
        device: Device,
        expected_source_identity: SourceIdentity | tuple[int, int, int, int, int],
        *,
        final_verification: bool,
        temporary_root: Path | None = None,
        dependencies: RawWorkflowDependencies = RawWorkflowDependencies(),
    ) -> None:
        if not isinstance(source, Path) or not source.is_absolute():
            raise RawWorkflowError("The selected source path must be absolute")
        if type(inspection) is not ImageInspection:
            raise RawWorkflowError("An exact completed image inspection is required")
        if type(device) is not Device:
            raise RawWorkflowError("An exact discovered target device is required")
        if type(final_verification) is not bool:
            raise RawWorkflowError("The final verification choice must be boolean")
        if type(dependencies) is not RawWorkflowDependencies:
            raise RawWorkflowError("Raw workflow dependencies are invalid")
        if temporary_root is not None and not isinstance(temporary_root, Path):
            raise RawWorkflowError("The temporary root must be a Path")

        self.source_path = source
        self.inspection = inspection
        self.device = device
        self.expected_source_identity = _source_identity_tuple(
            expected_source_identity
        )
        self.final_verification = final_verification
        self.temporary_root = temporary_root
        self.dependencies = dependencies

        self._lock = threading.RLock()
        self._cancelled = threading.Event()
        self._state = RawWorkflowState.CREATED
        self._close_requested = False
        self._workspace: tempfile.TemporaryDirectory[str] | None = None
        self._snapshot_workspace: Path | None = None
        self._container_workspace: Path | None = None
        self._source: ImageSource | None = None
        self._snapshot_builder: RawSnapshotBuilder | None = None
        self._virtual_stager: VirtualDiskStager | None = None
        self._compressed_virtual: CompressedVirtualDiskPreparer | None = None
        self._prepared_container: PreparedCompressedVirtualDisk | None = None
        self._prepared: PreparedRawSnapshot | None = None
        self._runner: RawDeviceWriteRunner | None = None
        self._plan: RawDeviceWritePlan | None = None
        self._confirmation: ConfirmedRawDeviceWrite | None = None
        self._result: RawDeviceWriteResult | None = None

    @property
    def state(self) -> RawWorkflowState:
        with self._lock:
            return self._state

    @property
    def plan(self) -> RawDeviceWritePlan | None:
        with self._lock:
            return self._plan

    @property
    def confirmation(self) -> ConfirmedRawDeviceWrite | None:
        with self._lock:
            return self._confirmation

    @property
    def result(self) -> RawDeviceWriteResult | None:
        with self._lock:
            return self._result

    @property
    def confirmation_phrase(self) -> str:
        with self._lock:
            if self._plan is None or self._state not in {
                RawWorkflowState.PREPARED,
                RawWorkflowState.CONFIRMED,
            }:
                raise RawWorkflowError(
                    "A prepared raw target plan is required before confirmation"
                )
            return self._plan.confirmation_phrase

    def _check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise RawWorkflowCancelled("The raw image workflow was cancelled")

    def _set_state(self, state: RawWorkflowState) -> None:
        with self._lock:
            self._state = state

    def _profile(self) -> tuple[str, str | None]:
        sparse = str(self.inspection.sparse_format or "").casefold()
        virtual = str(self.inspection.virtual_format or "").casefold()
        compression = str(self.inspection.compression or "none").casefold()
        if sparse and sparse != "vtsi":
            raise RawWorkflowError(
                f"Sparse raw materialization is unsupported: {sparse}"
            )
        if sparse and virtual:
            raise RawWorkflowError(
                "An image cannot be both sparse and a virtual-disk container"
            )
        if virtual:
            expected_format = _VIRTUAL_FORMATS.get(virtual)
            if expected_format is None:
                raise RawWorkflowError(
                    f"Unsupported virtual-disk format: {self.inspection.virtual_format}"
                )
            return (
                "compressed-virtual" if compression != "none" else "virtual",
                expected_format,
            )
        if sparse == "vtsi":
            if compression != "none":
                raise RawWorkflowError("Compressed VTSI input is not supported")
            return "vtsi", None
        return ("compressed" if compression != "none" else "plain"), None

    def _preflight_constraints(self) -> tuple[str, str | None]:
        size = self.inspection.size
        if type(size) is not int or isinstance(size, bool) or size < MINIMUM_RAW_BYTES:
            raise RawWorkflowError(
                "The raw helper requires an expanded image of at least 1024 bytes"
            )
        if size % SECTOR_BYTES:
            raise RawWorkflowError(
                "The raw helper requires an expanded image size divisible by 512 bytes"
            )
        if self.device.logical_sector_size != SECTOR_BYTES:
            raise RawWorkflowError(
                "The raw helper requires a target reporting 512-byte logical sectors"
            )
        if self.device.size % SECTOR_BYTES:
            raise RawWorkflowError(
                "The raw helper requires a sector-aligned target capacity"
            )
        if size > self.device.size:
            raise RawWorkflowError(
                "The expanded raw image is larger than the selected target"
            )
        profile, expected_format = self._profile()
        if profile == "vtsi" and size != self.device.size:
            raise RawWorkflowError(
                "VTSI restore requires a target whose capacity exactly matches "
                "the expanded image"
            )
        return profile, expected_format

    def _translate(self, error: BaseException) -> RawWorkflowError:
        if isinstance(error, RawWorkflowCancelled):
            return error
        if isinstance(
            error,
            (
                RawSnapshotCancelled,
                RawDevicePlanCancelled,
                RawDeviceRunCancelled,
                VirtualConversionCancelled,
            ),
        ):
            return RawWorkflowCancelled(str(error) or "The raw workflow was cancelled")
        if isinstance(error, RawWorkflowError):
            return error
        if isinstance(
            error,
            (
                RawSnapshotError,
                RawDevicePlanError,
                RawDeviceRunError,
                VirtualDiskError,
                VirtualDiskChanged,
                ImageSourceError,
                SourceChanged,
                OSError,
                ValueError,
            ),
        ):
            return RawWorkflowError(str(error) or "The raw workflow failed")
        return RawWorkflowError(str(error) or error.__class__.__name__)

    @staticmethod
    def _raise_translated(error: BaseException, translated: RawWorkflowError) -> None:
        if translated is error:
            raise translated
        raise translated from error

    def _close_source_resources(self) -> None:
        with self._lock:
            container = self._prepared_container
            source = self._source
            self._prepared_container = None
            self._source = None
            self._snapshot_builder = None
            self._virtual_stager = None
            self._compressed_virtual = None
        for resource in (container, source):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    logger.exception("Could not close a raw source preparation resource")

    def _cleanup_owned(self) -> None:
        with self._lock:
            prepared = self._prepared
            container = self._prepared_container
            source = self._source
            workspace = self._workspace
            self._prepared = None
            self._prepared_container = None
            self._source = None
            self._workspace = None
            self._snapshot_workspace = None
            self._container_workspace = None
            self._snapshot_builder = None
            self._virtual_stager = None
            self._compressed_virtual = None
            self._runner = None
        for resource in (prepared, container, source):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    logger.exception("Could not close a raw workflow resource")
        if workspace is not None:
            try:
                workspace.cleanup()
            except OSError:
                logger.exception("Could not remove the raw workflow workspace")

    def _fail(self, error: BaseException) -> RawWorkflowError:
        translated = self._translate(error)
        self._cleanup_owned()
        with self._lock:
            self._state = (
                RawWorkflowState.CLOSED
                if self._close_requested
                else RawWorkflowState.CANCELLED
                if isinstance(translated, RawWorkflowCancelled)
                else RawWorkflowState.FAILED
            )
        return translated

    def _open_bound_source(self) -> ImageSource:
        source = self.dependencies.open_source(
            self.source_path,
            cancel_check=self._check_cancelled,
        )
        if type(source) is not ImageSource:
            raise RawWorkflowError("The source opener returned an invalid ImageSource")
        try:
            current_identity = _opened_source_identity(source)
        except BaseException:
            source.close()
            raise
        if current_identity != self.expected_source_identity:
            source.close()
            raise RawWorkflowError(
                "The selected image changed after inspection and selection"
            )
        with self._lock:
            self._source = source
        return source

    def _validate_source_profile(self, source: ImageSource, profile: str) -> None:
        expected_compression = str(self.inspection.compression or "none").casefold()
        if source.compression.casefold() != expected_compression:
            raise RawWorkflowError(
                "The selected image compression changed after inspection"
            )
        if profile == "vtsi":
            if (
                source.sparse_format != "vtsi"
                or not source.requires_exact_target_size
                or source.required_logical_sector_size != SECTOR_BYTES
            ):
                raise RawWorkflowError("The selected VTSI constraints changed")
        elif source.sparse_format:
            raise RawWorkflowError(
                "The selected image sparse format changed after inspection"
            )

    def _prepare_virtual(
        self,
        profile: str,
        expected_format: str,
        source: ImageSource,
        snapshot_plan: object,
        progress: WorkflowProgress,
    ) -> PreparedRawSnapshot:
        if profile == "compressed-virtual":
            container_workspace = self._container_workspace
            if container_workspace is None:
                raise RawWorkflowError(
                    "The virtual-container workspace is unavailable"
                )
            preparer = self.dependencies.compressed_virtual_factory()
            with self._lock:
                self._compressed_virtual = preparer
            progress("decode-virtual", 0, 0)
            container = preparer.prepare(
                self.source_path,
                expected_identity=self.expected_source_identity,
                expected_format=expected_format,
                expected_virtual_size=self.inspection.size,
                temporary_root=container_workspace,
                cancel_check=self._check_cancelled,
            )
            with self._lock:
                self._prepared_container = container
            info = container.info
            progress("decode-virtual", container.decoded_size, container.decoded_size)
        else:
            info = self.dependencies.inspect_virtual(
                self.source_path,
                cancel_check=self._check_cancelled,
            )
            if _virtual_identity(info) != self.expected_source_identity:
                raise RawWorkflowError(
                    "The selected virtual disk changed after inspection"
                )
            if info.format != expected_format or info.virtual_size != self.inspection.size:
                raise RawWorkflowError(
                    "The virtual-disk format or guest-visible size changed "
                    "after inspection"
                )

        stager = self.dependencies.virtual_stager_factory()
        builder = self.dependencies.snapshot_builder_factory()
        with self._lock:
            self._virtual_stager = stager
            self._snapshot_builder = builder

        def materialize(descriptor: int, cancel_check: Callable[[], None]) -> None:
            cancel_check()
            stager.convert_into_descriptor(
                info,
                descriptor,
                lambda done, total: progress("convert-virtual", done, total),
            )
            cancel_check()

        return builder.execute_materialized(
            snapshot_plan,
            materialize,
            cancel_check=self._check_cancelled,
            progress=lambda done, total: progress("snapshot", done, total),
        )

    def prepare(
        self,
        progress: WorkflowProgress = lambda _stage, _done, _total: None,
    ) -> RawDeviceWritePlan:
        with self._lock:
            if self._state is not RawWorkflowState.CREATED:
                raise RawWorkflowError("A raw workflow can only be prepared once")
            self._state = RawWorkflowState.PREPARING
        try:
            profile, expected_format = self._preflight_constraints()
            self._check_cancelled()
            # Validate exact root-owned host integration before an expensive
            # decode, sparse expansion, virtual conversion, or full snapshot.
            self.dependencies.resolve_helper()
            self._check_cancelled()
            topology = self.dependencies.observe_target(
                self.device,
                cancel_check=self._check_cancelled,
            )
            self._check_cancelled()
            if type(topology) is not frozenset or not topology or any(
                type(number) is not int or number < 0 for number in topology
            ):
                raise RawWorkflowError("The target topology evidence is invalid")
            temporary_root = self.temporary_root or Path(tempfile.gettempdir())
            try:
                temporary_root = temporary_root.resolve(strict=True)
                root_status = temporary_root.stat()
            except OSError as error:
                raise RawWorkflowError(
                    "The raw workflow temporary root is unavailable"
                ) from error
            if not stat.S_ISDIR(root_status.st_mode):
                raise RawWorkflowError(
                    "The raw workflow temporary root must be a directory"
                )
            if root_status.st_dev in topology:
                raise RawWorkflowError(
                    "The raw workflow temporary root resides on the selected target"
                )
            self._check_cancelled()
            workspace = tempfile.TemporaryDirectory(
                prefix=".isopropyl-raw-",
                dir=str(temporary_root),
            )
            os.chmod(workspace.name, 0o700)
            workspace_path = Path(workspace.name)
            snapshot_workspace = workspace_path / "snapshot"
            container_workspace = workspace_path / "staging"
            snapshot_workspace.mkdir(mode=0o700)
            container_workspace.mkdir(mode=0o700)
            if (
                workspace_path.stat().st_dev != root_status.st_dev
                or snapshot_workspace.stat().st_dev != root_status.st_dev
                or container_workspace.stat().st_dev != root_status.st_dev
            ):
                workspace.cleanup()
                raise RawWorkflowError(
                    "The raw workflow workspace filesystem changed during creation"
                )
            with self._lock:
                self._workspace = workspace
                self._snapshot_workspace = snapshot_workspace
                self._container_workspace = container_workspace
            source = self._open_bound_source()
            self._validate_source_profile(source, profile)

            if profile in {"virtual", "compressed-virtual"}:
                assert expected_format is not None
                snapshot_plan = self.dependencies.build_materialized_plan(
                    source,
                    snapshot_workspace,
                    expected_expanded_size=self.inspection.size,
                    materialization_profile=profile,
                    target_device_numbers=topology,
                    cancel_check=self._check_cancelled,
                )
                prepared = self._prepare_virtual(
                    profile,
                    expected_format,
                    source,
                    snapshot_plan,
                    progress,
                )
            else:
                snapshot_plan = self.dependencies.build_stream_plan(
                    source,
                    snapshot_workspace,
                    expected_expanded_size=self.inspection.size,
                    materialization_profile=profile,
                    requires_exact_target_size=source.requires_exact_target_size,
                    required_logical_sector_size=(
                        source.required_logical_sector_size or None
                    ),
                    target_device_numbers=topology,
                    cancel_check=self._check_cancelled,
                )
                builder = self.dependencies.snapshot_builder_factory()
                with self._lock:
                    self._snapshot_builder = builder
                prepared = builder.execute(
                    snapshot_plan,
                    cancel_check=self._check_cancelled,
                    progress=lambda done, total: progress("snapshot", done, total),
                )
            with self._lock:
                self._prepared = prepared
            self._check_cancelled()
            evidence = self.dependencies.source_evidence(prepared)
            target_plan = self.dependencies.build_target_plan(
                evidence,
                self.device,
                final_verification=self.final_verification,
                cancel_check=self._check_cancelled,
            )
            self._check_cancelled()
            self._close_source_resources()
            with self._lock:
                if (
                    self._close_requested
                    or self._cancelled.is_set()
                    or self._state is not RawWorkflowState.PREPARING
                ):
                    raise RawWorkflowCancelled(
                        "The raw workflow was closed"
                        if self._close_requested
                        else "The raw workflow was cancelled"
                    )
                self._plan = target_plan
                self._state = RawWorkflowState.PREPARED
            return target_plan
        except BaseException as error:
            translated = self._fail(error)
            self._raise_translated(error, translated)

    def confirm(self, phrase: str) -> ConfirmedRawDeviceWrite:
        with self._lock:
            plan = self._plan
            if self._state is not RawWorkflowState.PREPARED or plan is None:
                raise RawWorkflowError("The raw workflow is not ready for confirmation")
            if type(phrase) is not str or phrase != plan.confirmation_phrase:
                raise RawWorkflowError(
                    "The destructive confirmation phrase did not match exactly"
                )
        try:
            self._check_cancelled()
            confirmation = self.dependencies.confirm_target(
                plan,
                phrase,
                cancel_check=self._check_cancelled,
            )
            self._check_cancelled()
            with self._lock:
                if self._state is not RawWorkflowState.PREPARED:
                    raise RawWorkflowCancelled("The raw workflow was cancelled")
                self._confirmation = confirmation
                self._state = RawWorkflowState.CONFIRMED
            return confirmation
        except BaseException as error:
            translated = self._fail(error)
            self._raise_translated(error, translated)

    def execute(
        self,
        progress: WorkflowProgress = lambda _stage, _done, _total: None,
    ) -> RawDeviceWriteResult:
        with self._lock:
            if (
                self._state is not RawWorkflowState.CONFIRMED
                or self._plan is None
                or self._confirmation is None
                or self._prepared is None
            ):
                raise RawWorkflowError(
                    "The raw workflow requires an exact confirmation before execution"
                )
            runner = self.dependencies.runner_factory()
            self._runner = runner
            self._state = RawWorkflowState.EXECUTING
            plan = self._plan
            confirmation = self._confirmation
            prepared = self._prepared
        try:
            result = runner.run(
                plan,
                confirmation,
                prepared,
                lambda stage, _path, done, total: progress(stage, done, total),
            )
            with self._lock:
                self._result = result
            self._cleanup_owned()
            with self._lock:
                self._state = (
                    RawWorkflowState.CLOSED
                    if self._close_requested
                    else RawWorkflowState.COMPLETED
                )
            return result
        except BaseException as error:
            translated = self._fail(error)
            self._raise_translated(error, translated)

    def cancel(self) -> None:
        self._cancelled.set()
        with self._lock:
            state = self._state
            operations = (
                self._snapshot_builder,
                self._virtual_stager,
                self._compressed_virtual,
                self._runner,
            )
            immediate = state in {
                RawWorkflowState.CREATED,
                RawWorkflowState.PREPARED,
                RawWorkflowState.CONFIRMED,
            }
        for operation in operations:
            if operation is not None:
                try:
                    operation.cancel()
                except Exception:
                    logger.exception("Could not signal raw workflow cancellation")
        if immediate:
            self._cleanup_owned()
            with self._lock:
                self._state = (
                    RawWorkflowState.CLOSED
                    if self._close_requested
                    else RawWorkflowState.CANCELLED
                )

    def close(self) -> None:
        with self._lock:
            self._close_requested = True
            active = self._state in {
                RawWorkflowState.PREPARING,
                RawWorkflowState.EXECUTING,
            }
            if self._state is RawWorkflowState.CLOSED:
                return
        if active:
            self.cancel()
            return
        self._cleanup_owned()
        self._set_state(RawWorkflowState.CLOSED)

    def __enter__(self) -> RawWriteWorkflow:
        if self.state is RawWorkflowState.CLOSED:
            raise RawWorkflowError("The raw workflow is closed")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
