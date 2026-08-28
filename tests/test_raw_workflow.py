from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import gzip
import os
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from isopropyl.devices import Device
from isopropyl.images import ImageInspection
from isopropyl.raw_device_runner import RawDeviceRunCancelled, RawDeviceRunError
from isopropyl.raw_snapshot import (
    RawSnapshotBuilder,
    RawSnapshotCancelled,
    build_materialized_snapshot_plan,
)
from isopropyl.raw_workflow import (
    RawWorkflowCancelled,
    RawWorkflowDependencies,
    RawWorkflowError,
    RawWorkflowState,
    RawWriteWorkflow,
)
from isopropyl.sources import open_image_source
from isopropyl.virtual import (
    FileIdentity,
    ToolIdentity,
    VirtualConversionCancelled,
    VirtualDiskInfo,
)


def inspection(**changes: object) -> ImageInspection:
    original = ImageInspection(
        size=4096,
        kind="Raw disk image",
        volume_label="",
        has_mbr=True,
        has_gpt=False,
        is_iso9660=False,
        looks_windows=False,
        boot_modes=("BIOS",),
        architectures=("x64",),
        bootloader="Unknown",
        has_windows_installer=False,
        contents_scanned=False,
    )
    return replace(original, **changes)


def device(**changes: object) -> Device:
    original = Device(
        "/dev/sdz",
        8192,
        "Test USB",
        "ISOpropyl",
        "usb",
        "SERIAL",
        "WWN",
        "8:240",
        True,
        True,
        False,
        ("/media/test",),
        ("/dev/sdz1",),
        512,
    )
    return replace(original, **changes)


def identity(path: Path) -> tuple[int, int, int, int, int]:
    status = path.stat()
    return (
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


class FakePrepared:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeSnapshotBuilder:
    def __init__(self) -> None:
        self.cancelled = threading.Event()
        self.execute_calls = []
        self.materialized_calls = []
        self.result = None

    def cancel(self) -> None:
        self.cancelled.set()

    def execute(self, plan, *, cancel_check, progress):
        self.execute_calls.append(plan)
        cancel_check()
        progress(4096, 4096)
        self.result = FakePrepared()
        return self.result

    def execute_materialized(
        self,
        plan,
        materializer,
        *,
        cancel_check,
        progress,
    ):
        self.materialized_calls.append(plan)
        cancel_check()
        materializer(97, cancel_check)
        progress(4096, 4096)
        self.result = FakePrepared()
        return self.result


class BlockingSnapshotBuilder(FakeSnapshotBuilder):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()

    def execute(self, plan, *, cancel_check, progress):
        del plan, progress
        self.started.set()
        self.cancelled.wait(2)
        cancel_check()
        raise AssertionError("cancel_check did not stop the snapshot")


class FakeVirtualStager:
    def __init__(self) -> None:
        self.cancelled = False
        self.calls = []

    def cancel(self) -> None:
        self.cancelled = True

    def convert_into_descriptor(self, info, descriptor, progress) -> None:
        self.calls.append((info, descriptor))
        if self.cancelled:
            raise VirtualConversionCancelled("conversion cancelled")
        progress(info.virtual_size, info.virtual_size)


class BlockingVirtualStager(FakeVirtualStager):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.cancel_event = threading.Event()

    def cancel(self) -> None:
        super().cancel()
        self.cancel_event.set()

    def convert_into_descriptor(self, info, descriptor, progress) -> None:
        del info, descriptor, progress
        self.started.set()
        self.cancel_event.wait(2)
        raise VirtualConversionCancelled("conversion cancelled")


class TruncatingVirtualStager(FakeVirtualStager):
    def convert_into_descriptor(self, info, descriptor, progress) -> None:
        self.calls.append((info, descriptor))
        os.ftruncate(descriptor, info.virtual_size)
        progress(info.virtual_size, info.virtual_size)


class FakeContainer:
    def __init__(self, info: VirtualDiskInfo) -> None:
        self.info = info
        self.decoded_size = 2048
        self.closed = False

    def close(self) -> None:
        self.closed = True


class BlockingCloseContainer(FakeContainer):
    def __init__(self, info: VirtualDiskInfo) -> None:
        super().__init__(info)
        self.started = threading.Event()
        self.release = threading.Event()

    def close(self) -> None:
        self.started.set()
        self.release.wait(2)
        super().close()


class FakeCompressedPreparer:
    def __init__(self, info: VirtualDiskInfo) -> None:
        self.info = info
        self.calls = []
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True

    def prepare(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.cancelled:
            raise VirtualConversionCancelled("decode cancelled")
        return FakeContainer(self.info)


class WorkspaceMutatingCompressedPreparer(FakeCompressedPreparer):
    def __init__(self, info: VirtualDiskInfo) -> None:
        super().__init__(info)
        self.workspace = None

    def prepare(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        self.workspace = Path(kwargs["temporary_root"])
        (self.workspace / "decoded-stage").mkdir()
        return FakeContainer(self.info)


class BlockingCompressedPreparer(FakeCompressedPreparer):
    def __init__(self, info: VirtualDiskInfo) -> None:
        super().__init__(info)
        self.started = threading.Event()
        self.cancel_event = threading.Event()

    def cancel(self) -> None:
        super().cancel()
        self.cancel_event.set()

    def prepare(self, *args, **kwargs):
        del args, kwargs
        self.started.set()
        self.cancel_event.wait(2)
        raise VirtualConversionCancelled("decode cancelled")


class FakeRunner:
    def __init__(self) -> None:
        self.calls = []
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True

    def run(self, plan, confirmation, prepared, progress):
        self.calls.append((plan, confirmation, prepared))
        if self.cancelled:
            raise RawDeviceRunCancelled("run cancelled")
        progress("writing", "", 4096, 4096)
        return SimpleNamespace(cancellation_deferred=False)


class BlockingRunner(FakeRunner):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.cancel_event = threading.Event()

    def cancel(self) -> None:
        super().cancel()
        self.cancel_event.set()

    def run(self, plan, confirmation, prepared, progress):
        del plan, confirmation, prepared, progress
        self.started.set()
        self.cancel_event.wait(2)
        raise RawDeviceRunCancelled("run cancelled")


class PostCommitFailureRunner(FakeRunner):
    """Model a committed helper that fails after cancellation was requested."""

    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.cancel_event = threading.Event()

    def cancel(self) -> None:
        super().cancel()
        self.cancel_event.set()

    def run(self, plan, confirmation, prepared, progress):
        del plan, confirmation, prepared, progress
        self.started.set()
        self.cancel_event.wait(2)
        raise RawDeviceRunError("post-commit target state is unknown")


class RawWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "selected.img"
        self.source.write_bytes(b"R" * 4096)
        self.calls: list[str] = []
        self.builders: list[FakeSnapshotBuilder] = []
        self.stagers: list[FakeVirtualStager] = []
        self.runners: list[FakeRunner] = []
        self.containers: list[FakeContainer] = []
        self.stream_plans = []
        self.materialized_plans = []
        self.target_plan = SimpleNamespace(
            confirmation_phrase="WRITE RAW /dev/sdz 8:240"
        )
        self.confirmation = SimpleNamespace(plan=self.target_plan)

    def virtual_info(self, path: Path | None = None, image_format: str = "vhdx"):
        selected = path or self.source
        source_status = selected.stat()
        tool = self.root / "qemu-img"
        if not tool.exists():
            tool.write_bytes(b"tool")
            tool.chmod(0o700)
        tool_status = tool.stat()
        return VirtualDiskInfo(
            selected,
            FileIdentity(
                source_status.st_dev,
                source_status.st_ino,
                source_status.st_size,
                source_status.st_mtime_ns,
                source_status.st_ctime_ns,
            ),
            ToolIdentity(
                tool,
                FileIdentity(
                    tool_status.st_dev,
                    tool_status.st_ino,
                    tool_status.st_size,
                    tool_status.st_mtime_ns,
                    tool_status.st_ctime_ns,
                ),
            ),
            image_format,
            4096,
            1024,
            False,
        )

    def dependencies(
        self,
        *,
        source_opener=None,
        builder_factory=None,
        stager_factory=None,
        compressed_factory=None,
        runner_factory=None,
        helper=None,
        observer=None,
        inspect_virtual=None,
        materialized_plan_builder=None,
        target_builder=None,
        confirmer=None,
    ) -> RawWorkflowDependencies:
        def open_source(path, **kwargs):
            self.calls.append("open-source")
            return (source_opener or open_image_source)(path, **kwargs)

        def build_stream(source, workspace, **kwargs):
            self.calls.append("build-stream")
            plan = SimpleNamespace(
                source=source,
                workspace=workspace,
                arguments=kwargs,
            )
            self.stream_plans.append(plan)
            return plan

        def build_materialized(source, workspace, **kwargs):
            self.calls.append("build-materialized")
            if materialized_plan_builder is None:
                plan = SimpleNamespace(
                    source=source,
                    workspace=workspace,
                    arguments=kwargs,
                )
            else:
                plan = materialized_plan_builder(source, workspace, **kwargs)
            self.materialized_plans.append(plan)
            return plan

        def make_builder():
            instance = (
                builder_factory() if builder_factory is not None
                else FakeSnapshotBuilder()
            )
            self.builders.append(instance)
            return instance

        def make_stager():
            instance = (
                stager_factory() if stager_factory is not None
                else FakeVirtualStager()
            )
            self.stagers.append(instance)
            return instance

        def make_runner():
            instance = runner_factory() if runner_factory else FakeRunner()
            self.runners.append(instance)
            return instance

        return RawWorkflowDependencies(
            resolve_helper=(
                helper
                if helper is not None
                else lambda: self.calls.append("helper")
            ),
            observe_target=(
                observer
                if observer is not None
                else lambda *_args, **_kwargs: (
                    self.calls.append("topology")
                    or frozenset({os.makedev(240, 1)})
                )
            ),
            open_source=open_source,
            build_stream_plan=build_stream,
            build_materialized_plan=build_materialized,
            source_evidence=lambda prepared: SimpleNamespace(prepared=prepared),
            build_target_plan=(
                target_builder
                if target_builder is not None
                else lambda *_args, **_kwargs: self.target_plan
            ),
            confirm_target=(
                confirmer
                if confirmer is not None
                else lambda *_args, **_kwargs: self.confirmation
            ),
            inspect_virtual=(
                inspect_virtual
                if inspect_virtual is not None
                else lambda path, **_kwargs: self.virtual_info(path)
            ),
            snapshot_builder_factory=make_builder,
            virtual_stager_factory=make_stager,
            compressed_virtual_factory=(
                compressed_factory
                if compressed_factory is not None
                else lambda: FakeCompressedPreparer(self.virtual_info())
            ),
            runner_factory=make_runner,
        )

    def workflow(
        self,
        image_inspection: ImageInspection | None = None,
        *,
        source: Path | None = None,
        selected_device: Device | None = None,
        dependencies: RawWorkflowDependencies | None = None,
    ) -> RawWriteWorkflow:
        selected = source or self.source
        return RawWriteWorkflow(
            selected,
            image_inspection or inspection(),
            selected_device or device(),
            identity(selected),
            final_verification=True,
            temporary_root=self.root,
            dependencies=dependencies or self.dependencies(),
        )

    def test_plain_prepare_confirm_execute_has_one_owned_lifecycle(self):
        updates = []
        workflow = self.workflow()
        plan = workflow.prepare(lambda *values: updates.append(values))
        self.assertIs(plan, self.target_plan)
        self.assertEqual(workflow.state, RawWorkflowState.PREPARED)
        self.assertEqual(workflow.confirmation_phrase, plan.confirmation_phrase)
        self.assertEqual(self.calls[:3], ["helper", "topology", "open-source"])
        self.assertEqual(
            self.stream_plans[0].arguments["materialization_profile"],
            "plain",
        )
        workspace = Path(self.stream_plans[0].workspace)
        self.assertTrue(workspace.is_dir())

        with self.assertRaisesRegex(RawWorkflowError, "did not match exactly"):
            workflow.confirm("WRITE RAW /dev/sda 8:0")
        self.assertEqual(workflow.state, RawWorkflowState.PREPARED)
        receipt = workflow.confirm(plan.confirmation_phrase)
        self.assertIs(receipt, self.confirmation)
        result = workflow.execute(lambda *values: updates.append(values))
        self.assertIs(result, workflow.result)
        self.assertEqual(workflow.state, RawWorkflowState.COMPLETED)
        self.assertFalse(workspace.exists())
        self.assertTrue(any(update[0] == "snapshot" for update in updates))
        self.assertTrue(any(update[0] == "writing" for update in updates))
        self.assertTrue(self.runners[0].calls)

    def test_all_supported_materialization_profiles_reach_one_snapshot_backend(self):
        cases = (
            ("plain", ".img", b"R" * 4096, {}, None),
            (
                "compressed",
                ".img.gz",
                gzip.compress(b"R" * 4096),
                {"compression": "gzip"},
                None,
            ),
            (
                "vtsi",
                ".img",
                b"V" * 4096,
                {"sparse_format": "VTSI"},
                "vtsi",
            ),
            (
                "virtual",
                ".vhdx",
                b"Q" * 4096,
                {"virtual_format": "VHDX"},
                None,
            ),
            (
                "compressed-virtual",
                ".vhdx.gz",
                gzip.compress(b"Q" * 4096),
                {"compression": "gzip", "virtual_format": "VHDX"},
                None,
            ),
        )
        for profile, suffix, payload, changes, sparse_override in cases:
            with self.subTest(profile=profile):
                self.stream_plans.clear()
                self.materialized_plans.clear()
                selected = self.root / f"selected-{profile}{suffix}"
                selected.write_bytes(payload)

                def opener(path, **kwargs):
                    source = open_image_source(path, **kwargs)
                    if sparse_override:
                        source.sparse_format = sparse_override
                        source.requires_exact_target_size = True
                        source.required_logical_sector_size = 512
                    return source

                virtual_info = self.virtual_info(
                    selected,
                    "vhdx",
                )
                dependencies = self.dependencies(
                    source_opener=opener,
                    inspect_virtual=lambda *_args, **_kwargs: virtual_info,
                    compressed_factory=lambda: FakeCompressedPreparer(virtual_info),
                )
                workflow = self.workflow(
                    inspection(**changes),
                    source=selected,
                    selected_device=(
                        device(size=4096) if profile == "vtsi" else device()
                    ),
                    dependencies=dependencies,
                )
                updates = []
                workflow.prepare(lambda *values: updates.append(values))
                plans = self.materialized_plans if "virtual" in profile else self.stream_plans
                self.assertEqual(plans[0].arguments["materialization_profile"], profile)
                self.assertEqual(
                    plans[0].arguments["target_device_numbers"],
                    frozenset({os.makedev(240, 1)}),
                )
                if profile == "vtsi":
                    self.assertTrue(plans[0].arguments["requires_exact_target_size"])
                    self.assertEqual(
                        plans[0].arguments["required_logical_sector_size"],
                        512,
                    )
                if "virtual" in profile:
                    self.assertTrue(self.stagers[-1].calls)
                    self.assertTrue(
                        any(update[0] == "convert-virtual" for update in updates)
                    )
                if profile == "compressed-virtual":
                    self.assertTrue(
                        any(update[0] == "decode-virtual" for update in updates)
                    )
                workflow.close()
                self.assertEqual(workflow.state, RawWorkflowState.CLOSED)

    def test_helper_profile_constraints_fail_before_host_or_source_work(self):
        cases = (
            (inspection(size=512), device(), "at least 1024"),
            (inspection(size=1025), device(), "divisible by 512"),
            (
                inspection(),
                device(logical_sector_size=4096),
                "512-byte logical sectors",
            ),
        )
        for image_inspection, target, message in cases:
            with self.subTest(message=message):
                self.calls.clear()
                workflow = self.workflow(
                    image_inspection,
                    selected_device=target,
                )
                with self.assertRaisesRegex(RawWorkflowError, message):
                    workflow.prepare()
                self.assertEqual(workflow.state, RawWorkflowState.FAILED)
                self.assertEqual(self.calls, [])

    def test_vtsi_exact_capacity_fails_before_helper_preflight(self):
        def opener(path, **kwargs):
            source = open_image_source(path, **kwargs)
            source.sparse_format = "vtsi"
            source.requires_exact_target_size = True
            source.required_logical_sector_size = 512
            return source

        workflow = self.workflow(
            inspection(sparse_format="VTSI"),
            selected_device=device(size=8192),
            dependencies=self.dependencies(source_opener=opener),
        )
        with self.assertRaisesRegex(RawWorkflowError, "exactly matches"):
            workflow.prepare()
        self.assertEqual(self.calls, [])

    def test_missing_helper_fails_before_topology_source_or_workspace(self):
        before = set(self.root.iterdir())

        def unavailable():
            self.calls.append("helper")
            raise RawDeviceRunError("raw integration is not installed")

        workflow = self.workflow(
            dependencies=self.dependencies(helper=unavailable),
        )
        with self.assertRaisesRegex(RawWorkflowError, "not installed"):
            workflow.prepare()
        self.assertEqual(self.calls, ["helper"])
        self.assertEqual(set(self.root.iterdir()), before)
        self.assertEqual(workflow.state, RawWorkflowState.FAILED)

    def test_target_resident_temporary_root_is_rejected_without_mutation(self):
        before = self.root.stat()
        children = set(self.root.iterdir())

        def target_resident(*_args, **_kwargs):
            self.calls.append("topology")
            return frozenset({before.st_dev})

        workflow = self.workflow(
            dependencies=self.dependencies(observer=target_resident),
        )
        with self.assertRaisesRegex(RawWorkflowError, "resides on the selected target"):
            workflow.prepare()
        after = self.root.stat()
        self.assertEqual(set(self.root.iterdir()), children)
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(after.st_ctime_ns, before.st_ctime_ns)
        self.assertEqual(self.calls, ["helper", "topology"])
        self.assertEqual(workflow.state, RawWorkflowState.FAILED)

    def test_empty_topology_is_rejected_before_workspace_mutation(self):
        before = self.root.stat()
        children = set(self.root.iterdir())

        def empty_topology(*_args, **_kwargs):
            self.calls.append("topology")
            return frozenset()

        workflow = self.workflow(
            dependencies=self.dependencies(observer=empty_topology),
        )
        with self.assertRaisesRegex(RawWorkflowError, "topology evidence"):
            workflow.prepare()
        after = self.root.stat()
        self.assertEqual(set(self.root.iterdir()), children)
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(after.st_ctime_ns, before.st_ctime_ns)
        self.assertEqual(self.calls, ["helper", "topology"])
        self.assertEqual(workflow.state, RawWorkflowState.FAILED)

    def test_cancel_during_stream_snapshot_reaches_builder_and_cleans(self):
        builder = BlockingSnapshotBuilder()
        workflow = self.workflow(
            dependencies=self.dependencies(builder_factory=lambda: builder),
        )
        errors = []

        def run() -> None:
            try:
                workflow.prepare()
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=run)
        worker.start()
        self.assertTrue(builder.started.wait(2))
        workspace = Path(self.stream_plans[0].workspace)
        workflow.cancel()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertTrue(builder.cancelled.is_set())
        self.assertTrue(errors and isinstance(errors[0], RawWorkflowCancelled))
        self.assertEqual(workflow.state, RawWorkflowState.CANCELLED)
        self.assertFalse(workspace.exists())

    def test_cancel_during_compressed_virtual_decode_reaches_preparer(self):
        selected = self.root / "blocking.vhdx.gz"
        selected.write_bytes(gzip.compress(b"Q" * 4096))
        info = self.virtual_info(selected)
        preparer = BlockingCompressedPreparer(info)
        workflow = self.workflow(
            inspection(compression="gzip", virtual_format="VHDX"),
            source=selected,
            dependencies=self.dependencies(
                compressed_factory=lambda: preparer,
            ),
        )
        errors = []
        worker = threading.Thread(
            target=lambda: self._capture(errors, workflow.prepare)
        )
        worker.start()
        self.assertTrue(preparer.started.wait(2))
        workspace = Path(self.materialized_plans[0].workspace)
        workflow.cancel()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertTrue(preparer.cancelled)
        self.assertTrue(errors and isinstance(errors[0], RawWorkflowCancelled))
        self.assertEqual(workflow.state, RawWorkflowState.CANCELLED)
        self.assertFalse(workspace.exists())

    def test_close_during_virtual_conversion_reaches_stager_and_cleans(self):
        selected = self.root / "blocking.vhdx"
        selected.write_bytes(b"Q" * 4096)
        info = self.virtual_info(selected)
        stager = BlockingVirtualStager()
        workflow = self.workflow(
            inspection(virtual_format="VHDX"),
            source=selected,
            dependencies=self.dependencies(
                inspect_virtual=lambda *_args, **_kwargs: info,
                stager_factory=lambda: stager,
            ),
        )
        errors = []
        worker = threading.Thread(
            target=lambda: self._capture(errors, workflow.prepare)
        )
        worker.start()
        self.assertTrue(stager.started.wait(2))
        workspace = Path(self.materialized_plans[0].workspace)
        workflow.close()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertTrue(stager.cancelled)
        self.assertTrue(errors and isinstance(errors[0], RawWorkflowCancelled))
        self.assertEqual(workflow.state, RawWorkflowState.CLOSED)
        self.assertFalse(workspace.exists())

    def test_compressed_virtual_uses_separate_workspace_with_real_snapshot_builder(self):
        selected = self.root / "continuity.vhdx.gz"
        selected.write_bytes(gzip.compress(b"Q" * 4096))
        info = self.virtual_info(selected)
        preparer = WorkspaceMutatingCompressedPreparer(info)
        workflow = self.workflow(
            inspection(compression="gzip", virtual_format="VHDX"),
            source=selected,
            dependencies=self.dependencies(
                builder_factory=RawSnapshotBuilder,
                stager_factory=TruncatingVirtualStager,
                compressed_factory=lambda: preparer,
                materialized_plan_builder=build_materialized_snapshot_plan,
            ),
        )
        workflow.prepare()
        plan = self.materialized_plans[0]
        snapshot_workspace = Path(plan.workspace_path)
        self.assertIsNotNone(preparer.workspace)
        self.assertNotEqual(preparer.workspace, snapshot_workspace)
        self.assertEqual(preparer.workspace.stat().st_dev, snapshot_workspace.stat().st_dev)
        workflow.close()
        self.assertFalse(snapshot_workspace.exists())
        self.assertFalse(preparer.workspace.exists())

    def test_cancel_during_runner_reaches_runner_and_cleans_snapshot(self):
        runner = BlockingRunner()
        workflow = self.workflow(
            dependencies=self.dependencies(runner_factory=lambda: runner),
        )
        workflow.prepare()
        workspace = Path(self.stream_plans[0].workspace)
        workflow.confirm(workflow.confirmation_phrase)
        errors = []
        worker = threading.Thread(
            target=lambda: self._capture(errors, workflow.execute)
        )
        worker.start()
        self.assertTrue(runner.started.wait(2))
        workflow.cancel()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertTrue(runner.cancelled)
        self.assertTrue(errors and isinstance(errors[0], RawWorkflowCancelled))
        self.assertEqual(workflow.state, RawWorkflowState.CANCELLED)
        self.assertFalse(workspace.exists())

    def test_post_commit_failure_is_not_hidden_as_cancellation(self):
        runner = PostCommitFailureRunner()
        workflow = self.workflow(
            dependencies=self.dependencies(runner_factory=lambda: runner),
        )
        workflow.prepare()
        workspace = Path(self.stream_plans[0].workspace)
        workflow.confirm(workflow.confirmation_phrase)
        errors = []
        worker = threading.Thread(
            target=lambda: self._capture(errors, workflow.execute)
        )
        worker.start()
        self.assertTrue(runner.started.wait(2))
        workflow.cancel()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertTrue(errors)
        self.assertIsInstance(errors[0], RawWorkflowError)
        self.assertNotIsInstance(errors[0], RawWorkflowCancelled)
        self.assertIn("target state is unknown", str(errors[0]))
        self.assertEqual(workflow.state, RawWorkflowState.FAILED)
        self.assertFalse(workspace.exists())

    def test_cancel_while_source_resources_close_cannot_publish_prepared(self):
        selected = self.root / "closing.vhdx.gz"
        selected.write_bytes(gzip.compress(b"Q" * 4096))
        info = self.virtual_info(selected)
        container = BlockingCloseContainer(info)
        preparer = FakeCompressedPreparer(info)
        preparer.prepare = lambda *_args, **_kwargs: container
        workflow = self.workflow(
            inspection(compression="gzip", virtual_format="VHDX"),
            source=selected,
            dependencies=self.dependencies(
                compressed_factory=lambda: preparer,
            ),
        )
        errors = []
        worker = threading.Thread(
            target=lambda: self._capture(errors, workflow.prepare)
        )
        worker.start()
        self.assertTrue(container.started.wait(2))
        workspace = Path(self.materialized_plans[0].workspace)
        workflow.cancel()
        container.release.set()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertTrue(errors and isinstance(errors[0], RawWorkflowCancelled))
        self.assertEqual(workflow.state, RawWorkflowState.CANCELLED)
        self.assertIsNone(workflow.plan)
        self.assertFalse(workspace.exists())

    def test_cancel_or_close_while_prepared_discards_every_owned_resource(self):
        for method, expected in (
            ("cancel", RawWorkflowState.CANCELLED),
            ("close", RawWorkflowState.CLOSED),
        ):
            with self.subTest(method=method):
                self.stream_plans.clear()
                workflow = self.workflow()
                workflow.prepare()
                prepared = self.builders[-1].result
                workspace = Path(self.stream_plans[0].workspace)
                getattr(workflow, method)()
                self.assertEqual(workflow.state, expected)
                self.assertFalse(workspace.exists())
                self.assertIsNone(workflow.result)
                self.assertIsNotNone(prepared)
                self.assertTrue(prepared.closed)

    def test_source_identity_drift_is_rejected_and_workspace_is_removed(self):
        workflow = self.workflow()
        self.source.write_bytes(b"S" * 4096)
        with self.assertRaisesRegex(RawWorkflowError, "changed after inspection"):
            workflow.prepare()
        self.assertEqual(workflow.state, RawWorkflowState.FAILED)
        self.assertEqual(len(self.stream_plans), 0)
        self.assertFalse(
            any(path.name.startswith(".isopropyl-raw-") for path in self.root.iterdir())
        )

    def test_target_plan_confirmation_and_runner_failures_clean_and_terminalize(self):
        cases = (
            (
                "plan",
                {"target_builder": lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    RawWorkflowError("plan failed")
                )},
            ),
            (
                "confirm",
                {"confirmer": lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    RawWorkflowError("confirm failed")
                )},
            ),
            (
                "execute",
                {"runner_factory": lambda: SimpleNamespace(
                    cancel=lambda: None,
                    run=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                        RawDeviceRunError("execute failed")
                    ),
                )},
            ),
        )
        for stage, arguments in cases:
            with self.subTest(stage=stage):
                self.stream_plans.clear()
                workflow = self.workflow(
                    dependencies=self.dependencies(**arguments),
                )
                with self.assertRaisesRegex(RawWorkflowError, "failed"):
                    if stage == "plan":
                        workflow.prepare()
                    else:
                        workflow.prepare()
                        if stage == "confirm":
                            workflow.confirm(workflow.confirmation_phrase)
                        else:
                            workflow.confirm(workflow.confirmation_phrase)
                            workflow.execute()
                workspace = Path(self.stream_plans[0].workspace)
                self.assertEqual(workflow.state, RawWorkflowState.FAILED)
                self.assertFalse(workspace.exists())
                self.assertTrue(self.builders[-1].result.closed)

    @staticmethod
    def _capture(errors: list[BaseException], operation) -> None:
        try:
            operation()
        except BaseException as error:
            errors.append(error)


if __name__ == "__main__":
    unittest.main()
