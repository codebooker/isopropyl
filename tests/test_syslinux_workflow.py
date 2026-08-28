from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from isopropyl.devices import Device
from isopropyl.iso import (
    BootStrategy,
    FileSystem,
    FirmwareTarget,
    PartitionTable,
    TargetLayout,
    Transformation,
    WriteMode,
    WritePlan,
)
from isopropyl.iso_staging import (
    IsoStagingCancelled,
    IsoStagingPlan,
    IsoStagingProgress,
    IsoStagingResult,
)
from isopropyl.syslinux_device import (
    ConfirmedSyslinuxDeviceWrite,
    SyslinuxDeviceWritePlan,
)
from isopropyl.syslinux_device_runner import (
    SyslinuxDeviceRunError,
    SyslinuxDeviceWriteResult,
)
from isopropyl.syslinux_iso_fat32 import SyslinuxIsoFat32Plan
from isopropyl.syslinux_transaction import MAX_SYSLINUX_REGULAR_IMAGE_BYTES
from isopropyl.syslinux_workflow import (
    SyslinuxWorkflowCancelled,
    SyslinuxWorkflowDependencies,
    SyslinuxWorkflowError,
    SyslinuxWorkflowInputs,
    SyslinuxWorkflowState,
    SyslinuxWriteWorkflow,
)


IMAGE_SIZE = 64 * 1024 * 1024


class FakeStager:
    def __init__(self, result: IsoStagingResult) -> None:
        self.result = result
        self.calls: list[IsoStagingPlan] = []
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True

    def execute(self, plan, progress):
        self.calls.append(plan)
        progress(IsoStagingProgress("Extracting", "README.txt", 5, 5))
        if self.cancelled:
            raise IsoStagingCancelled("cancelled")
        return self.result


class FakeRunner:
    def __init__(self, result: SyslinuxDeviceWriteResult) -> None:
        self.result = result
        self.calls = []
        self.cancelled = False
        self.committed = False

    def cancel(self) -> None:
        self.cancelled = True

    def run(self, plan, confirmation, progress):
        self.calls.append((plan, confirmation))
        self.committed = True
        progress("writing", plan.device.path, plan.image_size, plan.image_size)
        if self.cancelled:
            raise SyslinuxDeviceRunError("cancelled")
        return self.result


class BlockingStager(FakeStager):
    def __init__(self, result: IsoStagingResult) -> None:
        super().__init__(result)
        self.started = threading.Event()
        self.released = threading.Event()

    def cancel(self) -> None:
        super().cancel()
        self.released.set()

    def execute(self, plan, progress):
        self.calls.append(plan)
        self.started.set()
        self.released.wait(timeout=5)
        if self.cancelled:
            raise IsoStagingCancelled("staging cancelled")
        return self.result


class SyslinuxWorkflowTests(unittest.TestCase):
    def make_fixture(self):
        workspace = tempfile.TemporaryDirectory(prefix="isopropyl-workflow-test-")
        self.addCleanup(workspace.cleanup)
        root = Path(workspace.name)
        image = root / "source.iso"
        image.write_bytes(b"ISO")
        info = image.stat()
        image_identity = (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
        parent = root.stat()
        layout = TargetLayout(
            partition_table=PartitionTable.GPT,
            main_filesystem=FileSystem.FAT32,
            partition_count=1,
            boot_partition_filesystem=None,
            bios_bootable=False,
            uefi_bootable=True,
            boot_strategy=BootStrategy.IMAGE_NATIVE,
        )
        selected = WritePlan(
            mode=WriteMode.EXTRACTED_ISO,
            firmware_target=FirmwareTarget.UEFI_ONLY,
            layout=layout,
            requirements=(),
            transformations=(),
            warnings=(),
            minimum_content_bytes=0,
            minimum_target_bytes=1,
            content_constraints_checked=True,
            blockers=(),
        )
        staging = IsoStagingPlan(
            image=image,
            image_identity=image_identity,
            destination=root / "ready-media",
            destination_parent_identity=(parent.st_dev, parent.st_ino),
            entries=(),
            catalog_digest="a" * 64,
            write_plan=selected,
            seven_zip="/usr/bin/7z",
            content_bytes=0,
            required_free_bytes=0,
            wim_source=None,
            wim_selection=None,
            wimlib_imagex=None,
            autounattend_xml=None,
            syslinux_analysis=object(),
            syslinux_c32_bundle=object(),
            syslinux_payload_bundle=object(),
            syslinux_staging=object(),
            staged_catalog_digest="b" * 64,
        )
        device = Device(
            "/dev/sdz",
            IMAGE_SIZE,
            "Test Stick",
            "ISOpropyl",
            "usb",
            "SERIAL",
            "WWN",
            "65:144",
            True,
            True,
            False,
            (),
            (),
            512,
        )
        staged = IsoStagingResult(
            staging.destination,
            staging.image_identity,
            staging.staged_catalog_digest,
            1,
            2,
            5,
            (),
            False,
        )
        private_plan = SimpleNamespace(
            geometry=SimpleNamespace(image_size=IMAGE_SIZE),
            plan_sha256="c" * 64,
        )
        composite = SyslinuxIsoFat32Plan(
            staging,
            staged,
            private_plan,
            "d" * 64,
            "e" * 64,
            "f" * 64,
            "6.03-2014-10-06",
            "syslinux:6.03-2014-10-06",
            "/isolinux",
            32,
            "1" * 64,
            "2" * 64,
        )
        target = SyslinuxDeviceWritePlan(
            composite,
            device,
            123,
            composite.plan_sha256,
            private_plan.plan_sha256,
            composite.source_manifest_sha256,
            IMAGE_SIZE,
            0x12345678,
            0x87654321,
            512,
            "bios-and-uefi",
            True,
            "io.github.codebooker.isopropyl/syslinux-device-helper/v1",
            ("warning",),
            "WRITE DUAL /dev/sdz 65:144",
            "3" * 64,
        )
        confirmation = ConfirmedSyslinuxDeviceWrite(
            target,
            target.plan_sha256,
            device.identity,
            512,
            target.confirmation_phrase,
        )
        result = SyslinuxDeviceWriteResult(
            target.plan_sha256,
            "4" * 64,
            "00" * 16,
            device.path,
            device.major_minor,
            target.disk_sequence,
            IMAGE_SIZE,
            "5" * 64,
            target.disk_signature,
            target.volume_id,
            512,
            target.required_executor_profile,
            True,
            True,
            True,
            False,
        )
        inputs = SyslinuxWorkflowInputs(selected, staging, device, workspace)
        return SimpleNamespace(
            root=root,
            workspace=workspace,
            selected=selected,
            staging=staging,
            device=device,
            staged=staged,
            composite=composite,
            target=target,
            confirmation=confirmation,
            result=result,
            inputs=inputs,
        )

    @staticmethod
    def dependencies(fixture, *, stager=None, runner=None, resolve_helper=None):
        stager = stager or FakeStager(fixture.staged)
        runner = runner or FakeRunner(fixture.result)
        calls = []

        def build_composite(plan, result, workspace, **kwargs):
            calls.append(("composite", plan, result, workspace, kwargs))
            kwargs["cancel_check"]()
            return fixture.composite

        def build_target(composite, device, **kwargs):
            calls.append(("target", composite, device, kwargs))
            kwargs["cancel_check"]()
            return fixture.target

        def confirm_target(plan, phrase, **kwargs):
            calls.append(("confirm", plan, phrase, kwargs))
            kwargs["cancel_check"]()
            return fixture.confirmation

        helper = resolve_helper or (lambda: calls.append(("helper",)))
        dependencies = SyslinuxWorkflowDependencies(
            resolve_helper=helper,
            staging_executor_factory=lambda: stager,
            build_composite_plan=build_composite,
            build_target_plan=build_target,
            confirm_target=confirm_target,
            runner_factory=lambda: runner,
        )
        return dependencies, stager, runner, calls

    def test_exact_one_shot_state_machine_reaches_verified_result(self):
        fixture = self.make_fixture()
        dependencies, stager, runner, calls = self.dependencies(fixture)
        progress = []
        workflow = SyslinuxWriteWorkflow(
            fixture.inputs,
            dependencies=dependencies,
        )
        self.assertEqual(workflow.state, SyslinuxWorkflowState.CREATED)
        plan = workflow.prepare(lambda *update: progress.append(update))
        self.assertIs(plan, fixture.target)
        self.assertIs(workflow.plan, fixture.target)
        self.assertEqual(workflow.confirmation_phrase, plan.confirmation_phrase)
        self.assertEqual(workflow.state, SyslinuxWorkflowState.PREPARED)
        self.assertEqual(stager.calls, [fixture.staging])
        self.assertEqual(calls[0], ("helper",))
        self.assertIs(calls[1][1], fixture.staging)
        self.assertIs(calls[1][2], fixture.staged)
        self.assertEqual(calls[1][3], fixture.root)
        self.assertEqual(calls[1][4]["image_size"], IMAGE_SIZE)
        self.assertIs(calls[2][1], fixture.composite)
        self.assertIs(calls[2][2], fixture.device)

        confirmation = workflow.confirm(plan.confirmation_phrase)
        self.assertIs(confirmation, fixture.confirmation)
        self.assertIs(workflow.confirmation, fixture.confirmation)
        self.assertEqual(workflow.state, SyslinuxWorkflowState.CONFIRMED)

        result = workflow.execute(lambda *update: progress.append(update))
        self.assertIs(result, fixture.result)
        self.assertIs(workflow.result, fixture.result)
        self.assertTrue(workflow.committed)
        self.assertEqual(workflow.state, SyslinuxWorkflowState.COMPLETED)
        self.assertEqual(runner.calls, [(fixture.target, fixture.confirmation)])
        self.assertFalse(fixture.root.exists())
        self.assertIn(("Extracting", 5, 5), progress)
        self.assertIn(("Binding the private dual-firmware image", 5, 5), progress)
        self.assertIn(("writing", IMAGE_SIZE, IMAGE_SIZE), progress)
        with self.assertRaisesRegex(SyslinuxWorkflowError, "only be prepared once"):
            workflow.prepare()

    def test_wrong_phrase_is_exact_and_retryable(self):
        fixture = self.make_fixture()
        dependencies, _stager, _runner, calls = self.dependencies(fixture)
        workflow = SyslinuxWriteWorkflow(fixture.inputs, dependencies=dependencies)
        plan = workflow.prepare()
        for wrong in (
            plan.confirmation_phrase.lower(),
            plan.confirmation_phrase + " ",
            "",
        ):
            with self.assertRaisesRegex(SyslinuxWorkflowError, "match exactly"):
                workflow.confirm(wrong)
            self.assertEqual(workflow.state, SyslinuxWorkflowState.PREPARED)
        self.assertFalse(any(call[0] == "confirm" for call in calls))
        self.assertIs(workflow.confirm(plan.confirmation_phrase), fixture.confirmation)

    def test_selected_write_plan_must_be_the_identical_plan_object(self):
        fixture = self.make_fixture()
        cloned = replace(fixture.selected)
        inputs = replace(fixture.inputs, write_plan=cloned)
        with self.assertRaisesRegex(SyslinuxWorkflowError, "exact selected"):
            SyslinuxWriteWorkflow(inputs)

    def test_generic_planner_blockers_and_other_transforms_stay_rejected(self):
        # Build each variant from a fresh owned workspace because rejection
        # does not transfer ownership or clean the caller's input.
        for mutation in ("blocker", "transformation", "firmware"):
            fixture = self.make_fixture()
            selected = fixture.selected
            if mutation == "blocker":
                selected = replace(selected, blockers=("unsupported",))
            elif mutation == "transformation":
                selected = replace(
                    selected,
                    transformations=(Transformation.SPLIT_WINDOWS_WIM,),
                )
            else:
                selected = replace(selected, firmware_target=FirmwareTarget.BOTH)
            staging = replace(fixture.staging, write_plan=selected)
            inputs = replace(
                fixture.inputs,
                write_plan=selected,
                staging_plan=staging,
            )
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                SyslinuxWorkflowError,
                "single-partition",
            ):
                SyslinuxWriteWorkflow(inputs)

    def test_pending_transform_profiles_are_explicitly_rejected(self):
        fixture = self.make_fixture()
        with self.assertRaisesRegex(SyslinuxWorkflowError, "other ISO transformations"):
            SyslinuxWriteWorkflow(
                replace(fixture.inputs, persistence_profile=object())
            )
        fixture = self.make_fixture()
        with self.assertRaisesRegex(SyslinuxWorkflowError, "other ISO transformations"):
            SyslinuxWriteWorkflow(
                replace(fixture.inputs, runtime_validation=object())
            )

    def test_fixed_4kn_and_oversized_targets_are_rejected_before_helper_use(self):
        for changes in (
            {"removable": False},
            {"logical_sector_size": 4096},
            {"size": MAX_SYSLINUX_REGULAR_IMAGE_BYTES + 512},
            {"read_only": True},
            {"transport": "nvme"},
        ):
            fixture = self.make_fixture()
            device = replace(fixture.device, **changes)
            inputs = replace(fixture.inputs, device=device)
            with self.subTest(changes=changes), self.assertRaises(
                SyslinuxWorkflowError,
            ):
                SyslinuxWriteWorkflow(inputs)

    def test_unavailable_helper_fails_before_staging_and_cleans_workspace(self):
        fixture = self.make_fixture()
        stager = FakeStager(fixture.staged)

        def unavailable():
            raise SyslinuxDeviceRunError("installed helper unavailable")

        dependencies, _stager, _runner, _calls = self.dependencies(
            fixture,
            stager=stager,
            resolve_helper=unavailable,
        )
        workflow = SyslinuxWriteWorkflow(fixture.inputs, dependencies=dependencies)
        with self.assertRaisesRegex(SyslinuxWorkflowError, "helper unavailable"):
            workflow.prepare()
        self.assertEqual(stager.calls, [])
        self.assertEqual(workflow.state, SyslinuxWorkflowState.FAILED)
        self.assertFalse(fixture.root.exists())
        self.assertIsNone(workflow.plan)

    def test_peak_workspace_capacity_is_checked_before_helper_or_staging(self):
        fixture = self.make_fixture()
        dependencies, stager, _runner, calls = self.dependencies(fixture)
        required = fixture.staging.required_free_bytes + fixture.device.size
        dependencies = replace(
            dependencies,
            disk_usage=lambda _path: SimpleNamespace(free=required - 1),
        )
        workflow = SyslinuxWriteWorkflow(fixture.inputs, dependencies=dependencies)
        with self.assertRaisesRegex(
            SyslinuxWorkflowError, "fully allocated target-sized image",
        ):
            workflow.prepare()
        self.assertEqual(calls, [])
        self.assertEqual(stager.calls, [])
        self.assertEqual(workflow.state, SyslinuxWorkflowState.FAILED)
        self.assertFalse(fixture.root.exists())

    def test_cancel_interrupts_active_staging_and_clears_authorization(self):
        fixture = self.make_fixture()
        stager = BlockingStager(fixture.staged)
        dependencies, _stager, _runner, _calls = self.dependencies(
            fixture,
            stager=stager,
        )
        workflow = SyslinuxWriteWorkflow(fixture.inputs, dependencies=dependencies)
        errors = []

        def prepare():
            try:
                workflow.prepare()
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=prepare)
        thread.start()
        self.assertTrue(stager.started.wait(timeout=5))
        workflow.cancel()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertTrue(stager.cancelled)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], SyslinuxWorkflowCancelled)
        self.assertEqual(workflow.state, SyslinuxWorkflowState.CANCELLED)
        self.assertIsNone(workflow.plan)
        self.assertFalse(fixture.root.exists())

    def test_cancel_after_prepare_clears_plan_and_workspace_without_runner(self):
        fixture = self.make_fixture()
        dependencies, _stager, runner, _calls = self.dependencies(fixture)
        workflow = SyslinuxWriteWorkflow(fixture.inputs, dependencies=dependencies)
        workflow.prepare()
        workflow.cancel()
        self.assertEqual(workflow.state, SyslinuxWorkflowState.CANCELLED)
        self.assertIsNone(workflow.plan)
        self.assertIsNone(workflow.confirmation)
        self.assertFalse(runner.calls)
        self.assertFalse(fixture.root.exists())

    def test_cross_wired_composite_is_rejected_and_cleaned(self):
        fixture = self.make_fixture()
        wrong_staged = replace(fixture.staged, bytes_staged=6)
        wrong_composite = replace(
            fixture.composite,
            staging_result=wrong_staged,
        )
        stager = FakeStager(fixture.staged)
        dependencies = SyslinuxWorkflowDependencies(
            resolve_helper=lambda: None,
            staging_executor_factory=lambda: stager,
            build_composite_plan=lambda *_args, **_kwargs: wrong_composite,
            build_target_plan=lambda *_args, **_kwargs: fixture.target,
            confirm_target=lambda *_args, **_kwargs: fixture.confirmation,
            runner_factory=lambda: FakeRunner(fixture.result),
        )
        workflow = SyslinuxWriteWorkflow(fixture.inputs, dependencies=dependencies)
        with self.assertRaisesRegex(SyslinuxWorkflowError, "exact staging result"):
            workflow.prepare()
        self.assertEqual(workflow.state, SyslinuxWorkflowState.FAILED)
        self.assertFalse(fixture.root.exists())

    def test_forged_runner_result_never_completes(self):
        fixture = self.make_fixture()
        forged = replace(fixture.result, target_path="/dev/sdy")
        runner = FakeRunner(forged)
        dependencies, _stager, _runner, _calls = self.dependencies(
            fixture,
            runner=runner,
        )
        workflow = SyslinuxWriteWorkflow(fixture.inputs, dependencies=dependencies)
        plan = workflow.prepare()
        workflow.confirm(plan.confirmation_phrase)
        with self.assertRaisesRegex(SyslinuxWorkflowError, "another transaction"):
            workflow.execute()
        self.assertEqual(workflow.state, SyslinuxWorkflowState.FAILED)
        self.assertIsNone(workflow.plan)
        self.assertIsNone(workflow.result)
        self.assertFalse(fixture.root.exists())

    def test_runner_construction_failure_consumes_authorization_and_workspace(self):
        for mode in ("raises", "invalid"):
            fixture = self.make_fixture()
            dependencies, _stager, _runner, _calls = self.dependencies(fixture)

            def raise_factory():
                raise OSError("runner construction failed")

            factory = raise_factory if mode == "raises" else lambda: object()
            workflow = SyslinuxWriteWorkflow(
                fixture.inputs,
                dependencies=replace(dependencies, runner_factory=factory),
            )
            plan = workflow.prepare()
            workflow.confirm(plan.confirmation_phrase)
            with self.subTest(mode=mode), self.assertRaises(SyslinuxWorkflowError):
                workflow.execute()
            self.assertEqual(workflow.state, SyslinuxWorkflowState.FAILED)
            self.assertIsNone(workflow.plan)
            self.assertIsNone(workflow.confirmation)
            self.assertFalse(fixture.root.exists())
            with self.assertRaisesRegex(
                SyslinuxWorkflowError, "requires exact confirmation",
            ):
                workflow.execute()

    def test_runner_receipt_hex_and_boolean_fields_are_strict(self):
        mutations = (
            {"ready_sha256": "g" * 64},
            {"request_id": "0" * 31},
            {"cancellation_deferred": 1},
        )
        for changes in mutations:
            fixture = self.make_fixture()
            runner = FakeRunner(replace(fixture.result, **changes))
            dependencies, _stager, _runner, _calls = self.dependencies(
                fixture,
                runner=runner,
            )
            workflow = SyslinuxWriteWorkflow(
                fixture.inputs,
                dependencies=dependencies,
            )
            plan = workflow.prepare()
            workflow.confirm(plan.confirmation_phrase)
            with self.subTest(changes=changes), self.assertRaisesRegex(
                SyslinuxWorkflowError, "another transaction",
            ):
                workflow.execute()
            self.assertTrue(workflow.committed)
            self.assertEqual(workflow.state, SyslinuxWorkflowState.FAILED)
            self.assertIsNone(workflow.plan)
            self.assertIsNone(workflow.result)
            self.assertFalse(fixture.root.exists())

    def test_close_is_idempotent_and_cleans_created_workflow(self):
        fixture = self.make_fixture()
        dependencies, _stager, _runner, _calls = self.dependencies(fixture)
        workflow = SyslinuxWriteWorkflow(fixture.inputs, dependencies=dependencies)
        workflow.close()
        workflow.close()
        self.assertEqual(workflow.state, SyslinuxWorkflowState.CLOSED)
        self.assertFalse(fixture.root.exists())
        with self.assertRaisesRegex(SyslinuxWorkflowError, "only be prepared once"):
            workflow.prepare()


if __name__ == "__main__":
    unittest.main()
