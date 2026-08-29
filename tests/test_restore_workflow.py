from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import threading
import unittest
from dataclasses import replace

from isopropyl.devices import Device
from isopropyl.formatting import (
    Filesystem,
    FormatPlan,
    PartitionTable,
    create_format_plan,
)
from isopropyl.restore_device_runner import RestoreDeviceRunResult
from isopropyl.restore_device_helper import (
    Filesystem as HelperFilesystem,
    _filesystem_receipt_digest,
)
from isopropyl.restore_workflow import (
    ConfirmedRestoreWorkflow,
    RestoreTargetObservation,
    RestoreWorkflow,
    RestoreWorkflowCancelled,
    RestoreWorkflowDependencies,
    RestoreWorkflowError,
    RestoreWorkflowPlan,
    RestoreWorkflowState,
    build_restore_workflow_plan,
    confirm_restore_workflow_plan,
    validate_confirmed_restore_workflow,
    validate_restore_workflow_plan,
)


CAPACITY = 128 * 1024 * 1024
DISK_SEQUENCE = 928374
REQUEST_ID = bytes.fromhex("102132435465768798a9bacbdcedfe0f")


class ObservationSource:
    def __init__(self, device: Device) -> None:
        self.device = device
        self.sequence = DISK_SEQUENCE
        self.calls = 0

    def __call__(self, device: Device) -> RestoreTargetObservation:
        self.calls += 1
        if device is not self.device:
            raise RestoreWorkflowError("cross-wired device")
        major, minor = (int(item) for item in device.major_minor.split(":"))
        return RestoreTargetObservation(
            device,
            frozenset({os.makedev(major, minor), os.makedev(major, minor + 1)}),
            self.sequence,
        )


class FakeRunner:
    def __init__(self) -> None:
        self.calls = []
        self.cancelled = False
        self.committed = False
        self.before_commit = None
        self.after_commit = None
        self.mutate_result = None

    def cancel(self) -> None:
        self.cancelled = True

    def run(self, request, *, confirm_commit, progress):
        self.calls.append(request)
        if self.before_commit is not None:
            self.before_commit()
        if confirm_commit() is not True:
            raise AssertionError("workflow did not authorize COMMIT")
        self.committed = True
        if self.after_commit is not None:
            self.after_commit()
        progress("zero-scan", request.expected_capacity, request.expected_capacity)
        progress("zero-readback", request.expected_capacity, request.expected_capacity)
        sectors_per_cluster = (
            request.plan.allocation_unit_size // request.logical_sector_size
            if request.plan.allocation_unit_size is not None
            else 8
        )
        metadata_sha256 = bytes.fromhex("12" * 32)
        receipt_sha256 = _filesystem_receipt_digest(
            request,
            request.plan.filesystem,
            "65:145",
            sectors_per_cluster,
            request.plan.label,
            metadata_sha256,
        )
        result = RestoreDeviceRunResult(
            request.request_id,
            request.expected_major_minor,
            "65:145",
            request.expected_disk_sequence,
            request.expected_capacity,
            request.partition_start_sector,
            request.partition_sector_count,
            request.expected_capacity,
            request.expected_capacity // 2,
            request.expected_capacity // 2,
            request.expected_capacity,
            request.logical_sector_size,
            request.plan.filesystem,
            sectors_per_cluster,
            request.logical_sector_size * sectors_per_cluster,
            request.plan.label,
            metadata_sha256,
            receipt_sha256,
        )
        return self.mutate_result(result) if self.mutate_result else result


class RestoreWorkflowTests(unittest.TestCase):
    def make_device(self, **changes) -> Device:
        values = dict(
            path="/dev/sdz",
            size=CAPACITY,
            model="Test Stick",
            vendor="ISOpropyl",
            transport="usb",
            serial="SERIAL-ONE",
            wwn="",
            major_minor="65:144",
            removable=True,
            hotplug=True,
            read_only=False,
            mountpoints=(),
            partitions=(),
            logical_sector_size=512,
        )
        values.update(changes)
        return Device(**values)

    def make_workflow(self, *, device=None, filesystem=Filesystem.FAT32):
        device = device or self.make_device()
        format_plan = create_format_plan(
            device,
            filesystem,
            PartitionTable.GPT,
            "RESTORE",
            4096 if filesystem is Filesystem.FAT32 else None,
        )
        observation = ObservationSource(device)
        runner = FakeRunner()
        dependencies = RestoreWorkflowDependencies(
            resolve_helper=lambda: object(),
            observe_target=observation,
            request_id_factory=lambda size: REQUEST_ID if size == 16 else b"",
            runner_factory=lambda: runner,
        )
        return (
            RestoreWorkflow(device, format_plan, dependencies=dependencies),
            observation,
            runner,
        )

    def prepare_confirm(self, workflow: RestoreWorkflow):
        plan = workflow.prepare()
        confirmation = workflow.confirm(plan.confirmation_phrase)
        return plan, confirmation

    def test_success_path_uses_only_runner_and_validates_complete_receipt(self) -> None:
        workflow, observation, runner = self.make_workflow()
        self.assertEqual(workflow.state, RestoreWorkflowState.CREATED)
        plan, confirmation = self.prepare_confirm(workflow)
        self.assertEqual(workflow.state, RestoreWorkflowState.CONFIRMED)
        self.assertIs(confirmation.plan, plan)
        progress = []
        result = workflow.execute(lambda *update: progress.append(update))
        self.assertEqual(workflow.state, RestoreWorkflowState.COMPLETED)
        self.assertIs(workflow.result, result)
        self.assertEqual(runner.calls, [plan.request])
        self.assertTrue(runner.committed)
        self.assertEqual(observation.calls, 3)  # prepare, typed consent, COMMIT
        self.assertEqual(
            progress,
            [
                ("zero-scan", CAPACITY, CAPACITY),
                ("zero-readback", CAPACITY, CAPACITY),
            ],
        )
        self.assertEqual(result.plan_sha256, plan.plan_sha256)
        self.assertEqual(result.request_id, REQUEST_ID)
        self.assertEqual(result.written_bytes + result.skipped_bytes, CAPACITY)
        self.assertEqual(result.verified_bytes, CAPACITY)
        self.assertEqual(result.logical_sector_size, 512)
        self.assertEqual(result.filesystem, Filesystem.FAT32.value)
        self.assertEqual(result.cluster_size, 4096)
        self.assertEqual(len(result.metadata_sha256), 32)
        self.assertEqual(len(result.filesystem_receipt_sha256), 32)
        self.assertFalse(result.cancellation_deferred)
        workflow.cancel()
        self.assertFalse(workflow.cancellation_deferred)
        self.assertEqual(workflow.state, RestoreWorkflowState.COMPLETED)

    def test_rejects_fixed_non_usb_unstable_mounted_and_unsupported_formats(self) -> None:
        cases = (
            self.make_device(removable=False),
            self.make_device(transport="sata"),
            self.make_device(serial="", wwn=""),
            self.make_device(mountpoints=("/media/test",)),
            self.make_device(logical_sector_size=0),
        )
        for device in cases:
            with self.subTest(device=device):
                plan = FormatPlan(
                    device.path,
                    device.identity,
                    Filesystem.FAT32,
                    PartitionTable.GPT,
                    "RESTORE",
                )
                with self.assertRaises(RestoreWorkflowError):
                    build_restore_workflow_plan(
                        device,
                        plan,
                        observe_target=ObservationSource(device),
                    )
        exfat_device = self.make_device()
        exfat = create_format_plan(
            exfat_device, Filesystem.EXFAT, PartitionTable.GPT, "RESTORE",
        )
        with self.assertRaisesRegex(RestoreWorkflowError, "FAT32 and NTFS"):
            build_restore_workflow_plan(
                exfat_device,
                exfat,
                observe_target=ObservationSource(exfat_device),
            )

    def test_equal_plan_identity_still_retains_receipt_owned_device(self) -> None:
        device = self.make_device()
        clone = replace(device)
        format_plan = create_format_plan(
            clone, Filesystem.FAT32, PartitionTable.GPT, "RESTORE",
        )
        # FormatPlan carries an identity tuple rather than a Device object, but
        # the new process-local receipt still retains the selected Device.
        observation = ObservationSource(device)
        built = build_restore_workflow_plan(
            device,
            format_plan,
            observe_target=observation,
            request_id_factory=lambda _size: REQUEST_ID,
        )
        self.assertIs(built.device, device)
        self.assertIs(built.format_plan, format_plan)

    def test_stale_disk_generation_is_rejected_at_confirmation_and_commit(self) -> None:
        workflow, observation, _runner = self.make_workflow()
        plan = workflow.prepare()
        observation.sequence += 1
        with self.assertRaisesRegex(RestoreWorkflowError, "changed"):
            workflow.confirm(plan.confirmation_phrase)
        self.assertEqual(workflow.state, RestoreWorkflowState.FAILED)

        workflow, observation, _runner = self.make_workflow()
        plan, _confirmation = self.prepare_confirm(workflow)
        observation.sequence += 1
        with self.assertRaisesRegex(RestoreWorkflowError, "changed"):
            workflow.execute()
        self.assertEqual(workflow.state, RestoreWorkflowState.FAILED)

    def test_plan_and_confirmation_clones_or_cross_wires_are_rejected(self) -> None:
        workflow, _observation, _runner = self.make_workflow()
        plan, confirmation = self.prepare_confirm(workflow)
        plan_clone = replace(plan)
        self.assertIsInstance(plan_clone, RestoreWorkflowPlan)
        with self.assertRaisesRegex(RestoreWorkflowError, "cloned"):
            validate_restore_workflow_plan(plan_clone)
        confirmation_clone = replace(confirmation)
        self.assertIsInstance(confirmation_clone, ConfirmedRestoreWorkflow)
        with self.assertRaisesRegex(RestoreWorkflowError, "cloned"):
            validate_confirmed_restore_workflow(plan, confirmation_clone)

        other, _other_observation, _other_runner = self.make_workflow(
            device=self.make_device(serial="SERIAL-TWO"),
        )
        other_plan = other.prepare()
        with self.assertRaisesRegex(RestoreWorkflowError, "cross-wired"):
            validate_confirmed_restore_workflow(other_plan, confirmation)

    def test_phrase_is_ascii_exact_and_binds_path_size_and_serial_identity(self) -> None:
        workflow, observation, _runner = self.make_workflow()
        plan = workflow.prepare()
        self.assertIn("/dev/sdz", plan.confirmation_phrase)
        self.assertIn(str(CAPACITY), plan.confirmation_phrase)
        self.assertIn("ID-", plan.confirmation_phrase)
        self.assertNotIn("SERIAL-ONE", plan.confirmation_phrase)
        for phrase in (
            plan.confirmation_phrase.lower(),
            plan.confirmation_phrase + " ",
            plan.confirmation_phrase.replace("/dev/sdz", "/dev/sdy"),
            plan.confirmation_phrase.replace(str(CAPACITY), str(CAPACITY + 1)),
        ):
            with self.subTest(phrase=phrase):
                with self.assertRaisesRegex(RestoreWorkflowError, "match exactly"):
                    confirm_restore_workflow_plan(
                        plan, phrase, observe_target=observation,
                    )
        self.assertEqual(workflow.state, RestoreWorkflowState.PREPARED)

    def test_one_shot_state_machine_and_close_are_fail_closed(self) -> None:
        workflow, _observation, _runner = self.make_workflow()
        plan = workflow.prepare()
        self.assertEqual(workflow.state, RestoreWorkflowState.PREPARED)
        with self.assertRaisesRegex(RestoreWorkflowError, "only be prepared once"):
            workflow.prepare()
        with self.assertRaises(RestoreWorkflowError):
            workflow.execute()
        workflow.confirm(plan.confirmation_phrase)
        self.assertEqual(workflow.state, RestoreWorkflowState.CONFIRMED)
        with self.assertRaises(RestoreWorkflowError):
            workflow.confirm(plan.confirmation_phrase)
        workflow.close()
        self.assertEqual(workflow.state, RestoreWorkflowState.CLOSED)
        workflow.close()
        with self.assertRaises(RestoreWorkflowError):
            workflow.execute()

    def test_precommit_cancel_never_commits_and_is_terminal(self) -> None:
        workflow, _observation, runner = self.make_workflow()
        self.prepare_confirm(workflow)
        runner.before_commit = workflow.cancel
        with self.assertRaises(RestoreWorkflowCancelled):
            workflow.execute()
        self.assertFalse(runner.committed)
        self.assertFalse(workflow.committed)
        self.assertTrue(runner.cancelled)
        self.assertEqual(workflow.state, RestoreWorkflowState.CANCELLED)
        self.assertIsNone(workflow.result)

    def test_postcommit_cancel_is_deferred_until_bound_success(self) -> None:
        workflow, _observation, runner = self.make_workflow()
        self.prepare_confirm(workflow)
        runner.after_commit = workflow.cancel
        result = workflow.execute()
        self.assertTrue(runner.committed)
        self.assertTrue(workflow.committed)
        self.assertTrue(runner.cancelled)
        self.assertTrue(result.cancellation_deferred)
        self.assertTrue(workflow.cancellation_deferred)
        self.assertEqual(workflow.state, RestoreWorkflowState.COMPLETED)

    def test_committed_property_requires_exact_runner_boolean(self) -> None:
        workflow, _observation, runner = self.make_workflow()
        self.prepare_confirm(workflow)
        self.assertFalse(workflow.committed)
        runner.committed = "yes"
        workflow._runner = runner
        self.assertFalse(workflow.committed)
        runner.committed = True
        self.assertTrue(workflow.committed)

    def test_close_after_commit_retains_runner_and_publishes_result(self) -> None:
        workflow, _observation, runner = self.make_workflow()
        self.prepare_confirm(workflow)
        runner.after_commit = workflow.close
        result = workflow.execute()
        self.assertTrue(result.cancellation_deferred)
        self.assertIs(workflow.result, result)
        self.assertEqual(workflow.state, RestoreWorkflowState.CLOSED)

    def test_result_binding_rejects_wrong_identity_geometry_and_accounting(self) -> None:
        mutations = (
            lambda result: replace(result, request_id=b"x" * 16),
            lambda result: replace(result, target_major_minor="65:143"),
            lambda result: replace(result, partition_major_minor="partition"),
            lambda result: replace(result, partition_major_minor="65:146"),
            lambda result: replace(result, disk_sequence=DISK_SEQUENCE + 1),
            lambda result: replace(result, capacity=CAPACITY - 512),
            lambda result: replace(result, partition_start_sector=1),
            lambda result: replace(result, verified_bytes=CAPACITY - 512),
            lambda result: replace(result, skipped_bytes=result.skipped_bytes - 1),
            lambda result: replace(result, logical_sector_size=4096),
            lambda result: replace(result, filesystem=HelperFilesystem.NTFS),
            lambda result: replace(result, sectors_per_cluster=16, cluster_size=8192),
            lambda result: replace(result, cluster_size=2048),
            lambda result: replace(result, normalized_label="OTHER"),
            lambda result: replace(result, metadata_sha256=b"x" * 31),
            lambda result: replace(result, filesystem_receipt_sha256=b"x" * 32),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                workflow, _observation, runner = self.make_workflow()
                self.prepare_confirm(workflow)
                runner.mutate_result = mutate
                with self.assertRaises(RestoreWorkflowError):
                    workflow.execute()
                self.assertEqual(workflow.state, RestoreWorkflowState.FAILED)
                self.assertIsNone(workflow.result)

    def test_cancel_during_prepare_cannot_publish_a_plan(self) -> None:
        workflow, observation, _runner = self.make_workflow()
        entered = threading.Event()
        release = threading.Event()

        def blocking_observe(device):
            entered.set()
            release.wait(timeout=5)
            return observation(device)

        dependencies = replace(
            workflow.dependencies,
            observe_target=blocking_observe,
        )
        workflow = RestoreWorkflow(
            workflow.device,
            workflow.format_plan,
            dependencies=dependencies,
        )
        errors = []
        thread = threading.Thread(
            target=lambda: self._capture_error(workflow.prepare, errors),
        )
        thread.start()
        self.assertTrue(entered.wait(timeout=5))
        workflow.cancel()
        release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], RestoreWorkflowCancelled)
        self.assertEqual(workflow.state, RestoreWorkflowState.CANCELLED)
        self.assertIsNone(workflow.plan)

    @staticmethod
    def _capture_error(operation, errors) -> None:
        try:
            operation()
        except BaseException as error:
            errors.append(error)


if __name__ == "__main__":
    unittest.main()
