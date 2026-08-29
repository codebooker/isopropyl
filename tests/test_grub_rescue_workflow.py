from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import isopropyl.grub_rescue_device as grub_device
import isopropyl.grub_rescue_workflow as workflow_module
import tests.test_grub_rescue as grub_fixtures
from isopropyl.devices import Device
from isopropyl.grub_rescue import (
    GrubRescueBuilder,
    build_grub_rescue_plan,
)
from isopropyl.grub_rescue_device import (
    build_grub_rescue_device_write_plan,
    confirm_grub_rescue_device_write,
)
from isopropyl.grub_rescue_device_runner import (
    GrubRescueDeviceRunCancelled,
    GrubRescueDeviceRunError,
    GrubRescueDeviceWriteResult,
    HelperInstallation,
)
from isopropyl.private_fat32 import PrivateFat32State
from isopropyl.syslinux_device import SyslinuxDevicePlanError
from isopropyl.syslinux_device_helper import GRUB_RESCUE_HELPER_PROFILE
from isopropyl.grub_rescue_workflow import (
    FREE_SPACE_RESERVE,
    GrubRescueWorkflowDependencies,
    GrubRescueWorkflowError,
    GrubRescueWorkflowState,
    GrubRescueWriteWorkflow,
)


IMAGE_SIZE = grub_fixtures.IMAGE_SIZE


def _device(**changes: object) -> Device:
    values: dict[str, object] = {
        "path": "/dev/sdz",
        "size": IMAGE_SIZE,
        "model": "Workflow rescue drive",
        "vendor": "ISOpropyl",
        "transport": "usb",
        "serial": "WORKFLOW-214",
        "wwn": "",
        "major_minor": "65:144",
        "removable": True,
        "hotplug": True,
        "read_only": False,
        "mountpoints": ("/media/grub",),
        "partitions": ("/dev/sdz1",),
        "logical_sector_size": 512,
    }
    values.update(changes)
    return Device(**values)  # type: ignore[arg-type]


def _block_status() -> SimpleNamespace:
    return SimpleNamespace(
        st_mode=stat.S_IFBLK | 0o600,
        st_rdev=os.makedev(65, 144),
    )


def _helper() -> HelperInstallation:
    return HelperInstallation(
        "/usr/bin/pkexec",
        "/usr/libexec/isopropyl-device-helper",
        "/usr/libexec/isopropyl/syslinux_device_helper.py",
        "/usr/share/polkit-1/actions/grub.policy",
    )


class _Runner:
    def __init__(self) -> None:
        self.committed = False
        self.cancelled = False
        self.before_result = None
        self.failure: BaseException | None = None

    def cancel(self) -> None:
        self.cancelled = True

    def run(self, plan, confirmation, progress):
        if confirmation.plan is not plan:
            raise AssertionError("cross-wired runner fixture")
        progress("source-validation", "", plan.image_size, plan.image_size)
        if isinstance(self.failure, GrubRescueDeviceRunCancelled):
            raise self.failure
        self.committed = True
        if self.before_result is not None:
            self.before_result()
        if self.failure is not None:
            raise self.failure
        result = plan.rescue_result
        return GrubRescueDeviceWriteResult(
            plan_sha256=plan.plan_sha256,
            ready_sha256="a" * 64,
            rescue_plan_sha256=plan.rescue_plan_sha256,
            private_plan_sha256=plan.private_plan_sha256,
            request_id="b" * 32,
            target_path=plan.device.path,
            major_minor=plan.device.major_minor,
            disk_sequence=plan.disk_sequence,
            image_size=plan.image_size,
            image_sha256=plan.final_image_sha256,
            final_fat_manifest_sha256=plan.final_fat_manifest_sha256,
            disk_signature=plan.disk_signature,
            volume_id=plan.volume_id,
            logical_sector_size=plan.logical_sector_size,
            image_profile=result.profile,
            result_semantics=result.result_semantics,
            helper_profile=GRUB_RESCUE_HELPER_PROFILE,
            exclusive_open=True,
            cache_invalidated=True,
            mandatory_readback=True,
            cancellation_deferred=self.cancelled,
        )


class GrubRescueWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = grub_fixtures.GrubRescueTests(
            "test_build_is_deterministic_empty_and_preserves_exact_disk_layout",
        )
        cls.fixture.setUp()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture.doCleanups()

    def setUp(self) -> None:
        self.target = _device()
        self.live = self.target
        self.sequence = 9_214
        self.related = frozenset({_block_status().st_rdev})
        self.events: list[str] = []
        self.bundle_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self.plan_directories: list[tuple[Path, Path]] = []
        self.runner = _Runner()
        self.owned: tempfile.TemporaryDirectory[str] | None = None
        self.workflow: GrubRescueWriteWorkflow | None = None
        patches = (
            patch(
                "isopropyl.grub_rescue_workflow._validate_target_node",
                return_value=_block_status(),
            ),
            patch(
                "isopropyl.grub_rescue_workflow._validate_live_target",
                side_effect=self._validate_live_fixture,
            ),
            patch(
                "isopropyl.grub_rescue_device._validate_target_node",
                return_value=_block_status(),
            ),
            patch(
                "isopropyl.grub_rescue_device._validate_live_target",
                side_effect=self._validate_live_fixture,
            ),
            patch(
                "isopropyl.grub_rescue_device._probe_live_target",
                side_effect=lambda _path: grub_device._LiveTargetObservation(
                    self.live, self.related,
                ),
            ),
            patch(
                "isopropyl.grub_rescue_device._read_disk_sequence",
                side_effect=lambda _identity: self.sequence,
            ),
        )
        for active in patches:
            active.start()
            self.addCleanup(active.stop)

    def tearDown(self) -> None:
        if self.workflow is not None:
            self.workflow.close()
        if self.owned is not None:
            self.owned.cleanup()

    def _validate_live_fixture(
        self,
        device: Device,
        _status: object,
    ) -> grub_device._LiveTargetObservation:
        if device != self.live:
            raise SyslinuxDevicePlanError("The selected target changed")
        return grub_device._LiveTargetObservation(self.live, self.related)

    def _prepare_bundle(self, *args: object, **kwargs: object):
        self.events.append("network")
        self.bundle_calls.append((args, kwargs))
        progress = kwargs.get("progress")
        if callable(progress):
            progress(1, 2)
        return self.fixture.bundle

    def _build_rescue(self, bundle, staging, workspace, **kwargs):
        staging_path = Path(staging)
        workspace_path = Path(workspace)
        self.plan_directories.append((staging_path, workspace_path))
        self.assertEqual(list(staging_path.iterdir()), [])
        self.assertEqual(list(workspace_path.iterdir()), [])
        self.assertEqual(stat.S_IMODE(staging_path.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(workspace_path.stat().st_mode), 0o700)
        return build_grub_rescue_plan(
            bundle,
            staging,
            workspace,
            **kwargs,
        )

    def dependencies(self, **changes: object) -> GrubRescueWorkflowDependencies:
        def resolve():
            self.events.append("helper")
            return _helper()

        values: dict[str, object] = {
            "resolve_helper": resolve,
            "prepare_exact_bundle": self._prepare_bundle,
            "build_rescue_plan": self._build_rescue,
            "builder_factory": GrubRescueBuilder,
            "build_target_plan": build_grub_rescue_device_write_plan,
            "confirm_target": confirm_grub_rescue_device_write,
            "runner_factory": lambda: self.runner,
            "disk_usage": lambda _path: SimpleNamespace(
                free=IMAGE_SIZE + FREE_SPACE_RESERVE + 1,
            ),
        }
        values.update(changes)
        return GrubRescueWorkflowDependencies(**values)  # type: ignore[arg-type]

    def make_workflow(
        self,
        *,
        device: Device | None = None,
        dependencies: GrubRescueWorkflowDependencies | None = None,
    ) -> GrubRescueWriteWorkflow:
        self.owned = tempfile.TemporaryDirectory()
        self.workflow = GrubRescueWriteWorkflow(
            device or self.target,
            self.owned,
            dependencies=dependencies or self.dependencies(),
        )
        return self.workflow

    def prepared_workflow(self) -> GrubRescueWriteWorkflow:
        workflow = self.make_workflow()
        plan = workflow.prepare()
        self.assertIs(plan, workflow.plan)
        return workflow

    def test_complete_authoritative_lifecycle_and_cleanup(self) -> None:
        workflow = self.prepared_workflow()
        plan = workflow.plan
        assert plan is not None
        root = Path(self.owned.name)  # type: ignore[union-attr]
        self.assertEqual(workflow.state, GrubRescueWorkflowState.PREPARED)
        self.assertTrue(root.is_dir())
        confirmation = workflow.confirm(plan.confirmation_phrase)
        self.assertIs(confirmation, workflow.confirmation)
        self.assertEqual(workflow.state, GrubRescueWorkflowState.CONFIRMED)
        result = workflow.execute()
        self.assertIs(result, workflow.result)
        self.assertEqual(workflow.state, GrubRescueWorkflowState.COMPLETED)
        self.assertTrue(workflow.committed)
        self.assertEqual(result.image_sha256, plan.final_image_sha256)
        self.assertEqual(
            result.final_fat_manifest_sha256,
            plan.final_fat_manifest_sha256,
        )
        self.assertFalse(root.exists())

    def test_helper_is_resolved_before_exact_network_request(self) -> None:
        workflow = self.make_workflow()
        workflow.prepare()
        self.assertLess(self.events.index("helper"), self.events.index("network"))
        self.assertEqual(len(self.bundle_calls), 1)
        args, kwargs = self.bundle_calls[0]
        self.assertEqual(args, ("grub", "2.14", "blank-bios-rescue-media"))
        self.assertIs(kwargs["cancel_event"], workflow._cancelled)
        self.assertTrue(callable(kwargs["progress"]))
        self.assertEqual(len(self.plan_directories), 1)

    def test_helper_failure_prevents_network_and_cleans_workspace(self) -> None:
        def unavailable():
            self.events.append("helper")
            raise GrubRescueDeviceRunError("missing helper")

        workflow = self.make_workflow(
            dependencies=self.dependencies(resolve_helper=unavailable),
        )
        root = Path(self.owned.name)  # type: ignore[union-attr]
        with self.assertRaisesRegex(GrubRescueWorkflowError, "missing helper"):
            workflow.prepare()
        self.assertEqual(self.events, ["helper"])
        self.assertEqual(workflow.state, GrubRescueWorkflowState.FAILED)
        self.assertFalse(root.exists())

    def test_free_space_and_non_target_storage_fail_before_network(self) -> None:
        low = self.dependencies(
            disk_usage=lambda _path: SimpleNamespace(
                free=IMAGE_SIZE + FREE_SPACE_RESERVE - 1,
            ),
        )
        workflow = self.make_workflow(dependencies=low)
        with self.assertRaisesRegex(GrubRescueWorkflowError, "64 MiB reserve"):
            workflow.prepare()
        self.assertNotIn("network", self.events)

        self.workflow = None
        self.owned = None
        resident = tempfile.TemporaryDirectory()
        storage_device = os.stat(resident.name).st_dev
        resident.cleanup()
        self.related = frozenset({_block_status().st_rdev, storage_device})
        workflow = self.make_workflow()
        with self.assertRaisesRegex(GrubRescueWorkflowError, "resides"):
            workflow.prepare()
        self.assertNotIn("network", self.events)

    def test_wrong_confirmation_preserves_prepared_owner(self) -> None:
        workflow = self.prepared_workflow()
        root = Path(self.owned.name)  # type: ignore[union-attr]
        with self.assertRaisesRegex(GrubRescueWorkflowError, "did not match"):
            workflow.confirm(workflow.confirmation_phrase.lower())
        self.assertEqual(workflow.state, GrubRescueWorkflowState.PREPARED)
        self.assertTrue(root.exists())
        self.assertIs(
            workflow.plan.prepared.state,  # type: ignore[union-attr]
            workflow_module.PrivateFat32State.PATCHED_ATTESTED,
        )

    def test_cancel_before_commit_closes_image_and_owned_workspace(self) -> None:
        workflow = self.prepared_workflow()
        plan = workflow.plan
        assert plan is not None
        root = Path(self.owned.name)  # type: ignore[union-attr]
        workflow.cancel()
        self.assertEqual(workflow.state, GrubRescueWorkflowState.CANCELLED)
        self.assertFalse(workflow.committed)
        self.assertIs(plan.prepared.state, PrivateFat32State.CLOSED)
        self.assertFalse(root.exists())

    def test_precommit_execution_cancel_is_cancelled_not_unknown(self) -> None:
        workflow = self.prepared_workflow()
        workflow.confirm(workflow.confirmation_phrase)
        self.runner.failure = GrubRescueDeviceRunCancelled("cancelled before commit")
        with self.assertRaises(workflow_module.GrubRescueWorkflowCancelled):
            workflow.execute()
        self.assertEqual(workflow.state, GrubRescueWorkflowState.CANCELLED)
        self.assertFalse(workflow.committed)

    def test_cancel_after_commit_is_deferred_and_success_remains_authoritative(self) -> None:
        workflow = self.prepared_workflow()
        workflow.confirm(workflow.confirmation_phrase)
        self.runner.before_result = workflow.cancel
        result = workflow.execute()
        self.assertTrue(result.cancellation_deferred)
        self.assertTrue(workflow.committed)
        self.assertEqual(workflow.state, GrubRescueWorkflowState.COMPLETED)

    def test_postcommit_failure_preserves_unknown_target_semantics(self) -> None:
        workflow = self.prepared_workflow()
        workflow.confirm(workflow.confirmation_phrase)
        self.runner.failure = GrubRescueDeviceRunError("post-commit transport loss")
        with self.assertRaisesRegex(GrubRescueWorkflowError, "transport loss"):
            workflow.execute()
        self.assertTrue(workflow.committed)
        self.assertEqual(workflow.state, GrubRescueWorkflowState.FAILED)

    def test_forged_target_plan_confirmation_and_runner_result_fail_closed(self) -> None:
        real_build = build_grub_rescue_device_write_plan

        def forged_build(*args, **kwargs):
            return replace(real_build(*args, **kwargs))

        workflow = self.make_workflow(
            dependencies=self.dependencies(build_target_plan=forged_build),
        )
        with self.assertRaises(GrubRescueWorkflowError):
            workflow.prepare()
        self.assertEqual(workflow.state, GrubRescueWorkflowState.FAILED)

        workflow = self.make_workflow()
        workflow.prepare()
        plan = workflow.plan
        assert plan is not None

        def forged_confirm(*args, **kwargs):
            return replace(confirm_grub_rescue_device_write(*args, **kwargs))

        object.__setattr__(
            workflow.dependencies,
            "confirm_target",
            forged_confirm,
        )
        with self.assertRaises(GrubRescueWorkflowError):
            workflow.confirm(plan.confirmation_phrase)

        workflow = self.prepared_workflow()
        workflow.confirm(workflow.confirmation_phrase)
        original_run = self.runner.run

        def forged_run(*args, **kwargs):
            return replace(original_run(*args, **kwargs), image_sha256="0" * 64)

        self.runner.run = forged_run
        with self.assertRaisesRegex(GrubRescueWorkflowError, "does not match"):
            workflow.execute()
        self.assertEqual(workflow.state, GrubRescueWorkflowState.FAILED)

    def test_close_and_state_machine_are_one_shot(self) -> None:
        workflow = self.prepared_workflow()
        with self.assertRaisesRegex(GrubRescueWorkflowError, "only be prepared once"):
            workflow.prepare()
        root = Path(self.owned.name)  # type: ignore[union-attr]
        workflow.close()
        self.assertEqual(workflow.state, GrubRescueWorkflowState.CLOSED)
        self.assertFalse(root.exists())
        with self.assertRaises(GrubRescueWorkflowError):
            workflow.confirm("anything")

    def test_initial_target_constraints_fail_before_workspace_mutation(self) -> None:
        for changes in (
            {"removable": False},
            {"transport": "sata"},
            {"read_only": True},
            {"logical_sector_size": 4096},
            {"mountpoints": ("/",)},
        ):
            owned = tempfile.TemporaryDirectory()
            self.addCleanup(owned.cleanup)
            with self.subTest(changes=changes), self.assertRaises(
                GrubRescueWorkflowError,
            ):
                GrubRescueWriteWorkflow(
                    _device(**changes),
                    owned,
                    dependencies=self.dependencies(),
                )
            self.assertEqual(list(Path(owned.name).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
