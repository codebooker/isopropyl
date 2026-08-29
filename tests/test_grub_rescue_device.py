from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import stat
import unittest
from dataclasses import fields, replace
from types import SimpleNamespace
from unittest.mock import patch

import isopropyl.grub_rescue_device as grub_device
import tests.test_grub_rescue as grub_fixtures
from isopropyl.devices import Device
from isopropyl.grub_rescue import GrubRescueBuilder, PreparedGrubRescueImage
from isopropyl.grub_rescue_device import (
    ConfirmedGrubRescueDeviceWrite,
    GrubRescueDevicePlanCancelled,
    GrubRescueDevicePlanError,
    GrubRescueDeviceWritePlan,
    ReadyGrubRescueDeviceWrite,
    authorize_unmounted_grub_rescue_device_write,
    build_grub_rescue_device_write_plan,
    confirm_grub_rescue_device_write,
    validate_confirmed_grub_rescue_device_write,
    validate_grub_rescue_device_write_plan,
    validate_ready_grub_rescue_device_write,
)
from isopropyl.syslinux_device import SyslinuxDevicePlanError


IMAGE_SIZE = grub_fixtures.IMAGE_SIZE


def _device(**changes: object) -> Device:
    values: dict[str, object] = {
        "path": "/dev/sdz",
        "size": IMAGE_SIZE,
        "model": "GRUB rescue test drive",
        "vendor": "ISOpropyl",
        "transport": "usb",
        "serial": "GRUB-214",
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


class GrubRescueDeviceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = grub_fixtures.GrubRescueTests(
            "test_build_is_deterministic_empty_and_preserves_exact_disk_layout",
        )
        cls.fixture.setUp()
        cls.rescue_plan = cls.fixture.plan()
        cls.prepared = GrubRescueBuilder().execute(cls.rescue_plan)
        cls.rescue_result = cls.prepared.result

    @classmethod
    def tearDownClass(cls) -> None:
        cls.prepared.close()
        cls.fixture.doCleanups()

    def setUp(self) -> None:
        self.target = _device()
        self.live = self.target
        self.sequence = 2_140_731
        self.related = frozenset({_block_status().st_rdev})
        patches = (
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
                side_effect=lambda _major_minor: self.sequence,
            ),
        )
        for active in patches:
            active.start()
            self.addCleanup(active.stop)

    def _validate_live_fixture(
        self,
        device: Device,
        _status: object,
    ) -> grub_device._LiveTargetObservation:
        if self.live != device:
            raise SyslinuxDevicePlanError("The selected target changed after discovery")
        return grub_device._LiveTargetObservation(self.live, self.related)

    def plan(self, device: Device | None = None) -> GrubRescueDeviceWritePlan:
        return build_grub_rescue_device_write_plan(
            self.rescue_plan,
            self.rescue_result,
            self.prepared,
            device or self.target,
        )

    def test_plan_confirmation_and_ready_bind_every_authoritative_input(self) -> None:
        plan = self.plan()
        self.assertIs(plan.rescue_plan, self.rescue_plan)
        self.assertIs(plan.rescue_result, self.rescue_result)
        self.assertIs(plan.prepared, self.prepared)
        self.assertIs(plan.device, self.target)
        self.assertEqual(plan.rescue_plan_sha256, self.rescue_plan.plan_sha256)
        self.assertEqual(
            plan.private_plan_sha256,
            self.rescue_plan.private_plan.plan_sha256,
        )
        self.assertEqual(plan.image_size, self.target.size)
        self.assertEqual(plan.final_image_sha256, self.rescue_result.final_image_sha256)
        self.assertEqual(plan.final_mbr_sha256, self.rescue_result.final_mbr_sha256)
        self.assertEqual(
            plan.final_fat_manifest_sha256,
            self.rescue_result.final_fat_manifest_sha256,
        )
        self.assertEqual(plan.disk_signature, self.rescue_result.disk_signature)
        self.assertEqual(plan.volume_id, self.rescue_result.volume_id)
        self.assertEqual(plan.disk_sequence, self.sequence)
        self.assertEqual(plan.logical_sector_size, 512)
        self.assertEqual(plan.image_profile, grub_device.IMAGE_PROFILE)
        self.assertTrue(plan.mandatory_preactivation_readback)
        self.assertTrue(plan.mandatory_final_readback)
        self.assertEqual(
            plan.required_executor_profile,
            grub_device.REQUIRED_EXECUTOR_PROFILE,
        )
        self.assertEqual(plan.warnings, grub_device._warnings(self.target))
        self.assertEqual(
            plan.confirmation_phrase,
            "WRITE GRUB RESCUE /dev/sdz 65:144",
        )
        self.assertRegex(plan.plan_sha256, r"^[0-9a-f]{64}$")
        validate_grub_rescue_device_write_plan(plan)

        confirmation = confirm_grub_rescue_device_write(
            plan, plan.confirmation_phrase,
        )
        self.assertIs(type(confirmation), ConfirmedGrubRescueDeviceWrite)
        self.assertEqual(confirmation.device_identity, self.target.identity)
        self.assertEqual(confirmation.final_image_sha256, plan.final_image_sha256)
        validate_confirmed_grub_rescue_device_write(plan, confirmation)

        self.live = replace(self.target, mountpoints=())
        ready = authorize_unmounted_grub_rescue_device_write(plan, confirmation)
        self.assertIs(type(ready), ReadyGrubRescueDeviceWrite)
        self.assertEqual(ready.disk_sequence, self.sequence)
        self.assertEqual(ready.final_image_sha256, plan.final_image_sha256)
        self.assertEqual(
            grub_device._ready_snapshot(ready),
            (
                ready.plan_sha256,
                ready.final_image_sha256,
                ready.disk_sequence,
                ready.ready_sha256,
                ready.device,
            ),
        )
        validate_ready_grub_rescue_device_write(plan, confirmation, ready)

    def test_confirmation_phrase_is_distinct_exact_and_case_sensitive(self) -> None:
        plan = self.plan()
        for value in (
            plan.confirmation_phrase.lower(),
            plan.confirmation_phrase + " ",
            "WRITE RAW /dev/sdz 65:144",
            "WRITE GRUB RESCUE /dev/sdy 65:144",
            "",
        ):
            with self.subTest(value=value), self.assertRaisesRegex(
                GrubRescueDevicePlanError, "did not match",
            ):
                confirm_grub_rescue_device_write(plan, value)

    def test_clones_subclasses_and_modified_plan_fields_have_no_authority(self) -> None:
        plan = self.plan()
        values = {
            item.name: getattr(plan, item.name)
            for item in fields(plan)
            if item.init
        }

        class DerivedPlan(GrubRescueDeviceWritePlan):
            pass

        for forged in (
            replace(plan),
            replace(plan, mandatory_final_readback=False),
            replace(plan, required_executor_profile="generic"),
            GrubRescueDeviceWritePlan(**values),
            DerivedPlan(**values),
        ):
            with self.subTest(forged=type(forged)), self.assertRaises(
                GrubRescueDevicePlanError,
            ):
                validate_grub_rescue_device_write_plan(forged)

    def test_forged_result_and_cross_wired_prepared_owner_are_rejected(self) -> None:
        forged_result = replace(self.rescue_result)
        with self.assertRaisesRegex(GrubRescueDevicePlanError, "prepared owner"):
            build_grub_rescue_device_write_plan(
                self.rescue_plan,
                forged_result,
                self.prepared,
                self.target,
            )
        forged_plan = replace(self.rescue_plan)
        with self.assertRaises(GrubRescueDevicePlanError):
            build_grub_rescue_device_write_plan(
                forged_plan,
                self.rescue_result,
                self.prepared,
                self.target,
            )
        forged_prepared = object.__new__(PreparedGrubRescueImage)
        forged_prepared._image = None
        forged_prepared._plan = self.rescue_plan
        forged_prepared._result = self.rescue_result
        forged_prepared._witness = object()
        with self.assertRaisesRegex(GrubRescueDevicePlanError, "owner receipt"):
            build_grub_rescue_device_write_plan(
                self.rescue_plan,
                self.rescue_result,
                forged_prepared,
                self.target,
            )

        closed = GrubRescueBuilder().execute(self.rescue_plan)
        closed_result = closed.result
        closed.close()
        with self.assertRaisesRegex(GrubRescueDevicePlanError, "prepared owner"):
            build_grub_rescue_device_write_plan(
                self.rescue_plan,
                closed_result,
                closed,
                self.target,
            )

    def test_confirmations_and_ready_receipts_cannot_be_cloned_or_cross_wired(self) -> None:
        first = self.plan()
        second = self.plan()
        confirmation = confirm_grub_rescue_device_write(
            first, first.confirmation_phrase,
        )
        confirmation_values = {
            item.name: getattr(confirmation, item.name)
            for item in fields(confirmation)
            if item.init
        }

        class DerivedConfirmation(ConfirmedGrubRescueDeviceWrite):
            pass

        for forged_confirmation in (
            replace(confirmation),
            ConfirmedGrubRescueDeviceWrite(**confirmation_values),
            DerivedConfirmation(**confirmation_values),
        ):
            with self.assertRaises(GrubRescueDevicePlanError):
                validate_confirmed_grub_rescue_device_write(
                    first, forged_confirmation,
                )
        with self.assertRaisesRegex(GrubRescueDevicePlanError, "cross-wired"):
            validate_confirmed_grub_rescue_device_write(second, confirmation)

        second_confirmation = confirm_grub_rescue_device_write(
            second, second.confirmation_phrase,
        )
        self.live = replace(self.target, mountpoints=())
        ready = authorize_unmounted_grub_rescue_device_write(first, confirmation)
        ready_values = {
            item.name: getattr(ready, item.name)
            for item in fields(ready)
            if item.init
        }

        class DerivedReady(ReadyGrubRescueDeviceWrite):
            pass

        for forged_ready in (
            replace(ready),
            ReadyGrubRescueDeviceWrite(**ready_values),
            DerivedReady(**ready_values),
        ):
            with self.assertRaises(GrubRescueDevicePlanError):
                validate_ready_grub_rescue_device_write(
                    first, confirmation, forged_ready,
                )
        with self.assertRaises(GrubRescueDevicePlanError):
            validate_ready_grub_rescue_device_write(
                second, second_confirmation, ready,
            )

    def test_only_kernel_removable_usb_or_mmc_is_accepted(self) -> None:
        mmc = _device(transport="mmc", hotplug=False)
        self.live = mmc
        accepted = self.plan(mmc)
        validate_grub_rescue_device_write_plan(accepted)
        for changes in (
            {"removable": False, "hotplug": True},
            {"transport": "sata"},
            {"read_only": True},
            {"mountpoints": ("/",)},
        ):
            candidate = _device(**changes)
            self.live = candidate
            with self.subTest(changes=changes), self.assertRaises(
                GrubRescueDevicePlanError,
            ):
                self.plan(candidate)

    def test_exact_capacity_sector_geometry_and_128_gib_limit_are_mandatory(self) -> None:
        for candidate in (
            _device(size=IMAGE_SIZE + 512),
            _device(logical_sector_size=4096),
        ):
            self.live = candidate
            with self.subTest(candidate=candidate), self.assertRaises(
                GrubRescueDevicePlanError,
            ):
                self.plan(candidate)
        self.live = self.target
        with patch.object(grub_device, "MAX_TARGET_BYTES", IMAGE_SIZE - 512):
            with self.assertRaisesRegex(GrubRescueDevicePlanError, "128 GiB"):
                self.plan()

    def test_source_and_workspace_on_target_topology_are_rejected(self) -> None:
        private = self.rescue_plan.private_plan
        for resident in (
            private.directories[0].source.device,
            private.workspace_identity.device,
        ):
            self.related = frozenset({_block_status().st_rdev, resident})
            with self.subTest(resident=resident), self.assertRaisesRegex(
                GrubRescueDevicePlanError, "resides on the target",
            ):
                self.plan()

    def test_stale_live_identity_topology_and_disk_generation_fail_closed(self) -> None:
        self.live = replace(self.target, model="replacement")
        with self.assertRaisesRegex(GrubRescueDevicePlanError, "changed"):
            self.plan()
        self.live = self.target
        self.related = frozenset({os.makedev(65, 145)})
        with self.assertRaisesRegex(GrubRescueDevicePlanError, "topology"):
            self.plan()
        self.related = frozenset({_block_status().st_rdev})
        plan = self.plan()
        self.sequence += 1
        with self.assertRaisesRegex(GrubRescueDevicePlanError, "generation"):
            validate_grub_rescue_device_write_plan(plan)

    def test_post_unmount_authorization_rejects_mounts_and_identity_changes(self) -> None:
        plan = self.plan()
        confirmation = confirm_grub_rescue_device_write(
            plan, plan.confirmation_phrase,
        )
        with self.assertRaisesRegex(GrubRescueDevicePlanError, "remains mounted"):
            authorize_unmounted_grub_rescue_device_write(plan, confirmation)
        self.live = replace(self.target, mountpoints=(), serial="replacement")
        with self.assertRaisesRegex(GrubRescueDevicePlanError, "changed"):
            authorize_unmounted_grub_rescue_device_write(plan, confirmation)

    def test_cancellation_prevents_each_receipt_from_being_minted(self) -> None:
        def cancelled() -> None:
            raise GrubRescueDevicePlanCancelled("cancelled fixture")

        with self.assertRaises(GrubRescueDevicePlanCancelled):
            build_grub_rescue_device_write_plan(
                self.rescue_plan,
                self.rescue_result,
                self.prepared,
                self.target,
                cancel_check=cancelled,
            )
        plan = self.plan()
        with self.assertRaises(GrubRescueDevicePlanCancelled):
            confirm_grub_rescue_device_write(
                plan, plan.confirmation_phrase, cancel_check=cancelled,
            )
        confirmation = confirm_grub_rescue_device_write(
            plan, plan.confirmation_phrase,
        )
        self.live = replace(self.target, mountpoints=())
        with self.assertRaises(GrubRescueDevicePlanCancelled):
            authorize_unmounted_grub_rescue_device_write(
                plan, confirmation, cancel_check=cancelled,
            )


if __name__ == "__main__":
    unittest.main()
