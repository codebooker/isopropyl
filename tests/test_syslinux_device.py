from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import os
import stat
import subprocess
import unittest
from dataclasses import fields, replace
from types import SimpleNamespace
from unittest.mock import patch

import tests.test_syslinux_iso_fat32 as composite_fixtures
import isopropyl.syslinux_device as syslinux_device
from isopropyl.devices import Device
from isopropyl.syslinux_device import (
    ConfirmedSyslinuxDeviceWrite,
    ReadySyslinuxDeviceWrite,
    REQUIRED_EXECUTOR_PROFILE,
    SyslinuxDevicePlanCancelled,
    SyslinuxDevicePlanError,
    SyslinuxDeviceWritePlan,
    authorize_unmounted_syslinux_device_write,
    build_syslinux_device_write_plan,
    confirm_syslinux_device_write,
    validate_confirmed_syslinux_device_write,
    validate_ready_syslinux_device_write,
    validate_syslinux_device_write_plan,
)


def _device(**changes) -> Device:
    values = {
        "path": "/dev/sdz",
        "size": composite_fixtures.IMAGE_SIZE,
        "model": "Test flash drive",
        "vendor": "ISOpropyl",
        "transport": "usb",
        "serial": "SERIAL-123",
        "wwn": "",
        "major_minor": "65:144",
        "removable": True,
        "hotplug": True,
        "read_only": False,
        "mountpoints": ("/media/test",),
        "partitions": ("/dev/sdz1",),
        "logical_sector_size": 512,
    }
    values.update(changes)
    return Device(**values)


def _block_status(major: int = 65, minor: int = 144):
    return SimpleNamespace(
        st_mode=stat.S_IFBLK | 0o600,
        st_rdev=os.makedev(major, minor),
    )


def _live_payload(
    device: Device,
    *,
    partition_major_minor: str | None = "65:145",
    descendants: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    partition: dict[str, object] = {
        "path": device.partitions[0],
        "type": "part",
        "mountpoints": [],
    }
    if partition_major_minor is not None:
        partition["maj:min"] = partition_major_minor
    if descendants is not None:
        partition["children"] = descendants
    return {
        "blockdevices": [{
            "path": device.path,
            "size": device.size,
            "type": "disk",
            "rm": device.removable,
            "hotplug": device.hotplug,
            "tran": device.transport,
            "model": device.model,
            "vendor": device.vendor,
            "serial": device.serial,
            "wwn": device.wwn,
            "maj:min": device.major_minor,
            "mountpoints": list(device.mountpoints),
            "ro": device.read_only,
            "log-sec": device.logical_sector_size,
            "children": [partition],
        }],
    }


class SyslinuxDevicePlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = composite_fixtures.SyslinuxIsoFat32Tests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        _iso_plan, _staging_result, self.composite = self.fixture.composite_plan()
        self.target = _device()
        self.live_device = self.target
        self.disk_sequence = 982_451_653
        self.related_device_numbers = frozenset({_block_status().st_rdev})
        self.real_probe = syslinux_device._probe_live_target
        self.status_patch = patch(
            "isopropyl.syslinux_device._lstat",
            return_value=_block_status(),
        )
        self.status_patch.start()
        self.addCleanup(self.status_patch.stop)
        self.probe_patch = patch(
            "isopropyl.syslinux_device._probe_live_target",
            side_effect=lambda _path: syslinux_device._LiveTargetObservation(
                self.live_device,
                self.related_device_numbers,
            ),
        )
        self.probe_patch.start()
        self.addCleanup(self.probe_patch.stop)
        self.disk_sequence_patch = patch(
            "isopropyl.syslinux_device._read_disk_sequence",
            return_value=self.disk_sequence,
        )
        self.disk_sequence_probe = self.disk_sequence_patch.start()
        self.addCleanup(self.disk_sequence_patch.stop)

    def plan(self, device: Device | None = None) -> SyslinuxDeviceWritePlan:
        return build_syslinux_device_write_plan(
            self.composite,
            device or self.target,
        )

    def test_exact_target_plan_and_typed_confirmation_are_witnessed(self):
        plan = self.plan()
        self.assertIs(type(plan), SyslinuxDeviceWritePlan)
        self.assertIs(plan.composite_plan, self.composite)
        self.assertIs(plan.device, self.target)
        self.assertEqual(plan.image_size, composite_fixtures.IMAGE_SIZE)
        self.assertEqual(plan.image_size, plan.device.size)
        self.assertEqual(plan.disk_sequence, self.disk_sequence)
        self.assertEqual(plan.logical_sector_size, 512)
        self.assertEqual(plan.firmware_profile, "bios-and-uefi")
        self.assertTrue(plan.mandatory_readback)
        self.assertEqual(plan.required_executor_profile, REQUIRED_EXECUTOR_PROFILE)
        self.assertEqual(
            plan.confirmation_phrase,
            "WRITE BIOS /dev/sdz 65:144",
        )
        self.assertEqual(len(plan.plan_sha256), 64)
        self.assertIn("permanently erased", plan.warnings[0])
        self.assertIn("not yet hardware-certified", plan.warnings[1])
        self.assertIn("exact SHA-256 read-back", plan.warnings[2])
        validate_syslinux_device_write_plan(plan)

        confirmation = confirm_syslinux_device_write(
            plan,
            plan.confirmation_phrase,
        )
        self.assertIs(type(confirmation), ConfirmedSyslinuxDeviceWrite)
        self.assertIs(confirmation.plan, plan)
        self.assertEqual(confirmation.device_identity, self.target.identity)
        validate_confirmed_syslinux_device_write(plan, confirmation)

        for wrong in (
            plan.confirmation_phrase.lower(),
            plan.confirmation_phrase + " ",
            "WRITE BIOS /dev/sdy 65:144",
            "",
        ):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(
                SyslinuxDevicePlanError,
                "did not match",
            ):
                confirm_syslinux_device_write(plan, wrong)

    def test_clones_manual_values_subclasses_and_cross_wiring_lose_authority(self):
        plan = self.plan()
        init_names = [item.name for item in fields(plan) if item.init]
        values = {name: getattr(plan, name) for name in init_names}

        class ForgedPlan(SyslinuxDeviceWritePlan):
            pass

        forged_plans = (
            replace(plan),
            replace(plan, plan_sha256="0" * 64),
            replace(plan, device=replace(plan.device)),
            replace(plan, composite_plan=replace(plan.composite_plan)),
            SyslinuxDeviceWritePlan(**values),
            ForgedPlan(**values),
        )
        for forged in forged_plans:
            with self.subTest(forged=type(forged).__name__), self.assertRaises(
                SyslinuxDevicePlanError,
            ):
                validate_syslinux_device_write_plan(forged)

        confirmation = confirm_syslinux_device_write(plan, plan.confirmation_phrase)
        confirmation_values = {
            item.name: getattr(confirmation, item.name)
            for item in fields(confirmation)
            if item.init
        }

        class ForgedConfirmation(ConfirmedSyslinuxDeviceWrite):
            pass

        for forged in (
            replace(confirmation),
            replace(confirmation, plan_sha256="0" * 64),
            ConfirmedSyslinuxDeviceWrite(**confirmation_values),
            ForgedConfirmation(**confirmation_values),
        ):
            with self.subTest(forged=type(forged).__name__), self.assertRaises(
                SyslinuxDevicePlanError,
            ):
                validate_confirmed_syslinux_device_write(plan, forged)

        other_plan = build_syslinux_device_write_plan(
            self.composite,
            replace(self.target),
        )
        with self.assertRaisesRegex(SyslinuxDevicePlanError, "another plan"):
            validate_confirmed_syslinux_device_write(other_plan, confirmation)

    def test_receipts_cannot_be_transplanted_to_equivalent_objects(self):
        plan = self.plan()
        plan_clone = replace(plan)
        object.__setattr__(plan_clone, "_authorization", plan._authorization)
        with self.assertRaisesRegex(SyslinuxDevicePlanError, "authoritative"):
            validate_syslinux_device_write_plan(plan_clone)

        other_plan = build_syslinux_device_write_plan(
            self.composite,
            replace(self.target),
        )
        object.__setattr__(other_plan, "_authorization", plan._authorization)
        with self.assertRaisesRegex(SyslinuxDevicePlanError, "authoritative"):
            validate_syslinux_device_write_plan(other_plan)

        confirmation = confirm_syslinux_device_write(plan, plan.confirmation_phrase)
        confirmation_clone = replace(confirmation)
        object.__setattr__(
            confirmation_clone,
            "_authorization",
            confirmation._authorization,
        )
        with self.assertRaisesRegex(SyslinuxDevicePlanError, "forged, cloned"):
            validate_confirmed_syslinux_device_write(plan, confirmation_clone)

        other_confirmation = confirm_syslinux_device_write(
            self.plan(),
            plan.confirmation_phrase,
        )
        object.__setattr__(
            other_confirmation,
            "_authorization",
            confirmation._authorization,
        )
        with self.assertRaisesRegex(SyslinuxDevicePlanError, "another plan"):
            validate_confirmed_syslinux_device_write(plan, other_confirmation)

    def test_exact_composite_clone_cannot_acquire_target_authority(self):
        # A singleton witness copied by dataclasses.replace() is not a
        # self-bound authority receipt.  The device boundary must reject the
        # equivalent clone before it mints target authorization.
        with self.assertRaises(SyslinuxDevicePlanError):
            build_syslinux_device_write_plan(
                replace(self.composite),
                self.target,
            )

    def test_every_public_plan_field_is_covered_by_authority(self):
        plan = self.plan()
        mutations = {
            "composite_plan": replace(plan.composite_plan),
            "device": replace(plan.device),
            "composite_plan_sha256": "0" * 64,
            "private_plan_sha256": "1" * 64,
            "source_manifest_sha256": "2" * 64,
            "image_size": plan.image_size + 512,
            "disk_signature": plan.disk_signature ^ 1,
            "volume_id": plan.volume_id ^ 1,
            "logical_sector_size": 4096,
            "firmware_profile": "bios-only",
            "mandatory_readback": False,
            "required_executor_profile": "untrusted/helper/v0",
            "warnings": plan.warnings + ("injected",),
            "confirmation_phrase": plan.confirmation_phrase + " ",
            "plan_sha256": "f" * 64,
        }
        for name, mutation in mutations.items():
            original = getattr(plan, name)
            with self.subTest(field=name):
                object.__setattr__(plan, name, mutation)
                try:
                    with self.assertRaises(SyslinuxDevicePlanError):
                        validate_syslinux_device_write_plan(plan)
                finally:
                    object.__setattr__(plan, name, original)
                validate_syslinux_device_write_plan(plan)

    def test_every_discovered_device_field_remains_bound_after_authorization(self):
        plan = self.plan()
        mutations = {
            "path": "/dev/sdy",
            "size": plan.device.size + 512,
            "model": "Different model",
            "vendor": "Different vendor",
            "transport": "mmc",
            "serial": "DIFFERENT-SERIAL",
            "wwn": "different-wwn",
            "major_minor": "65:145",
            "removable": False,
            "hotplug": False,
            "read_only": True,
            "mountpoints": (),
            "partitions": (),
            "logical_sector_size": 4096,
        }
        for name, mutation in mutations.items():
            original = getattr(plan.device, name)
            with self.subTest(field=name):
                object.__setattr__(plan.device, name, mutation)
                try:
                    with self.assertRaises(SyslinuxDevicePlanError):
                        validate_syslinux_device_write_plan(plan)
                finally:
                    object.__setattr__(plan.device, name, original)
                validate_syslinux_device_write_plan(plan)

    def test_capacity_sector_and_selection_policy_fail_closed(self):
        unsafe = (
            (_device(size=self.target.size - 512), "exactly match"),
            (_device(size=self.target.size + 512), "exactly match"),
            (_device(logical_sector_size=4096), "512-byte"),
            (_device(logical_sector_size=0), "512-byte"),
            (_device(read_only=True), "read-only"),
            (_device(transport="nvme", removable=False, hotplug=False), "USB and SD"),
            (_device(removable=False, hotplug=False), "not removable"),
            (_device(mountpoints=("/",)), "running system"),
            (_device(path="/dev/sdz1"), "whole-disk"),
            (_device(partitions=("/dev/sdy1",)), "Unsafe partition"),
        )
        for device, message in unsafe:
            with self.subTest(device=device), self.assertRaisesRegex(
                SyslinuxDevicePlanError,
                message,
            ):
                build_syslinux_device_write_plan(self.composite, device)

    def test_block_identity_is_bound_at_build_and_every_validation(self):
        plan = self.plan()
        with patch(
            "isopropyl.syslinux_device._lstat",
            return_value=_block_status(65, 145),
        ), self.assertRaisesRegex(SyslinuxDevicePlanError, "device number changed"):
            validate_syslinux_device_write_plan(plan)
        with patch(
            "isopropyl.syslinux_device._lstat",
            return_value=SimpleNamespace(st_mode=stat.S_IFREG, st_rdev=0),
        ), self.assertRaisesRegex(SyslinuxDevicePlanError, "not a whole-disk block"):
            validate_syslinux_device_write_plan(plan)
        with patch(
            "isopropyl.syslinux_device._lstat",
            side_effect=FileNotFoundError("removed"),
        ), self.assertRaisesRegex(SyslinuxDevicePlanError, "removed"):
            validate_syslinux_device_write_plan(plan)

    def test_target_resident_staging_or_workspace_is_rejected(self):
        manifest = self.composite.staging_result.tree_manifest
        assert manifest is not None
        source_device = manifest.source_directories[0].device
        workspace_device = self.composite.private_plan.workspace_identity.device
        original = self.related_device_numbers
        for backing_device in (source_device, workspace_device):
            self.related_device_numbers = original | {backing_device}
            with self.subTest(backing_device=backing_device), self.assertRaisesRegex(
                SyslinuxDevicePlanError,
                "resides on the target",
            ):
                self.plan()
        self.related_device_numbers = original

    def test_target_residency_is_rechecked_after_plan_and_confirmation(self):
        plan = self.plan()
        confirmation = confirm_syslinux_device_write(
            plan,
            plan.confirmation_phrase,
        )
        manifest = self.composite.staging_result.tree_manifest
        assert manifest is not None
        self.related_device_numbers |= {manifest.source_directories[0].device}
        try:
            with self.assertRaisesRegex(SyslinuxDevicePlanError, "resides on the target"):
                validate_syslinux_device_write_plan(plan)
            with self.assertRaisesRegex(SyslinuxDevicePlanError, "resides on the target"):
                confirm_syslinux_device_write(plan, plan.confirmation_phrase)
            with self.assertRaisesRegex(SyslinuxDevicePlanError, "resides on the target"):
                validate_confirmed_syslinux_device_write(plan, confirmation)
        finally:
            self.related_device_numbers = frozenset({_block_status().st_rdev})

    def test_live_reprobe_rejects_same_node_identity_with_changed_device_facts(self):
        plan = self.plan()
        confirmation = confirm_syslinux_device_write(
            plan,
            plan.confirmation_phrase,
        )
        changes = (
            {"size": self.target.size + 512},
            {"model": "Replacement model"},
            {"vendor": "Replacement vendor"},
            {"transport": "mmc"},
            {"serial": "REPLACEMENT"},
            {"wwn": "replacement-wwn"},
            {"removable": False},
            {"hotplug": False},
            {"read_only": True},
            {"mountpoints": ()},
            {"partitions": ()},
            {"logical_sector_size": 4096},
        )
        for change in changes:
            self.live_device = replace(self.target, **change)
            with self.subTest(change=change):
                self.assertEqual(self.live_device.path, self.target.path)
                self.assertEqual(
                    self.live_device.major_minor,
                    self.target.major_minor,
                )
                with self.assertRaisesRegex(SyslinuxDevicePlanError, "changed after discovery"):
                    validate_syslinux_device_write_plan(plan)
                with self.assertRaisesRegex(SyslinuxDevicePlanError, "changed after discovery"):
                    validate_confirmed_syslinux_device_write(plan, confirmation)
        self.live_device = self.target

    def test_real_live_probe_is_bounded_absolute_and_captures_descendants(self):
        child_number = os.makedev(65, 145)
        mapped_number = os.makedev(253, 7)
        payload = {
            "blockdevices": [{
                "path": self.target.path,
                "size": self.target.size,
                "type": "disk",
                "rm": True,
                "hotplug": True,
                "tran": "usb",
                "model": self.target.model,
                "vendor": self.target.vendor,
                "serial": self.target.serial,
                "wwn": self.target.wwn,
                "maj:min": self.target.major_minor,
                "mountpoints": list(self.target.mountpoints),
                "ro": False,
                "log-sec": 512,
                "children": [{
                    "path": "/dev/sdz1",
                    "type": "part",
                    "maj:min": "65:145",
                    "mountpoints": [],
                    "children": [{
                        "path": "/dev/mapper/test",
                        "type": "crypt",
                        "maj:min": "253:7",
                        "mountpoints": [],
                    }],
                }],
            }],
        }
        completed = subprocess.CompletedProcess(
            ["/usr/bin/lsblk"],
            0,
            json.dumps(payload),
            "",
        )
        with (
            patch("isopropyl.syslinux_device._which", return_value="/usr/bin/lsblk") as which,
            patch("isopropyl.syslinux_device._run", return_value=completed) as run,
        ):
            observed = self.real_probe(self.target.path)
        self.assertEqual(observed.device, self.target)
        self.assertEqual(
            observed.related_device_numbers,
            frozenset({_block_status().st_rdev, child_number, mapped_number}),
        )
        self.assertEqual(which.call_args.kwargs["path"], "/usr/sbin:/usr/bin:/sbin:/bin")
        command = run.call_args.args[0]
        self.assertEqual(command[0], "/usr/bin/lsblk")
        self.assertEqual(command[-1], self.target.path)
        self.assertTrue(run.call_args.kwargs["shell"] is False)
        self.assertEqual(run.call_args.kwargs["timeout"], 15)

    def test_live_probe_rejects_malformed_and_oversized_output(self):
        malformed = (
            "",
            "not json",
            "null",
            "[]",
            '{"blockdevices": null}',
            '{"blockdevices": "not-a-list"}',
            '{"blockdevices": [null]}',
        )
        with patch(
            "isopropyl.syslinux_device._which",
            return_value="/usr/bin/lsblk",
        ):
            for stdout in malformed:
                completed = subprocess.CompletedProcess(
                    ["/usr/bin/lsblk"],
                    0,
                    stdout,
                    "",
                )
                with self.subTest(stdout=stdout), patch(
                    "isopropyl.syslinux_device._run",
                    return_value=completed,
                ), self.assertRaises(SyslinuxDevicePlanError):
                    self.real_probe(self.target.path)

            for stdout, stderr in (("x" * 9, ""), ("", "é" * 5)):
                completed = subprocess.CompletedProcess(
                    ["/usr/bin/lsblk"],
                    0,
                    stdout,
                    stderr,
                )
                with self.subTest((stdout, stderr)), patch(
                    "isopropyl.syslinux_device._MAX_LSBLK_OUTPUT",
                    8,
                ), patch(
                    "isopropyl.syslinux_device._run",
                    return_value=completed,
                ), self.assertRaisesRegex(
                    SyslinuxDevicePlanError,
                    "too much output",
                ):
                    self.real_probe(self.target.path)

            decode_error = UnicodeDecodeError(
                "utf-8",
                b"\xff",
                0,
                1,
                "invalid output byte",
            )
            with patch(
                "isopropyl.syslinux_device._run",
                side_effect=decode_error,
            ), self.assertRaises(SyslinuxDevicePlanError):
                self.real_probe(self.target.path)

    def test_live_probe_requires_kernel_identity_for_every_descendant(self):
        malformed_descendants = (
            _live_payload(self.target, partition_major_minor=None),
            _live_payload(
                self.target,
                descendants=[{
                    "path": "/dev/mapper/test",
                    "type": "crypt",
                    "mountpoints": [],
                }],
            ),
            _live_payload(
                self.target,
                descendants=[{
                    "path": "/dev/mapper/test",
                    "type": "crypt",
                    "maj:min": "not-an-identity",
                    "mountpoints": [],
                }],
            ),
        )
        with patch(
            "isopropyl.syslinux_device._which",
            return_value="/usr/bin/lsblk",
        ):
            for payload in malformed_descendants:
                completed = subprocess.CompletedProcess(
                    ["/usr/bin/lsblk"],
                    0,
                    json.dumps(payload),
                    "",
                )
                with self.subTest(payload=payload), patch(
                    "isopropyl.syslinux_device._run",
                    return_value=completed,
                ), self.assertRaisesRegex(
                    SyslinuxDevicePlanError,
                    "kernel identity",
                ):
                    self.real_probe(self.target.path)

    def test_real_descendant_topology_rejects_source_and_workspace_devices(self):
        manifest = self.composite.staging_result.tree_manifest
        assert manifest is not None
        backing_devices = (
            manifest.source_directories[0].device,
            self.composite.private_plan.workspace_identity.device,
        )
        with patch(
            "isopropyl.syslinux_device._which",
            return_value="/usr/bin/lsblk",
        ):
            for backing_device in backing_devices:
                major_minor = (
                    f"{os.major(backing_device)}:{os.minor(backing_device)}"
                )
                payload = _live_payload(
                    self.target,
                    descendants=[{
                        "path": "/dev/mapper/source-or-workspace",
                        "type": "crypt",
                        "maj:min": major_minor,
                        "mountpoints": [],
                    }],
                )
                completed = subprocess.CompletedProcess(
                    ["/usr/bin/lsblk"],
                    0,
                    json.dumps(payload),
                    "",
                )
                with self.subTest(backing_device=backing_device), patch(
                    "isopropyl.syslinux_device._run",
                    return_value=completed,
                ), patch(
                    "isopropyl.syslinux_device._probe_live_target",
                    side_effect=self.real_probe,
                ), self.assertRaisesRegex(
                    SyslinuxDevicePlanError,
                    "resides on the target",
                ):
                    self.plan()

    def test_cancellation_after_live_probe_precedes_receipt_mint(self):
        cancellation_active = False

        def probe(_path: str):
            nonlocal cancellation_active
            cancellation_active = True
            return syslinux_device._LiveTargetObservation(
                self.target,
                self.related_device_numbers,
            )

        def cancel() -> None:
            if cancellation_active:
                raise SyslinuxDevicePlanCancelled("cancelled after live probe")

        with (
            patch(
                "isopropyl.syslinux_device._probe_live_target",
                side_effect=probe,
            ),
            patch(
                "isopropyl.syslinux_device._PlanReceipt",
                side_effect=AssertionError("receipt minted after cancellation"),
            ) as receipt,
            self.assertRaisesRegex(
                SyslinuxDevicePlanCancelled,
                "cancelled after live probe",
            ),
        ):
            build_syslinux_device_write_plan(
                self.composite,
                self.target,
                cancel_check=cancel,
            )
        receipt.assert_not_called()

    def test_live_source_mutation_invalidates_plan_before_confirmation(self):
        plan = self.plan()
        source = plan.composite_plan.staging_result.destination / "README.txt"
        before = source.stat()
        source.write_bytes(b"other")
        os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
        with self.assertRaisesRegex(SyslinuxDevicePlanError, "changed"):
            validate_syslinux_device_write_plan(plan)
        with self.assertRaisesRegex(SyslinuxDevicePlanError, "changed"):
            confirm_syslinux_device_write(plan, plan.confirmation_phrase)

    def test_cancellation_never_mints_a_plan_or_confirmation(self):
        def cancel() -> None:
            raise SyslinuxDevicePlanCancelled("injected cancellation")

        with self.assertRaisesRegex(SyslinuxDevicePlanCancelled, "injected"):
            build_syslinux_device_write_plan(
                self.composite,
                self.target,
                cancel_check=cancel,
            )
        plan = self.plan()
        with self.assertRaisesRegex(SyslinuxDevicePlanCancelled, "injected"):
            confirm_syslinux_device_write(
                plan,
                plan.confirmation_phrase,
                cancel_check=cancel,
            )

        confirmation = confirm_syslinux_device_write(
            plan,
            plan.confirmation_phrase,
        )
        with self.assertRaisesRegex(SyslinuxDevicePlanCancelled, "injected"):
            validate_syslinux_device_write_plan(plan, cancel_check=cancel)
        with self.assertRaisesRegex(SyslinuxDevicePlanCancelled, "injected"):
            validate_confirmed_syslinux_device_write(
                plan,
                confirmation,
                cancel_check=cancel,
            )

    def test_confirmation_type_and_every_public_field_are_exactly_bound(self):
        plan = self.plan()
        for wrong in (
            None,
            plan.confirmation_phrase.encode(),
            plan.confirmation_phrase + "\n",
            plan.confirmation_phrase.replace("I", "\N{FULLWIDTH LATIN CAPITAL LETTER I}"),
        ):
            with self.subTest(value=wrong), self.assertRaisesRegex(
                SyslinuxDevicePlanError,
                "did not match",
            ):
                confirm_syslinux_device_write(plan, wrong)  # type: ignore[arg-type]

        confirmation = confirm_syslinux_device_write(
            plan,
            plan.confirmation_phrase,
        )
        mutations = {
            "plan": replace(plan),
            "plan_sha256": "0" * 64,
            "device_identity": confirmation.device_identity[:-1] + ("other",),
            "logical_sector_size": 4096,
            "confirmation_phrase": confirmation.confirmation_phrase + " ",
        }
        for name, mutation in mutations.items():
            original = getattr(confirmation, name)
            with self.subTest(field=name):
                object.__setattr__(confirmation, name, mutation)
                try:
                    with self.assertRaises(SyslinuxDevicePlanError):
                        validate_confirmed_syslinux_device_write(plan, confirmation)
                finally:
                    object.__setattr__(confirmation, name, original)
                validate_confirmed_syslinux_device_write(plan, confirmation)

    def test_post_unmount_receipt_allows_only_mountpoints_to_become_empty(self):
        plan = self.plan()
        confirmation = confirm_syslinux_device_write(plan, plan.confirmation_phrase)
        self.live_device = replace(self.target, mountpoints=())
        ready = authorize_unmounted_syslinux_device_write(plan, confirmation)
        self.assertIs(type(ready), ReadySyslinuxDeviceWrite)
        self.assertIs(ready.plan, plan)
        self.assertIs(ready.confirmation, confirmation)
        self.assertEqual(ready.device, self.live_device)
        self.assertEqual(ready.device.mountpoints, ())
        self.assertEqual(ready.disk_sequence, self.disk_sequence)
        self.assertEqual(len(ready.ready_sha256), 64)
        validate_ready_syslinux_device_write(plan, confirmation, ready)

        for name, value in {
            "model": "replacement",
            "vendor": "replacement",
            "serial": "replacement",
            "wwn": "replacement",
            "size": self.target.size + 512,
            "major_minor": "65:145",
            "partitions": (),
            "logical_sector_size": 4096,
            "read_only": True,
            "transport": "mmc",
        }.items():
            self.live_device = replace(self.target, mountpoints=(), **{name: value})
            with self.subTest(field=name), self.assertRaisesRegex(
                SyslinuxDevicePlanError,
                "changed during unmounting",
            ):
                authorize_unmounted_syslinux_device_write(plan, confirmation)

        self.live_device = self.target
        with self.assertRaisesRegex(SyslinuxDevicePlanError, "still has a mounted"):
            authorize_unmounted_syslinux_device_write(plan, confirmation)

    def test_disk_generation_is_bound_before_confirmation_and_survives_unmount(self):
        plan = self.plan()
        self.disk_sequence_probe.return_value = self.disk_sequence + 1
        with self.assertRaisesRegex(SyslinuxDevicePlanError, "different disk generation"):
            confirm_syslinux_device_write(plan, plan.confirmation_phrase)

        self.disk_sequence_probe.return_value = self.disk_sequence
        confirmation = confirm_syslinux_device_write(plan, plan.confirmation_phrase)
        self.live_device = replace(self.target, mountpoints=())
        self.disk_sequence_probe.return_value = self.disk_sequence + 1
        with self.assertRaisesRegex(SyslinuxDevicePlanError, "confirmed plan"):
            authorize_unmounted_syslinux_device_write(plan, confirmation)

    def test_ready_receipts_are_self_bound_and_reprobed(self):
        plan = self.plan()
        confirmation = confirm_syslinux_device_write(plan, plan.confirmation_phrase)
        self.live_device = replace(self.target, mountpoints=())
        ready = authorize_unmounted_syslinux_device_write(plan, confirmation)
        values = {
            item.name: getattr(ready, item.name)
            for item in fields(ready)
            if item.init
        }

        class ForgedReady(ReadySyslinuxDeviceWrite):
            pass

        for forged in (
            replace(ready),
            replace(ready, ready_sha256="0" * 64),
            replace(ready, device=replace(ready.device)),
            ReadySyslinuxDeviceWrite(**values),
            ForgedReady(**values),
        ):
            with self.subTest(forged=type(forged).__name__), self.assertRaises(
                SyslinuxDevicePlanError,
            ):
                validate_ready_syslinux_device_write(plan, confirmation, forged)

        transplanted = replace(ready)
        object.__setattr__(transplanted, "_authorization", ready._authorization)
        with self.assertRaisesRegex(SyslinuxDevicePlanError, "forged, cloned"):
            validate_ready_syslinux_device_write(plan, confirmation, transplanted)

        self.live_device = replace(ready.device, serial="replacement")
        with self.assertRaisesRegex(SyslinuxDevicePlanError, "changed after discovery"):
            validate_ready_syslinux_device_write(plan, confirmation, ready)

        self.live_device = ready.device
        self.disk_sequence_probe.return_value = self.disk_sequence + 1
        with self.assertRaisesRegex(SyslinuxDevicePlanError, "disk generation changed"):
            validate_ready_syslinux_device_write(plan, confirmation, ready)

    def test_post_unmount_cancellation_precedes_ready_receipt_mint(self):
        plan = self.plan()
        confirmation = confirm_syslinux_device_write(plan, plan.confirmation_phrase)
        self.live_device = replace(self.target, mountpoints=())
        probed = False

        def probe(_path: str):
            nonlocal probed
            probed = True
            return syslinux_device._LiveTargetObservation(
                self.live_device,
                self.related_device_numbers,
            )

        def cancel() -> None:
            if probed:
                raise SyslinuxDevicePlanCancelled("cancelled after unmount probe")

        with (
            patch("isopropyl.syslinux_device._probe_live_target", side_effect=probe),
            patch(
                "isopropyl.syslinux_device._ReadyReceipt",
                side_effect=AssertionError("ready receipt minted after cancellation"),
            ) as receipt,
            self.assertRaisesRegex(SyslinuxDevicePlanCancelled, "after unmount probe"),
        ):
            authorize_unmounted_syslinux_device_write(
                plan,
                confirmation,
                cancel_check=cancel,
            )
        receipt.assert_not_called()

    def test_planning_and_confirmation_never_prepare_or_touch_a_target(self):
        self.assertFalse(hasattr(__import__(
            "isopropyl.syslinux_device", fromlist=["x"],
        ), "SyslinuxDeviceWriteRunner"))

        with (
            patch(
                "isopropyl.syslinux_iso_fat32.prepare_syslinux_iso_fat32",
                side_effect=AssertionError("planning must not prepare an image"),
            ) as prepare,
            patch.object(
                subprocess,
                "Popen",
                side_effect=AssertionError("planning must not spawn a process"),
            ) as popen,
        ):
            plan = self.plan()
            confirmation = confirm_syslinux_device_write(
                plan,
                plan.confirmation_phrase,
            )
            validate_confirmed_syslinux_device_write(plan, confirmation)
        prepare.assert_not_called()
        popen.assert_not_called()

    def test_no_image_builder_transaction_or_target_write_is_reachable(self):
        real_open = os.open

        def read_only_open(path, flags, *args, **kwargs):
            target = os.fspath(path)
            self.assertNotEqual(target, self.target.path)
            write_flags = (
                os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
            )
            self.assertFalse(flags & write_flags, f"write-capable open reached for {target}")
            return real_open(path, flags, *args, **kwargs)

        unreachable = AssertionError("mutation-capable execution was reached")
        with (
            patch(
                "isopropyl.syslinux_iso_fat32.prepare_syslinux_iso_fat32",
                side_effect=unreachable,
            ) as prepare,
            patch(
                "isopropyl.syslinux_iso_fat32.PrivateFat32Builder.execute",
                side_effect=unreachable,
            ) as build,
            patch(
                "isopropyl.syslinux_iso_fat32.patch_private_fat32_syslinux",
                side_effect=unreachable,
            ) as patch_syslinux,
            patch(
                "isopropyl.syslinux_transaction."
                "SyslinuxRegularFileTransaction.execute",
                side_effect=unreachable,
            ) as transaction,
            patch(
                "isopropyl.writer.ImageWriter.write",
                side_effect=unreachable,
            ) as writer,
            patch.object(os, "open", side_effect=read_only_open),
            patch.object(os, "write", side_effect=unreachable) as os_write,
            patch.object(os, "pwrite", side_effect=unreachable) as os_pwrite,
            patch.object(os, "ftruncate", side_effect=unreachable) as truncate,
            patch.object(os, "fsync", side_effect=unreachable) as fsync,
        ):
            plan = self.plan()
            confirmation = confirm_syslinux_device_write(
                plan,
                plan.confirmation_phrase,
            )
            validate_syslinux_device_write_plan(plan)
            validate_confirmed_syslinux_device_write(plan, confirmation)

        for mocked in (
            prepare,
            build,
            patch_syslinux,
            transaction,
            writer,
            os_write,
            os_pwrite,
            truncate,
            fsync,
        ):
            mocked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
