from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import os
import stat
import subprocess
import tempfile
import unittest
from dataclasses import fields, replace
from types import SimpleNamespace
from unittest.mock import patch

import isopropyl.raw_device as raw_device
import isopropyl.raw_snapshot as raw_snapshot
from isopropyl.devices import Device
from isopropyl.raw_snapshot import (
    PreparedRawSnapshot,
    RawSnapshotIdentity,
    RawSnapshotResult,
    RawSourceIdentity,
    RawWorkspaceIdentity,
)
from isopropyl.raw_device import (
    ConfirmedRawDeviceWrite,
    REQUIRED_EXECUTOR_PROFILE,
    RawDevicePlanCancelled,
    RawDevicePlanError,
    RawDeviceWritePlan,
    RawSourceEvidence,
    ReadyRawDeviceWrite,
    authorize_unmounted_raw_device_write,
    build_raw_device_write_plan,
    confirm_raw_device_write,
    observe_raw_target_device_numbers,
    raw_source_evidence_from_snapshot,
    validate_confirmed_raw_device_write,
    validate_raw_device_write_plan,
    validate_ready_raw_device_write,
)


TARGET_SIZE = 64 * 1024 * 1024
SOURCE_SIZE = 24 * 1024 * 1024


def _device(**changes: object) -> Device:
    values: dict[str, object] = {
        "path": "/dev/sdz",
        "size": TARGET_SIZE,
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
    return Device(**values)  # type: ignore[arg-type]


def _source(**changes: object) -> RawSourceEvidence:
    values: dict[str, object] = {
        "source_sha256": "a" * 64,
        "source_size": SOURCE_SIZE,
        "original_device": os.makedev(8, 1),
        "original_inode": 982451653,
        "original_size": SOURCE_SIZE,
        "original_modified_ns": 1_730_000_000_000_000_000,
        "original_changed_ns": 1_730_000_000_100_000_000,
        "workspace_device": os.makedev(8, 2),
        "raw_snapshot_plan_sha256": "9" * 64,
    }
    values.update(changes)
    return RawSourceEvidence(**values)  # type: ignore[arg-type]


def _block_status(major: int = 65, minor: int = 144):
    return SimpleNamespace(
        st_mode=stat.S_IFBLK | 0o600,
        st_rdev=os.makedev(major, minor),
    )


class RawDevicePlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = _source()
        self.target = _device()
        self.live_device = self.target
        self.disk_sequence = 7_140_673
        self.related_device_numbers = frozenset({
            _block_status().st_rdev,
            os.makedev(65, 145),
        })
        self.real_probe = raw_device._probe_live_target
        self.status_patch = patch(
            "isopropyl.raw_device._lstat",
            return_value=_block_status(),
        )
        self.status_patch.start()
        self.addCleanup(self.status_patch.stop)
        self.probe_patch = patch(
            "isopropyl.raw_device._probe_live_target",
            side_effect=lambda _path: raw_device._LiveTargetObservation(
                self.live_device,
                self.related_device_numbers,
            ),
        )
        self.probe_patch.start()
        self.addCleanup(self.probe_patch.stop)
        self.disk_sequence_patch = patch(
            "isopropyl.raw_device._read_disk_sequence",
            return_value=self.disk_sequence,
        )
        self.disk_sequence_probe = self.disk_sequence_patch.start()
        self.addCleanup(self.disk_sequence_patch.stop)

    def plan(
        self,
        *,
        source: RawSourceEvidence | None = None,
        device: Device | None = None,
        final_verification: bool = True,
    ) -> RawDeviceWritePlan:
        return build_raw_device_write_plan(
            source or self.source,
            device or self.target,
            final_verification=final_verification,
        )

    def test_source_evidence_is_strict_and_identity_digest_is_derived(self):
        evidence = self.source
        self.assertEqual(len(evidence.snapshot_plan_sha256), 64)
        self.assertEqual(
            evidence.original_identity,
            (
                evidence.original_device,
                evidence.original_inode,
                evidence.original_size,
                evidence.original_modified_ns,
                evidence.original_changed_ns,
            ),
        )
        self.assertEqual(
            evidence.snapshot_plan_sha256,
            replace(evidence).snapshot_plan_sha256,
        )
        changes = {
            "raw_snapshot_plan_sha256": "8" * 64,
            "source_sha256": "b" * 64,
            "source_size": evidence.source_size + 1,
            "original_device": evidence.original_device + 1,
            "original_inode": evidence.original_inode + 1,
            "original_size": evidence.original_size + 1,
            "original_modified_ns": evidence.original_modified_ns + 1,
            "original_changed_ns": evidence.original_changed_ns + 1,
            "workspace_device": evidence.workspace_device + 1,
            "requires_exact_target_size": True,
            "required_logical_sector_size": 512,
        }
        for field_name, value in changes.items():
            with self.subTest(field=field_name):
                changed = replace(evidence, **{field_name: value})
                self.assertNotEqual(
                    changed.snapshot_plan_sha256,
                    evidence.snapshot_plan_sha256,
                )

        invalid = (
            {"source_sha256": "A" * 64},
            {"source_sha256": "a" * 63},
            {"raw_snapshot_plan_sha256": "A" * 64},
            {"raw_snapshot_plan_sha256": "9" * 63},
            {"source_size": 0},
            {"source_size": True},
            {"original_device": -1},
            {"original_inode": 0},
            {"original_inode": True},
            {"original_size": 0},
            {"original_modified_ns": -1},
            {"original_changed_ns": -1},
            {"workspace_device": -1},
            {"requires_exact_target_size": None},
            {"requires_exact_target_size": 1},
            {"required_logical_sector_size": 0},
            {"required_logical_sector_size": -512},
            {"required_logical_sector_size": True},
            {"required_logical_sector_size": "512"},
        )
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(
                RawDevicePlanError,
            ):
                _source(**changes)

    def test_snapshot_result_derives_every_source_evidence_binding(self):
        result = RawSnapshotResult(
            "9" * 64,
            RawSourceIdentity(
                self.source.original_device,
                self.source.original_inode,
                self.source.original_size,
                self.source.original_modified_ns,
                self.source.original_changed_ns,
            ),
            RawWorkspaceIdentity(
                self.source.workspace_device,
                17,
                os.geteuid(),
                0o700,
                123,
            ),
            RawSnapshotIdentity(
                os.makedev(8, 3),
                23,
                SOURCE_SIZE,
                456,
                789,
                os.geteuid(),
                0o600,
                SOURCE_SIZE // 512,
            ),
            SOURCE_SIZE,
            "a" * 64,
            True,
        )
        source = tempfile.TemporaryFile()
        prepared = PreparedRawSnapshot(
            os.dup(source.fileno()),
            result,
            raw_snapshot._OWNER_WITNESS,
        )
        self.addCleanup(prepared.close)
        self.addCleanup(source.close)
        evidence = raw_source_evidence_from_snapshot(prepared)
        self.assertEqual(evidence.raw_snapshot_plan_sha256, result.plan_sha256)
        self.assertEqual(evidence.source_sha256, result.image_sha256)
        self.assertEqual(evidence.source_size, result.image_size)
        self.assertEqual(evidence.original_identity, self.source.original_identity)
        self.assertEqual(
            evidence.workspace_device,
            result.workspace_identity.device,
        )
        self.assertFalse(evidence.requires_exact_target_size)
        self.assertIsNone(evidence.required_logical_sector_size)

        explicit_generic = raw_source_evidence_from_snapshot(
            prepared,
            requires_exact_target_size=False,
            required_logical_sector_size=None,
        )
        self.assertEqual(explicit_generic, evidence)
        with self.assertRaisesRegex(RawDevicePlanError, "disagree"):
            raw_source_evidence_from_snapshot(
                prepared,
                requires_exact_target_size=True,
            )

        constrained_result = replace(
            result,
            requires_exact_target_size=True,
            required_logical_sector_size=512,
        )
        constrained_prepared = PreparedRawSnapshot(
            os.dup(source.fileno()),
            constrained_result,
            raw_snapshot._OWNER_WITNESS,
        )
        self.addCleanup(constrained_prepared.close)
        constrained = raw_source_evidence_from_snapshot(
            constrained_prepared,
            requires_exact_target_size=True,
            required_logical_sector_size=512,
        )
        self.assertTrue(constrained.requires_exact_target_size)
        self.assertEqual(constrained.required_logical_sector_size, 512)
        self.assertNotEqual(
            constrained.snapshot_plan_sha256,
            evidence.snapshot_plan_sha256,
        )
        for invalid_keywords in (
            {"requires_exact_target_size": 1},
            {"requires_exact_target_size": None},
            {"required_logical_sector_size": True},
            {"required_logical_sector_size": 0},
        ):
            with self.subTest(invalid_keywords=invalid_keywords), self.assertRaises(
                RawDevicePlanError,
            ):
                raw_source_evidence_from_snapshot(
                    prepared,
                    **invalid_keywords,
                )

        derived = raw_source_evidence_from_snapshot(constrained_prepared)
        self.assertTrue(derived.requires_exact_target_size)
        self.assertEqual(derived.required_logical_sector_size, 512)
        with self.assertRaisesRegex(RawDevicePlanError, "disagree"):
            raw_source_evidence_from_snapshot(
                constrained_prepared,
                requires_exact_target_size=False,
            )
        with self.assertRaisesRegex(RawDevicePlanError, "disagree"):
            raw_source_evidence_from_snapshot(
                constrained_prepared,
                required_logical_sector_size=None,
            )
        object.__setattr__(constrained_result, "requires_exact_target_size", "yes")
        with self.assertRaisesRegex(RawDevicePlanError, "constraint"):
            raw_source_evidence_from_snapshot(constrained_prepared)
        object.__setattr__(constrained_result, "requires_exact_target_size", True)
        with self.assertRaises(RawDevicePlanError):
            raw_source_evidence_from_snapshot(result)  # type: ignore[arg-type]
        prepared.close()
        with self.assertRaises(RawDevicePlanError):
            raw_source_evidence_from_snapshot(prepared)

    def test_topology_observation_is_fresh_validated_and_cancel_aware(self):
        self.assertEqual(
            observe_raw_target_device_numbers(self.target),
            self.related_device_numbers,
        )
        with self.assertRaises(RawDevicePlanCancelled):
            observe_raw_target_device_numbers(
                self.target,
                cancel_check=lambda: (_ for _ in ()).throw(
                    RawDevicePlanCancelled("cancelled"),
                ),
            )
        self.live_device = replace(self.target, serial="replacement")
        with self.assertRaisesRegex(RawDevicePlanError, "changed"):
            observe_raw_target_device_numbers(self.target)

    def test_plan_confirmation_and_verification_policy_are_fully_bound(self):
        for requested in (False, True):
            with self.subTest(final_verification=requested):
                plan = self.plan(final_verification=requested)
                self.assertIs(type(plan), RawDeviceWritePlan)
                self.assertIs(plan.source_evidence, self.source)
                self.assertIs(plan.device, self.target)
                self.assertEqual(
                    plan.raw_snapshot_plan_sha256,
                    self.source.raw_snapshot_plan_sha256,
                )
                self.assertEqual(
                    plan.snapshot_plan_sha256,
                    self.source.snapshot_plan_sha256,
                )
                self.assertEqual(plan.source_sha256, self.source.source_sha256)
                self.assertEqual(plan.source_size, SOURCE_SIZE)
                self.assertEqual(
                    plan.original_source_identity,
                    self.source.original_identity,
                )
                self.assertEqual(plan.target_capacity, TARGET_SIZE)
                self.assertEqual(plan.disk_sequence, self.disk_sequence)
                self.assertEqual(plan.logical_sector_size, 512)
                self.assertTrue(plan.mandatory_preactivation_readback)
                self.assertIs(plan.final_verification_requested, requested)
                self.assertEqual(
                    plan.required_executor_profile,
                    REQUIRED_EXECUTOR_PROFILE,
                )
                self.assertEqual(
                    plan.confirmation_phrase,
                    "WRITE RAW /dev/sdz 65:144",
                )
                self.assertEqual(len(plan.plan_sha256), 64)
                validate_raw_device_write_plan(plan)

                confirmation = confirm_raw_device_write(
                    plan,
                    plan.confirmation_phrase,
                )
                self.assertIs(type(confirmation), ConfirmedRawDeviceWrite)
                self.assertIs(confirmation.plan, plan)
                self.assertEqual(confirmation.source_sha256, plan.source_sha256)
                self.assertEqual(confirmation.source_size, plan.source_size)
                self.assertIs(
                    confirmation.final_verification_requested,
                    requested,
                )
                validate_confirmed_raw_device_write(plan, confirmation)

    def test_source_may_be_shorter_or_equal_but_not_larger_than_target(self):
        for size in (1024, TARGET_SIZE - 512, TARGET_SIZE):
            with self.subTest(size=size):
                plan = self.plan(source=_source(source_size=size))
                self.assertEqual(plan.source_size, size)
                self.assertEqual(plan.target_capacity, TARGET_SIZE)
                retained_gap = max(0, TARGET_SIZE - size - 512)
                self.assertEqual(
                    any("may retain previous data" in item for item in plan.warnings),
                    bool(retained_gap),
                )
        with self.assertRaisesRegex(RawDevicePlanError, "larger than"):
            self.plan(source=_source(source_size=TARGET_SIZE + 1))
        with self.assertRaisesRegex(RawDevicePlanError, "exceeds"):
            self.plan(
                source=_source(
                    source_size=raw_device.MAX_RAW_SOURCE_BYTES + 512,
                ),
                device=_device(
                    size=raw_device.MAX_RAW_SOURCE_BYTES + 1024,
                ),
            )
        for size in (1, 513, 1025):
            with self.subTest(size=size), self.assertRaisesRegex(
                RawDevicePlanError,
                "sector-aligned",
            ):
                self.plan(source=_source(source_size=size))

    def test_authoritative_source_geometry_constraints_are_enforced(self):
        exact = _source(
            source_size=TARGET_SIZE,
            original_size=TARGET_SIZE,
            requires_exact_target_size=True,
            required_logical_sector_size=512,
        )
        plan = self.plan(source=exact)
        self.assertTrue(plan.requires_exact_target_size)
        self.assertEqual(plan.required_logical_sector_size, 512)
        confirmation = confirm_raw_device_write(plan, plan.confirmation_phrase)
        self.assertTrue(confirmation.requires_exact_target_size)
        self.assertEqual(confirmation.required_logical_sector_size, 512)
        validate_confirmed_raw_device_write(plan, confirmation)

        generic = replace(
            exact,
            requires_exact_target_size=False,
            required_logical_sector_size=None,
        )
        generic_plan = self.plan(source=generic)
        self.assertNotEqual(plan.snapshot_plan_sha256, generic_plan.snapshot_plan_sha256)
        self.assertNotEqual(plan.plan_sha256, generic_plan.plan_sha256)
        with self.assertRaisesRegex(RawDevicePlanError, "another plan"):
            validate_confirmed_raw_device_write(generic_plan, confirmation)

        for size in (TARGET_SIZE - 512, TARGET_SIZE + 512):
            with self.subTest(size=size), self.assertRaisesRegex(
                RawDevicePlanError,
                "exactly matches",
            ):
                self.plan(
                    source=_source(
                        source_size=size,
                        requires_exact_target_size=True,
                    ),
                )

        with self.assertRaisesRegex(RawDevicePlanError, "requires.*4096-byte"):
            self.plan(
                source=_source(required_logical_sector_size=4096),
            )
        with self.assertRaisesRegex(RawDevicePlanError, "profile requires 512-byte"):
            self.plan(
                source=_source(required_logical_sector_size=4096),
                device=_device(logical_sector_size=4096),
            )
        with self.assertRaisesRegex(RawDevicePlanError, "profile requires 512-byte"):
            self.plan(
                source=_source(required_logical_sector_size=None),
                device=_device(logical_sector_size=4096),
            )

    def test_target_policy_binds_capacity_sector_and_complete_device(self):
        invalid = (
            (_device(logical_sector_size=4096), "512-byte"),
            (_device(size=TARGET_SIZE + 1), "sector aligned"),
            (
                _device(size=raw_device.MAX_RAW_DEVICE_BYTES + 512),
                "exceeds",
            ),
            (_device(read_only=True), "read-only"),
            (_device(transport="nvme", removable=False, hotplug=False), "USB and SD"),
            (_device(mountpoints=("/",)), "running system"),
            (_device(path="/dev/sdz1"), "whole-disk"),
            (_device(partitions=("/dev/sdy1",)), "Unsafe partition"),
        )
        for device, message in invalid:
            with self.subTest(device=device), self.assertRaisesRegex(
                RawDevicePlanError,
                message,
            ):
                self.plan(device=device)

        plan = self.plan()
        self.assertFalse(plan.requires_exact_target_size)
        self.assertIsNone(plan.required_logical_sector_size)
        changes = {
            "path": "/dev/sdy",
            "size": plan.device.size + 512,
            "model": "replacement model",
            "vendor": "replacement vendor",
            "transport": "mmc",
            "serial": "replacement serial",
            "wwn": "replacement wwn",
            "major_minor": "65:145",
            "removable": False,
            "hotplug": False,
            "read_only": True,
            "mountpoints": (),
            "partitions": (),
            "logical_sector_size": 4096,
        }
        for name, value in changes.items():
            original = getattr(plan.device, name)
            with self.subTest(field=name):
                object.__setattr__(plan.device, name, value)
                try:
                    with self.assertRaises(RawDevicePlanError):
                        validate_raw_device_write_plan(plan)
                finally:
                    object.__setattr__(plan.device, name, original)
                validate_raw_device_write_plan(plan)

    def test_plan_evidence_confirmation_and_receipts_are_clone_resistant(self):
        plan = self.plan()
        values = {
            item.name: getattr(plan, item.name)
            for item in fields(plan)
            if item.init
        }

        class ForgedPlan(RawDeviceWritePlan):
            pass

        for forged in (
            replace(plan),
            replace(plan, source_evidence=replace(self.source)),
            replace(plan, device=replace(self.target)),
            replace(plan, plan_sha256="0" * 64),
            RawDeviceWritePlan(**values),
            ForgedPlan(**values),
        ):
            with self.subTest(forged=type(forged).__name__), self.assertRaises(
                RawDevicePlanError,
            ):
                validate_raw_device_write_plan(forged)

        transplanted = replace(plan)
        object.__setattr__(transplanted, "_authorization", plan._authorization)
        with self.assertRaisesRegex(RawDevicePlanError, "authoritative"):
            validate_raw_device_write_plan(transplanted)

        confirmation = confirm_raw_device_write(plan, plan.confirmation_phrase)
        self.assertFalse(confirmation.requires_exact_target_size)
        self.assertIsNone(confirmation.required_logical_sector_size)
        confirmation_values = {
            item.name: getattr(confirmation, item.name)
            for item in fields(confirmation)
            if item.init
        }

        class ForgedConfirmation(ConfirmedRawDeviceWrite):
            pass

        for forged in (
            replace(confirmation),
            replace(confirmation, plan_sha256="0" * 64),
            ConfirmedRawDeviceWrite(**confirmation_values),
            ForgedConfirmation(**confirmation_values),
        ):
            with self.subTest(forged=type(forged).__name__), self.assertRaises(
                RawDevicePlanError,
            ):
                validate_confirmed_raw_device_write(plan, forged)

        other = self.plan(source=replace(self.source))
        with self.assertRaisesRegex(RawDevicePlanError, "another plan"):
            validate_confirmed_raw_device_write(other, confirmation)

        confirmation_mutations = {
            "plan": replace(plan),
            "plan_sha256": "0" * 64,
            "source_sha256": "1" * 64,
            "source_size": confirmation.source_size + 512,
            "requires_exact_target_size": True,
            "required_logical_sector_size": 512,
            "device_identity": confirmation.device_identity[:-1] + ("other",),
            "target_capacity": confirmation.target_capacity + 512,
            "logical_sector_size": 4096,
            "final_verification_requested": (
                not confirmation.final_verification_requested
            ),
            "confirmation_phrase": confirmation.confirmation_phrase + " ",
        }
        for name, mutation in confirmation_mutations.items():
            original = getattr(confirmation, name)
            with self.subTest(confirmation_field=name):
                object.__setattr__(confirmation, name, mutation)
                try:
                    with self.assertRaises(RawDevicePlanError):
                        validate_confirmed_raw_device_write(plan, confirmation)
                finally:
                    object.__setattr__(confirmation, name, original)
                validate_confirmed_raw_device_write(plan, confirmation)

    def test_every_public_plan_field_is_receipt_and_digest_bound(self):
        plan = self.plan()
        mutations = {
            "source_evidence": replace(plan.source_evidence),
            "device": replace(plan.device),
            "disk_sequence": plan.disk_sequence + 1,
            "raw_snapshot_plan_sha256": "2" * 64,
            "snapshot_plan_sha256": "0" * 64,
            "source_sha256": "1" * 64,
            "source_size": plan.source_size + 1,
            "original_source_identity": plan.original_source_identity[:-1] + (0,),
            "workspace_device": plan.workspace_device + 1,
            "requires_exact_target_size": True,
            "required_logical_sector_size": 512,
            "target_capacity": plan.target_capacity + 512,
            "logical_sector_size": 4096,
            "mandatory_preactivation_readback": False,
            "final_verification_requested": False,
            "required_executor_profile": "untrusted/helper/v0",
            "warnings": plan.warnings + ("injected",),
            "confirmation_phrase": plan.confirmation_phrase + " ",
            "plan_sha256": "f" * 64,
        }
        for name, mutation in mutations.items():
            original = getattr(plan, name)
            if mutation == original:
                mutation = not mutation
            with self.subTest(field=name):
                object.__setattr__(plan, name, mutation)
                try:
                    with self.assertRaises(RawDevicePlanError):
                        validate_raw_device_write_plan(plan)
                finally:
                    object.__setattr__(plan, name, original)
                validate_raw_device_write_plan(plan)

    def test_source_evidence_mutation_after_plan_is_detected(self):
        plan = self.plan()
        mutations = {
            "original_changed_ns": self.source.original_changed_ns + 1,
            "requires_exact_target_size": True,
            "required_logical_sector_size": 512,
        }
        for name, mutation in mutations.items():
            original = getattr(self.source, name)
            with self.subTest(source_evidence_field=name):
                object.__setattr__(self.source, name, mutation)
                try:
                    with self.assertRaises(RawDevicePlanError):
                        validate_raw_device_write_plan(plan)
                    with self.assertRaises(RawDevicePlanError):
                        confirm_raw_device_write(plan, plan.confirmation_phrase)
                finally:
                    object.__setattr__(self.source, name, original)
                validate_raw_device_write_plan(plan)

    def test_source_and_workspace_residency_are_rejected_at_every_boundary(self):
        for field_name in ("original_device", "workspace_device"):
            evidence = replace(
                self.source,
                **{field_name: os.makedev(253, 7)},
            )
            self.related_device_numbers |= {os.makedev(253, 7)}
            try:
                with self.subTest(field=field_name), self.assertRaisesRegex(
                    RawDevicePlanError,
                    "resides on the target",
                ):
                    self.plan(source=evidence)
            finally:
                self.related_device_numbers = frozenset({
                    _block_status().st_rdev,
                    os.makedev(65, 145),
                })

        plan = self.plan()
        confirmation = confirm_raw_device_write(plan, plan.confirmation_phrase)
        self.related_device_numbers |= {self.source.workspace_device}
        with self.assertRaisesRegex(RawDevicePlanError, "resides on the target"):
            validate_raw_device_write_plan(plan)
        with self.assertRaisesRegex(RawDevicePlanError, "resides on the target"):
            validate_confirmed_raw_device_write(plan, confirmation)
        self.live_device = replace(self.target, mountpoints=())
        with self.assertRaisesRegex(RawDevicePlanError, "resides on the target"):
            authorize_unmounted_raw_device_write(plan, confirmation)

    def test_block_node_dev_t_and_live_complete_observation_are_rechecked(self):
        plan = self.plan()
        with patch(
            "isopropyl.raw_device._lstat",
            return_value=_block_status(65, 145),
        ), self.assertRaisesRegex(RawDevicePlanError, "device number changed"):
            validate_raw_device_write_plan(plan)
        with patch(
            "isopropyl.raw_device._lstat",
            return_value=SimpleNamespace(st_mode=stat.S_IFREG, st_rdev=0),
        ), self.assertRaisesRegex(RawDevicePlanError, "not a whole-disk block"):
            validate_raw_device_write_plan(plan)

        confirmation = confirm_raw_device_write(plan, plan.confirmation_phrase)
        for change in (
            {"size": self.target.size + 512},
            {"model": "replacement"},
            {"vendor": "replacement"},
            {"transport": "mmc"},
            {"serial": "replacement"},
            {"wwn": "replacement"},
            {"removable": False},
            {"hotplug": False},
            {"read_only": True},
            {"mountpoints": ()},
            {"partitions": ()},
            {"logical_sector_size": 4096},
        ):
            self.live_device = replace(self.target, **change)
            with self.subTest(change=change), self.assertRaisesRegex(
                RawDevicePlanError,
                "changed after discovery",
            ):
                validate_confirmed_raw_device_write(plan, confirmation)
        self.live_device = self.target

    def test_phrase_is_exact_ascii_case_sensitive_and_type_strict(self):
        plan = self.plan()
        for wrong in (
            plan.confirmation_phrase.lower(),
            plan.confirmation_phrase + " ",
            plan.confirmation_phrase + "\n",
            "WRITE RAW /dev/sdy 65:144",
            "",
            None,
            plan.confirmation_phrase.encode(),
            plan.confirmation_phrase.replace("I", "\N{FULLWIDTH LATIN CAPITAL LETTER I}"),
        ):
            with self.subTest(value=wrong), self.assertRaisesRegex(
                RawDevicePlanError,
                "did not match",
            ):
                confirm_raw_device_write(plan, wrong)  # type: ignore[arg-type]

    def test_ready_allows_only_unmount_and_reprobes_same_disk_generation(self):
        plan = self.plan(final_verification=False)
        confirmation = confirm_raw_device_write(plan, plan.confirmation_phrase)
        self.live_device = replace(self.target, mountpoints=())
        ready = authorize_unmounted_raw_device_write(plan, confirmation)
        self.assertIs(type(ready), ReadyRawDeviceWrite)
        self.assertIs(ready.plan, plan)
        self.assertIs(ready.confirmation, confirmation)
        self.assertIs(ready.device, self.live_device)
        self.assertEqual(ready.device.mountpoints, ())
        self.assertEqual(ready.disk_sequence, self.disk_sequence)
        self.assertEqual(len(ready.ready_sha256), 64)
        validate_ready_raw_device_write(plan, confirmation, ready)

        self.live_device = replace(ready.device, serial="replacement")
        with self.assertRaisesRegex(RawDevicePlanError, "changed after discovery"):
            validate_ready_raw_device_write(plan, confirmation, ready)
        self.live_device = ready.device
        self.disk_sequence_probe.return_value = self.disk_sequence + 1
        with self.assertRaisesRegex(RawDevicePlanError, "disk generation changed"):
            validate_ready_raw_device_write(plan, confirmation, ready)

    def test_ready_rejects_target_change_during_unmount_and_diskseq_reuse(self):
        plan = self.plan()
        confirmation = confirm_raw_device_write(plan, plan.confirmation_phrase)
        for field_name, value in {
            "model": "replacement",
            "vendor": "replacement",
            "serial": "replacement",
            "wwn": "replacement",
            "size": TARGET_SIZE + 512,
            "major_minor": "65:145",
            "partitions": (),
            "logical_sector_size": 4096,
            "read_only": True,
            "transport": "mmc",
        }.items():
            self.live_device = replace(
                self.target,
                mountpoints=(),
                **{field_name: value},
            )
            with self.subTest(field=field_name), self.assertRaisesRegex(
                RawDevicePlanError,
                "changed during unmounting",
            ):
                authorize_unmounted_raw_device_write(plan, confirmation)

        self.live_device = self.target
        with self.assertRaisesRegex(RawDevicePlanError, "still has a mounted"):
            authorize_unmounted_raw_device_write(plan, confirmation)

        self.live_device = replace(self.target, mountpoints=())
        self.disk_sequence_probe.return_value = self.disk_sequence + 1
        with self.assertRaisesRegex(RawDevicePlanError, "confirmed plan"):
            authorize_unmounted_raw_device_write(plan, confirmation)

    def test_diskseq_is_bound_before_confirmation_and_ready_is_clone_resistant(self):
        plan = self.plan()
        self.disk_sequence_probe.return_value = self.disk_sequence + 1
        with self.assertRaisesRegex(RawDevicePlanError, "different disk generation"):
            confirm_raw_device_write(plan, plan.confirmation_phrase)

        self.disk_sequence_probe.return_value = self.disk_sequence
        confirmation = confirm_raw_device_write(plan, plan.confirmation_phrase)
        self.live_device = replace(self.target, mountpoints=())
        ready = authorize_unmounted_raw_device_write(plan, confirmation)
        ready_values = {
            item.name: getattr(ready, item.name)
            for item in fields(ready)
            if item.init
        }

        class ForgedReady(ReadyRawDeviceWrite):
            pass

        for forged in (
            replace(ready),
            replace(ready, ready_sha256="0" * 64),
            replace(ready, device=replace(ready.device)),
            ReadyRawDeviceWrite(**ready_values),
            ForgedReady(**ready_values),
        ):
            with self.subTest(forged=type(forged).__name__), self.assertRaises(
                RawDevicePlanError,
            ):
                validate_ready_raw_device_write(plan, confirmation, forged)

        transplanted = replace(ready)
        object.__setattr__(transplanted, "_authorization", ready._authorization)
        with self.assertRaisesRegex(RawDevicePlanError, "forged, cloned"):
            validate_ready_raw_device_write(plan, confirmation, transplanted)

    def test_real_probe_is_bounded_trusted_and_captures_descendants(self):
        child = os.makedev(65, 145)
        mapped = os.makedev(253, 7)
        payload = {
            "blockdevices": [{
                "path": self.target.path,
                "size": self.target.size,
                "type": "disk",
                "rm": self.target.removable,
                "hotplug": self.target.hotplug,
                "tran": self.target.transport,
                "model": self.target.model,
                "vendor": self.target.vendor,
                "serial": self.target.serial,
                "wwn": self.target.wwn,
                "maj:min": self.target.major_minor,
                "mountpoints": list(self.target.mountpoints),
                "ro": self.target.read_only,
                "log-sec": self.target.logical_sector_size,
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
            patch("isopropyl.raw_device._which", return_value="/usr/bin/lsblk") as which,
            patch("isopropyl.raw_device._run", return_value=completed) as run,
        ):
            observed = self.real_probe(self.target.path)
        self.assertEqual(observed.device, self.target)
        self.assertEqual(
            observed.related_device_numbers,
            frozenset({_block_status().st_rdev, child, mapped}),
        )
        self.assertEqual(
            which.call_args.kwargs["path"],
            "/usr/sbin:/usr/bin:/sbin:/bin",
        )
        command = run.call_args.args[0]
        self.assertEqual(command[0], "/usr/bin/lsblk")
        self.assertEqual(command[-1], self.target.path)
        self.assertIs(run.call_args.kwargs["shell"], False)
        self.assertEqual(run.call_args.kwargs["timeout"], 15)

    def test_cancellation_never_mints_plan_confirmation_or_ready_receipt(self):
        def cancel() -> None:
            raise RawDevicePlanCancelled("injected cancellation")

        with self.assertRaisesRegex(RawDevicePlanCancelled, "injected"):
            build_raw_device_write_plan(
                self.source,
                self.target,
                final_verification=True,
                cancel_check=cancel,
            )
        plan = self.plan()
        with self.assertRaisesRegex(RawDevicePlanCancelled, "injected"):
            confirm_raw_device_write(
                plan,
                plan.confirmation_phrase,
                cancel_check=cancel,
            )

        confirmation = confirm_raw_device_write(plan, plan.confirmation_phrase)
        self.live_device = replace(self.target, mountpoints=())
        with self.assertRaisesRegex(RawDevicePlanCancelled, "injected"):
            authorize_unmounted_raw_device_write(
                plan,
                confirmation,
                cancel_check=cancel,
            )

    def test_planning_never_exposes_a_writer_or_write_capable_api(self):
        self.assertFalse(hasattr(raw_device, "RawDeviceWriteRunner"))
        self.assertFalse(hasattr(raw_device, "execute_helper_transaction"))
        with (
            patch.object(
                subprocess,
                "Popen",
                side_effect=AssertionError("planning must not spawn a process"),
            ) as popen,
            patch.object(
                os,
                "write",
                side_effect=AssertionError("planning must not write"),
            ) as write,
            patch.object(
                os,
                "pwrite",
                side_effect=AssertionError("planning must not pwrite"),
            ) as pwrite,
        ):
            plan = self.plan()
            confirmation = confirm_raw_device_write(
                plan,
                plan.confirmation_phrase,
            )
            validate_confirmed_raw_device_write(plan, confirmation)
        popen.assert_not_called()
        write.assert_not_called()
        pwrite.assert_not_called()


if __name__ == "__main__":
    unittest.main()
