from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import stat
import tempfile
import unittest
from dataclasses import fields, replace
from types import SimpleNamespace
from unittest.mock import patch

import isopropyl.windows_device as windows_device
from isopropyl.devices import Device
from isopropyl.syslinux_device import SyslinuxDevicePlanError
from isopropyl.windows_device import (
    ConfirmedWindowsDeviceWrite,
    ReadyWindowsDeviceWrite,
    REQUIRED_EXECUTOR_PROFILE,
    WINDOWS_IMAGE_PROFILE,
    WindowsDevicePlanError,
    WindowsDeviceWritePlan,
    authorize_unmounted_windows_device_write,
    build_windows_device_write_plan,
    confirm_windows_device_write,
    validate_confirmed_windows_device_write,
    validate_ready_windows_device_write,
    validate_windows_device_write_plan,
)
from tests.test_windows_iso_fat32 import IMAGE_SIZE, WindowsIsoFat32Tests


def _device(**changes: object) -> Device:
    values: dict[str, object] = {
        "path": "/dev/sdz",
        "size": IMAGE_SIZE,
        "model": "Windows test flash drive",
        "vendor": "ISOpropyl",
        "transport": "usb",
        "serial": "WINDOWS-123",
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


def _block_status() -> SimpleNamespace:
    return SimpleNamespace(
        st_mode=stat.S_IFBLK | 0o600,
        st_rdev=os.makedev(65, 144),
    )


class WindowsDevicePlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.composite, _workspace = WindowsIsoFat32Tests().build_plan(
            self.directory.name,
        )
        self.target = _device()
        self.live = self.target
        self.sequence = 731_337
        self.related = frozenset({_block_status().st_rdev})
        patches = (
            patch("isopropyl.windows_device._validate_target_node", return_value=_block_status()),
            patch(
                "isopropyl.windows_device._validate_live_target",
                side_effect=lambda _device, _status: windows_device._LiveTargetObservation(
                    self.live, self.related,
                ),
            ),
            patch(
                "isopropyl.windows_device._probe_live_target",
                side_effect=lambda _path: windows_device._LiveTargetObservation(
                    self.live, self.related,
                ),
            ),
            patch(
                "isopropyl.windows_device._read_disk_sequence",
                side_effect=lambda _major_minor: self.sequence,
            ),
        )
        for active in patches:
            active.start()
            self.addCleanup(active.stop)

    def plan(self, device: Device | None = None) -> WindowsDeviceWritePlan:
        return build_windows_device_write_plan(self.composite, device or self.target)

    def test_plan_confirmation_and_ready_receipts_bind_the_exact_target(self) -> None:
        plan = self.plan()
        self.assertIs(type(plan), WindowsDeviceWritePlan)
        self.assertEqual(plan.image_size, IMAGE_SIZE)
        self.assertEqual(plan.image_profile, WINDOWS_IMAGE_PROFILE)
        self.assertEqual(plan.required_executor_profile, REQUIRED_EXECUTOR_PROFILE)
        self.assertEqual(plan.confirmation_phrase, "WRITE WINDOWS DUAL /dev/sdz 65:144")
        self.assertTrue(plan.mandatory_readback)
        self.assertEqual(plan.composite_plan_sha256, self.composite.plan_sha256)
        validate_windows_device_write_plan(plan)

        confirmation = confirm_windows_device_write(plan, plan.confirmation_phrase)
        self.assertIs(type(confirmation), ConfirmedWindowsDeviceWrite)
        validate_confirmed_windows_device_write(plan, confirmation)
        self.live = replace(self.target, mountpoints=())
        ready = authorize_unmounted_windows_device_write(plan, confirmation)
        self.assertIs(type(ready), ReadyWindowsDeviceWrite)
        validate_ready_windows_device_write(plan, confirmation, ready)

    def test_confirmation_is_distinct_exact_and_case_sensitive(self) -> None:
        plan = self.plan()
        for wrong in (
            "WRITE DUAL /dev/sdz 65:144",
            plan.confirmation_phrase.lower(),
            plan.confirmation_phrase + " ",
            "",
        ):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(
                WindowsDevicePlanError, "did not match",
            ):
                confirm_windows_device_write(plan, wrong)

    def test_dataclass_clones_and_modified_receipts_have_no_authority(self) -> None:
        plan = self.plan()
        values = {
            item.name: getattr(plan, item.name)
            for item in fields(plan)
            if item.init
        }
        for forged in (
            replace(plan),
            replace(plan, image_profile="other"),
            WindowsDeviceWritePlan(**values),
        ):
            with self.subTest(forged=forged.image_profile), self.assertRaises(
                WindowsDevicePlanError,
            ):
                validate_windows_device_write_plan(forged)

        confirmation = confirm_windows_device_write(plan, plan.confirmation_phrase)
        with self.assertRaises(WindowsDevicePlanError):
            validate_confirmed_windows_device_write(plan, replace(confirmation))

    def test_capacity_sector_removability_generation_and_mount_state_fail_closed(self) -> None:
        for target in (
            _device(size=IMAGE_SIZE + 512),
            _device(logical_sector_size=4096),
            _device(removable=False),
        ):
            with self.subTest(target=target), self.assertRaises(WindowsDevicePlanError):
                self.plan(target)

        plan = self.plan()
        confirmation = confirm_windows_device_write(plan, plan.confirmation_phrase)
        with self.assertRaisesRegex(WindowsDevicePlanError, "mounted"):
            authorize_unmounted_windows_device_write(plan, confirmation)
        self.live = replace(self.target, mountpoints=())
        self.sequence += 1
        with self.assertRaisesRegex(WindowsDevicePlanError, "generation"):
            authorize_unmounted_windows_device_write(plan, confirmation)

    def test_post_unmount_syslinux_probe_errors_do_not_escape_windows_api(self) -> None:
        plan = self.plan()
        confirmation = confirm_windows_device_write(plan, plan.confirmation_phrase)
        with patch(
            "isopropyl.windows_device._probe_live_target",
            side_effect=SyslinuxDevicePlanError("probe failed"),
        ), self.assertRaisesRegex(WindowsDevicePlanError, "probe failed"):
            authorize_unmounted_windows_device_write(plan, confirmation)


if __name__ == "__main__":
    unittest.main()
