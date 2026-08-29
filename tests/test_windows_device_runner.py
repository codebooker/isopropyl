from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import tempfile
import unittest
import xml.etree.ElementTree as ET
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import isopropyl.syslinux_device_helper as protocol
import tests.test_syslinux_device_runner as syslinux_fixtures
from isopropyl.windows_device_runner import (
    POLICY_ACTION,
    POLICY_DESCRIPTION,
    POLICY_MESSAGE,
    WindowsDeviceRunError,
    WindowsDeviceWriteRunner,
    WindowsHelperInstallation,
    _validate_prepared,
)
from isopropyl.windows_iso_fat32 import prepare_windows_iso_fat32
from tests.test_windows_iso_fat32 import WindowsIsoFat32Tests


ROOT = Path(__file__).resolve().parents[1]
REQUEST_ID = bytes(range(16))


class WindowsDeviceRunnerTests(unittest.TestCase):
    def test_inherited_broker_uses_windows_magic_operation_and_result_profile(self) -> None:
        factory = syslinux_fixtures.PopenFactory()
        runner = WindowsDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
        )
        plan = SimpleNamespace(
            image_size=syslinux_fixtures.IMAGE_SIZE,
            logical_sector_size=512,
            disk_signature=syslinux_fixtures.DISK_SIGNATURE,
            volume_id=syslinux_fixtures.VOLUME_ID,
            plan_sha256="11" * 32,
            composite_plan_sha256="22" * 32,
            image_profile="windows-test-profile",
        )
        ready = SimpleNamespace(
            ready_sha256="33" * 32,
            disk_sequence=syslinux_fixtures.DISK_SEQUENCE,
            device=SimpleNamespace(path="/dev/sdz", major_minor="8:240"),
        )
        prepared = syslinux_fixtures.FakePrepared()
        prepared_result = SimpleNamespace(
            final_image_sha256=syslinux_fixtures.IMAGE_SHA256,
        )
        installation = WindowsHelperInstallation(
            syslinux_fixtures.PKEXEC_PATH,
            syslinux_fixtures.HELPER_PATH,
            syslinux_fixtures.HELPER_SCRIPT_PATH,
            "/usr/share/polkit-1/actions/io.github.codebooker.isopropyl.windows-write.policy",
        )
        # The generic fake server exercises the exact broker state machine;
        # use the Windows profile magic for both peers in this test process.
        with patch.object(
            protocol, "PROTOCOL_MAGIC", protocol.WINDOWS_PROTOCOL_MAGIC,
        ):
            result = runner._invoke_helper(
                installation, plan, ready, prepared, prepared_result,
                lambda *_update: None,
            )
        self.assertEqual(result.helper_profile, protocol.WINDOWS_HELPER_PROFILE)
        self.assertEqual(result.image_sha256, syslinux_fixtures.IMAGE_SHA256)
        self.assertTrue(result.mandatory_readback)
        command, kwargs = factory.calls[0]
        self.assertEqual(command[-1], protocol.WINDOWS_OPERATION)
        self.assertFalse(kwargs["shell"])
        self.assertNotIn("pass_fds", kwargs)
        self.assertEqual(
            prepared.sent_packets[0][:len(protocol.WINDOWS_PROTOCOL_MAGIC)],
            protocol.WINDOWS_PROTOCOL_MAGIC,
        )

    def test_prepared_result_binds_every_device_relevant_composite_witness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            composite, _workspace = WindowsIsoFat32Tests().build_plan(directory)
            plan = SimpleNamespace(
                composite_plan_sha256=composite.plan_sha256,
                private_plan_sha256=composite.private_plan.plan_sha256,
                source_manifest_sha256=composite.source_manifest_sha256,
                disk_signature=composite.private_plan.disk_signature,
                volume_id=composite.private_plan.volume_id,
                image_size=composite.private_plan.geometry.image_size,
            )
            with prepare_windows_iso_fat32(composite) as prepared:
                result = _validate_prepared(plan, prepared)
                self.assertEqual(result.plan_sha256, composite.plan_sha256)
                original = prepared._result
                prepared._result = replace(
                    original,
                    final_image_sha256=original.unpatched_image_sha256,
                )
                with self.assertRaisesRegex(WindowsDeviceRunError, "does not match"):
                    _validate_prepared(plan, prepared)

    def test_policy_is_a_separate_admin_only_exact_argv_endpoint(self) -> None:
        path = ROOT / "data/io.github.codebooker.isopropyl.windows-write.policy"
        root = ET.parse(path).getroot()
        actions = root.findall("action")
        self.assertEqual(len(actions), 1)
        action = actions[0]
        self.assertEqual(action.get("id"), POLICY_ACTION)
        self.assertEqual(action.findtext("description"), POLICY_DESCRIPTION)
        self.assertEqual(action.findtext("message"), POLICY_MESSAGE)
        defaults = action.find("defaults")
        self.assertIsNotNone(defaults)
        self.assertEqual(defaults.findtext("allow_any"), "no")
        self.assertEqual(defaults.findtext("allow_inactive"), "no")
        self.assertEqual(defaults.findtext("allow_active"), "auth_admin")
        annotations = {
            node.get("key"): (node.text or "").strip()
            for node in action.findall("annotate")
        }
        self.assertEqual(
            annotations["org.freedesktop.policykit.exec.argv1"],
            protocol.WINDOWS_OPERATION,
        )
        self.assertNotEqual(protocol.WINDOWS_OPERATION, protocol.OPERATION)


if __name__ == "__main__":
    unittest.main()
