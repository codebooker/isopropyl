from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import QApplication, QDialog, QLabel, QLineEdit, QMessageBox, QPushButton

import isopropyl.app as app_module
from isopropyl.app import GrubRescuePreparationToken, Window
from isopropyl.devices import Device
from isopropyl.grub_rescue_device import GrubRescueDeviceWritePlan
from isopropyl.grub_rescue_device_runner import GrubRescueDeviceWriteResult
from isopropyl.grub_rescue_workflow import GrubRescueWorkflowState


class ImmediateThread:
    def __init__(self, *, target, daemon: bool) -> None:
        self.target = target
        self.daemon = daemon

    def start(self) -> None:
        self.target()


def removable_device(**changes: object) -> Device:
    value = Device(
        "/dev/sdz", 8 * 1024**3, "Test Drive", "ISOpropyl", "usb", "SERIAL",
        "", "65:144", True, True, False, (), (), 512,
    )
    return replace(value, **changes)


def plan_for(device: Device) -> GrubRescueDeviceWritePlan:
    digest = "ab" * 32
    return GrubRescueDeviceWritePlan(
        Mock(), Mock(), Mock(), device, 91234,
        "10" * 32, "20" * 32, digest, "30" * 32, "40" * 32,
        device.size, 0x12345678, 0x87654321, 512,
        "grub-2.14/bios/rescue-prompt/fat32-mbr/v1", True, True,
        "io.github.codebooker.isopropyl/grub-2.14-rescue-device-helper/v1",
        ("Everything is erased",),
        f"WRITE GRUB RESCUE {device.path} {device.major_minor}",
        "50" * 32,
    )


def result_for(plan: GrubRescueDeviceWritePlan) -> GrubRescueDeviceWriteResult:
    return GrubRescueDeviceWriteResult(
        plan.plan_sha256, "60" * 32, plan.rescue_plan_sha256,
        plan.private_plan_sha256, "0" * 32, plan.device.path,
        plan.device.major_minor, plan.disk_sequence, plan.image_size,
        plan.final_image_sha256, plan.final_fat_manifest_sha256,
        plan.disk_signature, plan.volume_id, 512, plan.image_profile,
        "intentional-rescue-prompt",
        plan.required_executor_profile, True, True, True, False,
    )


class GrubRescueAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.settings_home = tempfile.TemporaryDirectory()
        settings = QSettings(
            str(Path(self.settings_home.name) / "settings.ini"),
            QSettings.Format.IniFormat,
        )
        with (
            patch("isopropyl.app.QSettings", return_value=settings),
            patch("isopropyl.app.list_devices", return_value=[]),
        ):
            self.window = Window()
        self.window.device_refresh_generation += 1
        self.window.device_refresh_busy = False
        self.select(removable_device())

    def tearDown(self) -> None:
        self.window.grub_rescue_workflow = None
        self.window.grub_rescue_token = None
        self.window.close()
        self.window.deleteLater()
        self.application.processEvents()
        self.settings_home.cleanup()

    def select(self, device: Device) -> None:
        self.window.devices = [device]
        self.window.device_combo.clear()
        self.window.device_combo.addItem(device.label)

    def test_exact_developer_gate_blocks_before_workspace_or_workflow(self) -> None:
        for value in (None, "0", "true", "01", " 1"):
            environment = {} if value is None else {
                "ISOPROPYL_EXPERIMENTAL_GRUB_RESCUE": value,
            }
            with (
                patch.dict(os.environ, environment, clear=True),
                patch("isopropyl.app.tempfile.TemporaryDirectory") as temporary,
                patch("isopropyl.app.GrubRescueWriteWorkflow") as workflow,
                patch("isopropyl.app.QMessageBox.information"),
            ):
                self.window.create_grub_rescue_media()
            temporary.assert_not_called()
            workflow.assert_not_called()
        with patch.dict(
            os.environ, {"ISOPROPYL_EXPERIMENTAL_GRUB_RESCUE": "1"}, clear=True,
        ):
            self.assertTrue(self.window.grub_rescue_developer_enabled())

    def test_boot_media_chooser_has_both_truthful_labels_and_gates_grub(self) -> None:
        observed: list[tuple[set[str], bool]] = []

        def inspect(dialog: QDialog) -> QDialog.DialogCode:
            buttons = dialog.findChildren(QPushButton)
            labels = {button.text() for button in buttons}
            grub = next(button for button in buttons if "GRUB 2.14" in button.text())
            observed.append((labels, grub.isEnabled()))
            return QDialog.DialogCode.Rejected

        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(QDialog, "exec", inspect),
        ):
            self.window.choose_boot_media()
        with (
            patch.dict(
                os.environ,
                {"ISOPROPYL_EXPERIMENTAL_GRUB_RESCUE": "1"},
                clear=True,
            ),
            patch.object(QDialog, "exec", inspect),
        ):
            self.window.choose_boot_media()
        expected = {
            "Create multi-architecture UEFI Shell…",
            "Create GRUB 2.14 blank BIOS rescue media…",
        }
        self.assertTrue(expected.issubset(observed[0][0]))
        self.assertFalse(observed[0][1])
        self.assertTrue(observed[1][1])
        self.assertEqual(self.window.boot_media_button.text(), "Create boot media…")

    def test_declining_download_disclosure_creates_no_private_work(self) -> None:
        with (
            patch.dict(
                os.environ,
                {"ISOPROPYL_EXPERIMENTAL_GRUB_RESCUE": "1"},
                clear=True,
            ),
            patch(
                "isopropyl.app.QMessageBox.question",
                return_value=QMessageBox.StandardButton.Cancel,
            ) as question,
            patch("isopropyl.app.tempfile.TemporaryDirectory") as temporary,
            patch("isopropyl.app.GrubRescueWriteWorkflow") as workflow,
        ):
            self.window.create_grub_rescue_media()
        disclosure = question.call_args.args[2]
        for phrase in (
            "boot.img", "core.img", "never executed on Linux",
            "Source reproduction has not been verified or claimed",
            "grub rescue>", "not an operating system", "normal.mod", "UEFI",
        ):
            self.assertIn(phrase, disclosure)
        temporary.assert_not_called()
        workflow.assert_not_called()
        self.assertFalse(self.window.operation_active)

    def test_ineligible_targets_are_rejected_before_consent(self) -> None:
        invalid = (
            removable_device(removable=False),
            removable_device(transport="nvme"),
            removable_device(read_only=True),
            removable_device(logical_sector_size=4096),
            removable_device(size=129 * 1024**3),
        )
        for candidate in invalid:
            with self.subTest(candidate=candidate):
                self.select(candidate)
                with (
                    patch.dict(
                        os.environ,
                        {"ISOPROPYL_EXPERIMENTAL_GRUB_RESCUE": "1"},
                        clear=True,
                    ),
                    patch("isopropyl.app.QMessageBox.warning") as warning,
                    patch("isopropyl.app.QMessageBox.question") as question,
                    patch("isopropyl.app.tempfile.TemporaryDirectory") as temporary,
                ):
                    self.window.create_grub_rescue_media()
                warning.assert_called_once()
                question.assert_not_called()
                temporary.assert_not_called()

    def test_yes_starts_exact_workflow_prepare_in_background(self) -> None:
        selected = self.window.devices[0]
        plan = plan_for(selected)
        workspace = Mock()
        workflow = Mock()
        workflow.device = selected
        workflow.plan = plan
        workflow.state = GrubRescueWorkflowState.PREPARED
        workflow.prepare.return_value = plan
        confirmer = Mock()
        self.window._confirm_and_write_grub_rescue = confirmer
        with (
            patch.dict(
                os.environ,
                {"ISOPROPYL_EXPERIMENTAL_GRUB_RESCUE": "1"},
                clear=True,
            ),
            patch(
                "isopropyl.app.QMessageBox.question",
                return_value=QMessageBox.StandardButton.Yes,
            ),
            patch("isopropyl.app.tempfile.TemporaryDirectory", return_value=workspace),
            patch("isopropyl.app.GrubRescueWriteWorkflow", return_value=workflow) as factory,
            patch("isopropyl.app.threading.Thread", ImmediateThread),
        ):
            self.window.create_grub_rescue_media()
        factory.assert_called_once_with(selected, workspace)
        workflow.prepare.assert_called_once()
        self.assertTrue(callable(workflow.prepare.call_args.args[0]))
        confirmer.assert_called_once_with(self.window.grub_rescue_token, plan)
        self.assertIs(self.window.grub_rescue_workflow, workflow)

    def test_stale_preparation_closes_only_stale_workflow(self) -> None:
        stale_workflow = Mock()
        current_workflow = Mock()
        stale = GrubRescuePreparationToken(stale_workflow, self.window.devices[0].identity)
        current = GrubRescuePreparationToken(current_workflow, self.window.devices[0].identity)
        self.window.grub_rescue_workflow = current_workflow
        self.window.grub_rescue_token = current
        self.window.on_grub_rescue_preparation_finished(stale, Mock())
        stale_workflow.close.assert_called_once_with()
        current_workflow.close.assert_not_called()
        self.assertIs(self.window.grub_rescue_workflow, current_workflow)
        self.assertIs(self.window.grub_rescue_token, current)

    def test_final_disclosure_binds_target_plan_phrase_and_reject_cleans_up(self) -> None:
        device = self.window.devices[0]
        plan = plan_for(device)
        workflow = Mock()
        token = GrubRescuePreparationToken(workflow, device.identity)
        self.window.grub_rescue_workflow = workflow
        self.window.grub_rescue_token = token
        captured: dict[str, str] = {}

        def inspect(dialog: QDialog) -> QDialog.DialogCode:
            disclosure = dialog.findChild(QLabel, "grubRescueDisclosure")
            phrase = dialog.findChild(QLineEdit, "grubRescueConfirmationPhrase")
            assert disclosure is not None and phrase is not None
            captured["disclosure"] = disclosure.text()
            captured["placeholder"] = phrase.placeholderText()
            return QDialog.DialogCode.Rejected

        with patch.object(QDialog, "exec", inspect):
            self.window._confirm_and_write_grub_rescue(token, plan)
        text = captured["disclosure"]
        for phrase in (
            device.model, device.serial, device.path, device.major_minor,
            str(plan.disk_sequence), str(plan.image_size), plan.final_image_sha256,
            "LBA 2048", "BIOS-only", "mandatory complete whole-device",
            "QEMU TCG/SeaBIOS", "physical-device boot validation remains pending",
            "grub rescue>", "normal.mod", "no OS",
        ):
            self.assertIn(phrase, text)
        self.assertEqual(captured["placeholder"], plan.confirmation_phrase)
        workflow.close.assert_called_once_with()
        self.assertIsNone(self.window.grub_rescue_workflow)
        self.assertFalse(self.window.operation_active)

    def test_cancel_and_generic_finish_cleanup_honor_committed_state(self) -> None:
        workflow = Mock()
        workflow.committed = True
        dialog = Mock()
        token = GrubRescuePreparationToken(workflow, self.window.devices[0].identity)
        self.window.grub_rescue_workflow = workflow
        self.window.grub_rescue_token = token
        self.window.grub_rescue_confirmation_dialog = dialog
        self.window.set_busy(True)
        self.window.cancel()
        workflow.cancel.assert_called_once_with()
        dialog.reject.assert_called_once_with()
        self.assertIn("Finishing the committed GRUB rescue write safely", self.window.status.text())
        self.assertFalse(self.window.cancel_button.isEnabled())
        with (
            patch("isopropyl.app.QMessageBox.critical"),
            patch.object(self.window, "refresh_devices"),
        ):
            self.window.on_finished(False, "committed transaction failed")
        workflow.close.assert_called_once_with()
        self.assertIsNone(self.window.grub_rescue_workflow)
        self.assertIsNone(self.window.grub_rescue_token)

    def test_success_message_is_bound_and_rescue_only(self) -> None:
        plan = plan_for(self.window.devices[0])
        result = result_for(plan)
        workflow = Mock()
        workflow.plan = plan
        workflow.result = result
        workflow.state = GrubRescueWorkflowState.COMPLETED
        token = GrubRescuePreparationToken(workflow, plan.device.identity)
        self.window.grub_rescue_workflow = workflow
        self.window.grub_rescue_token = token
        observed: list[tuple[bool, str]] = []
        self.window.bridge.finished.disconnect(self.window.on_finished)
        self.window.bridge.finished.connect(
            lambda success, message: observed.append((success, message)),
        )
        self.window.on_grub_rescue_execution_finished(token, result)
        self.assertEqual(len(observed), 1)
        success, message = observed[0]
        self.assertTrue(success)
        for phrase in (
            plan.device.path, plan.final_image_sha256, "grub rescue>",
            "no OS", "normal.mod", "UEFI loader", "whole-device SHA-256",
            "physical-device boot validation remains pending",
        ):
            self.assertIn(phrase, message)

    def test_committed_failure_disables_cancel_and_reports_unknown_media(self) -> None:
        plan = plan_for(self.window.devices[0])
        workflow = Mock()
        workflow.committed = True
        workflow.plan = plan
        token = GrubRescuePreparationToken(workflow, plan.device.identity)
        self.window.grub_rescue_workflow = workflow
        self.window.grub_rescue_token = token
        self.window.set_busy(True)
        observed: list[tuple[bool, str]] = []
        self.window.bridge.finished.disconnect(self.window.on_finished)
        self.window.bridge.finished.connect(
            lambda success, message: observed.append((success, message)),
        )

        self.window.on_progress(
            0,
            0,
            "GRUB rescue device transaction · waiting-for-committed-helper-recovery",
        )
        self.assertFalse(self.window.cancel_button.isEnabled())
        self.window.on_grub_rescue_execution_finished(
            token,
            RuntimeError("authenticated result channel was lost"),
        )

        self.assertEqual(len(observed), 1)
        success, message = observed[0]
        self.assertFalse(success)
        for phrase in (
            "privileged helper has now exited",
            "target state is unknown",
            "remove and reinsert it",
            "rewrite or restore the entire device",
            "authenticated result channel was lost",
        ):
            self.assertIn(phrase, message)

    def test_app_contains_no_generic_grub_writer_fallback(self) -> None:
        source = Path(app_module.__file__).read_text(encoding="utf-8")
        grub_section = source[
            source.index("def create_grub_rescue_media"):
            source.index("def create_uefi_shell_media")
        ]
        self.assertIn("GrubRescueWriteWorkflow", grub_section)
        self.assertNotIn("ConstructedMediaExecutor", grub_section)
        self.assertNotIn("ImageWriter", grub_section)


if __name__ == "__main__":
    unittest.main()
