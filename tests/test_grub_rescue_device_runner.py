from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import array
import io
import os
import socket
import subprocess
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import isopropyl.grub_rescue as rescue_module
import isopropyl.grub_rescue_device_runner as runner_module
import isopropyl.syslinux_device_helper as protocol
from isopropyl.grub_rescue import GrubRescueResult, PreparedGrubRescueImage
from isopropyl.grub_rescue_device_runner import (
    HELPER_PATH,
    HELPER_SCRIPT_PATH,
    PKEXEC_PATH,
    POLICY_ACTION,
    POLICY_DESCRIPTION,
    POLICY_MESSAGE,
    POLICY_PATH,
    GrubRescueDeviceHelperUnavailable,
    GrubRescueDeviceRunCancelled,
    GrubRescueDeviceRunError,
    GrubRescueDeviceWriteRunner,
    HelperInstallation,
)


REQUEST_ID = bytes(range(16))
IMAGE_SIZE = 2 * 1024 * 1024
IMAGE_SHA256 = "ab" * 32
DISK_SIGNATURE = 0x12345678
VOLUME_ID = 0x87654321
DISK_SEQUENCE = 982_451_653


class FakePrepared:
    def __init__(self) -> None:
        self.sent_packets: list[bytes] = []

    def _send_to_privileged_helper(
        self,
        channel: socket.socket,
        packet: bytes,
        *,
        cancel_check=None,
    ) -> None:
        if cancel_check is not None:
            cancel_check()
        self.sent_packets.append(packet)
        with tempfile.TemporaryFile() as source:
            source.write(b"source")
            source.flush()
            rights = array.array("i", [source.fileno()])
            sent = channel.sendmsg(
                [packet],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
            )
        if sent != len(packet):
            raise AssertionError("short test protocol send")


class FakeHelperProcess:
    def __init__(self, child_fd: int, *, mode: str = "success") -> None:
        self.mode = mode
        self.channel = socket.socket(fileno=os.dup(child_fd))
        self.stderr = io.BytesIO()
        self.returncode: int | None = None
        self.terminated = 0
        self.killed = 0
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _send(self, packet: bytes) -> None:
        self.channel.send(packet)

    def _serve(self) -> None:
        received: list[int] = []
        try:
            self._send(protocol._HEADER.pack(
                protocol.GRUB_RESCUE_PROTOCOL_MAGIC,
                protocol.PROTOCOL_VERSION,
                protocol.PACKET_READY,
                0,
            ))
            packet, ancillary, flags, _address = self.channel.recvmsg(
                protocol.MAX_PROTOCOL_PACKET,
                socket.CMSG_SPACE(array.array("i").itemsize),
            )
            if flags:
                raise AssertionError(flags)
            for level, kind, value in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    descriptors = array.array("i")
                    descriptors.frombytes(value)
                    received.extend(descriptors)
            if len(received) != 1:
                raise AssertionError(received)
            (
                magic,
                version,
                kind,
                reserved,
                request_id,
                major_number,
                minor_number,
                disk_sequence,
                size,
                sector_size,
                disk_signature,
                volume_id,
                digest,
            ) = protocol._REQUEST_PACKET.unpack(packet)
            if (magic, version, kind, reserved) != (
                protocol.GRUB_RESCUE_PROTOCOL_MAGIC,
                protocol.PROTOCOL_VERSION,
                protocol.PACKET_REQUEST,
                0,
            ):
                raise AssertionError("bad GRUB request")
            if self.mode == "stall-precommit":
                self.channel.recv(protocol.MAX_PROTOCOL_PACKET)
                self.returncode = 5
                return
            phases = list(protocol.PHASE_CODES)
            if self.mode == "out-of-order":
                phases = ["writing", "source-validation"]
            prepared_sent = False
            for phase in phases:
                if phase == "writing" and not prepared_sent and self.mode != "out-of-order":
                    self._send(protocol._CONTROL_PACKET.pack(
                        protocol.GRUB_RESCUE_PROTOCOL_MAGIC,
                        protocol.PROTOCOL_VERSION,
                        protocol.PACKET_PREPARED,
                        0,
                        request_id,
                    ))
                    prepared_sent = True
                    decision = self.channel.recv(protocol.MAX_PROTOCOL_PACKET)
                    control = protocol._CONTROL_PACKET.unpack(decision)
                    if (
                        control[0] != protocol.GRUB_RESCUE_PROTOCOL_MAGIC
                        or control[1] != protocol.PROTOCOL_VERSION
                        or control[3] != 0
                        or control[4] != request_id
                        or control[2]
                        not in {protocol.PACKET_COMMIT, protocol.PACKET_CANCEL}
                    ):
                        raise AssertionError("bad GRUB control decision")
                    if control[2] == protocol.PACKET_CANCEL:
                        self.returncode = 7
                        return
                    self._send(protocol._MUTATION_PACKET.pack(
                        protocol.GRUB_RESCUE_PROTOCOL_MAGIC,
                        protocol.PROTOCOL_VERSION,
                        protocol.PACKET_MUTATION_STARTED,
                        0,
                        request_id,
                    ))
                total = size - 512 if phase == "preactivation-readback" else size
                for done in (0, total):
                    self._send(protocol._PROGRESS_PACKET.pack(
                        protocol.GRUB_RESCUE_PROTOCOL_MAGIC,
                        protocol.PROTOCOL_VERSION,
                        protocol.PACKET_PROGRESS,
                        0,
                        request_id,
                        protocol.PHASE_CODES[phase],
                        done,
                        total,
                    ))
            if self.mode == "post-mutation-error":
                self.stderr = io.BytesIO(b"injected GRUB helper error")
                self.returncode = 4
                return
            result_digest = b"\0" * 32 if self.mode == "wrong-digest" else digest
            self._send(protocol._SUCCESS_PACKET.pack(
                protocol.GRUB_RESCUE_PROTOCOL_MAGIC,
                protocol.PROTOCOL_VERSION,
                protocol.PACKET_SUCCESS,
                0,
                request_id,
                major_number,
                minor_number,
                disk_sequence,
                size,
                sector_size,
                disk_signature,
                volume_id,
                digest,
                digest,
                result_digest,
            ))
            self.returncode = 0
        except BaseException as error:
            self.stderr = io.BytesIO(str(error).encode())
            self.returncode = 5
        finally:
            for descriptor in received:
                os.close(descriptor)
            try:
                self.channel.close()
            except OSError:
                pass
            if self.returncode is None:
                self.returncode = 5
            self.done.set()

    def poll(self):
        return self.returncode if self.done.is_set() else None

    def wait(self, timeout=None):
        if not self.done.wait(timeout):
            raise subprocess.TimeoutExpired("fake-grub-helper", timeout)
        return self.returncode

    def terminate(self) -> None:
        self.terminated += 1
        if self.mode == "post-mutation-error":
            return
        try:
            self.channel.close()
        except OSError:
            pass

    def kill(self) -> None:
        self.killed += 1
        self.terminate()


class PopenFactory:
    def __init__(self, mode: str = "success") -> None:
        self.mode = mode
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.processes: list[FakeHelperProcess] = []

    def __call__(self, command, **kwargs):
        self.calls.append((list(command), dict(kwargs)))
        process = FakeHelperProcess(kwargs["stdin"], mode=self.mode)
        self.processes.append(process)
        return process


def helper_inputs():
    plan = SimpleNamespace(
        image_size=IMAGE_SIZE,
        logical_sector_size=512,
        disk_signature=DISK_SIGNATURE,
        volume_id=VOLUME_ID,
        plan_sha256="11" * 32,
        final_image_sha256=IMAGE_SHA256,
    )
    ready = SimpleNamespace(
        ready_sha256="22" * 32,
        disk_sequence=DISK_SEQUENCE,
        device=SimpleNamespace(path="/dev/sdz", major_minor="8:240"),
    )
    prepared = FakePrepared()
    prepared_result = SimpleNamespace(
        plan_sha256="33" * 32,
        private_plan_sha256="44" * 32,
        final_image_sha256=IMAGE_SHA256,
        final_fat_manifest_sha256="55" * 32,
        profile=rescue_module.PROFILE_ID,
        result_semantics=rescue_module.RESULT_SEMANTICS,
    )
    installation = HelperInstallation(
        PKEXEC_PATH,
        HELPER_PATH,
        HELPER_SCRIPT_PATH,
        POLICY_PATH,
    )
    return plan, ready, prepared, prepared_result, installation


class ProtocolRunnerTests(unittest.TestCase):
    def test_committed_helper_wait_keeps_quarantine_until_process_exit(self):
        runner = GrubRescueDeviceWriteRunner()
        process = Mock()
        process.poll.side_effect = (None, None, None, None, 0)
        process.wait.side_effect = (
            subprocess.TimeoutExpired("fake-grub-helper", 300),
            OSError("temporary wait failure"),
            0,
        )
        updates: list[tuple[str, str, int, int]] = []

        runner._wait_for_committed_helper(
            process,
            lambda stage, path, done, total: updates.append(
                (stage, path, done, total),
            ),
        )

        self.assertEqual(process.wait.call_count, 3)
        self.assertEqual(
            updates,
            [
                ("waiting-for-committed-helper-recovery", "", 0, 0),
                ("waiting-for-committed-helper-recovery", "", 0, 0),
                ("waiting-for-committed-helper-recovery", "", 0, 0),
            ],
        )

    def test_exact_grub_operation_fd_transfer_and_bound_success(self):
        factory = PopenFactory()
        runner = GrubRescueDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
        )
        plan, ready, prepared, prepared_result, installation = helper_inputs()
        updates = []
        result = runner._invoke_helper(
            installation,
            plan,
            ready,
            prepared,
            prepared_result,
            lambda *update: updates.append(update),
        )
        self.assertTrue(runner.committed)
        self.assertEqual(result.request_id, REQUEST_ID.hex())
        self.assertEqual(result.image_sha256, IMAGE_SHA256)
        self.assertTrue(result.mandatory_readback)
        self.assertFalse(result.cancellation_deferred)
        self.assertEqual(len(prepared.sent_packets), 1)
        command, kwargs = factory.calls[0]
        self.assertEqual(command, [
            PKEXEC_PATH,
            "--disable-internal-agent",
            HELPER_PATH,
            protocol.GRUB_RESCUE_OPERATION,
        ])
        self.assertTrue(kwargs["close_fds"])
        self.assertFalse(kwargs["shell"])
        self.assertNotIn("pass_fds", kwargs)
        self.assertEqual({item[0] for item in updates}, set(protocol.PHASE_CODES))

    def test_wrong_digest_and_out_of_order_progress_are_rejected(self):
        for mode, message in (
            ("wrong-digest", "does not match"),
            ("out-of-order", "sequence"),
        ):
            factory = PopenFactory(mode)
            runner = GrubRescueDeviceWriteRunner(
                popen=factory,
                request_id=lambda _size: REQUEST_ID,
            )
            plan, ready, prepared, prepared_result, installation = helper_inputs()
            with self.subTest(mode=mode), self.assertRaisesRegex(
                GrubRescueDeviceRunError,
                message,
            ):
                runner._invoke_helper(
                    installation, plan, ready, prepared, prepared_result,
                    lambda *_update: None,
                )

    def test_cancel_before_commit_uses_in_band_cancel_without_killing_helper(self):
        factory = PopenFactory()
        runner = GrubRescueDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
        )
        plan, ready, prepared, prepared_result, installation = helper_inputs()

        def cancel_at_preflight(stage: str, _path: str, done: int, total: int) -> None:
            if stage == "source-validation" and done == total:
                runner.cancel()

        with self.assertRaises(GrubRescueDeviceRunCancelled):
            runner._invoke_helper(
                installation, plan, ready, prepared, prepared_result,
                cancel_at_preflight,
            )
        self.assertFalse(runner.committed)
        self.assertEqual(factory.processes[0].terminated, 0)
        self.assertEqual(factory.processes[0].killed, 0)

    def test_cancel_after_commit_is_deferred_until_verified_success(self):
        factory = PopenFactory()
        runner = GrubRescueDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
        )
        plan, ready, prepared, prepared_result, installation = helper_inputs()

        def cancel_during_write(stage: str, *_update) -> None:
            if stage == "writing":
                runner.cancel()

        result = runner._invoke_helper(
            installation, plan, ready, prepared, prepared_result,
            cancel_during_write,
        )
        self.assertTrue(runner.committed)
        self.assertTrue(result.cancellation_deferred)
        self.assertEqual(factory.processes[0].terminated, 0)

    def test_postcommit_failure_is_unknown_not_cancelled_or_killed(self):
        factory = PopenFactory("post-mutation-error")
        runner = GrubRescueDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
        )
        plan, ready, prepared, prepared_result, installation = helper_inputs()

        def cancel_during_write(stage: str, *_update) -> None:
            if stage == "writing":
                runner.cancel()

        with self.assertRaises(GrubRescueDeviceRunError) as caught:
            runner._invoke_helper(
                installation, plan, ready, prepared, prepared_result,
                cancel_during_write,
            )
        self.assertNotIsInstance(caught.exception, GrubRescueDeviceRunCancelled)
        self.assertIn("injected GRUB helper error", str(caught.exception))
        self.assertEqual(factory.processes[0].killed, 0)

    def test_runner_is_single_use_and_precancelled_run_does_nothing(self):
        runner = GrubRescueDeviceWriteRunner()
        runner.cancel()
        with self.assertRaises(GrubRescueDeviceRunCancelled):
            runner.run(None, None)  # type: ignore[arg-type]
        with self.assertRaisesRegex(GrubRescueDeviceRunError, "only be used once"):
            runner.run(None, None)  # type: ignore[arg-type]


class PreparedOwnerTransferTests(unittest.TestCase):
    def test_owner_sends_one_duplicate_without_exposing_it(self):
        source = tempfile.TemporaryFile()
        source.write(b"prepared rescue")
        source.flush()
        image_size = source.seek(0, os.SEEK_END)

        class Image:
            def _duplicate_attested_descriptor(self, cancel_check=None):
                if cancel_check is not None:
                    cancel_check()
                return os.dup(source.fileno()), image_size

        owner = object.__new__(PreparedGrubRescueImage)
        owner._image = Image()
        owner._plan = object()
        owner._result = SimpleNamespace(image_size=image_size)
        owner._witness = rescue_module._OWNER_WITNESS
        owner._transferred = False
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        received: list[int] = []
        try:
            owner._send_to_privileged_helper(left, b"bound-request")
            packet, ancillary, flags, _address = right.recvmsg(
                128,
                socket.CMSG_SPACE(array.array("i").itemsize),
            )
            self.assertEqual(packet, b"bound-request")
            self.assertFalse(flags)
            for level, kind, value in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    descriptors = array.array("i")
                    descriptors.frombytes(value)
                    received.extend(descriptors)
            self.assertEqual(len(received), 1)
            self.assertEqual(os.pread(received[0], image_size, 0), b"prepared rescue")
            self.assertEqual(
                owner.state,
                rescue_module.PrivateFat32State.CLOSED,
            )
            with self.assertRaisesRegex(rescue_module.GrubRescueError, "closed"):
                owner._send_to_privileged_helper(left, b"second-request")
        finally:
            for descriptor in received:
                os.close(descriptor)
            left.close()
            right.close()
            source.close()
            owner._image = None


class OrchestrationTests(unittest.TestCase):
    def test_prepared_result_is_exactly_bound_to_device_plan(self):
        rescue_plan = SimpleNamespace(
            plan_sha256="10" * 32,
            profile=rescue_module.PROFILE_ID,
            result_semantics=rescue_module.RESULT_SEMANTICS,
            private_plan=SimpleNamespace(
                plan_sha256="20" * 32,
                geometry=SimpleNamespace(image_size=IMAGE_SIZE),
            ),
        )
        result = GrubRescueResult(
            plan_sha256=rescue_plan.plan_sha256,
            private_plan_sha256=rescue_plan.private_plan.plan_sha256,
            profile=rescue_module.PROFILE_ID,
            result_semantics=rescue_module.RESULT_SEMANTICS,
            image_size=IMAGE_SIZE,
            disk_signature=DISK_SIGNATURE,
            volume_id=VOLUME_ID,
            boot_image_sha256=rescue_module.BOOT_IMAGE_SHA256,
            bootstrap_sha256=rescue_module.BOOTSTRAP_SHA256,
            final_mbr_sha256="30" * 32,
            core_sha256=rescue_module.CORE_SHA256,
            core_offset=rescue_module.CORE_OFFSET,
            core_size=rescue_module.CORE_SIZE,
            core_padded_size=rescue_module.CORE_PADDED_SIZE,
            embedding_gap_zero_verified=True,
            unpatched_image_sha256="40" * 32,
            final_image_sha256=IMAGE_SHA256,
            final_fat_manifest_sha256="50" * 32,
            files_verified=0,
            directories_verified=1,
            bytes_verified=0,
        )
        owner = object.__new__(PreparedGrubRescueImage)
        owner._image = object()
        owner._plan = rescue_plan
        owner._result = result
        owner._witness = rescue_module._OWNER_WITNESS
        owner._transferred = False
        plan = SimpleNamespace(
            rescue_plan=rescue_plan,
            rescue_result=result,
            prepared=owner,
            image_size=IMAGE_SIZE,
            disk_signature=DISK_SIGNATURE,
            volume_id=VOLUME_ID,
            final_image_sha256=result.final_image_sha256,
            final_mbr_sha256=result.final_mbr_sha256,
            final_fat_manifest_sha256=result.final_fat_manifest_sha256,
        )
        self.assertIs(runner_module._validate_prepared(plan, owner), result)

        forged = replace(result, final_fat_manifest_sha256="60" * 32)
        owner._result = forged
        with self.assertRaisesRegex(GrubRescueDeviceRunError, "does not match"):
            runner_module._validate_prepared(plan, owner)
        owner._image = None

    def test_helper_is_validated_before_unmount(self):
        runner = GrubRescueDeviceWriteRunner()
        plan = SimpleNamespace(prepared=Mock())
        with (
            patch.object(runner_module, "validate_confirmed_grub_rescue_device_write"),
            patch.object(
                runner_module,
                "resolve_grub_rescue_helper_installation",
                side_effect=GrubRescueDeviceHelperUnavailable("not installed"),
            ),
            patch.object(
                runner_module,
                "unmount_device",
                side_effect=AssertionError("unmounted before helper validation"),
            ) as unmount,
            self.assertRaises(GrubRescueDeviceHelperUnavailable),
        ):
            runner.run(plan, object())
        unmount.assert_not_called()

    def test_revalidate_unmount_ready_and_invoke_order(self):
        order: list[str] = []
        owner = Mock()
        owner.__enter__ = Mock(return_value=owner)
        owner.__exit__ = Mock(return_value=None)
        plan = SimpleNamespace(prepared=owner, device=object())
        confirmation = object()
        prepared_result = object()
        ready = object()
        final = object()
        installation = HelperInstallation(
            PKEXEC_PATH, HELPER_PATH, HELPER_SCRIPT_PATH, POLICY_PATH,
        )
        tools = SimpleNamespace(pkexec=PKEXEC_PATH)
        runner = GrubRescueDeviceWriteRunner()

        with (
            patch.object(
                runner_module,
                "validate_confirmed_grub_rescue_device_write",
                side_effect=lambda *_args, **_kwargs: order.append("validate"),
            ),
            patch.object(
                runner_module,
                "resolve_grub_rescue_helper_installation",
                side_effect=lambda: (order.append("helper") or installation),
            ),
            patch.object(
                runner_module,
                "resolve_writer_tools",
                side_effect=lambda _which: (order.append("tools") or tools),
            ),
            patch.object(
                runner_module,
                "_validate_prepared",
                side_effect=lambda *_args: (order.append("prepared") or prepared_result),
            ),
            patch.object(
                runner_module,
                "unmount_device",
                side_effect=lambda *_args, **_kwargs: order.append("unmount"),
            ),
            patch.object(
                runner_module,
                "authorize_unmounted_grub_rescue_device_write",
                side_effect=lambda *_args, **_kwargs: (order.append("ready") or ready),
            ),
            patch.object(
                runner_module,
                "validate_ready_grub_rescue_device_write",
                side_effect=lambda *_args, **_kwargs: order.append("ready-validate"),
            ),
            patch.object(
                runner,
                "_invoke_helper",
                side_effect=lambda *_args, **_kwargs: (order.append("invoke") or final),
            ),
        ):
            self.assertIs(runner.run(plan, confirmation), final)
        self.assertEqual(order, [
            "validate", "helper", "tools", "prepared", "validate", "unmount",
            "ready", "ready-validate", "invoke",
        ])
        owner.__exit__.assert_called_once()


class InstallationTests(unittest.TestCase):
    def test_plan_and_helper_executor_profiles_must_match(self):
        with (
            patch.object(runner_module, "DEVICE_EXECUTOR_PROFILE", "wrong-profile"),
            self.assertRaisesRegex(
                GrubRescueDeviceHelperUnavailable,
                "profiles disagree",
            ),
        ):
            runner_module.resolve_grub_rescue_helper_installation()

    def test_policy_validation_is_exact_and_rejects_broader_action(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy = Path(temporary) / "policy"
            policy.write_text(
                f'''<?xml version="1.0"?>
<policyconfig><action id="{POLICY_ACTION}">
<description>{POLICY_DESCRIPTION}</description>
<message>{POLICY_MESSAGE}</message><defaults>
<allow_any>no</allow_any><allow_inactive>no</allow_inactive>
<allow_active>auth_admin</allow_active></defaults>
<annotate key="org.freedesktop.policykit.exec.path">{HELPER_PATH}</annotate>
<annotate key="org.freedesktop.policykit.exec.argv1">{protocol.GRUB_RESCUE_OPERATION}</annotate>
</action></policyconfig>''',
                encoding="utf-8",
            )
            with (
                patch.object(runner_module, "POLICY_PATH", str(policy)),
                patch.object(runner_module, "_trusted_file"),
                patch.object(runner_module, "_trusted_parents"),
            ):
                runner_module._validate_policy()
                policy.write_text(
                    policy.read_text(encoding="utf-8").replace(
                        "<allow_any>no</allow_any>",
                        "<allow_any>yes</allow_any>",
                    ),
                    encoding="utf-8",
                )
                with self.assertRaises(GrubRescueDeviceHelperUnavailable):
                    runner_module._validate_policy()


if __name__ == "__main__":
    unittest.main()
