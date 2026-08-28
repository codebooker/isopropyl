from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import array
import io
import os
import socket
import stat
import subprocess
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import isopropyl.raw_device_runner as runner_module
import isopropyl.raw_snapshot as snapshot_module
import isopropyl.syslinux_device_helper as protocol
from isopropyl.raw_device import RawDevicePlanError, RawSourceEvidence
from isopropyl.raw_device_runner import (
    HELPER_PATH,
    HELPER_SCRIPT_PATH,
    PKEXEC_PATH,
    POLICY_ACTION,
    POLICY_DESCRIPTION,
    POLICY_MESSAGE,
    POLICY_PATH,
    RawDeviceHelperUnavailable,
    RawDeviceRunCancelled,
    RawDeviceRunError,
    RawDeviceWriteRunner,
    RawHelperInstallation,
    resolve_raw_helper_installation,
)
from isopropyl.raw_snapshot import (
    PreparedRawSnapshot,
    RawSnapshotIdentity,
    RawSnapshotResult,
    RawSnapshotState,
    RawSourceIdentity,
    RawWorkspaceIdentity,
)


REQUEST_ID = bytes(range(16))
SOURCE_SIZE = 2 * 1024 * 1024
TARGET_SIZE = 4 * 1024 * 1024
SOURCE_SHA256 = "ab" * 32
RAW_SNAPSHOT_PLAN_SHA256 = "cd" * 32
DISK_SEQUENCE = 982_451_653
WORKSPACE_DEVICE = os.makedev(8, 2)


class FakePrepared:
    def __init__(self) -> None:
        self.sent_packets: list[bytes] = []
        self.transfers = 0

    def transfer_to_helper(
        self,
        channel: socket.socket,
        packet: bytes,
        *,
        cancel_check=None,
    ) -> None:
        if cancel_check is not None:
            cancel_check()
        self.sent_packets.append(packet)
        self.transfers += 1
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


class FakeRawHelperProcess:
    def __init__(self, child_fd: int, *, mode: str = "success") -> None:
        self.mode = mode
        self.channel = socket.socket(fileno=os.dup(child_fd))
        self.stderr = io.BytesIO()
        self.returncode: int | None = None
        self.terminated = 0
        self.killed = 0
        self.done = threading.Event()
        self.control_packet = b""
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _send(self, packet: bytes) -> None:
        self.channel.send(packet)

    def _header(self, kind: int) -> bytes:
        return protocol._HEADER.pack(
            protocol.RAW_PROTOCOL_MAGIC,
            protocol.PROTOCOL_VERSION,
            kind,
            0,
        )

    def _serve(self) -> None:
        received: list[int] = []
        extra_fd = -1
        try:
            ready = self._header(protocol.PACKET_READY)
            if self.mode == "wrong-magic":
                ready = protocol._HEADER.pack(
                    protocol.PROTOCOL_MAGIC,
                    protocol.PROTOCOL_VERSION,
                    protocol.PACKET_READY,
                    0,
                )
            if self.mode == "ancillary-response":
                extra_fd = os.open("/dev/null", os.O_RDONLY)
                rights = array.array("i", [extra_fd])
                self.channel.sendmsg(
                    [ready],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                )
                self.returncode = 5
                return
            if self.mode == "oversized-response":
                self._send(b"x" * (protocol.MAX_PROTOCOL_PACKET + 2))
                self.returncode = 5
                return
            self._send(ready)
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
                target_size,
                sector_size,
                source_size,
                final_verification,
                trailing_reserved,
                digest,
            ) = protocol._RAW_REQUEST_PACKET.unpack(packet)
            if (magic, version, kind, reserved) != (
                protocol.RAW_PROTOCOL_MAGIC,
                protocol.PROTOCOL_VERSION,
                protocol.PACKET_REQUEST,
                0,
            ) or trailing_reserved != b"\0" * 7:
                raise AssertionError("bad raw request")
            if self.mode == "stall-precommit":
                self.control_packet = self.channel.recv(protocol.MAX_PROTOCOL_PACKET)
                self.returncode = 7
                return
            phases = [
                "source-validation",
                "writing",
                "preactivation-readback",
            ]
            if final_verification:
                phases.append("readback")
            if self.mode == "out-of-order":
                phases = ["writing", "source-validation"]
            elif self.mode == "missing-phase":
                phases = phases[:-1]
            guard = min(protocol.RAW_FRONT_GUARD_BYTES, source_size - 512)
            prepared_sent = False
            mutation_sent = False
            for phase in phases:
                if (
                    phase == "writing"
                    and not prepared_sent
                    and self.mode != "out-of-order"
                ):
                    prepared_packet = protocol._CONTROL_PACKET.pack(
                        protocol.RAW_PROTOCOL_MAGIC,
                        protocol.PROTOCOL_VERSION,
                        protocol.PACKET_PREPARED,
                        0,
                        request_id,
                    )
                    self._send(prepared_packet)
                    if self.mode == "repeated-prepared":
                        self._send(prepared_packet)
                    prepared_sent = True
                    self.control_packet = self.channel.recv(
                        protocol.MAX_PROTOCOL_PACKET,
                    )
                    (
                        control_magic,
                        control_version,
                        control_type,
                        control_reserved,
                        control_id,
                    ) = protocol._CONTROL_PACKET.unpack(self.control_packet)
                    if (
                        control_magic != protocol.RAW_PROTOCOL_MAGIC
                        or control_version != protocol.PROTOCOL_VERSION
                        or control_reserved != 0
                        or control_id != request_id
                        or control_type not in {
                            protocol.PACKET_COMMIT,
                            protocol.PACKET_CANCEL,
                        }
                    ):
                        raise AssertionError("bad raw control decision")
                    if control_type == protocol.PACKET_CANCEL:
                        self.returncode = 7
                        return
                    if self.mode == "progress-after-prepared":
                        self._send(protocol._PROGRESS_PACKET.pack(
                            protocol.RAW_PROTOCOL_MAGIC,
                            protocol.PROTOCOL_VERSION,
                            protocol.PACKET_PROGRESS,
                            0,
                            request_id,
                            protocol.PHASE_CODES["source-validation"],
                            source_size,
                            source_size,
                        ))
                    if self.mode not in {
                        "missing-mutation",
                        "success-before-mutation",
                    }:
                        self._send(protocol._MUTATION_PACKET.pack(
                            protocol.RAW_PROTOCOL_MAGIC,
                            protocol.PROTOCOL_VERSION,
                            protocol.PACKET_MUTATION_STARTED,
                            0,
                            request_id,
                        ))
                        mutation_sent = True
                    if self.mode == "stall-postcommit":
                        self.channel.recv(protocol.MAX_PROTOCOL_PACKET)
                        self.returncode = 5
                        return
                if phase == "preactivation-readback":
                    total = source_size - guard - 512
                else:
                    total = source_size
                for done in dict.fromkeys((0, total)):
                    self._send(protocol._PROGRESS_PACKET.pack(
                        protocol.RAW_PROTOCOL_MAGIC,
                        protocol.PROTOCOL_VERSION,
                        protocol.PACKET_PROGRESS,
                        0,
                        (
                            b"X" * 16
                            if self.mode == "wrong-request"
                            else request_id
                        ),
                        protocol.PHASE_CODES[phase],
                        done,
                        total + (1 if self.mode == "wrong-total" else 0),
                    ))
                    if self.mode == "repeat-progress" and done == total:
                        self._send(protocol._PROGRESS_PACKET.pack(
                            protocol.RAW_PROTOCOL_MAGIC,
                            protocol.PROTOCOL_VERSION,
                            protocol.PACKET_PROGRESS,
                            0,
                            request_id,
                            protocol.PHASE_CODES[phase],
                            done,
                            total,
                        ))
            if self.mode in {"exit-error", "post-mutation-error"}:
                self.stderr = io.BytesIO(b"injected raw helper error")
                self.returncode = 4
                return
            if self.mode == "success-before-mutation":
                mutation_sent = False
            result_digest = b"\0" * 32 if self.mode == "wrong-digest" else digest
            result_disk_sequence = (
                disk_sequence + 1
                if self.mode == "wrong-diskseq"
                else disk_sequence
            )
            result_guard = guard + (512 if self.mode == "wrong-guard" else 0)
            tail_sanitized = int(target_size != source_size)
            if self.mode == "wrong-tail":
                tail_sanitized ^= 1
            result_verification = int(bool(final_verification))
            if self.mode == "wrong-verification":
                result_verification ^= 1
            readback = digest if result_verification else b"\0" * 32
            if self.mode == "wrong-readback":
                readback = b"\0" * 32
            self._send(protocol._RAW_SUCCESS_PACKET.pack(
                protocol.RAW_PROTOCOL_MAGIC,
                protocol.PROTOCOL_VERSION,
                protocol.PACKET_SUCCESS,
                0,
                request_id,
                major_number,
                minor_number,
                result_disk_sequence,
                target_size,
                sector_size,
                source_size,
                result_guard,
                tail_sanitized,
                result_verification,
                b"\0" * 2,
                result_digest,
                digest,
                readback,
            ))
            if self.mode == "extra":
                self._send(b"unexpected trailing packet")
            if not mutation_sent and self.mode != "missing-mutation":
                raise AssertionError("test helper mutation state is inconsistent")
            self.returncode = 0
        except BaseException as error:
            self.stderr = io.BytesIO(str(error).encode())
            self.returncode = 5
        finally:
            for descriptor in received:
                os.close(descriptor)
            if extra_fd >= 0:
                os.close(extra_fd)
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
            raise subprocess.TimeoutExpired("fake-raw-helper", timeout)
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
        self.processes: list[FakeRawHelperProcess] = []

    def __call__(self, command, **kwargs):
        self.calls.append((list(command), dict(kwargs)))
        process = FakeRawHelperProcess(kwargs["stdin"], mode=self.mode)
        self.processes.append(process)
        return process


def helper_inputs(*, final_verification: bool = True, equal_size: bool = False):
    target_size = SOURCE_SIZE if equal_size else TARGET_SIZE
    plan = SimpleNamespace(
        plan_sha256="11" * 32,
        raw_snapshot_plan_sha256=RAW_SNAPSHOT_PLAN_SHA256,
        snapshot_plan_sha256="22" * 32,
        target_capacity=target_size,
        source_size=SOURCE_SIZE,
        source_sha256=SOURCE_SHA256,
        logical_sector_size=512,
        mandatory_preactivation_readback=True,
        final_verification_requested=final_verification,
    )
    ready = SimpleNamespace(
        ready_sha256="33" * 32,
        disk_sequence=DISK_SEQUENCE,
        device=SimpleNamespace(path="/dev/sdz", major_minor="8:240"),
    )
    prepared = FakePrepared()
    prepared_result = SimpleNamespace(
        plan_sha256=RAW_SNAPSHOT_PLAN_SHA256,
        image_size=SOURCE_SIZE,
        image_sha256=SOURCE_SHA256,
    )
    installation = RawHelperInstallation(
        PKEXEC_PATH,
        HELPER_PATH,
        HELPER_SCRIPT_PATH,
        POLICY_PATH,
    )
    return plan, ready, prepared, prepared_result, installation


class ProtocolRunnerTests(unittest.TestCase):
    def test_exact_socket_fd_request_control_and_bound_success(self):
        factory = PopenFactory()
        runner = RawDeviceWriteRunner(
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
        self.assertEqual(result.request_id, REQUEST_ID.hex())
        self.assertEqual(result.raw_snapshot_plan_sha256, RAW_SNAPSHOT_PLAN_SHA256)
        self.assertEqual(result.disk_sequence, DISK_SEQUENCE)
        self.assertEqual(result.target_capacity, TARGET_SIZE)
        self.assertEqual(result.source_size, SOURCE_SIZE)
        self.assertEqual(result.source_sha256, SOURCE_SHA256)
        self.assertEqual(result.written_sha256, SOURCE_SHA256)
        self.assertEqual(result.readback_sha256, SOURCE_SHA256)
        self.assertEqual(result.front_guard_bytes, protocol.RAW_FRONT_GUARD_BYTES)
        self.assertTrue(result.target_tail_sanitized)
        self.assertTrue(result.exclusive_open)
        self.assertTrue(result.cache_invalidated)
        self.assertTrue(result.mandatory_preactivation_readback)
        self.assertTrue(result.final_verification)
        self.assertFalse(result.cancellation_deferred)
        self.assertEqual(prepared.transfers, 1)
        command, kwargs = factory.calls[0]
        self.assertEqual(command, [
            PKEXEC_PATH,
            "--disable-internal-agent",
            HELPER_PATH,
            protocol.RAW_OPERATION,
        ])
        self.assertTrue(kwargs["close_fds"])
        self.assertFalse(kwargs["shell"])
        self.assertNotIn("pass_fds", kwargs)
        self.assertIsInstance(kwargs["stdin"], int)
        phases = {update[0] for update in updates}
        self.assertEqual(phases, set(protocol.PHASE_CODES))
        control = protocol._CONTROL_PACKET.unpack(
            factory.processes[0].control_packet,
        )
        self.assertEqual(control[0], protocol.RAW_PROTOCOL_MAGIC)
        self.assertEqual(control[2], protocol.PACKET_COMMIT)
        self.assertEqual(control[4], REQUEST_ID)

    def test_no_final_verification_has_no_readback_phase_or_digest(self):
        factory = PopenFactory()
        runner = RawDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
        )
        plan, ready, prepared, prepared_result, installation = helper_inputs(
            final_verification=False,
            equal_size=True,
        )
        updates = []
        result = runner._invoke_helper(
            installation,
            plan,
            ready,
            prepared,
            prepared_result,
            lambda *update: updates.append(update),
        )
        self.assertFalse(result.final_verification)
        self.assertEqual(result.readback_sha256, "")
        self.assertFalse(result.target_tail_sanitized)
        self.assertNotIn("readback", {update[0] for update in updates})
        self.assertIn("preactivation-readback", {update[0] for update in updates})

    def test_spoofed_result_progress_and_protocol_sequences_are_rejected(self):
        cases = (
            ("wrong-digest", "does not match"),
            ("wrong-readback", "does not match"),
            ("wrong-diskseq", "does not match"),
            ("wrong-guard", "does not match"),
            ("wrong-tail", "does not match"),
            ("wrong-verification", "verification|does not match"),
            ("wrong-request", "another request"),
            ("wrong-total", "sequence"),
            ("repeat-progress", "sequence"),
            ("progress-after-prepared", "sequence"),
            ("out-of-order", "sequence"),
            ("missing-phase", "does not match"),
            ("missing-mutation", "sequence|does not match"),
            ("success-before-mutation", "sequence|does not match"),
            ("repeated-prepared", "boundary|out of order"),
            ("wrong-magic", "unsupported"),
            ("extra", "after its terminal result"),
            ("exit-error", "injected raw helper error"),
        )
        for mode, message in cases:
            factory = PopenFactory(mode)
            runner = RawDeviceWriteRunner(
                popen=factory,
                request_id=lambda _size: REQUEST_ID,
            )
            inputs = helper_inputs()
            with self.subTest(mode=mode), self.assertRaisesRegex(
                RawDeviceRunError,
                message,
            ):
                runner._invoke_helper(
                    inputs[4],
                    inputs[0],
                    inputs[1],
                    inputs[2],
                    inputs[3],
                    lambda *_update: None,
                )

    def test_response_ancillary_and_truncation_are_rejected(self):
        for mode, message in (
            ("ancillary-response", "ancillary"),
            ("oversized-response", "ancillary|oversized"),
        ):
            factory = PopenFactory(mode)
            runner = RawDeviceWriteRunner(
                popen=factory,
                request_id=lambda _size: REQUEST_ID,
            )
            inputs = helper_inputs()
            with self.subTest(mode=mode), self.assertRaisesRegex(
                RawDeviceRunError,
                message,
            ):
                runner._invoke_helper(
                    inputs[4],
                    inputs[0],
                    inputs[1],
                    inputs[2],
                    inputs[3],
                    lambda *_update: None,
                )

    def test_request_identifier_is_exact_and_transfer_is_not_attempted(self):
        for value in (b"", b"x" * 15, b"x" * 17, "x" * 16):
            runner = RawDeviceWriteRunner(request_id=lambda _size, v=value: v)
            inputs = helper_inputs()
            with self.subTest(value=value), self.assertRaisesRegex(
                RawDeviceRunError,
                "identifier",
            ):
                runner._invoke_helper(
                    inputs[4],
                    inputs[0],
                    inputs[1],
                    inputs[2],
                    inputs[3],
                    lambda *_update: None,
                )
            self.assertEqual(inputs[2].transfers, 0)

    def test_precommit_cancel_is_in_band_and_never_terminates_helper(self):
        factory = PopenFactory()
        runner = RawDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
        )
        inputs = helper_inputs()

        def cancel_at_source_end(
            stage: str,
            _path: str,
            done: int,
            total: int,
        ) -> None:
            if stage == "source-validation" and done == total:
                runner.cancel()

        with self.assertRaises(RawDeviceRunCancelled):
            runner._invoke_helper(
                inputs[4],
                inputs[0],
                inputs[1],
                inputs[2],
                inputs[3],
                cancel_at_source_end,
            )
        process = factory.processes[0]
        self.assertEqual(process.terminated, 0)
        self.assertEqual(process.killed, 0)
        control = protocol._CONTROL_PACKET.unpack(process.control_packet)
        self.assertEqual(control[0], protocol.RAW_PROTOCOL_MAGIC)
        self.assertEqual(control[2], protocol.PACKET_CANCEL)

    def test_cancel_after_commit_is_deferred_to_verified_success(self):
        factory = PopenFactory()
        runner = RawDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
        )
        inputs = helper_inputs()

        def cancel_during_write(stage: str, *_update) -> None:
            if stage == "writing":
                runner.cancel()

        result = runner._invoke_helper(
            inputs[4],
            inputs[0],
            inputs[1],
            inputs[2],
            inputs[3],
            cancel_during_write,
        )
        self.assertTrue(result.cancellation_deferred)
        self.assertEqual(factory.processes[0].terminated, 0)
        self.assertEqual(factory.processes[0].killed, 0)

    def test_postcommit_failure_is_never_classified_as_cancellation(self):
        factory = PopenFactory("post-mutation-error")
        runner = RawDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
        )
        inputs = helper_inputs()

        def cancel_during_write(stage: str, *_update) -> None:
            if stage == "writing":
                runner.cancel()

        with self.assertRaises(RawDeviceRunError) as caught:
            runner._invoke_helper(
                inputs[4],
                inputs[0],
                inputs[1],
                inputs[2],
                inputs[3],
                cancel_during_write,
            )
        self.assertNotIsInstance(caught.exception, RawDeviceRunCancelled)
        self.assertIn("injected raw helper error", str(caught.exception))
        self.assertEqual(factory.processes[0].terminated, 0)

    def test_stalled_precommit_helper_never_claims_commit(self):
        factory = PopenFactory("stall-precommit")
        ticks = iter((0.0, 0.0, 301.0, 301.0))
        runner = RawDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
            clock=lambda: next(ticks, 301.0),
        )
        inputs = helper_inputs()
        with self.assertRaisesRegex(RawDeviceRunError, "no write commit was sent"):
            runner._invoke_helper(
                inputs[4],
                inputs[0],
                inputs[1],
                inputs[2],
                inputs[3],
                lambda *_update: None,
            )
        self.assertFalse(runner._commit_sent)
        self.assertEqual(factory.processes[0].terminated, 0)

    def test_stalled_postcommit_helper_reports_unknown_and_is_not_killed(self):
        factory = PopenFactory("stall-postcommit")
        now = 0.0

        def clock() -> float:
            nonlocal now
            now += 301.0
            return now

        runner = RawDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
            clock=clock,
        )
        inputs = helper_inputs()
        with self.assertRaisesRegex(RawDeviceRunError, "target state is unknown"):
            runner._invoke_helper(
                inputs[4],
                inputs[0],
                inputs[1],
                inputs[2],
                inputs[3],
                lambda *_update: None,
            )
        self.assertTrue(runner._commit_sent)
        self.assertEqual(factory.processes[0].terminated, 0)
        self.assertEqual(factory.processes[0].killed, 0)


def authentic_prepared_inputs():
    source_identity = RawSourceIdentity(
        os.makedev(8, 1),
        12345,
        SOURCE_SIZE,
        1_730_000_000_000_000_000,
        1_730_000_000_100_000_000,
    )
    workspace_identity = RawWorkspaceIdentity(
        WORKSPACE_DEVICE,
        9876,
        os.geteuid(),
        0o700,
        1_730_000_000_200_000_000,
    )
    snapshot_identity = RawSnapshotIdentity(
        WORKSPACE_DEVICE,
        6543,
        SOURCE_SIZE,
        1_730_000_000_300_000_000,
        1_730_000_000_400_000_000,
        os.geteuid(),
        0o600,
        SOURCE_SIZE // 512,
    )
    result = RawSnapshotResult(
        RAW_SNAPSHOT_PLAN_SHA256,
        source_identity,
        workspace_identity,
        snapshot_identity,
        SOURCE_SIZE,
        SOURCE_SHA256,
        True,
    )
    owner = object.__new__(PreparedRawSnapshot)
    owner._descriptor = -1
    owner._result = result
    owner._lifecycle = threading.RLock()
    owner._state = RawSnapshotState.READY
    owner._witness = snapshot_module._OWNER_WITNESS
    evidence = RawSourceEvidence(
        source_sha256=result.image_sha256,
        source_size=result.image_size,
        original_device=source_identity.device,
        original_inode=source_identity.inode,
        original_size=source_identity.size,
        original_modified_ns=source_identity.modified_ns,
        original_changed_ns=source_identity.changed_ns,
        workspace_device=workspace_identity.device,
        raw_snapshot_plan_sha256=result.plan_sha256,
    )
    plan = SimpleNamespace(
        source_evidence=evidence,
        raw_snapshot_plan_sha256=result.plan_sha256,
        snapshot_plan_sha256=evidence.snapshot_plan_sha256,
        original_source_identity=evidence.original_identity,
        workspace_device=evidence.workspace_device,
        source_size=evidence.source_size,
        source_sha256=evidence.source_sha256,
    )
    return plan, owner, result


class PreparedBindingTests(unittest.TestCase):
    def test_authentic_owner_and_every_result_identity_are_bound(self):
        plan, owner, result = authentic_prepared_inputs()
        self.assertIs(runner_module._validate_prepared(plan, owner), result)
        changes = {
            "plan_sha256": "00" * 32,
            "source_identity": replace(result.source_identity, inode=999),
            "workspace_identity": replace(
                result.workspace_identity,
                device=os.makedev(8, 3),
            ),
            "snapshot_identity": replace(
                result.snapshot_identity,
                device=os.makedev(8, 3),
            ),
            "image_size": result.image_size + 512,
            "image_sha256": "ef" * 32,
            "fully_preallocated": False,
        }
        for field_name, value in changes.items():
            owner._result = replace(result, **{field_name: value})
            with self.subTest(field=field_name), self.assertRaisesRegex(
                RawDeviceRunError,
                "does not match|malformed",
            ):
                runner_module._validate_prepared(plan, owner)
        owner._result = result
        owner._state = RawSnapshotState.TRANSFERRED
        with self.assertRaisesRegex(RawDeviceRunError, "malformed|does not match"):
            runner_module._validate_prepared(plan, owner)

    def test_forged_owner_type_and_snapshot_plan_mismatch_are_rejected(self):
        plan, owner, result = authentic_prepared_inputs()

        class ForgedPrepared(PreparedRawSnapshot):
            pass

        forged = object.__new__(ForgedPrepared)
        forged._result = result
        forged._witness = snapshot_module._OWNER_WITNESS
        with self.assertRaisesRegex(RawDeviceRunError, "authentic"):
            runner_module._validate_prepared(plan, forged)

        owner._result = replace(result, plan_sha256="12" * 32)
        with self.assertRaisesRegex(RawDeviceRunError, "does not match"):
            runner_module._validate_prepared(plan, owner)


class OrchestrationTests(unittest.TestCase):
    def test_helper_prepared_validation_revalidation_unmount_ready_and_invoke_order(self):
        order: list[str] = []
        plan = SimpleNamespace(device=object())
        confirmation = object()
        prepared = object()
        prepared_result = object()
        ready = object()
        final = object()
        installation = RawHelperInstallation(
            PKEXEC_PATH,
            HELPER_PATH,
            HELPER_SCRIPT_PATH,
            POLICY_PATH,
        )
        tools = SimpleNamespace(pkexec=PKEXEC_PATH)
        runner = RawDeviceWriteRunner()

        def validate(*_args, **_kwargs):
            order.append("validate")

        with (
            patch.object(
                runner_module,
                "validate_confirmed_raw_device_write",
                side_effect=validate,
            ),
            patch.object(
                runner_module,
                "resolve_raw_helper_installation",
                side_effect=lambda: (order.append("helper") or installation),
            ),
            patch.object(
                runner_module,
                "_resolve_unmount_tools",
                side_effect=lambda _which: (order.append("tools") or tools),
            ),
            patch.object(
                runner_module,
                "_validate_prepared",
                side_effect=lambda *_args: (
                    order.append("prepared") or prepared_result
                ),
            ),
            patch.object(
                runner_module,
                "unmount_device",
                side_effect=lambda *_args, **_kwargs: order.append("unmount"),
            ),
            patch.object(
                runner_module,
                "authorize_unmounted_raw_device_write",
                side_effect=lambda *_args, **_kwargs: (
                    order.append("ready") or ready
                ),
            ),
            patch.object(
                runner_module,
                "validate_ready_raw_device_write",
                side_effect=lambda *_args, **_kwargs: order.append("ready-validate"),
            ),
            patch.object(
                runner,
                "_invoke_helper",
                side_effect=lambda *_args, **_kwargs: (
                    order.append("invoke") or final
                ),
            ),
        ):
            self.assertIs(runner.run(plan, confirmation, prepared), final)
        self.assertEqual(order, [
            "validate",
            "helper",
            "tools",
            "prepared",
            "validate",
            "unmount",
            "ready",
            "ready-validate",
            "invoke",
        ])

    def test_missing_helper_fails_before_prepared_validation_or_unmount(self):
        runner = RawDeviceWriteRunner()
        with (
            patch.object(runner_module, "validate_confirmed_raw_device_write"),
            patch.object(
                runner_module,
                "resolve_raw_helper_installation",
                side_effect=RawDeviceHelperUnavailable("not installed"),
            ),
            patch.object(
                runner_module,
                "_validate_prepared",
                side_effect=AssertionError("snapshot examined after helper failure"),
            ) as prepared,
            patch.object(
                runner_module,
                "unmount_device",
                side_effect=AssertionError("unmounted before helper validation"),
            ) as unmount,
            self.assertRaises(RawDeviceHelperUnavailable),
        ):
            runner.run(SimpleNamespace(), SimpleNamespace(), SimpleNamespace())
        prepared.assert_not_called()
        unmount.assert_not_called()

    def test_runner_is_single_use_and_precancel_reaches_nothing(self):
        runner = RawDeviceWriteRunner()
        runner.cancel()
        with self.assertRaises(RawDeviceRunCancelled):
            runner.run(None, None, None)  # type: ignore[arg-type]
        with self.assertRaisesRegex(RawDeviceRunError, "only be used once"):
            runner.run(None, None, None)  # type: ignore[arg-type]

    def test_plan_or_prepared_mismatch_does_not_unmount_or_transfer(self):
        plan, owner, _result = authentic_prepared_inputs()
        plan.raw_snapshot_plan_sha256 = "00" * 32
        runner = RawDeviceWriteRunner()
        installation = RawHelperInstallation(
            PKEXEC_PATH,
            HELPER_PATH,
            HELPER_SCRIPT_PATH,
            POLICY_PATH,
        )
        tools = SimpleNamespace(pkexec=PKEXEC_PATH)
        with (
            patch.object(runner_module, "validate_confirmed_raw_device_write"),
            patch.object(
                runner_module,
                "resolve_raw_helper_installation",
                return_value=installation,
            ),
            patch.object(
                runner_module,
                "_resolve_unmount_tools",
                return_value=tools,
            ),
            patch.object(
                runner_module,
                "unmount_device",
                side_effect=AssertionError("mismatch reached unmount"),
            ) as unmount,
            self.assertRaisesRegex(RawDeviceRunError, "does not match"),
        ):
            runner.run(plan, object(), owner)
        unmount.assert_not_called()
        self.assertIs(owner.state, RawSnapshotState.READY)

    def test_planning_path_has_no_dd_or_image_writer_fallback(self):
        self.assertNotIn("dd", runner_module.__dict__)
        self.assertNotIn("ImageWriter", runner_module.__dict__)
        source = Path(runner_module.__file__).read_text(encoding="utf-8")
        self.assertNotIn("cooperative_lock_command", source)
        self.assertNotIn("_write_stream", source)

    def test_unmount_tool_resolution_never_looks_up_or_requires_dd(self):
        calls: list[str] = []

        def which(name: str) -> str | None:
            calls.append(name)
            return f"/usr/bin/{name}"

        tools = runner_module._resolve_unmount_tools(which)
        self.assertEqual(calls, ["pkexec", "udisksctl", "lsblk"])
        self.assertNotIn("dd", calls)
        self.assertEqual(
            tools.dd,
            "/nonexistent/isopropyl-raw-runner-has-no-dd",
        )
        for untrusted in (
            None,
            "pkexec",
            "/tmp/pkexec",
            "/usr/bin/../bin/pkexec",
            "/usr/bin/lsblk",
        ):
            with self.subTest(untrusted=untrusted), self.assertRaises(
                RawDeviceHelperUnavailable,
            ):
                runner_module._resolve_unmount_tools(
                    lambda name, value=untrusted: (
                        value if name == "pkexec" else f"/usr/bin/{name}"
                    ),
                )


class InstallationTests(unittest.TestCase):
    def _staged(self, root: Path, *, policy_active: str = "auth_admin"):
        pkexec = root / "usr" / "bin" / "pkexec"
        launcher = root / "usr" / "libexec" / "isopropyl-device-helper"
        script = (
            root
            / "usr"
            / "libexec"
            / "isopropyl"
            / "syslinux_device_helper.py"
        )
        policy = (
            root
            / "usr"
            / "share"
            / "polkit-1"
            / "actions"
            / "io.github.codebooker.isopropyl.raw-write.policy"
        )
        for path in (pkexec, launcher, script, policy):
            path.parent.mkdir(parents=True, exist_ok=True)
        pkexec.write_bytes(b"pkexec")
        launcher.write_bytes(b"helper")
        script.write_bytes(b"script")
        policy.write_text(
            f'''<?xml version="1.0"?>
<policyconfig><action id="{POLICY_ACTION}">
<description>{POLICY_DESCRIPTION}</description>
<message>{POLICY_MESSAGE}</message><defaults>
<allow_any>no</allow_any><allow_inactive>no</allow_inactive>
<allow_active>{policy_active}</allow_active></defaults>
<annotate key="org.freedesktop.policykit.exec.path">{launcher}</annotate>
<annotate key="org.freedesktop.policykit.exec.argv1">{protocol.RAW_OPERATION}</annotate>
</action></policyconfig>''',
            encoding="utf-8",
        )
        return pkexec, launcher, script, policy

    @staticmethod
    def _root_status_factory(pkexec: Path, launcher: Path):
        actual_lstat = os.lstat

        def root_status(path):
            status = actual_lstat(path)
            mode = status.st_mode & ~0o022
            if os.fspath(path) == os.fspath(pkexec):
                mode |= stat.S_ISUID | 0o500
            elif os.fspath(path) == os.fspath(launcher):
                mode |= 0o500
            elif stat.S_ISREG(mode):
                mode |= 0o400
            return SimpleNamespace(st_mode=mode, st_uid=0)

        return root_status

    def test_fixed_root_owned_install_and_exact_raw_policy_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pkexec, launcher, script, policy = self._staged(root)
            root_status = self._root_status_factory(pkexec, launcher)
            with (
                patch.object(runner_module, "PKEXEC_PATH", os.fspath(pkexec)),
                patch.object(runner_module, "HELPER_PATH", os.fspath(launcher)),
                patch.object(
                    runner_module,
                    "HELPER_SCRIPT_PATH",
                    os.fspath(script),
                ),
                patch.object(runner_module, "POLICY_PATH", os.fspath(policy)),
                patch.object(runner_module.os, "lstat", side_effect=root_status),
                patch.object(
                    runner_module.os.path,
                    "realpath",
                    side_effect=lambda value: value,
                ),
                patch.object(runner_module, "_trusted_parents"),
            ):
                installation = resolve_raw_helper_installation()
                self.assertEqual(installation.helper, os.fspath(launcher))
                self.assertEqual(installation.policy, os.fspath(policy))

            for old, new, message in (
                ("auth_admin", "auth_admin_keep", "broader"),
                (POLICY_ACTION, POLICY_ACTION + ".other", "identity"),
                (protocol.RAW_OPERATION, protocol.OPERATION, "broader"),
                ("caller-supplied raw image", "friendly image", "misleading"),
                ("will overwrite", "may update", "misleading"),
            ):
                valid = self._staged(root)[3].read_text(encoding="utf-8")
                policy.write_text(valid.replace(old, new), encoding="utf-8")
                with (
                    self.subTest(replacement=(old, new)),
                    patch.object(runner_module, "PKEXEC_PATH", os.fspath(pkexec)),
                    patch.object(runner_module, "HELPER_PATH", os.fspath(launcher)),
                    patch.object(
                        runner_module,
                        "HELPER_SCRIPT_PATH",
                        os.fspath(script),
                    ),
                    patch.object(runner_module, "POLICY_PATH", os.fspath(policy)),
                    patch.object(
                        runner_module.os,
                        "lstat",
                        side_effect=root_status,
                    ),
                    patch.object(
                        runner_module.os.path,
                        "realpath",
                        side_effect=lambda value: value,
                    ),
                    patch.object(runner_module, "_trusted_parents"),
                    self.assertRaisesRegex(RawDeviceHelperUnavailable, message),
                ):
                    resolve_raw_helper_installation()

    def test_duplicate_or_extra_policy_structure_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pkexec, launcher, script, policy = self._staged(root)
            valid = policy.read_text(encoding="utf-8")
            root_status = self._root_status_factory(pkexec, launcher)
            additions = (
                f"<description>{POLICY_DESCRIPTION}</description>",
                f"<message>{POLICY_MESSAGE}</message>",
                "<defaults><allow_any>yes</allow_any><allow_inactive>yes"
                "</allow_inactive><allow_active>yes</allow_active></defaults>",
                '<annotate key="org.freedesktop.policykit.exec.path">'
                f"{launcher}</annotate>",
                "<unknown>deceptive prompt metadata</unknown>",
            )
            for addition in additions:
                policy.write_text(
                    valid.replace("</action>", addition + "</action>"),
                    encoding="utf-8",
                )
                with (
                    self.subTest(addition=addition[:20]),
                    patch.object(runner_module, "PKEXEC_PATH", os.fspath(pkexec)),
                    patch.object(runner_module, "HELPER_PATH", os.fspath(launcher)),
                    patch.object(
                        runner_module,
                        "HELPER_SCRIPT_PATH",
                        os.fspath(script),
                    ),
                    patch.object(runner_module, "POLICY_PATH", os.fspath(policy)),
                    patch.object(
                        runner_module.os,
                        "lstat",
                        side_effect=root_status,
                    ),
                    patch.object(
                        runner_module.os.path,
                        "realpath",
                        side_effect=lambda value: value,
                    ),
                    patch.object(runner_module, "_trusted_parents"),
                    self.assertRaisesRegex(
                        RawDeviceHelperUnavailable,
                        "ambiguous",
                    ),
                ):
                    resolve_raw_helper_installation()


if __name__ == "__main__":
    unittest.main()
