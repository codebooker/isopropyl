from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import io
import os
import socket
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import isopropyl.fast_zero as fast_zero_module
import isopropyl.syslinux_device_helper as protocol
from isopropyl.devices import Device
from isopropyl.fast_zero import (
    FAST_ZERO_BOUNDARY_BYTES,
    FAST_ZERO_CHUNK_BYTES,
    ConfirmedFastZero,
    FastZeroCancelled,
    FastZeroDependencies,
    FastZeroHelperInstallation,
    FastZeroPartialFailure,
    FastZeroPartialResult,
    FastZeroPlanError,
    FastZeroResult,
    FastZeroRunError,
    FastZeroRunner,
    FastZeroState,
    FastZeroTargetObservation,
    FastZeroWorkflow,
    authorize_unmounted_fast_zero,
    build_fast_zero_plan,
    confirm_fast_zero,
    resolve_fast_zero_helper_installation,
    validate_fast_zero_plan,
    validate_ready_fast_zero,
)


REQUEST_ID = bytes(range(16))
TARGET_SIZE = 64 * 1024 * 1024
DISK_SEQUENCE = 9_824_516


def device(*, mounted: bool = True, **changes: object) -> Device:
    values: dict[str, object] = {
        "path": "/dev/sdz",
        "size": TARGET_SIZE,
        "model": "Test Stick",
        "vendor": "ISOpropyl",
        "transport": "usb",
        "serial": "SERIAL-123",
        "wwn": "WWN-123",
        "major_minor": "8:240",
        "removable": True,
        "hotplug": True,
        "read_only": False,
        "mountpoints": ("/media/test",) if mounted else (),
        "partitions": ("/dev/sdz1",),
        "logical_sector_size": 512,
    }
    values.update(changes)
    return Device(**values)  # type: ignore[arg-type]


def observation(
    value: Device | None = None,
    *,
    disk_sequence: int = DISK_SEQUENCE,
) -> FastZeroTargetObservation:
    return FastZeroTargetObservation(
        value or device(),
        frozenset({os.makedev(8, 240), os.makedev(8, 241)}),
        disk_sequence,
    )


def plan_and_ready() -> tuple[object, ConfirmedFastZero, object]:
    selected = device()
    plan = build_fast_zero_plan(selected, observe=lambda _device: observation(selected))
    confirmed = confirm_fast_zero(
        plan,
        plan.confirmation_phrase,
        observe=lambda _device: observation(selected),
    )
    unmounted = observation(device(mounted=False))
    ready = authorize_unmounted_fast_zero(
        plan,
        confirmed,
        observe_path=lambda _path: unmounted,
    )
    return plan, confirmed, ready


class PlanTests(unittest.TestCase):
    def test_plan_binds_exact_target_generation_and_phrase(self) -> None:
        selected = device()
        plan = build_fast_zero_plan(selected, observe=lambda _device: observation(selected))
        self.assertEqual(plan.confirmation_phrase, "FAST ZERO /dev/sdz 8:240")
        self.assertEqual(plan.disk_sequence, DISK_SEQUENCE)
        self.assertEqual(plan.chunk_size, FAST_ZERO_CHUNK_BYTES)
        self.assertEqual(plan.boundary_bytes, FAST_ZERO_BOUNDARY_BYTES)
        self.assertEqual(len(plan.plan_sha256), 64)
        self.assertIn("logical overwrite", " ".join(plan.warnings))
        self.assertIn("only while the exact target identity", " ".join(plan.warnings))
        self.assertIn("reported as unknown", " ".join(plan.warnings))

    def test_nonremovable_and_unsupported_transport_are_rejected(self) -> None:
        for candidate in (
            device(removable=False),
            device(transport="sata"),
            device(logical_sector_size=1000),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(FastZeroPlanError):
                    build_fast_zero_plan(
                        candidate,
                        observe=lambda _device, candidate=candidate: observation(candidate),
                    )

    def test_replacement_disk_sequence_is_rejected(self) -> None:
        selected = device()
        plan = build_fast_zero_plan(selected, observe=lambda _device: observation(selected))
        with self.assertRaisesRegex(FastZeroPlanError, "generation changed"):
            validate_fast_zero_plan(
                plan,
                observe=lambda _device: observation(selected, disk_sequence=DISK_SEQUENCE + 1),
            )

    def test_frozen_dataclass_clone_cannot_reuse_private_receipt(self) -> None:
        selected = device()
        plan = build_fast_zero_plan(selected, observe=lambda _device: observation(selected))
        cloned = replace(plan)
        with self.assertRaisesRegex(FastZeroPlanError, "forged, cloned"):
            validate_fast_zero_plan(cloned, observe=lambda _device: observation(selected))

    def test_confirmation_is_exact_case_sensitive_and_ascii(self) -> None:
        selected = device()
        plan = build_fast_zero_plan(selected, observe=lambda _device: observation(selected))
        for phrase in (plan.confirmation_phrase.lower(), plan.confirmation_phrase + " ", "é"):
            with self.assertRaises(FastZeroPlanError):
                confirm_fast_zero(plan, phrase, observe=lambda _device: observation(selected))

    def test_only_mountpoints_may_change_during_unmount(self) -> None:
        plan, confirmed, ready = plan_and_ready()
        validate_ready_fast_zero(
            plan,
            confirmed,
            ready,
            observe_path=lambda _path: observation(device(mounted=False)),
        )
        with self.assertRaisesRegex(FastZeroPlanError, "changed"):
            authorize_unmounted_fast_zero(
                plan,
                confirmed,
                observe_path=lambda _path: observation(
                    device(mounted=False, serial="replacement"),
                ),
            )

    def test_stale_ready_receipt_rejects_replug(self) -> None:
        plan, confirmed, ready = plan_and_ready()
        with self.assertRaisesRegex(FastZeroPlanError, "changed"):
            validate_ready_fast_zero(
                plan,
                confirmed,
                ready,
                observe_path=lambda _path: observation(
                    device(mounted=False),
                    disk_sequence=DISK_SEQUENCE + 1,
                ),
            )


class InstallationTests(unittest.TestCase):
    @staticmethod
    def _policy(helper_path: str, *, allow_active: str = "auth_admin") -> str:
        return f'''<?xml version="1.0"?>
<policyconfig><action id="{fast_zero_module.POLICY_ACTION}">
<description>{fast_zero_module.POLICY_DESCRIPTION}</description>
<message>{fast_zero_module.POLICY_MESSAGE}</message>
<defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive>
<allow_active>{allow_active}</allow_active></defaults>
<annotate key="org.freedesktop.policykit.exec.path">{helper_path}</annotate>
<annotate key="org.freedesktop.policykit.exec.argv1">{protocol.FAST_ZERO_OPERATION}</annotate>
</action></policyconfig>'''

    def _resolver_context(
        self,
        pkexec: Path,
        helper: Path,
        script: Path,
        policy: Path,
        root_status: object,
    ) -> tuple[object, ...]:
        return (
            patch.object(fast_zero_module, "PKEXEC_PATH", os.fspath(pkexec)),
            patch.object(fast_zero_module, "HELPER_PATH", os.fspath(helper)),
            patch.object(
                fast_zero_module,
                "HELPER_SCRIPT_PATH",
                os.fspath(script),
            ),
            patch.object(fast_zero_module, "POLICY_PATH", os.fspath(policy)),
            patch.object(fast_zero_module.os, "lstat", side_effect=root_status),
            patch.object(
                fast_zero_module.os.path,
                "realpath",
                side_effect=lambda value: value,
            ),
            patch.object(fast_zero_module, "_trusted_parents"),
        )

    def test_exact_policy_resolves_and_broader_or_ambiguous_policy_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pkexec = root / "usr/bin/pkexec"
            helper = root / "usr/libexec/isopropyl-device-helper"
            script = root / "usr/libexec/isopropyl/syslinux_device_helper.py"
            policy = root / "usr/share/polkit-1/actions/fast-zero.policy"
            for path in (pkexec, helper, script, policy):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            valid = self._policy(os.fspath(helper))
            policy.write_text(valid, encoding="utf-8")
            actual_lstat = os.lstat

            def root_status(path: str) -> SimpleNamespace:
                status = actual_lstat(path)
                mode = status.st_mode & ~0o022
                if os.fspath(path) == os.fspath(pkexec):
                    mode |= stat.S_ISUID | 0o500
                elif os.fspath(path) == os.fspath(helper):
                    mode |= 0o500
                else:
                    mode |= 0o400
                return SimpleNamespace(st_mode=mode, st_uid=0)

            contexts = self._resolver_context(
                pkexec,
                helper,
                script,
                policy,
                root_status,
            )
            with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4], contexts[5], contexts[6]:
                installation = resolve_fast_zero_helper_installation()
                self.assertEqual(installation.helper, os.fspath(helper))

            invalid = (
                (valid.replace("auth_admin", "auth_admin_keep"), "broader"),
                (
                    valid.replace(
                        "</action>",
                        "<defaults><allow_any>yes</allow_any></defaults></action>",
                    ),
                    "ambiguous",
                ),
            )
            for text, message in invalid:
                policy.write_text(text, encoding="utf-8")
                contexts = self._resolver_context(
                    pkexec,
                    helper,
                    script,
                    policy,
                    root_status,
                )
                with (
                    self.subTest(message=message),
                    contexts[0],
                    contexts[1],
                    contexts[2],
                    contexts[3],
                    contexts[4],
                    contexts[5],
                    contexts[6],
                    self.assertRaisesRegex(FastZeroRunError, message),
                ):
                    resolve_fast_zero_helper_installation()


class FakeFastZeroProcess:
    def __init__(self, child_fd: int, *, mode: str = "success") -> None:
        self.mode = mode
        self.channel = socket.socket(fileno=os.dup(child_fd))
        self.stderr = io.BytesIO()
        self.returncode: int | None = None
        self.terminated = 0
        self.killed = 0
        self.request_packet = b""
        self.control_packets: list[bytes] = []
        self.request_seen = threading.Event()
        self.allow_ready = threading.Event()
        if mode != "delay-ready":
            self.allow_ready.set()
        self.allow_prepared = threading.Event()
        if mode != "delay-prepared":
            self.allow_prepared.set()
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    @staticmethod
    def _header(kind: int) -> bytes:
        return protocol._HEADER.pack(
            protocol.FAST_ZERO_PROTOCOL_MAGIC,
            protocol.PROTOCOL_VERSION,
            kind,
            0,
        )

    @staticmethod
    def _control(kind: int) -> bytes:
        return protocol._CONTROL_PACKET.pack(
            protocol.FAST_ZERO_PROTOCOL_MAGIC,
            protocol.PROTOCOL_VERSION,
            kind,
            0,
            REQUEST_ID,
        )

    @staticmethod
    def _progress(phase: str, done: int, total: int) -> bytes:
        return protocol._PROGRESS_PACKET.pack(
            protocol.FAST_ZERO_PROTOCOL_MAGIC,
            protocol.PROTOCOL_VERSION,
            protocol.PACKET_PROGRESS,
            0,
            REQUEST_ID,
            protocol.FAST_ZERO_PHASE_CODES[phase],
            done,
            total,
        )

    @staticmethod
    def _result(outcome: str, *, invalid_accounting: bool = False) -> bytes:
        partial = outcome != "success"
        scanned = 0 if partial else TARGET_SIZE
        written = scanned if not invalid_accounting else scanned - 512
        skipped = 0
        helper_result = protocol.FastZeroHelperResult(
            REQUEST_ID,
            protocol.FAST_ZERO_HELPER_PROFILE,
            "/dev/sdz",
            "8:240",
            DISK_SEQUENCE,
            TARGET_SIZE,
            512,
            FAST_ZERO_CHUNK_BYTES,
            scanned,
            written,
            skipped,
            0 if partial else TARGET_SIZE,
            0 if partial else 2,
            0 if partial else 2,
            0,
            min(TARGET_SIZE, 2 * FAST_ZERO_BOUNDARY_BYTES) if partial else 0,
            (
                protocol.FAST_ZERO_FAILURE_CANCELLED
                if outcome == "partial-cancel"
                else (
                    protocol.FAST_ZERO_FAILURE_IO
                    if outcome == "partial-failure"
                    else protocol.FAST_ZERO_FAILURE_NONE
                )
            ),
            outcome,
            True,
            True,
            not partial,
            partial,
            True,
        )
        return protocol._pack_fast_zero_result(helper_result)

    def _serve(self) -> None:
        try:
            self.allow_ready.wait(2)
            ready = self._header(protocol.PACKET_READY)
            if self.mode == "wrong-ready":
                ready = protocol._HEADER.pack(
                    protocol.RAW_PROTOCOL_MAGIC,
                    protocol.PROTOCOL_VERSION,
                    protocol.PACKET_READY,
                    0,
                )
            self.channel.send(ready)
            if self.mode == "wrong-ready":
                return
            packet, ancillary, flags, _address = self.channel.recvmsg(
                protocol.MAX_PROTOCOL_PACKET,
                socket.CMSG_SPACE(4),
            )
            self.request_packet = packet
            self.request_seen.set()
            if ancillary or flags:
                self.stderr.write(b"unexpected descriptor or ancillary data")
                self.returncode = 2
                return
            self.allow_prepared.wait(2)
            self.channel.send(self._control(protocol.PACKET_PREPARED))
            decision = self.channel.recv(protocol.MAX_PROTOCOL_PACKET)
            self.control_packets.append(decision)
            decoded = protocol._CONTROL_PACKET.unpack(decision)
            if decoded[2] == protocol.PACKET_CANCEL:
                return
            self.channel.send(self._control(protocol.PACKET_MUTATION_STARTED))
            self.channel.send(self._progress("scanning", 0, TARGET_SIZE))
            if self.mode in {"partial-cancel", "partial-failure"}:
                if self.mode == "partial-cancel":
                    decision = self.channel.recv(protocol.MAX_PROTOCOL_PACKET)
                    self.control_packets.append(decision)
                self.channel.send(
                    self._progress(
                        "cleanup",
                        0,
                        min(TARGET_SIZE, 2 * FAST_ZERO_BOUNDARY_BYTES),
                    ),
                )
                self.channel.send(
                    self._progress(
                        "cleanup",
                        min(TARGET_SIZE, 2 * FAST_ZERO_BOUNDARY_BYTES),
                        min(TARGET_SIZE, 2 * FAST_ZERO_BOUNDARY_BYTES),
                    ),
                )
                self.channel.send(self._result(self.mode))
                return
            self.channel.send(self._progress("scanning", TARGET_SIZE, TARGET_SIZE))
            self.channel.send(self._progress("readback", 0, TARGET_SIZE))
            self.channel.send(self._progress("readback", TARGET_SIZE, TARGET_SIZE))
            self.channel.send(
                self._result(
                    "success",
                    invalid_accounting=self.mode == "bad-accounting",
                ),
            )
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.returncode = self.returncode or 0
            try:
                self.channel.close()
            except OSError:
                pass
            self.done.set()

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if not self.done.wait(timeout):
            raise subprocess.TimeoutExpired("fake-fast-zero", timeout)
        assert self.returncode is not None
        return self.returncode

    def terminate(self) -> None:
        self.terminated += 1
        self.returncode = -15
        self.channel.close()
        self.done.set()

    def kill(self) -> None:
        self.killed += 1
        self.terminate()


class RunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan, self.confirmed, self.ready = plan_and_ready()
        self.installation = FastZeroHelperInstallation(
            "/usr/bin/pkexec",
            "/usr/libexec/isopropyl-device-helper",
            "/usr/libexec/isopropyl/syslinux_device_helper.py",
            "/usr/share/polkit-1/actions/test.policy",
        )

    def _runner(self, mode: str) -> tuple[FastZeroRunner, list[FakeFastZeroProcess]]:
        processes: list[FakeFastZeroProcess] = []

        def popen(_argv: object, **kwargs: object) -> FakeFastZeroProcess:
            process = FakeFastZeroProcess(int(kwargs["stdin"]), mode=mode)
            processes.append(process)
            return process

        runner = FastZeroRunner(
            popen=popen,  # type: ignore[arg-type]
            request_id=lambda _size: REQUEST_ID,
        )
        return runner, processes

    def test_success_is_fully_bound_and_no_descriptor_is_transferred(self) -> None:
        runner, processes = self._runner("success")
        seen: list[tuple[str, int, int]] = []
        result = runner._invoke_helper(
            self.installation,
            self.plan,
            self.ready,
            lambda *values: seen.append(values),
        )
        self.assertIsInstance(result, FastZeroResult)
        self.assertEqual(result.scanned_bytes, TARGET_SIZE)
        self.assertEqual(result.verified_bytes, TARGET_SIZE)
        self.assertEqual(result.written_bytes + result.skipped_bytes, TARGET_SIZE)
        self.assertTrue(result.complete)
        self.assertFalse(result.cleanup_verified)
        self.assertEqual([item[0] for item in seen], ["scanning", "scanning", "readback", "readback"])
        self.assertEqual(len(processes), 1)
        request = protocol._FAST_ZERO_REQUEST_PACKET.unpack(
            processes[0].request_packet,
        )
        self.assertEqual(request[4], REQUEST_ID)
        self.assertEqual(request[11].hex(), self.plan.plan_sha256)
        self.assertEqual(request[12].hex(), self.ready.ready_sha256)

    def test_committed_helper_is_reaped_before_operation_ownership_returns(self) -> None:
        class HeldCommittedProcess:
            def __init__(self) -> None:
                self.released = threading.Event()
                self.returncode: int | None = None
                self.terminated = 0

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                if not self.released.wait(timeout):
                    raise subprocess.TimeoutExpired("held-fast-zero", timeout)
                self.returncode = 0
                return 0

            def terminate(self) -> None:
                self.terminated += 1

        process = HeldCommittedProcess()
        runner = FastZeroRunner()
        returned = threading.Event()

        def reap() -> None:
            runner._stop_and_reap(  # type: ignore[arg-type]
                process,
                safe_to_kill=False,
            )
            returned.set()

        worker = threading.Thread(target=reap)
        worker.start()
        self.assertFalse(returned.wait(0.05))
        self.assertEqual(process.terminated, 0)
        process.released.set()
        worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertTrue(returned.is_set())

    def test_postcommit_cancel_returns_only_verified_partial_evidence(self) -> None:
        runner, _processes = self._runner("partial-cancel")

        def progress(phase: str, done: int, _total: int) -> None:
            if phase == "scanning" and done == 0:
                runner.cancel()

        with self.assertRaises(FastZeroCancelled) as caught:
            runner._invoke_helper(
                self.installation,
                self.plan,
                self.ready,
                progress,
            )
        partial = caught.exception.partial
        self.assertIsInstance(partial, FastZeroPartialResult)
        assert partial is not None
        self.assertFalse(partial.complete)
        self.assertTrue(partial.cleanup_verified)
        self.assertTrue(partial.cleanup_durable)
        self.assertEqual(partial.boundary_cleanup_bytes, 32 * 1024 * 1024)

    def test_generic_postcommit_failure_is_not_reported_as_cancellation(self) -> None:
        runner, _processes = self._runner("partial-failure")
        with self.assertRaises(FastZeroRunError) as caught:
            runner._invoke_helper(
                self.installation,
                self.plan,
                self.ready,
                lambda *_values: None,
            )
        self.assertIsInstance(caught.exception.partial, FastZeroPartialFailure)
        assert caught.exception.partial is not None
        self.assertEqual(
            caught.exception.partial.failure_code,
            protocol.FAST_ZERO_FAILURE_IO,
        )

    def test_wrong_protocol_magic_and_bad_accounting_fail_closed(self) -> None:
        for mode in ("wrong-ready", "bad-accounting"):
            with self.subTest(mode=mode):
                runner, _processes = self._runner(mode)
                with self.assertRaises(FastZeroRunError):
                    runner._invoke_helper(
                        self.installation,
                        self.plan,
                        self.ready,
                        lambda *_values: None,
                    )

    def test_impossible_byte_chunk_geometry_fails_closed(self) -> None:
        terminal = list(
            protocol.unpack_fast_zero_server_packet(
                FakeFastZeroProcess._result("success"),
            ),
        )
        terminal[9] = 1
        terminal[10] = TARGET_SIZE - 1
        terminal[13] = 1
        terminal[14] = 1
        with self.assertRaisesRegex(FastZeroRunError, "accounting"):
            FastZeroRunner._validate_accounting(
                tuple(terminal),
                plan=self.plan,
                ready=self.ready,
                request_id=REQUEST_ID,
                major=8,
                minor=240,
                mutation_started=True,
                progress={"scanning": TARGET_SIZE, "readback": TARGET_SIZE},
            )

    def test_zero_counter_partial_accepts_cleanup_as_first_progress_phase(self) -> None:
        terminal = protocol.unpack_fast_zero_server_packet(
            FakeFastZeroProcess._result("partial-failure"),
        )
        outcome, values = FastZeroRunner._validate_accounting(
            terminal,
            plan=self.plan,
            ready=self.ready,
            request_id=REQUEST_ID,
            major=8,
            minor=240,
            mutation_started=True,
            progress={
                "cleanup": min(
                    TARGET_SIZE,
                    2 * FAST_ZERO_BOUNDARY_BYTES,
                ),
            },
        )
        self.assertEqual(outcome, "partial-failure")
        self.assertEqual(values["scanned_bytes"], 0)
        self.assertTrue(values["cleanup_verified"])

    def test_precommit_cancel_sends_cancel_and_never_returns_partial(self) -> None:
        runner, processes = self._runner("success")
        runner.cancel()
        with self.assertRaises(FastZeroCancelled) as caught:
            runner._invoke_helper(
                self.installation,
                self.plan,
                self.ready,
                lambda *_values: None,
            )
        self.assertIsNone(caught.exception.partial)
        # Cancellation before helper launch is rejected without starting root.
        self.assertEqual(processes, [])

    def test_cancel_during_initial_handshake_is_precommit_cancellation(self) -> None:
        runner, processes = self._runner("delay-ready")
        caught: list[BaseException] = []

        def invoke() -> None:
            try:
                runner._invoke_helper(
                    self.installation,
                    self.plan,
                    self.ready,
                    lambda *_values: None,
                )
            except BaseException as error:
                caught.append(error)

        worker = threading.Thread(target=invoke)
        worker.start()
        while not processes:
            time.sleep(0.001)
        runner.cancel()
        processes[0].allow_ready.set()
        worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertIsInstance(caught[0], FastZeroCancelled)
        self.assertIsNone(caught[0].partial)  # type: ignore[attr-defined]
        self.assertFalse(runner._commit_sent)

    def test_cancel_after_request_but_before_prepared_never_commits(self) -> None:
        runner, processes = self._runner("delay-prepared")
        caught: list[BaseException] = []

        def invoke() -> None:
            try:
                runner._invoke_helper(
                    self.installation,
                    self.plan,
                    self.ready,
                    lambda *_values: None,
                )
            except BaseException as error:
                caught.append(error)

        thread = threading.Thread(target=invoke)
        thread.start()
        while not processes:
            time.sleep(0.001)
        self.assertTrue(processes[0].request_seen.wait(1))
        runner.cancel()
        processes[0].allow_prepared.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertIsInstance(caught[0], FastZeroCancelled)
        self.assertIsNone(caught[0].partial)  # type: ignore[attr-defined]
        controls = [protocol._CONTROL_PACKET.unpack(item)[2] for item in processes[0].control_packets]
        self.assertEqual(controls, [protocol.PACKET_CANCEL])

    def test_full_runner_preflights_unmounts_and_rewitnesses_before_helper(self) -> None:
        events: list[str] = []

        def resolve() -> FastZeroHelperInstallation:
            events.append("preflight")
            return self.installation

        runner = FastZeroRunner(
            resolve_installation=resolve,
            observe_selected=lambda _device: observation(device()),
            observe_path=lambda _path: observation(device(mounted=False)),
            which=lambda name: f"/usr/bin/{name}",
        )
        expected = success_result(self.plan)

        def unmount(*_args: object, **_kwargs: object) -> None:
            events.append("unmount")

        def invoke(*_args: object, **_kwargs: object) -> FastZeroResult:
            events.append("helper")
            return expected

        with (
            patch("isopropyl.fast_zero.unmount_device", side_effect=unmount),
            patch.object(runner, "_invoke_helper", side_effect=invoke),
        ):
            result = runner.run(self.plan, self.confirmed)
        self.assertIs(result, expected)
        self.assertEqual(events, ["preflight", "unmount", "helper"])

    def test_replacement_before_unmount_never_reaches_preflight_or_mutation(self) -> None:
        events: list[str] = []
        replacement = observation(
            device(serial="replacement"),
            disk_sequence=DISK_SEQUENCE + 1,
        )
        runner = FastZeroRunner(
            resolve_installation=lambda: events.append("preflight"),  # type: ignore[arg-type]
            observe_selected=lambda _device: replacement,
        )
        with (
            patch("isopropyl.fast_zero.unmount_device") as unmount,
            self.assertRaises(FastZeroPlanError),
        ):
            runner.run(self.plan, self.confirmed)
        self.assertEqual(events, [])
        unmount.assert_not_called()


def success_result(plan: object) -> FastZeroResult:
    return FastZeroResult(
        REQUEST_ID.hex(),
        plan.plan_sha256,  # type: ignore[attr-defined]
        "ef" * 32,
        "/dev/sdz",
        "8:240",
        DISK_SEQUENCE,
        TARGET_SIZE,
        512,
        FAST_ZERO_CHUNK_BYTES,
        TARGET_SIZE,
        TARGET_SIZE,
        0,
        TARGET_SIZE,
        2,
        2,
        0,
        0,
        False,
        True,
        True,
        True,
        True,
        False,
    )


class FakeWorkflowRunner:
    def __init__(self, *, error: BaseException | None = None) -> None:
        self.error = error
        self.cancelled = 0

    def run(self, plan: object, _confirmation: object, _progress: object) -> FastZeroResult:
        if self.error is not None:
            raise self.error
        return success_result(plan)

    def cancel(self) -> None:
        self.cancelled += 1


class WorkflowTests(unittest.TestCase):
    def _dependencies(
        self,
        events: list[str],
        runner: FakeWorkflowRunner,
    ) -> FastZeroDependencies:
        selected = device()

        def resolve() -> object:
            events.append("preflight")
            return object()

        def build(value: Device, **_kwargs: object) -> object:
            events.append("plan")
            return build_fast_zero_plan(
                value,
                observe=lambda _device: observation(selected),
            )

        def confirm(plan: object, phrase: str) -> ConfirmedFastZero:
            events.append("confirm")
            return confirm_fast_zero(
                plan,  # type: ignore[arg-type]
                phrase,
                observe=lambda _device: observation(selected),
            )

        return FastZeroDependencies(
            resolve_helper=resolve,
            build_plan=build,  # type: ignore[arg-type]
            confirm_plan=confirm,  # type: ignore[arg-type]
            runner_factory=lambda: runner,  # type: ignore[arg-type]
        )

    def test_full_lifecycle_preflights_before_planning(self) -> None:
        events: list[str] = []
        fake = FakeWorkflowRunner()
        workflow = FastZeroWorkflow(
            device(),
            dependencies=self._dependencies(events, fake),
        )
        plan = workflow.prepare()
        self.assertEqual(events, ["preflight", "plan"])
        workflow.confirm(plan.confirmation_phrase)
        result = workflow.execute()
        self.assertTrue(result.complete)
        self.assertEqual(workflow.state, FastZeroState.COMPLETED)
        self.assertIs(result, workflow.result)

    def test_wrong_confirmation_never_reaches_runner(self) -> None:
        events: list[str] = []
        fake = FakeWorkflowRunner()
        workflow = FastZeroWorkflow(
            device(),
            dependencies=self._dependencies(events, fake),
        )
        workflow.prepare()
        with self.assertRaises(FastZeroPlanError):
            workflow.confirm("FAST ZERO /dev/sdz 8:241")
        self.assertEqual(workflow.state, FastZeroState.PREPARED)

    def test_partial_cancel_state_and_evidence_are_retained(self) -> None:
        events: list[str] = []
        plan = build_fast_zero_plan(
            device(),
            observe=lambda _device: observation(device()),
        )
        base = success_result(plan)
        partial = FastZeroPartialResult(
            **{
                key: value
                for key, value in base.__dict__.items()
                if key != "cancellation_deferred"
            }
        )
        partial = replace(
            partial,
            complete=False,
            boundary_cleanup_bytes=32 * 1024 * 1024,
            cleanup_verified=True,
        )
        fake = FakeWorkflowRunner(error=FastZeroCancelled("partial", partial=partial))
        workflow = FastZeroWorkflow(
            device(),
            dependencies=self._dependencies(events, fake),
        )
        selected = workflow.prepare()
        workflow.confirm(selected.confirmation_phrase)
        with self.assertRaises(FastZeroCancelled):
            workflow.execute()
        self.assertEqual(workflow.state, FastZeroState.PARTIAL_CANCELLED)
        self.assertIs(workflow.partial_result, partial)

    def test_cancel_and_close_propagate_to_active_runner(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        class BlockingRunner(FakeWorkflowRunner):
            def run(self, plan: object, _confirmation: object, _progress: object) -> FastZeroResult:
                entered.set()
                release.wait(2)
                raise FastZeroCancelled("cancelled")

            def cancel(self) -> None:
                super().cancel()
                release.set()

        events: list[str] = []
        runner = BlockingRunner()
        workflow = FastZeroWorkflow(
            device(),
            dependencies=self._dependencies(events, runner),
        )
        plan = workflow.prepare()
        workflow.confirm(plan.confirmation_phrase)
        failures: list[BaseException] = []

        def execute() -> None:
            try:
                workflow.execute()
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=execute)
        thread.start()
        self.assertTrue(entered.wait(1))
        workflow.close()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(runner.cancelled, 1)
        self.assertEqual(workflow.state, FastZeroState.CLOSED)
        self.assertIsInstance(failures[0], FastZeroCancelled)

    def test_cancel_race_during_prepare_cannot_publish_plan(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        events: list[str] = []
        fake = FakeWorkflowRunner()
        dependencies = self._dependencies(events, fake)

        def blocking_build(*args: object, **kwargs: object) -> object:
            entered.set()
            release.wait(2)
            return dependencies.build_plan(*args, **kwargs)

        workflow = FastZeroWorkflow(
            device(),
            dependencies=replace(dependencies, build_plan=blocking_build),
        )
        failures: list[BaseException] = []

        def prepare() -> None:
            try:
                workflow.prepare()
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=prepare)
        thread.start()
        self.assertTrue(entered.wait(1))
        workflow.cancel()
        release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertIsNone(workflow.plan)
        self.assertEqual(workflow.state, FastZeroState.CANCELLED)
        self.assertIsInstance(failures[0], FastZeroCancelled)


if __name__ == "__main__":
    unittest.main()
