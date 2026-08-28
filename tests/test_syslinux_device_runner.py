from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import array
import io
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import isopropyl.syslinux_device_helper as protocol
import isopropyl.syslinux_device_runner as runner_module
import isopropyl.syslinux_iso_fat32 as composite_module
from isopropyl.syslinux_iso_fat32 import (
    PreparedSyslinuxIsoFat32,
    SyslinuxIsoFat32Result,
)
from isopropyl.syslinux_device_runner import (
    HELPER_PATH,
    HELPER_SCRIPT_PATH,
    PKEXEC_PATH,
    POLICY_ACTION,
    POLICY_PATH,
    HelperInstallation,
    SyslinuxDeviceHelperUnavailable,
    SyslinuxDeviceRunCancelled,
    SyslinuxDeviceRunError,
    SyslinuxDeviceWriteRunner,
    resolve_syslinux_helper_installation,
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
                protocol.PROTOCOL_MAGIC,
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
                protocol.PROTOCOL_MAGIC,
                protocol.PROTOCOL_VERSION,
                protocol.PACKET_REQUEST,
                0,
            ):
                raise AssertionError("bad request")
            if self.mode == "stall-precommit":
                self.channel.recv(protocol.MAX_PROTOCOL_PACKET)
                self.returncode = 5
                return
            phases = list(protocol.PHASE_CODES)
            if self.mode == "out-of-order":
                phases = ["writing", "source-validation"]
            elif self.mode == "missing-phase":
                phases = phases[:-1]
            mutation_sent = False
            prepared_sent = False
            for phase in phases:
                if (
                    phase == "writing"
                    and not prepared_sent
                    and self.mode != "out-of-order"
                ):
                    self._send(protocol._CONTROL_PACKET.pack(
                        protocol.PROTOCOL_MAGIC,
                        protocol.PROTOCOL_VERSION,
                        protocol.PACKET_PREPARED,
                        0,
                        request_id,
                    ))
                    prepared_sent = True
                    decision = self.channel.recv(protocol.MAX_PROTOCOL_PACKET)
                    (
                        control_magic,
                        control_version,
                        control_type,
                        control_reserved,
                        control_id,
                    ) = protocol._CONTROL_PACKET.unpack(decision)
                    if (
                        control_magic != protocol.PROTOCOL_MAGIC
                        or control_version != protocol.PROTOCOL_VERSION
                        or control_reserved != 0
                        or control_id != request_id
                        or control_type not in {
                            protocol.PACKET_COMMIT,
                            protocol.PACKET_CANCEL,
                        }
                    ):
                        raise AssertionError("bad control decision")
                    if control_type == protocol.PACKET_CANCEL:
                        self.returncode = 7
                        return
                    if self.mode != "missing-mutation":
                        self._send(protocol._MUTATION_PACKET.pack(
                            protocol.PROTOCOL_MAGIC,
                            protocol.PROTOCOL_VERSION,
                            protocol.PACKET_MUTATION_STARTED,
                            0,
                            request_id,
                        ))
                        mutation_sent = True
                total = size - 512 if phase == "preactivation-readback" else size
                for done in (0, total):
                    self._send(protocol._PROGRESS_PACKET.pack(
                        protocol.PROTOCOL_MAGIC,
                        protocol.PROTOCOL_VERSION,
                        protocol.PACKET_PROGRESS,
                        0,
                        b"X" * 16 if self.mode == "wrong-request" else request_id,
                        protocol.PHASE_CODES[phase],
                        done,
                        total,
                    ))
            if self.mode in {"exit-error", "post-mutation-error"}:
                self.stderr = io.BytesIO(b"injected helper error")
                self.returncode = 4
                return
            result_digest = b"\0" * 32 if self.mode == "wrong-digest" else digest
            result_disk_sequence = (
                disk_sequence + 1
                if self.mode == "wrong-diskseq"
                else disk_sequence
            )
            self._send(protocol._SUCCESS_PACKET.pack(
                protocol.PROTOCOL_MAGIC,
                protocol.PROTOCOL_VERSION,
                protocol.PACKET_SUCCESS,
                0,
                request_id,
                major_number,
                minor_number,
                result_disk_sequence,
                size,
                sector_size,
                disk_signature,
                volume_id,
                digest,
                digest,
                result_digest,
            ))
            if self.mode == "extra":
                self._send(b"unexpected trailing packet")
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
            raise subprocess.TimeoutExpired("fake-helper", timeout)
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
    )
    ready = SimpleNamespace(
        ready_sha256="22" * 32,
        disk_sequence=DISK_SEQUENCE,
        device=SimpleNamespace(path="/dev/sdz", major_minor="8:240"),
    )
    prepared = FakePrepared()
    prepared_result = SimpleNamespace(final_image_sha256=IMAGE_SHA256)
    installation = HelperInstallation(
        PKEXEC_PATH,
        HELPER_PATH,
        HELPER_SCRIPT_PATH,
        POLICY_PATH,
    )
    return plan, ready, prepared, prepared_result, installation


class ProtocolRunnerTests(unittest.TestCase):
    def test_exact_pkexec_socket_fd_transfer_and_bound_success(self):
        factory = PopenFactory()
        runner = SyslinuxDeviceWriteRunner(
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
        self.assertEqual(result.disk_sequence, DISK_SEQUENCE)
        self.assertEqual(result.image_sha256, IMAGE_SHA256)
        self.assertTrue(result.exclusive_open)
        self.assertTrue(result.cache_invalidated)
        self.assertTrue(result.mandatory_readback)
        self.assertFalse(result.cancellation_deferred)
        self.assertEqual(len(prepared.sent_packets), 1)
        command, kwargs = factory.calls[0]
        self.assertEqual(command, [
            PKEXEC_PATH,
            "--disable-internal-agent",
            HELPER_PATH,
            protocol.OPERATION,
        ])
        self.assertTrue(kwargs["close_fds"])
        self.assertFalse(kwargs["shell"])
        self.assertNotIn("pass_fds", kwargs)
        self.assertIsInstance(kwargs["stdin"], int)
        self.assertEqual({update[0] for update in updates}, set(protocol.PHASE_CODES))

    def test_wrong_digest_out_of_order_and_error_exit_are_rejected(self):
        for mode, message in (
            ("wrong-digest", "does not match"),
            ("out-of-order", "sequence"),
            ("wrong-request", "another request"),
            ("wrong-diskseq", "does not match"),
            ("missing-phase", "does not match"),
            ("missing-mutation", "sequence"),
            ("exit-error", "injected helper error"),
            ("extra", "after its terminal result"),
        ):
            factory = PopenFactory(mode)
            runner = SyslinuxDeviceWriteRunner(
                popen=factory,
                request_id=lambda _size: REQUEST_ID,
            )
            plan, ready, prepared, prepared_result, installation = helper_inputs()
            with self.subTest(mode=mode), self.assertRaisesRegex(
                SyslinuxDeviceRunError,
                message,
            ):
                runner._invoke_helper(
                    installation,
                    plan,
                    ready,
                    prepared,
                    prepared_result,
                    lambda *_update: None,
                )

    def test_runner_is_single_use_and_precancel_reaches_nothing(self):
        runner = SyslinuxDeviceWriteRunner()
        runner.cancel()
        with self.assertRaises(SyslinuxDeviceRunCancelled):
            runner.run(None, None)  # type: ignore[arg-type]
        with self.assertRaisesRegex(SyslinuxDeviceRunError, "only be used once"):
            runner.run(None, None)  # type: ignore[arg-type]

    def test_postmutation_failure_is_not_misreported_as_cancellation(self):
        factory = PopenFactory("post-mutation-error")
        runner = SyslinuxDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
        )
        plan, ready, prepared, prepared_result, installation = helper_inputs()

        def cancel_after_mutation(stage: str, *_update) -> None:
            if stage == "writing":
                runner.cancel()

        with self.assertRaises(SyslinuxDeviceRunError) as caught:
            runner._invoke_helper(
                installation,
                plan,
                ready,
                prepared,
                prepared_result,
                cancel_after_mutation,
            )
        self.assertNotIsInstance(caught.exception, SyslinuxDeviceRunCancelled)
        self.assertIn("injected helper error", str(caught.exception))

    def test_in_band_cancel_before_commit_never_terminates_root_helper(self):
        factory = PopenFactory()
        runner = SyslinuxDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
        )
        plan, ready, prepared, prepared_result, installation = helper_inputs()

        def cancel_during_source(stage: str, _path: str, done: int, total: int) -> None:
            if stage == "source-validation" and done == total:
                runner.cancel()

        with self.assertRaises(SyslinuxDeviceRunCancelled):
            runner._invoke_helper(
                installation,
                plan,
                ready,
                prepared,
                prepared_result,
                cancel_during_source,
            )
        self.assertEqual(factory.processes[0].terminated, 0)
        self.assertEqual(factory.processes[0].killed, 0)

    def test_cancel_after_commit_is_deferred_through_verified_success(self):
        factory = PopenFactory()
        runner = SyslinuxDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
        )
        plan, ready, prepared, prepared_result, installation = helper_inputs()

        def cancel_during_write(stage: str, *_update) -> None:
            if stage == "writing":
                runner.cancel()

        result = runner._invoke_helper(
            installation,
            plan,
            ready,
            prepared,
            prepared_result,
            cancel_during_write,
        )
        self.assertTrue(result.cancellation_deferred)
        self.assertEqual(factory.processes[0].terminated, 0)

    def test_stalled_precommit_helper_returns_without_claiming_mutation(self):
        factory = PopenFactory("stall-precommit")
        ticks = iter((0.0, 0.0, 301.0, 301.0))
        runner = SyslinuxDeviceWriteRunner(
            popen=factory,
            request_id=lambda _size: REQUEST_ID,
            clock=lambda: next(ticks, 301.0),
        )
        plan, ready, prepared, prepared_result, installation = helper_inputs()
        with self.assertRaisesRegex(SyslinuxDeviceRunError, "no write commit was sent"):
            runner._invoke_helper(
                installation,
                plan,
                ready,
                prepared,
                prepared_result,
                lambda *_update: None,
            )
        self.assertFalse(runner._commit_sent)


class OrchestrationTests(unittest.TestCase):
    def test_prepared_validation_uses_the_real_composite_result_schema(self):
        plan = SimpleNamespace(
            composite_plan=SimpleNamespace(
                plan_sha256="11" * 32,
                version="6.04",
            ),
            private_plan_sha256="22" * 32,
            disk_signature=DISK_SIGNATURE,
            volume_id=VOLUME_ID,
            image_size=IMAGE_SIZE,
        )
        result = SyslinuxIsoFat32Result(
            plan_sha256=plan.composite_plan.plan_sha256,
            private_plan_sha256=plan.private_plan_sha256,
            transaction_plan_sha256="33" * 32,
            version=plan.composite_plan.version,
            disk_signature=plan.disk_signature,
            volume_id=plan.volume_id,
            image_size=plan.image_size,
            unpatched_image_sha256="44" * 32,
            final_image_sha256="55" * 32,
            unpatched_manifest_sha256="66" * 32,
            final_manifest_sha256="77" * 32,
            unpatched_ldlinux_sha256="88" * 32,
            patched_ldlinux_sha256="99" * 32,
            files_verified=3,
            directories_verified=2,
            bytes_verified=1_024,
        )
        owner = object.__new__(PreparedSyslinuxIsoFat32)
        owner._image = None
        owner._result = result
        owner._witness = composite_module._OWNER_WITNESS

        self.assertIs(runner_module._validate_prepared(plan, owner), result)

        owner._result = replace(
            result,
            final_image_sha256=result.unpatched_image_sha256,
        )
        with self.assertRaisesRegex(SyslinuxDeviceRunError, "does not match"):
            runner_module._validate_prepared(plan, owner)

    def test_helper_is_verified_before_image_preparation_or_unmount(self):
        runner = SyslinuxDeviceWriteRunner()
        with (
            patch.object(runner_module, "validate_confirmed_syslinux_device_write"),
            patch.object(
                runner_module,
                "resolve_syslinux_helper_installation",
                side_effect=SyslinuxDeviceHelperUnavailable("not installed"),
            ),
            patch.object(
                runner_module,
                "prepare_syslinux_iso_fat32",
                side_effect=AssertionError("prepared before helper validation"),
            ) as prepare,
            patch.object(
                runner_module,
                "unmount_device",
                side_effect=AssertionError("unmounted before helper validation"),
            ) as unmount,
            self.assertRaises(SyslinuxDeviceHelperUnavailable),
        ):
            runner.run(SimpleNamespace(), SimpleNamespace())
        prepare.assert_not_called()
        unmount.assert_not_called()

    def test_prepare_then_revalidate_unmount_ready_and_invoke_order(self):
        order: list[str] = []
        plan = SimpleNamespace(composite_plan=object(), device=object())
        confirmation = object()
        owner = Mock()
        owner.__enter__ = Mock(return_value=owner)
        owner.__exit__ = Mock(return_value=None)
        prepared_result = object()
        ready = object()
        final = object()
        installation = HelperInstallation(PKEXEC_PATH, HELPER_PATH, HELPER_SCRIPT_PATH, POLICY_PATH)
        tools = SimpleNamespace(pkexec=PKEXEC_PATH)
        runner = SyslinuxDeviceWriteRunner()

        def validate(*_args, **_kwargs):
            order.append("validate")

        with (
            patch.object(runner_module, "validate_confirmed_syslinux_device_write", side_effect=validate),
            patch.object(runner_module, "resolve_syslinux_helper_installation", side_effect=lambda: (order.append("helper") or installation)),
            patch.object(runner_module, "resolve_writer_tools", side_effect=lambda _which: (order.append("tools") or tools)),
            patch.object(runner_module, "prepare_syslinux_iso_fat32", side_effect=lambda *_args, **_kwargs: (order.append("prepare") or owner)),
            patch.object(runner_module, "_validate_prepared", side_effect=lambda *_args: (order.append("prepared") or prepared_result)),
            patch.object(runner_module, "unmount_device", side_effect=lambda *_args, **_kwargs: order.append("unmount")),
            patch.object(runner_module, "authorize_unmounted_syslinux_device_write", side_effect=lambda *_args, **_kwargs: (order.append("ready") or ready)),
            patch.object(runner_module, "validate_ready_syslinux_device_write", side_effect=lambda *_args, **_kwargs: order.append("ready-validate")),
            patch.object(runner, "_invoke_helper", side_effect=lambda *_args, **_kwargs: (order.append("invoke") or final)),
        ):
            self.assertIs(runner.run(plan, confirmation), final)
        self.assertEqual(order, [
            "validate", "helper", "tools", "prepare", "prepared", "validate",
            "unmount", "ready", "ready-validate", "invoke",
        ])
        owner.__exit__.assert_called_once()


class InstallationTests(unittest.TestCase):
    def _staged(self, root: Path, *, policy_active: str = "auth_admin"):
        pkexec = root / "usr" / "bin" / "pkexec"
        launcher = root / "usr" / "libexec" / "isopropyl-device-helper"
        script = root / "usr" / "libexec" / "isopropyl" / "syslinux_device_helper.py"
        policy = root / "usr" / "share" / "polkit-1" / "actions" / "io.github.codebooker.isopropyl.policy"
        for path in (pkexec, launcher, script, policy):
            path.parent.mkdir(parents=True, exist_ok=True)
        pkexec.write_bytes(b"pkexec")
        launcher.write_bytes(b"helper")
        script.write_bytes(b"script")
        policy.write_text(
            f'''<?xml version="1.0"?>
<policyconfig><action id="{POLICY_ACTION}"><defaults>
<allow_any>no</allow_any><allow_inactive>no</allow_inactive>
<allow_active>{policy_active}</allow_active></defaults>
<annotate key="org.freedesktop.policykit.exec.path">{launcher}</annotate>
<annotate key="org.freedesktop.policykit.exec.argv1">{protocol.OPERATION}</annotate>
</action></policyconfig>''',
            encoding="utf-8",
        )
        return pkexec, launcher, script, policy

    def _assert_raw_policy(self, path: Path) -> None:
        policy_text = path.read_text(encoding="utf-8")
        policy_root = ET.parse(path).getroot()
        self.assertEqual(policy_root.tag, "policyconfig")
        actions = policy_root.findall("action")
        self.assertEqual(len(actions), 1)
        action = actions[0]
        self.assertEqual(
            action.get("id"),
            "io.github.codebooker.isopropyl.write-raw-image",
        )
        self.assertEqual(len(action.findall("description")), 1)
        self.assertEqual(len(action.findall("message")), 1)
        defaults = action.findall("defaults")
        self.assertEqual(len(defaults), 1)
        self.assertEqual(len(list(defaults[0])), 3)
        self.assertEqual(
            {child.tag: (child.text or "").strip() for child in defaults[0]},
            {
                "allow_any": "no",
                "allow_inactive": "no",
                "allow_active": "auth_admin",
            },
        )
        annotations = action.findall("annotate")
        self.assertEqual(len(annotations), 2)
        self.assertEqual(
            {
                node.get("key"): (node.text or "").strip()
                for node in annotations
            },
            {
                "org.freedesktop.policykit.exec.path":
                "/usr/libexec/isopropyl-device-helper",
                "org.freedesktop.policykit.exec.argv1": "write-raw-image-v1",
            },
        )
        self.assertIn("caller-supplied raw image", policy_text)
        self.assertIn(
            "overwrite the selected removable or external USB target",
            policy_text,
        )

    def test_raw_policy_launcher_and_make_targets_are_narrow_at_source(self):
        repository = Path(__file__).resolve().parents[1]
        raw_policy = (
            repository
            / "data/io.github.codebooker.isopropyl.raw-write.policy"
        )
        self._assert_raw_policy(raw_policy)

        launcher = (
            repository / "helper/isopropyl-device-helper"
        ).read_text(encoding="utf-8")
        self.assertIn(
            '/usr/libexec/isopropyl/syslinux_device_helper.py "$@"',
            launcher,
        )

        makefile = (repository / "Makefile").read_text(encoding="utf-8")
        ordinary_install = makefile.split("\ninstall:\n", 1)[1].split(
            "\nuninstall:\n", 1,
        )[0]
        host_install = makefile.split("\ninstall-host-helper:\n", 1)[1].split(
            "\nuninstall-host-helper:\n", 1,
        )[0]
        host_uninstall = makefile.split("\nuninstall-host-helper:\n", 1)[1]
        self.assertNotIn("libexec/isopropyl-device-helper", ordinary_install)
        self.assertNotIn("polkit-1/actions", ordinary_install)
        self.assertIn('test "$(PREFIX)" = "/usr"', host_install)
        self.assertIn('test "$(PREFIX)" = "/usr"', host_uninstall)
        for asset in (
            "helper/isopropyl-device-helper",
            "isopropyl/syslinux_device_helper.py",
            "data/io.github.codebooker.isopropyl.policy",
            "data/io.github.codebooker.isopropyl.raw-write.policy",
            "data/io.github.codebooker.isopropyl.fast-zero.policy",
        ):
            self.assertIn(asset, host_install)
        self.assertIn(
            "io.github.codebooker.isopropyl.raw-write.policy",
            host_uninstall,
        )
        self.assertIn(
            "io.github.codebooker.isopropyl.fast-zero.policy",
            host_uninstall,
        )

    def test_fixed_root_owned_install_and_exact_policy_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pkexec, launcher, script, policy = self._staged(root)
            actual_lstat = os.lstat

            def root_status(path):
                status = actual_lstat(path)
                mode = status.st_mode & ~0o022
                if os.fspath(path) == os.fspath(pkexec):
                    mode |= stat.S_ISUID | 0o500
                elif stat.S_ISREG(mode) and os.fspath(path) == os.fspath(launcher):
                    mode |= 0o500
                elif stat.S_ISREG(mode):
                    mode |= 0o400
                return SimpleNamespace(st_mode=mode, st_uid=0)

            with (
                patch.object(runner_module, "PKEXEC_PATH", os.fspath(pkexec)),
                patch.object(runner_module, "HELPER_PATH", os.fspath(launcher)),
                patch.object(runner_module, "HELPER_SCRIPT_PATH", os.fspath(script)),
                patch.object(runner_module, "POLICY_PATH", os.fspath(policy)),
                patch.object(runner_module.os, "lstat", side_effect=root_status),
                patch.object(runner_module.os.path, "realpath", side_effect=lambda value: value),
                patch.object(runner_module, "_trusted_parents"),
            ):
                installation = resolve_syslinux_helper_installation()
                self.assertEqual(installation.helper, os.fspath(launcher))

            policy.write_text(
                policy.read_text().replace("auth_admin", "auth_admin_keep"),
                encoding="utf-8",
            )
            with (
                patch.object(runner_module, "PKEXEC_PATH", os.fspath(pkexec)),
                patch.object(runner_module, "HELPER_PATH", os.fspath(launcher)),
                patch.object(runner_module, "HELPER_SCRIPT_PATH", os.fspath(script)),
                patch.object(runner_module, "POLICY_PATH", os.fspath(policy)),
                patch.object(runner_module.os, "lstat", side_effect=root_status),
                patch.object(runner_module.os.path, "realpath", side_effect=lambda value: value),
                patch.object(runner_module, "_trusted_parents"),
                self.assertRaisesRegex(SyslinuxDeviceHelperUnavailable, "broader"),
            ):
                resolve_syslinux_helper_installation()

    def test_duplicate_policy_defaults_or_annotations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pkexec, launcher, script, policy = self._staged(root)
            valid = policy.read_text(encoding="utf-8")
            actual_lstat = os.lstat

            def root_status(path):
                status = actual_lstat(path)
                mode = status.st_mode & ~0o022
                if os.fspath(path) == os.fspath(pkexec):
                    mode |= stat.S_ISUID | 0o500
                elif os.fspath(path) == os.fspath(launcher):
                    mode |= 0o500
                else:
                    mode |= 0o400
                return SimpleNamespace(st_mode=mode, st_uid=0)

            additions = (
                "<defaults><allow_any>yes</allow_any><allow_inactive>yes</allow_inactive>"
                "<allow_active>yes</allow_active></defaults>",
                f'<annotate key="org.freedesktop.policykit.exec.path">{launcher}</annotate>',
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
                    patch.object(runner_module, "HELPER_SCRIPT_PATH", os.fspath(script)),
                    patch.object(runner_module, "POLICY_PATH", os.fspath(policy)),
                    patch.object(runner_module.os, "lstat", side_effect=root_status),
                    patch.object(runner_module.os.path, "realpath", side_effect=lambda value: value),
                    patch.object(runner_module, "_trusted_parents"),
                    self.assertRaisesRegex(SyslinuxDeviceHelperUnavailable, "ambiguous"),
                ):
                    resolve_syslinux_helper_installation()

    @unittest.skipUnless(shutil.which("make"), "make is not installed")
    def test_explicit_host_install_stages_only_fixed_integration_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = Path(__file__).resolve().parents[1]
            completed = subprocess.run(
                [
                    "make",
                    "install-host-helper",
                    "PREFIX=/usr",
                    f"DESTDIR={root}",
                ],
                cwd=repository,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            expected = {
                root / "usr/libexec/isopropyl-device-helper": 0o755,
                root / "usr/libexec/isopropyl/syslinux_device_helper.py": 0o644,
                root / "usr/share/polkit-1/actions/io.github.codebooker.isopropyl.policy": 0o644,
                root / "usr/share/polkit-1/actions/io.github.codebooker.isopropyl.raw-write.policy": 0o644,
                root / "usr/share/polkit-1/actions/io.github.codebooker.isopropyl.fast-zero.policy": 0o644,
            }
            for path, mode in expected.items():
                with self.subTest(path=path):
                    self.assertTrue(path.is_file())
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)

            launcher_text = (
                root / "usr/libexec/isopropyl-device-helper"
            ).read_text(encoding="utf-8")
            self.assertIn(
                '/usr/libexec/isopropyl/syslinux_device_helper.py "$@"',
                launcher_text,
            )

            raw_policy_path = (
                root
                / "usr/share/polkit-1/actions/"
                "io.github.codebooker.isopropyl.raw-write.policy"
            )
            self._assert_raw_policy(raw_policy_path)
            fast_zero_policy = ET.parse(
                root
                / "usr/share/polkit-1/actions/"
                "io.github.codebooker.isopropyl.fast-zero.policy"
            ).getroot()
            actions = fast_zero_policy.findall("action")
            self.assertEqual(len(actions), 1)
            self.assertEqual(
                actions[0].attrib,
                {"id": "io.github.codebooker.isopropyl.fast-zero-drive"},
            )

    @unittest.skipUnless(shutil.which("make"), "make is not installed")
    def test_ordinary_install_excludes_privileged_helper_and_policies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = Path(__file__).resolve().parents[1]
            completed = subprocess.run(
                [
                    "make",
                    "install",
                    "PREFIX=/usr",
                    "PYTHON_SITE=/usr/lib/python3/site-packages",
                    f"DESTDIR={root}",
                ],
                cwd=repository,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse((root / "usr/libexec/isopropyl-device-helper").exists())
            self.assertFalse((root / "usr/libexec/isopropyl").exists())
            actions = root / "usr/share/polkit-1/actions"
            self.assertFalse(actions.exists())


if __name__ == "__main__":
    unittest.main()
