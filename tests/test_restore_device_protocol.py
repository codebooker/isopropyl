from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import io
import os
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import xml.etree.ElementTree as ET
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import isopropyl.restore_device_helper as protocol
import isopropyl.restore_device_runner as runner
from isopropyl.formatting import Filesystem, FormatPlan, PartitionTable


CAPACITY = 16 * 1024 * 1024
DISKSEQ = 123456
REQUEST_ID = bytes(range(16))


def request() -> protocol.RestoreDeviceRequest:
    return protocol.build_restore_device_request(
        FormatPlan(
            "/dev/sdz",
            ("/dev/sdz", CAPACITY, "SER", "", "USB", "8:240"),
            Filesystem.FAT32,
            PartitionTable.GPT,
            "TEST",
        ),
        request_id=REQUEST_ID,
        disk_sequence=DISKSEQ,
        logical_sector_size=512,
        chunk_size=1024 * 1024,
    )


class ProtocolTests(unittest.TestCase):
    def test_main_resets_and_unblocks_inherited_signals_before_dispatch(self) -> None:
        with (
            patch.object(protocol.signal, "signal") as set_disposition,
            patch.object(protocol.signal, "pthread_sigmask") as set_mask,
        ):
            self.assertEqual(protocol.main([]), 2)
        ordinary = {
            signal.SIGINT, signal.SIGHUP, signal.SIGTERM, signal.SIGQUIT,
        }
        for signum in ordinary:
            self.assertIn(
                (signum, signal.SIG_DFL),
                [call.args for call in set_disposition.call_args_list],
            )
        self.assertNotIn(
            (signal.SIGPIPE, signal.SIG_DFL),
            [call.args for call in set_disposition.call_args_list],
        )
        self.assertEqual(
            set_disposition.call_args_list[-1].args,
            (signal.SIGPIPE, signal.SIG_IGN),
        )
        self.assertEqual(set_mask.call_count, 1)
        self.assertEqual(set_mask.call_args.args[0], signal.SIG_UNBLOCK)
        self.assertEqual(set_mask.call_args.args[1], ordinary | {signal.SIGPIPE})

    def test_postcommit_defers_all_four_ordinary_termination_signals(self) -> None:
        with patch.object(protocol.signal, "signal") as set_disposition:
            protocol._defer_ordinary_termination()
        self.assertEqual(
            {call.args for call in set_disposition.call_args_list},
            {
                (signal.SIGINT, signal.SIG_IGN),
                (signal.SIGHUP, signal.SIG_IGN),
                (signal.SIGTERM, signal.SIG_IGN),
                (signal.SIGQUIT, signal.SIG_IGN),
            },
        )

    def test_root_hardening_closes_extra_descriptors_and_locks_process_state(self) -> None:
        channel = SimpleNamespace(fileno=lambda: 7)
        with (
            patch.object(protocol.os, "listdir", return_value=["0", "1", "2", "7", "9"]),
            patch.object(protocol.os, "close") as close,
            patch.object(protocol.os, "fstat"),
            patch.object(protocol.os, "set_inheritable") as set_inheritable,
        ):
            protocol._close_unexpected_descriptors(channel)
        close.assert_called_once_with(9)
        set_inheritable.assert_called_once_with(7, False)

        prctl_calls = []

        def prctl(option, *_arguments):
            prctl_calls.append(option)
            return 1 if option == 39 else 0

        libc = SimpleNamespace(prctl=prctl)
        channel = SimpleNamespace()
        with (
            patch.object(protocol.os, "getuid", return_value=0),
            patch.object(protocol.os, "geteuid", return_value=0),
            patch.object(protocol, "_peer_uid", return_value=1000),
            patch.object(protocol.os, "readlink", return_value="same"),
            patch.object(protocol, "_close_unexpected_descriptors") as close_fds,
            patch.object(protocol.os, "umask"),
            patch.object(protocol.os, "chdir"),
            patch.object(protocol.resource, "setrlimit") as setrlimit,
            patch.object(protocol.resource, "getrlimit", return_value=(0, 0)),
            patch.object(protocol.ctypes, "CDLL", return_value=libc),
            patch.dict(protocol.os.environ, {"POISON": "value"}, clear=True),
        ):
            protocol._harden_root_process(1000, channel)
            self.assertEqual(
                dict(protocol.os.environ),
                {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
            )
        close_fds.assert_called_once_with(channel)
        setrlimit.assert_called_once_with(protocol.resource.RLIMIT_CORE, (0, 0))
        self.assertEqual(prctl_calls, [4, 38, 39])

    def test_main_rejects_unattested_installed_script_before_peer_handling(self) -> None:
        with (
            patch.object(protocol, "_reset_inherited_signal_state"),
            patch.object(
                protocol,
                "_verify_installed_script",
                side_effect=protocol.HelperTargetError("poisoned install"),
            ),
            patch.object(protocol, "_invoking_uid") as invoking_uid,
        ):
            self.assertEqual(protocol.main([protocol.RESTORE_DEVICE_OPERATION]), 2)
        invoking_uid.assert_not_called()

    def test_request_roundtrip_is_canonical_and_resolves_path_from_device_number(self) -> None:
        original = request()
        packet = protocol.pack_restore_device_request(original)
        decoded = protocol.unpack_restore_device_request(
            packet,
            target_path=lambda device: (
                "/dev/sdz" if device == os.makedev(8, 240) else "bad"
            ),
        )
        self.assertEqual(decoded, original)
        self.assertEqual(protocol.pack_restore_device_request(decoded), packet)
        self.assertEqual(len(packet), protocol._REQUEST.size)
        self.assertNotIn(b"/dev/sdz", packet)

    def test_request_rejects_flags_padding_digest_and_geometry_changes(self) -> None:
        original = bytearray(protocol.pack_restore_device_request(request()))
        mutations = []
        flags = bytearray(original)
        flags[18] = 1
        mutations.append(flags)
        padding = bytearray(original)
        label_offset = protocol._REQUEST.size - 32 - 128
        padding[label_offset + 120] = 1
        mutations.append(padding)
        digest = bytearray(original)
        digest[-1] ^= 1
        mutations.append(digest)
        for mutation in mutations:
            with self.subTest(offset=next(
                index for index, pair in enumerate(zip(original, mutation))
                if pair[0] != pair[1]
            )):
                with self.assertRaises(protocol.HelperTargetError):
                    protocol.unpack_restore_device_request(
                        bytes(mutation), target_path=lambda _device: "/dev/sdz",
                    )

    def test_control_and_server_packets_are_fixed_and_strict(self) -> None:
        digest = request().plan_sha256
        self.assertEqual(protocol._CONTROL.size, 68)
        commit = protocol.pack_restore_control(REQUEST_ID, digest, commit=True)
        self.assertEqual(protocol._CONTROL.unpack(commit)[2], protocol.PACKET_COMMIT)
        prepared = protocol._CONTROL.pack(
            protocol._WIRE_MAGIC, 1, protocol.PACKET_PREPARED, 0, REQUEST_ID,
            digest,
        )
        self.assertEqual(
            protocol.unpack_restore_server_packet(prepared),
            ("prepared", REQUEST_ID, digest),
        )
        self.assertTrue(protocol.unpack_restore_control(
            commit,
            request_id=REQUEST_ID,
            plan_sha256=digest,
        ))
        for mutation in (
            commit[:-1],
            commit[:-1] + bytes((commit[-1] ^ 1,)),
            protocol._CONTROL.pack(
                protocol._WIRE_MAGIC, 1, protocol.PACKET_COMMIT, 0,
                bytes(reversed(REQUEST_ID)), digest,
            ),
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(protocol.HelperTargetError):
                    protocol.unpack_restore_control(
                        mutation,
                        request_id=REQUEST_ID,
                        plan_sha256=digest,
                    )
        with self.assertRaises(protocol.HelperTargetError):
            protocol.unpack_restore_server_packet(prepared + b"x")
        for bad_digest in (digest[:-1], bytearray(digest)):
            with self.subTest(digest=bad_digest):
                with self.assertRaises(protocol.HelperTargetError):
                    protocol.pack_restore_control(
                        REQUEST_ID,
                        bad_digest,  # type: ignore[arg-type]
                        commit=True,
                    )
        with self.assertRaises(protocol.HelperTargetError):
            protocol.pack_restore_control(
                REQUEST_ID,
                digest,
                commit=1,  # type: ignore[arg-type]
            )

    def test_installed_root_script_attestation_is_exact(self) -> None:
        safe_script = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
        safe_parent = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        unsafe_script = SimpleNamespace(st_mode=stat.S_IFREG | 0o664, st_uid=0)
        with (
            patch.object(protocol, "__file__", protocol.INSTALLED_SCRIPT_PATH),
            patch.object(protocol.sys, "argv", [protocol.INSTALLED_SCRIPT_PATH]),
            patch.object(protocol.os, "lstat", side_effect=[
                safe_script, safe_parent, safe_parent, safe_parent,
            ]),
        ):
            protocol._verify_installed_script()
        for bad_file, bad_argv, statuses in (
            ("/tmp/helper.py", protocol.INSTALLED_SCRIPT_PATH, [safe_script] * 4),
            (protocol.INSTALLED_SCRIPT_PATH, "/tmp/helper.py", [safe_script] * 4),
            (protocol.INSTALLED_SCRIPT_PATH, protocol.INSTALLED_SCRIPT_PATH,
             [unsafe_script, safe_parent, safe_parent, safe_parent]),
            (protocol.INSTALLED_SCRIPT_PATH, protocol.INSTALLED_SCRIPT_PATH,
             [safe_script, SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0)]),
        ):
            with (
                self.subTest(file=bad_file, argv=bad_argv),
                patch.object(protocol, "__file__", bad_file),
                patch.object(protocol.sys, "argv", [bad_argv]),
                patch.object(protocol.os, "lstat", side_effect=statuses),
                self.assertRaises(protocol.HelperTargetError),
            ):
                protocol._verify_installed_script()

    def test_root_script_is_stdlib_only_and_launcher_is_fixed_isolated_mode(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "isopropyl/restore_device_helper.py").read_text(encoding="utf-8")
        self.assertNotIn("from .", source)
        self.assertNotIn("import isopropyl", source)
        launcher = (root / "helper/isopropyl-restore-device-helper").read_text(
            encoding="utf-8",
        )
        self.assertIn(
            "exec /usr/bin/python3 -I -S /usr/libexec/isopropyl/restore_device_helper.py",
            launcher,
        )

    def test_policy_is_single_exact_nonpersistent_admin_action(self) -> None:
        path = Path(__file__).resolve().parents[1] / (
            "data/io.github.codebooker.isopropyl.restore-device.policy"
        )
        root = ET.parse(path).getroot()
        actions = root.findall("action")
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].attrib, {"id": runner.POLICY_ACTION})
        defaults = actions[0].find("defaults")
        self.assertIsNotNone(defaults)
        self.assertEqual(
            {node.tag: (node.text or "").strip() for node in defaults},
            {"allow_any": "no", "allow_inactive": "no", "allow_active": "auth_admin"},
        )
        self.assertNotIn("auth_admin_keep", path.read_text(encoding="utf-8"))
        runner._policy(os.fspath(path), runner.HELPER_PATH)

    def test_policy_parser_rejects_poisoned_prompts_and_structure(self) -> None:
        source = Path(__file__).resolve().parents[1] / (
            "data/io.github.codebooker.isopropyl.restore-device.policy"
        )
        mutations = (
            lambda root: setattr(root.find("action/description"), "text", "Erase a file"),
            lambda root: root.find("action").append(ET.Element("description")),
            lambda root: root.find("action/defaults").set("xml:lang", "en"),
            lambda root: root.find("action/annotate").set("extra", "value"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index), tempfile.TemporaryDirectory() as directory:
                document = ET.parse(source)
                mutate(document.getroot())
                path = Path(directory) / "restore.policy"
                document.write(path, encoding="utf-8", xml_declaration=True)
                with self.assertRaises(runner.RestoreDeviceHelperUnavailable):
                    runner._policy(os.fspath(path), runner.HELPER_PATH)

    def test_installation_checks_reject_untrusted_files_and_parents(self) -> None:
        safe_file = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        unsafe_file = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=1000)
        safe_parent = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        unsafe_parent = SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0)
        path = "/usr/libexec/isopropyl-restore-device-helper"

        with patch.object(os, "lstat", return_value=unsafe_file):
            with self.assertRaises(runner.RestoreDeviceHelperUnavailable):
                runner._trusted_file(path, executable=True)
        with (
            patch.object(os, "lstat", return_value=safe_file),
            patch.object(os.path, "realpath", return_value="/tmp/poisoned-helper"),
        ):
            with self.assertRaises(runner.RestoreDeviceHelperUnavailable):
                runner._trusted_file(path, executable=True)
        with (
            patch.object(os, "lstat", return_value=safe_file),
            patch.object(os.path, "realpath", return_value=path),
            patch.object(os, "stat", side_effect=[unsafe_parent, safe_parent, safe_parent]),
        ):
            with self.assertRaises(runner.RestoreDeviceHelperUnavailable):
                runner._trusted_file(path, executable=True)
        with (
            patch.object(os, "lstat", return_value=safe_file),
            patch.object(os.path, "realpath", return_value=path),
            patch.object(os, "stat", side_effect=FileNotFoundError("missing parent")),
        ):
            with self.assertRaises(runner.RestoreDeviceHelperUnavailable):
                runner._trusted_file(path, executable=True)


class FakeProcess:
    def __init__(self, argv, *, script=None, **kwargs) -> None:
        self.argv = argv
        self.script = script
        self.returncode = None
        self.stderr = io.BytesIO()
        self.terminated = False
        self.killed = False
        self.wait_calls = 0
        self.channel = socket.socket(fileno=os.dup(kwargs["stdin"]))
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def send_prepared(self, value) -> None:
        self.channel.sendall(protocol._CONTROL.pack(
            protocol._WIRE_MAGIC, 1, protocol.PACKET_PREPARED, 0, value.request_id,
            value.plan_sha256,
        ))

    def send_progress(self, value, phase: int, done: int, total: int | None = None) -> None:
        self.channel.sendall(protocol._PROGRESS.pack(
            protocol._WIRE_MAGIC, 1, protocol.PACKET_PROGRESS, 0,
            value.request_id, phase, done,
            value.expected_capacity if total is None else total,
        ))

    def send_result(self, value) -> None:
        self.channel.sendall(protocol._RESULT.pack(
            protocol._WIRE_MAGIC, 1, protocol.PACKET_RESULT, 0,
            value.request_id, 8, 240, value.expected_disk_sequence,
            value.expected_capacity, value.expected_capacity,
            value.expected_capacity // 2, value.expected_capacity // 2,
            value.expected_capacity, 8, 241,
            value.partition_start_sector, value.partition_sector_count,
            value.plan_sha256,
        ))

    def _serve(self) -> None:
        try:
            self.channel.sendall(protocol._HEADER.pack(
                protocol._WIRE_MAGIC, 1, protocol.PACKET_READY, 0,
            ))
            incoming = self.channel.recv(protocol.MAX_PROTOCOL_PACKET)
            value = protocol.unpack_restore_device_request(
                incoming, target_path=lambda _device: "/dev/sdz",
            )
            self.send_prepared(value)
            decision = self.channel.recv(protocol.MAX_PROTOCOL_PACKET)
            if protocol._CONTROL.unpack(decision)[2] == protocol.PACKET_CANCEL:
                self.returncode = 1
                return
            if self.script is None:
                self.send_progress(value, 1, value.expected_capacity)
                self.send_progress(value, 2, value.expected_capacity)
                self.send_result(value)
            else:
                self.script(self, value)
            self.returncode = 0
        except OSError:
            self.returncode = 1
        finally:
            self.channel.close()

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.wait_calls += 1
        self.thread.join(timeout)
        if self.thread.is_alive():
            raise subprocess.TimeoutExpired(self.argv, timeout)
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15
        self.channel.close()

    def kill(self):
        self.killed = True
        self.returncode = -9
        self.channel.close()


class RunnerTests(unittest.TestCase):
    def test_delivered_commit_then_keyboard_interrupt_never_signals_helper(self) -> None:
        actual_socketpair = socket.socketpair
        processes = []

        class InterruptAfterCommit:
            def __init__(self, channel) -> None:
                self.channel = channel

            def fileno(self):
                return self.channel.fileno()

            def recv(self, size):
                return self.channel.recv(size)

            def close(self):
                return self.channel.close()

            def send(self, packet):
                count = self.channel.send(packet)
                if (
                    len(packet) == protocol._CONTROL.size
                    and protocol._CONTROL.unpack(packet)[2] == protocol.PACKET_COMMIT
                ):
                    raise KeyboardInterrupt("delivered after kernel accepted COMMIT")
                return count

        def socketpair(*args, **kwargs):
            parent, child = actual_socketpair(*args, **kwargs)
            return InterruptAfterCommit(parent), child

        def popen(*args, **kwargs):
            value = FakeProcess(*args, **kwargs)
            processes.append(value)
            return value

        installation = runner.RestoreDeviceInstallation("p", "h", "s", "x")
        worker = runner.RestoreDeviceRunner(
            installation=lambda: installation,
            popen=popen,
            timeout=2,
        )
        with (
            patch.object(runner.socket, "socketpair", side_effect=socketpair),
            self.assertRaises(KeyboardInterrupt),
        ):
            worker.run(request(), confirm_commit=lambda: True)
        self.assertTrue(worker.committed)
        self.assertEqual(len(processes), 1)
        processes[0].thread.join(1)
        self.assertFalse(processes[0].thread.is_alive())
        self.assertFalse(processes[0].terminated)
        self.assertFalse(processes[0].killed)

    def test_runner_commits_only_after_prepared_and_validates_complete_receipt(self) -> None:
        processes = []

        def popen(*args, **kwargs):
            value = FakeProcess(*args, **kwargs)
            processes.append(value)
            return value

        installation = runner.RestoreDeviceInstallation(
            "/usr/bin/pkexec",
            "/usr/libexec/isopropyl-restore-device-helper",
            "/usr/libexec/isopropyl/restore_device_helper.py",
            "/usr/share/polkit-1/actions/io.github.codebooker.isopropyl.restore-device.policy",
        )
        progress = []
        worker = runner.RestoreDeviceRunner(
            installation=lambda: installation,
            popen=popen,
            timeout=2,
        )
        result = worker.run(
            request(),
            confirm_commit=lambda: True,
            progress=lambda *values: progress.append(values),
        )
        self.assertTrue(worker.committed)
        self.assertEqual(result.verified_bytes, CAPACITY)
        self.assertEqual(progress, [
            ("zero-scan", CAPACITY, CAPACITY),
            ("zero-readback", CAPACITY, CAPACITY),
        ])
        self.assertEqual(processes[0].argv[-1], protocol.RESTORE_DEVICE_OPERATION)

    def test_runner_rejects_prepared_with_wrong_plan_digest_before_commit(self) -> None:
        class WrongDigestProcess(FakeProcess):
            def _serve(self) -> None:
                try:
                    self.channel.sendall(protocol._HEADER.pack(
                        protocol._WIRE_MAGIC, 1, protocol.PACKET_READY, 0,
                    ))
                    value = protocol.unpack_restore_device_request(
                        self.channel.recv(protocol.MAX_PROTOCOL_PACKET),
                        target_path=lambda _device: "/dev/sdz",
                    )
                    self.channel.sendall(protocol._CONTROL.pack(
                        protocol._WIRE_MAGIC,
                        1,
                        protocol.PACKET_PREPARED,
                        0,
                        value.request_id,
                        bytes((value.plan_sha256[0] ^ 1,)) + value.plan_sha256[1:],
                    ))
                    self.returncode = 0
                finally:
                    self.channel.close()

        processes = []

        def popen(*args, **kwargs):
            value = WrongDigestProcess(*args, **kwargs)
            processes.append(value)
            return value

        installation = runner.RestoreDeviceInstallation("p", "h", "s", "x")
        worker = runner.RestoreDeviceRunner(
            installation=lambda: installation,
            popen=popen,
            timeout=2,
        )
        with self.assertRaisesRegex(runner.RestoreDeviceRunError, "PREPARED boundary"):
            worker.run(request(), confirm_commit=lambda: True)
        self.assertFalse(worker.committed)
        processes[0].thread.join(1)
        self.assertFalse(processes[0].thread.is_alive())

    def test_runner_cancel_at_prepared_never_marks_commit(self) -> None:
        installation = runner.RestoreDeviceInstallation("p", "h", "s", "x")
        worker = runner.RestoreDeviceRunner(
            installation=lambda: installation,
            popen=FakeProcess,
            timeout=2,
        )
        with self.assertRaises(runner.RestoreDeviceRunCancelled):
            worker.run(request(), confirm_commit=lambda: False)
        self.assertFalse(worker.committed)

    def test_cancel_during_confirmation_wins_before_commit_send(self) -> None:
        installation = runner.RestoreDeviceInstallation("p", "h", "s", "x")
        worker = runner.RestoreDeviceRunner(
            installation=lambda: installation, popen=FakeProcess, timeout=2,
        )

        def confirm() -> bool:
            worker.cancel()
            return True

        with self.assertRaises(runner.RestoreDeviceRunCancelled):
            worker.run(request(), confirm_commit=confirm)
        self.assertFalse(worker.committed)

    def test_runner_is_one_shot_and_cancel_before_run_does_not_launch(self) -> None:
        installation = runner.RestoreDeviceInstallation("p", "h", "s", "x")
        launches = []

        def popen(*args, **kwargs):
            launches.append(args)
            return FakeProcess(*args, **kwargs)

        worker = runner.RestoreDeviceRunner(
            installation=lambda: installation, popen=popen, timeout=2,
        )
        worker.run(request(), confirm_commit=lambda: True)
        with self.assertRaisesRegex(runner.RestoreDeviceRunError, "only be used once"):
            worker.run(request(), confirm_commit=lambda: True)
        self.assertEqual(len(launches), 1)

        cancelled = runner.RestoreDeviceRunner(
            installation=lambda: installation, popen=popen, timeout=2,
        )
        cancelled.cancel()
        with self.assertRaises(runner.RestoreDeviceRunCancelled):
            cancelled.run(request(), confirm_commit=lambda: True)
        self.assertEqual(len(launches), 1)

    def test_runner_rejects_repeated_or_invalid_progress_sequences(self) -> None:
        def repeated_prepared(process, value):
            process.send_prepared(value)

        def out_of_order(process, value):
            process.send_progress(value, 2, value.expected_capacity)

        def regressing(process, value):
            process.send_progress(value, 1, 1024)
            process.send_progress(value, 1, 512)

        def wrong_total(process, value):
            process.send_progress(value, 1, 0, value.expected_capacity - 1)

        def incomplete(process, value):
            process.send_progress(value, 1, value.expected_capacity)
            process.send_result(value)

        installation = runner.RestoreDeviceInstallation("p", "h", "s", "x")
        for name, script in (
            ("repeated-prepared", repeated_prepared),
            ("out-of-order", out_of_order),
            ("regressing", regressing),
            ("wrong-total", wrong_total),
            ("incomplete", incomplete),
        ):
            processes = []

            def popen(*args, **kwargs):
                process = FakeProcess(*args, script=script, **kwargs)
                processes.append(process)
                return process

            with self.subTest(case=name):
                worker = runner.RestoreDeviceRunner(
                    installation=lambda: installation, popen=popen, timeout=2,
                )
                with self.assertRaises(runner.RestoreDeviceRunError):
                    worker.run(request(), confirm_commit=lambda: True)
                self.assertTrue(worker.committed)
                self.assertFalse(processes[0].terminated)
                self.assertFalse(processes[0].killed)

    def test_progress_callback_failure_is_logged_and_ignored(self) -> None:
        installation = runner.RestoreDeviceInstallation("p", "h", "s", "x")
        worker = runner.RestoreDeviceRunner(
            installation=lambda: installation, popen=FakeProcess, timeout=2,
        )

        def broken_progress(_phase, _done, _total):
            raise RuntimeError("broken UI callback")

        with self.assertLogs("isopropyl", level="ERROR") as captured:
            result = worker.run(
                request(), confirm_commit=lambda: True, progress=broken_progress,
            )
        self.assertEqual(result.verified_bytes, CAPACITY)
        self.assertTrue(any("progress callback failure" in item for item in captured.output))

    def test_postcommit_failure_waits_in_bounded_polls_without_signalling(self) -> None:
        def wait_for_disconnect(process, value):
            process.send_progress(value, 2, value.expected_capacity)
            while process.channel.recv(protocol.MAX_PROTOCOL_PACKET):
                pass
            time.sleep(0.25)

        installation = runner.RestoreDeviceInstallation("p", "h", "s", "x")
        processes = []

        def popen(*args, **kwargs):
            process = FakeProcess(*args, script=wait_for_disconnect, **kwargs)
            processes.append(process)
            return process

        worker = runner.RestoreDeviceRunner(
            installation=lambda: installation, popen=popen, timeout=2,
        )
        with self.assertRaises(runner.RestoreDeviceRunError):
            worker.run(request(), confirm_commit=lambda: True)
        self.assertGreaterEqual(processes[0].wait_calls, 2)
        self.assertFalse(processes[0].terminated)
        self.assertFalse(processes[0].killed)


if __name__ == "__main__":
    unittest.main()
