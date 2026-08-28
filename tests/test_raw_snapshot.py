from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import array
import fcntl
import hashlib
import os
import socket
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import isopropyl.raw_snapshot as raw_snapshot
from isopropyl.raw_snapshot import (
    PreparedRawSnapshot,
    RawSnapshotBuilder,
    RawSnapshotCancelled,
    RawSnapshotError,
    RawSnapshotOperations,
    RawSnapshotState,
    build_raw_snapshot_plan,
    observe_raw_source,
    prepare_raw_snapshot,
    validate_raw_snapshot_plan,
)


class RawSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "selected.img"
        self.payload = bytes(range(251)) * 19_000 + b"raw-image-tail"
        self.source.write_bytes(self.payload)
        self.workspace = self.root / "private-workspace"
        self.workspace.mkdir(mode=0o700)
        self.workspace.chmod(0o700)
        candidate = os.makedev(240, 1)
        while candidate in {self.source.stat().st_dev, self.workspace.stat().st_dev}:
            candidate += 1
        self.target_numbers = frozenset({candidate})

    def plan(self):
        selected = observe_raw_source(self.source)
        return build_raw_snapshot_plan(
            self.source,
            self.workspace,
            expected_source_identity=selected,
            target_device_numbers=self.target_numbers,
        )

    @staticmethod
    def receive_descriptor(channel: socket.socket) -> tuple[bytes, int]:
        packet, ancillary, flags, _address = channel.recvmsg(
            4_096,
            socket.CMSG_SPACE(array.array("i").itemsize),
        )
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise AssertionError("descriptor transfer was truncated")
        descriptors: list[int] = []
        for level, kind, value in ancillary:
            if (level, kind) != (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                raise AssertionError("unexpected ancillary record")
            rights = array.array("i")
            rights.frombytes(value)
            descriptors.extend(int(item) for item in rights)
        if len(descriptors) != 1:
            raise AssertionError(f"received {len(descriptors)} descriptors")
        return packet, descriptors[0]

    @staticmethod
    def descriptor_bytes(descriptor: int, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            block = os.pread(descriptor, size - len(data), len(data))
            if not block:
                raise AssertionError("descriptor ended early")
            data.extend(block)
        return bytes(data)

    def test_real_snapshot_is_private_preallocated_hashed_and_transferable_once(self):
        plan = self.plan()
        validate_raw_snapshot_plan(plan)
        updates: list[tuple[int, int]] = []
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        received = -1
        try:
            with prepare_raw_snapshot(
                plan,
                progress=lambda done, total: updates.append((done, total)),
            ) as prepared:
                self.assertIs(type(prepared), PreparedRawSnapshot)
                self.assertFalse(hasattr(prepared, "fileno"))
                self.assertEqual(prepared.state, RawSnapshotState.READY)
                result = prepared.result
                self.assertEqual(result.plan_sha256, plan.plan_sha256)
                self.assertEqual(result.source_identity, plan.source_identity)
                self.assertEqual(result.workspace_identity, plan.workspace_identity)
                self.assertEqual(result.image_size, len(self.payload))
                self.assertEqual(
                    result.image_sha256,
                    hashlib.sha256(self.payload).hexdigest(),
                )
                self.assertTrue(result.fully_preallocated)
                self.assertEqual(result.snapshot_identity.mode, 0o600)
                self.assertGreaterEqual(
                    result.snapshot_identity.blocks * 512,
                    len(self.payload),
                )
                self.assertEqual(os.listdir(self.workspace), [])

                prepared.transfer_to_helper(parent, b"raw-request-v1")
                self.assertEqual(prepared.state, RawSnapshotState.TRANSFERRED)
                packet, received = self.receive_descriptor(child)
                self.assertEqual(packet, b"raw-request-v1")
                status = os.fstat(received)
                self.assertTrue(stat.S_ISREG(status.st_mode))
                self.assertEqual(status.st_nlink, 0)
                self.assertEqual(stat.S_IMODE(status.st_mode), 0o600)
                self.assertEqual(status.st_size, len(self.payload))
                self.assertEqual(
                    fcntl.fcntl(received, fcntl.F_GETFL) & os.O_ACCMODE,
                    os.O_RDWR,
                )
                self.assertEqual(
                    self.descriptor_bytes(received, len(self.payload)),
                    self.payload,
                )
                with self.assertRaisesRegex(RawSnapshotError, "not transferable"):
                    prepared.transfer_to_helper(parent, b"again")
            self.assertEqual(prepared.state, RawSnapshotState.CLOSED)
        finally:
            if received >= 0:
                os.close(received)
            parent.close()
            child.close()
        self.assertEqual(updates[0], (0, len(self.payload)))
        self.assertEqual(updates[-1], (len(self.payload), len(self.payload)))
        self.assertEqual(os.listdir(self.workspace), [])

    def test_source_selection_binds_ctime_and_rejects_same_size_mtime_restore(self):
        selected = observe_raw_source(self.source)
        before = self.source.stat()
        self.source.write_bytes(b"X" * len(self.payload))
        os.utime(
            self.source,
            ns=(before.st_atime_ns, before.st_mtime_ns),
        )
        current = observe_raw_source(self.source)
        self.assertEqual(current.size, selected.size)
        self.assertEqual(current.modified_ns, selected.modified_ns)
        self.assertNotEqual(current.changed_ns, selected.changed_ns)
        with self.assertRaisesRegex(RawSnapshotError, "changed"):
            build_raw_snapshot_plan(
                self.source,
                self.workspace,
                expected_source_identity=selected,
                target_device_numbers=self.target_numbers,
            )

    def test_source_change_after_plan_fails_before_anonymous_creation(self):
        plan = self.plan()
        before = self.source.stat()
        self.source.write_bytes(b"Y" * len(self.payload))
        os.utime(self.source, ns=(before.st_atime_ns, before.st_mtime_ns))
        with patch.object(
            RawSnapshotBuilder,
            "_open_anonymous",
            side_effect=AssertionError("must reject before O_TMPFILE"),
        ) as anonymous:
            with self.assertRaisesRegex(RawSnapshotError, "changed"):
                RawSnapshotBuilder().execute(plan)
        anonymous.assert_not_called()

    def test_source_mutation_during_read_never_reaches_snapshot(self):
        plan = self.plan()
        changed = False

        def mutating_read(descriptor: int, length: int, offset: int) -> bytes:
            nonlocal changed
            block = os.pread(descriptor, length, offset)
            if not changed:
                changed = True
                before = self.source.stat()
                with self.source.open("r+b", buffering=0) as stream:
                    stream.seek(0)
                    stream.write(b"Z")
                os.utime(
                    self.source,
                    ns=(before.st_atime_ns, before.st_mtime_ns),
                )
            return block

        operations = RawSnapshotOperations(pread=mutating_read)
        with self.assertRaisesRegex(RawSnapshotError, "changed while copying"):
            RawSnapshotBuilder(operations=operations).execute(plan)
        self.assertTrue(changed)
        self.assertEqual(os.listdir(self.workspace), [])

    def test_source_and_workspace_target_residency_are_rejected(self):
        selected = observe_raw_source(self.source)
        for resident in (self.source.stat().st_dev, self.workspace.stat().st_dev):
            with self.subTest(resident=resident), self.assertRaisesRegex(
                RawSnapshotError,
                "resides on the target topology",
            ):
                build_raw_snapshot_plan(
                    self.source,
                    self.workspace,
                    expected_source_identity=selected,
                    target_device_numbers=frozenset({resident}),
                )

    def test_topology_evidence_must_be_nonempty_exact_frozenset_of_numbers(self):
        selected = observe_raw_source(self.source)
        candidates = (frozenset(), set(self.target_numbers), frozenset({-1}), frozenset({True}))
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaisesRegex(
                RawSnapshotError,
                "topology",
            ):
                build_raw_snapshot_plan(
                    self.source,
                    self.workspace,
                    expected_source_identity=selected,
                    target_device_numbers=candidate,  # type: ignore[arg-type]
                )

    def test_private_workspace_identity_permissions_and_free_space_are_bound(self):
        selected = observe_raw_source(self.source)
        self.workspace.chmod(0o755)
        with self.assertRaisesRegex(RawSnapshotError, "private 0700"):
            build_raw_snapshot_plan(
                self.source,
                self.workspace,
                expected_source_identity=selected,
                target_device_numbers=self.target_numbers,
            )
        self.workspace.chmod(0o700)
        no_space = SimpleNamespace(f_frsize=4096, f_bsize=4096, f_bavail=0)
        with patch("isopropyl.raw_snapshot.os.fstatvfs", return_value=no_space):
            with self.assertRaisesRegex(RawSnapshotError, "enough free space"):
                build_raw_snapshot_plan(
                    self.source,
                    self.workspace,
                    expected_source_identity=selected,
                    target_device_numbers=self.target_numbers,
                )

    def test_workspace_replacement_after_plan_is_rejected(self):
        plan = self.plan()
        displaced = self.root / "old-workspace"
        self.workspace.rename(displaced)
        self.workspace.mkdir(mode=0o700)
        self.workspace.chmod(0o700)
        with self.assertRaisesRegex(RawSnapshotError, "workspace changed"):
            validate_raw_snapshot_plan(plan)

    def test_source_and_workspace_symlinks_and_hardlinked_source_are_rejected(self):
        source_link = self.root / "source-link.img"
        source_link.symlink_to(self.source)
        with self.assertRaisesRegex(RawSnapshotError, "symbolic links"):
            observe_raw_source(source_link)

        hardlink = self.root / "source-hardlink.img"
        os.link(self.source, hardlink)
        with self.assertRaisesRegex(RawSnapshotError, "one link"):
            observe_raw_source(self.source)

        hardlink.unlink()
        workspace_link = self.root / "workspace-link"
        workspace_link.symlink_to(self.workspace, target_is_directory=True)
        selected = observe_raw_source(self.source)
        with self.assertRaisesRegex(RawSnapshotError, "symbolic links"):
            build_raw_snapshot_plan(
                self.source,
                workspace_link,
                expected_source_identity=selected,
                target_device_numbers=self.target_numbers,
            )

    def test_forged_or_replaced_plan_cannot_acquire_authority(self):
        plan = self.plan()
        candidates = (
            replace(plan),
            replace(plan, image_size=plan.image_size + 1),
            replace(plan, plan_sha256="0" * 64),
            replace(plan, target_device_numbers=frozenset({999})),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaisesRegex(
                RawSnapshotError,
                "authentic|forged",
            ):
                validate_raw_snapshot_plan(candidate)

    def test_anonymous_open_uses_tmpfile_exclusive_rdwr_and_mode_0600(self):
        plan = self.plan()
        real_open = os.open
        observed: list[tuple[int, int]] = []

        def recording_open(path, flags, mode=0o777, *, dir_fd=None):
            if path == "." and flags & getattr(os, "O_TMPFILE", 0):
                observed.append((flags, mode))
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with patch("isopropyl.raw_snapshot.os.open", side_effect=recording_open):
            prepared = RawSnapshotBuilder().execute(plan)
        try:
            self.assertEqual(len(observed), 1)
            flags, mode = observed[0]
            self.assertTrue(flags & os.O_TMPFILE)
            self.assertTrue(flags & os.O_EXCL)
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDWR)
            self.assertEqual(mode, 0o600)
            status = os.fstat(prepared._descriptor)
            self.assertEqual(status.st_nlink, 0)
            self.assertEqual(stat.S_IMODE(status.st_mode), 0o600)
        finally:
            prepared.close()

    def test_full_preallocation_is_required_not_merely_truncation(self):
        plan = self.plan()
        operations = RawSnapshotOperations(preallocate=lambda _fd, _offset, _size: None)
        with self.assertRaisesRegex(RawSnapshotError, "fully allocated"):
            RawSnapshotBuilder(operations=operations).execute(plan)
        self.assertEqual(os.listdir(self.workspace), [])

    def test_interrupted_and_short_io_are_retried_exactly(self):
        plan = self.plan()
        calls = {"pread": 0, "pwrite": 0, "preallocate": 0, "fsync": 0}

        def interrupted_pread(fd: int, length: int, offset: int) -> bytes:
            calls["pread"] += 1
            if calls["pread"] == 1:
                raise InterruptedError()
            return os.pread(fd, max(1, length // 2), offset)

        def interrupted_pwrite(fd: int, data: bytes, offset: int) -> int:
            calls["pwrite"] += 1
            if calls["pwrite"] == 1:
                raise InterruptedError()
            return os.pwrite(fd, data[:max(1, len(data) // 2)], offset)

        def interrupted_preallocate(fd: int, offset: int, size: int) -> None:
            calls["preallocate"] += 1
            if calls["preallocate"] == 1:
                raise InterruptedError()
            os.posix_fallocate(fd, offset, size)

        def interrupted_fsync(fd: int) -> None:
            calls["fsync"] += 1
            if calls["fsync"] == 1:
                raise InterruptedError()
            os.fsync(fd)

        operations = RawSnapshotOperations(
            pread=interrupted_pread,
            pwrite=interrupted_pwrite,
            preallocate=interrupted_preallocate,
            fsync=interrupted_fsync,
        )
        prepared = RawSnapshotBuilder(operations=operations).execute(plan)
        try:
            self.assertEqual(prepared.result.image_sha256, hashlib.sha256(self.payload).hexdigest())
            self.assertGreater(calls["pread"], 2)
            self.assertGreater(calls["pwrite"], 2)
            self.assertEqual(calls["preallocate"], 2)
            self.assertEqual(calls["fsync"], 2)
        finally:
            prepared.close()

    def test_invalid_io_progress_fails_closed(self):
        plan = self.plan()
        invalid_operations = (
            RawSnapshotOperations(pread=lambda _fd, _length, _offset: b""),
            RawSnapshotOperations(pwrite=lambda _fd, _data, _offset: 0),
            RawSnapshotOperations(pwrite=lambda _fd, data, _offset: len(data) + 1),
        )
        for operations in invalid_operations:
            with self.subTest(operations=operations), self.assertRaisesRegex(
                RawSnapshotError,
                "invalid progress",
            ):
                RawSnapshotBuilder(operations=operations).execute(plan)
            self.assertEqual(os.listdir(self.workspace), [])

    def test_cancel_before_and_during_copy_discards_anonymous_snapshot(self):
        plan = self.plan()
        before = RawSnapshotBuilder()
        before.cancel()
        with self.assertRaisesRegex(RawSnapshotCancelled, "cancelled"):
            before.execute(plan)
        self.assertEqual(os.listdir(self.workspace), [])

        during = RawSnapshotBuilder()
        updates: list[tuple[int, int]] = []

        def cancel_at_start(done: int, total: int) -> None:
            updates.append((done, total))
            if done == 0:
                during.cancel()

        with self.assertRaisesRegex(RawSnapshotCancelled, "cancelled"):
            during.execute(plan, progress=cancel_at_start)
        self.assertEqual(updates, [(0, len(self.payload))])
        self.assertEqual(os.listdir(self.workspace), [])

    def test_builder_is_one_shot_even_after_failure(self):
        plan = self.plan()
        builder = RawSnapshotBuilder(
            operations=RawSnapshotOperations(pwrite=lambda _fd, _data, _offset: 0),
        )
        with self.assertRaises(RawSnapshotError):
            builder.execute(plan)
        with self.assertRaisesRegex(RawSnapshotError, "only be used once"):
            builder.execute(plan)

    def test_invalid_transfer_request_does_not_consume_ready_owner(self):
        prepared = prepare_raw_snapshot(self.plan())
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            with self.assertRaisesRegex(RawSnapshotError, "transfer request"):
                prepared.transfer_to_helper(parent, b"request")
            self.assertEqual(prepared.state, RawSnapshotState.READY)
            with self.assertRaisesRegex(RawSnapshotError, "transfer request"):
                prepared.transfer_to_helper(parent, b"")
            self.assertEqual(prepared.state, RawSnapshotState.READY)
        finally:
            prepared.close()
            parent.close()
            child.close()

    def test_snapshot_mutation_poisons_owner_before_transfer(self):
        prepared = prepare_raw_snapshot(self.plan())
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            os.pwrite(prepared._descriptor, b"!", 0)
            os.fsync(prepared._descriptor)
            with self.assertRaisesRegex(RawSnapshotError, "changed"):
                prepared.transfer_to_helper(parent, b"request")
            self.assertEqual(prepared.state, RawSnapshotState.POISONED)
            self.assertEqual(prepared._descriptor, -1)
        finally:
            prepared.close()
            parent.close()
            child.close()

    def test_failed_socket_transfer_poison_consumes_snapshot(self):
        prepared = prepare_raw_snapshot(self.plan())
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        child.close()
        try:
            with self.assertRaisesRegex(RawSnapshotError, "Could not transfer"):
                prepared.transfer_to_helper(parent, b"request")
            self.assertEqual(prepared.state, RawSnapshotState.POISONED)
            with self.assertRaisesRegex(RawSnapshotError, "not transferable"):
                prepared.transfer_to_helper(parent, b"request")
        finally:
            prepared.close()
            parent.close()

    def test_context_close_discards_untransferred_snapshot(self):
        with prepare_raw_snapshot(self.plan()) as prepared:
            descriptor = prepared._descriptor
            self.assertGreaterEqual(descriptor, 0)
            self.assertEqual(prepared.state, RawSnapshotState.READY)
        self.assertEqual(prepared.state, RawSnapshotState.CLOSED)
        self.assertEqual(prepared._descriptor, -1)
        with self.assertRaises(OSError):
            os.fstat(descriptor)


if __name__ == "__main__":
    unittest.main()
