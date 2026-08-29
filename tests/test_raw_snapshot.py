from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import array
import errno
import fcntl
import gzip
import hashlib
import os
import socket
import stat
import struct
import tempfile
import unittest
import zipfile
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
    build_image_source_snapshot_plan,
    build_materialized_snapshot_plan,
    build_raw_snapshot_plan,
    observe_raw_source,
    prepare_image_source_snapshot,
    prepare_materialized_snapshot,
    prepare_raw_snapshot,
    validate_raw_snapshot_plan,
)
from isopropyl.sources import ImageSource, open_image_source


def vtsi_fixture(path: Path, *, disk_sectors: int = 12) -> bytes:
    sector_size = 512
    signature = 0x78563412
    sector_zero = bytearray(b"A" * sector_size)
    sector_zero[440:444] = signature.to_bytes(4, "little")
    segments = (
        (0, bytes(sector_zero)),
        (3, b"B" * (2 * sector_size)),
        (disk_sectors - 1, b"Z" * sector_size),
    )
    data = bytearray()
    records = bytearray()
    for disk_start, payload in segments:
        records.extend(struct.pack(
            "<QQQ",
            disk_start,
            len(payload) // sector_size,
            len(data),
        ))
        data.extend(payload)
    segment_offset = len(data)
    padding = b"\0" * (-len(records) % sector_size)
    footer = bytearray(sector_size)
    struct.pack_into(
        "<8sHHQIIIIQ",
        footer,
        0,
        b"VENTOY\0\0",
        1,
        0,
        disk_sectors * sector_size,
        signature,
        0,
        len(segments),
        (~sum(records)) & 0xFFFFFFFF,
        segment_offset,
    )
    struct.pack_into("<I", footer, 24, (~sum(footer)) & 0xFFFFFFFF)
    path.write_bytes(bytes(data) + bytes(records) + padding + bytes(footer))
    expanded = bytearray(disk_sectors * sector_size)
    for disk_start, payload in segments:
        offset = disk_start * sector_size
        expanded[offset:offset + len(payload)] = payload
    return bytes(expanded)


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

    def image_plan(
        self,
        source: ImageSource,
        expected_size: int,
        profile: str,
    ):
        return build_image_source_snapshot_plan(
            source,
            self.workspace,
            expected_expanded_size=expected_size,
            materialization_profile=profile,
            requires_exact_target_size=source.requires_exact_target_size,
            required_logical_sector_size=(
                source.required_logical_sector_size or None
            ),
            target_device_numbers=self.target_numbers,
        )

    def virtual_plan(
        self,
        source: ImageSource,
        expected_size: int,
        profile: str,
    ):
        return build_materialized_snapshot_plan(
            source,
            self.workspace,
            expected_expanded_size=expected_size,
            materialization_profile=profile,
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

    @staticmethod
    def write_descriptor(descriptor: int, payload: bytes) -> None:
        written = 0
        while written < len(payload):
            count = os.pwrite(descriptor, payload[written:], written)
            if count <= 0:
                raise AssertionError("test descriptor write made no progress")
            written += count

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
        calls = {"pread": 0, "pwrite": 0}

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

        operations = RawSnapshotOperations(
            pread=interrupted_pread,
            pwrite=interrupted_pwrite,
        )
        prepared = RawSnapshotBuilder(operations=operations).execute(plan)
        try:
            self.assertEqual(prepared.result.image_sha256, hashlib.sha256(self.payload).hexdigest())
            self.assertGreater(calls["pread"], 2)
            self.assertGreater(calls["pwrite"], 2)
        finally:
            prepared.close()

    def test_nonpositional_snapshot_operations_are_never_replayed(self):
        plan = self.plan()
        for field, message in (
            ("preallocate", "fully allocated"),
            ("fsync", "durability check"),
        ):
            with self.subTest(field=field):
                calls = 0

                def interrupted(*_args) -> None:
                    nonlocal calls
                    calls += 1
                    raise InterruptedError()

                operations = RawSnapshotOperations(**{field: interrupted})
                with self.assertRaisesRegex(RawSnapshotError, message):
                    RawSnapshotBuilder(operations=operations).execute(plan)
                self.assertEqual(calls, 1)
                self.assertEqual(os.listdir(self.workspace), [])

    def test_transient_positional_io_retries_without_reopening(self):
        plan = self.plan()
        calls = {"pread": 0, "pwrite": 0}
        clock = [100.0]
        waits: list[float] = []

        def transient_pread(fd: int, length: int, offset: int) -> bytes:
            calls["pread"] += 1
            if calls["pread"] == 1:
                raise BlockingIOError(errno.EAGAIN, "temporarily unavailable")
            return os.pread(fd, length, offset)

        def transient_pwrite(fd: int, data: bytes, offset: int) -> int:
            calls["pwrite"] += 1
            if calls["pwrite"] == 1:
                raise BlockingIOError(errno.EAGAIN, "temporarily unavailable")
            return os.pwrite(fd, data, offset)

        def sleep(duration: float) -> None:
            waits.append(duration)
            clock[0] += duration

        operations = RawSnapshotOperations(
            pread=transient_pread,
            pwrite=transient_pwrite,
            monotonic=lambda: clock[0],
            sleep=sleep,
        )
        prepared = RawSnapshotBuilder(operations=operations).execute(plan)
        try:
            self.assertEqual(
                prepared.result.image_sha256,
                hashlib.sha256(self.payload).hexdigest(),
            )
            self.assertGreater(calls["pread"], 1)
            self.assertGreater(calls["pwrite"], 1)
            self.assertAlmostEqual(sum(waits), 0.2)
            self.assertTrue(all(0 < delay <= 0.05 for delay in waits))
        finally:
            prepared.close()

    def test_transient_write_after_positive_progress_retries_exact_remainder(self):
        plan = self.plan()
        calls: list[tuple[int, int]] = []
        transient_raised = False
        clock = [100.0]

        def partial_then_transient(fd: int, data: bytes, offset: int) -> int:
            nonlocal transient_raised
            calls.append((offset, len(data)))
            if len(calls) == 1:
                portion = max(1, len(data) // 2)
                return os.pwrite(fd, data[:portion], offset)
            if not transient_raised:
                transient_raised = True
                raise BlockingIOError(errno.EAGAIN, "temporarily unavailable")
            return os.pwrite(fd, data, offset)

        operations = RawSnapshotOperations(
            pwrite=partial_then_transient,
            monotonic=lambda: clock[0],
            sleep=lambda duration: clock.__setitem__(0, clock[0] + duration),
        )
        with RawSnapshotBuilder(operations=operations).execute(plan) as prepared:
            self.assertTrue(transient_raised)
            self.assertEqual(calls[1], calls[2])
            self.assertEqual(
                prepared.result.image_sha256,
                hashlib.sha256(self.payload).hexdigest(),
            )

    def test_bound_source_retry_accepts_earlier_snapshot_progress(self):
        calls = 0
        clock = [100.0]

        def later_transient(fd: int, data: bytes, offset: int) -> int:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise BlockingIOError(errno.EAGAIN, "temporarily unavailable")
            return os.pwrite(fd, data, offset)

        operations = RawSnapshotOperations(
            pwrite=later_transient,
            monotonic=lambda: clock[0],
            sleep=lambda duration: clock.__setitem__(0, clock[0] + duration),
        )
        with open_image_source(self.source) as source:
            plan = self.image_plan(source, len(self.payload), "plain")
            with RawSnapshotBuilder(operations=operations).execute(plan) as prepared:
                self.assertGreaterEqual(calls, 3)
                self.assertEqual(
                    prepared.result.image_sha256,
                    hashlib.sha256(self.payload).hexdigest(),
                )

    def test_ambiguous_snapshot_write_error_is_not_retried(self):
        plan = self.plan()
        calls = 0

        def failing_pwrite(_fd: int, _data: bytes, _offset: int) -> int:
            nonlocal calls
            calls += 1
            raise OSError(errno.EIO, "device I/O error")

        with self.assertRaisesRegex(RawSnapshotError, "write failed"):
            RawSnapshotBuilder(
                operations=RawSnapshotOperations(pwrite=failing_pwrite),
            ).execute(plan)
        self.assertEqual(calls, 1)
        self.assertEqual(os.listdir(self.workspace), [])

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

    def test_bound_plain_gzip_and_zip_sources_materialize_exact_bytes(self):
        plain = self.root / "bound.img"
        compressed = self.root / "bound.img.gz"
        archive = self.root / "bound.zip"
        plain.write_bytes(self.payload)
        compressed.write_bytes(gzip.compress(self.payload, mtime=0))
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            output.writestr("nested/bound.img", self.payload)

        for path, profile in (
            (plain, "plain"),
            (compressed, "compressed"),
            (archive, "compressed"),
        ):
            with self.subTest(path=path.name), open_image_source(path) as source:
                plan = self.image_plan(source, len(self.payload), profile)
                validate_raw_snapshot_plan(plan)
                updates: list[tuple[int, int]] = []
                with prepare_image_source_snapshot(
                    plan,
                    progress=lambda done, total: updates.append((done, total)),
                ) as prepared:
                    result = prepared.result
                    self.assertEqual(result.materialization_profile, profile)
                    self.assertFalse(result.requires_exact_target_size)
                    self.assertIsNone(result.required_logical_sector_size)
                    self.assertEqual(result.source_identity, plan.source_identity)
                    self.assertEqual(result.image_size, len(self.payload))
                    self.assertEqual(
                        result.image_sha256,
                        hashlib.sha256(self.payload).hexdigest(),
                    )
                    self.assertEqual(
                        self.descriptor_bytes(
                            prepared._descriptor,
                            len(self.payload),
                        ),
                        self.payload,
                    )
                self.assertEqual(updates[0], (0, len(self.payload)))
                self.assertEqual(updates[-1], (len(self.payload), len(self.payload)))
                self.assertEqual(os.listdir(self.workspace), [])

    def test_real_vtsi_materialization_carries_exact_target_constraints(self):
        path = self.root / "disk.vtsi"
        expanded = vtsi_fixture(path)
        with open_image_source(path) as source:
            self.assertEqual(source.measure(), len(expanded))
            plan = self.image_plan(source, len(expanded), "vtsi")
            self.assertTrue(plan.requires_exact_target_size)
            self.assertEqual(plan.required_logical_sector_size, 512)
            with prepare_image_source_snapshot(plan) as prepared:
                result = prepared.result
                self.assertEqual(result.materialization_profile, "vtsi")
                self.assertTrue(result.requires_exact_target_size)
                self.assertEqual(result.required_logical_sector_size, 512)
                self.assertEqual(
                    self.descriptor_bytes(prepared._descriptor, len(expanded)),
                    expanded,
                )

    def test_materialized_stream_rejects_short_and_extra_expanded_bytes(self):
        path = self.root / "wrong-length.img.gz"
        path.write_bytes(gzip.compress(self.payload, mtime=0))
        with open_image_source(path) as source:
            for expected, message in (
                (len(self.payload) - 1, "more|size"),
                (len(self.payload) + 1, "ended|expected"),
            ):
                plan = self.image_plan(source, expected, "compressed")
                with self.subTest(expected=expected), self.assertRaisesRegex(
                    RawSnapshotError,
                    message,
                ):
                    prepare_image_source_snapshot(plan)
                self.assertEqual(os.listdir(self.workspace), [])

    def test_outer_source_mutation_is_rejected_before_decoded_bytes_are_written(self):
        path = self.root / "mutable.img.gz"
        path.write_bytes(gzip.compress(self.payload, mtime=0))
        with open_image_source(path) as source:
            plan = self.image_plan(source, len(self.payload), "compressed")
            original_chunks = source.chunks
            changed = False

            def mutating_chunks(*args, **kwargs):
                nonlocal changed
                for block in original_chunks(*args, **kwargs):
                    if not changed:
                        changed = True
                        before = path.stat()
                        with path.open("r+b", buffering=0) as stream:
                            stream.seek(0)
                            stream.write(b"X")
                        os.utime(
                            path,
                            ns=(before.st_atime_ns, before.st_mtime_ns),
                        )
                    yield block

            with (
                patch.object(source, "chunks", new=mutating_chunks),
                self.assertRaisesRegex(RawSnapshotError, "changed"),
            ):
                prepare_image_source_snapshot(plan)
            self.assertTrue(changed)
            self.assertEqual(os.listdir(self.workspace), [])

    def test_materialized_snapshot_cancel_and_forged_constraints_fail_closed(self):
        path = self.root / "cancel.img.gz"
        path.write_bytes(gzip.compress(self.payload, mtime=0))
        with open_image_source(path) as source:
            plan = self.image_plan(source, len(self.payload), "compressed")
            for forged in (
                replace(plan, materialization_profile="plain"),
                replace(plan, requires_exact_target_size=True),
                replace(plan, required_logical_sector_size=512),
                replace(plan, image_size=plan.image_size + 1),
                replace(plan, _bound_source=None),
            ):
                with self.subTest(forged=forged), self.assertRaisesRegex(
                    RawSnapshotError,
                    "forged|authentic",
                ):
                    validate_raw_snapshot_plan(forged)

            with self.assertRaisesRegex(RawSnapshotError, "constraints"):
                build_image_source_snapshot_plan(
                    source,
                    self.workspace,
                    expected_expanded_size=len(self.payload),
                    materialization_profile="plain",
                    requires_exact_target_size=False,
                    required_logical_sector_size=None,
                    target_device_numbers=self.target_numbers,
                )

            builder = RawSnapshotBuilder()

            def cancel_at_start(done: int, _total: int) -> None:
                if done == 0:
                    builder.cancel()

            with self.assertRaisesRegex(RawSnapshotCancelled, "cancelled"):
                builder.execute(plan, progress=cancel_at_start)
            self.assertEqual(os.listdir(self.workspace), [])

    def test_virtual_and_compressed_virtual_materializers_are_authenticated(self):
        virtual = self.root / "guest.qcow2"
        compressed = self.root / "guest.qcow2.gz"
        virtual.write_bytes(b"bound virtual container")
        compressed.write_bytes(gzip.compress(b"bound virtual container", mtime=0))

        for path, profile in (
            (virtual, "virtual"),
            (compressed, "compressed-virtual"),
        ):
            with self.subTest(profile=profile), open_image_source(path) as source:
                plan = self.virtual_plan(source, len(self.payload), profile)
                updates: list[tuple[int, int]] = []
                callback_descriptors: list[int] = []

                def materialize(descriptor: int, check) -> None:
                    callback_descriptors.append(descriptor)
                    status = os.fstat(descriptor)
                    self.assertEqual(status.st_nlink, 0)
                    self.assertEqual(status.st_size, 0)
                    self.assertEqual(stat.S_IMODE(status.st_mode), 0o600)
                    self.assertEqual(
                        fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE,
                        os.O_RDWR,
                    )
                    self.assertTrue(
                        fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
                    )
                    check()
                    os.ftruncate(descriptor, len(self.payload))
                    self.write_descriptor(descriptor, self.payload)
                    check()

                with prepare_materialized_snapshot(
                    plan,
                    materialize,
                    progress=lambda done, total: updates.append((done, total)),
                ) as prepared:
                    self.assertEqual(prepared.result.materialization_profile, profile)
                    self.assertFalse(prepared.result.requires_exact_target_size)
                    self.assertIsNone(prepared.result.required_logical_sector_size)
                    self.assertEqual(
                        prepared.result.image_sha256,
                        hashlib.sha256(self.payload).hexdigest(),
                    )
                    self.assertEqual(
                        self.descriptor_bytes(prepared._descriptor, len(self.payload)),
                        self.payload,
                    )
                    os.fstat(source.fileno())
                self.assertEqual(
                    updates,
                    [(0, len(self.payload)), (len(self.payload), len(self.payload))],
                )
                with self.assertRaises(OSError):
                    os.fstat(callback_descriptors[0])
                os.fstat(source.fileno())
                self.assertEqual(os.listdir(self.workspace), [])

    def test_sparse_virtual_output_is_fully_allocated_and_double_hashed(self):
        path = self.root / "sparse.vhdx"
        path.write_bytes(b"virtual container")
        expanded_size = 4 * 1024 * 1024
        expected = b"A" + b"\0" * (expanded_size - 2) + b"Z"
        read_bytes = 0
        sparse_blocks: list[int] = []

        def counting_pread(descriptor: int, length: int, offset: int) -> bytes:
            nonlocal read_bytes
            block = os.pread(descriptor, length, offset)
            read_bytes += len(block)
            return block

        operations = RawSnapshotOperations(pread=counting_pread)
        with open_image_source(path) as source:
            plan = self.virtual_plan(source, expanded_size, "virtual")

            def sparse_materializer(descriptor: int, check) -> None:
                os.ftruncate(descriptor, expanded_size)
                os.pwrite(descriptor, b"A", 0)
                os.pwrite(descriptor, b"Z", expanded_size - 1)
                sparse_blocks.append(os.fstat(descriptor).st_blocks)
                check()

            builder = RawSnapshotBuilder(operations=operations)
            with builder.execute_materialized(plan, sparse_materializer) as prepared:
                self.assertLess(sparse_blocks[0] * 512, expanded_size)
                self.assertGreaterEqual(
                    prepared.result.snapshot_identity.blocks * 512,
                    expanded_size,
                )
                self.assertEqual(
                    prepared.result.image_sha256,
                    hashlib.sha256(expected).hexdigest(),
                )
                self.assertEqual(
                    self.descriptor_bytes(prepared._descriptor, expanded_size),
                    expected,
                )
        self.assertEqual(read_bytes, expanded_size * 2)

    def test_virtual_materializer_failure_cancel_and_wrong_sizes_clean_up(self):
        path = self.root / "failure.qcow2"
        path.write_bytes(b"virtual container")
        expected_size = 8192
        with open_image_source(path) as source:
            plan = self.virtual_plan(source, expected_size, "virtual")

            def fail(_descriptor: int, check) -> None:
                check()
                raise ValueError("callback exploded")

            with self.assertRaisesRegex(RawSnapshotError, "callback exploded"):
                prepare_materialized_snapshot(plan, fail)
            os.fstat(source.fileno())

            for size in (expected_size - 1, expected_size + 1):
                def wrong_size(descriptor: int, _check, size=size) -> None:
                    os.ftruncate(descriptor, size)

                with self.subTest(size=size), self.assertRaisesRegex(
                    RawSnapshotError,
                    "exact private",
                ):
                    prepare_materialized_snapshot(plan, wrong_size)

            builder = RawSnapshotBuilder()

            def cancel(_descriptor: int, check) -> None:
                builder.cancel()
                check()

            with self.assertRaisesRegex(RawSnapshotCancelled, "cancelled"):
                builder.execute_materialized(plan, cancel)
            os.fstat(source.fileno())
        self.assertEqual(os.listdir(self.workspace), [])

    def test_materializer_fd_substitution_does_not_close_caller_descriptor(self):
        path = self.root / "substitute.vhd"
        path.write_bytes(b"virtual container")
        caller_path = self.root / "caller-owned"
        caller_path.write_bytes(b"caller")
        caller_descriptor = os.open(caller_path, os.O_RDWR)
        substituted = -1
        try:
            with open_image_source(path) as source:
                plan = self.virtual_plan(source, 4096, "virtual")

                def substitute(descriptor: int, _check) -> None:
                    nonlocal substituted
                    substituted = descriptor
                    os.dup2(caller_descriptor, descriptor)
                    os.ftruncate(descriptor, 4096)

                with self.assertRaisesRegex(
                    RawSnapshotError,
                    "closed or substituted",
                ):
                    prepare_materialized_snapshot(plan, substitute)
                self.assertEqual(
                    os.fstat(substituted).st_ino,
                    os.fstat(caller_descriptor).st_ino,
                )
                os.fstat(source.fileno())
        finally:
            if substituted >= 0 and substituted != caller_descriptor:
                os.close(substituted)
            os.close(caller_descriptor)

    def test_linked_mode_mutated_and_unlocked_destinations_fail_closed(self):
        path = self.root / "identity.qcow2"
        path.write_bytes(b"virtual container")
        with open_image_source(path) as source:
            plan = self.virtual_plan(source, 4096, "virtual")
            named = self.root / "named-output"
            named_descriptor = os.open(
                named,
                os.O_CREAT | os.O_EXCL | os.O_RDWR,
                0o600,
            )
            called = False

            def must_not_run(_descriptor: int, _check) -> None:
                nonlocal called
                called = True

            with patch.object(
                RawSnapshotBuilder,
                "_open_anonymous",
                return_value=named_descriptor,
            ):
                with self.assertRaisesRegex(RawSnapshotError, "unlinked"):
                    prepare_materialized_snapshot(plan, must_not_run)
            self.assertFalse(called)
            named.unlink()

            def mutate_mode(descriptor: int, _check) -> None:
                os.ftruncate(descriptor, 4096)
                os.fchmod(descriptor, 0o644)

            with self.assertRaisesRegex(RawSnapshotError, "private"):
                prepare_materialized_snapshot(plan, mutate_mode)

            def unlock(descriptor: int, _check) -> None:
                os.ftruncate(descriptor, 4096)
                fcntl.flock(descriptor, fcntl.LOCK_UN)

            with self.assertRaisesRegex(RawSnapshotError, "lock was released"):
                prepare_materialized_snapshot(plan, unlock)
        self.assertEqual(os.listdir(self.workspace), [])

    def test_virtual_outer_identity_and_plan_profile_forgery_fail_closed(self):
        path = self.root / "mutable.qcow2"
        outer = b"virtual container"
        path.write_bytes(outer)
        with open_image_source(path) as source:
            source_descriptor = source.fileno()
            plan = self.virtual_plan(source, 4096, "virtual")
            for forged in (
                replace(plan),
                replace(plan, materialization_profile="compressed-virtual"),
                replace(plan, requires_exact_target_size=True),
                replace(plan, required_logical_sector_size=512),
                replace(plan, image_size=8192),
            ):
                with self.subTest(forged=forged), self.assertRaisesRegex(
                    RawSnapshotError,
                    "forged|authentic",
                ):
                    validate_raw_snapshot_plan(forged)

            with self.assertRaisesRegex(RawSnapshotError, "stream materialization"):
                build_image_source_snapshot_plan(
                    source,
                    self.workspace,
                    expected_expanded_size=4096,
                    materialization_profile="virtual",
                    requires_exact_target_size=False,
                    required_logical_sector_size=None,
                    target_device_numbers=self.target_numbers,
                )
            with self.assertRaisesRegex(RawSnapshotError, "execute_materialized"):
                RawSnapshotBuilder().execute(plan)

            def mutate_source(descriptor: int, check) -> None:
                os.ftruncate(descriptor, 4096)
                before = path.stat()
                path.write_bytes(b"X" * len(outer))
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                check()

            with self.assertRaisesRegex(RawSnapshotError, "changed"):
                prepare_materialized_snapshot(plan, mutate_source)
            os.fstat(source_descriptor)
        self.assertEqual(os.listdir(self.workspace), [])

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
