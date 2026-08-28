from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import errno
import fcntl
import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import isopropyl.syslinux as syslinux
import isopropyl.private_fat32 as private_fat32
from isopropyl.fat_image import FatImageError, inspect_regular_fat32_image
from isopropyl.private_fat32 import (
    AnonymousFat32Image,
    PrivateFat32Builder,
    PrivateFat32Error,
    PrivateFat32Plan,
    PrivateFat32State,
    build_private_fat32_plan,
    patch_private_fat32_syslinux,
    validate_private_fat32_plan,
)
from isopropyl.syslinux import make_empty_adv
from isopropyl.syslinux_transaction import SyslinuxRegularFileTransaction
from tests.test_syslinux_transaction import BUILD, PROVENANCE, _payload_fixture


IMAGE_SIZE = 36_888_576
FIXED_MTIME_NS = 1_700_000_000_000_000_000


def _set_fixed_times(root: Path) -> None:
    paths = sorted(root.rglob("*"), key=lambda value: len(value.parts), reverse=True)
    for path in paths:
        os.utime(path, ns=(FIXED_MTIME_NS, FIXED_MTIME_NS), follow_symlinks=False)
    os.utime(root, ns=(FIXED_MTIME_NS, FIXED_MTIME_NS), follow_symlinks=False)


class PrivateFat32Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.source_tmp = tempfile.TemporaryDirectory()
        self.workspace_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.source_tmp.cleanup)
        self.addCleanup(self.workspace_tmp.cleanup)
        self.source = Path(self.source_tmp.name)
        self.workspace = Path(self.workspace_tmp.name)
        self.bundle, raw, _bss, self.pins = _payload_fixture()
        self.unpatched = raw + make_empty_adv()
        (self.source / "ldlinux.sys").write_bytes(self.unpatched)
        (self.source / "syslinux.cfg").write_text("DEFAULT linux\n", encoding="utf-8")
        (self.source / "empty.bin").write_bytes(b"")
        (self.source / "EFI" / "BOOT").mkdir(parents=True)
        (self.source / "EFI" / "BOOT" / "BOOTX64.EFI").write_bytes(b"MZ fixture")
        (self.source / "Long Unicode Name").mkdir()
        (self.source / "Long Unicode Name" / "café.txt").write_bytes(b"coffee")
        (self.source / "Long Unicode Name" / "straße.txt").write_bytes(b"street")
        _set_fixed_times(self.source)
        self.pin_patch = patch.object(
            syslinux,
            "PINNED_SYSLINUX_PAYLOADS",
            {BUILD: self.pins},
        )
        self.provenance_patch = patch.object(
            syslinux,
            "PINNED_SYSLINUX_PROVENANCE",
            {BUILD: PROVENANCE},
        )
        self.pin_patch.start()
        self.provenance_patch.start()
        self.addCleanup(self.pin_patch.stop)
        self.addCleanup(self.provenance_patch.stop)

    def plan(self):
        return build_private_fat32_plan(
            self.source,
            self.workspace,
            image_size=IMAGE_SIZE,
            expected_root_ldlinux=self.unpatched,
        )

    def test_builds_deterministic_mount_free_tree_and_attests_every_file(self):
        plan = self.plan()
        self.assertEqual(plan.geometry.partition_sectors, 70_000)
        self.assertEqual(plan.geometry.sectors_per_cluster, 1)
        self.assertEqual(plan.geometry.sectors_per_fat, 539)
        self.assertEqual(plan.geometry.data_start_sector, 1_110)
        self.assertEqual(plan.geometry.cluster_count, 68_890)
        self.assertEqual(plan.disk_signature, 0xA9FDCB00)
        self.assertEqual(plan.volume_id, 0x68D08716)
        self.assertNotEqual(plan.disk_signature, plan.volume_id)
        self.assertEqual(plan.directories[0].first_cluster, 2)
        loader = next(item for item in plan.files if item.source.parts == ("ldlinux.sys",))
        self.assertEqual(loader.first_cluster, 3)
        self.assertEqual(loader.short_name, b"LDLINUX SYS")
        self.assertFalse(loader.long_name)

        with PrivateFat32Builder().execute(plan) as image:
            self.assertIs(type(image), AnonymousFat32Image)
            self.assertFalse(hasattr(image, "fileno"))
            self.assertEqual(image.state, PrivateFat32State.UNPATCHED_ATTESTED)
            descriptor = image._owned_descriptor()
            info = os.fstat(descriptor)
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_nlink, 0)
            self.assertEqual(info.st_uid, os.geteuid())
            self.assertEqual(info.st_size, IMAGE_SIZE)
            self.assertTrue(fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
            self.assertEqual(image.inspection.disk_signature, plan.disk_signature)
            self.assertEqual(image.inspection.volume_id, plan.volume_id)
            self.assertEqual(os.listdir(self.workspace), [])
            self.assertEqual(
                tuple(entry.path for entry in image.inspection.entries),
                (
                    "EFI",
                    "EFI/BOOT",
                    "EFI/BOOT/BOOTX64.EFI",
                    "empty.bin",
                    "ldlinux.sys",
                    "Long Unicode Name",
                    "Long Unicode Name/café.txt",
                    "Long Unicode Name/straße.txt",
                    "syslinux.cfg",
                ),
            )
            self.assertEqual(image.result.files_verified, 6)
            self.assertEqual(image.result.directories_verified, 3)
            self.assertEqual(image.result.bytes_verified, plan.total_content_bytes)
            self.assertEqual(
                image.result.image_sha256,
                "0986c55793f48679e6f9b62db4e8a423001e86c7bef65abbf17d5b529caab24b",
            )
            with self.assertRaisesRegex(PrivateFat32Error, "patched, attested"):
                next(image.chunks())
        self.assertEqual(image.state, PrivateFat32State.CLOSED)

    def test_builder_to_syslinux_transaction_preserves_the_complete_tree(self):
        plan = self.plan()
        image = PrivateFat32Builder().execute(plan)
        self.addCleanup(image.close)
        before = image.inspection
        result = patch_private_fat32_syslinux(
            image,
            self.bundle,
            config_directory="",
            expected_unpatched=self.unpatched,
        )
        self.assertEqual(image.state, PrivateFat32State.PATCHED_ATTESTED)
        self.assertIs(image.transaction_result, result)
        self.assertEqual(
            result.final_image_sha256,
            "1102e26f5d4f42cc67f323d6623673c1ca46ca8bf83072fe5955e24b06132121",
        )
        self.assertEqual(result.bytes_written, len(self.unpatched) + 3 * 512)
        self.assertEqual(result.writes_verified, len(result.sectors) + 3)
        self.assertEqual(
            tuple(
                (entry.path, entry.size, entry.first_cluster, entry.clusters)
                for entry in image.inspection.entries
            ),
            tuple(
                (entry.path, entry.size, entry.first_cluster, entry.clusters)
                for entry in before.entries
            ),
        )
        for old, new in zip(before.entries, image.inspection.entries, strict=True):
            if old.path == "ldlinux.sys":
                self.assertEqual(new.sha256, result.patched_ldlinux_sha256)
                self.assertNotEqual(new.sha256, old.sha256)
            else:
                self.assertEqual(new.sha256, old.sha256)
        streamed = hashlib.sha256()
        streamed_bytes = 0
        for block in image.chunks(1_003):
            streamed.update(block)
            streamed_bytes += len(block)
        self.assertEqual(streamed_bytes, IMAGE_SIZE)
        self.assertEqual(streamed.hexdigest(), result.final_image_sha256)

    def test_wrong_stale_and_forged_plans_fail_without_an_output_name(self):
        with self.assertRaisesRegex(PrivateFat32Error, "exact payload"):
            build_private_fat32_plan(
                self.source,
                self.workspace,
                image_size=IMAGE_SIZE,
                expected_root_ldlinux=b"wrong",
            )
        plan = self.plan()
        (self.source / "syslinux.cfg").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(PrivateFat32Error, "changed"):
            validate_private_fat32_plan(plan)
        self.assertEqual(os.listdir(self.workspace), [])

        class ForgedPlan(PrivateFat32Plan):
            pass

        forged = ForgedPlan(**plan.__dict__)
        with self.assertRaisesRegex(PrivateFat32Error, "authentic"):
            PrivateFat32Builder().execute(forged)
        with self.assertRaisesRegex(PrivateFat32Error, "forged"):
            PrivateFat32Builder().execute(replace(plan, allocated_clusters=1))
        self.assertEqual(os.listdir(self.workspace), [])

    def test_workspace_cannot_be_the_source_or_nested_inside_it(self):
        with self.assertRaisesRegex(PrivateFat32Error, "outside the staging tree"):
            build_private_fat32_plan(
                self.source,
                self.source,
                image_size=IMAGE_SIZE,
                expected_root_ldlinux=self.unpatched,
            )

    def test_media_ids_are_output_bound_and_plan_validation_rederives_them(self):
        first = self.plan()
        second_root = Path(self.source_tmp.name).parent / (Path(self.source_tmp.name).name + "-copy")
        second_workspace = Path(self.workspace_tmp.name).parent / (
            Path(self.workspace_tmp.name).name + "-copy"
        )
        shutil.copytree(self.source, second_root)
        second_workspace.mkdir()
        self.addCleanup(shutil.rmtree, second_root, True)
        self.addCleanup(shutil.rmtree, second_workspace, True)
        _set_fixed_times(second_root)
        second = build_private_fat32_plan(
            second_root,
            second_workspace,
            image_size=IMAGE_SIZE,
            expected_root_ldlinux=self.unpatched,
        )
        self.assertEqual(
            (second.disk_signature, second.volume_id),
            (first.disk_signature, first.volume_id),
        )
        self.assertNotEqual(second.plan_sha256, first.plan_sha256)

        (second_root / "syslinux.cfg").write_text("DEFAULU linux\n", encoding="utf-8")
        _set_fixed_times(second_root)
        changed = build_private_fat32_plan(
            second_root,
            second_workspace,
            image_size=IMAGE_SIZE,
            expected_root_ldlinux=self.unpatched,
        )
        self.assertNotEqual(
            (changed.disk_signature, changed.volume_id),
            (first.disk_signature, first.volume_id),
        )
        resized = build_private_fat32_plan(
            self.source,
            self.workspace,
            image_size=IMAGE_SIZE + 512,
            expected_root_ldlinux=self.unpatched,
        )
        self.assertNotEqual(
            (resized.disk_signature, resized.volume_id),
            (first.disk_signature, first.volume_id),
        )

        for candidate in (
            replace(first, disk_signature=0),
            replace(first, disk_signature=0xFFFFFFFF),
            replace(first, volume_id=first.disk_signature),
            replace(first, volume_id=1),
        ):
            forged = replace(
                candidate,
                plan_sha256=private_fat32._plan_digest(candidate),
            )
            with self.subTest(forged=forged), self.assertRaises(PrivateFat32Error):
                validate_private_fat32_plan(forged)

    def test_root_volume_label_short_name_is_reserved(self):
        (self.source / "ISOPROPY.L").write_bytes(b"label alias")
        _set_fixed_times(self.source)
        plan = self.plan()
        colliding = next(
            item for item in plan.files if item.source.parts == ("ISOPROPY.L",)
        )
        self.assertTrue(colliding.long_name)
        self.assertNotEqual(colliding.short_name, private_fat32.VOLUME_LABEL)
        with PrivateFat32Builder().execute(plan) as image:
            self.assertIn("ISOPROPY.L", (entry.path for entry in image.inspection.entries))
            root = (
                plan.geometry.volume_offset
                + plan.geometry.data_start_sector * 512
            )
            os.pwrite(
                image._owned_descriptor(),
                private_fat32.VOLUME_LABEL,
                root + 32,
            )
            os.fsync(image._owned_descriptor())
            with self.assertRaisesRegex(FatImageError, "short names alias"):
                inspect_regular_fat32_image(image._owned_descriptor())

    def test_source_root_descriptor_closes_when_initial_fstat_fails(self):
        plan = self.plan()
        real_open = os.open
        real_fstat = os.fstat
        captured = -1

        def opening(path, flags, *args, **kwargs):
            nonlocal captured
            descriptor = real_open(path, flags, *args, **kwargs)
            if path == plan.source_root:
                captured = descriptor
            return descriptor

        def inspecting(descriptor):
            if descriptor == captured:
                raise OSError(errno.EIO, "injected fstat failure")
            return real_fstat(descriptor)

        with (
            patch.object(private_fat32.os, "open", side_effect=opening),
            patch.object(private_fat32.os, "fstat", side_effect=inspecting),
            self.assertRaisesRegex(PrivateFat32Error, "fstat failure"),
        ):
            private_fat32._open_source_root(plan.source_root, plan.directories[0].source)
        self.assertGreaterEqual(captured, 0)
        with self.assertRaises(OSError) as raised:
            real_fstat(captured)
        self.assertEqual(raised.exception.errno, errno.EBADF)
        nested = self.source / "private-workspace"
        nested.mkdir()
        _set_fixed_times(self.source)
        with self.assertRaisesRegex(PrivateFat32Error, "outside the staging tree"):
            build_private_fat32_plan(
                self.source,
                nested,
                image_size=IMAGE_SIZE,
                expected_root_ldlinux=self.unpatched,
            )

    def test_short_writes_and_eintr_are_retried(self):
        plan = self.plan()
        interrupted = False
        short_writes = 0

        def writer(descriptor: int, data: bytes, offset: int) -> int:
            nonlocal interrupted, short_writes
            if not interrupted:
                interrupted = True
                raise InterruptedError
            take = min(37, len(data))
            if take < len(data):
                short_writes += 1
            return os.pwrite(descriptor, data[:take], offset)

        with PrivateFat32Builder(write_at=writer).execute(plan) as image:
            self.assertTrue(interrupted)
            self.assertGreater(short_writes, 1)
            self.assertEqual(
                image.result.image_sha256,
                "0986c55793f48679e6f9b62db4e8a423001e86c7bef65abbf17d5b529caab24b",
            )

    def test_preallocation_and_sync_eintr_are_retried(self):
        preallocate_calls = 0
        sync_calls = 0

        def preallocate(descriptor: int, offset: int, length: int) -> None:
            nonlocal preallocate_calls
            preallocate_calls += 1
            if preallocate_calls == 1:
                raise InterruptedError
            os.posix_fallocate(descriptor, offset, length)

        def sync(descriptor: int) -> None:
            nonlocal sync_calls
            sync_calls += 1
            if sync_calls == 1:
                raise InterruptedError
            os.fsync(descriptor)

        with PrivateFat32Builder(preallocate=preallocate, sync=sync).execute(
            self.plan(),
        ) as image:
            self.assertEqual(
                image.result.image_sha256,
                "0986c55793f48679e6f9b62db4e8a423001e86c7bef65abbf17d5b529caab24b",
            )
        self.assertEqual(preallocate_calls, 2)
        self.assertEqual(sync_calls, 2)

    def test_preallocation_write_and_sync_failures_discard_anonymous_image(self):
        scenarios = []

        def no_space(_descriptor: int, _offset: int, _length: int) -> None:
            raise OSError(errno.ENOSPC, "injected no space")

        scenarios.append(PrivateFat32Builder(preallocate=no_space))
        scenarios.append(PrivateFat32Builder(write_at=lambda _fd, _data, _offset: 0))

        def bad_sync(_descriptor: int) -> None:
            raise OSError(errno.EIO, "injected sync failure")

        scenarios.append(PrivateFat32Builder(sync=bad_sync))
        for builder in scenarios:
            with self.subTest(builder=builder), self.assertRaises(PrivateFat32Error):
                builder.execute(self.plan())
            self.assertEqual(os.listdir(self.workspace), [])

    def test_noop_preallocation_and_invalid_write_progress_close_the_image(self):
        captured: list[int] = []

        def noop_preallocate(descriptor: int, _offset: int, _length: int) -> None:
            captured.append(descriptor)

        with self.assertRaisesRegex(PrivateFat32Error, "preallocated"):
            PrivateFat32Builder(preallocate=noop_preallocate).execute(self.plan())
        with self.assertRaises(OSError) as raised:
            os.fstat(captured.pop())
        self.assertEqual(raised.exception.errno, errno.EBADF)

        for invalid in (False, 0, -1, "oversized"):
            captured.clear()

            def writer(descriptor: int, data: bytes, _offset: int, value=invalid):
                captured.append(descriptor)
                return len(data) + 1 if value == "oversized" else value

            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                PrivateFat32Error,
                "invalid progress",
            ):
                PrivateFat32Builder(write_at=writer).execute(self.plan())
            with self.assertRaises(OSError) as raised:
                os.fstat(captured.pop())
            self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_side_effect_write_outside_the_plan_is_detected_and_closed(self):
        captured = -1
        injected = False

        def writer(descriptor: int, data: bytes, offset: int) -> int:
            nonlocal captured, injected
            captured = descriptor
            written = os.pwrite(descriptor, data, offset)
            if not injected:
                injected = True
                os.pwrite(descriptor, b"X", 512)
            return written

        with self.assertRaisesRegex(PrivateFat32Error, "outside its write plan"):
            PrivateFat32Builder(write_at=writer).execute(self.plan())
        self.assertTrue(injected)
        with self.assertRaises(OSError) as raised:
            os.fstat(captured)
        self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_final_builder_hash_honors_cancellation_and_closes(self):
        captured = -1
        hashing_started = False
        hash_reads = 0
        real_read_exact = private_fat32._read_exact

        def preallocate(descriptor: int, offset: int, length: int) -> None:
            nonlocal captured
            captured = descriptor
            os.posix_fallocate(descriptor, offset, length)

        def reading(descriptor: int, offset: int, length: int, label: str) -> bytes:
            nonlocal hashing_started, hash_reads
            block = real_read_exact(descriptor, offset, length, label)
            if label == "the complete anonymous FAT32 image":
                hashing_started = True
                hash_reads += 1
            return block

        def cancel() -> None:
            if hashing_started:
                raise private_fat32.PrivateFat32Cancelled("cancelled in final hash")

        with (
            patch.object(private_fat32, "_read_exact", side_effect=reading),
            self.assertRaisesRegex(private_fat32.PrivateFat32Cancelled, "final hash"),
        ):
            PrivateFat32Builder(preallocate=preallocate).execute(
                self.plan(),
                cancel_check=cancel,
            )
        self.assertEqual(hash_reads, 1)
        with self.assertRaises(OSError) as raised:
            os.fstat(captured)
        self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_source_change_during_population_discards_before_attestation(self):
        plan = self.plan()
        changed = False

        def writer(descriptor: int, data: bytes, offset: int) -> int:
            nonlocal changed
            written = os.pwrite(descriptor, data, offset)
            if not changed:
                changed = True
                (self.source / "syslinux.cfg").write_text(
                    "MUTATED linux\n",
                    encoding="utf-8",
                )
            return written

        with self.assertRaisesRegex(PrivateFat32Error, "changed"):
            PrivateFat32Builder(write_at=writer).execute(plan)
        self.assertTrue(changed)
        self.assertEqual(os.listdir(self.workspace), [])

    def test_source_change_between_large_file_blocks_closes_the_image(self):
        large_path = self.source / "large.bin"
        large_path.write_bytes(b"A" * (private_fat32.COPY_BLOCK_BYTES + 17))
        _set_fixed_times(self.source)
        plan = self.plan()
        large = next(item for item in plan.files if item.source.parts == ("large.bin",))
        image_offset = private_fat32._cluster_offset(
            plan.geometry,
            large.first_cluster,
        )
        captured = -1
        changed = False

        def writer(descriptor: int, data: bytes, offset: int) -> int:
            nonlocal captured, changed
            captured = descriptor
            written = os.pwrite(descriptor, data, offset)
            if offset == image_offset and not changed:
                changed = True
                source_fd = os.open(large_path, os.O_WRONLY | os.O_CLOEXEC)
                try:
                    os.pwrite(source_fd, b"Z" * len(data), 0)
                    os.fsync(source_fd)
                finally:
                    os.close(source_fd)
            return written

        with self.assertRaisesRegex(PrivateFat32Error, "changed"):
            PrivateFat32Builder(write_at=writer).execute(plan)
        self.assertTrue(changed)
        with self.assertRaises(OSError) as raised:
            os.fstat(captured)
        self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_transaction_failure_poisons_and_never_enables_streaming(self):
        image = PrivateFat32Builder().execute(self.plan())
        failing = SyslinuxRegularFileTransaction(
            write_at=lambda _descriptor, _data, _offset: 0,
        )
        with self.assertRaisesRegex(PrivateFat32Error, "discarded"):
            patch_private_fat32_syslinux(
                image,
                self.bundle,
                config_directory="",
                expected_unpatched=self.unpatched,
                transaction=failing,
            )
        self.assertEqual(image.state, PrivateFat32State.POISONED)
        with self.assertRaises(PrivateFat32Error):
            next(image.chunks())

    def test_post_transaction_gap_mutation_fails_full_image_attestation(self):
        image = PrivateFat32Builder().execute(self.plan())
        real = SyslinuxRegularFileTransaction()

        class MutatingExecutor:
            @staticmethod
            def execute(plan, bundle, descriptor, *, cancel_check=None):
                result = real.execute(
                    plan,
                    bundle,
                    descriptor,
                    cancel_check=cancel_check,
                )
                os.pwrite(descriptor, b"INJECTED", 512)
                os.fsync(descriptor)
                return result

        with self.assertRaisesRegex(PrivateFat32Error, "final tree attestation"):
            patch_private_fat32_syslinux(
                image,
                self.bundle,
                config_directory="",
                expected_unpatched=self.unpatched,
                transaction=MutatingExecutor(),
            )
        self.assertEqual(image.state, PrivateFat32State.POISONED)
        with self.assertRaises(PrivateFat32Error):
            next(image.chunks())

    def test_cancellation_after_transaction_discards_before_final_attestation(self):
        image = PrivateFat32Builder().execute(self.plan())
        descriptor = image._owned_descriptor()
        real = SyslinuxRegularFileTransaction()
        armed = False

        class ArmingExecutor:
            @staticmethod
            def execute(plan, bundle, target, *, cancel_check=None):
                nonlocal armed
                result = real.execute(
                    plan,
                    bundle,
                    target,
                    cancel_check=cancel_check,
                )
                armed = True
                return result

        def cancel() -> None:
            if armed:
                raise private_fat32.PrivateFat32Cancelled("cancelled after transaction")

        with self.assertRaisesRegex(
            private_fat32.PrivateFat32Cancelled,
            "after transaction",
        ):
            patch_private_fat32_syslinux(
                image,
                self.bundle,
                config_directory="",
                expected_unpatched=self.unpatched,
                cancel_check=cancel,
                transaction=ArmingExecutor(),
            )
        self.assertEqual(image.state, PrivateFat32State.POISONED)
        with self.assertRaises(OSError) as raised:
            os.fstat(descriptor)
        self.assertEqual(raised.exception.errno, errno.EBADF)
        with self.assertRaises(PrivateFat32Error):
            next(image.chunks())

    def test_reentrant_close_during_transaction_fails_closed(self):
        image = PrivateFat32Builder().execute(self.plan())

        class ClosingExecutor:
            @staticmethod
            def execute(_plan, _bundle, _descriptor, *, cancel_check=None):
                del cancel_check
                image.close()

        with self.assertRaisesRegex(PrivateFat32Error, "being patched"):
            patch_private_fat32_syslinux(
                image,
                self.bundle,
                config_directory="",
                expected_unpatched=self.unpatched,
                transaction=ClosingExecutor(),
            )
        self.assertEqual(image.state, PrivateFat32State.POISONED)

    def test_forged_transaction_accounting_fields_poison_the_image(self):
        fields = {
            "bytes_written": 0,
            "writes_verified": 0,
            "patched_vbr_sha256": "0" * 64,
            "patched_mbr_sha256": "0" * 64,
        }
        for field, value in fields.items():
            with self.subTest(field=field):
                image = PrivateFat32Builder().execute(self.plan())
                real = SyslinuxRegularFileTransaction()

                class ForgingExecutor:
                    @staticmethod
                    def execute(plan, bundle, descriptor, *, cancel_check=None):
                        result = real.execute(
                            plan,
                            bundle,
                            descriptor,
                            cancel_check=cancel_check,
                        )
                        return replace(result, **{field: value})

                with self.assertRaisesRegex(PrivateFat32Error, "final tree attestation"):
                    patch_private_fat32_syslinux(
                        image,
                        self.bundle,
                        config_directory="",
                        expected_unpatched=self.unpatched,
                        transaction=ForgingExecutor(),
                    )
                self.assertEqual(image.state, PrivateFat32State.POISONED)

    def test_mutation_after_attestation_is_rejected_before_streaming(self):
        image = PrivateFat32Builder().execute(self.plan())
        patch_private_fat32_syslinux(
            image,
            self.bundle,
            config_directory="",
            expected_unpatched=self.unpatched,
        )
        descriptor = image._owned_descriptor()
        os.pwrite(descriptor, b"X", 512)
        os.fsync(descriptor)
        with self.assertRaisesRegex(PrivateFat32Error, "changed before streaming"):
            next(image.chunks())
        self.assertEqual(image.state, PrivateFat32State.POISONED)

    def test_active_stream_owns_a_duplicate_descriptor_across_close(self):
        image = PrivateFat32Builder().execute(self.plan())
        patch_private_fat32_syslinux(
            image,
            self.bundle,
            config_directory="",
            expected_unpatched=self.unpatched,
        )
        owned = image._owned_descriptor()
        expected = os.pread(owned, 2, 0)
        stream = image.chunks(1)
        self.assertEqual(next(stream), expected[:1])
        image.close()
        with tempfile.TemporaryFile() as unrelated:
            self.assertEqual(unrelated.fileno(), owned)
            unrelated.write(b"ZZ")
            unrelated.flush()
            self.assertEqual(next(stream), expected[1:2])
        stream.close()
        self.assertEqual(image.state, PrivateFat32State.CLOSED)

    def test_independent_parser_rejects_fat_and_fsinfo_corruption(self):
        for region in (
            "fat_mirror",
            "fsinfo_mirror",
            "orphan_cluster",
            "fat_padding",
            "fsinfo_accounting",
            "fsinfo_next_free",
            "fsinfo_reserved",
            "volume_label",
            "root_child_dotdot",
            "directory_tail",
        ):
            with self.subTest(region=region):
                image = PrivateFat32Builder().execute(self.plan())
                descriptor = image._owned_descriptor()
                geometry = image.plan.geometry
                volume = geometry.volume_offset
                fat0 = volume + 32 * 512
                fat1 = fat0 + geometry.sectors_per_fat * 512
                if region == "fat_mirror":
                    offset = (
                        volume
                        + geometry.sectors_per_fat * 512
                        + 32 * 512
                    )
                    current = os.pread(descriptor, 1, offset)
                    os.pwrite(descriptor, bytes([current[0] ^ 1]), offset)
                elif region == "fsinfo_mirror":
                    offset = volume + 512
                    current = os.pread(descriptor, 1, offset)
                    os.pwrite(descriptor, bytes([current[0] ^ 1]), offset)
                elif region == "orphan_cluster":
                    cluster = geometry.cluster_count + 1
                    for fat in (fat0, fat1):
                        os.pwrite(descriptor, (0x0FFFFFFF).to_bytes(4, "little"), fat + cluster * 4)
                elif region == "fat_padding":
                    cluster = geometry.cluster_count + 2
                    for fat in (fat0, fat1):
                        os.pwrite(descriptor, (0x0FFFFFFF).to_bytes(4, "little"), fat + cluster * 4)
                elif region == "fsinfo_accounting":
                    for sector in (1, 7):
                        offset = volume + sector * 512 + 488
                        free = int.from_bytes(os.pread(descriptor, 4, offset), "little")
                        os.pwrite(descriptor, (free - 1).to_bytes(4, "little"), offset)
                elif region == "fsinfo_next_free":
                    for sector in (1, 7):
                        offset = volume + sector * 512 + 492
                        next_free = int.from_bytes(os.pread(descriptor, 4, offset), "little")
                        os.pwrite(descriptor, (next_free + 1).to_bytes(4, "little"), offset)
                elif region == "fsinfo_reserved":
                    for sector in (1, 7):
                        os.pwrite(descriptor, b"X", volume + sector * 512 + 4)
                elif region == "volume_label":
                    root = volume + geometry.data_start_sector * 512
                    os.pwrite(descriptor, b"X", root)
                elif region == "root_child_dotdot":
                    efi = next(entry for entry in image.inspection.entries if entry.path == "EFI")
                    directory = (
                        volume
                        + (
                            geometry.data_start_sector
                            + (efi.first_cluster - 2) * geometry.sectors_per_cluster
                        ) * 512
                    )
                    os.pwrite(descriptor, (2).to_bytes(2, "little"), directory + 32 + 26)
                else:
                    root = volume + geometry.data_start_sector * 512
                    directory = os.pread(descriptor, geometry.cluster_bytes, root)
                    terminator = next(
                        offset
                        for offset in range(0, len(directory), 32)
                        if directory[offset] == 0
                    )
                    self.assertLess(terminator + 32, len(directory))
                    os.pwrite(descriptor, b"X", root + terminator + 32)
                os.fsync(descriptor)
                with self.assertRaises(FatImageError):
                    inspect_regular_fat32_image(descriptor)
                image.close()

    def test_non_bmp_names_and_unsafe_image_sizes_fail_closed(self):
        (self.source / "emoji-😀.txt").write_bytes(b"no")
        _set_fixed_times(self.source)
        with self.assertRaisesRegex(PrivateFat32Error, "non-BMP"):
            self.plan()
        (self.source / "emoji-😀.txt").unlink()
        _set_fixed_times(self.source)
        with self.assertRaisesRegex(PrivateFat32Error, "size"):
            build_private_fat32_plan(
                self.source,
                self.workspace,
                image_size=1_024,
                expected_root_ldlinux=self.unpatched,
            )

    @unittest.skipUnless(
        Path("/usr/sbin/fsck.fat").is_file()
        and Path("/proc/self/fd").is_dir()
        and hasattr(os, "O_TMPFILE"),
        "requires Linux O_TMPFILE, /proc/self/fd, and fsck.fat",
    )
    def test_anonymous_partition_passes_external_read_only_fsck(self):
        plan = self.plan()
        with PrivateFat32Builder().execute(plan) as image:
            workspace_fd = os.open(self.workspace, os.O_RDONLY | os.O_DIRECTORY)
            partition_fd = -1
            read_fd = -1
            try:
                partition_fd = os.open(
                    ".",
                    os.O_TMPFILE | os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=workspace_fd,
                )
                os.ftruncate(partition_fd, plan.geometry.volume_size)
                copied = 0
                while copied < plan.geometry.volume_size:
                    take = min(
                        private_fat32.COPY_BLOCK_BYTES,
                        plan.geometry.volume_size - copied,
                    )
                    block = os.pread(
                        image._owned_descriptor(),
                        take,
                        plan.geometry.volume_offset + copied,
                    )
                    self.assertEqual(len(block), take)
                    written = 0
                    while written < len(block):
                        count = os.pwrite(
                            partition_fd,
                            block[written:],
                            copied + written,
                        )
                        self.assertGreater(count, 0)
                        written += count
                    copied += take
                os.fsync(partition_fd)
                read_fd = os.open(
                    f"/proc/self/fd/{partition_fd}",
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                )
                info = os.fstat(read_fd)
                self.assertEqual(info.st_nlink, 0)
                self.assertEqual(info.st_size, plan.geometry.volume_size)
                os.close(partition_fd)
                partition_fd = -1
                completed = subprocess.run(
                    [
                        "/usr/sbin/fsck.fat",
                        "-n",
                        "-v",
                        f"/proc/self/fd/{read_fd}",
                    ],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                    pass_fds=(read_fd,),
                    env={
                        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                        "LANG": "C",
                        "LC_ALL": "C",
                    },
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    (completed.stdout + completed.stderr)[-4_096:],
                )
            finally:
                if read_fd >= 0:
                    os.close(read_fd)
                if partition_fd >= 0:
                    os.close(partition_fd)
                os.close(workspace_fd)


if __name__ == "__main__":
    unittest.main()
