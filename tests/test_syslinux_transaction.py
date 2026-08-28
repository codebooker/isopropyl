from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import fcntl
import hashlib
import os
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

import isopropyl.syslinux as syslinux
import isopropyl.syslinux_staging as syslinux_staging
import isopropyl.syslinux_transaction as syslinux_transaction
from isopropyl.bootloaders import BoundBootArtifact, BoundBootBundle
from isopropyl.syslinux import SyslinuxPatchError, make_empty_adv
from isopropyl.syslinux_fat import map_root_ldlinux
from isopropyl.syslinux_transaction import (
    SyslinuxRegularFileTransaction,
    SyslinuxRegularFileTransactionPlan,
    SyslinuxTransactionCancelled,
    SyslinuxTransactionError,
    SyslinuxWriteKind,
    build_syslinux_regular_file_transaction_plan,
    validate_syslinux_regular_file_transaction_plan,
)
from tests.test_syslinux_fat import (
    DATA_START,
    TOTAL_SECTORS,
    disk_mbr,
    make_image,
    patch_payloads,
)
from tests.test_syslinux_staging import (
    analysis as staging_analysis,
    entries as staging_entries,
    source_member_bytes,
)


PARTITION_START = 2_048
VOLUME_OFFSET = PARTITION_START * 512
VOLUME_SIZE = TOTAL_SECTORS * 512
PROVENANCE = "https://example.invalid/syslinux-transaction-source"
BUILD = "fixture"


def _payload_fixture(version: str = BUILD) -> tuple[BoundBootBundle, bytes, bytes, dict]:
    raw, bss = patch_payloads()
    pins = {
        "ldlinux.bss": (len(bss), hashlib.sha256(bss).hexdigest()),
        "ldlinux.sys": (len(raw), hashlib.sha256(raw).hexdigest()),
    }
    bundle = BoundBootBundle(
        "syslinux",
        version,
        "matched-bios-payloads",
        (
            BoundBootArtifact("ldlinux.bss", bss, pins["ldlinux.bss"][1]),
            BoundBootArtifact("ldlinux.sys", raw, pins["ldlinux.sys"][1]),
        ),
        "GPL-2.0-or-later",
        PROVENANCE,
    )
    return bundle, raw, bss, pins


def _read_all(descriptor: int) -> bytes:
    size = os.fstat(descriptor).st_size
    result = bytearray()
    while len(result) < size:
        block = os.pread(descriptor, min(4 * 1024 * 1024, size - len(result)), len(result))
        if not block:
            raise AssertionError("short fixture read")
        result.extend(block)
    return bytes(result)


class SyslinuxTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        _bundle, _raw, _bss, pins = _payload_fixture()
        self.payload_pins = {
            BUILD: pins,
            "6.03-2014-10-06": pins,
        }
        self.provenance_pins = {
            BUILD: PROVENANCE,
            "6.03-2014-10-06": PROVENANCE,
        }
        self.pin_patch = patch.object(
            syslinux,
            "PINNED_SYSLINUX_PAYLOADS",
            self.payload_pins,
        )
        self.provenance_patch = patch.object(
            syslinux,
            "PINNED_SYSLINUX_PROVENANCE",
            self.provenance_pins,
        )
        self.pin_patch.start()
        self.provenance_patch.start()
        self.addCleanup(self.pin_patch.stop)
        self.addCleanup(self.provenance_patch.stop)

    def image(self, *, raw: bytes | None = None, chain=None):
        bundle, default_raw, _bss, _pins = _payload_fixture()
        selected = default_raw if raw is None else raw
        unpatched = selected + make_empty_adv()
        image = tempfile.TemporaryFile()
        kwargs = {
            "file_bytes": unpatched,
            "volume_offset_sectors": PARTITION_START,
        }
        if chain is not None:
            kwargs["chain"] = chain
        make_image(image.fileno(), **kwargs)
        os.pwrite(image.fileno(), disk_mbr(), 0)
        os.fsync(image.fileno())
        return image, bundle, unpatched

    def plan(self, image, bundle, unpatched, *, directory="/isolinux"):
        return build_syslinux_regular_file_transaction_plan(
            bundle,
            image.fileno(),
            volume_offset=VOLUME_OFFSET,
            volume_size=VOLUME_SIZE,
            config_directory=directory,
            expected_unpatched=unpatched,
        )

    def test_cross_boundary_staging_plan_executes_exact_fragmented_golden(self):
        bundle, raw, _bss, pins = _payload_fixture("6.03-2014-10-06")
        c32 = b"transaction fixture c32"
        c32_digest = hashlib.sha256(c32).hexdigest()
        c32_bundle = BoundBootBundle(
            "syslinux",
            "6.03-2014-10-06",
            "blank-bios-module",
            (BoundBootArtifact("ldlinux.c32", c32, c32_digest),),
            "GPL-2.0-or-later",
            "fixture://transaction-c32",
        )
        root = raw + make_empty_adv()
        with (
            patch.object(
                syslinux_staging,
                "PINNED_SYSLINUX_C32",
                {
                    "6.03-2014-10-06": (
                        len(c32), c32_digest, "fixture://transaction-c32",
                    ),
                },
            ),
            patch.object(
                syslinux_staging,
                "PINNED_SYSLINUX_ROOTS",
                {
                    "6.03-2014-10-06": (
                        len(root), hashlib.sha256(root).hexdigest(),
                    ),
                },
            ),
        ):
            staged = syslinux_staging.plan_syslinux_staging(
                staging_entries(),
                staging_analysis(),
                c32_bundle,
                bundle,
                source_files=source_member_bytes(),
            )
        self.assertEqual(staged.root_ldlinux_sys.data, root)
        self.assertEqual(staged.config_directory, "/isolinux")

        image = tempfile.TemporaryFile()
        self.addCleanup(image.close)
        make_image(
            image.fileno(),
            file_bytes=staged.root_ldlinux_sys.data,
            volume_offset_sectors=PARTITION_START,
        )
        os.pwrite(image.fileno(), disk_mbr(), 0)
        os.fsync(image.fileno())
        before = _read_all(image.fileno())
        plan = build_syslinux_regular_file_transaction_plan(
            bundle,
            image.fileno(),
            volume_offset=VOLUME_OFFSET,
            volume_size=VOLUME_SIZE,
            config_directory=staged.config_directory,
            expected_unpatched=staged.root_ldlinux_sys.data,
        )

        self.assertEqual(
            plan.source_image_sha256,
            "fe5380a9168a75d1fcf377186c6458ae5c22576e16c7e640028025a83d25d1a0",
        )
        self.assertEqual(
            plan.expected_image_sha256,
            "0de3a0ae94e11a4a161472fba5870cfc5938d09fa490cd311009d03c36427c01",
        )
        self.assertEqual(
            plan.patched_sha256,
            "5b70c79c75c8f14e32dfc2ff3b43cc9b9e630a93210403fc212f9e7c30f43383",
        )
        self.assertEqual(plan.sectors, (1233, 1235, 1234, 1238, 1236, 1237))
        self.assertEqual(
            tuple(item.offset for item in plan.writes[:6]),
            (1679872, 1680896, 1680384, 1682432, 1681408, 1681920),
        )
        result = SyslinuxRegularFileTransaction().execute(
            plan,
            bundle,
            image.fileno(),
        )
        expected = bytearray(before)
        for item in plan.writes:
            expected[item.offset:item.offset + len(item.after)] = item.after
        self.assertEqual(_read_all(image.fileno()), bytes(expected))
        self.assertEqual(result.final_image_sha256, plan.expected_image_sha256)
        self.assertEqual(
            result.patched_vbr_sha256,
            "0c022c93668a85469b666c4b6ec69bbb62b7b51d016868b8aa0b1bdb56822589",
        )
        self.assertEqual(
            result.patched_mbr_sha256,
            "8f4bf817730559222b31b62389576a7ac796bbca7627f8e8ee2c6812c2ca774d",
        )
        remapped = map_root_ldlinux(
            image.fileno(),
            volume_offset=VOLUME_OFFSET,
            volume_size=VOLUME_SIZE,
            expected_file=b"".join(item.after for item in plan.writes[:6]),
        )
        self.assertEqual(remapped.sectors, plan.sectors)
        self.assertEqual(remapped.clusters, plan.clusters)

    def test_write_order_is_loader_backup_primary_mbr_with_barriers(self):
        image, bundle, unpatched = self.image()
        self.addCleanup(image.close)
        plan = self.plan(image, bundle, unpatched)
        events: list[tuple[str, object]] = []
        real_verify = SyslinuxRegularFileTransaction._verify_records

        def writer(descriptor: int, data: bytes, offset: int) -> int:
            events.append(("write", offset))
            return os.pwrite(descriptor, data, offset)

        def sync(descriptor: int) -> None:
            events.append(("sync", -1))
            os.fsync(descriptor)

        def verify(descriptor: int, records) -> None:
            events.append(("verify", tuple(item.offset for item in records)))
            real_verify(descriptor, records)

        with patch.object(
            SyslinuxRegularFileTransaction,
            "_verify_records",
            side_effect=verify,
        ):
            SyslinuxRegularFileTransaction(write_at=writer, sync=sync).execute(
                plan,
                bundle,
                image.fileno(),
            )
        loader = [("write", item.offset) for item in plan.writes[:-3]]
        loader_offsets = tuple(item.offset for item in plan.writes[:-3])
        all_offsets = tuple(item.offset for item in plan.writes)
        self.assertEqual(
            events,
            [
                ("sync", -1),
                *loader,
                ("sync", -1),
                ("verify", loader_offsets),
                ("write", plan.writes[-3].offset),
                ("sync", -1),
                ("verify", (plan.writes[-3].offset,)),
                ("write", plan.writes[-2].offset),
                ("sync", -1),
                ("verify", (plan.writes[-2].offset,)),
                ("write", plan.writes[-1].offset),
                ("sync", -1),
                ("verify", (plan.writes[-1].offset,)),
                ("verify", all_offsets),
            ],
        )
        self.assertEqual(plan.writes[-1].offset, 0)
        self.assertEqual(plan.writes[-3].kind, SyslinuxWriteKind.BACKUP_VBR)
        self.assertEqual(plan.writes[-2].kind, SyslinuxWriteKind.PRIMARY_VBR)
        self.assertEqual(plan.writes[-1].kind, SyslinuxWriteKind.MBR)

    def test_short_writes_and_eintr_are_retried(self):
        image, bundle, unpatched = self.image()
        self.addCleanup(image.close)
        plan = self.plan(image, bundle, unpatched)
        interrupted = False

        def writer(descriptor: int, data: bytes, offset: int) -> int:
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise InterruptedError
            take = min(17, len(data))
            return os.pwrite(descriptor, data[:take], offset)

        result = SyslinuxRegularFileTransaction(write_at=writer).execute(
            plan,
            bundle,
            image.fileno(),
        )
        self.assertTrue(interrupted)
        self.assertEqual(result.final_image_sha256, plan.expected_image_sha256)

    def test_zero_progress_or_corrupt_loader_never_reaches_boot_sectors(self):
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt):
                image, bundle, unpatched = self.image()
                self.addCleanup(image.close)
                plan = self.plan(image, bundle, unpatched)
                before = _read_all(image.fileno())
                attempted: list[int] = []

                def writer(descriptor: int, data: bytes, offset: int) -> int:
                    attempted.append(offset)
                    if corrupt:
                        return os.pwrite(descriptor, b"X" * len(data), offset)
                    return 0

                with self.assertRaisesRegex(
                    SyslinuxTransactionError,
                    "must be discarded",
                ):
                    SyslinuxRegularFileTransaction(write_at=writer).execute(
                        plan,
                        bundle,
                        image.fileno(),
                    )
                expected = bytearray(before)
                if corrupt:
                    for item in plan.writes[:-3]:
                        expected[item.offset:item.offset + len(item.after)] = (
                            b"X" * len(item.after)
                        )
                    self.assertEqual(
                        attempted,
                        [item.offset for item in plan.writes[:-3]],
                    )
                else:
                    self.assertEqual(attempted, [plan.writes[0].offset])
                self.assertEqual(_read_all(image.fileno()), bytes(expected))

    def test_loader_sync_failure_keeps_vbr_and_mbr_unactivated(self):
        image, bundle, unpatched = self.image()
        self.addCleanup(image.close)
        plan = self.plan(image, bundle, unpatched)
        before = _read_all(image.fileno())
        calls = 0

        def sync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected loader barrier failure")
            os.fsync(descriptor)

        with self.assertRaisesRegex(SyslinuxTransactionError, "must be discarded"):
            SyslinuxRegularFileTransaction(sync=sync).execute(
                plan,
                bundle,
                image.fileno(),
            )
        expected = bytearray(before)
        for item in plan.writes[:-3]:
            expected[item.offset:item.offset + len(item.after)] = item.after
        self.assertEqual(calls, 2)
        self.assertEqual(_read_all(image.fileno()), bytes(expected))

    def test_each_boot_region_write_failure_leaves_mbr_unactivated(self):
        for index in (-3, -2, -1):
            with self.subTest(kind=index):
                image, bundle, unpatched = self.image()
                self.addCleanup(image.close)
                plan = self.plan(image, bundle, unpatched)
                before = _read_all(image.fileno())
                failed_offset = plan.writes[index].offset
                failed_position = len(plan.writes) + index
                attempted: list[int] = []

                def writer(descriptor: int, data: bytes, offset: int) -> int:
                    attempted.append(offset)
                    if offset == failed_offset:
                        return 0
                    return os.pwrite(descriptor, data, offset)

                with self.assertRaisesRegex(
                    SyslinuxTransactionError,
                    "must be discarded",
                ):
                    SyslinuxRegularFileTransaction(write_at=writer).execute(
                        plan,
                        bundle,
                        image.fileno(),
                    )
                expected = bytearray(before)
                for item in plan.writes[:failed_position]:
                    expected[item.offset:item.offset + len(item.after)] = item.after
                self.assertEqual(
                    attempted,
                    [item.offset for item in plan.writes[:failed_position + 1]],
                )
                self.assertEqual(_read_all(image.fileno()), bytes(expected))

    def test_final_whole_image_hash_catches_unrelated_corruption(self):
        image, bundle, unpatched = self.image()
        self.addCleanup(image.close)
        plan = self.plan(image, bundle, unpatched)
        calls = 0

        def sync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            os.fsync(descriptor)
            if calls == 5:
                os.pwrite(descriptor, b"X", VOLUME_OFFSET + 20 * 512)
                os.fsync(descriptor)

        with self.assertRaisesRegex(
            SyslinuxTransactionError,
            "outside the witnessed write set.*must be discarded",
        ):
            SyslinuxRegularFileTransaction(sync=sync).execute(
                plan,
                bundle,
                image.fileno(),
            )

    def test_final_hash_is_bound_to_identity_across_attestation(self):
        image, bundle, unpatched = self.image()
        self.addCleanup(image.close)
        plan = self.plan(image, bundle, unpatched)
        real_digest = syslinux_transaction._plain_image_digest

        def digest_then_change(descriptor: int, size: int) -> str:
            digest = real_digest(descriptor, size)
            os.pwrite(descriptor, b"X", VOLUME_OFFSET + 20 * 512)
            os.fsync(descriptor)
            return digest

        with (
            patch.object(
                syslinux_transaction,
                "_plain_image_digest",
                side_effect=digest_then_change,
            ),
            self.assertRaisesRegex(
                SyslinuxTransactionError,
                "identity changed during final attestation.*must be discarded",
            ),
        ):
            SyslinuxRegularFileTransaction().execute(
                plan,
                bundle,
                image.fileno(),
            )

    def test_unexpected_exception_after_mutation_requires_discard(self):
        image, bundle, unpatched = self.image()
        self.addCleanup(image.close)
        plan = self.plan(image, bundle, unpatched)
        calls = 0

        def sync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValueError("injected unexpected failure")
            os.fsync(descriptor)

        with self.assertRaisesRegex(
            SyslinuxTransactionError,
            "injected unexpected failure.*must be discarded",
        ):
            SyslinuxRegularFileTransaction(sync=sync).execute(
                plan,
                bundle,
                image.fileno(),
            )

    def test_stale_or_forged_plan_fails_before_first_write(self):
        image, bundle, unpatched = self.image()
        self.addCleanup(image.close)
        plan = self.plan(image, bundle, unpatched)
        candidates = (
            replace(plan, config_directory=""),
            replace(plan, version="other"),
            replace(plan, plan_sha256="0" * 64),
            replace(
                plan,
                writes=(
                    replace(plan.writes[0], offset=plan.writes[0].offset + 512),
                    *plan.writes[1:],
                ),
            ),
        )

        class ForgedPlan(SyslinuxRegularFileTransactionPlan):
            pass

        candidates += (ForgedPlan(**plan.__dict__),)
        for candidate in candidates:
            writes = 0

            def writer(_descriptor: int, _data: bytes, _offset: int) -> int:
                nonlocal writes
                writes += 1
                return 0

            with self.subTest(candidate=candidate), self.assertRaises(
                SyslinuxTransactionError,
            ):
                SyslinuxRegularFileTransaction(write_at=writer).execute(
                    candidate,
                    bundle,
                    image.fileno(),
                )
            self.assertEqual(writes, 0)

        os.pwrite(image.fileno(), b"X", plan.writes[0].offset)
        writes = 0

        def stale_writer(_descriptor: int, _data: bytes, _offset: int) -> int:
            nonlocal writes
            writes += 1
            return 0

        with self.assertRaises(SyslinuxTransactionError):
            SyslinuxRegularFileTransaction(write_at=stale_writer).execute(
                plan,
                bundle,
                image.fileno(),
            )
        self.assertEqual(writes, 0)

    def test_plan_validation_rebuilds_the_live_whole_image(self):
        image, bundle, unpatched = self.image()
        self.addCleanup(image.close)
        plan = self.plan(image, bundle, unpatched)
        validate_syslinux_regular_file_transaction_plan(
            plan,
            bundle,
            image.fileno(),
        )
        os.pwrite(image.fileno(), b"X", VOLUME_OFFSET + 20 * 512)
        with self.assertRaises(SyslinuxTransactionError):
            validate_syslinux_regular_file_transaction_plan(
                plan,
                bundle,
                image.fileno(),
            )

    def test_wrong_staged_root_or_config_directory_never_builds_a_plan(self):
        image, bundle, unpatched = self.image()
        self.addCleanup(image.close)
        before = hashlib.sha256(_read_all(image.fileno())).hexdigest()
        for root, directory in (
            (b"X" * len(unpatched), "/isolinux"),
            (unpatched, "relative/path"),
            (unpatched, "/isolinux/../other"),
        ):
            with self.subTest(directory=directory), self.assertRaises(
                SyslinuxTransactionError,
            ):
                build_syslinux_regular_file_transaction_plan(
                    bundle,
                    image.fileno(),
                    volume_offset=VOLUME_OFFSET,
                    volume_size=VOLUME_SIZE,
                    config_directory=directory,
                    expected_unpatched=root,
                )
        self.assertEqual(hashlib.sha256(_read_all(image.fileno())).hexdigest(), before)

    def test_cancellation_before_mutation_is_a_noop(self):
        image, bundle, unpatched = self.image()
        self.addCleanup(image.close)
        plan = self.plan(image, bundle, unpatched)
        before = hashlib.sha256(_read_all(image.fileno())).hexdigest()

        def cancelled() -> None:
            raise SyslinuxTransactionCancelled("cancelled")

        with self.assertRaises(SyslinuxTransactionCancelled):
            SyslinuxRegularFileTransaction().execute(
                plan,
                bundle,
                image.fileno(),
                cancel_check=cancelled,
            )
        self.assertEqual(hashlib.sha256(_read_all(image.fileno())).hexdigest(), before)

    def test_rejects_named_readonly_append_nonregular_and_locked_descriptors(self):
        bundle, raw, _bss, _pins = _payload_fixture()
        unpatched = raw + make_empty_adv()
        with tempfile.NamedTemporaryFile() as named:
            make_image(
                named.fileno(),
                file_bytes=unpatched,
                volume_offset_sectors=PARTITION_START,
            )
            os.pwrite(named.fileno(), disk_mbr(), 0)
            with self.assertRaisesRegex(SyslinuxTransactionError, "anonymous"):
                self.plan(named, bundle, unpatched)

        image, bundle, unpatched = self.image()
        self.addCleanup(image.close)
        readonly = os.open(f"/proc/self/fd/{image.fileno()}", os.O_RDONLY)
        try:
            with self.assertRaisesRegex(SyslinuxTransactionError, "O_RDWR"):
                build_syslinux_regular_file_transaction_plan(
                    bundle,
                    readonly,
                    volume_offset=VOLUME_OFFSET,
                    volume_size=VOLUME_SIZE,
                    config_directory="/isolinux",
                    expected_unpatched=unpatched,
                )
        finally:
            os.close(readonly)

        original_flags = fcntl.fcntl(image.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(image.fileno(), fcntl.F_SETFL, original_flags | os.O_APPEND)
        try:
            with self.assertRaisesRegex(SyslinuxTransactionError, "O_APPEND"):
                self.plan(image, bundle, unpatched)
        finally:
            fcntl.fcntl(image.fileno(), fcntl.F_SETFL, original_flags)

        read_end, write_end = os.pipe()
        try:
            with self.assertRaises(SyslinuxTransactionError):
                build_syslinux_regular_file_transaction_plan(
                    bundle,
                    read_end,
                    volume_offset=VOLUME_OFFSET,
                    volume_size=VOLUME_SIZE,
                    config_directory="/isolinux",
                    expected_unpatched=unpatched,
                )
        finally:
            os.close(read_end)
            os.close(write_end)

        competing = os.open(f"/proc/self/fd/{image.fileno()}", os.O_RDWR)
        try:
            fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(SyslinuxTransactionError, "already in use"):
                self.plan(image, bundle, unpatched)
        finally:
            fcntl.flock(competing, fcntl.LOCK_UN)
            os.close(competing)

    def test_partial_final_sector_slack_is_never_overwritten(self):
        _bundle, raw, _bss, _pins = _payload_fixture()
        extended_raw = raw + b"Z"
        bundle, _ignored, bss, _old_pins = _payload_fixture()
        pins = {
            "ldlinux.bss": (len(bss), hashlib.sha256(bss).hexdigest()),
            "ldlinux.sys": (
                len(extended_raw), hashlib.sha256(extended_raw).hexdigest(),
            ),
        }
        bundle = replace(
            bundle,
            artifacts=(
                bundle.artifacts[0],
                BoundBootArtifact("ldlinux.sys", extended_raw, pins["ldlinux.sys"][1]),
            ),
        )
        unpatched = extended_raw + make_empty_adv()
        with patch.object(syslinux, "PINNED_SYSLINUX_PAYLOADS", {BUILD: pins}):
            image = tempfile.TemporaryFile()
            self.addCleanup(image.close)
            chain = (3, 5, 4, 8, 6, 7, 9)
            make_image(
                image.fileno(),
                chain=chain,
                file_bytes=unpatched,
                volume_offset_sectors=PARTITION_START,
            )
            os.pwrite(image.fileno(), disk_mbr(), 0)
            last_sector = DATA_START + chain[-1] - 2
            slack_offset = VOLUME_OFFSET + last_sector * 512 + 1
            sentinel = bytes((index * 31) & 0xFF for index in range(511))
            os.pwrite(image.fileno(), sentinel, slack_offset)
            os.fsync(image.fileno())
            plan = self.plan(image, bundle, unpatched)
            self.assertEqual(len(plan.writes[6].after), 1)
            SyslinuxRegularFileTransaction().execute(
                plan,
                bundle,
                image.fileno(),
            )
            self.assertEqual(os.pread(image.fileno(), 511, slack_offset), sentinel)

    def test_map_subclasses_and_malformed_fields_fail_closed(self):
        image, bundle, unpatched = self.image()
        self.addCleanup(image.close)
        mapping = map_root_ldlinux(
            image.fileno(),
            volume_offset=VOLUME_OFFSET,
            volume_size=VOLUME_SIZE,
            expected_file=unpatched,
        )

        class ForgedMap(type(mapping)):
            pass

        forged = ForgedMap(**mapping.__dict__)
        from isopropyl.syslinux_fat import prepare_syslinux_patch_from_map

        with self.assertRaises(SyslinuxPatchError):
            prepare_syslinux_patch_from_map(
                bundle,
                image.fileno(),
                forged,
                directory="/isolinux",
            )
        malformed = replace(mapping)
        object.__setattr__(malformed, "sectors", [])
        with self.assertRaises(SyslinuxPatchError):
            prepare_syslinux_patch_from_map(
                bundle,
                image.fileno(),
                malformed,
                directory="/isolinux",
            )


if __name__ == "__main__":
    unittest.main()
