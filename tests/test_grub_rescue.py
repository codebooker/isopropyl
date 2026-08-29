from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import os
import struct
import tempfile
import unittest
from dataclasses import fields, replace
from pathlib import Path
from unittest.mock import patch

import isopropyl.grub_rescue as grub_rescue
import isopropyl.private_fat32 as private_fat32
from isopropyl.bootloaders import BoundBootArtifact, BoundBootBundle
from isopropyl.grub_rescue import (
    GrubRescueBuilder,
    GrubRescueCancelled,
    GrubRescueError,
    GrubRescuePlan,
    build_grub_rescue_plan,
    validate_grub_rescue_plan,
)
from isopropyl.private_fat32 import (
    PrivateFat32BuildProfile,
    PrivateFat32Builder,
    PrivateFat32Error,
    PrivateFat32State,
    build_grub_rescue_private_fat32_plan,
    validate_private_fat32_plan,
)


IMAGE_SIZE = 36_888_576
FIXED_MTIME_NS = 1_700_000_000_000_000_000


def _fixed_time(path: Path) -> None:
    os.utime(path, ns=(FIXED_MTIME_NS, FIXED_MTIME_NS), follow_symlinks=False)


def _fake_boot_image() -> bytes:
    payload = bytearray((index * 29 + 7) & 0xFF for index in range(512))
    struct.pack_into("<Q", payload, 0x5C, 1)
    payload[0x64] = 0xFF
    payload[0x66:0x68] = b"\x90\x90"
    return bytes(payload)


def _fake_core_image() -> bytes:
    payload = bytearray((index * 37 + 11) & 0xFF for index in range(700))
    start = grub_rescue.CORE_BLOCKLIST_OFFSET
    payload[start:start + len(grub_rescue.CORE_BLOCKLIST)] = (
        grub_rescue.CORE_BLOCKLIST
    )
    return bytes(payload)


class GrubRescueTests(unittest.TestCase):
    def setUp(self) -> None:
        source_tmp = tempfile.TemporaryDirectory()
        workspace_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(source_tmp.cleanup)
        self.addCleanup(workspace_tmp.cleanup)
        self.source = Path(source_tmp.name)
        self.workspace = Path(workspace_tmp.name)
        _fixed_time(self.source)

        self.boot = _fake_boot_image()
        self.core = _fake_core_image()
        self.boot_sha256 = hashlib.sha256(self.boot).hexdigest()
        self.bootstrap_sha256 = hashlib.sha256(
            self.boot[:grub_rescue.BOOTSTRAP_SIZE],
        ).hexdigest()
        self.core_sha256 = hashlib.sha256(self.core).hexdigest()
        self.core_padded_size = (
            (len(self.core) + grub_rescue.SECTOR_SIZE - 1)
            // grub_rescue.SECTOR_SIZE
            * grub_rescue.SECTOR_SIZE
        )
        constants = patch.multiple(
            grub_rescue,
            BOOT_IMAGE_SHA256=self.boot_sha256,
            BOOTSTRAP_SHA256=self.bootstrap_sha256,
            CORE_SIZE=len(self.core),
            CORE_SHA256=self.core_sha256,
            CORE_PADDED_SIZE=self.core_padded_size,
        )
        constants.start()
        self.addCleanup(constants.stop)
        self.bundle = self.make_bundle()

    def make_bundle(
        self,
        *,
        boot: bytes | None = None,
        core: bytes | None = None,
        boot_sha256: str | None = None,
        core_sha256: str | None = None,
        family: str = grub_rescue.GRUB_FAMILY,
        version: str = grub_rescue.GRUB_VERSION,
        purpose: str = grub_rescue.GRUB_PURPOSE,
        artifacts: tuple[BoundBootArtifact, ...] | None = None,
    ) -> BoundBootBundle:
        boot = self.boot if boot is None else boot
        core = self.core if core is None else core
        if artifacts is None:
            artifacts = (
                BoundBootArtifact(
                    "boot.img",
                    boot,
                    self.boot_sha256 if boot_sha256 is None else boot_sha256,
                ),
                BoundBootArtifact(
                    "core.img",
                    core,
                    self.core_sha256 if core_sha256 is None else core_sha256,
                ),
            )
        return BoundBootBundle(
            family=family,
            version=version,
            purpose=purpose,
            artifacts=artifacts,
            license=grub_rescue.GRUB_LICENSE,
            provenance_url=grub_rescue.GRUB_PROVENANCE_URL,
        )

    def plan(self) -> GrubRescuePlan:
        return build_grub_rescue_plan(
            self.bundle,
            self.source,
            self.workspace,
            image_size=IMAGE_SIZE,
        )

    def test_build_is_deterministic_empty_and_preserves_exact_disk_layout(self) -> None:
        plan_digests: list[str] = []
        image_digests: list[str] = []
        for _index in range(2):
            plan = self.plan()
            validate_grub_rescue_plan(plan)
            self.assertIs(
                plan.private_plan.profile,
                PrivateFat32BuildProfile.GRUB_RESCUE,
            )
            self.assertEqual(plan.private_plan.files, ())
            self.assertEqual(len(plan.private_plan.directories), 1)
            self.assertEqual(plan.private_plan.directories[0].source.parts, ())
            with GrubRescueBuilder().execute(plan) as image:
                self.assertEqual(image.state, PrivateFat32State.PATCHED_ATTESTED)
                self.assertEqual(image.result.files_verified, 0)
                self.assertEqual(image.result.bytes_verified, 0)
                self.assertTrue(image.result.embedding_gap_zero_verified)
                descriptor, image_size = image._duplicate_attested_descriptor()
                try:
                    final_mbr = os.pread(descriptor, 512, 0)
                    expected_unpatched = grub_rescue._expected_unpatched_mbr(
                        plan.private_plan,
                    )
                    self.assertEqual(
                        final_mbr,
                        self.boot[:grub_rescue.BOOTSTRAP_SIZE]
                        + expected_unpatched[grub_rescue.BOOTSTRAP_SIZE:],
                    )
                    self.assertEqual(
                        final_mbr[grub_rescue.BOOTSTRAP_SIZE:],
                        expected_unpatched[grub_rescue.BOOTSTRAP_SIZE:],
                    )
                    self.assertEqual(
                        os.pread(descriptor, len(self.core), grub_rescue.CORE_OFFSET),
                        self.core,
                    )
                    gap_start = grub_rescue.CORE_OFFSET + len(self.core)
                    gap = os.pread(
                        descriptor,
                        grub_rescue.EMBEDDING_LIMIT - gap_start,
                        gap_start,
                    )
                    self.assertEqual(gap, bytes(len(gap)))
                    digest = hashlib.sha256()
                    offset = 0
                    while offset < image_size:
                        block = os.pread(
                            descriptor,
                            min(1024 * 1024, image_size - offset),
                            offset,
                        )
                        self.assertTrue(block)
                        digest.update(block)
                        offset += len(block)
                    self.assertEqual(
                        digest.hexdigest(),
                        image.result.final_image_sha256,
                    )
                finally:
                    os.close(descriptor)
                self.assertEqual(
                    image.result.final_mbr_sha256,
                    hashlib.sha256(final_mbr).hexdigest(),
                )
                self.assertEqual(image.result.core_sha256, self.core_sha256)
                self.assertEqual(
                    image.result.final_fat_manifest_sha256,
                    image._image.inspection.manifest_sha256,
                )
                plan_digests.append(plan.plan_sha256)
                image_digests.append(image.result.final_image_sha256)
        self.assertEqual(plan_digests[0], plan_digests[1])
        self.assertEqual(image_digests[0], image_digests[1])
        self.assertEqual(os.listdir(self.workspace), [])

    def test_unpatched_rescue_profile_cannot_be_streamed_or_duplicated(self) -> None:
        plan = self.plan().private_plan
        with PrivateFat32Builder().execute(plan) as image:
            self.assertEqual(image.state, PrivateFat32State.UNPATCHED_ATTESTED)
            with self.assertRaisesRegex(PrivateFat32Error, "patched, attested"):
                next(image.chunks(4096))
            with self.assertRaisesRegex(PrivateFat32Error, "patched, attested"):
                image._duplicate_attested_descriptor()

    def test_nonempty_tree_is_rejected(self) -> None:
        (self.source / "README.txt").write_text("not empty\n", encoding="utf-8")
        _fixed_time(self.source / "README.txt")
        _fixed_time(self.source)
        with self.assertRaisesRegex(GrubRescueError, "tree must be empty"):
            self.plan()

    def test_plan_receipt_rejects_replacement_forgery_and_subclass(self) -> None:
        plan = self.plan()
        forged = replace(plan, core_offset=plan.core_offset + 512)
        forged = replace(forged, plan_sha256=grub_rescue._plan_digest(forged))
        with self.assertRaisesRegex(GrubRescueError, "receipt is invalid"):
            validate_grub_rescue_plan(forged)

        class DerivedPlan(GrubRescuePlan):
            pass

        derived = DerivedPlan(**{
            item.name: getattr(plan, item.name)
            for item in fields(GrubRescuePlan)
            if item.init
        })
        with self.assertRaisesRegex(GrubRescueError, "authentic.*plan"):
            validate_grub_rescue_plan(derived)

    def test_bundle_exact_type_order_version_purpose_and_payload_hash_are_bound(self) -> None:
        class DerivedBundle(BoundBootBundle):
            pass

        class DerivedArtifact(BoundBootArtifact):
            pass

        bad_boot = bytearray(self.boot)
        bad_boot[200] ^= 0xFF
        cases = {
            "bundle subclass": DerivedBundle(**self.bundle.__dict__),
            "artifact subclass": self.make_bundle(artifacts=(
                DerivedArtifact("boot.img", self.boot, self.boot_sha256),
                self.bundle.artifacts[1],
            )),
            "artifact order": self.make_bundle(
                artifacts=tuple(reversed(self.bundle.artifacts)),
            ),
            "version": self.make_bundle(version="2.12"),
            "purpose": self.make_bundle(purpose="blank-bios-core-image"),
            "payload hash": self.make_bundle(
                boot=bytes(bad_boot),
                boot_sha256=self.boot_sha256,
            ),
        }
        for label, bundle in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(GrubRescueError):
                    build_grub_rescue_plan(
                        bundle,
                        self.source,
                        self.workspace,
                        image_size=IMAGE_SIZE,
                    )

    def test_boot_layout_is_checked_after_its_exact_hash(self) -> None:
        malformed = bytearray(self.boot)
        struct.pack_into("<Q", malformed, 0x5C, 2)
        malformed = bytes(malformed)
        full_digest = hashlib.sha256(malformed).hexdigest()
        bootstrap_digest = hashlib.sha256(
            malformed[:grub_rescue.BOOTSTRAP_SIZE],
        ).hexdigest()
        bundle = self.make_bundle(
            boot=malformed,
            boot_sha256=full_digest,
        )
        with patch.multiple(
            grub_rescue,
            BOOT_IMAGE_SHA256=full_digest,
            BOOTSTRAP_SHA256=bootstrap_digest,
        ):
            with self.assertRaisesRegex(GrubRescueError, "first-stage layout"):
                build_grub_rescue_plan(
                    bundle,
                    self.source,
                    self.workspace,
                    image_size=IMAGE_SIZE,
                )

    def test_core_blocklist_is_checked_after_its_exact_hash(self) -> None:
        malformed = bytearray(self.core)
        malformed[grub_rescue.CORE_BLOCKLIST_OFFSET] ^= 0x01
        malformed = bytes(malformed)
        digest = hashlib.sha256(malformed).hexdigest()
        bundle = self.make_bundle(core=malformed, core_sha256=digest)
        with patch.object(grub_rescue, "CORE_SHA256", digest):
            with self.assertRaisesRegex(GrubRescueError, "diskboot blocklist"):
                build_grub_rescue_plan(
                    bundle,
                    self.source,
                    self.workspace,
                    image_size=IMAGE_SIZE,
                )

    def test_rescue_private_plan_cannot_be_recast_as_generic(self) -> None:
        plan = build_grub_rescue_private_fat32_plan(
            self.source,
            self.workspace,
            image_size=IMAGE_SIZE,
        )
        forged = replace(plan, profile=PrivateFat32BuildProfile.GENERIC)
        forged = replace(
            forged,
            plan_sha256=private_fat32._plan_digest(forged),
        )
        with self.assertRaisesRegex(
            PrivateFat32Error,
            "profile does not match its construction",
        ):
            validate_private_fat32_plan(forged)

    def test_builder_is_one_shot(self) -> None:
        plan = self.plan()
        builder = GrubRescueBuilder()
        with builder.execute(plan):
            pass
        with self.assertRaisesRegex(GrubRescueError, "only be used once"):
            builder.execute(plan)

    def test_cancellation_before_mbr_activation_poisons_private_image(self) -> None:
        plan = self.plan()
        real_builder = grub_rescue.PrivateFat32Builder
        real_zero_check = grub_rescue._require_zero_range
        captured: dict[str, object] = {}
        activation_ready = False

        class CapturingBuilder:
            def execute(self, *args, **kwargs):
                image = real_builder().execute(*args, **kwargs)
                captured["image"] = image
                return image

        def check_cancelled() -> None:
            if activation_ready:
                raise GrubRescueCancelled("cancelled before activation")

        def zero_check(descriptor, start, end, **kwargs):
            nonlocal activation_ready
            result = real_zero_check(descriptor, start, end, **kwargs)
            if start == grub_rescue.CORE_OFFSET + len(self.core):
                activation_ready = True
            return result

        with (
            patch.object(grub_rescue, "PrivateFat32Builder", CapturingBuilder),
            patch.object(grub_rescue, "_require_zero_range", zero_check),
            self.assertRaisesRegex(GrubRescueCancelled, "before activation"),
        ):
            GrubRescueBuilder().execute(plan, cancel_check=check_cancelled)
        image = captured["image"]
        self.assertEqual(image.state, PrivateFat32State.POISONED)
        with self.assertRaisesRegex(PrivateFat32Error, "closed"):
            image._owned_descriptor()

    def test_cancellation_during_final_hash_is_honored_after_attestation(self) -> None:
        plan = self.plan()
        real_builder = grub_rescue.PrivateFat32Builder
        real_hash = grub_rescue._hash_descriptor
        captured: dict[str, object] = {}
        hash_calls = 0
        cancelled = False

        class CapturingBuilder:
            def execute(self, *args, **kwargs):
                image = real_builder().execute(*args, **kwargs)
                captured["image"] = image
                return image

        def hashing(*args, **kwargs):
            nonlocal hash_calls, cancelled
            result = real_hash(*args, **kwargs)
            hash_calls += 1
            if hash_calls == 2:
                cancelled = True
            return result

        def check_cancelled() -> None:
            if cancelled:
                raise GrubRescueCancelled("cancelled during final attestation")

        with (
            patch.object(grub_rescue, "PrivateFat32Builder", CapturingBuilder),
            patch.object(grub_rescue, "_hash_descriptor", hashing),
            self.assertRaisesRegex(GrubRescueCancelled, "final attestation"),
        ):
            GrubRescueBuilder().execute(plan, cancel_check=check_cancelled)
        self.assertEqual(hash_calls, 2)
        image = captured["image"]
        self.assertEqual(image.state, PrivateFat32State.POISONED)
        with self.assertRaisesRegex(PrivateFat32Error, "closed"):
            image._owned_descriptor()

    def test_core_readback_mutation_fails_closed_and_poisons_image(self) -> None:
        plan = self.plan()
        real_builder = grub_rescue.PrivateFat32Builder
        real_write = grub_rescue._write_exact
        captured: dict[str, object] = {}

        class CapturingBuilder:
            def execute(self, *args, **kwargs):
                image = real_builder().execute(*args, **kwargs)
                captured["image"] = image
                return image

        def corrupting_write(descriptor, offset, data, **kwargs):
            real_write(descriptor, offset, data, **kwargs)
            if offset == grub_rescue.CORE_OFFSET:
                original = os.pread(descriptor, 1, offset)
                os.pwrite(descriptor, bytes((original[0] ^ 0xFF,)), offset)

        with (
            patch.object(grub_rescue, "PrivateFat32Builder", CapturingBuilder),
            patch.object(grub_rescue, "_write_exact", corrupting_write),
            self.assertRaisesRegex(GrubRescueError, "core write failed read-back"),
        ):
            GrubRescueBuilder().execute(plan)
        image = captured["image"]
        self.assertEqual(image.state, PrivateFat32State.POISONED)
        with self.assertRaisesRegex(PrivateFat32Error, "closed"):
            image._owned_descriptor()


if __name__ == "__main__":
    unittest.main()
