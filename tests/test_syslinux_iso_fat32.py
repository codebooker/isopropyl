from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import ast
import hashlib
import inspect
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from dataclasses import fields, replace
from pathlib import Path
from unittest.mock import patch

import isopropyl.iso_staging as iso_staging
import isopropyl.private_fat32 as private_fat32
import isopropyl.syslinux as syslinux
import isopropyl.syslinux_iso_fat32 as syslinux_iso_fat32
import isopropyl.syslinux_staging as syslinux_staging
from isopropyl.bootloaders import BoundBootArtifact, BoundBootBundle
from isopropyl.iso_staging import IsoStagingExecutor, build_iso_staging_plan
from isopropyl.iso import ArchiveEntry, EntryKind
from isopropyl.private_fat32 import (
    PrivateFat32Builder,
    PrivateFat32State,
)
from isopropyl.syslinux import make_empty_adv
from isopropyl.syslinux_iso_fat32 import (
    PreparedSyslinuxIsoFat32,
    SyslinuxIsoFat32Cancelled,
    SyslinuxIsoFat32Error,
    SyslinuxIsoFat32Plan,
    build_syslinux_iso_fat32_plan,
    prepare_syslinux_iso_fat32,
    validate_syslinux_iso_fat32_plan,
)
from tests.test_iso_staging import (
    FakeExtractor,
    SEVEN_ZIP,
    SYSLINUX_BLOB,
    SYSLINUX_C32,
    SYSLINUX_CONFIG,
    SYSLINUX_PROVENANCE,
    basic_entries,
    fake_catalog_scanner,
    syslinux_analysis,
    syslinux_entries,
    write_plan,
)
from tests.test_syslinux_transaction import PROVENANCE, _payload_fixture


BUILD = "6.03-2014-10-06"
IMAGE_SIZE = 36_888_576
REDIRECT = (
    b"DEFAULT loadconfig\n\n"
    b"LABEL loadconfig\n"
    b"  CONFIG /isolinux/isolinux.cfg\n"
    b"  APPEND /isolinux/\n"
)


def _c32_bundle() -> BoundBootBundle:
    digest = hashlib.sha256(SYSLINUX_C32).hexdigest()
    return BoundBootBundle(
        "syslinux",
        BUILD,
        "blank-bios-module",
        (BoundBootArtifact("ldlinux.c32", SYSLINUX_C32, digest),),
        "GPL-2.0-or-later",
        SYSLINUX_PROVENANCE,
    )


class SyslinuxIsoFat32Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.payload_bundle, self.raw_sys, _bss, self.payload_pins = (
            _payload_fixture(BUILD)
        )
        self.root_loader = self.raw_sys + make_empty_adv()
        patches = (
            patch.object(
                syslinux_staging,
                "PINNED_SYSLINUX_C32",
                {
                    BUILD: (
                        len(SYSLINUX_C32),
                        hashlib.sha256(SYSLINUX_C32).hexdigest(),
                        SYSLINUX_PROVENANCE,
                    ),
                },
            ),
            patch.object(
                syslinux_staging,
                "PINNED_SYSLINUX_ROOTS",
                {
                    BUILD: (
                        len(self.root_loader),
                        hashlib.sha256(self.root_loader).hexdigest(),
                    ),
                },
            ),
            patch.object(
                syslinux,
                "PINNED_SYSLINUX_PAYLOADS",
                {BUILD: self.payload_pins},
            ),
            patch.object(
                syslinux,
                "PINNED_SYSLINUX_PROVENANCE",
                {BUILD: PROVENANCE},
            ),
        )
        for active in patches:
            active.start()
            self.addCleanup(active.stop)

    def stage(self):
        entries = syslinux_entries()
        payloads = {
            "isolinux/isolinux.bin": SYSLINUX_BLOB,
            "isolinux/isolinux.cfg": SYSLINUX_CONFIG,
        }
        image = self.root / "source.iso"
        image.write_bytes(b"ISO placeholder")

        def populate_sources(tree: Path, _image: Path) -> None:
            for relative, data in payloads.items():
                tree.joinpath(*Path(relative).parts).write_bytes(data)

        with (
            patch(
                "isopropyl.iso_staging.scan_image_contents",
                fake_catalog_scanner(entries),
            ),
            patch(
                "isopropyl.iso_staging.analyze_iso_bootloaders",
                return_value=syslinux_analysis(),
            ),
            patch(
                "isopropyl.iso_staging.read_archive_member_with_7z",
                side_effect=lambda _image, member, **_kwargs: payloads[member],
            ),
        ):
            plan = build_iso_staging_plan(
                image,
                self.root / "ready-media",
                entries,
                write_plan(entries),
                seven_zip=SEVEN_ZIP,
                syslinux_c32_bundle=_c32_bundle(),
                syslinux_payload_bundle=self.payload_bundle,
            )
            result = IsoStagingExecutor(
                extractor=FakeExtractor(mutate=populate_sources),
            ).execute(plan)
        self.assertIsNotNone(result.tree_manifest)
        return plan, result

    def composite_plan(self):
        iso_plan, staging_result = self.stage()
        plan = build_syslinux_iso_fat32_plan(
            iso_plan,
            staging_result,
            self.workspace,
            image_size=IMAGE_SIZE,
        )
        return iso_plan, staging_result, plan

    def test_real_nested_receipt_builds_patches_and_streams_anonymous_image(self):
        iso_plan, staging_result, plan = self.composite_plan()
        staging = iso_plan.syslinux_staging
        assert staging is not None
        self.assertEqual(staging.config_path, "isolinux/isolinux.cfg")
        self.assertEqual(staging.config_directory, "/isolinux")
        self.assertEqual(staging.root_redirect.data, REDIRECT)
        self.assertEqual(
            (staging_result.files, staging_result.directories),
            (7, 4),
        )
        self.assertEqual(staging_result.bytes_staged, plan.private_plan.total_content_bytes)
        self.assertEqual(plan.root_ldlinux_size, len(self.root_loader))
        self.assertEqual(
            plan.root_ldlinux_sha256,
            hashlib.sha256(self.root_loader).hexdigest(),
        )
        validate_syslinux_iso_fat32_plan(plan)

        patch_call = {}
        real_patch = syslinux_iso_fat32.patch_private_fat32_syslinux

        def recording_patch(
            image,
            bundle,
            *,
            config_directory,
            expected_unpatched,
            cancel_check=None,
        ):
            self.assertEqual(image.state, PrivateFat32State.UNPATCHED_ATTESTED)
            with self.assertRaises(private_fat32.PrivateFat32Error):
                next(image.chunks())
            patch_call.update({
                "bundle": bundle,
                "config_directory": config_directory,
                "expected_unpatched": expected_unpatched,
            })
            return real_patch(
                image,
                bundle,
                config_directory=config_directory,
                expected_unpatched=expected_unpatched,
                cancel_check=cancel_check,
            )

        updates = []
        with (
            patch.object(
                syslinux_iso_fat32,
                "patch_private_fat32_syslinux",
                side_effect=recording_patch,
            ),
            prepare_syslinux_iso_fat32(
                plan,
                progress=lambda *update: updates.append(update),
            ) as prepared,
        ):
            self.assertIs(type(prepared), PreparedSyslinuxIsoFat32)
            self.assertFalse(hasattr(prepared, "fileno"))
            self.assertFalse(hasattr(prepared, "image"))
            result = prepared.result
            self.assertEqual(result.plan_sha256, plan.plan_sha256)
            self.assertEqual(
                result.private_plan_sha256,
                plan.private_plan.plan_sha256,
            )
            self.assertEqual(result.version, BUILD)
            self.assertEqual(result.image_size, IMAGE_SIZE)
            self.assertEqual(result.files_verified, 7)
            self.assertEqual(result.directories_verified, 3)
            self.assertEqual(result.bytes_verified, staging_result.bytes_staged)
            self.assertNotEqual(
                result.unpatched_image_sha256,
                result.final_image_sha256,
            )
            self.assertNotEqual(
                result.unpatched_manifest_sha256,
                result.final_manifest_sha256,
            )
            self.assertEqual(
                result.unpatched_ldlinux_sha256,
                hashlib.sha256(self.root_loader).hexdigest(),
            )
            self.assertNotEqual(
                result.unpatched_ldlinux_sha256,
                result.patched_ldlinux_sha256,
            )
            streamed = hashlib.sha256()
            streamed_bytes = 0
            for block in prepared.chunks(1_003_007):
                streamed.update(block)
                streamed_bytes += len(block)
            self.assertEqual(streamed_bytes, IMAGE_SIZE)
            self.assertEqual(streamed.hexdigest(), result.final_image_sha256)

        self.assertIs(patch_call["bundle"], iso_plan.syslinux_payload_bundle)
        self.assertEqual(patch_call["config_directory"], "/isolinux")
        self.assertEqual(
            patch_call["expected_unpatched"],
            self.root_loader,
        )
        self.assertIn(
            ("Patching Syslinux", "ldlinux.sys", plan.private_plan.total_content_bytes,
             plan.private_plan.total_content_bytes),
            updates,
        )
        stages = [update[0] for update in updates]
        self.assertEqual(stages.count("Complete"), 1)
        self.assertEqual(stages[-1], "Complete")
        self.assertLess(
            stages.index("FAT32 image built"),
            stages.index("Patching Syslinux"),
        )
        self.assertLess(stages.index("Patching Syslinux"), stages.index("Complete"))
        self.assertEqual(os.listdir(self.workspace), [])
        with self.assertRaisesRegex(SyslinuxIsoFat32Error, "closed"):
            prepared.chunks()

    def test_forged_and_cloned_composite_relationships_are_rejected(self):
        iso_plan, staging_result, plan = self.composite_plan()

        class ForgedPlan(SyslinuxIsoFat32Plan):
            pass

        values = {
            item.name: getattr(plan, item.name)
            for item in fields(plan)
            if item.init
        }
        subclass = ForgedPlan(**values)
        manual = SyslinuxIsoFat32Plan(**values)
        forged = (
            subclass,
            manual,
            replace(plan),
            replace(plan, plan_sha256="0" * 64),
            replace(plan, iso_plan=replace(iso_plan)),
            replace(plan, staging_result=replace(staging_result)),
            replace(
                plan,
                private_plan=replace(
                    plan.private_plan,
                    total_content_bytes=plan.private_plan.total_content_bytes + 1,
                ),
            ),
        )
        for candidate in forged:
            with self.subTest(candidate=type(candidate).__name__), self.assertRaises(
                SyslinuxIsoFat32Error,
            ):
                validate_syslinux_iso_fat32_plan(candidate)

    def test_authoritative_root_config_uses_empty_patch_directory(self):
        root_config = b"DEFAULT linux\nLABEL linux\n  LINUX /vmlinuz\n"
        entries = basic_entries() + (
            ArchiveEntry("isolinux", kind=EntryKind.DIRECTORY),
            ArchiveEntry("isolinux/isolinux.bin", len(SYSLINUX_BLOB)),
            ArchiveEntry("syslinux.cfg", len(root_config)),
        )
        payloads = {
            "isolinux/isolinux.bin": SYSLINUX_BLOB,
            "syslinux.cfg": root_config,
        }
        image = self.root / "root-config.iso"
        image.write_bytes(b"ISO placeholder")

        def populate_sources(tree: Path, _image: Path) -> None:
            for relative, data in payloads.items():
                tree.joinpath(*Path(relative).parts).write_bytes(data)

        with (
            patch(
                "isopropyl.iso_staging.scan_image_contents",
                fake_catalog_scanner(entries),
            ),
            patch(
                "isopropyl.iso_staging.analyze_iso_bootloaders",
                return_value=syslinux_analysis(),
            ),
            patch(
                "isopropyl.iso_staging.read_archive_member_with_7z",
                side_effect=lambda _image, member, **_kwargs: payloads[member],
            ),
        ):
            iso_plan = build_iso_staging_plan(
                image,
                self.root / "root-ready-media",
                entries,
                write_plan(entries),
                seven_zip=SEVEN_ZIP,
                syslinux_c32_bundle=_c32_bundle(),
                syslinux_payload_bundle=self.payload_bundle,
            )
            staging_result = IsoStagingExecutor(
                extractor=FakeExtractor(mutate=populate_sources),
            ).execute(iso_plan)
        staging = iso_plan.syslinux_staging
        assert staging is not None
        self.assertEqual(staging.config_path, "syslinux.cfg")
        self.assertEqual(staging.config_directory, "")
        self.assertIsNone(staging.root_redirect)
        self.assertEqual(staging.ldlinux_c32.path, "ldlinux.c32")
        plan = build_syslinux_iso_fat32_plan(
            iso_plan,
            staging_result,
            self.workspace,
            image_size=IMAGE_SIZE,
        )

        patch_call = {}
        real_patch = syslinux_iso_fat32.patch_private_fat32_syslinux

        def recording_patch(image, bundle, **kwargs):
            patch_call.update(kwargs)
            return real_patch(image, bundle, **kwargs)

        with patch.object(
            syslinux_iso_fat32,
            "patch_private_fat32_syslinux",
            side_effect=recording_patch,
        ), prepare_syslinux_iso_fat32(plan) as prepared:
            self.assertEqual(
                sum(len(block) for block in prepared.chunks()),
                IMAGE_SIZE,
            )
        self.assertEqual(patch_call["config_directory"], "")

    def test_same_size_live_mutation_fails_before_anonymous_creation(self):
        _iso_plan, staging_result, plan = self.composite_plan()
        readme = staging_result.destination / "README.txt"
        before = readme.stat()
        self.assertEqual(before.st_size, 5)
        readme.write_bytes(b"other")
        os.utime(readme, ns=(before.st_atime_ns, before.st_mtime_ns))

        with patch.object(
            syslinux_iso_fat32.PrivateFat32Builder,
            "execute",
            side_effect=AssertionError("must reject before O_TMPFILE"),
        ) as builder:
            with self.assertRaisesRegex(SyslinuxIsoFat32Error, "changed"):
                prepare_syslinux_iso_fat32(plan)
        builder.assert_not_called()

    def test_wrong_bundle_config_and_root_bindings_fail_before_build(self):
        _iso_plan, _staging_result, plan = self.composite_plan()
        mutations = (
            replace(plan, c32_bundle_sha256="0" * 64),
            replace(plan, payload_bundle_sha256="0" * 64),
            replace(plan, config_directory="/other"),
            replace(plan, root_ldlinux_size=plan.root_ldlinux_size + 1),
            replace(plan, root_ldlinux_sha256="0" * 64),
        )
        with patch.object(
            syslinux_iso_fat32.PrivateFat32Builder,
            "execute",
            side_effect=AssertionError("invalid binding reached the builder"),
        ) as builder:
            for candidate in mutations:
                with self.subTest(candidate=candidate), self.assertRaises(
                    SyslinuxIsoFat32Error,
                ):
                    prepare_syslinux_iso_fat32(candidate)
        builder.assert_not_called()
        self.assertEqual(os.listdir(self.workspace), [])

    def test_failure_and_cancellation_close_unpatched_anonymous_images(self):
        _iso_plan, _staging_result, plan = self.composite_plan()

        failed_images = []

        def failing_patch(image, _bundle, **_kwargs):
            failed_images.append(image)
            self.assertEqual(image.state, PrivateFat32State.UNPATCHED_ATTESTED)
            raise private_fat32.PrivateFat32Error("injected patch failure")

        failed_updates = []
        with (
            patch.object(
                syslinux_iso_fat32,
                "patch_private_fat32_syslinux",
                side_effect=failing_patch,
            ),
            self.assertRaisesRegex(SyslinuxIsoFat32Error, "injected patch failure"),
        ):
            prepare_syslinux_iso_fat32(
                plan,
                progress=lambda *update: failed_updates.append(update),
            )
        self.assertEqual(len(failed_images), 1)
        failed_image = failed_images[0]
        self.assertEqual(failed_image.state, PrivateFat32State.CLOSED)
        with self.assertRaises(private_fat32.PrivateFat32Error):
            next(failed_image.chunks())
        self.assertNotIn("Complete", [update[0] for update in failed_updates])
        self.assertEqual(os.listdir(self.workspace), [])

        cancelled = False

        def cancel_check() -> None:
            if cancelled:
                raise SyslinuxIsoFat32Cancelled("injected cancellation")

        real_execute = PrivateFat32Builder.execute
        cancelled_images = []
        cancelled_updates = []

        def cancelling_execute(builder, private_plan, **kwargs):
            nonlocal cancelled
            image = real_execute(
                builder,
                private_plan,
                progress=kwargs["progress"],
            )
            cancelled_images.append(image)
            cancelled = True
            return image

        with (
            patch.object(
                syslinux_iso_fat32.PrivateFat32Builder,
                "execute",
                new=cancelling_execute,
            ),
            self.assertRaisesRegex(
                SyslinuxIsoFat32Cancelled,
                "injected cancellation",
            ),
        ):
            prepare_syslinux_iso_fat32(
                plan,
                cancel_check=cancel_check,
                progress=lambda *update: cancelled_updates.append(update),
            )
        self.assertEqual(len(cancelled_images), 1)
        self.assertEqual(cancelled_images[0].state, PrivateFat32State.CLOSED)
        self.assertNotIn("Complete", [update[0] for update in cancelled_updates])
        self.assertEqual(os.listdir(self.workspace), [])

    def test_post_receipt_path_never_reaches_gui_device_formatter_or_writer(self):
        iso_plan, staging_result = self.stage()
        self.assertEqual(
            tuple(inspect.signature(prepare_syslinux_iso_fat32).parameters),
            ("plan", "cancel_check", "progress"),
        )

        source = Path(syslinux_iso_fat32.__file__).read_text(encoding="utf-8")
        imports = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        self.assertTrue(
            imports.isdisjoint({
                "app",
                "constructed",
                "devices",
                "formatting",
                "subprocess",
                "writer",
            }),
        )

        import isopropyl.constructed as constructed
        import isopropyl.devices as devices
        import isopropyl.formatting as formatting
        import isopropyl.writer as writer

        app_loaded_before = "isopropyl.app" in sys.modules
        real_import = __import__
        real_open = os.open
        forbidden_imports = (
            "isopropyl.app",
            "PySide6",
        )
        opened_paths = []

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            if any(name == item or name.startswith(item + ".") for item in forbidden_imports):
                raise AssertionError(f"forbidden GUI import: {name}")
            return real_import(name, globals, locals, fromlist, level)

        def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
            rendered = os.fsdecode(os.fspath(path))
            opened_paths.append((rendered, flags, dir_fd))
            if os.path.isabs(rendered):
                target = Path(os.path.normpath(rendered))
                if target == Path("/dev") or Path("/dev") in target.parents:
                    raise AssertionError(f"forbidden device open: {target}")
                try:
                    if stat.S_ISBLK(os.stat(target, follow_symlinks=False).st_mode):
                        raise AssertionError(f"forbidden block open: {target}")
                except FileNotFoundError:
                    pass
            if dir_fd is None:
                return real_open(path, flags, mode)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        forbidden_calls = (
            (iso_staging, "validate_iso_staging_plan"),
            (iso_staging, "read_archive_member_with_7z"),
            (iso_staging, "scan_image_contents"),
            (iso_staging, "analyze_iso_bootloaders"),
            (devices, "list_devices"),
            (constructed.ConstructedMediaExecutor, "execute"),
            (formatting.FormatExecutor, "execute"),
            (writer.ImageWriter, "write"),
            (writer.ImageWriter, "unmount"),
        )
        with ExitStack() as stack:
            mocks = [
                stack.enter_context(
                    patch.object(
                        owner,
                        name,
                        side_effect=AssertionError(f"forbidden call: {name}"),
                    ),
                )
                for owner, name in forbidden_calls
            ]
            mocks.extend((
                stack.enter_context(
                    patch.object(
                        subprocess,
                        "run",
                        side_effect=AssertionError("forbidden subprocess.run"),
                    ),
                ),
                stack.enter_context(
                    patch.object(
                        subprocess,
                        "Popen",
                        side_effect=AssertionError("forbidden subprocess.Popen"),
                    ),
                ),
            ))
            stack.enter_context(patch("builtins.__import__", side_effect=guarded_import))
            stack.enter_context(patch.object(os, "open", side_effect=guarded_open))
            plan = build_syslinux_iso_fat32_plan(
                iso_plan,
                staging_result,
                self.workspace,
                image_size=IMAGE_SIZE,
            )
            with prepare_syslinux_iso_fat32(plan) as prepared:
                streamed = sum(len(block) for block in prepared.chunks())
                self.assertEqual(streamed, IMAGE_SIZE)
            for mocked in mocks:
                mocked.assert_not_called()

        self.assertTrue(opened_paths)
        self.assertTrue(any(
            path == "." and flags & getattr(os, "O_TMPFILE", 0)
            for path, flags, _dir_fd in opened_paths
        ))
        self.assertFalse(any(os.path.isabs(path) and path.startswith("/dev") for path, *_ in opened_paths))
        self.assertEqual(os.listdir(self.workspace), [])
        self.assertEqual("isopropyl.app" in sys.modules, app_loaded_before)


if __name__ == "__main__":
    unittest.main()
