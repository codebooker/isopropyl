from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import tempfile
import threading
import unittest
import zipfile
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

import isopropyl.iso_staging as iso_staging
from isopropyl.extraction import (
    ExtractionCancelled,
    ExtractionProgress,
    ExtractionResult,
)
from isopropyl.iso import (
    FAT32_MAX_FILE_SIZE,
    ArchiveEntry,
    BootStrategy,
    EntryKind,
    FileSystem,
    FirmwareTarget,
    PartitionTable,
    TargetLayout,
    Transformation,
    WriteMode,
    WritePlan,
    merge_additive_overlay_entries,
)
from isopropyl.iso_staging import (
    IsoStagingCancelled,
    IsoStagingError,
    IsoStagingExecutor,
    IsoStagingSafetyError,
    build_iso_staging_plan,
    validate_iso_staging_plan,
)
from isopropyl.timestamps import TimestampPreservationError
from isopropyl.wim import (
    DEFAULT_SPLIT_PART_MIB,
    WimCancelled,
    WimEdition,
    WimError,
    WimInfo,
    WimSelection,
    WimSplitPlan,
    WimSplitResult,
)
from isopropyl.windows import (
    WindowsCustomization, answer_file_install_index, answer_file_install_path,
)
from isopropyl.zip_overlay import (
    apply_zip_overlay,
    build_zip_overlay_plan,
)


SEVEN_ZIP = "/usr/bin/7z"
WIMLIB = "/usr/bin/wimlib-imagex"
LARGE_TEMP_PARENT = Path(__file__).resolve().parent.parent


def basic_entries() -> tuple[ArchiveEntry, ...]:
    return (
        ArchiveEntry("EFI", kind=EntryKind.DIRECTORY),
        ArchiveEntry("EFI/BOOT", kind=EntryKind.DIRECTORY),
        ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 8),
        ArchiveEntry("README.txt", 5),
    )


def windows_entries() -> tuple[ArchiveEntry, ...]:
    return basic_entries() + (
        ArchiveEntry("sources", kind=EntryKind.DIRECTORY),
        ArchiveEntry("sources/install.wim", FAT32_MAX_FILE_SIZE + 1),
    )


def selected_esd_entries() -> tuple[ArchiveEntry, ...]:
    return basic_entries() + (
        ArchiveEntry("sources", kind=EntryKind.DIRECTORY),
        ArchiveEntry("sources/install.esd", 7),
    )


def selected_esd(build: int = 26100) -> WimSelection:
    edition = WimEdition(
        index=3, name="Windows 11 Pro", description="Professional desktop",
        edition_id="Professional", architecture="amd64",
        major_version=10, minor_version=0, build=build, service_pack_build=0,
    )
    return WimSelection("sources/install.esd", 7, (edition,), 3)


def inspected_wim(path: Path, editions: tuple[WimEdition, ...]) -> WimInfo:
    info = path.stat()
    return WimInfo(
        str(path.resolve()), info.st_size, editions,
        (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_nlink,
        ),
    )


def write_plan(
    entries: tuple[ArchiveEntry, ...],
    *,
    blockers: tuple[str, ...] = (),
    mode: WriteMode = WriteMode.EXTRACTED_ISO,
    firmware: FirmwareTarget = FirmwareTarget.UEFI_ONLY,
    filesystem: FileSystem = FileSystem.FAT32,
) -> WritePlan:
    needs_split = filesystem is FileSystem.FAT32 and any(
        entry.kind is EntryKind.FILE
        and entry.path.casefold() == "sources/install.wim"
        and entry.size > FAT32_MAX_FILE_SIZE
        for entry in entries
    )
    layout = TargetLayout(
        partition_table=PartitionTable.GPT,
        main_filesystem=filesystem,
        partition_count=1 if filesystem is FileSystem.FAT32 else 2,
        boot_partition_filesystem=None,
        bios_bootable=False,
        uefi_bootable=True,
        boot_strategy=(
            BootStrategy.IMAGE_NATIVE
            if filesystem is FileSystem.FAT32 else BootStrategy.UEFI_NTFS
        ),
    )
    content = sum(entry.size for entry in entries if entry.kind is EntryKind.FILE)
    return WritePlan(
        mode=mode,
        firmware_target=firmware,
        layout=layout,
        requirements=(),
        transformations=(Transformation.SPLIT_WINDOWS_WIM,) if needs_split else (),
        warnings=(),
        minimum_content_bytes=content,
        minimum_target_bytes=content + 64 * 1024 * 1024,
        content_constraints_checked=True,
        blockers=blockers,
    )


def make_overlay(
    root: Path,
    members: tuple[tuple[str, bytes | None], ...] = (
        ("efi/", None),
        ("efi/tools/", None),
        ("efi/tools/diagnostic.txt", b"hello"),
    ),
):
    archive = root / "overlay.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        for name, payload in members:
            output.writestr(name, b"" if payload is None else payload)
    return build_zip_overlay_plan(archive)


def overlay_write_plan(
    entries: tuple[ArchiveEntry, ...], overlay,
) -> WritePlan:
    merged = merge_additive_overlay_entries(
        entries, (member.entry for member in overlay.members),
    )
    return write_plan(merged.merged_entries)


class FakeExtractor:
    def __init__(self, *, mutate=None, error: BaseException | None = None):
        self.mutate = mutate
        self.error = error
        self.cancelled = False
        self.calls = []

    def cancel(self):
        self.cancelled = True

    def execute(self, plan, progress):
        self.calls.append(plan)
        if self.cancelled:
            raise ExtractionCancelled("cancelled")
        if self.error:
            raise self.error
        plan.destination.mkdir()
        files = directories = done = 0
        directory_mtimes = []
        for entry in plan.entries:
            path = plan.destination.joinpath(*Path(entry.path).parts)
            if entry.kind is EntryKind.DIRECTORY:
                path.mkdir(parents=True, exist_ok=True)
                if entry.modified_ns is not None:
                    directory_mtimes.append((path, entry.modified_ns))
                directories += 1
            elif entry.kind is EntryKind.FILE:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("wb") as stream:
                    stream.truncate(entry.size)
                done += entry.size
                files += 1
                progress(ExtractionProgress(
                    entry.path, entry.size, entry.size, done, plan.content_bytes,
                ))
                if entry.modified_ns is not None:
                    os.utime(path, ns=(entry.modified_ns, entry.modified_ns))
            else:
                raise AssertionError("test extractor only supports regular catalogs")
        for path, modified_ns in sorted(
            directory_mtimes, key=lambda item: len(item[0].parts), reverse=True,
        ):
            os.utime(path, ns=(modified_ns, modified_ns))
        if self.mutate:
            self.mutate(plan.destination, plan.image)
        return ExtractionResult(plan.destination, files, directories, 0, done)


class BlockingExtractor(FakeExtractor):
    def __init__(self):
        super().__init__()
        self.started = threading.Event()
        self.released = threading.Event()

    def cancel(self):
        super().cancel()
        self.released.set()

    def execute(self, plan, progress):
        self.started.set()
        self.released.wait(timeout=5)
        if self.cancelled:
            raise ExtractionCancelled("cancelled")
        return super().execute(plan, progress)


def fake_split_plan(source: Path, destination: Path, tool: str) -> WimSplitPlan:
    info = source.stat()
    return WimSplitPlan(
        source=str(source.resolve()),
        source_identity=(
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_nlink,
        ),
        destination_directory=str(destination),
        part_size_mib=DEFAULT_SPLIT_PART_MIB,
        wimlib_imagex=tool,
    )


class FakeSplitter:
    def __init__(self, *, error: BaseException | None = None, names=None):
        self.error = error
        self.names = names or ("install.swm", "install2.swm")
        self.cancelled = False
        self.calls = []

    def cancel(self):
        self.cancelled = True

    def execute(self, plan, stage):
        self.calls.append(plan)
        if self.cancelled:
            raise WimCancelled("cancelled")
        if self.error:
            raise self.error
        stage("Splitting install.wim")
        destination = Path(plan.destination_directory)
        destination.mkdir()
        parts = []
        for number, name in enumerate(self.names, 1):
            part = destination / name
            part.write_bytes(f"part-{number}".encode())
            parts.append(str(part))
        stage("Complete")
        return WimSplitResult(
            str(destination), tuple(parts),
            sum(Path(path).stat().st_size for path in parts),
        )


class BlockingSplitter(FakeSplitter):
    def __init__(self):
        super().__init__()
        self.started = threading.Event()
        self.released = threading.Event()

    def cancel(self):
        super().cancel()
        self.released.set()

    def execute(self, plan, stage):
        self.started.set()
        self.released.wait(timeout=5)
        if self.cancelled:
            raise WimCancelled("cancelled")
        return super().execute(plan, stage)


class IsoStagingTests(unittest.TestCase):
    def make_plan(self, root: Path, entries=None, **kwargs):
        selected = entries or basic_entries()
        image = root / "source.iso"
        image.write_bytes(b"ISO placeholder")
        return build_iso_staging_plan(
            image,
            root / "ready-media",
            selected,
            kwargs.pop("write_plan", write_plan(selected)),
            seven_zip=SEVEN_ZIP,
            **kwargs,
        )

    def test_plan_is_frozen_and_binds_source_catalog_parent_and_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = self.make_plan(Path(directory))
            validate_iso_staging_plan(plan)
            self.assertEqual(plan.image_identity[2], len(b"ISO placeholder"))
            self.assertEqual(len(plan.catalog_digest), 64)
            self.assertEqual(plan.content_bytes, 13)
            self.assertFalse(plan.needs_wim_split)
            self.assertIsNone(plan.autounattend_xml)
            with self.assertRaises(FrozenInstanceError):
                plan.catalog_digest = "0" * 64  # type: ignore[misc]
            forged_entries = tuple(
                replace(entry, modified_ns=1_709_210_096_000_000_000)
                if entry.path == "README.txt" else entry
                for entry in plan.entries
            )
            with self.assertRaisesRegex(IsoStagingSafetyError, "catalog binding"):
                validate_iso_staging_plan(replace(plan, entries=forged_entries))

    def test_plan_rejects_nonintegral_boolean_negative_and_malformed_bindings(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = self.make_plan(Path(directory))
            forged = (
                replace(plan, content_bytes=True),
                replace(plan, content_bytes=13.0),
                replace(plan, content_bytes=-1),
                replace(plan, required_free_bytes=False),
                replace(plan, required_free_bytes=float(plan.required_free_bytes)),
                replace(plan, required_free_bytes=-1),
                replace(plan, image_identity=(True, 1, 1, 1)),
                replace(plan, image_identity=(1, 1, 0, 1)),
                replace(plan, image_identity=(1, 1, 1.0, 1)),
                replace(plan, destination_parent_identity=(1, 0)),
                replace(plan, destination_parent_identity=(1, 2.0)),
                replace(plan, destination_parent_identity=(1,)),
            )
            for candidate in forged:
                with self.subTest(candidate=candidate), self.assertRaises(
                    IsoStagingSafetyError,
                ):
                    validate_iso_staging_plan(candidate)

    def test_precancelled_overlay_validation_never_rehashes_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            overlay = make_overlay(
                root, (("efi/tools/diagnostic.txt", b"hello"),),
            )
            plan = self.make_plan(
                root,
                overlay=overlay,
                write_plan=overlay_write_plan(basic_entries(), overlay),
            )

            def cancelled() -> None:
                raise IsoStagingCancelled("cancelled before validation")

            with (
                patch("isopropyl.iso_staging.validate_zip_overlay_plan") as validator,
                self.assertRaises(IsoStagingCancelled),
            ):
                validate_iso_staging_plan(plan, cancel_check=cancelled)
            validator.assert_not_called()

    def test_success_atomically_publishes_constructed_media_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.make_plan(root)
            updates = []
            result = IsoStagingExecutor(
                extractor=FakeExtractor(),
            ).execute(plan, updates.append)
            self.assertEqual(result.destination, root / "ready-media")
            self.assertEqual((result.files, result.bytes_staged), (2, 13))
            self.assertEqual(result.wim_parts, ())
            self.assertFalse(result.autounattend_added)
            self.assertTrue((result.destination / "EFI/BOOT/BOOTX64.EFI").is_file())
            self.assertEqual(updates[-1].stage, "Complete")
            self.assertEqual(updates[-1].fraction, 1.0)
            self.assertEqual(list(root.glob(".ready-media.*.partial")), [])

    def test_overlay_uses_canonical_targets_for_explicit_and_implicit_base_dirs(self):
        entries = (
            ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 8),
            ArchiveEntry("README.txt", 5),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            overlay = make_overlay(root)
            plan = self.make_plan(
                root,
                entries,
                overlay=overlay,
                write_plan=overlay_write_plan(entries, overlay),
            )
            self.assertEqual(plan.content_bytes, 18)
            self.assertEqual(
                tuple(member.path for member in plan.effective_entries),
                (
                    "EFI/BOOT/BOOTX64.EFI",
                    "README.txt",
                    "EFI/tools",
                    "EFI/tools/diagnostic.txt",
                ),
            )
            received_targets = []

            def canonical_apply(overlay_plan, tree, targets, **kwargs):
                received_targets.extend(entry.path for entry in targets)
                return apply_zip_overlay(overlay_plan, tree, targets, **kwargs)

            updates = []
            result = IsoStagingExecutor(
                extractor=FakeExtractor(), overlay_applier=canonical_apply,
            ).execute(plan, updates.append)

            self.assertEqual(
                received_targets,
                ["EFI", "EFI/tools", "EFI/tools/diagnostic.txt"],
            )
            self.assertEqual(
                (result.destination / "EFI/tools/diagnostic.txt").read_bytes(),
                b"hello",
            )
            self.assertEqual((result.files, result.bytes_staged), (3, 18))
            self.assertEqual(result.catalog_digest, plan.effective_catalog_digest)
            overlay_updates = [
                update for update in updates
                if update.stage == "Adding ZIP overlay" and update.relative_path
            ]
            self.assertTrue(overlay_updates)
            self.assertTrue(all(update.total_bytes == 18 for update in overlay_updates))

    def test_overlay_plan_binds_effective_catalog_write_plan_and_space(self):
        entries = basic_entries()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            overlay = make_overlay(
                root, (("efi/tools/diagnostic.txt", b"hello"),),
            )
            with self.assertRaisesRegex(IsoStagingSafetyError, "bound"):
                self.make_plan(root, entries, overlay=overlay)

            plan = self.make_plan(
                root,
                entries,
                overlay=overlay,
                write_plan=overlay_write_plan(entries, overlay),
            )
            self.assertEqual(plan.content_bytes, 13 + overlay.content_bytes)
            self.assertEqual(
                plan.required_free_bytes,
                plan.content_bytes + iso_staging.OUTPUT_SPACE_RESERVE,
            )
            validate_iso_staging_plan(plan)

            extractors = []
            for forged in (
                replace(plan, effective_catalog_digest="0" * 64),
                replace(plan, effective_entries=plan.entries),
                replace(plan, content_bytes=plan.content_bytes + 1),
                replace(plan, required_free_bytes=plan.required_free_bytes + 1),
            ):
                extractor = FakeExtractor()
                extractors.append(extractor)
                with self.subTest(forged=forged), self.assertRaises(
                    IsoStagingSafetyError,
                ):
                    IsoStagingExecutor(extractor=extractor).execute(forged)
            self.assertTrue(all(extractor.calls == [] for extractor in extractors))

    def test_base_catalog_is_verified_before_overlay_and_failures_never_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            overlay = make_overlay(
                root, (("efi/tools/diagnostic.txt", b"hello"),),
            )
            plan = self.make_plan(
                root,
                overlay=overlay,
                write_plan=overlay_write_plan(basic_entries(), overlay),
            )
            calls = []

            def must_not_apply(*args, **kwargs):
                calls.append((args, kwargs))
                raise AssertionError("overlay ran before exact base validation")

            def corrupt_base(tree: Path, _image: Path) -> None:
                (tree / "README.txt").write_bytes(b"wrong-size")

            with self.assertRaisesRegex(IsoStagingSafetyError, "ISO catalog"):
                IsoStagingExecutor(
                    extractor=FakeExtractor(mutate=corrupt_base),
                    overlay_applier=must_not_apply,
                ).execute(plan)
            self.assertEqual(calls, [])
            self.assertFalse(plan.destination.exists())
            self.assertEqual(list(root.glob(".ready-media.*.partial")), [])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            overlay = make_overlay(
                root, (("efi/tools/diagnostic.txt", b"hello"),),
            )
            plan = self.make_plan(
                root,
                overlay=overlay,
                write_plan=overlay_write_plan(basic_entries(), overlay),
            )

            def forged_result(overlay_plan, tree, targets, **kwargs):
                result = apply_zip_overlay(
                    overlay_plan, tree, targets, **kwargs,
                )
                return replace(result, bytes_written=result.bytes_written + 1)

            with self.assertRaisesRegex(IsoStagingSafetyError, "result"):
                IsoStagingExecutor(
                    extractor=FakeExtractor(), overlay_applier=forged_result,
                ).execute(plan)
            self.assertFalse(plan.destination.exists())
            self.assertEqual(list(root.glob(".ready-media.*.partial")), [])

    def test_overlay_cancellation_cleans_private_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            overlay = make_overlay(
                root, (("efi/tools/diagnostic.txt", b"hello"),),
            )
            plan = self.make_plan(
                root,
                overlay=overlay,
                write_plan=overlay_write_plan(basic_entries(), overlay),
            )
            executor = IsoStagingExecutor(extractor=FakeExtractor())

            def cancel_during_overlay(update) -> None:
                if update.stage == "Adding ZIP overlay" and update.relative_path:
                    executor.cancel()

            with self.assertRaises(IsoStagingCancelled):
                executor.execute(plan, cancel_during_overlay)
            self.assertFalse(plan.destination.exists())
            self.assertEqual(list(root.glob(".ready-media.*.partial")), [])

    def test_changed_or_colliding_overlay_fails_before_base_extraction(self):
        entries = basic_entries()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collision = make_overlay(
                root, (("readme.TXT", b"replacement"),),
            )
            with self.assertRaisesRegex(IsoStagingSafetyError, "collides"):
                self.make_plan(
                    root,
                    overlay=collision,
                    write_plan=write_plan(entries),
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            overlay = make_overlay(
                root, (("efi/tools/diagnostic.txt", b"hello"),),
            )
            plan = self.make_plan(
                root,
                overlay=overlay,
                write_plan=overlay_write_plan(entries, overlay),
            )
            overlay.archive.write_bytes(b"changed")
            extractor = FakeExtractor()
            with self.assertRaises(IsoStagingSafetyError):
                IsoStagingExecutor(extractor=extractor).execute(plan)
            self.assertEqual(extractor.calls, [])
            self.assertFalse(plan.destination.exists())

    def test_refuses_wrong_or_unexecutable_write_plans_and_catalog_mismatch(self):
        entries = basic_entries()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for candidate in (
                write_plan(entries, blockers=("not ready",)),
                write_plan(entries, mode=WriteMode.DD),
                write_plan(entries, firmware=FirmwareTarget.AUTOMATIC),
                replace(write_plan(entries), minimum_content_bytes=999),
            ):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(IsoStagingSafetyError):
                        self.make_plan(root, write_plan=candidate)
            linked = entries + (
                ArchiveEntry("link", kind=EntryKind.SYMLINK, link_target="README.txt"),
            )
            with self.assertRaises(IsoStagingSafetyError):
                self.make_plan(root, linked, write_plan=write_plan(linked))

    def test_ntfs_plan_stages_large_files_without_wim_splitting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = basic_entries() + (
                ArchiveEntry("large.bin", FAT32_MAX_FILE_SIZE + 1),
            )
            plan = self.make_plan(
                root, entries,
                write_plan=write_plan(entries, filesystem=FileSystem.NTFS),
            )
            self.assertFalse(plan.needs_wim_split)
            self.assertIsNone(plan.wimlib_imagex)
            validate_iso_staging_plan(plan)

    def test_fat32_plan_cannot_split_a_nested_install_wim(self):
        entries = basic_entries() + (
            ArchiveEntry("x64/sources/install.wim", FAT32_MAX_FILE_SIZE + 1),
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                IsoStagingSafetyError, "cannot be safely transformed",
            ):
                self.make_plan(
                    Path(directory), entries,
                    write_plan=write_plan(entries),
                )

    def test_fat32_plan_cannot_split_wim_when_an_esd_source_coexists(self):
        entries = windows_entries() + (
            ArchiveEntry("sources/install.esd", 7),
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                IsoStagingSafetyError, "cannot be safely transformed",
            ):
                self.make_plan(
                    Path(directory), entries,
                    write_plan=write_plan(entries),
                )

    def test_requires_absolute_absent_destination_and_unchanged_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "source.iso"
            image.write_bytes(b"iso")
            entries = basic_entries()
            with self.assertRaises(IsoStagingSafetyError):
                build_iso_staging_plan(
                    image, Path("relative"), entries, write_plan(entries),
                    seven_zip=SEVEN_ZIP,
                )
            (root / "ready-media").mkdir()
            with self.assertRaises(IsoStagingSafetyError):
                build_iso_staging_plan(
                    image, root / "ready-media", entries, write_plan(entries),
                    seven_zip=SEVEN_ZIP,
                )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.make_plan(root)
            plan.image.write_bytes(b"changed source")
            with self.assertRaises(IsoStagingSafetyError):
                IsoStagingExecutor(extractor=FakeExtractor()).execute(plan)

    def test_splits_install_wim_privately_and_publishes_only_verified_swm_parts(self):
        with tempfile.TemporaryDirectory(dir=LARGE_TEMP_PARENT) as directory:
            root = Path(directory)
            source_directory_time = 1_709_210_096_123_456_789
            entries = tuple(
                replace(entry, modified_ns=source_directory_time)
                if entry.path == "sources" else entry
                for entry in windows_entries()
            )
            plan = self.make_plan(
                root, entries,
                wimlib_resolver=lambda: WIMLIB,
            )
            splitter = FakeSplitter()
            result = IsoStagingExecutor(
                extractor=FakeExtractor(),
                wim_splitter=splitter,
                split_plan_builder=fake_split_plan,
            ).execute(plan)
            self.assertTrue(plan.needs_wim_split)
            self.assertEqual(
                result.wim_parts,
                ("sources/install.swm", "sources/install2.swm"),
            )
            self.assertFalse((result.destination / "sources/install.wim").exists())
            self.assertTrue((result.destination / "sources/install.swm").is_file())
            self.assertTrue((result.destination / "sources/install2.swm").is_file())
            self.assertEqual(
                (result.destination / "sources").stat().st_mtime_ns,
                source_directory_time,
            )
            self.assertEqual(len(splitter.calls), 1)
            self.assertEqual(list(root.glob(".ready-media.*.partial")), [])

    def test_wim_transform_restores_first_observed_normalized_directory_time(self):
        with tempfile.TemporaryDirectory(dir=LARGE_TEMP_PARENT) as directory:
            root = Path(directory)
            requested = 1_709_210_096_987_654_321
            normalized = requested - 1_500_000_000
            entries = tuple(
                replace(entry, modified_ns=requested)
                if entry.path == "sources" else entry
                for entry in windows_entries()
            )
            plan = self.make_plan(
                root, entries, wimlib_resolver=lambda: WIMLIB,
            )

            def normalize_directory(tree: Path, _image: Path) -> None:
                sources = tree / "sources"
                os.utime(sources, ns=(normalized, normalized))

            result = IsoStagingExecutor(
                extractor=FakeExtractor(mutate=normalize_directory),
                wim_splitter=FakeSplitter(),
                split_plan_builder=fake_split_plan,
            ).execute(plan)

            self.assertEqual(
                (result.destination / "sources").stat().st_mtime_ns,
                normalized,
            )

    def test_post_transform_directory_timestamp_failure_cleans_private_work(self):
        with tempfile.TemporaryDirectory(dir=LARGE_TEMP_PARENT) as directory:
            root = Path(directory)
            entries = tuple(
                replace(entry, modified_ns=1_709_210_096_000_000_000)
                if entry.path == "sources" else entry
                for entry in windows_entries()
            )
            plan = self.make_plan(
                root, entries, wimlib_resolver=lambda: WIMLIB,
            )
            with (
                patch(
                    "isopropyl.iso_staging.apply_descriptor_mtime",
                    side_effect=TimestampPreservationError("timestamp fixture"),
                ),
                self.assertRaisesRegex(IsoStagingSafetyError, "directory time"),
            ):
                IsoStagingExecutor(
                    extractor=FakeExtractor(),
                    wim_splitter=FakeSplitter(),
                    split_plan_builder=fake_split_plan,
                ).execute(plan)
            self.assertFalse(plan.destination.exists())
            self.assertEqual(list(root.glob(".ready-media.*.partial")), [])

    def test_rejects_existing_split_part_collision_before_extraction(self):
        entries = windows_entries() + (ArchiveEntry("sources/INSTALL.SWM", 4),)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(IsoStagingSafetyError, "collide"):
                self.make_plan(
                    Path(directory), entries,
                    write_plan=write_plan(entries),
                    wimlib_resolver=lambda: WIMLIB,
                )

    def test_split_failure_or_malformed_parts_never_publish(self):
        for splitter in (
            FakeSplitter(error=WimError("split failed")),
            FakeSplitter(names=("install.swm", "install3.swm")),
        ):
            with self.subTest(splitter=splitter), tempfile.TemporaryDirectory(
                dir=LARGE_TEMP_PARENT,
            ) as directory:
                root = Path(directory)
                entries = windows_entries()
                plan = self.make_plan(
                    root, entries, wimlib_resolver=lambda: WIMLIB,
                )
                with self.assertRaises(IsoStagingError):
                    IsoStagingExecutor(
                        extractor=FakeExtractor(),
                        wim_splitter=splitter,
                        split_plan_builder=fake_split_plan,
                    ).execute(plan)
                self.assertFalse(plan.destination.exists())
                self.assertEqual(list(root.glob(".ready-media.*.partial")), [])

    def test_adds_generated_autounattend_without_replacing_iso_content(self):
        customization = WindowsCustomization(
            bypass_hardware_requirements=True,
            hide_online_account=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.make_plan(root, windows_customization=customization)
            self.assertEqual(plan.windows_customization, customization)
            self.assertEqual(plan.windows_architecture, "amd64")
            result = IsoStagingExecutor(extractor=FakeExtractor()).execute(plan)
            answer = result.destination / "autounattend.xml"
            self.assertTrue(result.autounattend_added)
            self.assertTrue(answer.read_text().startswith("<?xml"))
        collision = basic_entries() + (ArchiveEntry("AutoUnattend.XML", 4),)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(IsoStagingSafetyError, "already contains"):
                self.make_plan(
                    Path(directory), collision,
                    write_plan=write_plan(collision),
                    windows_customization=customization,
                )

    def test_answer_file_must_exactly_match_bound_customization(self):
        customization = WindowsCustomization(
            hide_online_account=True,
            reduce_data_collection=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            plan = self.make_plan(
                Path(directory), windows_customization=customization,
            )
            xml = plan.autounattend_xml or ""
            alterations = (
                xml.replace(
                    "</unattend>",
                    "  <!-- structurally harmless but unbound -->\n</unattend>",
                ),
                xml.replace(
                    "</unattend>",
                    "  <settings pass=\"specialize\" />\n</unattend>",
                ),
                xml + "\n",
            )
            for forged_xml in alterations:
                with self.subTest(forged_xml=forged_xml):
                    extractor = FakeExtractor()
                    with self.assertRaisesRegex(
                        IsoStagingSafetyError, "bound customization",
                    ):
                        IsoStagingExecutor(extractor=extractor).execute(
                            replace(plan, autounattend_xml=forged_xml),
                        )
                    self.assertEqual(extractor.calls, [])

    def test_answer_file_requires_consistent_bound_generation_inputs(self):
        customization = WindowsCustomization(hide_online_account=True)
        with tempfile.TemporaryDirectory() as directory:
            plan = self.make_plan(
                Path(directory), windows_customization=customization,
            )
            invalid = (
                replace(plan, windows_customization=None),
                replace(plan, windows_architecture=None),
                replace(plan, windows_customization=WindowsCustomization()),
                replace(plan, autounattend_xml=None),
                replace(
                    plan,
                    windows_customization=replace(
                        customization, reduce_data_collection=True,
                    ),
                ),
                replace(plan, autounattend_xml=b"not text"),
                replace(plan, autounattend_xml="\ud800"),
            )
            for forged in invalid:
                with self.subTest(forged=forged), self.assertRaises(
                    IsoStagingSafetyError,
                ):
                    validate_iso_staging_plan(forged)

    def test_answer_file_binds_selection_and_generation_architecture(self):
        selection = selected_esd()
        customization = WindowsCustomization(install_image=selection)
        with tempfile.TemporaryDirectory() as directory:
            plan = self.make_plan(
                Path(directory), selected_esd_entries(),
                windows_customization=customization,
                windows_architecture="amd64",
                wimlib_resolver=lambda: WIMLIB,
            )
            changed_selection = selected_esd(build=22631)
            with self.assertRaisesRegex(
                IsoStagingSafetyError, "selection is inconsistent",
            ):
                validate_iso_staging_plan(replace(
                    plan,
                    windows_customization=replace(
                        customization, install_image=changed_selection,
                    ),
                ))
            with self.assertRaisesRegex(IsoStagingSafetyError, "architecture"):
                validate_iso_staging_plan(replace(
                    plan, windows_architecture="arm64",
                ))

    def test_refuses_known_oem_answer_file_case_insensitively(self):
        customization = WindowsCustomization(hide_online_account=True)
        collision = basic_entries() + (
            ArchiveEntry("SoUrCeS/$OeM$/$$/PaNtHeR/UnAtTeNd.XmL", 4),
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                IsoStagingSafetyError, r"\$OeM\$.*UnAtTeNd\.XmL",
            ):
                self.make_plan(
                    Path(directory), collision,
                    write_plan=write_plan(collision),
                    windows_customization=customization,
                )

    def test_forged_plan_cannot_combine_generated_and_oem_answer_files(self):
        customization = WindowsCustomization(hide_online_account=True)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.make_plan(root, windows_customization=customization)
            forged_entries = plan.entries + (
                ArchiveEntry("sources/$OEM$/$$/Panther/unattend.xml", 4),
            )
            forged = replace(
                plan,
                entries=forged_entries,
                catalog_digest=iso_staging._catalog_digest(forged_entries),
                effective_entries=forged_entries,
                effective_catalog_digest=iso_staging._catalog_digest(
                    forged_entries,
                ),
                write_plan=write_plan(forged_entries),
            )
            with self.assertRaisesRegex(IsoStagingSafetyError, "conflicts"):
                validate_iso_staging_plan(forged)

    def test_selected_esd_index_is_bound_reinspected_and_published(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = selected_esd_entries()
            selection = selected_esd()
            plan = self.make_plan(
                root, entries,
                windows_customization=WindowsCustomization(install_image=selection),
                windows_architecture="amd64",
                wimlib_resolver=lambda: WIMLIB,
            )
            validate_iso_staging_plan(plan)
            self.assertFalse(plan.needs_wim_split)
            self.assertEqual(plan.wim_selection, selection)
            self.assertEqual(plan.wimlib_imagex, WIMLIB)
            self.assertEqual(answer_file_install_index(plan.autounattend_xml or ""), 3)
            inspected = []

            def inspector(source: Path, tool: str, _cancel_event) -> WimInfo:
                inspected.append((source, tool))
                return inspected_wim(source, selection.editions)

            result = IsoStagingExecutor(
                extractor=FakeExtractor(), wim_inspector=inspector,
            ).execute(plan)
            self.assertTrue(result.autounattend_added)
            self.assertEqual(len(inspected), 1)
            self.assertEqual(inspected[0][0].name, "install.esd")
            self.assertEqual(inspected[0][1], WIMLIB)
            self.assertTrue((result.destination / "sources/install.esd").is_file())

    def test_selected_nested_wim_path_is_bound_and_unselected_wim_is_preserved(self):
        entries = basic_entries() + (
            ArchiveEntry("x64/sources/install.wim", 7),
            ArchiveEntry("x86/sources/install.wim", 9),
        )
        selection = replace(
            selected_esd(), source_name="x64/sources/install.wim", source_size=7,
        )
        customization = WindowsCustomization(
            install_image=selection,
            install_image_path=selection.source_name,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.make_plan(
                root, entries,
                write_plan=write_plan(entries),
                windows_customization=customization,
                windows_architecture="amd64",
                wimlib_resolver=lambda: WIMLIB,
            )
            self.assertEqual(
                answer_file_install_path(plan.autounattend_xml or "", "amd64"),
                selection.source_name,
            )

            def inspector(source: Path, _tool: str, _cancel_event) -> WimInfo:
                self.assertEqual(
                    source.relative_to(source.parents[2]).as_posix(),
                    selection.source_name,
                )
                return inspected_wim(source, selection.editions)

            result = IsoStagingExecutor(
                extractor=FakeExtractor(), wim_inspector=inspector,
            ).execute(plan)
            self.assertTrue(result.autounattend_added)
            self.assertEqual(
                (result.destination / "x64/sources/install.wim").stat().st_size,
                7,
            )
            self.assertEqual(
                (result.destination / "x86/sources/install.wim").stat().st_size,
                9,
            )

    def test_multi_source_wim_selection_requires_an_explicit_answer_path(self):
        entries = basic_entries() + (
            ArchiveEntry("x64/sources/install.wim", 7),
            ArchiveEntry("x86/sources/install.wim", 9),
        )
        selection = replace(
            selected_esd(), source_name="x64/sources/install.wim", source_size=7,
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(IsoStagingSafetyError, "explicit answer-file"):
                self.make_plan(
                    Path(directory), entries,
                    write_plan=write_plan(entries),
                    windows_customization=WindowsCustomization(
                        install_image=selection,
                    ),
                    windows_architecture="amd64",
                    wimlib_resolver=lambda: WIMLIB,
                )

    def test_nested_wim_selection_requires_an_explicit_answer_path(self):
        entries = basic_entries() + (
            ArchiveEntry("x64/sources/install.wim", 7),
        )
        selection = replace(
            selected_esd(), source_name="x64/sources/install.wim", source_size=7,
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(IsoStagingSafetyError, "explicit answer-file"):
                self.make_plan(
                    Path(directory), entries,
                    write_plan=write_plan(entries),
                    windows_customization=WindowsCustomization(
                        install_image=selection,
                    ),
                    windows_architecture="amd64",
                    wimlib_resolver=lambda: WIMLIB,
                )

    def test_canonical_single_wim_selection_can_use_index_only(self):
        entries = basic_entries() + (
            ArchiveEntry("sources/install.wim", 7),
        )
        selection = replace(
            selected_esd(), source_name="sources/install.wim", source_size=7,
        )
        with tempfile.TemporaryDirectory() as directory:
            plan = self.make_plan(
                Path(directory), entries,
                write_plan=write_plan(entries),
                windows_customization=WindowsCustomization(
                    install_image=selection,
                ),
                windows_architecture="amd64",
                wimlib_resolver=lambda: WIMLIB,
            )
        self.assertIsNone(
            answer_file_install_path(plan.autounattend_xml or "", "amd64"),
        )

    def test_selection_refuses_more_than_four_wim_sources(self):
        entries = basic_entries() + tuple(
            ArchiveEntry(f"edition-{index}/sources/install.wim", 7)
            for index in range(5)
        )
        selection = replace(
            selected_esd(), source_name=entries[-1].path, source_size=7,
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(IsoStagingSafetyError, "at most four"):
                self.make_plan(
                    Path(directory), entries,
                    write_plan=write_plan(entries),
                    windows_customization=WindowsCustomization(
                        install_image=selection,
                        install_image_path=selection.source_name,
                    ),
                    windows_architecture="amd64",
                    wimlib_resolver=lambda: WIMLIB,
                )

    def test_forged_answer_file_cannot_redirect_to_another_wim_source(self):
        entries = basic_entries() + (
            ArchiveEntry("x64/sources/install.wim", 7),
            ArchiveEntry("x86/sources/install.wim", 9),
        )
        selection = replace(
            selected_esd(), source_name="x64/sources/install.wim", source_size=7,
        )
        with tempfile.TemporaryDirectory() as directory:
            plan = self.make_plan(
                Path(directory), entries,
                write_plan=write_plan(entries),
                windows_customization=WindowsCustomization(
                    install_image=selection,
                    install_image_path=selection.source_name,
                ),
                windows_architecture="amd64",
                wimlib_resolver=lambda: WIMLIB,
            )
            forged_xml = (plan.autounattend_xml or "").replace(
                "x64\\sources\\install.wim", "x86\\sources\\install.wim",
            )
            self.assertNotEqual(forged_xml, plan.autounattend_xml)
            with self.assertRaisesRegex(IsoStagingSafetyError, "does not match"):
                validate_iso_staging_plan(
                    replace(plan, autounattend_xml=forged_xml),
                )

    def test_changed_or_ambiguous_selected_wim_metadata_never_publishes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = selected_esd_entries()
            selection = selected_esd()
            plan = self.make_plan(
                root, entries,
                windows_customization=WindowsCustomization(install_image=selection),
                windows_architecture="amd64",
                wimlib_resolver=lambda: WIMLIB,
            )

            def changed(source: Path, _tool: str, _cancel_event) -> WimInfo:
                return inspected_wim(source, selected_esd(build=22631).editions)

            with self.assertRaisesRegex(IsoStagingSafetyError, "metadata changed"):
                IsoStagingExecutor(
                    extractor=FakeExtractor(), wim_inspector=changed,
                ).execute(plan)
            self.assertFalse(plan.destination.exists())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = selected_esd_entries()
            selection = selected_esd()
            plan = self.make_plan(
                root, entries,
                windows_customization=WindowsCustomization(install_image=selection),
                windows_architecture="amd64",
                wimlib_resolver=lambda: WIMLIB,
            )
            inspected_source: list[Path] = []

            def inspector(source: Path, _tool: str, _cancel_event) -> WimInfo:
                inspected_source.append(source)
                return inspected_wim(source, selection.editions)

            def mutate_after_inspection(update) -> None:
                if update.stage == "Adding Windows customization":
                    inspected_source[0].write_bytes(b"changed")

            with self.assertRaisesRegex(IsoStagingSafetyError, "changed before"):
                IsoStagingExecutor(
                    extractor=FakeExtractor(), wim_inspector=inspector,
                ).execute(plan, mutate_after_inspection)
            self.assertFalse(plan.destination.exists())

        entries = selected_esd_entries() + (ArchiveEntry("sources/install.wim", 4),)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(IsoStagingSafetyError, "sole install source"):
                self.make_plan(
                    Path(directory), entries,
                    write_plan=write_plan(entries),
                    windows_customization=WindowsCustomization(
                        install_image=selected_esd(),
                    ),
                    windows_architecture="amd64",
                    wimlib_resolver=lambda: WIMLIB,
                )

    def test_forged_selected_index_or_catalog_size_fails_plan_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = selected_esd_entries()
            selection = selected_esd()
            plan = self.make_plan(
                root, entries,
                windows_customization=WindowsCustomization(install_image=selection),
                windows_architecture="amd64",
                wimlib_resolver=lambda: WIMLIB,
            )
            forged_xml = (plan.autounattend_xml or "").replace(
                "<Value>3</Value>", "<Value>2</Value>",
            )
            with self.assertRaisesRegex(IsoStagingSafetyError, "does not match"):
                validate_iso_staging_plan(
                    replace(plan, autounattend_xml=forged_xml),
                )
            missing_action = (plan.autounattend_xml or "").replace(
                ' wcm:action="add"', "", 1,
            )
            with self.assertRaisesRegex(IsoStagingSafetyError, "wcm:action"):
                validate_iso_staging_plan(
                    replace(plan, autounattend_xml=missing_action),
                )
            forged_architecture = (plan.autounattend_xml or "").replace(
                'processorArchitecture="amd64"',
                'processorArchitecture="arm64"',
                1,
            )
            with self.assertRaisesRegex(IsoStagingSafetyError, "architecture"):
                validate_iso_staging_plan(
                    replace(plan, autounattend_xml=forged_architecture),
                )
            with self.assertRaisesRegex(IsoStagingSafetyError, "not bound"):
                self.make_plan(
                    root, entries,
                    windows_customization=WindowsCustomization(
                        install_image=replace(selection, source_size=8),
                    ),
                    windows_architecture="amd64",
                    wimlib_resolver=lambda: WIMLIB,
                )

    def test_cancel_before_start_and_during_extraction_cleans_private_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.make_plan(root)
            executor = IsoStagingExecutor(extractor=FakeExtractor())
            executor.cancel()
            with self.assertRaises(IsoStagingCancelled):
                executor.execute(plan)
            self.assertFalse(plan.destination.exists())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.make_plan(root)
            extractor = BlockingExtractor()
            executor = IsoStagingExecutor(extractor=extractor)
            errors = []
            thread = threading.Thread(
                target=lambda: self._capture_error(errors, executor.execute, plan),
            )
            thread.start()
            self.assertTrue(extractor.started.wait(timeout=2))
            executor.cancel()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], IsoStagingCancelled)
            self.assertTrue(extractor.cancelled)
            self.assertFalse(plan.destination.exists())
            self.assertEqual(list(root.glob(".ready-media.*.partial")), [])

    def test_cancel_during_wim_split_propagates_and_cleans(self):
        with tempfile.TemporaryDirectory(dir=LARGE_TEMP_PARENT) as directory:
            root = Path(directory)
            entries = windows_entries()
            plan = self.make_plan(root, entries, wimlib_resolver=lambda: WIMLIB)
            splitter = BlockingSplitter()
            executor = IsoStagingExecutor(
                extractor=FakeExtractor(),
                wim_splitter=splitter,
                split_plan_builder=fake_split_plan,
            )
            errors = []
            thread = threading.Thread(
                target=lambda: self._capture_error(errors, executor.execute, plan),
            )
            thread.start()
            self.assertTrue(splitter.started.wait(timeout=2))
            executor.cancel()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], IsoStagingCancelled)
            self.assertTrue(splitter.cancelled)
            self.assertFalse(plan.destination.exists())
            self.assertEqual(list(root.glob(".ready-media.*.partial")), [])

    def test_cancel_during_wim_metadata_inspection_cleans_private_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = selected_esd_entries()
            plan = self.make_plan(
                root,
                entries,
                windows_customization=WindowsCustomization(
                    install_image=selected_esd(),
                ),
                windows_architecture="amd64",
                wimlib_resolver=lambda: WIMLIB,
            )
            started = threading.Event()

            def inspector(_source: Path, _tool: str, cancel_event) -> WimInfo:
                started.set()
                cancel_event.wait(timeout=3)
                raise WimCancelled("WIM operation was cancelled")

            executor = IsoStagingExecutor(
                extractor=FakeExtractor(), wim_inspector=inspector,
            )
            errors = []
            thread = threading.Thread(
                target=lambda: self._capture_error(errors, executor.execute, plan),
            )
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            executor.cancel()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], IsoStagingCancelled)
            self.assertFalse(plan.destination.exists())
            self.assertEqual(list(root.glob(".ready-media.*.partial")), [])

    def test_source_change_after_extraction_fails_closed_and_cleans(self):
        def change_source(_tree, image):
            image.write_bytes(b"changed after extraction")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.make_plan(root)
            with self.assertRaisesRegex(IsoStagingSafetyError, "source changed"):
                IsoStagingExecutor(
                    extractor=FakeExtractor(mutate=change_source),
                ).execute(plan)
            self.assertFalse(plan.destination.exists())
            self.assertEqual(list(root.glob(".ready-media.*.partial")), [])

    def test_destination_race_never_overwrites_and_private_work_is_cleaned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.make_plan(root)

            def race(update):
                if update.stage == "Validating staging tree":
                    plan.destination.mkdir()
                    (plan.destination / "owned.txt").write_text("racer")

            with self.assertRaisesRegex(IsoStagingSafetyError, "appeared"):
                IsoStagingExecutor(extractor=FakeExtractor()).execute(plan, race)
            self.assertEqual((plan.destination / "owned.txt").read_text(), "racer")
            self.assertEqual(list(root.glob(".ready-media.*.partial")), [])

    def test_unexpected_case_collision_link_hardlink_fifo_and_file_fail_closed(self):
        def collision(tree, _image):
            (tree / "readme.TXT").write_text("collision")

        def symlink(tree, _image):
            (tree / "link").symlink_to("README.txt")

        def hardlink(tree, _image):
            os.link(tree / "README.txt", tree / "hardlink.txt")

        def fifo(tree, _image):
            os.mkfifo(tree / "pipe")

        def unexpected(tree, _image):
            (tree / "extra.txt").write_text("extra")

        for mutation in (collision, symlink, hardlink, fifo, unexpected):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                plan = self.make_plan(root)
                with self.assertRaises(IsoStagingSafetyError):
                    IsoStagingExecutor(
                        extractor=FakeExtractor(mutate=mutation),
                    ).execute(plan)
                self.assertFalse(plan.destination.exists())
                self.assertEqual(list(root.glob(".ready-media.*.partial")), [])

    def test_forged_plan_and_executor_reuse_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.make_plan(root)
            with self.assertRaises(IsoStagingSafetyError):
                validate_iso_staging_plan(replace(plan, catalog_digest="0" * 64))
            extractor = FakeExtractor(mutate=lambda tree, _image: (
                tree / "unexpected"
            ).write_text("x"))
            executor = IsoStagingExecutor(extractor=extractor)
            with self.assertRaises(IsoStagingSafetyError):
                executor.execute(plan)
            with self.assertRaisesRegex(IsoStagingSafetyError, "only be used once"):
                executor.execute(plan)

    @staticmethod
    def _capture_error(errors, function, *args):
        try:
            function(*args)
        except BaseException as error:
            errors.append(error)


if __name__ == "__main__":
    unittest.main()
