from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import stat
import struct
import tempfile
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from isopropyl.iso import ArchiveEntry, EntryKind
from isopropyl.zip_overlay import (
    ZIP_ARCHIVE_MAX_BYTES,
    ZIP_CENTRAL_DIRECTORY_MAX_BYTES,
    ZIP_EXPANDED_MAX_BYTES,
    ZIP_MEMBER_MAX_COUNT,
    ZipOverlayChanged,
    ZipOverlayDeadlineExceeded,
    ZipOverlaySafetyError,
    apply_zip_overlay,
    build_zip_overlay_plan,
    validate_zip_overlay_plan,
)


class ZipOverlayTests(unittest.TestCase):
    def make_zip(
        self,
        root: Path,
        members: tuple[tuple[str, bytes], ...] = (("extras/readme.txt", b"hello"),),
        *,
        compression: int = zipfile.ZIP_DEFLATED,
    ) -> Path:
        path = root / "overlay.zip"
        with zipfile.ZipFile(path, "w", compression=compression) as archive:
            for name, payload in members:
                archive.writestr(name, payload)
        return path

    def test_constants_expose_the_security_limits(self):
        self.assertEqual(ZIP_ARCHIVE_MAX_BYTES, 8 * 1024**3)
        self.assertEqual(ZIP_EXPANDED_MAX_BYTES, 8 * 1024**3)
        self.assertEqual(ZIP_CENTRAL_DIRECTORY_MAX_BYTES, 16 * 1024**2)
        self.assertEqual(ZIP_MEMBER_MAX_COUNT, 4096)

    def test_build_validate_and_apply_with_canonical_target_spelling(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self.make_zip(root, (("efi/tools/readme.txt", b"payload"),))
            staging = root / "staging"
            (staging / "EFI").mkdir(parents=True)

            plan = build_zip_overlay_plan(archive)
            validate_zip_overlay_plan(plan)
            targets = (ArchiveEntry("EFI/tools/readme.txt", 7),)
            updates = []
            result = apply_zip_overlay(plan, staging, targets, progress=updates.append)

            self.assertEqual((staging / "EFI/tools/readme.txt").read_bytes(), b"payload")
            self.assertFalse((staging / "efi").exists())
            self.assertEqual(result.files, 1)
            self.assertEqual(result.bytes_written, 7)
            self.assertEqual(result.archive_sha256, plan.archive_sha256)
            self.assertEqual(updates[-1].bytes_done, 7)

    def test_explicit_compressed_directory_is_safely_merged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self.make_zip(
                root, (("extras/", b""), ("extras/file", b"x")),
            )
            staging = root / "staging"
            (staging / "extras").mkdir(parents=True)
            plan = build_zip_overlay_plan(archive)

            result = apply_zip_overlay(
                plan, staging, tuple(member.entry for member in plan.members),
            )

            self.assertEqual(result.directories, 1)
            self.assertEqual((staging / "extras/file").read_bytes(), b"x")

    def test_force_zip64_local_header_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "overlay.zip"
            with zipfile.ZipFile(archive_path, "w", allowZip64=True) as archive:
                with archive.open("large-format.bin", "w", force_zip64=True) as output:
                    output.write(b"zip64 fixture")

            plan = build_zip_overlay_plan(archive_path)

            self.assertEqual(plan.content_bytes, len(b"zip64 fixture"))

    def test_malformed_zip64_extra_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "overlay.zip"
            with zipfile.ZipFile(archive_path, "w", allowZip64=True) as archive:
                with archive.open("large-format.bin", "w", force_zip64=True) as output:
                    output.write(b"zip64 fixture")
            data = bytearray(archive_path.read_bytes())
            local = data.find(b"PK\x03\x04")
            name_size = int.from_bytes(data[local + 26:local + 28], "little")
            extra = local + 30 + name_size
            self.assertEqual(data[extra:extra + 2], b"\x01\x00")
            struct.pack_into("<H", data, extra + 2, 1)
            archive_path.write_bytes(data)

            with self.assertRaisesRegex(ZipOverlaySafetyError, "extra data|ZIP64"):
                build_zip_overlay_plan(archive_path)

    def test_force_zip64_data_descriptor_is_supported(self):
        class NonSeekableWriter:
            def __init__(self) -> None:
                self.data = bytearray()

            def write(self, value: bytes) -> int:
                self.data.extend(value)
                return len(value)

            def flush(self) -> None:
                pass

            def seekable(self) -> bool:
                return False

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = NonSeekableWriter()
            with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
                with archive.open("descriptor.bin", "w", force_zip64=True) as member:
                    member.write(b"zip64 data descriptor")
            archive_path = root / "overlay.zip"
            archive_path.write_bytes(output.data)

            plan = build_zip_overlay_plan(archive_path)

            self.assertEqual(plan.content_bytes, len(b"zip64 data descriptor"))

    def test_zip64_end_of_directory_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root)
            data = path.read_bytes()
            eocd_offset = data.rfind(b"PK\x05\x06")
            eocd = bytearray(data[eocd_offset:eocd_offset + 22])
            count = int.from_bytes(eocd[10:12], "little")
            directory_size = int.from_bytes(eocd[12:16], "little")
            directory_offset = int.from_bytes(eocd[16:20], "little")
            zip64 = struct.pack(
                "<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0,
                count, count, directory_size, directory_offset,
            )
            locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, eocd_offset, 1)
            struct.pack_into("<HHII", eocd, 8, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
            path.write_bytes(data[:eocd_offset] + zip64 + locator + eocd)

            plan = build_zip_overlay_plan(path)

            self.assertEqual(plan.content_bytes, 5)

    def test_inconsistent_zip64_locator_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root)
            data = path.read_bytes()
            eocd_offset = data.rfind(b"PK\x05\x06")
            eocd = bytearray(data[eocd_offset:eocd_offset + 22])
            count = int.from_bytes(eocd[10:12], "little")
            directory_size = int.from_bytes(eocd[12:16], "little")
            directory_offset = int.from_bytes(eocd[16:20], "little")
            zip64 = struct.pack(
                "<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0,
                count, count, directory_size, directory_offset,
            )
            locator = struct.pack(
                "<4sIQI", b"PK\x06\x07", 0, eocd_offset + 1, 1,
            )
            struct.pack_into(
                "<HHII", eocd, 8,
                0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            )
            path.write_bytes(data[:eocd_offset] + zip64 + locator + eocd)

            with self.assertRaisesRegex(ZipOverlaySafetyError, "ZIP64.*invalid"):
                build_zip_overlay_plan(path)

    def test_mismatched_data_descriptor_is_rejected(self):
        class NonSeekableWriter:
            def __init__(self) -> None:
                self.data = bytearray()

            def write(self, value: bytes) -> int:
                self.data.extend(value)
                return len(value)

            def flush(self) -> None:
                pass

            def seekable(self) -> bool:
                return False

        with tempfile.TemporaryDirectory() as directory:
            output = NonSeekableWriter()
            with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("descriptor.bin", b"descriptor payload")
            descriptor = output.data.find(b"PK\x07\x08")
            self.assertGreaterEqual(descriptor, 0)
            output.data[descriptor + 4] ^= 1
            path = Path(directory) / "overlay.zip"
            path.write_bytes(output.data)

            with self.assertRaisesRegex(ZipOverlaySafetyError, "descriptor disagrees"):
                build_zip_overlay_plan(path)

    def test_source_symlink_and_hardlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self.make_zip(root)
            symlink = root / "link.zip"
            symlink.symlink_to(archive)
            with self.assertRaisesRegex(ZipOverlaySafetyError, "opened safely"):
                build_zip_overlay_plan(symlink)

            hardlink = root / "hardlink.zip"
            os.link(archive, hardlink)
            with self.assertRaisesRegex(ZipOverlaySafetyError, "hard-link"):
                build_zip_overlay_plan(archive)

    def test_fifo_source_is_rejected_without_a_blocking_open(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "overlay.zip"
            os.mkfifo(fifo)

            with self.assertRaisesRegex(ZipOverlaySafetyError, "regular file"):
                build_zip_overlay_plan(fifo)

    def test_strict_portable_path_policy(self):
        unsafe = (
            "../escape", "/absolute", "C:/drive", "back\\slash", "a//b",
            "dot/./file", "question?", "trailing. ", "con.txt", "CON .txt",
            "control\x7f",
            f"{'a' * 256}/file",
        )
        for name in unsafe:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = self.make_zip(root, ((name, b"x"),))
                with self.assertRaises(ZipOverlaySafetyError):
                    build_zip_overlay_plan(path)

    def test_case_normalization_and_ancestor_collisions_are_rejected(self):
        fixtures = (
            (("EFI/file", b"x"), ("efi/FILE", b"y")),
            (("caf\N{LATIN SMALL LETTER E WITH ACUTE}", b"x"),
             ("cafe\N{COMBINING ACUTE ACCENT}", b"y")),
            (("Drivers/a", b"x"), ("drivers/b", b"y")),
            (("parent", b"x"), ("parent/child", b"y")),
        )
        for members in fixtures:
            with self.subTest(members=members), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = self.make_zip(root, members)
                with self.assertRaises(ZipOverlaySafetyError):
                    build_zip_overlay_plan(path)

    def test_unix_symlink_and_special_member_are_rejected(self):
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFCHR | 0o600):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / "overlay.zip"
                info = zipfile.ZipInfo("unsafe")
                info.create_system = 3
                info.external_attr = mode << 16
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(info, b"target")
                with self.assertRaisesRegex(ZipOverlaySafetyError, "special-file|symlink"):
                    build_zip_overlay_plan(path)

    def test_non_unix_creator_cannot_hide_special_mode_bits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "overlay.zip"
            info = zipfile.ZipInfo("unsafe")
            info.create_system = 0
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(info, b"target")
            with self.assertRaisesRegex(ZipOverlaySafetyError, "special-file|symlink"):
                build_zip_overlay_plan(path)

    def test_unsupported_compression_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root, compression=zipfile.ZIP_BZIP2)
            with self.assertRaisesRegex(ZipOverlaySafetyError, "stored and deflated"):
                build_zip_overlay_plan(path)

    def test_encrypted_flag_is_rejected_before_zipfile_opens_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root, compression=zipfile.ZIP_STORED)
            data = bytearray(path.read_bytes())
            local = data.find(b"PK\x03\x04")
            central = data.find(b"PK\x01\x02")
            struct.pack_into("<H", data, local + 6, 1)
            struct.pack_into("<H", data, central + 8, 1)
            path.write_bytes(data)

            with self.assertRaisesRegex(ZipOverlaySafetyError, "Encrypted"):
                build_zip_overlay_plan(path)

    def test_multidisk_and_sfx_archives_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root)
            data = bytearray(path.read_bytes())
            eocd = data.rfind(b"PK\x05\x06")
            struct.pack_into("<H", data, eocd + 4, 1)
            path.write_bytes(data)
            with self.assertRaisesRegex(ZipOverlaySafetyError, "Multi-disk"):
                build_zip_overlay_plan(path)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root)
            path.write_bytes(b"executable-prefix" + path.read_bytes())
            with self.assertRaisesRegex(ZipOverlaySafetyError, "Self-extracting"):
                build_zip_overlay_plan(path)

    def test_nul_and_inconsistent_local_filename_are_rejected(self):
        for replacement in (0, ord("X")):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = self.make_zip(root, (("member", b"x"),), compression=zipfile.ZIP_STORED)
                data = bytearray(path.read_bytes())
                local = data.find(b"PK\x03\x04")
                data[local + 30] = replacement
                path.write_bytes(data)
                with self.assertRaises(ZipOverlaySafetyError):
                    build_zip_overlay_plan(path)

    def test_overlapping_local_records_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(
                root, (("first", b"one"), ("second", b"two")),
                compression=zipfile.ZIP_STORED,
            )
            data = bytearray(path.read_bytes())
            first_central = data.find(b"PK\x01\x02")
            second_central = data.find(b"PK\x01\x02", first_central + 4)
            first_offset = int.from_bytes(data[first_central + 42:first_central + 46], "little")
            struct.pack_into("<I", data, second_central + 42, first_offset)
            path.write_bytes(data)

            with self.assertRaises(ZipOverlaySafetyError):
                build_zip_overlay_plan(path)

    def test_unexplained_bytes_between_members_and_directory_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root, compression=zipfile.ZIP_STORED)
            data = bytearray(path.read_bytes())
            directory_offset = data.find(b"PK\x01\x02")
            data[directory_offset:directory_offset] = b"unmodeled"
            eocd = data.rfind(b"PK\x05\x06")
            struct.pack_into("<I", data, eocd + 16, directory_offset + 9)
            path.write_bytes(data)

            with self.assertRaisesRegex(ZipOverlaySafetyError, "unexplained"):
                build_zip_overlay_plan(path)

    def test_metadata_limits_are_enforced_before_zipfile_catalog_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root, (("one", b"1"), ("two", b"2")))
            with (
                patch("isopropyl.zip_overlay.ZIP_MEMBER_MAX_COUNT", 1),
                self.assertRaisesRegex(ZipOverlaySafetyError, "too many"),
            ):
                build_zip_overlay_plan(path)
            with (
                patch("isopropyl.zip_overlay.ZIP_CENTRAL_DIRECTORY_MAX_BYTES", 1),
                self.assertRaisesRegex(ZipOverlaySafetyError, "central directory"),
            ):
                build_zip_overlay_plan(path)

    def test_archive_and_expanded_limits_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root, (("member", b"payload"),))
            with (
                patch("isopropyl.zip_overlay.ZIP_ARCHIVE_MAX_BYTES", 1),
                self.assertRaisesRegex(ZipOverlaySafetyError, "8 GiB archive"),
            ):
                build_zip_overlay_plan(path)
            with (
                patch("isopropyl.zip_overlay.ZIP_EXPANDED_MAX_BYTES", 1),
                self.assertRaisesRegex(ZipOverlaySafetyError, "expanded limit"),
            ):
                build_zip_overlay_plan(path)

    def test_validation_rejects_archive_mutation_and_forged_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root, compression=zipfile.ZIP_STORED)
            plan = build_zip_overlay_plan(path)
            forged_member = replace(plan.members[0], crc32=plan.members[0].crc32 ^ 1)
            forged = replace(plan, members=(forged_member,))
            with self.assertRaises(ZipOverlayChanged):
                validate_zip_overlay_plan(forged)

            with path.open("r+b") as output:
                output.seek(35)
                byte = output.read(1)
                output.seek(35)
                output.write(bytes((byte[0] ^ 1,)))
                output.flush()
                os.fsync(output.fileno())
            with self.assertRaises((ZipOverlayChanged, ZipOverlaySafetyError)):
                validate_zip_overlay_plan(plan)

    def test_validation_rejects_numerically_equal_forged_model_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root, compression=zipfile.ZIP_STORED)

            for field in ("size",):
                with self.subTest(field=field):
                    plan = build_zip_overlay_plan(path)
                    object.__setattr__(
                        plan.members[0].entry,
                        field,
                        float(getattr(plan.members[0].entry, field)),
                    )
                    with self.assertRaisesRegex(ZipOverlaySafetyError, "model"):
                        validate_zip_overlay_plan(plan)

            plan = build_zip_overlay_plan(path)
            object.__setattr__(plan.identity, "size", float(plan.identity.size))
            with self.assertRaisesRegex(ZipOverlaySafetyError, "model"):
                validate_zip_overlay_plan(plan)

            plan = build_zip_overlay_plan(path)
            object.__setattr__(plan.members[0], "crc32", float(plan.members[0].crc32))
            with self.assertRaisesRegex(ZipOverlaySafetyError, "model"):
                validate_zip_overlay_plan(plan)

    def test_apply_fails_closed_on_crc_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root, (("member", b"payload"),), compression=zipfile.ZIP_STORED)
            plan = build_zip_overlay_plan(path)
            data = bytearray(path.read_bytes())
            local = data.find(b"PK\x03\x04")
            name_size = int.from_bytes(data[local + 26:local + 28], "little")
            extra_size = int.from_bytes(data[local + 28:local + 30], "little")
            data[local + 30 + name_size + extra_size] = 6
            path.write_bytes(data)
            corrupted = build_zip_overlay_plan(path)
            staging = root / "staging"
            staging.mkdir()

            with self.assertRaisesRegex(ZipOverlaySafetyError, "integrity"):
                apply_zip_overlay(
                    corrupted, staging,
                    tuple(member.entry for member in corrupted.members),
                )

    def test_apply_verifies_compressed_directory_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root, (("directory/", b""),))
            plan = build_zip_overlay_plan(path)
            data = bytearray(path.read_bytes())
            local = data.find(b"PK\x03\x04")
            name_size = int.from_bytes(data[local + 26:local + 28], "little")
            extra_size = int.from_bytes(data[local + 28:local + 30], "little")
            data[local + 30 + name_size + extra_size] = 6
            path.write_bytes(data)
            corrupted = build_zip_overlay_plan(path)
            staging = root / "staging"
            staging.mkdir()

            with self.assertRaisesRegex(ZipOverlaySafetyError, "integrity"):
                apply_zip_overlay(
                    corrupted, staging,
                    tuple(member.entry for member in corrupted.members),
                )

    def test_apply_refuses_overwrite_symlink_parent_and_redirected_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root)
            plan = build_zip_overlay_plan(path)

            staging = root / "existing"
            (staging / "extras").mkdir(parents=True)
            (staging / "extras/readme.txt").write_bytes(b"base")
            with self.assertRaisesRegex(ZipOverlaySafetyError, "already exists"):
                apply_zip_overlay(
                    plan, staging, tuple(member.entry for member in plan.members),
                )
            self.assertEqual((staging / "extras/readme.txt").read_bytes(), b"base")

            outside = root / "outside"
            outside.mkdir()
            linked = root / "linked"
            linked.mkdir()
            (linked / "extras").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ZipOverlaySafetyError, "parent"):
                apply_zip_overlay(
                    plan, linked, tuple(member.entry for member in plan.members),
                )
            self.assertEqual(list(outside.iterdir()), [])

            empty = root / "empty"
            empty.mkdir()
            with self.assertRaisesRegex(ZipOverlaySafetyError, "does not match"):
                apply_zip_overlay(plan, empty, (ArchiveEntry("other/readme.txt", 5),))

    def test_apply_rejects_non_normalized_or_misaligned_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root)
            plan = build_zip_overlay_plan(path)
            staging = root / "staging"
            staging.mkdir()
            for targets in (
                (),
                (ArchiveEntry("extras/readme.txt", 4),),
                (ArchiveEntry("extras/readme.txt", kind=EntryKind.DIRECTORY),),
            ):
                with self.subTest(targets=targets), self.assertRaises(ZipOverlaySafetyError):
                    apply_zip_overlay(plan, staging, targets)

    def test_cancellation_exception_and_deadline_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root)

            def cancel() -> None:
                raise RuntimeError("fixture cancellation")

            with self.assertRaisesRegex(RuntimeError, "fixture cancellation"):
                build_zip_overlay_plan(path, cancel_check=cancel)
            with (
                patch("isopropyl.zip_overlay.time.monotonic", side_effect=(0.0, 1.0)),
                self.assertRaises(ZipOverlayDeadlineExceeded),
            ):
                build_zip_overlay_plan(path, timeout_seconds=0.5)

    def test_apply_cancellation_exception_and_deadline_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.make_zip(root)
            plan = build_zip_overlay_plan(path)
            staging = root / "staging"
            staging.mkdir()

            def cancel() -> None:
                raise RuntimeError("fixture apply cancellation")

            with self.assertRaisesRegex(RuntimeError, "apply cancellation"):
                apply_zip_overlay(
                    plan,
                    staging,
                    tuple(member.entry for member in plan.members),
                    cancel_check=cancel,
                )
            with (
                patch("isopropyl.zip_overlay.time.monotonic", side_effect=(0.0, 1.0)),
                self.assertRaises(ZipOverlayDeadlineExceeded),
            ):
                apply_zip_overlay(
                    plan,
                    staging,
                    tuple(member.entry for member in plan.members),
                    timeout_seconds=0.5,
                )


if __name__ == "__main__":
    unittest.main()
