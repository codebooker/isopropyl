from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from isopropyl.extraction import (
    ExtractionCancelled, ExtractionError, ExtractionSafetyError, SafeIsoExtractor,
    build_extraction_plan, extraction_command,
)
from isopropyl.iso import ArchiveEntry, EntryKind, UnsafeArchiveError


TOOL = "/usr/bin/7z"


def payload_streamer(payloads):
    def stream(_image, member, output, cancel):
        cancel()
        data = payloads[member]
        output.write(data)
        return len(data)
    return stream


class ExtractionTests(unittest.TestCase):
    def plan(self, root: Path, entries):
        image = root / "source.iso"
        image.write_bytes(b"ISO placeholder")
        return build_extraction_plan(
            image, root / "media", entries, seven_zip=TOOL,
        )

    def test_extracts_regular_tree_and_atomically_publishes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = (
                ArchiveEntry("EFI", kind=EntryKind.DIRECTORY),
                ArchiveEntry("EFI/BOOT", kind=EntryKind.DIRECTORY),
                ArchiveEntry("EFI/BOOT/BOOTX64.EFI", 4),
                ArchiveEntry("README.txt", 5),
            )
            plan = self.plan(root, entries)
            updates = []
            result = SafeIsoExtractor(streamer=payload_streamer({
                "EFI/BOOT/BOOTX64.EFI": b"BOOT", "README.txt": b"hello",
            })).execute(plan, updates.append)
            self.assertEqual((result.files, result.bytes_written), (2, 9))
            self.assertEqual((root / "media/EFI/BOOT/BOOTX64.EFI").read_bytes(), b"BOOT")
            self.assertEqual((root / "media/README.txt").read_text(), "hello")
            self.assertEqual(updates[-1].fraction, 1.0)
            self.assertEqual(list(root.glob(".media.*.partial")), [])

    def test_preserves_cataloged_file_and_directory_times(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent_time = 1_704_067_200_000_000_000
            child_time = 1_709_210_096_123_456_789
            file_time = 1_725_192_000_987_654_321
            entries = (
                ArchiveEntry(
                    "EFI", kind=EntryKind.DIRECTORY, modified_ns=parent_time,
                ),
                ArchiveEntry(
                    "EFI/BOOT", kind=EntryKind.DIRECTORY,
                    modified_ns=child_time,
                ),
                ArchiveEntry(
                    "EFI/BOOT/BOOTX64.EFI", 4, modified_ns=file_time,
                ),
            )
            plan = self.plan(root, entries)
            SafeIsoExtractor(streamer=payload_streamer({
                "EFI/BOOT/BOOTX64.EFI": b"BOOT",
            })).execute(plan)

            self.assertEqual((root / "media/EFI").stat().st_mtime_ns, parent_time)
            self.assertEqual((root / "media/EFI/BOOT").stat().st_mtime_ns, child_time)
            self.assertEqual(
                (root / "media/EFI/BOOT/BOOTX64.EFI").stat().st_mtime_ns,
                file_time,
            )

    def test_timestamp_failure_cleans_private_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.plan(root, (
                ArchiveEntry("file", 1, modified_ns=1_709_210_096_000_000_000),
            ))
            with (
                patch(
                    "isopropyl.timestamps.os.utime",
                    side_effect=OSError("timestamp fixture"),
                ),
                self.assertRaisesRegex(ExtractionError, "modification time"),
            ):
                SafeIsoExtractor(
                    streamer=payload_streamer({"file": b"x"}),
                ).execute(plan)
            self.assertFalse((root / "media").exists())
            self.assertEqual(list(root.glob(".media.*.partial")), [])

    def test_accepts_and_carries_bounded_workspace_timestamp_normalization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requested = 1_709_210_096_987_654_321
            normalized = requested - 1_500_000_000
            plan = self.plan(root, (
                ArchiveEntry("file", 1, modified_ns=requested),
            ))
            real_utime = os.utime

            def normalize(path_or_fd, *, ns):
                real_utime(path_or_fd, ns=(ns[0], normalized))

            with patch("isopropyl.timestamps.os.utime", side_effect=normalize):
                SafeIsoExtractor(
                    streamer=payload_streamer({"file": b"x"}),
                ).execute(plan)

            self.assertEqual((root / "media/file").stat().st_mtime_ns, normalized)

    def test_rejects_workspace_timestamp_normalization_beyond_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requested = 1_709_210_096_000_000_000
            plan = self.plan(root, (
                ArchiveEntry("file", 1, modified_ns=requested),
            ))
            real_utime = os.utime

            def over_normalize(path_or_fd, *, ns):
                real_utime(path_or_fd, ns=(ns[0], ns[1] + 2_000_000_000))

            with (
                patch(
                    "isopropyl.timestamps.os.utime",
                    side_effect=over_normalize,
                ),
                self.assertRaisesRegex(ExtractionError, "normalized"),
            ):
                SafeIsoExtractor(
                    streamer=payload_streamer({"file": b"x"}),
                ).execute(plan)
            self.assertFalse((root / "media").exists())
            self.assertEqual(list(root.glob(".media.*.partial")), [])

    def test_safe_relative_symlink_is_recreated_without_following_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.plan(root, (
                ArchiveEntry("boot", kind=EntryKind.DIRECTORY),
                ArchiveEntry("boot/grub.cfg", 3),
                ArchiveEntry(
                    "boot/current", kind=EntryKind.SYMLINK, link_target="grub.cfg",
                ),
            ))
            SafeIsoExtractor(streamer=payload_streamer({"boot/grub.cfg": b"cfg"})).execute(plan)
            link = root / "media/boot/current"
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.readlink(link), "grub.cfg")

    def test_unsafe_catalog_is_rejected_before_destination_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "source.iso"
            image.write_bytes(b"iso")
            with self.assertRaises(UnsafeArchiveError):
                build_extraction_plan(
                    image, root / "media", (ArchiveEntry("../escape", 1),),
                    seven_zip=TOOL,
                )
            self.assertFalse((root / "media").exists())

    def test_size_mismatch_cleans_private_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.plan(root, (ArchiveEntry("file", 4),))
            with self.assertRaisesRegex(ExtractionError, "expected 4"):
                SafeIsoExtractor(streamer=payload_streamer({"file": b"short"})).execute(plan)
            self.assertFalse((root / "media").exists())
            self.assertEqual(list(root.glob(".media.*.partial")), [])

    def test_source_change_and_destination_race_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.plan(root, (ArchiveEntry("file", 1),))
            plan.image.write_bytes(b"changed")
            with self.assertRaisesRegex(ExtractionSafetyError, "source changed"):
                SafeIsoExtractor(streamer=payload_streamer({"file": b"x"})).execute(plan)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.plan(root, (ArchiveEntry("file", 1),))
            plan.destination.mkdir()
            with self.assertRaisesRegex(ExtractionSafetyError, "appeared"):
                SafeIsoExtractor(streamer=payload_streamer({"file": b"x"})).execute(plan)

    def test_cancel_before_start_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.plan(root, (ArchiveEntry("file", 1),))
            executor = SafeIsoExtractor(streamer=payload_streamer({"file": b"x"}))
            executor.cancel()
            with self.assertRaises(ExtractionCancelled):
                executor.execute(plan)
            self.assertFalse(plan.destination.exists())

    def test_command_is_fixed_and_uses_option_terminator(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.iso"
            image.write_bytes(b"iso")
            command = extraction_command(TOOL, image, "EFI/BOOT/BOOTX64.EFI")
            self.assertEqual(command[:6], (TOOL, "x", "-so", "-spd", "-y", "--"))
            self.assertEqual(command[-1], "EFI/BOOT/BOOTX64.EFI")


if __name__ == "__main__":
    unittest.main()
