from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from isopropyl.extraction import (
    ExtractionCancelled, ExtractionError, ExtractionSafetyError, SafeIsoExtractor,
    build_extraction_plan, extraction_command,
)
from isopropyl.iso import ArchiveEntry, EntryKind, UnsafeArchiveError
from isopropyl.images import SevenZipNamespace


TOOL = "/usr/bin/7z"


def payload_streamer(payloads):
    def stream(_image, member, output, cancel):
        cancel()
        data = payloads[member]
        output.write(data)
        return len(data)
    return stream


class FakeExtractionProcess:
    def __init__(self, payload: bytes):
        stdout_read, stdout_write = os.pipe()
        stderr_read, stderr_write = os.pipe()
        os.write(stdout_write, payload)
        os.close(stdout_write)
        os.close(stderr_write)
        self.stdout = os.fdopen(stdout_read, "rb", buffering=0)
        self.stderr = os.fdopen(stderr_read, "rb", buffering=0)
        self.returncode = 0

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        del timeout
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


class ExtractionTests(unittest.TestCase):
    def plan(self, root: Path, entries):
        image = root / "source.iso"
        image.write_bytes(b"ISO placeholder")
        return build_extraction_plan(
            image, root / "media", entries, seven_zip=TOOL,
            archive_namespace=SevenZipNamespace.ISO9660,
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

    def test_same_size_source_rewrite_with_restored_mtime_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.plan(root, (ArchiveEntry("file", 1),))
            before = plan.image.stat()
            plan.image.write_bytes(b"X" * before.st_size)
            os.utime(
                plan.image,
                ns=(before.st_atime_ns, before.st_mtime_ns),
            )

            with self.assertRaisesRegex(ExtractionSafetyError, "source changed"):
                SafeIsoExtractor(
                    streamer=payload_streamer({"file": b"x"}),
                ).execute(plan)

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
            command = extraction_command(
                TOOL, image, "EFI/BOOT/BOOTX64.EFI",
                SevenZipNamespace.UDF,
            )
            self.assertEqual(
                command[:7],
                (TOOL, "x", "-so", "-spd", "-y", "-tUdf", "--"),
            )
            self.assertEqual(command[-1], "EFI/BOOT/BOOTX64.EFI")

    def test_default_streamer_uses_bound_descriptor_and_plan_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.plan(root, (ArchiveEntry("file", 4),))
            process = FakeExtractionProcess(b"data")
            popen = Mock(return_value=process)
            result = SafeIsoExtractor(popen=popen).execute(plan)
            command = popen.call_args.args[0]
            inherited = popen.call_args.kwargs["pass_fds"]
            self.assertEqual(len(inherited), 1)
            self.assertIn("-tIso", command)
            self.assertIn(f"/proc/self/fd/{inherited[0]}", command)
            self.assertNotIn(str(plan.image), command)
            self.assertEqual((result.destination / "file").read_bytes(), b"data")

    def test_forged_namespace_is_rejected_before_private_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.plan(root, (ArchiveEntry("file", 1),))
            forged = replace(plan, archive_namespace="Iso")
            with self.assertRaisesRegex(ExtractionSafetyError, "namespace"):
                SafeIsoExtractor(
                    streamer=payload_streamer({"file": b"x"}),
                ).execute(forged)
            self.assertFalse(plan.destination.exists())

    @unittest.skipUnless(
        shutil.which("genisoimage") and shutil.which("7z"),
        "genisoimage and 7z are required for dual-namespace regression coverage",
    )
    def test_real_dual_namespace_plan_and_extraction_use_bound_udf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = root / "tree"
            tree.mkdir()
            (tree / "ISOONLY.TXT").write_bytes(b"iso")
            (tree / "UDFONLY.TXT").write_bytes(b"udf")
            image = root / "dual.iso"
            subprocess.run(
                [
                    shutil.which("genisoimage") or "genisoimage",
                    "-quiet", "-udf", "-o", str(image),
                    "-hide", "UDFONLY.TXT", str(tree),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            entries = (
                ArchiveEntry("ISOONLY.TXT", 3),
                ArchiveEntry("UDFONLY.TXT", 3),
            )
            plan = build_extraction_plan(
                image, root / "media", entries, seven_zip=TOOL,
            )
            self.assertIs(plan.archive_namespace, SevenZipNamespace.UDF)
            result = SafeIsoExtractor().execute(plan)
            self.assertEqual(result.bytes_written, 6)
            self.assertEqual((result.destination / "ISOONLY.TXT").read_bytes(), b"iso")
            self.assertEqual((result.destination / "UDFONLY.TXT").read_bytes(), b"udf")


if __name__ == "__main__":
    unittest.main()
