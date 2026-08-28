# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from isopropyl import windows_bcd_capture_import as importer
from isopropyl.windows_bcd_capture import RAW_BCD_CAPTURE_VARIANTS
from isopropyl.windows_bcd_oracle import (
    parse_bcd_oracle_bytes,
    validate_bcd_oracle_differential_set,
)
from tests.test_windows_bcd_capture import (
    capture_fixtures,
    observation,
    payload,
    raw_document,
)
from tools import import_windows_bcd_capture as cli


class WindowsBcdCaptureImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.parent = self.root / "published"
        self.parent.mkdir()
        self.parent.chmod(0o700)
        self.source = self.root / "source"
        self.source.mkdir()
        self.destination = self.parent / "capture"
        self._populate(self.source)

    def _populate(self, source: Path) -> None:
        fixtures = capture_fixtures()
        collector = b"# synthetic collector fixture\r\n"
        template = b"regf-synthetic-bcd-template"
        document = raw_document()
        document["profile"]["collector"] = {
            "size": len(collector),
            "sha256": hashlib.sha256(collector).hexdigest(),
        }
        document["profile"]["template"] = {
            "size": len(template),
            "sha256": hashlib.sha256(template).hexdigest(),
        }
        self.hive_payloads = {}
        self.observations = {}
        for fixture in fixtures:
            hive = b"regf-synthetic-" + fixture.variant.encode("ascii")
            digest = hashlib.sha256(hive).hexdigest()
            self.hive_payloads[fixture.variant] = hive
            self.observations[fixture.variant] = replace(
                observation(fixture),
                store_size=len(hive),
                store_sha256=digest,
            )
            capture = next(
                item
                for item in document["captures"]
                if item["variant"] == fixture.variant
            )
            capture["store"] = {"size": len(hive), "sha256": digest}

        (source / importer.RAW_CAPTURE_NAME).write_bytes(payload(document))
        (source / importer.COLLECTOR_NAME).write_bytes(collector)
        (source / importer.TEMPLATE_NAME).write_bytes(template)
        for variant, name in importer.HIVE_NAMES.items():
            (source / name).write_bytes(self.hive_payloads[variant])

    def _read_hive(self, descriptor):
        value = os.pread(descriptor, os.fstat(descriptor).st_size, 0)
        variant = next(
            variant
            for variant, payload_bytes in self.hive_payloads.items()
            if payload_bytes == value
        )
        return self.observations[variant]

    def _import(self):
        with patch.object(
            importer,
            "read_bcd_hive_descriptor",
            side_effect=self._read_hive,
        ):
            return importer.import_windows_bcd_capture(
                self.source,
                self.destination,
            )

    def _assert_no_partial(self) -> None:
        self.assertFalse(self.destination.exists())
        self.assertEqual(
            [item.name for item in self.parent.iterdir()],
            [],
        )

    def test_exact_bundle_is_copied_derived_fsynced_and_published(self) -> None:
        source_bytes = {
            name: (self.source / name).read_bytes() for name in importer.SOURCE_NAMES
        }
        receipt = self._import()

        self.assertEqual(receipt.destination, str(self.destination))
        self.assertEqual(
            {item.name for item in receipt.source_artifacts},
            set(importer.SOURCE_NAMES),
        )
        self.assertEqual(
            {item.name for item in receipt.fixture_artifacts},
            set(importer.FIXTURE_NAMES),
        )
        self.assertEqual(
            {item.name for item in self.destination.iterdir()},
            set(importer.OUTPUT_NAMES),
        )
        for name, expected in source_bytes.items():
            self.assertEqual((self.destination / name).read_bytes(), expected)
        for name in importer.OUTPUT_NAMES:
            status = (self.destination / name).stat()
            self.assertTrue(stat.S_ISREG(status.st_mode))
            self.assertEqual(stat.S_IMODE(status.st_mode), 0o600)
            self.assertEqual(status.st_nlink, 1)

        fixtures = tuple(
            parse_bcd_oracle_bytes(
                (self.destination / f"{variant}.json").read_bytes(),
            )
            for variant in RAW_BCD_CAPTURE_VARIANTS
        )
        validate_bcd_oracle_differential_set(fixtures)
        self.assertEqual(
            [fixture.variant for fixture in fixtures],
            list(RAW_BCD_CAPTURE_VARIANTS),
        )

    def test_inventory_must_be_exact_before_any_hive_is_read(self) -> None:
        for mutation in ("missing", "extra"):
            with self.subTest(mutation=mutation):
                source = self.root / f"source-{mutation}"
                source.mkdir()
                self._populate(source)
                destination = self.parent / mutation
                if mutation == "missing":
                    (source / importer.TEMPLATE_NAME).unlink()
                else:
                    (source / "unexpected.txt").write_bytes(b"unexpected")
                with patch.object(importer, "read_bcd_hive_descriptor") as read_hive:
                    with self.assertRaises(importer.BcdCaptureImportError):
                        importer.import_windows_bcd_capture(source, destination)
                read_hive.assert_not_called()
                self.assertFalse(destination.exists())

    def test_inventory_reopens_a_fresh_directory_stream(self) -> None:
        directory = self.root / "inventory-offset"
        directory.mkdir()
        (directory / "first").write_bytes(b"1")
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, descriptor)
        self.assertEqual(importer._inventory(descriptor), ("first",))
        (directory / "second").write_bytes(b"2")
        self.assertEqual(importer._inventory(descriptor), ("first", "second"))

    def test_links_and_aliases_are_rejected(self) -> None:
        source = self.root / "source-alias"
        source.mkdir()
        self._populate(source)
        (source / importer.COLLECTOR_NAME).unlink()
        os.link(source / importer.TEMPLATE_NAME, source / importer.COLLECTOR_NAME)
        with patch.object(importer, "read_bcd_hive_descriptor") as read_hive:
            with self.assertRaisesRegex(importer.BcdCaptureImportError, "singly linked"):
                importer.import_windows_bcd_capture(source, self.parent / "alias")
        read_hive.assert_not_called()

        source = self.root / "source-symlink"
        source.mkdir()
        self._populate(source)
        external = self.root / "external.ps1"
        external.write_bytes(b"external")
        (source / importer.COLLECTOR_NAME).unlink()
        (source / importer.COLLECTOR_NAME).symlink_to(external)
        with patch.object(importer, "read_bcd_hive_descriptor") as read_hive:
            with self.assertRaises(importer.BcdCaptureImportError):
                importer.import_windows_bcd_capture(source, self.parent / "symlink")
        read_hive.assert_not_called()

    def test_source_mutation_after_pinning_fails_without_output(self) -> None:
        original_reader = self._read_hive
        calls = 0

        def mutate(descriptor):
            nonlocal calls
            result = original_reader(descriptor)
            calls += 1
            if calls == 1:
                collector = self.source / importer.COLLECTOR_NAME
                collector.write_bytes(b"x" * collector.stat().st_size)
            return result

        with (
            patch.object(importer, "read_bcd_hive_descriptor", side_effect=mutate),
            self.assertRaises(importer.BcdCaptureImportError),
        ):
            importer.import_windows_bcd_capture(self.source, self.destination)
        self._assert_no_partial()

    def test_existing_destination_is_never_replaced(self) -> None:
        self.destination.mkdir()
        marker = self.destination / "marker"
        marker.write_bytes(b"keep")
        with patch.object(importer, "read_bcd_hive_descriptor") as read_hive:
            with self.assertRaisesRegex(importer.BcdCaptureImportError, "already exists"):
                importer.import_windows_bcd_capture(self.source, self.destination)
        read_hive.assert_not_called()
        self.assertEqual(marker.read_bytes(), b"keep")
        self.assertEqual([item.name for item in self.parent.iterdir()], ["capture"])

    def test_destination_parent_must_exclude_other_writers(self) -> None:
        self.parent.chmod(0o770)
        with patch.object(importer, "read_bcd_hive_descriptor") as read_hive:
            with self.assertRaisesRegex(importer.BcdCaptureImportError, "not writable"):
                importer.import_windows_bcd_capture(self.source, self.destination)
        read_hive.assert_not_called()
        self.assertFalse(self.destination.exists())

    def test_commit_time_collision_preserves_competing_destination(self) -> None:
        real_rename = importer._rename_noreplace

        def collide(parent_descriptor, temporary_name, destination_name):
            os.mkdir(destination_name, 0o700, dir_fd=parent_descriptor)
            directory = os.open(
                destination_name,
                os.O_RDONLY | os.O_DIRECTORY,
                dir_fd=parent_descriptor,
            )
            try:
                marker = os.open(
                    "marker",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory,
                )
                try:
                    os.write(marker, b"competitor")
                finally:
                    os.close(marker)
            finally:
                os.close(directory)
            return real_rename(parent_descriptor, temporary_name, destination_name)

        with (
            patch.object(importer, "read_bcd_hive_descriptor", side_effect=self._read_hive),
            patch.object(importer, "_rename_noreplace", side_effect=collide),
            self.assertRaisesRegex(importer.BcdCaptureImportError, "destination appeared"),
        ):
            importer.import_windows_bcd_capture(self.source, self.destination)
        self.assertEqual((self.destination / "marker").read_bytes(), b"competitor")
        self.assertEqual([item.name for item in self.parent.iterdir()], ["capture"])

    def test_namespace_substitution_cannot_return_success(self) -> None:
        real_rename = importer._rename_noreplace
        escaped_name = "verified-escaped"

        def substitute(parent_descriptor, temporary_name, destination_name):
            os.rename(
                temporary_name,
                escaped_name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            os.mkdir(temporary_name, 0o700, dir_fd=parent_descriptor)
            directory = os.open(
                temporary_name,
                os.O_RDONLY | os.O_DIRECTORY,
                dir_fd=parent_descriptor,
            )
            try:
                replacement = os.open(
                    "attacker",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory,
                )
                try:
                    os.write(replacement, b"replacement")
                finally:
                    os.close(replacement)
            finally:
                os.close(directory)
            real_rename(parent_descriptor, temporary_name, destination_name)

        with (
            patch.object(importer, "read_bcd_hive_descriptor", side_effect=self._read_hive),
            patch.object(importer, "_rename_noreplace", side_effect=substitute),
            self.assertRaises(importer.BcdCaptureImportCommittedError),
        ):
            importer.import_windows_bcd_capture(self.source, self.destination)
        self.assertEqual((self.destination / "attacker").read_bytes(), b"replacement")
        self.assertEqual(
            {item.name for item in (self.parent / escaped_name).iterdir()},
            set(importer.OUTPUT_NAMES),
        )

    def test_destination_parent_path_substitution_cannot_return_success(self) -> None:
        real_rename = importer._rename_noreplace
        moved_parent = self.root / "moved-published"

        def substitute_parent(parent_descriptor, temporary_name, destination_name):
            self.parent.rename(moved_parent)
            self.parent.mkdir(mode=0o700)
            (self.parent / "attacker").write_bytes(b"replacement parent")
            real_rename(parent_descriptor, temporary_name, destination_name)

        with (
            patch.object(importer, "read_bcd_hive_descriptor", side_effect=self._read_hive),
            patch.object(importer, "_rename_noreplace", side_effect=substitute_parent),
            self.assertRaises(importer.BcdCaptureImportCommittedError),
        ):
            importer.import_windows_bcd_capture(self.source, self.destination)
        self.assertEqual((self.parent / "attacker").read_bytes(), b"replacement parent")
        self.assertEqual(
            {item.name for item in (moved_parent / "capture").iterdir()},
            set(importer.OUTPUT_NAMES),
        )

    def test_publish_failure_cleans_only_private_tree_and_leaves_no_partial(self) -> None:
        with (
            patch.object(
                importer,
                "read_bcd_hive_descriptor",
                side_effect=self._read_hive,
            ),
            patch.object(
                importer,
                "_rename_noreplace",
                side_effect=importer.BcdCaptureImportError("injected publish failure"),
            ),
            self.assertRaisesRegex(importer.BcdCaptureImportError, "publish failure"),
        ):
            importer.import_windows_bcd_capture(self.source, self.destination)
        self._assert_no_partial()

    def test_mid_copy_failure_leaves_no_destination_or_private_sibling(self) -> None:
        real_create = importer._create_output_file
        calls = 0

        def fail_after_two(directory_descriptor, name, data):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise importer.BcdCaptureImportError("injected copy failure")
            return real_create(directory_descriptor, name, data)

        with (
            patch.object(
                importer,
                "read_bcd_hive_descriptor",
                side_effect=self._read_hive,
            ),
            patch.object(importer, "_create_output_file", side_effect=fail_after_two),
            self.assertRaisesRegex(importer.BcdCaptureImportError, "copy failure"),
        ):
            importer.import_windows_bcd_capture(self.source, self.destination)
        self._assert_no_partial()

    def test_parent_fsync_failure_reports_committed_complete_directory(self) -> None:
        real_fsync = os.fsync
        parent_identity = (self.parent.stat().st_dev, self.parent.stat().st_ino)

        def fail_published_parent(descriptor):
            status = os.fstat(descriptor)
            if (status.st_dev, status.st_ino) == parent_identity:
                raise OSError("injected parent fsync failure")
            return real_fsync(descriptor)

        with (
            patch.object(
                importer,
                "read_bcd_hive_descriptor",
                side_effect=self._read_hive,
            ),
            patch.object(importer.os, "fsync", side_effect=fail_published_parent),
            self.assertRaises(importer.BcdCaptureImportCommittedError),
        ):
            importer.import_windows_bcd_capture(self.source, self.destination)
        self.assertTrue(self.destination.is_dir())
        self.assertEqual(
            {item.name for item in self.destination.iterdir()},
            set(importer.OUTPUT_NAMES),
        )
        self.assertEqual(
            [item.name for item in self.parent.iterdir()],
            [self.destination.name],
        )

    def test_fsync_order_precedes_and_follows_atomic_rename(self) -> None:
        events: list[str] = []
        real_fsync = os.fsync
        real_rename = importer._rename_noreplace

        def record_fsync(descriptor):
            kind = "file-fsync" if stat.S_ISREG(os.fstat(descriptor).st_mode) else "dir-fsync"
            events.append(kind)
            return real_fsync(descriptor)

        def record_rename(*arguments):
            events.append("rename")
            return real_rename(*arguments)

        with (
            patch.object(importer, "read_bcd_hive_descriptor", side_effect=self._read_hive),
            patch.object(importer.os, "fsync", side_effect=record_fsync),
            patch.object(importer, "_rename_noreplace", side_effect=record_rename),
        ):
            importer.import_windows_bcd_capture(self.source, self.destination)
        rename_index = events.index("rename")
        self.assertEqual(events[:rename_index].count("file-fsync"), len(importer.OUTPUT_NAMES))
        self.assertEqual(events[rename_index - 1], "dir-fsync")
        self.assertEqual(events[rename_index + 1 :], ["dir-fsync"])

    def test_cli_success_report_is_explicitly_non_authorizing(self) -> None:
        receipt = self._import()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(cli, "import_windows_bcd_capture", return_value=receipt),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = cli.main([str(self.source), str(self.parent / "unused")])
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["status"], "non-authorizing-capture-imported")
        self.assertTrue(all(value is False for value in report["authorization"].values()))
        self.assertTrue(all(value is False for value in report["scope"].values()))

    def test_cli_distinguishes_precommit_and_committed_failures(self) -> None:
        for failure, expected in (
            (importer.BcdCaptureImportError("precommit"), 1),
            (importer.BcdCaptureImportCommittedError("committed"), 2),
        ):
            stderr = io.StringIO()
            with (
                patch.object(cli, "import_windows_bcd_capture", side_effect=failure),
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(cli.main(["source", "destination"]), expected)
            self.assertIn(str(failure), stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
