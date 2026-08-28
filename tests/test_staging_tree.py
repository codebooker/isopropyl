from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import isopropyl.staging_tree as staging_tree
from isopropyl.staging_tree import (
    StagedDirectory,
    StagedFile,
    StagingTreeSafetyError,
    build_staging_tree_manifest,
    scan_staging_tree,
    validate_staging_tree_manifest,
)


def make_tree(parent: Path) -> Path:
    root = parent / "tree"
    (root / "Alpha").mkdir(parents=True)
    (root / "zeta").mkdir()
    (root / "root.bin").write_bytes(b"root payload")
    (root / "Alpha" / "two.bin").write_bytes(b"two" * 2_000)
    (root / "zeta" / "empty.bin").write_bytes(b"")
    return root


class StagingTreeTests(unittest.TestCase):
    def test_module_import_does_not_reach_device_or_constructed_backends(self):
        command = (
            "import sys; import isopropyl.staging_tree; "
            "forbidden={'isopropyl.app','isopropyl.constructed',"
            "'isopropyl.devices','isopropyl.formatting'}; "
            "raise SystemExit(1 if forbidden.intersection(sys.modules) else 0)"
        )
        result = subprocess.run(
            [sys.executable, "-c", command],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_constructed_reexports_exact_neutral_scanner_aliases(self):
        from isopropyl import constructed

        self.assertIs(constructed.StagedDirectory, StagedDirectory)
        self.assertIs(constructed.StagedFile, StagedFile)
        self.assertTrue(issubclass(
            constructed.ConstructedMediaSafetyError, StagingTreeSafetyError,
        ))
        self.assertFalse(issubclass(
            constructed.ConstructedMediaCancelled,
            constructed.ConstructedMediaSafetyError,
        ))
        with self.assertRaises(constructed.ConstructedMediaSafetyError):
            constructed.scan_staging_tree("relative")

    def test_manifest_streams_ordered_complete_tree_and_revalidates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = make_tree(Path(directory))
            manifest = build_staging_tree_manifest(root)

            self.assertEqual(
                tuple(item.path for item in manifest.directories),
                (".", "Alpha", "zeta"),
            )
            self.assertEqual(
                tuple(item.path for item in manifest.files),
                ("Alpha/two.bin", "root.bin", "zeta/empty.bin"),
            )
            expected = {
                "Alpha/two.bin": hashlib.sha256(b"two" * 2_000).hexdigest(),
                "root.bin": hashlib.sha256(b"root payload").hexdigest(),
                "zeta/empty.bin": hashlib.sha256(b"").hexdigest(),
            }
            self.assertEqual(
                {item.path: item.sha256 for item in manifest.files}, expected,
            )
            self.assertEqual(manifest.total_bytes, len(b"two" * 2_000) + 12)
            self.assertRegex(manifest.manifest_sha256, r"^[0-9a-f]{64}$")
            self.assertEqual(
                manifest.source_directories,
                tuple(item.source for item in manifest.directories),
            )
            self.assertEqual(
                manifest.source_files,
                tuple(item.source for item in manifest.files),
            )
            validate_staging_tree_manifest(manifest)

    def test_manifest_detects_same_size_change_after_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = make_tree(Path(directory))
            manifest = build_staging_tree_manifest(root)
            (root / "root.bin").write_bytes(b"other payloa")

            with self.assertRaisesRegex(
                StagingTreeSafetyError, "changed after manifest creation",
            ):
                validate_staging_tree_manifest(manifest)

    def test_manifest_detects_mutation_during_stream_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = make_tree(Path(directory))
            target = root / "Alpha" / "two.bin"
            real_read = staging_tree.os.read
            mutated = False

            def reading(descriptor: int, size: int) -> bytes:
                nonlocal mutated
                block = real_read(descriptor, size)
                if block and not mutated:
                    mutated = True
                    target.write_bytes(b"x" * target.stat().st_size)
                return block

            with (
                patch.object(staging_tree.os, "read", side_effect=reading),
                self.assertRaisesRegex(StagingTreeSafetyError, "changed while hashing"),
            ):
                build_staging_tree_manifest(root)

    def test_manifest_detects_namespace_change_between_identity_scans(self):
        with tempfile.TemporaryDirectory() as directory:
            root = make_tree(Path(directory))
            real_scan = staging_tree.scan_staging_tree
            scans = 0

            def scanning(*args, **kwargs):
                nonlocal scans
                result = real_scan(*args, **kwargs)
                scans += 1
                if scans == 1:
                    (root / "late.bin").write_bytes(b"late")
                return result

            with (
                patch.object(staging_tree, "scan_staging_tree", side_effect=scanning),
                self.assertRaisesRegex(StagingTreeSafetyError, "changed"),
            ):
                build_staging_tree_manifest(root)

    def test_manifest_rejects_forged_digest_and_releases_descriptors_on_cancel(self):
        with tempfile.TemporaryDirectory() as directory:
            root = make_tree(Path(directory))
            manifest = build_staging_tree_manifest(root)
            forged = replace(manifest, manifest_sha256="0" * 64)
            with self.assertRaisesRegex(StagingTreeSafetyError, "manifest is invalid"):
                validate_staging_tree_manifest(forged)

            calls = 0

            def cancelled() -> None:
                nonlocal calls
                calls += 1
                if calls >= 3:
                    raise RuntimeError("cancelled")

            with self.assertRaisesRegex(RuntimeError, "cancelled"):
                build_staging_tree_manifest(root, cancel_check=cancelled)
            renamed = root.with_name("renamed")
            root.rename(renamed)
            self.assertTrue(renamed.is_dir())


if __name__ == "__main__":
    unittest.main()
