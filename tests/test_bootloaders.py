# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import threading
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from isopropyl.bootloaders import (
    BootloaderCatalog, BootloaderResource, CatalogError, DependencyUnavailable,
    DownloadError, delete_cached_artifacts, fetch_resource, installed_tool_matches,
    inventory_cache, load_catalog, resolve_artifact, resolve_system_tool,
    reverify_artifact,
)


class Response(BytesIO):
    def __init__(self, value: bytes, url: str = "https://downloads.example.test/core.img"):
        super().__init__(value)
        self.url = url

    def geturl(self) -> str:
        return self.url


def resource(
    value: bytes = b"trusted bootloader bytes",
    *,
    family: str = "grub",
    version: str = "2.12",
    name: str = "core.img",
) -> BootloaderResource:
    return BootloaderResource(
        family=family, version=version, name=name,
        url="https://downloads.example.test/core.img",
        sha256=hashlib.sha256(value).hexdigest(), size=len(value),
        allowed_hosts=("downloads.example.test",),
    )


class BootloaderTests(unittest.TestCase):
    def test_bundled_catalog_is_valid_and_network_inactive(self):
        catalog = load_catalog()
        self.assertEqual(len(catalog.resources), 1)
        image = catalog.find(
            "uefi-ntfs", "2.8-rufus-2368e49a", "uefi-ntfs.img",
        )
        self.assertIsNotNone(image)
        assert image is not None
        self.assertEqual(image.size, 1_048_576)
        self.assertEqual(
            image.sha256,
            "72683fa1250eeea772d3399277b434d4e55ba8dd0dc926e52d817e701fc2eb9e",
        )
        self.assertEqual(image.allowed_hosts, ("raw.githubusercontent.com",))

    def test_catalog_rejects_http_and_unsafe_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            base = {
                "catalog_version": 1,
                "resources": [{
                    "family": "grub", "version": "2.12", "name": "core.img",
                    "url": "http://example.test/core.img", "sha256": "0" * 64,
                    "size": 12,
                }],
            }
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaises(CatalogError):
                load_catalog(path)
            base["resources"][0]["url"] = "https://example.test/core.img"
            base["resources"][0]["name"] = "../core.img"
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaises(CatalogError):
                load_catalog(path)

    def test_download_is_cached_only_after_hash_and_size_verification(self):
        value = b"trusted bootloader bytes"
        calls = 0

        def open_download(_request, timeout):
            nonlocal calls
            calls += 1
            self.assertEqual(timeout, 30)
            return Response(value)

        with tempfile.TemporaryDirectory() as directory:
            path = fetch_resource(resource(value), Path(directory), open_download)
            self.assertEqual(path.read_bytes(), value)
            self.assertEqual(fetch_resource(resource(value), Path(directory), open_download), path)
            self.assertEqual(calls, 1)

    def test_bad_hash_and_untrusted_redirect_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            bad_hash = resource(b"expected")
            with self.assertRaises(DownloadError):
                fetch_resource(
                    bad_hash, Path(directory), lambda *_args, **_kwargs: Response(b"tampered")
                )
            with self.assertRaises(DownloadError):
                fetch_resource(
                    resource(), Path(directory),
                    lambda *_args, **_kwargs: Response(
                        b"trusted bootloader bytes", "https://attacker.test/core.img"
                    ),
                )
            self.assertEqual(list(Path(directory).rglob("core.img")), [])

    def test_cancelled_download_is_not_published_or_cached(self):
        value = b"trusted bootloader bytes"
        cancelled = threading.Event()

        class CancellingResponse(Response):
            def read(self, size=-1):
                block = super().read(4 if size < 0 else min(size, 4))
                cancelled.set()
                return block

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(DownloadError, "cancelled"):
                fetch_resource(
                    resource(value), root,
                    lambda *_args, **_kwargs: CancellingResponse(value),
                    cancelled,
                )
            self.assertEqual(list(root.rglob("core.img")), [])
            self.assertEqual(
                [path for path in root.rglob("*") if path.name.startswith(".isopropyl-download-")],
                [],
            )

    def test_pre_cancelled_download_never_opens_network(self):
        cancelled = threading.Event()
        cancelled.set()
        opened = False

        def should_not_open(*_args, **_kwargs):
            nonlocal opened
            opened = True
            raise AssertionError("network should not be opened")

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(DownloadError, "cancelled"):
                fetch_resource(
                    resource(), Path(directory), should_not_open,
                    cancel_event=cancelled,
                )
        self.assertFalse(opened)

    def test_installed_exact_version_is_preferred(self):
        def run(_args, **_kwargs):
            return subprocess.CompletedProcess([], 0, "grub-install (GRUB) 2.12-5ubuntu2", "")

        with patch("isopropyl.bootloaders.shutil.which", return_value="/usr/sbin/grub-install"):
            self.assertEqual(
                installed_tool_matches("grub-install", "2.12", run),
                Path("/usr/sbin/grub-install"),
            )
            self.assertIsNone(installed_tool_matches("grub-install", "2.12.1", run))
            resolved = resolve_system_tool("grub", "2.12", "grub-install", runner=run)
            self.assertEqual(resolved.source, "system-tool")

    def test_host_tool_cannot_satisfy_a_boot_artifact_request(self):
        with patch("isopropyl.bootloaders.shutil.which", return_value="/usr/sbin/grub-install"):
            with self.assertRaises(DependencyUnavailable):
                resolve_artifact("grub", "2.12", "core.img", catalog=BootloaderCatalog(()))

    def test_unknown_dependency_fails_closed_without_network(self):
        with self.assertRaises(DependencyUnavailable):
            resolve_artifact("grub", "9.99", "core.img", catalog=BootloaderCatalog(()))

    def test_artifact_can_be_reverified_immediately_before_use(self):
        value = b"trusted bootloader bytes"
        item = resource(value)
        catalog = BootloaderCatalog((item,))
        with tempfile.TemporaryDirectory() as directory:
            dependency = resolve_artifact(
                "grub", "2.12", "core.img", catalog=catalog,
                cache_dir=Path(directory),
                opener=lambda *_args, **_kwargs: Response(value),
            )
            self.assertTrue(reverify_artifact(dependency, "core.img", catalog))
            dependency.path.write_bytes(b"tampered bootloader")
            self.assertFalse(reverify_artifact(dependency, "core.img", catalog))


class CacheManagementTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.environment = patch.dict(
            os.environ, {"XDG_CACHE_HOME": self.temporary.name}, clear=False,
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.root = Path(self.temporary.name) / "isopropyl" / "bootloaders"

    def put(self, item: BootloaderResource, value: bytes) -> Path:
        path = self.root / item.family / item.version / item.name
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.write_bytes(value)
        return path

    def test_inventory_reports_only_exact_catalog_paths_hashes_and_sizes(self):
        good_value = b"verified"
        bad_value = b"wrong"
        good = resource(good_value)
        bad = resource(b"expected", family="syslinux", version="6.04", name="ldlinux.c32")
        good_path = self.put(good, good_value)
        bad_path = self.put(bad, bad_value)
        unknown = good_path.parent / "unknown.bin"
        unknown.write_bytes(b"not cataloged")

        result = inventory_cache(catalog=BootloaderCatalog((good, bad)))

        self.assertEqual([item.key for item in result.artifacts], [good.key, bad.key])
        self.assertEqual([item.hash_valid for item in result.artifacts], [True, False])
        self.assertTrue(all(item.deletion_safe for item in result.artifacts))
        self.assertEqual(result.total_size, good_path.stat().st_size + bad_path.stat().st_size)
        self.assertEqual(result.deletable_size, result.total_size)
        self.assertNotIn(unknown.name, tuple(item.name for item in result.artifacts))

    def test_inventory_normalizes_one_read_error_and_continues(self):
        first = resource(b"first")
        second = resource(
            b"second", family="syslinux", version="6.04", name="ldlinux.c32",
        )
        self.put(first, b"first")
        self.put(second, b"second")
        real_read = os.read
        calls = 0

        def fail_first_read(descriptor, size):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("simulated read failure")
            return real_read(descriptor, size)

        with patch("isopropyl.bootloaders.os.read", side_effect=fail_first_read):
            result = inventory_cache(catalog=BootloaderCatalog((first, second)))

        self.assertEqual([item.key for item in result.artifacts], [first.key, second.key])
        self.assertFalse(result.artifacts[0].deletion_safe)
        self.assertIn("simulated read failure", result.artifacts[0].issue)
        self.assertTrue(result.artifacts[1].hash_valid)

    def test_missing_cache_is_empty_and_is_not_created(self):
        result = inventory_cache(catalog=BootloaderCatalog((resource(),)))
        self.assertEqual(result.artifacts, ())
        self.assertEqual(result.total_size, 0)
        self.assertFalse(self.root.exists())

    def test_inventory_and_deletion_never_follow_file_symlinks(self):
        item = resource(b"outside")
        outside = Path(self.temporary.name) / "outside.img"
        outside.write_bytes(b"outside")
        path = self.root / item.family / item.version / item.name
        path.parent.mkdir(parents=True)
        path.symlink_to(outside)

        inventory = inventory_cache(catalog=BootloaderCatalog((item,)))
        self.assertEqual(len(inventory.artifacts), 1)
        self.assertFalse(inventory.artifacts[0].hash_valid)
        self.assertFalse(inventory.artifacts[0].deletion_safe)
        self.assertIn("symbolic link", inventory.artifacts[0].issue)
        result = delete_cached_artifacts((item.key,), catalog=BootloaderCatalog((item,)))
        self.assertEqual(result.deleted, ())
        self.assertIn("symbolic link", result.skipped[0].reason)
        self.assertTrue(path.is_symlink())
        self.assertEqual(outside.read_bytes(), b"outside")

    def test_cache_directory_symlink_is_rejected_without_following_it(self):
        item = resource(b"outside")
        outside = Path(self.temporary.name) / "outside-cache"
        target = outside / item.family / item.version / item.name
        target.parent.mkdir(parents=True)
        target.write_bytes(b"outside")
        self.root.parent.mkdir(parents=True)
        self.root.symlink_to(outside, target_is_directory=True)

        inventory = inventory_cache(catalog=BootloaderCatalog((item,)))
        self.assertEqual(inventory.artifacts, ())
        self.assertTrue(inventory.issues)
        deleted = delete_cached_artifacts((item.key,), catalog=BootloaderCatalog((item,)))
        self.assertEqual(deleted.deleted, ())
        self.assertTrue(deleted.skipped)
        self.assertEqual(target.read_bytes(), b"outside")

    def test_hardlinked_artifact_is_visible_but_never_deleted(self):
        value = b"linked"
        item = resource(value)
        path = self.put(item, value)
        other = Path(self.temporary.name) / "other-link"
        os.link(path, other)

        inventory = inventory_cache(catalog=BootloaderCatalog((item,)))
        cached = inventory.artifacts[0]
        self.assertTrue(cached.hash_valid)
        self.assertFalse(cached.deletion_safe)
        self.assertIn("hard link", cached.issue)
        result = delete_cached_artifacts((item.key,), catalog=BootloaderCatalog((item,)))
        self.assertEqual(result.deleted, ())
        self.assertIn("multiply linked", result.skipped[0].reason)
        self.assertEqual(path.read_bytes(), value)
        self.assertEqual(other.read_bytes(), value)

    def test_non_regular_catalog_path_is_reported_and_left_untouched(self):
        item = resource()
        path = self.root / item.family / item.version / item.name
        path.mkdir(parents=True)
        inventory = inventory_cache(catalog=BootloaderCatalog((item,)))
        self.assertEqual(len(inventory.artifacts), 1)
        self.assertFalse(inventory.artifacts[0].deletion_safe)
        self.assertIn("not a regular file", inventory.artifacts[0].issue)
        result = delete_cached_artifacts((item.key,), catalog=BootloaderCatalog((item,)))
        self.assertEqual(result.deleted, ())
        self.assertIn("non-regular", result.skipped[0].reason)
        self.assertTrue(path.is_dir())

    def test_explicit_deletion_removes_regular_catalog_file_and_fsyncs(self):
        item = resource(b"trusted")
        path = self.put(item, b"corrupt but deletable")
        unknown = path.parent / "unknown.img"
        unknown.write_bytes(b"keep")
        fsync_calls = []
        real_fsync = os.fsync

        def observed_fsync(descriptor):
            fsync_calls.append(descriptor)
            return real_fsync(descriptor)

        with patch("isopropyl.bootloaders.os.fsync", side_effect=observed_fsync):
            result = delete_cached_artifacts(
                (item.key, (item.family, item.version, "unknown.img")),
                catalog=BootloaderCatalog((item,)),
            )
        self.assertEqual([entry.key for entry in result.deleted], [item.key])
        self.assertEqual(result.bytes_deleted, len(b"corrupt but deletable"))
        self.assertEqual(len(result.skipped), 1)
        self.assertIn("trusted catalog", result.skipped[0].reason)
        self.assertFalse(path.exists())
        self.assertEqual(unknown.read_bytes(), b"keep")
        self.assertGreaterEqual(len(fsync_calls), 2)
        self.assertEqual(list(path.parent.glob(".isopropyl-delete-*")), [])

    def test_replacement_race_is_restored_and_not_deleted(self):
        original = b"original"
        replacement = b"replacement"
        item = resource(original)
        path = self.put(item, original)
        real_rename = os.rename
        raced = False

        def racing_rename(source, destination, **kwargs):
            nonlocal raced
            if source == item.name and destination == "artifact" and not raced:
                raced = True
                path.unlink()
                path.write_bytes(replacement)
            return real_rename(source, destination, **kwargs)

        with patch("isopropyl.bootloaders.os.rename", side_effect=racing_rename):
            result = delete_cached_artifacts((item.key,), catalog=BootloaderCatalog((item,)))
        self.assertTrue(raced)
        self.assertEqual(result.deleted, ())
        self.assertIn("changed during deletion", result.skipped[0].reason)
        self.assertEqual(path.read_bytes(), replacement)
        self.assertEqual(list(path.parent.glob(".isopropyl-delete-*")), [])

    def test_hardlink_race_after_open_is_refused_and_restored(self):
        value = b"artifact"
        item = resource(value)
        path = self.put(item, value)
        outside_link = Path(self.temporary.name) / "raced-link"
        real_rename = os.rename
        raced = False

        def racing_rename(source, destination, **kwargs):
            nonlocal raced
            if source == item.name and destination == "artifact" and not raced:
                raced = True
                os.link(path, outside_link)
            return real_rename(source, destination, **kwargs)

        with patch("isopropyl.bootloaders.os.rename", side_effect=racing_rename):
            result = delete_cached_artifacts((item.key,), catalog=BootloaderCatalog((item,)))
        self.assertEqual(result.deleted, ())
        self.assertIn("changed during deletion", result.skipped[0].reason)
        self.assertEqual(path.read_bytes(), value)
        self.assertEqual(outside_link.read_bytes(), value)

    def test_final_fstat_failure_restores_and_skips_artifact(self):
        value = b"artifact"
        item = resource(value)
        path = self.put(item, value)
        real_fstat = os.fstat
        calls = 0

        def fail_final_fstat(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated final fstat failure")
            return real_fstat(descriptor)

        with patch("isopropyl.bootloaders.os.fstat", side_effect=fail_final_fstat):
            result = delete_cached_artifacts((item.key,), catalog=BootloaderCatalog((item,)))

        self.assertEqual(result.deleted, ())
        self.assertEqual(len(result.skipped), 1)
        self.assertIn("final fstat failure", result.skipped[0].reason)
        self.assertIn("was restored", result.skipped[0].reason)
        self.assertEqual(path.read_bytes(), value)
        self.assertEqual(list(path.parent.glob(".isopropyl-delete-*")), [])

    def test_unlink_failure_restores_and_skips_artifact(self):
        value = b"artifact"
        item = resource(value)
        path = self.put(item, value)
        real_unlink = os.unlink
        failed = False

        def fail_delete_unlink(name, **kwargs):
            nonlocal failed
            if name == "artifact" and not failed:
                failed = True
                raise OSError("simulated unlink failure")
            return real_unlink(name, **kwargs)

        with patch("isopropyl.bootloaders.os.unlink", side_effect=fail_delete_unlink):
            result = delete_cached_artifacts((item.key,), catalog=BootloaderCatalog((item,)))

        self.assertTrue(failed)
        self.assertEqual(result.deleted, ())
        self.assertIn("unlink failure", result.skipped[0].reason)
        self.assertIn("was restored", result.skipped[0].reason)
        self.assertEqual(path.read_bytes(), value)
        self.assertEqual(list(path.parent.glob(".isopropyl-delete-*")), [])

    def test_restore_fsync_failure_reports_restored_not_retained(self):
        value = b"artifact"
        item = resource(value)
        path = self.put(item, value)
        real_fstat = os.fstat
        real_fsync = os.fsync
        fstat_calls = 0
        fsync_failed = False

        def fail_final_fstat(descriptor):
            nonlocal fstat_calls
            fstat_calls += 1
            if fstat_calls == 2:
                raise OSError("force restore")
            return real_fstat(descriptor)

        def fail_first_fsync(descriptor):
            nonlocal fsync_failed
            if not fsync_failed:
                fsync_failed = True
                raise OSError("simulated restore fsync failure")
            return real_fsync(descriptor)

        with (
            patch("isopropyl.bootloaders.os.fstat", side_effect=fail_final_fstat),
            patch("isopropyl.bootloaders.os.fsync", side_effect=fail_first_fsync),
        ):
            result = delete_cached_artifacts((item.key,), catalog=BootloaderCatalog((item,)))

        self.assertEqual(result.deleted, ())
        self.assertIn("was restored", result.skipped[0].reason)
        self.assertNotIn("retained in a private quarantine", result.skipped[0].reason)
        self.assertTrue(any("restore fsync failure" in issue for issue in result.issues))
        self.assertEqual(path.read_bytes(), value)
        self.assertEqual(list(path.parent.glob(".isopropyl-delete-*")), [])

    def test_restore_collision_truthfully_reports_retained_quarantine(self):
        value = b"artifact"
        item = resource(value)
        path = self.put(item, value)
        real_fstat = os.fstat
        calls = 0

        def collide_before_final_fstat(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                path.write_bytes(b"replacement")
                raise OSError("force restore collision")
            return real_fstat(descriptor)

        with patch(
            "isopropyl.bootloaders.os.fstat", side_effect=collide_before_final_fstat,
        ):
            result = delete_cached_artifacts((item.key,), catalog=BootloaderCatalog((item,)))

        self.assertEqual(result.deleted, ())
        self.assertIn("retained in a private quarantine", result.skipped[0].reason)
        self.assertEqual(path.read_bytes(), b"replacement")
        quarantines = list(path.parent.glob(".isopropyl-delete-*"))
        self.assertEqual(len(quarantines), 1)
        self.assertEqual((quarantines[0] / "artifact").read_bytes(), value)

    def test_batch_preserves_success_continues_after_failure_then_deletes_next(self):
        first = resource(b"first")
        second = resource(
            b"second", family="syslinux", version="6.04", name="ldlinux.c32",
        )
        third = resource(
            b"third", family="grub", version="2.14", name="boot.img",
        )
        paths = {
            item.key: self.put(item, value)
            for item, value in ((first, b"first"), (second, b"second"), (third, b"third"))
        }
        real_fstat = os.fstat
        calls = 0

        def fail_second_artifact_final_fstat(descriptor):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise OSError("second artifact final fstat failure")
            return real_fstat(descriptor)

        catalog = BootloaderCatalog((first, second, third))
        with patch(
            "isopropyl.bootloaders.os.fstat",
            side_effect=fail_second_artifact_final_fstat,
        ):
            result = delete_cached_artifacts(
                (first.key, second.key, third.key), catalog=catalog,
            )

        self.assertEqual([item.key for item in result.deleted], [first.key, third.key])
        self.assertEqual([item.key for item in result.skipped], [second.key])
        self.assertFalse(paths[first.key].exists())
        self.assertEqual(paths[second.key].read_bytes(), b"second")
        self.assertFalse(paths[third.key].exists())

    def test_forged_catalog_path_cannot_escape_cache(self):
        forged = resource(name="../outside")
        outside = Path(self.temporary.name) / "outside"
        outside.write_bytes(b"keep")
        with self.assertRaises(CatalogError):
            inventory_cache(catalog=BootloaderCatalog((forged,)))
        with self.assertRaises(CatalogError):
            delete_cached_artifacts((forged.key,), catalog=BootloaderCatalog((forged,)))
        self.assertEqual(outside.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
