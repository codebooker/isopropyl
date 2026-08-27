# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import threading
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from isopropyl.bootloaders import (
    BootloaderCatalog, BootloaderResource, CatalogError, DependencyUnavailable,
    DownloadError, fetch_resource, installed_tool_matches, load_catalog,
    resolve_artifact, resolve_system_tool, reverify_artifact,
)


class Response(BytesIO):
    def __init__(self, value: bytes, url: str = "https://downloads.example.test/core.img"):
        super().__init__(value)
        self.url = url

    def geturl(self) -> str:
        return self.url


def resource(value: bytes = b"trusted bootloader bytes") -> BootloaderResource:
    return BootloaderResource(
        family="grub", version="2.12", name="core.img",
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


if __name__ == "__main__":
    unittest.main()
