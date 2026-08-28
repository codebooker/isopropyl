# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch

import isopropyl.linux_downloads as downloads
from isopropyl.linux_downloads import (
    LinuxDownloadCancelled, LinuxDownloadCatalogError, LinuxDownloadError,
    LinuxIsoDownloader, available_linux_images, load_linux_image_catalog,
)


_OFFICIAL_MANIFEST = b"""faabcf33ae53976d2b8207a001ff32f4e5daae013505ac7188c9ea63988f8328 *ubuntu-24.04.3-desktop-amd64.iso
c3514bf0056180d09376462a7a1b4f213c1d6e8ea67fae5c25099c6fd3d8274b *ubuntu-24.04.3-live-server-amd64.iso
c74833a55e525b1e99e1541509c566bb3e32bdb53bf27ea3347174364a57f47c *ubuntu-24.04.3-wsl-amd64.wsl
3a4c9877b483ab46d7c3fbe165a0db275e1ae3cfe56a5657e5a47c2f99a99d1e *ubuntu-24.04.4-desktop-amd64.iso
e907d92eeec9df64163a7e454cbc8d7755e8ddc7ed42f99dbc80c40f1a138433 *ubuntu-24.04.4-live-server-amd64.iso
9b2f7730dc68227dd04a9f3e5eab86ad85caf556b8606ad94f1f29ff5c4fd3f5 *ubuntu-24.04.4-wsl-amd64.wsl
"""
_OFFICIAL_SIGNATURE = base64.b64decode(
    "LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0tLS0KCmlRSXpCQUFCQ2dBZEZpRUVoRGs0M3lLTkl2"
    "ZXpkQ3ZBMlVxajhPL2lFSklGQW1tTjU3NEFDZ2tRMlVxajhPL2kKRUpLNFpRLy9lcmN0b2Z2VWdh"
    "NC9yS0l3VndOeTVSZ3p4bTM2Zjd0T2VVWjNuREdEUm1BZWJ1QXJESnJ2ZEx6MQpva2VHSWJjL1FW"
    "R25aYUJZeStsUVhHbFZpQ2k0OWY5a1REaWVkQlRqbFlkWGpGb2dEQlZzRWY0WVJLczh3UE8zCkgx"
    "WWs2NEp1WU9rY011Sml0eEZtT1BDU1lULzFBaFlLTnNJVk5HSzlCNk1wVzc1SmVLMDl6d0tnckpL"
    "aGlITGUKSEZDbjU1bS9vWkV3MVNIdGpiR3pBYktDdXVTekpvL2tMcXhsbmR3LzhDOFZ1WnNCL1FG"
    "TG85TmQzekh0WGJ6dwpGaVdHL3dEdmxoRGFpSHBVaWhZeTFKN0s4aExQWVFzRzF0emJnTm5BZmlQ"
    "bGk1aUovUGFudTZzZzRNNFJlL3ZSClh6RTg3Rkg3N0pCVGdBRWYyVCs2eXdmd2duR2wyb0Y5Z2ZS"
    "ZXZGdnlXcUNhZ1A3WUNGYnJBUGNhRERxRWhBS2QKTXN1ZWczTjVVeVZjYngrdGdzbDhyVFBlcGRX"
    "SXdsNERFODZSOU5jb1NzQ0ljaEREWnVSNXZpOVlueVliejJObwpEaWZnekF4OFRwMk9xTGc4cjNHa2wr"
    "L2NxOUtHUlhiYTJpVEZUcEJ2WDBBOGU0bUFBRXVETlBualFNRHVKb01QCkhoMks0V0dwZ25tN09jakpK"
    "N25CeXhOeGRYWjJ3bFNUbDR6cGVQRE4xRXJham05L1E5aTJTRkpmRFZRYnR2WXcKb2Q2QWNKaE1ObFNx"
    "eG1mTWxHc3hSVm9rekxveUVYUmE3OFB4cEwxV2RZSW94QXpNZ0F6TldJb0k5R2V0dCs0UgpDOUF0c3I5"
    "Wmg0OWt1dE4rdGNqcG1NS0hnQ3k2RDNDdzZwQ0ZWTEptQk5uNmNENVpBS1E9Cj1pZ0NaCi0tLS0tRU5E"
    "IFBHUCBTSUdOQVRVUkUtLS0tLQo="
)


class Response(BytesIO):
    def __init__(
        self, body: bytes, url: str, *, status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(body)
        self.url = url
        self.status = status
        self.headers = headers or {"Content-Length": str(len(body))}

    def geturl(self) -> str:
        return self.url

    def getcode(self) -> int:
        return self.status


def small_release(payload: bytes):
    original = available_linux_images()[0]
    return replace(
        original, id="ubuntu-test-desktop-amd64", filename="ubuntu-test.iso",
        size=len(payload), sha256=hashlib.sha256(payload).hexdigest(),
        image_url="https://releases.ubuntu.com/test/ubuntu-test.iso",
    )


def resume_stage(root: str | Path, release) -> Path:
    return Path(root) / downloads._verified.resume_stage_name(release)


class LinuxDownloadTests(unittest.TestCase):
    def test_bundled_catalog_is_exact_and_network_inactive(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            releases = load_linux_image_catalog()
        self.assertEqual(len(releases), 1)
        release = releases[0]
        self.assertEqual(release.id, "ubuntu-24.04.4-desktop-amd64")
        self.assertEqual(release.filename, "ubuntu-24.04.4-desktop-amd64.iso")
        self.assertEqual(release.size, 6_655_619_072)
        self.assertEqual(
            release.sha256,
            "3a4c9877b483ab46d7c3fbe165a0db275e1ae3cfe56a5657e5a47c2f99a99d1e",
        )
        self.assertEqual(release.allowed_hosts, ("releases.ubuntu.com",))
        self.assertIs(available_linux_images()[0], available_linux_images()[0])

    def test_equal_but_unbound_catalog_object_is_rejected_before_io(self):
        trusted = available_linux_images()[0]
        crafted = replace(trusted)
        self.assertEqual(crafted, trusted)
        self.assertIsNot(crafted, trusted)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / trusted.filename
            with patch.object(downloads, "_verify_release_metadata") as verify:
                with self.assertRaisesRegex(
                    LinuxDownloadCatalogError, "not an exact catalog entry",
                ):
                    LinuxIsoDownloader().download(
                        crafted, destination,
                        opener=lambda *_args, **_kwargs: self.fail("network used"),
                    )
            verify.assert_not_called()
            self.assertEqual(os.listdir(directory), [])

    def test_path_subclass_cannot_run_name_property_during_publication(self):
        release = available_linux_images()[0]
        native_path_type = type(Path())
        accessed = False

        class MutatingPath(native_path_type):
            @property
            def name(self):
                nonlocal accessed
                accessed = True
                return super().name

        with tempfile.TemporaryDirectory() as directory:
            destination = MutatingPath(directory) / release.filename
            with patch.object(downloads, "_verify_release_metadata") as verify:
                with self.assertRaisesRegex(ValueError, "exact native pathlib.Path"):
                    LinuxIsoDownloader().download(
                        release, destination,
                        opener=lambda *_args, **_kwargs: self.fail("network used"),
                    )
            self.assertFalse(accessed)
            verify.assert_not_called()
            self.assertEqual(os.listdir(directory), [])

    def test_catalog_rejects_unknown_fields_and_unsafe_urls(self):
        source = Path(downloads.__file__).parent / "data/linux-images-v1.json"
        payload = json.loads(source.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            payload["images"][0]["surprise"] = True
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(LinuxDownloadCatalogError):
                load_linux_image_catalog(path)
            del payload["images"][0]["surprise"]
            payload["images"][0]["image_url"] = "https://user@releases.ubuntu.com/image.iso"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(LinuxDownloadCatalogError):
                load_linux_image_catalog(path)

    @unittest.skipUnless(Path("/usr/bin/gpgv").is_file(), "fixed gpgv is unavailable")
    def test_bundled_key_verifies_official_pinned_manifest(self):
        release = available_linux_images()[0]
        self.assertEqual(len(_OFFICIAL_MANIFEST), release.checksums_size)
        self.assertEqual(hashlib.sha256(_OFFICIAL_MANIFEST).hexdigest(), release.checksums_sha256)
        self.assertEqual(len(_OFFICIAL_SIGNATURE), release.signature_size)
        self.assertEqual(hashlib.sha256(_OFFICIAL_SIGNATURE).hexdigest(), release.signature_sha256)
        downloads._verify_signed_manifest(
            _OFFICIAL_MANIFEST, _OFFICIAL_SIGNATURE, release.signing_fingerprint,
            deadline=time.monotonic() + 10, cancel_event=threading.Event(),
            cancel_check=None,
        )
        changed = bytearray(_OFFICIAL_MANIFEST)
        changed[0] ^= 1
        with self.assertRaises(LinuxDownloadError):
            downloads._verify_signed_manifest(
                bytes(changed), _OFFICIAL_SIGNATURE, release.signing_fingerprint,
                deadline=time.monotonic() + 10, cancel_event=threading.Event(),
                cancel_check=None,
            )

    @unittest.skipUnless(Path("/usr/bin/gpgv").is_file(), "fixed gpgv is unavailable")
    def test_exact_official_metadata_responses_verify_end_to_end(self):
        release = available_linux_images()[0]
        responses = iter((
            Response(_OFFICIAL_MANIFEST, release.checksums_url),
            Response(_OFFICIAL_SIGNATURE, release.signature_url),
        ))
        requested: list[str] = []

        def opener(request, **_kwargs):
            requested.append(request.full_url)
            return next(responses)

        downloads._verify_release_metadata(
            release, opener, deadline=time.monotonic() + 10,
            cancel_event=threading.Event(), cancel_check=None,
        )
        self.assertEqual(requested, [release.checksums_url, release.signature_url])

    def test_metadata_redirect_is_rejected_before_resume_state_exists(self):
        release = available_linux_images()[0]
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / release.filename
            redirected = Response(
                _OFFICIAL_MANIFEST,
                "https://releases.ubuntu.com/24.04.4/not-SHA256SUMS",
            )
            with self.assertRaisesRegex(LinuxDownloadError, "redirected"):
                LinuxIsoDownloader().download(
                    release, destination,
                    opener=lambda *_args, **_kwargs: redirected,
                )
            self.assertEqual(os.listdir(directory), [])

    def test_metadata_content_length_uses_bounded_decimal_parser(self):
        release = available_linux_images()[0]
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / release.filename
            response = Response(
                _OFFICIAL_MANIFEST, release.checksums_url,
                headers={"Content-Length": "9" * 21},
            )
            with self.assertRaisesRegex(LinuxDownloadError, "valid Content-Length"):
                LinuxIsoDownloader().download(
                    release, destination,
                    opener=lambda *_args, **_kwargs: response,
                )
            self.assertEqual(os.listdir(directory), [])

    def _download(self, payload: bytes, directory: str, opener, **kwargs):
        release = small_release(payload)
        destination = Path(directory) / release.filename
        with (
            patch.object(downloads, "available_linux_images", return_value=(release,)),
            patch.object(downloads, "_verify_release_metadata"),
        ):
            result = LinuxIsoDownloader().download(
                release, destination, opener=opener, **kwargs,
            )
        return release, destination, result

    def test_full_download_is_verified_published_and_cleaned(self):
        payload = b"verified Ubuntu image" * 4096
        progress: list[tuple[int, int]] = []
        with tempfile.TemporaryDirectory() as directory:
            release = small_release(payload)

            def opener(request, **_kwargs):
                self.assertEqual(request.full_url, release.image_url)
                self.assertEqual(request.get_header("Accept-encoding"), "identity")
                return Response(payload, release.image_url)

            release, destination, result = self._download(
                payload, directory, opener, progress=lambda done, total: progress.append((done, total)),
            )
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(result.path, destination)
            self.assertEqual(result.sha256, release.sha256)
            self.assertFalse(resume_stage(directory, release).exists())
            self.assertEqual(progress[-1], (len(payload), len(payload)))
            self.assertEqual([done for done, _total in progress], sorted(done for done, _total in progress))

    def test_resume_uses_exact_range_and_reconstructs_image(self):
        payload = b"0123456789" * 8192
        prefix = payload[:12345]
        with tempfile.TemporaryDirectory() as directory:
            release = small_release(payload)
            stage = resume_stage(directory, release)
            stage.mkdir(mode=0o700)
            partial = stage / "partial"
            partial.write_bytes(prefix)
            partial.chmod(0o600)

            def opener(request, **_kwargs):
                self.assertEqual(request.get_header("Range"), f"bytes={len(prefix)}-")
                body = payload[len(prefix):]
                return Response(
                    body, release.image_url, status=206,
                    headers={
                        "Content-Length": str(len(body)),
                        "Content-Range": f"bytes {len(prefix)}-{len(payload) - 1}/{len(payload)}",
                    },
                )

            _release, destination, _result = self._download(payload, directory, opener)
            self.assertEqual(destination.read_bytes(), payload)

    def test_server_ignoring_range_restarts_only_after_validating_length(self):
        payload = b"new complete image" * 4096
        updates: list[tuple[int, int]] = []
        with tempfile.TemporaryDirectory() as directory:
            release = small_release(payload)
            stage = resume_stage(directory, release)
            stage.mkdir(mode=0o700)
            (stage / "partial").write_bytes(b"old")
            (stage / "partial").chmod(0o600)
            _release, destination, _result = self._download(
                payload, directory, lambda *_args, **_kwargs: Response(payload, release.image_url),
                progress=lambda done, total: updates.append((done, total)),
            )
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(updates[0], (0, len(payload)))
            self.assertEqual([done for done, _total in updates], sorted(done for done, _total in updates))

    def test_bad_resume_range_is_rejected_without_destroying_partial(self):
        payload = b"range image" * 4096
        prefix = payload[:100]
        with tempfile.TemporaryDirectory() as directory:
            release = small_release(payload)
            stage = resume_stage(directory, release)
            stage.mkdir(mode=0o700)
            partial = stage / "partial"
            partial.write_bytes(prefix)
            partial.chmod(0o600)
            body = payload[len(prefix):]
            response = Response(
                body, release.image_url, status=206,
                headers={"Content-Length": str(len(body)), "Content-Range": "bytes 0-1/2"},
            )
            with self.assertRaisesRegex(LinuxDownloadError, "Content-Range"):
                self._download(payload, directory, lambda *_args, **_kwargs: response)
            self.assertEqual(partial.read_bytes(), prefix)
            self.assertFalse((Path(directory) / release.filename).exists())

    def test_redirect_is_rejected_and_partial_is_resumable(self):
        payload = b"redirect image" * 4096
        with tempfile.TemporaryDirectory() as directory:
            release = small_release(payload)
            response = Response(payload, "https://releases.ubuntu.com/other.iso")
            with self.assertRaisesRegex(LinuxDownloadError, "redirected"):
                self._download(payload, directory, lambda *_args, **_kwargs: response)
            partial = resume_stage(directory, release) / "partial"
            self.assertTrue(partial.exists())
            self.assertEqual(partial.stat().st_size, 0)

    def test_bad_checksum_removes_known_bad_partial(self):
        payload = b"good image" * 4096
        wrong = b"x" * len(payload)
        with tempfile.TemporaryDirectory() as directory:
            release = small_release(payload)
            with self.assertRaisesRegex(LinuxDownloadError, "checksum"):
                self._download(
                    payload, directory,
                    lambda *_args, **_kwargs: Response(wrong, release.image_url),
                )
            partial = resume_stage(directory, release) / "partial"
            self.assertFalse(partial.exists())
            self.assertFalse((Path(directory) / release.filename).exists())

    def test_existing_destination_is_refused_before_metadata_or_network(self):
        payload = b"existing"
        release = small_release(payload)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / release.filename
            destination.write_bytes(b"keep")
            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata") as verify,
            ):
                with self.assertRaisesRegex(LinuxDownloadError, "already exists"):
                    LinuxIsoDownloader().download(
                        release, destination,
                        opener=lambda *_args, **_kwargs: self.fail("network used"),
                    )
            verify.assert_not_called()
            self.assertEqual(destination.read_bytes(), b"keep")

    def test_destination_appearing_at_publish_is_never_overwritten(self):
        payload = b"publish race" * 4096
        release = small_release(payload)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / release.filename

            def raced_link(*_args, **_kwargs):
                destination.write_bytes(b"other process")
                raise FileExistsError

            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(downloads.os, "link", side_effect=raced_link),
            ):
                with self.assertRaisesRegex(LinuxDownloadError, "not overwritten"):
                    LinuxIsoDownloader().download(
                        release, destination,
                        opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                    )
            self.assertEqual(destination.read_bytes(), b"other process")

    def test_post_commit_replacement_is_outside_guarantee_and_never_unlinked(self):
        payload = b"rollback identity" * 4096
        release = small_release(payload)
        real_link = os.link
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / release.filename
            def replace_after_link(*args, **kwargs):
                real_link(*args, **kwargs)
                destination.unlink()
                destination.write_bytes(b"unrelated replacement")

            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(downloads.os, "link", side_effect=replace_after_link),
            ):
                result = LinuxIsoDownloader().download(
                    release, destination,
                    opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                )
            self.assertEqual(result.path, destination)
            self.assertEqual(destination.read_bytes(), b"unrelated replacement")
            partial = resume_stage(root, release) / "partial"
            self.assertEqual(partial.read_bytes(), payload)

    def test_signed_metadata_failure_does_not_create_resume_state(self):
        payload = b"metadata first"
        release = small_release(payload)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / release.filename
            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(
                    downloads, "_verify_release_metadata",
                    side_effect=LinuxDownloadError("bad signature"),
                ),
            ):
                with self.assertRaisesRegex(LinuxDownloadError, "bad signature"):
                    LinuxIsoDownloader().download(release, destination)
            self.assertEqual(os.listdir(directory), [])

    def test_cancellation_and_caller_exception_are_authoritative_before_disk_touch(self):
        payload = b"cancel"
        release = small_release(payload)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / release.filename
            downloader = LinuxIsoDownloader()
            downloader.cancel()
            with patch.object(downloads, "available_linux_images", return_value=(release,)):
                with self.assertRaises(LinuxDownloadCancelled):
                    downloader.download(release, destination)
            self.assertEqual(os.listdir(directory), [])

            class CallerCancelled(Exception):
                pass

            with patch.object(downloads, "available_linux_images", return_value=(release,)):
                with self.assertRaises(CallerCancelled):
                    LinuxIsoDownloader().download(
                        release, destination,
                        cancel_check=lambda: (_ for _ in ()).throw(CallerCancelled()),
                    )
            self.assertEqual(os.listdir(directory), [])

    def test_final_full_reread_catches_mutation_of_already_hashed_bytes(self):
        payload = b"immutable at publish" * 4096
        release = small_release(payload)
        real_download = downloads._download_image

        def mutate_after_running_digest(*args, **kwargs):
            result = real_download(*args, **kwargs)
            os.pwrite(args[1], b"X", 0)
            return result

        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(downloads, "_download_image", side_effect=mutate_after_running_digest),
            ):
                with self.assertRaisesRegex(LinuxDownloadError, "final signed SHA-256"):
                    LinuxIsoDownloader().download(
                        release, Path(directory) / release.filename,
                        opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                    )
            self.assertFalse((Path(directory) / release.filename).exists())

    def test_internal_cancel_after_verifier_return_does_not_interrupt_commit(self):
        payload = b"late cancellation" * 4096
        release = small_release(payload)
        downloader = LinuxIsoDownloader()
        real_verify = downloads._verify_completed_partial

        def cancel_after_verify(*args, **kwargs):
            result = real_verify(*args, **kwargs)
            downloader.cancel()
            return result

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / release.filename
            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(downloads, "_verify_completed_partial", side_effect=cancel_after_verify),
            ):
                result = downloader.download(
                    release, destination,
                    opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                )
            self.assertTrue(downloader.cancelled)
            self.assertEqual(result.path, destination)
            self.assertEqual(destination.read_bytes(), payload)

    def test_event_override_never_runs_between_verifier_return_and_link(self):
        payload = b"no event final gap" * 4096
        release = small_release(payload)
        real_verify = downloads._verify_completed_partial
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / release.filename
            partial = resume_stage(root, release) / "partial"

            class MutatingEvent(threading.Event):
                armed = False
                mutated = False

                def is_set(self):
                    if self.armed:
                        with partial.open("r+b") as stream:
                            stream.write(b"X")
                            stream.flush()
                            os.fsync(stream.fileno())
                        self.mutated = True
                    return super().is_set()

            event = MutatingEvent()

            def arm_after_verifier(*args, **kwargs):
                result = real_verify(*args, **kwargs)
                event.armed = True
                return result

            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(
                    downloads, "_verify_completed_partial",
                    side_effect=arm_after_verifier,
                ),
            ):
                result = LinuxIsoDownloader(event).download(
                    release, destination,
                    opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                )
            self.assertTrue(event.armed)
            self.assertFalse(event.mutated)
            self.assertEqual(result.path, destination)
            self.assertEqual(destination.read_bytes(), payload)

    def test_same_inode_mutation_before_link_is_never_published(self):
        payload = b"pre-link mutation" * 4096
        release = small_release(payload)
        real_revalidate = downloads._revalidate_directory
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / release.filename
            partial = resume_stage(root, release) / "partial"
            calls = 0

            def mutate_before_link(path, descriptor):
                nonlocal calls
                calls += 1
                result = real_revalidate(path, descriptor)
                if calls == 1:
                    with partial.open("r+b") as stream:
                        stream.write(b"X")
                        stream.flush()
                        os.fsync(stream.fileno())
                return result

            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(downloads, "_revalidate_directory", side_effect=mutate_before_link),
                patch.object(downloads.os, "link") as link,
            ):
                with self.assertRaisesRegex(LinuxDownloadError, "final signed SHA-256"):
                    LinuxIsoDownloader().download(
                        release, destination,
                        opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                    )
            link.assert_not_called()
            self.assertFalse(destination.exists())

    def test_callback_mutation_at_verifier_posthash_check_is_detected(self):
        payload = b"callback verifier mutation" * 4096
        release = small_release(payload)
        real_hash = downloads._hash_partial
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / release.filename
            partial = resume_stage(root, release) / "partial"
            final_hash_finished = False
            mutated = False

            def mark_final_hash(*args, **kwargs):
                nonlocal final_hash_finished
                result = real_hash(*args, **kwargs)
                if args[1] == len(payload):
                    final_hash_finished = True
                return result

            def mutate_from_callback():
                nonlocal mutated
                if final_hash_finished and not mutated:
                    with partial.open("r+b") as stream:
                        stream.write(b"X")
                        stream.flush()
                        os.fsync(stream.fileno())
                    mutated = True

            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(downloads, "_hash_partial", side_effect=mark_final_hash),
            ):
                with self.assertRaisesRegex(LinuxDownloadError, "during final verification"):
                    LinuxIsoDownloader().download(
                        release, destination, cancel_check=mutate_from_callback,
                        opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                    )
            self.assertTrue(mutated)
            self.assertFalse(destination.exists())
            self.assertEqual(partial.read_bytes()[:1], b"X")

    def test_caller_callback_never_runs_between_verified_return_and_link(self):
        payload = b"no callback final gap" * 4096
        release = small_release(payload)
        real_verify = downloads._verify_completed_partial
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / release.filename
            partial = resume_stage(root, release) / "partial"
            verifier_returned = False
            mutated = False

            def mark_verifier_return(*args, **kwargs):
                nonlocal verifier_returned
                result = real_verify(*args, **kwargs)
                verifier_returned = True
                return result

            def mutate_if_called_in_gap():
                nonlocal mutated
                if verifier_returned:
                    with partial.open("r+b") as stream:
                        stream.write(b"X")
                        stream.flush()
                        os.fsync(stream.fileno())
                    mutated = True

            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(
                    downloads, "_verify_completed_partial",
                    side_effect=mark_verifier_return,
                ),
            ):
                result = LinuxIsoDownloader().download(
                    release, destination, cancel_check=mutate_if_called_in_gap,
                    opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                )
            self.assertTrue(verifier_returned)
            self.assertFalse(mutated)
            self.assertEqual(result.path, destination)
            self.assertEqual(destination.read_bytes(), payload)

    def test_same_inode_mutation_after_commit_is_outside_guarantee(self):
        payload = b"post-link mutation" * 4096
        release = small_release(payload)
        real_link = os.link
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / release.filename

            def link_then_mutate(*args, **kwargs):
                real_link(*args, **kwargs)
                with destination.open("r+b") as stream:
                    stream.write(b"X")
                    stream.flush()
                    os.fsync(stream.fileno())

            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(downloads.os, "link", side_effect=link_then_mutate),
            ):
                result = LinuxIsoDownloader().download(
                    release, destination,
                    opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                )
            self.assertEqual(result.path, destination)
            self.assertTrue(destination.exists())
            self.assertEqual(destination.read_bytes()[:1], b"X")

    def test_post_commit_private_cleanup_failure_still_returns_verified_result(self):
        payload = b"cleanup failure" * 4096
        release = small_release(payload)
        real_unlink = os.unlink
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / release.filename

            def fail_private_unlink(path, *args, **kwargs):
                if path == "partial":
                    raise OSError("simulated cleanup failure")
                return real_unlink(path, *args, **kwargs)

            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(downloads.os, "unlink", side_effect=fail_private_unlink),
            ):
                result = LinuxIsoDownloader().download(
                    release, destination,
                    opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                )
            self.assertEqual(result.path, destination)
            self.assertEqual(destination.read_bytes(), payload)
            partial = resume_stage(root, release) / "partial"
            self.assertTrue(partial.exists())
            self.assertEqual(destination.stat().st_ino, partial.stat().st_ino)

    def test_cancellation_after_atomic_commit_does_not_turn_success_into_failure(self):
        payload = b"committed cancellation" * 4096
        release = small_release(payload)
        downloader = LinuxIsoDownloader()
        real_link = os.link
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / release.filename

            def commit_then_cancel(*args, **kwargs):
                real_link(*args, **kwargs)
                downloader.cancel()

            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(downloads.os, "link", side_effect=commit_then_cancel),
            ):
                result = downloader.download(
                    release, destination,
                    opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                )
            self.assertTrue(downloader.cancelled)
            self.assertEqual(result.path, destination)
            self.assertEqual(destination.read_bytes(), payload)

    def test_cancel_during_final_prelink_reread_preserves_complete_partial(self):
        payload = b"cancel final reread" * 4096
        release = small_release(payload)
        downloader = LinuxIsoDownloader()
        real_hash = downloads._hash_partial
        calls = 0

        def cancel_second_hash(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                downloader.cancel()
            return real_hash(*args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / release.filename
            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(downloads, "_hash_partial", side_effect=cancel_second_hash),
            ):
                with self.assertRaises(LinuxDownloadCancelled):
                    downloader.download(
                        release, destination,
                        opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                    )
            self.assertFalse(destination.exists())
            partial = resume_stage(root, release) / "partial"
            self.assertEqual(partial.read_bytes(), payload)

    def test_read_error_during_final_prelink_reread_preserves_complete_partial(self):
        payload = b"failed final reread" * 4096
        release = small_release(payload)
        real_hash = downloads._hash_partial
        calls = 0

        def fail_second_hash(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated read failure")
            return real_hash(*args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / release.filename
            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(downloads, "_hash_partial", side_effect=fail_second_hash),
            ):
                with self.assertRaisesRegex(LinuxDownloadError, "read failure"):
                    LinuxIsoDownloader().download(
                        release, destination,
                        opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                    )
            self.assertFalse(destination.exists())
            partial = resume_stage(root, release) / "partial"
            self.assertEqual(partial.read_bytes(), payload)

    def test_deadline_during_final_prelink_reread_preserves_complete_partial(self):
        payload = b"deadline final reread" * 4096
        release = small_release(payload)
        real_hash = downloads._hash_partial
        calls = 0

        def expire_second_hash(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                kwargs["deadline"] = time.monotonic() - 1
            return real_hash(*args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / release.filename
            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(downloads, "_hash_partial", side_effect=expire_second_hash),
            ):
                with self.assertRaisesRegex(LinuxDownloadError, "time limit"):
                    LinuxIsoDownloader().download(
                        release, destination,
                        opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                    )
            self.assertFalse(destination.exists())
            partial = resume_stage(root, release) / "partial"
            self.assertEqual(partial.read_bytes(), payload)

    def test_default_transport_installs_no_redirect_handler(self):
        request = urllib.request.Request("https://releases.ubuntu.com/fixed")
        built = Mock()
        built.open.return_value = object()
        with patch.object(urllib.request, "build_opener", return_value=built) as factory:
            result = downloads._default_urlopen(request, timeout=3)
        self.assertIs(result, built.open.return_value)
        self.assertTrue(
            any(isinstance(item, downloads._RejectRedirectHandler) for item in factory.call_args.args)
        )
        built.open.assert_called_once_with(request, timeout=3)
        handler = downloads._RejectRedirectHandler()
        with self.assertRaises(urllib.error.HTTPError) as raised:
            handler.redirect_request(
                request, None, 302, "Found", {}, "https://evil.example/bounce",
            )
        raised.exception.close()

    def test_cancelled_connect_has_no_owned_daemon_worker(self):
        payload = b"connect lifecycle" * 4096
        release = small_release(payload)
        downloader = LinuxIsoDownloader()
        entered = threading.Event()
        release_call = threading.Event()
        errors: list[BaseException] = []
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / release.filename

            def blocked_opener(*_args, **_kwargs):
                entered.set()
                release_call.wait(2)
                return Response(payload, release.image_url)

            def run():
                try:
                    downloader.download(release, destination, opener=blocked_opener)
                except BaseException as error:
                    errors.append(error)

            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
            ):
                worker = threading.Thread(target=run, name="linux-download-test")
                worker.start()
                self.assertTrue(entered.wait(2))
                downloader.cancel()
                release_call.set()
                worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], LinuxDownloadCancelled)
            self.assertFalse(any(
                thread.name in {"isopropyl-linux-connect", "isopropyl-linux-read"}
                for thread in threading.enumerate()
            ))

    def test_cancelled_read_has_no_owned_daemon_worker(self):
        payload = b"read lifecycle" * 4096
        release = small_release(payload)
        downloader = LinuxIsoDownloader()
        entered = threading.Event()
        release_call = threading.Event()
        errors: list[BaseException] = []

        class BlockedRead(Response):
            def read(self, size=-1):
                entered.set()
                release_call.wait(2)
                return super().read(size)

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / release.filename

            def run():
                try:
                    downloader.download(
                        release, destination,
                        opener=lambda *_args, **_kwargs: BlockedRead(
                            payload, release.image_url,
                        ),
                    )
                except BaseException as error:
                    errors.append(error)

            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
            ):
                worker = threading.Thread(target=run, name="linux-read-test")
                worker.start()
                self.assertTrue(entered.wait(2))
                downloader.cancel()
                release_call.set()
                worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], LinuxDownloadCancelled)
            self.assertFalse(any(
                thread.name in {"isopropyl-linux-connect", "isopropyl-linux-read"}
                for thread in threading.enumerate()
            ))

    def test_post_hash_stage_swap_cannot_redirect_cleanup_or_fail_commit(self):
        payload = b"stage identity" * 4096
        release = small_release(payload)
        real_verify = downloads._verify_completed_partial
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = resume_stage(root, release)
            moved = root / "moved-stage"

            def swap_stage(*args, **kwargs):
                result = real_verify(*args, **kwargs)
                stage.rename(moved)
                stage.mkdir(mode=0o700)
                return result

            with (
                patch.object(downloads, "available_linux_images", return_value=(release,)),
                patch.object(downloads, "_verify_release_metadata"),
                patch.object(downloads, "_verify_completed_partial", side_effect=swap_stage),
            ):
                result = LinuxIsoDownloader().download(
                    release, root / release.filename,
                    opener=lambda *_args, **_kwargs: Response(payload, release.image_url),
                )
            self.assertEqual(result.path.read_bytes(), payload)
            self.assertTrue(stage.is_dir())
            self.assertTrue(moved.is_dir())

    def test_symlink_or_hardlinked_partial_is_rejected(self):
        payload = b"partial safety" * 4096
        release = small_release(payload)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = resume_stage(root, release)
            stage.mkdir(mode=0o700)
            outside = root / "outside"
            outside.write_bytes(b"keep")
            (stage / "partial").symlink_to(outside)
            with self.assertRaisesRegex(LinuxDownloadError, "unsafe"):
                self._download(payload, directory, lambda *_args, **_kwargs: self.fail("network"))
            self.assertEqual(outside.read_bytes(), b"keep")
            (stage / "partial").unlink()
            (stage / "partial").write_bytes(b"part")
            (stage / "partial").chmod(0o600)
            os.link(stage / "partial", root / "alias")
            with self.assertRaisesRegex(LinuxDownloadError, "unsafe"):
                self._download(payload, directory, lambda *_args, **_kwargs: self.fail("network"))


if __name__ == "__main__":
    unittest.main()
