# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import uuid
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import isopropyl.windows_downloads as downloads
from isopropyl.windows_downloads import (
    DownloadedWindowsImage,
    MicrosoftWindowsResolver, WindowsDownloadCancelled,
    WindowsDownloadCatalogError, WindowsDownloadError,
    WindowsIsoDownloader, available_windows_images, load_windows_image_catalog,
    validate_microsoft_download_url,
)


NOW = dt.datetime(2026, 8, 28, 12, 0, tzinfo=dt.timezone.utc)
SESSION = uuid.UUID("11111111-2222-4333-8444-555555555555")
TOKEN = "secret-capability-token"


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


def sku_document(release=None) -> bytes:
    release = release or available_windows_images()[0]
    return json.dumps(
        {
            "Skus": [
                {
                    "Id": release.sku_id,
                    "Language": release.language_id,
                    "LocalizedLanguage": release.language,
                    "LocalizedProductDisplayName": release.localized_product_display_name,
                    "ProductDisplayName": release.product_display_name,
                },
                {
                    "Id": "29999",
                    "Language": "French",
                    "LocalizedLanguage": "French",
                    "LocalizedProductDisplayName": "Windows 11  French",
                    "ProductDisplayName": release.product_display_name,
                },
            ],
            "ValidationContainer": {},
        },
        separators=(",", ":"),
    ).encode()


def image_url(
    release=None, *,
    query=(
        "t=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee&P1=1788004800&"
        "P2=602&P3=2&P4=0123456789abcdef0123456789abcdef"
    ),
) -> str:
    release = release or available_windows_images()[0]
    return f"https://software.download.prss.microsoft.com{release.image_path}?{query}"


def link_document(release=None, *, uri: str | None = None, expiry: object = None) -> bytes:
    release = release or available_windows_images()[0]
    uri = uri or image_url(release)
    if expiry is None:
        expiry = "2026-08-29T12:00:00Z"
    option = {
        "Name": release.filename,
        "Uri": uri,
        "ProductDisplayName": release.product_display_name,
        "Language": release.language_id,
        "LocalizedLanguage": release.language,
        "LocalizedProductDisplayName": release.localized_product_display_name,
        "DownloadType": 1,
    }
    return json.dumps(
        {
            "DownloadExpirationDatetime": expiry,
            "ProductDownload": {"Uri": uri, "DownloadType": 1},
            "ProductDownloadOptions": [option],
            "ValidationContainer": {},
        },
        separators=(",", ":"),
    ).encode()


def successful_opener(release=None):
    release = release or available_windows_images()[0]
    bodies = [
        b"tag-ok",
        b"payload?w=ABCDEF0123&x=1;rticks\\=\\\"+123456789",
        b"reply-ok",
        sku_document(release),
        link_document(release),
    ]
    requests = []

    def open_url(request, *, timeout):
        requests.append((request, timeout))
        body = bodies.pop(0)
        return Response(body, request.full_url)

    return open_url, requests, bodies


def provenance_opener(release=None, *, sha256: str | None = None):
    release = release or available_windows_images()[0]
    digest = sha256 or release.sha256
    body = (
        f'<select><option value="{release.product_edition_id}">Windows 11</option>'
        f'</select><table><tr><td>English 64-bit</td><td>{digest.upper()}</td>'
        f'</tr></table>'
    ).encode()
    calls = []

    def open_url(request, *, timeout):
        calls.append(request)
        return Response(body, request.full_url)

    return open_url, calls


def small_release(payload: bytes):
    return replace(
        available_windows_images()[0], id="windows-test-english-x64",
        filename="windows-test.iso", image_path="/dbazure/windows-test.iso",
        size=len(payload), sha256=hashlib.sha256(payload).hexdigest(),
    )


def resume_stage(root: str | Path, release) -> Path:
    return Path(root) / downloads._verified.resume_stage_name(release)


class WindowsCatalogTests(unittest.TestCase):
    def test_bundled_catalog_is_exact_and_network_inactive(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            releases = load_windows_image_catalog()
        self.assertEqual(len(releases), 1)
        release = releases[0]
        self.assertEqual(release.id, "windows-11-25h2-v2-english-x64")
        self.assertEqual(release.filename, "Win11_25H2_English_x64_v2.iso")
        self.assertEqual(release.size, 8_471_603_200)
        self.assertEqual(
            release.sha256,
            "768984706b909479417b2368438909440f2967ff05c6a9195ed2667254e465e3",
        )
        self.assertEqual(release.product_edition_id, "3321")
        self.assertEqual(release.sku_id, "20046")
        self.assertEqual(
            release.image_hosts, ("software.download.prss.microsoft.com",)
        )
        self.assertIs(available_windows_images()[0], available_windows_images()[0])

    def test_catalog_rejects_unknown_missing_and_unsafe_fields(self):
        source = Path(downloads.__file__).with_name("data") / "windows-images-v1.json"
        original = json.loads(source.read_text())
        cases = []
        changed = json.loads(json.dumps(original)); changed["surprise"] = True
        cases.append(changed)
        changed = json.loads(json.dumps(original)); del changed["images"][0]["sha256"]
        cases.append(changed)
        changed = json.loads(json.dumps(original)); changed["images"][0]["filename"] = "../bad.iso"
        cases.append(changed)
        changed = json.loads(json.dumps(original)); changed["images"][0]["sha256"] = "0" * 63
        cases.append(changed)
        changed = json.loads(json.dumps(original)); changed["images"][0]["size"] = True
        cases.append(changed)
        changed = json.loads(json.dumps(original)); changed["images"][0]["metadata_hosts"].append("evil.example")
        cases.append(changed)
        changed = json.loads(json.dumps(original)); changed["images"][0]["provenance_url"] += "?mutable=1"
        cases.append(changed)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            for value in cases:
                with self.subTest(value=value):
                    path.write_text(json.dumps(value))
                    with self.assertRaises(WindowsDownloadCatalogError):
                        load_windows_image_catalog(path)


class MicrosoftResolverTests(unittest.TestCase):
    def setUp(self):
        self.release = available_windows_images()[0]

    def resolve(self, opener):
        return MicrosoftWindowsResolver().resolve(
            self.release, opener=opener, session_id=SESSION, now=NOW,
        )

    def test_equal_but_unbound_release_is_rejected_before_io(self):
        crafted = replace(self.release)
        self.assertEqual(crafted, self.release)
        self.assertIsNot(crafted, self.release)
        with self.assertRaisesRegex(
            WindowsDownloadCatalogError, "not an exact catalog entry"
        ):
            MicrosoftWindowsResolver().resolve(
                crafted, opener=lambda *_a, **_k: self.fail("network used")
            )

    def test_fixed_request_sequence_resolves_only_pinned_source(self):
        opener, requests, remaining = successful_opener(self.release)
        result = self.resolve(opener)
        self.assertEqual(result.url, image_url(self.release))
        self.assertEqual(result.expires_at, NOW + dt.timedelta(days=1))
        self.assertEqual(remaining, [])
        self.assertEqual(len(requests), 5)
        urls = [request.full_url for request, _ in requests]
        self.assertEqual(
            [downloads.urllib.parse.urlsplit(value).hostname for value in urls],
            [
                "vlscppe.microsoft.com", "ov-df.microsoft.com",
                "ov-df.microsoft.com", "www.microsoft.com", "www.microsoft.com",
            ],
        )
        self.assertTrue(all(request.get_method() == "GET" for request, _ in requests))
        self.assertTrue(all(request.get_header("Accept-encoding") == "identity" for request, _ in requests))
        self.assertIsNone(requests[3][0].get_header("Referer"))
        self.assertEqual(requests[4][0].get_header("Referer"), downloads._REFERER)
        self.assertIn("productEditionId=3321", urls[3])
        self.assertIn("SKU=20046", urls[4])
        self.assertNotIn(TOKEN, "\n".join(urls))

    def test_remote_challenge_is_never_executed(self):
        opener, _, bodies = successful_opener(self.release)
        poison = b"__import__('pathlib').Path('/tmp/isopropyl-executed').touch();?w=AA&rticks\\=\\\"+1"
        bodies[1] = poison

        marker = Path("/tmp/isopropyl-executed")
        if marker.exists():
            marker.unlink()
        self.resolve(opener)
        self.assertFalse(marker.exists())

    def test_cancelled_before_resolution_makes_no_request(self):
        event = threading.Event(); event.set()
        with self.assertRaises(WindowsDownloadCancelled):
            MicrosoftWindowsResolver(event).resolve(
                self.release, opener=lambda *_a, **_k: self.fail("network used")
            )

    def test_redirect_compression_and_excess_metadata_fail_closed(self):
        variants = (
            lambda request: Response(b"ok", request.full_url + "&redirected=1"),
            lambda request: Response(
                b"ok", request.full_url,
                headers={"Content-Length": "2", "Content-Encoding": "gzip"},
            ),
            lambda request: Response(
                b"", request.full_url,
                headers={"Content-Length": str(65 * 1024)},
            ),
        )
        for first in variants:
            with self.subTest(first=first):
                with self.assertRaises(WindowsDownloadError):
                    self.resolve(lambda request, *, timeout: first(request))

    def test_connection_error_never_leaks_url_or_capability(self):
        secret = f"https://example.invalid/file.iso?t={TOKEN}"

        def fail(*_args, **_kwargs):
            raise urllib.error.URLError(secret)

        with self.assertRaises(WindowsDownloadError) as raised:
            self.resolve(fail)
        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertNotIn("example.invalid", str(raised.exception))

    def test_language_schema_and_identity_are_strict(self):
        valid = json.loads(sku_document(self.release))
        cases = []
        changed = json.loads(json.dumps(valid)); changed["unknown"] = 1
        cases.append(changed)
        changed = json.loads(json.dumps(valid)); changed["Skus"][0]["unknown"] = 1
        cases.append(changed)
        changed = json.loads(json.dumps(valid)); changed["Skus"].append(changed["Skus"][0])
        cases.append(changed)
        changed = json.loads(json.dumps(valid)); changed["Skus"][0]["ProductDisplayName"] = "Windows 11 future"
        cases.append(changed)
        changed = {"Errors": [{"Value": TOKEN}]}
        cases.append(changed)
        for document in cases:
            with self.subTest(document=document):
                opener, _, bodies = successful_opener(self.release)
                bodies[3] = json.dumps(document).encode()
                with self.assertRaises(WindowsDownloadError) as raised:
                    self.resolve(opener)
                self.assertNotIn(TOKEN, str(raised.exception))

    def test_link_schema_cannot_change_pinned_identity(self):
        valid = json.loads(link_document(self.release))
        cases = []
        changed = json.loads(json.dumps(valid)); changed["unknown"] = 1
        cases.append(changed)
        changed = json.loads(json.dumps(valid)); changed["ProductDownloadOptions"][0]["unknown"] = 1
        cases.append(changed)
        changed = json.loads(json.dumps(valid)); changed["ProductDownloadOptions"].append(changed["ProductDownloadOptions"][0])
        cases.append(changed)
        changed = json.loads(json.dumps(valid)); changed["ProductDownloadOptions"][0]["Language"] = "French"
        cases.append(changed)
        changed = json.loads(json.dumps(valid)); changed["ProductDownloadOptions"][0]["DownloadType"] = 2
        cases.append(changed)
        changed = {"Errors": [{"Value": TOKEN}]}
        cases.append(changed)
        for document in cases:
            with self.subTest(document=document):
                opener, _, bodies = successful_opener(self.release)
                bodies[4] = json.dumps(document).encode()
                with self.assertRaises(WindowsDownloadError) as raised:
                    self.resolve(opener)
                self.assertNotIn(TOKEN, str(raised.exception))

    def test_ephemeral_url_validation_rejects_ambiguous_or_unpinned_urls(self):
        unsafe = (
            image_url(self.release).replace("https://", "http://"),
            image_url(self.release).replace(
                "software.download.prss.microsoft.com", "evil.example"
            ),
            image_url(self.release).replace("https://", "https://user@"),
            image_url(self.release).replace(".com/", ".com:444/"),
            image_url(self.release) + "#fragment",
            image_url(self.release).replace("/dbazure/", "/other/"),
            image_url(self.release).replace("Win11", "%57in11"),
            image_url(self.release).split("?", 1)[0],
            image_url(self.release, query="x=" + "a" * 2049),
        )
        for uri in unsafe:
            with self.subTest(uri=uri[:100]):
                opener, _, bodies = successful_opener(self.release)
                bodies[4] = link_document(self.release, uri=uri)
                with self.assertRaisesRegex(WindowsDownloadError, "unsafe download URL"):
                    self.resolve(opener)

    def test_expiry_must_be_future_bounded_utc(self):
        invalid = (
            "not-a-time", "2026-08-28T12:01:00Z", "2026-08-30T12:01:00Z",
            "2026-08-29T12:00:00", 123,
        )
        for expiry in invalid:
            with self.subTest(expiry=expiry):
                opener, _, bodies = successful_opener(self.release)
                bodies[4] = link_document(self.release, expiry=expiry)
                with self.assertRaisesRegex(WindowsDownloadError, "expiry"):
                    self.resolve(opener)

    def test_http_error_token_is_closed_and_redacted(self):
        error = urllib.error.HTTPError(
            f"https://example.invalid/file?t={TOKEN}", 403, "Forbidden", {}, BytesIO()
        )
        with self.assertRaises(WindowsDownloadError) as raised:
            self.resolve(lambda *_a, **_k: (_ for _ in ()).throw(error))
        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertTrue(error.fp is None or error.fp.closed)

    def test_browser_assisted_url_validator_accepts_only_current_bound_capability(self):
        result = validate_microsoft_download_url(
            self.release, image_url(self.release), now=NOW,
        )
        self.assertEqual(result.url, image_url(self.release))
        self.assertEqual(result.expires_at, NOW + dt.timedelta(days=1))

    def test_browser_assisted_url_rejects_duplicate_missing_or_changed_parameters(self):
        base = image_url(self.release).split("?", 1)[0]
        queries = (
            "t=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee&P1=1788004800&P2=602&P3=2",
            "t=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee&P1=1788004800&P2=602&P3=2&P4="
            "0123456789abcdef0123456789abcdef&P4=duplicate-value-here",
            "t=not-a-uuid&P1=1788004800&P2=602&P3=2&P4=0123456789abcdef0123456789abcdef",
            "t=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee&P1=1788004800&P2=999&P3=2&P4="
            "0123456789abcdef0123456789abcdef",
            "t=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee&P1=1788004800&P2=602&P3=9&P4="
            "0123456789abcdef0123456789abcdef",
        )
        for query in queries:
            with self.subTest(query=query):
                with self.assertRaises(WindowsDownloadError):
                    validate_microsoft_download_url(
                        self.release, f"{base}?{query}", now=NOW,
                    )


class WindowsIsoDownloaderTests(unittest.TestCase):
    def test_browser_assisted_download_hashes_and_atomically_publishes(self):
        payload = b"pinned Windows installer ISO fixture"
        release = small_release(payload)
        url = image_url(release)
        requests = []

        def opener(request, *, timeout):
            requests.append(request)
            return Response(
                payload, request.full_url,
                headers={"Content-Length": str(len(payload))},
            )

        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_windows_images", return_value=(release,),
        ):
            destination = Path(directory) / release.filename
            page, page_calls = provenance_opener(release)
            result = WindowsIsoDownloader().download(
                release, destination, source_url=url, opener=opener, now=NOW,
                provenance_opener=page,
            )
            self.assertEqual(
                result,
                DownloadedWindowsImage(
                    destination, release.id, release.size, release.sha256,
                ),
            )
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0].full_url, url)
            self.assertEqual(requests[0].get_header("Accept-encoding"), "identity")
            self.assertNotIn("Referer", requests[0].headers)
            self.assertNotIn("Cookie", requests[0].headers)
            self.assertNotIn(TOKEN, repr(result))
            self.assertEqual(
                [request.full_url for request in page_calls],
                [release.provenance_url],
            )

    def test_automatic_resolver_is_bound_before_stage_creation(self):
        payload = b"resolved ISO"
        release = small_release(payload)
        url = image_url(release)
        observed = []

        def resolved(_resolver, selected, **kwargs):
            observed.append((selected, kwargs["now"]))
            return downloads.ResolvedWindowsSource(
                url, NOW + dt.timedelta(days=1)
            )

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(downloads, "available_windows_images", return_value=(release,)),
            patch.object(downloads.MicrosoftWindowsResolver, "resolve", new=resolved),
        ):
            destination = Path(directory) / release.filename
            page, _ = provenance_opener(release)
            result = WindowsIsoDownloader().download(
                release, destination, now=NOW,
                provenance_opener=page,
                opener=lambda request, *, timeout: Response(
                    payload, request.full_url,
                    headers={"Content-Length": str(len(payload))},
                ),
            )
        self.assertEqual(observed, [(release, NOW)])
        self.assertEqual(result.sha256, release.sha256)

    def test_resume_rehashes_partial_and_uses_fresh_url_exact_range(self):
        payload = b"0123456789abcdef"
        release = small_release(payload)
        fresh = image_url(
            release,
            query=(
                "t=bbbbbbbb-cccc-4ddd-8eee-ffffffffffff&P1=1788004800&"
                "P2=602&P3=2&P4=abcdef0123456789abcdef0123456789"
            ),
        )
        requests = []
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_windows_images", return_value=(release,),
        ):
            destination = Path(directory) / release.filename
            stage = resume_stage(directory, release)
            stage.mkdir(mode=0o700)
            partial = stage / "partial"
            partial.write_bytes(payload[:6]); partial.chmod(0o600)

            def opener(request, *, timeout):
                requests.append(request)
                body = payload[6:]
                return Response(
                    body, request.full_url, status=206,
                    headers={
                        "Content-Length": str(len(body)),
                        "Content-Range": f"bytes 6-{len(payload) - 1}/{len(payload)}",
                    },
                )

            WindowsIsoDownloader().download(
                release, destination, source_url=fresh, opener=opener, now=NOW,
                provenance_opener=provenance_opener(release)[0],
            )
            self.assertEqual(destination.read_bytes(), payload)
        self.assertEqual(requests[0].full_url, fresh)
        self.assertEqual(requests[0].get_header("Range"), "bytes=6-")

    def test_wrong_hash_never_publishes_and_removes_known_bad_partial(self):
        payload = b"expected bytes"
        release = small_release(payload)
        wrong = b"corrupted byte"
        self.assertEqual(len(wrong), len(payload))
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_windows_images", return_value=(release,),
        ):
            destination = Path(directory) / release.filename
            stage = resume_stage(directory, release)
            with self.assertRaisesRegex(WindowsDownloadError, "SHA-256"):
                WindowsIsoDownloader().download(
                    release, destination, source_url=image_url(release), now=NOW,
                    provenance_opener=provenance_opener(release)[0],
                    opener=lambda request, *, timeout: Response(
                        wrong, request.full_url,
                        headers={"Content-Length": str(len(wrong))},
                    ),
                )
            self.assertFalse(destination.exists())
            self.assertFalse((stage / "partial").exists())

    def test_expired_manual_url_fails_before_resume_state_is_created(self):
        payload = b"fixture"
        release = small_release(payload)
        expired = image_url(release).replace("P1=1788004800", "P1=1787918400")
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_windows_images", return_value=(release,),
        ):
            destination = Path(directory) / release.filename
            with self.assertRaisesRegex(WindowsDownloadError, "expiry"):
                WindowsIsoDownloader().download(
                    release, destination, source_url=expired, now=NOW,
                    opener=lambda *_a, **_k: self.fail("CDN network used"),
                )
            self.assertEqual(os.listdir(directory), [])

    def test_cdn_error_does_not_expose_capability(self):
        payload = b"fixture"
        release = small_release(payload)
        url = image_url(release)

        def fail(request, *, timeout):
            raise urllib.error.HTTPError(
                request.full_url, 403, "expired", {}, BytesIO()
            )

        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_windows_images", return_value=(release,),
        ):
            destination = Path(directory) / release.filename
            with self.assertRaises(WindowsDownloadError) as raised:
                WindowsIsoDownloader().download(
                    release, destination, source_url=url, now=NOW, opener=fail,
                    provenance_opener=provenance_opener(release)[0],
                )
        self.assertNotIn("P4=", str(raised.exception))
        self.assertNotIn("aaaaaaaa-bbbb", str(raised.exception))

    def test_current_microsoft_hash_drift_fails_before_resume_state(self):
        payload = b"fixture"
        release = small_release(payload)
        wrong_page, _ = provenance_opener(release, sha256="f" * 64)
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_windows_images", return_value=(release,),
        ):
            destination = Path(directory) / release.filename
            with self.assertRaisesRegex(WindowsDownloadError, "no longer matches"):
                WindowsIsoDownloader().download(
                    release, destination, source_url=image_url(release), now=NOW,
                    provenance_opener=wrong_page,
                    opener=lambda *_a, **_k: self.fail("CDN network used"),
                )
            self.assertEqual(os.listdir(directory), [])


if __name__ == "__main__":
    unittest.main()
