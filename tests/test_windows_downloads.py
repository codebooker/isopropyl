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
    validate_microsoft_download_url, windows_inspection_matches_release,
)
from isopropyl.images import ImageInspection


NOW = dt.datetime(2026, 8, 28, 12, 0, tzinfo=dt.timezone.utc)
SESSION = uuid.UUID("11111111-2222-4333-8444-555555555555")
TOKEN = "secret-capability-token"
OBSERVATIONS_PATH = Path(__file__).with_name(
    "windows-profile-observations-v1.json"
)


def release_for(architecture: str):
    matches = tuple(
        release for release in available_windows_images()
        if release.architecture == architecture
    )
    if len(matches) != 1:
        raise AssertionError(f"expected one {architecture} Windows catalog entry")
    return matches[0]


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
    download_type = downloads._WINDOWS_DOWNLOAD_PROFILES[
        release.download_profile
    ].download_type
    option = {
        "Name": release.filename,
        "Uri": uri,
        "ProductDisplayName": release.product_display_name,
        "Language": release.language_id,
        "LocalizedLanguage": release.language,
        "LocalizedProductDisplayName": release.localized_product_display_name,
        "DownloadType": download_type,
    }
    return json.dumps(
        {
            "DownloadExpirationDatetime": expiry,
            "ProductDownload": {"Uri": uri, "DownloadType": download_type},
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


def small_release(payload: bytes, architecture: str = "x64"):
    return replace(
        release_for(architecture),
        id=f"windows-test-english-{architecture.casefold()}",
        filename="windows-test.iso", image_path="/dbazure/windows-test.iso",
        size=len(payload), sha256=hashlib.sha256(payload).hexdigest(),
    )


def resume_stage(root: str | Path, release) -> Path:
    return Path(root) / downloads._verified.resume_stage_name(release)


def installer_inspection(release, architectures: tuple[str, ...] | None = None):
    return ImageInspection(
        size=release.size,
        kind="Optical ISO",
        volume_label="WINDOWS",
        has_mbr=False,
        has_gpt=False,
        is_iso9660=True,
        looks_windows=True,
        boot_modes=("UEFI",),
        architectures=architectures or (release.architecture,),
        bootloader="Windows Boot Manager",
        has_windows_installer=True,
        contents_scanned=True,
    )


class WindowsCatalogTests(unittest.TestCase):
    def test_bundled_catalog_is_exact_and_network_inactive(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            releases = load_windows_image_catalog()
        self.assertEqual(len(releases), 2)
        expected = {
            "x64": (
                "windows-11-25h2-v2-english-x64",
                "windows11-x64-v1",
                "Win11_25H2_English_x64_v2.iso",
                8_471_603_200,
                "768984706b909479417b2368438909440f2967ff05c6a9195ed2667254e465e3",
                "3321", "20046",
                "https://www.microsoft.com/en-us/software-download/windows11",
            ),
            "ARM64": (
                "windows-11-25h2-v2-english-arm64",
                "windows11-arm64-v1",
                "Win11_25H2_English_Arm64_v2.iso",
                7_994_415_104,
                "638aa2c88e94385b00f4f178d071e3df0b7d9e335577a83bd533b7f2eb65adf0",
                "3324", "20086",
                "https://www.microsoft.com/en-us/software-download/windows11arm64",
            ),
        }
        for release in releases:
            with self.subTest(architecture=release.architecture):
                values = expected[release.architecture]
                self.assertEqual(release.id, values[0])
                self.assertEqual(release.download_profile, values[1])
                self.assertIs(release.direct_resolver_supported, True)
                self.assertEqual(release.filename, values[2])
                self.assertEqual(release.size, values[3])
                self.assertEqual(release.sha256, values[4])
                self.assertEqual(release.product_edition_id, values[5])
                self.assertEqual(release.sku_id, values[6])
                self.assertEqual(release.provenance_url, values[7])
                self.assertEqual(
                    release.image_hosts,
                    ("software.download.prss.microsoft.com",),
                )
        self.assertIs(available_windows_images()[0], available_windows_images()[0])

    def test_catalog_rejects_unknown_missing_and_unsafe_fields(self):
        source = Path(downloads.__file__).with_name("data") / "windows-images-v2.json"
        original = json.loads(source.read_text())
        cases = []
        changed = json.loads(json.dumps(original)); changed["surprise"] = True
        cases.append(changed)
        for key, value in (
            ("catalog_version", 2.0),
            ("resolver_version", 1.0),
            ("resolver_version", True),
        ):
            changed = json.loads(json.dumps(original)); changed[key] = value
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
        changed = json.loads(json.dumps(original)); changed["images"][0]["download_profile"] = "future-profile"
        cases.append(changed)
        changed = json.loads(json.dumps(original)); changed["images"][0]["download_profile"] = []
        cases.append(changed)
        changed = json.loads(json.dumps(original)); changed["images"][0]["architecture"] = "ARM64"
        cases.append(changed)
        changed = json.loads(json.dumps(original)); changed["images"][0]["direct_resolver_supported"] = 1
        cases.append(changed)
        for field in ("id", "filename", "image_path"):
            changed = json.loads(json.dumps(original))
            changed["images"][1][field] = changed["images"][0][field]
            cases.append(changed)
        changed = json.loads(json.dumps(original))
        for field in ("product", "release", "edition", "language", "architecture"):
            changed["images"][1][field] = changed["images"][0][field]
        changed["images"][1]["download_profile"] = changed["images"][0]["download_profile"]
        changed["images"][1]["provenance_url"] = changed["images"][0]["provenance_url"]
        cases.append(changed)
        changed = json.loads(json.dumps(original))
        for left, right in ((0, 1), (1, 0)):
            for field in ("download_profile", "architecture", "provenance_url"):
                changed["images"][left][field] = original["images"][right][field]
        cases.append(changed)
        for field in (
            "size", "sha256", "product_edition_id", "sku_id",
            "product_display_name", "localized_product_display_name",
        ):
            changed = json.loads(json.dumps(original))
            changed["images"][0][field] = changed["images"][1][field]
            cases.append(changed)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            for value in cases:
                with self.subTest(value=value):
                    path.write_text(json.dumps(value))
                    with self.assertRaises(WindowsDownloadCatalogError):
                        load_windows_image_catalog(path)

    def test_post_download_inspection_is_exactly_architecture_bound(self):
        for release, other in (
            (release_for("x64"), release_for("ARM64")),
            (release_for("ARM64"), release_for("x64")),
        ):
            valid = installer_inspection(release)
            with self.subTest(architecture=release.architecture):
                self.assertTrue(
                    windows_inspection_matches_release(
                        release, valid, release.size,
                    )
                )
                invalid = (
                    (replace(valid, architectures=(other.architecture,)), release.size),
                    (
                        replace(
                            valid,
                            architectures=(release.architecture, other.architecture),
                        ),
                        release.size,
                    ),
                    (
                        replace(
                            valid,
                            architectures=(release.architecture, "IA-64"),
                        ),
                        release.size,
                    ),
                    (
                        replace(
                            valid,
                            architectures=(release.architecture, "unknown"),
                        ),
                        release.size,
                    ),
                    (replace(valid, has_windows_installer=False), release.size),
                    (replace(valid, contents_scanned=False), release.size),
                    (replace(valid, is_iso9660=False), release.size),
                    (replace(valid, size=release.size - 1), release.size),
                    (valid, release.size - 1),
                )
                for inspection, observed_size in invalid:
                    self.assertFalse(
                        windows_inspection_matches_release(
                            release, inspection, observed_size,
                        )
                    )

    def test_future_browser_only_profile_fails_before_direct_network_or_staging(self):
        release = replace(
            release_for("x64"), direct_resolver_supported=False,
        )
        with patch.object(
            downloads, "available_windows_images", return_value=(release,),
        ):
            with self.assertRaisesRegex(WindowsDownloadError, "browser-generated"):
                MicrosoftWindowsResolver().resolve(
                    release, opener=lambda *_a, **_k: self.fail("network used"),
                )
            with tempfile.TemporaryDirectory() as directory:
                destination = Path(directory) / release.filename
                with self.assertRaisesRegex(
                    WindowsDownloadError, "browser-generated",
                ):
                    WindowsIsoDownloader().download(
                        release, destination,
                        opener=lambda *_a, **_k: self.fail("network used"),
                    )
                self.assertEqual(os.listdir(directory), [])


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
        self.assertEqual(
            requests[4][0].get_header("Referer"), self.release.provenance_url,
        )
        self.assertIn("productEditionId=3321", urls[3])
        self.assertIn("SKU=20046", urls[4])
        self.assertNotIn(TOKEN, "\n".join(urls))

    def test_fixed_profile_requests_are_architecture_specific(self):
        expected = {"x64": 1, "ARM64": 2}
        for architecture, download_type in expected.items():
            release = release_for(architecture)
            with self.subTest(architecture=architecture):
                opener, requests, remaining = successful_opener(release)
                result = MicrosoftWindowsResolver().resolve(
                    release, opener=opener, session_id=SESSION, now=NOW,
                )
                self.assertEqual(result.url, image_url(release))
                self.assertEqual(remaining, [])
                urls = [request.full_url for request, _ in requests]
                self.assertIn(
                    f"productEditionId={release.product_edition_id}", urls[3],
                )
                self.assertIn(f"SKU={release.sku_id}", urls[4])
                self.assertEqual(
                    requests[4][0].get_header("Referer"),
                    release.provenance_url,
                )
                document = json.loads(link_document(release))
                self.assertEqual(
                    document["ProductDownload"]["DownloadType"], download_type,
                )

    def test_sanitized_live_profile_observations_bind_the_catalog_and_parser(self):
        observations = json.loads(OBSERVATIONS_PATH.read_text())
        self.assertEqual(observations["observation_date"], "2026-08-28")
        self.assertIn("ephemeral", observations["method"])
        for fact in observations["profiles"]:
            release = release_for(fact["architecture"])
            with self.subTest(architecture=release.architecture):
                for field in (
                    "download_profile", "provenance_url", "product_edition_id",
                    "sku_id", "product_display_name",
                    "localized_product_display_name", "filename", "image_path",
                ):
                    self.assertEqual(getattr(release, field), fact[field])
                self.assertEqual(
                    downloads._WINDOWS_DOWNLOAD_PROFILES[
                        release.download_profile
                    ].download_type,
                    fact["download_type"],
                )

                uri = image_url(release)
                sku = json.dumps(
                    {
                        "Skus": [
                            {
                                "Id": fact["sku_id"],
                                "Language": "English",
                                "LocalizedLanguage": "English (United States)",
                                "LocalizedProductDisplayName": fact[
                                    "localized_product_display_name"
                                ],
                                "ProductDisplayName": fact[
                                    "product_display_name"
                                ],
                            }
                        ],
                        "ValidationContainer": {},
                    },
                    separators=(",", ":"),
                ).encode()
                option = {
                    "Name": fact["filename"],
                    "Uri": uri,
                    "ProductDisplayName": fact["product_display_name"],
                    "Language": "English",
                    "LocalizedLanguage": "English (United States)",
                    "LocalizedProductDisplayName": fact[
                        "localized_product_display_name"
                    ],
                    "DownloadType": fact["download_type"],
                }
                link_body = json.dumps(
                    {
                        "DownloadExpirationDatetime": "2026-08-29T12:00:00Z",
                        "ProductDownload": {
                            "Uri": uri,
                            "DownloadType": fact["download_type"],
                        },
                        "ProductDownloadOptions": [option],
                        "ValidationContainer": {},
                    },
                    separators=(",", ":"),
                ).encode()
                opener, _, bodies = successful_opener(release)
                bodies[3] = sku
                bodies[4] = link_body
                result = MicrosoftWindowsResolver().resolve(
                    release, opener=opener, session_id=SESSION, now=NOW,
                )
                self.assertEqual(result.url, uri)

    def test_cross_profile_url_and_download_type_are_rejected(self):
        for release, other in (
            (release_for("x64"), release_for("ARM64")),
            (release_for("ARM64"), release_for("x64")),
        ):
            with self.subTest(architecture=release.architecture):
                opener, _, bodies = successful_opener(release)
                bodies[4] = link_document(release, uri=image_url(other))
                with self.assertRaises(WindowsDownloadError):
                    MicrosoftWindowsResolver().resolve(
                        release, opener=opener, session_id=SESSION, now=NOW,
                    )

                with self.assertRaises(WindowsDownloadError):
                    validate_microsoft_download_url(
                        release, image_url(other), now=NOW,
                    )

                document = json.loads(link_document(release))
                wrong_type = downloads._WINDOWS_DOWNLOAD_PROFILES[
                    other.download_profile
                ].download_type
                document["ProductDownload"]["DownloadType"] = wrong_type
                document["ProductDownloadOptions"][0]["DownloadType"] = wrong_type
                opener, _, bodies = successful_opener(release)
                bodies[4] = json.dumps(document).encode()
                with self.assertRaises(WindowsDownloadError):
                    MicrosoftWindowsResolver().resolve(
                        release, opener=opener, session_id=SESSION, now=NOW,
                    )

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
        changed = json.loads(json.dumps(valid)); changed["ProductDownloadOptions"][0]["Name"] = "other.iso"
        cases.append(changed)
        changed = json.loads(json.dumps(valid)); changed["ProductDownloadOptions"][0]["DownloadType"] = 2
        cases.append(changed)
        changed = json.loads(json.dumps(valid)); changed["ProductDownload"]["Uri"] = image_url(
            self.release,
            query=(
                "t=bbbbbbbb-cccc-4ddd-8eee-ffffffffffff&P1=1788004800&"
                "P2=602&P3=2&P4=abcdef0123456789abcdef0123456789"
            ),
        )
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
    def test_each_official_profile_hash_page_is_independently_bound(self):
        x64 = release_for("x64")
        arm64 = release_for("ARM64")
        for release in (x64, arm64):
            with self.subTest(architecture=release.architecture):
                valid_page, _ = provenance_opener(release)
                response = valid_page(
                    downloads.urllib.request.Request(release.provenance_url),
                    timeout=1,
                )
                downloads._verify_current_microsoft_hash(
                    response.read(), release,
                )

                other = arm64 if release is x64 else x64
                wrong_page, _ = provenance_opener(other)
                response = wrong_page(
                    downloads.urllib.request.Request(other.provenance_url),
                    timeout=1,
                )
                with self.assertRaises(WindowsDownloadError):
                    downloads._verify_current_microsoft_hash(
                        response.read(), release,
                    )

    def test_arm64_browser_assisted_download_uses_its_own_profile(self):
        payload = b"pinned ARM64 Windows installer ISO fixture"
        release = small_release(payload, "ARM64")
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
            page, calls = provenance_opener(release)
            result = WindowsIsoDownloader().download(
                release, destination, source_url=image_url(release),
                opener=opener, now=NOW, provenance_opener=page,
            )
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(result.release_id, release.id)
            self.assertEqual(requests[0].full_url, image_url(release))
            self.assertEqual(calls[0].full_url, release.provenance_url)

    def test_resume_stage_names_cannot_cross_profiles(self):
        payload = b"same payload identity"
        x64 = small_release(payload, "x64")
        arm64 = replace(
            small_release(payload, "ARM64"),
            filename=x64.filename,
            image_path=x64.image_path,
        )
        self.assertNotEqual(
            downloads._verified.resume_stage_name(x64),
            downloads._verified.resume_stage_name(arm64),
        )

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
