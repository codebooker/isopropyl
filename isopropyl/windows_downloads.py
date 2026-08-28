from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Pinned Microsoft Windows ISO discovery without remote-code execution.

Microsoft's public Windows download service returns short-lived CDN URLs.  A
URL returned by that service is only a transport capability: the bundled exact
filename, length, and Microsoft-published SHA-256 remain the artifact identity.
The small ``mdt.js`` response used by Microsoft's request-validation protocol
is read as bounded inert text and two opaque values are extracted from it.  It
is never evaluated or imported, and no Fido or PowerShell code is downloaded.
"""

import datetime as dt
import http.cookiejar
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Protocol

from . import verified_download as _verified
from .images import ImageInspection


CATALOG_VERSION = 2
RESOLVER_VERSION = 1
MAX_METADATA_BYTES = 256 * 1024
MAX_EPHEMERAL_URL = 4096
MAX_EPHEMERAL_QUERY = 2048
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,127}\Z")
SAFE_FILENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL_RE = re.compile(r"[0-9]{1,20}\Z")
ASCII_QUERY_RE = re.compile(r"[!-~]{1,2048}\Z")
CHALLENGE_W_RE = re.compile(r"[?&]w=([A-F0-9]{1,256})")
CHALLENGE_RTICKS_RES = (
    re.compile(r"rticks\\?=\\?[\"']?\\?\+?([0-9]{1,32})"),
    re.compile(r"rticks\\=\\\"\\\+?([0-9]{1,32})"),
)
_ENGLISH_64_BIT_HASH_ROW_RE = re.compile(
    rb"<td[^>]{0,512}>\s*English 64-bit\s*</td>\s*"
    rb"<td[^>]{0,512}>\s*([A-Fa-f0-9]{64})\s*</td>",
    re.IGNORECASE | re.DOTALL,
)

_ORG_ID = "y6jn8c31"
_PROFILE_ID = "606624d44113"
_INSTANCE_ID = "560dc9f3-1aa5-4a2f-b63c-9e18f8d0e175"
_TAGS_ENDPOINT = "https://vlscppe.microsoft.com/tags"
_CHALLENGE_ENDPOINT = "https://ov-df.microsoft.com/mdt.js"
_CHALLENGE_REPLY_ENDPOINT = "https://ov-df.microsoft.com/"
_SKU_ENDPOINT = (
    "https://www.microsoft.com/software-download-connector/api/"
    "getskuinformationbyproductedition"
)
_LINK_ENDPOINT = (
    "https://www.microsoft.com/software-download-connector/api/"
    "GetProductDownloadLinksBySku"
)


@dataclass(frozen=True)
class _WindowsDownloadProfile:
    architecture: str
    provenance_url: str
    download_type: int
    hash_row: re.Pattern[bytes]
    direct_resolver_capable: bool
    release_id: str
    product: str
    release: str
    edition: str
    filename: str
    size: int
    sha256: str
    product_edition_id: str
    sku_id: str
    product_display_name: str
    localized_product_display_name: str


_WINDOWS_DOWNLOAD_PROFILES = {
    "windows11-x64-v1": _WindowsDownloadProfile(
        architecture="x64",
        provenance_url="https://www.microsoft.com/en-us/software-download/windows11",
        download_type=1,
        hash_row=_ENGLISH_64_BIT_HASH_ROW_RE,
        direct_resolver_capable=True,
        release_id="windows-11-25h2-v2-english-x64",
        product="Windows 11",
        release="25H2 v2",
        edition="Consumer multi-edition",
        filename="Win11_25H2_English_x64_v2.iso",
        size=8_471_603_200,
        sha256="768984706b909479417b2368438909440f2967ff05c6a9195ed2667254e465e3",
        product_edition_id="3321",
        sku_id="20046",
        product_display_name="Windows 11 25H2__V2",
        localized_product_display_name="Windows 11  English",
    ),
    "windows11-arm64-v1": _WindowsDownloadProfile(
        architecture="ARM64",
        provenance_url="https://www.microsoft.com/en-us/software-download/windows11arm64",
        download_type=2,
        hash_row=_ENGLISH_64_BIT_HASH_ROW_RE,
        direct_resolver_capable=True,
        release_id="windows-11-25h2-v2-english-arm64",
        product="Windows 11",
        release="25H2 v2",
        edition="Consumer multi-edition",
        filename="Win11_25H2_English_Arm64_v2.iso",
        size=7_994_415_104,
        sha256="638aa2c88e94385b00f4f178d071e3df0b7d9e335577a83bd533b7f2eb65adf0",
        product_edition_id="3324",
        sku_id="20086",
        product_display_name="Windows 11 Arm64 25H2__V2",
        localized_product_display_name="Windows 11 Arm64  English",
    ),
}
class WindowsDownloadCatalogError(ValueError):
    """The bundled Windows-image catalog is malformed or unsafe."""


class WindowsDownloadError(_verified.VerifiedDownloadError):
    """A pinned Microsoft image could not be resolved or downloaded safely."""


class WindowsDownloadCancelled(
    WindowsDownloadError, _verified.VerifiedDownloadCancelled,
):
    """The caller cancelled Windows-image resolution or download."""


class ResolverResponse(Protocol):
    headers: object

    def read(self, size: int = -1) -> bytes: ...
    def geturl(self) -> str: ...
    def close(self) -> None: ...
    def getcode(self) -> int: ...


OpenUrl = Callable[..., ResolverResponse]
CancelCheck = Callable[[], None]


@dataclass(frozen=True)
class WindowsImageRelease:
    id: str
    download_profile: str
    direct_resolver_supported: bool
    product: str
    release: str
    edition: str
    language: str
    language_id: str
    locale: str
    architecture: str
    filename: str
    image_path: str
    size: int
    sha256: str
    product_edition_id: str
    sku_id: str
    product_display_name: str
    localized_product_display_name: str
    metadata_hosts: tuple[str, ...]
    image_hosts: tuple[str, ...]
    provenance_url: str


@dataclass(frozen=True)
class ResolvedWindowsSource:
    url: str
    expires_at: dt.datetime


@dataclass(frozen=True)
class DownloadedWindowsImage:
    path: Path
    release_id: str
    size: int
    sha256: str


_WINDOWS_DOWNLOAD_POLICY = _verified.DownloadErrorPolicy(
    error_type=WindowsDownloadError,
    cancelled_type=WindowsDownloadCancelled,
    subject="Windows image",
    hash_authority="Microsoft-published",
)


def _exact_dict(value: object, expected: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected:
        raise WindowsDownloadCatalogError(f"{label} has unknown or missing fields")
    return value


def _catalog_url(value: object, hosts: tuple[str, ...]) -> str:
    if type(value) is not str or len(value) > MAX_EPHEMERAL_URL:
        raise WindowsDownloadCatalogError("Catalog contains an unsafe HTTPS URL")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise WindowsDownloadCatalogError("Catalog contains an unsafe HTTPS URL") from error
    host = (parsed.hostname or "").casefold().rstrip(".")
    if (
        parsed.scheme != "https" or host not in hosts or parsed.username is not None
        or parsed.password is not None or port not in (None, 443) or parsed.query
        or parsed.fragment or not parsed.path.startswith("/")
    ):
        raise WindowsDownloadCatalogError("Catalog contains an unsafe HTTPS URL")
    return value


def _host_tuple(value: object) -> tuple[str, ...]:
    if (
        type(value) is not list or not value
        or any(type(host) is not str for host in value)
    ):
        raise WindowsDownloadCatalogError("Catalog host allowlist is invalid")
    hosts = tuple(host.casefold().rstrip(".") for host in value)
    if hosts != tuple(sorted(set(hosts))) or any(
        not host or len(host) > 253 or ":" in host or "/" in host or "@" in host
        for host in hosts
    ):
        raise WindowsDownloadCatalogError("Catalog host allowlist is unsafe")
    return hosts


def load_windows_image_catalog(path: Path | None = None) -> tuple[WindowsImageRelease, ...]:
    """Load and strictly validate the bundled, network-inactive catalog."""

    if path is None:
        text = resources.files("isopropyl").joinpath(
            "data/windows-images-v2.json"
        ).read_text(encoding="utf-8")
    else:
        text = path.read_text(encoding="utf-8")
    try:
        root = json.loads(text)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise WindowsDownloadCatalogError("Windows-image catalog is not valid JSON") from error
    root = _exact_dict(
        root, {"catalog_version", "resolver_version", "images"}, "Catalog"
    )
    if (
        type(root["catalog_version"]) is not int
        or root["catalog_version"] != CATALOG_VERSION
    ):
        raise WindowsDownloadCatalogError("Unsupported Windows-image catalog version")
    if (
        type(root["resolver_version"]) is not int
        or root["resolver_version"] != RESOLVER_VERSION
    ):
        raise WindowsDownloadCatalogError("Unsupported Microsoft resolver version")
    if type(root["images"]) is not list or not root["images"]:
        raise WindowsDownloadCatalogError("Windows-image catalog must contain images")

    fields = set(WindowsImageRelease.__dataclass_fields__)
    releases: list[WindowsImageRelease] = []
    seen_ids: set[str] = set()
    seen_filenames: set[str] = set()
    seen_paths: set[str] = set()
    seen_selections: set[tuple[str, str, str, str, str]] = set()
    for raw in root["images"]:
        item = _exact_dict(raw, fields, "Catalog image")
        values = dict(item)
        values["metadata_hosts"] = _host_tuple(item["metadata_hosts"])
        values["image_hosts"] = _host_tuple(item["image_hosts"])
        try:
            release = WindowsImageRelease(**values)  # type: ignore[arg-type]
        except TypeError as error:
            raise WindowsDownloadCatalogError("Catalog image fields are invalid") from error
        labels = (
            release.product, release.release, release.edition, release.language,
            release.language_id, release.locale, release.architecture,
            release.product_display_name, release.localized_product_display_name,
        )
        profile = (
            _WINDOWS_DOWNLOAD_PROFILES.get(release.download_profile)
            if type(release.download_profile) is str
            else None
        )
        if profile is None:
            raise WindowsDownloadCatalogError("Catalog image metadata is invalid")
        selection = (
            release.product,
            release.release,
            release.edition,
            release.language,
            release.architecture,
        )
        if (
            type(release.id) is not str or not SAFE_ID_RE.fullmatch(release.id)
            or release.id in seen_ids
            or type(release.direct_resolver_supported) is not bool
            or (
                release.direct_resolver_supported
                and not profile.direct_resolver_capable
            )
            or any(type(value) is not str or not value or len(value) > 128 for value in labels)
            or release.id != profile.release_id
            or release.product != profile.product
            or release.release != profile.release
            or release.edition != profile.edition
            or release.architecture != profile.architecture
            or release.provenance_url != profile.provenance_url
            or release.filename != profile.filename
            or release.size != profile.size
            or release.sha256 != profile.sha256
            or release.product_edition_id != profile.product_edition_id
            or release.sku_id != profile.sku_id
            or release.product_display_name != profile.product_display_name
            or release.localized_product_display_name
            != profile.localized_product_display_name
            or release.language != "English (United States)"
            or release.language_id != "English"
            or release.locale != "en-US"
            or type(release.filename) is not str
            or not SAFE_FILENAME_RE.fullmatch(release.filename)
            or release.filename in seen_filenames
            or type(release.image_path) is not str
            or release.image_path != f"/dbazure/{release.filename}"
            or release.image_path in seen_paths
            or type(release.size) is not int or release.size <= 0
            or type(release.sha256) is not str or not SHA256_RE.fullmatch(release.sha256)
            or type(release.product_edition_id) is not str
            or not DECIMAL_RE.fullmatch(release.product_edition_id)
            or type(release.sku_id) is not str or not DECIMAL_RE.fullmatch(release.sku_id)
            or selection in seen_selections
        ):
            raise WindowsDownloadCatalogError("Catalog image metadata is invalid")
        if release.metadata_hosts != (
            "ov-df.microsoft.com", "vlscppe.microsoft.com", "www.microsoft.com"
        ) or release.image_hosts != ("software.download.prss.microsoft.com",):
            raise WindowsDownloadCatalogError("Catalog host allowlist is not supported")
        _catalog_url(release.provenance_url, release.metadata_hosts)
        seen_ids.add(release.id)
        seen_filenames.add(release.filename)
        seen_paths.add(release.image_path)
        seen_selections.add(selection)
        releases.append(release)
    return tuple(releases)


@lru_cache(maxsize=1)
def available_windows_images() -> tuple[WindowsImageRelease, ...]:
    """Return the process-bound immutable Windows selection objects."""

    return load_windows_image_catalog()


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(
            req.full_url, code, "Redirects are disabled", headers, fp
        )


def _resolver_opener() -> OpenUrl:
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookies), _RejectRedirectHandler()
    )
    return opener.open  # type: ignore[return-value]


def _check_cancel(
    cancel_event: threading.Event, cancel_check: CancelCheck | None,
) -> None:
    if cancel_check is not None:
        cancel_check()
    if cancel_event.is_set():
        raise WindowsDownloadCancelled("Windows image download was cancelled")


def _status(response: ResolverResponse) -> int:
    value = getattr(response, "status", None)
    if type(value) is not int:
        try:
            value = response.getcode()
        except Exception:
            value = None
    if type(value) is not int:
        raise WindowsDownloadError("Microsoft response omitted its HTTP status")
    return value


def _header(response: ResolverResponse, name: str) -> str | None:
    headers = getattr(response, "headers", None)
    value = headers.get(name) if headers is not None and hasattr(headers, "get") else None
    return value if type(value) is str else None


def _bounded_response(
    opener: OpenUrl, url: str, *, headers: dict[str, str] | None,
    maximum: int, deadline: float, cancel_event: threading.Event,
    cancel_check: CancelCheck | None,
) -> bytes:
    _check_cancel(cancel_event, cancel_check)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise WindowsDownloadError("Microsoft resolver reached its time limit")
    request_headers = {"Accept-Encoding": "identity"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers, method="GET")
    try:
        response = opener(request, timeout=min(30, max(0.001, remaining)))
    except Exception as error:
        if isinstance(error, urllib.error.HTTPError):
            error.close()
        # Never include str(error): HTTP errors commonly contain the capability URL.
        raise WindowsDownloadError(
            f"Microsoft resolver connection failed ({type(error).__name__})"
        ) from error
    try:
        _check_cancel(cancel_event, cancel_check)
        if time.monotonic() > deadline:
            raise WindowsDownloadError("Microsoft resolver reached its time limit")
        try:
            final_url = response.geturl()
        except Exception as error:
            raise WindowsDownloadError("Microsoft response omitted its final URL") from error
        if final_url != url:
            raise WindowsDownloadError("Microsoft resolver redirected unexpectedly")
        if _status(response) != 200:
            raise WindowsDownloadError("Microsoft resolver returned an unexpected status")
        if _header(response, "Content-Encoding") not in (None, "identity"):
            raise WindowsDownloadError("Microsoft resolver used content encoding")
        content_length = _header(response, "Content-Length")
        if content_length is not None:
            if not DECIMAL_RE.fullmatch(content_length) or int(content_length) > maximum:
                raise WindowsDownloadError("Microsoft response exceeded its size limit")
        try:
            body = response.read(maximum + 1)
        except Exception as error:
            raise WindowsDownloadError(
                f"Microsoft resolver read failed ({type(error).__name__})"
            ) from error
        _check_cancel(cancel_event, cancel_check)
        if type(body) is not bytes or len(body) > maximum:
            raise WindowsDownloadError("Microsoft response exceeded its size limit")
        if content_length is not None and len(body) != int(content_length):
            raise WindowsDownloadError("Microsoft response length was inconsistent")
        return body
    finally:
        try:
            response.close()
        except Exception:
            pass


def _url(base: str, pairs: tuple[tuple[str, str], ...]) -> str:
    return base + "?" + urllib.parse.urlencode(pairs)


def _json_object(body: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WindowsDownloadError(f"Microsoft {label} response was not valid JSON") from error
    if type(value) is not dict:
        raise WindowsDownloadError(f"Microsoft {label} response had an invalid schema")
    if "Errors" in value:
        raise WindowsDownloadError(f"Microsoft rejected the {label} request")
    return value


def _parse_sku(body: bytes, release: WindowsImageRelease) -> str:
    root = _json_object(body, "language")
    if set(root) != {"Skus", "ValidationContainer"}:
        raise WindowsDownloadError("Microsoft language response had an invalid schema")
    if type(root["ValidationContainer"]) is not dict:
        raise WindowsDownloadError("Microsoft language validation data was invalid")
    skus = root["Skus"]
    if type(skus) is not list or not 1 <= len(skus) <= 128:
        raise WindowsDownloadError("Microsoft language list was invalid")
    expected_keys = {
        "Id", "Language", "LocalizedLanguage", "LocalizedProductDisplayName",
        "ProductDisplayName",
    }
    ids: set[str] = set()
    matches: list[dict[str, object]] = []
    for value in skus:
        if type(value) is not dict or set(value) != expected_keys:
            raise WindowsDownloadError("Microsoft language entry had an invalid schema")
        if any(type(item) is not str or not item or len(item) > 256 for item in value.values()):
            raise WindowsDownloadError("Microsoft language entry was invalid")
        sku_id = value["Id"]
        if not DECIMAL_RE.fullmatch(sku_id) or sku_id in ids:  # type: ignore[arg-type]
            raise WindowsDownloadError("Microsoft language identifiers were invalid")
        ids.add(sku_id)  # type: ignore[arg-type]
        if sku_id == release.sku_id:
            matches.append(value)
    if len(matches) != 1:
        raise WindowsDownloadError("Pinned Microsoft language was not available")
    selected = matches[0]
    if (
        selected["Language"] != release.language_id
        or selected["LocalizedLanguage"] != release.language
        or selected["ProductDisplayName"] != release.product_display_name
        or selected["LocalizedProductDisplayName"]
        != release.localized_product_display_name
    ):
        raise WindowsDownloadError("Microsoft release identity changed")
    return release.sku_id


def _verify_current_microsoft_hash(
    body: bytes, release: WindowsImageRelease,
) -> None:
    """Bind the bundled pin to its profile's current official English hash row."""

    profile = _WINDOWS_DOWNLOAD_PROFILES[release.download_profile]
    edition_marker = f'<option value="{release.product_edition_id}">'.encode()
    if body.count(edition_marker) != 1:
        raise WindowsDownloadError("Microsoft product edition changed")
    matches = [
        value.decode("ascii").casefold()
        for value in profile.hash_row.findall(body)
    ]
    if matches != [release.sha256]:
        raise WindowsDownloadError(
            f"Microsoft's current English {release.architecture} SHA-256 no longer "
            "matches ISOpropyl's pin"
        )


def _parse_expiry(value: object, *, now: dt.datetime) -> dt.datetime:
    if type(value) is not str or not value.isascii() or len(value) > 64:
        raise WindowsDownloadError("Microsoft link expiry was invalid")
    try:
        expiry = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise WindowsDownloadError("Microsoft link expiry was invalid") from error
    if expiry.tzinfo is None or expiry.utcoffset() != dt.timedelta(0):
        raise WindowsDownloadError("Microsoft link expiry was not UTC")
    expiry = expiry.astimezone(dt.timezone.utc)
    if not now + dt.timedelta(minutes=2) < expiry <= now + dt.timedelta(hours=25):
        raise WindowsDownloadError("Microsoft link expiry was outside the safe window")
    return expiry


def _ephemeral_url(
    value: object, release: WindowsImageRelease, *, now: dt.datetime,
    expected_expiry: dt.datetime | None = None,
) -> tuple[str, dt.datetime]:
    if type(value) is not str or not value.isascii() or len(value) > MAX_EPHEMERAL_URL:
        raise WindowsDownloadError("Microsoft returned an unsafe download URL")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise WindowsDownloadError("Microsoft returned an unsafe download URL") from error
    host = (parsed.hostname or "").casefold().rstrip(".")
    if (
        parsed.scheme != "https" or host not in release.image_hosts
        or parsed.username is not None or parsed.password is not None
        or port not in (None, 443) or parsed.fragment
        or parsed.path != release.image_path or "%" in parsed.path
        or "\\" in parsed.path or not parsed.query
        or len(parsed.query) > MAX_EPHEMERAL_QUERY
        or not ASCII_QUERY_RE.fullmatch(parsed.query)
        or PurePosixPath(parsed.path).name != release.filename
    ):
        raise WindowsDownloadError("Microsoft returned an unsafe download URL")
    # Reject malformed percent escapes before parse_qsl normalizes them.
    if re.search(r"%(?![0-9A-Fa-f]{2})", parsed.query):
        raise WindowsDownloadError("Microsoft returned an unsafe download URL")
    try:
        pairs = urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True, strict_parsing=True,
            encoding="utf-8", errors="strict",
        )
    except (UnicodeError, ValueError) as error:
        raise WindowsDownloadError("Microsoft returned an unsafe download URL") from error
    if len(pairs) != 5 or {key for key, _ in pairs} != {"t", "P1", "P2", "P3", "P4"}:
        raise WindowsDownloadError("Microsoft returned an unsafe download URL")
    query = dict(pairs)
    try:
        capability_id = uuid.UUID(query["t"])
    except (ValueError, AttributeError) as error:
        raise WindowsDownloadError("Microsoft returned an unsafe download URL") from error
    if str(capability_id) != query["t"] or query["P2"] != "602" or query["P3"] != "2":
        raise WindowsDownloadError("Microsoft returned an unsafe download URL")
    if (
        not DECIMAL_RE.fullmatch(query["P1"])
        or not 16 <= len(query["P4"]) <= 1024
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in query["P4"])
    ):
        raise WindowsDownloadError("Microsoft returned an unsafe download URL")
    try:
        query_expiry = dt.datetime.fromtimestamp(
            int(query["P1"]), tz=dt.timezone.utc
        )
    except (OverflowError, OSError, ValueError) as error:
        raise WindowsDownloadError("Microsoft returned an unsafe download URL") from error
    if not now + dt.timedelta(minutes=5) < query_expiry <= now + dt.timedelta(hours=25):
        raise WindowsDownloadError("Microsoft download URL expiry was outside the safe window")
    if (
        expected_expiry is not None
        and abs((query_expiry - expected_expiry).total_seconds()) > 5 * 60
    ):
        raise WindowsDownloadError("Microsoft download URL expiry was inconsistent")
    return value, query_expiry


def validate_microsoft_download_url(
    release: WindowsImageRelease, value: str, *, now: dt.datetime | None = None,
) -> ResolvedWindowsSource:
    """Validate a user-pasted official capability without logging or persisting it."""

    if (
        type(release) is not WindowsImageRelease
        or not any(release is item for item in available_windows_images())
    ):
        raise WindowsDownloadCatalogError("URL release is not an exact catalog entry")
    if now is None:
        now = dt.datetime.now(dt.timezone.utc)
    if type(now) is not dt.datetime or now.tzinfo is None:
        raise ValueError("URL validation clock must be a timezone-aware datetime")
    now = now.astimezone(dt.timezone.utc)
    url, expiry = _ephemeral_url(value, release, now=now)
    return ResolvedWindowsSource(url, expiry)


def _parse_link(
    body: bytes, release: WindowsImageRelease, *, now: dt.datetime,
) -> ResolvedWindowsSource:
    profile = _WINDOWS_DOWNLOAD_PROFILES[release.download_profile]
    root = _json_object(body, "download-link")
    expected = {
        "DownloadExpirationDatetime", "ProductDownload", "ProductDownloadOptions",
        "ValidationContainer",
    }
    if set(root) != expected:
        raise WindowsDownloadError("Microsoft download-link response had an invalid schema")
    if type(root["ValidationContainer"]) is not dict:
        raise WindowsDownloadError("Microsoft link validation data was invalid")
    product_download = root["ProductDownload"]
    if (
        type(product_download) is not dict
        or set(product_download) != {"Uri", "DownloadType"}
        or type(product_download["Uri"]) is not str
        or type(product_download["DownloadType"]) is not int
    ):
        raise WindowsDownloadError("Microsoft product-download data was invalid")
    options = root["ProductDownloadOptions"]
    if type(options) is not list or not 1 <= len(options) <= 4:
        raise WindowsDownloadError("Microsoft download-link options were invalid")
    matches: list[dict[str, object]] = []
    for value in options:
        if type(value) is not dict:
            raise WindowsDownloadError("Microsoft download-link option was invalid")
        if set(value) != {
            "Name", "Uri", "ProductDisplayName", "Language",
            "LocalizedLanguage", "LocalizedProductDisplayName", "DownloadType",
        }:
            raise WindowsDownloadError("Microsoft download-link option schema changed")
        if (
            type(value["Name"]) is not str or not value["Name"]
            or len(value["Name"]) > 256
            or type(value["Uri"]) is not str
            or type(value["ProductDisplayName"]) is not str
            or type(value["Language"]) is not str
            or type(value["LocalizedLanguage"]) is not str
            or type(value["LocalizedProductDisplayName"]) is not str
            or type(value["DownloadType"]) is not int
        ):
            raise WindowsDownloadError("Microsoft download-link option was invalid")
        if value["DownloadType"] == profile.download_type:
            matches.append(value)
    if len(matches) != 1:
        raise WindowsDownloadError("Pinned Microsoft architecture was not available")
    selected = matches[0]
    if (
        product_download["DownloadType"] != profile.download_type
        or product_download["Uri"] != selected["Uri"]
        or selected["Name"] != release.filename
        or selected["ProductDisplayName"] != release.product_display_name
        or selected["Language"] != release.language_id
        or selected["LocalizedLanguage"] != release.language
        or selected["LocalizedProductDisplayName"]
        != release.localized_product_display_name
    ):
        raise WindowsDownloadError("Microsoft download identity changed")
    expiry = _parse_expiry(root["DownloadExpirationDatetime"], now=now)
    url, query_expiry = _ephemeral_url(
        selected["Uri"], release, now=now, expected_expiry=expiry
    )
    return ResolvedWindowsSource(url, query_expiry)


class MicrosoftWindowsResolver:
    """Resolve one exact catalog release through Microsoft's fixed web protocol."""

    def __init__(self, cancel_event: threading.Event | None = None) -> None:
        self._cancel_event = cancel_event or threading.Event()

    @property
    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def cancel(self) -> None:
        self._cancel_event.set()

    def resolve(
        self, release: WindowsImageRelease, *, cancel_check: CancelCheck | None = None,
        overall_timeout: float = 3 * 60, opener: OpenUrl | None = None,
        session_id: uuid.UUID | None = None, now: dt.datetime | None = None,
    ) -> ResolvedWindowsSource:
        catalog = available_windows_images()
        if (
            type(release) is not WindowsImageRelease
            or not any(release is item for item in catalog)
        ):
            raise WindowsDownloadCatalogError("Resolve release is not an exact catalog entry")
        if not release.direct_resolver_supported:
            raise WindowsDownloadError(
                "The selected Windows profile requires a browser-generated "
                "Microsoft download link"
            )
        if (
            isinstance(overall_timeout, bool)
            or not isinstance(overall_timeout, (int, float))
            or not 0 < overall_timeout <= 10 * 60
        ):
            raise ValueError("Resolver timeout must be between 0 and 10 minutes")
        if opener is None:
            opener = _resolver_opener()
        if session_id is None:
            session_id = uuid.uuid4()
        if type(session_id) is not uuid.UUID:
            raise ValueError("Resolver session ID must be an exact UUID")
        if now is None:
            now = dt.datetime.now(dt.timezone.utc)
        if type(now) is not dt.datetime or now.tzinfo is None:
            raise ValueError("Resolver clock must be a timezone-aware datetime")
        now = now.astimezone(dt.timezone.utc)
        deadline = time.monotonic() + float(overall_timeout)
        sid = str(session_id)

        _bounded_response(
            opener, _url(_TAGS_ENDPOINT, (("org_id", _ORG_ID), ("session_id", sid))),
            headers=None, maximum=64 * 1024, deadline=deadline,
            cancel_event=self._cancel_event, cancel_check=cancel_check,
        )
        challenge_url = _url(
            _CHALLENGE_ENDPOINT,
            (("instanceId", _INSTANCE_ID), ("PageId", "si"), ("session_id", sid)),
        )
        challenge = _bounded_response(
            opener, challenge_url, headers=None, maximum=64 * 1024,
            deadline=deadline, cancel_event=self._cancel_event,
            cancel_check=cancel_check,
        )
        try:
            challenge_text = challenge.decode("ascii")
        except UnicodeDecodeError as error:
            raise WindowsDownloadError("Microsoft challenge was not ASCII") from error
        w_matches = CHALLENGE_W_RE.findall(challenge_text)
        rticks_matches: list[str] = []
        for pattern in CHALLENGE_RTICKS_RES:
            rticks_matches.extend(pattern.findall(challenge_text))
        if len(set(w_matches)) != 1 or len(set(rticks_matches)) != 1:
            raise WindowsDownloadError("Microsoft challenge shape changed")
        w = w_matches[0]
        rticks = rticks_matches[0]
        reply_url = _url(
            _CHALLENGE_REPLY_ENDPOINT,
            (
                ("session_id", sid), ("CustomerId", _INSTANCE_ID), ("PageId", "si"),
                ("w", w), ("mdt", str(int(now.timestamp() * 1000))),
                ("rticks", rticks),
            ),
        )
        _bounded_response(
            opener, reply_url, headers=None, maximum=64 * 1024,
            deadline=deadline, cancel_event=self._cancel_event,
            cancel_check=cancel_check,
        )
        sku_url = _url(
            _SKU_ENDPOINT,
            (
                ("profile", _PROFILE_ID),
                ("productEditionId", release.product_edition_id),
                ("SKU", "undefined"), ("friendlyFileName", "undefined"),
                ("Locale", release.locale), ("sessionID", sid),
            ),
        )
        sku_body = _bounded_response(
            opener, sku_url, headers=None, maximum=MAX_METADATA_BYTES,
            deadline=deadline, cancel_event=self._cancel_event,
            cancel_check=cancel_check,
        )
        sku_id = _parse_sku(sku_body, release)
        link_url = _url(
            _LINK_ENDPOINT,
            (
                ("profile", _PROFILE_ID), ("productEditionId", "undefined"),
                ("SKU", sku_id), ("friendlyFileName", "undefined"),
                ("Locale", release.locale), ("sessionID", sid),
            ),
        )
        link_body = _bounded_response(
            opener, link_url, headers={"Referer": release.provenance_url},
            maximum=MAX_METADATA_BYTES, deadline=deadline,
            cancel_event=self._cancel_event, cancel_check=cancel_check,
        )
        return _parse_link(link_body, release, now=now)


class WindowsIsoDownloader:
    """Resolve and atomically publish one exact Microsoft-pinned Windows ISO.

    A caller may provide a freshly copied Microsoft capability URL for the
    privacy-clean browser-assisted path.  Otherwise the fixed connector client
    is attempted.  Resolver cookies, session IDs, and capability URLs remain in
    memory only and are never passed to the result or persisted resume state.
    """

    def __init__(self, cancel_event: threading.Event | None = None) -> None:
        self._cancel_event = cancel_event or threading.Event()

    @property
    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def cancel(self) -> None:
        self._cancel_event.set()

    def download(
        self, release: WindowsImageRelease, destination: Path,
        progress: _verified.Progress | None = None, *, source_url: str | None = None,
        cancel_check: CancelCheck | None = None,
        overall_timeout: float = 6 * 60 * 60,
        opener: _verified.OpenUrl = _verified.default_urlopen,
        resolver_opener: OpenUrl | None = None,
        provenance_opener: OpenUrl | None = None,
        resolver_session_id: uuid.UUID | None = None,
        now: dt.datetime | None = None,
    ) -> DownloadedWindowsImage:
        catalog = available_windows_images()
        if (
            type(release) is not WindowsImageRelease
            or not any(release is item for item in catalog)
        ):
            raise WindowsDownloadCatalogError(
                "Download release is not an exact catalog entry"
            )
        if source_url is not None and type(source_url) is not str:
            raise ValueError("Microsoft source URL must be an exact string")
        if source_url is None and not release.direct_resolver_supported:
            raise WindowsDownloadError(
                "The selected Windows profile requires a browser-generated "
                "Microsoft download link"
            )

        def authorize_source(
            _download_opener: _verified.OpenUrl,
            deadline: float,
            cancel_event: threading.Event,
            selected_cancel_check: CancelCheck | None,
        ) -> _verified.ResolvedDownloadSource:
            _check_cancel(cancel_event, selected_cancel_check)
            if source_url is not None:
                source = validate_microsoft_download_url(
                    release, source_url, now=now,
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WindowsDownloadError(
                    "Windows image download reached its overall time limit"
                )
            page_body = _bounded_response(
                provenance_opener or _resolver_opener(),
                release.provenance_url,
                headers=None,
                maximum=512 * 1024,
                deadline=deadline,
                cancel_event=cancel_event,
                cancel_check=selected_cancel_check,
            )
            _verify_current_microsoft_hash(page_body, release)
            if source_url is None:
                source = MicrosoftWindowsResolver(cancel_event).resolve(
                    release, cancel_check=selected_cancel_check,
                    overall_timeout=min(3 * 60, remaining),
                    opener=resolver_opener, session_id=resolver_session_id, now=now,
                )
            return _verified.ResolvedDownloadSource(source.url)

        result = _verified.execute_verified_download(
            release,
            destination,
            authorize_source,
            progress,
            cancel_event=self._cancel_event,
            cancel_check=cancel_check,
            overall_timeout=overall_timeout,
            opener=opener,
            policy=_WINDOWS_DOWNLOAD_POLICY,
        )
        return DownloadedWindowsImage(
            result.path, result.release_id, result.size, result.sha256,
        )


def windows_inspection_matches_release(
    release: WindowsImageRelease,
    inspection: ImageInspection,
    observed_size: int,
) -> bool:
    """Return whether a published ISO matches its exact catalog architecture."""

    if (
        type(release) is not WindowsImageRelease
        or not any(release is item for item in available_windows_images())
        or type(inspection) is not ImageInspection
        or type(observed_size) is not int
    ):
        return False
    profile = _WINDOWS_DOWNLOAD_PROFILES[release.download_profile]
    if any(
        type(architecture) is not str
        for architecture in inspection.architectures
    ):
        return False
    detected = frozenset(inspection.architectures)
    return bool(
        observed_size == release.size
        and inspection.size == release.size
        and inspection.is_iso9660
        and inspection.contents_scanned
        and inspection.has_windows_installer
        and detected == frozenset({profile.architecture})
    )
