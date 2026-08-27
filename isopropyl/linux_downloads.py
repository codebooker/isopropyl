from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Explicit, signed downloads from ISOpropyl's small curated Linux catalog.

The bundled Ubuntu key is the exact ``ubuntu-keyring-2012-cdimage.gpg`` member
from Ubuntu's official ``ubuntu-keyring_2023.11.28.1.tar.xz`` source package:

* https://archive.ubuntu.com/ubuntu/pool/main/u/ubuntu-keyring/
  ubuntu-keyring_2023.11.28.1.tar.xz
* source archive SHA-256:
  aecd455ae15561371d6e454f121f079f0641d5e1b579a5563a2bc363fc74aa2e
* keyring SHA-256:
  192b3782ba2e00e05b6521371fbe67847efad3fdd1cfb87621882d833c8703fa
* signing fingerprint: 843938DF228D22F7B3742BC0D94AA3F0EFE21092

Ubuntu's source-package copyright file says the public keys in ``keyrings``
do not fall under copyright. The bytes below are not generated or fetched at
runtime; their digest and the expected signature fingerprint are both pinned.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit


CATALOG_VERSION = 1
MAX_METADATA_SIZE = 64 * 1024
FREE_SPACE_RESERVE = 64 * 1024 * 1024
MAX_DOWNLOAD_TIMEOUT = 24 * 60 * 60
READ_SIZE = 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
FINGERPRINT_RE = re.compile(r"[0-9A-F]{40}\Z")
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,127}\Z")
SAFE_FILENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}\Z")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
_DIRECTORY_FLAGS |= getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
_TRUSTED_PATH = "/usr/bin:/bin"
_KEYRING_SHA256 = "192b3782ba2e00e05b6521371fbe67847efad3fdd1cfb87621882d833c8703fa"
_KEYRING_B64 = """
mQINBE+tjmgBEAC7pKK78t89DW7mvMoSgiScLfPNF8/TSF380is0hFRL3dOmcXEfNsX26jtv8bdv
vtkElB1fPwOntmqSAsrLOuURVQ6GSxH7IDU5QFfaTIsudtLR5YTlC3ZuOTOb1HWEK26fDRXuIWjh
FDXJH3KLv+rSrq0+x7ZtH++CHq5XJWk7VUh/wWcGxZefs7+1HTivymhjXCOwQvqblzZ5MAec9i4Q
IXxkqX1HY7ryxGVdjj9lApOnoU5EcSYr08cm7xQEgrdDLAZFQxDYBLDuV6E6jKEfAfwZINSEe4Oc
m82vtCF5K0HiwhFU09ky2yogbMuTTi2f8ibN8SbbhZDJlDPd2ZkkpsKNfIALmOiPhHGvXGmtg6Fd
zRUOSGirSm8tcakpS+d0/IElbD453sksxg6s3cTs7Q+PudaccyQ0BqatMnzmfxCVOotT65kVnmz2
P+4Q0gRSQ/Zi9Inz+OrzWxtn6/Tdw+FMUwvBccxW1r88k6uVLz23jW/8jOuwnUp4JKmZta/U2UZK
TyPyrvTYhp/zK332BEnxiRY4ZfQjA4Iwlw00l4pYBDLLc6TFJtLbDv859UCisXa8MtWYWrlM3YfG
Fs9k1WemML8u79g2DK8g3VPkD94Q5anqufEGm74K/keOmss8cQoBX9VPFMpS1mFCT+2UdGP0UvMl
ADct0aFnAwtb9QARAQABtEFVYnVudHUgQ0QgSW1hZ2UgQXV0b21hdGljIFNpZ25pbmcgS2V5ICgy
MDEyKSA8Y2RpbWFnZUB1YnVudHUuY29tPokCNwQTAQoAIQUCT62OaAIbAwULCQgHAwUVCgkICwUW
AgMBAAIeAQIXgAAKCRDZSqPw7+IQkkhAEACJjZZXuAabMrC49Z52HywVZipJgoV5ufMi2LQYMkyG
KVQQ/E74lUjccMmbQ4j00ihTYB+F/i29AxfavJnlSpWgmwjPO4YY5jvooUiXQmVHX10oM1w3+Y9w
ScmeUY3IhTtwiFaBJr6TZ7RvOTg/pbQ0GvzxNlkSobuqFCZ023mcl2Y7OkY1PZgxiLafD6Rx2O/g
clQPs4YfHo8bKRA4o10702nE8YE+dixIgAQw67Txhq5idNxsWpudKq9J1fLgnEz7i9AJUOf12sg9
X7ZvpXZ3QvMV5iOvLA4DRLv9HIxyz70XqeakS+uzfKXuCMzhdUTIb/tNACNB37+reIqdPsyUF3tx
VyWaL1jMkRsv617yKAiYvPNwMDRvrbKiJ4Icnd4tPzmqz5HBFUyULns3JzJNjpgKCvLGhVq+lVsd
pMlpQxEG5/bhzJgB1jrIbkcOSfnQ1y0Gv9CItel+1q0BHMn0dPVWaNfKYFGsz4igW+uj//C09/gt
GMm78PQfjqEoR2j/Tam/tmucxSK331yfm5ag2CQYGC3bswfII+4EanX9dN/RG3/2dsSyYruWpTIQ
G6Xa7+AZtYBDEXNYovgdJtXWyUtW0X7R6vIjh1HYer3dR6ivJ+q/bWGY45zHeNBNU33hlnlxEENi
f3RZ/j/w3SjGrtSQK69maNR6onq492e+6w==
"""


class LinuxDownloadCatalogError(ValueError):
    """The bundled Linux-image catalog is malformed or unsafe."""


class LinuxDownloadError(RuntimeError):
    """A curated Linux image could not be securely downloaded."""


class LinuxDownloadCancelled(LinuxDownloadError):
    """The caller cancelled a Linux-image download."""


class DownloadResponse(Protocol):
    headers: object

    def read(self, size: int = -1) -> bytes: ...
    def geturl(self) -> str: ...
    def close(self) -> None: ...
    def getcode(self) -> int: ...


OpenUrl = Callable[..., DownloadResponse]
Progress = Callable[[int, int], None]
CancelCheck = Callable[[], None]


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(
            req.full_url, code, "Redirects are disabled for curated downloads",
            headers, fp,
        )


def _default_urlopen(
    request: urllib.request.Request, *, timeout: float,
) -> DownloadResponse:
    """Open one request with redirects disabled at the transport boundary."""

    opener = urllib.request.build_opener(_RejectRedirectHandler())
    return opener.open(request, timeout=timeout)  # type: ignore[return-value]


@dataclass(frozen=True)
class LinuxImageRelease:
    id: str
    distribution: str
    release: str
    edition: str
    architecture: str
    filename: str
    size: int
    sha256: str
    image_url: str
    checksums_url: str
    checksums_size: int
    checksums_sha256: str
    signature_url: str
    signature_size: int
    signature_sha256: str
    signing_fingerprint: str
    allowed_hosts: tuple[str, ...]
    provenance_url: str


@dataclass(frozen=True)
class DownloadedLinuxImage:
    path: Path
    release_id: str
    size: int
    sha256: str


def _strict_https_url(value: object, allowed_hosts: tuple[str, ...] | None = None) -> str:
    if type(value) is not str:
        raise LinuxDownloadCatalogError("Catalog URLs must be strings")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise LinuxDownloadCatalogError("Catalog contains an unsafe HTTPS URL") from error
    host = (parsed.hostname or "").casefold().rstrip(".")
    if (
        parsed.scheme != "https" or not host or parsed.username is not None
        or parsed.password is not None or port not in (None, 443)
        or parsed.query or parsed.fragment or not parsed.path.startswith("/")
    ):
        raise LinuxDownloadCatalogError("Catalog contains an unsafe HTTPS URL")
    if allowed_hosts is not None and host not in allowed_hosts:
        raise LinuxDownloadCatalogError("Catalog URL host is not allowlisted")
    return value


def _exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected:
        raise LinuxDownloadCatalogError(f"{label} has unknown or missing fields")
    return value


def load_linux_image_catalog(path: Path | None = None) -> tuple[LinuxImageRelease, ...]:
    """Load and strictly validate the bundled, network-inactive catalog."""

    if path is None:
        text = resources.files("isopropyl").joinpath(
            "data/linux-images-v1.json"
        ).read_text(encoding="utf-8")
    else:
        text = path.read_text(encoding="utf-8")
    try:
        root = json.loads(text)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LinuxDownloadCatalogError("Linux-image catalog is not valid JSON") from error
    root = _exact_keys(root, {"catalog_version", "images"}, "Catalog")
    if type(root["catalog_version"]) is not int or root["catalog_version"] != CATALOG_VERSION:
        raise LinuxDownloadCatalogError("Unsupported Linux-image catalog version")
    if type(root["images"]) is not list or not root["images"]:
        raise LinuxDownloadCatalogError("Linux-image catalog must contain images")
    fields = set(LinuxImageRelease.__dataclass_fields__)
    releases: list[LinuxImageRelease] = []
    seen: set[str] = set()
    for raw in root["images"]:
        item = _exact_keys(raw, fields, "Catalog image")
        hosts_raw = item["allowed_hosts"]
        if (
            type(hosts_raw) is not list or not hosts_raw
            or any(type(host) is not str for host in hosts_raw)
        ):
            raise LinuxDownloadCatalogError("Image allowlist is invalid")
        hosts = tuple(host.casefold().rstrip(".") for host in hosts_raw)
        if hosts != tuple(sorted(set(hosts))) or any(
            not host or ":" in host or "/" in host or "@" in host for host in hosts
        ):
            raise LinuxDownloadCatalogError("Image allowlist is unsafe")
        values = dict(item)
        values["allowed_hosts"] = hosts
        try:
            release = LinuxImageRelease(**values)  # type: ignore[arg-type]
        except TypeError as error:
            raise LinuxDownloadCatalogError("Catalog image fields are invalid") from error
        strings = (
            release.distribution, release.release, release.edition,
            release.architecture,
        )
        if (
            type(release.id) is not str or not SAFE_ID_RE.fullmatch(release.id)
            or release.id in seen
            or any(type(value) is not str or not value or len(value) > 128 for value in strings)
            or type(release.filename) is not str
            or not SAFE_FILENAME_RE.fullmatch(release.filename)
            or type(release.size) is not int or release.size <= 0
            or type(release.checksums_size) is not int
            or not 0 < release.checksums_size <= MAX_METADATA_SIZE
            or type(release.signature_size) is not int
            or not 0 < release.signature_size <= MAX_METADATA_SIZE
            or type(release.sha256) is not str or not SHA256_RE.fullmatch(release.sha256)
            or type(release.checksums_sha256) is not str
            or not SHA256_RE.fullmatch(release.checksums_sha256)
            or type(release.signature_sha256) is not str
            or not SHA256_RE.fullmatch(release.signature_sha256)
            or type(release.signing_fingerprint) is not str
            or not FINGERPRINT_RE.fullmatch(release.signing_fingerprint)
        ):
            raise LinuxDownloadCatalogError("Catalog image metadata is invalid")
        _strict_https_url(release.image_url, hosts)
        _strict_https_url(release.checksums_url, hosts)
        _strict_https_url(release.signature_url, hosts)
        _strict_https_url(release.provenance_url, hosts)
        if Path(urlsplit(release.image_url).path).name != release.filename:
            raise LinuxDownloadCatalogError("Image URL does not match its exact filename")
        seen.add(release.id)
        releases.append(release)
    return tuple(releases)


@lru_cache(maxsize=1)
def available_linux_images() -> tuple[LinuxImageRelease, ...]:
    """Return the process-bound immutable selection objects."""

    return load_linux_image_catalog()


def _check_cancel(cancel_event: threading.Event, cancel_check: CancelCheck | None) -> None:
    if cancel_check is not None:
        cancel_check()
    if cancel_event.is_set():
        raise LinuxDownloadCancelled("Linux image download was cancelled")


def _deadline_check(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise LinuxDownloadError("Linux image download reached its overall time limit")


def _open_response(
    opener: OpenUrl, request: urllib.request.Request, *, deadline: float,
    cancel_event: threading.Event, cancel_check: CancelCheck | None,
) -> DownloadResponse:
    _check_cancel(cancel_event, cancel_check)
    _deadline_check(deadline)
    try:
        response = opener(
            request, timeout=min(30, max(0.001, deadline - time.monotonic()))
        )
    except Exception as error:
        if isinstance(error, urllib.error.HTTPError):
            error.close()
        raise LinuxDownloadError(f"Download connection failed: {error}") from error
    try:
        _check_cancel(cancel_event, cancel_check)
        _deadline_check(deadline)
    except BaseException:
        try:
            response.close()
        except Exception:
            pass
        raise
    return response


def _response_blocks(
    response: DownloadResponse, *, deadline: float, cancel_event: threading.Event,
    cancel_check: CancelCheck | None,
) -> Iterable[bytes]:
    while True:
        _check_cancel(cancel_event, cancel_check)
        _deadline_check(deadline)
        try:
            block = response.read(READ_SIZE)
        except Exception as error:
            raise LinuxDownloadError(f"Download read failed: {error}") from error
        _check_cancel(cancel_event, cancel_check)
        _deadline_check(deadline)
        if not block:
            return
        if type(block) is not bytes:
            raise LinuxDownloadError("Download returned non-byte data")
        yield block


def _header(response: DownloadResponse, name: str) -> str | None:
    headers = getattr(response, "headers", None)
    value = headers.get(name) if headers is not None and hasattr(headers, "get") else None
    return value if type(value) is str else None


def _status(response: DownloadResponse) -> int:
    value = getattr(response, "status", None)
    if type(value) is not int:
        try:
            value = response.getcode()
        except Exception:
            value = None
    if type(value) is not int:
        raise LinuxDownloadError("Download response omitted its HTTP status")
    return value


def _validate_response_url(response: DownloadResponse, expected: str) -> None:
    try:
        final = response.geturl()
    except Exception as error:
        raise LinuxDownloadError("Download response omitted its final URL") from error
    if final != expected:
        raise LinuxDownloadError("Download redirected away from its exact pinned URL")


def _fetch_exact_metadata(
    url: str, size: int, digest: str, opener: OpenUrl, *, deadline: float,
    cancel_event: threading.Event, cancel_check: CancelCheck | None,
) -> bytes:
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
    response = _open_response(
        opener, request, deadline=deadline, cancel_event=cancel_event,
        cancel_check=cancel_check,
    )
    try:
        _validate_response_url(response, url)
        if _status(response) != 200:
            raise LinuxDownloadError("Signed metadata server returned an unexpected status")
        if _header(response, "Content-Encoding") not in (None, "identity"):
            raise LinuxDownloadError("Signed metadata used an unexpected content encoding")
        content_length = _parse_decimal_header(
            _header(response, "Content-Length"), "Content-Length",
        )
        if content_length != size:
            raise LinuxDownloadError("Signed metadata size differs from the pinned catalog")
        body = bytearray()
        for block in _response_blocks(
            response, deadline=deadline, cancel_event=cancel_event,
            cancel_check=cancel_check,
        ):
            body.extend(block)
            if len(body) > size:
                raise LinuxDownloadError("Signed metadata exceeded its exact size")
        value = bytes(body)
        if len(value) != size or not hmac.compare_digest(hashlib.sha256(value).hexdigest(), digest):
            raise LinuxDownloadError("Signed metadata did not match the pinned catalog")
        return value
    finally:
        try:
            response.close()
        except Exception:
            pass


def _gpgv_path() -> Path:
    for candidate in (Path("/usr/bin/gpgv"), Path("/bin/gpgv")):
        try:
            status = candidate.stat(follow_symlinks=False)
        except OSError:
            continue
        if (
            stat.S_ISREG(status.st_mode) and status.st_uid == 0
            and not status.st_mode & 0o022 and status.st_mode & 0o111
        ):
            return candidate
    raise LinuxDownloadError("gpgv is required to authenticate Ubuntu download metadata")


def _tool_identity(status: os.stat_result) -> tuple[int, int, int, int, int]:
    return status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns, status.st_mode


def _verify_signed_manifest(
    manifest: bytes, signature: bytes, fingerprint: str, *, deadline: float,
    cancel_event: threading.Event, cancel_check: CancelCheck | None,
) -> None:
    keyring = base64.b64decode(b"".join(_KEYRING_B64.encode("ascii").split()), validate=True)
    if not hmac.compare_digest(hashlib.sha256(keyring).hexdigest(), _KEYRING_SHA256):
        raise LinuxDownloadError("Bundled Ubuntu signing key failed its integrity check")
    tool_path = _gpgv_path()
    tool_fd = -1
    with tempfile.TemporaryDirectory(prefix="isopropyl-linux-signature-") as directory:
        root = Path(directory)
        for name, value in (("keyring.gpg", keyring), ("SHA256SUMS", manifest), ("SHA256SUMS.gpg", signature)):
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            try:
                view = memoryview(value)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise LinuxDownloadError("Could not stage signed metadata")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        try:
            tool_fd = os.open(tool_path, _READ_FLAGS)
            opened = os.fstat(tool_fd)
            command = [
                f"/proc/self/fd/{tool_fd}", "--status-fd", "1", "--keyring",
                str(root / "keyring.gpg"), str(root / "SHA256SUMS.gpg"),
                str(root / "SHA256SUMS"),
            ]
            output_fd = os.open(root / "gpgv.status", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            error_fd = os.open(root / "gpgv.stderr", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            try:
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=output_fd,
                    stderr=error_fd, pass_fds=(tool_fd,), close_fds=True,
                    env={"PATH": _TRUSTED_PATH, "LANG": "C", "LC_ALL": "C", "GNUPGHOME": str(root)},
                )
                while process.poll() is None:
                    try:
                        _check_cancel(cancel_event, cancel_check)
                        _deadline_check(deadline)
                    except BaseException:
                        process.terminate()
                        try:
                            process.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                        raise
                    time.sleep(0.05)
                _check_cancel(cancel_event, cancel_check)
                _deadline_check(deadline)
                if os.fstat(output_fd).st_size > MAX_METADATA_SIZE or os.fstat(error_fd).st_size > MAX_METADATA_SIZE:
                    raise LinuxDownloadError("gpgv returned excessive output")
                stdout = os.pread(output_fd, MAX_METADATA_SIZE + 1, 0)
                stderr = os.pread(error_fd, MAX_METADATA_SIZE + 1, 0)
            finally:
                os.close(output_fd)
                os.close(error_fd)
            if len(stdout) > MAX_METADATA_SIZE or len(stderr) > MAX_METADATA_SIZE:
                raise LinuxDownloadError("gpgv returned excessive output")
            final = os.fstat(tool_fd)
            if _tool_identity(opened) != _tool_identity(final):
                raise LinuxDownloadError("gpgv changed during signature verification")
            valid: list[str] = []
            forbidden = {"BADSIG", "ERRSIG", "REVKEYSIG", "EXPKEYSIG", "EXPSIG", "NO_PUBKEY"}
            for raw_line in stdout.decode("utf-8", "replace").splitlines():
                if not raw_line.startswith("[GNUPG:] "):
                    continue
                fields = raw_line[9:].split()
                if fields and fields[0] in forbidden:
                    raise LinuxDownloadError("Ubuntu metadata signature is not valid")
                if len(fields) >= 2 and fields[0] == "VALIDSIG":
                    valid.append(fields[1])
            if process.returncode != 0 or valid != [fingerprint]:
                raise LinuxDownloadError("Ubuntu metadata was not signed by the pinned key")
        except OSError as error:
            raise LinuxDownloadError(f"Could not run fixed gpgv verifier: {error}") from error
        finally:
            if tool_fd >= 0:
                os.close(tool_fd)


def _manifest_digest(manifest: bytes, filename: str) -> str:
    try:
        text = manifest.decode("ascii")
    except UnicodeDecodeError as error:
        raise LinuxDownloadError("Signed checksum manifest is not ASCII") from error
    found: list[str] = []
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) \*([A-Za-z0-9][A-Za-z0-9._+-]{0,254})", line)
        if match is None:
            raise LinuxDownloadError("Signed checksum manifest has an unsafe line")
        if match.group(2) == filename:
            found.append(match.group(1))
    if len(found) != 1:
        raise LinuxDownloadError("Signed checksum manifest does not name the exact image once")
    return found[0]


def _verify_release_metadata(
    release: LinuxImageRelease, opener: OpenUrl, *, deadline: float,
    cancel_event: threading.Event, cancel_check: CancelCheck | None,
) -> None:
    manifest = _fetch_exact_metadata(
        release.checksums_url, release.checksums_size, release.checksums_sha256,
        opener, deadline=deadline, cancel_event=cancel_event, cancel_check=cancel_check,
    )
    signature = _fetch_exact_metadata(
        release.signature_url, release.signature_size, release.signature_sha256,
        opener, deadline=deadline, cancel_event=cancel_event, cancel_check=cancel_check,
    )
    _verify_signed_manifest(
        manifest, signature, release.signing_fingerprint, deadline=deadline,
        cancel_event=cancel_event, cancel_check=cancel_check,
    )
    if not hmac.compare_digest(_manifest_digest(manifest, release.filename), release.sha256):
        raise LinuxDownloadError("Signed checksum does not match the curated image hash")


def _open_absolute_directory(path: Path) -> int:
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise LinuxDownloadError("Download destination parent must be a canonical absolute path")
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            if component in {"", ".", ".."}:
                raise LinuxDownloadError("Download destination parent is unsafe")
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev, left.st_ino, left.st_size, left.st_mtime_ns, left.st_ctime_ns,
    ) == (
        right.st_dev, right.st_ino, right.st_size, right.st_mtime_ns, right.st_ctime_ns,
    )


def _assert_destination_absent(parent_fd: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise LinuxDownloadError("Download destination already exists; it will not be overwritten")


def _open_stage(parent_fd: int, name: str) -> tuple[int, str, os.stat_result]:
    stage_name = f".{name}.isopropyl-download"
    try:
        os.mkdir(stage_name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    try:
        descriptor = os.open(stage_name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        raise LinuxDownloadError(f"Download resume directory is unsafe: {error}") from error
    status = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(status.st_mode) or status.st_uid != os.geteuid()
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise LinuxDownloadError("Download resume directory has unsafe ownership or mode")
    if any(entry != "partial" for entry in os.listdir(descriptor)):
        os.close(descriptor)
        raise LinuxDownloadError("Download resume directory contains unexpected entries")
    return descriptor, stage_name, status


def _revalidate_directory(path: Path, descriptor: int) -> None:
    current = -1
    try:
        current = _open_absolute_directory(path)
        opened = os.fstat(descriptor)
        named = os.fstat(current)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise LinuxDownloadError("Download destination directory changed")
    except OSError as error:
        raise LinuxDownloadError(f"Download destination directory changed: {error}") from error
    finally:
        if current >= 0:
            os.close(current)


def _open_partial(stage_fd: int, expected_size: int) -> tuple[int, os.stat_result]:
    try:
        descriptor = os.open("partial", _FILE_FLAGS, dir_fd=stage_fd)
    except FileNotFoundError:
        try:
            descriptor = os.open(
                "partial", _FILE_FLAGS | os.O_CREAT | os.O_EXCL, 0o600,
                dir_fd=stage_fd,
            )
        except OSError as error:
            raise LinuxDownloadError(f"Partial download path is unsafe: {error}") from error
    except OSError as error:
        raise LinuxDownloadError(f"Partial download path is unsafe: {error}") from error
    status = os.fstat(descriptor)
    if (
        not stat.S_ISREG(status.st_mode) or status.st_uid != os.geteuid()
        or status.st_nlink != 1 or stat.S_IMODE(status.st_mode) != 0o600
        or status.st_size > expected_size
    ):
        os.close(descriptor)
        raise LinuxDownloadError("Partial download has unsafe identity, mode, or size")
    return descriptor, status


def _hash_partial(
    descriptor: int, size: int, *, deadline: float, cancel_event: threading.Event,
    cancel_check: CancelCheck | None,
) -> hashlib._Hash:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        _check_cancel(cancel_event, cancel_check)
        _deadline_check(deadline)
        block = os.pread(descriptor, min(READ_SIZE, size - offset), offset)
        if not block:
            raise LinuxDownloadError("Partial download changed while it was read")
        digest.update(block)
        offset += len(block)
    return digest


def _verify_completed_partial(
    stage_fd: int, descriptor: int, release: LinuxImageRelease, *, deadline: float,
    cancel_event: threading.Event, cancel_check: CancelCheck | None,
) -> tuple[os.stat_result, str]:
    """Re-read exact final bytes and freeze descriptor/path identity for publish."""

    before = os.fstat(descriptor)
    named_before = os.stat("partial", dir_fd=stage_fd, follow_symlinks=False)
    if (
        not _same_file(before, named_before) or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1 or before.st_size != release.size
    ):
        raise LinuxDownloadError("Completed partial image changed before final verification")
    digest = _hash_partial(
        descriptor, release.size, deadline=deadline, cancel_event=cancel_event,
        cancel_check=cancel_check,
    ).hexdigest()
    _check_cancel(cancel_event, cancel_check)
    _deadline_check(deadline)
    after = os.fstat(descriptor)
    named_after = os.stat("partial", dir_fd=stage_fd, follow_symlinks=False)
    if not _same_file(before, after) or not _same_file(after, named_after):
        raise LinuxDownloadError("Completed partial image changed during final verification")
    if not hmac.compare_digest(digest, release.sha256):
        raise LinuxDownloadError("Completed image failed its final signed SHA-256 checksum")
    return after, digest


def _revalidate_stage(parent_fd: int, name: str, descriptor: int, expected: os.stat_result) -> None:
    opened = os.fstat(descriptor)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        not stat.S_ISDIR(named.st_mode)
        or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
        or (named.st_dev, named.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        raise LinuxDownloadError("Download resume directory changed while it was in use")


def _parse_decimal_header(value: str | None, label: str) -> int:
    if (
        value is None or len(value) > 20 or not value.isascii()
        or not value.isdecimal()
    ):
        raise LinuxDownloadError(f"Response omitted a valid {label}")
    return int(value)


def _download_image(
    release: LinuxImageRelease, descriptor: int, initial: os.stat_result,
    opener: OpenUrl, progress: Progress | None, *, deadline: float,
    cancel_event: threading.Event, cancel_check: CancelCheck | None,
) -> tuple[os.stat_result, str]:
    done = initial.st_size
    digest = _hash_partial(
        descriptor, done, deadline=deadline, cancel_event=cancel_event,
        cancel_check=cancel_check,
    )
    if done == release.size:
        value = digest.hexdigest()
        if not hmac.compare_digest(value, release.sha256):
            raise LinuxDownloadError("Completed partial download has the wrong checksum")
        if progress is not None:
            progress(done, release.size)
        return os.fstat(descriptor), value
    filesystem = os.fstatvfs(descriptor)
    available = filesystem.f_bavail * filesystem.f_frsize
    if available < release.size - done + FREE_SPACE_RESERVE:
        raise LinuxDownloadError("Not enough free space for the image and safety reserve")
    headers = {"Accept-Encoding": "identity"}
    if done:
        headers["Range"] = f"bytes={done}-"
    request = urllib.request.Request(release.image_url, headers=headers)
    response = _open_response(
        opener, request, deadline=deadline, cancel_event=cancel_event,
        cancel_check=cancel_check,
    )
    try:
        _validate_response_url(response, release.image_url)
        status = _status(response)
        if _header(response, "Content-Encoding") not in (None, "identity"):
            raise LinuxDownloadError("Image response used an unexpected content encoding")
        content_length = _parse_decimal_header(
            _header(response, "Content-Length"), "Content-Length"
        )
        if done and status == 200:
            if content_length != release.size:
                raise LinuxDownloadError("Restart response has the wrong exact size")
            os.ftruncate(descriptor, 0)
            os.fsync(descriptor)
            done = 0
            digest = hashlib.sha256()
        elif done and status == 206:
            expected_range = f"bytes {done}-{release.size - 1}/{release.size}"
            if _header(response, "Content-Range") != expected_range:
                raise LinuxDownloadError("Resume response has the wrong Content-Range")
        elif not done and status != 200:
            raise LinuxDownloadError("Image server returned an unexpected HTTP status")
        elif done and status not in (200, 206):
            raise LinuxDownloadError("Image server refused a safe resume")
        expected_body = release.size - done
        if content_length != expected_body:
            raise LinuxDownloadError("Image response has the wrong exact size")
        os.lseek(descriptor, done, os.SEEK_SET)
        if progress is not None:
            progress(done, release.size)
        for block in _response_blocks(
            response, deadline=deadline, cancel_event=cancel_event,
            cancel_check=cancel_check,
        ):
            if done + len(block) > release.size:
                raise LinuxDownloadError("Image response exceeded its cataloged size")
            view = memoryview(block)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise LinuxDownloadError("Could not write the partial image")
                view = view[written:]
            digest.update(block)
            done += len(block)
            if progress is not None:
                progress(done, release.size)
        if done != release.size:
            raise LinuxDownloadError("Image download ended before its exact size")
        value = digest.hexdigest()
        if not hmac.compare_digest(value, release.sha256):
            raise LinuxDownloadError("Downloaded image failed its signed SHA-256 checksum")
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        return final, value
    finally:
        try:
            response.close()
        except Exception:
            pass


class LinuxIsoDownloader:
    """Cancellable downloader; network I/O starts only when ``download`` is called.

    Cancellation is observed between synchronous transport operations. With the
    production transport, acknowledgement can therefore wait for the current
    connection or read operation's timeout, normally no more than 30 seconds.
    The atomic destination hardlink is the absolute commit point. Same-user
    mutation or namespace replacement after that syscall is outside the
    downloader's guarantee, just as mutation immediately after return is.
    """

    def __init__(self, cancel_event: threading.Event | None = None) -> None:
        self._cancel_event = cancel_event or threading.Event()

    @property
    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def cancel(self) -> None:
        self._cancel_event.set()

    def download(
        self, release: LinuxImageRelease, destination: Path,
        progress: Progress | None = None, *, cancel_check: CancelCheck | None = None,
        overall_timeout: float = 6 * 60 * 60, opener: OpenUrl = _default_urlopen,
    ) -> DownloadedLinuxImage:
        catalog = available_linux_images()
        if (
            type(release) is not LinuxImageRelease
            or not any(release is item for item in catalog)
        ):
            raise LinuxDownloadCatalogError("Download release is not an exact catalog entry")
        if (
            isinstance(overall_timeout, bool) or not isinstance(overall_timeout, (int, float))
            or not 0 < overall_timeout <= MAX_DOWNLOAD_TIMEOUT
        ):
            raise ValueError("Download timeout must be between 0 and 24 hours")
        native_path_type = type(Path())
        if type(destination) is not native_path_type:
            raise ValueError("Download destination must be an exact native pathlib.Path")
        if not destination.is_absolute():
            raise ValueError("Download destination must be an absolute pathlib.Path")
        destination_name = destination.name
        destination_parent = destination.parent
        if (
            type(destination_name) is not str
            or type(destination_parent) is not native_path_type
        ):
            raise ValueError("Download destination path primitives are invalid")
        if destination_name != release.filename:
            raise ValueError("Download destination must retain the exact cataloged filename")
        deadline = time.monotonic() + float(overall_timeout)
        parent_fd = stage_fd = partial_fd = -1
        stage_name = ""
        stage_identity: os.stat_result | None = None
        remove_bad_partial = False
        published_identity: tuple[int, int] | None = None
        committed = False
        try:
            parent_fd = _open_absolute_directory(destination_parent)
            _assert_destination_absent(parent_fd, destination_name)
            _check_cancel(self._cancel_event, cancel_check)
            _verify_release_metadata(
                release, opener, deadline=deadline, cancel_event=self._cancel_event,
                cancel_check=cancel_check,
            )
            # Metadata is authenticated before the resumable on-disk state is touched.
            _assert_destination_absent(parent_fd, destination_name)
            stage_fd, stage_name, stage_identity = _open_stage(parent_fd, destination_name)
            partial_fd, initial = _open_partial(stage_fd, release.size)
            _download_image(
                release, partial_fd, initial, opener, progress, deadline=deadline,
                cancel_event=self._cancel_event, cancel_check=cancel_check,
            )
            assert stage_identity is not None
            _revalidate_stage(parent_fd, stage_name, stage_fd, stage_identity)
            _revalidate_directory(destination_parent, parent_fd)
            _check_cancel(self._cancel_event, cancel_check)
            _deadline_check(deadline)
            os.fsync(partial_fd)
            os.fsync(stage_fd)
            final, digest = _verify_completed_partial(
                stage_fd, partial_fd, release, deadline=deadline,
                cancel_event=self._cancel_event, cancel_check=cancel_check,
            )
            # The verifier's pre-stat cancellation/deadline check is the final
            # boundary. Both cancel_check and a supplied Event.is_set may be
            # caller code, so os.link must be the very next operation.
            try:
                os.link(
                    "partial", destination_name, src_dir_fd=stage_fd,
                    dst_dir_fd=parent_fd, follow_symlinks=False,
                )
            except FileExistsError as error:
                raise LinuxDownloadError(
                    "Download destination appeared and was not overwritten"
                ) from error
            committed = True
            published_identity = (final.st_dev, final.st_ino)
            try:
                os.fsync(parent_fd)
            except OSError:
                pass

            # Cleanup is deliberately best-effort after commit. It must never
            # convert a verified published image into an ambiguous failure.
            cleanup_private = False
            try:
                linked = os.fstat(partial_fd)
                named_partial = os.stat(
                    "partial", dir_fd=stage_fd, follow_symlinks=False,
                )
                named_destination = os.stat(
                    destination_name, dir_fd=parent_fd, follow_symlinks=False,
                )
                if (
                    _same_file(linked, named_partial)
                    and _same_file(linked, named_destination)
                    and stat.S_ISREG(linked.st_mode) and linked.st_nlink == 2
                    and linked.st_size == release.size
                    and linked.st_mtime_ns == final.st_mtime_ns
                    and (linked.st_dev, linked.st_ino) == published_identity
                ):
                    os.unlink("partial", dir_fd=stage_fd)
                    cleanup_private = True
            except OSError:
                pass

            if cleanup_private:
                try:
                    _revalidate_stage(parent_fd, stage_name, stage_fd, stage_identity)
                    named_stage = os.stat(
                        stage_name, dir_fd=parent_fd, follow_symlinks=False,
                    )
                    if (
                        stat.S_ISDIR(named_stage.st_mode)
                        and (named_stage.st_dev, named_stage.st_ino)
                        == (stage_identity.st_dev, stage_identity.st_ino)
                    ):
                        os.rmdir(stage_name, dir_fd=parent_fd)
                except (LinuxDownloadError, OSError):
                    pass
            try:
                os.fsync(parent_fd)
            except OSError:
                pass

            # Link success is absolute commit. Even a subsequent identity check
            # could race a same-user namespace mutation, so nothing below the
            # commit point is permitted to turn the verified result into failure.
            return DownloadedLinuxImage(destination, release.id, release.size, digest)
        except LinuxDownloadCancelled:
            raise
        except LinuxDownloadError as error:
            remove_bad_partial = "checksum" in str(error).casefold()
            raise
        except (OSError, urllib.error.URLError) as error:
            raise LinuxDownloadError(f"Linux image download failed safely: {error}") from error
        finally:
            if partial_fd >= 0:
                try:
                    os.close(partial_fd)
                except OSError:
                    if not committed:
                        raise
            if remove_bad_partial and stage_fd >= 0:
                try:
                    os.unlink("partial", dir_fd=stage_fd)
                except OSError:
                    pass
            if stage_fd >= 0:
                try:
                    os.close(stage_fd)
                except OSError:
                    if not committed:
                        raise
            if parent_fd >= 0:
                try:
                    os.close(parent_fd)
                except OSError:
                    if not committed:
                        raise
