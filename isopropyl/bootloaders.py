from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import urllib.request
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol
from urllib.parse import urlparse


CATALOG_VERSION = 1
MAX_ARTIFACT_SIZE = 256 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~@-]*\Z")


class CatalogError(ValueError):
    """The bundled bootloader catalog is malformed or unsafe."""


class DownloadError(RuntimeError):
    """A bootloader dependency could not be downloaded and verified."""


class DependencyUnavailable(RuntimeError):
    """No matching local or cataloged dependency is available."""


class DownloadResponse(Protocol):
    def read(self, size: int = -1) -> bytes: ...
    def geturl(self) -> str: ...
    def close(self) -> None: ...


OpenUrl = Callable[..., DownloadResponse]
RunCommand = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class BootloaderResource:
    family: str
    version: str
    name: str
    url: str
    sha256: str
    size: int
    allowed_hosts: tuple[str, ...]

    @property
    def key(self) -> tuple[str, str, str]:
        return self.family, self.version, self.name


@dataclass(frozen=True)
class BootloaderCatalog:
    resources: tuple[BootloaderResource, ...]

    def find(self, family: str, version: str, name: str) -> BootloaderResource | None:
        wanted = family.casefold(), version, name
        return next(
            (item for item in self.resources
             if (item.family.casefold(), item.version, item.name) == wanted),
            None,
        )


@dataclass(frozen=True)
class ResolvedDependency:
    path: Path
    source: str
    family: str
    version: str


def default_catalog_path() -> Path:
    return Path(__file__).with_name("data") / "bootloaders-v1.json"


def default_cache_dir() -> Path:
    configured = os.environ.get("XDG_CACHE_HOME")
    root = Path(configured).expanduser() if configured else Path.home() / ".cache"
    return root / "isopropyl" / "bootloaders"


def _required_text(item: dict[str, object], field: str) -> str:
    value = item.get(field)
    if not isinstance(value, str) or not value:
        raise CatalogError(f"Bootloader resource field {field!r} must be non-empty text")
    return value


def _safe_component(value: str, field: str) -> str:
    if not SAFE_COMPONENT.fullmatch(value) or value in {".", ".."}:
        raise CatalogError(f"Unsafe bootloader resource {field}: {value!r}")
    return value


def _https_host(url: str, field: str = "url") -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise CatalogError(f"Bootloader resource {field} must be an HTTPS URL")
    return parsed.hostname.casefold()


def load_catalog(path: Path | None = None) -> BootloaderCatalog:
    source = path or default_catalog_path()
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CatalogError(f"Could not read bootloader catalog: {error}") from error
    if not isinstance(payload, dict) or payload.get("catalog_version") != CATALOG_VERSION:
        raise CatalogError(f"Bootloader catalog must use version {CATALOG_VERSION}")
    raw_resources = payload.get("resources")
    if not isinstance(raw_resources, list):
        raise CatalogError("Bootloader catalog resources must be a list")

    resources: list[BootloaderResource] = []
    keys: set[tuple[str, str, str]] = set()
    for raw in raw_resources:
        if not isinstance(raw, dict):
            raise CatalogError("Each bootloader resource must be an object")
        family = _safe_component(_required_text(raw, "family"), "family")
        version = _safe_component(_required_text(raw, "version"), "version")
        name = _safe_component(_required_text(raw, "name"), "name")
        url = _required_text(raw, "url")
        origin_host = _https_host(url)
        digest = _required_text(raw, "sha256").casefold()
        if not SHA256.fullmatch(digest):
            raise CatalogError("Bootloader resource sha256 must contain 64 hexadecimal digits")
        size = raw.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_ARTIFACT_SIZE:
            raise CatalogError(
                f"Bootloader resource size must be between 1 and {MAX_ARTIFACT_SIZE} bytes"
            )
        raw_hosts = raw.get("allowed_hosts", [])
        if not isinstance(raw_hosts, list) or not all(
            isinstance(host, str) and host for host in raw_hosts
        ):
            raise CatalogError("Bootloader resource allowed_hosts must be a list of host names")
        allowed_hosts = {origin_host}
        for host in raw_hosts:
            assert isinstance(host, str)
            if "://" in host or "/" in host or "@" in host:
                raise CatalogError(f"Invalid allowed download host: {host!r}")
            allowed_hosts.add(host.casefold().rstrip("."))
        resource = BootloaderResource(
            family, version, name, url, digest, size, tuple(sorted(allowed_hosts))
        )
        if resource.key in keys:
            raise CatalogError(f"Duplicate bootloader resource: {'/'.join(resource.key)}")
        keys.add(resource.key)
        resources.append(resource)
    return BootloaderCatalog(tuple(resources))


def verify_resource(path: Path, resource: BootloaderResource) -> bool:
    try:
        if path.stat().st_size != resource.size or not path.is_file():
            return False
        digest = hashlib.sha256()
        with path.open("rb", buffering=0) as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
        return hmac.compare_digest(digest.hexdigest(), resource.sha256)
    except OSError:
        return False


def _validate_final_url(url: str, resource: BootloaderResource) -> None:
    try:
        host = _https_host(url, "redirect")
    except CatalogError as error:
        raise DownloadError(str(error)) from error
    if host not in resource.allowed_hosts:
        raise DownloadError(f"Download redirected to untrusted host {host!r}")


def fetch_resource(
    resource: BootloaderResource,
    cache_dir: Path | None = None,
    opener: OpenUrl = urllib.request.urlopen,
    cancel_event: threading.Event | None = None,
) -> Path:
    """Fetch a cataloged artifact, accepting it only after size and SHA-256 checks.

    The catalog is shipped with ISOpropyl. Network metadata is never trusted to
    choose a URL, version, size, or digest.
    """
    def check_cancelled() -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise DownloadError("Bootloader download was cancelled")

    check_cancelled()
    root = cache_dir or default_cache_dir()
    destination = root / resource.family / resource.version / resource.name
    if verify_resource(destination, resource):
        check_cancelled()
        return destination
    # Never retain a known-bad object under a trusted cache key. A failed
    # replacement download must leave the dependency unavailable, not leave a
    # tampered file for another consumer to find.
    destination.unlink(missing_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    request = urllib.request.Request(
        resource.url,
        headers={"User-Agent": "ISOpropyl-USB-Writer/0.1 bootloader-resolver"},
    )
    temporary: Path | None = None
    try:
        check_cancelled()
        response = opener(request, timeout=30)
        with closing(response):
            check_cancelled()
            _validate_final_url(response.geturl(), resource)
            descriptor, name = tempfile.mkstemp(
                prefix=".isopropyl-download-", dir=destination.parent
            )
            temporary = Path(name)
            digest = hashlib.sha256()
            total = 0
            with os.fdopen(descriptor, "wb", buffering=0) as output:
                while True:
                    check_cancelled()
                    block = response.read(min(1024 * 1024, resource.size - total + 1))
                    if not block:
                        break
                    total += len(block)
                    if total > resource.size:
                        raise DownloadError("Downloaded bootloader artifact is larger than cataloged")
                    digest.update(block)
                    output.write(block)
                check_cancelled()
                os.fsync(output.fileno())
        if total != resource.size:
            raise DownloadError(
                f"Downloaded {total} bytes, but the trusted catalog requires {resource.size}"
            )
        if not hmac.compare_digest(digest.hexdigest(), resource.sha256):
            raise DownloadError("Downloaded bootloader artifact failed SHA-256 verification")
        temporary.chmod(0o600)
        os.replace(temporary, destination)
        temporary = None
        return destination
    except DownloadError:
        raise
    except Exception as error:
        raise DownloadError(f"Could not download bootloader artifact: {error}") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def installed_tool_matches(
    program: str,
    version: str,
    runner: RunCommand = subprocess.run,
) -> Path | None:
    executable = shutil.which(program)
    if not executable:
        return None
    try:
        result = runner(
            [executable, "--version"], capture_output=True, text=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = f"{result.stdout}\n{result.stderr}"
    # A distro package suffix such as `2.12-5ubuntu2` is acceptable for an
    # upstream 2.12 request. A different point release such as 2.12.1 is not.
    pattern = rf"(?<![A-Za-z0-9.]){re.escape(version)}(?![A-Za-z0-9.])"
    return Path(executable) if result.returncode == 0 and re.search(pattern, output) else None


def resolve_system_tool(
    family: str,
    version: str,
    program: str,
    *,
    runner: RunCommand = subprocess.run,
) -> ResolvedDependency:
    """Resolve a host executable only; it can never stand in for boot payload bytes."""
    installed = installed_tool_matches(program, version, runner)
    if not installed:
        raise DependencyUnavailable(
            f"No installed {family} {version} tool named {program!r} is available"
        )
    return ResolvedDependency(installed, "system-tool", family, version)


def resolve_artifact(
    family: str,
    version: str,
    name: str,
    *,
    catalog: BootloaderCatalog | None = None,
    cache_dir: Path | None = None,
    opener: OpenUrl = urllib.request.urlopen,
) -> ResolvedDependency:
    """Resolve boot payload bytes only from the release-bundled trusted catalog."""
    available = catalog or load_catalog()
    resource = available.find(family, version, name)
    if not resource:
        raise DependencyUnavailable(
            f"No verified {family} {version} dependency named {name!r} is cataloged"
        )
    return ResolvedDependency(
        fetch_resource(resource, cache_dir, opener), "verified-download", family, version
    )


def reverify_artifact(
    dependency: ResolvedDependency,
    name: str,
    catalog: BootloaderCatalog | None = None,
) -> bool:
    """Recheck a resolved artifact immediately before a privileged consumer uses it."""
    if dependency.source != "verified-download":
        return False
    available = catalog or load_catalog()
    resource = available.find(dependency.family, dependency.version, name)
    return bool(resource and verify_resource(dependency.path, resource))
