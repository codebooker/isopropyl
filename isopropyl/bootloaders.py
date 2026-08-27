from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import threading
import urllib.request
from collections.abc import Callable, Iterable
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


@dataclass(frozen=True)
class CachedBootloaderArtifact:
    """One catalog-known path currently present in the verified artifact cache."""

    family: str
    version: str
    name: str
    size: int
    hash_valid: bool
    deletion_safe: bool
    issue: str = ""

    @property
    def key(self) -> tuple[str, str, str]:
        return self.family, self.version, self.name


@dataclass(frozen=True)
class BootloaderCacheInventory:
    artifacts: tuple[CachedBootloaderArtifact, ...]
    total_size: int
    deletable_size: int
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class CacheDeletion:
    family: str
    version: str
    name: str
    size: int

    @property
    def key(self) -> tuple[str, str, str]:
        return self.family, self.version, self.name


@dataclass(frozen=True)
class CacheDeletionSkip:
    family: str
    version: str
    name: str
    reason: str

    @property
    def key(self) -> tuple[str, str, str]:
        return self.family, self.version, self.name


@dataclass(frozen=True)
class BootloaderCacheDeletionResult:
    deleted: tuple[CacheDeletion, ...]
    skipped: tuple[CacheDeletionSkip, ...]
    bytes_deleted: int
    issues: tuple[str, ...] = ()


def default_catalog_path() -> Path:
    return Path(__file__).with_name("data") / "bootloaders-v1.json"


def default_cache_dir() -> Path:
    configured = os.environ.get("XDG_CACHE_HOME")
    root = Path(configured).expanduser() if configured else Path.home() / ".cache"
    return root / "isopropyl" / "bootloaders"


_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_OPEN_FLAGS = (
    os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
)


class _CachePathMissing(Exception):
    pass


class _CachePathUnsafe(Exception):
    pass


def _validated_cache_resources(
    catalog: BootloaderCatalog,
) -> tuple[BootloaderResource, ...]:
    seen: set[tuple[str, str, str]] = set()
    validated: list[BootloaderResource] = []
    for resource in catalog.resources:
        if not isinstance(resource, BootloaderResource):
            raise CatalogError("The bootloader cache catalog contains an invalid resource")
        for field, value in (
            ("family", resource.family),
            ("version", resource.version),
            ("name", resource.name),
        ):
            _safe_component(value, field)
        if (
            not isinstance(resource.size, int)
            or isinstance(resource.size, bool)
            or not 0 < resource.size <= MAX_ARTIFACT_SIZE
            or not isinstance(resource.sha256, str)
            or not SHA256.fullmatch(resource.sha256)
        ):
            raise CatalogError("The bootloader cache catalog has invalid size or hash metadata")
        if resource.key in seen:
            raise CatalogError(f"Duplicate bootloader resource: {'/'.join(resource.key)}")
        seen.add(resource.key)
        validated.append(resource)
    return tuple(validated)


def _open_absolute_directory_nofollow(path: Path) -> int:
    """Open every component independently so no cache-directory symlink is followed."""

    if not path.is_absolute() or any(part == ".." for part in path.parts):
        raise _CachePathUnsafe("The bootloader cache path is not a safe absolute path")
    descriptor = os.open("/", _DIRECTORY_OPEN_FLAGS)
    try:
        for component in path.parts[1:]:
            if component in {"", ".", ".."}:
                raise _CachePathUnsafe("The bootloader cache path is not canonical")
            try:
                child = os.open(component, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
            except FileNotFoundError as error:
                raise _CachePathMissing from error
            except OSError as error:
                raise _CachePathUnsafe(
                    f"The bootloader cache directory is unsafe: {error.strerror or error}"
                ) from error
            previous = descriptor
            descriptor = -1
            try:
                os.close(previous)
            except BaseException:
                os.close(child)
                raise
            descriptor = child
        return descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _open_resource_parent(root_descriptor: int, resource: BootloaderResource) -> int:
    descriptor = os.dup(root_descriptor)
    try:
        for component in (resource.family, resource.version):
            try:
                child = os.open(component, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
            except FileNotFoundError as error:
                raise _CachePathMissing from error
            except OSError as error:
                raise _CachePathUnsafe(
                    f"Unsafe cache directory for {'/'.join(resource.key)}: "
                    f"{error.strerror or error}"
                ) from error
            previous = descriptor
            descriptor = -1
            try:
                os.close(previous)
            except BaseException:
                os.close(child)
                raise
            descriptor = child
        return descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_nlink,
        left.st_size,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_nlink,
        right.st_size,
    )


def _stable_file(left: os.stat_result, right: os.stat_result) -> bool:
    return _same_object(left, right) and (
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _unsafe_artifact(
    resource: BootloaderResource, issue: str, size: int = 0,
) -> CachedBootloaderArtifact:
    return CachedBootloaderArtifact(
        resource.family, resource.version, resource.name, max(0, size),
        False, False, issue,
    )


def _inventory_resource(
    root_descriptor: int,
    resource: BootloaderResource,
) -> CachedBootloaderArtifact | None:
    try:
        parent = _open_resource_parent(root_descriptor, resource)
    except _CachePathMissing:
        return None
    except _CachePathUnsafe as error:
        return _unsafe_artifact(resource, str(error))
    try:
        try:
            observed = os.stat(resource.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as error:
            return _unsafe_artifact(resource, f"Could not inspect cache entry: {error}")
        if stat.S_ISLNK(observed.st_mode):
            return _unsafe_artifact(resource, "Cache entry is a symbolic link")
        if not stat.S_ISREG(observed.st_mode):
            return _unsafe_artifact(resource, "Cache entry is not a regular file")
        try:
            artifact = os.open(resource.name, _FILE_OPEN_FLAGS, dir_fd=parent)
        except OSError as error:
            return _unsafe_artifact(
                resource, f"Could not safely open cache entry: {error}", observed.st_size,
            )
        try:
            opened = os.fstat(artifact)
            if not _same_object(observed, opened):
                return _unsafe_artifact(
                    resource, "Cache entry changed while it was opened", observed.st_size,
                )
            valid = False
            if opened.st_size == resource.size:
                digest = hashlib.sha256()
                remaining = resource.size
                while remaining:
                    block = os.read(artifact, min(1024 * 1024, remaining))
                    if not block:
                        break
                    digest.update(block)
                    remaining -= len(block)
                final = os.fstat(artifact)
                valid = (
                    remaining == 0
                    and _stable_file(opened, final)
                    and hmac.compare_digest(digest.hexdigest(), resource.sha256)
                )
                if not _stable_file(opened, final):
                    return _unsafe_artifact(
                        resource, "Cache entry changed while it was verified", final.st_size,
                    )
            deletion_safe = opened.st_nlink == 1
            issue = "" if deletion_safe else "Cache entry has more than one hard link"
            return CachedBootloaderArtifact(
                resource.family, resource.version, resource.name, opened.st_size,
                valid, deletion_safe, issue,
            )
        except OSError as error:
            return _unsafe_artifact(
                resource, f"Could not safely verify cache entry: {error}", observed.st_size,
            )
        finally:
            os.close(artifact)
    finally:
        os.close(parent)


def inventory_cache(
    *,
    catalog: BootloaderCatalog | None = None,
) -> BootloaderCacheInventory:
    """Inventory only catalog-known paths in the existing XDG ISOpropyl cache."""

    resources = _validated_cache_resources(catalog or load_catalog())
    try:
        root = _open_absolute_directory_nofollow(default_cache_dir())
    except _CachePathMissing:
        return BootloaderCacheInventory((), 0, 0)
    except _CachePathUnsafe as error:
        return BootloaderCacheInventory((), 0, 0, (str(error),))
    try:
        artifacts = tuple(
            artifact
            for resource in resources
            if (artifact := _inventory_resource(root, resource)) is not None
        )
    finally:
        os.close(root)
    return BootloaderCacheInventory(
        artifacts,
        sum(item.size for item in artifacts),
        sum(item.size for item in artifacts if item.deletion_safe),
    )


def _deletion_skip(
    key: tuple[str, str, str], reason: str,
) -> CacheDeletionSkip:
    return CacheDeletionSkip(*key, reason)


@dataclass(frozen=True)
class _QuarantineRestore:
    note: str
    issues: tuple[str, ...] = ()


def _restore_quarantined_entry(
    quarantine: int,
    parent: int,
    name: str,
) -> _QuarantineRestore:
    """Restore without replacing anything that appeared at the catalog path."""

    try:
        os.link(
            "artifact", name, src_dir_fd=quarantine, dst_dir_fd=parent,
            follow_symlinks=False,
        )
    except OSError as error:
        return _QuarantineRestore(
            f"; the cache artifact could not be restored and was retained in "
            f"a private quarantine: {error}"
        )
    try:
        os.unlink("artifact", dir_fd=quarantine)
    except OSError as error:
        return _QuarantineRestore(
            f"; the cache artifact was restored, but a second link was retained "
            f"in the private quarantine: {error}"
        )
    try:
        os.fsync(parent)
    except OSError as error:
        issue = f"Could not fsync the restored cache artifact directory: {error}"
        return _QuarantineRestore(
            "; the cache artifact was restored, but its directory could not be fsynced",
            (issue,),
        )
    return _QuarantineRestore("; the cache artifact was restored")


def _delete_resource(
    root_descriptor: int,
    resource: BootloaderResource,
) -> tuple[CacheDeletion | None, CacheDeletionSkip | None, tuple[str, ...]]:
    key = resource.key
    try:
        parent = _open_resource_parent(root_descriptor, resource)
    except _CachePathMissing:
        return None, _deletion_skip(key, "Cache artifact is not present"), ()
    except _CachePathUnsafe as error:
        return None, _deletion_skip(key, str(error)), ()
    quarantine_name = ""
    quarantine = -1
    artifact = -1
    issues: list[str] = []

    def finish_quarantine() -> None:
        nonlocal quarantine, quarantine_name
        if quarantine >= 0:
            try:
                os.close(quarantine)
            except OSError as error:
                issues.append(
                    f"Could not close deletion quarantine for {'/'.join(key)}: {error}"
                )
            quarantine = -1
        if not quarantine_name:
            return
        try:
            os.rmdir(quarantine_name, dir_fd=parent)
        except OSError as error:
            issues.append(
                f"Could not remove deletion quarantine for {'/'.join(key)}: {error}"
            )
        else:
            try:
                os.fsync(parent)
            except OSError as error:
                issues.append(
                    f"Could not fsync cache directory after quarantine removal for "
                    f"{'/'.join(key)}: {error}"
                )
        quarantine_name = ""

    def refuse_after_isolation(reason: str) -> tuple[
        CacheDeletion | None, CacheDeletionSkip | None, tuple[str, ...]
    ]:
        restored = _restore_quarantined_entry(
            quarantine, parent, resource.name,
        )
        issues.extend(restored.issues)
        finish_quarantine()
        return None, _deletion_skip(key, reason + restored.note), tuple(issues)

    try:
        try:
            observed = os.stat(resource.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None, _deletion_skip(key, "Cache artifact is not present"), ()
        except OSError as error:
            return None, _deletion_skip(key, f"Could not inspect cache artifact: {error}"), ()
        if stat.S_ISLNK(observed.st_mode):
            return None, _deletion_skip(key, "Refusing to delete a symbolic link"), ()
        if not stat.S_ISREG(observed.st_mode):
            return None, _deletion_skip(key, "Refusing to delete a non-regular file"), ()
        if observed.st_nlink != 1:
            return None, _deletion_skip(key, "Refusing to delete a multiply linked file"), ()
        try:
            artifact = os.open(resource.name, _FILE_OPEN_FLAGS, dir_fd=parent)
        except OSError as error:
            return None, _deletion_skip(key, f"Could not safely open cache artifact: {error}"), ()
        try:
            opened = os.fstat(artifact)
        except OSError as error:
            return None, _deletion_skip(
                key, f"Could not bind cache artifact before deletion: {error}",
            ), ()
        if (
            not _same_object(observed, opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
        ):
            return None, _deletion_skip(key, "Cache artifact changed before deletion"), ()

        for _attempt in range(16):
            candidate = f".isopropyl-delete-{secrets.token_hex(16)}"
            try:
                os.mkdir(candidate, mode=0o700, dir_fd=parent)
            except FileExistsError:
                continue
            except OSError as error:
                return None, _deletion_skip(
                    key, f"Could not allocate a private deletion quarantine: {error}",
                ), ()
            quarantine_name = candidate
            break
        if not quarantine_name:
            return None, _deletion_skip(key, "Could not allocate a private deletion quarantine"), ()
        try:
            quarantine = os.open(
                quarantine_name, _DIRECTORY_OPEN_FLAGS, dir_fd=parent,
            )
        except OSError as error:
            finish_quarantine()
            return None, _deletion_skip(
                key, f"Could not open the private deletion quarantine: {error}",
            ), tuple(issues)

        try:
            os.rename(
                resource.name, "artifact", src_dir_fd=parent, dst_dir_fd=quarantine,
            )
        except FileNotFoundError:
            finish_quarantine()
            return None, _deletion_skip(
                key, "Cache artifact disappeared before deletion",
            ), tuple(issues)
        except OSError as error:
            finish_quarantine()
            return None, _deletion_skip(
                key, f"Could not isolate cache artifact: {error}",
            ), tuple(issues)

        try:
            isolated = os.stat("artifact", dir_fd=quarantine, follow_symlinks=False)
        except OSError as error:
            return refuse_after_isolation(
                f"Could not revalidate isolated cache artifact: {error}"
            )
        try:
            final_open = os.fstat(artifact)
        except OSError as error:
            return refuse_after_isolation(
                f"Could not revalidate the opened cache artifact: {error}"
            )
        if (
            not _same_object(opened, final_open)
            or not _same_object(isolated, final_open)
            or not stat.S_ISREG(isolated.st_mode)
            or isolated.st_nlink != 1
        ):
            return refuse_after_isolation("Cache artifact changed during deletion")

        try:
            os.unlink("artifact", dir_fd=quarantine)
        except OSError as error:
            return refuse_after_isolation(
                f"Could not delete isolated cache artifact: {error}"
            )
        try:
            os.fsync(quarantine)
        except OSError as error:
            issues.append(f"Could not fsync deletion quarantine for {'/'.join(key)}: {error}")
        size = isolated.st_size
        finish_quarantine()
        return CacheDeletion(*key, size), None, tuple(issues)
    finally:
        try:
            if artifact >= 0:
                os.close(artifact)
        finally:
            try:
                finish_quarantine()
            finally:
                os.close(parent)


def delete_cached_artifacts(
    keys: Iterable[tuple[str, str, str]],
    *,
    catalog: BootloaderCatalog | None = None,
) -> BootloaderCacheDeletionResult:
    """Delete explicitly requested catalog-known files from the XDG cache.

    Unknown keys and unsafe filesystem objects are reported but never removed.
    No directory is created and no cache path is resolved through a symlink.
    """

    requested = tuple(keys)
    if any(
        not isinstance(key, tuple)
        or len(key) != 3
        or not all(isinstance(component, str) for component in key)
        for key in requested
    ):
        raise ValueError("Cache deletion keys must be exact family/version/name tuples")
    resources = _validated_cache_resources(catalog or load_catalog())
    known = {resource.key: resource for resource in resources}
    deleted: list[CacheDeletion] = []
    skipped: list[CacheDeletionSkip] = []
    issues: list[str] = []
    known_requests: list[BootloaderResource] = []
    for key in requested:
        resource = known.get(key)
        if resource is None:
            skipped.append(_deletion_skip(key, "Artifact is not present in the trusted catalog"))
        else:
            known_requests.append(resource)
    if not known_requests:
        return BootloaderCacheDeletionResult((), tuple(skipped), 0)
    try:
        root = _open_absolute_directory_nofollow(default_cache_dir())
    except _CachePathMissing:
        skipped.extend(
            _deletion_skip(resource.key, "Bootloader cache does not exist")
            for resource in known_requests
        )
        return BootloaderCacheDeletionResult((), tuple(skipped), 0)
    except _CachePathUnsafe as error:
        skipped.extend(_deletion_skip(resource.key, str(error)) for resource in known_requests)
        return BootloaderCacheDeletionResult((), tuple(skipped), 0, (str(error),))
    try:
        for resource in known_requests:
            try:
                removed, refused, item_issues = _delete_resource(root, resource)
            except OSError as error:
                removed = None
                refused = _deletion_skip(
                    resource.key,
                    f"A filesystem error interrupted cache deletion for this artifact: {error}",
                )
                item_issues = (
                    f"Unexpected cache-deletion filesystem error for "
                    f"{'/'.join(resource.key)}: {error}",
                )
            if removed is not None:
                deleted.append(removed)
            if refused is not None:
                skipped.append(refused)
            issues.extend(item_issues)
    finally:
        try:
            os.close(root)
        except OSError as error:
            issues.append(f"Could not close the bootloader cache directory: {error}")
    return BootloaderCacheDeletionResult(
        tuple(deleted), tuple(skipped), sum(item.size for item in deleted), tuple(issues),
    )


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
