from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import hmac
import json
import os
import queue
import re
import secrets
import shutil
import stat
import subprocess
import threading
import time
import urllib.request
from collections.abc import Callable, Iterable
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol
from urllib.parse import urlparse


CATALOG_VERSION = 2
MAX_ARTIFACT_SIZE = 256 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~@-]*\Z")
LICENSE_EXPRESSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+() -]{0,127}\Z")
TOOL_VERSION = re.compile(
    r"[0-9]{1,3}(?:\.[0-9]{1,3})+"
    r"(?:[-+~._:@][0-9A-Za-z.+~:_@-]{1,63})?\Z"
)
_TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_TRUSTED_TOOL_DIRECTORIES = frozenset(_TRUSTED_TOOL_PATH.split(":"))


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
DownloadProgress = Callable[[int, int], None]


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
    bundles: tuple["BootloaderBundle", ...] = ()

    def find(self, family: str, version: str, name: str) -> BootloaderResource | None:
        wanted = family.casefold(), version, name
        return next(
            (item for item in self.resources
             if (item.family.casefold(), item.version, item.name) == wanted),
            None,
        )

    def find_bundle(
        self, family: str, version: str, purpose: str,
    ) -> "BootloaderBundle | None":
        wanted = family.casefold(), version, purpose.casefold()
        return next(
            (
                item for item in self.bundles
                if (item.family.casefold(), item.version, item.purpose.casefold()) == wanted
            ),
            None,
        )


@dataclass(frozen=True)
class BootloaderBundle:
    """One exact, license-reviewed set of mutually compatible payload files."""

    family: str
    version: str
    purpose: str
    artifact_names: tuple[str, ...]
    license: str
    provenance_url: str


@dataclass(frozen=True)
class BoundBootArtifact:
    """Immutable payload bytes accepted from one exact catalog resource."""

    name: str
    data: bytes
    sha256: str

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass(frozen=True)
class BoundBootBundle:
    """An exact catalog bundle frozen in memory for a future privileged consumer."""

    family: str
    version: str
    purpose: str
    artifacts: tuple[BoundBootArtifact, ...]
    license: str
    provenance_url: str

    @property
    def total_size(self) -> int:
        return sum(item.size for item in self.artifacts)


_DEPENDENCY_PURPOSES = {
    "syslinux": "matched-bios-payloads",
}
_BUNDLE_ARTIFACTS = {
    ("uefi-ntfs", "uefi-ntfs-bridge"): ("uefi-ntfs.img",),
    ("uefi-shell", "blank-uefi-shell"): (
        "shellaa64.efi",
        "shellia32.efi",
        "shellloongarch64.efi",
        "shellriscv64.efi",
        "shellx64.efi",
    ),
    ("uefi-md5sum", "runtime-media-validation"): (
        "bootaa64_signed.efi",
        "bootarm.efi",
        "bootia32_signed.efi",
        "bootloongarch64.efi",
        "bootriscv64.efi",
        "bootx64_signed.efi",
    ),
    ("syslinux", "matched-bios-payloads"): ("ldlinux.bss", "ldlinux.sys"),
    ("syslinux", "blank-bios-module"): ("ldlinux.c32",),
    ("grub", "blank-bios-core-image"): ("core.img",),
    ("grub", "blank-bios-rescue-media"): ("boot.img", "core.img"),
}


def bundle_for_dependency(
    dependency_key: str,
    *,
    catalog: BootloaderCatalog | None = None,
) -> BootloaderBundle | None:
    """Return only an exact catalog match; version-prefix fallback is forbidden."""

    if not isinstance(dependency_key, str) or dependency_key.count(":") != 1:
        return None
    family, version = dependency_key.split(":", 1)
    if (
        family not in _DEPENDENCY_PURPOSES
        or not SAFE_COMPONENT.fullmatch(version)
    ):
        return None
    available = catalog or load_catalog()
    purpose = _DEPENDENCY_PURPOSES[family]
    return next(
        (
            item for item in _validated_catalog_bundles(available)
            if (
                item.family.casefold(), item.version, item.purpose.casefold()
            ) == (family, version, purpose)
        ),
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
    return Path(__file__).with_name("data") / "bootloaders-v2.json"


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
        origin_host = _https_host(resource.url)
        if (
            not isinstance(resource.allowed_hosts, tuple)
            or not resource.allowed_hosts
            or not all(isinstance(host, str) and host for host in resource.allowed_hosts)
        ):
            raise CatalogError("The bootloader cache catalog has invalid allowed hosts")
        normalized_hosts = tuple(sorted({host.casefold().rstrip(".") for host in resource.allowed_hosts}))
        if (
            normalized_hosts != resource.allowed_hosts
            or origin_host not in normalized_hosts
            or any(
                "://" in host or "/" in host or "@" in host
                for host in normalized_hosts
            )
        ):
            raise CatalogError("The bootloader cache catalog has unsafe allowed hosts")
        normalized_key = resource.family.casefold(), resource.version, resource.name
        if normalized_key in seen:
            raise CatalogError(f"Duplicate bootloader resource: {'/'.join(resource.key)}")
        seen.add(normalized_key)
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


def _open_or_create_absolute_directory_nofollow(path: Path) -> int:
    """Create missing directory components without ever traversing a symlink."""

    if (
        not path.is_absolute()
        or path == Path("/")
        or path != Path(os.path.normpath(path))
        or any(part == ".." for part in path.parts)
    ):
        raise _CachePathUnsafe("The bootloader cache path is not a safe absolute path")
    descriptor = os.open("/", _DIRECTORY_OPEN_FLAGS)
    try:
        for component in path.parts[1:]:
            if component in {"", ".", ".."}:
                raise _CachePathUnsafe("The bootloader cache path is not canonical")
            try:
                child = os.open(component, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                except OSError as error:
                    raise _CachePathUnsafe(
                        f"Could not create bootloader cache directory safely: "
                        f"{error.strerror or error}"
                    ) from error
                try:
                    child = os.open(component, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
                except OSError as error:
                    raise _CachePathUnsafe(
                        f"The bootloader cache directory is unsafe: "
                        f"{error.strerror or error}"
                    ) from error
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


def _revalidate_directory_path(path: Path, descriptor: int) -> None:
    """Require a bound directory to remain the object named by its path."""

    current = -1
    try:
        current = _open_absolute_directory_nofollow(path)
        bound_stat = os.fstat(descriptor)
        current_stat = os.fstat(current)
        if (
            bound_stat.st_dev,
            bound_stat.st_ino,
        ) != (
            current_stat.st_dev,
            current_stat.st_ino,
        ):
            raise DownloadError(
                "The bootloader cache directory changed while it was in use"
            )
    except (_CachePathMissing, _CachePathUnsafe, OSError) as error:
        raise DownloadError(
            f"The bootloader cache path changed while it was in use: {error}"
        ) from error
    finally:
        if current >= 0:
            os.close(current)


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


def _safe_component(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not SAFE_COMPONENT.fullmatch(value)
        or value in {".", ".."}
    ):
        raise CatalogError(f"Unsafe bootloader resource {field}: {value!r}")
    return value


def _license_expression(value: object) -> str:
    if not isinstance(value, str) or not LICENSE_EXPRESSION.fullmatch(value):
        raise CatalogError(f"Invalid bootloader bundle license expression: {value!r}")
    return value


def _https_host(url: object, field: str = "url") -> str:
    if not isinstance(url, str):
        raise CatalogError(f"Bootloader resource {field} must be an HTTPS URL")
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
        normalized_key = resource.family.casefold(), resource.version, resource.name
        if normalized_key in keys:
            raise CatalogError(f"Duplicate bootloader resource: {'/'.join(resource.key)}")
        keys.add(normalized_key)
        resources.append(resource)
    raw_bundles = payload.get("bundles")
    if not isinstance(raw_bundles, list):
        raise CatalogError("Bootloader catalog bundles must be a list")
    resources_by_key = {
        (item.family.casefold(), item.version, item.name): item for item in resources
    }
    bundles: list[BootloaderBundle] = []
    bundle_keys: set[tuple[str, str, str]] = set()
    for raw in raw_bundles:
        if not isinstance(raw, dict):
            raise CatalogError("Each bootloader bundle must be an object")
        family = _safe_component(_required_text(raw, "family"), "family")
        version = _safe_component(_required_text(raw, "version"), "version")
        purpose = _safe_component(_required_text(raw, "purpose"), "purpose")
        license_name = _license_expression(_required_text(raw, "license"))
        provenance_url = _required_text(raw, "provenance_url")
        _https_host(provenance_url, "provenance_url")
        raw_names = raw.get("artifacts")
        if (
            not isinstance(raw_names, list)
            or not raw_names
            or not all(isinstance(name, str) for name in raw_names)
        ):
            raise CatalogError("Bootloader bundle artifacts must be a non-empty list")
        names = tuple(_safe_component(name, "artifact") for name in raw_names)
        if len(names) != len(set(names)):
            raise CatalogError("Bootloader bundle artifact names must be unique")
        expected_names = _BUNDLE_ARTIFACTS.get(
            (family.casefold(), purpose.casefold())
        )
        if expected_names is None or names != expected_names:
            raise CatalogError(
                f"Bootloader bundle {family}/{purpose} has an unsupported artifact set"
            )
        missing = next(
            (
                name for name in names
                if (family.casefold(), version, name) not in resources_by_key
            ),
            None,
        )
        if missing is not None:
            raise CatalogError(
                f"Bootloader bundle references missing resource {family}/{version}/{missing}"
            )
        key = family.casefold(), version, purpose.casefold()
        if key in bundle_keys:
            raise CatalogError(f"Duplicate bootloader bundle: {'/'.join(key)}")
        bundle_keys.add(key)
        bundles.append(BootloaderBundle(
            family, version, purpose, names, license_name, provenance_url,
        ))
    return BootloaderCatalog(tuple(resources), tuple(bundles))


def bind_resource_bytes(
    path: Path,
    resource: BootloaderResource,
    *,
    cancel_event: threading.Event | None = None,
    deadline: float | None = None,
) -> BoundBootArtifact:
    """Open one cache object without following its final link and freeze verified bytes."""

    if not path.is_absolute() or path.name != resource.name:
        raise DownloadError("Downloaded boot artifact path is not safe or canonical")
    parent = -1
    descriptor = -1
    try:
        parent = _open_absolute_directory_nofollow(path.parent)
        observed = os.stat(resource.name, dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(resource.name, _FILE_OPEN_FLAGS, dir_fd=parent)
    except (_CachePathMissing, _CachePathUnsafe, OSError) as error:
        raise DownloadError(f"Could not safely open downloaded boot artifact: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or observed.st_nlink != 1
            or opened.st_nlink != 1
            or not _stable_file(observed, opened)
            or opened.st_size != resource.size
        ):
            raise DownloadError("Downloaded boot artifact is not a stable singly linked file")
        payload = bytearray()
        remaining = resource.size
        digest = hashlib.sha256()
        for block in _descriptor_blocks(
            descriptor, resource.size,
            deadline=deadline, cancel_event=cancel_event,
        ):
            payload.extend(block)
            digest.update(block)
            remaining -= len(block)
        if remaining:
            raise DownloadError("Downloaded boot artifact ended before its cataloged size")
        final = os.fstat(descriptor)
        if not _stable_file(opened, final):
            raise DownloadError("Downloaded boot artifact changed while it was bound")
        if not hmac.compare_digest(digest.hexdigest(), resource.sha256):
            raise DownloadError("Downloaded boot artifact failed SHA-256 verification")
        _revalidate_directory_path(path.parent, parent)
        return BoundBootArtifact(resource.name, bytes(payload), resource.sha256)
    except OSError as error:
        raise DownloadError(f"Could not bind downloaded boot artifact: {error}") from error
    finally:
        try:
            if descriptor >= 0:
                os.close(descriptor)
        finally:
            if parent >= 0:
                os.close(parent)


def _validated_catalog_bundles(
    catalog: BootloaderCatalog,
) -> tuple[BootloaderBundle, ...]:
    resources = _validated_cache_resources(catalog)
    resource_keys = {
        (item.family.casefold(), item.version, item.name) for item in resources
    }
    seen: set[tuple[str, str, str]] = set()
    validated: list[BootloaderBundle] = []
    for bundle in catalog.bundles:
        if not isinstance(bundle, BootloaderBundle):
            raise CatalogError("The bootloader catalog contains an invalid bundle")
        family = _safe_component(bundle.family, "family")
        version = _safe_component(bundle.version, "version")
        purpose = _safe_component(bundle.purpose, "purpose")
        _license_expression(bundle.license)
        _https_host(bundle.provenance_url, "provenance_url")
        if (
            not isinstance(bundle.artifact_names, tuple)
            or not bundle.artifact_names
            or not all(isinstance(name, str) for name in bundle.artifact_names)
        ):
            raise CatalogError("Bootloader bundle artifacts must be a non-empty tuple")
        names = tuple(_safe_component(name, "artifact") for name in bundle.artifact_names)
        if len(names) != len(set(names)):
            raise CatalogError("Bootloader bundle artifact names must be unique")
        expected_names = _BUNDLE_ARTIFACTS.get(
            (family.casefold(), purpose.casefold())
        )
        if expected_names is None or names != expected_names:
            raise CatalogError(
                f"Bootloader bundle {family}/{purpose} has an unsupported artifact set"
            )
        missing = next(
            (
                name for name in names
                if (family.casefold(), version, name) not in resource_keys
            ),
            None,
        )
        if missing is not None:
            raise CatalogError(
                f"Bootloader bundle references missing resource {family}/{version}/{missing}"
            )
        key = family.casefold(), version, purpose.casefold()
        if key in seen:
            raise CatalogError(f"Duplicate bootloader bundle: {'/'.join(key)}")
        seen.add(key)
        validated.append(bundle)
    return tuple(validated)


def prepare_bundle(
    family: str,
    version: str,
    purpose: str,
    *,
    catalog: BootloaderCatalog | None = None,
    cache_dir: Path | None = None,
    opener: OpenUrl = urllib.request.urlopen,
    cancel_event: threading.Event | None = None,
    progress: DownloadProgress | None = None,
    overall_timeout: float = 180.0,
) -> BoundBootBundle:
    """Download and freeze one exact bundle; no partial set is ever returned.

    This function does not grant consent and never performs a privileged or
    destructive operation. A GUI caller must obtain explicit network consent
    before invoking it and retain the returned immutable bytes through final
    erase confirmation.
    """

    available = catalog or load_catalog()
    bundle = next(
        (
            item for item in _validated_catalog_bundles(available)
            if (
                item.family.casefold(), item.version, item.purpose.casefold()
            ) == (family.casefold(), version, purpose.casefold())
        ),
        None,
    )
    if bundle is None:
        raise DependencyUnavailable(
            f"No verified {family} {version} bundle for {purpose!r} is cataloged"
        )
    if (
        isinstance(overall_timeout, bool)
        or not isinstance(overall_timeout, (int, float))
        or not 0 < overall_timeout <= 600
    ):
        raise ValueError("Bootloader bundle timeout must be between 0 and 600 seconds")
    resources: list[BootloaderResource] = []
    for name in bundle.artifact_names:
        resource = available.find(bundle.family, bundle.version, name)
        if resource is None:
            # load_catalog() enforces this, but custom in-memory catalogs must
            # fail closed at the same trust boundary.
            raise CatalogError(
                f"Bootloader bundle references missing resource "
                f"{bundle.family}/{bundle.version}/{name}"
            )
        resources.append(resource)
    deadline = time.monotonic() + overall_timeout
    total_size = sum(resource.size for resource in resources)
    completed = 0
    artifacts: list[BoundBootArtifact] = []
    for resource in resources:
        if cancel_event is not None and cancel_event.is_set():
            raise DownloadError("Bootloader download was cancelled")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DownloadError("Bootloader bundle download reached its overall time limit")

        def report(done: int, _resource_total: int, *, base: int = completed) -> None:
            if progress is not None:
                progress(base + done, total_size)

        path = fetch_resource(
            resource, cache_dir, opener, cancel_event=cancel_event,
            progress=report if progress is not None else None,
            overall_timeout=remaining,
        )
        artifacts.append(bind_resource_bytes(
            path, resource, cancel_event=cancel_event, deadline=deadline,
        ))
        completed += resource.size
    return BoundBootBundle(
        bundle.family, bundle.version, bundle.purpose, tuple(artifacts),
        bundle.license, bundle.provenance_url,
    )


def verify_resource(path: Path, resource: BootloaderResource) -> bool:
    try:
        bind_resource_bytes(path, resource)
        return True
    except (CatalogError, DownloadError, OSError):
        return False


def _descriptor_blocks(
    descriptor: int,
    total: int,
    *,
    deadline: float | None,
    cancel_event: threading.Event | None,
) -> Iterable[bytes]:
    """Read a descriptor behind a cancellable, caller-visible deadline."""

    messages: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=2)
    stopped = threading.Event()

    def publish(kind: str, value: object) -> bool:
        while not stopped.is_set():
            try:
                messages.put((kind, value), timeout=0.1)
                return True
            except queue.Full:
                continue
        return False

    def read_descriptor() -> None:
        remaining = total
        try:
            while remaining and not stopped.is_set():
                block = os.read(descriptor, min(1024 * 1024, remaining))
                if not block:
                    publish("eof", b"")
                    return
                remaining -= len(block)
                if not publish("data", block):
                    return
            publish("eof", b"")
        except Exception as error:
            publish("error", error)

    worker = threading.Thread(
        target=read_descriptor, name="isopropyl-boot-cache-read", daemon=True,
    )
    worker.start()
    try:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise DownloadError("Bootloader download was cancelled")
            remaining_time = (
                float("inf") if deadline is None else deadline - time.monotonic()
            )
            if remaining_time <= 0:
                raise DownloadError(
                    "Bootloader bundle preparation reached its overall time limit"
                )
            try:
                kind, value = messages.get(timeout=min(0.1, remaining_time))
            except queue.Empty:
                continue
            if deadline is not None and time.monotonic() > deadline:
                raise DownloadError(
                    "Bootloader bundle preparation reached its overall time limit"
                )
            if kind == "eof":
                return
            if kind == "error":
                assert isinstance(value, Exception)
                raise value
            if not isinstance(value, bytes):
                raise DownloadError("Bootloader cache returned invalid data")
            yield value
    finally:
        stopped.set()
        worker.join(timeout=0.25)


def _fsync_with_deadline(
    descriptor: int,
    *,
    deadline: float,
    cancel_event: threading.Event | None,
) -> None:
    """Durably sync a duplicate descriptor without trapping the caller forever."""

    owned = os.dup(descriptor)
    messages: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=1)
    abandoned = threading.Event()

    def sync_descriptor() -> None:
        try:
            os.fsync(owned)
        except Exception as error:
            message: tuple[str, object] = ("error", error)
        else:
            message = ("done", None)
        finally:
            os.close(owned)
        if not abandoned.is_set():
            messages.put(message)

    worker = threading.Thread(
        target=sync_descriptor, name="isopropyl-boot-cache-sync", daemon=True,
    )
    worker.start()
    while True:
        if cancel_event is not None and cancel_event.is_set():
            abandoned.set()
            raise DownloadError("Bootloader download was cancelled")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            abandoned.set()
            raise DownloadError("Bootloader download reached its overall time limit")
        try:
            kind, value = messages.get(timeout=min(0.1, remaining))
        except queue.Empty:
            continue
        if time.monotonic() > deadline:
            raise DownloadError("Bootloader download reached its overall time limit")
        if kind == "error":
            assert isinstance(value, Exception)
            raise value
        worker.join(timeout=0.25)
        return


def _verify_resource_at(
    parent: int,
    resource: BootloaderResource,
    *,
    deadline: float,
    cancel_event: threading.Event | None,
) -> bool:
    descriptor = -1
    try:
        observed = os.stat(resource.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
            return False
        descriptor = os.open(resource.name, _FILE_OPEN_FLAGS, dir_fd=parent)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != resource.size
            or not _stable_file(observed, opened)
        ):
            return False
        digest = hashlib.sha256()
        remaining = resource.size
        for block in _descriptor_blocks(
            descriptor, resource.size,
            deadline=deadline, cancel_event=cancel_event,
        ):
            digest.update(block)
            remaining -= len(block)
        if remaining:
            return False
        final = os.fstat(descriptor)
        return (
            _stable_file(opened, final)
            and hmac.compare_digest(digest.hexdigest(), resource.sha256)
        )
    except FileNotFoundError:
        return False
    except DownloadError:
        raise
    except OSError:
        return False
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_final_url(url: str, resource: BootloaderResource) -> None:
    try:
        host = _https_host(url, "redirect")
    except CatalogError as error:
        raise DownloadError(str(error)) from error
    if host not in resource.allowed_hosts:
        raise DownloadError(f"Download redirected to untrusted host {host!r}")


def _open_response_with_deadline(
    opener: OpenUrl,
    request: urllib.request.Request,
    *,
    deadline: float,
    cancel_event: threading.Event | None,
) -> DownloadResponse:
    """Run connection setup behind the same caller-visible overall deadline."""

    messages: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=1)
    abandoned = threading.Event()
    claimed = threading.Event()

    def open_response() -> None:
        try:
            remaining = max(0.001, deadline - time.monotonic())
            response = opener(request, timeout=min(30, remaining))
        except Exception as error:
            if not abandoned.is_set():
                messages.put(("error", error))
            return
        if abandoned.is_set():
            try:
                response.close()
            except Exception:
                pass
            return
        messages.put(("response", response))
        while not claimed.wait(0.05):
            if abandoned.is_set():
                try:
                    response.close()
                except Exception:
                    pass
                return

    worker = threading.Thread(
        target=open_response, name="isopropyl-boot-connect", daemon=True,
    )
    worker.start()
    while True:
        if cancel_event is not None and cancel_event.is_set():
            abandoned.set()
            raise DownloadError("Bootloader download was cancelled")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            abandoned.set()
            raise DownloadError("Bootloader download reached its overall time limit")
        try:
            kind, value = messages.get(timeout=min(0.1, remaining))
        except queue.Empty:
            continue
        claimed.set()
        if time.monotonic() > deadline:
            if kind == "response":
                try:
                    value.close()  # type: ignore[attr-defined]
                except Exception:
                    pass
            raise DownloadError("Bootloader download reached its overall time limit")
        if kind == "error":
            assert isinstance(value, Exception)
            raise value
        return value  # type: ignore[return-value]


def _download_blocks(
    response: DownloadResponse,
    size: int,
    *,
    deadline: float,
    cancel_event: threading.Event | None,
) -> Iterable[bytes]:
    """Yield response blocks while enforcing a caller-visible overall deadline.

    ``urllib`` socket timeouts limit one blocking read, not an entire transfer.
    A single daemon reader lets the controlling thread stop waiting at the
    overall deadline and close the response to unblock ordinary sockets.
    """

    messages: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=2)
    stopped = threading.Event()

    def publish(kind: str, value: object) -> bool:
        while not stopped.is_set():
            try:
                messages.put((kind, value), timeout=0.1)
                return True
            except queue.Full:
                continue
        return False

    def read_response() -> None:
        try:
            while not stopped.is_set():
                block = response.read(size)
                if not block:
                    publish("eof", b"")
                    return
                if not publish("data", block):
                    return
        except Exception as error:
            publish("error", error)

    worker = threading.Thread(
        target=read_response, name="isopropyl-boot-download", daemon=True,
    )
    worker.start()
    try:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise DownloadError("Bootloader download was cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DownloadError("Bootloader download reached its overall time limit")
            try:
                kind, value = messages.get(timeout=min(0.1, remaining))
            except queue.Empty:
                continue
            if time.monotonic() > deadline:
                raise DownloadError("Bootloader download reached its overall time limit")
            if kind == "eof":
                return
            if kind == "error":
                assert isinstance(value, Exception)
                raise value
            if not isinstance(value, bytes):
                raise DownloadError("Bootloader download returned invalid response data")
            yield value
    finally:
        stopped.set()
        if worker.is_alive():
            try:
                response.close()
            except Exception:
                pass
        worker.join(timeout=0.25)


def fetch_resource(
    resource: BootloaderResource,
    cache_dir: Path | None = None,
    opener: OpenUrl = urllib.request.urlopen,
    cancel_event: threading.Event | None = None,
    *,
    progress: DownloadProgress | None = None,
    overall_timeout: float = 120.0,
) -> Path:
    """Fetch a cataloged artifact, accepting it only after size and SHA-256 checks.

    The catalog is shipped with ISOpropyl. Network metadata is never trusted to
    choose a URL, version, size, or digest.
    """
    def check_cancelled() -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise DownloadError("Bootloader download was cancelled")

    if (
        isinstance(overall_timeout, bool)
        or not isinstance(overall_timeout, (int, float))
        or not 0 < overall_timeout <= 600
    ):
        raise ValueError("Bootloader download timeout must be between 0 and 600 seconds")
    _validated_cache_resources(BootloaderCatalog((resource,)))
    deadline = time.monotonic() + overall_timeout
    check_cancelled()
    root = cache_dir or default_cache_dir()
    destination = root / resource.family / resource.version / resource.name
    parent = -1
    temporary = ""
    try:
        try:
            parent = _open_or_create_absolute_directory_nofollow(destination.parent)
        except _CachePathUnsafe as error:
            raise DownloadError(str(error)) from error
        if _verify_resource_at(
            parent, resource, deadline=deadline, cancel_event=cancel_event,
        ):
            check_cancelled()
            _revalidate_directory_path(destination.parent, parent)
            if progress is not None:
                progress(resource.size, resource.size)
            return destination
        # Never retain a known-bad object under a trusted cache key. All
        # inspection and mutation stays relative to the bound no-follow parent.
        try:
            existing = os.stat(resource.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise DownloadError(f"Could not inspect invalid cache artifact: {error}") from error
        else:
            if stat.S_ISDIR(existing.st_mode):
                raise DownloadError("Refusing to replace a cache artifact directory")
            try:
                os.unlink(resource.name, dir_fd=parent)
                _fsync_with_deadline(
                    parent, deadline=deadline, cancel_event=cancel_event,
                )
            except OSError as error:
                raise DownloadError(f"Could not remove invalid cache artifact: {error}") from error

        request = urllib.request.Request(
            resource.url,
            headers={"User-Agent": "ISOpropyl-USB-Writer/0.1 bootloader-resolver"},
        )
        check_cancelled()
        response = _open_response_with_deadline(
            opener, request, deadline=deadline, cancel_event=cancel_event,
        )
        with closing(response):
            check_cancelled()
            _validate_final_url(response.geturl(), resource)
            descriptor = -1
            for _attempt in range(16):
                candidate = f".isopropyl-download-{secrets.token_hex(16)}"
                try:
                    descriptor = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=parent,
                    )
                except FileExistsError:
                    continue
                except OSError as error:
                    raise DownloadError(
                        f"Could not create a private cache download: {error}"
                    ) from error
                temporary = candidate
                break
            if descriptor < 0:
                raise DownloadError("Could not allocate a private cache download")
            digest = hashlib.sha256()
            total = 0
            with os.fdopen(descriptor, "wb", buffering=0) as output:
                for block in _download_blocks(
                    response,
                    min(1024 * 1024, resource.size + 1),
                    deadline=deadline,
                    cancel_event=cancel_event,
                ):
                    check_cancelled()
                    total += len(block)
                    if total > resource.size:
                        raise DownloadError("Downloaded bootloader artifact is larger than cataloged")
                    digest.update(block)
                    pending = memoryview(block)
                    while pending:
                        written = output.write(pending)
                        if written is None or written <= 0:
                            raise DownloadError(
                                "Could not completely write the downloaded cache artifact"
                            )
                        pending = pending[written:]
                    if progress is not None:
                        progress(total, resource.size)
                check_cancelled()
                _fsync_with_deadline(
                    output.fileno(), deadline=deadline,
                    cancel_event=cancel_event,
                )
            if total != resource.size:
                raise DownloadError(
                    f"Downloaded {total} bytes, but the trusted catalog requires {resource.size}"
                )
            if not hmac.compare_digest(digest.hexdigest(), resource.sha256):
                raise DownloadError("Downloaded bootloader artifact failed SHA-256 verification")
        check_cancelled()
        if time.monotonic() > deadline:
            raise DownloadError("Bootloader download reached its overall time limit")
        try:
            os.replace(
                temporary, resource.name, src_dir_fd=parent, dst_dir_fd=parent,
            )
            temporary = ""
            _fsync_with_deadline(
                parent, deadline=deadline, cancel_event=cancel_event,
            )
        except OSError as error:
            raise DownloadError(f"Could not publish verified cache artifact: {error}") from error
        _revalidate_directory_path(destination.parent, parent)
        check_cancelled()
        if time.monotonic() > deadline:
            raise DownloadError("Bootloader download reached its overall time limit")
        return destination
    except DownloadError:
        raise
    except Exception as error:
        raise DownloadError(f"Could not download bootloader artifact: {error}") from error
    finally:
        if temporary and parent >= 0:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        if parent >= 0:
            os.close(parent)


def installed_tool_matches(
    program: str,
    version: str,
    runner: RunCommand = subprocess.run,
) -> Path | None:
    if (
        not isinstance(program, str)
        or not SAFE_COMPONENT.fullmatch(program)
        or "/" in program
        or not isinstance(version, str)
        or not TOOL_VERSION.fullmatch(version)
    ):
        return None
    executable = shutil.which(program, path=_TRUSTED_TOOL_PATH)
    if not executable:
        return None
    executable = os.path.normpath(executable)
    if (
        not os.path.isabs(executable)
        or os.path.dirname(executable) not in _TRUSTED_TOOL_DIRECTORIES
        or os.path.basename(executable) != program
    ):
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
