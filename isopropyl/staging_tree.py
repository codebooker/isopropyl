from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Block-free, descriptor-safe staging-tree inspection and manifests.

This module deliberately imports no device, formatting, mount, or application
backend.  It freezes one portable tree through no-follow descriptors and can
stream every regular file into a content manifest without retaining file data
in memory.
"""

import hashlib
import hmac
import json
import os
import re
import stat
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .timestamps import (
    MAX_PORTABLE_ARCHIVE_MTIME_NS,
    MIN_PORTABLE_ARCHIVE_MTIME_NS,
)


FAT32_MAX_FILE_BYTES = (4 * 1024 * 1024 * 1024) - 1
MAX_TREE_ENTRIES = 1_000_000
MAX_TREE_DEPTH = 128
MANIFEST_CHUNK_BYTES = 4 * 1024 * 1024
MAX_ERROR_CHARACTERS = 2_048
_MANIFEST_PROFILE = "io.github.codebooker.isopropyl/staging-tree-manifest/v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_WINDOWS_DEVICE = re.compile(
    r"^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])(?:\..*)?$",
    re.IGNORECASE,
)
_FAT_FORBIDDEN = frozenset('<>:"/\\|?*')
_DIR_FLAGS = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = (
    os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
)


class StagingTreeSafetyError(RuntimeError):
    """A staging tree cannot be proven stable, portable, and regular."""


@dataclass(frozen=True)
class StagedDirectory:
    parts: tuple[str, ...]
    device: int
    inode: int
    modified_ns: int
    changed_ns: int

    @property
    def path(self) -> str:
        return PurePosixPath(*self.parts).as_posix() if self.parts else "."


@dataclass(frozen=True)
class StagedFile:
    parts: tuple[str, ...]
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int
    link_count: int

    @property
    def path(self) -> str:
        return PurePosixPath(*self.parts).as_posix()


@dataclass(frozen=True)
class StagedDirectoryManifest:
    """One ordered directory manifest record with its live-tree identity."""

    source: StagedDirectory

    @property
    def path(self) -> str:
        return self.source.path

    @property
    def modified_ns(self) -> int:
        return self.source.modified_ns


@dataclass(frozen=True)
class StagedFileManifest:
    """One ordered file manifest record with its streamed SHA-256."""

    source: StagedFile
    sha256: str

    @property
    def path(self) -> str:
        return self.source.path

    @property
    def size(self) -> int:
        return self.source.size

    @property
    def modified_ns(self) -> int:
        return self.source.modified_ns


@dataclass(frozen=True)
class StagingTreeManifest:
    """One complete semantic manifest and the identities used to prove it."""

    root: Path
    directories: tuple[StagedDirectoryManifest, ...]
    files: tuple[StagedFileManifest, ...]
    total_bytes: int
    manifest_sha256: str

    @property
    def source_directories(self) -> tuple[StagedDirectory, ...]:
        return tuple(item.source for item in self.directories)

    @property
    def source_files(self) -> tuple[StagedFile, ...]:
        return tuple(item.source for item in self.files)


CancelCheck = Callable[[], None]


def _check_cancelled(cancel_check: CancelCheck | None) -> None:
    if cancel_check is not None:
        cancel_check()


def _bounded_message(value: object, fallback: str) -> str:
    rendered = str(value or "").strip()
    return rendered[-MAX_ERROR_CHARACTERS:] if rendered else fallback


def validate_staged_component(component: str, rendered_path: str) -> None:
    if not component or component in {".", ".."} or "\x00" in component:
        raise StagingTreeSafetyError(f"Unsafe staged path: {rendered_path!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in component):
        raise StagingTreeSafetyError(
            f"Control character in staged path: {rendered_path!r}"
        )
    if any(character in _FAT_FORBIDDEN for character in component):
        raise StagingTreeSafetyError(
            f"FAT32-incompatible character in staged path: {rendered_path!r}"
        )
    if component.endswith((" ", ".")):
        raise StagingTreeSafetyError(
            f"Trailing dot or space in staged path: {rendered_path!r}"
        )
    if _WINDOWS_DEVICE.fullmatch(unicodedata.normalize("NFC", component)):
        raise StagingTreeSafetyError(
            f"Reserved FAT32 device name in staged path: {rendered_path!r}"
        )
    try:
        utf16_units = len(component.encode("utf-16-le")) // 2
    except UnicodeEncodeError as error:
        raise StagingTreeSafetyError(
            f"Staged path is not valid Unicode: {rendered_path!r}"
        ) from error
    if utf16_units > 255:
        raise StagingTreeSafetyError(
            f"Staged path component exceeds the FAT32 name limit: {rendered_path!r}"
        )


def staged_case_key(parts: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFC", item).casefold() for item in parts)


def staged_directory_from_stat(
    parts: tuple[str, ...], info: os.stat_result,
) -> StagedDirectory:
    path = PurePosixPath(*parts).as_posix() if parts else "."
    if not (
        MIN_PORTABLE_ARCHIVE_MTIME_NS
        <= info.st_mtime_ns
        <= MAX_PORTABLE_ARCHIVE_MTIME_NS
    ):
        raise StagingTreeSafetyError(
            f"Staged directory has a modification time outside the portable range: {path!r}"
        )
    return StagedDirectory(
        parts, info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns,
    )


def staged_file_from_stat(parts: tuple[str, ...], info: os.stat_result) -> StagedFile:
    path = PurePosixPath(*parts).as_posix()
    if not (
        MIN_PORTABLE_ARCHIVE_MTIME_NS
        <= info.st_mtime_ns
        <= MAX_PORTABLE_ARCHIVE_MTIME_NS
    ):
        raise StagingTreeSafetyError(
            f"Staged file has a modification time outside the portable range: {path!r}"
        )
    return StagedFile(
        parts, info.st_dev, info.st_ino, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns, info.st_nlink,
    )


def _scan_directory_fd(
    directory_fd: int,
    parts: tuple[str, ...],
    root_device: int,
    directories: list[StagedDirectory],
    files: list[StagedFile],
    occupied: dict[tuple[str, ...], str],
    max_file_bytes: int | None,
) -> None:
    if len(parts) >= MAX_TREE_DEPTH:
        raise StagingTreeSafetyError("The staged tree exceeds the directory-depth limit")
    try:
        names = sorted(os.listdir(directory_fd), key=lambda item: item.casefold())
    except OSError as error:
        raise StagingTreeSafetyError(
            _bounded_message(error, "Could not enumerate the staged tree")
        ) from error
    for name in names:
        child_parts = parts + (name,)
        rendered = PurePosixPath(*child_parts).as_posix()
        validate_staged_component(name, rendered)
        key = staged_case_key(child_parts)
        if key in occupied:
            raise StagingTreeSafetyError(
                f"Case or Unicode-normalization collision: {occupied[key]!r} and {rendered!r}"
            )
        occupied[key] = rendered
        if len(directories) + len(files) >= MAX_TREE_ENTRIES:
            raise StagingTreeSafetyError("The staged tree contains too many entries")
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as error:
            raise StagingTreeSafetyError(
                _bounded_message(error, f"Could not inspect staged entry {rendered!r}")
            ) from error
        if before.st_dev != root_device:
            raise StagingTreeSafetyError(
                f"Cross-filesystem staged entries are forbidden: {rendered!r}"
            )
        if stat.S_ISLNK(before.st_mode):
            raise StagingTreeSafetyError(f"Symbolic links are forbidden: {rendered!r}")
        if stat.S_ISDIR(before.st_mode):
            try:
                child_fd = os.open(name, _DIR_FLAGS, dir_fd=directory_fd)
            except OSError as error:
                raise StagingTreeSafetyError(
                    _bounded_message(error, f"Could not safely open directory {rendered!r}")
                ) from error
            try:
                opened = os.fstat(child_fd)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                ):
                    raise StagingTreeSafetyError(
                        f"Staged directory changed while scanning: {rendered!r}"
                    )
                bound_directory = staged_directory_from_stat(child_parts, opened)
                directories.append(bound_directory)
                _scan_directory_fd(
                    child_fd, child_parts, root_device,
                    directories, files, occupied, max_file_bytes,
                )
                after = os.fstat(child_fd)
                rebound = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False,
                )
                if (
                    not _directory_matches(bound_directory, after)
                    or not _directory_matches(bound_directory, rebound)
                ):
                    raise StagingTreeSafetyError(
                        f"Staged directory changed while scanning: {rendered!r}"
                    )
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(before.st_mode):
            if before.st_nlink != 1:
                raise StagingTreeSafetyError(
                    f"Hard-linked staged files are forbidden: {rendered!r}"
                )
            if max_file_bytes is not None and before.st_size > max_file_bytes:
                raise StagingTreeSafetyError(
                    f"Staged file exceeds the selected filesystem's single-file limit: {rendered!r}"
                )
            files.append(staged_file_from_stat(child_parts, before))
        else:
            raise StagingTreeSafetyError(
                f"Only regular files and directories are allowed: {rendered!r}"
            )


def scan_staging_tree(
    root: Path | str,
    *,
    max_file_bytes: int | None = FAT32_MAX_FILE_BYTES,
) -> tuple[Path, tuple[StagedDirectory, ...], tuple[StagedFile, ...]]:
    staging = Path(root)
    if not staging.is_absolute():
        raise StagingTreeSafetyError("The staging tree must use an absolute path")
    staging = Path(os.path.normpath(staging))
    try:
        initial = os.lstat(staging)
    except OSError as error:
        raise StagingTreeSafetyError(
            _bounded_message(error, "The staging tree is unavailable")
        ) from error
    if stat.S_ISLNK(initial.st_mode) or not stat.S_ISDIR(initial.st_mode):
        raise StagingTreeSafetyError(
            "The staging root must be a real directory, not a link or special file"
        )
    try:
        root_fd = os.open(staging, _DIR_FLAGS)
    except OSError as error:
        raise StagingTreeSafetyError(
            _bounded_message(error, "Could not safely open the staging root")
        ) from error
    try:
        opened = os.fstat(root_fd)
        if (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino):
            raise StagingTreeSafetyError("The staging root changed while opening it")
        root_identity = staged_directory_from_stat((), opened)
        directories = [root_identity]
        files: list[StagedFile] = []
        _scan_directory_fd(
            root_fd, (), opened.st_dev, directories, files, {}, max_file_bytes,
        )
        after = os.fstat(root_fd)
        rebound = os.lstat(staging)
        if (
            not _directory_matches(root_identity, after)
            or not _directory_matches(root_identity, rebound)
        ):
            raise StagingTreeSafetyError("The staging root changed while scanning it")
    finally:
        os.close(root_fd)
    directories.sort(key=lambda item: (len(item.parts), staged_case_key(item.parts)))
    files.sort(key=lambda item: staged_case_key(item.parts))
    return staging, tuple(directories), tuple(files)


def _directory_matches(source: StagedDirectory, info: os.stat_result) -> bool:
    return (
        type(source) is StagedDirectory
        and stat.S_ISDIR(info.st_mode)
        and source.device == info.st_dev
        and source.inode == info.st_ino
        and source.modified_ns == info.st_mtime_ns
        and source.changed_ns == info.st_ctime_ns
    )


def _file_matches(source: StagedFile, info: os.stat_result) -> bool:
    return (
        type(source) is StagedFile
        and stat.S_ISREG(info.st_mode)
        and source.device == info.st_dev
        and source.inode == info.st_ino
        and source.size == info.st_size
        and source.modified_ns == info.st_mtime_ns
        and source.changed_ns == info.st_ctime_ns
        and source.link_count == info.st_nlink == 1
    )


def _open_bound_directory(
    root_fd: int,
    parts: tuple[str, ...],
    directories: dict[tuple[str, ...], StagedDirectory],
) -> int:
    current = os.dup(root_fd)
    walked: tuple[str, ...] = ()
    try:
        root = directories.get(())
        if root is None or not _directory_matches(root, os.fstat(current)):
            raise StagingTreeSafetyError("The staged root changed before manifest hashing")
        for component in parts:
            following = os.open(component, _DIR_FLAGS, dir_fd=current)
            os.close(current)
            current = following
            walked += (component,)
            expected = directories.get(walked)
            if expected is None or not _directory_matches(expected, os.fstat(current)):
                raise StagingTreeSafetyError(
                    f"Staged directory changed before hashing: {PurePosixPath(*walked)!s}"
                )
        return current
    except OSError as error:
        os.close(current)
        raise StagingTreeSafetyError(
            _bounded_message(error, "Could not safely traverse the staged tree")
        ) from error
    except BaseException:
        os.close(current)
        raise


def _hash_bound_file(
    root_fd: int,
    directories: dict[tuple[str, ...], StagedDirectory],
    source: StagedFile,
    cancel_check: CancelCheck | None,
) -> str:
    parent_fd = _open_bound_directory(root_fd, source.parts[:-1], directories)
    descriptor = -1
    try:
        _check_cancelled(cancel_check)
        try:
            before = os.stat(
                source.parts[-1], dir_fd=parent_fd, follow_symlinks=False,
            )
            descriptor = os.open(
                source.parts[-1], _READ_FLAGS, dir_fd=parent_fd,
            )
        except OSError as error:
            raise StagingTreeSafetyError(
                _bounded_message(error, f"Could not safely open staged file {source.path!r}")
            ) from error
        opened = os.fstat(descriptor)
        if not _file_matches(source, before) or not _file_matches(source, opened):
            raise StagingTreeSafetyError(
                f"Staged file changed before hashing: {source.path!r}"
            )
        digest = hashlib.sha256()
        remaining = source.size
        while remaining:
            _check_cancelled(cancel_check)
            try:
                block = os.read(descriptor, min(MANIFEST_CHUNK_BYTES, remaining))
            except InterruptedError:
                continue
            except OSError as error:
                raise StagingTreeSafetyError(
                    _bounded_message(error, f"Could not hash staged file {source.path!r}")
                ) from error
            if not block:
                raise StagingTreeSafetyError(
                    f"Staged file ended early while hashing: {source.path!r}"
                )
            digest.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise StagingTreeSafetyError(
                f"Staged file grew while hashing: {source.path!r}"
            )
        after = os.fstat(descriptor)
        rebound = os.stat(
            source.parts[-1], dir_fd=parent_fd, follow_symlinks=False,
        )
        parent = directories[source.parts[:-1]]
        if (
            not _file_matches(source, after)
            or not _file_matches(source, rebound)
            or not _directory_matches(parent, os.fstat(parent_fd))
        ):
            raise StagingTreeSafetyError(
                f"Staged file changed while hashing: {source.path!r}"
            )
        _check_cancelled(cancel_check)
        return digest.hexdigest()
    except OSError as error:
        raise StagingTreeSafetyError(
            _bounded_message(error, f"Could not hash staged file {source.path!r}")
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def _manifest_digest(
    directories: tuple[StagedDirectoryManifest, ...],
    files: tuple[StagedFileManifest, ...],
) -> str:
    encoded = json.dumps(
        {
            "profile": _MANIFEST_PROFILE,
            "directories": [
                {"path": item.path, "modified_ns": item.modified_ns}
                for item in directories
            ],
            "files": [
                {
                    "path": item.path,
                    "size": item.size,
                    "modified_ns": item.modified_ns,
                    "sha256": item.sha256,
                }
                for item in files
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_staging_tree_manifest(
    root: Path | str,
    *,
    max_file_bytes: int | None = FAT32_MAX_FILE_BYTES,
    cancel_check: CancelCheck | None = None,
) -> StagingTreeManifest:
    """Stream-hash a complete stable tree through no-follow descriptors."""

    if cancel_check is not None and not callable(cancel_check):
        raise StagingTreeSafetyError("The staging manifest cancel check is invalid")
    _check_cancelled(cancel_check)
    staging, source_directories, source_files = scan_staging_tree(
        root, max_file_bytes=max_file_bytes,
    )
    directory_map = {item.parts: item for item in source_directories}
    root_fd = -1
    try:
        root_fd = os.open(staging, _DIR_FLAGS)
        if not _directory_matches(source_directories[0], os.fstat(root_fd)):
            raise StagingTreeSafetyError(
                "The staging root changed before manifest hashing"
            )
        file_records = tuple(
            StagedFileManifest(
                item,
                _hash_bound_file(root_fd, directory_map, item, cancel_check),
            )
            for item in source_files
        )
    except OSError as error:
        raise StagingTreeSafetyError(
            _bounded_message(error, "Could not safely open the staging manifest root")
        ) from error
    finally:
        if root_fd >= 0:
            os.close(root_fd)
    _check_cancelled(cancel_check)
    rescanned = scan_staging_tree(staging, max_file_bytes=max_file_bytes)
    if rescanned != (staging, source_directories, source_files):
        raise StagingTreeSafetyError(
            "The staging tree changed while its manifest was hashed"
        )
    directory_records = tuple(
        StagedDirectoryManifest(item) for item in source_directories
    )
    total_bytes = sum(item.size for item in file_records)
    return StagingTreeManifest(
        staging,
        directory_records,
        file_records,
        total_bytes,
        _manifest_digest(directory_records, file_records),
    )


def validate_staging_tree_manifest(
    manifest: StagingTreeManifest,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    """Rebuild and compare one complete live staging-tree manifest."""

    shape_valid = (
        type(manifest) is StagingTreeManifest
        and isinstance(manifest.root, Path)
        and type(manifest.directories) is tuple
        and type(manifest.files) is tuple
        and bool(manifest.directories)
        and all(
            type(item) is StagedDirectoryManifest
            and type(item.source) is StagedDirectory
            for item in manifest.directories
        )
        and all(
            type(item) is StagedFileManifest
            and type(item.source) is StagedFile
            and type(item.sha256) is str
            and _SHA256.fullmatch(item.sha256) is not None
            for item in manifest.files
        )
        and manifest.directories[0].source.parts == ()
        and type(manifest.total_bytes) is int
        and manifest.total_bytes >= 0
        and type(manifest.manifest_sha256) is str
        and _SHA256.fullmatch(manifest.manifest_sha256) is not None
        and manifest.total_bytes == sum(item.size for item in manifest.files)
    )
    try:
        observed_digest = (
            _manifest_digest(manifest.directories, manifest.files)
            if shape_valid else ""
        )
    except (AttributeError, TypeError, UnicodeError, ValueError):
        observed_digest = ""
    if not shape_valid or not hmac.compare_digest(
        observed_digest, manifest.manifest_sha256,
    ):
        raise StagingTreeSafetyError("The staging-tree manifest is invalid")
    rebuilt = build_staging_tree_manifest(
        manifest.root,
        max_file_bytes=None,
        cancel_check=cancel_check,
    )
    if rebuilt != manifest:
        raise StagingTreeSafetyError("The staging tree changed after manifest creation")
