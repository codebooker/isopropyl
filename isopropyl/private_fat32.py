from __future__ import annotations

from .fat32_tree import (
    PrivateFat32BuildProfile, PrivateFat32Directory, PrivateFat32File, _assign_aliases, _decoded_short, _derive_media_ids, _derive_media_u32, _directory_content, _dos_timestamp, _expected_entries, _layout, _lfn_checksum, _lfn_records, _lfn_slots, _media_identity_seed, _short_candidate, _short_record,
)

from .fat32_layout import (
    PrivateFat32Error, PrivateFat32Geometry, _geometry, _mbr,
    _boot_sector, _fsinfo, _fat, _cluster_offset,
)

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Deterministic, mount-free FAT32 construction on a private ``O_TMPFILE``.

The builder accepts one descriptor-bound staging tree, creates one anonymous
regular file through a bound workspace directory, preallocates its complete
logical size, and writes the MBR, FAT32 metadata, directories, and file bytes
without a loop device, mount, or subprocess.  A separate read-only FAT parser
then hashes every resulting file before the opaque image can be consumed.  The
generic profile has no bootloader dependency; the legacy Syslinux constructor
and patch function are a strict adapter that preserves its loader-first layout.
"""

import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import struct
import threading
import time
import unicodedata
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from .staging_tree import (
    StagedDirectory,
    StagedFile,
    scan_staging_tree,
)
from .fat_image import (
    MAX_DEPTH,
    MAX_DIRECTORIES,
    MAX_DIRECTORY_BYTES,
    MAX_ENTRIES,
    MAX_PATH_UTF8_BYTES,
    FatImageEntry,
    FatImageError,
    RegularFat32Image,
    inspect_regular_fat32_image,
)
if TYPE_CHECKING:
    from .bootloaders import BoundBootBundle
    from .syslinux_transaction import (
        SyslinuxRegularFileTransaction,
        SyslinuxRegularFileTransactionResult,
    )


SECTOR_SIZE = 512
PARTITION_START_SECTOR = 2_048
RESERVED_SECTORS = 32
FAT_COUNT = 2
FSINFO_SECTOR = 1
BACKUP_BOOT_SECTOR = 6
VOLUME_LABEL = b"ISOPROPYL  "
COPY_BLOCK_BYTES = 4 * 1024 * 1024
MAX_PRIVATE_FAT32_IMAGE_BYTES = 128 * 1024**3
_MEDIA_ID_PROFILE = "io.github.codebooker.isopropyl/private-fat32/media-id/v1"
_FORBIDDEN_MEDIA_IDS = frozenset({0, 0xFFFFFFFF})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GENERIC_PLAN_WITNESS = object()
_SYSLINUX_PLAN_WITNESS = object()
_WINDOWS_PLAN_WITNESS = object()
_GRUB_RESCUE_PLAN_WITNESS = object()
_IMAGE_WITNESS = object()
_SHORT_ALLOWED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$%'-_@~`!(){}^#&"
)
_DIR_FLAGS = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)




class PrivateFat32Cancelled(PrivateFat32Error):
    """Private image construction was cancelled and its file was discarded."""


class PrivateFat32State(str, Enum):
    GENERIC_ATTESTED = "generic-attested"
    UNPATCHED_ATTESTED = "unpatched-attested"
    PATCHING = "patching"
    PATCHED_ATTESTED = "patched-attested"
    POISONED = "poisoned"
    CLOSED = "closed"




@dataclass(frozen=True)
class PrivateWorkspaceIdentity:
    device: int
    inode: int
    owner: int
    mode: int








@dataclass(frozen=True)
class PrivateFat32Plan:
    source_root: str
    workspace: str
    workspace_identity: PrivateWorkspaceIdentity
    geometry: PrivateFat32Geometry
    directories: tuple[PrivateFat32Directory, ...]
    files: tuple[PrivateFat32File, ...]
    profile: PrivateFat32BuildProfile
    root_ldlinux_size: int | None
    root_ldlinux_sha256: str | None
    total_content_bytes: int
    allocated_clusters: int
    disk_signature: int
    volume_id: int
    plan_sha256: str
    _witness: object = field(default=None, repr=False, compare=True)


@dataclass(frozen=True)
class PrivateFat32Result:
    plan_sha256: str
    image_sha256: str
    manifest_sha256: str
    files_verified: int
    directories_verified: int
    bytes_verified: int
    allocated_clusters: int
    free_clusters: int


CancelCheck = Callable[[], None]
Progress = Callable[[str, str, int, int], None]


def _check_cancelled(cancel_check: CancelCheck | None) -> None:
    if cancel_check is not None:
        cancel_check()


def _bounded(value: object, fallback: str) -> str:
    rendered = str(value or "").strip()
    return rendered[-2_048:] if rendered else fallback


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


def _canonical_path(value: Path | str, label: str) -> tuple[str, os.stat_result]:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise PrivateFat32Error(f"The {label} must be an absolute path")
    rendered = os.path.normpath(os.fspath(candidate))
    if rendered != os.fspath(candidate):
        raise PrivateFat32Error(f"The {label} path is not canonical")
    try:
        before = os.lstat(rendered)
        descriptor = os.open(rendered, _DIR_FLAGS)
        try:
            opened = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise PrivateFat32Error(
            _bounded(error, f"Could not safely open the {label}"),
        ) from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISDIR(before.st_mode)
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise PrivateFat32Error(f"The {label} must be one stable real directory")
    return rendered, opened


def _workspace_identity(info: os.stat_result) -> PrivateWorkspaceIdentity:
    return PrivateWorkspaceIdentity(
        info.st_dev,
        info.st_ino,
        info.st_uid,
        stat.S_IMODE(info.st_mode),
    )




def _validate_source_limits(
    directories: tuple[StagedDirectory, ...],
    files: tuple[StagedFile, ...],
) -> None:
    if (
        not directories
        or directories[0].parts
        or len(directories) > MAX_DIRECTORIES
        or len(directories) + len(files) > MAX_ENTRIES
    ):
        raise PrivateFat32Error("The staging tree exceeds the private FAT32 entry limits")
    for parts in tuple(item.parts for item in directories) + tuple(item.parts for item in files):
        if len(parts) > MAX_DEPTH:
            raise PrivateFat32Error("The staging tree exceeds the private FAT32 depth limit")
        rendered = PurePosixPath(*parts).as_posix() if parts else "."
        try:
            encoded_path = rendered.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise PrivateFat32Error("A staged path is not valid Unicode") from error
        if len(encoded_path) > MAX_PATH_UTF8_BYTES:
            raise PrivateFat32Error("A staged path exceeds the private FAT32 path limit")
        for component in parts:
            if unicodedata.normalize("NFC", component) != component:
                raise PrivateFat32Error("Private FAT32 construction requires NFC path names")
            if any(
                ord(character) > 0xFFFF or ord(character) == 0xFFFF
                for character in component
            ):
                raise PrivateFat32Error(
                    "Private FAT32 construction does not support non-BMP or U+FFFF names",
                )


def _open_source_root(root: str, expected: StagedDirectory) -> int:
    descriptor = -1
    try:
        descriptor = os.open(root, _DIR_FLAGS)
        info = os.fstat(descriptor)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise PrivateFat32Error(
            _bounded(error, "Could not reopen the bound staging root"),
        ) from error
    if not _directory_matches(expected, info):
        os.close(descriptor)
        raise PrivateFat32Error("The staging root changed after planning")
    return descriptor


def _open_source_directory(
    root_fd: int,
    parts: tuple[str, ...],
    directories: dict[tuple[str, ...], StagedDirectory],
) -> int:
    current = os.dup(root_fd)
    walked: tuple[str, ...] = ()
    try:
        for component in parts:
            following = os.open(component, _DIR_FLAGS, dir_fd=current)
            os.close(current)
            current = following
            walked += (component,)
            expected = directories.get(walked)
            if expected is None or not _directory_matches(expected, os.fstat(current)):
                raise PrivateFat32Error(
                    f"Staged directory changed after planning: {PurePosixPath(*walked)}",
                )
        return current
    except OSError as error:
        os.close(current)
        raise PrivateFat32Error(
            _bounded(error, "Could not traverse the bound staging tree"),
        ) from error
    except BaseException:
        os.close(current)
        raise


def _consume_source_file(
    root_fd: int,
    directories: dict[tuple[str, ...], StagedDirectory],
    source: StagedFile,
    consume: Callable[[bytes, int], None],
    *,
    cancel_check: CancelCheck | None,
) -> str:
    parent_fd = _open_source_directory(root_fd, source.parts[:-1], directories)
    descriptor = -1
    try:
        before = os.stat(source.parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if not _file_matches(source, before):
            raise PrivateFat32Error(f"Staged file changed: {source.path!r}")
        descriptor = os.open(source.parts[-1], _READ_FLAGS, dir_fd=parent_fd)
        if not _file_matches(source, os.fstat(descriptor)):
            raise PrivateFat32Error(f"Staged file changed while opening: {source.path!r}")
        digest = hashlib.sha256()
        consumed = 0
        while consumed < source.size:
            _check_cancelled(cancel_check)
            try:
                block = os.read(descriptor, min(COPY_BLOCK_BYTES, source.size - consumed))
            except InterruptedError:
                continue
            if not block:
                raise PrivateFat32Error(f"Staged file ended early: {source.path!r}")
            digest.update(block)
            consume(block, consumed)
            consumed += len(block)
        if os.read(descriptor, 1):
            raise PrivateFat32Error(f"Staged file grew while reading: {source.path!r}")
        if not _file_matches(source, os.fstat(descriptor)):
            raise PrivateFat32Error(f"Staged file changed while reading: {source.path!r}")
        return digest.hexdigest()
    except OSError as error:
        raise PrivateFat32Error(
            _bounded(error, f"Could not read staged file {source.path!r}"),
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def _hash_sources(
    root: str,
    directories: tuple[StagedDirectory, ...],
    files: tuple[StagedFile, ...],
    cancel_check: CancelCheck | None,
) -> tuple[str, ...]:
    root_fd = _open_source_root(root, directories[0])
    directory_map = {item.parts: item for item in directories}
    try:
        return tuple(
            _consume_source_file(
                root_fd,
                directory_map,
                item,
                lambda _block, _offset: None,
                cancel_check=cancel_check,
            )
            for item in files
        )
    finally:
        os.close(root_fd)












def _plan_payload(plan: PrivateFat32Plan) -> dict[str, object]:
    def source_directory(item: StagedDirectory) -> list[object]:
        return [*item.parts, item.device, item.inode, item.modified_ns, item.changed_ns]

    def source_file(item: StagedFile) -> list[object]:
        return [
            *item.parts,
            item.device,
            item.inode,
            item.size,
            item.modified_ns,
            item.changed_ns,
            item.link_count,
        ]

    return {
        "source_root": plan.source_root,
        "workspace": plan.workspace,
        "workspace_identity": [
            plan.workspace_identity.device,
            plan.workspace_identity.inode,
            plan.workspace_identity.owner,
            plan.workspace_identity.mode,
        ],
        "geometry": list(plan.geometry.__dict__.values()),
        "directories": [
            [
                source_directory(item.source),
                item.short_name.hex(),
                item.case_flags,
                item.long_name,
                item.first_cluster,
                item.cluster_count,
            ]
            for item in plan.directories
        ],
        "files": [
            [
                source_file(item.source),
                item.sha256,
                item.short_name.hex(),
                item.case_flags,
                item.long_name,
                item.first_cluster,
                item.cluster_count,
            ]
            for item in plan.files
        ],
        "profile": plan.profile.value,
        "root_ldlinux_size": plan.root_ldlinux_size,
        "root_ldlinux_sha256": plan.root_ldlinux_sha256,
        "total_content_bytes": plan.total_content_bytes,
        "allocated_clusters": plan.allocated_clusters,
        "disk_signature": plan.disk_signature,
        "volume_id": plan.volume_id,
    }


def _plan_digest(plan: PrivateFat32Plan) -> str:
    return hashlib.sha256(json.dumps(
        _plan_payload(plan),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")).hexdigest()








def _build_profiled_private_fat32_plan(
    staging_root: Path | str,
    workspace: Path | str,
    *,
    image_size: int,
    profile: PrivateFat32BuildProfile,
    expected_root_ldlinux: bytes | None,
    cancel_check: CancelCheck | None = None,
) -> PrivateFat32Plan:
    """Hash and allocate one final staged tree without creating an image."""

    if type(profile) is not PrivateFat32BuildProfile:
        raise PrivateFat32Error("The private FAT32 build profile is invalid")
    if profile is PrivateFat32BuildProfile.SYSLINUX:
        if type(expected_root_ldlinux) is not bytes or not expected_root_ldlinux:
            raise PrivateFat32Error("Exact unpatched root ldlinux.sys bytes are required")
    elif expected_root_ldlinux is not None:
        raise PrivateFat32Error("The generic FAT32 profile accepts no Syslinux payload")
    root, _root_info = _canonical_path(staging_root, "staging root")
    workspace_path, workspace_info = _canonical_path(workspace, "private workspace")
    if workspace_info.st_uid != os.geteuid():
        raise PrivateFat32Error("The private workspace must be owned by the current user")
    geometry = _geometry(image_size)
    scanned_root, directories, files = scan_staging_tree(root)
    if os.fspath(scanned_root) != root:
        raise PrivateFat32Error("The staging scanner returned a different root")
    if any(
        (item.device, item.inode) == (workspace_info.st_dev, workspace_info.st_ino)
        for item in directories
    ):
        raise PrivateFat32Error("The private workspace must be outside the staging tree")
    _validate_source_limits(directories, files)
    hashes = _hash_sources(root, directories, files, cancel_check)
    _check_cancelled(cancel_check)
    rescanned = scan_staging_tree(root)
    if rescanned != (scanned_root, directories, files):
        raise PrivateFat32Error("The staging tree changed while its content was hashed")
    planned_directories, planned_files, allocated = _layout(
        geometry,
        directories,
        files,
        hashes,
        priority_file=(
            ("ldlinux.sys",)
            if profile is PrivateFat32BuildProfile.SYSLINUX
            else None
        ),
    )
    root_ldlinux_size: int | None = None
    root_ldlinux_sha256: str | None = None
    if profile is PrivateFat32BuildProfile.SYSLINUX:
        assert type(expected_root_ldlinux) is bytes
        root_files = tuple(
            item for item in planned_files
            if item.source.parts == ("ldlinux.sys",)
        )
        expected_digest = hashlib.sha256(expected_root_ldlinux).hexdigest()
        if (
            len(root_files) != 1
            or root_files[0].source.size != len(expected_root_ldlinux)
            or not hmac.compare_digest(root_files[0].sha256, expected_digest)
        ):
            raise PrivateFat32Error(
                "The staged root ldlinux.sys does not match its exact payload",
            )
        root_ldlinux_size = len(expected_root_ldlinux)
        root_ldlinux_sha256 = expected_digest
    disk_signature, volume_id = _derive_media_ids(
        geometry,
        planned_directories,
        planned_files,
    )
    candidate = PrivateFat32Plan(
        root,
        workspace_path,
        _workspace_identity(workspace_info),
        geometry,
        planned_directories,
        planned_files,
        profile,
        root_ldlinux_size,
        root_ldlinux_sha256,
        sum(item.source.size for item in planned_files),
        allocated,
        disk_signature,
        volume_id,
        "",
        (
            _SYSLINUX_PLAN_WITNESS
            if profile is PrivateFat32BuildProfile.SYSLINUX
            else _WINDOWS_PLAN_WITNESS
            if profile is PrivateFat32BuildProfile.WINDOWS_BOOTMGR
            else _GRUB_RESCUE_PLAN_WITNESS
            if profile is PrivateFat32BuildProfile.GRUB_RESCUE
            else _GENERIC_PLAN_WITNESS
        ),
    )
    return PrivateFat32Plan(
        **{**candidate.__dict__, "plan_sha256": _plan_digest(candidate)},
    )


def build_generic_private_fat32_plan(
    staging_root: Path | str,
    workspace: Path | str,
    *,
    image_size: int,
    cancel_check: CancelCheck | None = None,
) -> PrivateFat32Plan:
    """Plan a deterministic anonymous MBR/FAT32 image for any safe tree."""

    return _build_profiled_private_fat32_plan(
        staging_root,
        workspace,
        image_size=image_size,
        profile=PrivateFat32BuildProfile.GENERIC,
        expected_root_ldlinux=None,
        cancel_check=cancel_check,
    )


def build_private_fat32_plan(
    staging_root: Path | str,
    workspace: Path | str,
    *,
    image_size: int,
    expected_root_ldlinux: bytes,
    cancel_check: CancelCheck | None = None,
) -> PrivateFat32Plan:
    """Build the legacy exact Syslinux plan through the generic engine."""

    return _build_profiled_private_fat32_plan(
        staging_root,
        workspace,
        image_size=image_size,
        profile=PrivateFat32BuildProfile.SYSLINUX,
        expected_root_ldlinux=expected_root_ldlinux,
        cancel_check=cancel_check,
    )


def build_windows_private_fat32_plan(
    staging_root: Path | str,
    workspace: Path | str,
    *,
    image_size: int,
    cancel_check: CancelCheck | None = None,
) -> PrivateFat32Plan:
    """Plan a Windows image whose unpatched form cannot be consumed."""

    return _build_profiled_private_fat32_plan(
        staging_root,
        workspace,
        image_size=image_size,
        profile=PrivateFat32BuildProfile.WINDOWS_BOOTMGR,
        expected_root_ldlinux=None,
        cancel_check=cancel_check,
    )


def build_grub_rescue_private_fat32_plan(
    staging_root: Path | str,
    workspace: Path | str,
    *,
    image_size: int,
    cancel_check: CancelCheck | None = None,
) -> PrivateFat32Plan:
    """Plan an empty GRUB rescue image that cannot be consumed pre-patch."""

    plan = _build_profiled_private_fat32_plan(
        staging_root,
        workspace,
        image_size=image_size,
        profile=PrivateFat32BuildProfile.GRUB_RESCUE,
        expected_root_ldlinux=None,
        cancel_check=cancel_check,
    )
    if len(plan.directories) != 1 or plan.directories[0].source.parts or plan.files:
        raise PrivateFat32Error("The GRUB rescue FAT32 tree must be empty")
    return plan


def _validate_plan_shape(plan: PrivateFat32Plan) -> None:
    if type(plan) is not PrivateFat32Plan:
        raise PrivateFat32Error("An authentic private FAT32 plan is required")
    expected_witness = (
        _SYSLINUX_PLAN_WITNESS
        if plan.profile is PrivateFat32BuildProfile.SYSLINUX
        else _WINDOWS_PLAN_WITNESS
        if plan.profile is PrivateFat32BuildProfile.WINDOWS_BOOTMGR
        else _GRUB_RESCUE_PLAN_WITNESS
        if plan.profile is PrivateFat32BuildProfile.GRUB_RESCUE
        else _GENERIC_PLAN_WITNESS
        if plan.profile is PrivateFat32BuildProfile.GENERIC
        else None
    )
    if plan._witness is not expected_witness:
        raise PrivateFat32Error(
            "The private FAT32 plan profile does not match its construction",
        )
    if (
        type(plan.source_root) is not str
        or not os.path.isabs(plan.source_root)
        or os.path.normpath(plan.source_root) != plan.source_root
        or type(plan.workspace) is not str
        or not os.path.isabs(plan.workspace)
        or os.path.normpath(plan.workspace) != plan.workspace
        or type(plan.workspace_identity) is not PrivateWorkspaceIdentity
        or any(
            type(value) is not int or value < 0
            for value in plan.workspace_identity.__dict__.values()
        )
        or type(plan.geometry) is not PrivateFat32Geometry
        or type(plan.directories) is not tuple
        or type(plan.files) is not tuple
        or any(type(item) is not PrivateFat32Directory for item in plan.directories)
        or any(type(item) is not PrivateFat32File for item in plan.files)
        or type(plan.profile) is not PrivateFat32BuildProfile
        or type(plan.total_content_bytes) is not int
        or plan.total_content_bytes < 0
        or type(plan.allocated_clusters) is not int
        or plan.allocated_clusters <= 0
        or type(plan.disk_signature) is not int
        or not 0 < plan.disk_signature < 0xFFFFFFFF
        or type(plan.volume_id) is not int
        or not 0 < plan.volume_id < 0xFFFFFFFF
        or plan.volume_id == plan.disk_signature
        or type(plan.plan_sha256) is not str
        or _SHA256.fullmatch(plan.plan_sha256) is None
    ):
        raise PrivateFat32Error("The private FAT32 plan fields are invalid")
    if plan.profile in {
        PrivateFat32BuildProfile.GENERIC,
        PrivateFat32BuildProfile.WINDOWS_BOOTMGR,
        PrivateFat32BuildProfile.GRUB_RESCUE,
    }:
        if plan.root_ldlinux_size is not None or plan.root_ldlinux_sha256 is not None:
            raise PrivateFat32Error("The FAT32 profile carries unexpected Syslinux state")
    elif (
        type(plan.root_ldlinux_size) is not int
        or plan.root_ldlinux_size <= 0
        or type(plan.root_ldlinux_sha256) is not str
        or _SHA256.fullmatch(plan.root_ldlinux_sha256) is None
    ):
        raise PrivateFat32Error("The Syslinux FAT32 profile lacks its root loader")
    if (
        plan.profile is PrivateFat32BuildProfile.GRUB_RESCUE
        and (
            len(plan.directories) != 1
            or plan.directories[0].source.parts
            or plan.files
            or plan.total_content_bytes != 0
        )
    ):
        raise PrivateFat32Error("The GRUB rescue FAT32 plan is not empty")
    if plan.geometry != _geometry(plan.geometry.image_size):
        raise PrivateFat32Error("The private FAT32 geometry is not canonical")
    sources_directories = tuple(item.source for item in plan.directories)
    sources_files = tuple(item.source for item in plan.files)
    _validate_source_limits(sources_directories, sources_files)
    for item in (*plan.directories, *plan.files):
        if (
            type(item.source) not in {StagedDirectory, StagedFile}
            or type(item.short_name) is not bytes
            or (item.source.parts and len(item.short_name) != 11)
            or (not item.source.parts and item.short_name != b"")
            or type(item.case_flags) is not int
            or item.case_flags & ~0x18
            or type(item.long_name) is not bool
            or type(item.first_cluster) is not int
            or type(item.cluster_count) is not int
            or item.cluster_count < 0
            or (item.cluster_count == 0) != (item.first_cluster == 0)
        ):
            raise PrivateFat32Error("A private FAT32 allocation record is invalid")
    if any(
        type(item.sha256) is not str or _SHA256.fullmatch(item.sha256) is None
        for item in plan.files
    ):
        raise PrivateFat32Error("A private FAT32 source digest is invalid")
    rebuilt_directories, rebuilt_files, rebuilt_allocated = _layout(
        plan.geometry,
        sources_directories,
        sources_files,
        tuple(item.sha256 for item in plan.files),
        priority_file=(
            ("ldlinux.sys",)
            if plan.profile is PrivateFat32BuildProfile.SYSLINUX
            else None
        ),
    )
    root_files = tuple(item for item in plan.files if item.source.parts == ("ldlinux.sys",))
    loader_invalid = (
        plan.profile is PrivateFat32BuildProfile.SYSLINUX
        and (
            len(root_files) != 1
            or root_files[0].source.size != plan.root_ldlinux_size
            or not hmac.compare_digest(
                root_files[0].sha256,
                plan.root_ldlinux_sha256 or "",
            )
        )
    )
    if (
        rebuilt_directories != plan.directories
        or rebuilt_files != plan.files
        or rebuilt_allocated != plan.allocated_clusters
        or loader_invalid
        or sum(item.source.size for item in plan.files) != plan.total_content_bytes
        or plan.allocated_clusters > plan.geometry.cluster_count
        or (plan.disk_signature, plan.volume_id)
        != _derive_media_ids(plan.geometry, plan.directories, plan.files)
        or not hmac.compare_digest(_plan_digest(plan), plan.plan_sha256)
    ):
        raise PrivateFat32Error("The private FAT32 plan is forged or inconsistent")


def validate_private_fat32_plan(
    plan: PrivateFat32Plan,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    """Rehash and rebind the complete live source tree and workspace."""

    _validate_plan_shape(plan)
    workspace, workspace_info = _canonical_path(plan.workspace, "private workspace")
    if (
        workspace != plan.workspace
        or _workspace_identity(workspace_info) != plan.workspace_identity
    ):
        raise PrivateFat32Error("The private workspace changed after planning")
    root, _root_info = _canonical_path(plan.source_root, "staging root")
    scanned_root, directories, files = scan_staging_tree(root)
    if (
        os.fspath(scanned_root) != plan.source_root
        or directories != tuple(item.source for item in plan.directories)
        or files != tuple(item.source for item in plan.files)
    ):
        raise PrivateFat32Error("The staging tree changed after planning")
    hashes = _hash_sources(root, directories, files, cancel_check)
    if hashes != tuple(item.sha256 for item in plan.files):
        raise PrivateFat32Error("Staged file content changed after planning")
    _check_cancelled(cancel_check)
    if scan_staging_tree(root) != (scanned_root, directories, files):
        raise PrivateFat32Error("The staging tree changed during plan validation")
























def _private_status(descriptor: int, expected_size: int) -> os.stat_result:
    try:
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        info = os.fstat(descriptor)
    except OSError as error:
        raise PrivateFat32Error(
            _bounded(error, "Could not inspect the anonymous FAT32 image"),
        ) from error
    if (
        flags & os.O_ACCMODE != os.O_RDWR
        or flags & os.O_APPEND
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 0
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size != expected_size
    ):
        raise PrivateFat32Error("The anonymous FAT32 image has unsafe descriptor state")
    return info


def _source_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_exact(descriptor: int, offset: int, length: int, label: str) -> bytes:
    result = bytearray()
    while len(result) < length:
        try:
            block = os.pread(descriptor, length - len(result), offset + len(result))
        except InterruptedError:
            continue
        except OSError as error:
            raise PrivateFat32Error(_bounded(error, f"Could not read {label}")) from error
        if not block:
            raise PrivateFat32Error(f"Could not read {label} completely")
        result.extend(block)
    return bytes(result)


def _image_digest(
    descriptor: int,
    size: int,
    cancel_check: CancelCheck | None = None,
) -> str:
    digest = hashlib.sha256()
    consumed = 0
    while consumed < size:
        _check_cancelled(cancel_check)
        block = _read_exact(
            descriptor,
            consumed,
            min(COPY_BLOCK_BYTES, size - consumed),
            "the complete anonymous FAT32 image",
        )
        digest.update(block)
        consumed += len(block)
    return digest.hexdigest()


def _verify_zero_unwritten_extents(
    descriptor: int,
    image_size: int,
    written_extents: list[tuple[int, int]],
    cancel_check: CancelCheck | None,
) -> None:
    """Require every byte outside the canonical write set to remain zero."""

    cursor = 0
    for offset, length in sorted(written_extents):
        if offset < cursor or length <= 0 or offset + length > image_size:
            raise PrivateFat32Error("The private FAT32 write extent map is invalid")
        while cursor < offset:
            _check_cancelled(cancel_check)
            take = min(COPY_BLOCK_BYTES, offset - cursor)
            if any(_read_exact(descriptor, cursor, take, "an unwritten image extent")):
                raise PrivateFat32Error(
                    "The anonymous FAT32 image has nonzero bytes outside its write plan",
                )
            cursor += take
        cursor = offset + length
    while cursor < image_size:
        _check_cancelled(cancel_check)
        take = min(COPY_BLOCK_BYTES, image_size - cursor)
        if any(_read_exact(descriptor, cursor, take, "an unwritten image extent")):
            raise PrivateFat32Error(
                "The anonymous FAT32 image has nonzero bytes outside its write plan",
            )
        cursor += take


class AnonymousFat32Image:
    """Opaque owner of one attested anonymous image descriptor."""

    __slots__ = (
        "_descriptor", "_inspection", "_lifecycle", "_plan", "_result", "_state",
        "_patched_image_sha256", "_transaction_result", "_witness",
    )

    def __init__(
        self,
        descriptor: int,
        plan: PrivateFat32Plan,
        result: PrivateFat32Result,
        inspection: RegularFat32Image,
        witness: object,
    ) -> None:
        if witness is not _IMAGE_WITNESS:
            raise PrivateFat32Error("Anonymous FAT32 images are builder-owned")
        self._descriptor = descriptor
        self._plan = plan
        self._result = result
        self._inspection = inspection
        self._lifecycle = threading.RLock()
        self._state = (
            PrivateFat32State.GENERIC_ATTESTED
            if plan.profile is PrivateFat32BuildProfile.GENERIC
            else PrivateFat32State.UNPATCHED_ATTESTED
        )
        self._transaction_result: SyslinuxRegularFileTransactionResult | None = None
        self._patched_image_sha256: str | None = None
        self._witness = witness

    @property
    def state(self) -> PrivateFat32State:
        return self._state

    @property
    def plan(self) -> PrivateFat32Plan:
        return self._plan

    @property
    def result(self) -> PrivateFat32Result:
        return self._result

    @property
    def inspection(self) -> RegularFat32Image:
        return self._inspection

    @property
    def transaction_result(self) -> SyslinuxRegularFileTransactionResult | None:
        return self._transaction_result

    def _owned_descriptor(self) -> int:
        if self._witness is not _IMAGE_WITNESS or self._descriptor < 0:
            raise PrivateFat32Error("The anonymous FAT32 image is closed")
        return self._descriptor

    def _begin_profile_patch(self, profile: PrivateFat32BuildProfile) -> int:
        self._lifecycle.acquire()
        try:
            if (
                self._witness is not _IMAGE_WITNESS
                or self._plan.profile is not profile
                or self._state is not PrivateFat32State.UNPATCHED_ATTESTED
            ):
                raise PrivateFat32Error(
                    "One unpatched builder-owned FAT32 image is required",
                )
            descriptor = self._owned_descriptor()
            self._state = PrivateFat32State.PATCHING
            return descriptor
        except BaseException:
            self._lifecycle.release()
            raise

    def _begin_patch(self) -> int:
        return self._begin_profile_patch(PrivateFat32BuildProfile.SYSLINUX)

    def _begin_windows_patch(self) -> int:
        return self._begin_profile_patch(PrivateFat32BuildProfile.WINDOWS_BOOTMGR)

    def _begin_grub_rescue_patch(self) -> int:
        return self._begin_profile_patch(PrivateFat32BuildProfile.GRUB_RESCUE)

    def _commit_windows_patch(
        self,
        inspection: RegularFat32Image,
        image_sha256: str,
    ) -> None:
        if (
            self._state is not PrivateFat32State.PATCHING
            or self._plan.profile is not PrivateFat32BuildProfile.WINDOWS_BOOTMGR
            or type(inspection) is not RegularFat32Image
            or type(image_sha256) is not str
            or _SHA256.fullmatch(image_sha256) is None
        ):
            raise PrivateFat32Error("The patched Windows FAT32 result is invalid")
        self._inspection = inspection
        self._patched_image_sha256 = image_sha256
        self._state = PrivateFat32State.PATCHED_ATTESTED

    def _commit_grub_rescue_patch(
        self,
        inspection: RegularFat32Image,
        image_sha256: str,
    ) -> None:
        if (
            self._state is not PrivateFat32State.PATCHING
            or self._plan.profile is not PrivateFat32BuildProfile.GRUB_RESCUE
            or type(inspection) is not RegularFat32Image
            or type(image_sha256) is not str
            or _SHA256.fullmatch(image_sha256) is None
        ):
            raise PrivateFat32Error("The patched GRUB rescue FAT32 result is invalid")
        self._inspection = inspection
        self._patched_image_sha256 = image_sha256
        self._state = PrivateFat32State.PATCHED_ATTESTED

    def _end_patch(self) -> None:
        self._lifecycle.release()

    def _poison(self) -> None:
        with self._lifecycle:
            if self._descriptor >= 0:
                descriptor = self._descriptor
                self._descriptor = -1
                self._state = PrivateFat32State.POISONED
                os.close(descriptor)
            else:
                self._state = PrivateFat32State.POISONED

    def close(self) -> None:
        with self._lifecycle:
            if self._state is PrivateFat32State.PATCHING:
                raise PrivateFat32Error("The anonymous FAT32 image is being patched")
            if self._descriptor >= 0:
                descriptor = self._descriptor
                self._descriptor = -1
                os.close(descriptor)
            self._state = PrivateFat32State.CLOSED

    def chunks(self, chunk_bytes: int = COPY_BLOCK_BYTES) -> Iterator[bytes]:
        """Yield bounded bytes from a generic or patched attested image."""

        if type(chunk_bytes) is not int or not 1 <= chunk_bytes <= COPY_BLOCK_BYTES:
            raise PrivateFat32Error("The private image chunk size is invalid")

        def iterate() -> Iterator[bytes]:
            descriptor, image_size = self._duplicate_attested_descriptor()
            try:
                consumed = 0
                while consumed < image_size:
                    block = _read_exact(
                        descriptor,
                        consumed,
                        min(chunk_bytes, image_size - consumed),
                        "the patched private image",
                    )
                    consumed += len(block)
                    yield block
            finally:
                os.close(descriptor)

        return iterate()

    def _duplicate_attested_descriptor(
        self,
        cancel_check: CancelCheck | None = None,
    ) -> tuple[int, int]:
        """Duplicate only a still-attested image for the owned helper bridge."""

        with self._lifecycle:
            generic = (
                self._plan.profile is PrivateFat32BuildProfile.GENERIC
                and self._state is PrivateFat32State.GENERIC_ATTESTED
            )
            patched = self._state is PrivateFat32State.PATCHED_ATTESTED
            if not (generic or patched):
                raise PrivateFat32Error(
                    (
                        "Only a patched, attested image can cross the helper boundary"
                        if self._plan.profile in {
                            PrivateFat32BuildProfile.SYSLINUX,
                            PrivateFat32BuildProfile.WINDOWS_BOOTMGR,
                            PrivateFat32BuildProfile.GRUB_RESCUE,
                        }
                        else "Only a generic attested image can be consumed"
                    ),
                )
            descriptor = os.dup(self._owned_descriptor())
            image_size = self._plan.geometry.image_size
            try:
                os.set_inheritable(descriptor, False)
                before_stream = _private_status(descriptor, image_size)
                stream_sha256 = _image_digest(
                    descriptor,
                    image_size,
                    cancel_check,
                )
                after_stream = _private_status(descriptor, image_size)
                expected_identity = (
                    (
                        self._inspection.source_identity.device,
                        self._inspection.source_identity.inode,
                        self._inspection.source_identity.size,
                        self._inspection.source_identity.modified_ns,
                        self._inspection.source_identity.changed_ns,
                    )
                    if generic
                    else (
                        self._inspection.source_identity.device,
                        self._inspection.source_identity.inode,
                        self._inspection.source_identity.size,
                        self._inspection.source_identity.modified_ns,
                        self._inspection.source_identity.changed_ns,
                    )
                    if self._patched_image_sha256 is not None
                    else None
                )
                expected_sha256 = (
                    self._result.image_sha256
                    if generic
                    else self._patched_image_sha256
                    if self._patched_image_sha256 is not None
                    else ""
                )
                if (
                    expected_identity is None
                    or _source_identity(before_stream)
                    != _source_identity(after_stream)
                    or _source_identity(after_stream)
                    != expected_identity
                    or not hmac.compare_digest(
                        stream_sha256,
                        expected_sha256,
                    )
                ):
                    self._poison()
                    raise PrivateFat32Error(
                        "The FAT32 image changed before streaming or helper transfer",
                    )
            except BaseException:
                os.close(descriptor)
                raise
            return descriptor, image_size

    def _duplicate_attested_readonly_descriptor(
        self,
        cancel_check: CancelCheck | None = None,
    ) -> tuple[int, int]:
        """Internally reopen one attested anonymous image read-only for a VM."""

        self._lifecycle.acquire()
        try:
            source, image_size = self._duplicate_attested_descriptor(cancel_check)
        except BaseException:
            self._lifecycle.release()
            raise
        readonly = -1
        try:
            source_status = _private_status(source, image_size)
            try:
                readonly = os.open(
                    f"/proc/self/fd/{source}",
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                )
                readonly_status = os.fstat(readonly)
                readonly_flags = fcntl.fcntl(readonly, fcntl.F_GETFL)
            except OSError as error:
                raise PrivateFat32Error(
                    "Could not create a read-only attested image descriptor",
                ) from error
            if (
                readonly_flags & os.O_ACCMODE != os.O_RDONLY
                or readonly_flags & os.O_APPEND
                or not stat.S_ISREG(readonly_status.st_mode)
                or readonly_status.st_nlink != 0
                or readonly_status.st_uid != os.geteuid()
                or stat.S_IMODE(readonly_status.st_mode) != 0o600
                or _source_identity(readonly_status) != _source_identity(source_status)
            ):
                raise PrivateFat32Error(
                    "The read-only attested image descriptor is unsafe",
                )
            before_hash = _source_identity(readonly_status)
            observed_sha256 = _image_digest(readonly, image_size, cancel_check)
            after_hash = _source_identity(os.fstat(readonly))
            expected_sha256 = (
                self._result.image_sha256
                if self._state is PrivateFat32State.GENERIC_ATTESTED
                else self._patched_image_sha256 or ""
            )
            if (
                before_hash != after_hash
                or not hmac.compare_digest(observed_sha256, expected_sha256)
            ):
                self._poison()
                raise PrivateFat32Error(
                    "The read-only image changed before virtual-machine transfer",
                )
            result = readonly
            readonly = -1
            return result, image_size
        finally:
            try:
                if readonly >= 0:
                    try:
                        os.close(readonly)
                    except OSError:
                        pass
            finally:
                try:
                    try:
                        os.close(source)
                    except OSError:
                        pass
                finally:
                    self._lifecycle.release()

    def __enter__(self) -> AnonymousFat32Image:
        with self._lifecycle:
            self._owned_descriptor()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class PrivateFat32Builder:
    """One-shot executor for a witnessed private FAT32 image plan."""

    def __init__(
        self,
        *,
        write_at: Callable[[int, bytes, int], int] = os.pwrite,
        sync: Callable[[int], None] = os.fsync,
        preallocate: Callable[[int, int, int], None] | None = None,
    ) -> None:
        self._write_at = write_at
        self._sync = sync
        self._preallocate = preallocate or getattr(os, 'posix_fallocate', None)
        self._used = False

    def _write_exact(self, descriptor: int, data: bytes, offset: int, label: str) -> None:
        written = 0
        while written < len(data):
            try:
                count = self._write_at(descriptor, data[written:], offset + written)
            except InterruptedError:
                continue
            if type(count) is not int or count <= 0 or count > len(data) - written:
                raise PrivateFat32Error(f"The {label} write made invalid progress")
            written += count

    def _preallocate_exact(self, descriptor: int, length: int) -> None:
        if self._preallocate is None:
            raise PrivateFat32Error('This runtime does not provide anonymous-image preallocation')
        while True:
            try:
                self._preallocate(descriptor, 0, length)
                return
            except InterruptedError:
                continue

    def _sync_exact(self, descriptor: int) -> None:
        while True:
            try:
                self._sync(descriptor)
                return
            except InterruptedError:
                continue

    @staticmethod
    def _open_anonymous(workspace_fd: int) -> int:
        if not hasattr(os, "O_TMPFILE"):
            raise PrivateFat32Error("This filesystem runtime does not support O_TMPFILE")
        flags = os.O_TMPFILE | os.O_EXCL | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        try:
            return os.open(".", flags, 0o600, dir_fd=workspace_fd)
        except OSError as error:
            raise PrivateFat32Error(
                _bounded(error, "The workspace cannot create a strict anonymous image"),
            ) from error

    def execute(
        self,
        plan: PrivateFat32Plan,
        *,
        cancel_check: CancelCheck | None = None,
        progress: Progress = lambda _stage, _path, _done, _total: None,
    ) -> AnonymousFat32Image:
        if self._used:
            raise PrivateFat32Error("A private FAT32 builder can only be used once")
        self._used = True
        validate_private_fat32_plan(plan, cancel_check=cancel_check)
        _check_cancelled(cancel_check)
        workspace_fd = -1
        descriptor = -1
        try:
            workspace_fd = os.open(plan.workspace, _DIR_FLAGS)
            if _workspace_identity(os.fstat(workspace_fd)) != plan.workspace_identity:
                raise PrivateFat32Error("The private workspace changed before image creation")
            descriptor = self._open_anonymous(workspace_fd)
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._preallocate_exact(descriptor, plan.geometry.image_size)
            os.ftruncate(descriptor, plan.geometry.image_size)
            allocated_status = _private_status(descriptor, plan.geometry.image_size)
            if allocated_status.st_blocks * 512 < plan.geometry.image_size:
                raise PrivateFat32Error(
                    "The anonymous FAT32 image was not completely preallocated",
                )
            _check_cancelled(cancel_check)

            boot = _boot_sector(plan)
            fsinfo = _fsinfo(plan)
            fat = _fat(plan)
            metadata: list[tuple[int, bytes, str]] = [
                (0, _mbr(plan), "formatted MBR"),
                (plan.geometry.volume_offset, boot, "primary FAT32 VBR"),
                (
                    plan.geometry.volume_offset + FSINFO_SECTOR * SECTOR_SIZE,
                    fsinfo,
                    "primary FAT32 FSInfo",
                ),
                (
                    plan.geometry.volume_offset + BACKUP_BOOT_SECTOR * SECTOR_SIZE,
                    boot,
                    "backup FAT32 VBR",
                ),
                (
                    plan.geometry.volume_offset
                    + (BACKUP_BOOT_SECTOR + FSINFO_SECTOR) * SECTOR_SIZE,
                    fsinfo,
                    "backup FAT32 FSInfo",
                ),
            ]
            for index in range(FAT_COUNT):
                metadata.append((
                    plan.geometry.volume_offset
                    + (RESERVED_SECTORS + index * plan.geometry.sectors_per_fat)
                    * SECTOR_SIZE,
                    fat,
                    f"FAT32 allocation table {index + 1}",
                ))
            for item in plan.directories:
                metadata.append((
                    _cluster_offset(plan.geometry, item.first_cluster),
                    _directory_content(plan, item),
                    f"directory {item.source.path!r}",
                ))
            for offset, data, label in metadata:
                _check_cancelled(cancel_check)
                self._write_exact(descriptor, data, offset, label)

            source_root_fd = _open_source_root(plan.source_root, plan.directories[0].source)
            directory_map = {item.source.parts: item.source for item in plan.directories}
            copied = 0
            try:
                allocation_order = sorted(
                    plan.files,
                    key=lambda item: (
                        item.first_cluster == 0,
                        item.first_cluster,
                        tuple(part.casefold() for part in item.source.parts),
                    ),
                )
                for item in allocation_order:
                    _check_cancelled(cancel_check)
                    base = (
                        _cluster_offset(plan.geometry, item.first_cluster)
                        if item.cluster_count else 0
                    )
                    observed = _consume_source_file(
                        source_root_fd,
                        directory_map,
                        item.source,
                        lambda block, relative, start=base: self._write_exact(
                            descriptor,
                            block,
                            start + relative,
                            f"file {item.source.path!r}",
                        ),
                        cancel_check=cancel_check,
                    )
                    if not hmac.compare_digest(observed, item.sha256):
                        raise PrivateFat32Error(
                            f"Staged file content changed while copying: {item.source.path!r}",
                        )
                    copied += item.source.size
                    progress("Copying", item.source.path, copied, plan.total_content_bytes)
            finally:
                os.close(source_root_fd)
            rescanned_root, rescanned_directories, rescanned_files = scan_staging_tree(
                plan.source_root,
            )
            if (
                os.fspath(rescanned_root) != plan.source_root
                or rescanned_directories != tuple(item.source for item in plan.directories)
                or rescanned_files != tuple(item.source for item in plan.files)
            ):
                raise PrivateFat32Error("The staging tree changed during image population")
            self._sync_exact(descriptor)
            for offset, data, label in metadata:
                if not hmac.compare_digest(
                    _read_exact(descriptor, offset, len(data), label),
                    data,
                ):
                    raise PrivateFat32Error(f"The {label} failed exact read-back")
            written_extents = [(offset, len(data)) for offset, data, _label in metadata]
            written_extents.extend(
                (
                    _cluster_offset(plan.geometry, item.first_cluster),
                    item.source.size,
                )
                for item in plan.files
                if item.source.size
            )
            _verify_zero_unwritten_extents(
                descriptor,
                plan.geometry.image_size,
                written_extents,
                cancel_check,
            )
            try:
                inspection = inspect_regular_fat32_image(
                    descriptor,
                    cancel_check=cancel_check,
                )
            except FatImageError as error:
                raise PrivateFat32Error(str(error)) from error
            expected_entries = _expected_entries(plan)
            if (
                inspection.entries != expected_entries
                or inspection.content_bytes != plan.total_content_bytes
                or inspection.filesystem_offset != plan.geometry.volume_offset
                or inspection.filesystem_size != plan.geometry.volume_size
                or inspection.disk_signature != plan.disk_signature
                or inspection.volume_id != plan.volume_id
                or inspection.sectors_per_cluster != plan.geometry.sectors_per_cluster
                or inspection.allocated_clusters != plan.allocated_clusters
                or inspection.free_clusters
                != plan.geometry.cluster_count - plan.allocated_clusters
            ):
                raise PrivateFat32Error("The independent FAT32 tree attestation disagrees")
            before_hash = _private_status(descriptor, plan.geometry.image_size)
            image_sha256 = _image_digest(
                descriptor,
                plan.geometry.image_size,
                cancel_check,
            )
            after_hash = _private_status(descriptor, plan.geometry.image_size)
            if _source_identity(before_hash) != _source_identity(after_hash):
                raise PrivateFat32Error("The anonymous FAT32 image changed during final hashing")
            result = PrivateFat32Result(
                plan.plan_sha256,
                image_sha256,
                inspection.manifest_sha256,
                len(plan.files),
                len(plan.directories) - 1,
                plan.total_content_bytes,
                plan.allocated_clusters,
                plan.geometry.cluster_count - plan.allocated_clusters,
            )
            image = AnonymousFat32Image(
                descriptor,
                plan,
                result,
                inspection,
                _IMAGE_WITNESS,
            )
            descriptor = -1
            try:
                progress(
                    "Complete", "", plan.total_content_bytes, plan.total_content_bytes,
                )
            except Exception:
                pass
            return image
        except PrivateFat32Cancelled:
            raise
        except BaseException as error:
            if isinstance(error, PrivateFat32Error):
                raise
            if isinstance(error, OSError):
                raise PrivateFat32Error(
                    _bounded(error, "Private FAT32 image construction failed"),
                ) from error
            raise
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if workspace_fd >= 0:
                os.close(workspace_fd)


def patch_private_fat32_syslinux(
    image: AnonymousFat32Image,
    bundle: BoundBootBundle,
    *,
    config_directory: str,
    expected_unpatched: bytes,
    cancel_check: CancelCheck | None = None,
    transaction: SyslinuxRegularFileTransaction | None = None,
) -> SyslinuxRegularFileTransactionResult:
    """Patch and re-attest one builder-owned image without exposing its fd."""

    from .syslinux_transaction import (
        SyslinuxRegularFileTransaction,
        SyslinuxRegularFileTransactionResult,
        SyslinuxWriteKind,
        build_syslinux_regular_file_transaction_plan,
    )

    if (
        type(image) is not AnonymousFat32Image
        or image.plan.profile is not PrivateFat32BuildProfile.SYSLINUX
    ):
        raise PrivateFat32Error("One unpatched builder-owned FAT32 image is required")
    descriptor = image._begin_patch()
    try:
        if (
            type(expected_unpatched) is not bytes
            or len(expected_unpatched) != image.plan.root_ldlinux_size
            or not hmac.compare_digest(
                hashlib.sha256(expected_unpatched).hexdigest(),
                image.plan.root_ldlinux_sha256,
            )
        ):
            raise PrivateFat32Error(
                "The Syslinux transaction does not match the staged root loader",
            )
        _check_cancelled(cancel_check)
        transaction_plan = build_syslinux_regular_file_transaction_plan(
            bundle,
            descriptor,
            volume_offset=image.plan.geometry.volume_offset,
            volume_size=image.plan.geometry.volume_size,
            config_directory=config_directory,
            expected_unpatched=expected_unpatched,
            cancel_check=cancel_check,
        )
        if not hmac.compare_digest(
            transaction_plan.source_image_sha256,
            image.result.image_sha256,
        ):
            raise PrivateFat32Error(
                "The Syslinux transaction source hash does not match the built image",
            )
        executor = transaction or SyslinuxRegularFileTransaction()
        result = executor.execute(
            transaction_plan,
            bundle,
            descriptor,
            cancel_check=cancel_check,
        )
        if type(result) is not SyslinuxRegularFileTransactionResult:
            raise PrivateFat32Error("The Syslinux transaction returned an invalid result")
        _check_cancelled(cancel_check)
        os.fsync(descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            final_inspection = inspect_regular_fat32_image(
                descriptor,
                cancel_check=cancel_check,
            )
        except FatImageError as error:
            raise PrivateFat32Error(str(error)) from error
        expected_entries = tuple(
            FatImageEntry(
                entry.path,
                entry.size,
                entry.is_directory,
                entry.first_cluster,
                entry.clusters,
                (
                    transaction_plan.patched_sha256
                    if entry.path.casefold() == "ldlinux.sys"
                    else entry.sha256
                ),
            )
            for entry in image.inspection.entries
        )
        before_final_hash = _private_status(
            descriptor,
            image.plan.geometry.image_size,
        )
        final_image_sha256 = _image_digest(
            descriptor,
            image.plan.geometry.image_size,
            cancel_check,
        )
        after_final_hash = _private_status(
            descriptor,
            image.plan.geometry.image_size,
        )
        live_identity = _source_identity(after_final_hash)
        reported_identity = (
            result.final_identity.device,
            result.final_identity.inode,
            result.final_identity.size,
            result.final_identity.modified_ns,
            result.final_identity.changed_ns,
        )
        inspected_identity = (
            final_inspection.source_identity.device,
            final_inspection.source_identity.inode,
            final_inspection.source_identity.size,
            final_inspection.source_identity.modified_ns,
            final_inspection.source_identity.changed_ns,
        )
        primary_vbr = next(
            item.after
            for item in transaction_plan.writes
            if item.kind is SyslinuxWriteKind.PRIMARY_VBR
        )
        patched_mbr = next(
            item.after
            for item in transaction_plan.writes
            if item.kind is SyslinuxWriteKind.MBR
        )
        if (
            final_inspection.entries != expected_entries
            or final_inspection.disk_signature != image.plan.disk_signature
            or final_inspection.volume_id != image.plan.volume_id
            or image._state is not PrivateFat32State.PATCHING
            or image._descriptor != descriptor
            or result.plan_sha256 != transaction_plan.plan_sha256
            or result.patched_ldlinux_sha256 != transaction_plan.patched_sha256
            or result.patched_vbr_sha256 != hashlib.sha256(primary_vbr).hexdigest()
            or result.patched_mbr_sha256 != hashlib.sha256(patched_mbr).hexdigest()
            or result.sectors != transaction_plan.sectors
            or result.bytes_written
            != sum(len(item.after) for item in transaction_plan.writes)
            or result.writes_verified != len(transaction_plan.writes)
            or not hmac.compare_digest(
                result.final_image_sha256,
                transaction_plan.expected_image_sha256,
            )
            or not hmac.compare_digest(
                final_image_sha256,
                transaction_plan.expected_image_sha256,
            )
            or _source_identity(before_final_hash) != live_identity
            or reported_identity != live_identity
            or inspected_identity != live_identity
        ):
            raise PrivateFat32Error("The patched FAT32 image failed final tree attestation")
        image._inspection = final_inspection
        image._transaction_result = result
        image._patched_image_sha256 = final_image_sha256
        image._state = PrivateFat32State.PATCHED_ATTESTED
        return result
    except BaseException as error:
        image._poison()
        if isinstance(error, PrivateFat32Error):
            raise
        raise PrivateFat32Error(
            f"The private Syslinux image was discarded: {_bounded(error, 'unknown failure')}",
        ) from error
    finally:
        image._end_patch()
