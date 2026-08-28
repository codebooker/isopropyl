from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Deterministic, mount-free FAT32 construction on a private ``O_TMPFILE``.

The builder accepts one descriptor-bound staging tree, creates one anonymous
regular file through a bound workspace directory, preallocates its complete
logical size, and writes the MBR, FAT32 metadata, directories, and file bytes
without a loop device, mount, or subprocess.  A separate read-only FAT parser
then hashes every resulting file before the opaque image can be handed to the
Syslinux transaction in this module.
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
from .bootloaders import BoundBootBundle
from .syslinux_transaction import (
    MAX_SYSLINUX_REGULAR_IMAGE_BYTES,
    SyslinuxRegularFileTransaction,
    SyslinuxRegularFileTransactionResult,
    SyslinuxWriteKind,
    build_syslinux_regular_file_transaction_plan,
)


SECTOR_SIZE = 512
PARTITION_START_SECTOR = 2_048
RESERVED_SECTORS = 32
FAT_COUNT = 2
FSINFO_SECTOR = 1
BACKUP_BOOT_SECTOR = 6
VOLUME_LABEL = b"ISOPROPYL  "
COPY_BLOCK_BYTES = 4 * 1024 * 1024
_MEDIA_ID_PROFILE = "io.github.codebooker.isopropyl/private-fat32/media-id/v1"
_FORBIDDEN_MEDIA_IDS = frozenset({0, 0xFFFFFFFF})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PLAN_WITNESS = object()
_IMAGE_WITNESS = object()
_SHORT_ALLOWED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$%'-_@~`!(){}^#&"
)
_DIR_FLAGS = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


class PrivateFat32Error(RuntimeError):
    """A private FAT32 image could not be built or attested safely."""


class PrivateFat32Cancelled(PrivateFat32Error):
    """Private image construction was cancelled and its file was discarded."""


class PrivateFat32State(str, Enum):
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
class PrivateFat32Geometry:
    image_size: int
    volume_offset: int
    volume_size: int
    partition_sectors: int
    sectors_per_cluster: int
    sectors_per_fat: int
    data_start_sector: int
    cluster_count: int

    @property
    def cluster_bytes(self) -> int:
        return self.sectors_per_cluster * SECTOR_SIZE


@dataclass(frozen=True)
class PrivateFat32Directory:
    source: StagedDirectory
    short_name: bytes
    case_flags: int
    long_name: bool
    first_cluster: int
    cluster_count: int


@dataclass(frozen=True)
class PrivateFat32File:
    source: StagedFile
    sha256: str
    short_name: bytes
    case_flags: int
    long_name: bool
    first_cluster: int
    cluster_count: int


@dataclass(frozen=True)
class PrivateFat32Plan:
    source_root: str
    workspace: str
    workspace_identity: PrivateWorkspaceIdentity
    geometry: PrivateFat32Geometry
    directories: tuple[PrivateFat32Directory, ...]
    files: tuple[PrivateFat32File, ...]
    root_ldlinux_size: int
    root_ldlinux_sha256: str
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


def _geometry(image_size: int) -> PrivateFat32Geometry:
    if (
        type(image_size) is not int
        or image_size <= PARTITION_START_SECTOR * SECTOR_SIZE
        or image_size > MAX_SYSLINUX_REGULAR_IMAGE_BYTES
        or image_size % SECTOR_SIZE
    ):
        raise PrivateFat32Error("The private FAT32 image size is invalid")
    image_sectors = image_size // SECTOR_SIZE
    partition_sectors = image_sectors - PARTITION_START_SECTOR
    if partition_sectors <= 0 or partition_sectors > 0xFFFFFFFF:
        raise PrivateFat32Error("The private FAT32 partition exceeds MBR bounds")
    if partition_sectors < 532_480:
        sectors_per_cluster = 1
    elif partition_sectors < 16_777_216:
        sectors_per_cluster = 8
    elif partition_sectors < 33_554_432:
        sectors_per_cluster = 16
    elif partition_sectors < 67_108_864:
        sectors_per_cluster = 32
    else:
        sectors_per_cluster = 64
    sectors_per_fat = max(
        1,
        ((partition_sectors - RESERVED_SECTORS) // sectors_per_cluster + 2) * 4
        // SECTOR_SIZE,
    )
    seen: set[int] = set()
    while True:
        data_sectors = partition_sectors - RESERVED_SECTORS - FAT_COUNT * sectors_per_fat
        if data_sectors <= 0:
            raise PrivateFat32Error("The FAT32 metadata consumes the private image")
        cluster_count = data_sectors // sectors_per_cluster
        required = (cluster_count + 2) * 4
        required = (required + SECTOR_SIZE - 1) // SECTOR_SIZE
        if required == sectors_per_fat:
            break
        if required in seen:
            sectors_per_fat = max(sectors_per_fat, required)
            break
        seen.add(sectors_per_fat)
        sectors_per_fat = required
    data_start = RESERVED_SECTORS + FAT_COUNT * sectors_per_fat
    cluster_count = (partition_sectors - data_start) // sectors_per_cluster
    if (
        cluster_count < 65_525
        or cluster_count + 2 > 0x0FFFFFF0
        or cluster_count + 2 > sectors_per_fat * SECTOR_SIZE // 4
    ):
        raise PrivateFat32Error("The image does not produce supported FAT32 geometry")
    return PrivateFat32Geometry(
        image_size,
        PARTITION_START_SECTOR * SECTOR_SIZE,
        partition_sectors * SECTOR_SIZE,
        partition_sectors,
        sectors_per_cluster,
        sectors_per_fat,
        data_start,
        cluster_count,
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


def _short_candidate(component: str) -> tuple[bytes, int] | None:
    if component.count(".") > 1 or component.startswith(".") or component.endswith("."):
        return None
    if "." in component:
        base, extension = component.rsplit(".", 1)
    else:
        base, extension = component, ""
    if (
        not 1 <= len(base) <= 8
        or len(extension) > 3
        or not base.isascii()
        or not extension.isascii()
    ):
        return None
    upper_base = base.upper()
    upper_extension = extension.upper()
    if (
        any(character not in _SHORT_ALLOWED for character in upper_base)
        or any(character not in _SHORT_ALLOWED for character in upper_extension)
        or not upper_base.isascii()
        or not upper_extension.isascii()
    ):
        return None
    flags = 0
    if base == upper_base:
        pass
    elif base == base.lower():
        flags |= 0x08
    else:
        return None
    if extension == upper_extension:
        pass
    elif extension == extension.lower():
        flags |= 0x10
    else:
        return None
    return (
        upper_base.encode("ascii").ljust(8, b" ")
        + upper_extension.encode("ascii").ljust(3, b" "),
        flags,
    )


def _decoded_short(short_name: bytes, flags: int) -> str:
    base = short_name[:8].rstrip(b" ").decode("ascii")
    extension = short_name[8:].rstrip(b" ").decode("ascii")
    if flags & 0x08:
        base = base.lower()
    if flags & 0x10:
        extension = extension.lower()
    return base + (("." + extension) if extension else "")


def _assign_aliases(
    directories: tuple[StagedDirectory, ...],
    files: tuple[StagedFile, ...],
) -> dict[tuple[str, ...], tuple[bytes, int, bool]]:
    children: dict[tuple[str, ...], list[tuple[str, ...]]] = {}
    for parts in tuple(item.parts for item in directories[1:]) + tuple(
        item.parts for item in files
    ):
        children.setdefault(parts[:-1], []).append(parts)
    aliases: dict[tuple[str, ...], tuple[bytes, int, bool]] = {}
    for parent in sorted(children, key=lambda value: (len(value), tuple(map(str.casefold, value)))):
        ordered = sorted(children[parent], key=lambda value: (value[-1].casefold(), value[-1]))
        visible = {parts[-1].casefold() for parts in ordered}
        used: set[bytes] = {VOLUME_LABEL} if not parent else set()
        deferred: list[tuple[str, ...]] = []
        for parts in ordered:
            candidate = _short_candidate(parts[-1])
            if candidate is not None and candidate[0] not in used:
                aliases[parts] = (candidate[0], candidate[1], False)
                used.add(candidate[0])
            else:
                deferred.append(parts)
        counter = 1
        for parts in deferred:
            while True:
                base = f"I{counter:07X}".encode("ascii")
                counter += 1
                short_name = base + b" " * 3
                if (
                    short_name not in used
                    and _decoded_short(short_name, 0).casefold() not in visible
                ):
                    break
            aliases[parts] = (short_name, 0, True)
            used.add(short_name)
    return aliases


def _lfn_slots(component: str) -> int:
    units = len(component.encode("utf-16-le")) // 2
    return (units + 12) // 13


def _layout(
    geometry: PrivateFat32Geometry,
    directories: tuple[StagedDirectory, ...],
    files: tuple[StagedFile, ...],
    hashes: tuple[str, ...],
) -> tuple[tuple[PrivateFat32Directory, ...], tuple[PrivateFat32File, ...], int]:
    aliases = _assign_aliases(directories, files)
    children: dict[tuple[str, ...], list[tuple[str, ...]]] = {}
    for parts in tuple(item.parts for item in directories[1:]) + tuple(
        item.parts for item in files
    ):
        children.setdefault(parts[:-1], []).append(parts)
    directory_specs: list[tuple[StagedDirectory, tuple[bytes, int, bool], int]] = []
    for source in directories:
        records = 2 if not source.parts else 3
        for child in children.get(source.parts, ()):
            records += 1 + (_lfn_slots(child[-1]) if aliases[child][2] else 0)
        directory_bytes = records * 32
        if directory_bytes > MAX_DIRECTORY_BYTES:
            raise PrivateFat32Error(f"FAT32 directory is too large: {source.path!r}")
        cluster_count = max(
            1,
            (directory_bytes + geometry.cluster_bytes - 1) // geometry.cluster_bytes,
        )
        directory_specs.append((
            source,
            (b"", 0, False) if not source.parts else aliases[source.parts],
            cluster_count,
        ))
    file_specs = [
        (
            index,
            source,
            digest,
            aliases[source.parts],
            (
                (source.size + geometry.cluster_bytes - 1) // geometry.cluster_bytes
                if source.size else 0
            ),
        )
        for index, (source, digest) in enumerate(zip(files, hashes, strict=True))
    ]
    root_specs = tuple(item for item in file_specs if item[1].parts == ("ldlinux.sys",))
    if len(root_specs) != 1 or root_specs[0][4] <= 0:
        raise PrivateFat32Error("The staging tree has no non-empty root ldlinux.sys")

    next_cluster = 2
    planned_directories_by_parts: dict[tuple[str, ...], PrivateFat32Directory] = {}
    root_source, root_alias, root_count = directory_specs[0]
    planned_directories_by_parts[()] = PrivateFat32Directory(
        root_source,
        root_alias[0],
        root_alias[1],
        root_alias[2],
        next_cluster,
        root_count,
    )
    next_cluster += root_count
    by_index: dict[int, PrivateFat32File] = {}
    root_index, root_file, root_digest, root_file_alias, root_file_count = root_specs[0]
    by_index[root_index] = PrivateFat32File(
        root_file,
        root_digest,
        root_file_alias[0],
        root_file_alias[1],
        root_file_alias[2],
        next_cluster,
        root_file_count,
    )
    next_cluster += root_file_count

    for source, alias, cluster_count in directory_specs[1:]:
        planned_directories_by_parts[source.parts] = PrivateFat32Directory(
            source,
            alias[0],
            alias[1],
            alias[2],
            next_cluster,
            cluster_count,
        )
        next_cluster += cluster_count
    for index, source, digest, alias, cluster_count in sorted(
        (item for item in file_specs if item[0] != root_index),
        key=lambda item: tuple(part.casefold() for part in item[1].parts),
    ):
        by_index[index] = PrivateFat32File(
            source,
            digest,
            alias[0],
            alias[1],
            alias[2],
            next_cluster if cluster_count else 0,
            cluster_count,
        )
        next_cluster += cluster_count
    allocated = next_cluster - 2
    if allocated > geometry.cluster_count:
        raise PrivateFat32Error("The staged tree does not fit in the private FAT32 image")
    planned_directories = tuple(
        planned_directories_by_parts[item.parts] for item in directories
    )
    planned_files = tuple(by_index[index] for index in range(len(files)))
    root_loader = tuple(item for item in planned_files if item.source.parts == ("ldlinux.sys",))
    if (
        len(root_loader) != 1
        or root_loader[0].long_name
        or root_loader[0].short_name != b"LDLINUX SYS"
    ):
        raise PrivateFat32Error("The root ldlinux.sys is not an unaliased FAT short name")
    return planned_directories, planned_files, allocated


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


def _media_identity_seed(
    geometry: PrivateFat32Geometry,
    directories: tuple[PrivateFat32Directory, ...],
    files: tuple[PrivateFat32File, ...],
) -> bytes:
    def common(item: PrivateFat32Directory | PrivateFat32File) -> list[object]:
        return [
            list(item.source.parts),
            list(_dos_timestamp(item.source.modified_ns)),
            item.short_name.hex(),
            item.case_flags,
            item.long_name,
            item.first_cluster,
            item.cluster_count,
        ]

    payload = {
        "profile": _MEDIA_ID_PROFILE,
        "label": VOLUME_LABEL.hex(),
        "geometry": list(geometry.__dict__.values()),
        "directories": [common(item) for item in directories],
        "files": [
            [*common(item), item.source.size, item.sha256]
            for item in files
        ],
    }
    return hashlib.sha256(json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")).digest()


def _derive_media_u32(seed: bytes, domain: bytes, forbidden: frozenset[int]) -> int:
    for counter in range(256):
        digest = hashlib.sha256(domain + counter.to_bytes(2, "little") + seed).digest()
        value = int.from_bytes(digest[:4], "little")
        if value not in forbidden:
            return value
    raise PrivateFat32Error("Could not derive a safe FAT32 media identifier")


def _derive_media_ids(
    geometry: PrivateFat32Geometry,
    directories: tuple[PrivateFat32Directory, ...],
    files: tuple[PrivateFat32File, ...],
) -> tuple[int, int]:
    seed = _media_identity_seed(geometry, directories, files)
    disk_signature = _derive_media_u32(
        seed,
        b"isopropyl-private-fat32-mbr-signature-v1\0",
        _FORBIDDEN_MEDIA_IDS,
    )
    volume_id = _derive_media_u32(
        seed,
        b"isopropyl-private-fat32-volume-id-v1\0",
        _FORBIDDEN_MEDIA_IDS | frozenset({disk_signature}),
    )
    return disk_signature, volume_id


def build_private_fat32_plan(
    staging_root: Path | str,
    workspace: Path | str,
    *,
    image_size: int,
    expected_root_ldlinux: bytes,
    cancel_check: CancelCheck | None = None,
) -> PrivateFat32Plan:
    """Hash and allocate one final staged tree without creating an image."""

    if type(expected_root_ldlinux) is not bytes or not expected_root_ldlinux:
        raise PrivateFat32Error("Exact unpatched root ldlinux.sys bytes are required")
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
    )
    root_files = tuple(item for item in planned_files if item.source.parts == ("ldlinux.sys",))
    expected_digest = hashlib.sha256(expected_root_ldlinux).hexdigest()
    if (
        len(root_files) != 1
        or root_files[0].source.size != len(expected_root_ldlinux)
        or not hmac.compare_digest(root_files[0].sha256, expected_digest)
    ):
        raise PrivateFat32Error("The staged root ldlinux.sys does not match its exact payload")
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
        len(expected_root_ldlinux),
        expected_digest,
        sum(item.source.size for item in planned_files),
        allocated,
        disk_signature,
        volume_id,
        "",
        _PLAN_WITNESS,
    )
    return PrivateFat32Plan(
        **{**candidate.__dict__, "plan_sha256": _plan_digest(candidate)},
    )


def _validate_plan_shape(plan: PrivateFat32Plan) -> None:
    if type(plan) is not PrivateFat32Plan or plan._witness is not _PLAN_WITNESS:
        raise PrivateFat32Error("An authentic private FAT32 plan is required")
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
        or type(plan.root_ldlinux_size) is not int
        or plan.root_ldlinux_size <= 0
        or type(plan.root_ldlinux_sha256) is not str
        or _SHA256.fullmatch(plan.root_ldlinux_sha256) is None
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
    )
    root_files = tuple(item for item in plan.files if item.source.parts == ("ldlinux.sys",))
    if (
        rebuilt_directories != plan.directories
        or rebuilt_files != plan.files
        or rebuilt_allocated != plan.allocated_clusters
        or len(root_files) != 1
        or root_files[0].source.size != plan.root_ldlinux_size
        or not hmac.compare_digest(root_files[0].sha256, plan.root_ldlinux_sha256)
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


def _dos_timestamp(modified_ns: int) -> tuple[int, int, int]:
    seconds = modified_ns // 1_000_000_000
    nanoseconds = modified_ns % 1_000_000_000
    value = time.gmtime(seconds)
    date = ((value.tm_year - 1980) << 9) | (value.tm_mon << 5) | value.tm_mday
    clock = (value.tm_hour << 11) | (value.tm_min << 5) | (value.tm_sec // 2)
    tenths = min(199, (value.tm_sec & 1) * 100 + nanoseconds // 10_000_000)
    return date, clock, tenths


def _lfn_checksum(short_name: bytes) -> int:
    checksum = 0
    for byte in short_name:
        checksum = (((checksum & 1) << 7) | (checksum >> 1)) + byte
        checksum &= 0xFF
    return checksum


def _lfn_records(component: str, short_name: bytes) -> tuple[bytes, ...]:
    encoded = component.encode("utf-16-le")
    units = list(struct.unpack(f"<{len(encoded) // 2}H", encoded))
    count = (len(units) + 12) // 13
    checksum = _lfn_checksum(short_name)
    records: list[bytes] = []
    for ordinal in range(count, 0, -1):
        chunk = units[(ordinal - 1) * 13:ordinal * 13]
        if ordinal == count and len(chunk) < 13:
            chunk.append(0)
            chunk.extend([0xFFFF] * (13 - len(chunk)))
        raw = bytearray(32)
        raw[0] = ordinal | (0x40 if ordinal == count else 0)
        raw[11] = 0x0F
        raw[13] = checksum
        name_bytes = struct.pack("<13H", *chunk)
        raw[1:11] = name_bytes[:10]
        raw[14:26] = name_bytes[10:22]
        raw[28:32] = name_bytes[22:]
        records.append(bytes(raw))
    return tuple(records)


def _short_record(
    short_name: bytes,
    case_flags: int,
    attributes: int,
    first_cluster: int,
    size: int,
    modified_ns: int,
) -> bytes:
    raw = bytearray(32)
    raw[:11] = short_name
    raw[11] = attributes
    raw[12] = case_flags
    date, clock, tenths = _dos_timestamp(modified_ns)
    raw[13] = tenths
    struct.pack_into("<H", raw, 14, clock)
    struct.pack_into("<H", raw, 16, date)
    struct.pack_into("<H", raw, 18, date)
    struct.pack_into("<H", raw, 20, (first_cluster >> 16) & 0xFFFF)
    struct.pack_into("<H", raw, 22, clock)
    struct.pack_into("<H", raw, 24, date)
    struct.pack_into("<H", raw, 26, first_cluster & 0xFFFF)
    struct.pack_into("<I", raw, 28, size)
    return bytes(raw)


def _directory_content(
    plan: PrivateFat32Plan,
    directory: PrivateFat32Directory,
) -> bytes:
    directory_map = {item.source.parts: item for item in plan.directories}
    child_directories = {
        item.source.parts: item
        for item in plan.directories[1:]
        if item.source.parts[:-1] == directory.source.parts
    }
    child_files = {
        item.source.parts: item
        for item in plan.files
        if item.source.parts[:-1] == directory.source.parts
    }
    records: list[bytes] = []
    if not directory.source.parts:
        records.append(_short_record(
            VOLUME_LABEL,
            0,
            0x08,
            0,
            0,
            directory.source.modified_ns,
        ))
    else:
        parent = directory_map[directory.source.parts[:-1]]
        records.extend((
            _short_record(
                b".          ", 0, 0x10, directory.first_cluster, 0,
                directory.source.modified_ns,
            ),
            _short_record(
                b"..         ", 0, 0x10,
                0 if not parent.source.parts else parent.first_cluster, 0,
                parent.source.modified_ns,
            ),
        ))
    children: list[PrivateFat32Directory | PrivateFat32File] = [
        *child_directories.values(), *child_files.values(),
    ]
    children.sort(key=lambda item: (item.source.parts[-1].casefold(), item.source.parts[-1]))
    for item in children:
        if item.long_name:
            records.extend(_lfn_records(item.source.parts[-1], item.short_name))
        is_directory = type(item) is PrivateFat32Directory
        attributes = 0x10 if is_directory else 0x20
        if item.source.parts == ("ldlinux.sys",):
            attributes = 0x07
        records.append(_short_record(
            item.short_name,
            item.case_flags,
            attributes,
            item.first_cluster,
            0 if is_directory else item.source.size,
            item.source.modified_ns,
        ))
    records.append(b"\0" * 32)
    result = b"".join(records)
    capacity = directory.cluster_count * plan.geometry.cluster_bytes
    if len(result) > capacity:
        raise PrivateFat32Error("A planned FAT32 directory exceeds its cluster chain")
    return result.ljust(capacity, b"\0")


def _mbr(plan: PrivateFat32Plan) -> bytes:
    result = bytearray(SECTOR_SIZE)
    struct.pack_into("<I", result, 440, plan.disk_signature)
    entry = bytearray(16)
    entry[0] = 0x80
    entry[1:4] = b"\x20\x21\x00"
    entry[4] = 0x0C
    entry[5:8] = b"\xfe\xff\xff"
    struct.pack_into("<I", entry, 8, PARTITION_START_SECTOR)
    struct.pack_into("<I", entry, 12, plan.geometry.partition_sectors)
    result[446:462] = entry
    result[510:512] = b"\x55\xaa"
    return bytes(result)


def _boot_sector(plan: PrivateFat32Plan) -> bytes:
    geometry = plan.geometry
    result = bytearray(SECTOR_SIZE)
    result[:3] = b"\xeb\x58\x90"
    result[3:11] = b"ISOPROPY"
    struct.pack_into("<H", result, 11, SECTOR_SIZE)
    result[13] = geometry.sectors_per_cluster
    struct.pack_into("<H", result, 14, RESERVED_SECTORS)
    result[16] = FAT_COUNT
    result[21] = 0xF8
    struct.pack_into("<H", result, 24, 63)
    struct.pack_into("<H", result, 26, 255)
    struct.pack_into("<I", result, 28, PARTITION_START_SECTOR)
    struct.pack_into("<I", result, 32, geometry.partition_sectors)
    struct.pack_into("<I", result, 36, geometry.sectors_per_fat)
    struct.pack_into("<I", result, 44, 2)
    struct.pack_into("<H", result, 48, FSINFO_SECTOR)
    struct.pack_into("<H", result, 50, BACKUP_BOOT_SECTOR)
    result[64] = 0x80
    result[66] = 0x29
    struct.pack_into("<I", result, 67, plan.volume_id)
    result[71:82] = VOLUME_LABEL
    result[82:90] = b"FAT32   "
    result[510:512] = b"\x55\xaa"
    return bytes(result)


def _fsinfo(plan: PrivateFat32Plan) -> bytes:
    result = bytearray(SECTOR_SIZE)
    free_clusters = plan.geometry.cluster_count - plan.allocated_clusters
    next_free = 2 + plan.allocated_clusters if free_clusters else 0xFFFFFFFF
    struct.pack_into("<I", result, 0, 0x41615252)
    struct.pack_into("<I", result, 484, 0x61417272)
    struct.pack_into("<I", result, 488, free_clusters)
    struct.pack_into("<I", result, 492, next_free)
    struct.pack_into("<I", result, 508, 0xAA550000)
    return bytes(result)


def _fat(plan: PrivateFat32Plan) -> bytes:
    result = bytearray(plan.geometry.sectors_per_fat * SECTOR_SIZE)
    struct.pack_into("<I", result, 0, 0x0FFFFFF8)
    struct.pack_into("<I", result, 4, 0x0FFFFFFF)
    for item in (*plan.directories, *plan.files):
        if item.cluster_count == 0:
            continue
        for index in range(item.cluster_count):
            cluster = item.first_cluster + index
            following = (
                cluster + 1 if index + 1 < item.cluster_count else 0x0FFFFFFF
            )
            struct.pack_into("<I", result, cluster * 4, following)
    return bytes(result)


def _cluster_offset(geometry: PrivateFat32Geometry, first_cluster: int) -> int:
    return geometry.volume_offset + (
        geometry.data_start_sector
        + (first_cluster - 2) * geometry.sectors_per_cluster
    ) * SECTOR_SIZE


def _expected_entries(plan: PrivateFat32Plan) -> tuple[FatImageEntry, ...]:
    values: list[FatImageEntry] = []
    for item in plan.directories[1:]:
        values.append(FatImageEntry(
            item.source.path,
            0,
            True,
            item.first_cluster,
            tuple(range(item.first_cluster, item.first_cluster + item.cluster_count)),
            "",
        ))
    for item in plan.files:
        values.append(FatImageEntry(
            item.source.path,
            item.source.size,
            False,
            item.first_cluster,
            tuple(range(item.first_cluster, item.first_cluster + item.cluster_count)),
            item.sha256,
        ))
    return tuple(sorted(values, key=lambda entry: (
        tuple(part.casefold() for part in PurePosixPath(entry.path).parts),
        not entry.is_directory,
    )))


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
        "_transaction_result", "_witness",
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
        self._state = PrivateFat32State.UNPATCHED_ATTESTED
        self._transaction_result: SyslinuxRegularFileTransactionResult | None = None
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

    def _begin_patch(self) -> int:
        self._lifecycle.acquire()
        try:
            if (
                self._witness is not _IMAGE_WITNESS
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
        """Yield bounded image bytes only after the Syslinux attestation."""

        if type(chunk_bytes) is not int or not 1 <= chunk_bytes <= COPY_BLOCK_BYTES:
            raise PrivateFat32Error("The private image chunk size is invalid")

        def iterate() -> Iterator[bytes]:
            with self._lifecycle:
                if self._state is not PrivateFat32State.PATCHED_ATTESTED:
                    raise PrivateFat32Error(
                        "Only a patched, attested image can be streamed",
                    )
                descriptor = os.dup(self._owned_descriptor())
                image_size = self._plan.geometry.image_size
                try:
                    before_stream = _private_status(descriptor, image_size)
                    stream_sha256 = _image_digest(descriptor, image_size)
                    after_stream = _private_status(descriptor, image_size)
                    transaction_result = self._transaction_result
                    if (
                        transaction_result is None
                        or _source_identity(before_stream)
                        != _source_identity(after_stream)
                        or _source_identity(after_stream)
                        != (
                            transaction_result.final_identity.device,
                            transaction_result.final_identity.inode,
                            transaction_result.final_identity.size,
                            transaction_result.final_identity.modified_ns,
                            transaction_result.final_identity.changed_ns,
                        )
                        or not hmac.compare_digest(
                            stream_sha256,
                            transaction_result.final_image_sha256,
                        )
                    ):
                        self._poison()
                        raise PrivateFat32Error(
                            "The patched FAT32 image changed before streaming",
                        )
                except BaseException:
                    os.close(descriptor)
                    raise
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
        preallocate: Callable[[int, int, int], None] = os.posix_fallocate,
    ) -> None:
        self._write_at = write_at
        self._sync = sync
        self._preallocate = preallocate
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
                allocation_order = sorted(plan.files, key=lambda item: (
                    item.source.parts != ("ldlinux.sys",),
                    tuple(part.casefold() for part in item.source.parts),
                ))
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

    if type(image) is not AnonymousFat32Image:
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
