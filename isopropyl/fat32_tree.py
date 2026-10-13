"""Shared FAT32 tree allocation and serialization, without host disk APIs."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations
import hashlib
import json
import struct
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from .tree_records import StagedDirectory,StagedFile
from .fat32_layout import PrivateFat32Geometry,PrivateFat32Error,VOLUME_LABEL
from .fat_image import FatImageEntry,MAX_DIRECTORY_BYTES
_SHORT_ALLOWED=frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$%'-_@~`!(){}^#&")
_MEDIA_ID_PROFILE="io.github.codebooker.isopropyl/private-fat32/media-id/v1"
_FORBIDDEN_MEDIA_IDS=frozenset({0,0xFFFFFFFF})
class PrivateFat32BuildProfile(str, Enum):
    """Allocation and consumption contract layered over the FAT32 engine."""

    GENERIC = "generic-v1"
    SYSLINUX = "syslinux-v1"
    WINDOWS_BOOTMGR = "windows-bootmgr-v1"
    GRUB_RESCUE = "grub-rescue-v1"


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
    *,
    priority_file: tuple[str, ...] | None,
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
    priority_specs = tuple(
        item for item in file_specs if item[1].parts == priority_file
    ) if priority_file is not None else ()
    if priority_file is not None and (
        len(priority_specs) != 1 or priority_specs[0][4] <= 0
    ):
        raise PrivateFat32Error("The staging tree lacks its required priority file")

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
    priority_index: int | None = None
    if priority_specs:
        (
            priority_index,
            priority_source,
            priority_digest,
            priority_alias,
            priority_count,
        ) = priority_specs[0]
        by_index[priority_index] = PrivateFat32File(
            priority_source,
            priority_digest,
            priority_alias[0],
            priority_alias[1],
            priority_alias[2],
            next_cluster,
            priority_count,
        )
        next_cluster += priority_count

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
        (item for item in file_specs if item[0] != priority_index),
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
    if priority_file is not None:
        priority = tuple(
            item for item in planned_files if item.source.parts == priority_file
        )
        if (
            len(priority) != 1
            or priority[0].long_name
            or priority[0].short_name != b"LDLINUX SYS"
        ):
            raise PrivateFat32Error(
                "The root ldlinux.sys is not an unaliased FAT short name",
            )
    return planned_directories, planned_files, allocated


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
            getattr(plan,'volume_label',VOLUME_LABEL),
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
        if (
            plan.profile is PrivateFat32BuildProfile.SYSLINUX
            and item.source.parts == ("ldlinux.sys",)
        ):
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


