from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bounded, read-only FAT images embedded in UEFI El Torito entries.

The parser deliberately supports only the narrow layouts needed by the Rufus
4.14 compatibility path: a direct FAT12/16/32 volume, or one active first FAT
partition in an otherwise empty MBR.  Every byte is read through an already
opened regular-file descriptor and every derived extent is bounded by the ISO
and the next El Torito image.
"""

import enum
import hashlib
import json
import os
import re
import stat
import struct
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .eltorito import (
    BootEntry,
    BootPlatform,
    ElToritoInspection,
    EmulationType,
)

MAX_FILESYSTEM_BYTES = 512 * 1024**2
MAX_REGULAR_FAT32_BYTES = 128 * 1024**3
MAX_FAT_BYTES = 32 * 1024**2
MAX_DIRECTORY_BYTES = 8 * 1024**2
MAX_ENTRIES = 16_384
MAX_DIRECTORIES = 1_024
MAX_DEPTH = 32
MAX_PATH_UTF8_BYTES = 4_096
MAX_COMPONENT_UTF16_UNITS = 255
MAX_READ_FILE_BYTES = 256 * 1024**2
MAX_EMBEDDED_IMAGES = 8
FAT_PARTITION_TYPES = frozenset({0x01, 0x04, 0x06, 0x0B, 0x0C, 0x0E})
_FALLBACK_LOADER = re.compile(
    r"boot(?:ia32|x64|arm|aa64|ia64|riscv64|loongarch64|ebc)\.efi",
    re.IGNORECASE,
)
_FORBIDDEN_COMPONENT = frozenset('<>:"/\\|?*')
_WINDOWS_DEVICE = re.compile(
    r"^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])(?:\..*)?$",
    re.IGNORECASE,
)


class FatImageError(ValueError):
    """The embedded image cannot be interpreted without ambiguity."""


class FatType(str, enum.Enum):
    FAT12 = "FAT12"
    FAT16 = "FAT16"
    FAT32 = "FAT32"


@dataclass(frozen=True)
class FatSourceIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class FatImageEntry:
    path: str
    size: int
    is_directory: bool
    first_cluster: int
    clusters: tuple[int, ...]
    sha256: str


@dataclass(frozen=True)
class EmbeddedFatImage:
    source_identity: FatSourceIdentity
    boot_entry: BootEntry
    image_offset: int
    image_limit: int
    filesystem_offset: int
    filesystem_size: int
    partition_start_lba: int | None
    partition_sectors: int | None
    fat_type: FatType
    bytes_per_sector: int
    sectors_per_cluster: int
    entries: tuple[FatImageEntry, ...]
    manifest_sha256: str

    @property
    def content_bytes(self) -> int:
        return sum(entry.size for entry in self.entries if not entry.is_directory)

    @property
    def fallback_loaders(self) -> tuple[FatImageEntry, ...]:
        return tuple(
            entry for entry in self.entries
            if (
                not entry.is_directory
                and entry.size > 0
                and len(PurePosixPath(entry.path).parts) == 3
                and PurePosixPath(entry.path).parts[0].casefold() == "efi"
                and PurePosixPath(entry.path).parts[1].casefold() == "boot"
                and _FALLBACK_LOADER.fullmatch(PurePosixPath(entry.path).parts[2])
            )
        )


@dataclass(frozen=True)
class RegularFat32Image:
    """One completely parsed MBR-wrapped FAT32 regular-file image."""

    source_identity: FatSourceIdentity
    image_size: int
    filesystem_offset: int
    filesystem_size: int
    partition_start_lba: int
    partition_sectors: int
    disk_signature: int
    volume_id: int
    bytes_per_sector: int
    sectors_per_cluster: int
    allocated_clusters: int
    free_clusters: int
    entries: tuple[FatImageEntry, ...]
    manifest_sha256: str

    @property
    def content_bytes(self) -> int:
        return sum(entry.size for entry in self.entries if not entry.is_directory)


CancelCheck = Callable[[], None]
MaterializeProgress = Callable[[str, int, int], None]


def _identity(status: os.stat_result) -> FatSourceIdentity:
    return FatSourceIdentity(
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


class _Reader:
    def __init__(self, descriptor: int, size: int) -> None:
        self.descriptor = descriptor
        self.size = size

    def exact(self, offset: int, length: int, label: str) -> bytes:
        if (
            type(offset) is not int
            or type(length) is not int
            or offset < 0
            or length < 0
            or offset > self.size
            or length > self.size - offset
        ):
            raise FatImageError(f"{label} lies outside the selected ISO")
        try:
            value = os.pread(self.descriptor, length, offset)
        except OSError as error:
            raise FatImageError(f"Could not read {label}: {error}") from error
        if len(value) != length:
            raise FatImageError(f"Could not read {label} completely")
        return value


@dataclass(frozen=True)
class _VolumeLayout:
    filesystem_offset: int
    filesystem_size: int
    fat_type: FatType
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    fat_count: int
    sectors_per_fat: int
    root_entry_count: int
    root_cluster: int
    root_directory_offset: int
    root_directory_bytes: int
    data_offset: int
    cluster_count: int
    media_descriptor: int

    @property
    def cluster_bytes(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster


class _FatVolume:
    def __init__(
        self,
        reader: _Reader,
        layout: _VolumeLayout,
        *,
        upper_bound: int,
        cancel_check: CancelCheck | None,
        maximum_content_bytes: int = MAX_FILESYSTEM_BYTES,
        maximum_entries: int = MAX_ENTRIES,
        maximum_directories: int = MAX_DIRECTORIES,
        strict_directories: bool = False,
    ) -> None:
        self.reader = reader
        self.layout = layout
        self.upper_bound = upper_bound
        self.cancel_check = cancel_check
        if type(maximum_content_bytes) is not int or maximum_content_bytes <= 0:
            raise FatImageError("The FAT content limit is invalid")
        self.maximum_content_bytes = maximum_content_bytes
        if type(maximum_entries) is not int or maximum_entries <= 0:
            raise FatImageError("The FAT entry limit is invalid")
        self.maximum_entries = maximum_entries
        if type(maximum_directories) is not int or maximum_directories <= 0:
            raise FatImageError("The FAT directory limit is invalid")
        self.maximum_directories = maximum_directories
        if type(strict_directories) is not bool:
            raise FatImageError("The FAT directory-validation mode is invalid")
        self.strict_directories = strict_directories
        self.volume_labels: list[bytes] = []
        self._claimed_clusters: dict[int, str] = {}
        self._entries: list[FatImageEntry] = []
        self._path_keys: dict[tuple[str, ...], str] = {}
        fat_bytes = layout.sectors_per_fat * layout.bytes_per_sector
        if fat_bytes <= 0 or fat_bytes > MAX_FAT_BYTES:
            raise FatImageError("The embedded FAT allocation table exceeds the limit")
        fat_offset = (
            layout.filesystem_offset
            + layout.reserved_sectors * layout.bytes_per_sector
        )
        self.fat = reader.exact(fat_offset, fat_bytes, "embedded FAT allocation table")
        for copy_index in range(1, layout.fat_count):
            other = reader.exact(
                fat_offset + copy_index * fat_bytes,
                fat_bytes,
                f"embedded FAT allocation-table copy {copy_index + 1}",
            )
            if other != self.fat:
                raise FatImageError("The embedded FAT allocation-table copies disagree")
        self._validate_reserved_fat_entries()

    def _check_cancelled(self) -> None:
        if self.cancel_check is not None:
            self.cancel_check()

    def _fat_value(self, cluster: int) -> int:
        if self.layout.fat_type is FatType.FAT12:
            offset = cluster + cluster // 2
            if offset + 2 > len(self.fat):
                raise FatImageError("A FAT12 cluster entry lies outside the table")
            pair = self.fat[offset] | (self.fat[offset + 1] << 8)
            return (pair >> 4) & 0xFFF if cluster & 1 else pair & 0xFFF
        if self.layout.fat_type is FatType.FAT16:
            offset = cluster * 2
            if offset + 2 > len(self.fat):
                raise FatImageError("A FAT16 cluster entry lies outside the table")
            return struct.unpack_from("<H", self.fat, offset)[0]
        offset = cluster * 4
        if offset + 4 > len(self.fat):
            raise FatImageError("A FAT32 cluster entry lies outside the table")
        return struct.unpack_from("<I", self.fat, offset)[0] & 0x0FFFFFFF

    def _validate_reserved_fat_entries(self) -> None:
        first = self._fat_value(0)
        second = self._fat_value(1)
        if first & 0xFF != self.layout.media_descriptor:
            raise FatImageError("The FAT media descriptor disagrees with its BPB")
        if self.layout.fat_type is FatType.FAT12:
            if first < 0xFF0 or second < 0xFF8:
                raise FatImageError("The FAT12 reserved entries are invalid")
        elif self.layout.fat_type is FatType.FAT16:
            if first < 0xFFF0 or second < 0xFFF8:
                raise FatImageError("The FAT16 reserved entries are invalid")
        elif first < 0x0FFFFFF0 or second < 0x0FFFFFF8:
            raise FatImageError("The FAT32 reserved entries are invalid")

    def _is_eoc(self, value: int) -> bool:
        if self.layout.fat_type is FatType.FAT12:
            return value >= 0xFF8
        if self.layout.fat_type is FatType.FAT16:
            return value >= 0xFFF8
        return value >= 0x0FFFFFF8

    def _is_bad(self, value: int) -> bool:
        if self.layout.fat_type is FatType.FAT12:
            return value == 0xFF7
        if self.layout.fat_type is FatType.FAT16:
            return value == 0xFFF7
        return value == 0x0FFFFFF7

    def _chain(self, first: int, label: str) -> tuple[int, ...]:
        if first < 2 or first >= self.layout.cluster_count + 2:
            raise FatImageError(f"{label} starts at an invalid FAT cluster")
        values: list[int] = []
        local: set[int] = set()
        current = first
        while True:
            self._check_cancelled()
            if current < 2 or current >= self.layout.cluster_count + 2:
                raise FatImageError(f"{label} references a cluster outside the volume")
            if current in local:
                raise FatImageError(f"{label} contains a FAT cluster loop")
            owner = self._claimed_clusters.get(current)
            if owner is not None:
                raise FatImageError(f"{label} cross-links a cluster already used by {owner}")
            local.add(current)
            self._claimed_clusters[current] = label
            values.append(current)
            if len(values) > self.layout.cluster_count:
                raise FatImageError(f"{label} exceeds the FAT cluster limit")
            following = self._fat_value(current)
            if self._is_eoc(following):
                break
            if following in {0, 1} or self._is_bad(following):
                raise FatImageError(f"{label} ends in a free, reserved, or bad cluster")
            current = following
        return tuple(values)

    def _cluster_offset(self, cluster: int) -> int:
        offset = (
            self.layout.data_offset
            + (cluster - 2) * self.layout.cluster_bytes
        )
        if (
            offset < self.layout.filesystem_offset
            or self.layout.cluster_bytes > self.upper_bound - offset
        ):
            raise FatImageError("An embedded FAT cluster lies outside its bounded extent")
        return offset

    def _chain_bytes(self, clusters: Sequence[int], label: str) -> bytes:
        total = len(clusters) * self.layout.cluster_bytes
        if total > MAX_DIRECTORY_BYTES:
            raise FatImageError(f"{label} exceeds the embedded directory-size limit")
        return b"".join(
            self.reader.exact(
                self._cluster_offset(cluster),
                self.layout.cluster_bytes,
                label,
            )
            for cluster in clusters
        )

    def _file_sha256(
        self,
        clusters: Sequence[int],
        size: int,
        label: str,
    ) -> str:
        digest = hashlib.sha256()
        remaining = size
        for cluster in clusters:
            self._check_cancelled()
            take = min(self.layout.cluster_bytes, remaining)
            digest.update(self.reader.exact(
                self._cluster_offset(cluster),
                take,
                f"embedded FAT file {label!r}",
            ))
            remaining -= take
        if remaining != 0:
            raise FatImageError(f"Embedded FAT file {label!r} is truncated")
        return digest.hexdigest()

    @staticmethod
    def _lfn_checksum(short_name: bytes) -> int:
        checksum = 0
        for byte in short_name:
            checksum = (((checksum & 1) << 7) | (checksum >> 1)) + byte
            checksum &= 0xFF
        return checksum

    @staticmethod
    def _lfn_units(raw: bytes) -> tuple[int, ...]:
        value = raw[1:11] + raw[14:26] + raw[28:32]
        return struct.unpack("<13H", value)

    @staticmethod
    def _decode_short(raw: bytes) -> str:
        name = bytearray(raw[:11])
        if name[0] == 0x05:
            name[0] = 0xE5
        if any(byte >= 0x7F or (byte < 0x20 and byte != 0x20) for byte in name):
            raise FatImageError("A FAT short name is not portable ASCII")
        base_raw = bytes(name[:8]).rstrip(b" ")
        extension_raw = bytes(name[8:]).rstrip(b" ")
        if not base_raw or b" " in base_raw or b" " in extension_raw:
            raise FatImageError("A FAT short name has invalid padding")
        base = base_raw.decode("ascii")
        extension = extension_raw.decode("ascii")
        flags = raw[12]
        if flags & ~0x18:
            raise FatImageError("A FAT short name has unsupported case flags")
        if flags & 0x08:
            base = base.lower()
        if flags & 0x10:
            extension = extension.lower()
        return base + (("." + extension) if extension else "")

    @staticmethod
    def _decode_lfn(
        chunks: dict[int, tuple[int, ...]],
        count: int,
    ) -> str:
        units = [unit for index in range(1, count + 1) for unit in chunks[index]]
        try:
            terminator = units.index(0)
        except ValueError:
            terminator = len(units)
        tail = units[terminator + 1:] if terminator < len(units) else ()
        if any(unit not in {0, 0xFFFF} for unit in tail):
            raise FatImageError("A FAT long name has invalid terminator padding")
        useful = units[:terminator]
        if (
            not useful
            or any(unit == 0xFFFF or 0xD800 <= unit <= 0xDFFF for unit in useful)
        ):
            raise FatImageError("A FAT long name is empty or malformed")
        try:
            encoded = b"".join(struct.pack("<H", unit) for unit in useful)
            return encoded.decode("utf-16-le", errors="strict")
        except (UnicodeDecodeError, struct.error) as error:
            raise FatImageError("A FAT long name is not valid UTF-16") from error

    @staticmethod
    def _safe_component(value: str) -> str:
        normalized = unicodedata.normalize("NFC", value)
        if (
            not normalized
            or normalized in {".", ".."}
            or normalized.endswith((" ", "."))
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized)
            or any(character in _FORBIDDEN_COMPONENT for character in normalized)
            or _WINDOWS_DEVICE.fullmatch(normalized)
            or len(normalized.encode("utf-16-le")) // 2 > MAX_COMPONENT_UTF16_UNITS
        ):
            raise FatImageError(f"Unsafe embedded FAT path component: {value!r}")
        return normalized

    def _record_path(self, parts: tuple[str, ...], rendered: str) -> None:
        if len(rendered.encode("utf-8")) > MAX_PATH_UTF8_BYTES:
            raise FatImageError("An embedded FAT path exceeds the portable length limit")
        key = tuple(unicodedata.normalize("NFC", part).casefold() for part in parts)
        previous = self._path_keys.get(key)
        if previous is not None:
            raise FatImageError(
                f"Embedded FAT paths collide case-insensitively: {previous!r} and {rendered!r}"
            )
        self._path_keys[key] = rendered

    def _parse_directory(
        self,
        raw_directory: bytes,
        parent: tuple[str, ...],
        depth: int,
        self_cluster: int,
        parent_cluster: int,
    ) -> None:
        if depth > MAX_DEPTH:
            raise FatImageError("The embedded FAT directory depth exceeds the limit")
        lfn_chunks: dict[int, tuple[int, ...]] = {}
        lfn_count = 0
        lfn_expected = 0
        lfn_checksum: int | None = None
        local_aliases: dict[str, str] = {}
        local_short_names: dict[bytes, str] = {}
        saw_dot = False
        saw_dotdot = False
        saw_terminator = False
        for offset in range(0, len(raw_directory), 32):
            self._check_cancelled()
            raw = raw_directory[offset:offset + 32]
            if len(raw) != 32:
                raise FatImageError("An embedded FAT directory is not entry-aligned")
            if raw[0] == 0x00:
                if lfn_chunks:
                    raise FatImageError("An embedded FAT directory ends with an orphan long name")
                if self.strict_directories and any(raw_directory[offset:]):
                    raise FatImageError("A FAT directory has nonzero data after its terminator")
                saw_terminator = True
                break
            if raw[0] == 0xE5:
                lfn_chunks.clear()
                lfn_count = lfn_expected = 0
                lfn_checksum = None
                continue
            attributes = raw[11]
            if attributes == 0x0F:
                ordinal_raw = raw[0]
                ordinal = ordinal_raw & 0x1F
                is_last = bool(ordinal_raw & 0x40)
                if (
                    ordinal_raw & 0xA0
                    or ordinal == 0
                    or ordinal > 20
                    or raw[12] != 0
                    or raw[26:28] != b"\0\0"
                ):
                    raise FatImageError("An embedded FAT long-name entry is malformed")
                if is_last:
                    if lfn_chunks:
                        raise FatImageError("Nested FAT long-name sequences are invalid")
                    lfn_count = ordinal
                    lfn_expected = ordinal
                    lfn_checksum = raw[13]
                if not lfn_chunks and not is_last:
                    raise FatImageError("A FAT long-name sequence has no final marker")
                if ordinal != lfn_expected or raw[13] != lfn_checksum:
                    raise FatImageError("A FAT long-name sequence is out of order")
                lfn_chunks[ordinal] = self._lfn_units(raw)
                lfn_expected -= 1
                continue
            if attributes & 0xC0:
                raise FatImageError("An embedded FAT directory entry uses reserved attributes")
            short_name = bytes(raw[:11])
            short = self._decode_short(raw)
            if short in {".", ".."}:
                high_cluster = struct.unpack_from("<H", raw, 20)[0]
                low_cluster = struct.unpack_from("<H", raw, 26)[0]
                cluster = (high_cluster << 16) | low_cluster
                expected_cluster = self_cluster if short == "." else parent_cluster
                expected_offset = 0 if short == "." else 32
                if (
                    lfn_chunks
                    or attributes != 0x10
                    or raw[:11] != (b".          " if short == "." else b"..         ")
                    or struct.unpack_from("<I", raw, 28)[0] != 0
                    or (
                        self.strict_directories
                        and (
                            not parent
                            or offset != expected_offset
                            or cluster != expected_cluster
                        )
                    )
                ):
                    raise FatImageError("A FAT dot entry is malformed")
                saw_dot = saw_dot or short == "."
                saw_dotdot = saw_dotdot or short == ".."
                continue
            had_lfn = bool(lfn_chunks)
            if lfn_chunks:
                if lfn_expected != 0 or self._lfn_checksum(short_name) != lfn_checksum:
                    raise FatImageError("A FAT long name does not match its short entry")
                visible = self._decode_lfn(lfn_chunks, lfn_count)
            else:
                visible = short
            lfn_chunks.clear()
            lfn_count = lfn_expected = 0
            lfn_checksum = None
            short_key = short_name.upper()
            previous_short = local_short_names.get(short_key)
            if previous_short is not None:
                raise FatImageError(
                    f"Embedded FAT short names alias each other: "
                    f"{previous_short!r} and {visible!r}"
                )
            local_short_names[short_key] = visible
            if attributes & 0x08:
                if attributes & 0x10:
                    raise FatImageError("A FAT volume label is also marked as a directory")
                if (
                    self.strict_directories
                    and (
                        parent
                        or had_lfn
                        or attributes != 0x08
                        or raw[12] != 0
                        or raw[20:22] != b"\0\0"
                        or raw[26:32] != b"\0" * 6
                    )
                ):
                    raise FatImageError("The FAT volume-label entry is malformed")
                self.volume_labels.append(short_name)
                continue
            visible = self._safe_component(visible)
            short_alias = self._safe_component(short)
            for alias in {visible.casefold(), short_alias.casefold()}:
                previous = local_aliases.get(alias)
                if previous is not None:
                    raise FatImageError(
                        f"Embedded FAT names alias each other: {previous!r} and {visible!r}"
                    )
                local_aliases[alias] = visible
            parts = parent + (visible,)
            rendered = PurePosixPath(*parts).as_posix()
            self._record_path(parts, rendered)
            high_cluster = struct.unpack_from("<H", raw, 20)[0]
            low_cluster = struct.unpack_from("<H", raw, 26)[0]
            if self.layout.fat_type is not FatType.FAT32 and high_cluster:
                raise FatImageError(f"{rendered!r} has a FAT32-only high cluster value")
            first_cluster = (high_cluster << 16) | low_cluster
            size = struct.unpack_from("<I", raw, 28)[0]
            is_directory = bool(attributes & 0x10)
            if is_directory:
                if size != 0:
                    raise FatImageError(f"Embedded directory {rendered!r} has a file size")
                clusters = self._chain(first_cluster, rendered)
                if len(self._entries) >= self.maximum_entries:
                    raise FatImageError("The embedded FAT tree has too many entries")
                if (
                    sum(entry.is_directory for entry in self._entries)
                    >= self.maximum_directories
                ):
                    raise FatImageError("The embedded FAT tree has too many directories")
                entry = FatImageEntry(rendered, 0, True, first_cluster, clusters, "")
                self._entries.append(entry)
                self._parse_directory(
                    self._chain_bytes(clusters, f"directory {rendered!r}"),
                    parts,
                    depth + 1,
                    first_cluster,
                    0 if not parent else self_cluster,
                )
            else:
                if size == 0:
                    if first_cluster != 0:
                        raise FatImageError(f"Empty embedded file {rendered!r} owns a cluster")
                    clusters = ()
                else:
                    clusters = self._chain(first_cluster, rendered)
                    needed = (size + self.layout.cluster_bytes - 1) // self.layout.cluster_bytes
                    if len(clusters) != needed:
                        raise FatImageError(
                            f"Embedded file {rendered!r} has an over- or under-sized cluster chain"
                        )
                if len(self._entries) >= self.maximum_entries:
                    raise FatImageError("The embedded FAT tree has too many entries")
                self._entries.append(
                    FatImageEntry(
                        rendered,
                        size,
                        False,
                        first_cluster,
                        clusters,
                        self._file_sha256(clusters, size, rendered),
                    )
                )
        if lfn_chunks:
            raise FatImageError("An embedded FAT directory ends with an orphan long name")
        if self.strict_directories and not saw_terminator:
            raise FatImageError("A FAT directory has no canonical end marker")
        if self.strict_directories and parent and not (saw_dot and saw_dotdot):
            raise FatImageError("A FAT subdirectory is missing its dot entries")

    def parse(self) -> tuple[FatImageEntry, ...]:
        if self.layout.fat_type is FatType.FAT32:
            root_clusters = self._chain(self.layout.root_cluster, "root directory")
            raw = self._chain_bytes(root_clusters, "root directory")
        else:
            raw = self.reader.exact(
                self.layout.root_directory_offset,
                self.layout.root_directory_bytes,
                "embedded FAT root directory",
            )
        self._parse_directory(raw, (), 0, self.layout.root_cluster, 0)
        ordered = tuple(
            sorted(
                self._entries,
                key=lambda entry: (
                    tuple(part.casefold() for part in PurePosixPath(entry.path).parts),
                    not entry.is_directory,
                ),
            )
        )
        total = sum(entry.size for entry in ordered if not entry.is_directory)
        if total > self.maximum_content_bytes:
            raise FatImageError("The embedded FAT file content exceeds the limit")
        return ordered


def _parse_layout(
    reader: _Reader,
    filesystem_offset: int,
    upper_bound: int,
    *,
    maximum_filesystem_bytes: int = MAX_FILESYSTEM_BYTES,
) -> _VolumeLayout:
    if type(maximum_filesystem_bytes) is not int or maximum_filesystem_bytes <= 0:
        raise FatImageError("The FAT filesystem-size limit is invalid")
    boot = reader.exact(filesystem_offset, 512, "embedded FAT boot sector")
    if (
        boot[0] not in {0xE9, 0xEB}
        or (boot[0] == 0xEB and boot[2] != 0x90)
        or boot[510:512] != b"\x55\xaa"
    ):
        raise FatImageError("The embedded image does not begin with a FAT boot sector")
    bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
    sectors_per_cluster = boot[13]
    reserved = struct.unpack_from("<H", boot, 14)[0]
    fat_count = boot[16]
    root_entries = struct.unpack_from("<H", boot, 17)[0]
    total16 = struct.unpack_from("<H", boot, 19)[0]
    fat16 = struct.unpack_from("<H", boot, 22)[0]
    total32 = struct.unpack_from("<I", boot, 32)[0]
    # Offset 36 is FATSz32 only when the FAT12/16 FATSz16 field is zero.  On a
    # normal FAT12/16 volume it begins the extended BPB (drive number, flags,
    # boot signature, and serial) and must not be interpreted as geometry.
    fat32 = struct.unpack_from("<I", boot, 36)[0] if fat16 == 0 else 0
    if bytes_per_sector not in {512, 1024, 2048, 4096}:
        raise FatImageError("The embedded FAT sector size is unsupported")
    if (
        sectors_per_cluster == 0
        or sectors_per_cluster & (sectors_per_cluster - 1)
        or sectors_per_cluster > 128
        or bytes_per_sector * sectors_per_cluster > 32 * 1024
    ):
        raise FatImageError("The embedded FAT cluster size is invalid")
    if reserved == 0 or fat_count not in {1, 2}:
        raise FatImageError("The embedded FAT reserved/FAT count is invalid")
    if bool(total16) == bool(total32):
        raise FatImageError("The embedded FAT total-sector count is ambiguous")
    total_sectors = total16 or total32
    sectors_per_fat = fat16 or fat32
    if sectors_per_fat == 0:
        raise FatImageError("The embedded FAT allocation table has zero sectors")
    filesystem_size = total_sectors * bytes_per_sector
    if (
        filesystem_size < bytes_per_sector
        or filesystem_size > maximum_filesystem_bytes
        or filesystem_offset > upper_bound
        or filesystem_size > upper_bound - filesystem_offset
    ):
        raise FatImageError("The embedded FAT volume exceeds its bounded image extent")
    root_directory_sectors = (
        root_entries * 32 + bytes_per_sector - 1
    ) // bytes_per_sector
    overhead = reserved + fat_count * sectors_per_fat + root_directory_sectors
    if overhead >= total_sectors:
        raise FatImageError("The embedded FAT metadata consumes the whole volume")
    data_sectors = total_sectors - overhead
    cluster_count = data_sectors // sectors_per_cluster
    if cluster_count < 1:
        raise FatImageError("The embedded FAT volume has no data clusters")
    if cluster_count < 4_085:
        fat_type = FatType.FAT12
    elif cluster_count < 65_525:
        fat_type = FatType.FAT16
    else:
        fat_type = FatType.FAT32
    if fat_type is FatType.FAT32:
        if root_entries != 0 or fat16 != 0 or fat32 == 0:
            raise FatImageError("The embedded FAT32 BPB fields are inconsistent")
        if struct.unpack_from("<H", boot, 42)[0] != 0:
            raise FatImageError("The embedded FAT32 version is unsupported")
        flags = struct.unpack_from("<H", boot, 40)[0]
        if flags != 0:
            raise FatImageError("Non-mirrored or flagged FAT32 images are unsupported")
        if any(boot[52:64]):
            raise FatImageError("The embedded FAT32 reserved BPB bytes are nonzero")
        root_cluster = struct.unpack_from("<I", boot, 44)[0]
        if root_cluster < 2 or root_cluster >= cluster_count + 2:
            raise FatImageError("The embedded FAT32 root cluster is invalid")
    else:
        if root_entries == 0 or fat16 == 0:
            raise FatImageError("The embedded FAT12/16 BPB fields are inconsistent")
        root_cluster = 0
    label = (
        boot[82:90].rstrip(b" \0").upper()
        if fat_type is FatType.FAT32
        else boot[54:62].rstrip(b" \0").upper()
    )
    recognized_labels = {b"FAT12", b"FAT16", b"FAT32"}
    if label in recognized_labels and label != fat_type.value.encode("ascii"):
        raise FatImageError("The embedded FAT type label contradicts its geometry")
    fat_capacity = (
        (sectors_per_fat * bytes_per_sector * 2) // 3
        if fat_type is FatType.FAT12
        else (sectors_per_fat * bytes_per_sector) // (2 if fat_type is FatType.FAT16 else 4)
    )
    if fat_capacity < cluster_count + 2:
        raise FatImageError("The embedded FAT table is too small for its data area")
    root_offset = filesystem_offset + (
        reserved + fat_count * sectors_per_fat
    ) * bytes_per_sector
    data_offset = root_offset + root_directory_sectors * bytes_per_sector
    return _VolumeLayout(
        filesystem_offset,
        filesystem_size,
        fat_type,
        bytes_per_sector,
        sectors_per_cluster,
        reserved,
        fat_count,
        sectors_per_fat,
        root_entries,
        root_cluster,
        root_offset,
        root_directory_sectors * bytes_per_sector,
        data_offset,
        cluster_count,
        boot[21],
    )


def _mbr_partition(
    reader: _Reader,
    image_offset: int,
    image_limit: int,
) -> tuple[int, int] | None:
    sector = reader.exact(image_offset, 512, "embedded MBR sector")
    first = sector[446:462]
    if (
        sector[510:512] != b"\x55\xaa"
        or first[0] != 0x80
        or first[4] not in FAT_PARTITION_TYPES
    ):
        return None
    if any(sector[offset:offset + 16] != b"\0" * 16 for offset in (462, 478, 494)):
        raise FatImageError("The embedded MBR contains additional partitions")
    start_lba, sectors = struct.unpack_from("<II", first, 8)
    if start_lba == 0 or sectors == 0 or start_lba % 4:
        raise FatImageError(
            "The embedded MBR FAT partition is empty or not ISO-sector aligned"
        )
    partition_offset = image_offset + start_lba * 512
    partition_bytes = sectors * 512
    if partition_offset > image_limit or partition_bytes > image_limit - partition_offset:
        raise FatImageError("The embedded MBR partition exceeds its image extent")
    return start_lba, sectors


def _manifest_digest(entries: Sequence[FatImageEntry]) -> str:
    payload = [
        {
            "path": entry.path,
            "size": entry.size,
            "directory": entry.is_directory,
            "first_cluster": entry.first_cluster,
            "clusters": entry.clusters,
            "sha256": entry.sha256,
        }
        for entry in entries
    ]
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _embedded_fat_context(
    descriptor: int,
    inspection: ElToritoInspection,
) -> tuple[FatSourceIdentity, _Reader, tuple[BootEntry, ...]]:
    try:
        before_status = os.fstat(descriptor)
    except OSError as error:
        raise FatImageError(f"Could not inspect the selected ISO: {error}") from error
    if not stat.S_ISREG(before_status.st_mode) or before_status.st_size <= 0:
        raise FatImageError("The selected ISO descriptor is not a regular file")
    before = _identity(before_status)
    if before.size != inspection.source_size:
        raise FatImageError("The El Torito catalog belongs to a different ISO size")
    if inspection.source_identity is not None and (
        before.device,
        before.inode,
        before.size,
        before.modified_ns,
        before.changed_ns,
    ) != (
        inspection.source_identity.device,
        inspection.source_identity.inode,
        inspection.source_identity.size,
        inspection.source_identity.modified_ns,
        inspection.source_identity.changed_ns,
    ):
        raise FatImageError("The El Torito catalog belongs to a different ISO identity")
    eligible = tuple(
        entry for entry in inspection.entries
        if (
            entry.bootable
            and entry.platform is BootPlatform.EFI
            and entry.emulation is EmulationType.NO_EMULATION
            and entry.image_offset is not None
        )
    )
    return before, _Reader(descriptor, before.size), eligible


def inspect_uefi_eltorito_fats(
    descriptor: int,
    inspection: ElToritoInspection,
    *,
    cancel_check: CancelCheck | None = None,
) -> tuple[EmbeddedFatImage, ...]:
    """Return all bounded bootable UEFI El Torito FAT images in offset order."""

    before, reader, eligible = _embedded_fat_context(descriptor, inspection)
    if not eligible:
        return ()
    if len(eligible) > MAX_EMBEDDED_IMAGES:
        raise FatImageError("The ISO has too many bootable UEFI El Torito images")
    offsets = tuple(entry.image_offset for entry in eligible)
    if len(set(offsets)) != len(offsets):
        raise FatImageError("Bootable UEFI El Torito images have duplicate offsets")

    results: list[EmbeddedFatImage] = []
    filesystem_bytes = 0
    content_bytes = 0
    entry_count = 0
    directory_count = 0
    for boot_entry in sorted(eligible, key=lambda entry: entry.image_offset or 0):
        filesystem_remaining = MAX_FILESYSTEM_BYTES - filesystem_bytes
        content_remaining = MAX_FILESYSTEM_BYTES - content_bytes
        entries_remaining = MAX_ENTRIES - entry_count
        directories_remaining = MAX_DIRECTORIES - directory_count
        if filesystem_remaining <= 0:
            raise FatImageError("The embedded FAT filesystems exceed the aggregate limit")
        if content_remaining <= 0:
            raise FatImageError("The embedded FAT file content exceeds the aggregate limit")
        if entries_remaining <= 0:
            raise FatImageError("The embedded FAT trees have too many aggregate entries")
        if directories_remaining <= 0:
            raise FatImageError("The embedded FAT trees have too many aggregate directories")
        result = _inspect_uefi_eltorito_fat_image(
            descriptor,
            inspection,
            boot_entry,
            before,
            reader,
            maximum_filesystem_bytes=filesystem_remaining,
            maximum_content_bytes=content_remaining,
            maximum_entries=entries_remaining,
            maximum_directories=directories_remaining,
            cancel_check=cancel_check,
        )
        results.append(result)
        filesystem_bytes += result.filesystem_size
        content_bytes += result.content_bytes
        entry_count += len(result.entries)
        directory_count += sum(entry.is_directory for entry in result.entries)
    return tuple(results)


def inspect_uefi_eltorito_fat(
    descriptor: int,
    inspection: ElToritoInspection,
    *,
    cancel_check: CancelCheck | None = None,
) -> EmbeddedFatImage | None:
    """Return one fully bound embedded FAT tree, or ``None`` when none exists."""

    before, reader, eligible = _embedded_fat_context(descriptor, inspection)
    if not eligible:
        return None
    if len(eligible) != 1:
        raise FatImageError("Multiple bootable UEFI El Torito images are ambiguous")
    return _inspect_uefi_eltorito_fat_image(
        descriptor,
        inspection,
        eligible[0],
        before,
        reader,
        maximum_filesystem_bytes=MAX_FILESYSTEM_BYTES,
        maximum_content_bytes=MAX_FILESYSTEM_BYTES,
        maximum_entries=MAX_ENTRIES,
        maximum_directories=MAX_DIRECTORIES,
        cancel_check=cancel_check,
    )


def _inspect_uefi_eltorito_fat_image(
    descriptor: int,
    inspection: ElToritoInspection,
    boot_entry: BootEntry,
    before: FatSourceIdentity,
    reader: _Reader,
    *,
    maximum_filesystem_bytes: int,
    maximum_content_bytes: int,
    maximum_entries: int,
    maximum_directories: int,
    cancel_check: CancelCheck | None = None,
) -> EmbeddedFatImage:
    assert boot_entry.image_offset is not None
    later_offsets = sorted({
        entry.image_offset
        for entry in inspection.entries
        if entry.image_offset is not None and entry.image_offset > boot_entry.image_offset
    })
    logical_limit = min(inspection.logical_volume_size or before.size, before.size)
    iso_structure_offsets = tuple(
        offset
        for offset in (16 * 2_048, inspection.catalog_offset)
        if offset > boot_entry.image_offset
    )
    image_limit = min(
        later_offsets[0] if later_offsets else logical_limit,
        min(iso_structure_offsets) if iso_structure_offsets else logical_limit,
        logical_limit,
    )
    if boot_entry.sector_count > 1:
        image_limit = min(image_limit, boot_entry.image_offset + boot_entry.load_size)
    if boot_entry.image_offset + 512 > image_limit:
        raise FatImageError("The UEFI El Torito image has no complete first sector")
    if cancel_check is not None:
        cancel_check()

    candidates: list[tuple[_VolumeLayout, int | None, int | None]] = []
    direct_error: FatImageError | None = None
    try:
        direct = _parse_layout(
            reader,
            boot_entry.image_offset,
            image_limit,
            maximum_filesystem_bytes=maximum_filesystem_bytes,
        )
        candidates.append((direct, None, None))
    except FatImageError as error:
        direct_error = error
    partition = _mbr_partition(reader, boot_entry.image_offset, image_limit)
    if partition is not None:
        start_lba, sectors = partition
        partition_offset = boot_entry.image_offset + start_lba * 512
        partition_limit = partition_offset + sectors * 512
        wrapped = _parse_layout(
            reader,
            partition_offset,
            partition_limit,
            maximum_filesystem_bytes=maximum_filesystem_bytes,
        )
        if wrapped.filesystem_size > sectors * 512:
            raise FatImageError("The embedded FAT volume exceeds its MBR partition")
        candidates.append((wrapped, start_lba, sectors))
    if not candidates:
        assert direct_error is not None
        raise direct_error
    if len(candidates) != 1:
        raise FatImageError("The embedded image is ambiguous between direct FAT and MBR FAT")
    layout, partition_start, partition_sectors = candidates[0]
    filesystem_end = layout.filesystem_offset + layout.filesystem_size
    catalog_start = inspection.catalog_offset
    catalog_end = catalog_start + (
        (inspection.catalog_size + 2_047) // 2_048
    ) * 2_048
    descriptor_start = 16 * 2_048
    descriptor_end = descriptor_start + inspection.descriptors_scanned * 2_048
    image_start = boot_entry.image_offset
    if image_start < catalog_end and catalog_start < filesystem_end:
        raise FatImageError("The embedded FAT volume overlaps the El Torito catalog")
    if image_start < descriptor_end and descriptor_start < filesystem_end:
        raise FatImageError("The embedded FAT volume overlaps ISO volume descriptors")
    volume = _FatVolume(
        reader,
        layout,
        upper_bound=layout.filesystem_offset + layout.filesystem_size,
        cancel_check=cancel_check,
        maximum_content_bytes=maximum_content_bytes,
        maximum_entries=maximum_entries,
        maximum_directories=maximum_directories,
    )
    entries = volume.parse()
    result = EmbeddedFatImage(
        before,
        boot_entry,
        boot_entry.image_offset,
        image_limit,
        layout.filesystem_offset,
        layout.filesystem_size,
        partition_start,
        partition_sectors,
        layout.fat_type,
        layout.bytes_per_sector,
        layout.sectors_per_cluster,
        entries,
        _manifest_digest(entries),
    )
    if not result.fallback_loaders:
        raise FatImageError(
            "The embedded UEFI FAT image has no supported non-empty EFI/BOOT fallback loader"
        )
    try:
        after = _identity(os.fstat(descriptor))
    except OSError as error:
        raise FatImageError(f"Could not recheck the selected ISO: {error}") from error
    if after != before:
        raise FatImageError("The selected ISO changed while its embedded FAT image was parsed")
    return result


def inspect_regular_fat32_image(
    descriptor: int,
    *,
    cancel_check: CancelCheck | None = None,
) -> RegularFat32Image:
    """Parse every entry in the bounded private FAT32 image profile.

    This descriptor-only inspector is independent of the writer. It accepts
    one exact MBR/FAT32 layout, hashes every file, and never mounts the image.
    """

    if type(descriptor) is not int or descriptor < 0:
        raise FatImageError("A valid regular-file image descriptor is required")
    try:
        before_status = os.fstat(descriptor)
    except OSError as error:
        raise FatImageError(f"Could not inspect the FAT32 image: {error}") from error
    if (
        not stat.S_ISREG(before_status.st_mode)
        or before_status.st_size <= 0
        or before_status.st_size > MAX_REGULAR_FAT32_BYTES
    ):
        raise FatImageError("The FAT32 image is not a supported bounded regular file")
    before = _identity(before_status)
    reader = _Reader(descriptor, before.size)
    if cancel_check is not None:
        cancel_check()
    mbr = reader.exact(0, 512, "regular-file MBR sector")
    partition = _mbr_partition(reader, 0, before.size)
    if partition is None:
        raise FatImageError("The regular-file image has no active FAT partition")
    start_lba, sectors = partition
    if start_lba != 2_048 or mbr[450] != 0x0C:
        raise FatImageError("The regular-file image is outside the private MBR profile")
    filesystem_offset = start_lba * 512
    filesystem_size = sectors * 512
    if filesystem_offset + filesystem_size != before.size:
        raise FatImageError("The FAT32 partition does not end at the image boundary")
    layout = _parse_layout(
        reader,
        filesystem_offset,
        before.size,
        maximum_filesystem_bytes=MAX_REGULAR_FAT32_BYTES,
    )
    boot = reader.exact(filesystem_offset, 512, "regular-file FAT32 boot sector")
    fsinfo_sector = struct.unpack_from("<H", boot, 48)[0]
    backup_sector = struct.unpack_from("<H", boot, 50)[0]
    if (
        layout.fat_type is not FatType.FAT32
        or layout.filesystem_size != filesystem_size
        or layout.bytes_per_sector != 512
        or layout.reserved_sectors != 32
        or layout.fat_count != 2
        or struct.unpack_from("<I", boot, 28)[0] != start_lba
        or fsinfo_sector != 1
        or backup_sector != 6
        or boot[66] != 0x29
        or boot[82:90] != b"FAT32   "
    ):
        raise FatImageError("The regular-file FAT32 geometry is outside the private profile")
    disk_signature = struct.unpack_from("<I", mbr, 440)[0]
    volume_id = struct.unpack_from("<I", boot, 67)[0]
    if (
        disk_signature in {0, 0xFFFFFFFF}
        or volume_id in {0, 0xFFFFFFFF}
        or volume_id == disk_signature
    ):
        raise FatImageError("The regular-file FAT32 media identifiers are invalid")
    backup = reader.exact(
        filesystem_offset + backup_sector * 512,
        512,
        "regular-file backup FAT32 boot sector",
    )
    if backup != boot:
        raise FatImageError("The primary and backup FAT32 boot sectors disagree")
    fsinfo = reader.exact(
        filesystem_offset + fsinfo_sector * 512,
        512,
        "regular-file FAT32 FSInfo sector",
    )
    backup_fsinfo = reader.exact(
        filesystem_offset + (backup_sector + fsinfo_sector) * 512,
        512,
        "regular-file backup FAT32 FSInfo sector",
    )
    if (
        fsinfo != backup_fsinfo
        or struct.unpack_from("<I", fsinfo, 0)[0] != 0x41615252
        or struct.unpack_from("<I", fsinfo, 484)[0] != 0x61417272
        or struct.unpack_from("<I", fsinfo, 508)[0] != 0xAA550000
        or any(fsinfo[4:484])
        or any(fsinfo[496:508])
    ):
        raise FatImageError("The FAT32 FSInfo copies or signatures are invalid")
    volume = _FatVolume(
        reader,
        layout,
        upper_bound=before.size,
        cancel_check=cancel_check,
        maximum_content_bytes=MAX_REGULAR_FAT32_BYTES,
        strict_directories=True,
    )
    entries = volume.parse()
    if volume.volume_labels != [boot[71:82]]:
        raise FatImageError("The FAT32 root volume label disagrees with its BPB")
    first_free = 0xFFFFFFFF
    for cluster in range(2, layout.cluster_count + 2):
        if cluster & 0xFFF == 0 and cancel_check is not None:
            cancel_check()
        value = volume._fat_value(cluster)
        claimed = cluster in volume._claimed_clusters
        if value != 0 and not claimed:
            raise FatImageError("The FAT32 image contains an unreachable allocated cluster")
        if value == 0 and first_free == 0xFFFFFFFF:
            first_free = cluster
    for cluster in range(layout.cluster_count + 2, len(volume.fat) // 4):
        if cluster & 0xFFF == 0 and cancel_check is not None:
            cancel_check()
        if struct.unpack_from("<I", volume.fat, cluster * 4)[0] != 0:
            raise FatImageError("The FAT32 table has nonzero entries beyond its data area")
    allocated_clusters = len(volume._claimed_clusters)
    free_clusters = layout.cluster_count - allocated_clusters
    if (
        struct.unpack_from("<I", fsinfo, 488)[0] != free_clusters
        or struct.unpack_from("<I", fsinfo, 492)[0] != first_free
    ):
        raise FatImageError("The FAT32 FSInfo allocation accounting is incorrect")
    result = RegularFat32Image(
        before,
        before.size,
        filesystem_offset,
        filesystem_size,
        start_lba,
        sectors,
        disk_signature,
        volume_id,
        layout.bytes_per_sector,
        layout.sectors_per_cluster,
        allocated_clusters,
        free_clusters,
        entries,
        _manifest_digest(entries),
    )
    try:
        after = _identity(os.fstat(descriptor))
    except OSError as error:
        raise FatImageError(f"Could not recheck the FAT32 image: {error}") from error
    if after != before:
        raise FatImageError("The FAT32 image changed while its tree was parsed")
    return result


def validate_uefi_eltorito_fat(
    descriptor: int,
    inspection: ElToritoInspection,
    expected: EmbeddedFatImage,
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    rebuilt = inspect_uefi_eltorito_fat(
        descriptor,
        inspection,
        cancel_check=cancel_check,
    )
    if rebuilt != expected:
        raise FatImageError("The embedded UEFI FAT image no longer matches its bound plan")


def validate_uefi_eltorito_fats(
    descriptor: int,
    inspection: ElToritoInspection,
    expected: tuple[EmbeddedFatImage, ...],
    *,
    cancel_check: CancelCheck | None = None,
) -> None:
    rebuilt = inspect_uefi_eltorito_fats(
        descriptor,
        inspection,
        cancel_check=cancel_check,
    )
    if rebuilt != expected:
        raise FatImageError("The embedded UEFI FAT images no longer match their bound plans")


def _entry_by_path(plan: EmbeddedFatImage, path: str) -> FatImageEntry:
    matches = tuple(entry for entry in plan.entries if entry.path == path)
    if len(matches) != 1:
        raise FatImageError("The requested embedded FAT file is not uniquely bound")
    return matches[0]


def _require_bound_layout(layout: _VolumeLayout, plan: EmbeddedFatImage) -> None:
    if (
        layout.filesystem_offset != plan.filesystem_offset
        or layout.filesystem_size != plan.filesystem_size
        or layout.fat_type is not plan.fat_type
        or layout.bytes_per_sector != plan.bytes_per_sector
        or layout.sectors_per_cluster != plan.sectors_per_cluster
    ):
        raise FatImageError("The embedded FAT geometry no longer matches its bound plan")


def read_embedded_fat_file(
    descriptor: int,
    plan: EmbeddedFatImage,
    path: str,
    *,
    maximum_bytes: int = MAX_READ_FILE_BYTES,
    cancel_check: CancelCheck | None = None,
) -> bytes:
    entry = _entry_by_path(plan, path)
    if entry.is_directory:
        raise FatImageError("The requested embedded FAT path is a directory")
    if type(maximum_bytes) is not int or maximum_bytes < 0 or entry.size > maximum_bytes:
        raise FatImageError("The embedded FAT file exceeds the read limit")
    before = _identity(os.fstat(descriptor))
    if before != plan.source_identity:
        raise FatImageError("The selected ISO no longer matches the embedded FAT plan")
    cluster_bytes = plan.bytes_per_sector * plan.sectors_per_cluster
    reader = _Reader(descriptor, before.size)
    layout = _parse_layout(
        reader,
        plan.filesystem_offset,
        plan.filesystem_offset + plan.filesystem_size,
    )
    _require_bound_layout(layout, plan)
    remaining = entry.size
    chunks: list[bytes] = []
    for cluster in entry.clusters:
        if cancel_check is not None:
            cancel_check()
        cluster_offset = layout.data_offset + (cluster - 2) * cluster_bytes
        take = min(cluster_bytes, remaining)
        chunks.append(reader.exact(
            cluster_offset, take, f"embedded FAT file {path!r}",
        ))
        remaining -= take
    if remaining != 0:
        raise FatImageError("The embedded FAT file chain ended before its declared size")
    if _identity(os.fstat(descriptor)) != before:
        raise FatImageError("The selected ISO changed while an embedded FAT file was read")
    value = b"".join(chunks)
    if hashlib.sha256(value).hexdigest() != entry.sha256:
        raise FatImageError("The embedded FAT file no longer matches its bound digest")
    return value


def materialize_embedded_fat(
    descriptor: int,
    inspection: ElToritoInspection,
    plan: EmbeddedFatImage,
    destination: Path,
    targets: Sequence[str | None],
    *,
    cancel_check: CancelCheck | None = None,
    progress: MaterializeProgress | None = None,
) -> int:
    """Add selected bound FAT entries without replacement.

    A ``None`` target skips an entry that the caller has already proven is an
    exact duplicate of an earlier bound embedded image.  The complete FAT plan
    is still revalidated before any selected entry is created.
    """

    rebuilt = inspect_uefi_eltorito_fats(
        descriptor,
        inspection,
        cancel_check=cancel_check,
    )
    if sum(candidate == plan for candidate in rebuilt) != 1:
        raise FatImageError(
            "The embedded UEFI FAT image no longer matches one unique bound plan"
        )
    if len(targets) != len(plan.entries):
        raise FatImageError("The embedded FAT target mapping is incomplete")
    if any(target is not None and type(target) is not str for target in targets):
        raise FatImageError("The embedded FAT target mapping is invalid")
    target_by_source = dict(zip((entry.path for entry in plan.entries), targets, strict=True))
    if len(target_by_source) != len(plan.entries):
        raise FatImageError("The embedded FAT target mapping is ambiguous")
    try:
        root_status = os.lstat(destination)
        root_fd = os.open(
            destination,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise FatImageError(f"Could not open the private staging tree: {error}") from error
    if not stat.S_ISDIR(root_status.st_mode):
        os.close(root_fd)
        raise FatImageError("The private staging tree is not a real directory")
    try:
        opened_root = os.fstat(root_fd)
        if (
            opened_root.st_dev,
            opened_root.st_ino,
        ) != (
            root_status.st_dev,
            root_status.st_ino,
        ):
            raise FatImageError("The private staging root changed while opening")
        layout = _parse_layout(
            _Reader(descriptor, plan.source_identity.size),
            plan.filesystem_offset,
            plan.filesystem_offset + plan.filesystem_size,
        )
        _require_bound_layout(layout, plan)
    except BaseException:
        os.close(root_fd)
        raise
    selected_entries = tuple(
        entry for entry in plan.entries
        if target_by_source[entry.path] is not None
    )
    total = sum(
        entry.size for entry in selected_entries if not entry.is_directory
    )
    written_total = 0

    def open_directory(parts: tuple[str, ...], create: bool) -> int:
        current = os.dup(root_fd)
        try:
            for component in parts:
                if create:
                    try:
                        os.mkdir(component, 0o700, dir_fd=current)
                    except FileExistsError:
                        pass
                following = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=current,
                )
                os.close(current)
                current = following
                info = os.fstat(current)
                if not stat.S_ISDIR(info.st_mode) or info.st_dev != opened_root.st_dev:
                    raise FatImageError("An embedded FAT target directory escaped staging")
            return current
        except OSError as error:
            os.close(current)
            raise FatImageError(f"Could not create an embedded FAT directory: {error}") from error
        except BaseException:
            os.close(current)
            raise

    try:
        for entry in sorted(
            selected_entries,
            key=lambda item: (
                len(PurePosixPath(target_by_source[item.path]).parts),
                item.path.casefold(),
            ),
        ):
            if cancel_check is not None:
                cancel_check()
            target = target_by_source[entry.path]
            assert target is not None
            parts = PurePosixPath(target).parts
            if not parts or PurePosixPath(target).is_absolute() or ".." in parts:
                raise FatImageError("An embedded FAT target path is unsafe")
            if entry.is_directory:
                directory_fd = open_directory(parts, True)
                os.close(directory_fd)
                continue
            parent_fd = open_directory(parts[:-1], True)
            file_fd = -1
            try:
                file_fd = os.open(
                    parts[-1],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=parent_fd,
                )
                remaining = entry.size
                digest = hashlib.sha256()
                for cluster in entry.clusters:
                    if cancel_check is not None:
                        cancel_check()
                    take = min(layout.cluster_bytes, remaining)
                    chunk = _Reader(descriptor, plan.source_identity.size).exact(
                        layout.data_offset + (cluster - 2) * layout.cluster_bytes,
                        take,
                        f"embedded FAT file {entry.path!r}",
                    )
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        count = os.write(file_fd, view)
                        if count <= 0:
                            raise FatImageError("An embedded FAT file write made no progress")
                        view = view[count:]
                    remaining -= take
                    written_total += take
                    if progress is not None:
                        progress(target, written_total, total)
                if remaining != 0:
                    raise FatImageError(
                        f"Embedded FAT file {entry.path!r} ended before its declared size"
                    )
                if digest.hexdigest() != entry.sha256:
                    raise FatImageError(
                        f"Embedded FAT file {entry.path!r} failed its bound SHA-256 check"
                    )
                os.fsync(file_fd)
            except FileExistsError as error:
                raise FatImageError(
                    f"Embedded FAT file would replace staged path {target!r}"
                ) from error
            except OSError as error:
                raise FatImageError(f"Could not materialize embedded FAT file {target!r}: {error}") from error
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
                os.close(parent_fd)
        if written_total != total:
            raise FatImageError("The embedded FAT extraction byte count is inconsistent")
        if _identity(os.fstat(descriptor)) != plan.source_identity:
            raise FatImageError("The selected ISO changed while its embedded FAT tree was staged")
        return written_total
    finally:
        os.close(root_fd)
