from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bounded, additive ZIP extraction into an already-private staging tree.

ZIP archives are untrusted input.  A plan binds the complete central catalog
and the SHA-256 digest of the selected regular file.  Applying a plan never
uses archive names as filesystem destinations: the caller supplies an aligned,
validated target catalog so a higher-level merge may adopt the exact spelling
of directories already present in the ISO tree.

This module deliberately does not publish or remove the staging tree.  The
caller owns that private tree and must discard it after any failure.
"""

import hashlib
import io
import json
import math
import os
import re
import stat
import time
import unicodedata
import zipfile
import zlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .iso import ArchiveEntry, EntryKind


ZIP_ARCHIVE_MAX_BYTES = 8 * 1024**3
ZIP_EXPANDED_MAX_BYTES = 8 * 1024**3
ZIP_CENTRAL_DIRECTORY_MAX_BYTES = 16 * 1024**2
ZIP_MEMBER_MAX_COUNT = 4096
ZIP_PATH_MAX_DEPTH = 64
ZIP_PATH_MAX_UTF8_BYTES = 1024
ZIP_COMPONENT_MAX_UTF16_UNITS = 255
ZIP_OPERATION_TIMEOUT_SECONDS = 300.0
STREAM_CHUNK_BYTES = 1024 * 1024

_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_CENTRAL_SIGNATURE = b"PK\x01\x02"
_LOCAL_SIGNATURE = b"PK\x03\x04"
_DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"
_ZIP64_EXTRA_ID = 0x0001
_SUPPORTED_COMPRESSION = frozenset((zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
_ENCRYPTION_FLAGS = 0x0001 | 0x0040 | 0x2000
_ALLOWED_FLAGS = 0x0002 | 0x0004 | 0x0008 | 0x0800
_FAT_FORBIDDEN = frozenset('<>:"/\\|?*')
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_WINDOWS_DEVICE = re.compile(
    r"^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])(?:\..*)?$",
    re.IGNORECASE,
)
_WINDOWS_DEVICE_STEM = re.compile(
    r"^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])$", re.IGNORECASE,
)
_READ_FLAGS = (
    os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0)
)
_DIR_FLAGS = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0)
)
_WRITE_FLAGS = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0)
)

CancelCheck = Callable[[], None]


class ZipOverlayError(RuntimeError):
    """The ZIP overlay could not be safely planned or applied."""


class ZipOverlaySafetyError(ZipOverlayError):
    pass


class ZipOverlayChanged(ZipOverlaySafetyError):
    pass


class ZipOverlayDeadlineExceeded(ZipOverlayError):
    pass


@dataclass(frozen=True)
class ZipOverlayIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int
    link_count: int

    def __post_init__(self) -> None:
        values = (
            self.device, self.inode, self.size, self.modified_ns,
            self.changed_ns, self.link_count,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise ValueError("ZIP overlay identity fields must be integers")
        if self.device < 0 or self.inode <= 0 or self.size <= 0:
            raise ValueError("ZIP overlay identity is invalid")
        if self.size > ZIP_ARCHIVE_MAX_BYTES:
            raise ValueError("ZIP overlay identity exceeds the archive-size limit")
        if self.link_count != 1:
            raise ValueError("ZIP overlay identity is not safely bound")


@dataclass(frozen=True)
class ZipOverlayMember:
    entry: ArchiveEntry
    archive_name: str
    crc32: int
    compressed_size: int
    compression: int
    flag_bits: int
    external_attr: int
    header_offset: int
    version_made_by: int
    extract_version: int

    def __post_init__(self) -> None:
        if self.entry.kind not in {EntryKind.FILE, EntryKind.DIRECTORY}:
            raise ValueError("ZIP overlay members must be files or directories")
        if not self.archive_name or "\x00" in self.archive_name:
            raise ValueError("ZIP overlay archive names must be non-empty and NUL-free")
        numeric = (
            self.crc32, self.compressed_size, self.compression, self.flag_bits,
            self.external_attr, self.header_offset, self.version_made_by,
            self.extract_version,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in numeric):
            raise ValueError("ZIP overlay member facts must be integers")
        if not 0 <= self.crc32 <= 0xFFFFFFFF:
            raise ValueError("ZIP overlay member CRC is invalid")
        if not 0 <= self.compressed_size <= ZIP_ARCHIVE_MAX_BYTES:
            raise ValueError("ZIP overlay compressed size is invalid")
        if self.compression not in _SUPPORTED_COMPRESSION:
            raise ValueError("ZIP overlay compression is unsupported")
        if not 0 <= self.flag_bits <= 0xFFFF or self.flag_bits & ~_ALLOWED_FLAGS:
            raise ValueError("ZIP overlay flags are invalid")
        if not 0 <= self.external_attr <= 0xFFFFFFFF or self.header_offset < 0:
            raise ValueError("ZIP overlay member metadata is invalid")
        if not 0 <= self.version_made_by <= 0xFFFF or not 0 <= self.extract_version <= 0xFFFF:
            raise ValueError("ZIP overlay version metadata is invalid")
        if self.entry.kind is EntryKind.DIRECTORY and (self.entry.size or self.crc32):
            raise ValueError("ZIP overlay directories must have empty contents")


@dataclass(frozen=True)
class ZipOverlayPlan:
    archive: Path
    identity: ZipOverlayIdentity
    members: tuple[ZipOverlayMember, ...]
    content_bytes: int
    archive_sha256: str
    catalog_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.archive, Path) or not self.archive.is_absolute():
            raise ValueError("ZIP overlay paths must be absolute")
        if not self.members or len(self.members) > ZIP_MEMBER_MAX_COUNT:
            raise ValueError("ZIP overlay member count is invalid")
        if (
            isinstance(self.content_bytes, bool)
            or not isinstance(self.content_bytes, int)
            or not 0 <= self.content_bytes <= ZIP_EXPANDED_MAX_BYTES
        ):
            raise ValueError("ZIP overlay expanded size is invalid")
        expected = sum(
            member.entry.size
            for member in self.members
            if member.entry.kind is EntryKind.FILE
        )
        if self.content_bytes != expected:
            raise ValueError("ZIP overlay expanded size does not match its members")
        for digest in (self.archive_sha256, self.catalog_digest):
            if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
                raise ValueError("ZIP overlay digests must be lowercase SHA-256 values")


@dataclass(frozen=True)
class ZipOverlayProgress:
    member: str
    member_bytes_done: int
    member_size: int
    bytes_done: int
    total_bytes: int

    @property
    def fraction(self) -> float:
        if self.total_bytes <= 0:
            return 1.0
        return min(1.0, max(0.0, self.bytes_done / self.total_bytes))


@dataclass(frozen=True)
class ZipOverlayResult:
    files: int
    directories: int
    bytes_written: int
    archive_sha256: str
    catalog_digest: str


@dataclass(frozen=True)
class _CentralFact:
    raw_name: bytes
    archive_name: str
    crc32: int
    compressed_size: int
    size: int
    compression: int
    flag_bits: int
    external_attr: int
    header_offset: int
    version_made_by: int
    extract_version: int
    modified_time: int
    modified_date: int
    directory: bool
    interval_end: int


class _Guard:
    def __init__(
        self,
        deadline: float,
        cancel_check: CancelCheck | None,
    ) -> None:
        self.deadline = deadline
        self.cancel_check = cancel_check

    def check(self) -> None:
        if self.cancel_check is not None:
            self.cancel_check()
        if time.monotonic() >= self.deadline:
            raise ZipOverlayDeadlineExceeded("ZIP overlay operation exceeded its deadline")


def _deadline(timeout_seconds: float) -> float:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("ZIP overlay timeout must be a positive finite number")
    return time.monotonic() + float(timeout_seconds)


def _identity_from_status(status: os.stat_result) -> ZipOverlayIdentity:
    if not stat.S_ISREG(status.st_mode) or status.st_size <= 0:
        raise ZipOverlaySafetyError("The ZIP overlay must be a non-empty regular file")
    if status.st_size > ZIP_ARCHIVE_MAX_BYTES:
        raise ZipOverlaySafetyError("The ZIP overlay exceeds the 8 GiB archive limit")
    if status.st_nlink != 1:
        raise ZipOverlaySafetyError("The ZIP overlay must not have hard-link aliases")
    return ZipOverlayIdentity(
        status.st_dev, status.st_ino, status.st_size,
        status.st_mtime_ns, status.st_ctime_ns, status.st_nlink,
    )


def _open_bound_archive(path: Path) -> tuple[int, ZipOverlayIdentity]:
    try:
        descriptor = os.open(path, _READ_FLAGS)
    except OSError as error:
        raise ZipOverlaySafetyError("The ZIP overlay could not be opened safely") from error
    try:
        identity = _identity_from_status(os.fstat(descriptor))
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, identity


def _ensure_unchanged(descriptor: int, identity: ZipOverlayIdentity) -> None:
    try:
        current = _identity_from_status(os.fstat(descriptor))
    except (OSError, ZipOverlaySafetyError, ValueError) as error:
        raise ZipOverlayChanged("The ZIP overlay is no longer safely available") from error
    if current != identity:
        raise ZipOverlayChanged("The ZIP overlay changed during inspection or extraction")


def _ensure_path_identity(path: Path, identity: ZipOverlayIdentity) -> None:
    try:
        current = _identity_from_status(os.stat(path, follow_symlinks=False))
    except (OSError, ZipOverlaySafetyError, ValueError) as error:
        raise ZipOverlayChanged("The ZIP overlay path is no longer safely bound") from error
    if current != identity:
        raise ZipOverlayChanged("The ZIP overlay path changed after it was selected")


def _pread_exact(
    descriptor: int,
    size: int,
    offset: int,
    identity: ZipOverlayIdentity,
    guard: _Guard,
    description: str,
) -> bytes:
    guard.check()
    if size < 0 or offset < 0 or size > identity.size - offset:
        raise ZipOverlaySafetyError(f"The ZIP {description} lies outside the archive")
    data = os.pread(descriptor, size, offset)
    _ensure_unchanged(descriptor, identity)
    guard.check()
    if len(data) != size:
        raise ZipOverlaySafetyError(f"The ZIP {description} is truncated")
    return data


class _DescriptorReader(io.RawIOBase):
    def __init__(
        self,
        descriptor: int,
        identity: ZipOverlayIdentity,
        guard: _Guard,
    ) -> None:
        super().__init__()
        self._descriptor = os.dup(descriptor)
        self._identity = identity
        self._guard = guard
        self._position = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        self._checkClosed()
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._checkClosed()
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self._position + offset
        elif whence == os.SEEK_END:
            position = self._identity.size + offset
        else:
            raise ValueError(f"unsupported whence value: {whence}")
        if position < 0:
            raise ValueError("negative seek position")
        self._position = position
        return position

    def readinto(self, buffer: object) -> int:
        self._checkClosed()
        view = memoryview(buffer).cast("B")
        self._guard.check()
        data = os.pread(self._descriptor, len(view), self._position)
        _ensure_unchanged(self._descriptor, self._identity)
        self._guard.check()
        view[:len(data)] = data
        self._position += len(data)
        return len(data)

    def close(self) -> None:
        if not self.closed:
            os.close(self._descriptor)
        super().close()


def _extra_fields(extra: bytes, description: str) -> dict[int, bytes]:
    fields: dict[int, bytes] = {}
    position = 0
    while position < len(extra):
        if len(extra) - position < 4:
            raise ZipOverlaySafetyError(f"The ZIP {description} extra data is malformed")
        field_id = int.from_bytes(extra[position:position + 2], "little")
        field_size = int.from_bytes(extra[position + 2:position + 4], "little")
        position += 4
        if field_size > len(extra) - position:
            raise ZipOverlaySafetyError(f"The ZIP {description} extra data is truncated")
        if field_id in fields:
            raise ZipOverlaySafetyError(f"The ZIP {description} repeats an extra-data field")
        fields[field_id] = extra[position:position + field_size]
        position += field_size
    return fields


def _resolved_zip64_values(
    uncompressed: int,
    compressed: int,
    offset: int | None,
    disk: int | None,
    extra: bytes,
    description: str,
) -> tuple[int, int, int | None, int | None]:
    needs = (
        uncompressed == 0xFFFFFFFF,
        compressed == 0xFFFFFFFF,
        offset == 0xFFFFFFFF,
        disk == 0xFFFF,
    )
    fields = _extra_fields(extra, description)
    payload = fields.get(_ZIP64_EXTRA_ID)
    if any(needs) and payload is None:
        raise ZipOverlaySafetyError(f"The ZIP {description} lacks required ZIP64 metadata")
    if payload is None:
        return uncompressed, compressed, offset, disk
    position = 0
    values: list[int | None] = [uncompressed, compressed, offset, disk]
    for index, needed in enumerate(needs):
        if not needed:
            continue
        width = 4 if index == 3 else 8
        if len(payload) - position < width:
            raise ZipOverlaySafetyError(f"The ZIP {description} ZIP64 metadata is truncated")
        values[index] = int.from_bytes(payload[position:position + width], "little")
        position += width
    if position != len(payload):
        raise ZipOverlaySafetyError(f"The ZIP {description} ZIP64 metadata is ambiguous")
    return values[0], values[1], values[2], values[3]  # type: ignore[return-value]


def _decode_name(raw_name: bytes, flags: int) -> str:
    if not raw_name or b"\x00" in raw_name:
        raise ZipOverlaySafetyError("A ZIP member name is empty or contains NUL")
    try:
        return raw_name.decode("utf-8" if flags & 0x0800 else "cp437")
    except UnicodeDecodeError as error:
        raise ZipOverlaySafetyError("A ZIP member name is not valid UTF-8") from error


def _portable_parts(name: str, *, directory: bool) -> tuple[str, ...]:
    if not name or "\x00" in name:
        raise ZipOverlaySafetyError("A ZIP member name is empty or contains NUL")
    if "\\" in name:
        raise ZipOverlaySafetyError(f"Backslashes are forbidden in ZIP member names: {name!r}")
    rendered = name[:-1] if directory and name.endswith("/") else name
    if not rendered or rendered.startswith("/") or _WINDOWS_DRIVE.match(rendered):
        raise ZipOverlaySafetyError(f"Absolute or empty ZIP member path is forbidden: {name!r}")
    raw_parts = rendered.split("/")
    if len(raw_parts) > ZIP_PATH_MAX_DEPTH:
        raise ZipOverlaySafetyError("A ZIP member path exceeds the maximum depth")
    normalized: list[str] = []
    for component in raw_parts:
        if not component or component in {".", ".."}:
            raise ZipOverlaySafetyError(f"Unsafe ZIP path component in {name!r}")
        if any(ord(character) < 32 or ord(character) == 127 for character in component):
            raise ZipOverlaySafetyError(f"Control character in ZIP member path: {name!r}")
        if any(character in _FAT_FORBIDDEN for character in component):
            raise ZipOverlaySafetyError(f"FAT-forbidden character in ZIP member path: {name!r}")
        if component.endswith((" ", ".")):
            raise ZipOverlaySafetyError(f"Trailing dot or space in ZIP member path: {name!r}")
        component = unicodedata.normalize("NFC", component)
        stem = component.split(".", 1)[0].rstrip(" .")
        if _WINDOWS_DEVICE.fullmatch(component) or _WINDOWS_DEVICE_STEM.fullmatch(stem):
            raise ZipOverlaySafetyError(f"Reserved device name in ZIP member path: {name!r}")
        try:
            utf16_units = len(component.encode("utf-16-le", errors="strict")) // 2
        except UnicodeEncodeError as error:
            raise ZipOverlaySafetyError("A ZIP member path contains invalid Unicode") from error
        if utf16_units > ZIP_COMPONENT_MAX_UTF16_UNITS:
            raise ZipOverlaySafetyError("A ZIP member path component is too long")
        normalized.append(component)
    path = PurePosixPath(*normalized).as_posix()
    try:
        encoded_path = path.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ZipOverlaySafetyError("A ZIP member path contains invalid Unicode") from error
    if len(encoded_path) > ZIP_PATH_MAX_UTF8_BYTES:
        raise ZipOverlaySafetyError("A ZIP member path is too long")
    return tuple(normalized)


def _path_key(parts: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in parts)


def _validate_namespace(entries: Sequence[ArchiveEntry]) -> tuple[ArchiveEntry, ...]:
    normalized: list[ArchiveEntry] = []
    by_key: dict[tuple[str, ...], ArchiveEntry] = {}
    prefix_spelling: dict[tuple[str, ...], tuple[str, ...]] = {}
    for entry in entries:
        if entry.kind not in {EntryKind.FILE, EntryKind.DIRECTORY}:
            raise ZipOverlaySafetyError("ZIP overlay targets must be files or directories")
        if entry.link_target is not None or entry.modified_ns is not None:
            raise ZipOverlaySafetyError("ZIP overlay targets cannot carry links or timestamps")
        parts = _portable_parts(entry.path, directory=False)
        canonical = ArchiveEntry(
            PurePosixPath(*parts).as_posix(), entry.size, entry.kind,
        )
        if canonical != entry:
            raise ZipOverlaySafetyError("ZIP overlay targets must already be normalized")
        if entry.kind is EntryKind.DIRECTORY and entry.size:
            raise ZipOverlaySafetyError("ZIP overlay directories must have size zero")
        key = _path_key(parts)
        if key in by_key:
            raise ZipOverlaySafetyError("ZIP overlay paths collide by case or normalization")
        by_key[key] = entry
        normalized.append(entry)
        prefix_limit = len(parts) if entry.kind is EntryKind.DIRECTORY else len(parts) - 1
        for length in range(1, prefix_limit + 1):
            prefix = parts[:length]
            prefix_key = _path_key(prefix)
            previous = prefix_spelling.setdefault(prefix_key, prefix)
            if previous != prefix:
                raise ZipOverlaySafetyError(
                    "ZIP overlay directory prefixes use inconsistent spelling"
                )
    for key, entry in by_key.items():
        parts = tuple(PurePosixPath(entry.path).parts)
        for length in range(1, len(parts)):
            ancestor = by_key.get(_path_key(parts[:length]))
            if ancestor is not None and ancestor.kind is not EntryKind.DIRECTORY:
                raise ZipOverlaySafetyError(
                    f"ZIP overlay member has a non-directory ancestor: {entry.path!r}"
                )
    return tuple(normalized)


def _directory_kind(version_made_by: int, external_attr: int, name: str) -> bool:
    slash_directory = name.endswith("/")
    create_system = version_made_by >> 8
    dos_attributes = external_attr & 0xFF
    mode_kind = stat.S_IFMT((external_attr >> 16) & 0xFFFF)
    if dos_attributes & 0x08:
        raise ZipOverlaySafetyError("ZIP volume-label entries are forbidden")
    # Even a forged non-Unix creator marker must not be able to smuggle
    # recognizable Unix link or special-file semantics into the catalog.
    if mode_kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise ZipOverlaySafetyError("ZIP symlink or special-file entries are forbidden")
    if create_system == 3:
        mode_directory = mode_kind == stat.S_IFDIR
        if mode_directory != slash_directory:
            raise ZipOverlaySafetyError("ZIP member type disagrees with its path syntax")
    elif bool(dos_attributes & 0x10) != slash_directory:
        raise ZipOverlaySafetyError("ZIP member type disagrees with its path syntax")
    return slash_directory


def _read_directory(
    descriptor: int,
    identity: ZipOverlayIdentity,
    guard: _Guard,
) -> tuple[list[_CentralFact], int]:
    tail_size = min(identity.size, 22 + 65535)
    tail_offset = identity.size - tail_size
    tail = _pread_exact(
        descriptor, tail_size, tail_offset, identity, guard, "archive tail",
    )
    eocd_index = tail.rfind(_EOCD_SIGNATURE)
    if eocd_index < 0 or eocd_index + 22 > len(tail):
        raise ZipOverlaySafetyError("The ZIP end-of-central-directory record is invalid")
    comment_size = int.from_bytes(tail[eocd_index + 20:eocd_index + 22], "little")
    eocd_offset = tail_offset + eocd_index
    if eocd_offset + 22 + comment_size != identity.size:
        raise ZipOverlaySafetyError("The ZIP end-of-central-directory record is invalid")
    eocd = tail[eocd_index:eocd_index + 22]
    disk = int.from_bytes(eocd[4:6], "little")
    directory_disk = int.from_bytes(eocd[6:8], "little")
    entries_on_disk = int.from_bytes(eocd[8:10], "little")
    entry_count = int.from_bytes(eocd[10:12], "little")
    directory_size = int.from_bytes(eocd[12:16], "little")
    directory_offset = int.from_bytes(eocd[16:20], "little")
    if disk or directory_disk or entries_on_disk != entry_count:
        raise ZipOverlaySafetyError("Multi-disk ZIP overlays are not supported")

    directory_end = eocd_offset
    classic_zip64 = (
        entry_count == 0xFFFF
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
    )
    locator_offset = eocd_offset - 20
    locator = (
        _pread_exact(
            descriptor, 20, locator_offset, identity, guard, "ZIP64 locator",
        ) if locator_offset >= 0 else b""
    )
    has_locator = len(locator) == 20 and locator[:4] == _ZIP64_LOCATOR_SIGNATURE
    if classic_zip64 and not has_locator:
        raise ZipOverlaySafetyError("The ZIP64 directory locator is invalid")
    if has_locator:
        if int.from_bytes(locator[4:8], "little") != 0:
            raise ZipOverlaySafetyError("Multi-disk ZIP64 overlays are not supported")
        record_offset = int.from_bytes(locator[8:16], "little")
        if int.from_bytes(locator[16:20], "little") != 1:
            raise ZipOverlaySafetyError("Multi-disk ZIP64 overlays are not supported")
        if record_offset > locator_offset - 56:
            raise ZipOverlaySafetyError("The ZIP64 directory locator is invalid")
        fixed = _pread_exact(
            descriptor, 56, record_offset, identity, guard, "ZIP64 directory record",
        )
        if fixed[:4] != _ZIP64_EOCD_SIGNATURE:
            raise ZipOverlaySafetyError("The ZIP64 directory record is invalid")
        record_size = int.from_bytes(fixed[4:12], "little")
        if record_size < 44 or record_offset + 12 + record_size != locator_offset:
            raise ZipOverlaySafetyError("The ZIP64 directory record is inconsistent")
        if (
            int.from_bytes(fixed[16:20], "little") != 0
            or int.from_bytes(fixed[20:24], "little") != 0
            or int.from_bytes(fixed[24:32], "little")
            != int.from_bytes(fixed[32:40], "little")
        ):
            raise ZipOverlaySafetyError("Multi-disk ZIP64 overlays are not supported")
        zip64_count = int.from_bytes(fixed[32:40], "little")
        zip64_size = int.from_bytes(fixed[40:48], "little")
        zip64_offset = int.from_bytes(fixed[48:56], "little")
        for classic, sentinel, exact in (
            (entry_count, 0xFFFF, zip64_count),
            (directory_size, 0xFFFFFFFF, zip64_size),
            (directory_offset, 0xFFFFFFFF, zip64_offset),
        ):
            if classic != sentinel and classic != exact:
                raise ZipOverlaySafetyError("Classic and ZIP64 directory facts disagree")
        entry_count, directory_size, directory_offset = (
            zip64_count, zip64_size, zip64_offset,
        )
        directory_end = record_offset

    if entry_count == 0:
        raise ZipOverlaySafetyError("The ZIP overlay is empty")
    if entry_count > ZIP_MEMBER_MAX_COUNT:
        raise ZipOverlaySafetyError("The ZIP overlay contains too many members")
    if directory_size > ZIP_CENTRAL_DIRECTORY_MAX_BYTES:
        raise ZipOverlaySafetyError("The ZIP central directory exceeds 16 MiB")
    if directory_offset + directory_size != directory_end:
        # Any positive discrepancy is a concatenated/SFX prefix or unmodeled
        # record.  Both are intentionally excluded from overlay archives.
        raise ZipOverlaySafetyError("Self-extracting or prefixed ZIP overlays are forbidden")
    directory = _pread_exact(
        descriptor, directory_size, directory_offset, identity, guard,
        "central directory",
    )
    facts: list[_CentralFact] = []
    position = 0
    expanded = 0
    while position < len(directory):
        guard.check()
        if len(directory) - position < 46 or directory[position:position + 4] != _CENTRAL_SIGNATURE:
            raise ZipOverlaySafetyError("The ZIP central directory is malformed")
        record = directory[position:position + 46]
        version_made_by = int.from_bytes(record[4:6], "little")
        extract_version = int.from_bytes(record[6:8], "little")
        flags = int.from_bytes(record[8:10], "little")
        compression = int.from_bytes(record[10:12], "little")
        modified_time = int.from_bytes(record[12:14], "little")
        modified_date = int.from_bytes(record[14:16], "little")
        crc32 = int.from_bytes(record[16:20], "little")
        compressed = int.from_bytes(record[20:24], "little")
        size = int.from_bytes(record[24:28], "little")
        name_size = int.from_bytes(record[28:30], "little")
        extra_size = int.from_bytes(record[30:32], "little")
        comment_size = int.from_bytes(record[32:34], "little")
        start_disk = int.from_bytes(record[34:36], "little")
        external_attr = int.from_bytes(record[38:42], "little")
        header_offset = int.from_bytes(record[42:46], "little")
        record_size = 46 + name_size + extra_size + comment_size
        if record_size > len(directory) - position:
            raise ZipOverlaySafetyError("A ZIP central-directory record is truncated")
        raw_name = directory[position + 46:position + 46 + name_size]
        extra = directory[
            position + 46 + name_size:position + 46 + name_size + extra_size
        ]
        size, compressed, header_offset, start_disk = _resolved_zip64_values(
            size, compressed, header_offset, start_disk, extra, "central member",
        )
        if start_disk != 0:
            raise ZipOverlaySafetyError("Multi-disk ZIP members are not supported")
        if flags & _ENCRYPTION_FLAGS:
            raise ZipOverlaySafetyError("Encrypted ZIP overlay members are forbidden")
        if flags & ~_ALLOWED_FLAGS:
            raise ZipOverlaySafetyError("Unsupported ZIP member flags are forbidden")
        if compression not in _SUPPORTED_COMPRESSION:
            raise ZipOverlaySafetyError("Only stored and deflated ZIP members are supported")
        if compression == zipfile.ZIP_STORED and flags & 0x0006:
            raise ZipOverlaySafetyError("Stored ZIP members contain invalid compression flags")
        archive_name = _decode_name(raw_name, flags)
        directory_member = _directory_kind(version_made_by, external_attr, archive_name)
        parts = _portable_parts(archive_name, directory=directory_member)
        if directory_member and (size or crc32):
            raise ZipOverlaySafetyError("ZIP directory entries must have empty contents")
        if size > ZIP_EXPANDED_MAX_BYTES - expanded:
            raise ZipOverlaySafetyError("The ZIP overlay exceeds the 8 GiB expanded limit")
        expanded += size
        facts.append(_CentralFact(
            raw_name, archive_name, crc32, compressed, size, compression,
            flags, external_attr, header_offset, version_made_by,
            extract_version, modified_time, modified_date, directory_member, 0,
        ))
        position += record_size
    if len(facts) != entry_count:
        raise ZipOverlaySafetyError("The ZIP central-directory count is inconsistent")

    intervals: list[tuple[int, int]] = []
    checked: list[_CentralFact] = []
    local_metadata_bytes = 0
    for fact in facts:
        local = _pread_exact(
            descriptor, 30, fact.header_offset, identity, guard, "local header",
        )
        if local[:4] != _LOCAL_SIGNATURE:
            raise ZipOverlaySafetyError("A ZIP local header is invalid")
        if (
            int.from_bytes(local[4:6], "little") != fact.extract_version
            or int.from_bytes(local[6:8], "little") != fact.flag_bits
            or int.from_bytes(local[8:10], "little") != fact.compression
            or int.from_bytes(local[10:12], "little") != fact.modified_time
            or int.from_bytes(local[12:14], "little") != fact.modified_date
        ):
            raise ZipOverlaySafetyError("A ZIP local header disagrees with its catalog")
        local_crc = int.from_bytes(local[14:18], "little")
        local_compressed = int.from_bytes(local[18:22], "little")
        local_size = int.from_bytes(local[22:26], "little")
        local_name_size = int.from_bytes(local[26:28], "little")
        local_extra_size = int.from_bytes(local[28:30], "little")
        local_metadata_bytes += 30 + local_name_size + local_extra_size
        if local_metadata_bytes > ZIP_CENTRAL_DIRECTORY_MAX_BYTES:
            raise ZipOverlaySafetyError("ZIP local-header metadata exceeds 16 MiB")
        variable = _pread_exact(
            descriptor, local_name_size + local_extra_size,
            fact.header_offset + 30, identity, guard, "local-header data",
        )
        if variable[:local_name_size] != fact.raw_name:
            raise ZipOverlaySafetyError("A ZIP local filename disagrees with its catalog")
        local_extra = variable[local_name_size:]
        local_zip64 = local_size == 0xFFFFFFFF or local_compressed == 0xFFFFFFFF
        local_size, local_compressed, _, _ = _resolved_zip64_values(
            local_size, local_compressed, None, None, local_extra, "local member",
        )
        descriptor_mode = bool(fact.flag_bits & 0x0008)
        if descriptor_mode:
            if local_crc not in {0, fact.crc32}:
                raise ZipOverlaySafetyError("A ZIP local CRC disagrees with its catalog")
            if local_size not in {0, fact.size} or local_compressed not in {0, fact.compressed_size}:
                raise ZipOverlaySafetyError("ZIP local sizes disagree with the catalog")
        elif (
            local_crc != fact.crc32
            or local_size != fact.size
            or local_compressed != fact.compressed_size
        ):
            raise ZipOverlaySafetyError("A ZIP local header disagrees with its cataloged sizes")
        data_start = fact.header_offset + 30 + len(variable)
        data_end = data_start + fact.compressed_size
        if data_end > directory_offset:
            raise ZipOverlaySafetyError("ZIP member data overlaps the central directory")
        interval_end = data_end
        if descriptor_mode:
            zip64_descriptor = (
                local_zip64
                or fact.size > 0xFFFFFFFF
                or fact.compressed_size > 0xFFFFFFFF
            )
            descriptor_size = 20 if zip64_descriptor else 12
            prefix = _pread_exact(
                descriptor, 4, data_end, identity, guard, "data descriptor",
            )
            if prefix == _DATA_DESCRIPTOR_SIGNATURE:
                descriptor_size += 4
                values = _pread_exact(
                    descriptor, descriptor_size - 4, data_end + 4,
                    identity, guard, "data descriptor",
                )
            else:
                values = _pread_exact(
                    descriptor, descriptor_size, data_end,
                    identity, guard, "data descriptor",
                )
            width = 8 if zip64_descriptor else 4
            if (
                int.from_bytes(values[0:4], "little") != fact.crc32
                or int.from_bytes(values[4:4 + width], "little") != fact.compressed_size
                or int.from_bytes(values[4 + width:4 + 2 * width], "little") != fact.size
            ):
                raise ZipOverlaySafetyError("A ZIP data descriptor disagrees with its catalog")
            interval_end += descriptor_size
        if interval_end > directory_offset:
            raise ZipOverlaySafetyError("A ZIP member overlaps the central directory")
        intervals.append((fact.header_offset, interval_end))
        checked.append(_CentralFact(
            fact.raw_name, fact.archive_name, fact.crc32, fact.compressed_size,
            fact.size, fact.compression, fact.flag_bits, fact.external_attr,
            fact.header_offset, fact.version_made_by, fact.extract_version,
            fact.modified_time, fact.modified_date, fact.directory, interval_end,
        ))
    intervals.sort()
    if intervals[0][0] != 0:
        raise ZipOverlaySafetyError("Self-extracting or prefixed ZIP overlays are forbidden")
    for previous, current in zip(intervals, intervals[1:]):
        if current[0] != previous[1]:
            raise ZipOverlaySafetyError("ZIP member records overlap or contain unexplained gaps")
    if intervals[-1][1] != directory_offset:
        raise ZipOverlaySafetyError(
            "ZIP member records contain unexplained data before the central directory"
        )
    return checked, expanded


def _members_from_facts(facts: Sequence[_CentralFact]) -> tuple[ZipOverlayMember, ...]:
    entries: list[ArchiveEntry] = []
    for fact in facts:
        parts = _portable_parts(fact.archive_name, directory=fact.directory)
        entries.append(ArchiveEntry(
            PurePosixPath(*parts).as_posix(), fact.size,
            EntryKind.DIRECTORY if fact.directory else EntryKind.FILE,
        ))
    safe_entries = _validate_namespace(entries)
    return tuple(
        ZipOverlayMember(
            entry, fact.archive_name, fact.crc32, fact.compressed_size,
            fact.compression, fact.flag_bits, fact.external_attr,
            fact.header_offset, fact.version_made_by, fact.extract_version,
        )
        for entry, fact in zip(safe_entries, facts)
    )


def _catalog_digest(members: Sequence[ZipOverlayMember]) -> str:
    payload = [
        {
            "path": member.entry.path,
            "kind": member.entry.kind.value,
            "size": member.entry.size,
            "archive_name": member.archive_name,
            "crc32": member.crc32,
            "compressed_size": member.compressed_size,
            "compression": member.compression,
            "flag_bits": member.flag_bits,
            "external_attr": member.external_attr,
            "header_offset": member.header_offset,
            "version_made_by": member.version_made_by,
            "extract_version": member.extract_version,
        }
        for member in members
    ]
    encoded = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _archive_sha256(
    descriptor: int,
    identity: ZipOverlayIdentity,
    guard: _Guard,
) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < identity.size:
        block = _pread_exact(
            descriptor, min(STREAM_CHUNK_BYTES, identity.size - offset), offset,
            identity, guard, "contents",
        )
        digest.update(block)
        offset += len(block)
    return digest.hexdigest()


def _compare_zipfile_catalog(
    descriptor: int,
    identity: ZipOverlayIdentity,
    guard: _Guard,
    facts: Sequence[_CentralFact],
) -> None:
    raw = _DescriptorReader(descriptor, identity, guard)
    buffered = io.BufferedReader(raw, buffer_size=STREAM_CHUNK_BYTES)
    try:
        with zipfile.ZipFile(buffered, "r") as archive:
            infos = archive.infolist()
            if len(infos) != len(facts):
                raise ZipOverlaySafetyError("The ZIP parser catalogs disagree")
            for info, fact in zip(infos, facts):
                guard.check()
                if "\x00" in info.orig_filename or info.orig_filename != fact.archive_name:
                    raise ZipOverlaySafetyError("The ZIP parser disagrees about a member name")
                if (
                    info.CRC != fact.crc32
                    or info.compress_size != fact.compressed_size
                    or info.file_size != fact.size
                    or info.compress_type != fact.compression
                    or info.flag_bits != fact.flag_bits
                    or info.external_attr != fact.external_attr
                    or info.header_offset != fact.header_offset
                    or ((info.create_system << 8) | info.create_version) != fact.version_made_by
                    or info.extract_version != fact.extract_version
                    or info.is_dir() != fact.directory
                ):
                    raise ZipOverlaySafetyError("The ZIP parser disagrees with bounded metadata")
    except ZipOverlayError:
        raise
    except (OSError, ValueError, zipfile.BadZipFile, NotImplementedError) as error:
        raise ZipOverlaySafetyError("The ZIP overlay catalog is malformed") from error
    finally:
        buffered.close()


def _inspect_open_archive(
    path: Path,
    descriptor: int,
    identity: ZipOverlayIdentity,
    guard: _Guard,
) -> ZipOverlayPlan:
    facts, expanded = _read_directory(descriptor, identity, guard)
    members = _members_from_facts(facts)
    _compare_zipfile_catalog(descriptor, identity, guard, facts)
    archive_digest = _archive_sha256(descriptor, identity, guard)
    _ensure_unchanged(descriptor, identity)
    _ensure_path_identity(path, identity)
    if expanded != sum(
        member.entry.size for member in members
        if member.entry.kind is EntryKind.FILE
    ):
        raise ZipOverlaySafetyError("The ZIP expanded-size accounting is inconsistent")
    return ZipOverlayPlan(
        path, identity, members, expanded, archive_digest,
        _catalog_digest(members),
    )


def build_zip_overlay_plan(
    archive: Path,
    *,
    cancel_check: CancelCheck | None = None,
    timeout_seconds: float = ZIP_OPERATION_TIMEOUT_SECONDS,
) -> ZipOverlayPlan:
    """Inspect and cryptographically bind one additive ZIP overlay."""

    guard = _Guard(_deadline(timeout_seconds), cancel_check)
    guard.check()
    path = Path(os.path.abspath(os.fspath(archive)))
    descriptor, identity = _open_bound_archive(path)
    try:
        return _inspect_open_archive(path, descriptor, identity, guard)
    finally:
        os.close(descriptor)


def _validate_plan_model(plan: ZipOverlayPlan) -> None:
    """Re-run frozen-model constructors so numerically equal forgeries fail."""

    if type(plan.identity) is not ZipOverlayIdentity or type(plan.members) is not tuple:
        raise ZipOverlaySafetyError("The ZIP overlay plan model is invalid")
    try:
        identity = ZipOverlayIdentity(
            plan.identity.device,
            plan.identity.inode,
            plan.identity.size,
            plan.identity.modified_ns,
            plan.identity.changed_ns,
            plan.identity.link_count,
        )
        members: list[ZipOverlayMember] = []
        for member in plan.members:
            if type(member) is not ZipOverlayMember:
                raise ValueError("ZIP overlay member type is invalid")
            entry = ArchiveEntry(
                member.entry.path,
                member.entry.size,
                member.entry.kind,
                member.entry.link_target,
                member.entry.modified_ns,
            )
            members.append(ZipOverlayMember(
                entry,
                member.archive_name,
                member.crc32,
                member.compressed_size,
                member.compression,
                member.flag_bits,
                member.external_attr,
                member.header_offset,
                member.version_made_by,
                member.extract_version,
            ))
        rebound = ZipOverlayPlan(
            plan.archive,
            identity,
            tuple(members),
            plan.content_bytes,
            plan.archive_sha256,
            plan.catalog_digest,
        )
        if rebound != plan or _validate_namespace(
            tuple(member.entry for member in members)
        ) != tuple(member.entry for member in members):
            raise ValueError("ZIP overlay plan model is inconsistent")
    except (AttributeError, TypeError, ValueError) as error:
        raise ZipOverlaySafetyError("The ZIP overlay plan model is invalid") from error


def validate_zip_overlay_plan(
    plan: ZipOverlayPlan,
    *,
    cancel_check: CancelCheck | None = None,
    timeout_seconds: float = ZIP_OPERATION_TIMEOUT_SECONDS,
) -> None:
    """Rebuild every bound fact and require exact equality with ``plan``."""

    if not isinstance(plan, ZipOverlayPlan):
        raise ZipOverlaySafetyError("The ZIP overlay plan has an invalid type")
    _validate_plan_model(plan)
    rebuilt = build_zip_overlay_plan(
        plan.archive, cancel_check=cancel_check, timeout_seconds=timeout_seconds,
    )
    if rebuilt != plan:
        raise ZipOverlayChanged("The ZIP overlay no longer matches its plan")


def _open_directory(parent_fd: int, component: str, root_device: int) -> int:
    try:
        descriptor = os.open(component, _DIR_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            os.mkdir(component, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        try:
            descriptor = os.open(component, _DIR_FLAGS, dir_fd=parent_fd)
        except OSError as error:
            raise ZipOverlaySafetyError("A ZIP overlay parent is unsafe") from error
    except OSError as error:
        raise ZipOverlaySafetyError("A ZIP overlay parent is unsafe") from error
    status = os.fstat(descriptor)
    if not stat.S_ISDIR(status.st_mode) or status.st_dev != root_device:
        os.close(descriptor)
        raise ZipOverlaySafetyError("A ZIP overlay parent left the staging filesystem")
    return descriptor


def _parent_fd(
    root_fd: int,
    parts: tuple[str, ...],
    root_device: int,
    guard: _Guard,
) -> int:
    current = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            guard.check()
            following = _open_directory(current, component, root_device)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


def _validate_targets(
    members: Sequence[ZipOverlayMember],
    targets: Sequence[ArchiveEntry],
) -> tuple[ArchiveEntry, ...]:
    safe = _validate_namespace(tuple(targets))
    if len(safe) != len(members):
        raise ZipOverlaySafetyError("The ZIP overlay target catalog is misaligned")
    for member, target in zip(members, safe):
        source_parts = tuple(PurePosixPath(member.entry.path).parts)
        target_parts = tuple(PurePosixPath(target.path).parts)
        if (
            target.kind is not member.entry.kind
            or target.size != member.entry.size
            or _path_key(target_parts) != _path_key(source_parts)
        ):
            raise ZipOverlaySafetyError(
                "A ZIP overlay target does not match its planned member"
            )
    return safe


def apply_zip_overlay(
    plan: ZipOverlayPlan,
    root: Path,
    target_entries: Sequence[ArchiveEntry],
    *,
    cancel_check: CancelCheck | None = None,
    progress: Callable[[ZipOverlayProgress], None] = lambda _update: None,
    timeout_seconds: float = ZIP_OPERATION_TIMEOUT_SECONDS,
) -> ZipOverlayResult:
    """Add planned members to an existing private root without overwriting.

    ``target_entries`` is aligned one-to-one with ``plan.members`` and may only
    change the exact spelling of path components, never their case-insensitive
    NFC identity.  Archive names select compressed data only.
    """

    guard = _Guard(_deadline(timeout_seconds), cancel_check)
    guard.check()
    if not isinstance(plan, ZipOverlayPlan):
        raise ZipOverlaySafetyError("The ZIP overlay plan has an invalid type")
    _validate_plan_model(plan)
    targets = _validate_targets(plan.members, target_entries)
    descriptor, identity = _open_bound_archive(plan.archive)
    try:
        rebuilt = _inspect_open_archive(plan.archive, descriptor, identity, guard)
        if rebuilt != plan:
            raise ZipOverlayChanged("The ZIP overlay no longer matches its plan")

        root_path = Path(os.path.abspath(os.fspath(root)))
        if root_path.parent == root_path:
            raise ZipOverlaySafetyError("The filesystem root cannot be an overlay staging root")
        try:
            root_fd = os.open(root_path, _DIR_FLAGS)
        except OSError as error:
            raise ZipOverlaySafetyError("The ZIP overlay root is not a safe directory") from error
        root_status = os.fstat(root_fd)
        root_device = root_status.st_dev
        files = directories = written = 0
        reader = _DescriptorReader(descriptor, identity, guard)
        buffered = io.BufferedReader(reader, buffer_size=STREAM_CHUNK_BYTES)
        try:
            with zipfile.ZipFile(buffered, "r") as archive:
                infos = archive.infolist()
                if len(infos) != len(plan.members):
                    raise ZipOverlayChanged("The ZIP member catalog changed")
                for info, member, target in zip(infos, plan.members, targets):
                    guard.check()
                    if info.orig_filename != member.archive_name:
                        raise ZipOverlayChanged("The ZIP member catalog changed")
                    parts = tuple(PurePosixPath(target.path).parts)
                    parent_fd = _parent_fd(root_fd, parts, root_device, guard)
                    try:
                        if target.kind is EntryKind.DIRECTORY:
                            # Directory entries may still carry a compressed
                            # representation of the empty stream. Consume it to
                            # EOF so its method, size and CRC are verified too.
                            try:
                                with archive.open(info, "r") as source:
                                    directory_data = source.read(1)
                            except (
                                OSError, EOFError, ValueError, zipfile.BadZipFile,
                                RuntimeError, zlib.error,
                            ) as error:
                                raise ZipOverlaySafetyError(
                                    f"ZIP directory {member.archive_name!r} failed integrity verification"
                                ) from error
                            _ensure_unchanged(descriptor, identity)
                            guard.check()
                            if directory_data:
                                raise ZipOverlaySafetyError(
                                    f"ZIP directory {member.archive_name!r} is not empty"
                                )
                            directory_fd = _open_directory(parent_fd, parts[-1], root_device)
                            os.close(directory_fd)
                            directories += 1
                            continue
                        try:
                            output_fd = os.open(
                                parts[-1], _WRITE_FLAGS, 0o600, dir_fd=parent_fd,
                            )
                        except OSError as error:
                            raise ZipOverlaySafetyError(
                                f"ZIP overlay target already exists or is unsafe: {target.path!r}"
                            ) from error
                        member_written = 0
                        try:
                            try:
                                source = archive.open(info, "r")
                            except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
                                raise ZipOverlaySafetyError(
                                    f"Could not open ZIP member {member.archive_name!r}"
                                ) from error
                            with source:
                                while True:
                                    guard.check()
                                    try:
                                        block = source.read(STREAM_CHUNK_BYTES)
                                    except (
                                        OSError, EOFError, ValueError,
                                        zipfile.BadZipFile, zlib.error,
                                    ) as error:
                                        raise ZipOverlaySafetyError(
                                            f"ZIP member {member.archive_name!r} failed integrity verification"
                                        ) from error
                                    _ensure_unchanged(descriptor, identity)
                                    guard.check()
                                    if not block:
                                        break
                                    if len(block) > target.size - member_written:
                                        raise ZipOverlaySafetyError(
                                            f"ZIP member {member.archive_name!r} exceeded its planned size"
                                        )
                                    view = memoryview(block)
                                    while view:
                                        guard.check()
                                        count = os.write(output_fd, view)
                                        if count <= 0:
                                            raise ZipOverlayError("Could not write the ZIP overlay member")
                                        view = view[count:]
                                    member_written += len(block)
                                    progress(ZipOverlayProgress(
                                        target.path, member_written, target.size,
                                        written + member_written, plan.content_bytes,
                                    ))
                            if member_written != target.size:
                                raise ZipOverlaySafetyError(
                                    f"ZIP member {member.archive_name!r} produced the wrong size"
                                )
                            os.fsync(output_fd)
                            status = os.fstat(output_fd)
                            if (
                                not stat.S_ISREG(status.st_mode)
                                or status.st_size != target.size
                                or status.st_nlink != 1
                                or status.st_dev != root_device
                            ):
                                raise ZipOverlaySafetyError(
                                    "A ZIP overlay output file failed identity validation"
                                )
                        finally:
                            os.close(output_fd)
                        written += member_written
                        files += 1
                    finally:
                        os.close(parent_fd)
            _ensure_unchanged(descriptor, identity)
            _ensure_path_identity(plan.archive, identity)
            guard.check()
        except ZipOverlayError:
            raise
        except (OSError, ValueError, zipfile.BadZipFile, NotImplementedError) as error:
            raise ZipOverlaySafetyError("The ZIP overlay could not be applied safely") from error
        finally:
            buffered.close()
            os.close(root_fd)
        if written != plan.content_bytes:
            raise ZipOverlaySafetyError("ZIP overlay extraction accounting is inconsistent")
        return ZipOverlayResult(
            files, directories, written, plan.archive_sha256, plan.catalog_digest,
        )
    finally:
        os.close(descriptor)
