from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Checksum-pinned official FreeDOS USB-image downloads.

FreeDOS publishes HTTPS downloads and a checksum page, but no detached signed
manifest.  ISOpropyl therefore treats its bundled, reviewed archive digest as
the trust anchor and uses the live official checksum row only as corroboration.
The downloaded ZIP is never executed or generically extracted: its complete
catalog must match, and only the exact disk-image member is streamed into a
private file and independently hash-verified before no-overwrite publication.
"""

import errno
import hashlib
import json
import os
import re
import stat
import struct
import threading
import time
import urllib.request
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from . import verified_download as _verified


CATALOG_VERSION = 1
READ_SIZE = 1024 * 1024
MAX_METADATA_SIZE = 64 * 1024
FREE_SPACE_RESERVE = 64 * 1024 * 1024
MAX_DOWNLOAD_TIMEOUT = 24 * 60 * 60
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,127}\Z")
SAFE_FILENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
CRC32_RE = re.compile(r"[0-9a-f]{8}\Z")
_STAGE_RE = re.compile(r"\.isopropyl-freedos-[0-9a-f]{32}\Z")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
_DIRECTORY_FLAGS |= getattr(os, "O_NOFOLLOW", 0)
_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
_OUTPUT_FLAGS = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)


class FreeDosDownloadCatalogError(ValueError):
    """The bundled FreeDOS catalog is malformed or the selection is unbound."""


class FreeDosDownloadError(_verified.VerifiedDownloadError):
    """A curated FreeDOS image could not be prepared safely."""


class FreeDosDownloadCancelled(
    FreeDosDownloadError, _verified.VerifiedDownloadCancelled,
):
    """The caller cancelled a FreeDOS download before publication."""


_FREEDOS_POLICY = _verified.DownloadErrorPolicy(
    error_type=FreeDosDownloadError,
    cancelled_type=FreeDosDownloadCancelled,
    subject="FreeDOS image",
    hash_authority="project-pinned official",
)


class DownloadResponse(Protocol):
    headers: object

    def read(self, size: int = -1) -> bytes: ...
    def geturl(self) -> str: ...
    def close(self) -> None: ...
    def getcode(self) -> int: ...


OpenUrl = Callable[..., DownloadResponse]
Progress = Callable[[int, int], None]
CancelCheck = Callable[[], None]


@dataclass(frozen=True)
class FreeDosArchiveMember:
    name: str
    role: str
    size: int
    compressed_size: int
    crc32: str
    sha256: str
    unix_mode: int


@dataclass(frozen=True)
class FreeDosImageRelease:
    id: str
    project: str
    release: str
    edition: str
    architecture: str
    firmware: str
    archive_filename: str
    archive_size: int
    archive_sha256: str
    archive_url: str
    image_filename: str
    image_size: int
    image_sha256: str
    partition_type: int
    partition_start_lba: int
    partition_sectors: int
    volume_label: str
    filesystem: str
    hashes_url: str
    provenance_url: str
    release_report_url: str
    allowed_hosts: tuple[str, ...]
    members: tuple[FreeDosArchiveMember, ...]


@dataclass(frozen=True)
class DownloadedFreeDosImage:
    path: Path
    release_id: str
    size: int
    sha256: str
    archive_sha256: str
    identity: tuple[int, int, int, int]


@dataclass(frozen=True)
class _ArchiveArtifact:
    id: str
    filename: str
    size: int
    sha256: str


def _exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected:
        raise FreeDosDownloadCatalogError(f"{label} has unknown or missing fields")
    return value


def _strict_https_url(value: object, allowed_hosts: tuple[str, ...]) -> str:
    if type(value) is not str:
        raise FreeDosDownloadCatalogError("Catalog URLs must be strings")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise FreeDosDownloadCatalogError("Catalog contains an unsafe HTTPS URL") from error
    host = (parsed.hostname or "").casefold().rstrip(".")
    if (
        parsed.scheme != "https" or not host or parsed.username is not None
        or parsed.password is not None or port not in (None, 443)
        or parsed.query or parsed.fragment or not parsed.path.startswith("/")
        or host not in allowed_hosts
    ):
        raise FreeDosDownloadCatalogError("Catalog contains an unsafe HTTPS URL")
    return value


def _safe_display_string(value: object, label: str) -> str:
    if (
        type(value) is not str or not value or len(value) > 128
        or any(ord(character) < 0x20 for character in value)
    ):
        raise FreeDosDownloadCatalogError(f"Catalog {label} is invalid")
    return value


def _load_member(raw: object) -> FreeDosArchiveMember:
    fields = set(FreeDosArchiveMember.__dataclass_fields__)
    item = _exact_keys(raw, fields, "FreeDOS archive member")
    try:
        member = FreeDosArchiveMember(**item)  # type: ignore[arg-type]
    except TypeError as error:
        raise FreeDosDownloadCatalogError("FreeDOS member fields are invalid") from error
    if (
        type(member.name) is not str or not SAFE_FILENAME_RE.fullmatch(member.name)
        or type(member.role) is not str
        or member.role not in {"disk-image", "vmdk-descriptor", "readme"}
        or type(member.size) is not int or member.size <= 0
        or type(member.compressed_size) is not int
        or not 0 < member.compressed_size <= member.size
        or type(member.crc32) is not str or not CRC32_RE.fullmatch(member.crc32)
        or type(member.sha256) is not str or not SHA256_RE.fullmatch(member.sha256)
        or type(member.unix_mode) is not int
        or not stat.S_ISREG(member.unix_mode)
        or stat.S_IMODE(member.unix_mode) not in {0o644, 0o755}
    ):
        raise FreeDosDownloadCatalogError("FreeDOS member metadata is invalid")
    return member


def load_freedos_image_catalog(path: Path | None = None) -> tuple[FreeDosImageRelease, ...]:
    """Load and strictly validate the bundled, network-inactive catalog."""

    if path is None:
        text = resources.files("isopropyl").joinpath(
            "data/freedos-images-v1.json"
        ).read_text(encoding="utf-8")
    else:
        text = path.read_text(encoding="utf-8")
    try:
        root = json.loads(text)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise FreeDosDownloadCatalogError("FreeDOS catalog is not valid JSON") from error
    root = _exact_keys(root, {"catalog_version", "images"}, "FreeDOS catalog")
    if type(root["catalog_version"]) is not int or root["catalog_version"] != CATALOG_VERSION:
        raise FreeDosDownloadCatalogError("Unsupported FreeDOS catalog version")
    if type(root["images"]) is not list or not root["images"]:
        raise FreeDosDownloadCatalogError("FreeDOS catalog must contain images")

    release_fields = set(FreeDosImageRelease.__dataclass_fields__) - {
        "allowed_hosts", "members",
    }
    expected_fields = release_fields | {"allowed_hosts", "members"}
    releases: list[FreeDosImageRelease] = []
    seen_ids: set[str] = set()
    seen_outputs: set[str] = set()
    for raw in root["images"]:
        item = _exact_keys(raw, expected_fields, "FreeDOS image")
        hosts_raw = item["allowed_hosts"]
        if (
            type(hosts_raw) is not list or not hosts_raw
            or any(type(host) is not str for host in hosts_raw)
        ):
            raise FreeDosDownloadCatalogError("FreeDOS host allowlist is invalid")
        hosts = tuple(host.casefold().rstrip(".") for host in hosts_raw)
        if hosts != tuple(sorted(set(hosts))) or any(
            not host or ":" in host or "/" in host or "@" in host for host in hosts
        ):
            raise FreeDosDownloadCatalogError("FreeDOS host allowlist is unsafe")
        members_raw = item["members"]
        if type(members_raw) is not list or len(members_raw) != 3:
            raise FreeDosDownloadCatalogError("FreeDOS archive must describe three members")
        members = tuple(_load_member(member) for member in members_raw)
        values = {key: value for key, value in item.items() if key not in {"allowed_hosts", "members"}}
        values["allowed_hosts"] = hosts
        values["members"] = members
        try:
            release = FreeDosImageRelease(**values)  # type: ignore[arg-type]
        except TypeError as error:
            raise FreeDosDownloadCatalogError("FreeDOS image fields are invalid") from error

        if (
            type(release.id) is not str or not SAFE_ID_RE.fullmatch(release.id)
            or release.id in seen_ids
            or release.image_filename in seen_outputs
            or any(
                not _safe_display_string(value, label)
                for value, label in (
                    (release.project, "project"), (release.release, "release"),
                    (release.edition, "edition"),
                    (release.architecture, "architecture"),
                    (release.firmware, "firmware"),
                )
            )
            or release.project != "FreeDOS"
            or type(release.archive_filename) is not str
            or not SAFE_FILENAME_RE.fullmatch(release.archive_filename)
            or type(release.image_filename) is not str
            or not SAFE_FILENAME_RE.fullmatch(release.image_filename)
            or not release.archive_filename.endswith(".zip")
            or not release.image_filename.endswith(".img")
            or type(release.archive_size) is not int or release.archive_size <= 0
            or type(release.image_size) is not int or release.image_size <= 0
            or release.image_size % 512
            or type(release.archive_sha256) is not str
            or not SHA256_RE.fullmatch(release.archive_sha256)
            or type(release.image_sha256) is not str
            or not SHA256_RE.fullmatch(release.image_sha256)
            or type(release.partition_type) is not int
            or not 1 <= release.partition_type <= 255
            or type(release.partition_start_lba) is not int
            or release.partition_start_lba <= 0
            or type(release.partition_sectors) is not int
            or release.partition_sectors <= 0
            or release.partition_start_lba + release.partition_sectors
            > release.image_size // 512
            or type(release.volume_label) is not str
            or not 1 <= len(release.volume_label) <= 11
            or not release.volume_label.isascii()
            or release.filesystem not in {"FAT16", "FAT32"}
        ):
            raise FreeDosDownloadCatalogError("FreeDOS image metadata is invalid")
        _strict_https_url(release.archive_url, hosts)
        _strict_https_url(release.hashes_url, hosts)
        _strict_https_url(release.provenance_url, hosts)
        _strict_https_url(release.release_report_url, hosts)
        if Path(urlsplit(release.archive_url).path).name != release.archive_filename:
            raise FreeDosDownloadCatalogError("FreeDOS archive URL filename is inconsistent")
        names = tuple(member.name for member in members)
        roles = tuple(member.role for member in members)
        if (
            len(set(names)) != 3 or len({name.casefold() for name in names}) != 3
            or set(roles) != {"disk-image", "vmdk-descriptor", "readme"}
        ):
            raise FreeDosDownloadCatalogError("FreeDOS member roles or names are ambiguous")
        image_members = tuple(member for member in members if member.role == "disk-image")
        if len(image_members) != 1:
            raise FreeDosDownloadCatalogError("FreeDOS archive has no unique disk image")
        image_member = image_members[0]
        if (
            image_member.name != release.image_filename
            or image_member.size != release.image_size
            or image_member.sha256 != release.image_sha256
            or sum(member.compressed_size for member in members) >= release.archive_size
        ):
            raise FreeDosDownloadCatalogError("FreeDOS disk-image metadata is inconsistent")
        seen_ids.add(release.id)
        seen_outputs.add(release.image_filename)
        releases.append(release)
    return tuple(releases)


@lru_cache(maxsize=1)
def available_freedos_images() -> tuple[FreeDosImageRelease, ...]:
    return load_freedos_image_catalog()


def _check_cancel(
    cancel_event: threading.Event, cancel_check: CancelCheck | None,
) -> None:
    _verified.check_cancel(
        cancel_event, cancel_check, policy=_FREEDOS_POLICY,
    )


def _deadline_check(deadline: float) -> None:
    _verified.deadline_check(deadline, policy=_FREEDOS_POLICY)


def _verify_official_hash_row(
    release: FreeDosImageRelease,
    opener: OpenUrl,
    *,
    deadline: float,
    cancel_event: threading.Event,
    cancel_check: CancelCheck | None,
) -> None:
    request = urllib.request.Request(
        release.hashes_url,
        headers={
            "Accept": "text/plain",
            "Accept-Encoding": "identity",
            "User-Agent": "ISOpropyl/0.1",
        },
    )
    response = _verified.open_response(
        opener, request, deadline=deadline, cancel_event=cancel_event,
        cancel_check=cancel_check, policy=_FREEDOS_POLICY,
    )
    try:
        _verified.validate_response_url(
            response, release.hashes_url, policy=_FREEDOS_POLICY,
        )
        if _verified.response_status(response, policy=_FREEDOS_POLICY) != 200:
            raise FreeDosDownloadError("FreeDOS verification page returned a non-success status")
        content_encoding = _verified.response_header(response, "Content-Encoding")
        if content_encoding not in (None, "", "identity"):
            raise FreeDosDownloadError(
                "FreeDOS verification page used an unexpected content encoding"
            )
        content_length = _verified.parse_decimal_header(
            _verified.response_header(response, "Content-Length"),
            "Content-Length", policy=_FREEDOS_POLICY,
        )
        if not 0 < content_length <= MAX_METADATA_SIZE:
            raise FreeDosDownloadError("FreeDOS verification page exceeds its size limit")
        body = bytearray()
        for block in _verified.response_blocks(
            response, deadline=deadline, cancel_event=cancel_event,
            cancel_check=cancel_check, policy=_FREEDOS_POLICY,
        ):
            body.extend(block)
            if len(body) > content_length or len(body) > MAX_METADATA_SIZE:
                raise FreeDosDownloadError("FreeDOS verification page exceeded its declared size")
        if len(body) != content_length:
            raise FreeDosDownloadError("FreeDOS verification page ended at an unexpected size")
    finally:
        try:
            response.close()
        except Exception:
            pass
    try:
        text = bytes(body).decode("ascii")
    except UnicodeDecodeError as error:
        raise FreeDosDownloadError("FreeDOS verification page is not strict ASCII") from error
    lines = text.replace("\r\n", "\n").splitlines()
    sha256_markers = [index for index, line in enumerate(lines) if line == "sha256sum:"]
    sha512_markers = [index for index, line in enumerate(lines) if line == "sha512sum:"]
    if (
        len(sha256_markers) != 1 or len(sha512_markers) != 1
        or sha256_markers[0] >= sha512_markers[0]
    ):
        raise FreeDosDownloadError("FreeDOS verification page has an ambiguous checksum section")
    rows: list[str] = []
    row_pattern = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]{0,254})\Z")
    for line in lines[sha256_markers[0] + 1:sha512_markers[0]]:
        match = row_pattern.fullmatch(line)
        if match is not None and match.group(2) == release.archive_filename:
            rows.append(match.group(1))
    if rows != [release.archive_sha256]:
        raise FreeDosDownloadError(
            "FreeDOS no longer publishes the cataloged archive SHA-256"
        )


def _ensure_free_space(parent_fd: int, required: int) -> None:
    try:
        space = os.fstatvfs(parent_fd)
    except OSError as error:
        raise FreeDosDownloadError(
            f"Could not determine destination free space: {_verified.safe_error_detail(error)}"
        ) from error
    available = space.f_bavail * space.f_frsize
    if available < required + FREE_SPACE_RESERVE:
        raise FreeDosDownloadError(
            "The destination does not have enough free space for the verified "
            "archive, extracted image, and safety reserve"
        )


def _private_stage_name(release: FreeDosImageRelease) -> str:
    digest = hashlib.sha256()
    for value in (
        release.id, release.archive_filename, str(release.archive_size),
        release.archive_sha256, release.image_filename,
        str(release.image_size), release.image_sha256,
    ):
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return f".isopropyl-freedos-{digest.hexdigest()[:32]}"


def _open_private_stage(
    parent_fd: int, release: FreeDosImageRelease,
) -> tuple[int, str, os.stat_result]:
    name = _private_stage_name(release)
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError as error:
        raise FreeDosDownloadError(
            f"Could not create private FreeDOS workspace: {_verified.safe_error_detail(error)}"
        ) from error
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        identity = os.fstat(descriptor)
    except OSError as error:
        raise FreeDosDownloadError("Private FreeDOS workspace is unsafe") from error
    if (
        not stat.S_ISDIR(identity.st_mode)
        or identity.st_uid != os.geteuid()
        or stat.S_IMODE(identity.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise FreeDosDownloadError("Private FreeDOS workspace has unsafe identity")
    return descriptor, name, identity


def _revalidate_private_stage(
    parent_fd: int, name: str, descriptor: int, identity: os.stat_result,
) -> None:
    if not _STAGE_RE.fullmatch(name):
        raise FreeDosDownloadError("Private FreeDOS workspace name is invalid")
    try:
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise FreeDosDownloadError("Private FreeDOS workspace changed") from error
    expected = (identity.st_dev, identity.st_ino)
    if (
        not stat.S_ISDIR(opened.st_mode) or not stat.S_ISDIR(named.st_mode)
        or (opened.st_dev, opened.st_ino) != expected
        or (named.st_dev, named.st_ino) != expected
        or opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        raise FreeDosDownloadError("Private FreeDOS workspace changed")


def _hash_descriptor(
    descriptor: int,
    size: int,
    *,
    deadline: float,
    cancel_event: threading.Event,
    cancel_check: CancelCheck | None,
) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        _check_cancel(cancel_event, cancel_check)
        _deadline_check(deadline)
        try:
            block = os.pread(descriptor, min(READ_SIZE, size - offset), offset)
        except OSError as error:
            raise FreeDosDownloadError(
                f"FreeDOS verification read failed: {_verified.safe_error_detail(error)}"
            ) from error
        if not block:
            raise FreeDosDownloadError("FreeDOS file changed while it was verified")
        digest.update(block)
        offset += len(block)
    return digest.hexdigest()


def _member_by_role(release: FreeDosImageRelease, role: str) -> FreeDosArchiveMember:
    matches = tuple(member for member in release.members if member.role == role)
    if len(matches) != 1:
        raise FreeDosDownloadError("FreeDOS catalog no longer has a unique disk image")
    return matches[0]


def _validate_zip_catalog(
    archive: zipfile.ZipFile, release: FreeDosImageRelease,
) -> zipfile.ZipInfo:
    if archive.comment != b"":
        raise FreeDosDownloadError("FreeDOS archive has an unexpected comment")
    try:
        infos = tuple(archive.infolist())
    except (OSError, zipfile.BadZipFile) as error:
        raise FreeDosDownloadError("FreeDOS archive catalog could not be read") from error
    if len(infos) != len(release.members):
        raise FreeDosDownloadError("FreeDOS archive has unexpected or missing members")
    names = tuple(info.filename for info in infos)
    if (
        names != tuple(member.name for member in release.members)
        or len(set(names)) != len(names)
        or len({name.casefold() for name in names}) != len(names)
    ):
        raise FreeDosDownloadError("FreeDOS archive member names do not match the catalog")
    selected: zipfile.ZipInfo | None = None
    for info, expected in zip(infos, release.members, strict=True):
        unix_mode = info.external_attr >> 16
        if (
            info.filename != expected.name
            or info.is_dir() or "/" in info.filename or "\\" in info.filename
            or info.compress_type != zipfile.ZIP_DEFLATED
            or info.flag_bits & 0x1
            or info.create_system != 3
            or not stat.S_ISREG(unix_mode)
            or unix_mode != expected.unix_mode
            or info.file_size != expected.size
            or info.compress_size != expected.compressed_size
            or info.CRC != int(expected.crc32, 16)
        ):
            raise FreeDosDownloadError(
                f"FreeDOS archive member {expected.name} does not match its exact catalog"
            )
        if expected.role == "disk-image":
            selected = info
    if selected is None:
        raise FreeDosDownloadError("FreeDOS archive contains no selected disk image")
    return selected


def _write_all(descriptor: int, data: bytes, offset: int) -> None:
    written = 0
    while written < len(data):
        try:
            count = os.pwrite(descriptor, data[written:], offset + written)
        except InterruptedError:
            continue
        except OSError as error:
            raise FreeDosDownloadError(
                f"FreeDOS extraction write failed: {_verified.safe_error_detail(error)}"
            ) from error
        if count <= 0:
            raise FreeDosDownloadError("FreeDOS extraction made no write progress")
        written += count


def _extract_disk_member(
    archive_fd: int,
    output_fd: int,
    release: FreeDosImageRelease,
    progress: Progress | None,
    *,
    deadline: float,
    cancel_event: threading.Event,
    cancel_check: CancelCheck | None,
) -> None:
    try:
        with os.fdopen(os.dup(archive_fd), "rb", closefd=True) as stream:
            with zipfile.ZipFile(stream, "r") as archive:
                selected = _validate_zip_catalog(archive, release)
                try:
                    source = archive.open(selected, "r")
                except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                    raise FreeDosDownloadError("FreeDOS disk image could not be opened") from error
                digest = hashlib.sha256()
                extracted = 0
                with source:
                    while True:
                        _check_cancel(cancel_event, cancel_check)
                        _deadline_check(deadline)
                        try:
                            block = source.read(READ_SIZE)
                        except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                            raise FreeDosDownloadError("FreeDOS disk image extraction failed") from error
                        if not block:
                            break
                        if type(block) is not bytes or extracted + len(block) > release.image_size:
                            raise FreeDosDownloadError("FreeDOS disk image exceeded its size limit")
                        _write_all(output_fd, block, extracted)
                        digest.update(block)
                        extracted += len(block)
                        if progress is not None:
                            progress(
                                release.archive_size + extracted,
                                release.archive_size + release.image_size,
                            )
    except FreeDosDownloadError:
        raise
    except (OSError, EOFError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise FreeDosDownloadError("FreeDOS archive is malformed or truncated") from error
    if extracted != release.image_size:
        raise FreeDosDownloadError("FreeDOS disk image ended at an unexpected size")
    if digest.hexdigest() != release.image_sha256:
        raise FreeDosDownloadError("FreeDOS disk image failed its reviewed inner SHA-256")


def _validate_disk_structure(descriptor: int, release: FreeDosImageRelease) -> None:
    try:
        mbr = os.pread(descriptor, 512, 0)
        boot_sector = os.pread(descriptor, 512, release.partition_start_lba * 512)
    except OSError as error:
        raise FreeDosDownloadError("FreeDOS disk structure could not be read") from error
    if len(mbr) != 512 or mbr[510:512] != b"\x55\xaa":
        raise FreeDosDownloadError("FreeDOS image has no valid MBR signature")
    entries = tuple(mbr[446 + index * 16:462 + index * 16] for index in range(4))
    first = entries[0]
    if (
        first[0] != 0x80 or first[4] != release.partition_type
        or struct.unpack_from("<I", first, 8)[0] != release.partition_start_lba
        or struct.unpack_from("<I", first, 12)[0] != release.partition_sectors
        or any(entry != bytes(16) for entry in entries[1:])
    ):
        raise FreeDosDownloadError("FreeDOS image partition layout is not the reviewed layout")
    if len(boot_sector) != 512 or boot_sector[510:512] != b"\x55\xaa":
        raise FreeDosDownloadError("FreeDOS FAT boot sector is invalid")
    bytes_per_sector = struct.unpack_from("<H", boot_sector, 11)[0]
    if bytes_per_sector != 512:
        raise FreeDosDownloadError("FreeDOS FAT geometry is not 512-byte-sector media")
    if release.filesystem == "FAT16":
        label = boot_sector[43:54].decode("ascii", "strict").rstrip()
        filesystem = boot_sector[54:62].decode("ascii", "strict").rstrip()
    else:
        label = boot_sector[71:82].decode("ascii", "strict").rstrip()
        filesystem = boot_sector[82:90].decode("ascii", "strict").rstrip()
    if label != release.volume_label or filesystem != release.filesystem:
        raise FreeDosDownloadError("FreeDOS FAT identity is not the reviewed identity")


def _final_verify_before_publish(
    output_fd: int,
    archive_fd: int,
    stage_fd: int,
    parent_fd: int,
    stage_name: str,
    stage_identity: os.stat_result,
    archive_identity: os.stat_result,
    release: FreeDosImageRelease,
    destination: Path,
    *,
    deadline: float,
    cancel_event: threading.Event,
    cancel_check: CancelCheck | None,
) -> tuple[os.stat_result, str]:
    before = os.fstat(output_fd)
    try:
        named = os.stat("image.partial", dir_fd=stage_fd, follow_symlinks=False)
    except OSError as error:
        raise FreeDosDownloadError("Private FreeDOS disk image changed") from error
    if (
        not _verified.same_file(before, named)
        or not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
        or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size != release.image_size
    ):
        raise FreeDosDownloadError("Private FreeDOS disk image has unsafe identity")
    digest = _hash_descriptor(
        output_fd, release.image_size, deadline=deadline,
        cancel_event=cancel_event, cancel_check=cancel_check,
    )
    if digest != release.image_sha256:
        raise FreeDosDownloadError("FreeDOS disk image changed during final verification")
    _validate_disk_structure(output_fd, release)
    after = os.fstat(output_fd)
    named_after = os.stat("image.partial", dir_fd=stage_fd, follow_symlinks=False)
    if not _verified.same_file(before, after) or not _verified.same_file(after, named_after):
        raise FreeDosDownloadError("FreeDOS disk image changed during final verification")
    archive_after = os.fstat(archive_fd)
    if not _verified.same_file(archive_identity, archive_after):
        raise FreeDosDownloadError("Verified FreeDOS archive changed during extraction")
    _verified.revalidate_directory(
        destination.parent, parent_fd, policy=_FREEDOS_POLICY,
    )
    _revalidate_private_stage(
        parent_fd, stage_name, stage_fd, stage_identity,
    )
    _verified.assert_destination_absent(
        parent_fd, destination.name, policy=_FREEDOS_POLICY,
    )
    _check_cancel(cancel_event, cancel_check)
    _deadline_check(deadline)
    return after, digest


def _safe_unlink(
    directory_fd: int, name: str, expected: tuple[int, int] | None,
) -> bool:
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            expected is not None and (current.st_dev, current.st_ino) != expected
        ) or not stat.S_ISREG(current.st_mode) or current.st_uid != os.geteuid():
            return False
        if current.st_nlink not in {1, 2}:
            return False
        os.unlink(name, dir_fd=directory_fd)
        return True
    except OSError:
        return False


def _list_directory(directory_fd: int) -> list[str]:
    """List through a fresh open file description, not a stale directory cursor."""

    scan_fd = -1
    try:
        scan_fd = os.open(".", _DIRECTORY_FLAGS, dir_fd=directory_fd)
        return os.listdir(scan_fd)
    finally:
        if scan_fd >= 0:
            os.close(scan_fd)


def _cleanup_download_stage(stage_fd: int, name: str) -> bool:
    """Remove one verified-download resume directory only when structurally safe."""

    if not _verified.is_resume_stage_name(name):
        return False
    child_fd = -1
    try:
        child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=stage_fd)
        status = os.fstat(child_fd)
        if (
            not stat.S_ISDIR(status.st_mode) or status.st_uid != os.geteuid()
            or stat.S_IMODE(status.st_mode) != 0o700
        ):
            return False
        entries = _list_directory(child_fd)
        if entries not in ([], ["partial"]):
            return False
        if entries:
            partial = os.stat("partial", dir_fd=child_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(partial.st_mode) or partial.st_uid != os.geteuid()
                or partial.st_nlink != 1 or stat.S_IMODE(partial.st_mode) != 0o600
            ):
                return False
            os.unlink("partial", dir_fd=child_fd)
        os.close(child_fd)
        child_fd = -1
        os.rmdir(name, dir_fd=stage_fd)
        return True
    except OSError:
        return False
    finally:
        if child_fd >= 0:
            try:
                os.close(child_fd)
            except OSError:
                pass


def _validate_download_stage(stage_fd: int, name: str) -> None:
    if not _verified.is_resume_stage_name(name):
        raise FreeDosDownloadError("FreeDOS resume workspace name is invalid")
    child_fd = -1
    try:
        child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=stage_fd)
        status = os.fstat(child_fd)
        if (
            not stat.S_ISDIR(status.st_mode) or status.st_uid != os.geteuid()
            or stat.S_IMODE(status.st_mode) != 0o700
        ):
            raise FreeDosDownloadError("FreeDOS resume workspace has unsafe identity")
        entries = _list_directory(child_fd)
        if entries not in ([], ["partial"]):
            raise FreeDosDownloadError("FreeDOS resume workspace has unexpected entries")
        if entries:
            partial = os.stat("partial", dir_fd=child_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(partial.st_mode) or partial.st_uid != os.geteuid()
                or partial.st_nlink != 1 or stat.S_IMODE(partial.st_mode) != 0o600
            ):
                raise FreeDosDownloadError("FreeDOS resume partial has unsafe identity")
    except FreeDosDownloadError:
        raise
    except OSError as error:
        raise FreeDosDownloadError("FreeDOS resume workspace is unsafe") from error
    finally:
        if child_fd >= 0:
            os.close(child_fd)


def _cleanup_private_stage(
    parent_fd: int,
    stage_fd: int,
    stage_name: str,
    stage_identity: os.stat_result,
    archive_name: str,
    archive_expected: tuple[int, int] | None,
    output_expected: tuple[int, int] | None,
    *,
    remove_download_state: bool,
    remove_archive: bool = False,
) -> None:
    try:
        _revalidate_private_stage(
            parent_fd, stage_name, stage_fd, stage_identity,
        )
    except FreeDosDownloadError:
        return
    for name in tuple(_list_directory(stage_fd)):
        if name == archive_name and (remove_download_state or remove_archive):
            _safe_unlink(stage_fd, name, archive_expected)
        elif name == "image.partial":
            _safe_unlink(stage_fd, name, output_expected)
        elif _verified.is_resume_stage_name(name) and remove_download_state:
            _cleanup_download_stage(stage_fd, name)
    try:
        if not _list_directory(stage_fd):
            os.rmdir(stage_name, dir_fd=parent_fd)
    except OSError:
        pass
    try:
        os.fsync(parent_fd)
    except OSError:
        pass


class FreeDosUsbDownloader:
    """Download and extract one exact official FreeDOS USB image."""

    def __init__(self, cancel_event: threading.Event | None = None) -> None:
        self._cancel_event = cancel_event or threading.Event()

    @property
    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def cancel(self) -> None:
        self._cancel_event.set()

    def download(
        self,
        release: FreeDosImageRelease,
        destination: Path,
        progress: Progress | None = None,
        *,
        cancel_check: CancelCheck | None = None,
        overall_timeout: float = 6 * 60 * 60,
        opener: OpenUrl = _verified.default_urlopen,
    ) -> DownloadedFreeDosImage:
        catalog = available_freedos_images()
        if (
            type(release) is not FreeDosImageRelease
            or not any(release is item for item in catalog)
        ):
            raise FreeDosDownloadCatalogError(
                "FreeDOS release is not an exact catalog entry"
            )
        if (
            isinstance(overall_timeout, bool)
            or not isinstance(overall_timeout, (int, float))
            or not 0 < overall_timeout <= MAX_DOWNLOAD_TIMEOUT
        ):
            raise ValueError("FreeDOS timeout must be between 0 and 24 hours")
        native_path_type = type(Path())
        if type(destination) is not native_path_type:
            raise ValueError("FreeDOS destination must be an exact native pathlib.Path")
        if not destination.is_absolute():
            raise ValueError("FreeDOS destination must be absolute")
        if destination.name != release.image_filename:
            raise ValueError("FreeDOS destination must retain the exact image filename")

        deadline = time.monotonic() + float(overall_timeout)
        parent_fd = stage_fd = archive_fd = output_fd = -1
        stage_name = ""
        stage_identity: os.stat_result | None = None
        archive_identity: os.stat_result | None = None
        output_identity: os.stat_result | None = None
        discard_archive = False
        committed = False
        try:
            parent_fd = _verified.open_absolute_directory(
                destination.parent, policy=_FREEDOS_POLICY,
            )
            _verified.assert_destination_absent(
                parent_fd, destination.name, policy=_FREEDOS_POLICY,
            )
            _check_cancel(self._cancel_event, cancel_check)
            stage_fd, stage_name, stage_identity = _open_private_stage(
                parent_fd, release,
            )
            stage_path = destination.parent / stage_name
            artifact = _ArchiveArtifact(
                f"{release.id}.archive", release.archive_filename,
                release.archive_size, release.archive_sha256,
            )

            def authorize_source(
                selected_opener: OpenUrl,
                selected_deadline: float,
                cancel_event: threading.Event,
                selected_cancel_check: CancelCheck | None,
            ) -> _verified.ResolvedDownloadSource:
                _verify_official_hash_row(
                    release, selected_opener, deadline=selected_deadline,
                    cancel_event=cancel_event,
                    cancel_check=selected_cancel_check,
                )
                return _verified.ResolvedDownloadSource(release.archive_url)

            def download_progress(done: int, _total: int) -> None:
                if progress is not None:
                    progress(done, release.archive_size + release.image_size)

            assert stage_identity is not None
            _revalidate_private_stage(
                parent_fd, stage_name, stage_fd, stage_identity,
            )
            existing_entries = tuple(_list_directory(stage_fd))
            expected_resume_name = _verified.resume_stage_name(artifact)
            unexpected = tuple(
                entry for entry in existing_entries
                if entry not in {
                    release.archive_filename, "image.partial", expected_resume_name,
                }
            )
            if unexpected:
                raise FreeDosDownloadError("Private FreeDOS workspace has unexpected entries")
            if expected_resume_name in existing_entries:
                _validate_download_stage(stage_fd, expected_resume_name)
            if "image.partial" in existing_entries:
                stale = os.stat("image.partial", dir_fd=stage_fd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(stale.st_mode) or stale.st_uid != os.geteuid()
                    or stale.st_nlink != 1 or stat.S_IMODE(stale.st_mode) != 0o600
                ):
                    raise FreeDosDownloadError("Private FreeDOS partial image is unsafe")
                os.unlink("image.partial", dir_fd=stage_fd)

            archive_cached = release.archive_filename in existing_entries
            _ensure_free_space(
                parent_fd,
                release.image_size + (0 if archive_cached else release.archive_size),
            )
            if not archive_cached:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _deadline_check(deadline)
                archive_result = _verified.execute_verified_download(
                    artifact,
                    stage_path / release.archive_filename,
                    authorize_source,
                    download_progress if progress is not None else None,
                    cancel_event=self._cancel_event,
                    cancel_check=cancel_check,
                    overall_timeout=remaining,
                    opener=opener,
                    policy=_FREEDOS_POLICY,
                )
                if (
                    archive_result.path != stage_path / release.archive_filename
                    or archive_result.release_id != artifact.id
                    or archive_result.size != release.archive_size
                    or archive_result.sha256 != release.archive_sha256
                ):
                    raise FreeDosDownloadError("Verified FreeDOS archive result is unbound")
                _revalidate_private_stage(
                    parent_fd, stage_name, stage_fd, stage_identity,
                )
            archive_fd = os.open(
                release.archive_filename, _READ_FLAGS, dir_fd=stage_fd,
            )
            archive_identity = os.fstat(archive_fd)
            if (
                not stat.S_ISREG(archive_identity.st_mode)
                or archive_identity.st_uid != os.geteuid()
                or archive_identity.st_nlink != 1
                or stat.S_IMODE(archive_identity.st_mode) != 0o600
                or archive_identity.st_size != release.archive_size
            ):
                raise FreeDosDownloadError("Verified FreeDOS archive has unsafe identity")
            archive_digest = _hash_descriptor(
                archive_fd, release.archive_size, deadline=deadline,
                cancel_event=self._cancel_event, cancel_check=cancel_check,
            )
            if archive_digest != release.archive_sha256:
                discard_archive = True
                raise FreeDosDownloadError("Verified FreeDOS archive changed before extraction")
            if archive_cached and progress is not None:
                progress(
                    release.archive_size,
                    release.archive_size + release.image_size,
                )

            output_fd = os.open(
                "image.partial", _OUTPUT_FLAGS | os.O_CREAT | os.O_EXCL,
                0o600, dir_fd=stage_fd,
            )
            output_identity = os.fstat(output_fd)
            try:
                os.posix_fallocate(output_fd, 0, release.image_size)
            except AttributeError:
                pass
            except OSError as error:
                if error.errno not in {errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP}:
                    raise FreeDosDownloadError(
                        f"Could not allocate the complete FreeDOS image: "
                        f"{_verified.safe_error_detail(error)}"
                    ) from error
            _extract_disk_member(
                archive_fd, output_fd, release, progress,
                deadline=deadline, cancel_event=self._cancel_event,
                cancel_check=cancel_check,
            )
            os.fsync(output_fd)
            os.fsync(stage_fd)
            final, digest = _final_verify_before_publish(
                output_fd, archive_fd, stage_fd, parent_fd,
                stage_name, stage_identity, archive_identity,
                release, destination, deadline=deadline,
                cancel_event=self._cancel_event, cancel_check=cancel_check,
            )
            # This must remain the immediate operation after final verification.
            try:
                os.link(
                    f"/proc/self/fd/{output_fd}", destination.name,
                    dst_dir_fd=parent_fd, follow_symlinks=True,
                )
            except FileExistsError as error:
                raise FreeDosDownloadError(
                    "FreeDOS destination appeared and was not overwritten"
                ) from error
            committed = True
            try:
                published = os.stat(
                    destination.name, dir_fd=parent_fd, follow_symlinks=False,
                )
            except OSError as error:
                raise FreeDosDownloadError(
                    "Published FreeDOS image path could not be rebound"
                ) from error
            if (
                (
                    final.st_dev, final.st_ino, final.st_size,
                    final.st_mtime_ns,
                ) != (
                    published.st_dev, published.st_ino, published.st_size,
                    published.st_mtime_ns,
                )
                or not stat.S_ISREG(published.st_mode)
                or published.st_uid != os.geteuid()
                or published.st_size != release.image_size
            ):
                raise FreeDosDownloadError(
                    "Published FreeDOS image identity changed"
                )
            try:
                os.fsync(parent_fd)
            except OSError:
                pass
            return DownloadedFreeDosImage(
                destination, release.id, final.st_size, digest,
                release.archive_sha256,
                (
                    published.st_dev, published.st_ino, published.st_size,
                    published.st_mtime_ns,
                ),
            )
        except FreeDosDownloadCancelled:
            raise
        except FreeDosDownloadError:
            raise
        except (OSError, zipfile.BadZipFile) as error:
            raise FreeDosDownloadError(
                f"FreeDOS image preparation failed safely: {_verified.safe_error_detail(error)}"
            ) from error
        finally:
            archive_expected = (
                (archive_identity.st_dev, archive_identity.st_ino)
                if archive_identity is not None else None
            )
            output_expected = (
                (output_identity.st_dev, output_identity.st_ino)
                if output_identity is not None else None
            )
            if parent_fd >= 0 and stage_fd >= 0 and stage_identity is not None and stage_name:
                try:
                    _cleanup_private_stage(
                        parent_fd, stage_fd, stage_name, stage_identity,
                        release.archive_filename, archive_expected, output_expected,
                        remove_download_state=committed,
                        remove_archive=discard_archive,
                    )
                except Exception:
                    # Cleanup happens strictly after the publication commit point
                    # on success and must never turn a safely published image into
                    # an apparent failed or resumable download.
                    pass
            for descriptor in (output_fd, archive_fd, stage_fd, parent_fd):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass


def freedos_inspection_matches_release(
    release: FreeDosImageRelease, inspection: object,
) -> bool:
    """Require the post-download semantic profile before GUI selection."""

    from .images import ImageInspection

    return bool(
        type(release) is FreeDosImageRelease
        and isinstance(inspection, ImageInspection)
        and inspection.size == release.image_size
        and inspection.kind == "Raw disk image"
        and inspection.compression == "none"
        and inspection.has_mbr
        and not inspection.has_gpt
        and not inspection.is_iso9660
        and inspection.partition_table_valid is True
        and inspection.partition_table_kind == "mbr"
        and inspection.partition_table_sector_size == 512
        and inspection.contents_scanned
        and inspection.boot_modes == ("BIOS",)
        and inspection.architectures == ("x86",)
        and inspection.bootloader == "FreeDOS"
        and not inspection.virtual_format
        and not inspection.sparse_format
    )
