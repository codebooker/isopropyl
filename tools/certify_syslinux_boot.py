#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Opt-in, device-free Syslinux ISO-mode certification under QEMU TCG.

The input is the exact upstream Syslinux 6.03 source archive.  This tool binds
and hashes that regular file, extracts four independently pinned build
artifacts from a sealed snapshot, obtains ISOpropyl's two real catalog bundles,
and requires their bytes to equal the upstream source evidence.  It then makes
a private certification ISO, exercises ISOpropyl's real inspection, ISO
staging, anonymous FAT32 builder, and Syslinux patch transaction, and boots the
exact resulting bytes from a sealed memfd under SeaBIOS.

No block-device path is accepted or opened.  QEMU uses TCG, snapshot mode, no
network, no KVM, and only one inherited read-only sealed regular-file fd.
"""

import argparse
import errno
import fcntl
import hashlib
import json
import lzma
import os
import pty
import selectors
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Sequence

# Direct execution puts ``tools/`` rather than the repository root on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from isopropyl.bootloaders import (
    BoundBootBundle,
    CatalogError,
    DependencyUnavailable,
    DownloadError,
    prepare_bundle,
)
from isopropyl.images import ImageMember, inspect_image
from isopropyl.iso import (
    ArchiveEntry,
    EntryKind,
    FileSystem,
    FirmwareTarget,
    PlanError,
    WriteMode,
    build_write_plan,
)
from isopropyl.iso_staging import (
    IsoStagingError,
    IsoStagingExecutor,
    build_iso_staging_plan,
)
from isopropyl.syslinux_iso_fat32 import (
    PreparedSyslinuxIsoFat32,
    SyslinuxIsoFat32Error,
    build_syslinux_iso_fat32_plan,
    prepare_syslinux_iso_fat32,
)
from tools import certify_freedos_boot as _hardened_qemu


SYSLINUX_BUILD = "6.03-2014-10-06"
SOURCE_ARCHIVE_FILENAME = "syslinux-6.03.tar.xz"
SOURCE_ARCHIVE_SIZE = 6_855_224
SOURCE_ARCHIVE_SHA256 = (
    "26d3986d2bea109d5dc0e4f8c4822a459276cf021125e8c9f23c3cca5d8c850e"
)
SOURCE_ARCHIVE_URL = (
    "https://www.kernel.org/pub/linux/utils/boot/syslinux/syslinux-6.03.tar.xz"
)
SOURCE_CHECKSUM_URL = (
    "https://www.kernel.org/pub/linux/utils/boot/syslinux/sha256sums.asc"
)


@dataclass(frozen=True)
class SourceMemberPin:
    archive_path: str
    artifact_name: str
    size: int
    sha256: str


SOURCE_MEMBERS = (
    SourceMemberPin(
        "syslinux-6.03/bios/core/isolinux.bin",
        "isolinux.bin",
        45_056,
        "c5e4e775a7aada9aa2b227806724c52c66625b88699b3f167b5ec690a7addb91",
    ),
    SourceMemberPin(
        "syslinux-6.03/bios/core/ldlinux.bss",
        "ldlinux.bss",
        512,
        "8814e576abc1aa44dde943b0caaee833a5810142614adeeb4cc725e78a5045b7",
    ),
    SourceMemberPin(
        "syslinux-6.03/bios/core/ldlinux.sys",
        "ldlinux.sys",
        68_599,
        "3f1206e0cc45dbe180e73adaeb221bfc7d5a800095738549390379d7d0282ac3",
    ),
    SourceMemberPin(
        "syslinux-6.03/bios/com32/elflink/ldlinux/ldlinux.c32",
        "ldlinux.c32",
        122_308,
        "5cef9ad0d0ca04097262241686c6c3a7306ab9b9cdf24b9d4ee3b16af01a5af2",
    ),
)

BOOT_MARKERS = (
    "Booting from Hard Disk...",
    "SYSLINUX 6.03",
    "ISOPROPYL-SYSLINUX-6.03-CERTIFIED",
    "boot:",
)
CERTIFICATION_CONFIG = (
    "PROMPT 1\n"
    "TIMEOUT 0\n"
    "SAY ISOPROPYL-SYSLINUX-6.03-CERTIFIED\n"
).encode("ascii")
PRIVATE_IMAGE_SIZE = 36_888_576
DEFAULT_TIMEOUT = 30
MIN_TIMEOUT = 5
MAX_TIMEOUT = 180
MAX_DIAGNOSTIC_BYTES = _hardened_qemu.MAX_DIAGNOSTIC_BYTES
MAX_TERMINAL_STREAM = _hardened_qemu.MAX_TERMINAL_STREAM
DEFAULT_EXECUTABLE_PATH = _hardened_qemu.DEFAULT_EXECUTABLE_PATH
REQUIRED_MEMFD_SEALS = _hardened_qemu.REQUIRED_MEMFD_SEALS

BootCertificationError = _hardened_qemu.BootCertificationError
FileIdentity = _hardened_qemu.FileIdentity
QemuIdentity = _hardened_qemu.QemuIdentity
BootCapture = _hardened_qemu.BootCapture
resolve_qemu = _hardened_qemu.resolve_qemu
verify_qemu_unchanged = _hardened_qemu.verify_qemu_unchanged
query_qemu_version = _hardened_qemu.query_qemu_version


@dataclass
class VerifiedSourceArchive:
    path: Path
    fd: int
    identity: FileIdentity
    snapshot_fd: int

    def close(self) -> None:
        if self.snapshot_fd >= 0:
            os.close(self.snapshot_fd)
            self.snapshot_fd = -1
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "VerifiedSourceArchive":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


@dataclass
class SealedPreparedImage:
    fd: int
    size: int
    sha256: str

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "SealedPreparedImage":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


@dataclass(frozen=True)
class PipelineEvidence:
    source_iso_size: int
    source_iso_sha256: str
    source_members: tuple[SourceMemberPin, ...]
    c32_bundle: BoundBootBundle
    payload_bundle: BoundBootBundle
    staging_catalog_sha256: str
    staging_manifest_sha256: str
    composite_plan_sha256: str
    private_plan_sha256: str
    transaction_plan_sha256: str
    unpatched_image_sha256: str
    final_image_sha256: str
    final_manifest_sha256: str
    files_verified: int
    directories_verified: int
    bytes_verified: int


def _descriptor_path(fd: int) -> str:
    return f"/proc/self/fd/{fd}"


def _new_sealable_memfd(name: str) -> int:
    required = ("memfd_create", "MFD_CLOEXEC", "MFD_ALLOW_SEALING")
    if any(not hasattr(os, item) for item in required):
        raise BootCertificationError(
            "Safe certification requires Linux sealed memfd support"
        )
    seal_names = (
        "F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE",
        "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL",
    )
    if any(not hasattr(fcntl, item) for item in seal_names):
        raise BootCertificationError("Safe certification requires Linux file seals")
    try:
        return os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    except OSError as error:
        raise BootCertificationError(f"Could not create a sealed memfd: {error}") from error


def _write_all(fd: int, data: bytes, offset: int) -> None:
    consumed = 0
    while consumed < len(data):
        written = os.pwrite(fd, data[consumed:], offset + consumed)
        if written <= 0:
            raise BootCertificationError("Could not populate a sealed snapshot")
        consumed += written


def _seal_readonly(fd: int, size: int, expected_sha256: str) -> int:
    readonly = -1
    try:
        if os.fstat(fd).st_size != size:
            raise BootCertificationError("The memfd snapshot has the wrong size")
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, REQUIRED_MEMFD_SEALS)
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        if seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS:
            raise BootCertificationError("The memfd snapshot could not be fully sealed")
        readonly = os.open(_descriptor_path(fd), os.O_RDONLY | os.O_CLOEXEC)
        digest = _hardened_qemu._sha256_fd(
            readonly, size, description="sealed Syslinux snapshot",
        )
        if digest != expected_sha256:
            raise BootCertificationError("The sealed snapshot changed while it was created")
        result = readonly
        readonly = -1
        return result
    except OSError as error:
        raise BootCertificationError(f"Could not seal a snapshot: {error}") from error
    finally:
        if readonly >= 0:
            os.close(readonly)


def _copy_source_to_sealed(fd: int, size: int) -> tuple[int, str]:
    writable = _new_sealable_memfd("isopropyl-syslinux-source")
    try:
        digest = hashlib.sha256()
        offset = 0
        while offset < size:
            block = os.pread(fd, min(1024 * 1024, size - offset), offset)
            if not block:
                raise BootCertificationError(
                    "The Syslinux source archive became truncated"
                )
            digest.update(block)
            _write_all(writable, block, offset)
            offset += len(block)
        if os.pread(fd, 1, size):
            raise BootCertificationError("The Syslinux source archive grew while hashing")
        rendered = digest.hexdigest()
        readonly = _seal_readonly(writable, size, rendered)
        return readonly, rendered
    finally:
        os.close(writable)


def open_verified_source_archive(path: Path) -> VerifiedSourceArchive:
    """Bind the exact official archive without following its final component."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    if absolute.name != SOURCE_ARCHIVE_FILENAME:
        raise BootCertificationError(
            f"The source archive filename must be exactly {SOURCE_ARCHIVE_FILENAME!r}"
        )
    if not hasattr(os, "O_PATH"):
        raise BootCertificationError("Safe source binding requires Linux O_PATH support")
    path_fd = data_fd = snapshot_fd = -1
    try:
        path_fd = os.open(
            absolute,
            os.O_PATH | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        status = os.fstat(path_fd)
        if not stat.S_ISREG(status.st_mode):
            raise BootCertificationError(
                "The Syslinux source archive must be a no-follow regular file"
            )
        if status.st_size != SOURCE_ARCHIVE_SIZE:
            raise BootCertificationError(
                "The Syslinux source archive size does not match the project pin"
            )
        data_fd = os.open(_descriptor_path(path_fd), os.O_RDONLY | os.O_CLOEXEC)
        identity = _hardened_qemu._identity(os.fstat(data_fd))
        if identity.device != status.st_dev or identity.inode != status.st_ino:
            raise BootCertificationError("The source archive changed while opening")
        snapshot_fd, digest = _copy_source_to_sealed(data_fd, SOURCE_ARCHIVE_SIZE)
        if (
            _hardened_qemu._identity(os.fstat(data_fd)) != identity
            or _hardened_qemu._path_identity(
                absolute, description="Syslinux source archive",
            ) != identity
        ):
            raise BootCertificationError("The source archive changed while hashing")
        if digest != SOURCE_ARCHIVE_SHA256:
            raise BootCertificationError(
                "The Syslinux source archive SHA-256 does not match the project pin"
            )
        result = VerifiedSourceArchive(absolute, data_fd, identity, snapshot_fd)
        data_fd = snapshot_fd = -1
        return result
    except OSError as error:
        raise BootCertificationError(
            f"Could not safely open the Syslinux source archive: {error}"
        ) from error
    finally:
        for descriptor in (snapshot_fd, data_fd, path_fd):
            if descriptor >= 0:
                os.close(descriptor)


def verify_source_archive_unchanged(archive: VerifiedSourceArchive) -> None:
    current = _hardened_qemu._identity(os.fstat(archive.fd))
    named = _hardened_qemu._path_identity(
        archive.path, description="Syslinux source archive",
    )
    if current != archive.identity or named != archive.identity:
        raise BootCertificationError(
            "The Syslinux source archive identity changed during certification"
        )
    digest = _hardened_qemu._sha256_fd(
        archive.fd, SOURCE_ARCHIVE_SIZE, description="Syslinux source archive",
    )
    if (
        digest != SOURCE_ARCHIVE_SHA256
        or _hardened_qemu._identity(os.fstat(archive.fd)) != archive.identity
        or _hardened_qemu._path_identity(
            archive.path, description="Syslinux source archive",
        ) != archive.identity
    ):
        raise BootCertificationError(
            "The Syslinux source archive changed during certification"
        )
    snapshot_status = os.fstat(archive.snapshot_fd)
    seals = fcntl.fcntl(archive.snapshot_fd, fcntl.F_GET_SEALS)
    if (
        not stat.S_ISREG(snapshot_status.st_mode)
        or snapshot_status.st_size != SOURCE_ARCHIVE_SIZE
        or seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS
        or _hardened_qemu._sha256_fd(
            archive.snapshot_fd,
            SOURCE_ARCHIVE_SIZE,
            description="sealed Syslinux source archive",
        ) != SOURCE_ARCHIVE_SHA256
    ):
        raise BootCertificationError("The sealed Syslinux source archive changed")


def _read_exact_member(fileobj: BinaryIO, pin: SourceMemberPin) -> bytes:
    block = fileobj.read(pin.size + 1)
    if len(block) != pin.size:
        raise BootCertificationError(
            f"Official source member {pin.archive_path!r} has the wrong size"
        )
    if hashlib.sha256(block).hexdigest() != pin.sha256:
        raise BootCertificationError(
            f"Official source member {pin.archive_path!r} failed its independent hash"
        )
    return block


def read_official_source_members(
    archive: VerifiedSourceArchive,
) -> dict[str, bytes]:
    """Extract only the four pinned regular members from the sealed archive."""

    # Reopening through procfs creates an independent file description, so a
    # tar reader cannot alter an offset shared with the retained evidence fd.
    duplicate = os.fdopen(
        os.open(_descriptor_path(archive.snapshot_fd), os.O_RDONLY | os.O_CLOEXEC),
        "rb",
    )
    try:
        with duplicate, tarfile.open(fileobj=duplicate, mode="r:xz") as source:
            catalog = source.getmembers()
            result: dict[str, bytes] = {}
            for pin in SOURCE_MEMBERS:
                matches = [item for item in catalog if item.name == pin.archive_path]
                if len(matches) != 1 or not matches[0].isreg():
                    raise BootCertificationError(
                        f"Official source member {pin.archive_path!r} is missing or unsafe"
                    )
                if matches[0].size != pin.size:
                    raise BootCertificationError(
                        f"Official source member {pin.archive_path!r} has unexpected metadata"
                    )
                extracted = source.extractfile(matches[0])
                if extracted is None:
                    raise BootCertificationError(
                        f"Official source member {pin.archive_path!r} could not be read"
                    )
                with extracted:
                    result[pin.artifact_name] = _read_exact_member(extracted, pin)
            return result
    except (tarfile.TarError, EOFError, OSError, lzma.LZMAError) as error:
        raise BootCertificationError(
            f"The pinned Syslinux source archive could not be parsed: {error}"
        ) from error


def _minimal_inert_efi_application() -> bytes:
    """Return a sectionless PE32+ EFI app used only to satisfy the staging gate."""

    pe_offset = 0x80
    optional_size = 0xF0
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into(
        "<HHIIIHH", data, coff, 0x8664, 0, 0, 0, 0, optional_size, 0x2022,
    )
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<Q", data, optional + 24, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x1000)
    struct.pack_into("<I", data, optional + 60, 0x400)
    struct.pack_into("<H", data, optional + 68, 10)
    struct.pack_into("<Q", data, optional + 72, 0x100000)
    struct.pack_into("<Q", data, optional + 80, 0x1000)
    struct.pack_into("<Q", data, optional + 88, 0x100000)
    struct.pack_into("<Q", data, optional + 96, 0x1000)
    struct.pack_into("<I", data, optional + 108, 16)
    return bytes(data)


def _resolve_xorriso() -> Path:
    found = shutil.which("xorriso", path=DEFAULT_EXECUTABLE_PATH)
    if found is None:
        raise BootCertificationError("xorriso is required to create the private source ISO")
    candidate = Path(found).resolve(strict=True)
    status = candidate.stat(follow_symlinks=False)
    if (
        candidate.name != "xorriso"
        or not stat.S_ISREG(status.st_mode)
        or status.st_mode & (stat.S_ISUID | stat.S_ISGID)
        or not os.access(candidate, os.X_OK)
    ):
        raise BootCertificationError("xorriso is not a safe regular executable")
    return candidate


def build_private_source_iso(
    root: Path,
    official_members: dict[str, bytes],
) -> Path:
    """Create the tiny source ISO consumed by the real staging pipeline."""

    tree = root / "source-tree"
    (tree / "isolinux").mkdir(parents=True)
    (tree / "EFI" / "BOOT").mkdir(parents=True)
    (tree / "isolinux" / "isolinux.bin").write_bytes(
        official_members["isolinux.bin"]
    )
    (tree / "isolinux" / "isolinux.cfg").write_bytes(CERTIFICATION_CONFIG)
    (tree / "EFI" / "BOOT" / "BOOTX64.EFI").write_bytes(
        _minimal_inert_efi_application()
    )
    destination = root / "syslinux-certification-source.iso"
    command = (
        str(_resolve_xorriso()),
        "-no_rc",
        "-as", "mkisofs",
        "-quiet",
        "-V", "ISOPROPYL_SYS_603",
        "-o", str(destination),
        ".",
    )
    try:
        result = subprocess.run(
            command,
            cwd=tree,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            timeout=30,
            check=False,
            env={
                "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "PATH": DEFAULT_EXECUTABLE_PATH, "TZ": "UTC",
            },
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise BootCertificationError(f"Could not create the private source ISO: {error}") from error
    if result.returncode != 0:
        raise BootCertificationError("xorriso could not create the private source ISO")
    status = destination.stat(follow_symlinks=False)
    if not stat.S_ISREG(status.st_mode) or status.st_size <= 0:
        raise BootCertificationError("xorriso did not publish a regular source ISO")
    return destination


def _archive_entries(members: Sequence[ImageMember]) -> tuple[ArchiveEntry, ...]:
    kinds = {
        "file": EntryKind.FILE,
        "directory": EntryKind.DIRECTORY,
        "symlink": EntryKind.SYMLINK,
        "hardlink": EntryKind.HARDLINK,
    }
    return tuple(
        ArchiveEntry(
            member.path,
            member.size,
            kinds.get(member.kind, EntryKind.FILE),
            member.link_target or None,
            member.modified_ns,
        )
        for member in members
    )


def _artifact_map(bundle: BoundBootBundle) -> dict[str, bytes]:
    return {item.name: item.data for item in bundle.artifacts}


def _hash_bound_regular_file(path: Path, description: str) -> tuple[FileIdentity, str]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        identity = _hardened_qemu._identity(os.fstat(descriptor))
        if not stat.S_ISREG(identity.mode) or identity.size <= 0:
            raise BootCertificationError(f"The {description} is not a regular file")
        digest = _hardened_qemu._sha256_fd(
            descriptor, identity.size, description=description,
        )
        if (
            _hardened_qemu._identity(os.fstat(descriptor)) != identity
            or _hardened_qemu._path_identity(path, description=description) != identity
        ):
            raise BootCertificationError(f"The {description} changed while hashing")
        return identity, digest
    except OSError as error:
        raise BootCertificationError(f"Could not bind the {description}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _verify_bound_regular_file(
    path: Path,
    identity: FileIdentity,
    digest: str,
    description: str,
) -> None:
    current, rendered = _hash_bound_regular_file(path, description)
    if current != identity or rendered != digest:
        raise BootCertificationError(f"The {description} changed during certification")


def _require_bundles_match_official_source(
    c32_bundle: BoundBootBundle,
    payload_bundle: BoundBootBundle,
    official: dict[str, bytes],
) -> None:
    if (
        c32_bundle.family != "syslinux"
        or c32_bundle.version != SYSLINUX_BUILD
        or c32_bundle.purpose != "blank-bios-module"
        or payload_bundle.family != "syslinux"
        or payload_bundle.version != SYSLINUX_BUILD
        or payload_bundle.purpose != "matched-bios-payloads"
    ):
        raise BootCertificationError("ISOpropyl returned the wrong Syslinux bundles")
    observed = _artifact_map(c32_bundle) | _artifact_map(payload_bundle)
    expected = {
        name: official[name] for name in ("ldlinux.c32", "ldlinux.bss", "ldlinux.sys")
    }
    if observed != expected:
        raise BootCertificationError(
            "ISOpropyl's prepared Syslinux bundles differ from official 6.03 source evidence"
        )


def seal_prepared_image(prepared: PreparedSyslinuxIsoFat32) -> SealedPreparedImage:
    """Copy the production owner's re-attested stream into a sealed memfd."""

    result = prepared.result
    size = result.image_size
    expected = result.final_image_sha256
    if (
        type(size) is not int or size <= 0
        or type(expected) is not str or len(expected) != 64
    ):
        raise BootCertificationError("The prepared Syslinux result is invalid")
    writable = _new_sealable_memfd("isopropyl-syslinux-prepared")
    try:
        digest = hashlib.sha256()
        offset = 0
        for block in prepared.chunks(1024 * 1024):
            if type(block) is not bytes or not block or offset + len(block) > size:
                raise BootCertificationError("The prepared Syslinux byte stream is invalid")
            _write_all(writable, block, offset)
            digest.update(block)
            offset += len(block)
        if offset != size:
            raise BootCertificationError("The prepared Syslinux byte stream is truncated")
        rendered = digest.hexdigest()
        if rendered != expected:
            raise BootCertificationError(
                "The prepared Syslinux byte stream failed its final attestation"
            )
        readonly = _seal_readonly(writable, size, rendered)
        return SealedPreparedImage(readonly, size, rendered)
    finally:
        os.close(writable)


def verify_sealed_prepared_image(image: SealedPreparedImage) -> None:
    status = os.fstat(image.fd)
    seals = fcntl.fcntl(image.fd, fcntl.F_GET_SEALS)
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_size != image.size
        or seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS
        or _hardened_qemu._sha256_fd(
            image.fd, image.size, description="sealed prepared Syslinux image",
        ) != image.sha256
    ):
        raise BootCertificationError("The sealed prepared Syslinux image changed")


def prepare_certification_pipeline(
    archive: VerifiedSourceArchive,
    workspace: Path,
) -> tuple[SealedPreparedImage, PipelineEvidence]:
    """Exercise all production regular-file stages and return only sealed bytes."""

    official = read_official_source_members(archive)
    cache = workspace / "bootloader-cache"
    c32 = prepare_bundle(
        "syslinux", SYSLINUX_BUILD, "blank-bios-module",
        cache_dir=cache, overall_timeout=180,
    )
    payloads = prepare_bundle(
        "syslinux", SYSLINUX_BUILD, "matched-bios-payloads",
        cache_dir=cache, overall_timeout=180,
    )
    _require_bundles_match_official_source(c32, payloads, official)

    source_iso = build_private_source_iso(workspace, official)
    source_identity, source_sha256 = _hash_bound_regular_file(
        source_iso, "private source ISO",
    )

    inspection = inspect_image(source_iso)
    if (
        inspection.is_iso9660 is not True
        or inspection.contents_scanned is not True
        or inspection.bootloader != "Syslinux/Isolinux"
        or inspection.bootloader_build != SYSLINUX_BUILD
        or inspection.bootloader_dependency != f"syslinux:{SYSLINUX_BUILD}"
        or not {"BIOS", "UEFI"}.issubset(inspection.boot_modes)
        or inspection.architectures != ("x64",)
    ):
        raise BootCertificationError(
            "The private source ISO did not produce the exact expected ISOpropyl inspection"
        )
    entries = _archive_entries(inspection.members)
    write_plan = build_write_plan(
        inspection,
        entries,
        requested_mode=WriteMode.EXTRACTED_ISO,
        requested_filesystem=FileSystem.FAT32,
        firmware_target=FirmwareTarget.UEFI_ONLY,
    )
    if not write_plan.executable:
        raise BootCertificationError(
            f"The ISOpropyl staging plan is not executable: {write_plan.blockers!r}"
        )
    staging_plan = build_iso_staging_plan(
        source_iso,
        workspace / "ready-media",
        entries,
        write_plan,
        syslinux_c32_bundle=c32,
        syslinux_payload_bundle=payloads,
    )
    staging_result = IsoStagingExecutor().execute(staging_plan)
    fat32_workspace = workspace / "fat32-workspace"
    fat32_workspace.mkdir(mode=0o700)
    composite = build_syslinux_iso_fat32_plan(
        staging_plan,
        staging_result,
        fat32_workspace,
        image_size=PRIVATE_IMAGE_SIZE,
    )
    with prepare_syslinux_iso_fat32(composite) as prepared:
        result = prepared.result
        sealed = seal_prepared_image(prepared)
    try:
        _verify_bound_regular_file(
            source_iso, source_identity, source_sha256, "private source ISO",
        )
        if staging_result.tree_manifest is None:
            raise BootCertificationError(
                "The Syslinux staging result has no authenticated tree manifest"
            )
        evidence = PipelineEvidence(
            source_identity.size,
            source_sha256,
            SOURCE_MEMBERS,
            c32,
            payloads,
            staging_result.catalog_digest,
            staging_result.tree_manifest.manifest_sha256,
            result.plan_sha256,
            result.private_plan_sha256,
            result.transaction_plan_sha256,
            result.unpatched_image_sha256,
            result.final_image_sha256,
            result.final_manifest_sha256,
            result.files_verified,
            result.directories_verified,
            result.bytes_verified,
        )
        return sealed, evidence
    except BaseException:
        sealed.close()
        raise


def build_qemu_command(qemu_fd: int, source_fd: int) -> tuple[str, ...]:
    """Build the fixed, device-free TCG/SeaBIOS command."""

    return (
        _descriptor_path(qemu_fd),
        "-no-user-config",
        "-sandbox", "on,obsolete=deny,spawn=deny,resourcecontrol=deny",
        "-machine", "pc,accel=tcg",
        "-cpu", "qemu32",
        "-m", "64M",
        "-snapshot",
        "-boot", "order=c,strict=on",
        "-add-fd", f"fd={source_fd},set=1,opaque=syslinux-prepared",
        "-drive",
        "file=/dev/fdset/1,if=ide,index=0,media=disk,format=raw,snapshot=on",
        "-nic", "none",
        "-monitor", "none",
        "-serial", "none",
        "-parallel", "none",
        "-display", "curses,charset=CP437",
        "-no-reboot",
        "-no-shutdown",
    )


class TerminalScreenCapture(_hardened_qemu.TerminalScreenCapture):
    """Use the hardened 80x25 model with Syslinux-specific ordered markers."""

    def __init__(self, limit: int = MAX_TERMINAL_STREAM) -> None:
        super().__init__(limit)

    @property
    def complete(self) -> bool:
        return len(self._markers) == len(BOOT_MARKERS)

    def _check_row(self, row: int) -> None:
        if self.complete:
            return
        expected = BOOT_MARKERS[len(self._markers)]
        if expected in "".join(self._screen[row]):
            self._markers.append(expected)


def capture_qemu_boot(
    qemu: QemuIdentity,
    source_fd: int,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> BootCapture:
    if type(timeout) is not int or not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ValueError(f"timeout must be an integer from {MIN_TIMEOUT} to {MAX_TIMEOUT}")
    verify_qemu_unchanged(qemu)
    command = build_qemu_command(qemu.fd, source_fd)
    master_fd = slave_fd = -1
    process: subprocess.Popen[bytes] | None = None
    terminal = TerminalScreenCapture()
    diagnostic = bytearray()
    started = time.monotonic()
    deadline = started + timeout
    selector = selectors.DefaultSelector()
    complete = False
    try:
        master_fd, slave_fd = pty.openpty()
        fcntl.ioctl(
            slave_fd,
            _hardened_qemu.termios_tiocswinsz(),
            struct.pack("HHHH", 25, 80, 0, 0),
        )
        os.set_blocking(master_fd, False)
        process = subprocess.Popen(
            command,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(qemu.fd, source_fd),
            start_new_session=True,
            env={
                "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "PATH": DEFAULT_EXECUTABLE_PATH, "TERM": "xterm-256color",
            },
        )
        os.close(slave_fd)
        slave_fd = -1
        selector.register(master_fd, selectors.EVENT_READ, "terminal")
        if process.stderr is None:
            raise BootCertificationError("QEMU diagnostic pipe was not created")
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(process.stderr, selectors.EVENT_READ, "diagnostic")
        while True:
            if terminal.complete:
                complete = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if process.poll() is not None and not selector.get_map():
                break
            for key, _mask in selector.select(min(remaining, 0.25)):
                try:
                    block = os.read(key.fd, 65_536)
                except OSError as error:
                    if error.errno == errno.EIO and key.data == "terminal":
                        block = b""
                    elif error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        continue
                    else:
                        raise BootCertificationError(
                            f"Could not read QEMU {key.data} output: {error}"
                        ) from error
                if not block:
                    selector.unregister(key.fileobj)
                elif key.data == "terminal":
                    terminal.feed(block)
                elif len(diagnostic) < MAX_DIAGNOSTIC_BYTES:
                    available = MAX_DIAGNOSTIC_BYTES - len(diagnostic)
                    diagnostic.extend(block[:available])
        if not complete:
            missing = list(BOOT_MARKERS[len(terminal.markers):])
            reason = (
                "QEMU exited before certification"
                if process.poll() is not None else "QEMU boot timed out"
            )
            details = _hardened_qemu._bounded_diagnostic(diagnostic)
            suffix = f"; diagnostic: {details}" if details else ""
            raise BootCertificationError(
                f"{reason}; missing exact markers: {missing!r}{suffix}"
            )
        return BootCapture(
            terminal.markers,
            terminal.size,
            round(time.monotonic() - started, 3),
        )
    except OSError as error:
        raise BootCertificationError(f"Could not run qemu-system-x86_64: {error}") from error
    finally:
        selector.close()
        stop_error: BootCertificationError | None = None
        if process is not None:
            try:
                _hardened_qemu._stop_and_reap(process)
            except BootCertificationError as error:
                stop_error = error
            if process.stderr is not None:
                process.stderr.close()
        if master_fd >= 0:
            os.close(master_fd)
        if slave_fd >= 0:
            os.close(slave_fd)
        if stop_error is not None:
            raise stop_error


def _bundle_json(bundle: BoundBootBundle) -> dict[str, object]:
    return {
        "family": bundle.family,
        "version": bundle.version,
        "purpose": bundle.purpose,
        "license": bundle.license,
        "provenance_url": bundle.provenance_url,
        "artifacts": [
            {"name": item.name, "size": item.size, "sha256": item.sha256}
            for item in bundle.artifacts
        ],
    }


def certify_syslinux_boot(
    source_archive: Path,
    *,
    qemu_path: Path | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, object]:
    if os.geteuid() == 0:
        raise BootCertificationError("Syslinux certification refuses to run as root")
    with (
        resolve_qemu(qemu_path) as qemu,
        open_verified_source_archive(source_archive) as archive,
        tempfile.TemporaryDirectory(prefix="isopropyl-syslinux-cert-") as temporary,
    ):
        qemu_version = query_qemu_version(qemu)
        workspace = Path(temporary)
        image: SealedPreparedImage | None = None
        try:
            try:
                image, evidence = prepare_certification_pipeline(archive, workspace)
            except BootCertificationError:
                raise
            except (
                CatalogError,
                DependencyUnavailable,
                DownloadError,
                IsoStagingError,
                PlanError,
                SyslinuxIsoFat32Error,
            ) as error:
                raise BootCertificationError(
                    f"The Syslinux production pipeline failed safely: {error}"
                ) from error
            verify_source_archive_unchanged(archive)
            verify_sealed_prepared_image(image)
            verify_qemu_unchanged(qemu)
            capture_error: BaseException | None = None
            capture: BootCapture | None = None
            try:
                capture = capture_qemu_boot(qemu, image.fd, timeout=timeout)
            except BaseException as error:
                capture_error = error
            verify_source_archive_unchanged(archive)
            verify_sealed_prepared_image(image)
            verify_qemu_unchanged(qemu)
            if capture_error is not None:
                raise capture_error
            assert capture is not None
            return {
                "schema_version": 1,
                "certified": True,
                "profile": "syslinux-6.03-extracted-iso-fat32-seabios",
                "source_archive": {
                    "filename": SOURCE_ARCHIVE_FILENAME,
                    "size": SOURCE_ARCHIVE_SIZE,
                    "sha256": SOURCE_ARCHIVE_SHA256,
                    "upstream_url": SOURCE_ARCHIVE_URL,
                    "upstream_checksum_url": SOURCE_CHECKSUM_URL,
                    "members": [
                        {
                            "archive_path": item.archive_path,
                            "artifact_name": item.artifact_name,
                            "size": item.size,
                            "sha256": item.sha256,
                        }
                        for item in evidence.source_members
                    ],
                },
                "source_iso": {
                    "size": evidence.source_iso_size,
                    "sha256": evidence.source_iso_sha256,
                    "inert_uefi_fixture": True,
                    "uefi_certified": False,
                },
                "bootloader_bundles": [
                    _bundle_json(evidence.c32_bundle),
                    _bundle_json(evidence.payload_bundle),
                ],
                "pipeline": {
                    "staging_catalog_sha256": evidence.staging_catalog_sha256,
                    "staging_manifest_sha256": evidence.staging_manifest_sha256,
                    "composite_plan_sha256": evidence.composite_plan_sha256,
                    "private_plan_sha256": evidence.private_plan_sha256,
                    "transaction_plan_sha256": evidence.transaction_plan_sha256,
                    "unpatched_image_sha256": evidence.unpatched_image_sha256,
                    "final_image_sha256": evidence.final_image_sha256,
                    "final_manifest_sha256": evidence.final_manifest_sha256,
                    "files_verified": evidence.files_verified,
                    "directories_verified": evidence.directories_verified,
                    "bytes_verified": evidence.bytes_verified,
                },
                "prepared_image": {
                    "size": image.size,
                    "sha256": image.sha256,
                    "sealed_memfd": True,
                },
                "markers": list(capture.markers),
                "capture": {
                    "method": "qemu-curses-private-pty-80x25-screen",
                    "terminal_stream_bytes": capture.terminal_stream_bytes,
                    "elapsed_seconds": capture.elapsed_seconds,
                },
                "isolation": {
                    "acceleration": "tcg",
                    "firmware": "SeaBIOS",
                    "snapshot": True,
                    "source_read_only": True,
                    "source_sealed_memfd": True,
                    "network": "none",
                    "attached_host_block_devices": [],
                    "unprivileged_process": True,
                    "qemu_executable_set_id": False,
                    "qemu_seccomp": True,
                    "qemu_seccomp_policy": (
                        "on,obsolete=deny,spawn=deny,resourcecontrol=deny"
                    ),
                },
                "scope": {
                    "bios_bootstrap_and_config_certified": True,
                    "kernel_or_operating_system_certified": False,
                    "uefi_certified": False,
                    "secure_boot_certified": False,
                    "physical_media_certified": False,
                    "privileged_device_transaction_certified": False,
                },
                "qemu": {
                    "executable": str(qemu.path),
                    "sha256": qemu.sha256,
                    "version": qemu_version,
                },
            }
        finally:
            if image is not None:
                image.close()


def _timeout(value: str) -> int:
    try:
        timeout = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be an integer") from error
    if not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(
            f"timeout must be from {MIN_TIMEOUT} to {MAX_TIMEOUT} seconds"
        )
    return timeout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "source_archive",
        type=Path,
        help=f"exact already-downloaded {SOURCE_ARCHIVE_FILENAME} path",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help=(
            "explicitly opt in to verified bootloader downloads, private regular-file "
            "construction, and networkless TCG QEMU boot"
        ),
    )
    parser.add_argument("--qemu", type=Path, help="absolute qemu-system-x86_64 path")
    parser.add_argument("--timeout", type=_timeout, default=DEFAULT_TIMEOUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.run:
        parser.error("certification is opt-in; pass --run to prepare and boot the image")
    try:
        observation = certify_syslinux_boot(
            args.source_archive,
            qemu_path=args.qemu,
            timeout=args.timeout,
        )
    except (BootCertificationError, ValueError, OSError) as error:
        print(f"certification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(observation, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
