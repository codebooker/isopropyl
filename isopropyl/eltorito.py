from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Strict, bounded, read-only El Torito boot-catalog inspection."""

import enum
import os
import stat
import struct
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

LOGICAL_BLOCK_SIZE = 2048
VOLUME_DESCRIPTOR_START_LBA = 16
MAX_VOLUME_DESCRIPTORS = 256
MAX_CATALOG_ENTRIES = 256
MAX_CATALOG_SECTIONS = 64


class ElToritoError(ValueError):
    pass


class ElToritoNotFound(ElToritoError):
    pass


class IsoChanged(ElToritoError):
    pass


class BootPlatform(enum.IntEnum):
    BIOS_X86 = 0x00
    POWERPC = 0x01
    MAC = 0x02
    EFI = 0xEF

    @property
    def display_name(self) -> str:
        return {
            BootPlatform.BIOS_X86: "BIOS x86",
            BootPlatform.POWERPC: "PowerPC",
            BootPlatform.MAC: "Mac",
            BootPlatform.EFI: "UEFI",
        }[self]


class EmulationType(enum.IntEnum):
    NO_EMULATION = 0
    FLOPPY_1_2_MB = 1
    FLOPPY_1_44_MB = 2
    FLOPPY_2_88_MB = 3
    HARD_DISK = 4

    @property
    def display_name(self) -> str:
        return {
            EmulationType.NO_EMULATION: "No emulation",
            EmulationType.FLOPPY_1_2_MB: "1.2 MB floppy",
            EmulationType.FLOPPY_1_44_MB: "1.44 MB floppy",
            EmulationType.FLOPPY_2_88_MB: "2.88 MB floppy",
            EmulationType.HARD_DISK: "Hard disk",
        }[self]


@dataclass(frozen=True)
class IsoIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class ValidationEntry:
    platform: BootPlatform
    identifier: str
    checksum: int


@dataclass(frozen=True)
class BootEntry:
    catalog_index: int
    is_default: bool
    platform: BootPlatform
    section_identifier: str
    bootable: bool
    emulation: EmulationType
    load_segment: int
    system_type: int
    sector_count: int
    image_lba: int
    image_offset: int | None
    load_size: int
    extent_end: int | None
    selection_criteria_type: int
    selection_criteria: bytes

    @property
    def effective_load_segment(self) -> int:
        if self.platform is BootPlatform.BIOS_X86 and self.load_segment == 0:
            return 0x07C0
        return self.load_segment

    @property
    def load_extent(self) -> tuple[int, int] | None:
        """Catalog-declared initial load extent, not the full embedded image."""

        if self.image_offset is None or self.extent_end is None:
            return None
        return self.image_offset, self.extent_end


@dataclass(frozen=True)
class ElToritoInspection:
    source_size: int
    catalog_lba: int
    catalog_offset: int
    catalog_size: int
    descriptors_scanned: int
    validation: ValidationEntry
    entries: tuple[BootEntry, ...]
    source_identity: IsoIdentity | None = None
    logical_volume_size: int = 0

    @property
    def bootable_platforms(self) -> tuple[BootPlatform, ...]:
        return tuple(dict.fromkeys(entry.platform for entry in self.entries if entry.bootable))


ReadAt = Callable[[int, int], bytes]


def _read_exact(read_at: ReadAt, size: int, offset: int, length: int, label: str) -> bytes:
    if offset < 0 or length < 0 or offset > size or length > size - offset:
        raise ElToritoError(f"{label} lies outside the ISO file")
    data = read_at(offset, length)
    if len(data) != length:
        raise ElToritoError(f"{label} could not be read completely")
    return data


def _decode_identifier(raw: bytes, label: str) -> str:
    text = raw.rstrip(b"\0 ")
    if any(byte < 0x20 or byte >= 0x7F for byte in text):
        raise ElToritoError(f"{label} contains non-printable characters")
    return text.decode("ascii")


def _platform(value: int, label: str) -> BootPlatform:
    try:
        return BootPlatform(value)
    except ValueError as error:
        raise ElToritoError(f"{label} uses unsupported platform ID 0x{value:02x}") from error


def _emulation(value: int, label: str) -> EmulationType:
    try:
        return EmulationType(value)
    except ValueError as error:
        raise ElToritoError(f"{label} uses invalid boot-media type 0x{value:02x}") from error


def _scan_volume_descriptors(
    read_at: ReadAt, size: int,
) -> tuple[int, int, int, int]:
    boot_catalogs: list[int] = []
    logical_volume_blocks: list[int] = []
    terminator_lba: int | None = None
    descriptors_scanned = 0
    for index in range(MAX_VOLUME_DESCRIPTORS):
        lba = VOLUME_DESCRIPTOR_START_LBA + index
        descriptor = _read_exact(
            read_at, size, lba * LOGICAL_BLOCK_SIZE, LOGICAL_BLOCK_SIZE,
            f"volume descriptor at LBA {lba}",
        )
        descriptors_scanned += 1
        descriptor_type = descriptor[0]
        if descriptor[1:6] != b"CD001" or descriptor[6] != 1:
            raise ElToritoError(f"invalid ISO volume descriptor at LBA {lba}")
        if descriptor_type == 0:
            system_identifier = descriptor[7:39].rstrip(b"\0 ")
            if system_identifier == b"EL TORITO SPECIFICATION":
                catalog_lba = struct.unpack_from("<I", descriptor, 71)[0]
                boot_catalogs.append(catalog_lba)
        elif descriptor_type == 1:
            little = struct.unpack_from("<I", descriptor, 80)[0]
            big = struct.unpack_from(">I", descriptor, 84)[0]
            if little == 0 or little != big:
                raise ElToritoError(
                    f"invalid ISO logical-volume size at LBA {lba}"
                )
            logical_volume_blocks.append(little)
        elif descriptor_type == 255:
            terminator_lba = lba
            break
        elif descriptor_type not in {1, 2, 3}:
            raise ElToritoError(
                f"unsupported ISO volume-descriptor type {descriptor_type} at LBA {lba}"
            )
    if terminator_lba is None:
        raise ElToritoError("ISO volume-descriptor terminator was not found within the limit")
    if not boot_catalogs:
        raise ElToritoNotFound("The ISO does not contain an El Torito boot record")
    if len(boot_catalogs) != 1:
        raise ElToritoError("Multiple El Torito boot records are ambiguous")
    if len(logical_volume_blocks) != 1:
        raise ElToritoError("The ISO must contain one unambiguous primary volume descriptor")
    logical_volume_size = logical_volume_blocks[0] * LOGICAL_BLOCK_SIZE
    if logical_volume_size > size:
        raise ElToritoError("The ISO logical volume extends beyond the selected file")
    catalog_lba = boot_catalogs[0]
    if catalog_lba <= terminator_lba:
        raise ElToritoError("El Torito boot catalog overlaps the ISO volume descriptors")
    return catalog_lba, terminator_lba, descriptors_scanned, logical_volume_size


def _parse_validation(raw: bytes) -> ValidationEntry:
    if raw[0] != 0x01:
        raise ElToritoError("boot-catalog validation entry has an invalid header ID")
    if raw[2:4] != b"\0\0":
        raise ElToritoError("boot-catalog validation entry reserved bytes are nonzero")
    if raw[30:32] != b"\x55\xaa":
        raise ElToritoError("boot-catalog validation signature is missing")
    checksum = sum(struct.unpack("<16H", raw)) & 0xFFFF
    if checksum:
        raise ElToritoError("boot-catalog validation checksum is invalid")
    return ValidationEntry(
        _platform(raw[1], "boot-catalog validation entry"),
        _decode_identifier(raw[4:28], "boot-catalog validation identifier"),
        struct.unpack_from("<H", raw, 28)[0],
    )


def _parse_boot_entry(
    raw: bytes,
    *,
    index: int,
    platform: BootPlatform,
    is_default: bool,
    section_identifier: str,
    source_size: int,
) -> BootEntry:
    label = f"boot-catalog entry {index}"
    if raw[0] not in {0x00, 0x88}:
        if raw[0] == 0x44:
            raise ElToritoError("section-entry extensions are not supported")
        raise ElToritoError(f"{label} has invalid boot indicator 0x{raw[0]:02x}")
    bootable = raw[0] == 0x88
    emulation = _emulation(raw[1], label)
    if platform is BootPlatform.EFI and emulation is not EmulationType.NO_EMULATION:
        raise ElToritoError("UEFI El Torito entries must use no-emulation media")
    load_segment = struct.unpack_from("<H", raw, 2)[0]
    system_type = raw[4]
    selection_type = raw[5] if not is_default else 0
    if is_default and (raw[5] != 0 or any(raw[12:32])):
        raise ElToritoError("default boot-catalog entry reserved bytes are nonzero")
    sector_count = struct.unpack_from("<H", raw, 6)[0]
    image_lba = struct.unpack_from("<I", raw, 8)[0]
    if bootable and image_lba == 0:
        raise ElToritoError(f"{label} has no boot-image extent")
    if (
        bootable
        and sector_count == 0
        and not (
            platform is BootPlatform.EFI
            and emulation is EmulationType.NO_EMULATION
        )
    ):
        raise ElToritoError(
            f"{label} has a zero sector count outside an EFI no-emulation entry"
        )
    if not bootable and bool(sector_count) != bool(image_lba):
        raise ElToritoError(f"{label} has an incomplete boot-image extent")
    load_size = sector_count * 512
    image_offset: int | None = None
    extent_end: int | None = None
    if image_lba:
        image_offset = image_lba * LOGICAL_BLOCK_SIZE
        if image_offset > source_size or load_size > source_size - image_offset:
            raise ElToritoError(f"{label} boot-image load extent lies outside the ISO file")
        extent_end = image_offset + load_size
    return BootEntry(
        index, is_default, platform, section_identifier, bootable, emulation,
        load_segment, system_type, sector_count, image_lba, image_offset,
        load_size, extent_end, selection_type, b"" if is_default else raw[12:32],
    )


def _inspect(read_at: ReadAt, source_size: int) -> ElToritoInspection:
    (
        catalog_lba,
        terminator_lba,
        descriptors_scanned,
        logical_volume_size,
    ) = _scan_volume_descriptors(
        read_at, source_size
    )
    catalog_offset = catalog_lba * LOGICAL_BLOCK_SIZE

    def catalog_entry(index: int) -> bytes:
        if index >= MAX_CATALOG_ENTRIES:
            raise ElToritoError("boot catalog exceeds the entry limit")
        return _read_exact(
            read_at, source_size, catalog_offset + index * 32, 32,
            f"boot-catalog entry {index}",
        )

    validation = _parse_validation(catalog_entry(0))
    entries = [
        _parse_boot_entry(
            catalog_entry(1), index=1, platform=validation.platform,
            is_default=True, section_identifier="", source_size=source_size,
        )
    ]
    index = 2
    raw = catalog_entry(index)
    if not any(raw):
        catalog_size = index * 32
    else:
        sections = 0
        while True:
            sections += 1
            if sections > MAX_CATALOG_SECTIONS:
                raise ElToritoError("boot catalog exceeds the section limit")
            header_indicator = raw[0]
            if header_indicator not in {0x90, 0x91}:
                raise ElToritoError(
                    f"boot-catalog entry {index} is not a valid section header"
                )
            platform = _platform(raw[1], f"boot-catalog section header {index}")
            section_count = struct.unpack_from("<H", raw, 2)[0]
            if section_count == 0:
                raise ElToritoError("boot-catalog section has no entries")
            if index + section_count >= MAX_CATALOG_ENTRIES:
                raise ElToritoError("boot catalog exceeds the entry limit")
            identifier = _decode_identifier(
                raw[4:32], f"boot-catalog section header {index} identifier"
            )
            for _ in range(section_count):
                index += 1
                entries.append(_parse_boot_entry(
                    catalog_entry(index), index=index, platform=platform,
                    is_default=False, section_identifier=identifier,
                    source_size=source_size,
                ))
            index += 1
            if header_indicator == 0x91:
                catalog_size = index * 32
                break
            raw = catalog_entry(index)

    catalog_extent_end = catalog_offset + (
        (catalog_size + LOGICAL_BLOCK_SIZE - 1) // LOGICAL_BLOCK_SIZE
    ) * LOGICAL_BLOCK_SIZE
    descriptors_start = VOLUME_DESCRIPTOR_START_LBA * LOGICAL_BLOCK_SIZE
    descriptors_end = (terminator_lba + 1) * LOGICAL_BLOCK_SIZE
    for entry in entries:
        if entry.image_offset is None or entry.extent_end is None:
            continue
        if entry.image_offset < catalog_extent_end and catalog_offset < entry.extent_end:
            raise ElToritoError(
                f"boot-catalog entry {entry.catalog_index} overlaps the boot catalog"
            )
        if entry.image_offset < descriptors_end and descriptors_start < entry.extent_end:
            raise ElToritoError(
                f"boot-catalog entry {entry.catalog_index} overlaps volume descriptors"
            )
    return ElToritoInspection(
        source_size, catalog_lba, catalog_offset, catalog_size,
        descriptors_scanned, validation, tuple(entries),
        logical_volume_size=logical_volume_size,
    )


def inspect_eltorito_bytes(blob: bytes) -> ElToritoInspection:
    def read_at(offset: int, length: int) -> bytes:
        return blob[offset:offset + length]

    return _inspect(read_at, len(blob))


def _identity(status: os.stat_result) -> IsoIdentity:
    return IsoIdentity(
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def inspect_eltorito_file(
    path: Path, *, image_fd: int | None = None,
) -> ElToritoInspection:
    """Inspect a regular ISO file and reject identity changes during parsing."""

    if image_fd is not None:
        try:
            before_status = os.fstat(image_fd)
            if not stat.S_ISREG(before_status.st_mode):
                raise ElToritoError("The selected ISO must be a regular file")
            before = _identity(before_status)

            def read_at(offset: int, length: int) -> bytes:
                return os.pread(image_fd, length, offset)

            result = _inspect(read_at, before.size)
            after = _identity(os.fstat(image_fd))
        except OSError as error:
            raise ElToritoError(f"Could not read the selected ISO: {error}") from error
        if after != before:
            raise IsoChanged("The selected ISO changed while its boot catalog was inspected")
        return replace(result, source_identity=before)

    try:
        with path.open("rb", buffering=0) as stream:
            before_status = os.fstat(stream.fileno())
            if not stat.S_ISREG(before_status.st_mode):
                raise ElToritoError("The selected ISO must be a regular file")
            before = _identity(before_status)

            def read_at(offset: int, length: int) -> bytes:
                stream.seek(offset)
                return stream.read(length)

            result = _inspect(read_at, before.size)
            after = _identity(os.fstat(stream.fileno()))
    except OSError as error:
        raise ElToritoError(f"Could not read the selected ISO: {error}") from error
    if after != before:
        raise IsoChanged("The selected ISO changed while its boot catalog was inspected")
    return replace(result, source_identity=before)
