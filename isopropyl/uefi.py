from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Conservative, read-only inspection of UEFI PE/COFF payloads.

This module parses enough PE metadata to identify architecture, EFI subsystem,
the Authenticode certificate-table container, and an optional ``.sbat``
section.  An isolated, resource-bounded backend can validate the Authenticode
file digest and embedded signer signature, but it does not establish Microsoft,
firmware, revocation, or signing-time trust.  Consequently, a structurally sound
certificate table remains ``PRESENT_UNVERIFIED`` even when integrity matches.
"""

import csv
import enum
import io
import os
import stat
import struct
import time
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from collections.abc import Callable, Iterable

from .authenticode import (
    WORKER_TIMEOUT_SECONDS,
    AuthenticodeIntegrityState,
    AuthenticodeResult,
    CertificateTableFacts,
    WinCertificateFacts,
    verify_authenticode,
)
from .boot_identity import read_archive_member_with_7z
from .dbx import DbxAssessment, DbxState, assess_dbx

MAX_PE_SIZE = 256 * 1024 * 1024
MAX_SECTIONS = 512
MAX_CERTIFICATES = 256
MAX_SBAT_SIZE = 1024 * 1024
MAX_SBAT_ROWS = 4096
MAX_SBAT_FIELD_SIZE = 4096
MAX_UEFI_MEMBERS = 16

MACHINE_ARCHITECTURES = {
    0x014C: "x86",
    0x01C0: "ARM",
    0x01C2: "Thumb",
    0x01C4: "ARMv7",
    0x0200: "IA-64",
    0x5032: "RISC-V32",
    0x5064: "RISC-V64",
    0x5128: "RISC-V128",
    0x6232: "LoongArch32",
    0x6264: "LoongArch64",
    0x8664: "x64",
    0xAA64: "ARM64",
}

EFI_SUBSYSTEMS = {
    10: "EFI application",
    11: "EFI boot-service driver",
    12: "EFI runtime driver",
    13: "EFI ROM image",
}


class PeFormatError(ValueError):
    """The input is not a structurally parseable PE image."""


class SignatureTableState(enum.Enum):
    ABSENT = "absent"
    PRESENT_UNVERIFIED = "present-unverified"
    MALFORMED = "malformed"


class SbatState(enum.Enum):
    ABSENT = "absent"
    PRESENT = "present"
    MALFORMED = "malformed"


class PolicyState(enum.Enum):
    PASSED = "passed"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CertificateEntry:
    file_offset: int
    length: int
    revision: int
    certificate_type: int


@dataclass(frozen=True)
class CertificateTable:
    state: SignatureTableState
    file_offset: int = 0
    size: int = 0
    entries: tuple[CertificateEntry, ...] = ()
    error: str = ""

    @property
    def cryptographically_verified(self) -> bool:
        # Parsing WIN_CERTIFICATE framing does not validate Authenticode.
        return False


@dataclass(frozen=True)
class SbatEntry:
    component: str
    generation: int
    vendor_name: str
    vendor_package_name: str
    vendor_version: str
    vendor_url: str


@dataclass(frozen=True)
class SbatMetadata:
    state: SbatState
    text: str = ""
    entries: tuple[SbatEntry, ...] = ()
    section_offset: int = 0
    section_size: int = 0
    error: str = ""


@dataclass(frozen=True)
class PeSection:
    name: str
    raw_offset: int
    raw_size: int


@dataclass(frozen=True)
class UefiInspection:
    machine: int
    architecture: str
    pe_kind: str
    subsystem: int
    subsystem_name: str
    sections: tuple[PeSection, ...]
    certificate_table: CertificateTable
    sbat: SbatMetadata
    warnings: tuple[str, ...] = ()
    authenticode: AuthenticodeResult | None = None
    dbx: DbxAssessment | None = None

    @property
    def is_uefi_image(self) -> bool:
        return self.subsystem in EFI_SUBSYSTEMS


@dataclass(frozen=True)
class ImageUefiPayload:
    path: str
    architecture: str
    subsystem_name: str
    is_uefi_image: bool
    signature_state: SignatureTableState
    sbat_state: SbatState
    warnings: tuple[str, ...]
    authenticode: AuthenticodeResult | None = None
    dbx: DbxAssessment | None = None


@dataclass(frozen=True)
class ImageUefiAnalysis:
    payloads: tuple[ImageUefiPayload, ...]
    issues: tuple[str, ...] = ()
    candidate_count: int = 0
    selected_count: int = 0
    complete: bool = True


@dataclass(frozen=True)
class UefiMemberSelection:
    paths: tuple[str, ...]
    candidate_count: int
    complete: bool


@dataclass(frozen=True)
class SbatRequirement:
    component: str
    minimum_generation: int

    def __post_init__(self) -> None:
        if not self.component or any(ord(char) < 0x21 for char in self.component):
            raise ValueError("SBAT requirement component must be non-empty printable text")
        if self.minimum_generation < 0:
            raise ValueError("SBAT minimum generation cannot be negative")


@dataclass(frozen=True)
class PolicyDecision:
    state: PolicyState
    reasons: tuple[str, ...]

    @property
    def allowed(self) -> bool:
        """Unknown policy state fails closed."""

        return self.state is PolicyState.PASSED


def _need(blob: bytes, offset: int, length: int, label: str) -> memoryview:
    if offset < 0 or length < 0 or offset > len(blob) or length > len(blob) - offset:
        raise PeFormatError(f"{label} lies outside the PE file")
    return memoryview(blob)[offset:offset + length]


def _u16(blob: bytes, offset: int, label: str) -> int:
    return struct.unpack_from("<H", _need(blob, offset, 2, label))[0]


def _u32(blob: bytes, offset: int, label: str) -> int:
    return struct.unpack_from("<I", _need(blob, offset, 4, label))[0]


def _parse_certificate_table(blob: bytes, file_offset: int, size: int) -> CertificateTable:
    if file_offset == 0 and size == 0:
        return CertificateTable(SignatureTableState.ABSENT)
    if file_offset == 0 or size == 0:
        return CertificateTable(
            SignatureTableState.MALFORMED, file_offset, size,
            error="certificate-table offset and size must both be nonzero",
        )
    if file_offset % 8:
        return CertificateTable(
            SignatureTableState.MALFORMED, file_offset, size,
            error="certificate-table offset is not 8-byte aligned",
        )
    if file_offset > len(blob) or size > len(blob) - file_offset:
        return CertificateTable(
            SignatureTableState.MALFORMED, file_offset, size,
            error="certificate table extends beyond the PE file",
        )
    if size < 8:
        return CertificateTable(
            SignatureTableState.MALFORMED, file_offset, size,
            error="certificate table is smaller than WIN_CERTIFICATE",
        )

    entries: list[CertificateEntry] = []
    cursor = file_offset
    end = file_offset + size
    while cursor < end:
        if len(entries) >= MAX_CERTIFICATES:
            return CertificateTable(
                SignatureTableState.MALFORMED, file_offset, size, tuple(entries),
                "certificate table has too many entries",
            )
        remaining = end - cursor
        if remaining < 8:
            return CertificateTable(
                SignatureTableState.MALFORMED, file_offset, size, tuple(entries),
                "trailing certificate-table data is too short for WIN_CERTIFICATE",
            )
        length = _u32(blob, cursor, "WIN_CERTIFICATE length")
        revision = _u16(blob, cursor + 4, "WIN_CERTIFICATE revision")
        certificate_type = _u16(blob, cursor + 6, "WIN_CERTIFICATE type")
        if length < 8 or length > remaining:
            return CertificateTable(
                SignatureTableState.MALFORMED, file_offset, size, tuple(entries),
                "WIN_CERTIFICATE length is outside the certificate table",
            )
        entries.append(CertificateEntry(cursor, length, revision, certificate_type))
        aligned_length = (length + 7) & ~7
        if aligned_length > remaining:
            # Padding after the final certificate is included in directory size.
            return CertificateTable(
                SignatureTableState.MALFORMED, file_offset, size, tuple(entries),
                "WIN_CERTIFICATE alignment exceeds the certificate table",
            )
        if any(blob[cursor + length:cursor + aligned_length]):
            return CertificateTable(
                SignatureTableState.MALFORMED, file_offset, size, tuple(entries),
                "WIN_CERTIFICATE alignment padding must be zero",
            )
        cursor += aligned_length

    return CertificateTable(
        SignatureTableState.PRESENT_UNVERIFIED, file_offset, size, tuple(entries)
    )


def _decode_section_name(raw: bytes) -> str:
    name = raw.split(b"\0", 1)[0]
    if not name or any(byte < 0x20 or byte >= 0x7F for byte in name):
        raise PeFormatError("PE section has an invalid name")
    return name.decode("ascii")


def _parse_sbat_section(blob: bytes, sections: tuple[PeSection, ...]) -> SbatMetadata:
    candidates = [section for section in sections if section.name == ".sbat"]
    if not candidates:
        return SbatMetadata(SbatState.ABSENT)
    if len(candidates) != 1:
        return SbatMetadata(
            SbatState.MALFORMED, error="multiple .sbat sections are ambiguous"
        )
    section = candidates[0]
    if section.raw_size == 0:
        return SbatMetadata(
            SbatState.MALFORMED, section_offset=section.raw_offset,
            error=".sbat section is empty",
        )
    if section.raw_size > MAX_SBAT_SIZE:
        return SbatMetadata(
            SbatState.MALFORMED, section_offset=section.raw_offset,
            section_size=section.raw_size, error=".sbat section exceeds the size limit",
        )
    raw = bytes(_need(blob, section.raw_offset, section.raw_size, ".sbat section"))
    raw = raw.rstrip(b"\0")
    if b"\0" in raw:
        return SbatMetadata(
            SbatState.MALFORMED, section_offset=section.raw_offset,
            section_size=section.raw_size, error=".sbat contains embedded NUL bytes",
        )
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return SbatMetadata(
            SbatState.MALFORMED, section_offset=section.raw_offset,
            section_size=section.raw_size, error=".sbat is not valid UTF-8",
        )
    if any(char not in "\r\n\t" and ord(char) < 0x20 for char in text):
        return SbatMetadata(
            SbatState.MALFORMED, text=text, section_offset=section.raw_offset,
            section_size=section.raw_size, error=".sbat contains control characters",
        )

    entries: list[SbatEntry] = []
    components: set[str] = set()
    try:
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        for row_number, row in enumerate(reader, 1):
            if row_number > MAX_SBAT_ROWS:
                raise ValueError(".sbat has too many rows")
            if not row or all(not field for field in row):
                continue
            if len(row) != 6:
                raise ValueError(f".sbat row {row_number} does not have 6 fields")
            if any(len(field) > MAX_SBAT_FIELD_SIZE for field in row):
                raise ValueError(f".sbat row {row_number} has an oversized field")
            component, generation_text, vendor, package, version, url = row
            if (
                not component or component in components
                or any(ord(char) < 0x21 or char == "," for char in component)
            ):
                raise ValueError(f".sbat row {row_number} has an invalid or duplicate component")
            if not generation_text.isascii() or not generation_text.isdecimal():
                raise ValueError(f".sbat row {row_number} has an invalid generation")
            generation = int(generation_text)
            if generation > 0xFFFFFFFF:
                raise ValueError(f".sbat row {row_number} generation is too large")
            components.add(component)
            entries.append(SbatEntry(component, generation, vendor, package, version, url))
    except (csv.Error, ValueError) as error:
        return SbatMetadata(
            SbatState.MALFORMED, text, tuple(entries), section.raw_offset,
            section.raw_size, str(error),
        )
    if not entries:
        return SbatMetadata(
            SbatState.MALFORMED, text, section_offset=section.raw_offset,
            section_size=section.raw_size, error=".sbat contains no metadata rows",
        )
    return SbatMetadata(
        SbatState.PRESENT, text, tuple(entries), section.raw_offset, section.raw_size
    )


AuthenticodeVerifier = Callable[..., AuthenticodeResult]


def inspect_pe_bytes(
    blob: bytes,
    *,
    authenticode_timeout: float = WORKER_TIMEOUT_SECONDS,
    authenticode_verifier: AuthenticodeVerifier = verify_authenticode,
    authenticode_cancel_check: Callable[[], None] | None = None,
) -> UefiInspection:
    """Inspect a complete PE/COFF payload without modifying it."""

    if len(blob) > MAX_PE_SIZE:
        raise PeFormatError("PE image exceeds the inspection size limit")
    if len(blob) < 64 or blob[:2] != b"MZ":
        raise PeFormatError("PE image does not have an MZ header")
    pe_offset = _u32(blob, 0x3C, "PE header offset")
    if pe_offset < 64:
        raise PeFormatError("PE header offset overlaps the DOS header")
    if bytes(_need(blob, pe_offset, 4, "PE signature")) != b"PE\0\0":
        raise PeFormatError("PE signature is missing")

    coff = pe_offset + 4
    machine = _u16(blob, coff, "COFF machine")
    section_count = _u16(blob, coff + 2, "COFF section count")
    optional_size = _u16(blob, coff + 16, "COFF optional-header size")
    if section_count > MAX_SECTIONS:
        raise PeFormatError("PE image has too many sections")
    optional = coff + 20
    _need(blob, optional, optional_size, "PE optional header")
    if optional_size < 70:
        raise PeFormatError("PE optional header is too short")
    magic = _u16(blob, optional, "PE optional-header magic")
    if magic == 0x10B:
        pe_kind = "PE32"
        number_of_directories_offset = 92
        data_directories_offset = 96
    elif magic == 0x20B:
        pe_kind = "PE32+"
        number_of_directories_offset = 108
        data_directories_offset = 112
    else:
        raise PeFormatError(f"unsupported PE optional-header magic 0x{magic:04x}")
    if optional_size < number_of_directories_offset + 4:
        raise PeFormatError("PE optional header omits its data-directory count")

    subsystem = _u16(blob, optional + 68, "PE subsystem")
    directory_count = _u32(
        blob, optional + number_of_directories_offset, "PE data-directory count"
    )
    directories_that_fit = max(0, (optional_size - data_directories_offset) // 8)
    if directory_count > directories_that_fit:
        raise PeFormatError("PE data-directory count exceeds the optional header")

    security_offset = 0
    security_size = 0
    if directory_count > 4:
        security_directory = optional + data_directories_offset + 4 * 8
        security_offset = _u32(blob, security_directory, "certificate-table file offset")
        security_size = _u32(blob, security_directory + 4, "certificate-table size")
    certificate_table = _parse_certificate_table(blob, security_offset, security_size)

    section_table = optional + optional_size
    _need(blob, section_table, section_count * 40, "PE section table")
    sections: list[PeSection] = []
    for index in range(section_count):
        header = section_table + index * 40
        name = _decode_section_name(bytes(_need(blob, header, 8, "PE section name")))
        raw_size = _u32(blob, header + 16, f"{name} raw size")
        raw_offset = _u32(blob, header + 20, f"{name} raw offset")
        if raw_size:
            _need(blob, raw_offset, raw_size, f"{name} section data")
        elif raw_offset > len(blob):
            raise PeFormatError(f"{name} empty-section offset lies outside the PE file")
        sections.append(PeSection(name, raw_offset, raw_size))

    if certificate_table.state is SignatureTableState.PRESENT_UNVERIFIED:
        certificate_start = certificate_table.file_offset
        certificate_end = certificate_start + certificate_table.size
        header_end = section_table + section_count * 40
        overlaps_headers = certificate_start < header_end
        overlaps_section = any(
            section.raw_size
            and certificate_start < section.raw_offset + section.raw_size
            and section.raw_offset < certificate_end
            for section in sections
        )
        if overlaps_headers or overlaps_section:
            certificate_table = CertificateTable(
                SignatureTableState.MALFORMED, certificate_table.file_offset,
                certificate_table.size, certificate_table.entries,
                "certificate table overlaps PE headers or section data",
            )

    sbat = _parse_sbat_section(blob, tuple(sections))
    dbx = assess_dbx(blob, cancel_check=authenticode_cancel_check)
    authenticode: AuthenticodeResult | None = None
    if certificate_table.state is SignatureTableState.PRESENT_UNVERIFIED:
        facts = CertificateTableFacts(
            certificate_table.file_offset,
            certificate_table.size,
            tuple(
                WinCertificateFacts(
                    entry.file_offset, entry.length, entry.revision,
                    entry.certificate_type,
                )
                for entry in certificate_table.entries
            ),
        )
        authenticode = authenticode_verifier(
            blob, facts, timeout=authenticode_timeout,
            cancel_check=authenticode_cancel_check,
        )
    warnings: list[str] = []
    if machine not in MACHINE_ARCHITECTURES:
        warnings.append(f"unknown PE machine type 0x{machine:04x}")
    if subsystem not in EFI_SUBSYSTEMS:
        warnings.append(f"PE subsystem {subsystem} is not a UEFI subsystem")
    if certificate_table.state is SignatureTableState.PRESENT_UNVERIFIED:
        if (
            authenticode is not None
            and authenticode.state is AuthenticodeIntegrityState.VALID_UNTRUSTED
        ):
            warnings.append(
                "Authenticode integrity matches; signer trust, revocation, "
                "signing time, and Secure Boot acceptance were not evaluated"
            )
        elif authenticode is not None:
            warnings.append(
                f"Authenticode integrity {authenticode.state.value}: "
                f"{authenticode.error or 'no diagnostic was returned'}"
            )
        else:
            warnings.append("Authenticode integrity was not checked")
    elif certificate_table.state is SignatureTableState.MALFORMED:
        warnings.append(f"malformed certificate table: {certificate_table.error}")
    if sbat.state is SbatState.MALFORMED:
        warnings.append(f"malformed SBAT metadata: {sbat.error}")
    if dbx.state is DbxState.MATCHED_UNFLAGGED:
        warnings.append(
            "Authenticode SHA-256 matches an unflagged entry in the bundled "
            f"Microsoft DBX {dbx.snapshot_release} snapshot"
        )
    elif dbx.state is DbxState.MATCHED_OPTIONAL:
        warnings.append(
            "Authenticode SHA-256 matches an optional entry published with the "
            f"Microsoft DBX {dbx.snapshot_release} snapshot"
        )

    return UefiInspection(
        machine, MACHINE_ARCHITECTURES.get(machine, f"unknown (0x{machine:04x})"),
        pe_kind, subsystem, EFI_SUBSYSTEMS.get(subsystem, f"subsystem {subsystem}"),
        tuple(sections), certificate_table, sbat, tuple(warnings), authenticode, dbx,
    )


def inspect_pe_file(path: Path) -> UefiInspection:
    try:
        with path.open("rb", buffering=0) as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise OSError("The selected UEFI payload is not a regular file")
            if before.st_size > MAX_PE_SIZE:
                raise PeFormatError("PE image exceeds the inspection size limit")
            data = stream.read(MAX_PE_SIZE + 1)
            after = os.fstat(stream.fileno())
    except FileNotFoundError as error:
        raise OSError("The selected UEFI payload does not exist") from error
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(data) != before.st_size:
        raise OSError("The UEFI payload changed while it was being inspected")
    return inspect_pe_bytes(data)


def _safe_archive_member(path: str) -> str | None:
    portable = path.replace("\\", "/")
    if (
        not portable or portable.startswith("/") or portable.startswith("//")
        or re.match(r"^[A-Za-z]:", portable)
        or any(ord(character) < 0x20 for character in portable)
    ):
        return None
    pure = PurePosixPath(portable)
    if ".." in pure.parts or any(character in portable for character in "*?[]"):
        return None
    return pure.as_posix()


def _uefi_member_selection(paths: Iterable[str]) -> UefiMemberSelection:
    """Choose EFI payloads and retain whether the bounded selection is complete."""
    selected: list[tuple[int, str]] = []
    candidate_count = 0
    complete = True
    occupied: set[tuple[str, ...]] = set()
    for original in paths:
        path = _safe_archive_member(original)
        if path is None:
            portable = original.replace("\\", "/").casefold()
            if portable.endswith(".efi") and "efi/" in f"/{portable}":
                complete = False
            continue
        lowered = path.casefold()
        if not lowered.endswith(".efi") or not (
            lowered.startswith("efi/") or "/efi/" in f"/{lowered}"
        ):
            continue
        candidate_count += 1
        key = tuple(
            unicodedata.normalize("NFC", part).casefold()
            for part in PurePosixPath(path).parts
        )
        if key in occupied:
            complete = False
            continue
        occupied.add(key)
        name = PurePosixPath(lowered).name
        if lowered.startswith("efi/boot/boot"):
            priority = 0
        elif name in {"bootmgfw.efi", "cdboot.efi", "cdboot_noprompt.efi"}:
            priority = 1
        else:
            priority = 2
        selected.append((priority, path))
    ordered = sorted(dict.fromkeys(selected), key=lambda item: (item[0], item[1].casefold()))
    if len(ordered) > MAX_UEFI_MEMBERS:
        complete = False
    chosen = tuple(path for _, path in ordered[:MAX_UEFI_MEMBERS])
    return UefiMemberSelection(chosen, candidate_count, complete)


def uefi_member_paths(paths: Iterable[str]) -> tuple[str, ...]:
    """Choose a bounded, deterministic set of EFI payloads from an ISO catalog."""
    return _uefi_member_selection(paths).paths


ArchiveReader = Callable[[Path, str], bytes]


def inspect_iso_uefi_payloads(
    image: Path,
    member_paths: Iterable[str],
    *,
    reader: ArchiveReader | None = None,
    timeout: float = 30.0,
    image_fd: int | None = None,
    cancel_check: Callable[[], None] | None = None,
    authenticode_verifier: AuthenticodeVerifier = verify_authenticode,
) -> ImageUefiAnalysis:
    """Read selected EFI members without privilege and inspect their PE structure."""
    if image_fd is None:
        if not image.is_file():
            raise OSError("The selected image is not a regular file")
    elif not stat.S_ISREG(os.fstat(image_fd).st_mode):
        raise OSError("The selected image descriptor is not a regular file")
    started = time.monotonic()
    payloads: list[ImageUefiPayload] = []
    issues: list[str] = []
    selection = _uefi_member_selection(member_paths)
    for member in selection.paths:
        if cancel_check is not None:
            cancel_check()
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            issues.append("UEFI payload inspection reached its overall time limit")
            break
        try:
            blob = (
                reader(image, member)
                if reader is not None
                else read_archive_member_with_7z(
                    image, member, timeout=min(15.0, remaining), image_fd=image_fd,
                    cancel_check=cancel_check,
                )
            )
            if cancel_check is not None:
                cancel_check()
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                issues.append("UEFI payload inspection reached its overall time limit")
                break
            parsed = inspect_pe_bytes(
                blob,
                authenticode_timeout=min(WORKER_TIMEOUT_SECONDS, remaining),
                authenticode_verifier=authenticode_verifier,
                authenticode_cancel_check=cancel_check,
            )
            if cancel_check is not None:
                cancel_check()
            if timeout - (time.monotonic() - started) <= 0:
                issues.append("UEFI payload inspection reached its overall time limit")
                break
        except (OSError, TimeoutError, ValueError) as error:
            # A cancellation/deadline callback can intentionally use one of
            # these exception types.  Recheck it before treating a payload
            # parser failure as a nonfatal analysis issue.
            if cancel_check is not None:
                cancel_check()
            issues.append(f"{member}: {error}")
            continue
        payloads.append(ImageUefiPayload(
            member,
            parsed.architecture,
            parsed.subsystem_name,
            parsed.is_uefi_image,
            parsed.certificate_table.state,
            parsed.sbat.state,
            parsed.warnings,
            parsed.authenticode,
            parsed.dbx,
        ))
    complete = bool(
        selection.complete
        and not issues
        and len(payloads) == len(selection.paths)
    )
    return ImageUefiAnalysis(
        tuple(payloads), tuple(issues), selection.candidate_count,
        len(selection.paths), complete,
    )


def evaluate_sbat_policy(
    metadata: SbatMetadata, requirements: tuple[SbatRequirement, ...]
) -> PolicyDecision:
    """Evaluate externally supplied SBAT generation requirements.

    The requirements may eventually come from trusted DBX/update metadata;
    this function does not download or authenticate that policy source.
    Missing/malformed SBAT is ``UNKNOWN`` and therefore not allowed.
    """

    if metadata.state is SbatState.ABSENT:
        return PolicyDecision(PolicyState.UNKNOWN, ("SBAT metadata is absent",))
    if metadata.state is SbatState.MALFORMED:
        return PolicyDecision(
            PolicyState.UNKNOWN, (f"SBAT metadata is malformed: {metadata.error}",)
        )
    available = {entry.component: entry.generation for entry in metadata.entries}
    reasons: list[str] = []
    rejected = False
    for requirement in requirements:
        generation = available.get(requirement.component)
        if generation is None:
            rejected = True
            reasons.append(f"SBAT component {requirement.component!r} is missing")
        elif generation < requirement.minimum_generation:
            rejected = True
            reasons.append(
                f"SBAT component {requirement.component!r} generation {generation} "
                f"is below required {requirement.minimum_generation}"
            )
    if rejected:
        return PolicyDecision(PolicyState.REJECTED, tuple(reasons))
    return PolicyDecision(PolicyState.PASSED, ("SBAT generation requirements are satisfied",))
