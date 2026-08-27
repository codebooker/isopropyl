from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Offline Microsoft Secure Boot DBX Authenticode-hash advice.

The bundled data is a compact, reproducible projection of one Microsoft
``secureboot_objects`` release.  It is not the target machine's firmware DBX,
and a missing hash is never a Secure Boot, trust, or compatibility verdict.
"""

import enum
import hashlib
import json
import re
import struct
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files


CATALOG_RESOURCE = "microsoft-dbx-authenticode-v1.json"
CATALOG_SCHEMA_VERSION = 1
CATALOG_POLICY_ID = "microsoft-secureboot-dbx-authenticode-sha256"
CATALOG_SHA256 = "7019eb890a75e0ab3a1ff8e137ee66c6bc4f40644ddfc216fd0fdb74e7926874"
SOURCE_REPOSITORY = "https://github.com/microsoft/secureboot_objects"
SOURCE_RELEASE = "v1.6.5"
SOURCE_COMMIT = "798cdc513e0c192fe90e99637105748ed3bb4ca5"
SOURCE_PATH = "PreSignedObjects/DBX/dbx_info_msft_latest.json"
SOURCE_SHA256 = "1020f0ef865f8cf22740298d928a01355ab51cb1d8d473b637fd6d83f74eb3f5"
SOURCE_SIZE = 394_305
SOURCE_RELEASE_DATE = "2026-07-07"
SOURCE_LATEST_IMAGE_ADDITION = "2026-04-09"
SOURCE_LICENSE = "BSD-2-Clause-Patent"

MAX_CATALOG_BYTES = 64 * 1024
MAX_PE_BYTES = 256 * 1024 * 1024
MAX_SECTIONS = 96
MAX_STAGED_DBX_CANDIDATES = 64
HASH_CHUNK_BYTES = 1024 * 1024
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_ARCHITECTURE_COUNTS = {
    "x64": (289, 154),
    "ia32": (62, 32),
    "aarch64": (22, 4),
    "arm": (16, 94),
}
_MACHINE_ARCHITECTURES = {
    0x014C: "ia32",
    0x01C0: "arm",
    0x01C2: "arm",
    0x01C4: "arm",
    0x8664: "x64",
    0xAA64: "aarch64",
}


class DbxError(ValueError):
    """Bundled policy or PE data could not be evaluated exactly."""


class DbxState(enum.Enum):
    MATCHED_UNFLAGGED = "matched-unflagged"
    MATCHED_OPTIONAL = "matched-optional"
    NOT_LISTED_IN_SNAPSHOT = "not-listed-in-snapshot"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DbxCatalog:
    unflagged: tuple[tuple[str, frozenset[str]], ...]
    optional: tuple[tuple[str, frozenset[str]], ...]

    def hashes_for(self, architecture: str) -> tuple[frozenset[str], frozenset[str]]:
        unflagged = dict(self.unflagged).get(architecture)
        optional = dict(self.optional).get(architecture)
        if unflagged is None or optional is None:
            raise DbxError(f"unsupported DBX architecture {architecture!r}")
        return unflagged, optional


@dataclass(frozen=True)
class PeAuthenticodeDigest:
    machine: int
    architecture: str
    sha256: str

    def __post_init__(self) -> None:
        if self.architecture not in _ARCHITECTURE_COUNTS:
            raise ValueError("invalid DBX architecture")
        if _HEX_SHA256.fullmatch(self.sha256) is None:
            raise ValueError("invalid Authenticode SHA-256 digest")


@dataclass(frozen=True)
class DbxAssessment:
    state: DbxState
    architecture: str = ""
    authenticode_sha256: str = ""
    error: str = ""
    snapshot_release: str = SOURCE_RELEASE
    snapshot_commit: str = SOURCE_COMMIT
    snapshot_date: str = SOURCE_RELEASE_DATE

    def __post_init__(self) -> None:
        if not isinstance(self.state, DbxState):
            raise ValueError("invalid DBX assessment state")
        if (
            self.snapshot_release != SOURCE_RELEASE
            or self.snapshot_commit != SOURCE_COMMIT
            or self.snapshot_date != SOURCE_RELEASE_DATE
        ):
            raise ValueError("DBX assessment provenance does not match the pinned snapshot")
        if self.architecture and self.architecture not in _ARCHITECTURE_COUNTS:
            raise ValueError("invalid DBX assessment architecture")
        if (
            self.authenticode_sha256
            and _HEX_SHA256.fullmatch(self.authenticode_sha256) is None
        ):
            raise ValueError("invalid DBX assessment digest")
        if len(self.error) > 512 or any(character in "\r\n" for character in self.error):
            raise ValueError("invalid DBX assessment diagnostic")
        if self.state is DbxState.UNKNOWN:
            if not self.error:
                raise ValueError("unknown DBX assessments require a diagnostic")
        elif not self.architecture or not self.authenticode_sha256 or self.error:
            raise ValueError("conclusive DBX assessments require architecture and digest")

    @property
    def matched(self) -> bool:
        return self.state in {DbxState.MATCHED_UNFLAGGED, DbxState.MATCHED_OPTIONAL}


@dataclass(frozen=True)
class StagedDbxPayload:
    path: str
    dbx: DbxAssessment

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path:
            raise ValueError("staged DBX payload paths must be non-empty text")
        if not isinstance(self.dbx, DbxAssessment):
            raise ValueError("staged DBX payloads require a DBX assessment")


@dataclass(frozen=True)
class StagedDbxAnalysis:
    payloads: tuple[StagedDbxPayload, ...]
    candidate_count: int
    selected_count: int
    complete: bool
    issues: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.payloads, tuple)
            or any(not isinstance(item, StagedDbxPayload) for item in self.payloads)
            or type(self.candidate_count) is not int
            or type(self.selected_count) is not int
            or self.candidate_count < 0
            or self.selected_count < 0
            or self.selected_count > self.candidate_count
            or len(self.payloads) != self.selected_count
            or type(self.complete) is not bool
            or not isinstance(self.issues, tuple)
            or any(
                not isinstance(issue, str)
                or not issue
                or any(character in "\r\n" for character in issue)
                for issue in self.issues
            )
        ):
            raise ValueError("invalid staged DBX analysis")
        has_unknown = any(
            payload.dbx.state is DbxState.UNKNOWN for payload in self.payloads
        )
        if self.complete and (
            self.selected_count != self.candidate_count
            or has_unknown
            or self.issues
        ):
            raise ValueError("a complete staged DBX analysis must be conclusive")
        if not self.complete and not self.issues:
            raise ValueError("an incomplete staged DBX analysis requires a diagnostic")

    @property
    def matches(self) -> tuple[StagedDbxPayload, ...]:
        return tuple(payload for payload in self.payloads if payload.dbx.matched)


def merge_staged_dbx_analyses(
    *analyses: StagedDbxAnalysis,
) -> StagedDbxAnalysis:
    """Combine independently bound inventories without losing incompleteness."""
    if not analyses or any(
        not isinstance(analysis, StagedDbxAnalysis) for analysis in analyses
    ):
        raise ValueError("one or more staged DBX analyses are required")
    return StagedDbxAnalysis(
        tuple(
            payload
            for analysis in analyses
            for payload in analysis.payloads
        ),
        sum(analysis.candidate_count for analysis in analyses),
        sum(analysis.selected_count for analysis in analyses),
        all(analysis.complete for analysis in analyses),
        tuple(issue for analysis in analyses for issue in analysis.issues),
    )


def _duplicate_rejecting_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DbxError(f"duplicate DBX catalog key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise DbxError(f"invalid JSON constant {value!r}")


def _exact_mapping(value: object, keys: set[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise DbxError(f"{label} has unexpected fields")
    return value


def _parse_hashes(value: object, expected: int, label: str) -> frozenset[str]:
    if not isinstance(value, list) or len(value) != expected:
        raise DbxError(f"{label} has an unexpected number of hashes")
    if any(not isinstance(item, str) for item in value):
        raise DbxError(f"{label} contains a non-string hash")
    hashes = tuple(value)
    if any(_HEX_SHA256.fullmatch(item) is None for item in hashes):
        raise DbxError(f"{label} contains an invalid SHA-256 hash")
    if hashes != tuple(sorted(hashes)) or len(set(hashes)) != len(hashes):
        raise DbxError(f"{label} hashes are not strictly sorted and unique")
    return frozenset(hashes)


def parse_dbx_catalog(blob: bytes) -> DbxCatalog:
    if not isinstance(blob, bytes) or not blob or len(blob) > MAX_CATALOG_BYTES:
        raise DbxError("the bundled DBX catalog is missing or outside its size limit")
    if hashlib.sha256(blob).hexdigest() != CATALOG_SHA256:
        raise DbxError("the bundled DBX catalog digest does not match the release build")
    try:
        decoded = json.loads(
            blob.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DbxError("the bundled DBX catalog is not strict UTF-8 JSON") from error
    top = _exact_mapping(
        decoded, {"schema_version", "policy_id", "source", "architectures"},
        "DBX catalog",
    )
    if (
        type(top["schema_version"]) is not int
        or top["schema_version"] != CATALOG_SCHEMA_VERSION
    ):
        raise DbxError("the bundled DBX catalog schema is unsupported")
    if not isinstance(top["policy_id"], str) or top["policy_id"] != CATALOG_POLICY_ID:
        raise DbxError("the bundled DBX catalog policy identifier is unexpected")
    source = _exact_mapping(
        top["source"],
        {
            "repository", "release", "commit", "path", "sha256", "size",
            "release_date", "latest_image_addition", "license",
        },
        "DBX catalog source",
    )
    expected_source = {
        "repository": SOURCE_REPOSITORY,
        "release": SOURCE_RELEASE,
        "commit": SOURCE_COMMIT,
        "path": SOURCE_PATH,
        "sha256": SOURCE_SHA256,
        "size": SOURCE_SIZE,
        "release_date": SOURCE_RELEASE_DATE,
        "latest_image_addition": SOURCE_LATEST_IMAGE_ADDITION,
        "license": SOURCE_LICENSE,
    }
    if (
        any(type(source[key]) is not type(expected) for key, expected in expected_source.items())
        or source != expected_source
    ):
        raise DbxError("the bundled DBX catalog provenance is unexpected")
    architectures = _exact_mapping(
        top["architectures"], set(_ARCHITECTURE_COUNTS),
        "DBX catalog architectures",
    )
    unflagged: list[tuple[str, frozenset[str]]] = []
    optional: list[tuple[str, frozenset[str]]] = []
    for architecture in sorted(_ARCHITECTURE_COUNTS):
        groups = _exact_mapping(
            architectures[architecture], {"unflagged", "optional"},
            f"DBX {architecture} policy",
        )
        unflagged_count, optional_count = _ARCHITECTURE_COUNTS[architecture]
        unflagged_hashes = _parse_hashes(
            groups["unflagged"], unflagged_count,
            f"DBX {architecture} unflagged entries",
        )
        optional_hashes = _parse_hashes(
            groups["optional"], optional_count, f"DBX {architecture} optional policy",
        )
        if unflagged_hashes & optional_hashes:
            raise DbxError(f"DBX {architecture} unflagged and optional entries overlap")
        unflagged.append((architecture, unflagged_hashes))
        optional.append((architecture, optional_hashes))
    return DbxCatalog(tuple(unflagged), tuple(optional))


@lru_cache(maxsize=1)
def load_dbx_catalog() -> DbxCatalog:
    try:
        blob = files("isopropyl").joinpath("data", CATALOG_RESOURCE).read_bytes()
    except (OSError, TypeError) as error:
        raise DbxError("the bundled DBX catalog could not be read") from error
    return parse_dbx_catalog(blob)


def _need(blob: bytes, offset: int, length: int, label: str) -> memoryview:
    if offset < 0 or length < 0 or offset > len(blob) or length > len(blob) - offset:
        raise DbxError(f"{label} lies outside the PE image")
    return memoryview(blob)[offset:offset + length]


def _u16(blob: bytes, offset: int, label: str) -> int:
    return struct.unpack_from("<H", _need(blob, offset, 2, label))[0]


def _u32(blob: bytes, offset: int, label: str) -> int:
    return struct.unpack_from("<I", _need(blob, offset, 4, label))[0]


def _hash_range(
    digest: object,
    blob: bytes,
    start: int,
    end: int,
    cancel_check: Callable[[], None] | None,
) -> None:
    if start < 0 or end < start or end > len(blob):
        raise DbxError("an Authenticode hash range lies outside the PE image")
    for offset in range(start, end, HASH_CHUNK_BYTES):
        if cancel_check is not None:
            cancel_check()
        digest.update(memoryview(blob)[offset:min(end, offset + HASH_CHUNK_BYTES)])


def pe_authenticode_sha256(
    blob: bytes,
    *,
    cancel_check: Callable[[], None] | None = None,
) -> PeAuthenticodeDigest:
    """Compute the PE/COFF Authenticode image digest used by UEFI hash policy."""

    if cancel_check is not None:
        cancel_check()
    if not isinstance(blob, bytes) or len(blob) > MAX_PE_BYTES:
        raise DbxError("the PE image is not immutable bytes within the size limit")
    if len(blob) < 64 or blob[:2] != b"MZ":
        raise DbxError("the PE image does not have an MZ header")
    pe_offset = _u32(blob, 0x3C, "PE header offset")
    if pe_offset < 64 or bytes(_need(blob, pe_offset, 4, "PE signature")) != b"PE\0\0":
        raise DbxError("the PE signature is missing or overlaps the DOS header")
    coff = pe_offset + 4
    machine = _u16(blob, coff, "COFF machine")
    architecture = _MACHINE_ARCHITECTURES.get(machine)
    if architecture is None:
        raise DbxError(f"PE machine 0x{machine:04x} has no Microsoft DBX hash set")
    section_count = _u16(blob, coff + 2, "COFF section count")
    optional_size = _u16(blob, coff + 16, "COFF optional-header size")
    if section_count > MAX_SECTIONS:
        raise DbxError("the PE image has too many sections for DBX evaluation")
    optional = coff + 20
    optional_end = optional + optional_size
    _need(blob, optional, optional_size, "PE optional header")
    if optional_size < 70:
        raise DbxError("the PE optional header is too short for Authenticode hashing")
    magic = _u16(blob, optional, "PE optional-header magic")
    if magic == 0x10B:
        directory_count_offset = 92
        directories_offset = 96
    elif magic == 0x20B:
        directory_count_offset = 108
        directories_offset = 112
    else:
        raise DbxError(f"unsupported PE optional-header magic 0x{magic:04x}")
    expected_magic = 0x20B if architecture in {"x64", "aarch64"} else 0x10B
    if magic != expected_magic:
        raise DbxError("the PE machine and optional-header kind are inconsistent")
    subsystem = _u16(blob, optional + 68, "PE subsystem")
    if subsystem not in {10, 11, 12, 13}:
        raise DbxError("the PE image does not use a UEFI subsystem")
    if optional_size < directory_count_offset + 4:
        raise DbxError("the PE optional header omits its data-directory count")
    size_of_headers = _u32(blob, optional + 60, "PE SizeOfHeaders")
    checksum_offset = optional + 64
    section_table = optional_end
    section_table_end = section_table + section_count * 40
    if (
        size_of_headers < section_table_end
        or size_of_headers > len(blob)
        or checksum_offset + 4 > size_of_headers
    ):
        raise DbxError("PE SizeOfHeaders does not contain the complete header table")
    directory_count = _u32(
        blob, optional + directory_count_offset, "PE data-directory count",
    )
    directories_that_fit = max(0, (optional_size - directories_offset) // 8)
    if directory_count > directories_that_fit:
        raise DbxError("the PE data-directory count exceeds the optional header")

    security_offset = 0
    security_size = 0
    security_directory: int | None = None
    if directory_count > 4:
        security_directory = optional + directories_offset + 4 * 8
        if security_directory + 8 > size_of_headers:
            raise DbxError("the certificate-table directory lies outside PE headers")
        security_offset = _u32(blob, security_directory, "certificate-table file offset")
        security_size = _u32(blob, security_directory + 4, "certificate-table size")
        if bool(security_offset) != bool(security_size):
            raise DbxError("certificate-table offset and size must both be zero or nonzero")
        if security_size:
            if security_offset % 8:
                raise DbxError("the certificate table is not 8-byte aligned")
            _need(blob, security_offset, security_size, "certificate table")
            if security_offset < size_of_headers:
                raise DbxError("the certificate table overlaps PE headers")

    file_alignment = _u32(blob, optional + 36, "PE FileAlignment")
    if not file_alignment or file_alignment & (file_alignment - 1):
        raise DbxError("PE FileAlignment is not a nonzero power of two")

    sections: list[tuple[int, int, int]] = []
    for index in range(section_count):
        header = section_table + index * 40
        raw_size = _u32(blob, header + 16, "PE section raw size")
        raw_offset = _u32(blob, header + 20, "PE section raw offset")
        virtual_address = _u32(blob, header + 12, "PE section virtual address")
        if not raw_size:
            continue
        if raw_offset < size_of_headers:
            raise DbxError("a PE section overlaps the image headers")
        _need(blob, raw_offset, raw_size, "PE section data")
        sections.append((raw_offset, raw_size, virtual_address))
    sections.sort(key=lambda section: section[0])
    previous_end = size_of_headers
    for raw_offset, raw_size, _virtual_address in sections:
        if raw_offset < previous_end:
            raise DbxError("PE sections overlap in the file image")
        previous_end = raw_offset + raw_size
    if security_size and any(
        raw_offset < security_offset + security_size
        and security_offset < raw_offset + raw_size
        for raw_offset, raw_size, _virtual_address in sections
    ):
        raise DbxError("the certificate table overlaps PE section data")
    if security_size:
        if security_offset < previous_end or security_offset + security_size != len(blob):
            raise DbxError("the PE certificate table is not the terminal file region")

    # First reproduce the Authenticode implementation used to produce the
    # pinned Microsoft JSON: omit CheckSum, the security-directory entry, and
    # the exact certificate-table byte range (which may be empty for unsigned
    # images).  This correctly covers unsigned PE files too.
    catalog_digest = hashlib.sha256()
    _hash_range(catalog_digest, blob, 0, checksum_offset, cancel_check)
    if security_directory is None:
        _hash_range(
            catalog_digest, blob, checksum_offset + 4, len(blob), cancel_check,
        )
    else:
        _hash_range(
            catalog_digest, blob, checksum_offset + 4, security_directory,
            cancel_check,
        )
        if security_size:
            if security_offset < security_directory + 8:
                raise DbxError("the certificate table precedes the end of PE headers")
            _hash_range(
                catalog_digest, blob, security_directory + 8, security_offset,
                cancel_check,
            )
            _hash_range(
                catalog_digest, blob, security_offset + security_size, len(blob),
                cancel_check,
            )
        else:
            _hash_range(
                catalog_digest, blob, security_directory + 8, len(blob), cancel_check,
            )

    # Independently reproduce the UEFI/TianoCore reference layout: hash the
    # filtered headers, sections ordered by raw file offset, and pre-certificate
    # extra data.  A noncanonical PE for which
    # these two authoritative interpretations differ is UNKNOWN, avoiding a
    # misleading catalog decision that firmware may calculate differently.
    reference_digest = hashlib.sha256()
    _hash_range(reference_digest, blob, 0, checksum_offset, cancel_check)
    after_checksum = checksum_offset + 4
    if security_directory is None:
        _hash_range(
            reference_digest, blob, after_checksum, size_of_headers, cancel_check,
        )
    else:
        _hash_range(
            reference_digest, blob, after_checksum, security_directory, cancel_check,
        )
        _hash_range(
            reference_digest, blob, security_directory + 8, size_of_headers,
            cancel_check,
        )
    sum_of_bytes_hashed = size_of_headers
    for raw_offset, raw_size, _virtual_address in sections:
        _hash_range(
            reference_digest, blob, raw_offset, raw_offset + raw_size, cancel_check,
        )
        sum_of_bytes_hashed += raw_size
    if len(blob) < sum_of_bytes_hashed + security_size:
        raise DbxError("PE sections and certificate size exceed the image")
    extra_end = len(blob) - security_size
    _hash_range(
        reference_digest, blob, sum_of_bytes_hashed, extra_end, cancel_check,
    )

    # Rufus's PE256 path uses the same filtered headers and raw-file ordering,
    # but rounds each section's raw size to FileAlignment.  Require its result
    # to agree as well before making a catalog claim.
    rufus_digest = hashlib.sha256()
    _hash_range(rufus_digest, blob, 0, checksum_offset, cancel_check)
    if security_directory is None:
        _hash_range(
            rufus_digest, blob, after_checksum, size_of_headers, cancel_check,
        )
    else:
        _hash_range(
            rufus_digest, blob, after_checksum, security_directory, cancel_check,
        )
        _hash_range(
            rufus_digest, blob, security_directory + 8, size_of_headers,
            cancel_check,
        )
    rufus_sum = size_of_headers
    rufus_previous_end = size_of_headers
    for raw_offset, raw_size, _virtual_address in sections:
        aligned_size = (raw_size + file_alignment - 1) & ~(file_alignment - 1)
        if aligned_size < raw_size:
            raise DbxError("a PE section's aligned size overflows")
        _need(blob, raw_offset, aligned_size, "Rufus-aligned PE section data")
        if raw_offset < rufus_previous_end:
            raise DbxError("Rufus-aligned PE sections overlap")
        _hash_range(
            rufus_digest, blob, raw_offset, raw_offset + aligned_size, cancel_check,
        )
        rufus_previous_end = raw_offset + aligned_size
        rufus_sum += aligned_size
    if len(blob) < rufus_sum + security_size:
        raise DbxError("Rufus-aligned sections and certificate exceed the image")
    _hash_range(
        rufus_digest, blob, rufus_sum, extra_end, cancel_check,
    )
    if cancel_check is not None:
        cancel_check()
    catalog_sha256 = catalog_digest.hexdigest()
    if (
        reference_digest.hexdigest() != catalog_sha256
        or rufus_digest.hexdigest() != catalog_sha256
    ):
        raise DbxError(
            "the PE layout has divergent Microsoft, firmware, or Rufus image digests"
        )
    return PeAuthenticodeDigest(machine, architecture, catalog_sha256)


def assess_dbx(
    blob: bytes,
    *,
    cancel_check: Callable[[], None] | None = None,
    catalog: DbxCatalog | None = None,
) -> DbxAssessment:
    """Compare one PE image to the pinned snapshot without claiming firmware state."""

    try:
        measured = pe_authenticode_sha256(blob, cancel_check=cancel_check)
        selected_catalog = catalog if catalog is not None else load_dbx_catalog()
        unflagged, optional = selected_catalog.hashes_for(measured.architecture)
    except DbxError as error:
        message = " ".join(str(error).split())[:512] or "DBX evaluation failed"
        return DbxAssessment(DbxState.UNKNOWN, error=message)
    if measured.sha256 in unflagged:
        state = DbxState.MATCHED_UNFLAGGED
    elif measured.sha256 in optional:
        state = DbxState.MATCHED_OPTIONAL
    else:
        state = DbxState.NOT_LISTED_IN_SNAPSHOT
    return DbxAssessment(state, measured.architecture, measured.sha256)


def assess_staged_dbx(
    plan: object,
    *,
    cancel_check: Callable[[], None] | None = None,
    catalog: DbxCatalog | None = None,
) -> StagedDbxAnalysis:
    """Assess a bounded EFI inventory bound to a constructed-media plan."""
    from .constructed import (
        ConstructedMediaPlan, ConstructedMediaSafetyError,
        read_bound_staged_file,
    )

    if not isinstance(plan, ConstructedMediaPlan):
        raise DbxError("a constructed-media plan is required for staged DBX analysis")
    candidates = []
    for entry in plan.files:
        lowered = tuple(part.casefold() for part in entry.parts)
        # EFI applications can be chainloaded from locations other than the
        # conventional EFI directory.  Assess every final `.efi` file so an
        # additive overlay or generated wrapper cannot evade review merely by
        # choosing a nonstandard path.
        if not lowered or not lowered[-1].endswith(".efi"):
            continue
        name = lowered[-1]
        if (
            len(lowered) == 3
            and lowered[:2] == ("efi", "boot")
            and name.startswith("boot")
        ):
            priority = 0
        elif name in {"bootmgfw.efi", "cdboot.efi", "cdboot_noprompt.efi"}:
            priority = 1
        else:
            priority = 2
        key = tuple(
            unicodedata.normalize("NFC", part).casefold()
            for part in entry.parts
        )
        candidates.append((priority, key, entry))
    candidates.sort(key=lambda item: (item[0], item[1]))
    selected = candidates[:MAX_STAGED_DBX_CANDIDATES]
    complete = len(selected) == len(candidates)
    payloads: list[StagedDbxPayload] = []
    issues: list[str] = []
    for _priority, _key, entry in selected:
        if cancel_check is not None:
            cancel_check()
        try:
            blob = read_bound_staged_file(
                plan, entry, max_bytes=MAX_PE_BYTES, cancel_check=cancel_check,
            )
        except ConstructedMediaSafetyError as error:
            message = " ".join(str(error).split())[:512] or "staged EFI read failed"
            issues.append(f"{entry.path}: {message}")
            payloads.append(StagedDbxPayload(
                entry.path, DbxAssessment(DbxState.UNKNOWN, error=message),
            ))
            complete = False
            continue
        assessment = assess_dbx(
            blob, cancel_check=cancel_check, catalog=catalog,
        )
        payloads.append(StagedDbxPayload(entry.path, assessment))
        if assessment.state is DbxState.UNKNOWN:
            issues.append(f"{entry.path}: {assessment.error}")
            complete = False
    if len(candidates) > len(selected):
        issues.append(
            f"selected {len(selected)} of {len(candidates)} staged EFI candidates"
        )
    if cancel_check is not None:
        cancel_check()
    return StagedDbxAnalysis(
        tuple(payloads), len(candidates), len(selected), complete, tuple(issues),
    )
