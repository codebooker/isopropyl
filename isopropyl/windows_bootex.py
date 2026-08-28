from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Conservative Windows UEFI CA 2023 (``BootEx``) staging transform.

The transform is deliberately narrower than a general WIM editor.  A caller
must first extract ``Windows\\Boot\\EFI_EX`` and ``Windows\\Boot\\Fonts_EX``
from the setup image in ``sources/boot.wim`` into a private directory.  This
module then:

* binds the source ISO to an exact Microsoft-published SHA-256 in ISOpropyl's
  bundled Windows catalog;
* treats the extracted directory as untrusted and accepts only a shallow,
  bounded, regular-file tree;
* requires structurally signed EFI applications for the selected architecture;
* replaces only the removable-media fallback loader, ``/bootmgr.efi``, and
  direct boot-font files in an already-private staging tree; and
* returns old/new SHA-256 evidence in a receipt-bound immutable result.

The catalog hash establishes the identity of the ISO, not the trust chain of
an individual PE signature.  The extraction linkage remains a caller boundary:
the caller must extract the two directories from the bound ISO's boot WIM.
No Microsoft CA-chain, revocation, signing-time, or target-firmware trust is
claimed here.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .authenticode import AuthenticodeIntegrityState, AuthenticodeResult
from .uefi import PeFormatError, SignatureTableState, inspect_pe_bytes
from .windows_downloads import available_windows_images


MIB = 1024 * 1024
MAX_EXTRACTED_FILES = 128
MAX_FONT_FILES = 64
MAX_EXTRACTED_FILE_BYTES = 64 * MIB
MAX_EXTRACTED_TOTAL_BYTES = 256 * MIB
COPY_CHUNK_BYTES = MIB

TRUST_BASIS = "exact-microsoft-published-whole-iso-sha256"
TRUST_SCOPE = (
    "The selected ISO exactly matches a bundled Microsoft-published whole-ISO "
    "SHA-256. Extracted-file PE signatures are only structurally present; "
    "certificate-chain, revocation, signing-time, Windows UEFI CA 2023, and "
    "target-firmware trust are not evaluated."
)
EXTRACTION_BOUNDARY = (
    "The caller must extract EFI_EX and Fonts_EX from sources/boot.wim in the "
    "bound ISO; this transform validates but cannot independently prove that "
    "WIM-to-directory linkage."
)

_SUPPORTED_RELEASES = frozenset({
    "windows-11-25h2-v2-english-x64",
    "windows-11-25h2-v2-english-arm64",
})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FONT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.ttf\Z", re.IGNORECASE)
_ARCHITECTURES = {
    "x64": ("x64", "efi/boot/bootx64.efi"),
    "arm64": ("ARM64", "efi/boot/bootaa64.efi"),
}
_DIR_FLAGS = (
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = (
    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_TEMP_FLAGS = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_PLAN_PROFILE = "io.github.codebooker.isopropyl/windows-bootex-plan/v1"
_RECEIPT_PROFILE = "io.github.codebooker.isopropyl/windows-bootex-receipt/v1"
_PLAN_WITNESS = object()

CancelCheck = Callable[[], None]
FileIdentity = tuple[int, int, int, int, int, int, int]
DirectoryIdentity = tuple[int, int]


class BootExError(RuntimeError):
    """Base class for BootEx staging failures."""


class BootExProvenanceError(BootExError, ValueError):
    """The source is not one of the exact supported official ISO profiles."""


class BootExSafetyError(BootExError):
    """The extracted or staging tree cannot satisfy the safety contract."""


@dataclass(frozen=True)
class BootExProfile:
    release_id: str
    product: str
    release: str
    language: str
    architecture: str
    filename: str
    iso_size: int
    iso_sha256: str
    provenance_url: str
    fallback_path: str
    trust_basis: str = TRUST_BASIS
    trust_scope: str = TRUST_SCOPE


@dataclass(frozen=True)
class WindowsBootExOptions:
    """User-facing, default-off authorization for the BootEx transform."""

    enabled: bool = False
    acknowledge_firmware_compatibility: bool = False

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool or type(
            self.acknowledge_firmware_compatibility
        ) is not bool:
            raise ValueError("Windows BootEx options must be boolean")
        if self.acknowledge_firmware_compatibility and not self.enabled:
            raise ValueError(
                "Windows BootEx firmware acknowledgment requires the feature"
            )


@dataclass(frozen=True)
class BootExRequest:
    source_iso: Path
    extracted_root: Path
    staging_root: Path
    architecture: str | None = None
    expected_release_id: str | None = None


@dataclass(frozen=True)
class BootExIsoEvidence:
    path: Path
    identity: FileIdentity
    size: int
    sha256: str


@dataclass(frozen=True)
class BootExSourceBinding:
    """A planning-time whole-ISO identity for later private-tree execution."""

    profile: BootExProfile
    source_iso: BootExIsoEvidence


@dataclass(frozen=True)
class BootExPeEvidence:
    architecture: str
    subsystem: str
    signature_table_state: str
    signature_trust_evaluated: bool = False


@dataclass(frozen=True)
class BootExReplacementPlan:
    kind: str
    source_path: str
    destination_path: str
    source_parent_identity: DirectoryIdentity
    source_identity: FileIdentity
    destination_parent_identity: DirectoryIdentity
    destination_identity: FileIdentity
    old_size: int
    old_sha256: str
    new_size: int
    new_sha256: str
    pe: BootExPeEvidence | None = None


@dataclass(frozen=True)
class BootExPlan:
    profile: BootExProfile
    source_iso: BootExIsoEvidence
    extracted_root: Path
    extracted_root_identity: DirectoryIdentity
    staging_root: Path
    staging_root_identity: DirectoryIdentity
    replacements: tuple[BootExReplacementPlan, ...]
    ignored_extracted_files: tuple[str, ...]
    extraction_boundary: str
    plan_sha256: str
    _witness: object | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class BootExReplacementReceipt:
    kind: str
    destination_path: str
    old_size: int
    old_sha256: str
    new_size: int
    new_sha256: str
    pe: BootExPeEvidence | None = None


@dataclass(frozen=True)
class BootExResult:
    release_id: str
    architecture: str
    source_iso_sha256: str
    trust_basis: str
    trust_scope: str
    extraction_boundary: str
    replacements: tuple[BootExReplacementReceipt, ...]
    receipt_sha256: str
    signature_trust_evaluated: bool = False


@dataclass(frozen=True)
class _FileSnapshot:
    identity: FileIdentity
    size: int
    sha256: str
    blob: bytes | None = None


@dataclass(frozen=True)
class _ExtractedFile:
    path: str
    parent_identity: DirectoryIdentity
    snapshot: _FileSnapshot


def _check_cancel(cancel_check: CancelCheck | None) -> None:
    if cancel_check is not None:
        cancel_check()


def _file_identity(value: os.stat_result) -> FileIdentity:
    return (
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns, value.st_nlink, value.st_mode,
    )


def _directory_identity(value: os.stat_result) -> DirectoryIdentity:
    return value.st_dev, value.st_ino


def _case_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _safe_component(value: str, rendered: str) -> None:
    if (
        not value or value in {".", ".."} or "\x00" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or "/" in value or "\\" in value
    ):
        raise BootExSafetyError(f"Unsafe BootEx path component: {rendered!r}")


def _list_unique(directory_fd: int, rendered: str) -> tuple[str, ...]:
    try:
        names = tuple(sorted(os.listdir(directory_fd), key=lambda item: (_case_key(item), item)))
    except OSError as error:
        raise BootExSafetyError(f"Could not enumerate {rendered!r}") from error
    occupied: dict[str, str] = {}
    for name in names:
        _safe_component(name, f"{rendered}/{name}")
        key = _case_key(name)
        if key in occupied:
            raise BootExSafetyError(
                f"Case or Unicode collision in {rendered!r}: "
                f"{occupied[key]!r} and {name!r}"
            )
        occupied[key] = name
    return names


def _open_root(path: Path, label: str) -> tuple[Path, int, os.stat_result]:
    descriptor = -1
    try:
        raw = Path(path).expanduser()
        linked = os.lstat(raw)
        if not stat.S_ISDIR(linked.st_mode) or stat.S_ISLNK(linked.st_mode):
            raise BootExSafetyError(f"{label} must be one no-follow directory")
        resolved = raw.resolve(strict=True)
        descriptor = os.open(resolved, _DIR_FLAGS)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(status.st_mode)
            or _directory_identity(status) != _directory_identity(linked)
        ):
            raise BootExSafetyError(f"{label} changed while it was opened")
        return resolved, descriptor, status
    except BootExSafetyError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except (OSError, RuntimeError) as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise BootExSafetyError(f"Could not open {label}") from error


def _open_directory_at(
    root_fd: int, parts: tuple[str, ...], label: str,
) -> tuple[int, os.stat_result]:
    descriptor = os.dup(root_fd)
    try:
        for index, part in enumerate(parts):
            rendered_parent = PurePosixPath(*parts[:index]).as_posix() or "."
            names = _list_unique(descriptor, f"{label}:{rendered_parent}")
            if part not in names:
                alias = next((item for item in names if _case_key(item) == _case_key(part)), None)
                if alias is not None:
                    raise BootExSafetyError(
                        f"BootEx path has unexpected case: {alias!r}; expected {part!r}"
                    )
                raise BootExSafetyError(
                    f"Required BootEx directory is missing: "
                    f"{PurePosixPath(*parts[:index + 1]).as_posix()!r}"
                )
            child = os.open(part, _DIR_FLAGS, dir_fd=descriptor)
            status = os.fstat(child)
            if not stat.S_ISDIR(status.st_mode):
                os.close(child)
                raise BootExSafetyError("BootEx path traverses a non-directory")
            os.close(descriptor)
            descriptor = child
        return descriptor, os.fstat(descriptor)
    except BootExSafetyError:
        os.close(descriptor)
        raise
    except OSError as error:
        os.close(descriptor)
        raise BootExSafetyError(
            f"Could not open a no-follow directory below {label}"
        ) from error


def _snapshot_file_at(
    parent_fd: int,
    name: str,
    rendered: str,
    *,
    include_blob: bool,
    max_bytes: int = MAX_EXTRACTED_FILE_BYTES,
    cancel_check: CancelCheck | None = None,
) -> _FileSnapshot:
    descriptor = -1
    try:
        linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(linked.st_mode) or linked.st_nlink != 1:
            raise BootExSafetyError(
                f"BootEx file must be one no-follow regular file: {rendered!r}"
            )
        descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _file_identity(before) != _file_identity(linked)
        ):
            raise BootExSafetyError(
                f"BootEx file must be one no-follow regular file: {rendered!r}"
            )
        if before.st_size <= 0:
            raise BootExSafetyError(f"BootEx file is empty: {rendered!r}")
        if before.st_size > max_bytes:
            raise BootExSafetyError(f"BootEx file exceeds the size limit: {rendered!r}")
        digest = hashlib.sha256()
        blocks: list[bytes] | None = [] if include_blob else None
        total = 0
        while True:
            _check_cancel(cancel_check)
            block = os.read(descriptor, min(COPY_CHUNK_BYTES, max_bytes + 1 - total))
            if not block:
                break
            total += len(block)
            if total > max_bytes:
                raise BootExSafetyError(f"BootEx file exceeds the size limit: {rendered!r}")
            digest.update(block)
            if blocks is not None:
                blocks.append(block)
        after = os.fstat(descriptor)
        linked_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            total != before.st_size
            or _file_identity(after) != _file_identity(before)
            or _file_identity(linked_after) != _file_identity(before)
        ):
            raise BootExSafetyError(f"BootEx file changed while hashing: {rendered!r}")
        return _FileSnapshot(
            _file_identity(before), total, digest.hexdigest(),
            b"".join(blocks) if blocks is not None else None,
        )
    except BootExSafetyError:
        raise
    except OSError as error:
        raise BootExSafetyError(f"Could not inspect BootEx file: {rendered!r}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _hash_source_iso(
    path: Path,
    *,
    architecture: str | None,
    expected_release_id: str | None,
    cancel_check: CancelCheck | None,
) -> tuple[BootExIsoEvidence, BootExProfile]:
    descriptor = -1
    try:
        raw = Path(path).expanduser()
        parent = raw.parent.resolve(strict=True)
        resolved = parent / raw.name
        descriptor = os.open(resolved, _READ_FLAGS)
        before = os.fstat(descriptor)
        linked = os.lstat(resolved)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _file_identity(before) != _file_identity(linked)
        ):
            raise BootExProvenanceError("The source ISO must be one no-follow regular file")
        wanted_arch = _normalize_architecture(architecture) if architecture is not None else None
        candidates = tuple(
            profile for profile in available_bootex_profiles()
            if profile.iso_size == before.st_size
            and (wanted_arch is None or profile.architecture == wanted_arch)
            and (expected_release_id is None or profile.release_id == expected_release_id)
        )
        if len(candidates) != 1:
            raise BootExProvenanceError(
                "The ISO size, architecture, and release do not identify exactly one "
                "supported official Windows BootEx profile"
            )
        digest = hashlib.sha256()
        total = 0
        while True:
            _check_cancel(cancel_check)
            block = os.read(descriptor, COPY_CHUNK_BYTES)
            if not block:
                break
            total += len(block)
            digest.update(block)
        after = os.fstat(descriptor)
        linked_after = os.lstat(resolved)
        if (
            total != before.st_size
            or _file_identity(after) != _file_identity(before)
            or _file_identity(linked_after) != _file_identity(before)
        ):
            raise BootExProvenanceError("The source ISO changed while it was hashed")
        observed = digest.hexdigest()
        profile = candidates[0]
        if not hmac.compare_digest(observed, profile.iso_sha256):
            raise BootExProvenanceError(
                "The source ISO SHA-256 does not match the Microsoft-published profile"
            )
        return (
            BootExIsoEvidence(resolved, _file_identity(before), total, observed),
            profile,
        )
    except BootExProvenanceError:
        raise
    except (OSError, RuntimeError) as error:
        raise BootExProvenanceError("Could not bind the source ISO") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _normalize_architecture(value: str) -> str:
    if not isinstance(value, str):
        raise BootExProvenanceError("BootEx architecture must be x64 or arm64")
    normalized = value.casefold()
    if normalized not in _ARCHITECTURES:
        raise BootExProvenanceError("BootEx architecture must be x64 or arm64")
    return normalized


def available_bootex_profiles() -> tuple[BootExProfile, ...]:
    """Return only catalog entries explicitly reviewed for this transform."""

    profiles: list[BootExProfile] = []
    for release in available_windows_images():
        if release.id not in _SUPPORTED_RELEASES:
            continue
        architecture = _normalize_architecture(release.architecture)
        profiles.append(BootExProfile(
            release.id, release.product, release.release, release.language,
            architecture, release.filename, release.size, release.sha256,
            release.provenance_url, _ARCHITECTURES[architecture][1],
        ))
    profiles.sort(key=lambda item: item.release_id)
    if {item.release_id for item in profiles} != _SUPPORTED_RELEASES:
        raise BootExProvenanceError(
            "The bundled Windows catalog no longer contains every reviewed BootEx profile"
        )
    if any(
        not _SHA256.fullmatch(item.iso_sha256)
        or item.trust_basis != TRUST_BASIS
        or item.trust_scope != TRUST_SCOPE
        for item in profiles
    ):
        raise BootExProvenanceError("A reviewed BootEx profile is malformed")
    return tuple(profiles)


def profile_for_official_iso(
    size: int, sha256: str, *, architecture: str | None = None,
) -> BootExProfile:
    """Resolve an exact supported profile from a whole-ISO identity."""

    if (
        isinstance(size, bool) or not isinstance(size, int) or size <= 0
        or not isinstance(sha256, str) or not _SHA256.fullmatch(sha256)
    ):
        raise BootExProvenanceError("Invalid whole-ISO identity")
    wanted_arch = _normalize_architecture(architecture) if architecture is not None else None
    matches = tuple(
        item for item in available_bootex_profiles()
        if item.iso_size == size and hmac.compare_digest(item.iso_sha256, sha256)
        and (wanted_arch is None or item.architecture == wanted_arch)
    )
    if len(matches) != 1:
        raise BootExProvenanceError(
            "The whole-ISO identity is not an exact supported official Windows profile"
        )
    return matches[0]


def bind_bootex_source(
    source_iso: Path,
    *,
    architecture: str | None = None,
    expected_release_id: str | None = None,
    cancel_check: CancelCheck | None = None,
) -> BootExSourceBinding:
    """Hash and bind one exact reviewed Microsoft ISO before confirmation."""

    evidence, profile = _hash_source_iso(
        source_iso,
        architecture=architecture,
        expected_release_id=expected_release_id,
        cancel_check=cancel_check,
    )
    return BootExSourceBinding(profile, evidence)


def validate_bootex_source_binding(binding: BootExSourceBinding) -> None:
    """Recheck a source binding without repeating its complete whole-file hash."""

    if not isinstance(binding, BootExSourceBinding):
        raise BootExSafetyError("A Windows BootEx source binding is required")
    if not isinstance(binding.profile, BootExProfile):
        raise BootExSafetyError("The Windows BootEx profile is malformed")
    reviewed = profile_for_official_iso(
        binding.profile.iso_size,
        binding.profile.iso_sha256,
        architecture=binding.profile.architecture,
    )
    if reviewed != binding.profile:
        raise BootExSafetyError("The Windows BootEx profile is no longer reviewed")
    evidence = binding.source_iso
    if (
        not isinstance(evidence, BootExIsoEvidence)
        or not isinstance(evidence.path, Path)
        or type(evidence.identity) is not tuple
        or len(evidence.identity) != 7
        or evidence.size != reviewed.iso_size
        or evidence.sha256 != reviewed.iso_sha256
        or evidence.identity[2] != reviewed.iso_size
        or not evidence.path.is_absolute()
    ):
        raise BootExSafetyError("The Windows BootEx source binding is malformed")
    _verify_iso_identity(evidence)


def _not_evaluated_authenticode(*_args, **_kwargs) -> AuthenticodeResult:
    return AuthenticodeResult(
        AuthenticodeIntegrityState.INDETERMINATE,
        error="BootEx performs structural signature-table validation only",
    )


def _inspect_bootex_pe(blob: bytes, expected_architecture: str) -> BootExPeEvidence:
    try:
        inspection = inspect_pe_bytes(
            blob, authenticode_verifier=_not_evaluated_authenticode,
        )
    except PeFormatError as error:
        raise BootExSafetyError("BootEx EFI payload is not a valid PE image") from error
    expected_pe = _ARCHITECTURES[expected_architecture][0]
    if inspection.architecture != expected_pe:
        raise BootExSafetyError(
            f"BootEx EFI payload architecture {inspection.architecture!r} does not "
            f"match {expected_pe!r}"
        )
    if inspection.subsystem != 10:
        raise BootExSafetyError("BootEx EFI payload is not an EFI application")
    if inspection.certificate_table.state is not SignatureTableState.PRESENT_UNVERIFIED:
        raise BootExSafetyError(
            "BootEx EFI payload does not have one structurally valid signature table"
        )
    return BootExPeEvidence(
        inspection.architecture,
        inspection.subsystem_name,
        inspection.certificate_table.state.value,
    )


def _destination_font_name(source_name: str) -> str:
    """Apply Rufus/Microsoft's literal ``_EX`` destination-name removal."""

    destination = source_name.replace("_EX", "")
    if _FONT_NAME.fullmatch(destination) is None:
        raise BootExSafetyError(
            f"BootEx boot font has no safe destination name: {source_name!r}"
        )
    return destination


def _scan_extracted_tree(
    root_fd: int,
    root_device: int,
    *,
    cancel_check: CancelCheck | None,
) -> dict[str, _ExtractedFile]:
    root_names = _list_unique(root_fd, "extracted-root")
    if set(root_names) != {"EFI_EX", "Fonts_EX"}:
        raise BootExSafetyError(
            "The extracted BootEx root must contain exactly EFI_EX and Fonts_EX"
        )
    files: dict[str, _ExtractedFile] = {}
    total_bytes = 0
    for directory_name in ("EFI_EX", "Fonts_EX"):
        directory_fd, directory_status = _open_directory_at(
            root_fd, (directory_name,), "extracted-root",
        )
        try:
            if directory_status.st_dev != root_device:
                raise BootExSafetyError("Cross-filesystem BootEx extraction is forbidden")
            parent_identity = _directory_identity(directory_status)
            names = _list_unique(directory_fd, f"extracted-root/{directory_name}")
            for name in names:
                _check_cancel(cancel_check)
                rendered = f"{directory_name}/{name}"
                try:
                    linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as error:
                    raise BootExSafetyError(
                        f"Could not inspect extracted BootEx entry: {rendered!r}"
                    ) from error
                if stat.S_ISDIR(linked.st_mode):
                    raise BootExSafetyError(
                        f"Unexpected nested BootEx directory: {rendered!r}"
                    )
                if not stat.S_ISREG(linked.st_mode) or linked.st_nlink != 1:
                    raise BootExSafetyError(
                        f"Extracted BootEx entry is not one regular, unlinked file: {rendered!r}"
                    )
                if linked.st_dev != root_device:
                    raise BootExSafetyError("Cross-filesystem BootEx extraction is forbidden")
                if linked.st_size > MAX_EXTRACTED_FILE_BYTES:
                    raise BootExSafetyError(
                        f"BootEx file exceeds the size limit: {rendered!r}"
                    )
                if len(files) >= MAX_EXTRACTED_FILES:
                    raise BootExSafetyError("The extracted BootEx tree has too many files")
                include_blob = rendered in {
                    "EFI_EX/bootmgfw_EX.efi", "EFI_EX/bootmgr_EX.efi",
                }
                snapshot = _snapshot_file_at(
                    directory_fd, name, rendered, include_blob=include_blob,
                    cancel_check=cancel_check,
                )
                total_bytes += snapshot.size
                if total_bytes > MAX_EXTRACTED_TOTAL_BYTES:
                    raise BootExSafetyError("The extracted BootEx tree exceeds the size limit")
                files[rendered] = _ExtractedFile(rendered, parent_identity, snapshot)
        finally:
            os.close(directory_fd)
    for required in ("EFI_EX/bootmgfw_EX.efi", "EFI_EX/bootmgr_EX.efi"):
        if required not in files:
            raise BootExSafetyError(f"Required BootEx payload is missing: {required!r}")
    font_paths = tuple(path for path in files if path.startswith("Fonts_EX/"))
    if not font_paths:
        raise BootExSafetyError("The extracted BootEx tree contains no direct boot fonts")
    if len(font_paths) > MAX_FONT_FILES:
        raise BootExSafetyError("The extracted BootEx tree has too many boot fonts")
    if any(_FONT_NAME.fullmatch(PurePosixPath(path).name) is None for path in font_paths):
        raise BootExSafetyError("BootEx boot fonts must be direct .ttf files with safe names")
    return files


def _snapshot_relative(
    root_fd: int,
    relative_path: str,
    *,
    include_blob: bool,
    cancel_check: CancelCheck | None,
) -> tuple[DirectoryIdentity, _FileSnapshot]:
    pure = PurePosixPath(relative_path)
    if not pure.parts or pure.is_absolute() or ".." in pure.parts:
        raise BootExSafetyError(f"Unsafe BootEx destination: {relative_path!r}")
    parent_fd, parent_status = _open_directory_at(
        root_fd, tuple(pure.parts[:-1]), "staging-root",
    )
    try:
        names = _list_unique(parent_fd, f"staging-root/{pure.parent.as_posix()}")
        name = pure.name
        if name not in names:
            alias = next((item for item in names if _case_key(item) == _case_key(name)), None)
            if alias is not None:
                raise BootExSafetyError(
                    f"BootEx destination has unexpected case: {alias!r}; expected {name!r}"
                )
            raise BootExSafetyError(
                f"BootEx only replaces existing staging files; missing {relative_path!r}"
            )
        snapshot = _snapshot_file_at(
            parent_fd, name, f"staging-root/{relative_path}",
            include_blob=include_blob, cancel_check=cancel_check,
        )
        return _directory_identity(parent_status), snapshot
    finally:
        os.close(parent_fd)


def _operation_dict(operation: BootExReplacementPlan) -> dict[str, object]:
    pe = None if operation.pe is None else {
        "architecture": operation.pe.architecture,
        "subsystem": operation.pe.subsystem,
        "signature_table_state": operation.pe.signature_table_state,
        "signature_trust_evaluated": operation.pe.signature_trust_evaluated,
    }
    return {
        "kind": operation.kind,
        "source_path": operation.source_path,
        "destination_path": operation.destination_path,
        "source_parent_identity": list(operation.source_parent_identity),
        "source_identity": list(operation.source_identity),
        "destination_parent_identity": list(operation.destination_parent_identity),
        "destination_identity": list(operation.destination_identity),
        "old_size": operation.old_size,
        "old_sha256": operation.old_sha256,
        "new_size": operation.new_size,
        "new_sha256": operation.new_sha256,
        "pe": pe,
    }


def _plan_digest(plan: BootExPlan) -> str:
    payload = {
        "profile": _PLAN_PROFILE,
        "release_id": plan.profile.release_id,
        "architecture": plan.profile.architecture,
        "iso_size": plan.profile.iso_size,
        "iso_sha256": plan.profile.iso_sha256,
        "trust_basis": plan.profile.trust_basis,
        "source_iso_path": os.fspath(plan.source_iso.path),
        "source_iso_identity": list(plan.source_iso.identity),
        "extracted_root": os.fspath(plan.extracted_root),
        "extracted_root_identity": list(plan.extracted_root_identity),
        "staging_root": os.fspath(plan.staging_root),
        "staging_root_identity": list(plan.staging_root_identity),
        "replacements": [_operation_dict(item) for item in plan.replacements],
        "ignored_extracted_files": list(plan.ignored_extracted_files),
        "extraction_boundary": plan.extraction_boundary,
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def build_bootex_plan(
    request: BootExRequest,
    *,
    cancel_check: CancelCheck | None = None,
) -> BootExPlan:
    """Bind and validate one exact private-tree BootEx transformation."""

    if not isinstance(request, BootExRequest):
        raise BootExSafetyError("A BootExRequest is required")
    iso_evidence, profile = _hash_source_iso(
        request.source_iso, architecture=request.architecture,
        expected_release_id=request.expected_release_id,
        cancel_check=cancel_check,
    )
    extracted_fd = staging_fd = -1
    try:
        extracted_root, extracted_fd, extracted_status = _open_root(
            request.extracted_root, "BootEx extracted root",
        )
        staging_root, staging_fd, staging_status = _open_root(
            request.staging_root, "BootEx private staging root",
        )
        if _directory_identity(extracted_status) == _directory_identity(staging_status):
            raise BootExSafetyError("Extracted and staging roots must be different directories")
        extracted = _scan_extracted_tree(
            extracted_fd, extracted_status.st_dev, cancel_check=cancel_check,
        )
        pe_by_source: dict[str, BootExPeEvidence] = {}
        for source_path in ("EFI_EX/bootmgfw_EX.efi", "EFI_EX/bootmgr_EX.efi"):
            blob = extracted[source_path].snapshot.blob
            assert blob is not None
            pe_by_source[source_path] = _inspect_bootex_pe(blob, profile.architecture)

        mappings: list[tuple[str, str, str]] = [
            ("fallback-efi", "EFI_EX/bootmgfw_EX.efi", profile.fallback_path),
            ("root-bootmgr-efi", "EFI_EX/bootmgr_EX.efi", "bootmgr.efi"),
        ]
        for source_path in sorted(
            (path for path in extracted if path.startswith("Fonts_EX/")),
            key=lambda item: (_case_key(PurePosixPath(item).name), item),
        ):
            name = PurePosixPath(source_path).name
            destination_name = _destination_font_name(name)
            mappings.append((
                "boot-font",
                source_path,
                f"efi/microsoft/boot/fonts/{destination_name}",
            ))

        operations: list[BootExReplacementPlan] = []
        destination_keys: set[tuple[str, ...]] = set()
        for kind, source_path, destination_path in mappings:
            _check_cancel(cancel_check)
            key = tuple(_case_key(part) for part in PurePosixPath(destination_path).parts)
            if key in destination_keys:
                raise BootExSafetyError("BootEx destination mapping contains a case collision")
            destination_keys.add(key)
            destination_parent, old = _snapshot_relative(
                staging_fd, destination_path, include_blob=False,
                cancel_check=cancel_check,
            )
            source = extracted[source_path]
            operations.append(BootExReplacementPlan(
                kind, source_path, destination_path,
                source.parent_identity, source.snapshot.identity,
                destination_parent, old.identity,
                old.size, old.sha256, source.snapshot.size, source.snapshot.sha256,
                pe_by_source.get(source_path),
            ))
        ignored = tuple(sorted(
            set(extracted) - {source for _, source, _ in mappings},
            key=lambda item: (_case_key(item), item),
        ))
        draft = BootExPlan(
            profile, iso_evidence,
            extracted_root, _directory_identity(extracted_status),
            staging_root, _directory_identity(staging_status),
            tuple(operations), ignored, EXTRACTION_BOUNDARY, "",
            _PLAN_WITNESS,
        )
        return BootExPlan(
            draft.profile, draft.source_iso, draft.extracted_root,
            draft.extracted_root_identity, draft.staging_root,
            draft.staging_root_identity, draft.replacements,
            draft.ignored_extracted_files, draft.extraction_boundary,
            _plan_digest(draft), _PLAN_WITNESS,
        )
    finally:
        if extracted_fd >= 0:
            os.close(extracted_fd)
        if staging_fd >= 0:
            os.close(staging_fd)


def validate_bootex_plan(plan: BootExPlan) -> None:
    """Reject forged, stale-format, or no-longer-reviewed plans."""

    if not isinstance(plan, BootExPlan) or plan._witness is not _PLAN_WITNESS:
        raise BootExSafetyError("BootEx plan was not created by this process")
    if (
        not isinstance(plan.profile, BootExProfile)
        or not isinstance(plan.source_iso, BootExIsoEvidence)
        or not isinstance(plan.source_iso.path, Path)
        or type(plan.source_iso.identity) is not tuple
        or len(plan.source_iso.identity) != 7
        or not isinstance(plan.extracted_root, Path)
        or not isinstance(plan.staging_root, Path)
        or type(plan.extracted_root_identity) is not tuple
        or type(plan.staging_root_identity) is not tuple
        or type(plan.replacements) is not tuple
        or type(plan.ignored_extracted_files) is not tuple
    ):
        raise BootExSafetyError("BootEx plan contains malformed bound objects")
    if not _SHA256.fullmatch(plan.plan_sha256) or not hmac.compare_digest(
        plan.plan_sha256, _plan_digest(plan),
    ):
        raise BootExSafetyError("BootEx plan digest is invalid")
    reviewed = profile_for_official_iso(
        plan.profile.iso_size, plan.profile.iso_sha256,
        architecture=plan.profile.architecture,
    )
    if reviewed != plan.profile or plan.extraction_boundary != EXTRACTION_BOUNDARY:
        raise BootExSafetyError("BootEx plan no longer matches a reviewed profile")
    if (
        plan.source_iso.size != reviewed.iso_size
        or plan.source_iso.sha256 != reviewed.iso_sha256
        or plan.source_iso.identity[2] != reviewed.iso_size
        or not plan.source_iso.path.is_absolute()
        or not plan.extracted_root.is_absolute()
        or not plan.staging_root.is_absolute()
        or len(plan.extracted_root_identity) != 2
        or len(plan.staging_root_identity) != 2
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (
                *plan.source_iso.identity,
                *plan.extracted_root_identity,
                *plan.staging_root_identity,
            )
        )
    ):
        raise BootExSafetyError("BootEx plan has invalid bound-source identities")
    destinations: set[tuple[str, ...]] = set()
    sources: set[tuple[str, ...]] = set()
    font_operations: list[BootExReplacementPlan] = []
    for operation in plan.replacements:
        if (
            not isinstance(operation, BootExReplacementPlan)
            or not isinstance(operation.source_path, str)
            or not isinstance(operation.destination_path, str)
            or type(operation.source_identity) is not tuple
            or type(operation.destination_identity) is not tuple
            or type(operation.source_parent_identity) is not tuple
            or type(operation.destination_parent_identity) is not tuple
            or (
                operation.pe is not None
                and not isinstance(operation.pe, BootExPeEvidence)
            )
        ):
            raise BootExSafetyError("BootEx plan contains malformed replacement evidence")
        destination_key = tuple(
            _case_key(part)
            for part in PurePosixPath(operation.destination_path).parts
        )
        source_key = tuple(
            _case_key(part) for part in PurePosixPath(operation.source_path).parts
        )
        if (
            destination_key in destinations
            or source_key in sources
            or not _SHA256.fullmatch(operation.old_sha256)
            or not _SHA256.fullmatch(operation.new_sha256)
            or not 0 < operation.old_size <= MAX_EXTRACTED_FILE_BYTES
            or not 0 < operation.new_size <= MAX_EXTRACTED_FILE_BYTES
            or len(operation.source_identity) != 7
            or len(operation.destination_identity) != 7
            or len(operation.source_parent_identity) != 2
            or len(operation.destination_parent_identity) != 2
            or operation.source_identity[2] != operation.new_size
            or operation.destination_identity[2] != operation.old_size
            or operation.source_identity[5] != 1
            or operation.destination_identity[5] != 1
            or not stat.S_ISREG(operation.source_identity[6])
            or not stat.S_ISREG(operation.destination_identity[6])
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in (
                    *operation.source_identity,
                    *operation.destination_identity,
                    *operation.source_parent_identity,
                    *operation.destination_parent_identity,
                )
            )
        ):
            raise BootExSafetyError("BootEx plan contains invalid replacement evidence")
        destinations.add(destination_key)
        sources.add(source_key)
        if operation.kind == "fallback-efi":
            if (
                operation.source_path != "EFI_EX/bootmgfw_EX.efi"
                or operation.destination_path != reviewed.fallback_path
                or operation.pe is None
            ):
                raise BootExSafetyError("BootEx plan has an invalid fallback-loader mapping")
        elif operation.kind == "root-bootmgr-efi":
            if (
                operation.source_path != "EFI_EX/bootmgr_EX.efi"
                or operation.destination_path != "bootmgr.efi"
                or operation.pe is None
            ):
                raise BootExSafetyError("BootEx plan has an invalid root boot-manager mapping")
        elif operation.kind == "boot-font":
            source = PurePosixPath(operation.source_path)
            name = source.name
            if (
                source.parts != ("Fonts_EX", name)
                or _FONT_NAME.fullmatch(name) is None
                or operation.destination_path
                != f"efi/microsoft/boot/fonts/{_destination_font_name(name)}"
                or operation.pe is not None
            ):
                raise BootExSafetyError("BootEx plan has an invalid direct-font mapping")
            font_operations.append(operation)
        else:
            raise BootExSafetyError("BootEx plan contains an unauthorized mapping kind")
        if operation.pe is not None and (
            operation.pe.architecture != _ARCHITECTURES[reviewed.architecture][0]
            or operation.pe.subsystem != "EFI application"
            or operation.pe.signature_table_state
            != SignatureTableState.PRESENT_UNVERIFIED.value
            or operation.pe.signature_trust_evaluated
        ):
            raise BootExSafetyError("BootEx plan contains invalid PE evidence")
    if (
        len(plan.replacements) != 2 + len(font_operations)
        or not 1 <= len(font_operations) <= MAX_FONT_FILES
        or sum(item.kind == "fallback-efi" for item in plan.replacements) != 1
        or sum(item.kind == "root-bootmgr-efi" for item in plan.replacements) != 1
        or tuple(item.source_path for item in font_operations) != tuple(sorted(
            (item.source_path for item in font_operations),
            key=lambda item: (_case_key(PurePosixPath(item).name), item),
        ))
    ):
        raise BootExSafetyError("BootEx plan contains an unauthorized destination mapping")


def validate_bootex_result(plan: BootExPlan, result: BootExResult) -> None:
    """Bind a claimed result to every exact replacement in its execution plan."""

    validate_bootex_plan(plan)
    if not isinstance(result, BootExResult):
        raise BootExSafetyError("A Windows BootEx result is required")
    expected = tuple(BootExReplacementReceipt(
        item.kind,
        item.destination_path,
        item.old_size,
        item.old_sha256,
        item.new_size,
        item.new_sha256,
        item.pe,
    ) for item in plan.replacements)
    if (
        result.release_id != plan.profile.release_id
        or result.architecture != plan.profile.architecture
        or result.source_iso_sha256 != plan.source_iso.sha256
        or result.trust_basis != plan.profile.trust_basis
        or result.trust_scope != plan.profile.trust_scope
        or result.extraction_boundary != plan.extraction_boundary
        or result.signature_trust_evaluated is not False
        or type(result.replacements) is not tuple
        or result.replacements != expected
        or not isinstance(result.receipt_sha256, str)
        or _SHA256.fullmatch(result.receipt_sha256) is None
        or not hmac.compare_digest(
            result.receipt_sha256,
            _receipt_digest(result),
        )
    ):
        raise BootExSafetyError(
            "The Windows BootEx result does not match its complete execution plan"
        )


def _verify_iso_identity(evidence: BootExIsoEvidence) -> None:
    try:
        status = os.lstat(evidence.path)
    except OSError as error:
        raise BootExSafetyError("The bound source ISO is unavailable") from error
    if _file_identity(status) != evidence.identity or not stat.S_ISREG(status.st_mode):
        raise BootExSafetyError("The bound source ISO changed after planning")


def _open_bound_root(
    path: Path, expected: DirectoryIdentity, label: str,
) -> int:
    resolved, descriptor, status = _open_root(path, label)
    del resolved
    if _directory_identity(status) != expected:
        os.close(descriptor)
        raise BootExSafetyError(f"{label} changed after planning")
    return descriptor


def _resnapshot_operation(
    root_fd: int,
    relative_path: str,
    expected_parent: DirectoryIdentity,
    expected_file: FileIdentity,
    expected_sha256: str,
    *,
    cancel_check: CancelCheck | None,
) -> tuple[int, str, _FileSnapshot]:
    pure = PurePosixPath(relative_path)
    parent_fd, parent_status = _open_directory_at(
        root_fd, tuple(pure.parts[:-1]), "bound-root",
    )
    try:
        if _directory_identity(parent_status) != expected_parent:
            raise BootExSafetyError(f"BootEx parent changed after planning: {relative_path!r}")
        names = _list_unique(parent_fd, f"bound-root/{pure.parent.as_posix()}")
        if pure.name not in names:
            raise BootExSafetyError(f"BootEx file disappeared after planning: {relative_path!r}")
        snapshot = _snapshot_file_at(
            parent_fd, pure.name, relative_path, include_blob=False,
            cancel_check=cancel_check,
        )
        if snapshot.identity != expected_file or not hmac.compare_digest(
            snapshot.sha256, expected_sha256,
        ):
            raise BootExSafetyError(f"BootEx file changed after planning: {relative_path!r}")
        return parent_fd, pure.name, snapshot
    except Exception:
        os.close(parent_fd)
        raise


def _stage_temp_copy(
    source_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
    destination_mode: int,
    destination_mtime_ns: int,
    expected_sha256: str,
    expected_size: int,
    *,
    cancel_check: CancelCheck | None,
) -> str:
    temp_name = f".isopropyl-bootex-{secrets.token_hex(16)}.tmp"
    source_descriptor = temp_descriptor = -1
    try:
        source_descriptor = os.open(source_name, _READ_FLAGS, dir_fd=source_fd)
        temp_descriptor = os.open(
            temp_name, _TEMP_FLAGS, destination_mode & 0o777,
            dir_fd=destination_parent_fd,
        )
        digest = hashlib.sha256()
        total = 0
        while True:
            _check_cancel(cancel_check)
            block = os.read(source_descriptor, COPY_CHUNK_BYTES)
            if not block:
                break
            total += len(block)
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(temp_descriptor, view)
                if written <= 0:
                    raise BootExSafetyError("Could not write the BootEx temporary file")
                view = view[written:]
        if total != expected_size or not hmac.compare_digest(
            digest.hexdigest(), expected_sha256,
        ):
            raise BootExSafetyError("BootEx source changed during atomic staging")
        os.fchmod(temp_descriptor, destination_mode & 0o777)
        os.fsync(temp_descriptor)
        os.close(temp_descriptor)
        temp_descriptor = -1
        os.utime(
            temp_name, ns=(destination_mtime_ns, destination_mtime_ns),
            dir_fd=destination_parent_fd, follow_symlinks=False,
        )
        return temp_name
    except Exception:
        if temp_descriptor >= 0:
            os.close(temp_descriptor)
        try:
            os.unlink(temp_name, dir_fd=destination_parent_fd)
        except OSError:
            pass
        raise
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)


def _receipt_digest(result: BootExResult) -> str:
    payload = {
        "profile": _RECEIPT_PROFILE,
        "release_id": result.release_id,
        "architecture": result.architecture,
        "source_iso_sha256": result.source_iso_sha256,
        "trust_basis": result.trust_basis,
        "trust_scope": result.trust_scope,
        "extraction_boundary": result.extraction_boundary,
        "signature_trust_evaluated": result.signature_trust_evaluated,
        "replacements": [
            {
                "kind": item.kind,
                "destination_path": item.destination_path,
                "old_size": item.old_size,
                "old_sha256": item.old_sha256,
                "new_size": item.new_size,
                "new_sha256": item.new_sha256,
                "pe": None if item.pe is None else {
                    "architecture": item.pe.architecture,
                    "subsystem": item.pe.subsystem,
                    "signature_table_state": item.pe.signature_table_state,
                    "signature_trust_evaluated": item.pe.signature_trust_evaluated,
                },
            }
            for item in result.replacements
        ],
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def apply_bootex_plan(
    plan: BootExPlan,
    *,
    cancel_check: CancelCheck | None = None,
) -> BootExResult:
    """Apply per-file atomic replacements inside an unpublished staging tree."""

    validate_bootex_plan(plan)
    _check_cancel(cancel_check)
    _verify_iso_identity(plan.source_iso)
    extracted_fd = staging_fd = -1
    prepared: list[tuple[BootExReplacementPlan, int, str, str]] = []
    try:
        extracted_fd = _open_bound_root(
            plan.extracted_root, plan.extracted_root_identity, "BootEx extracted root",
        )
        staging_fd = _open_bound_root(
            plan.staging_root, plan.staging_root_identity, "BootEx private staging root",
        )
        for operation in plan.replacements:
            source_parent_fd, source_name, _source = _resnapshot_operation(
                extracted_fd, operation.source_path,
                operation.source_parent_identity, operation.source_identity,
                operation.new_sha256, cancel_check=cancel_check,
            )
            destination_parent_fd = -1
            try:
                destination_parent_fd, destination_name, destination = _resnapshot_operation(
                    staging_fd, operation.destination_path,
                    operation.destination_parent_identity, operation.destination_identity,
                    operation.old_sha256, cancel_check=cancel_check,
                )
                temp_name = _stage_temp_copy(
                    source_parent_fd, source_name, destination_parent_fd,
                    destination_name, operation.destination_identity[6],
                    operation.destination_identity[3], operation.new_sha256,
                    operation.new_size, cancel_check=cancel_check,
                )
                prepared.append((operation, destination_parent_fd, destination_name, temp_name))
                destination_parent_fd = -1
            finally:
                os.close(source_parent_fd)
                if destination_parent_fd >= 0:
                    os.close(destination_parent_fd)

        # Revalidate every destination after all temporary files exist and before
        # the first commit.  Each os.replace below is atomic; the whole set is
        # intentionally scoped to a private, discardable tree rather than
        # presented as a cross-file filesystem transaction.
        for operation, parent_fd, destination_name, _temp_name in prepared:
            current = _snapshot_file_at(
                parent_fd, destination_name, operation.destination_path,
                include_blob=False, cancel_check=cancel_check,
            )
            if current.identity != operation.destination_identity or not hmac.compare_digest(
                current.sha256, operation.old_sha256,
            ):
                raise BootExSafetyError(
                    f"BootEx destination changed before commit: {operation.destination_path!r}"
                )
        for _operation, parent_fd, destination_name, temp_name in prepared:
            _check_cancel(cancel_check)
            os.replace(
                temp_name, destination_name,
                src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
            )
            os.fsync(parent_fd)

        # A receipt describes the committed private tree, not merely the bytes
        # that were prepared in temporary files.  Reopen every destination and
        # prove its exact length and digest after all replacements are durable.
        for operation, parent_fd, destination_name, _temp_name in prepared:
            committed = _snapshot_file_at(
                parent_fd,
                destination_name,
                operation.destination_path,
                include_blob=False,
                cancel_check=cancel_check,
            )
            if (
                committed.size != operation.new_size
                or not hmac.compare_digest(
                    committed.sha256, operation.new_sha256,
                )
            ):
                raise BootExSafetyError(
                    f"BootEx destination read-back failed: "
                    f"{operation.destination_path!r}"
                )

        receipts = tuple(BootExReplacementReceipt(
            item.kind, item.destination_path, item.old_size, item.old_sha256,
            item.new_size, item.new_sha256, item.pe,
        ) for item in plan.replacements)
        draft = BootExResult(
            plan.profile.release_id, plan.profile.architecture,
            plan.source_iso.sha256, plan.profile.trust_basis,
            plan.profile.trust_scope, plan.extraction_boundary,
            receipts, "",
        )
        result = BootExResult(
            draft.release_id, draft.architecture, draft.source_iso_sha256,
            draft.trust_basis, draft.trust_scope, draft.extraction_boundary,
            draft.replacements, _receipt_digest(draft),
        )
        validate_bootex_result(plan, result)
        return result
    except BootExError:
        raise
    except OSError as error:
        raise BootExSafetyError("Could not commit the BootEx staging transform") from error
    finally:
        for _operation, parent_fd, _destination_name, temp_name in prepared:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except OSError:
                pass
            os.close(parent_fd)
        if extracted_fd >= 0:
            os.close(extracted_fd)
        if staging_fd >= 0:
            os.close(staging_fd)
