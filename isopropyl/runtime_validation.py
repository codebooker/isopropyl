from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Safe, identity-bound installation of the uefi-md5sum runtime validator.

The caller supplies a private, fully constructed ISO-mode workspace.  This
module neither chooses a block device nor decides whether the feature is
appropriate for an image.  A returned stage is only a witness for the exact
tree that was transformed; consumers must validate it again before planning
or copying the tree.
"""

import hashlib
import hmac
import os
import secrets
import stat
import threading
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .bootloaders import (
    BootloaderCatalog,
    BoundBootArtifact,
    BoundBootBundle,
    DownloadProgress,
    OpenUrl,
    prepare_bundle,
)
from .uefi import (
    MAX_PE_SIZE,
    PeFormatError,
    SignatureTableState,
    UefiInspection,
    inspect_pe_bytes,
)


RUNTIME_VALIDATION_FAMILY = "uefi-md5sum"
RUNTIME_VALIDATION_VERSION = "1.2"
RUNTIME_VALIDATION_PURPOSE = "runtime-media-validation"
RUNTIME_VALIDATION_LICENSE = "GPL-2.0-or-later"
RUNTIME_VALIDATION_PROVENANCE_URL = (
    "https://github.com/pbatard/uefi-md5sum/tree/"
    "6195f2ef754c2ad390bda6590628708f410d55f6"
)
RUNTIME_VALIDATION_MANIFEST = "md5sum.txt"

# These are parser limits from uefi-md5sum v1.2, not tunable UX limits.
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_LINES = 100_000
MAX_MANIFEST_PATH_BYTES = 512
MAX_MANIFEST_PATH_UTF16_UNITS = 512
# Allows the upstream maximum covered-file count plus one unique parent per
# file, the wrapper/original pairs, and the generated manifest.
MAX_TREE_ENTRIES = 200_000
MAX_TOTAL_BYTES = (1 << 64) - 1
_READ_CHUNK = 1024 * 1024
_DIR_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = (
    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
)
_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _structural_pe_inspection(blob: bytes) -> UefiInspection:
    # Runtime wrapper trust is the independently pinned size/SHA-256 profile.
    # This checkpoint needs certificate-table framing only and must not launch
    # the separate Authenticode worker or imply platform trust.
    return inspect_pe_bytes(
        blob,
        authenticode_verifier=lambda *_args, **_kwargs: None,  # type: ignore[arg-type]
    )


class RuntimeValidationError(RuntimeError):
    """The runtime-validation release or operation is invalid."""


class RuntimeValidationSafetyError(RuntimeValidationError):
    """The private tree is unsafe, incompatible, or changed during use."""


class RuntimeValidationCancelled(RuntimeValidationError):
    """Runtime-validation preparation or transformation was cancelled."""


FileIdentity = tuple[int, int, int, int, int]


@dataclass(frozen=True)
class RuntimeValidationArtifactProfile:
    source_name: str
    fallback_path: str
    original_path: str
    architecture: str
    size: int
    sha256: str
    signature_state: SignatureTableState


RUNTIME_VALIDATION_ARTIFACTS = (
    RuntimeValidationArtifactProfile(
        "bootaa64_signed.efi", "EFI/BOOT/BOOTAA64.EFI",
        "EFI/BOOT/bootaa64_original.efi", "ARM64", 50_704,
        "799b64e8d32cbe5829b2f81c96a1a4936935da31df7ce70c0e6ae68ffdaf23bd",
        SignatureTableState.PRESENT_UNVERIFIED,
    ),
    RuntimeValidationArtifactProfile(
        "bootarm.efi", "EFI/BOOT/BOOTARM.EFI",
        "EFI/BOOT/bootarm_original.efi", "Thumb", 27_232,
        "10eadb8e80f446ebd62568f9275d6a328cfdc399ef8b2ee71857c3d2f7134f28",
        SignatureTableState.ABSENT,
    ),
    RuntimeValidationArtifactProfile(
        "bootia32_signed.efi", "EFI/BOOT/BOOTIA32.EFI",
        "EFI/BOOT/bootia32_original.efi", "x86", 40_280,
        "089190606ad0e16b58b208aa262533c941f11a9a27a48fade672efcca3a720c1",
        SignatureTableState.PRESENT_UNVERIFIED,
    ),
    RuntimeValidationArtifactProfile(
        "bootloongarch64.efi", "EFI/BOOT/BOOTLOONGARCH64.EFI",
        "EFI/BOOT/bootloongarch64_original.efi", "LoongArch64", 35_712,
        "0085afb9ca64ac5f922b21d541344b3ff140e13acf596041ff6ce7b7d71c229e",
        SignatureTableState.ABSENT,
    ),
    RuntimeValidationArtifactProfile(
        "bootriscv64.efi", "EFI/BOOT/BOOTRISCV64.EFI",
        "EFI/BOOT/bootriscv64_original.efi", "RISC-V64", 38_656,
        "3e53e975fad71c7e30ac35bfc83ba5b31fad7e6d9deaaee14f77dab820ed2c7a",
        SignatureTableState.ABSENT,
    ),
    RuntimeValidationArtifactProfile(
        "bootx64_signed.efi", "EFI/BOOT/BOOTX64.EFI",
        "EFI/BOOT/bootx64_original.efi", "x64", 40_536,
        "9b0b326ca3da0693fc99789f73e548c3dc69a2cd654bd7abcd1a92ba900878cc",
        SignatureTableState.PRESENT_UNVERIFIED,
    ),
)


@dataclass(frozen=True)
class RuntimeValidationPayload:
    source_name: str
    fallback_path: str
    original_path: str
    architecture: str
    data: bytes
    sha256: str
    signature_state: SignatureTableState

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass(frozen=True)
class PreparedRuntimeValidation:
    version: str
    payloads: tuple[RuntimeValidationPayload, ...]
    license: str
    provenance_url: str


@dataclass(frozen=True)
class RuntimeValidationTreeEntry:
    path: str
    kind: str
    identity: FileIdentity


@dataclass(frozen=True)
class RuntimeValidationLoaderCandidate:
    source_name: str
    architecture: str
    fallback_path: str
    original_path: str
    source_sha256: str
    source_identity: FileIdentity


@dataclass(frozen=True)
class RuntimeValidationCompatibility:
    root: Path
    root_identity: tuple[int, int]
    architectures: tuple[str, ...]
    loaders: tuple[RuntimeValidationLoaderCandidate, ...]
    tree: tuple[RuntimeValidationTreeEntry, ...]

    @property
    def unsigned_wrapper_architectures(self) -> tuple[str, ...]:
        unsigned = {
            profile.architecture for profile in RUNTIME_VALIDATION_ARTIFACTS
            if profile.signature_state is SignatureTableState.ABSENT
        }
        return tuple(item for item in self.architectures if item in unsigned)


@dataclass(frozen=True)
class RuntimeValidationLoader:
    source_name: str
    architecture: str
    fallback_path: str
    original_path: str
    wrapper_sha256: str
    wrapper_identity: FileIdentity
    original_identity: FileIdentity


@dataclass(frozen=True)
class RuntimeValidationStage:
    root: Path
    root_identity: tuple[int, int]
    version: str
    architectures: tuple[str, ...]
    loaders: tuple[RuntimeValidationLoader, ...]
    manifest_sha256: str
    manifest_identity: FileIdentity
    tree: tuple[RuntimeValidationTreeEntry, ...]
    license: str
    provenance_url: str

    @property
    def unsigned_wrapper_architectures(self) -> tuple[str, ...]:
        unsigned = {
            profile.architecture for profile in RUNTIME_VALIDATION_ARTIFACTS
            if profile.signature_state is SignatureTableState.ABSENT
        }
        return tuple(item for item in self.architectures if item in unsigned)


def _file_identity(info: os.stat_result) -> FileIdentity:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _check_cancel(cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise RuntimeValidationCancelled("Runtime media validation was cancelled")


def _validate_profile(profile: RuntimeValidationArtifactProfile) -> None:
    if (
        type(profile) is not RuntimeValidationArtifactProfile
        or not profile.source_name
        or not profile.fallback_path
        or not profile.original_path
        or profile.size <= 0
        or len(profile.sha256) != 64
        or profile.sha256 != profile.sha256.lower()
        or any(character not in "0123456789abcdef" for character in profile.sha256)
        or type(profile.signature_state) is not SignatureTableState
    ):
        raise RuntimeValidationError("The pinned runtime-validation profile is invalid")


def _payload_from_artifact(
    artifact: BoundBootArtifact,
    profile: RuntimeValidationArtifactProfile,
) -> RuntimeValidationPayload:
    if type(artifact) is not BoundBootArtifact or type(artifact.data) is not bytes:
        raise RuntimeValidationError("Runtime-validation payload bytes must be immutable")
    digest = hashlib.sha256(artifact.data).hexdigest()
    if (
        artifact.name != profile.source_name
        or artifact.sha256 != profile.sha256
        or len(artifact.data) != profile.size
        or not hmac.compare_digest(digest, profile.sha256)
    ):
        raise RuntimeValidationError(
            f"Runtime-validation payload {artifact.name!r} failed exact release verification"
        )
    try:
        inspection = _structural_pe_inspection(artifact.data)
    except PeFormatError as error:
        raise RuntimeValidationError(
            f"Runtime-validation payload {artifact.name!r} is not valid PE/COFF: {error}"
        ) from error
    if (
        not inspection.is_uefi_image
        or inspection.subsystem_name != "EFI application"
        or inspection.architecture != profile.architecture
        or inspection.certificate_table.state is not profile.signature_state
    ):
        raise RuntimeValidationError(
            f"Runtime-validation payload {artifact.name!r} changed architecture, subsystem, "
            "or certificate-table state"
        )
    return RuntimeValidationPayload(
        profile.source_name,
        profile.fallback_path,
        profile.original_path,
        profile.architecture,
        artifact.data,
        profile.sha256,
        profile.signature_state,
    )


def validate_runtime_validation_bundle(
    bundle: BoundBootBundle,
) -> PreparedRuntimeValidation:
    """Validate an immutable bundle against the independently pinned v1.2 set."""

    if type(bundle) is not BoundBootBundle:
        raise RuntimeValidationError("The prepared runtime-validation bundle has an invalid type")
    if (
        bundle.family != RUNTIME_VALIDATION_FAMILY
        or bundle.version != RUNTIME_VALIDATION_VERSION
        or bundle.purpose != RUNTIME_VALIDATION_PURPOSE
        or bundle.license != RUNTIME_VALIDATION_LICENSE
        or bundle.provenance_url != RUNTIME_VALIDATION_PROVENANCE_URL
    ):
        raise RuntimeValidationError("The prepared runtime-validation bundle metadata is not exact")
    for profile in RUNTIME_VALIDATION_ARTIFACTS:
        _validate_profile(profile)
    names = tuple(profile.source_name for profile in RUNTIME_VALIDATION_ARTIFACTS)
    if tuple(item.name for item in bundle.artifacts) != names:
        raise RuntimeValidationError("The runtime-validation artifact set or order is not exact")
    payloads = tuple(
        _payload_from_artifact(artifact, profile)
        for artifact, profile in zip(
            bundle.artifacts, RUNTIME_VALIDATION_ARTIFACTS, strict=True
        )
    )
    return PreparedRuntimeValidation(
        RUNTIME_VALIDATION_VERSION,
        payloads,
        RUNTIME_VALIDATION_LICENSE,
        RUNTIME_VALIDATION_PROVENANCE_URL,
    )


def prepare_runtime_validation(
    *,
    catalog: BootloaderCatalog | None = None,
    cache_dir: Path | None = None,
    opener: OpenUrl | None = None,
    cancel_event: threading.Event | None = None,
    progress: DownloadProgress | None = None,
    overall_timeout: float = 180.0,
) -> PreparedRuntimeValidation:
    """Acquire and freeze v1.2 after the caller has obtained network consent."""

    arguments: dict[str, object] = {
        "catalog": catalog,
        "cache_dir": cache_dir,
        "cancel_event": cancel_event,
        "progress": progress,
        "overall_timeout": overall_timeout,
    }
    if opener is not None:
        arguments["opener"] = opener
    bundle = prepare_bundle(
        RUNTIME_VALIDATION_FAMILY,
        RUNTIME_VALIDATION_VERSION,
        RUNTIME_VALIDATION_PURPOSE,
        **arguments,  # type: ignore[arg-type]
    )
    return validate_runtime_validation_bundle(bundle)


def validate_prepared_runtime_validation(
    prepared: PreparedRuntimeValidation,
) -> PreparedRuntimeValidation:
    """Revalidate an immutable prepared payload set before any trust claim."""

    if (
        type(prepared) is not PreparedRuntimeValidation
        or prepared.version != RUNTIME_VALIDATION_VERSION
        or prepared.license != RUNTIME_VALIDATION_LICENSE
        or prepared.provenance_url != RUNTIME_VALIDATION_PROVENANCE_URL
        or len(prepared.payloads) != len(RUNTIME_VALIDATION_ARTIFACTS)
    ):
        raise RuntimeValidationError("The prepared runtime-validation object is not exact")
    for payload, profile in zip(
        prepared.payloads, RUNTIME_VALIDATION_ARTIFACTS, strict=True
    ):
        if type(payload) is not RuntimeValidationPayload:
            raise RuntimeValidationError("The prepared runtime-validation payload type changed")
        artifact = BoundBootArtifact(payload.source_name, payload.data, payload.sha256)
        expected = _payload_from_artifact(artifact, profile)
        if payload != expected:
            raise RuntimeValidationError("The prepared runtime-validation object changed")
    return prepared


def _canonical_absolute(path: Path) -> bool:
    return (
        isinstance(path, Path)
        and path.is_absolute()
        and path == Path(os.path.normpath(path))
        and all(component not in {"", ".", ".."} for component in path.parts[1:])
    )


def _open_absolute_directory(path: Path) -> int:
    if not _canonical_absolute(path):
        raise RuntimeValidationSafetyError("The private staging root must be canonical and absolute")
    descriptor = os.open("/", _DIR_FLAGS)
    try:
        for component in path.parts[1:]:
            child = os.open(component, _DIR_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_name(name: str, rendered: str) -> None:
    if not name or name in {".", ".."} or "\x00" in name or "\\" in name:
        raise RuntimeValidationSafetyError(f"Unsafe runtime-validation path: {rendered!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise RuntimeValidationSafetyError(
            f"Control character in runtime-validation path: {rendered!r}"
        )
    try:
        name.encode("utf-8")
        name.encode("utf-16-le")
    except UnicodeEncodeError as error:
        raise RuntimeValidationSafetyError(
            f"Path is not representable in the runtime manifest: {rendered!r}"
        ) from error


def _path_key(parts: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFC", item).casefold() for item in parts)


def _entry(path: str, kind: str, info: os.stat_result) -> RuntimeValidationTreeEntry:
    return RuntimeValidationTreeEntry(path, kind, _file_identity(info))


def _scan_tree(
    root_fd: int,
    cancel_event: threading.Event | None = None,
) -> tuple[RuntimeValidationTreeEntry, ...]:
    _check_cancel(cancel_event)
    root = os.fstat(root_fd)
    if not stat.S_ISDIR(root.st_mode):
        raise RuntimeValidationSafetyError("The runtime-validation root is not a directory")
    entries: list[RuntimeValidationTreeEntry] = []
    aliases: set[tuple[str, ...]] = set()
    stack: list[tuple[int, tuple[str, ...]]] = [(os.dup(root_fd), ())]
    try:
        while stack:
            _check_cancel(cancel_event)
            directory_fd, parent_parts = stack.pop()
            try:
                try:
                    scan_fd = os.open(".", _DIR_FLAGS, dir_fd=directory_fd)
                    try:
                        names = os.listdir(scan_fd)
                    finally:
                        os.close(scan_fd)
                except OSError as error:
                    raise RuntimeValidationSafetyError(
                        f"Could not enumerate the private staging tree: {error}"
                    ) from error
                _check_cancel(cancel_event)
                names.sort(key=lambda value: value.encode("utf-8", "surrogatepass"))
                _check_cancel(cancel_event)
                for name in names:
                    _check_cancel(cancel_event)
                    parts = (*parent_parts, name)
                    path = PurePosixPath(*parts).as_posix()
                    _validate_name(name, path)
                    key = _path_key(parts)
                    if key in aliases:
                        raise RuntimeValidationSafetyError(
                            f"Case or Unicode path alias in private staging tree: {path!r}"
                        )
                    aliases.add(key)
                    try:
                        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    except OSError as error:
                        raise RuntimeValidationSafetyError(
                            f"Could not inspect private staging path {path!r}: {error}"
                        ) from error
                    if stat.S_ISDIR(before.st_mode):
                        try:
                            child = os.open(name, _DIR_FLAGS, dir_fd=directory_fd)
                        except OSError as error:
                            raise RuntimeValidationSafetyError(
                                f"Could not safely open directory {path!r}: {error}"
                            ) from error
                        after = os.fstat(child)
                        if (
                            not stat.S_ISDIR(after.st_mode)
                            or _file_identity(before) != _file_identity(after)
                            or after.st_dev != root.st_dev
                        ):
                            os.close(child)
                            raise RuntimeValidationSafetyError(
                                f"Directory changed while scanning: {path!r}"
                            )
                        entries.append(_entry(path, "directory", after))
                        stack.append((child, parts))
                    elif stat.S_ISREG(before.st_mode):
                        if before.st_dev != root.st_dev or before.st_nlink != 1:
                            raise RuntimeValidationSafetyError(
                                f"Hard-linked or cross-device file is unsafe: {path!r}"
                            )
                        entries.append(_entry(path, "file", before))
                    else:
                        raise RuntimeValidationSafetyError(
                            f"Symlink or special file is unsafe: {path!r}"
                        )
                    if len(entries) > MAX_TREE_ENTRIES:
                        raise RuntimeValidationSafetyError(
                            "The private staging tree exceeds the entry limit"
                        )
            finally:
                os.close(directory_fd)
    except BaseException:
        for descriptor, _parts in stack:
            os.close(descriptor)
        raise
    _check_cancel(cancel_event)
    ordered = tuple(sorted(entries, key=lambda item: item.path.encode("utf-8")))
    _check_cancel(cancel_event)
    return ordered


def _tree_map(
    tree: tuple[RuntimeValidationTreeEntry, ...],
) -> dict[str, RuntimeValidationTreeEntry]:
    return {entry.path: entry for entry in tree}


def _open_directory_parts(
    root_fd: int,
    parts: tuple[str, ...],
    expected: dict[str, RuntimeValidationTreeEntry] | None = None,
) -> int:
    descriptor = os.dup(root_fd)
    try:
        for index, component in enumerate(parts):
            child = os.open(component, _DIR_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            if expected is not None:
                path = PurePosixPath(*parts[: index + 1]).as_posix()
                wanted = expected.get(path)
                observed = os.fstat(descriptor)
                if (
                    wanted is None
                    or wanted.kind != "directory"
                    or (observed.st_dev, observed.st_ino) != wanted.identity[:2]
                ):
                    raise RuntimeValidationSafetyError(
                        f"Directory identity changed: {path!r}"
                    )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_bound_file(
    root_fd: int,
    entry: RuntimeValidationTreeEntry,
    tree: tuple[RuntimeValidationTreeEntry, ...],
    *,
    max_bytes: int | None,
    cancel_event: threading.Event | None,
) -> tuple[bytes, str]:
    _check_cancel(cancel_event)
    parts = PurePosixPath(entry.path).parts
    parent_fd = _open_directory_parts(root_fd, parts[:-1], _tree_map(tree))
    try:
        before = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _file_identity(before) != entry.identity
            or (max_bytes is not None and before.st_size > max_bytes)
        ):
            raise RuntimeValidationSafetyError(f"File is unsafe or changed: {entry.path!r}")
        descriptor = os.open(parts[-1], _READ_FLAGS, dir_fd=parent_fd)
        try:
            opened = os.fstat(descriptor)
            if _file_identity(opened) != entry.identity or opened.st_nlink != 1:
                raise RuntimeValidationSafetyError(
                    f"File changed while it was opened: {entry.path!r}"
                )
            chunks: list[bytes] = []
            digest = hashlib.sha256()
            remaining = opened.st_size
            while remaining:
                _check_cancel(cancel_event)
                block = os.read(descriptor, min(_READ_CHUNK, remaining))
                if not block:
                    raise RuntimeValidationSafetyError(
                        f"File ended during inspection: {entry.path!r}"
                    )
                chunks.append(block)
                digest.update(block)
                remaining -= len(block)
            if os.read(descriptor, 1):
                raise RuntimeValidationSafetyError(
                    f"File grew during inspection: {entry.path!r}"
                )
            final = os.fstat(descriptor)
            if _file_identity(final) != entry.identity:
                raise RuntimeValidationSafetyError(
                    f"File metadata changed during inspection: {entry.path!r}"
                )
            return b"".join(chunks), digest.hexdigest()
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def _supported_profile_by_key() -> dict[tuple[str, ...], RuntimeValidationArtifactProfile]:
    return {
        tuple(part.casefold() for part in PurePosixPath(profile.fallback_path).parts): profile
        for profile in RUNTIME_VALIDATION_ARTIFACTS
    }


def analyze_runtime_validation_compatibility(
    staging_root: Path,
    *,
    cancel_event: threading.Event | None = None,
) -> RuntimeValidationCompatibility:
    """Inspect and bind a final private tree without mutating it."""

    if not _canonical_absolute(staging_root) or staging_root == Path("/"):
        raise RuntimeValidationSafetyError("The private staging root must be canonical and absolute")
    _check_cancel(cancel_event)
    try:
        root_fd = _open_absolute_directory(staging_root)
    except (OSError, RuntimeValidationError) as error:
        if isinstance(error, RuntimeValidationError):
            raise
        raise RuntimeValidationSafetyError(
            f"Could not safely open the private staging root: {error}"
        ) from error
    try:
        root_info = os.fstat(root_fd)
        tree = _scan_tree(root_fd, cancel_event)
        by_key = {_path_key(PurePosixPath(entry.path).parts): entry for entry in tree}
        manifest_aliases = [
            entry for entry in tree
            if len(PurePosixPath(entry.path).parts) == 1
            and PurePosixPath(entry.path).name.casefold() == RUNTIME_VALIDATION_MANIFEST
        ]
        if manifest_aliases and manifest_aliases[0].path != RUNTIME_VALIDATION_MANIFEST:
            raise RuntimeValidationSafetyError(
                "A case alias of the root runtime-validation manifest already exists"
            )
        if manifest_aliases and manifest_aliases[0].kind != "file":
            raise RuntimeValidationSafetyError("The existing root manifest is not a regular file")

        covered_count = 0
        covered_total = 0
        supported_keys = set(_supported_profile_by_key())
        for entry in tree:
            if entry.kind != "file" or entry.path == RUNTIME_VALIDATION_MANIFEST:
                continue
            parts = PurePosixPath(entry.path).parts
            if _path_key(parts) not in supported_keys:
                _validate_manifest_path(entry.path)
            covered_count += 1
            if entry.identity[2] > MAX_TOTAL_BYTES - covered_total:
                raise RuntimeValidationSafetyError(
                    "The runtime manifest byte total overflows uint64"
                )
            covered_total += entry.identity[2]
        if covered_count + 2 > MAX_MANIFEST_LINES:
            raise RuntimeValidationSafetyError(
                "The runtime manifest would exceed the parser line limit"
            )

        profiles = _supported_profile_by_key()
        loaders: list[RuntimeValidationLoaderCandidate] = []
        for profile in RUNTIME_VALIDATION_ARTIFACTS:
            fallback_key = tuple(
                part.casefold() for part in PurePosixPath(profile.fallback_path).parts
            )
            found = by_key.get(fallback_key)
            if found is None:
                continue
            if found.kind != "file":
                raise RuntimeValidationSafetyError(
                    f"Supported fallback loader is not a regular file: {found.path!r}"
                )
            actual_parts = PurePosixPath(found.path).parts
            parent_parts = actual_parts[:-1]
            original_name = PurePosixPath(profile.original_path).name
            original_path = PurePosixPath(*parent_parts, original_name).as_posix()
            original_key = _path_key((*parent_parts, original_name))
            if original_key in by_key:
                raise RuntimeValidationSafetyError(
                    f"A chainload original already exists: {original_path!r}"
                )
            _validate_name(original_name, original_path)
            _validate_manifest_path(original_path)
            blob, digest = _read_bound_file(
                root_fd, found, tree, max_bytes=MAX_PE_SIZE, cancel_event=cancel_event
            )
            try:
                inspection = _structural_pe_inspection(blob)
            except PeFormatError as error:
                raise RuntimeValidationSafetyError(
                    f"Fallback loader {found.path!r} is not valid PE/COFF: {error}"
                ) from error
            if (
                not inspection.is_uefi_image
                or inspection.subsystem_name != "EFI application"
                or inspection.architecture != profile.architecture
            ):
                raise RuntimeValidationSafetyError(
                    f"Fallback loader {found.path!r} does not match {profile.architecture}"
                )
            if hmac.compare_digest(digest, profile.sha256):
                raise RuntimeValidationSafetyError(
                    f"Fallback loader {found.path!r} is already the validation wrapper"
                )
            loaders.append(RuntimeValidationLoaderCandidate(
                profile.source_name,
                profile.architecture,
                found.path,
                original_path,
                digest,
                found.identity,
            ))

        # Reject chainload-looking siblings even if the corresponding loader is absent.
        boot_keys = {
            tuple(part.casefold() for part in PurePosixPath(profile.fallback_path).parts[:-1])
            for profile in profiles.values()
        }
        for entry in tree:
            parts = PurePosixPath(entry.path).parts
            if (
                tuple(part.casefold() for part in parts[:-1]) in boot_keys
                and parts[-1].casefold().endswith("_original.efi")
            ):
                raise RuntimeValidationSafetyError(
                    f"A pre-existing chainload original is ambiguous: {entry.path!r}"
                )
        if not loaders:
            raise RuntimeValidationSafetyError(
                "The private tree has no recognized UEFI removable-media fallback loader"
            )
        replacement_paths = {
            loader.fallback_path: loader.original_path for loader in loaders
        }
        covered_paths = tuple(
            replacement_paths.get(entry.path, entry.path)
            for entry in tree
            if entry.kind == "file" and entry.path != RUNTIME_VALIDATION_MANIFEST
        )
        path_fields = tuple(_validate_manifest_path(path) for path in covered_paths)
        manifest_size = len(
            f"# md5sum_totalbytes = 0x{covered_total:x}\n".encode("ascii")
        ) + sum(32 + 2 + len(path) + 1 for path in path_fields)
        if manifest_size > MAX_MANIFEST_BYTES:
            raise RuntimeValidationSafetyError(
                "The runtime manifest would exceed the parser size limit"
            )
        _check_cancel(cancel_event)
        return RuntimeValidationCompatibility(
            staging_root,
            (root_info.st_dev, root_info.st_ino),
            tuple(loader.architecture for loader in loaders),
            tuple(loaders),
            tree,
        )
    except OSError as error:
        raise RuntimeValidationSafetyError(
            f"Could not safely analyze runtime-validation compatibility: {error}"
        ) from error
    finally:
        os.close(root_fd)


def _validate_manifest_path(path: str) -> bytes:
    rendered = ("./" + path).encode("utf-8")
    utf16_units = len(("./" + path).encode("utf-16-le")) // 2
    if (
        len(rendered) > MAX_MANIFEST_PATH_BYTES
        or utf16_units > MAX_MANIFEST_PATH_UTF16_UNITS
    ):
        raise RuntimeValidationSafetyError(
            f"Path exceeds the uefi-md5sum v1.2 parser limit: {path!r}"
        )
    return rendered


def _validate_compatibility(
    compatibility: RuntimeValidationCompatibility,
    root: Path,
) -> None:
    if (
        type(compatibility) is not RuntimeValidationCompatibility
        or compatibility.root != root
        or not compatibility.loaders
        or compatibility.architectures
        != tuple(loader.architecture for loader in compatibility.loaders)
        or any(type(entry) is not RuntimeValidationTreeEntry for entry in compatibility.tree)
        or any(
            type(loader) is not RuntimeValidationLoaderCandidate
            for loader in compatibility.loaders
        )
    ):
        raise RuntimeValidationSafetyError("The runtime-validation compatibility witness is invalid")


def _write_all(
    descriptor: int,
    data: bytes,
    cancel_event: threading.Event | None,
) -> None:
    offset = 0
    while offset < len(data):
        _check_cancel(cancel_event)
        block = memoryview(data)[offset:offset + _READ_CHUNK]
        while block:
            written = os.write(descriptor, block)
            if written <= 0:
                raise OSError("runtime-validation write made no progress")
            offset += written
            block = block[written:]


def _random_temp_name(prefix: str) -> str:
    return f".{prefix}-{secrets.token_hex(16)}.tmp"


def _install_wrapper(
    root_fd: int,
    candidate: RuntimeValidationLoaderCandidate,
    payload: RuntimeValidationPayload,
    tree: tuple[RuntimeValidationTreeEntry, ...],
    cancel_event: threading.Event | None,
) -> None:
    parts = PurePosixPath(candidate.fallback_path).parts
    original_parts = PurePosixPath(candidate.original_path).parts
    if parts[:-1] != original_parts[:-1]:
        raise RuntimeValidationSafetyError("The chainload original is outside its loader directory")
    parent_fd = _open_directory_parts(root_fd, parts[:-1], _tree_map(tree))
    temp_name = _random_temp_name("isopropyl-md5-wrapper")
    temp_created = False
    try:
        _check_cancel(cancel_event)
        before = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _file_identity(before) != candidate.source_identity
        ):
            raise RuntimeValidationSafetyError(
                f"Fallback loader changed before transformation: {candidate.fallback_path!r}"
            )
        os.link(
            parts[-1], original_parts[-1],
            src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False,
        )
        source = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        original = os.stat(original_parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (
            (
                source.st_dev, source.st_ino, source.st_size, source.st_mtime_ns
            ) != (
                candidate.source_identity[0], candidate.source_identity[1],
                candidate.source_identity[2], candidate.source_identity[3],
            )
            or (source.st_dev, source.st_ino) != (original.st_dev, original.st_ino)
            or source.st_nlink != 2
            or original.st_nlink != 2
        ):
            raise RuntimeValidationSafetyError(
                f"Could not bind the chainload original: {candidate.original_path!r}"
            )
        _check_cancel(cancel_event)
        descriptor = os.open(temp_name, _WRITE_FLAGS, 0o600, dir_fd=parent_fd)
        temp_created = True
        try:
            _write_all(descriptor, payload.data, cancel_event)
            os.fchmod(descriptor, 0o444)
            os.fsync(descriptor)
            written = os.fstat(descriptor)
            if not stat.S_ISREG(written.st_mode) or written.st_size != payload.size:
                raise RuntimeValidationSafetyError("The validation wrapper write was incomplete")
        finally:
            os.close(descriptor)
        _check_cancel(cancel_event)
        current = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        linked = os.stat(original_parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (
            (current.st_dev, current.st_ino) != (linked.st_dev, linked.st_ino)
            or current.st_nlink != 2
            or linked.st_nlink != 2
        ):
            raise RuntimeValidationSafetyError("The loader changed before wrapper installation")
        os.replace(temp_name, parts[-1], src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temp_created = False
        wrapper = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        original = os.stat(original_parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(wrapper.st_mode)
            or wrapper.st_nlink != 1
            or wrapper.st_size != payload.size
            or not stat.S_ISREG(original.st_mode)
            or original.st_nlink != 1
            or original.st_size != candidate.source_identity[2]
        ):
            raise RuntimeValidationSafetyError("The installed wrapper/original pair is unsafe")
        os.fsync(parent_fd)
    finally:
        if temp_created:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)


def _hash_manifest_file(
    root_fd: int,
    entry: RuntimeValidationTreeEntry,
    tree: tuple[RuntimeValidationTreeEntry, ...],
    cancel_event: threading.Event | None,
) -> str:
    _check_cancel(cancel_event)
    parts = PurePosixPath(entry.path).parts
    parent_fd = _open_directory_parts(root_fd, parts[:-1], _tree_map(tree))
    try:
        before = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _file_identity(before) != entry.identity
        ):
            raise RuntimeValidationSafetyError(f"File changed before hashing: {entry.path!r}")
        descriptor = os.open(parts[-1], _READ_FLAGS, dir_fd=parent_fd)
        try:
            opened = os.fstat(descriptor)
            if _file_identity(opened) != entry.identity or opened.st_nlink != 1:
                raise RuntimeValidationSafetyError(
                    f"File changed while opening for hashing: {entry.path!r}"
                )
            digest = hashlib.md5(usedforsecurity=False)
            remaining = opened.st_size
            while remaining:
                _check_cancel(cancel_event)
                block = os.read(descriptor, min(_READ_CHUNK, remaining))
                if not block:
                    raise RuntimeValidationSafetyError(
                        f"File ended while hashing: {entry.path!r}"
                    )
                digest.update(block)
                remaining -= len(block)
            if os.read(descriptor, 1):
                raise RuntimeValidationSafetyError(f"File grew while hashing: {entry.path!r}")
            final = os.fstat(descriptor)
            if _file_identity(final) != entry.identity:
                raise RuntimeValidationSafetyError(
                    f"File metadata changed while hashing: {entry.path!r}"
                )
            return digest.hexdigest()
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def _build_manifest(
    root_fd: int,
    tree: tuple[RuntimeValidationTreeEntry, ...],
    wrapper_paths: frozenset[str],
    cancel_event: threading.Event | None,
) -> bytes:
    _check_cancel(cancel_event)
    files = tuple(
        entry for entry in tree
        if entry.kind == "file"
        and entry.path != RUNTIME_VALIDATION_MANIFEST
        and entry.path not in wrapper_paths
    )
    if not files:
        raise RuntimeValidationSafetyError("The runtime manifest would cover no files")
    # Upstream initializes its line counter to one before counting newlines.
    if len(files) + 2 > MAX_MANIFEST_LINES:
        raise RuntimeValidationSafetyError("The runtime manifest exceeds the parser line limit")
    total = 0
    lines: list[bytes] = []
    for entry in files:
        _check_cancel(cancel_event)
        if entry.identity[2] > MAX_TOTAL_BYTES - total:
            raise RuntimeValidationSafetyError("The runtime manifest byte total overflows uint64")
        total += entry.identity[2]
        path_bytes = _validate_manifest_path(entry.path)
        digest = _hash_manifest_file(root_fd, entry, tree, cancel_event)
        lines.append(digest.encode("ascii") + b"  " + path_bytes + b"\n")
    manifest = f"# md5sum_totalbytes = 0x{total:x}\n".encode("ascii") + b"".join(lines)
    if len(manifest) > MAX_MANIFEST_BYTES:
        raise RuntimeValidationSafetyError("The runtime manifest exceeds the parser size limit")
    if 1 + manifest.count(b"\n") > MAX_MANIFEST_LINES:
        raise RuntimeValidationSafetyError("The runtime manifest exceeds the parser line limit")
    return manifest


def _write_manifest(
    root_fd: int,
    manifest: bytes,
    old_entry: RuntimeValidationTreeEntry | None,
    cancel_event: threading.Event | None,
) -> None:
    temp_name = _random_temp_name("isopropyl-md5sum")
    temp_created = False
    try:
        descriptor = os.open(temp_name, _WRITE_FLAGS, 0o600, dir_fd=root_fd)
        temp_created = True
        try:
            _write_all(descriptor, manifest, cancel_event)
            os.fchmod(descriptor, 0o444)
            os.fsync(descriptor)
            if os.fstat(descriptor).st_size != len(manifest):
                raise RuntimeValidationSafetyError("The runtime manifest write was incomplete")
        finally:
            os.close(descriptor)
        _check_cancel(cancel_event)
        if old_entry is not None:
            observed = os.stat(
                RUNTIME_VALIDATION_MANIFEST, dir_fd=root_fd, follow_symlinks=False
            )
            if (
                old_entry.kind != "file"
                or not stat.S_ISREG(observed.st_mode)
                or observed.st_nlink != 1
                or _file_identity(observed) != old_entry.identity
            ):
                raise RuntimeValidationSafetyError("The existing runtime manifest changed")
            os.replace(
                temp_name, RUNTIME_VALIDATION_MANIFEST,
                src_dir_fd=root_fd, dst_dir_fd=root_fd,
            )
            temp_created = False
        else:
            os.link(
                temp_name, RUNTIME_VALIDATION_MANIFEST,
                src_dir_fd=root_fd, dst_dir_fd=root_fd, follow_symlinks=False,
            )
            os.unlink(temp_name, dir_fd=root_fd)
            temp_created = False
            installed = os.stat(
                RUNTIME_VALIDATION_MANIFEST, dir_fd=root_fd, follow_symlinks=False
            )
            if not stat.S_ISREG(installed.st_mode) or installed.st_nlink != 1:
                raise RuntimeValidationSafetyError("The installed runtime manifest is unsafe")
        os.fsync(root_fd)
    finally:
        if temp_created:
            try:
                os.unlink(temp_name, dir_fd=root_fd)
            except OSError:
                pass


def _verify_exact_file(
    root_fd: int,
    entry: RuntimeValidationTreeEntry,
    tree: tuple[RuntimeValidationTreeEntry, ...],
    algorithm: str,
    expected_digest: str,
    cancel_event: threading.Event | None = None,
) -> None:
    _check_cancel(cancel_event)
    parts = PurePosixPath(entry.path).parts
    parent_fd = _open_directory_parts(root_fd, parts[:-1], _tree_map(tree))
    try:
        observed = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(parts[-1], _READ_FLAGS, dir_fd=parent_fd)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_nlink != 1
                or _file_identity(observed) != entry.identity
                or _file_identity(opened) != entry.identity
            ):
                raise RuntimeValidationSafetyError(f"Witness file changed: {entry.path!r}")
            digest = hashlib.new(algorithm)
            remaining = opened.st_size
            while remaining:
                _check_cancel(cancel_event)
                block = os.read(descriptor, min(_READ_CHUNK, remaining))
                if not block:
                    raise RuntimeValidationSafetyError(f"Witness file ended early: {entry.path!r}")
                digest.update(block)
                remaining -= len(block)
            final = os.fstat(descriptor)
            if (
                os.read(descriptor, 1)
                or _file_identity(final) != entry.identity
                or not hmac.compare_digest(digest.hexdigest(), expected_digest)
            ):
                raise RuntimeValidationSafetyError(f"Witness file content changed: {entry.path!r}")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def _stage_from_tree(
    root: Path,
    root_fd: int,
    prepared: PreparedRuntimeValidation,
    compatibility: RuntimeValidationCompatibility,
    tree: tuple[RuntimeValidationTreeEntry, ...],
    manifest: bytes,
    cancel_event: threading.Event | None,
) -> RuntimeValidationStage:
    mapping = _tree_map(tree)
    manifest_entry = mapping.get(RUNTIME_VALIDATION_MANIFEST)
    if manifest_entry is None or manifest_entry.kind != "file":
        raise RuntimeValidationSafetyError("The generated runtime manifest is missing")
    loaders: list[RuntimeValidationLoader] = []
    payloads = {payload.source_name: payload for payload in prepared.payloads}
    for candidate in compatibility.loaders:
        wrapper = mapping.get(candidate.fallback_path)
        original = mapping.get(candidate.original_path)
        payload = payloads[candidate.source_name]
        if (
            wrapper is None or wrapper.kind != "file"
            or original is None or original.kind != "file"
        ):
            raise RuntimeValidationSafetyError("An installed wrapper/original pair is missing")
        _verify_exact_file(
            root_fd, wrapper, tree, "sha256", payload.sha256, cancel_event
        )
        _verify_exact_file(
            root_fd, original, tree, "sha256", candidate.source_sha256, cancel_event
        )
        loaders.append(RuntimeValidationLoader(
            candidate.source_name,
            candidate.architecture,
            candidate.fallback_path,
            candidate.original_path,
            payload.sha256,
            wrapper.identity,
            original.identity,
        ))
    manifest_digest = hashlib.sha256(manifest).hexdigest()
    _verify_exact_file(
        root_fd, manifest_entry, tree, "sha256", manifest_digest, cancel_event
    )
    _check_cancel(cancel_event)
    root_info = os.fstat(root_fd)
    return RuntimeValidationStage(
        root,
        (root_info.st_dev, root_info.st_ino),
        RUNTIME_VALIDATION_VERSION,
        compatibility.architectures,
        tuple(loaders),
        manifest_digest,
        manifest_entry.identity,
        tree,
        RUNTIME_VALIDATION_LICENSE,
        RUNTIME_VALIDATION_PROVENANCE_URL,
    )


def apply_runtime_validation(
    prepared: PreparedRuntimeValidation,
    staging_root: Path,
    *,
    compatibility: RuntimeValidationCompatibility | None = None,
    cancel_event: threading.Event | None = None,
) -> RuntimeValidationStage:
    """Transform an already-final private tree and return an exact witness.

    Failure or cancellation never returns a usable witness.  Because mutations
    are intentionally in-place, the caller must discard the private workspace
    after any exception.
    """

    validate_prepared_runtime_validation(prepared)
    fresh_compatibility = analyze_runtime_validation_compatibility(
        staging_root, cancel_event=cancel_event
    )
    if compatibility is not None:
        _validate_compatibility(compatibility, staging_root)
        if compatibility != fresh_compatibility:
            raise RuntimeValidationSafetyError(
                "The supplied compatibility witness does not match a fresh analysis"
            )
    compatibility = fresh_compatibility
    _check_cancel(cancel_event)
    try:
        root_fd = _open_absolute_directory(staging_root)
    except (OSError, RuntimeValidationError) as error:
        if isinstance(error, RuntimeValidationError):
            raise
        raise RuntimeValidationSafetyError(
            f"Could not reopen the private staging root: {error}"
        ) from error
    try:
        root_info = os.fstat(root_fd)
        if (root_info.st_dev, root_info.st_ino) != compatibility.root_identity:
            raise RuntimeValidationSafetyError("The private staging root identity changed")
        if _scan_tree(root_fd, cancel_event) != compatibility.tree:
            raise RuntimeValidationSafetyError("The private staging tree changed after analysis")
        payloads = {payload.source_name: payload for payload in prepared.payloads}
        for candidate in compatibility.loaders:
            payload = payloads.get(candidate.source_name)
            if payload is None or payload.architecture != candidate.architecture:
                raise RuntimeValidationSafetyError("The prepared wrapper set is incompatible")
            _install_wrapper(
                root_fd, candidate, payload, compatibility.tree, cancel_event
            )
        _check_cancel(cancel_event)
        transformed_tree = _scan_tree(root_fd, cancel_event)
        wrappers = frozenset(loader.fallback_path for loader in compatibility.loaders)
        manifest = _build_manifest(root_fd, transformed_tree, wrappers, cancel_event)
        old_manifest = _tree_map(transformed_tree).get(RUNTIME_VALIDATION_MANIFEST)
        _write_manifest(root_fd, manifest, old_manifest, cancel_event)
        _check_cancel(cancel_event)
        final_tree = _scan_tree(root_fd, cancel_event)
        named_fd = _open_absolute_directory(staging_root)
        try:
            named = os.fstat(named_fd)
            if (named.st_dev, named.st_ino) != (root_info.st_dev, root_info.st_ino):
                raise RuntimeValidationSafetyError("The private staging root path changed")
        finally:
            os.close(named_fd)
        _validate_manifest_bytes(
            root_fd, manifest, final_tree, wrappers, cancel_event
        )
        _check_cancel(cancel_event)
        stage = _stage_from_tree(
            staging_root, root_fd, prepared, compatibility, final_tree, manifest,
            cancel_event,
        )
        _check_cancel(cancel_event)
        if _scan_tree(root_fd, cancel_event) != final_tree:
            raise RuntimeValidationSafetyError(
                "The private staging tree changed during final verification"
            )
        final_named_fd = _open_absolute_directory(staging_root)
        try:
            final_named = os.fstat(final_named_fd)
            if (final_named.st_dev, final_named.st_ino) != stage.root_identity:
                raise RuntimeValidationSafetyError(
                    "The private staging root path changed during final verification"
                )
        finally:
            os.close(final_named_fd)
        return stage
    except RuntimeValidationError:
        raise
    except OSError as error:
        raise RuntimeValidationSafetyError(
            f"Could not safely apply runtime media validation: {error}"
        ) from error
    finally:
        os.close(root_fd)


def _validate_manifest_bytes(
    root_fd: int,
    manifest: bytes,
    tree: tuple[RuntimeValidationTreeEntry, ...],
    wrapper_paths: frozenset[str],
    cancel_event: threading.Event | None,
) -> None:
    _check_cancel(cancel_event)
    if len(manifest) > MAX_MANIFEST_BYTES or not manifest.endswith(b"\n"):
        raise RuntimeValidationSafetyError("The runtime manifest framing is invalid")
    lines = manifest[:-1].split(b"\n")
    prefix = b"# md5sum_totalbytes = 0x"
    if not lines or not lines[0].startswith(prefix):
        raise RuntimeValidationSafetyError("The runtime manifest total is missing")
    if 1 + manifest.count(b"\n") > MAX_MANIFEST_LINES:
        raise RuntimeValidationSafetyError("The runtime manifest has too many lines")
    total_bytes = lines[0][len(prefix):]
    try:
        total_text = total_bytes.decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeValidationSafetyError(
            "The runtime manifest total is non-canonical"
        ) from error
    if (
        not total_text
        or len(total_text) > 16
        or total_text != total_text.lower()
        or any(character not in "0123456789abcdef" for character in total_text)
    ):
        raise RuntimeValidationSafetyError("The runtime manifest total is non-canonical")
    covered = tuple(
        entry for entry in tree
        if entry.kind == "file"
        and entry.path != RUNTIME_VALIDATION_MANIFEST
        and entry.path not in wrapper_paths
    )
    if len(lines) != len(covered) + 1:
        raise RuntimeValidationSafetyError("The runtime manifest coverage changed")
    expected_total = sum(entry.identity[2] for entry in covered)
    if int(total_text, 16) != expected_total:
        raise RuntimeValidationSafetyError("The runtime manifest total changed")
    for line, entry in zip(lines[1:], covered, strict=True):
        path_bytes = _validate_manifest_path(entry.path)
        if (
            len(line) != 32 + 2 + len(path_bytes)
            or line[32:34] != b"  "
            or line[34:] != path_bytes
            or any(character not in b"0123456789abcdef" for character in line[:32])
        ):
            raise RuntimeValidationSafetyError("The runtime manifest grammar changed")
        digest = _hash_manifest_file(root_fd, entry, tree, cancel_event)
        if not hmac.compare_digest(digest.encode("ascii"), line[:32]):
            raise RuntimeValidationSafetyError(
                f"The runtime manifest digest changed for {entry.path!r}"
            )


def _derive_installed_loaders(
    root_fd: int,
    tree: tuple[RuntimeValidationTreeEntry, ...],
    cancel_event: threading.Event | None,
) -> tuple[RuntimeValidationLoader, ...]:
    """Derive every installed wrapper/original pair from the current tree."""

    _check_cancel(cancel_event)
    by_key = {
        _path_key(PurePosixPath(entry.path).parts): entry
        for entry in tree
    }
    wrapper_digests = frozenset(
        profile.sha256 for profile in RUNTIME_VALIDATION_ARTIFACTS
    )
    installed: list[RuntimeValidationLoader] = []
    installed_original_keys: set[tuple[str, ...]] = set()
    for profile in RUNTIME_VALIDATION_ARTIFACTS:
        _check_cancel(cancel_event)
        fallback_key = _path_key(PurePosixPath(profile.fallback_path).parts)
        wrapper = by_key.get(fallback_key)
        if wrapper is None:
            continue
        if wrapper.kind != "file" or wrapper.identity[2] != profile.size:
            raise RuntimeValidationSafetyError(
                f"Recognized fallback is not the exact validation wrapper: {wrapper.path!r}"
            )
        _wrapper_blob, wrapper_digest = _read_bound_file(
            root_fd,
            wrapper,
            tree,
            max_bytes=profile.size,
            cancel_event=cancel_event,
        )
        if not hmac.compare_digest(wrapper_digest, profile.sha256):
            raise RuntimeValidationSafetyError(
                f"Recognized fallback is not the exact validation wrapper: {wrapper.path!r}"
            )

        fallback_parts = PurePosixPath(wrapper.path).parts
        original_name = PurePosixPath(profile.original_path).name
        expected_original_path = PurePosixPath(
            *fallback_parts[:-1], original_name,
        ).as_posix()
        original_key = _path_key((*fallback_parts[:-1], original_name))
        original = by_key.get(original_key)
        if (
            original is None
            or original.kind != "file"
            or original.path != expected_original_path
        ):
            raise RuntimeValidationSafetyError(
                f"The exact chainload original is missing for {wrapper.path!r}"
            )
        original_blob, original_digest = _read_bound_file(
            root_fd,
            original,
            tree,
            max_bytes=MAX_PE_SIZE,
            cancel_event=cancel_event,
        )
        if original_digest in wrapper_digests:
            raise RuntimeValidationSafetyError(
                f"The chainload original is itself a validation wrapper: {original.path!r}"
            )
        try:
            inspection = _structural_pe_inspection(original_blob)
        except PeFormatError as error:
            raise RuntimeValidationSafetyError(
                f"Chainload original {original.path!r} is not valid PE/COFF: {error}"
            ) from error
        if (
            not inspection.is_uefi_image
            or inspection.subsystem_name != "EFI application"
            or inspection.architecture != profile.architecture
        ):
            raise RuntimeValidationSafetyError(
                f"Chainload original {original.path!r} does not match {profile.architecture}"
            )
        installed.append(RuntimeValidationLoader(
            profile.source_name,
            profile.architecture,
            wrapper.path,
            original.path,
            profile.sha256,
            wrapper.identity,
            original.identity,
        ))
        installed_original_keys.add(original_key)

    boot_directory_keys = {
        _path_key(PurePosixPath(profile.fallback_path).parts[:-1])
        for profile in RUNTIME_VALIDATION_ARTIFACTS
    }
    for entry in tree:
        _check_cancel(cancel_event)
        parts = PurePosixPath(entry.path).parts
        if (
            _path_key(parts[:-1]) in boot_directory_keys
            and parts[-1].casefold().endswith("_original.efi")
            and _path_key(parts) not in installed_original_keys
        ):
            raise RuntimeValidationSafetyError(
                f"An unbound chainload original is ambiguous: {entry.path!r}"
            )
    if not installed:
        raise RuntimeValidationSafetyError(
            "The staged tree has no exact runtime-validation wrapper/original pair"
        )
    _check_cancel(cancel_event)
    return tuple(installed)


def validate_runtime_validation_stage(
    stage: RuntimeValidationStage,
    *,
    cancel_event: threading.Event | None = None,
) -> RuntimeValidationStage:
    """Reopen and exactly validate a returned witness before downstream use."""

    if (
        type(stage) is not RuntimeValidationStage
        or stage.version != RUNTIME_VALIDATION_VERSION
        or stage.license != RUNTIME_VALIDATION_LICENSE
        or stage.provenance_url != RUNTIME_VALIDATION_PROVENANCE_URL
        or not stage.loaders
        or stage.architectures != tuple(loader.architecture for loader in stage.loaders)
        or any(type(loader) is not RuntimeValidationLoader for loader in stage.loaders)
        or any(type(entry) is not RuntimeValidationTreeEntry for entry in stage.tree)
    ):
        raise RuntimeValidationSafetyError("The runtime-validation stage witness is invalid")
    _check_cancel(cancel_event)
    try:
        root_fd = _open_absolute_directory(stage.root)
    except (OSError, RuntimeValidationError) as error:
        if isinstance(error, RuntimeValidationError):
            raise
        raise RuntimeValidationSafetyError(
            f"Could not reopen the runtime-validation stage: {error}"
        ) from error
    try:
        root_info = os.fstat(root_fd)
        if (root_info.st_dev, root_info.st_ino) != stage.root_identity:
            raise RuntimeValidationSafetyError("The runtime-validation root identity changed")
        tree = _scan_tree(root_fd, cancel_event)
        if tree != stage.tree:
            raise RuntimeValidationSafetyError("The runtime-validation staged tree changed")
        mapping = _tree_map(tree)
        manifest_entry = mapping.get(RUNTIME_VALIDATION_MANIFEST)
        if (
            manifest_entry is None
            or manifest_entry.kind != "file"
            or manifest_entry.identity != stage.manifest_identity
        ):
            raise RuntimeValidationSafetyError("The runtime manifest identity changed")
        blob, digest = _read_bound_file(
            root_fd, manifest_entry, tree,
            max_bytes=MAX_MANIFEST_BYTES, cancel_event=cancel_event,
        )
        if not hmac.compare_digest(digest, stage.manifest_sha256):
            raise RuntimeValidationSafetyError("The runtime manifest content changed")
        installed_loaders = _derive_installed_loaders(
            root_fd, tree, cancel_event,
        )
        if (
            stage.loaders != installed_loaders
            or stage.architectures
            != tuple(loader.architecture for loader in installed_loaders)
        ):
            raise RuntimeValidationSafetyError(
                "The installed runtime-validation loader set is not exact"
            )
        wrapper_paths = frozenset(
            loader.fallback_path for loader in installed_loaders
        )
        _validate_manifest_bytes(
            root_fd, blob, tree, wrapper_paths, cancel_event
        )
        if _scan_tree(root_fd, cancel_event) != tree:
            raise RuntimeValidationSafetyError(
                "The runtime-validation staged tree changed during validation"
            )
        named_fd = _open_absolute_directory(stage.root)
        try:
            named = os.fstat(named_fd)
            if (named.st_dev, named.st_ino) != stage.root_identity:
                raise RuntimeValidationSafetyError(
                    "The runtime-validation root path changed during validation"
                )
        finally:
            os.close(named_fd)
        _check_cancel(cancel_event)
        return stage
    except OSError as error:
        raise RuntimeValidationSafetyError(
            f"Could not validate the runtime-validation stage: {error}"
        ) from error
    finally:
        os.close(root_fd)
