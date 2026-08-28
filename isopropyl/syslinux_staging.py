from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Pure, fail-closed staging policy for the first Syslinux BIOS profile.

This module opens no path and writes no byte.  It accepts a complete portable
ISO catalog, the immutable result of boot-payload analysis, descriptor-caller-
supplied immutable bytes for every source member on which the decision relies,
and one already downloaded catalog bundle.  Its output describes the only two
files the later private-tree executor may need to create or reuse:

* a root ``syslinux.cfg`` redirect; and
* the exact ``ldlinux.c32`` matching the selected Syslinux build.

The initial policy is deliberately narrow.  It supports only the two builds
whose installer payloads are independently pinned by :mod:`isopropyl.syslinux`,
never replaces a file, and rejects every other C32 module.  A future expansion
must first bind the complete C32 dependency closure for the selected image.
"""

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath
from types import MappingProxyType

from .boot_identity import (
    BootloaderAnalysis,
    BootloaderIdentity,
    identify_syslinux_blob,
)
from .bootloaders import BoundBootArtifact, BoundBootBundle
from .iso import (
    ArchiveEntry,
    EntryKind,
    UnsafeArchiveError,
    validate_portable_fat_entries,
)


MAX_SYSLINUX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_SYSLINUX_C32_BYTES = 1024 * 1024
MAX_SYSLINUX_DIRECTORY_BYTES = 127
MAX_SYSLINUX_IDENTITY_COUNT = 8
MAX_SYSLINUX_LOADER_BYTES = 4 * 1024 * 1024
MAX_SYSLINUX_IDENTITY_BYTES = 16 * 1024 * 1024
_CONFIG_NAMES = frozenset({"isolinux.cfg", "syslinux.cfg", "extlinux.conf"})
_DIRECTORY_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]*\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PLAN_WITNESS = object()

# These pins intentionally duplicate the acquisition catalog.  A catalog edit
# alone must not broaden this safety-critical consumer or silently substitute a
# different ABI payload.
PINNED_SYSLINUX_C32 = MappingProxyType({
    "6.03-2014-10-06": (
        122_308,
        "5cef9ad0d0ca04097262241686c6c3a7306ab9b9cdf24b9d4ee3b16af01a5af2",
        "https://github.com/pbatard/rufus-web/tree/"
        "e6e2182d325ae95ac15166ea2ee750cebccff3c1/files/syslinux-6.03",
    ),
    "6.04-pre1": (
        122_656,
        "d3472c02263acf9cd1da5db51e263c5484bad13ea68618c403d9cb01ca070aee",
        "https://github.com/pbatard/rufus-web/tree/"
        "e6e2182d325ae95ac15166ea2ee750cebccff3c1/files/syslinux-6.04",
    ),
})

_IDENTITY_SHAPES = MappingProxyType({
    "6.03-2014-10-06": ("6.03", True),
    "6.04-pre1": ("6.04", True),
})


class SyslinuxStagingError(ValueError):
    """The proposed Syslinux staging transformation is not provably safe."""


class StageDisposition(str, Enum):
    CREATE = "create"
    REUSE = "reuse"


@dataclass(frozen=True)
class BoundSyslinuxC32:
    version: str
    data: bytes
    sha256: str
    provenance_url: str


@dataclass(frozen=True)
class SyslinuxStageFile:
    path: str
    data: bytes
    sha256: str
    disposition: StageDisposition


@dataclass(frozen=True)
class SyslinuxStagingPlan:
    version: str
    dependency_key: str
    bootloader_path: str
    config_path: str
    config_directory: str
    root_redirect: SyslinuxStageFile | None
    ldlinux_c32: SyslinuxStageFile
    source_catalog_sha256: str
    analysis_sha256: str
    source_members_sha256: str
    config_sha256: str
    _witness: object = field(default=None, repr=False, compare=True)

    @property
    def additions(self) -> tuple[SyslinuxStageFile, ...]:
        """Return only files that a later executor must create exclusively."""

        candidates = (self.root_redirect, self.ldlinux_c32)
        return tuple(
            item for item in candidates
            if item is not None and item.disposition is StageDisposition.CREATE
        )


def _case_key(path: str) -> tuple[str, ...]:
    return tuple(
        unicodedata.normalize("NFC", part).casefold()
        for part in PurePosixPath(path).parts
    )


def _catalog_digest(entries: tuple[ArchiveEntry, ...]) -> str:
    encoded = json.dumps(
        [
            {
                "path": item.path,
                "size": item.size,
                "kind": item.kind.value,
                "link_target": item.link_target,
                "modified_ns": item.modified_ns,
            }
            for item in entries
        ],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _occupied_keys(entries: tuple[ArchiveEntry, ...]) -> frozenset[tuple[str, ...]]:
    return frozenset(
        tuple(part.casefold() for part in PurePosixPath(item.path).parts[:length])
        for item in entries
        for length in range(1, len(PurePosixPath(item.path).parts) + 1)
    )


def _analysis_digest(identities: tuple[BootloaderIdentity, ...]) -> str:
    encoded = json.dumps(
        [
            {
                "family": item.family,
                "version": item.version,
                "build": item.build,
                "source": item.source,
                "custom_build": item.custom_build,
                "ambiguous": item.ambiguous,
                "candidates": item.candidates,
                "evidence": item.evidence,
            }
            for item in sorted(identities, key=lambda value: value.source)
        ],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _source_members_digest(
    identities: tuple[BootloaderIdentity, ...],
    source_files: Mapping[str, bytes],
) -> str:
    encoded = json.dumps(
        [
            {
                "path": path,
                "size": len(source_files[path]),
                "sha256": hashlib.sha256(source_files[path]).hexdigest(),
            }
            for path in sorted({item.source for item in identities})
        ],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validated_catalog(entries: Sequence[ArchiveEntry]) -> tuple[ArchiveEntry, ...]:
    if isinstance(entries, (str, bytes, bytearray)) or not isinstance(entries, Sequence):
        raise SyslinuxStagingError("a concrete ISO catalog sequence is required")
    candidates = tuple(entries)
    if not candidates or any(type(item) is not ArchiveEntry for item in candidates):
        raise SyslinuxStagingError("the ISO catalog contains an invalid entry")
    try:
        validated = validate_portable_fat_entries(candidates)
    except (AttributeError, TypeError, UnsafeArchiveError, ValueError) as error:
        raise SyslinuxStagingError(str(error)) from error
    if validated != candidates:
        raise SyslinuxStagingError("the ISO catalog is not in canonical portable form")
    if any(
        item.kind not in {EntryKind.FILE, EntryKind.DIRECTORY}
        or item.link_target is not None
        for item in validated
    ):
        raise SyslinuxStagingError("Syslinux staging refuses links and special entries")
    directory_spellings: dict[tuple[str, ...], tuple[str, ...]] = {}
    for item in validated:
        parts = PurePosixPath(item.path).parts
        count = len(parts) if item.kind is EntryKind.DIRECTORY else len(parts) - 1
        for length in range(1, count + 1):
            prefix = parts[:length]
            key = tuple(part.casefold() for part in prefix)
            previous = directory_spellings.get(key)
            if previous is not None and previous != prefix:
                raise SyslinuxStagingError(
                    "the ISO catalog contains inconsistent FAT directory spellings",
                )
            directory_spellings[key] = prefix
    return validated


def syslinux_staging_analysis_paths(
    entries: Sequence[ArchiveEntry],
) -> tuple[str, ...]:
    """Return the bounded base-ISO Isolinux candidates safe to inspect."""

    catalog = _validated_catalog(entries)
    candidates = tuple(
        entry for entry in catalog
        if PurePosixPath(entry.path).name.casefold() == "isolinux.bin"
    )
    if (
        not candidates
        or len(candidates) > MAX_SYSLINUX_IDENTITY_COUNT
        or any(
            entry.kind is not EntryKind.FILE
            or entry.size <= 0
            or entry.size > MAX_SYSLINUX_LOADER_BYTES
            for entry in candidates
        )
        or sum(entry.size for entry in candidates) > MAX_SYSLINUX_IDENTITY_BYTES
    ):
        raise SyslinuxStagingError(
            "the Isolinux candidate set exceeds the bounded staging profile",
        )
    return tuple(entry.path for entry in candidates)


def bind_syslinux_c32_bundle(bundle: BoundBootBundle) -> BoundSyslinuxC32:
    """Independently bind one exact, immutable ``ldlinux.c32`` artifact."""

    if type(bundle) is not BoundBootBundle:
        raise SyslinuxStagingError("an exact bound Syslinux C32 bundle is required")
    if (
        type(bundle.family) is not str
        or type(bundle.version) is not str
        or type(bundle.purpose) is not str
        or type(bundle.license) is not str
        or type(bundle.provenance_url) is not str
    ):
        raise SyslinuxStagingError("the Syslinux C32 bundle fields are invalid")
    pin = PINNED_SYSLINUX_C32.get(bundle.version)
    if (
        pin is None
        or bundle.family != "syslinux"
        or bundle.purpose != "blank-bios-module"
        or bundle.license != "GPL-2.0-or-later"
        or bundle.provenance_url != pin[2]
        or type(bundle.artifacts) is not tuple
        or len(bundle.artifacts) != 1
    ):
        raise SyslinuxStagingError("the bundle is not a supported Syslinux C32 bundle")
    artifact = bundle.artifacts[0]
    if (
        type(artifact) is not BoundBootArtifact
        or type(artifact.name) is not str
        or artifact.name != "ldlinux.c32"
    ):
        raise SyslinuxStagingError("the Syslinux C32 bundle has an invalid artifact set")
    expected_size, expected_sha256, provenance = pin
    if type(artifact.data) is not bytes or type(artifact.sha256) is not str:
        raise SyslinuxStagingError("ldlinux.c32 is not immutable bound bytes")
    actual_sha256 = hashlib.sha256(artifact.data).hexdigest()
    if (
        len(artifact.data) != expected_size
        or artifact.sha256 != expected_sha256
        or actual_sha256 != expected_sha256
    ):
        raise SyslinuxStagingError("ldlinux.c32 does not match its independent pin")
    return BoundSyslinuxC32(
        bundle.version, artifact.data, expected_sha256, provenance,
    )


def _validated_syslinux_identities(
    analysis: BootloaderAnalysis,
    entries_by_path: Mapping[str, ArchiveEntry],
) -> tuple[str, tuple[BootloaderIdentity, ...]]:
    if (
        type(analysis) is not BootloaderAnalysis
        or analysis.complete is not True
        or type(analysis.identities) is not tuple
        or type(analysis.issues) is not tuple
        or analysis.issues
        or any(type(item) is not BootloaderIdentity for item in analysis.identities)
        or any(type(item.family) is not str for item in analysis.identities)
    ):
        raise SyslinuxStagingError("bootloader analysis is incomplete, invalid, or has issues")
    identities = tuple(
        item for item in analysis.identities
        if item.family in {"Syslinux", "Isolinux", "Syslinux/Isolinux"}
    )
    if not identities:
        raise SyslinuxStagingError("the image has no exact Isolinux identity")

    identity_sources = tuple(item.source for item in identities)
    cataloged_sources = tuple(
        entry.path for entry in entries_by_path.values()
        if PurePosixPath(entry.path).name.casefold() == "isolinux.bin"
    )
    if (
        len(set(identity_sources)) != len(identity_sources)
        or set(identity_sources) != set(cataloged_sources)
    ):
        raise SyslinuxStagingError(
            "every cataloged Isolinux payload requires an exact identity",
        )
    if (
        len(identity_sources) > MAX_SYSLINUX_IDENTITY_COUNT
        or any(
            entries_by_path[source].size > MAX_SYSLINUX_LOADER_BYTES
            for source in identity_sources
        )
        or sum(
            entries_by_path[source].size for source in identity_sources
        ) > MAX_SYSLINUX_IDENTITY_BYTES
    ):
        raise SyslinuxStagingError(
            "the Isolinux identity set exceeds the bounded staging profile",
        )

    builds: set[str] = set()
    for identity in identities:
        if (
            type(identity.family) is not str
            or type(identity.version) is not str
            or type(identity.build) is not str
            or type(identity.source) is not str
            or type(identity.custom_build) is not bool
            or type(identity.ambiguous) is not bool
            or type(identity.candidates) is not tuple
            or type(identity.evidence) is not tuple
            or any(type(value) is not str for value in identity.candidates)
            or any(type(value) is not str for value in identity.evidence)
        ):
            raise SyslinuxStagingError("the Isolinux identity fields are invalid")
        shape = _IDENTITY_SHAPES.get(identity.build or "")
        entry = entries_by_path.get(identity.source)
        if (
            identity.family != "Isolinux"
            or shape is None
            or identity.version != shape[0]
            or identity.custom_build is not shape[1]
            or identity.ambiguous is not False
            or identity.candidates != (identity.build,)
            or identity.evidence != ("embedded ISOLINUX version marker",)
            or identity.dependency_key != f"syslinux:{identity.build}"
            or PurePosixPath(identity.source).name.casefold() != "isolinux.bin"
            or entry is None
            or entry.path != identity.source
            or entry.kind is not EntryKind.FILE
            or entry.size <= 0
        ):
            raise SyslinuxStagingError("the Isolinux identity is forged or unsupported")
        assert identity.build is not None
        builds.add(identity.build)
    if len(builds) != 1:
        raise SyslinuxStagingError("the image contains conflicting Isolinux builds")
    build = next(iter(builds))
    resolved = analysis.resolved("Syslinux/Isolinux")
    if resolved is None or resolved.dependency_key != f"syslinux:{build}":
        raise SyslinuxStagingError("the Isolinux build does not resolve globally")
    return build, identities


def _relative_parent(path: str) -> str:
    parent = PurePosixPath(path).parent.as_posix()
    return "" if parent == "." else parent


def _patch_directory(relative_parent: str) -> str:
    if not relative_parent:
        return ""
    try:
        encoded = relative_parent.encode("ascii")
    except UnicodeEncodeError as error:
        raise SyslinuxStagingError(
            "the Syslinux configuration directory must be ASCII",
        ) from error
    parts = relative_parent.split("/")
    if (
        len(encoded) + 1 > MAX_SYSLINUX_DIRECTORY_BYTES
        or any(_DIRECTORY_COMPONENT.fullmatch(part) is None for part in parts)
    ):
        raise SyslinuxStagingError(
            "the Syslinux configuration directory is not safely patchable",
        )
    return "/" + relative_parent


def _validate_config_entry(entry: ArchiveEntry) -> None:
    if (
        entry.kind is not EntryKind.FILE
        or entry.size <= 0
        or entry.size > MAX_SYSLINUX_CONFIG_BYTES
    ):
        raise SyslinuxStagingError(
            "the selected Syslinux configuration is empty, oversized, or not a file",
        )
    try:
        entry.path.encode("ascii")
    except UnicodeEncodeError as error:
        raise SyslinuxStagingError(
            "the selected Syslinux configuration path must be ASCII",
        ) from error


def _source_bytes(
    source_files: Mapping[str, bytes] | None,
    expected_paths: tuple[str, ...],
) -> dict[str, bytes]:
    if source_files is None or not isinstance(source_files, Mapping):
        raise SyslinuxStagingError(
            "descriptor-bound ISO source member bytes are required",
        )
    result: dict[str, bytes] = {}
    keys: set[tuple[str, ...]] = set()
    for path, data in source_files.items():
        if type(path) is not str or type(data) is not bytes or not path:
            raise SyslinuxStagingError("ISO source member bytes contain an invalid item")
        key = _case_key(path)
        if key in keys:
            raise SyslinuxStagingError(
                "ISO source member bytes contain a casefold collision",
            )
        keys.add(key)
        result[path] = data
    if set(result) != set(expected_paths):
        raise SyslinuxStagingError(
            "ISO source member bytes are incomplete or contain unexpected paths",
        )
    return result


def _validate_identity_source_bytes(
    identities: tuple[BootloaderIdentity, ...],
    entries_by_path: Mapping[str, ArchiveEntry],
    source_files: Mapping[str, bytes],
) -> None:
    for identity in identities:
        data = source_files[identity.source]
        entry = entries_by_path[identity.source]
        if len(data) != entry.size:
            raise SyslinuxStagingError(
                "an Isolinux source member does not match its catalog size",
            )
        try:
            observed = identify_syslinux_blob(data, identity.source)
        except (TypeError, ValueError) as error:
            raise SyslinuxStagingError(
                "an Isolinux source member could not be re-identified",
            ) from error
        if observed != identity:
            raise SyslinuxStagingError(
                "the Isolinux identity does not match its exact source bytes",
            )


def _validate_config_bytes(entry: ArchiveEntry, data: bytes) -> str:
    if len(data) != entry.size:
        raise SyslinuxStagingError(
            "the selected Syslinux configuration does not match its catalog size",
        )
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise SyslinuxStagingError(
            "the selected Syslinux configuration must contain only ASCII",
        ) from error
    if any(
        (byte < 0x20 and byte not in {0x09, 0x0A, 0x0D}) or byte == 0x7F
        for byte in data
    ):
        raise SyslinuxStagingError(
            "the selected Syslinux configuration contains unsafe control bytes",
        )

    forbidden = {"ui", "com32", "config", "include"}
    for line in text.splitlines():
        stripped = line.lstrip(" \t")
        if not stripped or stripped.startswith("#"):
            continue
        lowered = stripped.casefold()
        words = lowered.split()
        if (
            words[0] in forbidden
            or words[0] == "menu" and len(words) > 1 and words[1] == "include"
            or ".c32" in lowered
        ):
            raise SyslinuxStagingError(
                "the initial Syslinux profile refuses configuration module dependencies",
            )
    return hashlib.sha256(data).hexdigest()


def _select_config(
    entries: tuple[ArchiveEntry, ...],
    identities: tuple[BootloaderIdentity, ...],
) -> tuple[BootloaderIdentity, ArchiveEntry]:
    root = next(
        (item for item in entries if _case_key(item.path) == ("syslinux.cfg",)),
        None,
    )
    if root is not None:
        _validate_config_entry(root)
        if len(identities) != 1:
            raise SyslinuxStagingError(
                "a root syslinux.cfg requires exactly one Isolinux payload",
            )
        return identities[0], root

    candidates = tuple(
        item for item in entries
        if PurePosixPath(item.path).name.casefold() in _CONFIG_NAMES
    )
    matches: list[tuple[BootloaderIdentity, ArchiveEntry]] = []
    for identity in identities:
        parent = _relative_parent(identity.source)
        local = tuple(
            item for item in candidates if _relative_parent(item.path) == parent
        )
        if len(local) > 1:
            raise SyslinuxStagingError(
                "the Isolinux directory contains multiple configuration candidates",
            )
        if local:
            _validate_config_entry(local[0])
            matches.append((identity, local[0]))
    if len(matches) != 1:
        raise SyslinuxStagingError(
            "exactly one configuration must be associated with an Isolinux payload",
        )
    return matches[0]


def _root_redirect(config_path: str) -> SyslinuxStageFile | None:
    if _case_key(config_path) == ("syslinux.cfg",):
        return None
    parent = _relative_parent(config_path)
    text = (
        "DEFAULT loadconfig\n\n"
        "LABEL loadconfig\n"
        f"  CONFIG /{config_path}\n"
    )
    if parent:
        text += f"  APPEND /{parent}/\n"
    data = text.encode("ascii")
    return SyslinuxStageFile(
        "syslinux.cfg", data, hashlib.sha256(data).hexdigest(),
        StageDisposition.CREATE,
    )


def _existing_bytes(
    existing_files: Mapping[str, bytes] | None,
) -> dict[str, bytes]:
    if existing_files is None:
        return {}
    if not isinstance(existing_files, Mapping):
        raise SyslinuxStagingError("existing file bytes must be an explicit mapping")
    result: dict[str, bytes] = {}
    keys: set[tuple[str, ...]] = set()
    for path, data in existing_files.items():
        if type(path) is not str or type(data) is not bytes or not path:
            raise SyslinuxStagingError("existing file bytes contain an invalid item")
        key = _case_key(path)
        if key in keys:
            raise SyslinuxStagingError("existing file bytes contain a casefold collision")
        keys.add(key)
        result[path] = data
    return result


def _cataloged_c32(
    entries: tuple[ArchiveEntry, ...],
    config_parent: str,
) -> tuple[str, ArchiveEntry | None]:
    # The patched CurrentDirName is added to Syslinux's module search path
    # before ldlinux.c32 is started. Rufus image mode likewise preserves the
    # extracted config-local module rather than adding the blank-media root one.
    target = (
        f"{config_parent}/ldlinux.c32" if config_parent else "ldlinux.c32"
    )
    c32_entries = tuple(
        item for item in entries
        if PurePosixPath(item.path).name.casefold().endswith(".c32")
    )
    unexpected = tuple(item for item in c32_entries if item.path != target)
    if unexpected:
        raise SyslinuxStagingError(
            "the initial Syslinux profile refuses non-pinned or misplaced C32 modules",
        )
    if len(c32_entries) > 1:
        raise SyslinuxStagingError("the ISO catalog contains ambiguous C32 modules")

    existing = c32_entries[0] if c32_entries else None
    if existing is not None and (
        existing.kind is not EntryKind.FILE
        or existing.size <= 0
        or existing.size > MAX_SYSLINUX_C32_BYTES
    ):
        raise SyslinuxStagingError(
            "the existing ldlinux.c32 catalog entry is invalid",
        )
    return target, existing


def syslinux_staging_read_paths(
    entries: Sequence[ArchiveEntry],
    analysis: BootloaderAnalysis,
) -> tuple[str, ...]:
    """Return the exact ISO members whose bytes the pure planner will require."""

    catalog = _validated_catalog(entries)
    entries_by_path = {item.path: item for item in catalog}
    occupied = _occupied_keys(catalog)
    _build, identities = _validated_syslinux_identities(analysis, entries_by_path)
    if ("ldlinux.sys",) in occupied:
        raise SyslinuxStagingError("the ISO already contains a root ldlinux.sys")
    _bootloader, config = _select_config(catalog, identities)
    parent = _relative_parent(config.path)
    _patch_directory(parent)
    _target, existing_c32 = _cataloged_c32(catalog, parent)
    paths = tuple(identity.source for identity in identities) + (config.path,)
    if existing_c32 is not None:
        paths += (existing_c32.path,)
    return tuple(dict.fromkeys(paths))


def _bind_c32_target(
    entries: tuple[ArchiveEntry, ...],
    config_parent: str,
    module: BoundSyslinuxC32,
    existing_files: Mapping[str, bytes] | None,
) -> SyslinuxStageFile:
    target, existing = _cataloged_c32(entries, config_parent)

    supplied = _existing_bytes(existing_files)
    if existing is None:
        if supplied:
            raise SyslinuxStagingError(
                "bytes were supplied for a C32 file absent from the catalog",
            )
        disposition = StageDisposition.CREATE
    else:
        if existing.size != len(module.data):
            raise SyslinuxStagingError(
                "the existing ldlinux.c32 catalog entry is invalid",
            )
        if set(supplied) != {target} or supplied[target] != module.data:
            raise SyslinuxStagingError("the existing ldlinux.c32 does not match its exact pin")
        disposition = StageDisposition.REUSE
    return SyslinuxStageFile(target, module.data, module.sha256, disposition)


def _build_plan(
    entries: Sequence[ArchiveEntry],
    analysis: BootloaderAnalysis,
    module_bundle: BoundBootBundle,
    source_files: Mapping[str, bytes] | None,
    existing_files: Mapping[str, bytes] | None,
) -> SyslinuxStagingPlan:
    catalog = _validated_catalog(entries)
    entries_by_path = {item.path: item for item in catalog}
    occupied = _occupied_keys(catalog)
    build, identities = _validated_syslinux_identities(analysis, entries_by_path)
    module = bind_syslinux_c32_bundle(module_bundle)
    if module.version != build:
        raise SyslinuxStagingError("the C32 bundle does not match the image's Isolinux build")

    if ("ldlinux.sys",) in occupied:
        raise SyslinuxStagingError("the ISO already contains a root ldlinux.sys")

    bootloader, config = _select_config(catalog, identities)
    parent = _relative_parent(config.path)
    directory = _patch_directory(parent)
    expected_source_paths = tuple(dict.fromkeys(
        tuple(item.source for item in identities) + (config.path,),
    ))
    supplied_sources = _source_bytes(source_files, expected_source_paths)
    _validate_identity_source_bytes(identities, entries_by_path, supplied_sources)
    config_sha256 = _validate_config_bytes(config, supplied_sources[config.path])
    redirect = _root_redirect(config.path)
    c32 = _bind_c32_target(catalog, parent, module, existing_files)
    additions = tuple(item for item in (redirect, c32) if item is not None)
    if any(
        item.disposition is StageDisposition.CREATE
        and _case_key(item.path) in occupied
        for item in additions
    ):
        raise SyslinuxStagingError(
            "a planned Syslinux file collides with the existing FAT namespace",
        )
    return SyslinuxStagingPlan(
        version=build,
        dependency_key=f"syslinux:{build}",
        bootloader_path=bootloader.source,
        config_path=config.path,
        config_directory=directory,
        root_redirect=redirect,
        ldlinux_c32=c32,
        source_catalog_sha256=_catalog_digest(catalog),
        analysis_sha256=_analysis_digest(identities),
        source_members_sha256=_source_members_digest(identities, supplied_sources),
        config_sha256=config_sha256,
        _witness=_PLAN_WITNESS,
    )


def plan_syslinux_staging(
    entries: Sequence[ArchiveEntry],
    analysis: BootloaderAnalysis,
    module_bundle: BoundBootBundle,
    *,
    source_files: Mapping[str, bytes] | None = None,
    existing_files: Mapping[str, bytes] | None = None,
) -> SyslinuxStagingPlan:
    """Return an immutable, non-writing Syslinux staging policy decision."""

    return _build_plan(
        entries, analysis, module_bundle, source_files, existing_files,
    )


def validate_syslinux_staging_plan(
    plan: SyslinuxStagingPlan,
    entries: Sequence[ArchiveEntry],
    analysis: BootloaderAnalysis,
    module_bundle: BoundBootBundle,
    *,
    source_files: Mapping[str, bytes] | None = None,
    existing_files: Mapping[str, bytes] | None = None,
) -> None:
    """Rebuild every input-derived field and reject a forged or stale plan."""

    if type(plan) is not SyslinuxStagingPlan or plan._witness is not _PLAN_WITNESS:
        raise SyslinuxStagingError("an authentic Syslinux staging plan is required")
    scalar_fields = (
        plan.version,
        plan.dependency_key,
        plan.bootloader_path,
        plan.config_path,
        plan.config_directory,
        plan.source_catalog_sha256,
        plan.analysis_sha256,
        plan.source_members_sha256,
        plan.config_sha256,
    )
    stage_files = tuple(
        item for item in (plan.root_redirect, plan.ldlinux_c32) if item is not None
    )
    if (
        any(type(value) is not str for value in scalar_fields)
        or plan.root_redirect is not None
        and type(plan.root_redirect) is not SyslinuxStageFile
        or type(plan.ldlinux_c32) is not SyslinuxStageFile
        or any(
            type(item.path) is not str
            or type(item.data) is not bytes
            or type(item.sha256) is not str
            or type(item.disposition) is not StageDisposition
            or _SHA256.fullmatch(item.sha256) is None
            or hashlib.sha256(item.data).hexdigest() != item.sha256
            for item in stage_files
        )
    ):
        raise SyslinuxStagingError("the Syslinux staging plan fields are invalid")
    if any(
        _SHA256.fullmatch(value) is None
        for value in (
            plan.source_catalog_sha256,
            plan.analysis_sha256,
            plan.source_members_sha256,
            plan.config_sha256,
        )
    ):
        raise SyslinuxStagingError("the Syslinux staging plan digests are invalid")
    rebuilt = _build_plan(
        entries, analysis, module_bundle, source_files, existing_files,
    )
    if plan != rebuilt:
        raise SyslinuxStagingError("the Syslinux staging plan is forged or stale")
