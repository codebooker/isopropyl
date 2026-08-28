from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Verified preparation and private staging for blank UEFI Shell media.

This module never chooses or writes a block device.  Network consent belongs to
the caller, and the completed private tree must still pass the constructed-media
planner and the application's destructive-action confirmation before use.
"""

import hashlib
import hmac
import os
import stat
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .bootloaders import (
    BootloaderCatalog,
    BoundBootBundle,
    DownloadProgress,
    OpenUrl,
    prepare_bundle,
)
from .uefi import PeFormatError, SignatureTableState, inspect_pe_bytes


UEFI_SHELL_FAMILY = "uefi-shell"
UEFI_SHELL_VERSION = "26H1"
UEFI_SHELL_PURPOSE = "blank-uefi-shell"
UEFI_SHELL_LICENSE = "BSD-2-Clause-Patent"
UEFI_SHELL_PROVENANCE_URL = (
    "https://github.com/pbatard/UEFI-Shell/releases/tag/26H1"
)
_READ_CHUNK = 1024 * 1024
_DIR_FLAGS = (
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = (
    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
)
_WRITE_FLAGS = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
)


class UefiShellError(RuntimeError):
    """The cataloged UEFI Shell bundle is not the reviewed release set."""


class UefiShellSafetyError(UefiShellError):
    """Private UEFI Shell staging encountered an unsafe filesystem object."""


class UefiShellCancelled(UefiShellError):
    """Private UEFI Shell staging was cancelled before completion."""


@dataclass(frozen=True)
class UefiShellArtifactProfile:
    source_name: str
    fallback_path: str
    architecture: str
    size: int
    sha256: str


UEFI_SHELL_ARTIFACTS = (
    UefiShellArtifactProfile(
        "shellaa64.efi", "EFI/BOOT/BOOTAA64.EFI", "ARM64", 1_093_632,
        "1569b6db4e391c3c59194aa3319a3945efb800fb25349eb9d36ff3d258517ea6",
    ),
    UefiShellArtifactProfile(
        "shellia32.efi", "EFI/BOOT/BOOTIA32.EFI", "x86", 1_009_408,
        "54ae3a8f58b6fe7123fd948d0773c88e8c26834e39acd3874732c96cbe7c0dd5",
    ),
    UefiShellArtifactProfile(
        "shellloongarch64.efi", "EFI/BOOT/BOOTLOONGARCH64.EFI", "LoongArch64",
        1_230_272,
        "d6c97ae52707ebbad4eda063cb0aefc467ec942b07461a6d6d1119cad0ac3e9c",
    ),
    UefiShellArtifactProfile(
        "shellriscv64.efi", "EFI/BOOT/BOOTRISCV64.EFI", "RISC-V64", 1_522_752,
        "ccdb9523276d470277f7676d6534916534cd70218ea5c4cc5ac302e149f65196",
    ),
    UefiShellArtifactProfile(
        "shellx64.efi", "EFI/BOOT/BOOTX64.EFI", "x64", 1_137_728,
        "4ea080ddd576117cd04f5c02d16712ea5d9249c0752214d8e4055e460d7b11e0",
    ),
)

_NOTICE_BYTES = (
    "ISOpropyl UEFI Shell media\n"
    f"Release: {UEFI_SHELL_VERSION}\n"
    f"License: {UEFI_SHELL_LICENSE}\n"
    f"Source: {UEFI_SHELL_PROVENANCE_URL}\n"
    "\n"
    "These upstream UEFI Shell executables are not Secure Boot signed.\n"
    "Disable Secure Boot before booting this media.\n"
).encode("ascii")


@dataclass(frozen=True)
class UefiShellPayload:
    source_name: str
    fallback_path: str
    architecture: str
    data: bytes
    sha256: str

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass(frozen=True)
class PreparedUefiShell:
    version: str
    payloads: tuple[UefiShellPayload, ...]
    license: str
    provenance_url: str

    @property
    def total_size(self) -> int:
        return sum(payload.size for payload in self.payloads)


FileIdentity = tuple[int, int, int, int, int]


@dataclass(frozen=True)
class StagedUefiShellFile:
    path: str
    size: int
    sha256: str
    identity: FileIdentity


@dataclass(frozen=True)
class UefiShellStage:
    root: Path
    root_identity: tuple[int, int]
    version: str
    architectures: tuple[str, ...]
    files: tuple[StagedUefiShellFile, ...]
    license: str
    provenance_url: str


def _file_identity(info: os.stat_result) -> FileIdentity:
    return (
        info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _validate_bound_bundle(bundle: BoundBootBundle) -> PreparedUefiShell:
    if not isinstance(bundle, BoundBootBundle):
        raise UefiShellError("The prepared UEFI Shell bundle has an invalid type")
    if (
        bundle.family != UEFI_SHELL_FAMILY
        or bundle.version != UEFI_SHELL_VERSION
        or bundle.purpose != UEFI_SHELL_PURPOSE
        or bundle.license != UEFI_SHELL_LICENSE
        or bundle.provenance_url != UEFI_SHELL_PROVENANCE_URL
    ):
        raise UefiShellError("The prepared UEFI Shell bundle metadata is not exact")
    expected_names = tuple(profile.source_name for profile in UEFI_SHELL_ARTIFACTS)
    if tuple(artifact.name for artifact in bundle.artifacts) != expected_names:
        raise UefiShellError("The prepared UEFI Shell artifact set is not exact")

    payloads: list[UefiShellPayload] = []
    for artifact, profile in zip(bundle.artifacts, UEFI_SHELL_ARTIFACTS, strict=True):
        if not isinstance(artifact.data, bytes):
            raise UefiShellError("UEFI Shell payload bytes must be immutable")
        digest = hashlib.sha256(artifact.data).hexdigest()
        if (
            artifact.sha256 != profile.sha256
            or len(artifact.data) != profile.size
            or not hmac.compare_digest(digest, profile.sha256)
        ):
            raise UefiShellError(
                f"UEFI Shell payload {artifact.name!r} failed exact release verification"
            )
        try:
            inspection = inspect_pe_bytes(artifact.data)
        except PeFormatError as error:
            raise UefiShellError(
                f"UEFI Shell payload {artifact.name!r} is not valid PE/COFF: {error}"
            ) from error
        if (
            not inspection.is_uefi_image
            or inspection.subsystem_name != "EFI application"
            or inspection.architecture != profile.architecture
        ):
            raise UefiShellError(
                f"UEFI Shell payload {artifact.name!r} has the wrong architecture or subsystem"
            )
        if inspection.certificate_table.state is not SignatureTableState.ABSENT:
            raise UefiShellError(
                f"UEFI Shell payload {artifact.name!r} changed signing state"
            )
        payloads.append(UefiShellPayload(
            artifact.name, profile.fallback_path, profile.architecture,
            artifact.data, profile.sha256,
        ))
    return PreparedUefiShell(
        UEFI_SHELL_VERSION, tuple(payloads), UEFI_SHELL_LICENSE,
        UEFI_SHELL_PROVENANCE_URL,
    )


def validate_uefi_shell_bundle(bundle: BoundBootBundle) -> PreparedUefiShell:
    """Validate a frozen bundle against the independently pinned release profile."""

    return _validate_bound_bundle(bundle)


def prepare_uefi_shell(
    *,
    catalog: BootloaderCatalog | None = None,
    cache_dir: Path | None = None,
    opener: OpenUrl | None = None,
    cancel_event: threading.Event | None = None,
    progress: DownloadProgress | None = None,
    overall_timeout: float = 180.0,
) -> PreparedUefiShell:
    """Acquire and freeze release 26H1 after the caller obtains network consent."""

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
        UEFI_SHELL_FAMILY, UEFI_SHELL_VERSION, UEFI_SHELL_PURPOSE,
        **arguments,  # type: ignore[arg-type]
    )
    return _validate_bound_bundle(bundle)


def _validate_prepared(prepared: PreparedUefiShell) -> None:
    if (
        not isinstance(prepared, PreparedUefiShell)
        or prepared.version != UEFI_SHELL_VERSION
        or prepared.license != UEFI_SHELL_LICENSE
        or prepared.provenance_url != UEFI_SHELL_PROVENANCE_URL
    ):
        raise UefiShellError("The prepared UEFI Shell object has invalid metadata")
    expected = UEFI_SHELL_ARTIFACTS
    if len(prepared.payloads) != len(expected):
        raise UefiShellError("The prepared UEFI Shell object is incomplete")
    for payload, profile in zip(prepared.payloads, expected, strict=True):
        if (
            not isinstance(payload, UefiShellPayload)
            or payload.source_name != profile.source_name
            or payload.fallback_path != profile.fallback_path
            or payload.architecture != profile.architecture
            or not isinstance(payload.data, bytes)
            or payload.size != profile.size
            or payload.sha256 != profile.sha256
            or not hmac.compare_digest(hashlib.sha256(payload.data).hexdigest(), profile.sha256)
        ):
            raise UefiShellError("The prepared UEFI Shell object changed after validation")


def _selected_payloads(
    prepared: PreparedUefiShell,
    architectures: Iterable[str] | None,
) -> tuple[UefiShellPayload, ...]:
    if architectures is None:
        return prepared.payloads
    try:
        requested = tuple(architectures)
    except TypeError as error:
        raise ValueError("UEFI Shell architectures must be an iterable of names") from error
    if not requested or any(not isinstance(item, str) or not item for item in requested):
        raise ValueError("Select at least one valid UEFI Shell architecture")
    folded = tuple(item.casefold() for item in requested)
    if len(folded) != len(set(folded)):
        raise ValueError("UEFI Shell architectures must not contain duplicates")
    known = {payload.architecture.casefold() for payload in prepared.payloads}
    unknown = next((item for item in folded if item not in known), None)
    if unknown is not None:
        raise ValueError(f"Unsupported UEFI Shell architecture: {unknown}")
    return tuple(
        payload for payload in prepared.payloads
        if payload.architecture.casefold() in set(folded)
    )


def _open_absolute_directory(path: Path) -> int:
    if (
        not path.is_absolute()
        or path != Path(os.path.normpath(path))
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise UefiShellSafetyError("The staging path must be canonical and absolute")
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


def _mkdir_open(parent: int, name: str) -> int:
    os.mkdir(name, 0o700, dir_fd=parent)
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    child = os.open(name, _DIR_FLAGS, dir_fd=parent)
    after = os.fstat(child)
    if (
        not stat.S_ISDIR(before.st_mode)
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    ):
        os.close(child)
        raise UefiShellSafetyError("A staging directory changed while it was opened")
    return child


def _revalidate_directory_path(path: Path, descriptor: int) -> None:
    current = -1
    try:
        current = _open_absolute_directory(path)
        opened = os.fstat(descriptor)
        named = os.fstat(current)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise UefiShellSafetyError("The UEFI Shell staging parent path changed")
    finally:
        if current >= 0:
            os.close(current)


def _check_cancel(cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise UefiShellCancelled("UEFI Shell staging was cancelled")


def _write_file(
    parent: int,
    name: str,
    data: bytes,
    *,
    cancel_event: threading.Event | None,
) -> None:
    descriptor = os.open(name, _WRITE_FLAGS, 0o600, dir_fd=parent)
    try:
        offset = 0
        while offset < len(data):
            _check_cancel(cancel_event)
            block = memoryview(data)[offset:offset + _READ_CHUNK]
            while block:
                written = os.write(descriptor, block)
                if written <= 0:
                    raise OSError("staging write made no progress")
                offset += written
                block = block[written:]
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_exact_file(
    parent: int,
    name: str,
    *,
    size: int,
    sha256: str,
) -> FileIdentity:
    observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
    descriptor = os.open(name, _READ_FLAGS, dir_fd=parent)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _file_identity(observed) != _file_identity(opened)
            or opened.st_size != size
        ):
            raise UefiShellSafetyError("A staged UEFI Shell file is unsafe or changed")
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            block = os.read(descriptor, min(_READ_CHUNK, remaining))
            if not block:
                raise UefiShellSafetyError("A staged UEFI Shell file ended early")
            digest.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise UefiShellSafetyError("A staged UEFI Shell file grew during verification")
        final = os.fstat(descriptor)
        if (
            _file_identity(opened) != _file_identity(final)
            or not hmac.compare_digest(digest.hexdigest(), sha256)
        ):
            raise UefiShellSafetyError("A staged UEFI Shell file failed verification")
        return _file_identity(final)
    finally:
        os.close(descriptor)


def _expected_stage_files(
    architectures: tuple[str, ...],
) -> tuple[tuple[str, int, str], ...]:
    selected = {
        profile.architecture for profile in UEFI_SHELL_ARTIFACTS
        if profile.architecture in architectures
    }
    payloads = tuple(
        (profile.fallback_path, profile.size, profile.sha256)
        for profile in UEFI_SHELL_ARTIFACTS
        if profile.architecture in selected
    )
    return (
        ("README.txt", len(_NOTICE_BYTES), hashlib.sha256(_NOTICE_BYTES).hexdigest()),
        *payloads,
    )


def _list_directory(directory_fd: int) -> list[str]:
    """List through a fresh open file description, not a stale directory cursor."""

    scan_fd = os.open(".", _DIR_FLAGS, dir_fd=directory_fd)
    try:
        return os.listdir(scan_fd)
    finally:
        os.close(scan_fd)


def _inspect_stage_tree(
    root_fd: int,
    architectures: tuple[str, ...],
) -> tuple[StagedUefiShellFile, ...]:
    expected = _expected_stage_files(architectures)
    if set(_list_directory(root_fd)) != {"EFI", "README.txt"}:
        raise UefiShellSafetyError("The UEFI Shell staging root has unexpected entries")
    efi_fd = os.open("EFI", _DIR_FLAGS, dir_fd=root_fd)
    try:
        if set(_list_directory(efi_fd)) != {"BOOT"}:
            raise UefiShellSafetyError("The staged EFI directory has unexpected entries")
        boot_fd = os.open("BOOT", _DIR_FLAGS, dir_fd=efi_fd)
        try:
            wanted_boot = {PurePosixPath(path).name for path, _size, _digest in expected[1:]}
            if set(_list_directory(boot_fd)) != wanted_boot:
                raise UefiShellSafetyError("The staged EFI/BOOT directory is not exact")
            files = [StagedUefiShellFile(
                "README.txt", expected[0][1], expected[0][2],
                _read_exact_file(
                    root_fd, "README.txt", size=expected[0][1], sha256=expected[0][2],
                ),
            )]
            for path, size, digest in expected[1:]:
                name = PurePosixPath(path).name
                files.append(StagedUefiShellFile(
                    path, size, digest,
                    _read_exact_file(boot_fd, name, size=size, sha256=digest),
                ))
            return tuple(files)
        finally:
            os.close(boot_fd)
    finally:
        os.close(efi_fd)


def stage_uefi_shell(
    prepared: PreparedUefiShell,
    destination: Path,
    *,
    architectures: Iterable[str] | None = None,
    cancel_event: threading.Event | None = None,
) -> UefiShellStage:
    """Create and verify a new caller-private tree; never overwrite a path.

    A failed or cancelled attempt may leave an incomplete, mode-0700 directory.
    It is never returned as a valid stage and the caller may discard it.
    """

    _validate_prepared(prepared)
    selected = _selected_payloads(prepared, architectures)
    selected_architectures = tuple(payload.architecture for payload in selected)
    if not isinstance(destination, Path):
        raise TypeError("The UEFI Shell staging destination must be a pathlib.Path")
    if destination == Path("/") or not destination.name:
        raise UefiShellSafetyError("The UEFI Shell staging destination is unsafe")

    parent_fd = -1
    root_fd = -1
    efi_fd = -1
    boot_fd = -1
    try:
        parent_fd = _open_absolute_directory(destination.parent)
        _check_cancel(cancel_event)
        root_fd = _mkdir_open(parent_fd, destination.name)
        efi_fd = _mkdir_open(root_fd, "EFI")
        boot_fd = _mkdir_open(efi_fd, "BOOT")
        for payload in selected:
            _write_file(
                boot_fd, PurePosixPath(payload.fallback_path).name, payload.data,
                cancel_event=cancel_event,
            )
        _write_file(root_fd, "README.txt", _NOTICE_BYTES, cancel_event=cancel_event)
        os.fsync(boot_fd)
        os.fsync(efi_fd)
        os.fsync(root_fd)
        _check_cancel(cancel_event)
        files = _inspect_stage_tree(root_fd, selected_architectures)
        root_info = os.fstat(root_fd)
        named = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(named.st_mode)
            or (named.st_dev, named.st_ino) != (root_info.st_dev, root_info.st_ino)
        ):
            raise UefiShellSafetyError("The UEFI Shell staging root changed during creation")
        _revalidate_directory_path(destination.parent, parent_fd)
        return UefiShellStage(
            destination, (root_info.st_dev, root_info.st_ino), UEFI_SHELL_VERSION,
            selected_architectures, files, UEFI_SHELL_LICENSE,
            UEFI_SHELL_PROVENANCE_URL,
        )
    except (UefiShellError, ValueError, TypeError):
        raise
    except (FileExistsError, FileNotFoundError, NotADirectoryError, OSError) as error:
        raise UefiShellSafetyError(f"Could not safely stage UEFI Shell: {error}") from error
    finally:
        for descriptor in (boot_fd, efi_fd, root_fd, parent_fd):
            if descriptor >= 0:
                os.close(descriptor)


def validate_uefi_shell_stage(stage: UefiShellStage) -> UefiShellStage:
    """Reopen and validate an existing stage before handing it to a media planner."""

    if (
        not isinstance(stage, UefiShellStage)
        or stage.version != UEFI_SHELL_VERSION
        or stage.license != UEFI_SHELL_LICENSE
        or stage.provenance_url != UEFI_SHELL_PROVENANCE_URL
        or not stage.architectures
    ):
        raise UefiShellSafetyError("The UEFI Shell staging manifest is invalid")
    known = tuple(profile.architecture for profile in UEFI_SHELL_ARTIFACTS)
    if (
        any(item not in known for item in stage.architectures)
        or tuple(item for item in known if item in stage.architectures) != stage.architectures
    ):
        raise UefiShellSafetyError("The UEFI Shell architecture manifest is not canonical")
    try:
        root_fd = _open_absolute_directory(stage.root)
    except (OSError, UefiShellError) as error:
        raise UefiShellSafetyError(f"Could not reopen UEFI Shell staging: {error}") from error
    try:
        root_info = os.fstat(root_fd)
        if (root_info.st_dev, root_info.st_ino) != stage.root_identity:
            raise UefiShellSafetyError("The UEFI Shell staging root identity changed")
        files = _inspect_stage_tree(root_fd, stage.architectures)
        if files != stage.files:
            raise UefiShellSafetyError("The UEFI Shell staging manifest changed")
        return stage
    except OSError as error:
        raise UefiShellSafetyError(f"Could not validate UEFI Shell staging: {error}") from error
    finally:
        os.close(root_fd)
