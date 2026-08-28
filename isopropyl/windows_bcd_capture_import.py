# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Filesystem importer for non-authorizing Windows BCD capture evidence.

All source artifacts are pinned through one directory descriptor and read in
full before any output is created.  Publication creates a private sibling tree
and atomically renames it without replacement only after the raw claims, four
hives, derived fixtures, copied bytes, and source identities all validate.
"""

import ctypes
import errno
import hashlib
import os
import secrets
import stat
from dataclasses import dataclass
from typing import Mapping

from .windows_bcd import BcdError
from .windows_bcd_capture import (
    RAW_BCD_CAPTURE_MAX_BYTES,
    RAW_BCD_CAPTURE_VARIANTS,
    RAW_COLLECTOR_MAX_BYTES,
    RAW_TEMPLATE_MAX_BYTES,
    VerifiedArtifactReceipt,
    derive_bcd_oracle_fixtures,
    parse_raw_bcd_capture_bytes,
)
from .windows_bcd_hivex import BCD_HIVE_MAX_BYTES, read_bcd_hive_descriptor
from .windows_bcd_oracle import canonical_bcd_oracle_bytes


RAW_CAPTURE_NAME = "capture.raw.json"
COLLECTOR_NAME = "collector.ps1"
TEMPLATE_NAME = "BCD-Template"
HIVE_NAMES = {variant: f"{variant}.BCD" for variant in RAW_BCD_CAPTURE_VARIANTS}
SOURCE_NAMES = (
    RAW_CAPTURE_NAME,
    COLLECTOR_NAME,
    TEMPLATE_NAME,
    *(HIVE_NAMES[variant] for variant in RAW_BCD_CAPTURE_VARIANTS),
)
FIXTURE_NAMES = tuple(f"{variant}.json" for variant in RAW_BCD_CAPTURE_VARIANTS)
OUTPUT_NAMES = SOURCE_NAMES + FIXTURE_NAMES

_RENAME_NOREPLACE = 1
_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW


class BcdCaptureImportError(RuntimeError):
    pass


class BcdCaptureImportCommittedError(BcdCaptureImportError):
    """Publication occurred, but final path identity or durability is uncertain."""


@dataclass(frozen=True)
class ImportedArtifact:
    name: str
    size: int
    sha256: str


@dataclass(frozen=True)
class BcdCaptureImportReceipt:
    destination: str
    source_artifacts: tuple[ImportedArtifact, ...]
    fixture_artifacts: tuple[ImportedArtifact, ...]


@dataclass
class _PinnedSource:
    name: str
    descriptor: int
    initial_status: os.stat_result
    maximum: int
    payload: bytes = b""
    receipt: ImportedArtifact | None = None

    @classmethod
    def open(
        cls,
        directory_descriptor: int,
        name: str,
        maximum: int,
    ) -> _PinnedSource:
        try:
            descriptor = os.open(name, _READ_FLAGS, dir_fd=directory_descriptor)
        except OSError as error:
            raise BcdCaptureImportError(f"cannot safely open source artifact {name}") from error
        try:
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                raise BcdCaptureImportError(
                    f"source artifact {name} must be a singly linked regular file",
                )
            if not 1 <= status.st_size <= maximum:
                raise BcdCaptureImportError(
                    f"source artifact {name} size is outside policy",
                )
            return cls(name, descriptor, status, maximum)
        except BaseException:
            os.close(descriptor)
            raise

    @property
    def identity(self) -> tuple[int, int]:
        return (self.initial_status.st_dev, self.initial_status.st_ino)

    @staticmethod
    def _status_key(status: os.stat_result) -> tuple[int, ...]:
        return (
            status.st_dev,
            status.st_ino,
            status.st_mode,
            status.st_nlink,
            status.st_uid,
            status.st_gid,
            status.st_size,
            status.st_mtime_ns,
            status.st_ctime_ns,
        )

    def _read(self) -> bytes:
        blocks: list[bytes] = []
        offset = 0
        while offset <= self.maximum:
            try:
                block = os.pread(
                    self.descriptor,
                    min(1024 * 1024, self.maximum + 1 - offset),
                    offset,
                )
            except OSError as error:
                raise BcdCaptureImportError(
                    f"cannot read pinned source artifact {self.name}",
                ) from error
            if not block:
                break
            blocks.append(block)
            offset += len(block)
        payload = b"".join(blocks)
        if not 1 <= len(payload) <= self.maximum:
            raise BcdCaptureImportError(
                f"source artifact {self.name} changed or exceeds policy",
            )
        return payload

    def capture(self) -> None:
        payload = self._read()
        self.require_unchanged()
        if len(payload) != self.initial_status.st_size:
            raise BcdCaptureImportError(f"source artifact {self.name} changed while reading")
        self.payload = payload
        self.receipt = ImportedArtifact(
            self.name,
            len(payload),
            hashlib.sha256(payload).hexdigest(),
        )

    def revalidate(self) -> None:
        if self.receipt is None or not self.payload:
            raise BcdCaptureImportError(f"source artifact {self.name} was not captured")
        payload = self._read()
        self.require_unchanged()
        if (
            len(payload) != self.receipt.size
            or hashlib.sha256(payload).hexdigest() != self.receipt.sha256
        ):
            raise BcdCaptureImportError(f"source artifact {self.name} changed during import")

    def require_unchanged(self) -> None:
        try:
            current = os.fstat(self.descriptor)
        except OSError as error:
            raise BcdCaptureImportError(
                f"source artifact {self.name} became unavailable",
            ) from error
        if self._status_key(current) != self._status_key(self.initial_status):
            raise BcdCaptureImportError(f"source artifact {self.name} changed during import")

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def _maximum_for(name: str) -> int:
    if name == RAW_CAPTURE_NAME:
        return RAW_BCD_CAPTURE_MAX_BYTES
    if name == COLLECTOR_NAME:
        return RAW_COLLECTOR_MAX_BYTES
    if name == TEMPLATE_NAME:
        return RAW_TEMPLATE_MAX_BYTES
    if name in HIVE_NAMES.values():
        return BCD_HIVE_MAX_BYTES
    raise BcdCaptureImportError("the source inventory contains an unknown artifact")


def _directory_key(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_uid,
        status.st_gid,
        status.st_nlink,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _directory_identity_key(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_uid,
        status.st_gid,
    )


def _require_directory_unchanged(
    descriptor: int,
    initial: os.stat_result,
    label: str,
) -> None:
    try:
        current = os.fstat(descriptor)
    except OSError as error:
        raise BcdCaptureImportError(f"the {label} directory became unavailable") from error
    if _directory_key(current) != _directory_key(initial):
        raise BcdCaptureImportError(f"the {label} directory changed during import")


def _require_private_parent(status: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.geteuid()
        or stat.S_IMODE(status.st_mode) & 0o022
    ):
        raise BcdCaptureImportError(
            "the destination parent must be owned by this user and not writable "
            "by group or other users",
        )


def _require_parent_path_binding(
    path: str,
    descriptor: int,
    expected: os.stat_result,
) -> None:
    rebound = -1
    try:
        rebound = os.open(path, _DIRECTORY_FLAGS)
        named = os.fstat(rebound)
        opened = os.fstat(descriptor)
    except OSError as error:
        raise BcdCaptureImportError(
            "the destination parent path became unavailable",
        ) from error
    finally:
        if rebound >= 0:
            try:
                os.close(rebound)
            except OSError:
                pass
    if (
        _directory_identity_key(named) != _directory_identity_key(opened)
        or _directory_identity_key(opened) != _directory_identity_key(expected)
    ):
        raise BcdCaptureImportError("the destination parent path identity changed")
    _require_private_parent(opened)


def _require_named_directory_identity(
    parent_descriptor: int,
    name: str,
    directory_descriptor: int,
    expected: os.stat_result,
    label: str,
) -> None:
    try:
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        opened = os.fstat(directory_descriptor)
    except OSError as error:
        raise BcdCaptureImportError(f"the {label} directory became unavailable") from error
    if (
        _directory_identity_key(named) != _directory_identity_key(opened)
        or _directory_identity_key(opened) != _directory_identity_key(expected)
        or stat.S_IMODE(opened.st_mode) != 0o700
        or opened.st_uid != os.geteuid()
    ):
        raise BcdCaptureImportError(f"the {label} directory identity changed")


def _inventory(directory_descriptor: int) -> tuple[str, ...]:
    fresh = -1
    try:
        fresh = os.open(".", _DIRECTORY_FLAGS, dir_fd=directory_descriptor)
        if _directory_identity_key(os.fstat(fresh)) != _directory_identity_key(
            os.fstat(directory_descriptor)
        ):
            raise BcdCaptureImportError("the directory inventory descriptor changed")
        names = os.listdir(fresh)
    except OSError as error:
        raise BcdCaptureImportError("cannot enumerate the source directory") from error
    finally:
        if fresh >= 0:
            try:
                os.close(fresh)
            except OSError:
                pass
    if any(type(name) is not str or name in {"", ".", ".."} for name in names):
        raise BcdCaptureImportError("the source directory inventory is invalid")
    return tuple(sorted(names))


def _path_text(path: str | os.PathLike[str], label: str) -> str:
    try:
        value = os.fspath(path)
    except TypeError as error:
        raise BcdCaptureImportError(f"the {label} path is invalid") from error
    if type(value) is not str or not value or "\0" in value:
        raise BcdCaptureImportError(f"the {label} path is invalid")
    return value


def _destination_parts(path: str) -> tuple[str, str]:
    normalized = os.path.normpath(path)
    name = os.path.basename(normalized)
    parent = os.path.dirname(normalized) or "."
    if name in {"", ".", ".."} or "/" in name:
        raise BcdCaptureImportError("the destination must name a new directory")
    return parent, name


def _destination_absent(parent_descriptor: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise BcdCaptureImportError("cannot inspect the destination name") from error
    raise BcdCaptureImportError("the destination already exists")


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except OSError as error:
            raise BcdCaptureImportError("cannot write the private import tree") from error
        if written <= 0:
            raise BcdCaptureImportError("the private import write made no progress")
        offset += written


def _read_output(descriptor: int, expected_size: int) -> bytes:
    blocks: list[bytes] = []
    offset = 0
    while offset <= expected_size:
        try:
            block = os.pread(
                descriptor,
                min(1024 * 1024, expected_size + 1 - offset),
                offset,
            )
        except OSError as error:
            raise BcdCaptureImportError("cannot verify the private import copy") from error
        if not block:
            break
        blocks.append(block)
        offset += len(block)
    payload = b"".join(blocks)
    if len(payload) != expected_size:
        raise BcdCaptureImportError("the private import copy has an unexpected size")
    return payload


def _create_output_file(
    directory_descriptor: int,
    name: str,
    payload: bytes,
) -> ImportedArtifact:
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_descriptor)
    except OSError as error:
        raise BcdCaptureImportError(f"cannot create private output artifact {name}") from error
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or stat.S_IMODE(status.st_mode) != 0o600
            or status.st_size != len(payload)
        ):
            raise BcdCaptureImportError(f"private output artifact {name} is unsafe")
        copied = _read_output(descriptor, len(payload))
        expected = hashlib.sha256(payload).hexdigest()
        if hashlib.sha256(copied).hexdigest() != expected:
            raise BcdCaptureImportError(f"private output artifact {name} differs from source")
        return ImportedArtifact(name, len(payload), expected)
    finally:
        os.close(descriptor)


def _verify_output_file(
    directory_descriptor: int,
    expected: ImportedArtifact,
) -> None:
    try:
        descriptor = os.open(expected.name, _READ_FLAGS, dir_fd=directory_descriptor)
    except OSError as error:
        raise BcdCaptureImportError(
            f"cannot reopen private output artifact {expected.name}",
        ) from error
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or stat.S_IMODE(status.st_mode) != 0o600
            or status.st_size != expected.size
        ):
            raise BcdCaptureImportError(
                f"private output artifact {expected.name} changed before publication",
            )
        copied = _read_output(descriptor, expected.size)
        if hashlib.sha256(copied).hexdigest() != expected.sha256:
            raise BcdCaptureImportError(
                f"private output artifact {expected.name} changed before publication",
            )
    finally:
        os.close(descriptor)


def _rename_noreplace(
    parent_descriptor: int,
    source_name: str,
    destination_name: str,
) -> None:
    try:
        library = ctypes.CDLL(None, use_errno=True)
        renameat2 = library.renameat2
    except (OSError, AttributeError) as error:
        raise BcdCaptureImportError("atomic no-replace publication is unavailable") from error
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_descriptor,
        os.fsencode(source_name),
        parent_descriptor,
        os.fsencode(destination_name),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise BcdCaptureImportError("the destination appeared before publication")
    if error_number in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
        raise BcdCaptureImportError("atomic no-replace publication is unsupported")
    raise BcdCaptureImportError(
        f"cannot atomically publish the capture: {os.strerror(error_number)}",
    )


def _cleanup_private_tree(
    parent_descriptor: int,
    temporary_name: str,
    temporary_descriptor: int,
    temporary_status: os.stat_result,
    created_names: tuple[str, ...],
) -> None:
    _require_named_directory_identity(
        parent_descriptor,
        temporary_name,
        temporary_descriptor,
        temporary_status,
        "private import",
    )
    errors: list[OSError] = []
    for name in reversed(created_names):
        try:
            os.unlink(name, dir_fd=temporary_descriptor)
        except FileNotFoundError:
            continue
        except OSError as error:
            errors.append(error)
    try:
        os.fsync(temporary_descriptor)
    except OSError as error:
        errors.append(error)
    try:
        os.rmdir(temporary_name, dir_fd=parent_descriptor)
    except FileNotFoundError:
        pass
    except OSError as error:
        errors.append(error)
    try:
        os.fsync(parent_descriptor)
    except OSError as error:
        errors.append(error)
    if errors:
        raise BcdCaptureImportError("the exact private import tree could not be cleaned")


def _receipt(value: _PinnedSource) -> ImportedArtifact:
    if value.receipt is None:
        raise BcdCaptureImportError(f"source artifact {value.name} has no receipt")
    return value.receipt


def import_windows_bcd_capture(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
) -> BcdCaptureImportReceipt:
    """Validate and atomically import one exact seven-artifact capture bundle."""

    source_path = _path_text(source, "source")
    destination_path = _path_text(destination, "destination")
    destination_parent_path, destination_name = _destination_parts(destination_path)

    source_descriptor = -1
    parent_descriptor = -1
    temporary_descriptor = -1
    temporary_name = ""
    temporary_created = False
    temporary_status: os.stat_result | None = None
    committed = False
    pinned: list[_PinnedSource] = []
    created: list[str] = []
    try:
        try:
            source_descriptor = os.open(source_path, _DIRECTORY_FLAGS)
            parent_descriptor = os.open(destination_parent_path, _DIRECTORY_FLAGS)
        except OSError as error:
            raise BcdCaptureImportError(
                "cannot safely open source or destination parent",
            ) from error
        source_status = os.fstat(source_descriptor)
        parent_status = os.fstat(parent_descriptor)
        if not stat.S_ISDIR(source_status.st_mode) or not stat.S_ISDIR(parent_status.st_mode):
            raise BcdCaptureImportError("source and destination parent must be directories")
        _require_private_parent(parent_status)
        if (source_status.st_dev, source_status.st_ino) == (
            parent_status.st_dev,
            parent_status.st_ino,
        ):
            raise BcdCaptureImportError("the destination parent must differ from the source")
        _destination_absent(parent_descriptor, destination_name)
        if _inventory(source_descriptor) != tuple(sorted(SOURCE_NAMES)):
            raise BcdCaptureImportError("the source directory inventory is not exact")

        for name in SOURCE_NAMES:
            item = _PinnedSource.open(source_descriptor, name, _maximum_for(name))
            pinned.append(item)
        identities = [item.identity for item in pinned]
        if len(set(identities)) != len(identities):
            raise BcdCaptureImportError("source artifacts must have distinct identities")
        for item in pinned:
            item.capture()
        by_name: Mapping[str, _PinnedSource] = {item.name: item for item in pinned}

        raw = parse_raw_bcd_capture_bytes(by_name[RAW_CAPTURE_NAME].payload)
        observations = {
            variant: read_bcd_hive_descriptor(by_name[HIVE_NAMES[variant]].descriptor)
            for variant in RAW_BCD_CAPTURE_VARIANTS
        }
        collector = _receipt(by_name[COLLECTOR_NAME])
        template = _receipt(by_name[TEMPLATE_NAME])
        fixtures = derive_bcd_oracle_fixtures(
            raw,
            observations,
            collector_receipt=VerifiedArtifactReceipt(collector.size, collector.sha256),
            template_receipt=VerifiedArtifactReceipt(template.size, template.sha256),
        )
        fixture_payloads = {
            f"{fixture.variant}.json": canonical_bcd_oracle_bytes(fixture)
            for fixture in fixtures
        }
        if tuple(fixture_payloads) != FIXTURE_NAMES:
            raise BcdCaptureImportError("derived fixture order is not canonical")

        for item in pinned:
            item.revalidate()
        _require_directory_unchanged(source_descriptor, source_status, "source")
        if _inventory(source_descriptor) != tuple(sorted(SOURCE_NAMES)):
            raise BcdCaptureImportError("the source inventory changed during validation")
        _require_directory_unchanged(parent_descriptor, parent_status, "destination parent")
        _require_parent_path_binding(
            destination_parent_path,
            parent_descriptor,
            parent_status,
        )
        _destination_absent(parent_descriptor, destination_name)

        temporary_name = (
            f".isopropyl-bcd-import-{os.getpid()}-{secrets.token_hex(12)}"
        )
        try:
            os.mkdir(temporary_name, 0o700, dir_fd=parent_descriptor)
            temporary_created = True
            temporary_descriptor = os.open(
                temporary_name,
                _DIRECTORY_FLAGS,
                dir_fd=parent_descriptor,
            )
        except OSError as error:
            raise BcdCaptureImportError("cannot create the private import directory") from error
        temporary_status = os.fstat(temporary_descriptor)
        if (
            not stat.S_ISDIR(temporary_status.st_mode)
            or stat.S_IMODE(temporary_status.st_mode) != 0o700
        ):
            raise BcdCaptureImportError("the private import directory is unsafe")
        parent_with_temporary_status = os.fstat(parent_descriptor)

        source_outputs: list[ImportedArtifact] = []
        fixture_outputs: list[ImportedArtifact] = []
        for name in SOURCE_NAMES:
            created.append(name)
            source_outputs.append(
                _create_output_file(temporary_descriptor, name, by_name[name].payload),
            )
        for name in FIXTURE_NAMES:
            created.append(name)
            fixture_outputs.append(
                _create_output_file(temporary_descriptor, name, fixture_payloads[name]),
            )
        if _inventory(temporary_descriptor) != tuple(sorted(OUTPUT_NAMES)):
            raise BcdCaptureImportError("the private output inventory is not exact")
        for artifact in (*source_outputs, *fixture_outputs):
            _verify_output_file(temporary_descriptor, artifact)
        for item in pinned:
            item.revalidate()
        _require_directory_unchanged(source_descriptor, source_status, "source")
        if _inventory(source_descriptor) != tuple(sorted(SOURCE_NAMES)):
            raise BcdCaptureImportError("the source inventory changed before publication")
        _require_directory_unchanged(
            parent_descriptor,
            parent_with_temporary_status,
            "destination parent",
        )
        _destination_absent(parent_descriptor, destination_name)
        os.fsync(temporary_descriptor)
        _require_named_directory_identity(
            parent_descriptor,
            temporary_name,
            temporary_descriptor,
            temporary_status,
            "private import",
        )
        if _inventory(temporary_descriptor) != tuple(sorted(OUTPUT_NAMES)):
            raise BcdCaptureImportError("the private output inventory changed before publication")
        for artifact in (*source_outputs, *fixture_outputs):
            _verify_output_file(temporary_descriptor, artifact)
        _rename_noreplace(parent_descriptor, temporary_name, destination_name)
        committed = True
        try:
            _require_named_directory_identity(
                parent_descriptor,
                destination_name,
                temporary_descriptor,
                temporary_status,
                "published import",
            )
            os.fsync(parent_descriptor)
            _require_parent_path_binding(
                destination_parent_path,
                parent_descriptor,
                parent_status,
            )
        except (OSError, BcdCaptureImportError) as error:
            raise BcdCaptureImportCommittedError(
                "the capture was published but final identity or durability is unconfirmed",
            ) from error
        return BcdCaptureImportReceipt(
            destination_path,
            tuple(source_outputs),
            tuple(fixture_outputs),
        )
    except BaseException as original:
        if temporary_descriptor >= 0 and temporary_status is not None and not committed:
            try:
                _cleanup_private_tree(
                    parent_descriptor,
                    temporary_name,
                    temporary_descriptor,
                    temporary_status,
                    tuple(created),
                )
            except BcdCaptureImportError as cleanup_error:
                raise cleanup_error from original
        elif temporary_created and not committed:
            try:
                os.rmdir(temporary_name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
            except OSError as cleanup_error:
                raise BcdCaptureImportError(
                    "the exact private import directory could not be cleaned",
                ) from cleanup_error
        if committed and not isinstance(original, BcdCaptureImportCommittedError):
            raise BcdCaptureImportCommittedError(
                "the capture was published but final validation did not complete",
            ) from original
        if isinstance(original, OSError):
            raise BcdCaptureImportError("the capture import encountered an OS failure") from original
        raise
    finally:
        for item in reversed(pinned):
            try:
                item.close()
            except OSError:
                pass
        if temporary_descriptor >= 0:
            try:
                os.close(temporary_descriptor)
            except OSError:
                pass
        if parent_descriptor >= 0:
            try:
                os.close(parent_descriptor)
            except OSError:
                pass
        if source_descriptor >= 0:
            try:
                os.close(source_descriptor)
            except OSError:
                pass
