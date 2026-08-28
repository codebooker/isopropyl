# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Bounded, read-only access to offline Windows registry hives.

``hivex`` accepts only a pathname.  To keep parsing bound to the file that was
actually inspected, this module copies an opened regular file into a sealed
anonymous memfd and gives hivex its ``/proc/self/fd`` path.  The source identity
and complete digest are checked again after the caller has extracted detached
evidence from the hive.

This module deliberately exposes no hive-writing operation.  A successful
inspection establishes only that the returned evidence came from the immutable
snapshot described by the receipt; it does not establish BCD semantics or
authorize changes to an offline Windows installation.
"""

import fcntl
import hashlib
import importlib
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, TypeVar


MAX_HIVE_BYTES = 256 * 1024 * 1024
MAX_REGISTRY_VALUE_BYTES = 1024 * 1024
COPY_BYTES = 1024 * 1024

REG_SZ = 1
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7

_MFD_CLOEXEC = getattr(os, "MFD_CLOEXEC", 0x0001)
_MFD_ALLOW_SEALING = getattr(os, "MFD_ALLOW_SEALING", 0x0002)
_F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
_F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
_F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
_F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
_F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
_F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
_REQUIRED_SEALS = _F_SEAL_SEAL | _F_SEAL_SHRINK | _F_SEAL_GROW | _F_SEAL_WRITE


class WindowsHiveError(RuntimeError):
    """A hive could not be inspected without weakening the safety boundary."""


class WindowsHiveUnavailable(WindowsHiveError):
    """The optional hivex backend or required Linux primitives are unavailable."""


class WindowsHiveChanged(WindowsHiveError):
    """The source hive changed while it was being inspected."""


class WindowsHiveFormatError(WindowsHiveError):
    """A raw registry value is malformed or unsupported."""


@dataclass(frozen=True)
class HiveSourceIdentity:
    device: int
    inode: int
    size: int
    mode: int
    owner: int
    group: int
    links: int
    modified_ns: int
    changed_ns: int


Evidence = TypeVar("Evidence")


@dataclass(frozen=True)
class HiveInspectionReceipt:
    identity: HiveSourceIdentity
    sha256: str


RegistryValue = str | tuple[str, ...] | int | bytes


@dataclass(frozen=True)
class DecodedRegistryValue:
    registry_type: int
    value: RegistryValue


class HivexHandle(Protocol):
    """The read-only hivex surface used by BCD and SYSTEM-hive inspectors."""

    def root(self) -> int: ...

    def node_name(self, node: int) -> str: ...

    def node_children(self, node: int) -> list[int]: ...

    def node_get_child(self, node: int, name: str) -> int: ...

    def node_values(self, node: int) -> list[int]: ...

    def node_get_value(self, node: int, key: str) -> int: ...

    def value_key(self, value: int) -> str: ...

    def value_type(self, value: int) -> tuple[int, int]: ...

    def value_value(self, value: int) -> tuple[int, bytes]: ...


HiveInspector = Callable[[HivexHandle], Evidence]


def _identity(status: os.stat_result) -> HiveSourceIdentity:
    return HiveSourceIdentity(
        device=status.st_dev,
        inode=status.st_ino,
        size=status.st_size,
        mode=status.st_mode,
        owner=status.st_uid,
        group=status.st_gid,
        links=status.st_nlink,
        modified_ns=status.st_mtime_ns,
        changed_ns=status.st_ctime_ns,
    )


def _read_exact_at(descriptor: int, offset: int, size: int) -> bytes:
    payload = bytearray()
    while len(payload) < size:
        try:
            block = os.pread(
                descriptor,
                min(COPY_BYTES, size - len(payload)),
                offset + len(payload),
            )
        except OSError as error:
            raise WindowsHiveError("The hive source could not be read") from error
        if not block:
            raise WindowsHiveChanged("The hive source ended during inspection")
        payload.extend(block)
    return bytes(payload)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except OSError as error:
            raise WindowsHiveError("The immutable hive snapshot could not be written") from error
        if written <= 0:
            raise WindowsHiveError("The immutable hive snapshot ended unexpectedly")
        offset += written


def _copy_and_hash(source: int, destination: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        block = _read_exact_at(source, offset, min(COPY_BYTES, size - offset))
        digest.update(block)
        _write_all(destination, block)
        offset += len(block)
    try:
        trailing = os.pread(source, 1, size)
    except OSError as error:
        raise WindowsHiveError("The hive source could not be read") from error
    if trailing:
        raise WindowsHiveChanged("The hive source grew during inspection")
    return digest.hexdigest()


def _hash_source(source: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        block = _read_exact_at(source, offset, min(COPY_BYTES, size - offset))
        digest.update(block)
        offset += len(block)
    try:
        trailing = os.pread(source, 1, size)
    except OSError as error:
        raise WindowsHiveError("The hive source could not be read") from error
    if trailing:
        raise WindowsHiveChanged("The hive source grew during inspection")
    return digest.hexdigest()


def _require_source_identity(source: int, expected: HiveSourceIdentity) -> None:
    try:
        current = _identity(os.fstat(source))
    except OSError as error:
        raise WindowsHiveError("The hive source descriptor became unavailable") from error
    if current != expected:
        raise WindowsHiveChanged("The hive source identity changed during inspection")


def _load_hivex() -> object:
    try:
        module = importlib.import_module("hivex")
    except (ImportError, OSError) as error:
        raise WindowsHiveUnavailable(
            "Read-only Windows hive inspection requires the optional python3-hivex package",
        ) from error
    if not callable(getattr(module, "Hivex", None)):
        raise WindowsHiveUnavailable("The installed hivex module has no Hivex reader")
    return module


def _create_snapshot() -> int:
    creator = getattr(os, "memfd_create", None)
    if not callable(creator):
        raise WindowsHiveUnavailable("Sealed Linux memfd support is required for hive inspection")
    try:
        return creator("isopropyl-windows-hive", _MFD_CLOEXEC | _MFD_ALLOW_SEALING)
    except OSError as error:
        raise WindowsHiveUnavailable(
            "A sealed anonymous hive snapshot could not be created",
        ) from error


def _seal_snapshot(snapshot: int) -> None:
    try:
        os.fchmod(snapshot, stat.S_IRUSR)
        fcntl.fcntl(snapshot, _F_ADD_SEALS, _REQUIRED_SEALS)
        actual = fcntl.fcntl(snapshot, _F_GET_SEALS)
    except OSError as error:
        raise WindowsHiveUnavailable("The anonymous hive snapshot could not be sealed") from error
    if actual & _REQUIRED_SEALS != _REQUIRED_SEALS:
        raise WindowsHiveUnavailable("The anonymous hive snapshot is not immutable")


def _inspect_open_source(
    source: int,
    inspector: HiveInspector[Evidence],
) -> tuple[HiveInspectionReceipt, Evidence]:
    snapshot = -1
    handle: object | None = None
    try:
        try:
            status = os.fstat(source)
        except OSError as error:
            raise WindowsHiveError("The hive source could not be identified") from error
        if not stat.S_ISREG(status.st_mode):
            raise WindowsHiveError("The hive source must be a regular file")
        if status.st_nlink < 1:
            raise WindowsHiveError("The hive source has no stable filesystem link")
        if status.st_size < 1:
            raise WindowsHiveError("The hive source is empty")
        if status.st_size > MAX_HIVE_BYTES:
            raise WindowsHiveError(
                f"The hive source exceeds the {MAX_HIVE_BYTES}-byte inspection limit",
            )
        expected = _identity(status)
        hivex = _load_hivex()

        snapshot = _create_snapshot()
        source_sha256 = _copy_and_hash(source, snapshot, expected.size)
        _require_source_identity(source, expected)
        _seal_snapshot(snapshot)
        snapshot_sha256 = _hash_source(snapshot, expected.size)
        if snapshot_sha256 != source_sha256:
            raise WindowsHiveChanged(
                "The sealed hive snapshot does not match the inspected source",
            )
        try:
            os.lseek(snapshot, 0, os.SEEK_SET)
        except OSError as error:
            raise WindowsHiveError("The immutable hive snapshot could not be rewound") from error

        constructor = getattr(hivex, "Hivex")
        try:
            handle = constructor(
                f"/proc/self/fd/{snapshot}",
                write=False,
                unsafe=False,
            )
        except Exception as error:
            raise WindowsHiveFormatError("hivex rejected the immutable hive snapshot") from error

        evidence = inspector(handle)  # type: ignore[arg-type]

        # Complete verification is intentionally delayed until all evidence has
        # been extracted, so a concurrent replacement or rewrite fails closed.
        _require_source_identity(source, expected)
        final_sha256 = _hash_source(source, expected.size)
        _require_source_identity(source, expected)
        if final_sha256 != source_sha256:
            raise WindowsHiveChanged("The hive source contents changed during inspection")
        return HiveInspectionReceipt(expected, source_sha256), evidence
    finally:
        try:
            if handle is not None:
                closer = getattr(handle, "close", None)
                if callable(closer):
                    closer()
                handle = None
        finally:
            try:
                if snapshot >= 0:
                    os.close(snapshot)
            finally:
                os.close(source)


def inspect_windows_hive(
    path: str | os.PathLike[str],
    inspector: HiveInspector[Evidence],
) -> tuple[HiveInspectionReceipt, Evidence]:
    """Safely open a path and inspect an immutable snapshot of that file.

    The callback must not retain the supplied handle.  Its result is returned
    only after a complete post-inspection identity and SHA-256 check of the
    already-open source descriptor succeeds.
    """

    if not callable(inspector):
        raise TypeError("The hive inspector must be callable")
    try:
        source_path = os.fspath(path)
    except TypeError as error:
        raise TypeError("The hive path must be path-like") from error
    if not isinstance(source_path, str):
        raise TypeError("The hive path must be a text path")

    open_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    open_flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        source = os.open(source_path, open_flags)
    except OSError as error:
        raise WindowsHiveError("The hive source could not be opened safely") from error
    return _inspect_open_source(source, inspector)


def inspect_windows_hive_descriptor(
    descriptor: int,
    inspector: HiveInspector[Evidence],
) -> tuple[HiveInspectionReceipt, Evidence]:
    """Inspect a duplicate of a caller-owned, readable file descriptor.

    The descriptor is never closed, reopened through ``/proc``, or seeked.  An
    ``O_PATH`` or writable descriptor is rejected: callers must have acquired
    the exact regular file for reading under their own no-follow policy.
    """

    if not callable(inspector):
        raise TypeError("The hive inspector must be callable")
    if type(descriptor) is not int or descriptor < 0:
        raise WindowsHiveError("The hive source descriptor is invalid")
    source = -1
    try:
        source = os.dup(descriptor)
        os.set_inheritable(source, False)
    except OSError as error:
        if source >= 0:
            os.close(source)
        raise WindowsHiveError("The hive source descriptor could not be duplicated") from error
    try:
        flags = fcntl.fcntl(source, fcntl.F_GETFL)
    except OSError as error:
        os.close(source)
        raise WindowsHiveError("The duplicated hive source is unavailable") from error
    if flags & os.O_ACCMODE != os.O_RDONLY:
        os.close(source)
        raise WindowsHiveError("The hive source descriptor must be read-only")
    path_flag = getattr(os, "O_PATH", 0)
    if path_flag and flags & path_flag:
        os.close(source)
        raise WindowsHiveError("An O_PATH descriptor cannot supply hive bytes")
    return _inspect_open_source(source, inspector)


def _raw_payload(payload: object) -> bytes:
    if type(payload) is not bytes:
        raise WindowsHiveFormatError("A registry value payload must be raw bytes")
    if len(payload) > MAX_REGISTRY_VALUE_BYTES:
        raise WindowsHiveFormatError(
            f"A registry value exceeds the {MAX_REGISTRY_VALUE_BYTES}-byte limit",
        )
    return payload


def decode_reg_sz(payload: bytes) -> str:
    raw = _raw_payload(payload)
    if len(raw) < 2 or len(raw) % 2 or not raw.endswith(b"\0\0"):
        raise WindowsHiveFormatError("REG_SZ is not a terminated UTF-16LE string")
    try:
        value = raw[:-2].decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as error:
        raise WindowsHiveFormatError("REG_SZ contains invalid UTF-16LE") from error
    if "\0" in value:
        raise WindowsHiveFormatError("REG_SZ contains an embedded NUL")
    return value


def decode_reg_multi_sz(payload: bytes) -> tuple[str, ...]:
    raw = _raw_payload(payload)
    if len(raw) < 4 or len(raw) % 2:
        raise WindowsHiveFormatError("REG_MULTI_SZ is not double-NUL-terminated UTF-16LE")
    try:
        value = raw.decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as error:
        raise WindowsHiveFormatError("REG_MULTI_SZ contains invalid UTF-16LE") from error
    if not value.endswith("\0\0") or value.endswith("\0\0\0"):
        raise WindowsHiveFormatError("REG_MULTI_SZ has a non-canonical terminator")
    body = value[:-2]
    if not body:
        return ()
    members = tuple(body.split("\0"))
    if any(not member for member in members):
        raise WindowsHiveFormatError("REG_MULTI_SZ contains an empty member")
    return members


def decode_reg_dword(payload: bytes) -> int:
    raw = _raw_payload(payload)
    if len(raw) != 4:
        raise WindowsHiveFormatError("REG_DWORD must contain exactly four bytes")
    return int.from_bytes(raw, byteorder="little", signed=False)


def decode_reg_binary(payload: bytes) -> bytes:
    return _raw_payload(payload)


def decode_registry_value(registry_type: int, payload: bytes) -> DecodedRegistryValue:
    if type(registry_type) is not int or registry_type < 0:
        raise WindowsHiveFormatError("The registry value type must be an unsigned integer")
    decoders: dict[int, Callable[[bytes], RegistryValue]] = {
        REG_SZ: decode_reg_sz,
        REG_BINARY: decode_reg_binary,
        REG_DWORD: decode_reg_dword,
        REG_MULTI_SZ: decode_reg_multi_sz,
    }
    decoder = decoders.get(registry_type)
    if decoder is None:
        raise WindowsHiveFormatError(f"Registry type {registry_type} is unsupported")
    return DecodedRegistryValue(registry_type, decoder(payload))


def read_hivex_value(handle: HivexHandle, value: int) -> DecodedRegistryValue:
    if type(value) is not int or value <= 0:
        raise WindowsHiveFormatError("The hivex value handle must be a positive integer")
    try:
        result = handle.value_value(value)
    except Exception as error:
        raise WindowsHiveFormatError("hivex could not read a registry value") from error
    if type(result) is not tuple or len(result) != 2:
        raise WindowsHiveFormatError("hivex returned a malformed registry value")
    registry_type, payload = result
    return decode_registry_value(registry_type, payload)
