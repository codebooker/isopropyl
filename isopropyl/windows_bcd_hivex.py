# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Read-only verification of captured Windows BCD registry hives.

The concrete path and descriptor entry points use ``windows_hive`` to parse a
sealed anonymous snapshot with optional hivex.  The byte-snapshot backend
protocol keeps the BCD schema independently testable.  Successfully reading or
matching a hive records an observation only.  It never authorizes BCD
generation, hive modification, or publication to boot media.
"""

import hashlib
import os
import re
import uuid
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Protocol

from .windows_bcd import BcdError
from .windows_bcd_oracle import (
    BCD_ORACLE_MAX_ELEMENTS,
    BCD_ORACLE_MAX_OBJECTS,
    BCD_ORACLE_MAX_RAW_ELEMENT_BYTES,
    BCD_REG_BINARY,
    BCD_REG_DWORD,
    BCD_REG_MULTI_SZ,
    BCD_REG_SZ,
    BcdOracleElement,
    BcdOracleFixture,
    BcdOracleObject,
    validate_bcd_oracle_fixture,
)


BCD_HIVE_MAX_BYTES = 16 * 1024 * 1024
BCD_HIVE_MAX_NAME_CHARS = 256
BCD_HIVE_MAX_BACKEND_HANDLES = 4096

_OBJECT_NAME = re.compile(
    r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}\Z",
)
_ELEMENT_NAME = re.compile(r"[0-9a-fA-F]{8}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

_RootDescription = tuple[
    str,
    int,
    int | None,
    int | None,
    int | None,
    int | None,
    str | None,
    int | None,
]
_RegistryEvidence = tuple[tuple[BcdOracleObject, ...], _RootDescription]


class BcdHiveError(BcdError):
    """A captured BCD hive is malformed or contradicts its oracle fixture."""


@dataclass(frozen=True)
class BcdHiveValue:
    """One backend-normalized registry value.

    Backends must expose REG_BINARY as ``bytes``, REG_SZ as ``str``,
    REG_MULTI_SZ as ``tuple[str, ...]``, and REG_DWORD as ``int``.  Keeping
    this normalization at one boundary isolates low-level hive API changes.
    """

    registry_type: int
    data: bytes | str | tuple[str, ...] | int


class BcdHiveSession(Protocol):
    """Read-only key/value operations over one opened hive snapshot."""

    def root_key(self) -> object: ...

    def subkey_names(self, key: object) -> tuple[str, ...]: ...

    def open_subkey(self, key: object, name: str) -> object: ...

    def value_names(self, key: object) -> tuple[str, ...]: ...

    def read_value(self, key: object, name: str) -> BcdHiveValue: ...


class BcdHiveBackend(Protocol):
    """Adapter boundary for an evolving low-level registry-hive reader."""

    def open_snapshot(
        self,
        snapshot: bytes,
    ) -> AbstractContextManager[BcdHiveSession]: ...


class _HivexSession:
    """The only adaptation point from ``windows_hive`` to the BCD scanner."""

    def __init__(self, handle: object) -> None:
        self._handle = handle

    @staticmethod
    def _handle_id(value: object, label: str) -> int:
        if type(value) is not int or value <= 0:
            raise BcdHiveError(f"hivex returned an invalid {label} handle")
        return value

    def _call(self, method: str, *arguments: object) -> object:
        callback = getattr(self._handle, method, None)
        if not callable(callback):
            raise BcdHiveError(f"The hivex reader lacks the required {method} operation")
        try:
            return callback(*arguments)
        except Exception as error:
            raise BcdHiveError(f"hivex failed during {method}") from error

    def root_key(self) -> object:
        return self._handle_id(self._call("root"), "root")

    def subkey_names(self, key: object) -> tuple[str, ...]:
        key_id = self._handle_id(key, "node")
        children = self._call("node_children", key_id)
        if type(children) is not list or len(children) > BCD_HIVE_MAX_BACKEND_HANDLES:
            raise BcdHiveError("hivex returned a malformed child-node collection")
        names: list[str] = []
        for child in children:
            child_id = self._handle_id(child, "child-node")
            name = self._call("node_name", child_id)
            if type(name) is not str:
                raise BcdHiveError("hivex returned a malformed child-node name")
            names.append(name)
        return tuple(names)

    def open_subkey(self, key: object, name: str) -> object:
        key_id = self._handle_id(key, "node")
        if type(name) is not str:
            raise BcdHiveError("A hivex child-node name must be text")
        return self._handle_id(self._call("node_get_child", key_id, name), "child-node")

    def value_names(self, key: object) -> tuple[str, ...]:
        key_id = self._handle_id(key, "node")
        values = self._call("node_values", key_id)
        if type(values) is not list or len(values) > BCD_HIVE_MAX_BACKEND_HANDLES:
            raise BcdHiveError("hivex returned a malformed value collection")
        names: list[str] = []
        for value in values:
            value_id = self._handle_id(value, "value")
            name = self._call("value_key", value_id)
            if type(name) is not str:
                raise BcdHiveError("hivex returned a malformed value name")
            names.append(name)
        return tuple(names)

    def read_value(self, key: object, name: str) -> BcdHiveValue:
        from .windows_hive import read_hivex_value

        key_id = self._handle_id(key, "node")
        if type(name) is not str:
            raise BcdHiveError("A hivex value name must be text")
        value_id = self._handle_id(
            self._call("node_get_value", key_id, name),
            "value",
        )
        try:
            decoded = read_hivex_value(self._handle, value_id)  # type: ignore[arg-type]
        except Exception as error:
            raise BcdHiveError("hivex returned malformed registry value data") from error
        return BcdHiveValue(decoded.registry_type, decoded.value)


@dataclass(frozen=True)
class BcdHiveObservation:
    """Bounded registry evidence read from one immutable byte snapshot."""

    store_sha256: str
    store_size: int
    objects: tuple[BcdOracleObject, ...]
    root_key_name: str
    root_key_name_registry_type: int
    root_system: int | None
    root_system_registry_type: int | None
    root_treat_as_system: int | None
    root_treat_as_system_registry_type: int | None
    root_guid_cache_hex: str | None
    root_guid_cache_registry_type: int | None


def _snapshot_identity(snapshot: bytes) -> tuple[int, str]:
    if type(snapshot) is not bytes:
        raise BcdHiveError("The BCD hive snapshot must be immutable bytes")
    if not 4 <= len(snapshot) <= BCD_HIVE_MAX_BYTES:
        raise BcdHiveError("The BCD hive snapshot size is outside policy")
    if snapshot[:4] != b"regf":
        raise BcdHiveError("The BCD hive snapshot lacks a registry-hive signature")
    return len(snapshot), hashlib.sha256(snapshot).hexdigest()


def _names(
    names: object,
    label: str,
    *,
    maximum: int,
) -> tuple[str, ...]:
    if type(names) is not tuple or len(names) > maximum:
        raise BcdHiveError(f"The BCD hive {label} collection is invalid")
    checked: list[str] = []
    folded: set[str] = set()
    for name in names:
        if (
            type(name) is not str
            or not name
            or len(name) > BCD_HIVE_MAX_NAME_CHARS
            or "\0" in name
            or "\\" in name
            or "/" in name
        ):
            raise BcdHiveError(f"The BCD hive {label} contains an invalid name")
        identity = name.casefold()
        if identity in folded:
            raise BcdHiveError(f"The BCD hive {label} repeats a name")
        folded.add(identity)
        checked.append(name)
    return tuple(checked)


def _exact_names(
    names: object,
    label: str,
    required: tuple[str, ...],
    optional: tuple[str, ...] = (),
) -> dict[str, str]:
    maximum = len(required) + len(optional)
    checked = _names(names, label, maximum=maximum)
    by_folded = {name.casefold(): name for name in checked}
    required_folded = {name.casefold() for name in required}
    allowed_folded = required_folded | {name.casefold() for name in optional}
    if not required_folded.issubset(by_folded) or set(by_folded) - allowed_folded:
        raise BcdHiveError(f"The BCD hive {label} names are not exact")
    return by_folded


def _open(session: BcdHiveSession, key: object, names: dict[str, str], name: str) -> object:
    try:
        return session.open_subkey(key, names[name.casefold()])
    except Exception as error:
        raise BcdHiveError(f"The BCD hive {name} key could not be opened") from error


def _read(
    session: BcdHiveSession,
    key: object,
    names: dict[str, str],
    name: str,
) -> BcdHiveValue:
    try:
        value = session.read_value(key, names[name.casefold()])
    except Exception as error:
        raise BcdHiveError(f"The BCD hive {name} value could not be read") from error
    if type(value) is not BcdHiveValue or type(value.registry_type) is not int:
        raise BcdHiveError(f"The BCD hive {name} value has an invalid backend form")
    if not 0 <= value.registry_type <= 0xFFFFFFFF:
        raise BcdHiveError(f"The BCD hive {name} registry type is invalid")
    return value


def _no_subkeys(session: BcdHiveSession, key: object, label: str) -> None:
    if _names(session.subkey_names(key), f"{label} subkeys", maximum=0):
        raise BcdHiveError(f"The BCD hive {label} contains unexpected subkeys")


def _no_values(session: BcdHiveSession, key: object, label: str) -> None:
    if _names(session.value_names(key), f"{label} values", maximum=0):
        raise BcdHiveError(f"The BCD hive {label} contains unexpected values")


def _dword(value: BcdHiveValue, label: str) -> int:
    if (
        value.registry_type != BCD_REG_DWORD
        or type(value.data) is not int
        or not 0 <= value.data <= 0xFFFFFFFF
    ):
        raise BcdHiveError(f"The BCD hive {label} is not a REG_DWORD")
    return value.data


def _string(value: BcdHiveValue, label: str, *, maximum: int) -> str:
    if (
        value.registry_type != BCD_REG_SZ
        or type(value.data) is not str
        or not value.data
        or len(value.data) > maximum
        or "\0" in value.data
    ):
        raise BcdHiveError(f"The BCD hive {label} is not a bounded REG_SZ")
    return value.data


def _binary(
    value: BcdHiveValue,
    label: str,
    *,
    nonempty: bool = True,
) -> bytes:
    if (
        value.registry_type != BCD_REG_BINARY
        or type(value.data) is not bytes
        or (nonempty and not value.data)
        or len(value.data) > BCD_ORACLE_MAX_RAW_ELEMENT_BYTES
    ):
        raise BcdHiveError(f"The BCD hive {label} is not bounded REG_BINARY data")
    return value.data


def _multi_string(value: BcdHiveValue, label: str) -> tuple[str, ...]:
    data = value.data
    if (
        value.registry_type != BCD_REG_MULTI_SZ
        or type(data) is not tuple
        or not 1 <= len(data) <= BCD_ORACLE_MAX_OBJECTS
        or any(
            type(member) is not str
            or not member
            or len(member) > 1024
            or "\0" in member
            for member in data
        )
    ):
        raise BcdHiveError(f"The BCD hive {label} is not bounded REG_MULTI_SZ data")
    return data


def _read_element(
    session: BcdHiveSession,
    elements_key: object,
    element_name: str,
) -> BcdOracleElement:
    if _ELEMENT_NAME.fullmatch(element_name) is None:
        raise BcdHiveError("A BCD hive element key is not exactly eight hexadecimal digits")
    element_type = int(element_name, 16)
    if element_type == 0:
        raise BcdHiveError("A BCD hive element type must be non-zero")
    element_key = session.open_subkey(elements_key, element_name)
    _no_subkeys(session, element_key, f"element {element_name}")
    value_names = _exact_names(
        session.value_names(element_key),
        f"element {element_name} values",
        ("Element",),
    )
    value = _read(session, element_key, value_names, "Element")
    element_format = (element_type >> 24) & 0xF
    if element_format == 1:
        payload = _binary(value, f"element {element_name}")
        return BcdOracleElement(element_type, value.registry_type, binary_hex=payload.hex())
    if element_format in {2, 3}:
        text = _string(value, f"element {element_name}", maximum=1024)
        return BcdOracleElement(element_type, value.registry_type, string_value=text)
    if element_format == 4:
        values = _multi_string(value, f"element {element_name}")
        return BcdOracleElement(
            element_type,
            value.registry_type,
            multi_string_value=values,
        )
    if element_format in {5, 6, 7}:
        payload = _binary(value, f"element {element_name}")
        return BcdOracleElement(element_type, value.registry_type, binary_hex=payload.hex())
    raise BcdHiveError("A BCD hive element uses an unsupported format")


def _read_object(
    session: BcdHiveSession,
    objects_key: object,
    object_name: str,
) -> BcdOracleObject:
    if _OBJECT_NAME.fullmatch(object_name) is None:
        raise BcdHiveError("A BCD hive object key is not a canonical braced UUID")
    object_id = uuid.UUID(object_name[1:-1])
    if object_id.int == 0:
        raise BcdHiveError("A BCD hive object key uses the zero UUID")
    object_key = session.open_subkey(objects_key, object_name)
    _no_values(session, object_key, f"object {object_name}")
    subkeys = _exact_names(
        session.subkey_names(object_key),
        f"object {object_name} subkeys",
        ("Description",),
        ("Elements",),
    )
    description_key = _open(session, object_key, subkeys, "Description")
    _no_subkeys(session, description_key, f"object {object_name} Description")
    description_values = _exact_names(
        session.value_names(description_key),
        f"object {object_name} Description values",
        ("Type",),
    )
    object_type_value = _read(session, description_key, description_values, "Type")
    object_type = _dword(object_type_value, f"object {object_name} Type")
    if object_type == 0:
        raise BcdHiveError("A BCD hive object Type must be non-zero")

    elements: list[BcdOracleElement] = []
    if "elements" in subkeys:
        elements_key = _open(session, object_key, subkeys, "Elements")
        _no_values(session, elements_key, f"object {object_name} Elements")
        element_names = _names(
            session.subkey_names(elements_key),
            f"object {object_name} element keys",
            maximum=128,
        )
        numeric_types: set[int] = set()
        for element_name in element_names:
            if _ELEMENT_NAME.fullmatch(element_name) is None:
                raise BcdHiveError(
                    "A BCD hive element key is not exactly eight hexadecimal digits",
                )
            element_type = int(element_name, 16)
            if element_type in numeric_types:
                raise BcdHiveError("A BCD hive object repeats an element type")
            numeric_types.add(element_type)
            elements.append(_read_element(session, elements_key, element_name))
    return BcdOracleObject(
        object_id=object_id,
        object_type=object_type,
        object_type_registry_type=object_type_value.registry_type,
        elements=tuple(sorted(elements, key=lambda item: item.element_type)),
    )


def _read_root_description(
    session: BcdHiveSession,
    root: object,
    root_subkeys: dict[str, str],
) -> _RootDescription:
    description_key = _open(session, root, root_subkeys, "Description")
    _no_subkeys(session, description_key, "root Description")
    values = _exact_names(
        session.value_names(description_key),
        "root Description values",
        ("KeyName",),
        ("System", "TreatAsSystem", "GuidCache"),
    )
    key_name_value = _read(session, description_key, values, "KeyName")
    key_name = _string(key_name_value, "root Description/KeyName", maximum=256)

    system = system_type = None
    if "system" in values:
        value = _read(session, description_key, values, "System")
        system, system_type = _dword(value, "root Description/System"), value.registry_type
    treat = treat_type = None
    if "treatassystem" in values:
        value = _read(session, description_key, values, "TreatAsSystem")
        treat, treat_type = (
            _dword(value, "root Description/TreatAsSystem"),
            value.registry_type,
        )
    guid_cache = guid_cache_type = None
    if "guidcache" in values:
        value = _read(session, description_key, values, "GuidCache")
        guid_cache, guid_cache_type = (
            _binary(value, "root Description/GuidCache").hex(),
            value.registry_type,
        )
    return (
        key_name,
        key_name_value.registry_type,
        system,
        system_type,
        treat,
        treat_type,
        guid_cache,
        guid_cache_type,
    )


def _read_registry_evidence(session: BcdHiveSession) -> _RegistryEvidence:
    root = session.root_key()
    _no_values(session, root, "root")
    root_subkeys = _exact_names(
        session.subkey_names(root),
        "root subkeys",
        ("Description", "Objects"),
    )
    root_description = _read_root_description(session, root, root_subkeys)
    objects_key = _open(session, root, root_subkeys, "Objects")
    _no_values(session, objects_key, "Objects")
    object_names = _names(
        session.subkey_names(objects_key),
        "object keys",
        maximum=BCD_ORACLE_MAX_OBJECTS,
    )
    if len(object_names) < 2:
        raise BcdHiveError("The BCD hive contains too few objects")
    object_ids: set[uuid.UUID] = set()
    objects: list[BcdOracleObject] = []
    element_count = 0
    for object_name in object_names:
        item = _read_object(session, objects_key, object_name)
        if item.object_id in object_ids:
            raise BcdHiveError("The BCD hive repeats an object UUID")
        object_ids.add(item.object_id)
        element_count += len(item.elements)
        if element_count > BCD_ORACLE_MAX_ELEMENTS:
            raise BcdHiveError("The BCD hive contains too many elements")
        objects.append(item)
    return tuple(sorted(objects, key=lambda item: item.object_id.hex)), root_description


def _observation(
    store_size: int,
    store_sha256: str,
    evidence: _RegistryEvidence,
) -> BcdHiveObservation:
    objects, root_description = evidence
    return BcdHiveObservation(
        store_sha256=store_sha256,
        store_size=store_size,
        objects=objects,
        root_key_name=root_description[0],
        root_key_name_registry_type=root_description[1],
        root_system=root_description[2],
        root_system_registry_type=root_description[3],
        root_treat_as_system=root_description[4],
        root_treat_as_system_registry_type=root_description[5],
        root_guid_cache_hex=root_description[6],
        root_guid_cache_registry_type=root_description[7],
    )


def read_bcd_hive_snapshot(
    snapshot: bytes,
    backend: BcdHiveBackend,
) -> BcdHiveObservation:
    """Read a bounded BCD hive snapshot without assigning it trust or authority."""

    store_size, store_sha256 = _snapshot_identity(snapshot)
    try:
        with backend.open_snapshot(snapshot) as session:
            evidence = _read_registry_evidence(session)
    except BcdHiveError:
        raise
    except Exception as error:
        raise BcdHiveError("The BCD hive backend could not read the snapshot") from error
    return _observation(store_size, store_sha256, evidence)


def _expected_observation(fixture: BcdOracleFixture) -> BcdHiveObservation:
    return BcdHiveObservation(
        store_sha256=fixture.provenance.store_sha256,
        store_size=fixture.provenance.store_size,
        objects=fixture.objects,
        root_key_name=fixture.root_key_name,
        root_key_name_registry_type=fixture.root_key_name_registry_type,
        root_system=fixture.root_system,
        root_system_registry_type=fixture.root_system_registry_type,
        root_treat_as_system=fixture.root_treat_as_system,
        root_treat_as_system_registry_type=fixture.root_treat_as_system_registry_type,
        root_guid_cache_hex=fixture.root_guid_cache_hex,
        root_guid_cache_registry_type=fixture.root_guid_cache_registry_type,
    )


def _validated_fixture(fixture: BcdOracleFixture) -> None:
    try:
        validate_bcd_oracle_fixture(fixture)
    except BcdError as error:
        raise BcdHiveError("The BCD oracle fixture is invalid") from error


def verify_bcd_hive_snapshot(
    snapshot: bytes,
    fixture: BcdOracleFixture,
    backend: BcdHiveBackend,
) -> BcdHiveObservation:
    """Require one raw hive snapshot to match every fixture registry claim.

    The fixture is still an untrusted evidence claim after this comparison.
    This function has no write path and cannot authorize Linux BCD publication.
    """

    _validated_fixture(fixture)
    store_size, store_sha256 = _snapshot_identity(snapshot)
    if (
        fixture.provenance.store_size != store_size
        or fixture.provenance.store_sha256 != store_sha256
    ):
        raise BcdHiveError("The BCD hive snapshot contradicts its store provenance")
    observed = read_bcd_hive_snapshot(snapshot, backend)
    expected = _expected_observation(fixture)
    if observed != expected:
        raise BcdHiveError("The BCD hive registry snapshot contradicts its oracle fixture")
    return observed


def verify_bcd_hive_against_fixture(
    path: str | os.PathLike[str],
    fixture: BcdOracleFixture,
) -> BcdHiveObservation:
    """Verify a pinned regular-file path through the concrete read-only reader.

    ``windows_hive`` owns path opening, immutable snapshotting, optional hivex
    loading, and source revalidation.  This adapter owns only the BCD schema and
    exact fixture comparison.  No fallback reopens ``path``.
    """

    try:
        from .windows_hive import WindowsHiveError, inspect_windows_hive
    except (ImportError, OSError) as error:
        raise BcdHiveError("The read-only Windows hive backend is unavailable") from error
    try:
        return _verify_concrete_hive(
            fixture,
            lambda inspector: inspect_windows_hive(path, inspector),
        )
    except BcdHiveError:
        raise
    except WindowsHiveError as error:
        raise BcdHiveError("The BCD hive could not be inspected read-only") from error
    except (OSError, TypeError, ValueError) as error:
        raise BcdHiveError("The BCD hive path or backend result is invalid") from error


def _read_concrete_hive(inspect: object) -> BcdHiveObservation:
    if not callable(inspect):
        raise BcdHiveError("The concrete hive inspector is unavailable")
    receipt, evidence = inspect(
        lambda handle: _read_registry_evidence(_HivexSession(handle)),
    )
    try:
        store_size = receipt.identity.size
        store_sha256 = receipt.sha256
    except AttributeError as error:
        raise BcdHiveError("The concrete hive receipt is malformed") from error
    if (
        type(store_size) is not int
        or not 1 <= store_size <= BCD_HIVE_MAX_BYTES
        or type(store_sha256) is not str
        or _SHA256.fullmatch(store_sha256) is None
    ):
        raise BcdHiveError("The concrete hive receipt is malformed")
    return _observation(store_size, store_sha256, evidence)


def _verify_concrete_hive(fixture: BcdOracleFixture, inspect: object) -> BcdHiveObservation:
    _validated_fixture(fixture)
    observed = _read_concrete_hive(inspect)
    if observed != _expected_observation(fixture):
        raise BcdHiveError("The BCD hive registry snapshot contradicts its oracle fixture")
    return observed


def read_bcd_hive_descriptor(descriptor: int) -> BcdHiveObservation:
    """Read typed evidence from one caller-owned descriptor without trusting it."""

    if type(descriptor) is not int or descriptor < 0:
        raise BcdHiveError("The BCD hive descriptor must be a non-negative integer")
    try:
        from .windows_hive import (
            WindowsHiveError,
            inspect_windows_hive_descriptor,
        )
    except (ImportError, OSError) as error:
        raise BcdHiveError("The read-only Windows hive backend is unavailable") from error
    try:
        return _read_concrete_hive(
            lambda inspector: inspect_windows_hive_descriptor(descriptor, inspector),
        )
    except BcdHiveError:
        raise
    except WindowsHiveError as error:
        raise BcdHiveError("The BCD hive descriptor could not be inspected read-only") from error
    except (OSError, TypeError, ValueError) as error:
        raise BcdHiveError("The BCD hive descriptor or backend result is invalid") from error


def verify_bcd_hive_descriptor_against_fixture(
    descriptor: int,
    fixture: BcdOracleFixture,
) -> BcdHiveObservation:
    """Verify one already-open descriptor without opening any path or procfd."""

    if type(descriptor) is not int or descriptor < 0:
        raise BcdHiveError("The BCD hive descriptor must be a non-negative integer")
    try:
        from .windows_hive import (
            WindowsHiveError,
            inspect_windows_hive_descriptor,
        )
    except (ImportError, OSError) as error:
        raise BcdHiveError("The read-only Windows hive backend is unavailable") from error
    try:
        return _verify_concrete_hive(
            fixture,
            lambda inspector: inspect_windows_hive_descriptor(descriptor, inspector),
        )
    except BcdHiveError:
        raise
    except WindowsHiveError as error:
        raise BcdHiveError("The BCD hive descriptor could not be inspected read-only") from error
    except (OSError, TypeError, ValueError) as error:
        raise BcdHiveError("The BCD hive descriptor or backend result is invalid") from error
