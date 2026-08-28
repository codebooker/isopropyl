# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import copy
import hashlib
import os
import sys
import tempfile
import unittest
from contextlib import AbstractContextManager
from dataclasses import dataclass, field, replace
from pathlib import Path
from unittest.mock import patch

from isopropyl.windows_bcd_hivex import (
    BCD_HIVE_MAX_BACKEND_HANDLES,
    BCD_HIVE_MAX_BYTES,
    BcdHiveError,
    BcdHiveValue,
    _HivexSession,
    read_bcd_hive_descriptor,
    read_bcd_hive_snapshot,
    verify_bcd_hive_descriptor_against_fixture,
    verify_bcd_hive_snapshot,
)
from isopropyl.windows_bcd_oracle import (
    BCD_REG_BINARY,
    BCD_REG_DWORD,
    BCD_REG_MULTI_SZ,
    BCD_REG_SZ,
)
from tests.test_windows_bcd_oracle import fixture as oracle_fixture


SNAPSHOT = b"regf" + bytes(range(256)) * 16


@dataclass
class FakeKey:
    children: dict[str, "FakeKey"] = field(default_factory=dict)
    values: dict[str, BcdHiveValue] = field(default_factory=dict)


class FakeSession:
    def __init__(self, root: FakeKey, *, reverse: bool = False) -> None:
        self.root = root
        self.reverse = reverse

    def root_key(self) -> object:
        return self.root

    def subkey_names(self, key: object) -> tuple[str, ...]:
        assert isinstance(key, FakeKey)
        names = tuple(key.children)
        return tuple(reversed(names)) if self.reverse else names

    def open_subkey(self, key: object, name: str) -> object:
        assert isinstance(key, FakeKey)
        return key.children[name]

    def value_names(self, key: object) -> tuple[str, ...]:
        assert isinstance(key, FakeKey)
        names = tuple(key.values)
        return tuple(reversed(names)) if self.reverse else names

    def read_value(self, key: object, name: str) -> BcdHiveValue:
        assert isinstance(key, FakeKey)
        return key.values[name]


class FakeContext(AbstractContextManager[FakeSession]):
    def __init__(self, session: FakeSession) -> None:
        self.session = session
        self.exited = False

    def __enter__(self) -> FakeSession:
        return self.session

    def __exit__(self, *_args) -> None:
        self.exited = True


class FakeBackend:
    def __init__(self, root: FakeKey, *, reverse: bool = False) -> None:
        self.root = root
        self.reverse = reverse
        self.opened: list[bytes] = []
        self.contexts: list[FakeContext] = []

    def open_snapshot(self, snapshot: bytes) -> FakeContext:
        self.opened.append(snapshot)
        context = FakeContext(FakeSession(self.root, reverse=self.reverse))
        self.contexts.append(context)
        return context


class FakeHivexHandle:
    def __init__(self, root: FakeKey) -> None:
        self.nodes: dict[int, tuple[str, FakeKey]] = {}
        self.children: dict[int, dict[str, int]] = {}
        self.values: dict[int, tuple[str, BcdHiveValue]] = {}
        self.node_values_by_name: dict[int, dict[str, int]] = {}
        self.closed = False
        self._next_node = 1
        self._next_value = 10_000
        self.root_id = self._add_node("ROOT", root)

    def _add_node(self, name: str, key: FakeKey) -> int:
        node = self._next_node
        self._next_node += 1
        self.nodes[node] = (name, key)
        self.children[node] = {}
        self.node_values_by_name[node] = {}
        for value_name, value in key.values.items():
            value_id = self._next_value
            self._next_value += 1
            self.values[value_id] = (value_name, value)
            self.node_values_by_name[node][value_name] = value_id
        for child_name, child in key.children.items():
            self.children[node][child_name] = self._add_node(child_name, child)
        return node

    def root(self) -> int:
        return self.root_id

    def node_name(self, node: int) -> str:
        return self.nodes[node][0]

    def node_children(self, node: int) -> list[int]:
        return list(self.children[node].values())

    def node_get_child(self, node: int, name: str) -> int:
        return self.children[node][name]

    def node_values(self, node: int) -> list[int]:
        return list(self.node_values_by_name[node].values())

    def node_get_value(self, node: int, name: str) -> int:
        return self.node_values_by_name[node][name]

    def value_key(self, value: int) -> str:
        return self.values[value][0]

    def value_value(self, value: int) -> tuple[int, bytes]:
        registry = self.values[value][1]
        data = registry.data
        if registry.registry_type == BCD_REG_SZ:
            assert isinstance(data, str)
            payload = data.encode("utf-16-le") + b"\0\0"
        elif registry.registry_type == BCD_REG_MULTI_SZ:
            assert isinstance(data, tuple)
            payload = ("\0".join(data) + "\0\0").encode("utf-16-le")
        elif registry.registry_type == BCD_REG_DWORD:
            assert isinstance(data, int)
            payload = data.to_bytes(4, "little")
        else:
            assert isinstance(data, bytes)
            payload = data
        return registry.registry_type, payload

    def close(self) -> None:
        self.closed = True


class FakeHivexModule:
    def __init__(self, root: FakeKey) -> None:
        self.root = root
        self.handles: list[FakeHivexHandle] = []

    def Hivex(self, _path: str, **_options: object) -> FakeHivexHandle:
        handle = FakeHivexHandle(self.root)
        self.handles.append(handle)
        return handle


def bound_fixture(snapshot: bytes = SNAPSHOT):
    observed = oracle_fixture()
    return replace(
        observed,
        provenance=replace(
            observed.provenance,
            store_sha256=hashlib.sha256(snapshot).hexdigest(),
            store_size=len(snapshot),
        ),
    )


def tree_for_fixture(observed) -> FakeKey:
    description_values = {
        "KeyName": BcdHiveValue(
            observed.root_key_name_registry_type,
            observed.root_key_name,
        ),
    }
    if observed.root_system is not None:
        description_values["System"] = BcdHiveValue(
            observed.root_system_registry_type,
            observed.root_system,
        )
    if observed.root_treat_as_system is not None:
        description_values["TreatAsSystem"] = BcdHiveValue(
            observed.root_treat_as_system_registry_type,
            observed.root_treat_as_system,
        )
    if observed.root_guid_cache_hex is not None:
        description_values["GuidCache"] = BcdHiveValue(
            observed.root_guid_cache_registry_type,
            bytes.fromhex(observed.root_guid_cache_hex),
        )
    objects: dict[str, FakeKey] = {}
    for item in observed.objects:
        children = {
            "Description": FakeKey(
                values={
                    "Type": BcdHiveValue(
                        item.object_type_registry_type,
                        item.object_type,
                    ),
                },
            ),
        }
        if item.elements:
            element_keys = {}
            for element in item.elements:
                if element.binary_hex is not None:
                    data = bytes.fromhex(element.binary_hex)
                elif element.string_value is not None:
                    data = element.string_value
                else:
                    data = element.multi_string_value
                element_keys[f"{element.element_type:08x}"] = FakeKey(
                    values={
                        "Element": BcdHiveValue(element.registry_type, data),
                    },
                )
            children["Elements"] = FakeKey(children=element_keys)
        objects["{" + str(item.object_id) + "}"] = FakeKey(children=children)
    return FakeKey(
        children={
            "Description": FakeKey(values=description_values),
            "Objects": FakeKey(children=objects),
        },
    )


def first_element_key(root: FakeKey) -> FakeKey:
    objects = root.children["Objects"]
    item = next(value for value in objects.children.values() if "Elements" in value.children)
    return next(iter(item.children["Elements"].children.values()))


class WindowsBcdHivexTests(unittest.TestCase):
    def test_concrete_backend_collections_are_bounded_before_name_resolution(self):
        handle = FakeHivexHandle(tree_for_fixture(bound_fixture()))
        session = _HivexSession(handle)
        oversized = list(range(1, BCD_HIVE_MAX_BACKEND_HANDLES + 2))
        with (
            patch.object(handle, "node_children", return_value=oversized),
            patch.object(handle, "node_name") as node_name,
            self.assertRaisesRegex(BcdHiveError, "child-node collection"),
        ):
            session.subkey_names(handle.root())
        node_name.assert_not_called()
        with (
            patch.object(handle, "node_values", return_value=oversized),
            patch.object(handle, "value_key") as value_key,
            self.assertRaisesRegex(BcdHiveError, "value collection"),
        ):
            session.value_names(handle.root())
        value_key.assert_not_called()

    def test_exact_snapshot_matches_fixture_and_closes_backend_session(self):
        observed = bound_fixture()
        backend = FakeBackend(tree_for_fixture(observed), reverse=True)
        result = verify_bcd_hive_snapshot(SNAPSHOT, observed, backend)
        self.assertEqual(result.store_sha256, observed.provenance.store_sha256)
        self.assertEqual(result.store_size, len(SNAPSHOT))
        self.assertEqual(result.objects, observed.objects)
        self.assertEqual(backend.opened, [SNAPSHOT])
        self.assertTrue(backend.contexts[0].exited)

    def test_descriptor_wrapper_uses_concrete_sealed_reader_and_leaves_fd_open(self):
        observed = bound_fixture()
        module = FakeHivexModule(tree_for_fixture(observed))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "BCD"
            path.write_bytes(SNAPSHOT)
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                with patch(
                    "isopropyl.windows_hive.importlib.import_module",
                    return_value=module,
                ):
                    result = verify_bcd_hive_descriptor_against_fixture(
                        descriptor,
                        observed,
                    )
                self.assertEqual(result.objects, observed.objects)
                self.assertEqual(os.fstat(descriptor).st_size, len(SNAPSHOT))
            finally:
                os.close(descriptor)
        self.assertEqual(len(module.handles), 1)
        self.assertTrue(module.handles[0].closed)

    def test_descriptor_reader_derives_observation_without_a_fixture_claim(self):
        expected = bound_fixture()
        module = FakeHivexModule(tree_for_fixture(expected))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "BCD"
            path.write_bytes(SNAPSHOT)
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                with patch(
                    "isopropyl.windows_hive.importlib.import_module",
                    return_value=module,
                ):
                    observed = read_bcd_hive_descriptor(descriptor)
                self.assertEqual(observed.objects, expected.objects)
                self.assertEqual(observed.store_size, len(SNAPSHOT))
                self.assertEqual(observed.store_sha256, hashlib.sha256(SNAPSHOT).hexdigest())
            finally:
                os.close(descriptor)

    def test_missing_concrete_reader_is_normalized_for_both_public_wrappers(self):
        from isopropyl.windows_bcd_hivex import verify_bcd_hive_against_fixture

        expected = bound_fixture()
        with (
            patch.dict(sys.modules, {"isopropyl.windows_hive": None}),
            self.assertRaisesRegex(BcdHiveError, "backend is unavailable"),
        ):
            verify_bcd_hive_against_fixture("missing.BCD", expected)
        with (
            patch.dict(sys.modules, {"isopropyl.windows_hive": None}),
            self.assertRaisesRegex(BcdHiveError, "backend is unavailable"),
        ):
            verify_bcd_hive_descriptor_against_fixture(0, expected)

    def test_reader_preserves_all_typed_root_and_object_registry_evidence(self):
        expected = bound_fixture()
        expected = replace(
            expected,
            root_guid_cache_hex="01020304",
            root_guid_cache_registry_type=BCD_REG_BINARY,
        )
        backend = FakeBackend(tree_for_fixture(expected))
        result = read_bcd_hive_snapshot(SNAPSHOT, backend)
        self.assertEqual(result.root_key_name, "BCD00000001")
        self.assertEqual(result.root_key_name_registry_type, BCD_REG_SZ)
        self.assertEqual(result.root_system, 1)
        self.assertEqual(result.root_system_registry_type, BCD_REG_DWORD)
        self.assertEqual(result.root_treat_as_system, 1)
        self.assertEqual(result.root_guid_cache_hex, "01020304")
        registry_types = {
            element.registry_type
            for item in result.objects
            for element in item.elements
        }
        self.assertEqual(
            registry_types,
            {BCD_REG_BINARY, BCD_REG_SZ, BCD_REG_MULTI_SZ},
        )

    def test_provenance_is_bound_before_the_backend_is_opened(self):
        observed = bound_fixture()
        backend = FakeBackend(tree_for_fixture(observed))
        mismatches = (
            replace(
                observed,
                provenance=replace(observed.provenance, store_size=len(SNAPSHOT) + 1),
            ),
            replace(
                observed,
                provenance=replace(observed.provenance, store_sha256="a" * 64),
            ),
        )
        for mismatch in mismatches:
            with self.subTest(mismatch=mismatch), self.assertRaisesRegex(
                BcdHiveError,
                "store provenance",
            ):
                verify_bcd_hive_snapshot(SNAPSHOT, mismatch, backend)
        self.assertEqual(backend.opened, [])

    def test_exact_comparison_rejects_one_registry_value_change(self):
        observed = bound_fixture()
        root = tree_for_fixture(observed)
        root.children["Description"].values["KeyName"] = BcdHiveValue(
            BCD_REG_SZ,
            "BCD00000002",
        )
        with self.assertRaisesRegex(BcdHiveError, "contradicts its oracle fixture"):
            verify_bcd_hive_snapshot(SNAPSHOT, observed, FakeBackend(root))

    def test_strict_key_and_value_names_reject_missing_extra_and_duplicate_names(self):
        expected = bound_fixture()

        roots = []
        root = tree_for_fixture(expected)
        root.children["Extra"] = FakeKey()
        roots.append(root)
        root = tree_for_fixture(expected)
        del root.children["Objects"]
        roots.append(root)
        root = tree_for_fixture(expected)
        root.children["description"] = root.children["Description"]
        roots.append(root)
        root = tree_for_fixture(expected)
        root.children["Description"].values["Unknown"] = BcdHiveValue(BCD_REG_DWORD, 1)
        roots.append(root)
        root = tree_for_fixture(expected)
        objects = root.children["Objects"].children
        name, item = next(iter(objects.items()))
        objects["not-a-guid"] = objects.pop(name)
        roots.append(root)
        root = tree_for_fixture(expected)
        element = first_element_key(root)
        element.values["Unexpected"] = element.values.pop("Element")
        roots.append(root)

        for root in roots:
            with self.subTest(root=root), self.assertRaises(BcdHiveError):
                read_bcd_hive_snapshot(SNAPSHOT, FakeBackend(root))

    def test_element_names_types_and_payloads_are_strict_and_bounded(self):
        expected = bound_fixture()
        roots = []
        root = tree_for_fixture(expected)
        objects = root.children["Objects"].children
        item = next(value for value in objects.values() if "Elements" in value.children)
        elements = item.children["Elements"].children
        name, element = next(iter(elements.items()))
        elements["123"] = elements.pop(name)
        roots.append(root)
        root = tree_for_fixture(expected)
        element = first_element_key(root)
        value = element.values["Element"]
        element.values["Element"] = BcdHiveValue(BCD_REG_DWORD, value.data)
        roots.append(root)
        root = tree_for_fixture(expected)
        element = first_element_key(root)
        element.values["Element"] = BcdHiveValue(
            BCD_REG_BINARY,
            b"x" * 4097,
        )
        roots.append(root)
        for root in roots:
            with self.subTest(root=root), self.assertRaises(BcdHiveError):
                read_bcd_hive_snapshot(SNAPSHOT, FakeBackend(root))

    def test_snapshot_shape_and_size_are_bounded_before_backend_use(self):
        backend = FakeBackend(tree_for_fixture(bound_fixture()))
        snapshots = (
            bytearray(SNAPSHOT),
            b"",
            b"nope",
            b"regf" + b"x" * BCD_HIVE_MAX_BYTES,
        )
        for snapshot in snapshots:
            with self.subTest(snapshot_type=type(snapshot)), self.assertRaises(BcdHiveError):
                read_bcd_hive_snapshot(snapshot, backend)  # type: ignore[arg-type]
        self.assertEqual(backend.opened, [])

    def test_object_count_is_bounded_and_backend_failures_are_normalized(self):
        observed = bound_fixture()
        root = tree_for_fixture(observed)
        original = next(iter(root.children["Objects"].children.values()))
        root.children["Objects"].children = {
            "{" + f"{index:08x}-0000-4000-8000-000000000000" + "}": copy.deepcopy(original)
            for index in range(1, 130)
        }
        with self.assertRaisesRegex(BcdHiveError, "object keys collection"):
            read_bcd_hive_snapshot(SNAPSHOT, FakeBackend(root))

        class BrokenBackend:
            def open_snapshot(self, _snapshot):
                raise RuntimeError("low-level API changed")

        with self.assertRaisesRegex(BcdHiveError, "backend could not read"):
            read_bcd_hive_snapshot(SNAPSHOT, BrokenBackend())


if __name__ == "__main__":
    unittest.main()
