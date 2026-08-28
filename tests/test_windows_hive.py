# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from isopropyl.windows_hive import (
    MAX_HIVE_BYTES,
    MAX_REGISTRY_VALUE_BYTES,
    REG_BINARY,
    REG_DWORD,
    REG_MULTI_SZ,
    REG_SZ,
    WindowsHiveChanged,
    WindowsHiveError,
    WindowsHiveFormatError,
    WindowsHiveUnavailable,
    decode_reg_binary,
    decode_reg_dword,
    decode_reg_multi_sz,
    decode_reg_sz,
    decode_registry_value,
    inspect_windows_hive,
    inspect_windows_hive_descriptor,
    read_hivex_value,
)


class FakeHive:
    def __init__(self, filename: str, **options: object) -> None:
        self.filename = filename
        self.options = options
        self.closed = False

    def value_value(self, value: int) -> tuple[int, bytes]:
        return REG_DWORD, value.to_bytes(4, "little")

    def close(self) -> None:
        self.closed = True


class FakeHivexModule:
    def __init__(self) -> None:
        self.handles: list[FakeHive] = []

    def Hivex(self, filename: str, **options: object) -> FakeHive:
        handle = FakeHive(filename, **options)
        self.handles.append(handle)
        return handle


class RegistryValueTests(unittest.TestCase):
    def test_strict_reg_sz(self) -> None:
        self.assertEqual(decode_reg_sz("Windows".encode("utf-16-le") + b"\0\0"), "Windows")
        self.assertEqual(decode_reg_sz(b"\0\0"), "")
        invalid = (
            b"",
            b"A",
            "A".encode("utf-16-le"),
            "A\0B".encode("utf-16-le") + b"\0\0",
            b"\x00\xd8\x00\x00",
        )
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(WindowsHiveFormatError):
                decode_reg_sz(payload)

    def test_strict_reg_multi_sz(self) -> None:
        payload = "one\0two\0\0".encode("utf-16-le")
        self.assertEqual(decode_reg_multi_sz(payload), ("one", "two"))
        self.assertEqual(decode_reg_multi_sz(b"\0\0\0\0"), ())
        invalid = (
            b"",
            "one\0".encode("utf-16-le"),
            "one\0\0\0".encode("utf-16-le"),
            "one\0\0two\0\0".encode("utf-16-le"),
            b"\x00\xd8\x00\x00\x00\x00",
        )
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(WindowsHiveFormatError):
                decode_reg_multi_sz(payload)

    def test_dword_binary_and_dispatch_are_exact(self) -> None:
        self.assertEqual(decode_reg_dword(b"\x78\x56\x34\x12"), 0x12345678)
        self.assertEqual(decode_reg_binary(b"\0\xff"), b"\0\xff")
        self.assertEqual(decode_registry_value(REG_SZ, b"A\0\0\0").value, "A")
        self.assertEqual(decode_registry_value(REG_MULTI_SZ, b"\0\0\0\0").value, ())
        self.assertEqual(decode_registry_value(REG_DWORD, b"\1\0\0\0").value, 1)
        self.assertEqual(decode_registry_value(REG_BINARY, b"").value, b"")
        with self.assertRaises(WindowsHiveFormatError):
            decode_reg_dword(b"\0\0\0")
        with self.assertRaises(WindowsHiveFormatError):
            decode_registry_value(True, b"")
        with self.assertRaises(WindowsHiveFormatError):
            decode_registry_value(99, b"")
        with self.assertRaises(WindowsHiveFormatError):
            decode_reg_binary(bytearray(b"x"))  # type: ignore[arg-type]
        with self.assertRaises(WindowsHiveFormatError):
            decode_reg_binary(b"x" * (MAX_REGISTRY_VALUE_BYTES + 1))

    def test_hivex_value_contract_is_strict(self) -> None:
        handle = types.SimpleNamespace(value_value=lambda value: (REG_DWORD, b"\2\0\0\0"))
        decoded = read_hivex_value(handle, 7)
        self.assertEqual((decoded.registry_type, decoded.value), (REG_DWORD, 2))
        malformed_results = (
            (REG_DWORD,),
            [REG_DWORD, b"\0" * 4],
            (True, b"\0" * 4),
            (REG_BINARY, bytearray()),
        )
        for result in malformed_results:
            malformed = types.SimpleNamespace(value_value=lambda value, result=result: result)
            with self.subTest(result=result), self.assertRaises(WindowsHiveFormatError):
                read_hivex_value(malformed, 1)
        with self.assertRaises(WindowsHiveFormatError):
            read_hivex_value(handle, True)
        failing = types.SimpleNamespace(
            value_value=lambda value: (_ for _ in ()).throw(OSError("bad")),
        )
        with self.assertRaises(WindowsHiveFormatError):
            read_hivex_value(failing, 1)


class HiveInspectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "BCD"
        self.payload = b"regf" + bytes(range(64))
        self.path.write_bytes(self.payload)
        self.module = FakeHivexModule()

    def _inspect(self, inspector):
        with patch("isopropyl.windows_hive.importlib.import_module", return_value=self.module):
            return inspect_windows_hive(self.path, inspector)

    def _inspect_descriptor(self, descriptor, inspector):
        with patch("isopropyl.windows_hive.importlib.import_module", return_value=self.module):
            return inspect_windows_hive_descriptor(descriptor, inspector)

    def test_descriptor_bound_sealed_snapshot_and_receipt(self) -> None:
        real_open = os.open
        seen_flags: list[int] = []

        def recording_open(path, flags, *args, **kwargs):
            seen_flags.append(flags)
            return real_open(path, flags, *args, **kwargs)

        def inspector(handle: FakeHive) -> bytes:
            with open(handle.filename, "rb", buffering=0) as snapshot:
                return snapshot.read()

        with patch("isopropyl.windows_hive.os.open", side_effect=recording_open):
            receipt, evidence = self._inspect(inspector)

        self.assertEqual(evidence, self.payload)
        self.assertEqual(receipt.sha256, hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(receipt.identity.size, len(self.payload))
        self.assertEqual(len(self.module.handles), 1)
        handle = self.module.handles[0]
        self.assertTrue(handle.filename.startswith("/proc/self/fd/"))
        self.assertEqual(handle.options, {"write": False, "unsafe": False})
        self.assertTrue(handle.closed)
        self.assertEqual(seen_flags[0] & os.O_ACCMODE, os.O_RDONLY)
        self.assertTrue(seen_flags[0] & os.O_CLOEXEC)
        self.assertTrue(seen_flags[0] & os.O_NOFOLLOW)

    def test_source_mutation_after_snapshot_fails_closed(self) -> None:
        def mutate(handle: FakeHive) -> bytes:
            before = Path(handle.filename).read_bytes()
            self.path.write_bytes(b"changed")
            return before

        with self.assertRaises(WindowsHiveChanged):
            self._inspect(mutate)
        self.assertTrue(self.module.handles[0].closed)

    def test_preseal_snapshot_mutation_cannot_change_the_parsed_bytes(self) -> None:
        from isopropyl import windows_hive

        real_seal = windows_hive._seal_snapshot

        def mutate_then_seal(snapshot: int) -> None:
            os.pwrite(snapshot, b"X", 0)
            real_seal(snapshot)

        with (
            patch("isopropyl.windows_hive._seal_snapshot", side_effect=mutate_then_seal),
            self.assertRaisesRegex(WindowsHiveChanged, "sealed hive snapshot"),
        ):
            self._inspect(lambda _handle: None)
        self.assertEqual(self.module.handles, [])

    def test_descriptor_api_preserves_caller_ownership_and_offset(self) -> None:
        descriptor = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.addCleanup(os.close, descriptor)
        os.lseek(descriptor, 3, os.SEEK_SET)
        real_dup = os.dup
        duplicates: list[int] = []

        def recording_dup(source: int) -> int:
            duplicate = real_dup(source)
            duplicates.append(duplicate)
            return duplicate

        with patch("isopropyl.windows_hive.os.dup", side_effect=recording_dup):
            receipt, evidence = self._inspect_descriptor(
                descriptor,
                lambda handle: Path(handle.filename).read_bytes(),
            )

        self.assertEqual(evidence, self.payload)
        self.assertEqual(receipt.identity.inode, os.fstat(descriptor).st_ino)
        self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), 3)
        self.assertGreaterEqual(os.fstat(descriptor).st_size, 1)
        self.assertEqual(len(duplicates), 1)
        with self.assertRaises(OSError):
            os.fstat(duplicates[0])

    def test_descriptor_api_rejects_opath_write_only_and_nonregular(self) -> None:
        descriptors: list[int] = []
        if hasattr(os, "O_PATH"):
            descriptors.append(os.open(self.path, os.O_PATH | os.O_CLOEXEC))
        descriptors.append(os.open(self.path, os.O_WRONLY | os.O_CLOEXEC))
        descriptors.append(os.open(self.path, os.O_RDWR | os.O_CLOEXEC))
        pipe_reader, pipe_writer = os.pipe()
        descriptors.extend((pipe_reader, pipe_writer))
        self.addCleanup(lambda: [os.close(item) for item in descriptors])

        for descriptor in descriptors:
            with self.subTest(descriptor=descriptor), self.assertRaises(WindowsHiveError):
                self._inspect_descriptor(descriptor, lambda handle: None)

    def test_descriptor_access_mode_is_checked_after_duplication(self) -> None:
        readable = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        writable = os.open(self.path, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.addCleanup(os.close, readable)
        self.addCleanup(os.close, writable)
        duplicated: list[int] = []
        real_dup = os.dup

        def substitute_duplicate(_descriptor: int) -> int:
            result = real_dup(writable)
            duplicated.append(result)
            return result

        with (
            patch(
                "isopropyl.windows_hive.os.dup",
                side_effect=substitute_duplicate,
            ),
            self.assertRaisesRegex(WindowsHiveError, "must be read-only"),
        ):
            self._inspect_descriptor(readable, lambda _handle: None)
        self.assertEqual(len(duplicated), 1)
        with self.assertRaises(OSError):
            os.fstat(duplicated[0])

    def test_same_size_source_mutation_is_caught_by_complete_hash(self) -> None:
        def mutate(handle: FakeHive) -> None:
            self.path.write_bytes(b"x" * len(self.payload))

        # Isolate the complete-digest guard from the independently tested
        # metadata-identity guard.
        with patch(
            "isopropyl.windows_hive._require_source_identity",
            return_value=None,
        ), self.assertRaises(WindowsHiveChanged):
            self._inspect(mutate)

    def test_missing_or_invalid_hivex_is_typed(self) -> None:
        for failure in (ModuleNotFoundError("hivex"), OSError("missing shared library")):
            with self.subTest(failure=failure), patch(
                "isopropyl.windows_hive.importlib.import_module",
                side_effect=failure,
            ), self.assertRaises(WindowsHiveUnavailable):
                inspect_windows_hive(self.path, lambda handle: None)
        with patch(
            "isopropyl.windows_hive.importlib.import_module",
            return_value=types.SimpleNamespace(),
        ), self.assertRaises(WindowsHiveUnavailable):
            inspect_windows_hive(self.path, lambda handle: None)

    def test_rejects_symlink_empty_nonregular_and_oversized_sources(self) -> None:
        symlink = Path(self.temporary.name) / "link"
        symlink.symlink_to(self.path)
        empty = Path(self.temporary.name) / "empty"
        empty.touch()
        directory = Path(self.temporary.name) / "directory"
        directory.mkdir()
        oversized = Path(self.temporary.name) / "large"
        with oversized.open("wb") as stream:
            stream.truncate(MAX_HIVE_BYTES + 1)
        for candidate in (symlink, empty, directory, oversized):
            with self.subTest(candidate=candidate), self.assertRaises(WindowsHiveError):
                with patch(
                    "isopropyl.windows_hive.importlib.import_module",
                    return_value=self.module,
                ):
                    inspect_windows_hive(candidate, lambda handle: None)

    def test_hivex_parse_failure_is_typed(self) -> None:
        module = types.SimpleNamespace(
            Hivex=lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("bad hive")),
        )
        with patch(
            "isopropyl.windows_hive.importlib.import_module",
            return_value=module,
        ), self.assertRaises(WindowsHiveFormatError):
            inspect_windows_hive(self.path, lambda handle: None)

    def test_inspector_exception_closes_snapshot_handle(self) -> None:
        def fail(handle: FakeHive) -> None:
            raise LookupError("missing evidence")

        with self.assertRaises(LookupError):
            self._inspect(fail)
        self.assertTrue(self.module.handles[0].closed)


if __name__ == "__main__":
    unittest.main()
