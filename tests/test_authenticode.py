# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import importlib.metadata
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from isopropyl import authenticode
from isopropyl.authenticode import (
    MAX_CERTIFICATES,
    MAX_ERROR_CHARACTERS,
    MAX_SUBJECT_CHARACTERS,
    MAX_WORKER_OUTPUT,
    AuthenticodeIntegrityState,
    AuthenticodeResult,
    CertificateTableFacts,
    WinCertificateFacts,
    verify_authenticode,
    worker_result_payload,
)
from isopropyl.authenticode_worker import (
    _OSCRYPTO_LIBRESSL_VERSION_PATTERN,
    _OSCRYPTO_SUFFIX_PATTERN,
    _OSCRYPTO_VERSION_PATTERN,
    _REQUIRED_BACKEND_VERSIONS,
    _run_with_oscrypto_version_compatibility,
    verify_descriptor,
)
from isopropyl.uefi import SignatureTableState, inspect_pe_bytes


FINGERPRINT = "a" * 64


def worker_payload(
    state: AuthenticodeIntegrityState = AuthenticodeIntegrityState.VALID_UNTRUSTED,
) -> bytes:
    if state is AuthenticodeIntegrityState.VALID_UNTRUSTED:
        result = AuthenticodeResult(
            state,
            digest_algorithm="sha256",
            signer_subject="CN=ISOpropyl Test",
            signer_sha256=FINGERPRINT,
            certificate_count=1,
        )
    else:
        result = AuthenticodeResult(state, error="fixture failure")
    return worker_result_payload(result)


def preflight_fixture(
    payload: bytes = b"synthetic-pkcs7",
) -> tuple[bytes, CertificateTableFacts]:
    offset = 8
    length = 8 + len(payload)
    table_size = (length + 7) & ~7
    certificate = struct.pack("<IHH", length, 0x0200, 0x0002) + payload
    blob = b"P" * offset + certificate + b"\0" * (table_size - length)
    facts = CertificateTableFacts(
        offset,
        table_size,
        (WinCertificateFacts(offset, length, 0x0200, 0x0002),),
    )
    return blob, facts


def make_minimal_pe(certificate: bytes | None = None) -> bytes:
    """Create the small sectionless PE32+ EFI application accepted by sbsign."""

    pe_offset = 0x80
    optional_size = 0xF0
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into(
        "<HHIIIHH", data, coff,
        0x8664, 0, 0, 0, 0, optional_size, 0x2022,
    )
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<Q", data, optional + 24, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x1000)
    struct.pack_into("<I", data, optional + 60, 0x400)
    struct.pack_into("<H", data, optional + 68, 10)
    struct.pack_into("<Q", data, optional + 72, 0x100000)
    struct.pack_into("<Q", data, optional + 80, 0x1000)
    struct.pack_into("<Q", data, optional + 88, 0x100000)
    struct.pack_into("<Q", data, optional + 96, 0x1000)
    struct.pack_into("<I", data, optional + 108, 16)
    if certificate is not None:
        offset = len(data)
        data.extend(certificate)
        directories = optional + 112
        struct.pack_into("<II", data, directories + 4 * 8, offset, len(certificate))
    return bytes(data)


class FakeProcess:
    """Selector-compatible process double backed by a local socket pair."""

    def __init__(
        self,
        output: bytes | None,
        *,
        returncode: int = 0,
        wait_never_exits: bool = False,
    ) -> None:
        reader, writer = socket.socketpair()
        self._writer_socket: socket.socket | None = writer
        self.stdout = reader.makefile("rb", buffering=0)
        reader.close()
        self.returncode: int | None = None if output is None else returncode
        self.final_returncode = returncode
        self.wait_never_exits = wait_never_exits
        self.terminate_calls = 0
        self.kill_calls = 0
        self.wait_calls = 0
        if output is not None:
            writer.sendall(output)
            writer.shutdown(socket.SHUT_WR)
            writer.close()
            self._writer_socket = None

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminate_calls += 1
        self.returncode = self.final_returncode
        self._close_writer()

    def kill(self) -> None:
        self.kill_calls += 1
        self.returncode = self.final_returncode
        self.wait_never_exits = False
        self._close_writer()

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        if self.wait_never_exits:
            raise subprocess.TimeoutExpired("authenticode-worker", timeout)
        if self.returncode is None:
            raise subprocess.TimeoutExpired("authenticode-worker", timeout)
        return self.returncode

    def _close_writer(self) -> None:
        if self._writer_socket is not None:
            self._writer_socket.close()
            self._writer_socket = None


class AuthenticodePreflightTests(unittest.TestCase):
    def test_fact_types_reject_booleans_negative_values_and_non_tuples(self):
        for value in (True, -1, 1.5, "1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                WinCertificateFacts(value, 16, 0x0200, 0x0002)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            CertificateTableFacts(8, 16, [])  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            CertificateTableFacts(8, 16, (object(),))  # type: ignore[arg-type]

    def test_non_bytes_missing_facts_and_empty_images_fail_without_worker(self):
        blob, facts = preflight_fixture()
        runner = Mock(return_value=worker_payload())
        cases = (
            (object(), facts, "bytes"),
            (blob, object(), "facts"),
            (b"", facts, "empty"),
        )
        for value, supplied_facts, message in cases:
            with self.subTest(message=message):
                result = verify_authenticode(  # type: ignore[arg-type]
                    value, supplied_facts, worker_runner=runner,
                )
                self.assertEqual(result.state, AuthenticodeIntegrityState.MALFORMED)
                self.assertIn(message, result.error.casefold())
        runner.assert_not_called()

    def test_bytearray_and_memoryview_are_frozen_before_worker(self):
        blob, facts = preflight_fixture()
        observed: list[bytes] = []

        def runner(value: bytes, _facts: CertificateTableFacts) -> bytes:
            observed.append(value)
            self.assertIsInstance(value, bytes)
            return worker_payload()

        for value in (bytearray(blob), memoryview(blob)):
            with self.subTest(type=type(value).__name__):
                result = verify_authenticode(value, facts, worker_runner=runner)
                self.assertTrue(result.integrity_valid)
        self.assertEqual(observed, [blob, blob])

    def test_size_and_pkcs7_limits_fail_before_worker(self):
        blob, facts = preflight_fixture(b"12345678")
        runner = Mock(return_value=worker_payload())
        with patch("isopropyl.authenticode.MAX_PE_SIZE", len(blob) - 1):
            result = verify_authenticode(blob, facts, worker_runner=runner)
        self.assertEqual(result.state, AuthenticodeIntegrityState.UNSUPPORTED)
        self.assertIn("PE image exceeds", result.error)

        with patch("isopropyl.authenticode.MAX_PKCS7_SIZE", 7):
            result = verify_authenticode(blob, facts, worker_runner=runner)
        self.assertEqual(result.state, AuthenticodeIntegrityState.UNSUPPORTED)
        self.assertIn("PKCS#7 payload exceeds", result.error)
        runner.assert_not_called()

    def test_entry_count_revision_and_type_are_strict(self):
        blob, facts = preflight_fixture()
        entry = facts.entries[0]
        cases = (
            (
                CertificateTableFacts(facts.file_offset, facts.size, ()),
                "exactly one", AuthenticodeIntegrityState.UNSUPPORTED,
            ),
            (
                CertificateTableFacts(facts.file_offset, facts.size, (entry, entry)),
                "exactly one", AuthenticodeIntegrityState.UNSUPPORTED,
            ),
            (
                CertificateTableFacts(
                    facts.file_offset, facts.size,
                    (WinCertificateFacts(entry.file_offset, entry.length, 0x0100, 2),),
                ),
                "revision 2.0", AuthenticodeIntegrityState.UNSUPPORTED,
            ),
            (
                CertificateTableFacts(
                    facts.file_offset, facts.size,
                    (WinCertificateFacts(entry.file_offset, entry.length, 0x0200, 1),),
                ),
                "revision 2.0", AuthenticodeIntegrityState.UNSUPPORTED,
            ),
        )
        runner = Mock(return_value=worker_payload())
        for changed, message, state in cases:
            with self.subTest(message=message, entries=len(changed.entries)):
                result = verify_authenticode(blob, changed, worker_runner=runner)
                self.assertEqual(result.state, state)
                self.assertIn(message, result.error)
        runner.assert_not_called()

    def test_alignment_header_length_table_size_and_bounds_are_strict(self):
        blob, facts = preflight_fixture()
        entry = facts.entries[0]
        cases = (
            CertificateTableFacts(
                9, facts.size, (WinCertificateFacts(9, entry.length, 0x0200, 2),),
            ),
            CertificateTableFacts(
                facts.file_offset, facts.size,
                (WinCertificateFacts(16, entry.length, 0x0200, 2),),
            ),
            CertificateTableFacts(
                facts.file_offset, 8,
                (WinCertificateFacts(entry.file_offset, 8, 0x0200, 2),),
            ),
            CertificateTableFacts(
                facts.file_offset, facts.size - 8, (entry,),
            ),
            CertificateTableFacts(
                len(blob), facts.size,
                (WinCertificateFacts(len(blob), entry.length, 0x0200, 2),),
            ),
        )
        runner = Mock(return_value=worker_payload())
        for changed in cases:
            with self.subTest(facts=changed):
                result = verify_authenticode(blob, changed, worker_runner=runner)
                self.assertEqual(result.state, AuthenticodeIntegrityState.MALFORMED)
        runner.assert_not_called()


class WorkerProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.blob, self.facts = preflight_fixture()
        self.document = json.loads(worker_payload().decode("ascii"))

    def verify_document(self, document: object) -> AuthenticodeResult:
        payload = json.dumps(document).encode("utf-8")
        return verify_authenticode(
            self.blob, self.facts, worker_runner=lambda _blob, _facts: payload,
        )

    def test_exact_valid_protocol_is_accepted_and_never_claims_trust(self):
        self.document["signer_sha256"] = FINGERPRINT.upper()
        result = self.verify_document(self.document)
        self.assertEqual(result.state, AuthenticodeIntegrityState.VALID_UNTRUSTED)
        self.assertTrue(result.integrity_valid)
        self.assertEqual(result.signer_sha256, FINGERPRINT)
        self.assertFalse(result.trust_evaluated)
        self.assertFalse(result.revocation_evaluated)
        self.assertFalse(result.timestamp_evaluated)

    def test_schema_keys_version_state_text_count_and_flags_are_strict(self):
        mutations = {
            "missing key": lambda value: value.pop("error"),
            "extra key": lambda value: value.update(extra="value"),
            "schema version": lambda value: value.update(schema=2),
            "state": lambda value: value.update(state="trusted"),
            "digest text": lambda value: value.update(digest_algorithm=12),
            "subject text": lambda value: value.update(signer_subject=[]),
            "fingerprint text": lambda value: value.update(signer_sha256=None),
            "error text": lambda value: value.update(error={}),
            "boolean count": lambda value: value.update(certificate_count=True),
            "large count": lambda value: value.update(
                certificate_count=MAX_CERTIFICATES + 1,
            ),
            "trust flag": lambda value: value.update(trust_evaluated=True),
            "revocation flag": lambda value: value.update(revocation_evaluated=0),
            "timestamp flag": lambda value: value.update(timestamp_evaluated=None),
            "weak digest": lambda value: value.update(digest_algorithm="sha1"),
            "short fingerprint": lambda value: value.update(signer_sha256="ab"),
            "valid with error": lambda value: value.update(error="not actually valid"),
            "valid without subject": lambda value: value.update(signer_subject=""),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                changed = dict(self.document)
                mutate(changed)
                result = self.verify_document(changed)
                self.assertEqual(
                    result.state, AuthenticodeIntegrityState.INDETERMINATE,
                )
                self.assertFalse(result.integrity_valid)
                self.assertFalse(result.trust_evaluated)

    def test_empty_oversized_non_utf8_and_malformed_json_are_indeterminate(self):
        payloads = (
            b"",
            b"x" * (MAX_WORKER_OUTPUT + 1),
            b"\xff",
            b"{",
            b"[]",
        )
        for payload in payloads:
            with self.subTest(length=len(payload)):
                result = verify_authenticode(
                    self.blob, self.facts,
                    worker_runner=lambda _blob, _facts, p=payload: p,
                )
                self.assertEqual(
                    result.state, AuthenticodeIntegrityState.INDETERMINATE,
                )

    def test_untrusted_text_is_sanitized_and_bounded(self):
        document = dict(self.document)
        document.update(
            state=AuthenticodeIntegrityState.INVALID.value,
            digest_algorithm="",
            signer_subject="  CN=Alice\n\t\x00  " + "S" * 400,
            signer_sha256="",
            certificate_count=0,
            error="  bad\r\n\t\x00  " + "E" * 700,
        )
        result = self.verify_document(document)
        self.assertEqual(result.state, AuthenticodeIntegrityState.INVALID)
        self.assertLessEqual(len(result.signer_subject), MAX_SUBJECT_CHARACTERS)
        self.assertLessEqual(len(result.error), MAX_ERROR_CHARACTERS)
        for character in "\r\n\t\x00":
            self.assertNotIn(character, result.signer_subject)
            self.assertNotIn(character, result.error)
        self.assertTrue(result.signer_subject.startswith("CN=Alice"))
        self.assertTrue(result.error.startswith("bad"))
        self.assertFalse(result.trust_evaluated)
        self.assertFalse(result.revocation_evaluated)
        self.assertFalse(result.timestamp_evaluated)

    def test_result_model_rejects_all_external_trust_claims(self):
        for field in (
            "trust_evaluated", "revocation_evaluated", "timestamp_evaluated",
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                AuthenticodeResult(
                    AuthenticodeIntegrityState.INVALID, **{field: True},
                )

    def test_worker_encoder_always_emits_exact_nontrust_schema(self):
        payload = worker_result_payload(AuthenticodeResult(
            AuthenticodeIntegrityState.INVALID,
            signer_subject="CN=Test\nSubject",
            error="bad\tresult",
        ))
        decoded = json.loads(payload)
        self.assertEqual(
            set(decoded),
            {
                "schema", "state", "digest_algorithm", "signer_subject",
                "signer_sha256", "certificate_count", "error",
                "trust_evaluated", "revocation_evaluated",
                "timestamp_evaluated",
            },
        )
        self.assertIs(decoded["trust_evaluated"], False)
        self.assertIs(decoded["revocation_evaluated"], False)
        self.assertIs(decoded["timestamp_evaluated"], False)
        self.assertNotIn("\n", decoded["signer_subject"])
        self.assertNotIn("\t", decoded["error"])


class OscryptoVersionCompatibilityTests(unittest.TestCase):
    def test_exact_oscrypto_pattern_accepts_multi_digit_components_and_suffix(self):
        observed: dict[str, str | None] = {}
        original_search = re.search
        original_sub = re.sub

        def loader() -> None:
            self.assertIsNot(re.search, original_search)
            self.assertIsNot(re.sub, original_sub)
            versions = {
                "openssl": "OpenSSL 3.0.16 11 Feb 2025",
                "libressl": "LibreSSL 3.10.2",
                "letter suffix": "OpenSSL 1.1.1w 11 Sep 2023",
            }
            for label, value in versions.items():
                match = re.search(_OSCRYPTO_VERSION_PATTERN, value)
                observed[label] = match.group(1) if match is not None else None

            unrelated = re.search(r"product=(\S+)", "product=3.0.16")
            observed["unrelated"] = (
                unrelated.group(1) if unrelated is not None else None
            )
            observed["flagged exact"] = str(
                re.search(_OSCRYPTO_VERSION_PATTERN, versions["openssl"], re.ASCII)
            )
            two_part = re.search(
                _OSCRYPTO_LIBRESSL_VERSION_PATTERN, "LibreSSL 3.10",
            )
            observed["two-part libressl"] = (
                two_part.group(1) if two_part is not None else None
            )
            observed["suffix split"] = re.sub(
                _OSCRYPTO_SUFFIX_PATTERN, r"\1.\2", "1.1.10a",
            )

        _run_with_oscrypto_version_compatibility(loader)

        self.assertIs(re.search, original_search)
        self.assertIs(re.sub, original_sub)
        self.assertEqual(observed, {
            "openssl": "3.0.16",
            "libressl": "3.10.2",
            "letter suffix": "1.1.1w",
            "unrelated": "3.0.16",
            "flagged exact": "None",
            "two-part libressl": "3.10",
            "suffix split": "1.1.10.a",
        })

    def test_regex_function_is_restored_when_backend_load_fails(self):
        original_search = re.search
        original_sub = re.sub

        def failed_loader() -> None:
            raise RuntimeError("fixture backend import failed")

        with self.assertRaisesRegex(RuntimeError, "backend import failed"):
            _run_with_oscrypto_version_compatibility(failed_loader)
        self.assertIs(re.search, original_search)
        self.assertIs(re.sub, original_sub)


class WorkerProcessTests(unittest.TestCase):
    def test_cancellation_stops_and_reaps_worker(self):
        process = FakeProcess(None)

        def cancelled() -> None:
            raise RuntimeError("fixture cancelled")

        with self.assertRaises(authenticode._CancellationRaised) as raised:
            authenticode._collect_worker_output(
                process, timeout=1.0, cancel_check=cancelled,
            )  # type: ignore[arg-type]
        self.assertIsInstance(raised.exception.reason, RuntimeError)
        self.assertIn("fixture cancelled", str(raised.exception.reason))
        self.assertEqual(process.terminate_calls, 1)
        self.assertGreaterEqual(process.wait_calls, 1)

    def test_public_boundary_preserves_oserror_deadline_from_worker_callback(self):
        blob, facts = preflight_fixture()
        process = FakeProcess(None)
        checks = 0

        def deadline() -> None:
            nonlocal checks
            checks += 1
            if checks > 1:
                raise OSError("fixture top-level deadline")

        with (
            patch("isopropyl.authenticode.subprocess.Popen", return_value=process),
            self.assertRaisesRegex(OSError, "top-level deadline"),
        ):
            verify_authenticode(blob, facts, cancel_check=deadline)
        self.assertEqual(process.terminate_calls, 1)
        self.assertGreaterEqual(process.wait_calls, 1)

    def test_timeout_terminates_and_reaps_worker(self):
        process = FakeProcess(None)
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            authenticode._collect_worker_output(process, timeout=0.01)  # type: ignore[arg-type]
        self.assertEqual(process.terminate_calls, 1)
        self.assertGreaterEqual(process.wait_calls, 1)

    def test_oversized_output_stops_worker(self):
        process = FakeProcess(b"x" * (MAX_WORKER_OUTPUT + 1))
        with self.assertRaisesRegex(RuntimeError, "too much output"):
            authenticode._collect_worker_output(process)  # type: ignore[arg-type]
        self.assertGreaterEqual(process.wait_calls, 1)

    def test_nonzero_exit_and_missing_pipe_are_failures(self):
        crashed = FakeProcess(b"", returncode=9)
        with self.assertRaisesRegex(RuntimeError, "worker failed"):
            authenticode._collect_worker_output(crashed)  # type: ignore[arg-type]

        missing = Mock()
        missing.stdout = None
        missing.poll.return_value = 1
        missing.wait.return_value = 1
        with self.assertRaisesRegex(RuntimeError, "no output pipe"):
            authenticode._collect_worker_output(missing)

    def test_worker_that_closes_output_but_does_not_exit_is_stopped(self):
        process = FakeProcess(b"", wait_never_exits=True)
        process.returncode = None
        with self.assertRaisesRegex(RuntimeError, "did not exit"):
            authenticode._collect_worker_output(process, timeout=0.05)  # type: ignore[arg-type]
        self.assertGreaterEqual(process.terminate_calls, 1)
        self.assertEqual(process.kill_calls, 1)

    def test_public_boundary_normalizes_runner_start_and_crash_errors(self):
        blob, facts = preflight_fixture()
        errors = (
            OSError("unsafe\nstart\t" + "x" * 700),
            subprocess.SubprocessError("worker crashed"),
        )
        for error in errors:
            with self.subTest(type=type(error).__name__):
                result = verify_authenticode(
                    blob, facts,
                    worker_runner=Mock(side_effect=error),
                )
                self.assertEqual(
                    result.state, AuthenticodeIntegrityState.INDETERMINATE,
                )
                self.assertLessEqual(len(result.error), MAX_ERROR_CHARACTERS)
                self.assertNotIn("\n", result.error)
                self.assertNotIn("\t", result.error)
                self.assertFalse(result.integrity_valid)

    def test_parent_launches_exact_isolated_seven_argument_worker_protocol(self):
        blob, facts = preflight_fixture()
        captured: dict[str, object] = {}
        process = FakeProcess(worker_payload(AuthenticodeIntegrityState.INVALID))

        def popen(command, **kwargs):
            captured["command"] = command
            captured["kwargs"] = kwargs
            return process

        result = authenticode._run_worker(blob, facts, popen=popen)
        self.assertEqual(
            authenticode._decode_worker_result(result).state,
            AuthenticodeIntegrityState.INVALID,
        )
        command = captured["command"]
        assert isinstance(command, list)
        self.assertEqual(
            command[:5],
            [
                authenticode.sys.executable,
                "-I", "-c", authenticode._WORKER_BOOTSTRAP,
                os.path.dirname(os.path.dirname(os.path.realpath(authenticode.__file__))),
            ],
        )
        arguments = command[5:]
        self.assertEqual(len(arguments), 7)
        self.assertEqual(
            arguments[1:],
            [
                str(len(blob)), str(facts.file_offset), str(facts.size),
                str(facts.entries[0].length),
                str(facts.entries[0].revision),
                str(facts.entries[0].certificate_type),
            ],
        )
        kwargs = captured["kwargs"]
        assert isinstance(kwargs, dict)
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["close_fds"], True)
        self.assertEqual(kwargs["env"], {
            "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
        })
        self.assertEqual(len(kwargs["pass_fds"]), 1)

    @unittest.skipUnless(hasattr(os, "memfd_create"), "Linux memfd is required")
    def test_sealed_transfer_handles_short_writes_and_cannot_be_modified(self):
        real_write = os.write

        def short_write(descriptor: int, value: bytes | memoryview) -> int:
            return real_write(descriptor, value[:3])

        with patch("isopropyl.authenticode.os.write", side_effect=short_write):
            descriptor = authenticode._sealed_memfd(b"sealed fixture bytes")
        try:
            self.assertEqual(os.pread(descriptor, 64, 0), b"sealed fixture bytes")
            with self.assertRaises(OSError):
                os.write(descriptor, b"tamper")
        finally:
            os.close(descriptor)

    def test_worker_structural_preflight_rejects_directory_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                result = verify_descriptor(
                    descriptor, 1, 0, 16, 16, 0x0200, 0x0002,
                )
            finally:
                os.close(descriptor)
        self.assertEqual(result.state, AuthenticodeIntegrityState.MALFORMED)
        self.assertIn("wrong type or size", result.error)


class GeneratedSignedPeTests(unittest.TestCase):
    @staticmethod
    def _available() -> bool:
        if not all(shutil.which(tool) for tool in ("openssl", "sbsign")):
            return False
        try:
            for name, expected in _REQUIRED_BACKEND_VERSIONS.items():
                if importlib.metadata.version(name) != expected:
                    return False
        except importlib.metadata.PackageNotFoundError:
            return False
        expected_versions = repr(_REQUIRED_BACKEND_VERSIONS)
        isolated = subprocess.run(
            [
                sys.executable, "-I", "-c",
                "import importlib.metadata as m;"
                f"v={expected_versions};"
                "raise SystemExit(any(m.version(n)!=x for n,x in v.items()))",
            ],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=5, check=False, shell=False,
        )
        return isolated.returncode == 0

    def test_dynamically_signed_pe_verifies_integrity_but_never_trust(self):
        if not self._available():
            if os.environ.get("ISOPROPYL_REQUIRE_AUTHENTICODE_FIXTURE") == "1":
                self.fail("CI requires the pinned Authenticode backend and signing tools")
            self.skipTest("requires signing tools and the pinned Authenticode backend")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned = root / "unsigned.efi"
            key = root / "key.pem"
            certificate = root / "certificate.pem"
            signed = root / "signed.efi"
            unsigned.write_bytes(make_minimal_pe())
            subprocess.run(
                [
                    shutil.which("openssl") or "/usr/bin/openssl",
                    "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(certificate), "-days", "2",
                    "-subj", "/CN=ISOpropyl Authenticode Test/",
                    "-addext", "basicConstraints=critical,CA:FALSE",
                    "-addext", "extendedKeyUsage=codeSigning",
                    "-addext", "keyUsage=critical,digitalSignature",
                ],
                check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, timeout=15, shell=False,
            )
            subprocess.run(
                [
                    shutil.which("sbsign") or "/usr/bin/sbsign",
                    "--key", str(key), "--cert", str(certificate),
                    "--output", str(signed), str(unsigned),
                ],
                check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, timeout=15, shell=False,
            )
            blob = signed.read_bytes()

        inspection = inspect_pe_bytes(blob)
        self.assertEqual(
            inspection.certificate_table.state,
            SignatureTableState.PRESENT_UNVERIFIED,
        )
        self.assertEqual(len(inspection.certificate_table.entries), 1)
        entry = inspection.certificate_table.entries[0]
        facts = CertificateTableFacts(
            inspection.certificate_table.file_offset,
            inspection.certificate_table.size,
            (WinCertificateFacts(
                entry.file_offset, entry.length, entry.revision,
                entry.certificate_type,
            ),),
        )
        result = verify_authenticode(blob, facts)
        self.assertEqual(result.state, AuthenticodeIntegrityState.VALID_UNTRUSTED)
        self.assertTrue(result.integrity_valid)
        self.assertEqual(result.digest_algorithm, "sha256")
        self.assertIn("ISOpropyl Authenticode Test", result.signer_subject)
        self.assertGreaterEqual(result.certificate_count, 1)
        self.assertFalse(result.trust_evaluated)
        self.assertFalse(result.revocation_evaluated)
        self.assertFalse(result.timestamp_evaluated)

        tampered = bytearray(blob)
        tampered[0x40] ^= 1
        invalid = verify_authenticode(tampered, facts)
        self.assertEqual(invalid.state, AuthenticodeIntegrityState.INVALID)
        self.assertFalse(invalid.integrity_valid)


if __name__ == "__main__":
    unittest.main()
