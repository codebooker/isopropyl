from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bounded, read-only Authenticode integrity verification.

This module deliberately has no dependency on :mod:`isopropyl.uefi`.  A caller
supplies the certificate-table facts it has already established structurally.
The cryptographic worker verifies integrity with an ephemeral store containing
only certificates embedded in the signature.  A successful result therefore
means ``VALID_UNTRUSTED``; it never means Microsoft, firmware, or revocation
trust.
"""

import enum
import fcntl
import json
import os
import re
import selectors
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO


MAX_PE_SIZE = 256 * 1024 * 1024
MAX_PKCS7_SIZE = 8 * 1024 * 1024
MAX_CERTIFICATES = 32
MAX_WORKER_OUTPUT = 16 * 1024
WORKER_TIMEOUT_SECONDS = 8.0
WORKER_STOP_SECONDS = 0.5
MAX_SUBJECT_CHARACTERS = 256
MAX_ERROR_CHARACTERS = 512
_PROTOCOL_SCHEMA = 1
_ALLOWED_DIGESTS = frozenset({"sha256", "sha384", "sha512"})
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")
_MFD_CLOEXEC = getattr(os, "MFD_CLOEXEC", 0x0001)
_MFD_ALLOW_SEALING = getattr(os, "MFD_ALLOW_SEALING", 0x0002)
_F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
_F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
_F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
_F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
_F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
_F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
_WORKER_BOOTSTRAP = (
    "import runpy,sys;"
    "sys.path.insert(0,sys.argv.pop(1));"
    "runpy.run_module('isopropyl.authenticode_worker',"
    "run_name='__main__',alter_sys=True)"
)


class AuthenticodeIntegrityState(enum.Enum):
    VALID_UNTRUSTED = "integrity-valid-untrusted"
    INVALID = "invalid"
    MALFORMED = "malformed"
    UNSUPPORTED = "unsupported"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class WinCertificateFacts:
    file_offset: int
    length: int
    revision: int
    certificate_type: int

    def __post_init__(self) -> None:
        for value in (
            self.file_offset, self.length, self.revision, self.certificate_type,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("WIN_CERTIFICATE facts must be non-negative integers")


@dataclass(frozen=True)
class CertificateTableFacts:
    file_offset: int
    size: int
    entries: tuple[WinCertificateFacts, ...]

    def __post_init__(self) -> None:
        if (
            isinstance(self.file_offset, bool)
            or not isinstance(self.file_offset, int)
            or self.file_offset < 0
            or isinstance(self.size, bool)
            or not isinstance(self.size, int)
            or self.size < 0
            or not isinstance(self.entries, tuple)
            or any(not isinstance(item, WinCertificateFacts) for item in self.entries)
        ):
            raise ValueError("certificate-table facts are invalid")


@dataclass(frozen=True)
class AuthenticodeResult:
    state: AuthenticodeIntegrityState
    digest_algorithm: str = ""
    signer_subject: str = ""
    signer_sha256: str = ""
    certificate_count: int = 0
    error: str = ""
    trust_evaluated: bool = False
    revocation_evaluated: bool = False
    timestamp_evaluated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.state, AuthenticodeIntegrityState):
            raise ValueError("invalid Authenticode result state")
        if self.trust_evaluated or self.revocation_evaluated or self.timestamp_evaluated:
            raise ValueError("this backend never establishes trust, revocation, or timestamp validity")
        if (
            isinstance(self.certificate_count, bool)
            or not isinstance(self.certificate_count, int)
            or not 0 <= self.certificate_count <= MAX_CERTIFICATES
        ):
            raise ValueError("invalid Authenticode certificate count")
        if len(self.signer_subject) > MAX_SUBJECT_CHARACTERS:
            raise ValueError("AuthentiCode signer subject is too long")
        if len(self.error) > MAX_ERROR_CHARACTERS:
            raise ValueError("AuthentiCode error is too long")
        if self.digest_algorithm and self.digest_algorithm not in _ALLOWED_DIGESTS:
            raise ValueError("invalid Authenticode digest algorithm")
        if self.signer_sha256 and _FINGERPRINT.fullmatch(self.signer_sha256) is None:
            raise ValueError("invalid signer certificate fingerprint")
        if self.state is AuthenticodeIntegrityState.VALID_UNTRUSTED and (
            self.digest_algorithm not in _ALLOWED_DIGESTS
            or not self.signer_subject
            or _FINGERPRINT.fullmatch(self.signer_sha256) is None
            or self.certificate_count < 1
            or self.error
        ):
            raise ValueError("an integrity-valid result is incomplete")

    @property
    def integrity_valid(self) -> bool:
        return self.state is AuthenticodeIntegrityState.VALID_UNTRUSTED


class _WorkerFailure(RuntimeError):
    pass


class _CancellationRaised(BaseException):
    def __init__(self, reason: BaseException) -> None:
        self.reason = reason
        super().__init__(str(reason))


WorkerRunner = Callable[[bytes, CertificateTableFacts], bytes]
PopenFactory = Callable[..., subprocess.Popen[bytes]]
CancelCheck = Callable[[], None]


def _sanitize(value: object, limit: int) -> str:
    text = str(value or "")
    text = "".join(
        character if character.isprintable() and character not in "\r\n\t" else " "
        for character in text
    )
    return " ".join(text.split())[:limit]


def _failure(state: AuthenticodeIntegrityState, error: object) -> AuthenticodeResult:
    return AuthenticodeResult(state, error=_sanitize(error, MAX_ERROR_CHARACTERS))


def _check_worker_cancellation(cancel_check: CancelCheck | None) -> None:
    if cancel_check is None:
        return
    try:
        cancel_check()
    except BaseException as error:
        # Preserve cancellation/deadline exception identity across worker cleanup,
        # including OSError-derived top-level inspection deadlines.
        raise _CancellationRaised(error) from error


def _preflight(
    blob: bytes, facts: CertificateTableFacts,
) -> AuthenticodeResult | WinCertificateFacts:
    if not blob:
        return _failure(AuthenticodeIntegrityState.MALFORMED, "the PE image is empty")
    if len(blob) > MAX_PE_SIZE:
        return _failure(
            AuthenticodeIntegrityState.UNSUPPORTED,
            f"the PE image exceeds the {MAX_PE_SIZE}-byte verification limit",
        )
    if len(facts.entries) != 1:
        return _failure(
            AuthenticodeIntegrityState.UNSUPPORTED,
            "exactly one embedded WIN_CERTIFICATE entry is required",
        )
    entry = facts.entries[0]
    if entry.revision != 0x0200 or entry.certificate_type != 0x0002:
        return _failure(
            AuthenticodeIntegrityState.UNSUPPORTED,
            "only WIN_CERTIFICATE revision 2.0 PKCS#7 signed data is supported",
        )
    if facts.file_offset % 8 or entry.file_offset != facts.file_offset:
        return _failure(
            AuthenticodeIntegrityState.MALFORMED,
            "the certificate table is not correctly aligned or bound",
        )
    if entry.length <= 8:
        return _failure(
            AuthenticodeIntegrityState.MALFORMED,
            "WIN_CERTIFICATE does not contain PKCS#7 data",
        )
    aligned_length = (entry.length + 7) & ~7
    if facts.size != aligned_length:
        return _failure(
            AuthenticodeIntegrityState.MALFORMED,
            "the certificate table does not contain exactly one complete entry",
        )
    if (
        facts.file_offset > len(blob)
        or facts.size > len(blob) - facts.file_offset
    ):
        return _failure(
            AuthenticodeIntegrityState.MALFORMED,
            "the certificate table extends beyond the PE image",
        )
    if entry.length - 8 > MAX_PKCS7_SIZE:
        return _failure(
            AuthenticodeIntegrityState.UNSUPPORTED,
            f"the PKCS#7 payload exceeds the {MAX_PKCS7_SIZE}-byte limit",
        )
    return entry


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("the sealed PE transfer made no progress")
        view = view[written:]


def _sealed_memfd(blob: bytes) -> int:
    flags = _MFD_CLOEXEC | _MFD_ALLOW_SEALING
    descriptor = os.memfd_create("isopropyl-authenticode", flags)
    try:
        _write_all(descriptor, blob)
        os.lseek(descriptor, 0, os.SEEK_SET)
        seals = _F_SEAL_SEAL | _F_SEAL_SHRINK | _F_SEAL_GROW | _F_SEAL_WRITE
        fcntl.fcntl(descriptor, _F_ADD_SEALS, seals)
        if fcntl.fcntl(descriptor, _F_GET_SEALS) & seals != seals:
            raise OSError("sealed memory files are unavailable")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _stop_worker(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        try:
            process.wait(timeout=WORKER_STOP_SECONDS)
        except (OSError, subprocess.SubprocessError):
            pass
        return
    try:
        process.terminate()
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=WORKER_STOP_SECONDS)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        process.kill()
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=WORKER_STOP_SECONDS)
    except (OSError, subprocess.SubprocessError):
        pass


def _collect_worker_output(
    process: subprocess.Popen[bytes], *, timeout: float = WORKER_TIMEOUT_SECONDS,
    cancel_check: CancelCheck | None = None,
) -> bytes:
    if not 0 < timeout <= WORKER_TIMEOUT_SECONDS:
        _stop_worker(process)
        raise _WorkerFailure("the Authenticode worker timeout is outside policy")
    if process.stdout is None:
        _stop_worker(process)
        raise _WorkerFailure("the Authenticode worker has no output pipe")
    deadline = time.monotonic() + timeout
    output = bytearray()
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            _check_worker_cancellation(cancel_check)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_worker(process)
                raise _WorkerFailure("the Authenticode worker timed out")
            events = selector.select(min(remaining, 0.1))
            if not events:
                if process.poll() is None:
                    continue
                # The direct worker exited.  A pipe that is still open without
                # readable data may be inherited by an unexpected descendant;
                # never issue a blocking read in that state.
                raise _WorkerFailure(
                    "the Authenticode worker left its output pipe open"
                )
            block = os.read(process.stdout.fileno(), 4096)
            if not block:
                break
            output.extend(block)
            if len(output) > MAX_WORKER_OUTPUT:
                _stop_worker(process)
                raise _WorkerFailure("the Authenticode worker produced too much output")
        _check_worker_cancellation(cancel_check)
        try:
            returncode = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            _stop_worker(process)
            raise _WorkerFailure("the Authenticode worker did not exit") from error
        if returncode != 0:
            raise _WorkerFailure("the Authenticode worker failed")
        return bytes(output)
    except BaseException:
        _stop_worker(process)
        raise
    finally:
        selector.close()
        try:
            process.stdout.close()
        except OSError:
            pass


def _run_worker(
    blob: bytes,
    facts: CertificateTableFacts,
    *,
    timeout: float = WORKER_TIMEOUT_SECONDS,
    cancel_check: CancelCheck | None = None,
    popen: PopenFactory | None = None,
) -> bytes:
    descriptor = _sealed_memfd(blob)
    entry = facts.entries[0]
    package_parent = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    command = [
        sys.executable,
        "-I",
        "-c",
        _WORKER_BOOTSTRAP,
        package_parent,
        str(descriptor),
        str(len(blob)),
        str(facts.file_offset),
        str(facts.size),
        str(entry.length),
        str(entry.revision),
        str(entry.certificate_type),
    ]
    try:
        try:
            process = (popen or subprocess.Popen)(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
                pass_fds=(descriptor,),
                env={
                    "PATH": "/usr/bin:/bin",
                    "LC_ALL": "C",
                    "LANG": "C",
                },
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise _WorkerFailure("the Authenticode worker could not start") from error
        return _collect_worker_output(
            process, timeout=timeout, cancel_check=cancel_check,
        )
    finally:
        os.close(descriptor)


def _decode_worker_result(payload: bytes) -> AuthenticodeResult:
    if not payload or len(payload) > MAX_WORKER_OUTPUT:
        raise _WorkerFailure("the Authenticode worker returned invalid output")
    try:
        decoded = json.loads(payload.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise _WorkerFailure("the Authenticode worker returned malformed JSON") from error
    expected_keys = {
        "schema", "state", "digest_algorithm", "signer_subject",
        "signer_sha256", "certificate_count", "error", "trust_evaluated",
        "revocation_evaluated", "timestamp_evaluated",
    }
    if not isinstance(decoded, dict) or set(decoded) != expected_keys:
        raise _WorkerFailure("the Authenticode worker returned an unexpected schema")
    if decoded.get("schema") != _PROTOCOL_SCHEMA:
        raise _WorkerFailure("the Authenticode worker returned an unsupported schema")
    try:
        state = AuthenticodeIntegrityState(decoded["state"])
    except (TypeError, ValueError) as error:
        raise _WorkerFailure("the Authenticode worker returned an invalid state") from error
    for key in ("digest_algorithm", "signer_subject", "signer_sha256", "error"):
        if not isinstance(decoded[key], str):
            raise _WorkerFailure("the Authenticode worker returned invalid text")
    if (
        isinstance(decoded["certificate_count"], bool)
        or not isinstance(decoded["certificate_count"], int)
        or not all(
            isinstance(decoded[key], bool) and decoded[key] is False
            for key in ("trust_evaluated", "revocation_evaluated", "timestamp_evaluated")
        )
    ):
        raise _WorkerFailure("the Authenticode worker returned invalid safety flags")
    try:
        return AuthenticodeResult(
            state=state,
            digest_algorithm=decoded["digest_algorithm"],
            signer_subject=_sanitize(decoded["signer_subject"], MAX_SUBJECT_CHARACTERS),
            signer_sha256=decoded["signer_sha256"].lower(),
            certificate_count=decoded["certificate_count"],
            error=_sanitize(decoded["error"], MAX_ERROR_CHARACTERS),
            trust_evaluated=False,
            revocation_evaluated=False,
            timestamp_evaluated=False,
        )
    except ValueError as error:
        raise _WorkerFailure("the Authenticode worker result failed validation") from error


def verify_authenticode(
    blob: bytes | bytearray | memoryview,
    facts: CertificateTableFacts,
    *,
    worker_runner: WorkerRunner | None = None,
    timeout: float = WORKER_TIMEOUT_SECONDS,
    cancel_check: CancelCheck | None = None,
) -> AuthenticodeResult:
    """Verify one structurally bound embedded signature without asserting trust."""

    if cancel_check is not None:
        cancel_check()
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        return _failure(AuthenticodeIntegrityState.MALFORMED, "the PE image is not bytes")
    if not isinstance(facts, CertificateTableFacts):
        return _failure(
            AuthenticodeIntegrityState.MALFORMED,
            "structurally validated certificate-table facts are required",
        )
    try:
        byte_length = (
            len(blob) if isinstance(blob, (bytes, bytearray)) else blob.nbytes
        )
    except (TypeError, ValueError):
        return _failure(
            AuthenticodeIntegrityState.MALFORMED,
            "the PE image byte view is unavailable",
        )
    if byte_length > MAX_PE_SIZE:
        return _failure(
            AuthenticodeIntegrityState.UNSUPPORTED,
            f"the PE image exceeds the {MAX_PE_SIZE}-byte verification limit",
        )
    data = bytes(blob)
    checked = _preflight(data, facts)
    if isinstance(checked, AuthenticodeResult):
        return checked
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not (
        0 < timeout <= WORKER_TIMEOUT_SECONDS
    ):
        return _failure(
            AuthenticodeIntegrityState.INDETERMINATE,
            "the Authenticode verification timeout is outside policy",
        )
    try:
        payload = (
            worker_runner(data, facts)
            if worker_runner is not None
            else _run_worker(
                data, facts, timeout=float(timeout), cancel_check=cancel_check,
            )
        )
        result = _decode_worker_result(payload)
    except _CancellationRaised as error:
        raise error.reason
    except _WorkerFailure as error:
        return _failure(AuthenticodeIntegrityState.INDETERMINATE, error)
    except (OSError, subprocess.SubprocessError) as error:
        return _failure(
            AuthenticodeIntegrityState.INDETERMINATE,
            _sanitize(error, MAX_ERROR_CHARACTERS) or "the Authenticode worker failed",
        )
    if cancel_check is not None:
        cancel_check()
    return result


def worker_result_payload(result: AuthenticodeResult) -> bytes:
    """Encode the fixed worker protocol; intended for the isolated worker only."""

    payload = json.dumps(
        {
            "schema": _PROTOCOL_SCHEMA,
            "state": result.state.value,
            "digest_algorithm": result.digest_algorithm,
            "signer_subject": _sanitize(result.signer_subject, MAX_SUBJECT_CHARACTERS),
            "signer_sha256": result.signer_sha256,
            "certificate_count": result.certificate_count,
            "error": _sanitize(result.error, MAX_ERROR_CHARACTERS),
            "trust_evaluated": False,
            "revocation_evaluated": False,
            "timestamp_evaluated": False,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if len(payload) > MAX_WORKER_OUTPUT:
        raise ValueError("encoded Authenticode worker result exceeds its protocol limit")
    return payload
