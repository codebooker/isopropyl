from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Isolated worker for bounded Authenticode integrity verification."""

import datetime
import importlib.metadata
import os
import re
import resource
import stat
import struct
import sys
from collections.abc import Callable
from typing import BinaryIO

from isopropyl.authenticode import (
    MAX_CERTIFICATES,
    MAX_ERROR_CHARACTERS,
    MAX_PE_SIZE,
    MAX_PKCS7_SIZE,
    MAX_SUBJECT_CHARACTERS,
    AuthenticodeIntegrityState,
    AuthenticodeResult,
    worker_result_payload,
)


_ALLOWED_DIGESTS = frozenset({"sha256", "sha384", "sha512"})
_ADDRESS_SPACE_LIMIT = 768 * 1024 * 1024
_CPU_SOFT_LIMIT = 6
_CPU_HARD_LIMIT = 7
_FILE_DESCRIPTOR_LIMIT = 32
_REQUIRED_BACKEND_VERSIONS = {
    "signify": "0.9.2",
    "asn1crypto": "1.5.1",
    "certvalidator": "0.11.1",
    "oscrypto": "1.3.0",
    "mscerts": "2026.7.1",
    "typing_extensions": "4.16.0",
}
_OSCRYPTO_VERSION_PATTERN = r"\b(\d\.\d\.\d[a-z]*)\b"
_OSCRYPTO_COMPATIBLE_VERSION_PATTERN = r"\b(\d+\.\d+\.\d+[a-z]*)\b"
_OSCRYPTO_LIBRESSL_VERSION_PATTERN = r"(?<=LibreSSL )(\d\.\d(\.\d)?)\b"
_OSCRYPTO_COMPATIBLE_LIBRESSL_VERSION_PATTERN = (
    r"(?<=LibreSSL )(\d+\.\d+(\.\d+)?)\b"
)
_OSCRYPTO_SUFFIX_PATTERN = r"(\d)([a-z]+)"
_OSCRYPTO_COMPATIBLE_SUFFIX_PATTERN = r"(\d+)([a-z]+)"


class _Malformed(ValueError):
    pass


class _Unsupported(ValueError):
    pass


class _Invalid(ValueError):
    pass


def _require_backend_versions() -> None:
    try:
        mismatched = tuple(
            name for name, expected in _REQUIRED_BACKEND_VERSIONS.items()
            if importlib.metadata.version(name) != expected
        )
    except importlib.metadata.PackageNotFoundError as error:
        raise _Unsupported("the pinned Authenticode backend is unavailable") from error
    if mismatched:
        raise _Unsupported("the pinned Authenticode backend versions do not match")


def _sanitize(value: object, limit: int) -> str:
    text = str(value or "")
    text = "".join(
        character if character.isprintable() and character not in "\r\n\t" else " "
        for character in text
    )
    return " ".join(text.split())[:limit]


def _set_resource_limits() -> None:
    limits = (
        (resource.RLIMIT_CORE, 0, 0),
        (resource.RLIMIT_CPU, _CPU_SOFT_LIMIT, _CPU_HARD_LIMIT),
        (resource.RLIMIT_AS, _ADDRESS_SPACE_LIMIT, _ADDRESS_SPACE_LIMIT),
        (resource.RLIMIT_FSIZE, 0, 0),
        (resource.RLIMIT_NOFILE, _FILE_DESCRIPTOR_LIMIT, _FILE_DESCRIPTOR_LIMIT),
    )
    for kind, soft, hard in limits:
        _current_soft, current_hard = resource.getrlimit(kind)
        bounded_hard = (
            hard
            if current_hard == resource.RLIM_INFINITY
            else min(hard, current_hard)
        )
        resource.setrlimit(kind, (min(soft, bounded_hard), bounded_hard))
    if hasattr(resource, "RLIMIT_NPROC"):
        # Signify is single-process.  Disallowing descendants also ensures no
        # child can retain the inherited result pipe beyond the worker deadline.
        resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))


def _run_with_oscrypto_version_compatibility(loader: Callable[[], None]) -> None:
    """Run one trusted import with oscrypto 1.3.0's version regex corrected.

    oscrypto 1.3.0 accepts only one digit in each OpenSSL/LibreSSL version
    component. The complete Python backend is version-pinned above, so this
    single-threaded worker can safely widen only that exact zero-flags lookup
    while the trusted crypto backend is imported. The process-wide functions
    are restored before any PE bytes or PKCS#7 structures are parsed.
    """

    original_search = re.search
    original_sub = re.sub
    compatible_search_patterns = {
        _OSCRYPTO_VERSION_PATTERN: _OSCRYPTO_COMPATIBLE_VERSION_PATTERN,
        _OSCRYPTO_LIBRESSL_VERSION_PATTERN:
            _OSCRYPTO_COMPATIBLE_LIBRESSL_VERSION_PATTERN,
    }

    def compatible_search(pattern, string, flags=0):
        if flags == 0:
            pattern = compatible_search_patterns.get(pattern, pattern)
        return original_search(pattern, string, flags)

    def compatible_sub(pattern, repl, string, count=0, flags=0):
        if pattern == _OSCRYPTO_SUFFIX_PATTERN and flags == 0:
            pattern = _OSCRYPTO_COMPATIBLE_SUFFIX_PATTERN
        return original_sub(pattern, repl, string, count=count, flags=flags)

    re.search = compatible_search
    re.sub = compatible_sub
    try:
        loader()
    finally:
        re.search = original_search
        re.sub = original_sub


def _prime_crypto_backend() -> None:
    """Resolve libcrypto before the no-descendant limit is installed.

    oscrypto may use a short-lived host probe while selecting its backend. No PE
    bytes have been accepted or parsed yet, and later verification still runs
    under every worker limit.
    """

    try:
        _require_backend_versions()

        def load() -> None:
            from oscrypto import asymmetric as _asymmetric  # noqa: F401

        _run_with_oscrypto_version_compatibility(load)
    except BaseException:
        # _verify_stream will return the bounded unsupported/indeterminate result.
        pass


def _pread_exact(descriptor: int, length: int, offset: int, label: str) -> bytes:
    if length < 0 or offset < 0:
        raise _Malformed(f"{label} has invalid bounds")
    data = os.pread(descriptor, length, offset)
    if len(data) != length:
        raise _Malformed(f"{label} lies outside the PE image")
    return data


def _u16(descriptor: int, offset: int, label: str) -> int:
    return struct.unpack("<H", _pread_exact(descriptor, 2, offset, label))[0]


def _u32(descriptor: int, offset: int, label: str) -> int:
    return struct.unpack("<I", _pread_exact(descriptor, 4, offset, label))[0]


def _validate_bound_structure(
    descriptor: int,
    expected_size: int,
    table_offset: int,
    table_size: int,
    entry_length: int,
    revision: int,
    certificate_type: int,
) -> None:
    try:
        info = os.fstat(descriptor)
    except OSError as error:
        raise _Malformed("the bound PE descriptor is unavailable") from error
    if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
        raise _Malformed("the bound PE descriptor has the wrong type or size")
    if expected_size <= 0 or expected_size > MAX_PE_SIZE:
        raise _Unsupported("the PE image exceeds the worker size policy")
    if table_offset % 8 or table_size != ((entry_length + 7) & ~7):
        raise _Malformed("the certificate table is not exactly bound and aligned")
    if entry_length <= 8 or entry_length - 8 > MAX_PKCS7_SIZE:
        raise _Unsupported("the PKCS#7 payload exceeds the worker size policy")
    if table_offset > expected_size or table_size > expected_size - table_offset:
        raise _Malformed("the certificate table extends beyond the PE image")
    if revision != 0x0200 or certificate_type != 0x0002:
        raise _Unsupported("the WIN_CERTIFICATE revision or type is unsupported")

    if _pread_exact(descriptor, 2, 0, "DOS signature") != b"MZ":
        raise _Malformed("the PE image has no MZ signature")
    pe_offset = _u32(descriptor, 0x3C, "PE header offset")
    if pe_offset < 64 or _pread_exact(descriptor, 4, pe_offset, "PE signature") != b"PE\0\0":
        raise _Malformed("the PE signature is invalid")
    coff = pe_offset + 4
    optional_size = _u16(descriptor, coff + 16, "optional-header size")
    optional = coff + 20
    magic = _u16(descriptor, optional, "optional-header magic")
    if magic == 0x10B:
        directory_count_offset = 92
        directories_offset = 96
    elif magic == 0x20B:
        directory_count_offset = 108
        directories_offset = 112
    else:
        raise _Unsupported("the PE optional-header format is unsupported")
    if optional_size < directory_count_offset + 4:
        raise _Malformed("the PE optional header omits its directory count")
    directory_count = _u32(
        descriptor, optional + directory_count_offset, "data-directory count",
    )
    directories_that_fit = max(0, (optional_size - directories_offset) // 8)
    if directory_count > directories_that_fit or directory_count <= 4:
        raise _Malformed("the PE has no complete Security Directory")
    security_directory = optional + directories_offset + 4 * 8
    bound_offset = _u32(descriptor, security_directory, "certificate-table offset")
    bound_size = _u32(descriptor, security_directory + 4, "certificate-table size")
    if (bound_offset, bound_size) != (table_offset, table_size):
        raise _Malformed("the PE Security Directory does not match the supplied facts")

    header = _pread_exact(descriptor, 8, table_offset, "WIN_CERTIFICATE header")
    actual_length, actual_revision, actual_type = struct.unpack("<IHH", header)
    if (actual_length, actual_revision, actual_type) != (
        entry_length, revision, certificate_type,
    ):
        raise _Malformed("WIN_CERTIFICATE does not match the supplied facts")
    padding_length = table_size - entry_length
    if padding_length and any(
        _pread_exact(
            descriptor, padding_length, table_offset + entry_length,
            "WIN_CERTIFICATE padding",
        )
    ):
        raise _Malformed("WIN_CERTIFICATE has nonzero alignment padding")


def _digest_name(signature: object) -> str:
    try:
        name = signature.digest_algorithm().name.lower().replace("-", "")  # type: ignore[attr-defined]
    except Exception as error:
        raise _Unsupported("the Authenticode digest algorithm is unavailable") from error
    if name not in _ALLOWED_DIGESTS:
        raise _Unsupported(f"the Authenticode digest algorithm {name!r} is unsupported")
    return name


def _strict_signer_checks(certificate: object) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = certificate.valid_from  # type: ignore[attr-defined]
    valid_to = certificate.valid_to  # type: ignore[attr-defined]
    if valid_from.tzinfo is None:
        valid_from = valid_from.replace(tzinfo=datetime.timezone.utc)
    if valid_to.tzinfo is None:
        valid_to = valid_to.replace(tzinfo=datetime.timezone.utc)
    if not valid_from <= now <= valid_to:
        raise _Invalid("the signer certificate is not currently valid")
    extensions = certificate.extensions  # type: ignore[attr-defined]
    extended_key_usage = extensions.get("extended_key_usage")
    if not extended_key_usage or "code_signing" not in extended_key_usage:
        raise _Invalid("the signer certificate lacks the code-signing EKU")
    key_usage = extensions.get("key_usage")
    if key_usage is not None and "digital_signature" not in key_usage:
        raise _Invalid("the signer certificate keyUsage forbids digital signatures")


def _verify_stream(stream: BinaryIO) -> AuthenticodeResult:
    try:
        _require_backend_versions()
        # Imported only after resource limits have been installed by main().
        from signify.authenticode import AuthenticodeFile
        from signify.exceptions import ParseError, VerificationError
        from signify.x509 import CertificateStore
    except importlib.metadata.PackageNotFoundError as error:
        raise _Unsupported("the pinned Authenticode backend is unavailable") from error

    try:
        # ``os.fdopen`` exposes an integer ``name``.  Pass a fixed, non-user
        # filename so Signify does not try to coerce that descriptor number to
        # a pathlib path while choosing its PE parser.
        signed_file = AuthenticodeFile.from_stream(stream, file_name="payload.efi")
        signatures = list(signed_file.iter_embedded_signatures(
            include_nested=True,
            ignore_parse_errors=False,
        ))
        if len(signatures) != 1:
            raise _Unsupported("exactly one embedded Authenticode signature is required")
        signature = signatures[0]
        digest = _digest_name(signature)
        raw_certificate_count = len(signature.asn1["certificates"])
        if not 1 <= raw_certificate_count <= MAX_CERTIFICATES:
            raise _Unsupported(
                f"the Authenticode signature must embed 1 to {MAX_CERTIFICATES} certificates"
            )
        certificates = tuple(signature.certificates)
        if len(certificates) != raw_certificate_count:
            raise _Unsupported("the signature contains unsupported certificate choices")
        matches = tuple(signature.certificates.find_certificates(
            issuer=signature.signer_info.issuer,
            serial_number=signature.signer_info.serial_number,
        ))
        if len(matches) != 1:
            raise _Malformed("the signer certificate is missing or ambiguous")
        signer = matches[0]
        _strict_signer_checks(signer)

        # Signify's Authenticode implementation otherwise defaults to its bundled
        # Microsoft store.  This nonempty store is deliberately made solely from
        # certificates embedded in this one signature.  It establishes enough of
        # a local chain to verify integrity, but it is not an external trust claim.
        ephemeral_store = CertificateStore(certificates, trusted=True)
        signature.verify(
            strict_validation=True,
            trusted_certificate_store=ephemeral_store,
            verification_context_kwargs={
                "timestamp": datetime.datetime.now(datetime.timezone.utc),
                "allow_fetching": False,
                "allow_legacy": False,
                "revocation_mode": "soft-fail",
                "crls": [],
                "ocsps": [],
            },
            countersignature_mode="ignore",
        )
        return AuthenticodeResult(
            AuthenticodeIntegrityState.VALID_UNTRUSTED,
            digest_algorithm=digest,
            signer_subject=_sanitize(signer.subject.dn, MAX_SUBJECT_CHARACTERS),
            signer_sha256=signer.sha256_fingerprint.lower(),
            certificate_count=raw_certificate_count,
            trust_evaluated=False,
            revocation_evaluated=False,
            timestamp_evaluated=False,
        )
    except _Unsupported:
        raise
    except _Malformed:
        raise
    except _Invalid:
        raise
    except ParseError as error:
        raise _Malformed(error) from error
    except VerificationError as error:
        raise _Invalid(error) from error
    except (TypeError, ValueError, KeyError, IndexError, struct.error) as error:
        raise _Malformed(error) from error


def verify_descriptor(
    descriptor: int,
    expected_size: int,
    table_offset: int,
    table_size: int,
    entry_length: int,
    revision: int,
    certificate_type: int,
) -> AuthenticodeResult:
    """Worker entry point, also exercised directly by project-owned fixture tests."""

    try:
        _validate_bound_structure(
            descriptor, expected_size, table_offset, table_size, entry_length,
            revision, certificate_type,
        )
        with os.fdopen(os.dup(descriptor), "rb", buffering=0) as stream:
            return _verify_stream(stream)
    except _Unsupported as error:
        return AuthenticodeResult(
            AuthenticodeIntegrityState.UNSUPPORTED,
            error=_sanitize(error, MAX_ERROR_CHARACTERS),
        )
    except _Invalid as error:
        return AuthenticodeResult(
            AuthenticodeIntegrityState.INVALID,
            error=_sanitize(error, MAX_ERROR_CHARACTERS),
        )
    except (_Malformed, OSError) as error:
        return AuthenticodeResult(
            AuthenticodeIntegrityState.MALFORMED,
            error=_sanitize(error, MAX_ERROR_CHARACTERS),
        )
    except BaseException as error:
        return AuthenticodeResult(
            AuthenticodeIntegrityState.INDETERMINATE,
            error=_sanitize(error, MAX_ERROR_CHARACTERS) or "worker verification failed",
        )


def _integer(value: str, label: str) -> int:
    if not value.isascii() or not value.isdecimal():
        raise _Malformed(f"{label} is not a non-negative decimal integer")
    parsed = int(value)
    if parsed > MAX_PE_SIZE * 2:
        raise _Malformed(f"{label} exceeds the worker argument limit")
    return parsed


def main(argv: list[str] | None = None) -> int:
    try:
        _prime_crypto_backend()
        _set_resource_limits()
        arguments = list(sys.argv[1:] if argv is None else argv)
        if len(arguments) != 7:
            raise _Malformed("the worker received the wrong number of arguments")
        descriptor = _integer(arguments[0], "descriptor")
        values = [
            _integer(value, label)
            for value, label in zip(
                arguments[1:],
                (
                    "PE size", "certificate-table offset", "certificate-table size",
                    "WIN_CERTIFICATE length", "WIN_CERTIFICATE revision",
                    "WIN_CERTIFICATE type",
                ),
                strict=True,
            )
        ]
        result = verify_descriptor(descriptor, *values)
    except BaseException as error:
        result = AuthenticodeResult(
            AuthenticodeIntegrityState.INDETERMINATE,
            error=_sanitize(error, MAX_ERROR_CHARACTERS) or "worker startup failed",
        )
    try:
        payload = worker_result_payload(result)
        written = 0
        while written < len(payload):
            count = os.write(1, payload[written:])
            if count <= 0:
                return 1
            written += count
        return 0
    except BaseException:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
