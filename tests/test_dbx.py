# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from isopropyl.dbx import (
    CATALOG_RESOURCE, DbxAssessment, DbxCatalog, DbxError, DbxState, assess_dbx,
    assess_staged_dbx, load_dbx_catalog, parse_dbx_catalog,
    pe_authenticode_sha256,
)
from tests.test_constructed import build_plan


def canonical_pe(
    *,
    machine: int = 0x8664,
    pe32: bool = False,
    certificate: bytes = b"",
    section_offset: int = 0x200,
    post_section_data: bytes = b"",
    directory_count: int = 16,
    trailer: bytes = b"",
) -> bytes:
    pe_offset = 0x80
    optional_size = 0xE0 if pe32 else 0xF0
    header_size = 0x200
    section_size = 0x200
    data = bytearray(header_size + section_size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into("<HH", data, coff, machine, 1)
    struct.pack_into("<H", data, coff + 16, optional_size)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x10B if pe32 else 0x20B)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<I", data, optional + 60, header_size)
    struct.pack_into("<H", data, optional + 68, 10)
    directories_offset = 96 if pe32 else 112
    directory_count_offset = 92 if pe32 else 108
    struct.pack_into("<I", data, optional + directory_count_offset, directory_count)
    section = optional + optional_size
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<II", data, section + 16, section_size, section_offset)
    if section_offset + section_size > len(data):
        data.extend(b"\0" * (section_offset + section_size - len(data)))
    data[section_offset:section_offset + section_size] = bytes(
        index % 251 for index in range(section_size)
    )
    data.extend(post_section_data)
    security = optional + directories_offset + 4 * 8
    if certificate:
        if directory_count <= 4:
            raise ValueError("fixture certificate needs a Security Directory")
        if len(certificate) % 8:
            raise ValueError("fixture certificate must be 8-byte aligned")
        certificate_offset = len(data)
        if certificate_offset % 8:
            raise ValueError("fixture certificate offset must be 8-byte aligned")
        struct.pack_into("<II", data, security, certificate_offset, len(certificate))
        if len(data) < certificate_offset:
            data.extend(b"\0" * (certificate_offset - len(data)))
        data.extend(certificate)
    data.extend(trailer)
    return bytes(data)


def divergent_multisection_pe() -> bytes:
    """PE whose exact and FileAlignment-rounded section regions diverge."""
    data = bytearray(canonical_pe())
    data.extend(bytes(index % 239 for index in range(0x200)))
    coff = 0x80 + 4
    optional = coff + 20
    section = optional + 0xF0
    struct.pack_into("<H", data, coff + 2, 2)
    struct.pack_into("<I", data, section + 16, 0x180)
    second = section + 40
    data[second:second + 8] = b".data\0\0\0"
    struct.pack_into("<I", data, second + 12, 0x2000)
    struct.pack_into("<II", data, second + 16, 0x200, 0x400)
    return bytes(data)


class DbxTests(unittest.TestCase):
    @staticmethod
    def catalog_with_x64(*digests: str) -> DbxCatalog:
        empty = frozenset()
        return DbxCatalog(
            (("aarch64", empty), ("arm", empty), ("ia32", empty),
             ("x64", frozenset(digests))),
            (("aarch64", empty), ("arm", empty), ("ia32", empty),
             ("x64", empty)),
        )

    def test_assessment_rejects_mislabelled_snapshot_provenance(self):
        with self.assertRaisesRegex(ValueError, "provenance"):
            DbxAssessment(
                DbxState.NOT_LISTED_IN_SNAPSHOT,
                "x64",
                "a" * 64,
                snapshot_release="v0.0.0",
            )

    def test_bundled_catalog_is_exact_and_architecture_specific(self):
        load_dbx_catalog.cache_clear()
        catalog = load_dbx_catalog()
        expected = {
            "x64": (289, 154),
            "ia32": (62, 32),
            "aarch64": (22, 4),
            "arm": (16, 94),
        }
        for architecture, counts in expected.items():
            unflagged, optional = catalog.hashes_for(architecture)
            self.assertEqual((len(unflagged), len(optional)), counts)
            self.assertFalse(unflagged & optional)
        x64 = catalog.hashes_for("x64")
        ia32 = catalog.hashes_for("ia32")
        shared = "7fddfe06c44dc4302da54577353c18fdbe11b41cb3e6064ec1c116ee102fe080"
        self.assertIn(shared, x64[1])
        self.assertIn(shared, ia32[1])

    def test_catalog_digest_and_duplicate_keys_fail_closed(self):
        from importlib.resources import files

        blob = files("isopropyl").joinpath("data", CATALOG_RESOURCE).read_bytes()
        with self.assertRaisesRegex(DbxError, "digest"):
            parse_dbx_catalog(blob[:-1] + b" ")
        duplicate = b'{"schema_version":1,"schema_version":1}'
        with (
            patch(
                "isopropyl.dbx.CATALOG_SHA256",
                hashlib.sha256(duplicate).hexdigest(),
            ),
            self.assertRaisesRegex(DbxError, "duplicate"),
        ):
            parse_dbx_catalog(duplicate)

    def test_catalog_numeric_provenance_is_type_strict(self):
        from importlib.resources import files

        original = files("isopropyl").joinpath("data", CATALOG_RESOURCE).read_bytes()
        for label, mutate in (
            ("boolean schema", lambda value: value.__setitem__("schema_version", True)),
            ("float schema", lambda value: value.__setitem__("schema_version", 1.0)),
            ("float size", lambda value: value["source"].__setitem__("size", 394305.0)),
        ):
            with self.subTest(label=label):
                decoded = json.loads(original)
                mutate(decoded)
                blob = json.dumps(
                    decoded, separators=(",", ":"), sort_keys=True,
                ).encode() + b"\n"
                with (
                    patch(
                        "isopropyl.dbx.CATALOG_SHA256",
                        hashlib.sha256(blob).hexdigest(),
                    ),
                    self.assertRaises(DbxError),
                ):
                    parse_dbx_catalog(blob)

    def test_fixed_pe32_plus_and_pe32_golden_digests(self):
        x64 = pe_authenticode_sha256(canonical_pe())
        ia32 = pe_authenticode_sha256(canonical_pe(machine=0x014C, pe32=True))
        self.assertEqual(x64.architecture, "x64")
        self.assertEqual(ia32.architecture, "ia32")
        self.assertEqual(
            x64.sha256,
            "62c421b83d734f209beccb057a95b1041847c137aa1d72c610185ed0f91f46e8",
        )
        self.assertEqual(
            ia32.sha256,
            "9fcc05a615ae28cef1a9fe2f9c8cc0a79323129dd2a738acf61ca07534488289",
        )

    def test_unsigned_and_signed_forms_have_the_same_image_digest(self):
        unsigned = canonical_pe()
        certificate = struct.pack("<IHH", 16, 0x0200, 0x0002) + b"12345678"
        signed = canonical_pe(certificate=certificate)
        changed_certificate = signed[:-1] + bytes((signed[-1] ^ 1,))
        expected = pe_authenticode_sha256(unsigned).sha256
        self.assertEqual(pe_authenticode_sha256(signed).sha256, expected)
        self.assertEqual(
            pe_authenticode_sha256(changed_certificate).sha256, expected,
        )

    def test_post_section_data_is_hashed_for_signed_and_unsigned_images(self):
        extra = b"0123456789ABCDEF"
        certificate = struct.pack("<IHH", 16, 0x0200, 0x0002) + b"12345678"
        unsigned = canonical_pe(post_section_data=extra)
        signed = canonical_pe(post_section_data=extra, certificate=certificate)
        expected = pe_authenticode_sha256(unsigned).sha256
        self.assertEqual(pe_authenticode_sha256(signed).sha256, expected)
        changed = canonical_pe(post_section_data=b"0123456789ABCDEf")
        self.assertNotEqual(pe_authenticode_sha256(changed).sha256, expected)

    def test_absent_security_directory_hashes_everything_except_checksum(self):
        blob = canonical_pe(directory_count=4, post_section_data=b"extra-data")
        checksum = 0x80 + 4 + 20 + 64
        expected = hashlib.sha256(blob[:checksum] + blob[checksum + 4:]).hexdigest()
        self.assertEqual(pe_authenticode_sha256(blob).sha256, expected)

    def test_checksum_is_excluded_but_section_bytes_are_covered(self):
        original = bytearray(canonical_pe())
        checksum_offset = 0x80 + 4 + 20 + 64
        checksum_changed = bytearray(original)
        checksum_changed[checksum_offset] ^= 1
        section_changed = bytearray(original)
        section_changed[0x200] ^= 1
        expected = pe_authenticode_sha256(bytes(original)).sha256
        self.assertEqual(
            pe_authenticode_sha256(bytes(checksum_changed)).sha256, expected,
        )
        self.assertNotEqual(
            pe_authenticode_sha256(bytes(section_changed)).sha256, expected,
        )

    def test_unflagged_optional_and_not_listed_results_are_distinct(self):
        blob = canonical_pe()
        measured = pe_authenticode_sha256(blob)
        empty = frozenset()
        unflagged = DbxCatalog(
            (("aarch64", empty), ("arm", empty), ("ia32", empty),
             ("x64", frozenset((measured.sha256,)))),
            (("aarch64", empty), ("arm", empty), ("ia32", empty), ("x64", empty)),
        )
        optional = DbxCatalog(
            (("aarch64", empty), ("arm", empty), ("ia32", empty), ("x64", empty)),
            (("aarch64", empty), ("arm", empty), ("ia32", empty),
             ("x64", frozenset((measured.sha256,)))),
        )
        absent = DbxCatalog(
            (("aarch64", empty), ("arm", empty), ("ia32", empty), ("x64", empty)),
            (("aarch64", empty), ("arm", empty), ("ia32", empty), ("x64", empty)),
        )
        self.assertIs(
            assess_dbx(blob, catalog=unflagged).state,
            DbxState.MATCHED_UNFLAGGED,
        )
        self.assertIs(
            assess_dbx(blob, catalog=optional).state, DbxState.MATCHED_OPTIONAL,
        )
        result = assess_dbx(blob, catalog=absent)
        self.assertIs(result.state, DbxState.NOT_LISTED_IN_SNAPSHOT)
        self.assertNotIn("safe", result.state.value)
        self.assertNotIn("compatible", result.state.value)

    def test_ambiguous_or_unsupported_pe_layouts_are_unknown(self):
        unsupported = canonical_pe(machine=0x5064)
        mismatched = canonical_pe(machine=0x014C, pe32=False)
        gapped = canonical_pe(section_offset=0x400)
        signed_trailer = canonical_pe(
            certificate=struct.pack("<IHH", 16, 0x0200, 0x0002) + b"12345678",
            trailer=b"overlay",
        )
        for blob in (unsupported, mismatched, gapped, signed_trailer):
            with self.subTest(size=len(blob)):
                result = assess_dbx(blob)
                self.assertIs(result.state, DbxState.UNKNOWN)
                self.assertTrue(result.error)

    def test_three_oracle_multisection_divergence_is_unknown(self):
        result = assess_dbx(divergent_multisection_pe())
        self.assertIs(result.state, DbxState.UNKNOWN)
        self.assertIn("divergent", result.error)

    def test_cancellation_exception_identity_is_preserved(self):
        blob = canonical_pe()
        marker = RuntimeError("fixture cancellation")

        def cancel() -> None:
            raise marker

        with self.assertRaises(RuntimeError) as raised:
            assess_dbx(blob, cancel_check=cancel)
        self.assertIs(raised.exception, marker)

    def test_cancellation_reaches_later_megabyte_chunks(self):
        blob = canonical_pe(post_section_data=b"x" * (3 * 1024 * 1024))
        marker = RuntimeError("late fixture cancellation")
        checks = 0

        def cancel() -> None:
            nonlocal checks
            checks += 1
            if checks == 6:
                raise marker

        with self.assertRaises(RuntimeError) as raised:
            assess_dbx(blob, cancel_check=cancel)
        self.assertIs(raised.exception, marker)
        self.assertEqual(checks, 6)

    def test_simple_exclusion_oracle_matches_production_digest(self):
        certificate = struct.pack("<IHH", 16, 0x0200, 0x0002) + b"12345678"
        blob = canonical_pe(certificate=certificate)
        optional = 0x80 + 4 + 20
        checksum = optional + 64
        security = optional + 112 + 4 * 8
        certificate_offset, certificate_size = struct.unpack_from("<II", blob, security)
        oracle = hashlib.sha256(
            blob[:checksum]
            + blob[checksum + 4:security]
            + blob[security + 8:certificate_offset]
            + blob[certificate_offset + certificate_size:]
        ).hexdigest()
        self.assertEqual(pe_authenticode_sha256(blob).sha256, oracle)

    def test_staged_tree_assessment_is_plan_bound_and_finds_added_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "staging"
            fallback = root / "EFI/BOOT/BOOTX64.EFI"
            vendor = root / "overlay/vendor/new.efi"
            fallback.parent.mkdir(parents=True)
            vendor.parent.mkdir(parents=True)
            fallback.write_bytes(canonical_pe())
            added = canonical_pe(post_section_data=b"overlay addition")
            vendor.write_bytes(added)
            plan = build_plan(root)
            digest = pe_authenticode_sha256(added).sha256
            result = assess_staged_dbx(
                plan, catalog=self.catalog_with_x64(digest),
            )
            self.assertTrue(result.complete)
            self.assertEqual(result.candidate_count, 2)
            self.assertEqual(tuple(item.path for item in result.matches), (
                "overlay/vendor/new.efi",
            ))

            vendor.write_bytes(canonical_pe(post_section_data=b"changed"))
            changed = assess_staged_dbx(
                plan, catalog=self.catalog_with_x64(digest),
            )
            self.assertFalse(changed.complete)
            self.assertTrue(any("changed" in issue for issue in changed.issues))

    def test_staged_tree_candidate_limit_is_explicitly_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "staging"
            fallback = root / "EFI/BOOT/BOOTX64.EFI"
            fallback.parent.mkdir(parents=True)
            fallback.write_bytes(canonical_pe())
            vendor = root / "EFI/vendor"
            vendor.mkdir(parents=True)
            for index in range(64):
                (vendor / f"tool-{index:02d}.efi").write_bytes(canonical_pe())
            plan = build_plan(root)
            result = assess_staged_dbx(
                plan, catalog=self.catalog_with_x64(),
            )
            self.assertEqual(result.candidate_count, 65)
            self.assertEqual(result.selected_count, 64)
            self.assertFalse(result.complete)
            self.assertTrue(any("selected 64 of 65" in issue for issue in result.issues))


if __name__ == "__main__":
    unittest.main()
