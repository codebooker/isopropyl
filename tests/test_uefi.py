# SPDX-License-Identifier: AGPL-3.0-or-later

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from isopropyl.authenticode import (
    AuthenticodeIntegrityState, AuthenticodeResult, CertificateTableFacts,
)
from isopropyl.uefi import (
    CertificateTable, ImageUefiPayload, PeFormatError, PolicyState, SbatMetadata,
    SbatRequirement, SbatState, SignatureTableState, UefiInspection,
    evaluate_sbat_policy, inspect_iso_uefi_payloads, inspect_pe_bytes, inspect_pe_file,
    uefi_member_paths,
)


def make_pe(
    *, machine: int = 0x8664, pe32: bool = False, subsystem: int = 10,
    sbat: bytes | None = None, certificate: bytes | None = None,
    security_override: tuple[int, int] | None = None,
    duplicate_sbat: bool = False,
) -> bytes:
    pe_offset = 0x80
    optional_size = 0xE0 if pe32 else 0xF0
    sections = []
    if sbat is not None:
        sections.append((b".sbat", sbat))
        if duplicate_sbat:
            sections.append((b".sbat", sbat))
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into("<HH", data, coff, machine, len(sections))
    struct.pack_into("<H", data, coff + 16, optional_size)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x10B if pe32 else 0x20B)
    struct.pack_into("<H", data, optional + 68, subsystem)
    directory_count_offset = 92 if pe32 else 108
    directories_offset = 96 if pe32 else 112
    struct.pack_into("<I", data, optional + directory_count_offset, 16)

    section_table = optional + optional_size
    raw_cursor = 0x400
    required_header = section_table + len(sections) * 40
    if len(data) < required_header:
        data.extend(b"\0" * (required_header - len(data)))
    for index, (name, payload) in enumerate(sections):
        header = section_table + index * 40
        data[header:header + 8] = name.ljust(8, b"\0")
        struct.pack_into("<II", data, header + 16, len(payload), raw_cursor)
        if len(data) < raw_cursor + len(payload):
            data.extend(b"\0" * (raw_cursor + len(payload) - len(data)))
        data[raw_cursor:raw_cursor + len(payload)] = payload
        raw_cursor = (raw_cursor + len(payload) + 0x1FF) & ~0x1FF

    security_offset = 0
    security_size = 0
    if certificate is not None:
        security_offset = max((len(data) + 7) & ~7, raw_cursor)
        if len(data) < security_offset:
            data.extend(b"\0" * (security_offset - len(data)))
        data.extend(certificate)
        security_size = len(certificate)
    if security_override is not None:
        security_offset, security_size = security_override
    security_directory = optional + directories_offset + 4 * 8
    struct.pack_into("<II", data, security_directory, security_offset, security_size)
    return bytes(data)


class UefiInspectionTests(unittest.TestCase):
    @staticmethod
    def auth_result(state: AuthenticodeIntegrityState) -> AuthenticodeResult:
        if state is AuthenticodeIntegrityState.VALID_UNTRUSTED:
            return AuthenticodeResult(
                state, "sha256", "CN=Embedded Claim", "a" * 64, 1,
            )
        return AuthenticodeResult(state, error="fixture result")

    def test_authenticode_is_additive_and_never_changes_structural_state(self):
        certificate = struct.pack("<IHH", 16, 0x0200, 0x0002) + b"12345678"
        blob = make_pe(certificate=certificate)
        for state in AuthenticodeIntegrityState:
            observed: list[tuple[bytes, CertificateTableFacts, float, object]] = []

            def verifier(data, facts, *, timeout, cancel_check):
                observed.append((data, facts, timeout, cancel_check))
                return self.auth_result(state)

            with self.subTest(state=state):
                result = inspect_pe_bytes(blob, authenticode_verifier=verifier)
                self.assertEqual(
                    result.certificate_table.state,
                    SignatureTableState.PRESENT_UNVERIFIED,
                )
                self.assertFalse(result.certificate_table.cryptographically_verified)
                self.assertIs(result.authenticode.state, state)
                self.assertEqual(observed[0][0], blob)
                self.assertEqual(observed[0][1].file_offset, result.certificate_table.file_offset)
                self.assertEqual(observed[0][1].size, result.certificate_table.size)
                self.assertEqual(len(observed[0][1].entries), 1)

    def test_absent_and_structurally_malformed_tables_never_start_verifier(self):
        verifier = Mock()
        absent = inspect_pe_bytes(make_pe(), authenticode_verifier=verifier)
        malformed_certificate = (
            struct.pack("<IHH", 9, 0x0200, 0x0002) + b"x" + b"\x01" * 7
        )
        malformed = inspect_pe_bytes(
            make_pe(certificate=malformed_certificate),
            authenticode_verifier=verifier,
        )
        verifier.assert_not_called()
        self.assertIsNone(absent.authenticode)
        self.assertIsNone(malformed.authenticode)

    def test_authenticode_result_propagates_through_iso_without_authorizing_trust(self):
        certificate = struct.pack("<IHH", 16, 0x0200, 0x0002) + b"12345678"
        valid = self.auth_result(AuthenticodeIntegrityState.VALID_UNTRUSTED)
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "fixture.iso"
            image.write_bytes(b"fixture")
            analysis = inspect_iso_uefi_payloads(
                image, ("EFI/BOOT/BOOTX64.EFI",),
                reader=lambda *_args: make_pe(certificate=certificate),
                authenticode_verifier=lambda *_args, **_kwargs: valid,
            )
        payload = analysis.payloads[0]
        self.assertIs(payload.authenticode, valid)
        self.assertEqual(payload.signature_state, SignatureTableState.PRESENT_UNVERIFIED)
        self.assertFalse(payload.authenticode.trust_evaluated)

    def test_iso_deadline_and_cancellation_prevent_or_stop_verification(self):
        certificate = struct.pack("<IHH", 16, 0x0200, 0x0002) + b"12345678"
        verifier = Mock(return_value=self.auth_result(
            AuthenticodeIntegrityState.INDETERMINATE,
        ))
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "fixture.iso"
            image.write_bytes(b"fixture")
            with patch("isopropyl.uefi.time.monotonic", side_effect=(0.0, 0.1, 2.0)):
                analysis = inspect_iso_uefi_payloads(
                    image, ("EFI/BOOT/BOOTX64.EFI",), timeout=1.0,
                    reader=lambda *_args: make_pe(certificate=certificate),
                    authenticode_verifier=verifier,
                )
            self.assertFalse(analysis.payloads)
            self.assertIn("overall time limit", analysis.issues[0])
            verifier.assert_not_called()

            with patch(
                "isopropyl.uefi.time.monotonic",
                side_effect=(0.0, 0.1, 0.2, 1.1),
            ):
                after_worker = inspect_iso_uefi_payloads(
                    image, ("EFI/BOOT/BOOTX64.EFI",), timeout=1.0,
                    reader=lambda *_args: make_pe(certificate=certificate),
                    authenticode_verifier=verifier,
                )
            self.assertFalse(after_worker.payloads)
            self.assertIn("overall time limit", after_worker.issues[0])
            verifier.assert_called_once()

            checks = 0

            def cancelled() -> None:
                nonlocal checks
                checks += 1
                if checks >= 3:
                    raise OSError("fixture inspection cancellation")

            def cancelling_verifier(*_args, **kwargs):
                kwargs["cancel_check"]()
                raise AssertionError("cancel callback should have raised")

            with self.assertRaisesRegex(OSError, "inspection cancellation"):
                inspect_iso_uefi_payloads(
                    image, ("EFI/BOOT/BOOTX64.EFI",),
                    reader=lambda *_args: make_pe(certificate=certificate),
                    cancel_check=cancelled,
                    authenticode_verifier=cancelling_verifier,
                )

    def test_existing_positional_models_retain_compatible_defaults(self):
        table = CertificateTable(SignatureTableState.ABSENT)
        sbat = SbatMetadata(SbatState.ABSENT)
        inspection = UefiInspection(
            0x8664, "x64", "PE32+", 10, "EFI application", (), table, sbat, (),
        )
        payload = ImageUefiPayload(
            "EFI/BOOT/BOOTX64.EFI", "x64", "EFI application", True,
            SignatureTableState.ABSENT, SbatState.ABSENT, (),
        )
        self.assertIsNone(inspection.authenticode)
        self.assertIsNone(payload.authenticode)

    def test_iso_member_selection_prioritizes_fallback_loaders_and_is_safe(self):
        selected = uefi_member_paths((
            "EFI/vendor/tool.efi", "EFI/BOOT/BOOTX64.EFI", "../escape.efi",
            "/absolute.efi", "not-efi.txt",
        ))
        self.assertEqual(selected[0], "EFI/BOOT/BOOTX64.EFI")
        self.assertIn("EFI/vendor/tool.efi", selected)
        self.assertNotIn("../escape.efi", selected)

    def test_iso_analysis_reports_structure_without_claiming_trust(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "test.iso"
            image.write_bytes(b"placeholder")
            certificate = struct.pack("<IHH", 16, 0x0200, 0x0002) + b"12345678"
            analysis = inspect_iso_uefi_payloads(
                image, ("EFI/BOOT/BOOTX64.EFI",),
                reader=lambda _image, _member: make_pe(certificate=certificate),
            )
        self.assertEqual(len(analysis.payloads), 1)
        payload = analysis.payloads[0]
        self.assertEqual(payload.architecture, "x64")
        self.assertEqual(payload.signature_state, SignatureTableState.PRESENT_UNVERIFIED)
        self.assertTrue(any("Authenticode integrity" in warning for warning in payload.warnings))
        self.assertFalse(any("trusted" in warning.casefold() for warning in payload.warnings))

    def test_parses_pe32_plus_architecture_and_efi_subsystem(self):
        result = inspect_pe_bytes(make_pe())
        self.assertEqual(result.architecture, "x64")
        self.assertEqual(result.pe_kind, "PE32+")
        self.assertTrue(result.is_uefi_image)
        self.assertEqual(result.subsystem_name, "EFI application")
        self.assertEqual(result.certificate_table.state, SignatureTableState.ABSENT)

    def test_parses_pe32_machine_and_directory_layout(self):
        result = inspect_pe_bytes(make_pe(machine=0x014C, pe32=True, subsystem=11))
        self.assertEqual(result.architecture, "x86")
        self.assertEqual(result.pe_kind, "PE32")
        self.assertEqual(result.subsystem_name, "EFI boot-service driver")

    def test_certificate_table_is_only_structurally_present_unverified(self):
        certificate = struct.pack("<IHH", 16, 0x0200, 0x0002) + b"12345678"
        result = inspect_pe_bytes(make_pe(certificate=certificate))
        table = result.certificate_table
        self.assertEqual(table.state, SignatureTableState.PRESENT_UNVERIFIED)
        self.assertEqual(len(table.entries), 1)
        self.assertEqual(table.entries[0].certificate_type, 0x0002)
        self.assertFalse(table.cryptographically_verified)
        self.assertTrue(any("Authenticode integrity" in item for item in result.warnings))
        self.assertFalse(any("trusted" in item.casefold() for item in result.warnings))

    def test_out_of_bounds_or_invalid_certificate_table_is_malformed(self):
        out_of_bounds = inspect_pe_bytes(make_pe(security_override=(0x800, 0x1000)))
        self.assertEqual(
            out_of_bounds.certificate_table.state, SignatureTableState.MALFORMED
        )
        short_entry = struct.pack("<IHH", 7, 0x0200, 0x0002)
        malformed = inspect_pe_bytes(make_pe(certificate=short_entry))
        self.assertEqual(malformed.certificate_table.state, SignatureTableState.MALFORMED)

        nonzero_padding = (
            struct.pack("<IHH", 9, 0x0200, 0x0002) + b"x" + b"\x01" * 7
        )
        padded = inspect_pe_bytes(make_pe(certificate=nonzero_padding))
        self.assertEqual(padded.certificate_table.state, SignatureTableState.MALFORMED)
        self.assertIn("padding", padded.certificate_table.error)

        overlapping = inspect_pe_bytes(make_pe(
            sbat=struct.pack("<IHH", 16, 0x0200, 0x0002) + b"12345678",
            security_override=(0x400, 16),
        ))
        self.assertEqual(overlapping.certificate_table.state, SignatureTableState.MALFORMED)
        self.assertIn("overlaps", overlapping.certificate_table.error)

    def test_strict_pe_header_and_section_bounds(self):
        with self.assertRaises(PeFormatError):
            inspect_pe_bytes(b"not a PE")
        bad_offset = bytearray(64)
        bad_offset[:2] = b"MZ"
        struct.pack_into("<I", bad_offset, 0x3C, 0x1000)
        with self.assertRaises(PeFormatError):
            inspect_pe_bytes(bytes(bad_offset))

        truncated = make_pe(sbat=b"sbat,1,pkg,1,url,extra\n")[:-10]
        with self.assertRaises(PeFormatError):
            inspect_pe_bytes(truncated)

    def test_valid_sbat_metadata_and_generation_policy(self):
        text = (
            b"sbat,1,SBAT Version,sbat,1,https://example.invalid/sbat\n"
            b"shim,2,Vendor,shim,15.8,https://example.invalid/shim\n"
        )
        metadata = inspect_pe_bytes(make_pe(sbat=text)).sbat
        self.assertEqual(metadata.state, SbatState.PRESENT)
        self.assertEqual(metadata.entries[1].component, "shim")
        self.assertEqual(metadata.entries[1].generation, 2)
        self.assertEqual(metadata.entries[1].vendor_name, "Vendor")
        self.assertEqual(metadata.entries[1].vendor_package_name, "shim")
        self.assertEqual(metadata.entries[1].vendor_version, "15.8")
        self.assertEqual(metadata.entries[1].vendor_url, "https://example.invalid/shim")
        passed = evaluate_sbat_policy(metadata, (SbatRequirement("shim", 2),))
        self.assertEqual(passed.state, PolicyState.PASSED)
        self.assertTrue(passed.allowed)
        rejected = evaluate_sbat_policy(metadata, (SbatRequirement("shim", 3),))
        self.assertEqual(rejected.state, PolicyState.REJECTED)
        self.assertFalse(rejected.allowed)

    def test_missing_or_malformed_sbat_policy_fails_closed(self):
        absent = inspect_pe_bytes(make_pe()).sbat
        decision = evaluate_sbat_policy(absent, (SbatRequirement("shim", 1),))
        self.assertEqual(decision.state, PolicyState.UNKNOWN)
        self.assertFalse(decision.allowed)

        duplicate = (
            b"shim,1,pkg,1,url,extra\n"
            b"shim,2,pkg,2,url,extra\n"
        )
        malformed = inspect_pe_bytes(make_pe(sbat=duplicate)).sbat
        self.assertEqual(malformed.state, SbatState.MALFORMED)
        decision = evaluate_sbat_policy(malformed, ())
        self.assertEqual(decision.state, PolicyState.UNKNOWN)
        self.assertFalse(decision.allowed)

    def test_multiple_sbat_sections_are_ambiguous(self):
        result = inspect_pe_bytes(
            make_pe(sbat=b"shim,1,pkg,1,url,extra\n", duplicate_sbat=True)
        )
        self.assertEqual(result.sbat.state, SbatState.MALFORMED)
        self.assertIn("multiple", result.sbat.error)

    def test_sbat_text_outside_named_section_is_not_scanned(self):
        result = inspect_pe_bytes(make_pe() + b"shim,1,pkg,1,url,extra\n")
        self.assertEqual(result.sbat.state, SbatState.ABSENT)

    def test_unknown_machine_and_non_efi_subsystem_are_reported(self):
        result = inspect_pe_bytes(make_pe(machine=0xFFFF, subsystem=3))
        self.assertEqual(result.architecture, "unknown (0xffff)")
        self.assertFalse(result.is_uefi_image)
        self.assertEqual(len(result.warnings), 2)

    def test_file_inspection_is_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "BOOTX64.EFI"
            payload = make_pe()
            path.write_bytes(payload)
            before = path.stat()
            result = inspect_pe_file(path)
            after = path.stat()
        self.assertEqual(result.architecture, "x64")
        self.assertEqual((before.st_size, before.st_mtime_ns), (after.st_size, after.st_mtime_ns))


if __name__ == "__main__":
    unittest.main()
