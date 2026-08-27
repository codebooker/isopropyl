# SPDX-License-Identifier: AGPL-3.0-or-later

import struct
import tempfile
import unittest
from pathlib import Path

from isopropyl.uefi import (
    PeFormatError, PolicyState, SbatRequirement, SbatState, SignatureTableState,
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
        self.assertTrue(any("not cryptographically verified" in warning for warning in payload.warnings))

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
        self.assertTrue(any("not cryptographically verified" in item for item in result.warnings))

    def test_out_of_bounds_or_invalid_certificate_table_is_malformed(self):
        out_of_bounds = inspect_pe_bytes(make_pe(security_override=(0x800, 0x1000)))
        self.assertEqual(
            out_of_bounds.certificate_table.state, SignatureTableState.MALFORMED
        )
        short_entry = struct.pack("<IHH", 7, 0x0200, 0x0002)
        malformed = inspect_pe_bytes(make_pe(certificate=short_entry))
        self.assertEqual(malformed.certificate_table.state, SignatureTableState.MALFORMED)

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
