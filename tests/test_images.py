import hashlib
# SPDX-License-Identifier: AGPL-3.0-or-later
import gzip
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from isopropyl.images import (
    boot_identity_fields, calculate_checksums, classify_boot_paths, compare_expected_checksum,
    inspect_image, parse_7z_listing, parse_expected_checksum,
)
from isopropyl.boot_identity import analyze_bootloader_members
from isopropyl.eltorito import (
    BootEntry, BootPlatform, ElToritoError, ElToritoInspection, EmulationType,
    ValidationEntry,
)


class ImageTests(unittest.TestCase):
    def test_parses_and_compares_provider_checksum_text(self):
        expected = "a" * 64
        self.assertEqual(
            parse_expected_checksum(f"SHA256 (linux.iso) = {expected}"),
            ("SHA-256", expected),
        )
        self.assertEqual(
            compare_expected_checksum({"SHA-256": expected}, f"{expected}  linux.iso"),
            ("SHA-256", True),
        )
        self.assertEqual(
            compare_expected_checksum({"SHA-256": "b" * 64}, expected),
            ("SHA-256", False),
        )

    def test_rejects_ambiguous_or_invalid_provider_checksums(self):
        with self.assertRaises(ValueError):
            parse_expected_checksum("not a checksum")
        with self.assertRaises(ValueError):
            parse_expected_checksum(f"{'a' * 32}\n{'b' * 32}")

    def test_parses_7z_member_catalog_with_sizes_and_links(self):
        members = parse_7z_listing("""header
----------
Path = EFI
Folder = +
Size =

Path = EFI/BOOT/BOOTX64.EFI
Folder = -
Size = 1234

Path = current
Folder = -
Size = 0
Symbolic Link = boot/grub
""")
        self.assertEqual(
            [(item.path, item.size, item.kind) for item in members],
            [("EFI", 0, "directory"), ("EFI/BOOT/BOOTX64.EFI", 1234, "file"),
             ("current", 0, "symlink")],
        )

    def test_detects_hybrid_iso_and_volume_label(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "linux.iso"
            data = bytearray(18 * 2048)
            data[510:512] = b"\x55\xaa"
            offset = 16 * 2048
            data[offset] = 1
            data[offset + 1:offset + 6] = b"CD001"
            data[offset + 40:offset + 72] = b"TEST_LINUX".ljust(32)
            path.write_bytes(data)
            result = inspect_image(path)
            self.assertTrue(result.raw_compatible)
            self.assertTrue(result.has_mbr)
            self.assertEqual(result.volume_label, "TEST_LINUX")

    def test_optical_only_iso_warns(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "optical.iso"
            data = bytearray(18 * 2048)
            offset = 16 * 2048
            data[offset + 1:offset + 6] = b"CD001"
            path.write_bytes(data)
            self.assertFalse(inspect_image(path).raw_compatible)

    def test_inspects_the_expanded_layout_and_size_of_compressed_images(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "linux.iso.gz"
            data = bytearray(18 * 2048)
            data[510:512] = b"\x55\xaa"
            offset = 16 * 2048
            data[offset + 1:offset + 6] = b"CD001"
            path.write_bytes(gzip.compress(data))
            result = inspect_image(path)
            self.assertEqual(result.size, len(data))
            self.assertEqual(result.compression, "gzip")
            self.assertTrue(result.raw_compatible)

    def test_non_raw_apply_formats_and_compressed_containers_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (
                "install.wim", "install.esd", "capture.ffu", "image.vtsi",
                "disk.vhdx.gz", "disk.qcow2.xz", "install.wim.zst",
            ):
                with self.subTest(name=name):
                    path = root / name
                    path.write_bytes(b"not a raw disk")
                    with self.assertRaisesRegex(OSError, "cannot be written|not accepted"):
                        inspect_image(path)

    def test_all_checksums_are_calculated_in_one_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.img"
            payload = b"isopropyl"
            path.write_bytes(payload)
            progress = []
            result = calculate_checksums(path, lambda done, total: progress.append((done, total)))
            self.assertEqual(result["SHA-256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(result["SHA-512"], hashlib.sha512(payload).hexdigest())
            self.assertEqual(progress[-1], (len(payload), len(payload)))

    def test_classifies_bios_uefi_architecture_and_windows_installer(self):
        modes, architectures, bootloader, windows = classify_boot_paths([
            "bootmgr", "efi/boot/bootx64.efi", "sources/install.wim",
        ])
        self.assertEqual(modes, ("BIOS", "UEFI"))
        self.assertEqual(architectures, ("x64",))
        self.assertEqual(bootloader, "Windows Boot Manager")
        self.assertTrue(windows)

    def test_classifies_grub_arm64(self):
        modes, architectures, bootloader, windows = classify_boot_paths([
            "EFI/BOOT/BOOTAA64.EFI", "boot/grub/grub.cfg",
        ])
        self.assertEqual(modes, ("UEFI",))
        self.assertEqual(architectures, ("ARM64",))
        self.assertEqual(bootloader, "GRUB")
        self.assertFalse(windows)

    def test_el_torito_catalog_augments_filename_boot_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.iso"
            data = bytearray(18 * 2048)
            offset = 16 * 2048
            data[offset + 1:offset + 6] = b"CD001"
            path.write_bytes(data)
            entry = BootEntry(
                1, True, BootPlatform.BIOS_X86, "", True,
                EmulationType.NO_EMULATION, 0, 0, 4, 24,
                24 * 2048, 2048, 25 * 2048, 0, b"",
            )
            catalog = ElToritoInspection(
                len(data), 20, 20 * 2048, 64, 3,
                ValidationEntry(BootPlatform.BIOS_X86, "TEST", 0),
                (entry,),
            )
            with patch("isopropyl.images.scan_image_contents", return_value=([], True)), patch(
                "isopropyl.images.inspect_eltorito_file", return_value=catalog,
            ):
                result = inspect_image(path)
            self.assertEqual(result.boot_modes, ("BIOS",))
            self.assertIs(result.eltorito, catalog)
            self.assertEqual(result.eltorito_issues, ())

    def test_el_torito_parse_failure_is_reported_without_losing_iso_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.iso"
            data = bytearray(18 * 2048)
            offset = 16 * 2048
            data[offset + 1:offset + 6] = b"CD001"
            path.write_bytes(data)
            with patch(
                "isopropyl.images.inspect_eltorito_file",
                side_effect=ElToritoError("invalid boot catalog"),
            ):
                result = inspect_image(path)
            self.assertTrue(result.is_iso9660)
            self.assertEqual(result.eltorito_issues, ("invalid boot catalog",))

    def test_maps_exact_or_conflicting_payload_identity_without_guessing(self):
        exact = analyze_bootloader_members({
            "isolinux/isolinux.bin": b"ISOLINUX 6.04 6.04-pre1* \0",
        })
        self.assertEqual(
            boot_identity_fields(exact, "Syslinux/Isolinux")[:4],
            ("6.04", "6.04-pre1", "syslinux:6.04-pre1", False),
        )
        conflict = analyze_bootloader_members({
            "one/isolinux.bin": b"ISOLINUX 4.07\0",
            "two/isolinux.bin": b"ISOLINUX 6.04\0",
        })
        self.assertEqual(boot_identity_fields(conflict, "Syslinux/Isolinux")[:4], (
            "", "", "", True,
        ))


if __name__ == "__main__":
    unittest.main()
