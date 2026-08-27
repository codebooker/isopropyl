import hashlib
# SPDX-License-Identifier: AGPL-3.0-or-later
import gzip
import os
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from isopropyl.images import (
    ImageInspectionCancelled, ImageInspectionTimedOut, NON_RAW_SUFFIXES,
    RAW_IMAGE_SUFFIXES,
    boot_identity_fields,
    calculate_checksums, classify_boot_paths, compare_expected_checksum,
    inspect_image, parse_7z_listing, parse_expected_checksum,
)
from isopropyl.boot_identity import analyze_bootloader_members
from isopropyl.partition_tables import PartitionTableInspection
from isopropyl.sources import ExpandedImageTooLarge
from isopropyl.eltorito import (
    BootEntry, BootPlatform, ElToritoError, ElToritoInspection, EmulationType,
    ValidationEntry,
)


def add_valid_mbr(data: bytearray, sector_size: int = 512) -> None:
    sectors = len(data) // sector_size
    if sectors < 2 or len(data) % sector_size:
        raise ValueError("The synthetic MBR fixture must contain complete sectors")
    struct.pack_into(
        "<B3sB3sII", data, 446, 0x80, b"\0\0\0", 0x0C,
        b"\0\0\0", 1, sectors - 1,
    )
    data[510:512] = b"\x55\xaa"


class ImageTests(unittest.TestCase):
    def test_inspection_rejects_a_source_changed_after_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img"
            payload = bytearray(4096)
            add_valid_mbr(payload)
            path.write_bytes(payload)
            status = path.stat()
            selected_identity = (
                status.st_dev, status.st_ino, status.st_size + 1,
                status.st_mtime_ns, status.st_ctime_ns,
            )

            with self.assertRaisesRegex(OSError, "changed before inspection"):
                inspect_image(path, expected_identity=selected_identity)

    def test_source_is_closed_when_opened_identity_does_not_match(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img"
            path.write_bytes(b"\0" * 4096)
            source = Mock()
            source.identity = SimpleNamespace(
                device=0, inode=0, size=0, modified_ns=0, changed_ns=0,
            )

            with (
                patch("isopropyl.images.open_image_source", return_value=source),
                self.assertRaisesRegex(OSError, "changed before it could be opened"),
            ):
                inspect_image(path)

            source.close.assert_called_once()

    def test_final_ctime_check_rejects_mixed_path_reopen_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img"
            payload = bytearray(4096)
            add_valid_mbr(payload)
            path.write_bytes(payload)
            before = path.stat()

            def mutate_during_catalog(_path):
                path.write_bytes(b"X" * len(payload))
                path.touch()
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                return [], False

            with (
                patch(
                    "isopropyl.images.scan_image_contents",
                    side_effect=mutate_during_catalog,
                ),
                self.assertRaisesRegex(OSError, "changed while it was being inspected"),
            ):
                inspect_image(path)

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
            add_valid_mbr(data)
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
            add_valid_mbr(data)
            offset = 16 * 2048
            data[offset + 1:offset + 6] = b"CD001"
            path.write_bytes(gzip.compress(data))
            result = inspect_image(path)
            self.assertEqual(result.size, len(data))
            self.assertEqual(result.compression, "gzip")
            self.assertTrue(result.raw_compatible)

    def test_compressed_inspection_enforces_an_expanded_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img.gz"
            path.write_bytes(gzip.compress(b"A" * 8192))

            with self.assertRaisesRegex(
                ExpandedImageTooLarge, "inspection limit",
            ):
                inspect_image(path, maximum_expanded_bytes=4096)

    def test_compressed_inspection_is_cooperatively_cancelled(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img.gz"
            path.write_bytes(gzip.compress(b"A" * 8192))
            checks = 0

            def cancel_after_open() -> None:
                nonlocal checks
                checks += 1
                if checks > 2:
                    raise ImageInspectionCancelled("fixture cancellation")

            with self.assertRaisesRegex(
                ImageInspectionCancelled, "fixture cancellation",
            ):
                inspect_image(path, cancel_check=cancel_after_open)

            self.assertGreaterEqual(checks, 3)

    def test_compressed_inspection_deadline_is_enforced_while_decoding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img.gz"
            path.write_bytes(gzip.compress(b"A" * 8192))

            with (
                patch(
                    "isopropyl.images.time.monotonic",
                    side_effect=(0.0, 0.0, 301.0),
                ),
                self.assertRaisesRegex(ImageInspectionTimedOut, "time limit"),
            ):
                inspect_image(path, timeout_seconds=300.0)

    def test_incomplete_compressed_partition_capture_is_not_called_malformed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img.gz"
            path.write_bytes(gzip.compress(b"\0" * 4096))
            incomplete = PartitionTableInspection(
                True, False, False, False, "incomplete", 0,
                "unknown", "unrecognized",
                ("Partition metadata lies outside the bounded capture",),
                False,
            )

            with patch(
                "isopropyl.images.inspect_partition_tables_capture",
                return_value=incomplete,
            ):
                result = inspect_image(path)

            self.assertTrue(result.partition_table_incomplete)
            self.assertFalse(result.partition_table_malformed)
            self.assertIsNone(result.partition_table_valid)
            self.assertFalse(result.raw_compatible)
            self.assertIn("incompletely inspected", result.summary)

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

    def test_usb_and_wic_are_explicit_raw_disk_image_aliases(self):
        self.assertTrue({".usb", ".wic"}.issubset(RAW_IMAGE_SUFFIXES))
        self.assertTrue(RAW_IMAGE_SUFFIXES.isdisjoint(NON_RAW_SUFFIXES))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("appliance.usb", "yocto.wic", "UPPER.USB", "UPPER.WIC"):
                with self.subTest(name=name):
                    path = root / name
                    payload = bytearray(4096)
                    add_valid_mbr(payload)
                    path.write_bytes(payload)
                    with patch("isopropyl.images.scan_image_contents", return_value=([], False)):
                        result = inspect_image(path)
                    self.assertEqual(result.kind, "Raw disk image")
                    self.assertEqual(result.size, len(payload))
                    self.assertTrue(result.has_mbr)
                    self.assertTrue(result.raw_compatible)

    def test_malformed_partition_marker_is_reported_but_still_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malformed.iso"
            payload = bytearray(18 * 2048)
            payload[510:512] = b"\x55\xaa"
            offset = 16 * 2048
            payload[offset + 1:offset + 6] = b"CD001"
            path.write_bytes(payload)
            result = inspect_image(path)
            self.assertTrue(result.has_mbr)
            self.assertFalse(result.has_gpt)
            self.assertFalse(result.partition_table_valid)
            self.assertTrue(result.partition_table_malformed)
            self.assertFalse(result.raw_compatible)
            self.assertEqual(result.partition_table_kind, "malformed")
            self.assertTrue(result.partition_table_issues)
            self.assertIn("malformed", result.summary.casefold())

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
