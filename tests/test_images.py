import hashlib
# SPDX-License-Identifier: AGPL-3.0-or-later
import gzip
import os
import struct
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from isopropyl.images import (
    ChecksumCancelled, ImageInspectionCancelled, ImageInspectionTimedOut,
    ImageMember,
    NON_RAW_SUFFIXES, RAW_IMAGE_SUFFIXES, SPARSE_SUFFIXES,
    boot_identity_fields,
    calculate_checksums, classify_boot_paths, classify_windows_installer_members,
    compare_expected_checksum, inspect_image, parse_7z_listing, parse_expected_checksum,
    scan_image_contents, inspect_squashfs_superblock,
)
from isopropyl.boot_identity import analyze_bootloader_members
from isopropyl.partition_tables import PartitionTableInspection
from isopropyl.sources import ExpandedImageTooLarge, ImageSourceError
from isopropyl.timestamps import (
    MAX_PORTABLE_ARCHIVE_MTIME_NS, MIN_PORTABLE_ARCHIVE_MTIME_NS,
)
from isopropyl.uefi import ImageUefiAnalysis
from isopropyl.eltorito import (
    BootEntry, BootPlatform, ElToritoError, ElToritoInspection,
    ElToritoNotFound, EmulationType, ValidationEntry,
)
from isopropyl.fat_image import FatType
from tests.test_fat_image import make_fat, write_container
from tests.test_uefi import make_pe


class FakeCatalogProcess:
    def __init__(self, output: bytes, returncode: int | None = 0):
        self.stdout = tempfile.TemporaryFile()
        self.stdout.write(output)
        self.stdout.seek(0)
        self.returncode = returncode
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired(["7z"], timeout)
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9


def add_valid_mbr(data: bytearray, sector_size: int = 512) -> None:
    sectors = len(data) // sector_size
    if sectors < 2 or len(data) % sector_size:
        raise ValueError("The synthetic MBR fixture must contain complete sectors")
    struct.pack_into(
        "<B3sB3sII", data, 446, 0x80, b"\0\0\0", 0x0C,
        b"\0\0\0", 1, sectors - 1,
    )
    data[510:512] = b"\x55\xaa"


def vtsi_fixture(expanded: bytes, stored_ranges: tuple[tuple[int, int], ...]) -> bytes:
    signature = int.from_bytes(expanded[440:444], "little")
    data = bytearray()
    records = bytearray()
    for start_sector, sector_count in stored_ranges:
        disk_offset = start_sector * 512
        byte_count = sector_count * 512
        records.extend(struct.pack("<QQQ", start_sector, sector_count, len(data)))
        data.extend(expanded[disk_offset:disk_offset + byte_count])
    table_checksum = (~sum(records)) & 0xFFFFFFFF
    padded_records = records + b"\0" * ((-len(records)) % 512)
    footer = bytearray(512)
    struct.pack_into(
        "<8sHHQIIIIQ", footer, 0, b"VENTOY\0\0", 1, 0, len(expanded),
        signature, 0, len(stored_ranges), table_checksum, len(data),
    )
    struct.pack_into("<I", footer, 24, (~sum(footer)) & 0xFFFFFFFF)
    return bytes(data + padded_records + footer)


def squashfs_fixture(*, image_size: int = 8192, **changes: int) -> bytes:
    values = {
        "magic": 0x73717368,
        "inodes": 12,
        "mkfs_time": 1_725_000_000,
        "block_size": 131_072,
        "fragments": 0,
        "compression": 6,
        "block_log": 17,
        "flags": 0,
        "ids": 1,
        "major": 4,
        "minor": 0,
        "root_inode": 0,
        "bytes_used": 4096,
        "id_table": 3072,
        "xattr_table": 0xFFFFFFFFFFFFFFFF,
        "inode_table": 96,
        "directory_table": 1024,
        "fragment_table": 0xFFFFFFFFFFFFFFFF,
        "lookup_table": 0xFFFFFFFFFFFFFFFF,
    }
    values.update(changes)
    data = bytearray(image_size)
    struct.pack_into(
        "<IIIIIHHHHHHQQQQQQQQ",
        data,
        0,
        *values.values(),
    )
    return bytes(data)


class ImageTests(unittest.TestCase):
    @staticmethod
    def file_identity(path: Path) -> tuple[int, int, int, int, int]:
        status = path.stat()
        return (
            status.st_dev, status.st_ino, status.st_size,
            status.st_mtime_ns, status.st_ctime_ns,
        )

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

            def mutate_during_catalog(_path, **_kwargs):
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

    def test_catalog_inspection_stays_bound_to_the_original_image_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img"
            moved = Path(directory) / "selected-image-moved.img"
            payload = bytearray(4096)
            add_valid_mbr(payload)
            payload[1024:1032] = b"ORIGINAL"
            path.write_bytes(payload)
            observed: list[bytes] = []

            def swap_path_during_catalog(_path, *, image_fd=None, **_kwargs):
                self.assertIsNotNone(image_fd)
                assert image_fd is not None
                path.rename(moved)
                path.write_bytes(b"D" * len(payload))
                observed.append(os.pread(image_fd, len(payload), 0))
                return [], False

            with (
                patch(
                    "isopropyl.images.scan_image_contents",
                    side_effect=swap_path_during_catalog,
                ),
                self.assertRaisesRegex(OSError, "changed while it was being inspected"),
            ):
                inspect_image(path)

            self.assertEqual(observed, [bytes(payload)])
            self.assertEqual(moved.read_bytes(), bytes(payload))
            self.assertEqual(path.read_bytes(), b"D" * len(payload))

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
Modified = 2024-02-29 12:34:56

Path = EFI/BOOT/BOOTX64.EFI
Folder = -
Size = 1234
Modified = 2024-02-29 12:34:56.123456789

Path = current
Folder = -
Size = 0
Symbolic Link = boot/grub
Modified = 2024-02-29 12:34:56
""")
        self.assertEqual(
            [(item.path, item.size, item.kind) for item in members],
            [("EFI", 0, "directory"), ("EFI/BOOT/BOOTX64.EFI", 1234, "file"),
             ("current", 0, "symlink")],
        )
        self.assertEqual(members[0].modified_ns, 1_709_210_096_000_000_000)
        self.assertEqual(members[1].modified_ns, 1_709_210_096_123_456_789)
        self.assertIsNone(members[2].modified_ns)

    def test_7z_member_times_fail_closed_when_blank_malformed_or_unportable(self):
        listing = "header\n----------\n" + "\n\n".join(
            f"Path = item-{index}\nFolder = -\nSize = 1\nModified = {value}"
            for index, value in enumerate((
                "", "not-a-time", "2023-02-29 00:00:00",
                "1980-01-01 00:00:00", "2107-12-31 23:59:58",
                "2024-01-01 00:00:00.1234567890",
            ))
        )
        self.assertTrue(all(
            member.modified_ns is None for member in parse_7z_listing(listing)
        ))

    def test_7z_member_times_accept_timezone_safe_portable_boundaries(self):
        members = parse_7z_listing("""header
----------
Path = earliest
Folder = -
Size = 1
Modified = 1980-01-02 00:00:00

Path = latest
Folder = -
Size = 1
Modified = 2107-12-30 23:59:58.999999999
""")
        self.assertEqual(
            [member.modified_ns for member in members],
            [MIN_PORTABLE_ARCHIVE_MTIME_NS, MAX_PORTABLE_ARCHIVE_MTIME_NS],
        )

    def test_archive_catalog_never_uses_an_untrusted_path_7z(self):
        with patch(
            "isopropyl.images.shutil.which",
            return_value="/home/example/bin/7z",
        ) as which:
            self.assertEqual(scan_image_contents(Path("fixture.iso")), ([], False))
        which.assert_called_once_with("7z", path="/usr/bin:/bin")

    def test_archive_catalog_output_and_member_count_are_bounded(self):
        too_large = FakeCatalogProcess(b"X" * 65)
        with (
            patch("isopropyl.images._trusted_7z", return_value="/usr/bin/7z"),
            patch("isopropyl.images.MAX_7Z_CATALOG_BYTES", 64),
            patch("isopropyl.images.subprocess.Popen", return_value=too_large),
        ):
            self.assertEqual(scan_image_contents(Path("fixture.iso")), ([], False))

        listing = """header
----------
Path = one
Folder = -
Size = 1

Path = two
Folder = -
Size = 1
"""
        with self.assertRaisesRegex(ValueError, "too many members"):
            parse_7z_listing(listing, maximum_members=1)

    def test_archive_catalog_scan_is_cancellable_and_reaps_7z(self):
        process = FakeCatalogProcess(b"", returncode=None)

        def cancelled():
            raise ImageInspectionCancelled("fixture reselection")

        with (
            patch("isopropyl.images._trusted_7z", return_value="/usr/bin/7z"),
            patch("isopropyl.images.subprocess.Popen", return_value=process),
            self.assertRaisesRegex(ImageInspectionCancelled, "reselection"),
        ):
            scan_image_contents(Path("fixture.iso"), cancel_check=cancelled)
        self.assertTrue(process.terminated)
        self.assertIsNotNone(process.returncode)

    def test_archive_catalog_scan_is_cancellable_after_stdout_eof(self):
        process = FakeCatalogProcess(b"", returncode=None)
        checks = 0

        def cancel_after_eof():
            nonlocal checks
            checks += 1
            if checks > 1:
                raise ImageInspectionCancelled("fixture post-EOF reselection")

        with (
            patch("isopropyl.images._trusted_7z", return_value="/usr/bin/7z"),
            patch("isopropyl.images.subprocess.Popen", return_value=process),
            self.assertRaisesRegex(ImageInspectionCancelled, "post-EOF"),
        ):
            scan_image_contents(
                Path("fixture.iso"), cancel_check=cancel_after_eof,
            )
        self.assertEqual(checks, 2)
        self.assertTrue(process.terminated)

    def test_archive_catalog_scan_passes_the_bound_image_descriptor(self):
        listing = b"""header
----------
Path = EFI/BOOT/BOOTX64.EFI
Folder = -
        Size = 123
"""
        process = FakeCatalogProcess(listing)
        with tempfile.TemporaryFile() as image:
            with (
                patch("isopropyl.images._trusted_7z", return_value="/usr/bin/7z"),
                patch(
                    "isopropyl.images.subprocess.Popen", return_value=process,
                ) as popen,
            ):
                members, complete = scan_image_contents(
                    Path("decoy.iso"), image_fd=image.fileno(),
                )
                self.assertTrue(complete)
                self.assertEqual(members[0].path, "EFI/BOOT/BOOTX64.EFI")
                self.assertEqual(
                    popen.call_args.kwargs["pass_fds"], (image.fileno(),),
                )
                self.assertEqual(
                    popen.call_args.args[0][-1], f"/proc/self/fd/{image.fileno()}",
                )
                self.assertEqual(
                    popen.call_args.kwargs["env"],
                    {
                        "LC_ALL": "C", "LANG": "C", "TZ": "UTC",
                        "PATH": "/usr/bin:/bin",
                    },
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

    def test_detects_standalone_squashfs_from_bound_superblock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, payload, outer_compression in (
                ("rootfs.squashfs", squashfs_fixture(), "none"),
                ("misnamed.iso", squashfs_fixture(), "none"),
                ("rootfs.img.gz", gzip.compress(squashfs_fixture()), "gzip"),
            ):
                with self.subTest(name=name):
                    path = root / name
                    path.write_bytes(payload)
                    with patch(
                        "isopropyl.images.scan_image_contents",
                        return_value=([], False),
                    ):
                        result = inspect_image(path)
                    self.assertEqual(result.kind, "SquashFS filesystem image")
                    self.assertIsNotNone(result.squashfs)
                    assert result.squashfs is not None
                    self.assertEqual(result.squashfs.version, "4.0")
                    self.assertEqual(result.squashfs.compression, "Zstandard")
                    self.assertEqual(result.squashfs.block_size, 131_072)
                    self.assertEqual(result.compression, outer_compression)
                    self.assertEqual(
                        result.layout,
                        "SquashFS 4.0 (Zstandard) filesystem image",
                    )
                    self.assertTrue(result.raw_compatible)

    def test_squashfs_magic_never_overrides_malformed_geometry(self):
        valid = squashfs_fixture()
        malformed = (
            valid[:4],
            squashfs_fixture(major=3),
            squashfs_fixture(block_size=65_536),
            squashfs_fixture(bytes_used=16_384),
            squashfs_fixture(id_table=4096),
            squashfs_fixture(fragments=1),
            squashfs_fixture(root_inode=(4096 << 16)),
            squashfs_fixture(ids=25),
            squashfs_fixture(fragments=13, fragment_table=2048),
        )
        for payload in malformed:
            with self.subTest(size=len(payload)):
                self.assertIsNone(
                    inspect_squashfs_superblock(payload, len(payload)),
                )

    def test_optical_only_iso_warns(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "optical.iso"
            data = bytearray(18 * 2048)
            offset = 16 * 2048
            data[offset + 1:offset + 6] = b"CD001"
            path.write_bytes(data)
            self.assertFalse(inspect_image(path).raw_compatible)

    def test_image_inspection_forwards_cancellation_to_uefi_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "uefi.iso"
            data = bytearray(18 * 2048)
            offset = 16 * 2048
            data[offset + 1:offset + 6] = b"CD001"
            path.write_bytes(data)
            callback_checks = 0
            observed: list[object] = []

            def outer_cancel() -> None:
                nonlocal callback_checks
                callback_checks += 1

            def inspect_uefi(*_args, **kwargs):
                observed.append(kwargs.get("cancel_check"))
                kwargs["cancel_check"]()
                return ImageUefiAnalysis(())

            with (
                patch(
                    "isopropyl.images.scan_image_contents",
                    return_value=([ImageMember(
                        "EFI/BOOT/BOOTX64.EFI", 1, "file",
                    )], True),
                ),
                patch(
                    "isopropyl.images.inspect_iso_uefi_payloads",
                    side_effect=inspect_uefi,
                ),
                patch(
                    "isopropyl.images.inspect_eltorito_file",
                    side_effect=ElToritoNotFound("fixture"),
                ),
            ):
                inspect_image(path, cancel_check=outer_cancel)

            self.assertEqual(len(observed), 1)
            self.assertTrue(callable(observed[0]))
            self.assertGreater(callback_checks, 1)

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

    def test_vtsi_inspection_uses_sparse_prefix_tail_and_reports_both_sizes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.vtsi"
            expanded = bytearray(256 * 512)
            add_valid_mbr(expanded)
            expanded[-512:] = b"T" * 512
            path.write_bytes(vtsi_fixture(
                bytes(expanded), ((0, 1), (len(expanded) // 512 - 1, 1)),
            ))
            stored_size = path.stat().st_size

            from isopropyl.vtsi import read_vtsi_at as real_read_vtsi_at
            with (
                patch(
                    "isopropyl.sources.read_vtsi_at",
                    wraps=real_read_vtsi_at,
                ) as sparse_read,
                patch("isopropyl.sources.iter_vtsi_chunks") as iterator,
                patch("isopropyl.images.scan_image_contents") as catalog,
            ):
                result = inspect_image(path)

            self.assertEqual(result.size, len(expanded))
            self.assertEqual(result.container_size, stored_size)
            self.assertEqual(result.sparse_format, "VTSI")
            self.assertEqual(result.virtual_format, "")
            self.assertEqual(result.kind, "Sparse disk image (VTSI)")
            self.assertEqual(result.layout, "Sparse VTSI disk image")
            self.assertTrue(result.has_mbr)
            self.assertTrue(result.raw_compatible)
            iterator.assert_not_called()
            catalog.assert_not_called()
            self.assertEqual(len(sparse_read.call_args_list), 2)
            self.assertTrue(all(
                call.args[3] <= max(17 * 2048, 16 * 1024 * 1024 + 3 * 4096)
                for call in sparse_read.call_args_list
            ))

    def test_vtsi_inspection_limit_and_cancellation_fail_before_expanded_stream(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.vtsi"
            expanded = bytearray(16 * 512)
            add_valid_mbr(expanded)
            path.write_bytes(vtsi_fixture(bytes(expanded), ((0, 1),)))

            with (
                patch("isopropyl.sources.iter_vtsi_chunks") as iterator,
                self.assertRaises(ExpandedImageTooLarge),
            ):
                inspect_image(path, maximum_expanded_bytes=len(expanded) - 1)
            iterator.assert_not_called()

            checks = 0

            def cancel() -> None:
                nonlocal checks
                checks += 1
                if checks >= 3:
                    raise ImageInspectionCancelled("cancel VTSI inspection")

            with self.assertRaisesRegex(
                ImageInspectionCancelled, "cancel VTSI inspection",
            ):
                inspect_image(path, cancel_check=cancel)

    def test_compressed_inspection_enforces_an_expanded_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img.gz"
            path.write_bytes(gzip.compress(b"A" * 8192))

            with self.assertRaisesRegex(
                ExpandedImageTooLarge, "inspection limit",
            ):
                inspect_image(path, maximum_expanded_bytes=4096)

    def test_compressed_virtual_dispatch_reports_outer_decoded_and_guest_sizes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                (root / "disk.qcow2.gz", None, "gzip", "QCOW2"),
                (root / "download.zip", "nested/disk.vhdx", "zip", "VHDX"),
            )
            for path, zip_member, compression, display_format in cases:
                with self.subTest(path=path.name):
                    if zip_member is None:
                        path.write_bytes(b"compressed fixture")
                    else:
                        with zipfile.ZipFile(path, "w") as archive:
                            archive.writestr(zip_member, b"virtual fixture")
                    status = path.stat()
                    info = SimpleNamespace(
                        virtual_size=8192,
                        display_format=display_format,
                    )
                    prepared = SimpleNamespace(
                        info=info,
                        compression=compression,
                        decoded_size=3072,
                        close=Mock(),
                    )
                    preparer = Mock()
                    preparer.prepare.return_value = prepared
                    with patch(
                        "isopropyl.images.CompressedVirtualDiskPreparer",
                        return_value=preparer,
                    ):
                        result = inspect_image(path)

                    self.assertEqual(result.size, 8192)
                    self.assertEqual(result.virtual_format, display_format)
                    self.assertEqual(result.compression, compression)
                    self.assertEqual(result.container_size, status.st_size)
                    self.assertEqual(result.decoded_container_size, 3072)
                    self.assertEqual(result.layout, f"Virtual {display_format} disk")
                    self.assertFalse(result.contents_scanned)
                    expected_identity = (
                        status.st_dev, status.st_ino, status.st_size,
                        status.st_mtime_ns, status.st_ctime_ns,
                    )
                    self.assertEqual(
                        preparer.prepare.call_args.kwargs["expected_identity"],
                        expected_identity,
                    )
                    prepared.close.assert_called_once()

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
                "install.wim", "install.esd", "capture.ffu",
                "install.wim.zst",
            ):
                with self.subTest(name=name):
                    path = root / name
                    path.write_bytes(b"not a raw disk")
                    with self.assertRaisesRegex(OSError, "cannot be written|not accepted"):
                        inspect_image(path)

            invalid_vtsi = root / "image.vtsi"
            invalid_vtsi.write_bytes(b"not a VTSI")
            with self.assertRaisesRegex(ImageSourceError, "Could not inspect"):
                inspect_image(invalid_vtsi)

            compressed_vtsi = root / "disk.vtsi.gz"
            compressed_vtsi.write_bytes(gzip.compress(b"not a VTSI"))
            with self.assertRaisesRegex(OSError, "not accepted"):
                inspect_image(compressed_vtsi)

    def test_usb_and_wic_are_explicit_raw_disk_image_aliases(self):
        self.assertTrue({".usb", ".wic"}.issubset(RAW_IMAGE_SUFFIXES))
        self.assertTrue(RAW_IMAGE_SUFFIXES.isdisjoint(NON_RAW_SUFFIXES))
        self.assertEqual(SPARSE_SUFFIXES, frozenset({".vtsi"}))
        self.assertTrue(SPARSE_SUFFIXES.isdisjoint(NON_RAW_SUFFIXES))
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
            result = calculate_checksums(
                path, lambda done, total: progress.append((done, total)),
            )
            self.assertEqual(result["SHA-256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(result["SHA-512"], hashlib.sha512(payload).hexdigest())
            self.assertEqual(progress[-1], (len(payload), len(payload)))

    def test_checksum_rejects_a_symbolic_link(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.img"
            target.write_bytes(b"approved")
            link = Path(directory) / "image.img"
            link.symlink_to(target)

            with self.assertRaisesRegex(OSError, "securely open"):
                calculate_checksums(link)

    def test_checksum_rejects_fifo_without_blocking_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.img"
            os.mkfifo(path)

            with self.assertRaisesRegex(OSError, "not a regular file"):
                calculate_checksums(path)

    def test_checksum_rejects_wrong_expected_identity_before_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.img"
            path.write_bytes(b"approved")
            expected = list(self.file_identity(path))
            expected[2] += 1

            with (
                patch("isopropyl.images.os.read", wraps=os.read) as read,
                self.assertRaisesRegex(OSError, "changed before checksums"),
            ):
                calculate_checksums(path, expected_identity=tuple(expected))

            read.assert_not_called()

    def test_checksum_rejects_path_replacement_without_reading_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.img"
            original = Path(directory) / "original.img"
            payload = b"a" * (8 * 1024 * 1024 + 17)
            path.write_bytes(payload)
            expected = self.file_identity(path)
            progress: list[tuple[int, int]] = []

            def replace_after_first_block(done: int, total: int) -> None:
                progress.append((done, total))
                if len(progress) == 1:
                    path.rename(original)
                    path.write_bytes(b"b" * len(payload))

            with self.assertRaisesRegex(OSError, "image changed"):
                calculate_checksums(
                    path, replace_after_first_block, expected_identity=expected,
                )

            self.assertEqual(progress, [(4 * 1024 * 1024, len(payload))])
            self.assertEqual(original.read_bytes(), payload)

    def test_checksum_catches_same_size_rewrite_with_restored_mtime(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.img"
            payload = b"approved checksum payload"
            path.write_bytes(payload)
            expected = self.file_identity(path)
            changed = False

            def rewrite(_done: int, _total: int) -> None:
                nonlocal changed
                if changed:
                    return
                changed = True
                path.write_bytes(b"x" * len(payload))
                os.utime(path, ns=(path.stat().st_atime_ns, expected[3]))

            with self.assertRaisesRegex(OSError, "image changed"):
                calculate_checksums(path, rewrite, expected_identity=expected)

    def test_checksum_cancellation_is_checked_before_and_during_io(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.img"
            path.write_bytes(b"a" * (5 * 1024 * 1024))
            expected = self.file_identity(path)

            def cancelled() -> None:
                raise ChecksumCancelled("cancelled fixture")

            with self.assertRaises(ChecksumCancelled):
                calculate_checksums(
                    path, expected_identity=expected, cancel_check=cancelled,
                )

            cancel_now = False

            def check_midstream() -> None:
                if cancel_now:
                    raise ChecksumCancelled("cancelled fixture")

            def progress(_done: int, _total: int) -> None:
                nonlocal cancel_now
                cancel_now = True

            with self.assertRaises(ChecksumCancelled):
                calculate_checksums(
                    path, progress, expected_identity=expected,
                    cancel_check=check_midstream,
                )

    def test_checksum_closes_descriptor_when_progress_callback_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.img"
            path.write_bytes(b"approved")
            opened: list[int] = []
            real_open = os.open

            def record_open(*args, **kwargs) -> int:
                descriptor = real_open(*args, **kwargs)
                opened.append(descriptor)
                return descriptor

            def fail_progress(_done: int, _total: int) -> None:
                raise RuntimeError("callback failed")

            with (
                patch("isopropyl.images.os.open", side_effect=record_open),
                patch("isopropyl.images.os.close", wraps=os.close) as close,
                self.assertRaisesRegex(RuntimeError, "callback failed"),
            ):
                calculate_checksums(path, fail_progress)

            self.assertEqual(len(opened), 1)
            close.assert_called_once_with(opened[0])

    def test_classifies_bios_uefi_architecture_and_windows_installer(self):
        modes, architectures, bootloader, windows = classify_boot_paths([
            "bootmgr", "efi/boot/bootx64.efi", "sources/install.wim",
        ])
        self.assertEqual(modes, ("BIOS", "UEFI"))
        self.assertEqual(architectures, ("x64",))
        self.assertEqual(bootloader, "Windows Boot Manager")
        self.assertTrue(windows)

    def test_classifies_complete_regular_freedos_root_markers(self):
        paths = [
            "KERNEL.SYS", "COMMAND.COM", "FDCONFIG.SYS", "FDAUTO.BAT",
            "SETUP.BAT",
        ]
        members = tuple(
            ImageMember(path, index + 1, "file")
            for index, path in enumerate(paths)
        )

        modes, architectures, bootloader, windows = classify_boot_paths(
            paths, members=members,
        )

        self.assertEqual(modes, ("BIOS",))
        self.assertEqual(architectures, ("x86",))
        self.assertEqual(bootloader, "FreeDOS")
        self.assertFalse(windows)

    def test_freedos_paths_without_a_member_catalog_are_not_authoritative(self):
        paths = [
            "kernel.sys", "command.com", "fdconfig.sys", "fdauto.bat",
            "setup.bat",
        ]

        modes, architectures, bootloader, windows = classify_boot_paths(paths)

        self.assertEqual(modes, ())
        self.assertEqual(architectures, ())
        self.assertEqual(bootloader, "Unknown")
        self.assertFalse(windows)

    def test_incomplete_or_unsafe_freedos_markers_are_not_classified(self):
        paths = [
            "kernel.sys", "command.com", "fdconfig.sys", "fdauto.bat",
            "setup.bat",
        ]
        complete = tuple(ImageMember(path, 1, "file") for path in paths)
        cases = {
            "incomplete": complete[:-1],
            "directory": complete[:-1] + (ImageMember("setup.bat", 1, "directory"),),
            "symlink": complete[:-1] + (
                ImageMember("setup.bat", 1, "symlink", "real-setup.bat"),
            ),
            "zero-size": complete[:-1] + (ImageMember("setup.bat", 0, "file"),),
        }

        for name, members in cases.items():
            with self.subTest(case=name):
                modes, architectures, bootloader, windows = classify_boot_paths(
                    paths, members=members,
                )
                self.assertEqual(modes, ())
                self.assertEqual(architectures, ())
                self.assertEqual(bootloader, "Unknown")
                self.assertFalse(windows)

    def test_classifies_up_to_four_total_canonical_and_nested_regular_wims(self):
        paths = (
            "sources/install.wim",
            "editions/home/sources/install.wim",
            "editions/pro/sources/INSTALL.WIM",
            "recovery/arm64/sources/install.wim",
        )
        result = classify_windows_installer_members(tuple(
            ImageMember(path, index + 1, "file")
            for index, path in enumerate(paths)
        ))

        self.assertTrue(result.valid)
        self.assertTrue(result.has_installer)
        self.assertEqual(result.wim_paths, paths)
        self.assertIsNone(result.esd_path)

        _, _, _, detected = classify_boot_paths(
            list(paths),
            members=tuple(
                ImageMember(path, index + 1, "file")
                for index, path in enumerate(paths)
            ),
        )
        self.assertTrue(detected)

    def test_retains_only_canonical_install_esd_detection(self):
        canonical = classify_windows_installer_members((
            ImageMember("SoUrCeS/INSTALL.ESD", 12, "file"),
        ))
        nested = classify_windows_installer_members((
            ImageMember("edition/sources/install.esd", 12, "file"),
        ))

        self.assertTrue(canonical.has_installer)
        self.assertEqual(canonical.esd_path, "SoUrCeS/INSTALL.ESD")
        self.assertTrue(nested.valid)
        self.assertFalse(nested.has_installer)

    def test_fifth_or_non_regular_wim_fails_closed(self):
        five = tuple(
            ImageMember(f"edition-{index}/sources/install.wim", 1, "file")
            for index in range(5)
        )
        self.assertFalse(classify_windows_installer_members(five).valid)
        for kind, link in (("directory", ""), ("symlink", "target")):
            with self.subTest(kind=kind):
                result = classify_windows_installer_members((
                    ImageMember("edition/sources/install.wim", 1, kind, link),
                ))
                self.assertFalse(result.valid)
                self.assertFalse(result.has_installer)

    def test_unsafe_or_casefold_unicode_alias_wim_fails_closed(self):
        unsafe = (
            "/sources/install.wim",
            "../sources/install.wim",
            "C:/sources/install.wim",
            r"edition\sources\install.wim",
            "edition/../sources/install.wim",
            "edition\x00/sources/install.wim",
            "edition%name/sources/install.wim",
            "edition/CONIN$/sources/install.wim",
            "edition/CONOUT$.txt/sources/install.wim",
            "edition/COM¹/sources/install.wim",
            "edition/LPT³.log/sources/install.wim",
            "edition/ leading/sources/install.wim",
            "edition/trailing /sources/install.wim",
            "edition/\x85/sources/install.wim",
            "edition/\u2066/sources/install.wim",
            "edition/\ud800/sources/install.wim",
            "cafe\u0301/sources/install.wim",
            f"{'a' * 256}/sources/install.wim",
            f"{'/'.join(['a' * 200] * 6)}/sources/install.wim",
            f"{'/'.join(['a'] * 15)}/sources/install.wim",
        )
        for path in unsafe:
            with self.subTest(path=path):
                result = classify_windows_installer_members((
                    ImageMember(path, 1, "file"),
                ))
                self.assertFalse(result.valid)

        aliases = (
            (
                ImageMember("Edition/sources/install.wim", 1, "file"),
                ImageMember("edition/SOURCES/INSTALL.WIM", 1, "file"),
            ),
            (
                ImageMember("café/sources/install.wim", 1, "file"),
                ImageMember("cafe\u0301/sources/install.wim", 1, "file"),
            ),
            (
                ImageMember("Straße/sources/install.wim", 1, "file"),
                ImageMember("STRASSE/sources/install.wim", 1, "file"),
            ),
        )
        for members in aliases:
            with self.subTest(members=members):
                result = classify_windows_installer_members(members)
                self.assertFalse(result.valid)
                self.assertEqual(result.wim_paths, ())

    def test_path_only_classification_does_not_authorize_nested_wim(self):
        _, _, _, canonical = classify_boot_paths(["sources/install.wim"])
        _, _, _, nested = classify_boot_paths(["edition/sources/install.wim"])
        self.assertTrue(canonical)
        self.assertFalse(nested)

    def test_inspection_detects_safe_nested_wims_but_not_a_fifth(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "windows.iso"
            payload = bytearray(18 * 2048)
            offset = 16 * 2048
            payload[offset + 1:offset + 6] = b"CD001"
            path.write_bytes(payload)

            accepted = [
                ImageMember(f"edition-{index}/sources/install.wim", 1, "file")
                for index in range(4)
            ]
            with (
                patch(
                    "isopropyl.images.scan_image_contents",
                    return_value=(accepted, True),
                ),
                patch(
                    "isopropyl.images.inspect_eltorito_file",
                    side_effect=ElToritoNotFound,
                ),
            ):
                result = inspect_image(path)
            self.assertTrue(result.contents_scanned)
            self.assertTrue(result.has_windows_installer)

            with (
                patch(
                    "isopropyl.images.scan_image_contents",
                    return_value=(accepted + [
                        ImageMember("edition-4/sources/install.wim", 1, "file"),
                    ], True),
                ),
                patch(
                    "isopropyl.images.inspect_eltorito_file",
                    side_effect=ElToritoNotFound,
                ),
            ):
                result = inspect_image(path)
            self.assertFalse(result.has_windows_installer)

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

    def test_el_torito_uefi_without_complete_file_catalog_marks_dbx_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.iso"
            data = bytearray(18 * 2048)
            offset = 16 * 2048
            data[offset + 1:offset + 6] = b"CD001"
            path.write_bytes(data)
            entry = BootEntry(
                1, True, BootPlatform.EFI, "", True,
                EmulationType.NO_EMULATION, 0, 0, 4, 24,
                24 * 2048, 2048, 25 * 2048, 0, b"",
            )
            catalog = ElToritoInspection(
                len(data), 20, 20 * 2048, 64, 3,
                ValidationEntry(BootPlatform.EFI, "TEST", 0),
                (entry,),
            )
            with (
                patch(
                    "isopropyl.images.scan_image_contents",
                    return_value=([], False),
                ),
                patch(
                    "isopropyl.images.inspect_eltorito_file",
                    return_value=catalog,
                ),
                patch(
                    "isopropyl.images.inspect_iso_uefi_payloads",
                    return_value=ImageUefiAnalysis((), (), 0, 0, True),
                ),
            ):
                result = inspect_image(path)
            self.assertEqual(result.boot_modes, ("UEFI",))
            self.assertFalse(result.contents_scanned)
            self.assertFalse(result.uefi_analysis_complete)
            self.assertTrue(any(
                "complete ISO file catalog" in issue
                for issue in result.uefi_analysis_issues
            ))

    def test_el_torito_efi_boot_image_prevents_complete_dbx_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.iso"
            data = bytearray(18 * 2048)
            offset = 16 * 2048
            data[offset + 1:offset + 6] = b"CD001"
            path.write_bytes(data)
            entry = BootEntry(
                1, True, BootPlatform.EFI, "", True,
                EmulationType.NO_EMULATION, 0, 0, 4, 24,
                24 * 2048, 2048, 25 * 2048, 0, b"",
            )
            catalog = ElToritoInspection(
                len(data), 20, 20 * 2048, 64, 3,
                ValidationEntry(BootPlatform.EFI, "TEST", 0),
                (entry,),
            )
            with (
                patch(
                    "isopropyl.images.scan_image_contents",
                    return_value=([ImageMember(
                        "EFI/BOOT/BOOTX64.EFI", 1, "file",
                    )], True),
                ),
                patch(
                    "isopropyl.images.inspect_eltorito_file",
                    return_value=catalog,
                ),
                patch(
                    "isopropyl.images.inspect_iso_uefi_payloads",
                    return_value=ImageUefiAnalysis((), (), 1, 1, True),
                ),
            ):
                result = inspect_image(path)
            self.assertTrue(result.contents_scanned)
            self.assertFalse(result.uefi_analysis_complete)
            self.assertTrue(any(
                "EFI El Torito boot image" in issue
                for issue in result.uefi_analysis_issues
            ))

    def test_embedded_fat_fallback_is_pe_inspected_and_adds_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "embedded.iso"
            write_container(
                path,
                make_fat(FatType.FAT12, payload=make_pe()),
            )
            with patch(
                "isopropyl.images.scan_image_contents",
                return_value=([ImageMember("README.txt", 5, "file")], True),
            ):
                result = inspect_image(path)
            self.assertEqual(result.boot_modes, ("UEFI",))
            self.assertEqual(result.architectures, ("x64",))
            self.assertIsNotNone(result.embedded_uefi_fat)
            self.assertEqual(result.embedded_uefi_issues, ())
            self.assertTrue(result.uefi_analysis_complete)
            self.assertEqual(result.uefi_candidate_count, 1)
            self.assertEqual(result.uefi_selected_count, 1)
            self.assertEqual(len(result.uefi_payloads), 1)
            payload = result.uefi_payloads[0]
            self.assertEqual(payload.source_kind, "eltorito-fat")
            self.assertEqual(payload.target_path, "EFI/BOOT/BOOTX64.EFI")
            self.assertTrue(payload.is_uefi_image)

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

    def test_el_torito_parse_failure_makes_visible_uefi_dbx_coverage_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.iso"
            data = bytearray(18 * 2048)
            offset = 16 * 2048
            data[offset + 1:offset + 6] = b"CD001"
            path.write_bytes(data)
            with (
                patch(
                    "isopropyl.images.scan_image_contents",
                    return_value=([ImageMember(
                        "EFI/BOOT/BOOTX64.EFI", 1, "file",
                    )], True),
                ),
                patch(
                    "isopropyl.images.inspect_eltorito_file",
                    side_effect=ElToritoError("invalid boot catalog"),
                ),
                patch(
                    "isopropyl.images.inspect_iso_uefi_payloads",
                    return_value=ImageUefiAnalysis((), (), 1, 1, True),
                ),
            ):
                result = inspect_image(path)
            self.assertEqual(result.boot_modes, ("UEFI",))
            self.assertFalse(result.uefi_analysis_complete)
            self.assertTrue(any(
                "malformed El Torito catalog" in issue
                for issue in result.uefi_analysis_issues
            ))

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
