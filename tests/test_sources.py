from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import gzip
import bz2
import io
import lzma
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from isopropyl.devices import Device
from isopropyl.sources import ExpandedImageTooLarge, ImageSourceError, open_image_source
from isopropyl.writer import ImageWriter, verify_image


PAYLOAD = (b"ISOPROPYL disk image\0" + bytes(range(256))) * 4096


class SourceTests(unittest.TestCase):
    def test_bzip2_alias_streams_the_expanded_image(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img.bzip2"
            payload = b"ISOPROPYL" * 4096
            path.write_bytes(bz2.compress(payload))
            source = open_image_source(path)
            self.assertEqual(source.compression, "bz2")
            self.assertEqual(b"".join(source.chunks()), payload)

    def test_legacy_compress_suffix_is_recognized_without_guessing_zstd(self):
        with tempfile.TemporaryDirectory() as directory:
            upper = Path(directory) / "disk.img.Z"
            lower = Path(directory) / "disk.img.z"
            upper.write_bytes(b"not a valid compress stream")
            lower.write_bytes(b"not a valid compress stream")
            self.assertEqual(open_image_source(upper).compression, "compress-z")
            self.assertEqual(open_image_source(lower).compression, "compress-z")

    def assert_source(self, path: Path) -> None:
        source = open_image_source(path)
        self.assertEqual(source.measure(), len(PAYLOAD))
        self.assertEqual(b"".join(source.chunks(expected_size=len(PAYLOAD))), PAYLOAD)

    def test_standard_library_compression_formats(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gzip_path = root / "disk.img.gz"
            gzip_path.write_bytes(gzip.compress(PAYLOAD))
            bz2_path = root / "disk.iso.bz2"
            bz2_path.write_bytes(bz2.compress(PAYLOAD))
            xz_path = root / "disk.img.xz"
            xz_path.write_bytes(lzma.compress(PAYLOAD, format=lzma.FORMAT_XZ))
            lzma_path = root / "disk.img.lzma"
            lzma_path.write_bytes(lzma.compress(PAYLOAD, format=lzma.FORMAT_ALONE))
            for path in (gzip_path, bz2_path, xz_path, lzma_path):
                with self.subTest(path=path.name):
                    self.assert_source(path)

    def test_single_file_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.zip"
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("nested/disk.iso", PAYLOAD)
            self.assert_source(path)

    def test_zip_rejects_multiple_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("one.img", b"one")
                archive.writestr("two.img", b"two")
            with self.assertRaisesRegex(ImageSourceError, "exactly one"):
                open_image_source(path).measure()

    def test_zstd_with_system_decoder(self):
        executable = shutil.which("zstd")
        if not executable:
            self.skipTest("zstd command is not installed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "disk.img"
            path = root / "disk.img.zst"
            raw.write_bytes(PAYLOAD)
            subprocess.run(
                [executable, "--quiet", "--force", "-o", str(path), str(raw)], check=True,
            )
            self.assert_source(path)

    def test_expansion_limit_is_checked_while_decoding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img.gz"
            path.write_bytes(gzip.compress(PAYLOAD))
            with self.assertRaises(ExpandedImageTooLarge):
                open_image_source(path).measure(maximum=len(PAYLOAD) - 1)

    def test_truncated_compressed_source_has_a_clear_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img.gz"
            path.write_bytes(gzip.compress(PAYLOAD)[:-8])
            with self.assertRaisesRegex(ImageSourceError, "Could not decode"):
                open_image_source(path).measure()

    def test_writer_rejects_oversized_expanded_image_before_unmount(self):
        class TrackingWriter(ImageWriter):
            unmounted = False

            def unmount(self, device: Device) -> None:
                self.unmounted = True

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img.gz"
            path.write_bytes(gzip.compress(PAYLOAD))
            device = Device(
                "/dev/sdz", len(PAYLOAD) - 1, "Test", "", "usb", "S", "", "8:99",
                True, True, False, (), (),
            )
            writer = TrackingWriter(
                which=lambda name: f"/usr/bin/{name}",
                device_lookup=lambda _path: device,
                block_stat=lambda _path: SimpleNamespace(
                    st_mode=stat.S_IFBLK, st_rdev=os.makedev(8, 99),
                ),
            )
            with self.assertRaises(ExpandedImageTooLarge):
                writer.write(path, device, lambda _done, _total: None)
            self.assertFalse(writer.unmounted)

    def test_writer_streams_expanded_bytes_to_privileged_dd(self):
        class NonClosingBuffer(io.BytesIO):
            def close(self) -> None:
                pass

        class FakeProcess:
            def __init__(self) -> None:
                self.stdin = NonClosingBuffer()
                self.stderr = io.BytesIO()
                self.returncode = 0

            def poll(self):
                return self.returncode

            def wait(self):
                return self.returncode

            def terminate(self):
                self.returncode = -15

        class NoUnmountWriter(ImageWriter):
            def unmount(self, device: Device) -> None:
                pass

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img.gz"
            path.write_bytes(gzip.compress(PAYLOAD))
            device = Device(
                "/dev/sdz", len(PAYLOAD), "Test", "", "usb", "S", "", "8:99",
                True, True, False, (), (),
            )
            process = FakeProcess()
            updates: list[tuple[int, int]] = []
            with patch("isopropyl.writer.subprocess.Popen", return_value=process) as popen:
                NoUnmountWriter(
                    which=lambda name: f"/usr/bin/{name}",
                    device_lookup=lambda _path: device,
                    block_stat=lambda _path: SimpleNamespace(
                        st_mode=stat.S_IFBLK, st_rdev=os.makedev(8, 99),
                    ),
                ).write(
                    path, device,
                    lambda done, total: updates.append((done, total)),
                )
            self.assertEqual(process.stdin.getvalue(), PAYLOAD)
            self.assertEqual(updates[-1], (len(PAYLOAD), len(PAYLOAD)))
            command = popen.call_args.args[0]
            self.assertEqual(command[:2], ["/usr/bin/pkexec", "/usr/bin/dd"])
            self.assertNotIn(f"if={path}", command)

    def test_verification_compares_decompressed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "disk.img.gz"
            target = root / "target"
            image.write_bytes(gzip.compress(PAYLOAD))
            target.write_bytes(PAYLOAD + b"unrelated trailing device bytes")
            updates: list[tuple[int, int]] = []
            self.assertTrue(
                ImageWriter().verify(
                    image, str(target), lambda done, total: updates.append((done, total)),
                )
            )
            self.assertEqual(updates[-1], (len(PAYLOAD) * 2, len(PAYLOAD) * 2))
            self.assertEqual(
                [done for done, _total in updates], sorted(done for done, _total in updates),
            )
            self.assertTrue(verify_image(image, str(target), lambda _done, _total: None))


if __name__ == "__main__":
    unittest.main()
