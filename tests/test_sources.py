from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import gzip
import bz2
import io
import lzma
import os
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from isopropyl.devices import Device
from isopropyl.sources import (
    ExpandedImageTooLarge, ImageSourceError, SourceChanged, open_image_source,
)
from isopropyl.writer import ImageWriter, verify_image
from isopropyl.vtsi import VtsiChanged


PAYLOAD = (b"ISOPROPYL disk image\0" + bytes(range(256))) * 4096


def vtsi_fixture(expanded: bytes, stored_ranges: tuple[tuple[int, int], ...]) -> bytes:
    if len(expanded) % 512:
        raise ValueError("expanded VTSI fixture must contain complete sectors")
    signature = int.from_bytes(expanded[440:444], "little")
    data = bytearray()
    records = bytearray()
    for start_sector, sector_count in stored_ranges:
        disk_offset = start_sector * 512
        byte_count = sector_count * 512
        records.extend(struct.pack("<QQQ", start_sector, sector_count, len(data)))
        data.extend(expanded[disk_offset:disk_offset + byte_count])
    if not data or len(data) % 512:
        raise ValueError("stored VTSI fixture data must be nonempty and aligned")
    table_checksum = (~sum(records)) & 0xFFFFFFFF
    padded_records = records + b"\0" * ((-len(records)) % 512)
    footer = bytearray(512)
    struct.pack_into(
        "<8sHHQIIIIQ", footer, 0, b"VENTOY\0\0", 1, 0, len(expanded),
        signature, 0, len(stored_ranges), table_checksum, len(data),
    )
    struct.pack_into("<I", footer, 24, (~sum(footer)) & 0xFFFFFFFF)
    return bytes(data + padded_records + footer)


class SourceTests(unittest.TestCase):
    def test_vtsi_measure_is_constant_space_and_stream_expands_sparse_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.vtsi"
            expanded = bytearray(8 * 512)
            expanded[:512] = b"A" * 512
            expanded[4 * 512:5 * 512] = b"B" * 512
            path.write_bytes(vtsi_fixture(bytes(expanded), ((0, 1), (4, 1))))

            with patch("isopropyl.sources.iter_vtsi_chunks") as iterator:
                source = open_image_source(path)
                self.assertEqual(source.measure(), len(expanded))
                iterator.assert_not_called()
            source.close()

            with open_image_source(path) as reopened:
                self.assertEqual(reopened.sparse_format, "vtsi")
                self.assertTrue(reopened.requires_exact_target_size)
                self.assertEqual(reopened.required_logical_sector_size, 512)
                self.assertFalse(reopened.compressed)
                self.assertEqual(
                    b"".join(reopened.chunks(expected_size=len(expanded))),
                    bytes(expanded),
                )
                with self.assertRaises(ExpandedImageTooLarge):
                    reopened.measure(maximum=len(expanded) - 1)

    def test_vtsi_open_and_stream_preserve_exact_cancellation_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.vtsi"
            expanded = b"A" * (4 * 512)
            path.write_bytes(vtsi_fixture(expanded, ((0, 1),)))
            checks = 0

            def cancel_open() -> None:
                nonlocal checks
                checks += 1
                if checks >= 2:
                    raise RuntimeError("cancel VTSI open")

            with self.assertRaisesRegex(RuntimeError, "cancel VTSI open"):
                open_image_source(path, cancel_check=cancel_open)

            source = open_image_source(path)

            def cancel_stream() -> None:
                raise OSError("cancel VTSI stream")

            with self.assertRaisesRegex(OSError, "cancel VTSI stream"):
                next(source.chunks(cancel_check=cancel_stream))
            source.close()

            exact = VtsiChanged("caller-owned cancellation")

            def cancel_with_backend_type() -> None:
                raise exact

            with self.assertRaises(VtsiChanged) as caught:
                open_image_source(path, cancel_check=cancel_with_backend_type)
            self.assertIs(caught.exception, exact)

    def test_vtsi_identity_change_is_rejected_before_measure_or_sparse_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.vtsi"
            expanded = b"A" * (4 * 512)
            path.write_bytes(vtsi_fixture(expanded, ((0, 1),)))
            source = open_image_source(path)
            path.write_bytes(path.read_bytes()[:-1] + b"X")

            with self.assertRaises(SourceChanged):
                source.measure()
            with self.assertRaises(SourceChanged):
                source.read_sparse_at(0, 512)
            source.close()

    def test_vtsi_fifo_is_rejected_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.vtsi"
            os.mkfifo(path)
            with self.assertRaisesRegex(ImageSourceError, "regular file"):
                open_image_source(path)

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

    def test_compressed_source_fails_closed_across_a_pathname_aba_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "disk.img.gz"
            parked = root / "selected.img.gz"
            attacker = root / "replacement.img.gz"
            path.write_bytes(gzip.compress(PAYLOAD))
            attacker_payload = b"replacement image" * 4096
            attacker.write_bytes(gzip.compress(attacker_payload))
            source = open_image_source(path)
            real_gzip_file = gzip.GzipFile
            swapped = False
            restored = False

            class RestoreAtEof:
                def __init__(self, stream):
                    self.stream = stream

                def read(self, size=-1):
                    nonlocal restored
                    data = self.stream.read(size)
                    if not data and not restored:
                        os.replace(path, attacker)
                        os.replace(parked, path)
                        restored = True
                    return data

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return self.stream.__exit__(*args)

                def __getattr__(self, name):
                    return getattr(self.stream, name)

            def swap_during_decoder_open(*args, **kwargs):
                nonlocal swapped
                if not swapped:
                    os.replace(path, parked)
                    os.replace(attacker, path)
                    swapped = True
                return RestoreAtEof(real_gzip_file(*args, **kwargs))

            decoded = bytearray()
            with patch("isopropyl.sources.gzip.GzipFile", side_effect=swap_during_decoder_open):
                with self.assertRaises(SourceChanged):
                    for block in source.chunks():
                        decoded.extend(block)

            self.assertTrue(swapped)
            self.assertFalse(restored)
            self.assertEqual(decoded, b"")

    def test_compressed_source_rejects_a_symbolic_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.img.gz"
            link = root / "disk.img.gz"
            target.write_bytes(gzip.compress(PAYLOAD))
            link.symlink_to(target)
            with self.assertRaisesRegex(ImageSourceError, "opened safely"):
                open_image_source(link)

    def test_plain_source_rejects_a_symbolic_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.img"
            link = root / "disk.img"
            target.write_bytes(PAYLOAD)
            link.symlink_to(target)

            with self.assertRaisesRegex(ImageSourceError, "opened safely"):
                open_image_source(link)

    def test_source_change_suppresses_the_first_post_change_chunk(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img"
            path.write_bytes(b"A" * (3 * 4 * 1024**2))
            with open_image_source(path) as source:
                blocks = source.chunks()
                self.assertEqual(next(blocks), b"A" * (4 * 1024**2))
                descriptor = os.open(path, os.O_WRONLY)
                try:
                    os.pwrite(descriptor, b"B" * 4096, 2 * 4 * 1024**2)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)

                with self.assertRaises(SourceChanged):
                    next(blocks)

    def test_external_decoder_receives_only_a_bound_descriptor_path(self):
        class FakeProcess:
            def __init__(self):
                self.stdout = tempfile.TemporaryFile()
                self.stdout.write(PAYLOAD)
                self.stdout.seek(0)
                self.stderr = io.BytesIO()
                self.returncode = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

            def terminate(self):
                self.returncode = -15

            def kill(self):
                self.returncode = -9

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img.Z"
            path.write_bytes(b"compressed bytes")
            process = FakeProcess()
            with (
                patch("isopropyl.sources.shutil.which", return_value="/usr/bin/gzip"),
                patch("isopropyl.sources.subprocess.Popen", return_value=process) as popen,
            ):
                source = open_image_source(path)
                self.assertEqual(b"".join(source.chunks()), PAYLOAD)

            command = popen.call_args.args[0]
            descriptor_path = command[-1]
            self.assertTrue(descriptor_path.startswith("/proc/self/fd/"))
            self.assertNotIn(str(path), command)
            self.assertEqual(
                popen.call_args.kwargs["pass_fds"],
                (int(descriptor_path.rsplit("/", 1)[-1]),),
            )

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

    def test_zip_metadata_is_bounded_before_catalog_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("disk.img", PAYLOAD)
            with (
                patch(
                    "isopropyl.sources.ZIP_CENTRAL_DIRECTORY_MAX_BYTES", 1,
                ),
                self.assertRaisesRegex(ImageSourceError, "directory is too large"),
            ):
                open_image_source(path).measure()

    def test_non_sentinel_classic_eocd_cannot_hide_zip64_catalog_size(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("disk.img", PAYLOAD)
            data = path.read_bytes()
            eocd_offset = data.rfind(b"PK\x05\x06")
            self.assertGreaterEqual(eocd_offset, 0)
            eocd = data[eocd_offset:eocd_offset + 22]
            entries = int.from_bytes(eocd[10:12], "little")
            directory_size = int.from_bytes(eocd[12:16], "little")
            directory_offset = int.from_bytes(eocd[16:20], "little")
            zip64_eocd = struct.pack(
                "<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0,
                entries, entries, directory_size, directory_offset,
            )
            locator = struct.pack(
                "<4sIQI", b"PK\x06\x07", 0, eocd_offset, 1,
            )
            path.write_bytes(
                data[:eocd_offset] + zip64_eocd + locator + data[eocd_offset:]
            )

            with (
                patch(
                    "isopropyl.sources.ZIP_CENTRAL_DIRECTORY_MAX_BYTES", 1,
                ),
                self.assertRaisesRegex(ImageSourceError, "directory is too large"),
            ):
                open_image_source(path).measure()

    def test_eocd_entry_count_cannot_understate_actual_catalog_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("directory/", b"")
                archive.writestr("directory/disk.img", PAYLOAD)
            data = bytearray(path.read_bytes())
            eocd_offset = data.rfind(b"PK\x05\x06")
            struct.pack_into("<HH", data, eocd_offset + 8, 1, 1)
            path.write_bytes(data)

            with (
                patch("isopropyl.sources.ZIP_MEMBER_MAX_COUNT", 1),
                self.assertRaisesRegex(ImageSourceError, "too many entries"),
            ):
                open_image_source(path).measure()

    def test_preflight_rejects_a_fake_final_eocd_inside_the_comment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("disk.img", PAYLOAD)
                archive.comment = b"comment" + b"PK\x05\x06" + b"\0" * 18 + b"X"

            with self.assertRaisesRegex(
                ImageSourceError, "end-of-central-directory",
            ):
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

    def test_cancel_check_exception_is_not_recast_as_a_decoder_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img.gz"
            path.write_bytes(gzip.compress(PAYLOAD))

            def cancel() -> None:
                raise RuntimeError("fixture cancellation")

            with self.assertRaisesRegex(RuntimeError, "fixture cancellation"):
                open_image_source(path).measure(cancel_check=cancel)

    def test_external_decoder_wait_is_interruptible(self):
        class BlockingProcess:
            def __init__(self) -> None:
                read_descriptor, self.write_descriptor = os.pipe()
                self.stdout = os.fdopen(read_descriptor, "rb", buffering=0)
                self.stderr = io.BytesIO()
                self.returncode = None

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

            def terminate(self):
                self.returncode = -15
                os.close(self.write_descriptor)

            def kill(self):
                self.returncode = -9

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img.Z"
            path.write_bytes(b"fixture")
            process = BlockingProcess()
            checks = 0

            def cancel() -> None:
                nonlocal checks
                checks += 1
                if checks >= 3:
                    raise RuntimeError("fixture cancellation")

            with (
                patch("isopropyl.sources.shutil.which", return_value="/usr/bin/gzip"),
                patch("isopropyl.sources.subprocess.Popen", return_value=process),
                patch("isopropyl.sources.DECODER_POLL_SECONDS", 0.001),
                self.assertRaisesRegex(RuntimeError, "fixture cancellation"),
            ):
                open_image_source(path).measure(cancel_check=cancel)

            self.assertEqual(process.returncode, -15)

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
            self.assertEqual(
                command[:8],
                [
                    "/usr/bin/pkexec", "/usr/bin/flock", "--exclusive",
                    "--nonblock", "--conflict-exit-code", "75", "--no-fork",
                    "/dev/sdz",
                ],
            )
            self.assertEqual(command[8], "/usr/bin/dd")
            self.assertNotIn(f"if={path}", command)

    def test_writer_streams_vtsi_expanded_disk_in_lba_order(self):
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

            def wait(self, timeout=None):
                return self.returncode

            def terminate(self):
                self.returncode = -15

        class NoUnmountWriter(ImageWriter):
            def unmount(self, device: Device) -> None:
                pass

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.vtsi"
            expanded = bytearray(8 * 512)
            expanded[1 * 512:2 * 512] = b"A" * 512
            expanded[5 * 512:7 * 512] = b"B" * (2 * 512)
            # Source payloads follow catalog order, while the expanded output
            # must follow disk-LBA order.
            path.write_bytes(
                vtsi_fixture(bytes(expanded), ((5, 2), (1, 1)))
            )
            device = Device(
                "/dev/sdz", len(expanded), "Test", "", "usb", "S", "", "8:99",
                True, True, False, (), (), 512,
            )
            process = FakeProcess()
            updates: list[tuple[int, int]] = []
            with patch("isopropyl.writer.subprocess.Popen", return_value=process):
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

            self.assertEqual(process.stdin.getvalue(), bytes(expanded))
            self.assertEqual(updates[-1], (len(expanded), len(expanded)))

    def test_writer_streams_plain_bytes_without_reopening_the_path_in_dd(self):
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

            def wait(self, timeout=None):
                return self.returncode

            def terminate(self):
                self.returncode = -15

        class NoUnmountWriter(ImageWriter):
            def unmount(self, device: Device) -> None:
                pass

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.img"
            path.write_bytes(PAYLOAD)
            device = Device(
                "/dev/sdz", len(PAYLOAD), "Test", "", "usb", "S", "", "8:99",
                True, True, False, (), (),
            )
            process = FakeProcess()
            with patch("isopropyl.writer.subprocess.Popen", return_value=process) as popen:
                NoUnmountWriter(
                    which=lambda name: f"/usr/bin/{name}",
                    device_lookup=lambda _path: device,
                    block_stat=lambda _path: SimpleNamespace(
                        st_mode=stat.S_IFBLK, st_rdev=os.makedev(8, 99),
                    ),
                ).write(path, device, lambda _done, _total: None)

            self.assertEqual(process.stdin.getvalue(), PAYLOAD)
            command = popen.call_args.args[0]
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
