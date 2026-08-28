# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
import tempfile
import threading
import unittest
import zipfile
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import isopropyl.freedos_downloads as downloads
from isopropyl.freedos_downloads import (
    DownloadedFreeDosImage, FreeDosArchiveMember, FreeDosDownloadCancelled,
    FreeDosDownloadCatalogError, FreeDosDownloadError, FreeDosUsbDownloader,
    available_freedos_images, load_freedos_image_catalog,
)


class Response(BytesIO):
    def __init__(
        self, body: bytes, url: str, *, status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(body)
        self.url = url
        self.status = status
        self.headers = headers or {"Content-Length": str(len(body))}

    def geturl(self) -> str:
        return self.url

    def getcode(self) -> int:
        return self.status


def synthetic_disk(size: int = 1024 * 1024) -> bytes:
    image = bytearray(size)
    image[510:512] = b"\x55\xaa"
    entry = bytearray(16)
    entry[0] = 0x80
    entry[4] = 0x04
    struct.pack_into("<II", entry, 8, 1, size // 512 - 1)
    image[446:462] = entry
    boot = 512
    image[boot:boot + 3] = b"\xeb\x3c\x90"
    image[boot + 3:boot + 11] = b"FRDOS5.1"
    struct.pack_into("<H", image, boot + 11, 512)
    image[boot + 43:boot + 54] = b"TEST-DISK  "
    image[boot + 54:boot + 62] = b"FAT16   "
    image[boot + 510:boot + 512] = b"\x55\xaa"
    # Make the transport large enough to exercise bounded streaming while
    # retaining the exact reviewed boot structures above.
    for offset in range(1024, size, 32):
        image[offset:offset + 32] = hashlib.sha256(
            offset.to_bytes(8, "little")
        ).digest()
    return bytes(image)


def build_archive(
    image: bytes,
    *,
    image_name: str = "TEST.img",
    image_mode: int = stat.S_IFREG | 0o755,
    image_compression: int = zipfile.ZIP_DEFLATED,
    extra: tuple[tuple[str, bytes], ...] = (),
) -> tuple[bytes, tuple[FreeDosArchiveMember, ...]]:
    payloads = (
        (image_name, "disk-image", image, image_mode, image_compression),
        ("TEST.vmdk", "vmdk-descriptor", b"descriptor", stat.S_IFREG | 0o644, zipfile.ZIP_DEFLATED),
        ("readme.txt", "readme", b"synthetic fixture", stat.S_IFREG | 0o644, zipfile.ZIP_DEFLATED),
    )
    output = BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, _role, body, mode, compression in payloads:
            info = zipfile.ZipInfo(name, (2025, 4, 2, 1, 4, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = compression
            archive.writestr(info, body, compresslevel=9)
        for name, body in extra:
            info = zipfile.ZipInfo(name, (2025, 4, 2, 1, 4, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, body, compresslevel=9)
    archive_bytes = output.getvalue()
    members: list[FreeDosArchiveMember] = []
    with zipfile.ZipFile(BytesIO(archive_bytes)) as archive:
        for info, (_name, role, body, mode, _compression) in zip(
            archive.infolist(), payloads, strict=False,
        ):
            if len(members) == 3:
                break
            members.append(FreeDosArchiveMember(
                info.filename, role, info.file_size, info.compress_size,
                f"{info.CRC:08x}", hashlib.sha256(body).hexdigest(), mode,
            ))
    return archive_bytes, tuple(members)


def fixture_release(
    image: bytes | None = None,
    *,
    archive_bytes: bytes | None = None,
    members: tuple[FreeDosArchiveMember, ...] | None = None,
):
    image = image or synthetic_disk()
    if archive_bytes is None or members is None:
        archive_bytes, members = build_archive(image)
    original = available_freedos_images()[0]
    return replace(
        original,
        id="freedos-test-liteusb-x86",
        release="test",
        edition="TestUSB",
        archive_filename="TEST.zip",
        archive_size=len(archive_bytes),
        archive_sha256=hashlib.sha256(archive_bytes).hexdigest(),
        archive_url="https://download.freedos.org/test/TEST.zip",
        image_filename="TEST.img",
        image_size=len(image),
        image_sha256=hashlib.sha256(image).hexdigest(),
        partition_type=4,
        partition_start_lba=1,
        partition_sectors=len(image) // 512 - 1,
        volume_label="TEST-DISK",
        filesystem="FAT16",
        members=members,
    ), archive_bytes


def verification_body(release) -> bytes:
    return (
        "Download verification hash signatures.\n\n"
        "md5sum:\n"
        "00000000000000000000000000000000  TEST.zip\n"
        "sha256sum:\n"
        f"{release.archive_sha256}  {release.archive_filename}\n"
        "sha512sum:\n"
        f"{'0' * 128}  {release.archive_filename}\n"
    ).encode("ascii")


def opener_for(release, archive_bytes: bytes, calls: list[tuple[str, str | None]]):
    metadata = verification_body(release)

    def opener(request, **_kwargs):
        url = request.full_url
        range_header = request.headers.get("Range")
        calls.append((url, range_header))
        if url == release.hashes_url:
            return Response(metadata, url)
        if url != release.archive_url:
            raise AssertionError(f"unexpected URL: {url}")
        if range_header:
            prefix = "bytes="
            if not range_header.startswith(prefix) or not range_header.endswith("-"):
                raise AssertionError(range_header)
            start = int(range_header[len(prefix):-1])
            body = archive_bytes[start:]
            return Response(
                body, url, status=206,
                headers={
                    "Content-Length": str(len(body)),
                    "Content-Range": f"bytes {start}-{len(archive_bytes) - 1}/{len(archive_bytes)}",
                },
            )
        return Response(archive_bytes, url)

    return opener


class FreeDosDownloadTests(unittest.TestCase):
    def test_private_directory_listing_uses_an_independent_cursor(self):
        with tempfile.TemporaryDirectory() as directory:
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                first = os.open(
                    "first", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600, dir_fd=descriptor,
                )
                os.close(first)
                self.assertEqual(
                    downloads._list_directory(descriptor), ["first"],
                )
                second = os.open(
                    "second", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600, dir_fd=descriptor,
                )
                os.close(second)
                self.assertEqual(
                    set(downloads._list_directory(descriptor)),
                    {"first", "second"},
                )
            finally:
                os.close(descriptor)

    def test_bundled_catalog_has_exact_official_usb_profiles_without_network(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            releases = load_freedos_image_catalog()
        self.assertEqual(
            [release.id for release in releases],
            ["freedos-1.4-liteusb-x86", "freedos-1.4-fullusb-x86"],
        )
        lite, full = releases
        self.assertEqual(lite.archive_size, 17_671_175)
        self.assertEqual(
            lite.archive_sha256,
            "857dcd2ebf9d3d094320154db5fb5b830acba6fb98f981a95a0ca7ab3350338b",
        )
        self.assertEqual(
            lite.image_sha256,
            "f539d456b792594bc3ca59d4e0f4c23d4f1fee73370c1390b2da245400718d36",
        )
        self.assertEqual(full.archive_size, 668_803_454)
        self.assertEqual(full.image_size, 1_073_741_824)
        self.assertEqual(full.members[0].crc32, "13a626d4")
        self.assertIs(available_freedos_images()[0], available_freedos_images()[0])

    def test_catalog_rejects_unknown_fields_bad_urls_and_member_aliases(self):
        source = Path(downloads.__file__).parent / "data/freedos-images-v1.json"
        payload = json.loads(source.read_text("utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            payload["images"][0]["surprise"] = True
            path.write_text(json.dumps(payload), "utf-8")
            with self.assertRaises(FreeDosDownloadCatalogError):
                load_freedos_image_catalog(path)
            del payload["images"][0]["surprise"]
            payload["images"][0]["archive_url"] = "https://user@download.freedos.org/file.zip"
            path.write_text(json.dumps(payload), "utf-8")
            with self.assertRaises(FreeDosDownloadCatalogError):
                load_freedos_image_catalog(path)
            payload = json.loads(source.read_text("utf-8"))
            payload["images"][0]["members"][1]["name"] = "fd14lite.IMG"
            path.write_text(json.dumps(payload), "utf-8")
            with self.assertRaises(FreeDosDownloadCatalogError):
                load_freedos_image_catalog(path)

    def test_equal_but_unbound_release_is_rejected_before_io_or_disk(self):
        trusted = available_freedos_images()[0]
        crafted = replace(trusted)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / trusted.image_filename
            with self.assertRaisesRegex(FreeDosDownloadCatalogError, "exact catalog"):
                FreeDosUsbDownloader().download(
                    crafted, destination,
                    opener=lambda *_args, **_kwargs: self.fail("network used"),
                )
            self.assertEqual(os.listdir(directory), [])

    def test_full_download_extracts_only_image_and_cleans_private_state(self):
        release, archive = fixture_release()
        calls: list[tuple[str, str | None]] = []
        progress: list[tuple[int, int]] = []
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ):
            destination = Path(directory) / release.image_filename
            result = FreeDosUsbDownloader().download(
                release, destination, lambda done, total: progress.append((done, total)),
                opener=opener_for(release, archive, calls), overall_timeout=30,
            )
            self.assertEqual(result, DownloadedFreeDosImage(
                destination, release.id, release.image_size,
                release.image_sha256, release.archive_sha256,
                (
                    destination.stat().st_dev, destination.stat().st_ino,
                    destination.stat().st_size, destination.stat().st_mtime_ns,
                ),
            ))
            self.assertEqual(destination.read_bytes(), synthetic_disk())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertEqual(os.listdir(directory), [release.image_filename])
        self.assertEqual([url for url, _range in calls], [release.hashes_url, release.archive_url])
        self.assertTrue(progress)
        self.assertEqual(progress[-1], (release.archive_size + release.image_size,) * 2)
        self.assertEqual(
            progress.count((release.archive_size + release.image_size,) * 2), 1,
        )
        self.assertEqual(progress, sorted(progress))

    def test_cancelled_extraction_keeps_verified_archive_then_reuses_it_offline(self):
        release, archive = fixture_release()
        event = threading.Event()
        calls: list[tuple[str, str | None]] = []
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ):
            destination = Path(directory) / release.image_filename

            def cancel_during_extraction(done: int, _total: int) -> None:
                if done > release.archive_size:
                    event.set()

            with self.assertRaises(FreeDosDownloadCancelled):
                FreeDosUsbDownloader(event).download(
                    release, destination, cancel_during_extraction,
                    opener=opener_for(release, archive, calls), overall_timeout=30,
                )
            self.assertFalse(destination.exists())
            stage = Path(directory) / downloads._private_stage_name(release)
            self.assertEqual(os.listdir(stage), [release.archive_filename])
            result = FreeDosUsbDownloader().download(
                release, destination,
                opener=lambda *_args, **_kwargs: self.fail("network used for cache"),
                overall_timeout=30,
            )
            self.assertEqual(result.path, destination)
            self.assertEqual(os.listdir(directory), [release.image_filename])

    def test_official_hash_row_mismatch_fails_before_archive_request(self):
        release, archive = fixture_release()
        wrong = verification_body(replace(release, archive_sha256="0" * 64))
        calls: list[str] = []

        def opener(request, **_kwargs):
            calls.append(request.full_url)
            return Response(wrong, request.full_url)

        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ):
            with self.assertRaisesRegex(FreeDosDownloadError, "no longer publishes"):
                FreeDosUsbDownloader().download(
                    release, Path(directory) / release.image_filename,
                    opener=opener, overall_timeout=30,
                )
            self.assertEqual(calls, [release.hashes_url])
            self.assertEqual(os.listdir(directory), [])
        self.assertTrue(archive)

    def test_metadata_redirect_length_encoding_and_ambiguity_fail_closed(self):
        release, _archive = fixture_release()
        cases = (
            Response(verification_body(release), "https://www.freedos.org/other"),
            Response(b"x", release.hashes_url, headers={"Content-Length": "9" * 21}),
            Response(
                verification_body(release), release.hashes_url,
                headers={
                    "Content-Length": str(len(verification_body(release))),
                    "Content-Encoding": "gzip",
                },
            ),
            Response(b"\xff", release.hashes_url),
            Response(
                verification_body(release) + b"sha256sum:\n",
                release.hashes_url,
            ),
        )
        for response in cases:
            with self.subTest(body=response.getvalue()[:12]):
                with tempfile.TemporaryDirectory() as directory, patch.object(
                    downloads, "available_freedos_images", return_value=(release,),
                ):
                    with self.assertRaises(FreeDosDownloadError):
                        FreeDosUsbDownloader().download(
                            release, Path(directory) / release.image_filename,
                            opener=lambda *_args, **_kwargs: response,
                            overall_timeout=30,
                        )

    def test_outer_archive_checksum_mismatch_is_never_extracted(self):
        release, archive = fixture_release()
        changed = bytearray(archive)
        changed[-1] ^= 1
        calls: list[tuple[str, str | None]] = []
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ), patch.object(downloads, "_extract_disk_member") as extract:
            with self.assertRaisesRegex(FreeDosDownloadError, "checksum"):
                FreeDosUsbDownloader().download(
                    release, Path(directory) / release.image_filename,
                    opener=opener_for(release, bytes(changed), calls),
                    overall_timeout=30,
                )
            extract.assert_not_called()

    def test_corrupted_completed_cache_is_removed_then_redownloaded(self):
        release, archive = fixture_release()
        corrupted = bytearray(archive)
        corrupted[-1] ^= 1
        calls: list[tuple[str, str | None]] = []
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ):
            destination = Path(directory) / release.image_filename
            stage = Path(directory) / downloads._private_stage_name(release)
            stage.mkdir(mode=0o700)
            cached = stage / release.archive_filename
            cached.write_bytes(corrupted)
            cached.chmod(0o600)

            with self.assertRaisesRegex(FreeDosDownloadError, "changed"):
                FreeDosUsbDownloader().download(
                    release, destination,
                    opener=lambda *_args, **_kwargs: self.fail("network used"),
                    overall_timeout=30,
                )
            self.assertFalse(cached.exists())
            self.assertFalse(destination.exists())

            result = FreeDosUsbDownloader().download(
                release, destination,
                opener=opener_for(release, archive, calls), overall_timeout=30,
            )
            self.assertEqual(result.path, destination)
            self.assertEqual(
                [url for url, _range in calls],
                [release.hashes_url, release.archive_url],
            )

    def test_completed_cache_requires_only_new_image_extraction_space(self):
        release, archive = fixture_release()
        required: list[int] = []
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ), patch.object(
            downloads, "_ensure_free_space",
            side_effect=lambda _parent, amount: required.append(amount),
        ):
            destination = Path(directory) / release.image_filename
            stage = Path(directory) / downloads._private_stage_name(release)
            stage.mkdir(mode=0o700)
            cached = stage / release.archive_filename
            cached.write_bytes(archive)
            cached.chmod(0o600)

            result = FreeDosUsbDownloader().download(
                release, destination,
                opener=lambda *_args, **_kwargs: self.fail("network used"),
                overall_timeout=30,
            )

            self.assertEqual(result.path, destination)
            self.assertEqual(required, [release.image_size])

    def test_exact_zip_catalog_rejects_extra_member_mode_and_compression(self):
        image = synthetic_disk()
        normal_archive, normal_members = build_archive(image)
        attacks = (
            build_archive(image, extra=(("extra.txt", b"extra"),))[0],
            build_archive(image, image_mode=stat.S_IFREG | 0o644)[0],
            build_archive(image, image_compression=zipfile.ZIP_STORED)[0],
        )
        for attack in attacks:
            release, _ = fixture_release(
                image, archive_bytes=attack, members=normal_members,
            )
            calls: list[tuple[str, str | None]] = []
            with self.subTest(size=len(attack)), tempfile.TemporaryDirectory() as directory, patch.object(
                downloads, "available_freedos_images", return_value=(release,),
            ):
                with self.assertRaisesRegex(FreeDosDownloadError, "archive"):
                    FreeDosUsbDownloader().download(
                        release, Path(directory) / release.image_filename,
                        opener=opener_for(release, attack, calls), overall_timeout=30,
                    )
        self.assertTrue(normal_archive)

    def test_wrong_inner_hash_cannot_be_published(self):
        release, archive = fixture_release()
        bad_member = replace(release.members[0], sha256="0" * 64)
        release = replace(
            release, image_sha256="0" * 64,
            members=(bad_member,) + release.members[1:],
        )
        calls: list[tuple[str, str | None]] = []
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ):
            destination = Path(directory) / release.image_filename
            with self.assertRaisesRegex(FreeDosDownloadError, "inner SHA-256"):
                FreeDosUsbDownloader().download(
                    release, destination, opener=opener_for(release, archive, calls),
                    overall_timeout=30,
                )
            self.assertFalse(destination.exists())

    def test_reviewed_mbr_partition_and_fat_identity_are_mandatory(self):
        base = bytearray(synthetic_disk())
        cases: dict[str, bytes] = {}
        missing_mbr = bytearray(base)
        missing_mbr[510:512] = b"\0\0"
        cases["MBR signature"] = bytes(missing_mbr)
        wrong_partition = bytearray(base)
        struct.pack_into("<I", wrong_partition, 446 + 8, 2)
        cases["partition layout"] = bytes(wrong_partition)
        wrong_label = bytearray(base)
        wrong_label[512 + 43:512 + 54] = b"WRONG-LABEL"
        cases["FAT identity"] = bytes(wrong_label)

        for expected_error, image in cases.items():
            release, archive = fixture_release(image)
            calls: list[tuple[str, str | None]] = []
            with self.subTest(expected_error=expected_error), tempfile.TemporaryDirectory() as directory, patch.object(
                downloads, "available_freedos_images", return_value=(release,),
            ):
                destination = Path(directory) / release.image_filename
                with self.assertRaisesRegex(FreeDosDownloadError, expected_error):
                    FreeDosUsbDownloader().download(
                        release, destination,
                        opener=opener_for(release, archive, calls),
                        overall_timeout=30,
                    )
                self.assertFalse(destination.exists())

    def test_archive_mutation_during_extraction_prevents_publication(self):
        release, archive = fixture_release()
        calls: list[tuple[str, str | None]] = []
        real_extract = downloads._extract_disk_member
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ):
            destination = Path(directory) / release.image_filename

            def mutate_after_extract(archive_fd, *args, **kwargs):
                real_extract(archive_fd, *args, **kwargs)
                byte = os.pread(archive_fd, 1, 0)
                writable = os.open(
                    f"/proc/self/fd/{archive_fd}", os.O_WRONLY | os.O_CLOEXEC,
                )
                try:
                    os.pwrite(writable, bytes((byte[0] ^ 1,)), 0)
                    os.fsync(writable)
                finally:
                    os.close(writable)

            with patch.object(
                downloads, "_extract_disk_member", new=mutate_after_extract,
            ), self.assertRaisesRegex(FreeDosDownloadError, "archive changed"):
                FreeDosUsbDownloader().download(
                    release, destination,
                    opener=opener_for(release, archive, calls),
                    overall_timeout=30,
                )
            self.assertFalse(destination.exists())

    def test_existing_destination_and_unsafe_private_stage_make_no_network_calls(self):
        release, archive = fixture_release()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ):
            destination = Path(directory) / release.image_filename
            destination.write_bytes(b"keep")
            with self.assertRaisesRegex(FreeDosDownloadError, "already exists"):
                FreeDosUsbDownloader().download(
                    release, destination,
                    opener=lambda *_args, **_kwargs: self.fail("network used"),
                )
            self.assertEqual(destination.read_bytes(), b"keep")
            destination.unlink()
            stage = Path(directory) / downloads._private_stage_name(release)
            stage.mkdir(mode=0o700)
            (stage / "unexpected").write_bytes(b"keep")
            with self.assertRaisesRegex(FreeDosDownloadError, "unexpected"):
                FreeDosUsbDownloader().download(
                    release, destination,
                    opener=lambda *_args, **_kwargs: self.fail("network used"),
                )
            self.assertEqual((stage / "unexpected").read_bytes(), b"keep")
        self.assertTrue(archive)

    def test_free_space_failure_precedes_network_and_workspace_creation(self):
        release, _archive = fixture_release()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ), patch.object(
            downloads, "_ensure_free_space",
            side_effect=FreeDosDownloadError("not enough free space"),
        ):
            with self.assertRaisesRegex(FreeDosDownloadError, "free space"):
                FreeDosUsbDownloader().download(
                    release, Path(directory) / release.image_filename,
                    opener=lambda *_args, **_kwargs: self.fail("network used"),
                )
            self.assertEqual(os.listdir(directory), [])

    def test_destination_appearance_during_extraction_is_preserved(self):
        release, archive = fixture_release()
        calls: list[tuple[str, str | None]] = []
        created = False
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ):
            destination = Path(directory) / release.image_filename

            def progress(done: int, _total: int) -> None:
                nonlocal created
                if done > release.archive_size and not created:
                    destination.write_bytes(b"do not overwrite")
                    created = True

            with self.assertRaisesRegex(FreeDosDownloadError, "already exists"):
                FreeDosUsbDownloader().download(
                    release, destination, progress,
                    opener=opener_for(release, archive, calls), overall_timeout=30,
                )
            self.assertEqual(destination.read_bytes(), b"do not overwrite")

    def test_final_verification_is_immediately_followed_by_output_link(self):
        release, archive = fixture_release()
        real_link = os.link
        events: list[str] = []
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ):
            destination = Path(directory) / release.image_filename
            stage = Path(directory) / downloads._private_stage_name(release)
            stage.mkdir(mode=0o700)
            archive_path = stage / release.archive_filename
            archive_path.write_bytes(archive)
            archive_path.chmod(0o600)
            real_verify = downloads._final_verify_before_publish

            def verify(*args, **kwargs):
                result = real_verify(*args, **kwargs)
                events.append("verify")
                return result

            def link(*args, **kwargs):
                events.append("link")
                return real_link(*args, **kwargs)

            with patch.object(downloads, "_final_verify_before_publish", new=verify), patch.object(
                downloads.os, "link", new=link,
            ):
                result = FreeDosUsbDownloader().download(
                    release, destination,
                    opener=lambda *_args, **_kwargs: self.fail("network used"),
                    overall_timeout=30,
                )
            self.assertEqual(result.path, destination)
            self.assertEqual(events, ["verify", "link"])

    def test_output_link_is_bound_to_verified_descriptor_not_swapped_stage_name(self):
        release, archive = fixture_release()
        real_link = os.link
        expected_image = synthetic_disk()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ):
            destination = Path(directory) / release.image_filename
            stage = Path(directory) / downloads._private_stage_name(release)
            stage.mkdir(mode=0o700)
            archive_path = stage / release.archive_filename
            archive_path.write_bytes(archive)
            archive_path.chmod(0o600)

            def swap_then_link(*args, **kwargs):
                partial = stage / "image.partial"
                partial.rename(stage / "verified-original")
                forged = bytearray(expected_image)
                forged[-1] ^= 1
                partial.write_bytes(forged)
                partial.chmod(0o600)
                return real_link(*args, **kwargs)

            with patch.object(downloads.os, "link", new=swap_then_link):
                result = FreeDosUsbDownloader().download(
                    release, destination,
                    opener=lambda *_args, **_kwargs: self.fail("network used"),
                    overall_timeout=30,
                )

            self.assertEqual(result.path, destination)
            self.assertEqual(destination.read_bytes(), expected_image)
            self.assertEqual(
                hashlib.sha256(destination.read_bytes()).hexdigest(),
                release.image_sha256,
            )

    def test_postcommit_cleanup_failure_does_not_hide_published_success(self):
        release, archive = fixture_release()
        calls: list[tuple[str, str | None]] = []
        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ), patch.object(
            downloads, "_cleanup_private_stage",
            side_effect=RuntimeError("synthetic cleanup failure"),
        ):
            destination = Path(directory) / release.image_filename
            result = FreeDosUsbDownloader().download(
                release, destination,
                opener=opener_for(release, archive, calls), overall_timeout=30,
            )

            self.assertEqual(result.path, destination)
            self.assertEqual(destination.stat().st_size, release.image_size)
            self.assertEqual(
                hashlib.sha256(destination.read_bytes()).hexdigest(),
                release.image_sha256,
            )

    def test_path_subclass_and_wrong_filename_are_rejected(self):
        release, _archive = fixture_release()
        native_path = type(Path())

        class CraftedPath(native_path):
            pass

        with tempfile.TemporaryDirectory() as directory, patch.object(
            downloads, "available_freedos_images", return_value=(release,),
        ):
            with self.assertRaisesRegex(ValueError, "exact native"):
                FreeDosUsbDownloader().download(
                    release,
                    CraftedPath(directory) / release.image_filename,
                )
            with self.assertRaisesRegex(ValueError, "exact image filename"):
                FreeDosUsbDownloader().download(
                    release, Path(directory) / "renamed.img",
                )


if __name__ == "__main__":
    unittest.main()
