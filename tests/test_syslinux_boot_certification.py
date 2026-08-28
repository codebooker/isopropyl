# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import errno
import fcntl
import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools import certify_syslinux_boot as harness


class _PreparedFixture:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.result = SimpleNamespace(
            image_size=len(data),
            final_image_sha256=hashlib.sha256(data).hexdigest(),
        )

    def chunks(self, chunk_size: int):
        for offset in range(0, len(self.data), chunk_size):
            yield self.data[offset:offset + chunk_size]


class SyslinuxBootCertificationTests(unittest.TestCase):
    def test_source_archive_and_retained_observation_cover_the_real_harness(self):
        root = Path(__file__).resolve().parents[1]
        manifest = {
            line.strip()
            for line in (root / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
        }
        self.assertIn("include tools/certify_freedos_boot.py", manifest)
        self.assertIn("include tools/certify_syslinux_boot.py", manifest)
        self.assertIn(
            "include certifications/syslinux-6.03-seabios-2026-08-28.json",
            manifest,
        )

        observation = json.loads(
            (root / "certifications/syslinux-6.03-seabios-2026-08-28.json")
            .read_text(encoding="utf-8")
        )
        self.assertIs(observation["certified"], True)
        self.assertEqual(observation["markers"], list(harness.BOOT_MARKERS))
        self.assertEqual(
            observation["source_archive"]["sha256"],
            harness.SOURCE_ARCHIVE_SHA256,
        )
        self.assertEqual(
            observation["prepared_image"]["sha256"],
            observation["pipeline"]["final_image_sha256"],
        )
        self.assertRegex(observation["qemu"]["sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertEqual(observation["isolation"]["network"], "none")
        self.assertEqual(
            observation["isolation"]["attached_host_block_devices"], []
        )
        self.assertIs(observation["scope"]["uefi_certified"], False)
        self.assertIs(observation["scope"]["physical_media_certified"], False)

    @staticmethod
    def screen_line(row: int, text: str) -> bytes:
        return f"\x1b[{row};1H{text}".encode("ascii")

    @staticmethod
    def write_test_archive(path: Path, members: dict[str, bytes]) -> None:
        with tarfile.open(path, "w:xz") as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(data))

    def test_source_archive_is_nofollow_hash_bound_and_sealed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / harness.SOURCE_ARCHIVE_FILENAME
            body = b"pinned source archive fixture"
            path.write_bytes(body)
            with (
                patch.object(harness, "SOURCE_ARCHIVE_SIZE", len(body)),
                patch.object(
                    harness,
                    "SOURCE_ARCHIVE_SHA256",
                    hashlib.sha256(body).hexdigest(),
                ),
            ):
                with harness.open_verified_source_archive(path) as archive:
                    seals = fcntl.fcntl(archive.snapshot_fd, fcntl.F_GET_SEALS)
                    self.assertEqual(
                        seals & harness.REQUIRED_MEMFD_SEALS,
                        harness.REQUIRED_MEMFD_SEALS,
                    )
                    writable = os.open(
                        f"/proc/self/fd/{archive.snapshot_fd}",
                        os.O_RDWR | os.O_CLOEXEC,
                    )
                    try:
                        with self.assertRaises(OSError) as write_error:
                            os.pwrite(writable, b"X", 0)
                        self.assertEqual(write_error.exception.errno, errno.EPERM)
                        with self.assertRaises(OSError) as truncate_error:
                            os.ftruncate(writable, 0)
                        self.assertEqual(truncate_error.exception.errno, errno.EPERM)
                    finally:
                        os.close(writable)
                    harness.verify_source_archive_unchanged(archive)
                    path.write_bytes(b"pinned source archive fixturE")
                    with self.assertRaisesRegex(
                        harness.BootCertificationError, "(identity|changed)",
                    ):
                        harness.verify_source_archive_unchanged(archive)

            path.unlink()
            path.symlink_to("/dev/null")
            with self.assertRaisesRegex(
                harness.BootCertificationError, "regular file",
            ):
                harness.open_verified_source_archive(path)

    def test_only_exact_pinned_regular_source_members_are_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / harness.SOURCE_ARCHIVE_FILENAME
            content = b"official member evidence"
            member_path = "syslinux-6.03/bios/core/isolinux.bin"
            self.write_test_archive(path, {member_path: content})
            body = path.read_bytes()
            pin = harness.SourceMemberPin(
                member_path,
                "isolinux.bin",
                len(content),
                hashlib.sha256(content).hexdigest(),
            )
            with (
                patch.object(harness, "SOURCE_ARCHIVE_SIZE", len(body)),
                patch.object(
                    harness,
                    "SOURCE_ARCHIVE_SHA256",
                    hashlib.sha256(body).hexdigest(),
                ),
                patch.object(harness, "SOURCE_MEMBERS", (pin,)),
            ):
                with harness.open_verified_source_archive(path) as archive:
                    self.assertEqual(
                        harness.read_official_source_members(archive),
                        {"isolinux.bin": content},
                    )

                    wrong_pin = harness.SourceMemberPin(
                        member_path,
                        "isolinux.bin",
                        len(content),
                        "0" * 64,
                    )
                    with (
                        patch.object(harness, "SOURCE_MEMBERS", (wrong_pin,)),
                        self.assertRaisesRegex(
                            harness.BootCertificationError,
                            "independent hash",
                        ),
                    ):
                        harness.read_official_source_members(archive)

    def test_catalog_bundles_must_equal_official_source_artifacts(self):
        official = {
            pin.artifact_name: bytes([index + 1]) * pin.size
            for index, pin in enumerate(harness.SOURCE_MEMBERS)
        }

        def artifact(name: str):
            data = official[name]
            return SimpleNamespace(name=name, data=data)

        c32 = SimpleNamespace(
            family="syslinux",
            version=harness.SYSLINUX_BUILD,
            purpose="blank-bios-module",
            artifacts=(artifact("ldlinux.c32"),),
        )
        payloads = SimpleNamespace(
            family="syslinux",
            version=harness.SYSLINUX_BUILD,
            purpose="matched-bios-payloads",
            artifacts=(artifact("ldlinux.bss"), artifact("ldlinux.sys")),
        )
        harness._require_bundles_match_official_source(c32, payloads, official)
        payloads.artifacts[1].data = b"different"
        with self.assertRaisesRegex(
            harness.BootCertificationError, "differ from official",
        ):
            harness._require_bundles_match_official_source(c32, payloads, official)

    def test_prepared_pipeline_bytes_are_fully_hashed_and_sealed(self):
        body = (b"exact prepared Syslinux image" * 100_000)[:2_000_000]
        prepared = _PreparedFixture(body)
        with harness.seal_prepared_image(prepared) as image:
            self.assertEqual(image.size, len(body))
            self.assertEqual(image.sha256, hashlib.sha256(body).hexdigest())
            harness.verify_sealed_prepared_image(image)
            writable = os.open(
                f"/proc/self/fd/{image.fd}", os.O_RDWR | os.O_CLOEXEC,
            )
            try:
                with self.assertRaises(OSError) as write_error:
                    os.pwrite(writable, b"X", 0)
                self.assertEqual(write_error.exception.errno, errno.EPERM)
                with self.assertRaises(OSError) as truncate_error:
                    os.ftruncate(writable, 0)
                self.assertEqual(truncate_error.exception.errno, errno.EPERM)
            finally:
                os.close(writable)

        truncated = _PreparedFixture(body)
        truncated.result.image_size += 1
        with self.assertRaisesRegex(
            harness.BootCertificationError, "truncated",
        ):
            harness.seal_prepared_image(truncated)

        changed = _PreparedFixture(body)
        changed.result.final_image_sha256 = "0" * 64
        with self.assertRaisesRegex(
            harness.BootCertificationError, "attestation",
        ):
            harness.seal_prepared_image(changed)

    def test_qemu_command_is_tcg_seabios_snapshot_networkless_and_fd_only(self):
        command = harness.build_qemu_command(17, 19)
        joined = " ".join(command)
        self.assertEqual(command[0], "/proc/self/fd/17")
        self.assertIn("pc,accel=tcg", command)
        self.assertIn("fd=19,set=1,opaque=syslinux-prepared", joined)
        self.assertIn("file=/dev/fdset/1", joined)
        self.assertIn("format=raw,snapshot=on", joined)
        self.assertIn("-nic none", joined)
        self.assertIn("-display curses,charset=CP437", joined)
        self.assertIn("spawn=deny", joined)
        self.assertNotIn("kvm", joined.casefold())
        self.assertNotIn("/dev/sd", joined)
        self.assertNotIn("/dev/nvme", joined)

    def test_screen_model_requires_visible_ordered_markers_without_synthesis(self):
        capture = harness.TerminalScreenCapture()
        for row, marker in enumerate(harness.BOOT_MARKERS, 1):
            capture.feed(self.screen_line(row, marker))
        self.assertTrue(capture.complete)
        self.assertEqual(capture.markers, harness.BOOT_MARKERS)

        moved = harness.TerminalScreenCapture()
        moved.feed(self.screen_line(1, harness.BOOT_MARKERS[0]))
        moved.feed(self.screen_line(2, "SYSLINUX"))
        moved.feed(b"\x1b[9;20H 6.03")
        self.assertEqual(moved.markers, harness.BOOT_MARKERS[:1])
        self.assertNotIn(harness.BOOT_MARKERS[1], moved.screen_text)

        erased = harness.TerminalScreenCapture()
        erased.feed(self.screen_line(1, harness.BOOT_MARKERS[0]))
        erased.feed(self.screen_line(2, "SYSLINUX 6.0"))
        erased.feed(b"\x1b[2;1H\x1b[2K\x1b[2;40H3")
        self.assertEqual(erased.markers, harness.BOOT_MARKERS[:1])

        reordered = harness.TerminalScreenCapture()
        reordered.feed(self.screen_line(2, harness.BOOT_MARKERS[1]))
        reordered.feed(self.screen_line(1, harness.BOOT_MARKERS[0]))
        reordered.feed(self.screen_line(3, harness.BOOT_MARKERS[2]))
        reordered.feed(self.screen_line(4, harness.BOOT_MARKERS[3]))
        self.assertFalse(reordered.complete)
        self.assertEqual(reordered.markers, harness.BOOT_MARKERS[:1])

    def test_fake_qemu_exact_marker_session_is_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid_file = root / "qemu.pid"
            writes = "\n".join(
                f"os.write(1, {self.screen_line(row, marker)!r})"
                for row, marker in enumerate(harness.BOOT_MARKERS, 1)
            )
            executable = root / "qemu-system-x86_64"
            executable.write_text(
                f"""#!/usr/bin/env python3
import os
import time
from pathlib import Path
Path({str(pid_file)!r}).write_text(str(os.getpid()), encoding='ascii')
{writes}
time.sleep(60)
""",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            source = root / "source.img"
            source.write_bytes(b"source")
            source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
            try:
                with harness.resolve_qemu(executable) as qemu:
                    capture = harness.capture_qemu_boot(qemu, source_fd, timeout=5)
                    self.assertEqual(capture.markers, harness.BOOT_MARKERS)
            finally:
                os.close(source_fd)
            pid = int(pid_file.read_text("ascii"))
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_missing_marker_fails_and_term_resistant_group_is_killed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent_file = root / "parent.pid"
            child_file = root / "child.pid"
            executable = root / "qemu-system-x86_64"
            executable.write_text(
                f"""#!/usr/bin/env python3
import os
import signal
import time
from pathlib import Path
child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    Path({str(child_file)!r}).write_text(str(os.getpid()), encoding='ascii')
    while True:
        time.sleep(1)
Path({str(parent_file)!r}).write_text(str(os.getpid()), encoding='ascii')
os.write(1, b'Booting from Hard Disk...\\r\\n')
while True:
    time.sleep(1)
""",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            source = root / "source.img"
            source.write_bytes(b"source")
            source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
            try:
                with (
                    harness.resolve_qemu(executable) as qemu,
                    patch.object(harness, "MIN_TIMEOUT", 1),
                    patch.object(
                        harness._hardened_qemu, "STOP_GRACE_SECONDS", 0.25,
                    ),
                    self.assertRaisesRegex(
                        harness.BootCertificationError,
                        "timed out.*SYSLINUX 6.03",
                    ),
                ):
                    harness.capture_qemu_boot(qemu, source_fd, timeout=1)
            finally:
                os.close(source_fd)

            deadline = time.monotonic() + 2
            for pid_file in (parent_file, child_file):
                pid = int(pid_file.read_text("ascii"))
                while True:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    if time.monotonic() >= deadline:
                        self.fail(f"process {pid} survived certification cleanup")
                    time.sleep(0.025)

    def test_main_requires_explicit_run_and_certification_refuses_root(self):
        with (
            patch.object(harness, "certify_syslinux_boot") as certify,
            self.assertRaises(SystemExit) as raised,
        ):
            harness.main([harness.SOURCE_ARCHIVE_FILENAME])
        self.assertEqual(raised.exception.code, 2)
        certify.assert_not_called()

        with (
            patch.object(harness.os, "geteuid", return_value=0),
            patch.object(harness, "resolve_qemu") as resolve,
            self.assertRaisesRegex(harness.BootCertificationError, "root"),
        ):
            harness.certify_syslinux_boot(Path(harness.SOURCE_ARCHIVE_FILENAME))
        resolve.assert_not_called()

    @unittest.skipUnless(
        os.environ.get("ISOPROPYL_SYSLINUX_SOURCE_ARCHIVE"),
        "set ISOPROPYL_SYSLINUX_SOURCE_ARCHIVE for real pipeline/QEMU certification",
    )
    def test_opt_in_real_production_pipeline_under_seabios(self):
        qemu = shutil.which("qemu-system-x86_64")
        if qemu is None:
            self.skipTest("qemu-system-x86_64 is unavailable")
        result = harness.certify_syslinux_boot(
            Path(os.environ["ISOPROPYL_SYSLINUX_SOURCE_ARCHIVE"]),
            qemu_path=Path(qemu),
            timeout=int(os.environ.get("ISOPROPYL_SYSLINUX_BOOT_TIMEOUT", "30")),
        )
        self.assertIs(result["certified"], True)
        self.assertEqual(result["markers"], list(harness.BOOT_MARKERS))
        self.assertEqual(result["prepared_image"]["sha256"], result["pipeline"]["final_image_sha256"])
        self.assertEqual(result["isolation"]["attached_host_block_devices"], [])
        self.assertIs(result["isolation"]["source_sealed_memfd"], True)
        self.assertIs(result["scope"]["bios_bootstrap_and_config_certified"], True)
        self.assertIs(result["scope"]["uefi_certified"], False)
        self.assertIs(result["scope"]["physical_media_certified"], False)


if __name__ == "__main__":
    unittest.main()
