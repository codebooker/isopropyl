# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import shutil
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from isopropyl.freedos_downloads import available_freedos_images
from tools import certify_freedos_boot as harness


class FreeDosBootCertificationTests(unittest.TestCase):
    def fixture(self, directory: str, body: bytes = b"catalog-bound image"):
        trusted = available_freedos_images()[0]
        release = replace(
            trusted,
            image_filename="TEST.img",
            image_size=len(body),
            image_sha256=hashlib.sha256(body).hexdigest(),
        )
        path = Path(directory) / release.image_filename
        path.write_bytes(body)
        return path, release

    def test_verified_source_requires_exact_filename_size_hash_and_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path, release = self.fixture(directory)
            wrong_name = path.with_name("test.img")
            wrong_name.write_bytes(path.read_bytes())
            with self.assertRaisesRegex(harness.BootCertificationError, "filename"):
                harness.open_verified_image(wrong_name, catalog=(release,))

            path.write_bytes(b"same-length-image!!")
            self.assertEqual(path.stat().st_size, release.image_size)
            with self.assertRaisesRegex(harness.BootCertificationError, "SHA-256"):
                harness.open_verified_image(path, catalog=(release,))

            path.unlink()
            path.symlink_to("/dev/null")
            with self.assertRaisesRegex(harness.BootCertificationError, "regular file"):
                harness.open_verified_image(path, catalog=(release,))

    def test_source_is_bound_by_descriptor_and_rechecked_afterward(self):
        with tempfile.TemporaryDirectory() as directory:
            path, release = self.fixture(directory)
            with harness.open_verified_image(path, catalog=(release,)) as image:
                command = harness.build_qemu_command(18, image.snapshot_fd)
                joined = " ".join(command)
                self.assertEqual(command[0], "/proc/self/fd/18")
                self.assertIn(
                    f"fd={image.snapshot_fd},set=1,opaque=freedos-source",
                    joined,
                )
                self.assertIn("file=/dev/fdset/1", joined)
                self.assertNotIn(str(path), joined)
                seals = fcntl.fcntl(image.snapshot_fd, fcntl.F_GET_SEALS)
                self.assertEqual(
                    seals & harness.REQUIRED_MEMFD_SEALS,
                    harness.REQUIRED_MEMFD_SEALS,
                )
                with self.assertRaises(OSError) as write_error:
                    os.pwrite(image.snapshot_fd, b"X", 0)
                self.assertIn(write_error.exception.errno, (errno.EBADF, errno.EPERM))
                with self.assertRaises(OSError) as truncate_error:
                    os.ftruncate(image.snapshot_fd, 0)
                self.assertIn(
                    truncate_error.exception.errno,
                    (errno.EBADF, errno.EINVAL, errno.EPERM),
                )
                writable_view = os.open(
                    f"/proc/self/fd/{image.snapshot_fd}",
                    os.O_RDWR | os.O_CLOEXEC,
                )
                try:
                    with self.assertRaises(OSError) as sealed_write_error:
                        os.pwrite(writable_view, b"X", 0)
                    self.assertEqual(sealed_write_error.exception.errno, errno.EPERM)
                    with self.assertRaises(OSError) as sealed_truncate_error:
                        os.ftruncate(writable_view, 0)
                    self.assertEqual(sealed_truncate_error.exception.errno, errno.EPERM)
                finally:
                    os.close(writable_view)
                harness.verify_image_unchanged(image)
                path.write_bytes(b"catalog-bound imagE")
                with self.assertRaisesRegex(harness.BootCertificationError, "(identity|hash)"):
                    harness.verify_image_unchanged(image)

    def test_qemu_command_is_tcg_snapshot_read_only_and_networkless(self):
        command = harness.build_qemu_command(17, 19)
        joined = " ".join(command)
        self.assertEqual(command[0], "/proc/self/fd/17")
        self.assertIn("pc,accel=tcg", command)
        self.assertIn("-snapshot", command)
        self.assertIn("format=raw,snapshot=on", joined)
        self.assertIn("-nic none", joined)
        self.assertIn("-display curses,charset=CP437", joined)
        self.assertIn("spawn=deny", joined)
        self.assertIn("resourcecontrol=deny", joined)
        self.assertNotIn("elevateprivileges", joined)
        self.assertNotIn("kvm", joined.casefold())
        self.assertNotIn("/dev/sd", joined)
        self.assertNotIn("/dev/nvme", joined)

    @staticmethod
    def screen_line(row: int, text: str) -> bytes:
        return f"\x1b[{row};1H{text}".encode("ascii")

    def test_terminal_screen_finds_complete_visible_markers_in_order(self):
        capture = harness.TerminalScreenCapture()
        capture.feed(b"\x1b[2J")
        for row, marker in enumerate(harness.BOOT_MARKERS, 1):
            capture.feed(self.screen_line(row, marker))
        self.assertTrue(capture.complete)
        self.assertEqual(capture.markers, harness.BOOT_MARKERS)

    def test_terminal_screen_does_not_join_across_cursor_move_or_erase(self):
        capture = harness.TerminalScreenCapture()
        capture.feed(self.screen_line(1, harness.BOOT_MARKERS[0]))
        capture.feed(self.screen_line(2, "FreeDOS ker"))
        capture.feed(b"\x1b[10;10Hnel 2043")
        self.assertEqual(capture.markers, harness.BOOT_MARKERS[:1])
        self.assertNotIn(harness.BOOT_MARKERS[1], capture.screen_text)

        capture.feed(b"\x1b[2;1H\x1b[2K")
        capture.feed(self.screen_line(2, "FreeDOS kernel 204"))
        capture.feed(b"\x1b[2;1H\x1b[K")
        capture.feed(b"\x1b[2;40H3")
        self.assertEqual(capture.markers, harness.BOOT_MARKERS[:1])

    def test_terminal_screen_requires_marker_order(self):
        capture = harness.TerminalScreenCapture()
        capture.feed(self.screen_line(2, harness.BOOT_MARKERS[1]))
        capture.feed(self.screen_line(1, harness.BOOT_MARKERS[0]))
        capture.feed(self.screen_line(3, harness.BOOT_MARKERS[2]))
        capture.feed(self.screen_line(4, harness.BOOT_MARKERS[3]))
        self.assertFalse(capture.complete)
        self.assertEqual(capture.markers, harness.BOOT_MARKERS[:1])

    def test_fake_qemu_vga_session_is_noninteractive_bounded_and_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid_file = root / "fake-qemu.pid"
            script = f"""#!/usr/bin/env python3
import os
import time
from pathlib import Path

Path({str(pid_file)!r}).write_text(str(os.getpid()), encoding='ascii')
chunks = (
    b'\\x1b[2JBooting from Hard Disk...\\r\\n',
    b'FreeDOS kernel 2043\\r\\n',
    b'FreeCom version 0.86\\r\\n',
    b'Done processing startup files FDCONFIG.SYS and FDAUTO.BAT\\r\\n',
)
for chunk in chunks:
    os.write(1, chunk)
time.sleep(60)
"""
            executable = root / "qemu-system-x86_64"
            executable.write_text(script, encoding="utf-8")
            executable.chmod(0o755)
            image = root / "source.img"
            image.write_bytes(b"source")
            source_fd = os.open(image, os.O_RDONLY | os.O_CLOEXEC)
            try:
                with harness.resolve_qemu(executable) as qemu:
                    started = time.monotonic()
                    result = harness.capture_qemu_boot(qemu, source_fd, timeout=5)
                    self.assertLess(time.monotonic() - started, 5)
                    self.assertEqual(result.markers, harness.BOOT_MARKERS)
            finally:
                os.close(source_fd)
            pid = int(pid_file.read_text("ascii"))
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_qemu_is_hashed_executed_by_descriptor_and_versioned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "qemu-system-x86_64"
            executable.write_text(
                """#!/usr/bin/env python3
import sys
if '--version' in sys.argv:
    print('QEMU emulator version fixture-1')
    raise SystemExit(0)
raise SystemExit(7)
""",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            with harness.resolve_qemu(executable) as qemu:
                self.assertEqual(
                    qemu.sha256,
                    hashlib.sha256(executable.read_bytes()).hexdigest(),
                )
                self.assertEqual(
                    harness.query_qemu_version(qemu),
                    "QEMU emulator version fixture-1",
                )
                original = root / "original-qemu"
                executable.rename(original)
                executable.write_text("replacement", encoding="utf-8")
                executable.chmod(0o755)
                with self.assertRaisesRegex(
                    harness.BootCertificationError, "changed",
                ):
                    harness.verify_qemu_unchanged(qemu)

    def test_complete_certificate_reports_bound_evidence_and_narrow_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, release = self.fixture(directory)
            executable = root / "qemu-system-x86_64"
            marker_writes = "\n".join(
                f"os.write(1, {self.screen_line(row, marker)!r})"
                for row, marker in enumerate(harness.BOOT_MARKERS, 1)
            )
            executable.write_text(
                f"""#!/usr/bin/env python3
import os
import sys
import time
if '--version' in sys.argv:
    print('QEMU emulator version fixture-2')
    raise SystemExit(0)
{marker_writes}
time.sleep(60)
""",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            with patch.object(
                harness, "load_freedos_image_catalog", return_value=(release,),
            ):
                result = harness.certify_freedos_boot(
                    image, qemu_path=executable, timeout=5,
                )
            self.assertIs(result["certified"], True)
            self.assertEqual(result["markers"], list(harness.BOOT_MARKERS))
            self.assertEqual(
                result["capture"]["method"],
                "qemu-curses-private-pty-80x25-screen",
            )
            self.assertEqual(result["isolation"]["attached_host_block_devices"], [])
            self.assertIs(result["isolation"]["source_sealed_memfd"], True)
            self.assertIs(result["isolation"]["qemu_seccomp"], True)
            self.assertIs(result["isolation"]["unprivileged_process"], True)
            self.assertIs(result["isolation"]["qemu_executable_set_id"], False)
            self.assertEqual(
                result["isolation"]["qemu_seccomp_policy"],
                "on,obsolete=deny,spawn=deny,resourcecontrol=deny",
            )
            self.assertEqual(
                result["qemu"]["sha256"],
                hashlib.sha256(executable.read_bytes()).hexdigest(),
            )
            self.assertEqual(
                result["qemu"]["version"], "QEMU emulator version fixture-2",
            )

    def test_timeout_kills_term_resistant_process_group_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent_pid_file = root / "parent.pid"
            child_pid_file = root / "child.pid"
            script = f"""#!/usr/bin/env python3
import os
import signal
import time
from pathlib import Path

child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    Path({str(child_pid_file)!r}).write_text(str(os.getpid()), encoding='ascii')
    while True:
        time.sleep(1)
Path({str(parent_pid_file)!r}).write_text(str(os.getpid()), encoding='ascii')
while True:
    time.sleep(1)
"""
            executable = root / "qemu-system-x86_64"
            executable.write_text(script, encoding="utf-8")
            executable.chmod(0o755)
            image = root / "source.img"
            image.write_bytes(b"source")
            source_fd = os.open(image, os.O_RDONLY | os.O_CLOEXEC)
            try:
                with (
                    harness.resolve_qemu(executable) as qemu,
                    patch.object(harness, "MIN_TIMEOUT", 1),
                    patch.object(harness, "STOP_GRACE_SECONDS", 0.25),
                ):
                    with self.assertRaisesRegex(
                        harness.BootCertificationError, "timed out",
                    ):
                        harness.capture_qemu_boot(qemu, source_fd, timeout=1)
            finally:
                os.close(source_fd)

            parent_pid = int(parent_pid_file.read_text("ascii"))
            child_pid = int(child_pid_file.read_text("ascii"))
            deadline = time.monotonic() + 2
            for pid in (parent_pid, child_pid):
                while True:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    if time.monotonic() >= deadline:
                        self.fail(f"process {pid} survived certification cleanup")
                    time.sleep(0.025)

    def test_early_exit_reports_ordered_missing_markers_and_reaps(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "qemu-system-x86_64"
            executable.write_text(
                """#!/usr/bin/env python3
import os
os.write(1, b'Booting from Hard Disk...\\r\\n')
""",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            image = root / "source.img"
            image.write_bytes(b"source")
            source_fd = os.open(image, os.O_RDONLY | os.O_CLOEXEC)
            try:
                with harness.resolve_qemu(executable) as qemu:
                    with self.assertRaisesRegex(
                        harness.BootCertificationError,
                        "exited before certification.*FreeDOS kernel 2043",
                    ):
                        harness.capture_qemu_boot(qemu, source_fd, timeout=5)
            finally:
                os.close(source_fd)

    def test_main_requires_explicit_run_before_resolving_or_opening_anything(self):
        with (
            patch.object(harness, "certify_freedos_boot") as certify,
            self.assertRaises(SystemExit) as raised,
        ):
            harness.main(["FD14LITE.img"])
        self.assertEqual(raised.exception.code, 2)
        certify.assert_not_called()

    def test_certification_refuses_root_execution(self):
        with (
            patch.object(harness.os, "geteuid", return_value=0),
            patch.object(harness, "resolve_qemu") as resolve,
            self.assertRaisesRegex(harness.BootCertificationError, "root"),
        ):
            harness.certify_freedos_boot(Path("FD14LITE.img"))
        resolve.assert_not_called()

    def test_qemu_resolver_rejects_set_id_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "qemu-system-x86_64"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o4755)
            with self.assertRaisesRegex(harness.BootCertificationError, "non-set-ID"):
                harness.resolve_qemu(executable)

    @unittest.skipUnless(
        os.environ.get("ISOPROPYL_FREEDOS_BOOT_IMAGE"),
        "set ISOPROPYL_FREEDOS_BOOT_IMAGE to opt in to real QEMU certification",
    )
    def test_opt_in_real_catalog_image_under_qemu(self):
        qemu = shutil.which("qemu-system-x86_64")
        if qemu is None:
            self.skipTest("qemu-system-x86_64 is unavailable")
        result = harness.certify_freedos_boot(
            Path(os.environ["ISOPROPYL_FREEDOS_BOOT_IMAGE"]),
            qemu_path=Path(qemu),
            timeout=int(os.environ.get("ISOPROPYL_FREEDOS_BOOT_TIMEOUT", "90")),
        )
        self.assertIs(result["certified"], True)
        self.assertEqual(result["markers"], list(harness.BOOT_MARKERS))
        self.assertEqual(result["isolation"]["attached_host_block_devices"], [])
        self.assertIs(result["isolation"]["source_sealed_memfd"], True)
        self.assertIs(result["isolation"]["qemu_seccomp"], True)
        self.assertEqual(len(result["qemu"]["sha256"]), 64)
        self.assertIn("QEMU", result["qemu"]["version"])


if __name__ == "__main__":
    unittest.main()
