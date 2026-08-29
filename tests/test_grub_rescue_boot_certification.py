# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from isopropyl.bootloaders import BoundBootArtifact, BoundBootBundle
from tools import certify_grub_rescue_boot as harness


class _PreparedFixture:
    def __init__(self, data: bytes, result: object | None = None) -> None:
        self.data = data
        self.result = result or SimpleNamespace(
            image_size=len(data),
            final_image_sha256=hashlib.sha256(data).hexdigest(),
        )
        self.closed = False

    def chunks(self, chunk_size: int):
        for offset in range(0, len(self.data), chunk_size):
            yield self.data[offset:offset + chunk_size]

    def close(self) -> None:
        self.closed = True


class _BuilderFixture:
    prepared: _PreparedFixture
    observed_plan: object | None = None

    def execute(self, plan: object) -> _PreparedFixture:
        type(self).observed_plan = plan
        return type(self).prepared


class GrubRescueBootCertificationTests(unittest.TestCase):
    def test_manifest_and_retained_observation_cover_the_real_harness(self):
        root = Path(__file__).resolve().parents[1]
        manifest = {
            line.strip()
            for line in (root / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
        }
        self.assertIn("include tools/certify_grub_rescue_boot.py", manifest)
        self.assertIn(
            "include certifications/grub-2.14-rescue-seabios-2026-08-29.json",
            manifest,
        )
        observation = json.loads(
            (root / "certifications/grub-2.14-rescue-seabios-2026-08-29.json")
            .read_text(encoding="utf-8")
        )
        self.assertIs(observation["certified"], True)
        self.assertEqual(observation["markers"], list(harness.BOOT_MARKERS))
        self.assertEqual(
            observation["prepared_image"]["sha256"],
            observation["construction"]["final_image_sha256"],
        )
        self.assertEqual(observation["bootloader_bundle"]["version"], "2.14")
        self.assertEqual(observation["layout"]["sector_size"], 512)
        self.assertEqual(observation["layout"]["partition_table"], "MBR")
        self.assertEqual(observation["layout"]["partition_1_start_sector"], 2048)
        self.assertEqual(observation["layout"]["filesystem_file_count"], 0)
        self.assertIs(observation["provenance"]["source_reproduction_verified"], False)
        self.assertIs(observation["scope"]["normal_mode_or_menu_certified"], False)
        self.assertIs(observation["scope"]["physical_media_certified"], False)

    @staticmethod
    def screen_line(row: int, text: str) -> bytes:
        return f"\x1b[{row};1H{text}".encode("ascii")

    @staticmethod
    def write_executables(root: Path) -> tuple[Path, Path, Path]:
        pid_file = root / "qemu.pid"
        writes = "\n".join(
            f"os.write(1, {GrubRescueBootCertificationTests.screen_line(row, marker)!r})"
            for row, marker in enumerate(harness.BOOT_MARKERS, 1)
        )
        qemu = root / "qemu-system-x86_64"
        qemu.write_text(
            f"""#!/usr/bin/env python3
import os
import sys
import time
from pathlib import Path
if '--version' in sys.argv:
    print('QEMU emulator version grub-fixture')
    raise SystemExit(0)
Path({str(pid_file)!r}).write_text(str(os.getpid()), encoding='ascii')
{writes}
time.sleep(60)
""",
            encoding="utf-8",
        )
        qemu.chmod(0o755)
        unshare = root / "unshare"
        unshare.write_text(
            """#!/usr/bin/env python3
import os
import sys
separator = sys.argv.index('--')
command = sys.argv[separator + 1:]
os.execv(command[0], command)
""",
            encoding="utf-8",
        )
        unshare.chmod(0o755)
        return qemu, unshare, pid_file

    @staticmethod
    def result_fixture(data: bytes) -> SimpleNamespace:
        digest = hashlib.sha256(data).hexdigest()
        return SimpleNamespace(
            image_size=len(data),
            final_image_sha256=digest,
            plan_sha256="1" * 64,
            private_plan_sha256="2" * 64,
            unpatched_image_sha256="3" * 64,
            final_fat_manifest_sha256="4" * 64,
            boot_image_sha256="5" * 64,
            bootstrap_sha256="6" * 64,
            final_mbr_sha256="7" * 64,
            core_sha256="8" * 64,
            core_offset=512,
            core_size=42_742,
            core_padded_size=43_008,
            embedding_gap_zero_verified=True,
            files_verified=0,
            directories_verified=1,
            bytes_verified=0,
            disk_signature=0x12345678,
            volume_id=0x87654321,
        )

    @staticmethod
    def bundle_fixture() -> BoundBootBundle:
        artifacts = (
            BoundBootArtifact("boot.img", b"boot", hashlib.sha256(b"boot").hexdigest()),
            BoundBootArtifact("core.img", b"core", hashlib.sha256(b"core").hexdigest()),
        )
        return BoundBootBundle(
            harness.GRUB_FAMILY,
            harness.GRUB_VERSION,
            harness.GRUB_PURPOSE,
            artifacts,
            "GPL-3.0-or-later",
            "https://example.invalid/pinned-grub",
        )

    def test_markers_are_exact_ordered_rescue_evidence_only(self):
        self.assertEqual(
            harness.BOOT_MARKERS,
            (
                "Booting from Hard Disk...",
                "Welcome to GRUB!",
                "Entering rescue mode...",
                "grub rescue>",
            ),
        )
        self.assertNotIn("normal.mod", " ".join(harness.BOOT_MARKERS))
        capture = harness.TerminalScreenCapture()
        for row, marker in enumerate(harness.BOOT_MARKERS, 1):
            capture.feed(self.screen_line(row, marker))
        self.assertTrue(capture.complete)
        self.assertEqual(capture.markers, harness.BOOT_MARKERS)

        reordered = harness.TerminalScreenCapture()
        reordered.feed(self.screen_line(2, harness.BOOT_MARKERS[1]))
        reordered.feed(self.screen_line(1, harness.BOOT_MARKERS[0]))
        reordered.feed(self.screen_line(3, harness.BOOT_MARKERS[2]))
        reordered.feed(self.screen_line(4, harness.BOOT_MARKERS[3]))
        self.assertFalse(reordered.complete)
        self.assertEqual(reordered.markers, harness.BOOT_MARKERS[:1])

        synthesized = harness.TerminalScreenCapture()
        synthesized.feed(self.screen_line(1, harness.BOOT_MARKERS[0]))
        synthesized.feed(self.screen_line(2, "Welcome to GR"))
        synthesized.feed(b"\x1b[9;20HUB!")
        self.assertEqual(synthesized.markers, harness.BOOT_MARKERS[:1])

    def test_prepared_production_stream_is_fully_hashed_readonly_and_sealed(self):
        body = (b"exact prepared GRUB image" * 100_000)[:2_000_000]
        prepared = _PreparedFixture(body)
        with harness.seal_prepared_image(prepared) as image:
            self.assertEqual(image.size, len(body))
            self.assertEqual(image.sha256, hashlib.sha256(body).hexdigest())
            self.assertEqual(fcntl.fcntl(image.fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
            seals = fcntl.fcntl(image.fd, fcntl.F_GET_SEALS)
            self.assertEqual(
                seals & harness.REQUIRED_MEMFD_SEALS,
                harness.REQUIRED_MEMFD_SEALS,
            )
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
        with self.assertRaisesRegex(harness.BootCertificationError, "truncated"):
            harness.seal_prepared_image(truncated)

        changed = _PreparedFixture(body)
        changed.result.final_image_sha256 = "0" * 64
        with self.assertRaisesRegex(harness.BootCertificationError, "attestation"):
            harness.seal_prepared_image(changed)

    def test_pipeline_uses_exact_prepare_bundle_and_production_planner_builder(self):
        body = b"prepared pipeline fixture"
        bundle = self.bundle_fixture()
        plan = SimpleNamespace(
            private_plan=SimpleNamespace(
                geometry=SimpleNamespace(partition_sectors=70_000),
            ),
        )
        prepared = _PreparedFixture(body)
        _BuilderFixture.prepared = prepared
        _BuilderFixture.observed_plan = None

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def build(
                observed_bundle: object,
                staging_root: Path,
                workspace: Path,
                *,
                image_size: int,
            ) -> object:
                self.assertIs(observed_bundle, bundle)
                self.assertEqual(image_size, harness.PRIVATE_IMAGE_SIZE)
                self.assertEqual(staging_root.name, "empty-staging")
                self.assertEqual(workspace.name, "build-workspace")
                self.assertEqual(list(staging_root.iterdir()), [])
                self.assertEqual(list(workspace.iterdir()), [])
                return plan

            with (
                patch.object(harness, "prepare_bundle", return_value=bundle) as obtain,
                patch.object(harness, "build_grub_rescue_plan", side_effect=build) as planner,
                patch.object(harness, "GrubRescueBuilder", _BuilderFixture),
            ):
                image, evidence = harness.prepare_certification_pipeline(root)
            try:
                obtain.assert_called_once_with(
                    harness.GRUB_FAMILY,
                    harness.GRUB_VERSION,
                    harness.GRUB_PURPOSE,
                    cache_dir=None,
                    overall_timeout=180,
                )
                planner.assert_called_once()
                self.assertIs(_BuilderFixture.observed_plan, plan)
                self.assertTrue(prepared.closed)
                self.assertIs(evidence.bundle, bundle)
                self.assertEqual(image.sha256, hashlib.sha256(body).hexdigest())
                harness.verify_sealed_prepared_image(image)
            finally:
                image.close()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "unexpected").write_text("dirty", encoding="utf-8")
            with (
                patch.object(harness, "prepare_bundle") as obtain,
                self.assertRaisesRegex(harness.BootCertificationError, "start empty"),
            ):
                harness.prepare_certification_pipeline(root)
            obtain.assert_not_called()

    def test_qemu_command_is_fixed_namespaced_seabios_readonly_and_fd_only(self):
        command = harness.build_qemu_command(13, 17, 19)
        joined = " ".join(command)
        self.assertEqual(
            command[:6],
            (
                "/proc/self/fd/13", "--user", "--map-current-user",
                "--net", "--", "/proc/self/fd/17",
            ),
        )
        self.assertIn("pc,accel=tcg", command)
        self.assertIn("fd=19,set=1,opaque=grub-rescue-prepared", joined)
        self.assertIn("file=/dev/fdset/1", joined)
        self.assertIn("format=raw,snapshot=on", joined)
        self.assertNotIn("readonly=on", joined)
        self.assertIn("-snapshot", command)
        self.assertIn("-nic none", joined)
        self.assertIn("-monitor none", joined)
        self.assertIn("-serial none", joined)
        self.assertIn("-parallel none", joined)
        self.assertIn("-display curses,charset=CP437", joined)
        self.assertIn("spawn=deny", joined)
        self.assertNotIn("kvm", joined.casefold())
        self.assertNotIn("/dev/sd", joined)
        self.assertNotIn("/dev/nvme", joined)

    def test_bound_namespace_executable_is_rechecked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "unshare"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            with harness.resolve_unshare(executable) as bound:
                self.assertEqual(
                    bound.sha256,
                    hashlib.sha256(executable.read_bytes()).hexdigest(),
                )
                original = root / "original-unshare"
                executable.rename(original)
                executable.write_text("replacement", encoding="utf-8")
                executable.chmod(0o755)
                with self.assertRaisesRegex(
                    harness.BootCertificationError, "changed",
                ):
                    harness.verify_executable_unchanged(bound)

    def test_fake_namespace_and_qemu_marker_session_is_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            qemu_path, unshare_path, pid_file = self.write_executables(root)
            source = root / "source.img"
            source.write_bytes(b"source")
            source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
            try:
                with (
                    harness.resolve_qemu(qemu_path) as qemu,
                    harness.resolve_unshare(unshare_path) as namespace_tool,
                ):
                    capture = harness.capture_qemu_boot(
                        qemu, namespace_tool, source_fd, timeout=5,
                    )
                    self.assertEqual(capture.markers, harness.BOOT_MARKERS)
            finally:
                os.close(source_fd)
            pid = int(pid_file.read_text("ascii"))
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_certificate_is_narrow_and_does_not_claim_menu_os_or_devices(self):
        body = b"sealed certificate fixture"
        result = self.result_fixture(body)
        prepared = _PreparedFixture(body, result)
        image = harness.seal_prepared_image(prepared)
        evidence = harness.PipelineEvidence(
            self.bundle_fixture(), result, 70_000, True, True,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            qemu_path, unshare_path, _pid_file = self.write_executables(root)
            with patch.object(
                harness,
                "prepare_certification_pipeline",
                return_value=(image, evidence),
            ):
                observation = harness.certify_grub_rescue_boot(
                    qemu_path=qemu_path,
                    unshare_path=unshare_path,
                    timeout=5,
                )
        self.assertIs(observation["certified"], True)
        self.assertEqual(observation["markers"], list(harness.BOOT_MARKERS))
        self.assertEqual(
            observation["prepared_image"]["sha256"],
            observation["construction"]["final_image_sha256"],
        )
        self.assertIs(observation["isolation"]["source_read_only"], True)
        self.assertIs(observation["isolation"]["user_namespace"], True)
        self.assertEqual(
            observation["isolation"]["network_namespace"],
            "new-empty-namespace",
        )
        self.assertEqual(observation["isolation"]["attached_host_block_devices"], [])
        self.assertIs(observation["scope"]["intentional_rescue_prompt_certified"], True)
        self.assertIs(observation["scope"]["source_reproduction_verified"], False)
        self.assertIs(observation["provenance"]["source_reproduction_verified"], False)
        self.assertEqual(observation["layout"]["sector_size"], 512)
        self.assertEqual(observation["layout"]["partition_table"], "MBR")
        self.assertEqual(observation["layout"]["partition_count"], 1)
        self.assertIs(observation["layout"]["partition_1_active"], True)
        self.assertEqual(observation["layout"]["partition_1_start_sector"], 2048)
        self.assertEqual(observation["layout"]["filesystem_file_count"], 0)
        self.assertIs(observation["scope"]["normal_mode_or_menu_certified"], False)
        self.assertIs(observation["scope"]["kernel_or_operating_system_certified"], False)
        self.assertIs(observation["scope"]["physical_media_certified"], False)
        self.assertIs(
            observation["scope"]["privileged_device_transaction_certified"], False,
        )

    def test_main_requires_explicit_run_and_certification_refuses_root(self):
        with (
            patch.object(harness, "certify_grub_rescue_boot") as certify,
            self.assertRaises(SystemExit) as raised,
        ):
            harness.main([])
        self.assertEqual(raised.exception.code, 2)
        certify.assert_not_called()

        with (
            patch.object(harness.os, "geteuid", return_value=0),
            patch.object(harness, "resolve_qemu") as resolve,
            patch.object(harness, "prepare_bundle") as obtain,
            self.assertRaisesRegex(harness.BootCertificationError, "root"),
        ):
            harness.certify_grub_rescue_boot()
        resolve.assert_not_called()
        obtain.assert_not_called()

    @unittest.skipUnless(
        os.environ.get("ISOPROPYL_GRUB_RESCUE_BOOT"),
        "set ISOPROPYL_GRUB_RESCUE_BOOT=1 for real production QEMU certification",
    )
    def test_opt_in_real_production_rescue_prompt_under_seabios(self):
        qemu = shutil.which("qemu-system-x86_64")
        unshare = shutil.which("unshare")
        if qemu is None or unshare is None:
            self.skipTest("qemu-system-x86_64 or unshare is unavailable")
        observation = harness.certify_grub_rescue_boot(
            qemu_path=Path(qemu),
            unshare_path=Path(unshare),
            timeout=int(os.environ.get("ISOPROPYL_GRUB_RESCUE_TIMEOUT", "30")),
        )
        self.assertIs(observation["certified"], True)
        self.assertEqual(observation["markers"], list(harness.BOOT_MARKERS))
        self.assertEqual(
            observation["prepared_image"]["sha256"],
            observation["construction"]["final_image_sha256"],
        )
        self.assertIs(observation["scope"]["intentional_rescue_prompt_certified"], True)
        self.assertIs(observation["scope"]["normal_mode_or_menu_certified"], False)
        self.assertIs(observation["scope"]["physical_media_certified"], False)


if __name__ == "__main__":
    unittest.main()
