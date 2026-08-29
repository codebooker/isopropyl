from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import io
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools import certify_windows_dual_boot as certification


class WindowsDualBootCertificationTests(unittest.TestCase):
    def test_seabios_command_is_networkless_tcg_snapshot_and_fd_only(self) -> None:
        command = certification.build_qemu_command("seabios", 10, 11)
        rendered = " ".join(command)
        self.assertEqual(command[0], "/proc/self/fd/10")
        self.assertIn("pc,accel=tcg", command)
        self.assertIn("-snapshot", command)
        self.assertIn("-nic none", rendered)
        self.assertIn("file=/dev/fdset/1", rendered)
        self.assertNotIn("/dev/sd", rendered)
        self.assertNotIn("/dev/nvme", rendered)
        self.assertNotIn("-enable-kvm", command)
        self.assertNotIn("-netdev", command)

    def test_ovmf_command_accepts_only_bound_firmware_fdsets(self) -> None:
        command = certification.build_qemu_command(
            "ovmf", 10, 11, ovmf_code_fd=12, ovmf_vars_fd=13,
        )
        rendered = " ".join(command)
        self.assertIn("q35,accel=tcg", command)
        self.assertIn("fd=12,set=2,opaque=ovmf-code", command)
        self.assertIn("fd=13,set=3,opaque=ovmf-vars", command)
        self.assertIn("file=/dev/fdset/2", rendered)
        self.assertIn("file=/dev/fdset/3", rendered)
        self.assertNotIn(str(certification.DEFAULT_OVMF_CODE), rendered)
        self.assertNotIn(str(certification.DEFAULT_OVMF_VARS), rendered)

    def test_explicit_kvm_command_uses_kvm_and_host_cpu(self) -> None:
        command = certification.build_qemu_command(
            "seabios", 10, 11, acceleration="kvm",
        )
        self.assertIn("pc,accel=kvm", command)
        self.assertIn("host", command)
        self.assertNotIn("max", command)

    def test_command_rejects_wrong_profile_and_resource_bounds(self) -> None:
        with self.assertRaisesRegex(ValueError, "firmware"):
            certification.build_qemu_command("secure-boot", 1, 2)
        with self.assertRaisesRegex(ValueError, "acceleration"):
            certification.build_qemu_command(
                "seabios", 1, 2, acceleration="hvf",
            )
        with self.assertRaisesRegex(ValueError, "memory_mib"):
            certification.build_qemu_command("seabios", 1, 2, memory_mib=1)
        with self.assertRaisesRegex(ValueError, "descriptors"):
            certification.build_qemu_command("ovmf", 1, 2)

    def test_windows_setup_gate_requires_title_and_independent_detail(self) -> None:
        self.assertFalse(certification._windows_setup_reached(("WINDOWS SETUP",)))
        self.assertFalse(certification._windows_setup_reached(("INSTALL NOW",)))
        self.assertTrue(certification._windows_setup_reached(
            ("WINDOWS SETUP", "INSTALL NOW"),
        ))
        self.assertTrue(certification._windows_setup_reached(
            ("WINDOWS SETUP", "LANGUAGE TO INSTALL"),
        ))
        self.assertTrue(certification._windows_setup_reached(
            ("WINDOWS 11 SETUP", "LANGUAGE TO INSTALL"),
        ))
        self.assertFalse(certification._windows_setup_reached(
            ("WINDOWS 11", "LANGUAGE TO INSTALL"),
        ))

    def test_ppm_parser_binds_exact_dimensions_and_pixels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "screen.ppm"
            pixels = bytes((0, 0, 0, 255, 255, 255))
            path.write_bytes(b"P6\n2 1\n255\n" + pixels)
            rendered, width, height, colors = certification._read_ppm(path)
            self.assertEqual(rendered, path.read_bytes())
            self.assertEqual((width, height), (2, 1))
            self.assertEqual(colors, 2)

    def test_ppm_parser_rejects_truncation_and_trailing_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "screen.ppm"
            for pixels in (b"\0" * 5, b"\0" * 7):
                with self.subTest(length=len(pixels)):
                    path.write_bytes(b"P6\n2 1\n255\n" + pixels)
                    with self.assertRaisesRegex(
                        certification.BootCertificationError, "dimensions",
                    ):
                        certification._read_ppm(path)

    def test_qmp_client_performs_greeting_and_id_bound_commands(self) -> None:
        client_socket, server_socket = socket.socketpair()
        client_stream = client_socket.makefile("rwb", buffering=0)
        server_stream = server_socket.makefile("rwb", buffering=0)
        observed: list[dict[str, object]] = []

        def server() -> None:
            server_stream.write(b'{"QMP":{"version":{},"capabilities":[]}}\r\n')
            for _ in range(2):
                command = json.loads(server_stream.readline())
                observed.append(command)
                server_stream.write(
                    json.dumps({"return": {}, "id": command["id"]}).encode() + b"\r\n"
                )

        thread = threading.Thread(target=server)
        thread.start()
        try:
            qmp = certification.QmpClient(client_stream, client_stream)
            qmp.greeting()
            qmp.execute("screendump", {"filename": "/private/frame.ppm"})
        finally:
            thread.join(2)
            client_stream.close()
            server_stream.close()
            client_socket.close()
            server_socket.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(observed[0]["execute"], "qmp_capabilities")
        self.assertEqual(observed[1]["execute"], "screendump")
        self.assertEqual(
            observed[1]["arguments"], {"filename": "/private/frame.ppm"},
        )

    def test_qmp_client_rejects_unbounded_output(self) -> None:
        client_socket, server_socket = socket.socketpair()
        client_stream = client_socket.makefile("rwb", buffering=0)
        try:
            server_socket.sendall(b"x" * 64)
            qmp = certification.QmpClient(client_stream, client_stream, limit=8)
            with self.assertRaisesRegex(
                certification.BootCertificationError, "too much QMP",
            ):
                qmp.greeting()
        finally:
            client_stream.close()
            client_socket.close()
            server_socket.close()

    def test_recommended_image_size_adds_headroom_and_mib_alignment(self) -> None:
        result = certification._recommended_image_size(100, 123456789)
        self.assertGreaterEqual(result, 123456789 + certification.IMAGE_HEADROOM)
        self.assertEqual(result % certification.MIB, 0)

    def test_ovmf_vars_copy_is_anonymous_read_only_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "OVMF_VARS_4M.fd"
            payload = b"vars" * 4096
            path.write_bytes(payload)
            with certification._bind_regular_file(
                path, description="OVMF variable template",
            ) as source:
                duplicate = certification._copy_ovmf_vars(source)
            try:
                self.assertEqual(os.fstat(duplicate).st_nlink, 0)
                self.assertEqual(os.pread(duplicate, len(payload), 0), payload)
                with self.assertRaises(OSError):
                    os.write(duplicate, b"x")
            finally:
                os.close(duplicate)

    def test_anonymous_descriptor_gate_requires_read_only_unlinked_file(self) -> None:
        if not hasattr(os, "O_TMPFILE"):
            self.skipTest("Linux O_TMPFILE unavailable")
        with tempfile.TemporaryDirectory() as directory:
            try:
                writable = os.open(
                    directory, os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600,
                )
            except OSError as error:
                self.skipTest(f"filesystem has no O_TMPFILE support: {error}")
            try:
                os.ftruncate(writable, 4096)

                class Owner:
                    result = SimpleNamespace(image_size=4096)

                    def _duplicate_attested_readonly_descriptor(self) -> tuple[int, int]:
                        return (
                            os.open(
                                f"/proc/self/fd/{writable}",
                                os.O_RDONLY | os.O_CLOEXEC,
                            ),
                            4096,
                        )

                duplicate = certification._duplicate_prepared_descriptor(Owner())
                try:
                    self.assertEqual(os.fstat(duplicate).st_nlink, 0)
                    with self.assertRaises(OSError):
                        os.write(duplicate, b"x")
                finally:
                    os.close(duplicate)
            finally:
                os.close(writable)

    def test_named_or_writable_duplicate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "named.img"
            path.write_bytes(b"x" * 4096)

            class Owner:
                result = SimpleNamespace(image_size=4096)

                def _duplicate_attested_readonly_descriptor(self) -> tuple[int, int]:
                    return os.open(path, os.O_RDONLY | os.O_CLOEXEC), 4096

            with self.assertRaisesRegex(
                certification.BootCertificationError, "duplicate is unsafe",
            ):
                certification._duplicate_prepared_descriptor(Owner())

    def test_main_requires_explicit_run_opt_in(self) -> None:
        with patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit) as caught:
            certification.main(["windows.iso"])
        self.assertEqual(caught.exception.code, 2)

    def test_parser_rejects_out_of_bounds_timeout(self) -> None:
        parser = certification.build_parser()
        with patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["windows.iso", "--run", "--timeout", "1"])

    def test_kvm_is_rejected_before_pipeline_when_device_is_unavailable(self) -> None:
        with patch.object(certification.os, "geteuid", return_value=1000), patch.object(
            certification.os, "access", return_value=False,
        ), self.assertRaisesRegex(
            certification.BootCertificationError, "/dev/kvm",
        ):
            certification.certify_windows_dual_boot(
                Path("windows.iso"), acceleration="kvm",
            )

    def test_source_binder_rejects_non_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                certification.BootCertificationError, "regular file",
            ):
                certification._bind_regular_file(
                    Path(directory), description="source Windows ISO",
                )

    def test_pipeline_binds_inspection_and_staging_to_hashed_iso_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "windows.iso"
            path.write_bytes(b"bound source")
            with certification._bind_regular_file(
                path, description="source Windows ISO",
            ) as source:
                expected = (
                    source.identity.device,
                    source.identity.inode,
                    source.identity.size,
                    source.identity.mtime_ns,
                    source.identity.ctime_ns,
                )
                inspection = SimpleNamespace(
                    size=source.identity.size,
                    kind="Optical ISO",
                    is_iso9660=True,
                    contents_scanned=True,
                    has_windows_installer=True,
                    bootloader="Windows Boot Manager",
                    bootloader_identity_ambiguous=False,
                    architectures=("x64",),
                    boot_modes=("BIOS", "UEFI"),
                    uefi_analysis_complete=True,
                    members=(),
                )
                wrong = (expected[0], expected[1] + 1, *expected[2:])
                with patch.object(
                    certification,
                    "inspect_image",
                    return_value=inspection,
                ) as inspect, patch.object(
                    certification,
                    "build_write_plan",
                    return_value=object(),
                ), patch.object(
                    certification,
                    "build_iso_staging_plan",
                    return_value=SimpleNamespace(image_identity=wrong),
                ), self.assertRaisesRegex(
                    certification.BootCertificationError,
                    "different source image",
                ):
                    certification.prepare_certification_pipeline(
                        source,
                        root / "workspace",
                    )
                inspect.assert_called_once_with(
                    source.path,
                    expected_identity=expected,
                )


if __name__ == "__main__":
    unittest.main()
