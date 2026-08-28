from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import gzip
import hashlib
import io
import os
import runpy
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "packaging/debian/build_deb.py"
DPKG_DEB = Path("/usr/bin/dpkg-deb")
DPKG = Path("/usr/bin/dpkg")
SOURCE_DATE_EPOCH = "1787788800"


def _normalized_name(name: str) -> str:
    return name[2:] if name.startswith("./") else name


@unittest.skipUnless(
    DPKG_DEB.is_file() and DPKG.is_file(),
    "the trusted Debian package tools are unavailable",
)
class DebianPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory()
        root = Path(cls._temporary.name)
        cls.output_one = root / "one"
        cls.output_two = root / "two"
        cls.deb_one = cls._build(cls.output_one)
        cls.deb_two = cls._build(cls.output_two)
        cls.data = cls._archive(cls.deb_one, "--fsys-tarfile")
        cls.control = cls._archive(cls.deb_one, "--ctrl-tarfile")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    @classmethod
    def _build(cls, output: Path) -> Path:
        environment = os.environ.copy()
        environment.update(
            {
                "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
                "PYTHONPATH": "/tmp/isopropyl-hostile-python-path",
                "PYTHONHOME": "",
            }
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                os.fspath(BUILDER),
                "--output-dir",
                os.fspath(output),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            timeout=120,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr or completed.stdout)
        result = Path(completed.stdout.strip())
        if not result.is_file():
            raise AssertionError(f"builder did not return a package: {result}")
        return result

    @staticmethod
    def _archive(package: Path, option: str) -> dict[str, tuple[tarfile.TarInfo, bytes]]:
        completed = subprocess.run(
            [os.fspath(DPKG_DEB), option, os.fspath(package)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        entries: dict[str, tuple[tarfile.TarInfo, bytes]] = {}
        with tarfile.open(fileobj=io.BytesIO(completed.stdout), mode="r:*") as archive:
            for member in archive.getmembers():
                content = b""
                if member.isfile():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise AssertionError(member.name)
                    content = stream.read()
                entries[_normalized_name(member.name)] = (member, content)
        return entries

    def test_build_is_reproducible_and_refuses_to_overwrite(self):
        self.assertEqual(self.deb_one.read_bytes(), self.deb_two.read_bytes())
        original = hashlib.sha256(self.deb_one.read_bytes()).hexdigest()
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                os.fspath(BUILDER),
                "--output-dir",
                os.fspath(self.output_one),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH},
            timeout=120,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Refusing to overwrite", completed.stderr)
        self.assertEqual(hashlib.sha256(self.deb_one.read_bytes()).hexdigest(), original)

    def test_control_metadata_is_native_offline_and_64_bit_only(self):
        fields = subprocess.run(
            [os.fspath(DPKG_DEB), "--field", os.fspath(self.deb_one)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout
        architecture = subprocess.run(
            [os.fspath(DPKG), "--print-architecture"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        self.assertIn(f"Architecture: {architecture}\n", fields)
        self.assertIn("Version: 0.1.0-1\n", fields)
        self.assertRegex(fields, r"Depends:.*\bpkexec\b")
        self.assertRegex(fields, r"Depends:.*\budisks2\b")
        self.assertRegex(fields, r"Depends:.*\b7zip \| p7zip-full\b")
        self.assertNotIn("policykit-1", fields)
        self.assertNotIn("util-linux", fields)
        self.assertNotIn("coreutils", fields)
        self.assertIn("Recommends: polkit-1-auth-agent", fields)
        self.assertIn("python3-zstandard | zstd", fields)
        self.assertIn("Suggests: python3-hivex", fields)
        for forbidden in ("preinst", "postinst", "prerm", "postrm", "conffiles"):
            self.assertNotIn(forbidden, self.control)

    def test_payload_has_safe_ownership_types_and_modes(self):
        executable_paths = {
            "usr/bin/isopropyl",
            "usr/bin/isopropyl-cli",
            "usr/bin/isopropyl-validate-windows-bcd-capture",
            "usr/bin/isopropyl-import-windows-bcd-capture",
            "usr/libexec/isopropyl-device-helper",
        }
        for name, (member, _content) in self.data.items():
            with self.subTest(path=name):
                self.assertEqual((member.uid, member.gid), (0, 0))
                self.assertFalse(member.issym() or member.islnk())
                self.assertTrue(member.isfile() or member.isdir())
                self.assertFalse(
                    any(
                        "xattr" in key.lower() or "capability" in key.lower()
                        for key in member.pax_headers
                    )
                )
                mode = stat.S_IMODE(member.mode)
                if member.isdir():
                    self.assertEqual(mode, 0o755)
                elif name in executable_paths:
                    self.assertEqual(mode, 0o755)
                else:
                    self.assertEqual(mode, 0o644)
                self.assertEqual(mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX), 0)

        required = {
            "usr/bin/isopropyl-validate-windows-bcd-capture",
            "usr/bin/isopropyl-import-windows-bcd-capture",
            "usr/lib/isopropyl-tools/import_windows_bcd_capture.py",
            "usr/share/doc/isopropyl/examples/capture_windows_bcd_oracle.ps1",
            "usr/lib/isopropyl-tools/validate_windows_bcd_capture.py",
            "usr/libexec/isopropyl/syslinux_device_helper.py",
            "usr/share/polkit-1/actions/io.github.codebooker.isopropyl.policy",
            "usr/share/polkit-1/actions/io.github.codebooker.isopropyl.raw-write.policy",
            "usr/share/polkit-1/actions/io.github.codebooker.isopropyl.fast-zero.policy",
            "usr/share/man/man1/isopropyl.1.gz",
            "usr/share/man/man1/isopropyl-cli.1.gz",
            "usr/share/doc/isopropyl/changelog.Debian.gz",
            "usr/share/doc/isopropyl/README.md.gz",
            "usr/share/doc/isopropyl/SECURITY.md.gz",
            "usr/share/doc/isopropyl/FEATURE_MATRIX.md.gz",
            "usr/share/doc/isopropyl/ROADMAP.md.gz",
            "usr/share/doc/isopropyl/THIRD_PARTY_NOTICES.md.gz",
            "usr/share/doc/isopropyl/LICENSE.gz",
            "usr/lib/python3/dist-packages/isopropyl/freedos_downloads.py",
            "usr/lib/python3/dist-packages/isopropyl/data/freedos-images-v1.json",
            "usr/lib/python3/dist-packages/isopropyl/data/windows-images-v2.json",
        }
        self.assertTrue(required.issubset(self.data))
        self.assertFalse(any("windows-images-v1.json" in name for name in self.data))
        self.assertFalse(any("__pycache__" in name or name.endswith(".pyc") for name in self.data))

    def test_large_documents_are_deterministically_compressed(self):
        builder = runpy.run_path(os.fspath(BUILDER))
        for source_name, destination_name in builder["COMPRESSED_DOCUMENTS"]:
            installed = f"usr/share/doc/isopropyl/{destination_name}"
            with self.subTest(document=source_name):
                payload = self.data[installed][1]
                self.assertEqual(gzip.decompress(payload), (ROOT / source_name).read_bytes())
                self.assertEqual(int.from_bytes(payload[4:8], "little"), int(SOURCE_DATE_EPOCH))
                self.assertNotIn(
                    f"usr/share/doc/isopropyl/{source_name}",
                    self.data,
                )

    def test_launchers_desktop_and_helper_are_fixed_and_consistent(self):
        for name in ("usr/bin/isopropyl", "usr/bin/isopropyl-cli"):
            text = self.data[name][1].decode("utf-8")
            self.assertTrue(text.startswith("#!/usr/bin/python3 -I\n"))
            self.assertLess(text.index("os.geteuid()"), text.index("from isopropyl"))
            self.assertIn("regular desktop user, not root", text)
        self.assertIn(
            "raise SystemExit(4)",
            self.data["usr/bin/isopropyl-cli"][1].decode("utf-8"),
        )
        validator_launcher = self.data[
            "usr/bin/isopropyl-validate-windows-bcd-capture"
        ][1].decode("utf-8")
        self.assertTrue(validator_launcher.startswith("#!/usr/bin/python3 -I\n"))
        self.assertIn(
            "/usr/lib/isopropyl-tools/validate_windows_bcd_capture.py",
            validator_launcher,
        )
        self.assertEqual(
            self.data["usr/lib/isopropyl-tools/validate_windows_bcd_capture.py"][1],
            (ROOT / "tools/validate_windows_bcd_capture.py").read_bytes(),
        )
        importer_launcher = self.data[
            "usr/bin/isopropyl-import-windows-bcd-capture"
        ][1].decode("utf-8")
        self.assertTrue(importer_launcher.startswith("#!/usr/bin/python3 -I\n"))
        self.assertIn(
            "/usr/lib/isopropyl-tools/import_windows_bcd_capture.py",
            importer_launcher,
        )
        self.assertEqual(
            self.data["usr/lib/isopropyl-tools/import_windows_bcd_capture.py"][1],
            (ROOT / "tools/import_windows_bcd_capture.py").read_bytes(),
        )
        self.assertEqual(
            self.data[
                "usr/share/doc/isopropyl/examples/capture_windows_bcd_oracle.ps1"
            ][1],
            (ROOT / "tools/capture_windows_bcd_oracle.ps1").read_bytes(),
        )
        desktop = self.data[
            "usr/share/applications/io.github.codebooker.isopropyl.desktop"
        ][1].decode("utf-8")
        self.assertIn("\nExec=/usr/bin/isopropyl %f\n", desktop)
        helper_launcher = self.data["usr/libexec/isopropyl-device-helper"][1]
        self.assertEqual(
            helper_launcher,
            (ROOT / "helper/isopropyl-device-helper").read_bytes(),
        )
        packaged_helper = self.data[
            "usr/libexec/isopropyl/syslinux_device_helper.py"
        ][1]
        public_helper = self.data[
            "usr/lib/python3/dist-packages/isopropyl/syslinux_device_helper.py"
        ][1]
        self.assertEqual(packaged_helper, public_helper)

    def test_python_and_license_payloads_match_explicit_source_allowlists(self):
        builder = runpy.run_path(os.fspath(BUILDER))
        packaged_python = {
            name.removeprefix("usr/lib/python3/dist-packages/isopropyl/")
            for name, (member, _content) in self.data.items()
            if member.isfile()
            and name.startswith("usr/lib/python3/dist-packages/isopropyl/")
        }
        packaged_licenses = {
            name.removeprefix("usr/share/doc/isopropyl/licenses/")
            for name, (member, _content) in self.data.items()
            if member.isfile()
            and name.startswith("usr/share/doc/isopropyl/licenses/")
        }
        self.assertEqual(packaged_python, set(builder["PYTHON_PACKAGE_FILES"]))
        self.assertEqual(packaged_licenses, set(builder["LICENSE_FILES"]))

    def test_builder_rejects_an_unknown_python_payload(self):
        builder = runpy.run_path(os.fspath(BUILDER))
        with tempfile.TemporaryDirectory() as directory:
            fake_root = Path(directory)
            package_root = fake_root / "isopropyl"
            for relative_name in builder["PYTHON_PACKAGE_FILES"]:
                path = package_root / relative_name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"test\n")
            (package_root / ".env").write_bytes(b"secret\n")
            copier = builder["_copy_python_package"]
            copier.__globals__["ROOT"] = fake_root
            with self.assertRaisesRegex(
                builder["PackageBuildError"],
                "allowlist mismatch",
            ):
                copier(fake_root / "stage")

    def test_md5_manifest_covers_every_regular_payload_file(self):
        manifest = self.control["md5sums"][1].decode("ascii").splitlines()
        observed = {}
        for line in manifest:
            digest, name = line.split("  ", 1)
            observed[name] = digest
        expected = {
            name: hashlib.md5(content, usedforsecurity=False).hexdigest()
            for name, (member, content) in self.data.items()
            if member.isfile()
        }
        self.assertEqual(observed, expected)


if __name__ == "__main__":
    unittest.main()
