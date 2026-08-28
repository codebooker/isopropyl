from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SourceInstallTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("make"), "GNU make is not installed")
    def test_make_install_replaces_an_existing_package_without_nesting(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            package = (
                destination / "usr/lib/python3/site-packages/isopropyl"
            )
            data = package / "data"
            data.mkdir(parents=True)
            (package / "stale-marker").write_text("old install")
            (data / "windows-images-v1.json").write_text("{}")

            subprocess.run(
                [
                    "make", "install", f"DESTDIR={destination}",
                    "PREFIX=/usr",
                    "PYTHON_SITE=/usr/lib/python3/site-packages",
                ],
                cwd=ROOT,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertTrue((package / "app.py").is_file())
            self.assertTrue((package / "freedos_downloads.py").is_file())
            self.assertTrue((data / "freedos-images-v1.json").is_file())
            self.assertTrue((data / "windows-images-v2.json").is_file())
            self.assertFalse((data / "windows-images-v1.json").exists())
            self.assertFalse((package / "stale-marker").exists())
            self.assertFalse((package / "isopropyl").exists())
