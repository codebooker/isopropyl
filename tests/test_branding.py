from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import re
import unittest
import xml.etree.ElementTree as ET
from importlib.resources import files
from pathlib import Path

from PyQt6.QtGui import QImage


ROOT = Path(__file__).resolve().parents[1]
APP_ID = "io.github.codebooker.isopropyl"


class BrandingTests(unittest.TestCase):
    def test_packaged_fallback_icon_matches_desktop_icon(self):
        desktop_icon = (ROOT / "data" / f"{APP_ID}.svg").read_bytes()
        packaged_resource = files("isopropyl").joinpath(
            f"data/{APP_ID}.svg"
        )
        packaged_icon = packaged_resource.read_bytes()
        self.assertEqual(packaged_icon, desktop_icon)

        root = ET.fromstring(desktop_icon)
        self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
        self.assertEqual(root.attrib.get("viewBox"), "0 0 256 256")
        rendered = QImage(str(packaged_resource))
        self.assertFalse(rendered.isNull())
        self.assertEqual((rendered.width(), rendered.height()), (256, 256))

    def test_raster_icons_have_exact_size_and_transparent_corners(self):
        for size in (48, 64, 128, 256):
            with self.subTest(size=size):
                path = (
                    ROOT / "data" / "icons" / f"{size}x{size}" / "apps"
                    / f"{APP_ID}.png"
                )
                image = QImage(str(path))
                self.assertFalse(image.isNull())
                self.assertEqual((image.width(), image.height()), (size, size))
                self.assertTrue(image.hasAlphaChannel())
                corners = (
                    (0, 0), (size - 1, 0),
                    (0, size - 1), (size - 1, size - 1),
                )
                for x, y in corners:
                    self.assertEqual(image.pixelColor(x, y).alpha(), 0)

    def test_hero_and_screenshot_are_well_formed(self):
        hero = ET.parse(ROOT / "data" / "isopropyl-hero.svg").getroot()
        self.assertEqual(hero.attrib.get("viewBox"), "0 0 1200 360")
        hero_text = "".join(hero.itertext())
        self.assertIn("Bootable media, without the guesswork.", hero_text)

        screenshot = QImage(str(ROOT / "data" / "screenshot.png"))
        self.assertFalse(screenshot.isNull())
        self.assertEqual((screenshot.width(), screenshot.height()), (1080, 960))

    def test_package_readme_uses_host_independent_asset_and_document_links(self):
        readme = (ROOT / "README.md").read_text("utf-8")
        image_targets = re.findall(r"!\[[^]]*\]\(([^)]+)\)", readme)
        self.assertGreaterEqual(len(image_targets), 2)
        self.assertTrue(
            all(target.startswith("https://") for target in image_targets),
            image_targets,
        )
        release_assets = tuple(
            target for target in image_targets
            if target.endswith(("/data/isopropyl-hero.svg", "/data/screenshot.png"))
        )
        self.assertEqual(len(release_assets), 2)
        for target in release_assets:
            self.assertNotIn("/main/", target)
            self.assertRegex(
                target,
                r"^https://raw\.githubusercontent\.com/codebooker/isopropyl/"
                r"[0-9a-f]{40}/data/(?:isopropyl-hero\.svg|screenshot\.png)$",
            )
        for document in (
            "BRANDING.md", "CONTRIBUTING.md", "FEATURE_MATRIX.md", "LICENSE",
            "ROADMAP.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md",
        ):
            self.assertNotIn(f"]({document})", readme)

    def test_desktop_and_appstream_identity_are_consistent(self):
        desktop = (ROOT / "data" / f"{APP_ID}.desktop").read_text("utf-8")
        self.assertIn("Name=ISOpropyl\n", desktop)
        self.assertIn(f"Icon={APP_ID}\n", desktop)

        metadata = ET.parse(ROOT / "data" / f"{APP_ID}.metainfo.xml").getroot()
        self.assertEqual(metadata.findtext("id"), APP_ID)
        self.assertEqual(metadata.findtext("name"), "ISOpropyl")
        self.assertEqual(metadata.findtext("launchable"), f"{APP_ID}.desktop")
        screenshot_url = metadata.findtext("screenshots/screenshot/image") or ""
        self.assertNotIn("/main/", screenshot_url)
        self.assertRegex(
            screenshot_url,
            rf"^https://raw\.githubusercontent\.com/codebooker/isopropyl/"
            rf"[0-9a-f]{{40}}/data/screenshot\.png$",
        )


if __name__ == "__main__":
    unittest.main()
