from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import json
import shutil
import unittest
from pathlib import Path

from isopropyl.rufus_prompt_mbr import (
    RUFUS_PROMPT_MBR_SHA256,
    RUFUS_PROMPT_MBR_SIZE,
    load_rufus_prompt_mbr,
    verify_reproducible_rufus_prompt_mbr,
)


ROOT = Path(__file__).resolve().parents[1]
BINUTILS = tuple(shutil.which(name) for name in ("as", "ld", "objcopy"))


class RufusPromptMbrTests(unittest.TestCase):
    def test_packaged_bootstrap_matches_exact_pin_and_manifest(self) -> None:
        asset = load_rufus_prompt_mbr()
        self.assertEqual(len(asset), RUFUS_PROMPT_MBR_SIZE)
        self.assertEqual(hashlib.sha256(asset).hexdigest(), RUFUS_PROMPT_MBR_SHA256)
        self.assertIn(b"Press any key to boot from USB.", asset)

        manifest = json.loads(
            (ROOT / "isopropyl/data/bundled-boot-assets-v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(manifest["schema_version"], 1)
        entry = manifest["artifacts"][0]
        self.assertEqual(entry["id"], "rufus-prompt-mbr-440")
        self.assertEqual(entry["size"], RUFUS_PROMPT_MBR_SIZE)
        self.assertEqual(entry["sha256"], RUFUS_PROMPT_MBR_SHA256)
        self.assertEqual(entry["license"], "GPL-3.0-or-later")

    @unittest.skipUnless(all(BINUTILS), "GNU as, ld, and objcopy are not installed")
    def test_vendored_sources_reproduce_asset_deterministically(self) -> None:
        tools = tuple(Path(value).resolve() for value in BINUTILS if value is not None)
        first = verify_reproducible_rufus_prompt_mbr(
            ROOT, assembler=tools[0], linker=tools[1], objcopy=tools[2]
        )
        second = verify_reproducible_rufus_prompt_mbr(
            ROOT, assembler=tools[0], linker=tools[1], objcopy=tools[2]
        )
        self.assertEqual(first, second)
        self.assertEqual(hashlib.sha256(first).hexdigest(), RUFUS_PROMPT_MBR_SHA256)


if __name__ == "__main__":
    unittest.main()
