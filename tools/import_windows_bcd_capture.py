#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Validate and atomically import a Windows BCD capture evidence directory."""

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from isopropyl.windows_bcd import BcdError
from isopropyl.windows_bcd_capture_import import (
    BcdCaptureImportCommittedError,
    BcdCaptureImportError,
    BcdCaptureImportReceipt,
    import_windows_bcd_capture,
)


def _report(receipt: BcdCaptureImportReceipt) -> dict[str, object]:
    return {
        "artifacts": {
            "derived_fixtures": [
                {
                    "name": item.name,
                    "sha256": item.sha256,
                    "size": item.size,
                }
                for item in receipt.fixture_artifacts
            ],
            "source_copies": [
                {
                    "name": item.name,
                    "sha256": item.sha256,
                    "size": item.size,
                }
                for item in receipt.source_artifacts
            ],
        },
        "authorization": {
            "authorizes_device_writes": False,
            "authorizes_hive_writes": False,
            "authorizes_linux_bcd_generation": False,
            "authorizes_windows_to_go_execution": False,
        },
        "destination": receipt.destination,
        "scope": {
            "boot_certified": False,
            "firmware_certified": False,
            "physical_media_certified": False,
            "windows_provenance_authenticated": False,
        },
        "status": "non-authorizing-capture-imported",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("source", help="exact seven-file source capture directory")
    parser.add_argument("destination", help="new destination directory to publish")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = import_windows_bcd_capture(args.source, args.destination)
    except BcdCaptureImportCommittedError as error:
        print(f"BCD capture import committed with uncertain final state: {error}", file=sys.stderr)
        return 2
    except (BcdError, BcdCaptureImportError, OSError, ValueError) as error:
        print(f"BCD capture import failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(_report(receipt), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
