#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

"""Validate a four-run Windows BCD oracle capture without authorizing writes.

The inputs are evidence only.  This tool accepts regular files, opens them
read-only, validates the complete differential cohort, and compares every BCD
hive with its canonical fixture.  A successful result does not authorize BCD,
device, or installation-media writes and is not a boot certification.
"""

import argparse
import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from isopropyl.windows_bcd import BcdError
from isopropyl.windows_bcd_hivex import (
    BCD_HIVE_MAX_BYTES,
    verify_bcd_hive_descriptor_against_fixture,
)
from isopropyl.windows_bcd_oracle import (
    BCD_ORACLE_MAX_BYTES,
    BCD_ORACLE_SCHEMA,
    BcdOracleFixture,
    parse_bcd_oracle_bytes,
    validate_bcd_oracle_differential_set,
)

CAPTURE_LABELS = ("baseline", "disk-guid", "esp-guid", "windows-guid")


class CaptureValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class CapturePair:
    label: str
    fixture_path: Path
    hive_path: Path


class _CaptureAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Sequence[str],
        option_string: str | None = None,
    ) -> None:
        captures = list(getattr(namespace, self.dest, None) or ())
        captures.append(CapturePair(str(self.const), Path(values[0]), Path(values[1])))
        setattr(namespace, self.dest, captures)


@dataclass
class _PinnedRegularFile:
    source_path: Path
    descriptor: int
    initial_status: os.stat_result

    @classmethod
    def open(cls, path: Path, label: str) -> _PinnedRegularFile:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        flags |= getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise CaptureValidationError(f"cannot pin {label} as a read-only input") from error
        try:
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode) or status.st_nlink < 1:
                raise CaptureValidationError(f"{label} is not a linked regular file")
            return cls(path, descriptor, status)
        except BaseException:
            os.close(descriptor)
            raise

    @property
    def identity(self) -> tuple[int, int]:
        return (self.initial_status.st_dev, self.initial_status.st_ino)

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def _status_key(self, status: os.stat_result) -> tuple[int, ...]:
        return (
            status.st_dev,
            status.st_ino,
            status.st_mode,
            status.st_nlink,
            status.st_uid,
            status.st_gid,
            status.st_size,
            status.st_mtime_ns,
            status.st_ctime_ns,
        )

    def require_unchanged(self, label: str) -> None:
        try:
            current = os.fstat(self.descriptor)
        except OSError as error:
            raise CaptureValidationError(f"cannot revalidate {label}") from error
        if self._status_key(current) != self._status_key(self.initial_status):
            raise CaptureValidationError(f"{label} changed during validation")

    def read_bytes(self, maximum: int, label: str) -> bytes:
        try:
            status = os.fstat(self.descriptor)
        except OSError as error:
            raise CaptureValidationError(f"cannot inspect pinned {label}") from error
        if (status.st_dev, status.st_ino) != self.identity:
            raise CaptureValidationError(f"{label} identity changed while reading")
        if not 1 <= status.st_size <= maximum:
            raise CaptureValidationError(f"{label} size is outside policy")
        blocks: list[bytes] = []
        offset = 0
        while offset <= maximum:
            try:
                block = os.pread(
                    self.descriptor,
                    min(1024 * 1024, maximum + 1 - offset),
                    offset,
                )
            except OSError as error:
                raise CaptureValidationError(f"cannot read pinned {label}") from error
            if not block:
                break
            blocks.append(block)
            offset += len(block)
        payload = b"".join(blocks)
        if len(payload) != status.st_size or len(payload) > maximum:
            raise CaptureValidationError(f"{label} changed or exceeds the size policy")
        return payload

    def sha256(self, maximum: int, label: str) -> str:
        return hashlib.sha256(self.read_bytes(maximum, label)).hexdigest()


def _capture_report(fixtures: tuple[BcdOracleFixture, ...]) -> dict[str, object]:
    return {
        "authorization": {
            "authorizes_device_writes": False,
            "authorizes_hive_writes": False,
            "authorizes_linux_bcd_generation": False,
            "authorizes_windows_to_go_execution": False,
        },
        "evidence": {
            "captures": [
                {
                    "store_sha256": fixture.provenance.store_sha256,
                    "store_size": fixture.provenance.store_size,
                    "variant": fixture.variant,
                }
                for fixture in fixtures
            ],
            "differential_cohort_validated": True,
            "hives_compared_read_only": len(fixtures),
            "variants": [fixture.variant for fixture in fixtures],
        },
        "fixture_schema": BCD_ORACLE_SCHEMA,
        "scope": {
            "boot_certified": False,
            "firmware_certified": False,
            "physical_media_certified": False,
        },
        "status": "non-authorizing-evidence-match",
    }


def validate_captures(captures: Sequence[CapturePair]) -> dict[str, object]:
    """Validate exactly one ordered fixture/hive pair for every capture label."""

    if type(captures) not in {list, tuple} or tuple(
        capture.label for capture in captures
    ) != CAPTURE_LABELS:
        raise CaptureValidationError(
            "captures must be baseline, disk-guid, esp-guid, and windows-guid in order",
        )

    pinned: list[_PinnedRegularFile] = []
    try:
        fixture_files: list[_PinnedRegularFile] = []
        hive_files: list[_PinnedRegularFile] = []
        for capture in captures:
            fixture_file = _PinnedRegularFile.open(
                capture.fixture_path,
                f"{capture.label} fixture",
            )
            pinned.append(fixture_file)
            fixture_files.append(fixture_file)
            hive_file = _PinnedRegularFile.open(
                capture.hive_path,
                f"{capture.label} BCD hive",
            )
            pinned.append(hive_file)
            hive_files.append(hive_file)

        identities = [item.identity for item in pinned]
        if len(set(identities)) != len(identities):
            raise CaptureValidationError("every fixture and BCD hive must be a distinct file")

        fixtures = tuple(
            parse_bcd_oracle_bytes(
                fixture_file.read_bytes(
                    BCD_ORACLE_MAX_BYTES,
                    f"{capture.label} fixture",
                ),
            )
            for capture, fixture_file in zip(captures, fixture_files, strict=True)
        )
        for capture, fixture in zip(captures, fixtures, strict=True):
            if fixture.variant != capture.label:
                raise CaptureValidationError(
                    f"{capture.label} label does not match fixture variant",
                )

        # No hive is opened by hivex until the entire evidence cohort is valid.
        validate_bcd_oracle_differential_set(fixtures)

        initial_hive_digests = [
            hive_file.sha256(BCD_HIVE_MAX_BYTES, f"{capture.label} BCD hive")
            for capture, hive_file in zip(captures, hive_files, strict=True)
        ]
        for capture, fixture, hive_file in zip(
            captures,
            fixtures,
            hive_files,
            strict=True,
        ):
            verify_bcd_hive_descriptor_against_fixture(
                hive_file.descriptor,
                fixture,
            )
            hive_file.require_unchanged(f"{capture.label} BCD hive")

        final_hive_digests = [
            hive_file.sha256(BCD_HIVE_MAX_BYTES, f"{capture.label} BCD hive")
            for capture, hive_file in zip(captures, hive_files, strict=True)
        ]
        if final_hive_digests != initial_hive_digests:
            raise CaptureValidationError("a BCD hive changed during validation")
        for capture, fixture_file in zip(captures, fixture_files, strict=True):
            fixture_file.require_unchanged(f"{capture.label} fixture")
        return _capture_report(fixtures)
    finally:
        for item in reversed(pinned):
            item.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for label in CAPTURE_LABELS:
        parser.add_argument(
            f"--{label}",
            action=_CaptureAction,
            const=label,
            dest="captures",
            metavar=("FIXTURE_JSON", "BCD_HIVE"),
            nargs=2,
            required=True,
            help=f"read-only {label} fixture and BCD hive",
        )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = validate_captures(args.captures)
    except (BcdError, CaptureValidationError, OSError, ValueError) as error:
        print(f"BCD capture validation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
