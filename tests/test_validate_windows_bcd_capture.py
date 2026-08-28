# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import contextlib
import fcntl
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from isopropyl.windows_bcd import BcdError
from isopropyl.windows_bcd_oracle import canonical_bcd_oracle_bytes
from tests.test_windows_bcd_oracle import differential_fixtures
from tools import validate_windows_bcd_capture as harness


class WindowsBcdCaptureValidationTests(unittest.TestCase):
    def _capture_files(self, root: Path):
        fixtures = differential_fixtures()
        pairs = []
        hive_payloads = {}
        for index, fixture in enumerate(fixtures):
            fixture_path = root / f"{fixture.variant}.json"
            fixture_path.write_bytes(canonical_bcd_oracle_bytes(fixture))
            hive_path = root / f"{fixture.variant}.bcd"
            payload = b"regf" + bytes([index]) + fixture.variant.encode("ascii")
            hive_path.write_bytes(payload)
            hive_payloads[fixture.variant] = payload
            pairs.append(harness.CapturePair(fixture.variant, fixture_path, hive_path))
        return fixtures, pairs, hive_payloads

    @staticmethod
    def _argv(pairs):
        argv = []
        for pair in pairs:
            argv.extend(
                (
                    f"--{pair.label}",
                    str(pair.fixture_path),
                    str(pair.hive_path),
                ),
            )
        return argv

    def test_success_reads_pinned_hives_and_reports_no_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixtures, pairs, hive_payloads = self._capture_files(root)
            original = {pair.hive_path: pair.hive_path.read_bytes() for pair in pairs}
            observed = []

            def verify(descriptor, fixture):
                flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
                self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
                self.assertTrue(flags & getattr(os, "O_NONBLOCK", 0))
                size = os.fstat(descriptor).st_size
                observed.append((fixture.variant, os.pread(descriptor, size, 0)))

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch.object(
                    harness,
                    "verify_bcd_hive_descriptor_against_fixture",
                    side_effect=verify,
                ) as mocked,
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                result = harness.main(self._argv(pairs))

            self.assertEqual(result, 0)
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(mocked.call_count, 4)
            self.assertEqual(
                observed,
                [(fixture.variant, hive_payloads[fixture.variant]) for fixture in fixtures],
            )
            self.assertEqual(len({call.args[0] for call in mocked.call_args_list}), 4)
            self.assertEqual(
                {path: path.read_bytes() for path in original},
                original,
            )
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["status"], "non-authorizing-evidence-match")
            self.assertEqual(report["evidence"]["hives_compared_read_only"], 4)
            self.assertEqual(report["evidence"]["variants"], list(harness.CAPTURE_LABELS))
            self.assertTrue(report["evidence"]["differential_cohort_validated"])
            self.assertTrue(all(value is False for value in report["authorization"].values()))
            self.assertTrue(all(value is False for value in report["scope"].values()))

    def test_missing_option_is_an_argparse_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, pairs, _ = self._capture_files(Path(temporary))
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(
                SystemExit,
            ) as raised:
                harness.main(self._argv(pairs[:-1]))
        self.assertEqual(raised.exception.code, 2)

    def test_capture_option_names_cannot_be_abbreviated(self):
        arguments = [
            "--base",
            "baseline.json",
            "baseline.BCD",
            "--disk-guid",
            "disk-guid.json",
            "disk-guid.BCD",
            "--esp-guid",
            "esp-guid.json",
            "esp-guid.BCD",
            "--windows-guid",
            "windows-guid.json",
            "windows-guid.BCD",
        ]
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(
            SystemExit,
        ) as raised:
            harness.build_parser().parse_args(arguments)
        self.assertEqual(raised.exception.code, 2)

    def test_options_must_appear_in_exact_capture_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, pairs, _ = self._capture_files(Path(temporary))
            reordered = [pairs[1], pairs[0], pairs[2], pairs[3]]
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch.object(
                    harness,
                    "verify_bcd_hive_descriptor_against_fixture",
                ) as verify,
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                result = harness.main(self._argv(reordered))
            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("in order", stderr.getvalue())
            verify.assert_not_called()

    def test_duplicate_or_extra_capture_fails_before_hive_comparison(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, pairs, _ = self._capture_files(Path(temporary))
            argv = self._argv(pairs)
            argv.extend(("--baseline", str(pairs[0].fixture_path), str(pairs[0].hive_path)))
            with (
                patch.object(
                    harness,
                    "verify_bcd_hive_descriptor_against_fixture",
                ) as verify,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                result = harness.main(argv)
            self.assertEqual(result, 1)
            verify.assert_not_called()

    def test_fixture_variant_must_match_its_cli_label(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, pairs, _ = self._capture_files(Path(temporary))
            swapped = list(pairs)
            swapped[0] = harness.CapturePair(
                "baseline",
                pairs[1].fixture_path,
                pairs[0].hive_path,
            )
            with (
                patch.object(
                    harness,
                    "verify_bcd_hive_descriptor_against_fixture",
                ) as verify,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                result = harness.main(self._argv(swapped))
            self.assertEqual(result, 1)
            verify.assert_not_called()

    def test_malformed_differential_fixture_fails_before_hive_comparison(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, pairs, _ = self._capture_files(Path(temporary))
            pairs[2].fixture_path.write_bytes(b"{}\n")
            stdout = io.StringIO()
            with (
                patch.object(
                    harness,
                    "verify_bcd_hive_descriptor_against_fixture",
                ) as verify,
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                result = harness.main(self._argv(pairs))
            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue(), "")
            verify.assert_not_called()

    def test_hive_mismatch_emits_no_success_report_and_preserves_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, pairs, _ = self._capture_files(Path(temporary))
            original = {pair.hive_path: pair.hive_path.read_bytes() for pair in pairs}
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch.object(
                    harness,
                    "verify_bcd_hive_descriptor_against_fixture",
                    side_effect=BcdError("fixture mismatch"),
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                result = harness.main(self._argv(pairs))
            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("fixture mismatch", stderr.getvalue())
            self.assertEqual(
                {path: path.read_bytes() for path in original},
                original,
            )

    def test_pathname_replacement_cannot_redirect_the_pinned_hive_descriptor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, pairs, _ = self._capture_files(root)
            original = pairs[0].hive_path.read_bytes()
            replacement = b"regf-replacement-path"
            inspected = []

            def replace_then_inspect(descriptor, fixture):
                candidate = root / "replacement.bcd"
                candidate.write_bytes(replacement)
                os.replace(candidate, pairs[0].hive_path)
                inspected.append(
                    (
                        fixture.variant,
                        os.pread(descriptor, os.fstat(descriptor).st_size, 0),
                    ),
                )

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch.object(
                    harness,
                    "verify_bcd_hive_descriptor_against_fixture",
                    side_effect=replace_then_inspect,
                ) as verify,
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                result = harness.main(self._argv(pairs))

            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("changed during validation", stderr.getvalue())
            self.assertEqual(verify.call_count, 1)
            self.assertEqual(inspected, [("baseline", original)])
            self.assertEqual(pairs[0].hive_path.read_bytes(), replacement)

    def test_aliases_and_symlinks_are_rejected_before_hive_comparison(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, pairs, _ = self._capture_files(root)
            aliases = list(pairs)
            aliases[1] = harness.CapturePair(
                aliases[1].label,
                aliases[1].fixture_path,
                aliases[0].hive_path,
            )
            symlink = root / "baseline-link.bcd"
            symlink.symlink_to(pairs[0].hive_path)
            linked = list(pairs)
            linked[0] = harness.CapturePair(
                linked[0].label,
                linked[0].fixture_path,
                symlink,
            )
            for candidate in (aliases, linked):
                with (
                    self.subTest(candidate=candidate[0].hive_path),
                    patch.object(
                        harness,
                        "verify_bcd_hive_descriptor_against_fixture",
                    ) as verify,
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    result = harness.main(self._argv(candidate))
                self.assertEqual(result, 1)
                verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
