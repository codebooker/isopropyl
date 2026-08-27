# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import unittest

from isopropyl.progress import ProgressEstimator, format_duration


class Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class ProgressTests(unittest.TestCase):
    def test_calculates_rate_and_eta_from_monotonic_samples(self):
        clock = Clock()
        estimator = ProgressEstimator(clock)
        estimator.update(0, 1000, "Writing")
        clock.value = 2.0
        result = estimator.update(200, 1000, "Writing")
        self.assertEqual(result.bytes_per_second, 100)
        self.assertEqual(result.eta_seconds, 8)
        self.assertEqual(result.fraction, 0.2)

    def test_stage_total_or_regression_resets_the_rate(self):
        clock = Clock()
        estimator = ProgressEstimator(clock)
        estimator.update(0, 100, "Writing")
        clock.value = 1
        self.assertIsNotNone(estimator.update(50, 100, "Writing").bytes_per_second)
        self.assertIsNone(estimator.update(0, 200, "Verifying").bytes_per_second)

    def test_formats_short_and_long_durations(self):
        self.assertEqual(format_duration(8.4), "8s")
        self.assertEqual(format_duration(125), "2m 05s")
        self.assertEqual(format_duration(3720), "1h 02m")


if __name__ == "__main__":
    unittest.main()
