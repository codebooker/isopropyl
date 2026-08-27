from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class ProgressSnapshot:
    done: int
    total: int
    fraction: float
    bytes_per_second: float | None
    eta_seconds: float | None
    elapsed_seconds: float


class ProgressEstimator:
    """Monotonic rolling rate/ETA estimator that resets between operation stages."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self.reset()

    def reset(self) -> None:
        self._stage = ""
        self._total = 0
        self._started = self._clock()
        self._samples: deque[tuple[float, int]] = deque()

    def update(self, done: int, total: int, stage: str) -> ProgressSnapshot:
        now = self._clock()
        done = max(0, min(done, total)) if total > 0 else max(0, done)
        if (
            stage != self._stage or total != self._total
            or (self._samples and done < self._samples[-1][1])
        ):
            self._stage = stage
            self._total = total
            self._started = now
            self._samples.clear()
        self._samples.append((now, done))
        while len(self._samples) > 2 and now - self._samples[0][0] > 8.0:
            self._samples.popleft()
        rate: float | None = None
        if len(self._samples) >= 2:
            elapsed = self._samples[-1][0] - self._samples[0][0]
            advanced = self._samples[-1][1] - self._samples[0][1]
            if elapsed >= 0.25 and advanced > 0:
                rate = advanced / elapsed
        eta = ((total - done) / rate) if rate and total > done else None
        return ProgressSnapshot(
            done=done, total=total, fraction=(done / total if total > 0 else 0.0),
            bytes_per_second=rate, eta_seconds=eta,
            elapsed_seconds=max(0.0, now - self._started),
        )


def format_duration(seconds: float) -> str:
    rounded = max(0, round(seconds))
    hours, remainder = divmod(rounded, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:d}h {minutes:02d}m"
    if minutes:
        return f"{minutes:d}m {secs:02d}s"
    return f"{secs:d}s"
