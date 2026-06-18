"""Controllable clocks.

Every timestamp in the testbed comes from a `Clock` so that (a) traces are
deterministic and replayable (assumption A5) and (b) Phase 2 can advance time and
inject delay without touching wall-clock time. `ManualClock` is the default for
the benign baseline and all tests.
"""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> float:
        """Seconds since an arbitrary epoch (monotonic, non-decreasing)."""
        ...


class ManualClock:
    """Deterministic clock advanced explicitly by the harness."""

    def __init__(self, start: float = 0.0) -> None:
        self._t = float(start)

    def now(self) -> float:
        return self._t

    def advance(self, dt: float) -> float:
        if dt < 0:
            raise ValueError("clock cannot move backwards")
        self._t += float(dt)
        return self._t


class WallClock:
    """Real monotonic clock — for live Home Assistant runs."""

    def now(self) -> float:
        return time.monotonic()
