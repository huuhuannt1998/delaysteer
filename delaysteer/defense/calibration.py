"""Startup calibration of the guard's active-poll tolerance.

`Config.poll_rtt_s` defaults to 0.05 s, the round trip measured on a localhost hub. Over a cloud
path every poll takes longer than that, so a guard shipped with the constant blocks every benign
commit there. This measures the deployment's own poll round trip before the guard runs and sets
the tolerance to its P99 plus a margin, the rule the paper uses for the freshness budget.

An adversary present while calibrating can delay the polls and inflate the tolerance. Run it at
install time on a path you trust, and pass `max_s` (at most the smallest critical budget) so an
inflated result is refused instead of silently widening what the guard admits.
"""

from __future__ import annotations

import math
import time
from typing import Callable, Iterable


def p99(samples: list[float]) -> float:
    xs = sorted(samples)
    return xs[min(len(xs) - 1, max(0, math.ceil(0.99 * len(xs)) - 1))]


def calibrate_poll_rtt(adapter, entity_ids: Iterable[str], n: int = 20, margin_s: float = 0.05,
                       max_s: float | None = None,
                       clock: Callable[[], float] = time.perf_counter) -> dict:
    """Time `n` forced re-reads of each entity and return the tolerance P99 + margin."""
    ids = list(entity_ids)
    if not ids or n < 1:
        raise ValueError("need at least one entity and one round")
    samples: list[float] = []
    previous = getattr(adapter, "active_poll", False)
    adapter.active_poll = True                     # the same forced refresh the guard issues
    try:
        for _ in range(n):
            for e in ids:
                t0 = clock()
                adapter.get_state(e)
                samples.append(clock() - t0)
    finally:
        adapter.active_poll = previous
    tol = round(p99(samples) + margin_s, 4)
    if max_s is not None and tol > max_s:
        raise ValueError(f"calibrated poll tolerance {tol}s exceeds the cap {max_s}s; "
                         "recalibrate on a trusted path or raise the budget deliberately")
    return {"poll_rtt_s": tol, "p99_s": round(p99(samples), 4), "n": len(samples),
            "max_s": round(max(samples), 4), "margin_s": margin_s}


def apply_poll_calibration(cfg, adapter, entity_ids: Iterable[str], **kw) -> dict:
    """Calibrate and write the result into `cfg.poll_rtt_s`; returns the calibration record."""
    rec = calibrate_poll_rtt(adapter, entity_ids, **kw)
    cfg.poll_rtt_s = rec["poll_rtt_s"]
    return rec
