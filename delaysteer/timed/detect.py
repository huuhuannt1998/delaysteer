#!/usr/bin/env python3
"""Stage 5 -- detectability, anchored to benign jitter rather than to the Guard.

Challenge 4 in the design is detectability circularity: if the attack budget is
tuned against our own detector, the evaluation proves only that we can beat
ourselves. The anchor therefore has to be the ENVIRONMENT. A smart-home transport
is already bursty and lossy, and a detector that flags ordinary congestion is
switched off within a week -- so the operating point is set by what a detector
must tolerate to remain usable, and the attack budget is whatever fits inside
that.

This module provides:
  * a benign inter-arrival model (log-normal with a heavy tail plus occasional
    retry stalls -- the shape smart-home transports actually produce);
  * three detector families, each a predicate over an observed delay sequence;
  * calibration at named false-positive rates on benign traffic ONLY;
  * the minimum detectable budget per property, and the severity-detectability
    Pareto frontier.

The number the paper needs from here is not "our detector catches X%". It is:
at the false-positive rate a real deployment would accept, what is the largest
hold an adversary can take without crossing the threshold -- and is that hold
big enough to run the attacks. If it is, the attacks live inside the envelope a
usable detector must tolerate.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Callable, Sequence

# ----------------------------------------------------------- benign model


@dataclass
class BenignJitter:
    """Inter-arrival delay for an unattacked smart-home sensor flow.

    Log-normal body (multiplicative noise from radio retries, mesh hops and
    hub scheduling) plus a stall component: with probability `p_stall` a message
    waits for a retry cycle. The stall matters more than the body -- it is why
    a naive max-age threshold has to sit high to stay usable, and therefore why
    an adversary has room.

    Defaults are ordinary consumer-mesh figures (sub-second typical, occasional
    multi-second stalls), stated as modelled rather than measured: no physical
    radio was used, per the design's realism commitment. That bounds the
    DEFENSE's cadence numbers, not the attack, because the attack acts on the
    arrival timestamp which is identical either way.
    """

    median_s: float = 0.35
    sigma: float = 0.9            # log-space spread
    p_stall: float = 0.04
    stall_s: float = 12.0
    stall_spread: float = 6.0

    def sample(self, rng: random.Random) -> float:
        d = math.exp(rng.gauss(math.log(self.median_s), self.sigma))
        if rng.random() < self.p_stall:
            d += max(0.0, rng.gauss(self.stall_s, self.stall_spread))
        return d

    def trace(self, n: int, rng: random.Random) -> list[float]:
        return [self.sample(rng) for _ in range(n)]


# ------------------------------------------------------------- detectors
# Each returns a SCORE; higher is more suspicious. Thresholds are calibrated on
# benign traffic only, never on attacked traffic -- calibrating on the attack is
# the circularity this stage exists to avoid.


def d_max_age(delays: Sequence[float]) -> float:
    """The obvious one: the largest single observed delay."""
    return max(delays) if delays else 0.0


def d_total_hold(delays: Sequence[float], window: int = 8) -> float:
    """Integrated delay over a sliding window.

    Catches an adversary that stays under any per-message cap but holds many
    messages a little -- exactly the schedule a `delta_max`-only budget invites.
    """
    if not delays:
        return 0.0
    if len(delays) <= window:
        return sum(delays)
    return max(sum(delays[i:i + window]) for i in range(len(delays) - window + 1))


def d_burst_ratio(delays: Sequence[float]) -> float:
    """Ratio of the worst delay to the flow's own median.

    Scale-free, so one threshold works across flows with different nominal
    cadences -- a per-flow absolute threshold would need per-device tuning that
    no deployment will do.
    """
    if not delays:
        return 0.0
    s = sorted(delays)
    med = s[len(s) // 2] or 1e-6
    return max(delays) / med


DETECTORS: dict[str, Callable[[Sequence[float]], float]] = {
    "max_age": d_max_age,
    "total_hold_w8": d_total_hold,
    "burst_ratio": d_burst_ratio,
}


# ----------------------------------------------------------- calibration


@dataclass
class Calibration:
    detector: str
    fpr: float
    threshold: float
    n_benign: int

    def flags(self, delays: Sequence[float]) -> bool:
        return DETECTORS[self.detector](delays) > self.threshold


def calibrate(detector: str, *, fpr: float, jitter: BenignJitter,
              flow_len: int = 40, n_flows: int = 4000,
              seed: int = 0) -> Calibration:
    """Set the threshold at the (1-fpr) quantile of BENIGN scores.

    Benign only. A threshold fitted with any sight of attacked traffic would
    make the resulting detectability numbers circular.
    """
    rng = random.Random(seed)
    scores = sorted(DETECTORS[detector](jitter.trace(flow_len, rng))
                    for _ in range(n_flows))
    idx = min(len(scores) - 1, int(math.ceil((1.0 - fpr) * len(scores))) - 1)
    return Calibration(detector, fpr, scores[max(0, idx)], n_flows)


# ------------------------------------------------- minimum detectable budget


@dataclass
class BudgetProbe:
    """Largest hold that stays under a calibrated threshold."""

    detector: str
    fpr: float
    threshold: float
    max_undetected_hold_s: float
    n_held: int

    @property
    def summary(self) -> str:
        return (f"{self.detector}@fpr={self.fpr:.3f}: an adversary holding "
                f"{self.n_held} message(s) can take up to "
                f"{self.max_undetected_hold_s:.1f}s without crossing")


def max_undetected_hold(cal: Calibration, *, jitter: BenignJitter,
                        n_held: int = 1, flow_len: int = 40,
                        seed: int = 1, hi: float = 3600.0,
                        tol: float = 0.5) -> BudgetProbe:
    """Binary-search the largest per-message hold that stays under threshold.

    The adversary is modelled as adding its hold to `n_held` messages of an
    otherwise benign flow, which is exactly what a delay-only adversary does:
    it does not change the number of messages or their payloads, only when some
    of them arrive.
    """
    rng = random.Random(seed)
    base = jitter.trace(flow_len, rng)

    def attacked(hold: float) -> list[float]:
        d = list(base)
        for i in range(min(n_held, len(d))):
            d[i * max(1, len(d) // max(1, n_held))] += hold
        return d

    lo, high = 0.0, hi
    if cal.flags(attacked(lo)):
        return BudgetProbe(cal.detector, cal.fpr, cal.threshold, 0.0, n_held)
    while high - lo > tol:
        mid = (lo + high) / 2
        if cal.flags(attacked(mid)):
            high = mid
        else:
            lo = mid
    return BudgetProbe(cal.detector, cal.fpr, cal.threshold, lo, n_held)


# ------------------------------------------------------------ the frontier


@dataclass
class ParetoPoint:
    fpr: float
    detector: str
    max_undetected_hold_s: float
    attack_needs_s: float
    feasible: bool = field(init=False)

    def __post_init__(self) -> None:
        self.feasible = self.max_undetected_hold_s >= self.attack_needs_s


def frontier(*, attack_needs_s: float, jitter: BenignJitter | None = None,
             fprs: Sequence[float] = (0.001, 0.005, 0.01, 0.05),
             n_held: int = 1, seed: int = 0) -> list[ParetoPoint]:
    """Severity-detectability frontier for one required hold.

    `attack_needs_s` is what the attack actually required in the measured runs,
    so this asks the only question that matters: does the schedule the attack
    needs fit under the threshold a usable detector must sit at?
    """
    j = jitter or BenignJitter()
    out: list[ParetoPoint] = []
    for name in DETECTORS:
        for fpr in fprs:
            cal = calibrate(name, fpr=fpr, jitter=j, seed=seed)
            p = max_undetected_hold(cal, jitter=j, n_held=n_held, seed=seed + 1)
            out.append(ParetoPoint(fpr, name, p.max_undetected_hold_s,
                                   attack_needs_s))
    return out
