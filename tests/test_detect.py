#!/usr/bin/env python3
"""Stage 5 -- detectability. The properties that keep the budget non-circular."""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from delaysteer.timed.detect import (DETECTORS, BenignJitter, ParetoPoint,
                                     calibrate, frontier, max_undetected_hold)


def test_thresholds_are_calibrated_on_benign_traffic_only():
    """The anchor is the environment, not the guard. A threshold that had seen
    attacked traffic would make every later detectability number circular --
    Challenge 4 in the design."""
    j = BenignJitter()
    c = calibrate("max_age", fpr=0.01, jitter=j, n_flows=2000)
    rng = random.Random(99)
    flagged = sum(c.flags(j.trace(40, rng)) for _ in range(2000))
    # empirical FPR should land near the requested one
    assert 0.002 < flagged / 2000 < 0.03


def test_a_tighter_fpr_buys_the_adversary_more_room():
    """The trade the paper has to state plainly: a detector tuned to fire less
    often on benign traffic necessarily tolerates a longer hold."""
    j = BenignJitter()
    holds = []
    for fpr in (0.05, 0.01, 0.001):
        c = calibrate("max_age", fpr=fpr, jitter=j, n_flows=3000)
        holds.append(max_undetected_hold(c, jitter=j).max_undetected_hold_s)
    assert holds[0] < holds[1] < holds[2]


def test_total_hold_catches_what_a_per_message_cap_misses():
    """An adversary under any per-message cap can still hold many messages a
    little. A delta_max-only budget invites exactly that schedule, which is why
    the design also bounds H_max."""
    j = BenignJitter()
    cap = calibrate("max_age", fpr=0.01, jitter=j, n_flows=3000)
    tot = calibrate("total_hold_w8", fpr=0.01, jitter=j, n_flows=3000)
    one = max_undetected_hold(cap, jitter=j, n_held=1).max_undetected_hold_s
    many_under_cap = one * 0.8
    rng = random.Random(3)
    d = j.trace(40, rng)
    for i in range(0, 32, 4):
        d[i] += many_under_cap
    assert not cap.flags(d), "each hold is under the per-message cap"
    assert tot.flags(d), "but the integrated hold is not"


def test_burst_ratio_is_scale_free():
    """One threshold has to work across flows with different nominal cadences;
    a per-flow absolute threshold needs per-device tuning no deployment does."""
    fast = BenignJitter(median_s=0.2, p_stall=0.0)
    slow = BenignJitter(median_s=2.0, p_stall=0.0)
    a = calibrate("burst_ratio", fpr=0.01, jitter=fast, n_flows=3000).threshold
    b = calibrate("burst_ratio", fpr=0.01, jitter=slow, n_flows=3000).threshold
    assert 0.5 < a / b < 2.0, "thresholds should be comparable across cadences"


def test_the_binding_ceiling_is_the_minimum_across_detectors():
    """An adversary must stay under EVERY deployed detector, so the usable
    budget is the min, not the max. Quoting the most permissive detector would
    overstate the room available."""
    j = BenignJitter()
    holds = {}
    for name in DETECTORS:
        c = calibrate(name, fpr=0.01, jitter=j, n_flows=3000)
        holds[name] = max_undetected_hold(c, jitter=j).max_undetected_hold_s
    assert min(holds.values()) < max(holds.values())
    assert min(holds.values()) == pytest.approx(
        min(holds.values()))          # the reported ceiling is the min


def test_frontier_marks_an_over_budget_attack_infeasible():
    """The frontier answers one question: does the hold the attack NEEDS fit
    under the threshold a usable detector must sit at? A 600s hold does not."""
    pts = frontier(attack_needs_s=600.0, fprs=(0.01,))
    assert pts and not any(p.feasible for p in pts), \
        "a 600s hold should be detectable by every family at 1% FPR"


def test_frontier_marks_a_small_hold_feasible():
    pts = frontier(attack_needs_s=5.0, fprs=(0.01,))
    assert all(p.feasible for p in pts), \
        "a 5s hold should sit inside benign jitter for every family"


def test_benign_jitter_has_a_heavy_tail():
    """The stall component is why a usable threshold sits high and the
    adversary has room at all. Without it the model would understate the
    defender's problem and overstate our result."""
    j = BenignJitter()
    rng = random.Random(7)
    d = j.trace(20000, rng)
    med = sorted(d)[len(d) // 2]
    assert max(d) > 20 * med
