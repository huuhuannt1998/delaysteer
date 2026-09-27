"""The repository carries more than one D0-D4 ladder. Make divergence FAIL a test.

`delaysteer/attack/profiles_ladder.py` is the canonical ladder: it owns the report's Sec. 9.1
semantics (D2 as a fraction of the budget, D3 as a position either side of a boundary, D1 drawn
from measured clean latencies) and it refuses to invent values it has not been given. But it is
imported by no harness. `run_misordering` and `run_late_effect` each compute their own delay
schedule, and `run_snapshot_coherence` its own again.

Consolidating them onto the canonical implementation is the obvious fix and is deliberately NOT
what this file does. Those harnesses have just produced committed results; rewriting the code
that computes their delays would make published rows unreproducible from the code that made
them, which is a worse failure than duplication.

So instead: pin the properties that must agree, and fail loudly when they stop agreeing. If a
future change makes a local ladder disagree with the canonical one on a spec-defined value, this
test says so with the two numbers side by side rather than letting the divergence reach a table.

The invariants below are the ones Sec. 9.1 actually fixes. Anything the report leaves to the
harness (poll periods, per-scenario boundaries, arm labels) is deliberately not pinned.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from delaysteer.attack.profiles_ladder import (
    D2SubBudgetDelay,
    D3BoundaryDelay,
    FAMILIES,
    build_ladder,
)
from delaysteer.config import DEFAULT_FRESHNESS_S

ROOT = Path(__file__).resolve().parent.parent
BUDGET = DEFAULT_FRESHNESS_S["contact_state"]   # 2.0s, the deployed contact budget
BASE_LATENCY = 0.05                              # Config.base_latency_s
BOUNDARY = 5.0                                   # Config.recovery_timeout_s


def _clean_latencies() -> list[float]:
    raw = json.loads((ROOT / "results" / "latency_calibration.json").read_text())
    return [float(x) for x in raw["read:binary_sensor.front_door_contact"]]


# --------------------------------------------------------------------------- #
# Sec. 9.1: D2 is a FRACTION OF THE BUDGET, measured at the delivered age
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fraction", [0.25, 0.50, 0.90])
def test_d2_delivers_the_specified_fraction_of_budget(fraction):
    """The report says "0.25, 0.50, and 0.90 of its freshness or timeout budget".

    That is a property of the DELIVERED age, not of the injected offset: the adapter adds the
    profile's value on top of its own base latency. An additive reading made the 0.90 rung
    deliver 0.925 of the budget.
    """
    p = D2SubBudgetDelay(budget_s=BUDGET, fraction=fraction, base_latency_s=BASE_LATENCY)
    delivered = BASE_LATENCY + p.extra_delay(0)
    assert delivered == pytest.approx(fraction * BUDGET, abs=1e-9), (
        f"D2 at fraction {fraction} delivered {delivered}s, which is "
        f"{delivered / BUDGET:.4f} of the {BUDGET}s budget, not {fraction}"
    )


# --------------------------------------------------------------------------- #
# Sec. 9.1: D3 is a POSITION either side of the boundary -- and must resolve a side
# --------------------------------------------------------------------------- #
def test_d3_lands_strictly_either_side_of_the_boundary():
    """`before` must deliver an age BELOW the boundary and `after` above it.

    With an additive basis and the shipped margin this failed: `before` delivered exactly the
    boundary, so which side it fell on was decided by float rounding against a strict
    `age > threshold` and the pair measured no discontinuity at all.
    """
    before = BASE_LATENCY + D3BoundaryDelay(
        boundary_s=BOUNDARY, side="before", base_latency_s=BASE_LATENCY).extra_delay(0)
    after = BASE_LATENCY + D3BoundaryDelay(
        boundary_s=BOUNDARY, side="after", base_latency_s=BASE_LATENCY).extra_delay(0)
    assert before < BOUNDARY, f"D3 'before' delivered {before}s, not below {BOUNDARY}s"
    assert after > BOUNDARY, f"D3 'after' delivered {after}s, not above {BOUNDARY}s"
    assert before != after


def test_d3_refuses_a_margin_that_cannot_resolve_a_side():
    """A margin inside the base latency cannot separate the arms under an additive basis."""
    with pytest.raises(ValueError, match="base_latency_s"):
        D3BoundaryDelay(boundary_s=BOUNDARY, side="before", margin_s=0.01,
                        base_latency_s=BASE_LATENCY, basis="additive")


# --------------------------------------------------------------------------- #
# Sec. 9.1: D1 is drawn from MEASURED clean observations, or not built at all
# --------------------------------------------------------------------------- #
def test_d1_refuses_to_invent_a_benign_band():
    """"Replay delay sampled from clean p50-p95 observations" is not a default.

    The canonical ladder raises rather than guessing. A local ladder that silently substitutes
    a synthetic band is not measuring a false-positive control, and this is the property that
    keeps the two honest about the same thing.
    """
    with pytest.raises(ValueError, match="clean_latencies"):
        build_ladder(budget_s=BUDGET, boundary_s=BOUNDARY, base_latency_s=BASE_LATENCY,
                     include=("D0", "D1"))


def test_d1_band_comes_from_the_measured_file_when_supplied():
    lat = _clean_latencies()
    levels = build_ladder(budget_s=BUDGET, boundary_s=BOUNDARY, base_latency_s=BASE_LATENCY,
                          clean_latencies=lat, include=("D0", "D1"))
    d1 = next(l for l in levels if l.family == "D1")
    assert d1.params["n_clean_samples"] == len(lat)
    lo, hi = d1.params["p50_s"], d1.params["p95_s"]
    assert lo <= hi
    # The measured read band on this testbed is milliseconds; if a future edit reintroduces a
    # synthetic 0.05-0.30s band this fires.
    assert hi < 0.05, (
        f"D1 p95 is {hi}s, which is above the adapter's own base latency -- that is the "
        f"signature of a synthetic band, not a measured one"
    )


# --------------------------------------------------------------------------- #
# The local ladders must agree with the canonical one where Sec. 9.1 fixes the value
# --------------------------------------------------------------------------- #
def test_the_two_ladders_differ_only_by_the_documented_base_latency_convention():
    """Pin the KNOWN, intentional difference between the two ladders so it stays known.

    The canonical ladder treats Sec. 9.1's fraction as a property of the DELIVERED age, so it
    subtracts the adapter's base latency. `run_misordering` treats it as the injected
    inter-arrival offset, because in S2 the quantity under test is delivery ORDER relative to
    the generation gap, not the observed age of a single value -- so adding the adapter's own
    latency to both channels would not change which arrives first.

    Both readings are defensible for their own scenario. What must not happen is either one
    drifting silently. This test states the exact relationship; if a future edit changes either
    convention the difference stops being `base_latency_s` and the assertion reports both
    numbers.
    """
    from delaysteer.config import Config
    from delaysteer.run_misordering import PATTERNS, delay_schedule

    cfg = Config()
    pat = PATTERNS["exit"]
    for level, frac in (("D2_25", 0.25), ("D2_50", 0.50), ("D2_90", 0.90)):
        injected, _, _, _, _ = delay_schedule(
            level, "invert", pat, cfg, seed=0, t_gen={}, control=None)
        sem = "contact_state" if pat.first.channel == "contact" else "occupancy"
        budget = cfg.freshness_s[sem]
        canonical = D2SubBudgetDelay(budget_s=budget, fraction=frac,
                                     base_latency_s=cfg.base_latency_s).extra_delay(0)

        # S2 injects the raw fraction of the budget...
        assert injected == pytest.approx(frac * budget, abs=1e-9), (
            f"run_misordering {level} injected {injected}s against a {budget}s budget "
            f"({injected / budget:.4f}); Sec. 9.1 fixes the fraction at {frac}"
        )
        # ...and the canonical ladder injects exactly base_latency_s less, so that the
        # DELIVERED age is the same fraction. Any other gap means one of them moved.
        assert injected - canonical == pytest.approx(cfg.base_latency_s, abs=1e-9), (
            f"{level}: run_misordering injects {injected}s, canonical injects {canonical}s. "
            f"The difference is {injected - canonical}s but should be exactly the base "
            f"latency {cfg.base_latency_s}s -- one of the two ladders has drifted."
        )


def test_families_cover_the_report_ladder():
    assert FAMILIES == ("D0", "D1", "D2", "D3", "D4")
