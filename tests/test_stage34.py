#!/usr/bin/env python3
"""Stage 3 characterization + Stage 4 realism, without a GPU."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from delaysteer.agentkit import Run, ToolCall
from delaysteer.timed import scenario2 as s2
from delaysteer.timed.capability import TIER_0, TIER_1, TIER_2
from delaysteer.timed.characterize import (ObservabilityPoint,
                                           SelectivityMatrix, check_monotone,
                                           minimum_sufficient_level,
                                           steering_horizon)
from delaysteer.timed.sched import Observability
from delaysteer.timed.tier2 import (CADENCES, CURRENT, TIER2_TARGET,
                                    RunProvenance, classify_tier,
                                    realism_statement, tier_shortfall)


# ------------------------------------------------------- observability

def _pt(level, reachable):
    return ObservabilityPoint(level, reachable, 1 if reachable else 0,
                              2 if reachable else None,
                              10.0 if reachable else None, 5)


def test_observability_must_be_monotone():
    """The lattice is nested, so reachability cannot DECREASE with more sight.
    A non-monotone curve is a feature-filter bug, not a finding."""
    good = [_pt(l, l in (Observability.O2, Observability.O3, Observability.O4))
            for l in Observability.ORDER]
    ok, _ = check_monotone(good)
    assert ok

    bad = [_pt(Observability.O0, True), _pt(Observability.O1, False)]
    ok, msg = check_monotone(bad)
    assert not ok and "nested" in msg


def test_minimum_sufficient_level_is_what_the_threat_model_may_quote():
    """Reporting success at O_3 while claiming a message-aware position would
    overstate the adversary; the weakest sufficient level is the honest one."""
    curve = [_pt(Observability.O0, False), _pt(Observability.O1, True),
             _pt(Observability.O2, True)]
    assert minimum_sufficient_level(curve) == Observability.O1
    assert minimum_sufficient_level([_pt(l, False)
                                     for l in Observability.ORDER]) is None


# --------------------------------------------------------- selectivity

def test_selectivity_separates_wrong_target_from_no_target():
    """Hitting the wrong target is a different failure from hitting nothing;
    averaging them lets a scattergun schedule look selective."""
    m = SelectivityMatrix(targets=["disarm_zone", "unlock_door"])
    for _ in range(8):
        m.add("disarm_zone", "disarm_zone")
    m.add("disarm_zone", "unlock_door")     # collateral
    m.add("disarm_zone", None)              # miss
    assert m.precision("disarm_zone") == pytest.approx(0.8)
    assert m.collateral("disarm_zone") == pytest.approx(0.1)


def test_a_scattergun_schedule_does_not_look_selective():
    m = SelectivityMatrix(targets=["a", "b"])
    for _ in range(5):
        m.add("a", "a")
        m.add("a", "b")
    assert m.precision("a") == pytest.approx(0.5)
    assert m.collateral("a") == pytest.approx(0.5)


# ------------------------------------------------------ steering horizon

def test_steering_horizon_is_measured_from_the_earliest_necessary_release():
    """A long horizon is a COST to the attacker -- it must commit before the
    evidence exists -- so it belongs in the paper even though it weakens the
    attack."""
    h = steering_horizon(plan_times=[10.0, 1200.0], target_time=1800.0)
    assert h["horizon_s"] == pytest.approx(1790.0)
    assert h["n_releases"] == 2
    assert h["span_between_releases_s"] == pytest.approx(1190.0)


def test_no_releases_means_no_horizon():
    assert steering_horizon(plan_times=[], target_time=100.0)["horizon_s"] == 0.0


# ---------------------------------------------------------- Tier 2

def test_tier2_requires_all_three_layers_third_party():
    """'Production-like' is the phrase papers use to mean nothing, so the tier
    is decided from three facts rather than asserted."""
    assert classify_tier(TIER2_TARGET) == TIER_2
    for missing in ("planner_is_third_party", "platform_api_is_third_party",
                    "transport_is_third_party"):
        p = RunProvenance(**{**TIER2_TARGET.__dict__})
        setattr(p, missing, False)
        assert classify_tier(p) == TIER_1, f"{missing} alone must drop it to T1"


def test_current_runs_are_tier_1_and_the_shortfall_is_named():
    assert classify_tier(CURRENT) == TIER_1
    short = tier_shortfall(CURRENT)
    assert len(short) == 3
    assert all("ours" in s for s in short)


def test_synthetic_planner_is_tier_0_and_supports_no_claim():
    assert classify_tier(TIER2_TARGET, synthetic_planner=True) == TIER_0


def test_cadence_figures_cannot_be_printed_bare():
    """Any defense-side timing number carries its own provenance, because there
    is no radio and a bare constant in a table would imply measurement."""
    for c in CADENCES:
        assert not c.measured_on_hardware
        assert "MODELLED" in c.caption()


def test_realism_statement_bounds_the_defense_not_the_attack():
    s = realism_statement()
    assert "does NOT bound the attack" in s
    assert "arrival timestamp" in s


# ------------------------------------------- Scenario 2's scripted human

def test_the_human_model_is_favourable_by_construction():
    """An ideal user approves only what the shown context justifies. A real user
    is worse -- habituation and fatigue push toward approval -- so the claim is
    bounded to 'the safeguard fails even against an ideal user'."""
    h = s2.ScriptedHuman()
    assert h.decide(visitor_shown=True, snapshot_age_s=5.0) is True
    assert h.decide(visitor_shown=False, snapshot_age_s=5.0) is False


def test_an_ideal_user_declines_an_obviously_ancient_snapshot_if_shown_the_age():
    h = s2.ScriptedHuman()
    assert h.decide(visitor_shown=True, snapshot_age_s=600.0,
                    age_shown=True) is False


def test_but_approves_it_when_the_interface_hides_the_age():
    """Whether the card shows the snapshot's age is a UI property, so it is a
    parameter rather than a hidden assumption -- and it is decisive."""
    h = s2.ScriptedHuman()
    assert h.decide(visitor_shown=True, snapshot_age_s=600.0,
                    age_shown=False) is True


def test_every_human_decision_records_the_evidence_it_was_given():
    """So a caption can state exactly what the user was looking at."""
    h = s2.ScriptedHuman()
    h.decide(visitor_shown=True, snapshot_age_s=42.0)
    d = h.decisions[-1]
    assert d["visitor_shown"] and d["snapshot_age_s"] == 42.0
    assert "approved" in d and "age_shown" in d
