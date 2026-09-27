#!/usr/bin/env python3
"""Algorithm 3 -- DelaySteerSearch, its recall check, and the mandatory baseline."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from delaysteer.timed import scenario4 as s4
from delaysteer.timed.reachability import enumerate_reachable
from delaysteer.timed.search import (best_single_delay, delay_steer_search,
                                     lexicographic_objective, validate_recall)


def _run_plan(plan):
    choices = []
    depth = {"i": 0}

    def on_boundary(e):
        choices.append(list(e))

    def policy(o_t, sched):
        i = depth["i"]
        depth["i"] = i + 1
        el = sched.eligible()
        return [m for m in el if m in plan[i]] if i < len(plan) else list(el)

    r = s4.run(policy=policy, on_boundary=on_boundary)
    return {"choices": choices, "target": r["target_reached"], "k": r["k"],
            "k_flows": r["k_flows"], "total_hold": r["total_hold"],
            "held": r["delayed_ids"], "flows": r["delayed_flows"],
            "persistence": 0, "breadth": r["k_flows"],
            "detector_exposure": r["total_hold"]}


@pytest.fixture(scope="module")
def enum():
    return enumerate_reachable(run_plan=_run_plan)


def test_search_finds_the_target_when_one_exists(enum):
    assert enum.reachable
    assert delay_steer_search(run_plan=_run_plan)["found_target"]


def test_search_recall_is_measured_not_assumed(enum):
    """Challenge 7. A heuristic that reports 'no schedule found' is worthless
    unless we know what it misses, so recall is checked against the closed
    space rather than asserted."""
    v = validate_recall(run_plan=_run_plan, enumeration=enum)
    assert v["reachability_recall"] == 1.0


def test_search_finds_a_minimal_witness_not_an_inflated_one(enum):
    """An inflated witness would overstate the budget a real attacker needs,
    which matters directly against the Stage 5 detectability ceiling."""
    v = validate_recall(run_plan=_run_plan, enumeration=enum)
    assert v["witness_inflation"] == pytest.approx(1.0)
    assert v["search_k_flows"] == v["exact_min_k_flows"]


def test_search_is_cheaper_than_exhaustive(enum):
    v = validate_recall(run_plan=_run_plan, enumeration=enum)
    assert v["nodes_expanded"] < v["exact_nodes"]


def test_best_single_delay_baseline_is_exact_and_empty(enum):
    """The mandatory baseline. Every composition claim is relative to the best
    a single delay could have done, so this must be computed, not assumed."""
    b = best_single_delay(run_plan=_run_plan, enumeration_outcomes=enum.outcomes)
    assert b["exact"] is True
    assert b["n_single_flow_schedules"] > 0, "the baseline must be non-vacuous"
    assert b["n_reaching_target"] == 0
    assert b["min_total_hold_reaching_target"] is None


def test_baseline_is_stated_over_flows_not_messages(enum):
    """Repeatedly delaying one sensor is a sustained single-channel delay and
    belongs in the BASELINE, not the composed arm. Stated over messages, the
    k=3/k_flows=1 case would be miscounted as composition -- the exact error the
    design warns is already present elsewhere in this codebase."""
    singles = [o for o in enum.outcomes if o.k_flows <= 1]
    multi_message_single_flow = [o for o in singles if o.k >= 2]
    assert multi_message_single_flow, "the case must exist to be misclassified"
    assert all(not o.target for o in multi_message_single_flow)


def test_objective_never_trades_a_violation_for_a_cheaper_schedule():
    """Security terms lead; cost and exposure enter negated and last."""
    hit_expensive = lexicographic_objective(
        {"target": True, "total_hold": 9999.0, "detector_exposure": 9999.0})
    miss_cheap = lexicographic_objective(
        {"target": False, "total_hold": 0.0, "detector_exposure": 0.0})
    assert hit_expensive > miss_cheap


def test_objective_prefers_the_quieter_of_two_successes():
    """Among schedules that reach the target, prefer the one a detector is less
    likely to see -- which is what makes the search's output comparable against
    the Stage 5 ceiling."""
    loud = lexicographic_objective(
        {"target": True, "total_hold": 900.0, "detector_exposure": 900.0})
    quiet = lexicographic_objective(
        {"target": True, "total_hold": 30.0, "detector_exposure": 30.0})
    assert quiet > loud
