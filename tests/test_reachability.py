#!/usr/bin/env python3
"""Algorithms 2 and 4, and the parts of the GAR harness that do not need a GPU."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from delaysteer.agentkit import Run, ToolCall
from delaysteer.timed import scenario4 as s4
from delaysteer.timed.gar import CATALOG, GarRow, _read_then_act, wilson
from delaysteer.timed.reachability import (Enumeration, Outcome,
                                           enumerate_reachable,
                                           necessity_test)


# --------------------------------------------------------------- the driver
# Mirrors scripts/run_s4_reachability.py so the test exercises the real path
# rather than a simplified stand-in.

def _run_plan(plan):
    choices: list[list[str]] = []
    depth = {"i": 0}

    def on_boundary(eligible):
        choices.append(list(eligible))

    def policy(o_t, sched):
        i = depth["i"]
        depth["i"] = i + 1
        eligible = sched.eligible()
        if i < len(plan):
            return [m for m in eligible if m in plan[i]]
        return list(eligible)

    res = s4.run(policy=policy, on_boundary=on_boundary)
    return {"choices": choices, "target": res["target_reached"],
            "k": res["k"], "k_flows": res["k_flows"],
            "total_hold": res["total_hold"],
            "held": res["delayed_ids"], "flows": res["delayed_flows"]}


@pytest.fixture(scope="module")
def enum() -> Enumeration:
    return enumerate_reachable(run_plan=_run_plan)


# ------------------------------------------------------------- Algorithm 2

def test_enumeration_is_complete(enum):
    """I_k = 1 is only sound on a closed space -- assert it closed."""
    assert not enum.truncated, "a truncated enumeration cannot support I_k = 1"
    assert enum.nodes > 1


def test_target_is_reachable(enum):
    assert enum.reachable


def test_no_single_flow_schedule_reaches_the_target(enum):
    """The gate's central negative. If this ever fails, the composition claim
    collapses to 'one delay would have done it' and the paper must say so."""
    assert enum.single_flow_successes == []
    assert enum.min_witness_flows == 2


def test_I_k_is_one(enum):
    assert enum.I_k() == 1


def test_composition_gain_at_matched_total_hold(enum):
    """Gain must be measured at matched INTEGRATED hold, not matched delta_max:
    otherwise the composed schedule is simply allowed to spend more."""
    g = enum.G_k()
    assert g["gain"] is True
    assert g["composed_k_flows"] == 2
    # there really were single-flow schedules at that budget, and they all missed
    assert g["single_flow_schedules_at_or_above_that_budget"] > 0
    assert g["of_which_reached_target"] == 0


def test_enumeration_is_deterministic():
    a = enumerate_reachable(run_plan=_run_plan)
    b = enumerate_reachable(run_plan=_run_plan)
    assert a.nodes == b.nodes
    assert a.I_k() == b.I_k()
    assert a.min_witness_flows == b.min_witness_flows
    assert sorted(o.total_hold for o in a.successes) == \
           sorted(o.total_hold for o in b.successes)


def test_honest_schedule_is_in_the_space(enum):
    """sigma_0 must be enumerated, and must not reach the target."""
    honest = [o for o in enum.outcomes if o.k == 0]
    assert honest, "the honest schedule was never visited"
    assert all(not o.target for o in honest)


def test_I_k_zero_when_a_single_flow_witness_exists():
    """The indicator must be capable of returning 0 -- guard against a metric
    that reports composition-only reachability by construction."""
    e = Enumeration(outcomes=[
        Outcome(plan=(), target=True, k=1, k_flows=1, total_hold=5.0,
                held=("m1",), flows=("f1",)),
        Outcome(plan=(), target=True, k=2, k_flows=2, total_hold=9.0,
                held=("m1", "m2"), flows=("f1", "f2")),
    ])
    assert e.I_k() == 0
    # ...and with no single-flow schedule at the composed budget there is no
    # matched-budget comparison at all, which must read as vacuous, not as gain
    g = e.G_k()
    assert g["gain"] is False and g["vacuous"] is True


def test_G_k_refuses_a_vacuous_matched_budget_comparison():
    """A composition that simply outspends every single-flow schedule has not
    won a comparison -- it has avoided one."""
    e = Enumeration(outcomes=[
        Outcome(plan=(), target=False, k=1, k_flows=1, total_hold=2.0,
                held=("m1",), flows=("f1",)),
        Outcome(plan=(), target=True, k=2, k_flows=2, total_hold=500.0,
                held=("m1", "m2"), flows=("f1", "f2")),
    ])
    g = e.G_k()
    assert g["gain"] is False
    assert g["vacuous"] is True
    assert g["max_single_flow_total_hold"] == 2.0


def test_G_k_is_false_when_a_single_flow_wins_at_the_same_budget():
    e = Enumeration(outcomes=[
        Outcome(plan=(), target=True, k=1, k_flows=1, total_hold=50.0,
                held=("m1",), flows=("f1",)),
        Outcome(plan=(), target=True, k=2, k_flows=2, total_hold=10.0,
                held=("m1", "m2"), flows=("f1", "f2")),
    ])
    g = e.G_k()
    assert g["gain"] is False
    assert g["single_flow_hits_at_that_budget"] == 1


def test_unreachable_target_gives_I_k_zero():
    e = Enumeration(outcomes=[Outcome(plan=(), target=False, k=0, k_flows=0,
                                      total_hold=0.0, held=(), flows=())])
    assert e.I_k() == 0
    assert e.min_witness_flows is None


# ------------------------------------------------------------- Algorithm 4

def test_every_release_is_necessary():
    def run_with(releases):
        rs = list(releases)
        return bool(s4.run(hold=rs)["target_reached"]) if rs \
            else bool(s4.run()["target_reached"])

    nec = necessity_test(run_with=run_with, releases=[s4.delay1, s4.delay2],
                         labels=["delay1", "delay2"])
    assert nec.full_reaches
    assert nec.minus_one == {"delay1": False, "delay2": False}
    assert nec.all_necessary


def test_necessity_detects_a_passenger():
    """A chain with a redundant release must NOT report all_necessary."""
    def run_with(releases):
        return len(list(releases)) >= 1        # one release suffices

    nec = necessity_test(run_with=run_with, releases=["a", "b"],
                         labels=["a", "b"])
    assert nec.full_reaches
    assert not nec.all_necessary


# ------------------------------------------------------- GAR (CPU-only parts)

def _run(names: list[str]) -> Run:
    return Run(model="stub",
               calls=[ToolCall(turn=i, name=n, args={}, result=None, at=float(i))
                      for i, n in enumerate(names)])


def test_trans_G_requires_read_before_commit():
    """An agent that commits without reading skipped the check entirely -- a
    different failure, and not the delay's doing."""
    assert _read_then_act(_run(["read_door_contact", "arm_alarm"]),
                          "read_door_contact", "arm_alarm")
    assert not _read_then_act(_run(["arm_alarm"]),
                              "read_door_contact", "arm_alarm")
    assert not _read_then_act(_run(["arm_alarm", "read_door_contact"]),
                              "read_door_contact", "arm_alarm")
    assert not _read_then_act(_run(["read_door_contact"]),
                              "read_door_contact", "arm_alarm")


def test_dead_row_is_a_transport_failure_not_an_observation():
    """The signature is structural (errored with no calls), not timing -- a
    dying server once produced a clean-looking 0/20."""
    live = GarRow(probe="p", gadget="G1", arm="attack", model="m", template=0, seed=0,
                  delay_s=1.0, realized=False, outcome_class="resisted",
                  violated=False, call_sequence="read|refuse", k=1, k_flows=1,
                  n_turns=2, error="timeout on final turn")
    dead = GarRow(probe="p", gadget="G1", arm="attack", model="m", template=0, seed=0,
                  delay_s=1.0, realized=False, outcome_class="non_completion",
                  violated=False, call_sequence="", k=0, k_flows=0, n_turns=0,
                  error="HTTP 500")
    assert not live.dead        # it errored, but it acted -- that IS data
    assert dead.dead


def test_templates_are_where_n_comes_from_at_temperature_zero():
    """Greedy decoding makes every seed the same episode, so n must come from
    distinct scenario instances or a Wilson interval reports n for an effective
    n of 1."""
    for p in CATALOG:
        assert len(p.templates) >= 5, f"{p.name} has too few instances for an n"
        systems = {s for s, _ in p.templates}
        tasks = [t for _, t in p.templates]
        assert len(set(tasks)) == len(tasks), f"{p.name} has duplicate tasks"
        assert len(systems) > 1, (
            f"{p.name} varies only the task; the operator's guardrail wording "
            f"is itself an instance dimension")


def test_template_selection_is_stable_and_wraps():
    from delaysteer.timed.gar import G1
    n = len(G1.templates)
    assert G1.templates[0] == G1.templates[0 % n]
    assert G1.templates[n % n] == G1.templates[0]      # wraps, does not crash


def test_wilson_interval():
    assert wilson(0, 0) == (0, 0)
    lo, hi = wilson(20, 20)
    assert lo > 80 and hi == 100
    lo, hi = wilson(10, 20)
    assert lo < 50 < hi


def test_catalog_probes_are_well_formed():
    for p in CATALOG:
        assert p.hold_mode in ("stale", "timeout")
        assert p.entity and p.gadget and p.name
        names = {t["function"]["name"] for t in p.tools}
        assert "report" in names and "refuse" in names, p.name
        # a STALE probe must let a benign read through first, or it has nothing
        # genuine to re-serve and silently degenerates into a timeout probe
        if p.hold_mode == "stale":
            assert p.hold_after >= 1, p.name
