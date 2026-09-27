#!/usr/bin/env python3
"""Algorithm 7 -- GuardedCommit, including the position-conditional Lite gap."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from delaysteer.timed.guard import (ALLOW, ATTESTED, COMFORT, CONFIG_EDIT,
                                    ESCALATE, LITE, PROTECTIVE, REEVALUATE,
                                    REJECT, REQUIRE_LEASE, SAFE_EXECUTE,
                                    SECURITY_WEAKENING, Action, Entity,
                                    LeaseBook, ReadObservation, TemporalGuard,
                                    Trigger)

DOOR = "binary_sensor.front_door"


def _guard(mode, t=1000.0, entities=None):
    ents = entities or {DOOR: Entity(DOOR, "off")}
    return TemporalGuard(mode=mode, entities=ents, now=lambda: t)


def _arm() -> Action:
    return Action("arm_alarm", SECURITY_WEAKENING, target="alarm")


# ------------------------------------------------------------ happy path

def test_all_predicates_holding_admits():
    g = _guard(ATTESTED, t=1000.0)
    tr = Trigger(DOOR, "off", generation_time=995.0, receipt_time=995.0)
    d = g.guarded_commit(_arm(), tr, [ReadObservation(DOOR, 0)])
    assert d.verdict == ALLOW and d.admitted


# ---------------------------------------- the central position-conditional gap

def test_lite_is_blind_to_a_delay_that_precedes_the_hub_stamp():
    """The paper's core defense claim, as an executable check.

    The message was generated at t=100 and delayed 895s before reaching the hub,
    which stamped it at t=995. Under Attested the true age is 900s and the
    commit is refused. Under Lite the hub's own stamp is 5s old, so the
    freshness check is computed on the ATTACKER'S timeline and the same commit
    is admitted.

    This is not an implementation weakness to be fixed -- it is what a
    receiver-side stamp can mean. Any defense that stamps at receipt inherits
    it, which is why the residual has to be reported per attacker position
    rather than as one number.
    """
    tr = Trigger(DOOR, "off", generation_time=100.0, receipt_time=995.0)

    attested = _guard(ATTESTED, t=1000.0).guarded_commit(
        _arm(), tr, [ReadObservation(DOOR, 0)])
    assert attested.age == pytest.approx(900.0)
    assert not attested.fresh
    assert attested.verdict == REJECT

    lite = _guard(LITE, t=1000.0).guarded_commit(
        _arm(), tr, [ReadObservation(DOOR, 0)])
    assert lite.age == pytest.approx(5.0)
    assert lite.fresh                       # believes it, and is wrong
    assert lite.verdict == ALLOW


def test_lite_does_bound_a_delay_after_the_stamp():
    """Lite is not useless -- its coverage is position-conditional. An adversary
    at P-B (hub to agent) delays AFTER the truthful stamp is minted, so the
    receiver-side age is real and Lite catches it."""
    tr = Trigger(DOOR, "off", generation_time=100.0, receipt_time=100.0)
    lite = _guard(LITE, t=1000.0).guarded_commit(
        _arm(), tr, [ReadObservation(DOOR, 0)])
    assert lite.age == pytest.approx(900.0)
    assert not lite.fresh
    assert lite.verdict == ESCALATE          # Lite asks a human; Attested refuses


# ------------------------------------------------------------- fact classes

def test_security_weakening_rejects_under_attested_escalates_under_lite():
    tr = Trigger(DOOR, "off", generation_time=0.0, receipt_time=0.0)
    assert _guard(ATTESTED).guarded_commit(_arm(), tr).verdict == REJECT
    assert _guard(LITE).guarded_commit(_arm(), tr).verdict == ESCALATE


def test_a_protective_action_is_never_blocked_by_staleness():
    """The failure mode of a spurious siren is noise; of a suppressed one, the
    thing being defended against. A uniform fail-closed guard gets this wrong."""
    tr = Trigger(DOOR, "on", generation_time=0.0, receipt_time=0.0)
    d = _guard(ATTESTED).guarded_commit(Action("sound_siren", PROTECTIVE), tr)
    assert d.verdict == SAFE_EXECUTE
    assert not d.fresh                    # stale, and executed anyway
    assert d.admitted


def test_comfort_reevaluates_rather_than_escalating():
    """Escalating comfort actions to the resident is how a guard trains people
    to dismiss its prompts."""
    tr = Trigger(DOOR, "off", generation_time=0.0, receipt_time=0.0)
    d = _guard(ATTESTED).guarded_commit(Action("set_lights", COMFORT), tr)
    assert d.verdict == REEVALUATE


# --------------------------------------------------------------- predicates

def test_current_fails_when_the_read_set_moved_under_the_agent():
    ents = {DOOR: Entity(DOOR, "off")}
    g = _guard(ATTESTED, t=1000.0, entities=ents)
    tr = Trigger(DOOR, "off", generation_time=999.0, receipt_time=999.0)
    ents[DOOR].set("on")                       # world moved after evaluation
    d = g.guarded_commit(_arm(), tr, [ReadObservation(DOOR, 0)])
    assert d.fresh and not d.current
    assert d.verdict == REJECT


def test_cond_fails_when_a_precondition_no_longer_holds():
    ents = {DOOR: Entity(DOOR, "on")}
    g = _guard(ATTESTED, t=1000.0, entities=ents)
    tr = Trigger(DOOR, "on", generation_time=999.0, receipt_time=999.0)
    a = Action("arm_alarm", SECURITY_WEAKENING, target="alarm",
               preconditions={DOOR: "off"})
    d = g.guarded_commit(a, tr, [ReadObservation(DOOR, 0)])
    assert not d.cond and d.verdict == REJECT


def test_notsup_fails_when_a_later_intent_already_committed():
    ents = {DOOR: Entity(DOOR, "off"), "alarm": Entity("alarm", "disarmed",
                                                       generation=5)}
    g = _guard(ATTESTED, t=1000.0, entities=ents)
    tr = Trigger(DOOR, "off", generation_time=999.0, receipt_time=999.0)
    a = Action("arm_alarm", SECURITY_WEAKENING, target="alarm",
               intent_generation=3)
    d = g.guarded_commit(a, tr, [ReadObservation(DOOR, 0)])
    assert not d.not_superseded and d.verdict == REJECT


def test_delta_is_keyed_by_action_class_not_sensor_type():
    """Delta_class(a), not Delta(sem). How stale a reading may be depends on
    what is about to be done with it."""
    tr = Trigger(DOOR, "off", generation_time=900.0, receipt_time=900.0)
    g = _guard(ATTESTED, t=1000.0)          # age = 100s
    assert not g.guarded_commit(_arm(), tr).fresh                    # 30s bound
    assert g.guarded_commit(Action("set_lights", COMFORT), tr).fresh  # 600s bound


# ------------------------------------------------- Scenario 5's hard case

def test_freshness_passes_on_the_attacked_config_edit_and_the_lease_still_catches_it():
    """The case per-commit freshness provably cannot see.

    In Scenario 5 every delayed message is delivered before the agent runs, so
    at the moment of the edit the trigger is fresh, the read set is current and
    nothing is superseded. A freshness-based guard ADMITS it. What distinguishes
    the attacked edit is the pattern, so the control is a lease plus an
    anti-thrash counter over the target's history."""
    g = _guard(ATTESTED, t=1000.0)
    tr = Trigger("self_check", "flaky", generation_time=999.0, receipt_time=999.0)
    a = Action("edit_rule", CONFIG_EDIT, target="R_intrusion")

    d = g.guarded_config_edit(a, tr, weakens=True)
    assert d.fresh, "the edit really is fresh -- that is the whole difficulty"
    assert d.verdict == REQUIRE_LEASE, "and it is still not admitted"


def test_a_legitimate_edit_under_a_lease_is_admitted():
    leases = LeaseBook()
    leases.grant("R_intrusion", until=2000.0)
    g = TemporalGuard(mode=ATTESTED, entities={}, leases=leases,
                      now=lambda: 1000.0)
    tr = Trigger("self_check", "flaky", generation_time=999.0, receipt_time=999.0)
    a = Action("edit_rule", CONFIG_EDIT, target="R_intrusion")
    assert g.guarded_config_edit(a, tr, weakens=True).verdict == ALLOW


def test_anti_thrash_stops_repeated_weakening_even_with_a_lease():
    """Repeated weakening of the same predicate is the signature, so the lease
    alone must not be enough."""
    leases = LeaseBook(max_weakenings=1)
    leases.grant("R_intrusion", until=2000.0)
    g = TemporalGuard(mode=ATTESTED, entities={}, leases=leases,
                      now=lambda: 1000.0)
    tr = Trigger("self_check", "flaky", generation_time=999.0, receipt_time=999.0)
    a = Action("edit_rule", CONFIG_EDIT, target="R_intrusion")
    assert g.guarded_config_edit(a, tr, weakens=True).verdict == ALLOW
    assert g.guarded_config_edit(a, tr, weakens=True).verdict == REQUIRE_LEASE


def test_a_non_weakening_edit_is_not_obstructed():
    g = _guard(ATTESTED, t=1000.0)
    tr = Trigger("self_check", "ok", generation_time=999.0, receipt_time=999.0)
    a = Action("edit_rule", CONFIG_EDIT, target="R_intrusion")
    assert g.guarded_config_edit(a, tr, weakens=False).verdict == ALLOW
