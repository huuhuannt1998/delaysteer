"""Strict deliver-once generalized across scenario families (deterministic reference).

Locks in the reviewer-facing generalization of Experiment A: a single held
pre-transition observation (``delivery_count == 1``, audited) steers three families
(secure_house / access / confirmation), both guards block it, and automation is
correctly CLASSIFIED multi-delay (one delayed delivery is insufficient).
"""

from __future__ import annotations

import pytest

from delaysteer.run_strict_delay_families import (
    FAMILIES,
    audit_delivery_once,
    run_one,
    wilson95,
)

DELIVER_ONCE = ["secure_house", "access", "confirmation"]


@pytest.mark.parametrize("scenario", DELIVER_ONCE)
def test_benign_completes_no_delivery(scenario):
    r = run_one(scenario, "reference", "benign", "deliver_once", 0, write_traces=False)
    assert r["violation"] is False
    assert r["completed"] is True
    assert r["delivery_count"] == 0  # channel disarmed -> nothing held


@pytest.mark.parametrize("scenario", DELIVER_ONCE)
def test_attack_violates_with_exactly_one_delivery(scenario):
    r = run_one(scenario, "reference", "attack", "deliver_once", 0, write_traces=False)
    assert r["violation"] is True
    assert r["delivery_count"] == 1          # AUDIT: released the held value exactly once
    assert r["n_stale_receipts"] == 1
    assert r["high_impact_commits"] >= 1     # the unsafe commit went through


@pytest.mark.parametrize("scenario", DELIVER_ONCE)
@pytest.mark.parametrize("condition", ["attack_static_guard", "attack_activepoll_guard"])
def test_guard_blocks_and_still_delivers_once(scenario, condition):
    r = run_one(scenario, "reference", condition, "deliver_once", 0, write_traces=False)
    assert r["violation"] is False
    assert r["blocked"] >= 1
    assert r["delivery_count"] == 1          # guard's re-read is a SEPARATE read -> still 1
    assert r["subsequent_truthful_reads"] >= 1  # the re-read returned ground truth (no replay)
    assert r["high_impact_commits"] == 0


def test_automation_is_multi_delay_not_deliver_once():
    # Genuine multi-delay attack (all K probes time out) DOES violate ...
    atk = run_one("automation", "reference", "attack", "multi_delay", 0, write_traces=False)
    assert atk["violation"] is True
    assert atk["n_stale_receipts"] == 3
    # ... but a single delayed probe (deliver-once magnitude) does NOT.
    one = run_one("automation", "reference", "attack", "single_delay", 0, write_traces=False)
    assert one["violation"] is False
    assert one["n_stale_receipts"] == 1
    # ... and both guards block the genuine attack.
    for cond in ("attack_static_guard", "attack_activepoll_guard"):
        g = run_one("automation", "reference", cond, "multi_delay", 0, write_traces=False)
        assert g["violation"] is False and g["blocked"] >= 1
    assert FAMILIES["automation"].family_class == "multi_delay"


def test_delivery_once_audit_passes_over_armed_runs():
    runs = []
    for scenario in DELIVER_ONCE:
        for cond in ("attack", "attack_static_guard", "attack_activepoll_guard"):
            runs.append(run_one(scenario, "reference", cond, "deliver_once", 0, write_traces=False))
    max_dc, dc1, n_armed = audit_delivery_once(runs)
    assert max_dc <= 1 and dc1 == n_armed == 9


def test_wilson95_bounds():
    lo, hi = wilson95(1, 1)
    assert 0.0 <= lo <= hi <= 1.0
    assert wilson95(0, 0) == (0.0, 0.0)
