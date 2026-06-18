"""Scenario families 3 (confirmation TOCTOU) and 4 (automation weakening)."""

from delaysteer.run_automation import run_auto
from delaysteer.run_confirm import run_confirm


# --- family 4: persistent automation weakening ---
def test_auto_benign_keeps_predicate():
    r = run_auto("virtual", with_delay=False, ablation="none", label="t_auto_benign")
    assert r["predicate_enabled"] is True
    assert r["violation"] is False


def test_auto_attack_removes_predicate():
    r = run_auto("virtual", with_delay=True, ablation="none", label="t_auto_attack")
    assert r["predicate_enabled"] is False    # persistent weakening
    assert r["violation"] is True
    assert r["probes"] == ["timeout", "timeout", "timeout"]


def test_auto_guard_blocks_weakening():
    r = run_auto("virtual", with_delay=True, ablation="full", label="t_auto_def")
    assert r["predicate_enabled"] is True
    assert r["violation"] is False
    assert r["blocked"] >= 1


# --- family 3: confirmation TOCTOU ---
def test_confirm_stale_snapshot_violates():
    r = run_confirm("virtual", present=False, with_delay=True, ablation="none",
                    hitl=False, label="t_cf_attack")
    assert r["granted"] is True
    assert r["present"] is False
    assert r["violation"] is True


def test_confirm_guard_fail_closed():
    r = run_confirm("virtual", present=False, with_delay=True, ablation="full",
                    hitl=False, label="t_cf_fc")
    assert r["violation"] is False
    assert r["blocked"] >= 1


def test_confirm_hitl_escalates_and_prevents():
    r = run_confirm("virtual", present=False, with_delay=True, ablation="full",
                    hitl=True, label="t_cf_hitl")
    assert r["violation"] is False
    assert r["escalations"] >= 1   # user re-prompted with fresh context
    assert r["granted"] is False
