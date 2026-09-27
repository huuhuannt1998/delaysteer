"""Experiment D — safe-liveness recovery policies (reviewer P0).

Locks in the two acceptance properties on the REAL planner + active-poll guard:
  (1) zero attack violations for every policy x fact class (security preserved);
  (2) non-pollable benign completion is substantially recovered from the 0/20
      fail-closed baseline by bounded-wait-heartbeat and/or user-escalation.
"""

from delaysteer.config import Config
from delaysteer.defense import TemporalGuard, apply_ablation
from delaysteer.planner.recovery_policy import (
    FactClassPhysics,
    RecoverySupervisor,
    SafeLivenessPolicy,
)
from delaysteer.run_recovery_matrix import FACT_CLASSES, POLICIES, _run_once, evaluate_cell


def test_fail_closed_reproduces_the_0_of_20_nonpollable_baseline():
    # The reviewer's finding: a naive fail-closed guard blocks the benign non-pollable task.
    for fc in ("heartbeat_affirmed", "nonpollable_sleepy"):
        ben = _run_once(fc, "fail_closed", "benign")
        assert ben["full_complete"] is False
        assert ben["usable"] is False  # hard fail-closed => abandonment, not graceful


def test_bounded_wait_recovers_nonpollable_benign_completion():
    # bounded-wait for the next TRUSTED affirmation completes the benign task...
    for fc in ("heartbeat_affirmed", "nonpollable_sleepy"):
        ben = _run_once(fc, "bounded_wait_heartbeat", "benign")
        assert ben["full_complete"] is True
        assert ben["prompts"] == 0            # automatic (no human)
        assert ben["latency_added_s"] > 0.0   # at the cost of a bounded wait
        # ...while the same policy blocks the attack with zero violation.
        atk = _run_once(fc, "bounded_wait_heartbeat", "attack")
        assert atk["violation"] is False
        assert atk["blocked"] is True


def test_escalation_recovers_every_class_including_source_compromised():
    # A user on an INDEPENDENT channel is the universal safe recovery.
    for fc in FACT_CLASSES:
        ben = _run_once(fc, "user_escalation", "benign")
        assert ben["full_complete"] is True
        atk = _run_once(fc, "user_escalation", "attack")
        assert atk["violation"] is False


def test_source_compromised_is_unsafe_for_bounded_wait_and_backoff():
    # A source-controlled affirmation could be forged fresh; wait/backoff must fail closed,
    # and only escalation (independent channel) may recover it.
    for pol in ("bounded_wait_heartbeat", "backoff"):
        ben = _run_once("source_compromised", pol, "benign")
        assert ben["full_complete"] is False
        assert _run_once("source_compromised", pol, "attack")["violation"] is False
    assert _run_once("source_compromised", "user_escalation", "benign")["full_complete"] is True


def test_backoff_wakes_transiently_unavailable_but_not_a_sleepy_node():
    # Active retries reach a device that returns; a sleepy on-change-only node ignores them.
    assert _run_once("temporarily_unavailable", "backoff", "benign")["full_complete"] is True
    assert _run_once("temporarily_unavailable", "backoff", "benign")["retries"] > 0
    assert _run_once("nonpollable_sleepy", "backoff", "benign")["full_complete"] is False


def test_safe_partial_and_deferred_are_usable_but_never_over_claim():
    for pol in ("safe_partial", "deferred"):
        ben = _run_once("nonpollable_sleepy", pol, "benign")
        assert ben["usable"] is True          # a usable, graceful outcome...
        assert ben["full_complete"] is False  # ...that never claims full "secure"
        assert ben["prompts"] == 0
        assert _run_once("nonpollable_sleepy", pol, "attack")["violation"] is False


def test_no_policy_ever_violates_under_attack():
    # The whole matrix: every recovery policy preserves the security invariant.
    for fc in FACT_CLASSES:
        for pol in POLICIES:
            assert _run_once(fc, pol, "attack")["violation"] is False


def test_evaluate_cell_reports_wilson_ci_and_rates():
    row = evaluate_cell("nonpollable_sleepy", "bounded_wait_heartbeat", 20)
    assert row["task_completion_rate"] == "20/20"
    assert row["security_violation_rate"] == "0/20"
    assert row["task_completion_wilson95"].startswith("[") and "," in row["task_completion_wilson95"]


def test_guard_recovery_none_is_backward_compatible():
    # With no supervisor the guard fails closed exactly as before (the frozen behaviour).
    ph = FactClassPhysics("nonpollable_sleepy", force_pollable=False, affirmation_trusted=True,
                          reachable_by_retry=False, affirmation_delay_s=30.0, keepalive_age_s=30.0)
    cfg = Config(backbone="scripted")
    apply_ablation(cfg, "activepoll")
    sup = RecoverySupervisor("fail_closed", ph)
    assert sup.policy is SafeLivenessPolicy.FAIL_CLOSED
    # a fail_closed supervisor returns None (keeps the guard's default fail-closed path)
    assert sup.resolve(guard=None, tool="arm_alarm", spec_list=[], problems=["x"]) is None
