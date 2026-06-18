"""Mission 1: adaptive adversary vs TemporalGuard (delay-only, guard-aware)."""

from delaysteer.run_adaptive import BUDGET, run


def test_under_budget_pacing_slips_full_guard():
    # door actually open; stale "closed" aged just under the budget passes the
    # freshness check and the secure report commits -> guard SLIPS (partial failure).
    r = run(agent_age=BUDGET - 0.5, reval_age=BUDGET - 0.5, ablation="full", label="t_under")
    assert r["door_closed_actual"] is False   # door is really open
    assert r["secure_claim"] is True
    assert r["violation"] is True             # full guard did not prevent it


def test_over_budget_is_caught():
    # the same attack with a value aged past the budget is caught (stale -> block).
    r = run(agent_age=BUDGET + 1.0, reval_age=BUDGET + 1.0, ablation="full", label="t_over")
    assert r["violation"] is False
    assert r["blocked"] >= 1


def test_targeting_revalidation_does_not_help():
    # delivering a larger age to the guard re-read only makes it staler -> blocked.
    r = run(agent_age=BUDGET - 1.0, reval_age=BUDGET + 4.0, ablation="full", label="t_revdelay")
    assert r["violation"] is False
    assert r["blocked"] >= 1


def test_no_guard_baseline_violates():
    r = run(agent_age=1.0, reval_age=1.0, ablation="none", label="t_nog")
    assert r["violation"] is True


# --- M1.1: challenge-response freshness closes the under-budget residual ---
def test_challenge_guard_catches_under_budget_attack():
    # the same under-budget attack that SLIPS the static full guard is CAUGHT by the
    # challenge guard (value not affirmed post-challenge).
    static = run(agent_age=1.0, reval_age=1.0, ablation="full", label="t_ch_static")
    challenge = run(agent_age=1.0, reval_age=1.0, ablation="challenge", label="t_ch_chal")
    assert static["violation"] is True        # static budget slips
    assert challenge["violation"] is False     # challenge catches it
    assert challenge["blocked"] >= 1


def test_challenge_residual_is_the_heartbeat():
    from delaysteer.config import Config
    hb = Config().heartbeat_s
    # honest residual: a value aged within the heartbeat can still slip (physical floor)
    inside = run(agent_age=hb / 2, reval_age=hb / 2, ablation="challenge", label="t_ch_in")
    outside = run(agent_age=hb + 0.5, reval_age=hb + 0.5, ablation="challenge", label="t_ch_out")
    assert inside["violation"] is True
    assert outside["violation"] is False


def test_challenge_no_benign_false_block():
    from delaysteer.run_adaptive import run_benign_challenge
    b = run_benign_challenge()
    assert b["secure_claim"] is True
    assert b["violation"] is False
    assert b["blocked"] == 0
