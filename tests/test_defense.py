"""Phase-4: TemporalGuard prevents the violations; benign is unaffected."""

from delaysteer.run_defense import run_benign_jitter, run_defended


def test_full_guard_prevents_both_attacks():
    for scenario in ("lock_timeout", "contact_contradiction"):
        r = run_defended("virtual", scenario, "full", True, f"t_full_{scenario}")
        assert r["violation"] is False, f"full guard failed to prevent {scenario}"
        assert r["blocked"] >= 1


def test_no_defense_leaves_violation():
    for scenario in ("lock_timeout", "contact_contradiction"):
        r = run_defended("virtual", scenario, "none", True, f"t_none_{scenario}")
        assert r["violation"] is True


def test_ablation_freshness_is_necessary_for_contradiction():
    # two-phase value revalidation alone is fooled by the stale-but-truthful value;
    # only the freshness contract catches the contradiction.
    twophase = run_defended("virtual", "contact_contradiction", "twophase", True, "t_2pc_cc")
    freshness = run_defended("virtual", "contact_contradiction", "freshness", True, "t_fr_cc")
    assert twophase["violation"] is True      # value check passes on stale "closed"
    assert freshness["violation"] is False    # freshness catches the aged reading


def test_benign_run_no_false_block_under_full_guard():
    b = run_defended("virtual", "lock_timeout", "full", False, "t_benign_full")
    assert b["secure_claim"] is True
    assert b["violation"] is False
    assert b["blocked"] == 0
    assert b["escalations"] == 0


def test_within_budget_jitter_no_false_positive():
    # freshness budget is 2.0s; jitter under it must not trip the guard
    within = run_benign_jitter("virtual", 0.5, 0.8, "t_jit_ok")     # max 1.3s
    assert within["false_blocks"] == 0
    assert within["secure_claim"] is True
    # jitter past the budget legitimately blocks (data is stale by contract)
    past = run_benign_jitter("virtual", 1.5, 2.0, "t_jit_fp")       # max 3.5s
    assert past["false_blocks"] >= 1
