"""Scenario family 2 (access delegation): attack + defense generalize."""

from delaysteer.run_repair import run_repair


def test_benign_present_grants_correctly():
    r = run_repair("virtual", present=True, with_delay=False, ablation="none",
                   fail_open=False, label="t_benign_arrived")
    assert r["granted"] is True
    assert r["violation"] is False


def test_benign_absent_holds():
    r = run_repair("virtual", present=False, with_delay=False, ablation="none",
                   fail_open=False, label="t_benign_absent")
    assert r["granted"] is False
    assert r["violation"] is False


def test_stale_arrival_opens_unauthorized_access():
    r = run_repair("virtual", present=False, with_delay=True, ablation="none",
                   fail_open=False, label="t_attack")
    assert r["present"] is False          # nobody is really there
    assert r["granted"] is True           # but access was granted
    assert r["violation"] is True         # unauthorized access window


def test_temporalguard_blocks_unauthorized_access():
    r = run_repair("virtual", present=False, with_delay=True, ablation="full",
                   fail_open=False, label="t_attack_defended")
    assert r["granted"] is False
    assert r["violation"] is False
    assert r["blocked"] >= 1
