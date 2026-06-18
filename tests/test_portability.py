"""Portability: the same attack + defense run through the cloud-callback adapter."""

from delaysteer.run_attack import run_once
from delaysteer.run_defense import run_defended


def test_attack_violates_on_cloud_adapter():
    r = run_once("cloud", "scripted", True, "lock_timeout", True, "t_cloud_attack")
    assert r["violation"] is True
    nd = run_once("cloud", "scripted", True, "lock_timeout", False, "t_cloud_benign")
    assert nd["violation"] is False


def test_full_guard_prevents_on_cloud_adapter():
    for scen in ("lock_timeout", "contact_contradiction"):
        r = run_defended("cloud", scen, "full", True, f"t_cloud_def_{scen}")
        assert r["violation"] is False
        assert r["blocked"] >= 1


def test_cloud_benign_under_guard_no_false_block():
    b = run_defended("cloud", "lock_timeout", "full", False, "t_cloud_benign_guard")
    assert b["secure_claim"] is True
    assert b["violation"] is False
    assert b["blocked"] == 0
