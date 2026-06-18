"""Phase-2: delay layer, profiles, and the fail-open divergence."""

from delaysteer.attack import (
    BurstDelay,
    DelayingAdapter,
    DelaySpec,
    FixedDelay,
    Jitter,
    LateArrivingContradiction,
    TimeoutCrossing,
)
from delaysteer.config import Config
from delaysteer.home.adapter import VirtualHomeAdapter
from delaysteer.home.clock import ManualClock
from delaysteer.home.virtual_home import ENTITIES, VirtualHome
from delaysteer.run_attack import run_once


def test_profiles():
    assert FixedDelay(3.0).extra_delay(0) == 3.0
    assert TimeoutCrossing(5.0, 1.0).extra_delay(7) == 6.0
    assert BurstDelay(2.0, start_n=1, count=2).extra_delay(0) == 0.0
    assert BurstDelay(2.0, start_n=1, count=2).extra_delay(1) == 2.0
    assert BurstDelay(2.0, start_n=1, count=2).extra_delay(3) == 0.0
    # jitter is deterministic and within bounds
    j = Jitter(1.0, 2.0, seed=7)
    d0, d1 = j.extra_delay(0), j.extra_delay(1)
    assert 1.0 <= d0 <= 3.0 and 1.0 <= d1 <= 3.0
    assert j.extra_delay(0) == d0  # reproducible
    # contradiction substitutes a stale-but-truthful value for the first reads
    c = LateArrivingContradiction("off", hold=2)
    assert c.override_value("on", 0) == "off"
    assert c.override_value("on", 2) is None


def test_delay_layer_inflates_arrival_preserves_value():
    home = VirtualHome(ManualClock())
    inner = VirtualHomeAdapter(home, base_latency_s=0.05)
    spec = DelaySpec("lock_state", FixedDelay(6.0), on_get_state=True)
    adapter = DelayingAdapter(inner, [spec])

    obs = adapter.get_state(ENTITIES["lock"])
    # payload truth preserved; only timing changed
    assert obs.value == "unlocked"
    assert obs.transit_delay >= 6.0
    assert len(adapter.injections) == 1

    # non-matching channel is untouched: no new injection recorded for it
    adapter.get_state(ENTITIES["contact"])
    assert len(adapter.injections) == 1
    assert adapter.injections[0]["channel"] == "lock_state"


def test_agentic_failopen_violates_under_delay():
    r = run_once("virtual", "scripted", True, "lock_timeout", True, "t_fo_delay")
    assert r["secure_claim"] is True
    assert r["actual_armed"] is False
    assert r["violation"] is True            # reported secure, alarm unarmed
    assert r["armed"] is False               # never armed (deferred)
    assert r["n_verify"] >= 2                # recovery ladder fired


def test_rule_based_fails_closed_under_same_delay():
    r = run_once("virtual", "rule_based", False, "lock_timeout", True, "t_rb_delay")
    assert r["secure_claim"] is False        # no false 'secure'
    assert r["violation"] is False           # fails closed


def test_contact_contradiction_fools_even_conservative_agent():
    # door truly open; stale "closed" delivered -> agent arms+reports secure (violation)
    delay = run_once("virtual", "scripted", False, "contact_contradiction", True, "t_cc_delay")
    assert delay["violation"] is True
    assert delay["actual_contact_closed"] is False  # door is really open
    assert delay["secure_claim"] is True
    assert any("open" in v for v in delay["violations"])

    # without delay the agent sees the true "open" and refuses to report secure
    nodelay = run_once("virtual", "scripted", False, "contact_contradiction", False, "t_cc_nodelay")
    assert nodelay["violation"] is False
    assert nodelay["secure_claim"] is False


def test_no_delay_runs_are_safe():
    for bk, fo in [("rule_based", False), ("scripted", False), ("scripted", True)]:
        r = run_once("virtual", bk, fo, "lock_timeout", False, f"t_nodelay_{bk}_{fo}")
        assert r["violation"] is False
        assert r["secure_claim"] is True
        assert r["actual_armed"] is True     # delay is the cause; without it, secure
