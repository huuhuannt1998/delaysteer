"""MA-5 SimuHome harness tests. Offline: a fake client supplies the true
(lockout) state, so the delay-only mechanism + guard ablation + residual-window
behaviour are asserted with no SimuHome server and no network."""
from __future__ import annotations

from delaysteer.simuhome.harness import residual_window, run_window


class FakeClient:
    """Frozen SimuHome stand-in: SafetyStatus is truly 1 (REMOTE_LOCKOUT)."""
    def __init__(self, t0: float = 100_000.0):
        self.t0 = t0

    def reset_frozen(self, rooms, to_tick, **kw):
        return None

    def attribute(self, device_id, key):
        return 1 if "SafetyStatus" in key else None  # true state = lockout

    def now_seconds(self):
        return self.t0


def test_window_ablation_pattern():
    c = FakeClient()
    # no-delay: agent reads true lockout, never overrides -> no violation, any ablation
    for ab in ("none", "freshness", "twophase", "full", "challenge"):
        assert run_window(c, ab, with_delay=False)["violation"] is False

    # attack: delay-only re-serves a stale "clear". Mechanism attribution:
    assert run_window(c, "none", with_delay=True)["violation"] is True
    assert run_window(c, "provenance", with_delay=True)["violation"] is True
    # freshness catches the stale-VALUE attack (aged reading), full+challenge too
    assert run_window(c, "freshness", with_delay=True)["violation"] is False
    assert run_window(c, "full", with_delay=True)["violation"] is False
    assert run_window(c, "challenge", with_delay=True)["violation"] is False
    # two-phase alone does NOT: the stale value still reads "clear" (== expected)
    assert run_window(c, "twophase", with_delay=True)["violation"] is True


def test_residual_window_l1_floor():
    c = FakeClient()
    fresh = residual_window(c, "freshness")["residual_window_s"]
    chal = residual_window(c, "challenge")["residual_window_s"]
    # static freshness residual ~ budget (2.0s); challenge-response ~ heartbeat (0.25s)
    assert fresh == 2.0
    assert chal == 0.25
    assert fresh / chal >= 7.0  # ~8x shrink, the L1 floor (domain-independent)


def test_generation_time_from_sim_clock_not_adversary():
    """SH-2: the delivered observation's generation_time traces to the sim clock,
    and the delay only ages/holds it -- the adversary never sets the clock."""
    from delaysteer.simuhome.harness import SimuHomeAdapter, WC_SPECS
    c = FakeClient(t0=555_000.0)
    obs = SimuHomeAdapter(c, WC_SPECS).get_state("safety")
    assert obs.generation_time == 555_000.0       # straight from the sim clock
    assert obs.value == "lockout"                  # truthful (no forgery)
