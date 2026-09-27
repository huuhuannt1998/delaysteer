"""Startup calibration of the active-poll tolerance."""
import pytest

from delaysteer.config import Config
from delaysteer.defense.calibration import apply_poll_calibration, calibrate_poll_rtt, p99


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class _Adapter:
    """Each forced read advances the fake clock by the next configured latency."""

    def __init__(self, clock, latencies):
        self.clock, self.latencies, self.i = clock, latencies, 0
        self.active_poll = False
        self.seen_active = []

    def get_state(self, entity_id):
        self.seen_active.append(self.active_poll)
        self.clock.t += self.latencies[self.i % len(self.latencies)]
        self.i += 1


def test_p99_picks_the_tail():
    assert p99([0.01] * 99 + [0.5]) == 0.01
    assert p99([0.01] * 98 + [0.4, 0.5]) == 0.4


def test_cloud_path_widens_the_tolerance_and_forces_polls():
    clk = _Clock()
    a = _Adapter(clk, [0.12, 0.15, 0.30])          # a cloud round trip, every sample above 50 ms
    rec = calibrate_poll_rtt(a, ["lock.front_door"], n=10, margin_s=0.05, clock=clk)
    assert rec["poll_rtt_s"] == pytest.approx(0.35)
    assert all(a.seen_active) and a.active_poll is False   # forced during, restored after


def test_cap_refuses_an_inflated_tolerance():
    clk = _Clock()
    a = _Adapter(clk, [3.0])                       # e.g. an adversary delaying the calibration
    with pytest.raises(ValueError, match="exceeds the cap"):
        calibrate_poll_rtt(a, ["binary_sensor.front_door_contact"], n=5, max_s=2.0, clock=clk)


def test_apply_writes_the_config():
    clk = _Clock()
    cfg = Config()
    rec = apply_poll_calibration(cfg, _Adapter(clk, [0.004]), ["alarm_control_panel.home_alarm"],
                                 n=20, margin_s=0.05, clock=clk)
    assert cfg.poll_rtt_s == rec["poll_rtt_s"] == pytest.approx(0.054)
