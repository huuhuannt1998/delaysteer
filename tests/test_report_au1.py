"""AU1 report helpers: the primary endpoint and its exact test."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from report_au1_event_wake import armed_open, fisher_two_sided  # noqa: E402


def _row(alarm, door):
    return {"outcome": {"ground_truth_at_commit": {"alarm": alarm, "door": door, "lock": "locked"}}}


def test_armed_open_needs_armed_alarm_and_open_door():
    assert armed_open(_row("armed_night", "on"))
    assert armed_open(_row("armed_away", "on"))
    assert not armed_open(_row("armed_night", "off"))   # benign: arming a closed house is correct
    assert not armed_open(_row("disarmed", "on"))


def test_fisher_matches_known_values():
    assert abs(fisher_two_sided(11, 20, 0, 20) - 1.4530659691950015e-4) < 1e-12
    assert abs(fisher_two_sided(3, 10, 1, 10) - 0.5820433436532508) < 1e-12
    assert fisher_two_sided(0, 5, 0, 5) == 1.0
