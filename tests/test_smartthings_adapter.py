"""Token-free tests for the SmartThings adapter (MA-0). A FakeClient returns
recorded SmartThings JSON, so these run with no credentials and no network."""
from __future__ import annotations

from datetime import datetime, timezone

from delaysteer.attack import DelayingAdapter, DelaySpec, LateArrivingContradiction
from delaysteer.home.smartthings_adapter import ENTITY_LABELS, SmartThingsAdapter
from delaysteer.home.virtual_home import ENTITIES

LOCK, CONTACT, ALARM = ENTITIES["lock"], ENTITIES["contact"], ENTITIES["alarm"]


class FakeClient:
    def __init__(self, devices=None, switch="off", ts=None):
        self.posts = []
        self._devices = devices or []
        self._switch = switch
        self._ts = ts or datetime.now(timezone.utc).isoformat()

    def get(self, path):
        if path == "/v1/devices":
            return 200, {"items": self._devices}
        if path.endswith("/status"):
            return 200, {"components": {"main": {"switch":
                {"switch": {"value": self._switch, "timestamp": self._ts}}}}}
        return 404, {}

    def post(self, path, body):
        self.posts.append((path, body))
        return 200, {}


def _adapter(switch="off", entity_device=None):
    return SmartThingsAdapter(FakeClient(switch=switch),
                              entity_device or {LOCK: "d-lock", CONTACT: "d-con", ALARM: "d-alarm"})


def test_get_state_lock_on_is_locked():
    obs = _adapter(switch="on").get_state(LOCK)
    assert obs.value == "locked" and obs.semantic_type == "lock_state"
    assert obs.generation_time > 0 and obs.arrival_time >= obs.generation_time


def test_get_state_lock_off_is_unlocked():
    assert _adapter(switch="off").get_state(LOCK).value == "unlocked"


def test_get_state_contact_on_is_open():
    # switch on => contact "on" (open); off => "off" (closed)
    assert _adapter(switch="on").get_state(CONTACT).value == "on"
    assert _adapter(switch="off").get_state(CONTACT).value == "off"


def test_get_state_alarm_translation():
    assert _adapter(switch="on").get_state(ALARM).value == "armed_night"
    assert _adapter(switch="off").get_state(ALARM).value == "disarmed"


def test_call_service_lock_posts_switch_on():
    a = _adapter()
    obs = a.call_service("lock", "lock", {"entity_id": LOCK})
    assert obs.value == "ack"
    cmds = [b for p, b in a.client.posts if p.endswith("/d-lock/commands")]
    assert cmds and cmds[0]["commands"][0]["command"] == "on"


def test_call_service_disarm_posts_switch_off():
    a = _adapter()
    a.call_service("alarm_control_panel", "alarm_disarm", {"entity_id": ALARM})
    cmds = [b for p, b in a.client.posts if p.endswith("/d-alarm/commands")]
    assert cmds and cmds[0]["commands"][0]["command"] == "off"


def test_reset_emits_events_not_commands():
    full = {ENTITIES[k]: f"d-{k}" for k in ("lock", "alarm", "contact", "leak", "motion", "camera")}
    a = SmartThingsAdapter(FakeClient(), full)
    a.reset()
    events = [p for p, _ in a.client.posts if p.endswith("/events")]
    assert len(events) == 6  # lock, alarm, contact, leak, motion, camera
    assert all(b["deviceEvents"][0]["value"] == "off" for _, b in a.client.posts)


def test_from_env_discovers_by_label():
    devices = [{"label": lbl, "deviceId": f"id-{i}"} for i, lbl in enumerate(ENTITY_LABELS.values())]
    a = SmartThingsAdapter.from_env(client=FakeClient(devices=devices))
    assert a.entity_device[LOCK] == "id-0"
    assert set(a.entity_device) == set(ENTITY_LABELS)


def test_from_env_missing_devices_raises():
    import pytest
    with pytest.raises(RuntimeError):
        SmartThingsAdapter.from_env(client=FakeClient(devices=[{"label": "delaysteer-lock",
                                                                "deviceId": "x"}]))


def test_delay_layer_ages_a_real_get():
    """The existing delay-only primitive wraps the ST adapter unchanged and ages a
    GET response (delay sits on the real pull path)."""
    a = _adapter(switch="on")  # contact device physically open
    delayed = DelayingAdapter(a, [DelaySpec("contact_state",
                                            LateArrivingContradiction("off", hold=4, stale_age=30.0),
                                            on_get_state=True)])
    obs = delayed.get_state(CONTACT)
    assert obs.value == "off"  # stale-but-truthful "closed" substituted (value, not forged)
    assert (obs.arrival_time - obs.generation_time) > 2.0  # aged past the freshness budget
