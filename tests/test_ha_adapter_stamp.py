"""The HA adapter's freshness stamp: REST view by default, live object on request."""
import json

from delaysteer.home.ha_adapter import HomeAssistantAdapter

REST_STAMP = "2026-09-25T01:00:00+00:00"
LIVE_STAMP = "2026-09-25T01:05:00+00:00"


class _Resp:
    def __init__(self, payload=None, text=""):
        self._payload, self.text = payload, text

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _Http:
    def __init__(self, live_text=None, fail_template=False, rest_state="off"):
        self.live_text, self.fail_template, self.rest_state = live_text, fail_template, rest_state
        self.templates = []

    def get(self, url, headers=None):
        return _Resp({"state": self.rest_state, "attributes": {}, "last_reported": REST_STAMP,
                      "last_updated": REST_STAMP})

    def post(self, url, headers=None, content=None):
        if url.endswith("/api/template"):
            self.templates.append(json.loads(content)["template"])
            if self.fail_template:
                raise RuntimeError("boom")
            return _Resp(text=self.live_text)
        return _Resp({})


def _adapter(http, source):
    a = HomeAssistantAdapter.__new__(HomeAssistantAdapter)
    a.base_url, a._http = "http://ha", http
    a._access_token, a._access_expiry = "t", float("inf")
    a.stamp_source = source
    return a


def _ts(s):
    from datetime import datetime
    return datetime.fromisoformat(s).timestamp()


def test_default_is_rest_and_never_calls_template():
    http = _Http(live_text=f"off|{LIVE_STAMP}")
    a = HomeAssistantAdapter.__new__(HomeAssistantAdapter)
    a.base_url, a._http, a._access_token, a._access_expiry = "http://ha", http, "t", float("inf")
    assert a.get_state("binary_sensor.front_door_contact").generation_time == _ts(REST_STAMP)
    assert http.templates == []


def test_template_uses_live_stamp_when_values_agree():
    http = _Http(live_text=f"off|{LIVE_STAMP}")
    obs = _adapter(http, "template").get_state("binary_sensor.front_door_contact")
    assert obs.generation_time == _ts(LIVE_STAMP) and obs.value == "off"


def test_template_falls_back_when_live_value_differs():
    http = _Http(live_text=f"on|{LIVE_STAMP}")
    obs = _adapter(http, "template").get_state("binary_sensor.front_door_contact")
    assert obs.generation_time == _ts(REST_STAMP)


def test_template_falls_back_on_failure():
    http = _Http(fail_template=True)
    assert _adapter(http, "template").get_state("lock.front_door").generation_time == _ts(REST_STAMP)


def test_template_refuses_non_plain_entity_ids():
    http = _Http(live_text=f"off|{LIVE_STAMP}")
    obs = _adapter(http, "template").get_state("binary_sensor.x }}{{ 7*7")
    assert obs.generation_time == _ts(REST_STAMP) and http.templates == []
