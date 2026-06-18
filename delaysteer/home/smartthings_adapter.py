"""Real SmartThings cloud adapter (virtual devices on the REAL SmartThings cloud).

MA-0 / W1: a second REAL platform's delivery path. Implements the same
`HomeAdapter` interface as the virtual home and the live-HA adapter, so the
planner, router, guard, and the delay-only `DelayingAdapter` are all unchanged
(Figure-1 separation). `get_state` is a real GET to the SmartThings cloud and
`call_service` a real POST command, so `generation_time` (the cloud's reported
attribute timestamp) vs `arrival_time` (receipt) is a measured real round-trip --
exactly what the delay layer widens.

HONEST SCOPE: the devices are VIRTUAL devices running on the real SmartThings
cloud (developer account), NOT physical hardware. Each testbed fact (lock,
contact, alarm, arrival, leak, ...) is represented by a virtual SWITCH whose
on/off state encodes the binary fact; the value translation is below. The claim
is "virtual devices on a real cloud's callback/command path", with physical-device
validation left as future work.

CREDENTIALS: the token is read at runtime from $SMARTTHINGS_TOKEN (or a gitignored
.env); never hardcoded, committed, or placed in the graph. Tests inject a fake
client + device map, so they run with no token and no network.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adapter import HomeAdapter, Observation, semantic_type_of
from .virtual_home import ENTITIES

API = "https://api.smartthings.com"

# testbed entity_id -> the label of its virtual switch on the real cloud
ENTITY_LABELS: dict[str, str] = {
    ENTITIES["lock"]:   "delaysteer-lock",
    ENTITIES["contact"]: "delaysteer-contact",
    ENTITIES["alarm"]:  "delaysteer-alarm",
    ENTITIES["camera"]: "delaysteer-arrival",
    ENTITIES["leak"]:   "delaysteer-leak",
    ENTITIES["motion"]: "delaysteer-motion",
    ENTITIES["light"]:  "delaysteer-light",
}
# switch on/off -> the testbed value string for each entity (truthful translation)
ON_OFF_VALUE: dict[str, tuple[str, str]] = {
    ENTITIES["lock"]:   ("locked", "unlocked"),
    ENTITIES["contact"]: ("on", "off"),        # on = open, off = closed
    ENTITIES["alarm"]:  ("armed_night", "disarmed"),
    ENTITIES["camera"]: ("on", "off"),
    ENTITIES["leak"]:   ("on", "off"),
    ENTITIES["motion"]: ("on", "off"),
    ENTITIES["light"]:  ("on", "off"),
}
# (domain, service) -> desired switch state ("on"/"off") for the named device
SERVICE_SWITCH: dict[tuple[str, str], str] = {
    ("lock", "lock"): "on", ("lock", "unlock"): "off",
    ("alarm_control_panel", "alarm_arm_night"): "on",
    ("alarm_control_panel", "alarm_arm_away"): "on",
    ("alarm_control_panel", "alarm_disarm"): "off",
    ("light", "turn_on"): "on", ("light", "turn_off"): "off",
    ("switch", "on"): "on", ("switch", "off"): "off",
}


def _iso_to_epoch(ts: str | None) -> float:
    if not ts:
        return time.time()
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time()


class _EpochClock:
    def now(self) -> float:
        return time.time()


class _LiveClient:
    """Real httpx client against the SmartThings cloud. New 24h PATs get lowered
    rate limits, so we throttle (a min gap between calls) and back off on 429."""
    MIN_GAP = 0.4   # seconds between calls (stay under the limit)

    def __init__(self, token: str) -> None:
        import httpx  # lazy: only a real run needs it
        self._h = httpx.Client(base_url=API, timeout=30,
                               headers={"Authorization": f"Bearer {token}"})
        self._last = 0.0

    def _throttle(self) -> None:
        gap = time.time() - self._last
        if gap < self.MIN_GAP:
            time.sleep(self.MIN_GAP - gap)
        self._last = time.time()

    def _retry(self, fn):
        delay = 2.0
        for _ in range(7):
            self._throttle()
            r = fn()
            if r.status_code != 429:
                return r
            time.sleep(delay)
            delay = min(delay * 2, 30.0)  # exponential backoff, cap 30s
        return r

    def get(self, path):
        r = self._retry(lambda: self._h.get(path))
        return r.status_code, (r.json() if r.content else {})

    def post(self, path, body):
        r = self._retry(lambda: self._h.post(path, json=body))
        return r.status_code, (r.json() if r.content else {})


def _token_from_env() -> str | None:
    tok = os.environ.get("SMARTTHINGS_TOKEN")
    if tok:
        return tok
    env = Path(__file__).resolve().parents[2] / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            line = line.strip()
            if line.startswith("SMARTTHINGS_TOKEN=") and "=" in line:
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


class SmartThingsAdapter(HomeAdapter):
    _LIVE_SINGLETON: "SmartThingsAdapter | None" = None  # one live adapter per run

    def __init__(self, client, entity_device: dict[str, str]) -> None:
        self.client = client                 # object with .get/.post (live or mock)
        self.entity_device = entity_device   # testbed entity_id -> ST deviceId
        self.clock = _EpochClock()

    # ---- HomeAdapter interface ----
    def get_state(self, entity_id: str) -> Observation:
        did = self.entity_device.get(entity_id)
        if did is None:  # an entity we don't model -> benign generic 'off', fresh
            return Observation(semantic_type=semantic_type_of(entity_id), value="off",
                               source="smartthings", entity_id=entity_id,
                               generation_time=time.time(), arrival_time=time.time())
        code, st = self.client.get(f"/v1/devices/{did}/status")
        if code != 200:
            raise RuntimeError(f"SmartThings GET status {did} -> HTTP {code}")
        raw, ts = self._read_switch(st)
        on_val, off_val = ON_OFF_VALUE.get(entity_id, ("on", "off"))
        return Observation(
            semantic_type=semantic_type_of(entity_id),
            value=(on_val if raw == "on" else off_val),
            attributes={"st_switch": raw, "deviceId": did},
            source="smartthings", entity_id=entity_id,
            generation_time=_iso_to_epoch(ts), arrival_time=time.time(),
        )

    def call_service(self, domain: str, service: str,
                     data: dict[str, Any] | None = None) -> Observation:
        data = data or {}
        gen = time.time()
        sw = SERVICE_SWITCH.get((domain, service))
        ent = data.get("entity_id")
        if sw is None or ent is None or ent not in self.entity_device:
            # nothing actuatable mapped (e.g. a no-op service) -> truthful ack, no call
            return Observation(semantic_type="actuation_ack", value="ack",
                               attributes={"domain": domain, "service": service, "noop": True},
                               source="smartthings", entity_id=ent,
                               generation_time=gen, arrival_time=time.time())
        did = self.entity_device[ent]
        code, _ = self.client.post(f"/v1/devices/{did}/commands",
            {"commands": [{"component": "main", "capability": "switch", "command": sw}]})
        if code not in (200, 202):
            raise RuntimeError(f"SmartThings command {did} {sw} -> HTTP {code}")
        return Observation(semantic_type="actuation_ack", value="ack",
                           attributes={"domain": domain, "service": service, "switch": sw},
                           source="smartthings", entity_id=ent,
                           generation_time=gen, arrival_time=time.time())

    def entities(self) -> dict[str, str]:
        return dict(ENTITIES)

    # ---- ground-truth pokes (the "physical world"; via virtual-device events) ----
    def set_fact(self, entity_id: str, on: bool) -> None:
        did = self.entity_device[entity_id]
        self.client.post(f"/v1/virtualdevices/{did}/events",
            {"deviceEvents": [{"component": "main", "capability": "switch",
                               "attribute": "switch", "value": ("on" if on else "off")}]})

    def open_door(self) -> None:
        self.set_fact(ENTITIES["contact"], True)

    def close_door(self) -> None:
        self.set_fact(ENTITIES["contact"], False)

    def reset(self) -> None:
        """Benign pre-scenario state: unlocked, disarmed, door closed, no leak/motion.
        Skips any entity not present in the device map (defensive)."""
        for ent in (ENTITIES["lock"], ENTITIES["alarm"], ENTITIES["contact"],
                    ENTITIES["leak"], ENTITIES["motion"], ENTITIES["camera"]):
            if ent in self.entity_device:
                self.set_fact(ent, False)

    # ---- helpers ----
    @staticmethod
    def _read_switch(status: dict) -> tuple[str, str | None]:
        """Pull (switch value, timestamp) from a device-status payload."""
        comp = status.get("components", {}).get("main", {})
        attr = comp.get("switch", {}).get("switch", {})
        return str(attr.get("value", "off")), attr.get("timestamp")

    # ---- construction ----
    @classmethod
    def from_env(cls, client=None) -> "SmartThingsAdapter":
        # The runners call from_env() once per cell; reuse a single live adapter
        # (one discovery, one HTTP client) across the whole run to respect the
        # lowered rate limits on 24h PATs. An injected client (tests) never caches.
        real = client is None
        if real and cls._LIVE_SINGLETON is not None:
            return cls._LIVE_SINGLETON
        if client is None:
            token = _token_from_env()
            if not token:
                raise RuntimeError("SMARTTHINGS_TOKEN not set (env or .env). Mint a fresh "
                                   "24h PAT and export it / put it in .env.")
            client = _LiveClient(token)
        # discover our virtual devices by label
        code, devs = client.get("/v1/devices")
        if code != 200:
            raise RuntimeError(f"SmartThings GET /v1/devices -> HTTP {code}")
        by_label = {d.get("label"): d.get("deviceId") for d in devs.get("items", [])}
        entity_device, missing = {}, []
        for ent, label in ENTITY_LABELS.items():
            if by_label.get(label):
                entity_device[ent] = by_label[label]
            else:
                missing.append(label)
        if missing:
            raise RuntimeError("missing virtual devices: " + ", ".join(missing) +
                               " -- run scripts/st_setup.py to create them.")
        inst = cls(client, entity_device)
        if real:
            cls._LIVE_SINGLETON = inst
        return inst
