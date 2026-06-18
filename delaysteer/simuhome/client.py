"""Minimal HTTP client for the SimuHome simulator REST API (routes under /api).

This talks to a SimuHome server started with `uv run simuhome server-start`
(default base http://127.0.0.1:8000). It can be pointed at the delay PROXY
instead (the SH-1 wire-interception proof); for the experiment matrix the delay
is applied at the `DelayingAdapter` Observation seam, identical to the other
targets, so this client only needs faithful read/command/clock primitives.

Time control facts (verified in the SH-1 probe):
  * The sim processes its API queue once per tick, so a large tick_interval
    starves reads. Use FROZEN mode (fast_forward=True + max_ticks=T) for
    deterministic reads at an exact tick; RUNNING mode (small tick_interval) when
    commands must apply and the clock must advance.
  * OnOff and similar are readonly attributes controlled by On/Off COMMANDS.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime

DEFAULT_BASE = "http://127.0.0.1:8000/api"
_FMT = "%Y-%m-%d %H:%M:%S"


class SimuHomeClient:
    def __init__(self, base_url: str = DEFAULT_BASE, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # ---- transport ----
    def _req(self, method: str, path: str, body: dict | None = None):
        url = self.base_url + path
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(url, data=data, method=method,
                                   headers={"Content-Type": "application/json"})
        try:
            resp = urllib.request.urlopen(r, timeout=self.timeout)
            return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except Exception:
                return e.code, {}

    def get(self, path: str):
        return self._req("GET", path)

    def post(self, path: str, body: dict):
        return self._req("POST", path, body)

    # ---- simulation control ----
    def reset(self, config: dict):
        return self.post("/simulation/reset", config)

    def reset_frozen(self, rooms: dict, to_tick: int, base_time: str = "2025-08-23 09:30:00",
                     tick_interval: float = 0.1, tries: int = 400):
        """Reset in fast-forward mode and wait until frozen at exactly `to_tick`."""
        self.reset({"tick_interval": tick_interval, "base_time": base_time,
                    "fast_forward": True, "max_ticks": to_tick,
                    "enable_aggregators": True, "rooms": rooms})
        for _ in range(tries):
            if self.current_tick() == to_tick:
                return
        raise RuntimeError(f"SimuHome did not freeze at tick {to_tick}")

    def reset_running(self, rooms: dict, base_time: str = "2025-08-23 09:30:00",
                      tick_interval: float = 0.1):
        return self.reset({"tick_interval": tick_interval, "base_time": base_time,
                           "fast_forward": False, "enable_aggregators": True, "rooms": rooms})

    def fast_forward_to(self, tick: int):
        return self.post("/simulation/fast_forward_to", {"to_tick": tick})

    # ---- reads ----
    def home_state(self) -> dict:
        return self.get("/home/state")[1].get("data", {})

    def current_tick(self) -> int:
        return self.home_state().get("current_tick")

    def now_str(self) -> str:
        """Authoritative sim time. /time requires the loop running, so read
        current_time from /home/state (the same clock; available frozen too)."""
        ct = self.home_state().get("current_time")
        if ct:
            return ct
        return self.get("/time")[1].get("data", {}).get("now")

    def now_seconds(self) -> float:
        """Authoritative sim time as float seconds (for generation_time)."""
        return datetime.strptime(self.now_str(), _FMT).timestamp()

    def device_attributes(self, device_id: str) -> dict:
        return self.get(f"/devices/{device_id}/attributes")[1].get("data", {})

    def attribute(self, device_id: str, key: str):
        """Read one attribute value by '<endpoint>.<Cluster>.<Attr>' key."""
        return self.device_attributes(device_id).get(key)

    def room_states(self, room_id: str) -> dict:
        return self.get(f"/rooms/{room_id}/states")[1].get("data", {})

    # ---- commands ----
    def command(self, device_id: str, endpoint_id: int, cluster_id: str,
                command_id: str, args: dict | None = None):
        return self.post(f"/devices/{device_id}/commands",
                         {"endpoint_id": endpoint_id, "cluster_id": cluster_id,
                          "command_id": command_id, "args": args or {}})
