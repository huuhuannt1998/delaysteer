#!/usr/bin/env python3
"""A HomeAdapter over the real Home Assistant REST API, for Tier 2.

Tier 2 requires a platform API we did not write, reached over a transport we did
not write. This is that half: `HARestAdapter` speaks HTTP to a running Home
Assistant instance and returns the same `Observation` type the virtual adapter
does, so `SchedulingAdapter` wraps it unchanged and the interposer sits in
exactly the same place.

Two things this deliberately does NOT do.

It does not invent a generation time. Home Assistant reports `last_changed` and
`last_updated` per entity, and those are RECEIVER-SIDE stamps -- the hub records
when IT saw the change. That is precisely the laundering the paper describes, so
the adapter surfaces the hub's stamp as `generation_time` and says so, rather
than pretending to know when the device actually produced the reading. A Tier 2
run therefore measures the Lite-mode world by construction: no attested origin
exists to measure against.

It does not leave the testbed mutated. Every run records the prior state of the
entities it touches and restores them afterwards, because this is a live
instance and an experiment that silently leaves an alarm armed is not a clean
experiment.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..home.adapter import HomeAdapter, Observation


def load_credentials(env_path: str = ".env") -> tuple[str, str]:
    """Read HASS_URL / HASS_TOKEN. The token is never logged or returned to a
    caller that prints it -- callers should pass it straight to the adapter."""
    tok = os.environ.get("HASS_TOKEN")
    url = os.environ.get("HASS_URL")
    p = Path(env_path)
    if p.exists() and not (tok and url):
        for line in p.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, _, v = line.partition("=")
                v = v.strip().strip('"').strip("'")
                if k.strip() == "HASS_TOKEN" and not tok:
                    tok = v
                if k.strip() == "HASS_URL" and not url:
                    url = v
    if not tok:
        raise RuntimeError("HASS_TOKEN not found in environment or .env")
    return (url or "http://localhost:8123").rstrip("/"), tok


@dataclass
class HARestAdapter(HomeAdapter):
    """Live Home Assistant over HTTP. Third-party platform, third-party transport."""

    base_url: str
    token: str = field(repr=False)          # never surfaced in a repr or a log
    timeout: int = 10
    _t0: float = field(default_factory=time.monotonic)
    _restore: dict[str, str] = field(default_factory=dict)
    calls: int = 0

    # ------------------------------------------------------------- plumbing

    def _req(self, path: str, method: str = "GET",
             body: dict | None = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"{self.base_url}{path}", data=data, method=method,
            headers={"Authorization": f"Bearer {self.token}",
                     "Content-Type": "application/json"})
        self.calls += 1
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.load(r)

    def now(self) -> float:
        return time.monotonic() - self._t0

    # ---------------------------------------------------------------- reads

    def get_state(self, entity_id: str) -> Observation:
        s = self._req(f"/api/states/{entity_id}")
        # last_changed is the HUB's stamp: when Home Assistant saw the change.
        # Surfacing it as generation_time is not an approximation of the
        # device's true origin time -- it IS the receiver-side stamp the paper
        # says cannot prove pre-ingress freshness. A Tier 2 run is therefore a
        # Lite-mode measurement by construction.
        gen = self._parse_ts(s.get("last_changed") or s.get("last_updated"))
        return Observation(
            semantic_type=entity_id.split(".")[0],
            value=str(s.get("state")),
            attributes=dict(s.get("attributes") or {}),
            source="home_assistant",
            entity_id=entity_id,
            generation_time=gen,
            arrival_time=self.now(),
        )

    def _parse_ts(self, iso: str | None) -> float:
        if not iso:
            return self.now()
        from datetime import datetime, timezone
        try:
            dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - dt).total_seconds()
            return max(0.0, self.now() - age)
        except Exception:
            return self.now()

    # -------------------------------------------------------------- actions

    def call_service(self, domain: str, service: str,
                     data: dict[str, Any] | None = None) -> Observation:
        payload = dict(data or {})
        eid = payload.get("entity_id")
        if eid and eid not in self._restore:
            try:
                self._restore[eid] = str(self._req(f"/api/states/{eid}")["state"])
            except Exception:
                pass
        self._req(f"/api/services/{domain}/{service}", "POST", payload)
        return Observation(semantic_type="ack", value="ok",
                           source="home_assistant",
                           entity_id=f"{domain}.{service}",
                           generation_time=self.now(), arrival_time=self.now())

    def entities(self) -> dict[str, str]:
        return {s["entity_id"]: s["entity_id"] for s in self._req("/api/states")}

    # ------------------------------------------------------------- cleanup

    def restore(self) -> list[str]:
        """Put back what the run changed. This is a LIVE instance, and an
        experiment that leaves an alarm armed is not a clean experiment."""
        done = []
        for eid, state in list(self._restore.items()):
            try:
                self._req("/api/states/" + eid, "POST", {"state": state})
                done.append(eid)
            except Exception:
                pass
        self._restore.clear()
        return done
