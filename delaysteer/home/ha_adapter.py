"""Real Home Assistant adapter (REST + token auth).

Implements the same `HomeAdapter` interface as the virtual home, so the planner
is unchanged when pointed at a live HA instance (Figure-1 separation). Auth uses
the refresh-token minted by `scripts/ha_bootstrap.py` (REST-only — no long-lived
WebSocket token needed). Timestamps are real epoch seconds: `generation_time`
comes from HA's `last_updated`, `arrival_time` from receipt — so transit delay is
measured, which is exactly what Phase 2's delay layer will widen.

WebSocket event subscription is intentionally left for Phase 2 (the event stream
is the natural place to inject delayed sensor observations).
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .adapter import HomeAdapter, Observation, semantic_type_of
from .virtual_home import ENTITIES

CREDENTIALS_PATH = Path(__file__).resolve().parents[2] / "config" / "ha_credentials.json"


class _EpochClock:
    def now(self) -> float:
        return time.time()


def _parse_ha_time(s: str | None) -> float:
    if not s:
        return time.time()
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return time.time()


class HomeAssistantAdapter(HomeAdapter):
    def __init__(self, base_url: str, refresh_token: str, client_id: str) -> None:
        import httpx  # lazy

        self.base_url = base_url.rstrip("/")
        self._refresh_token = refresh_token
        self._client_id = client_id
        self._http = httpx.Client(timeout=30)
        self._access_token: str | None = None
        self._access_expiry: float = 0.0
        self.clock = _EpochClock()

    # ---- auth ----
    def _token(self) -> str:
        if self._access_token and time.time() < self._access_expiry - 30:
            return self._access_token
        resp = self._http.post(
            f"{self.base_url}/auth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,
                "client_id": self._client_id,
            },
        )
        resp.raise_for_status()
        tok = resp.json()
        self._access_token = tok["access_token"]
        self._access_expiry = time.time() + tok.get("expires_in", 1800)
        return self._access_token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"}

    # ---- HomeAdapter interface ----
    def get_state(self, entity_id: str) -> Observation:
        resp = self._http.get(
            f"{self.base_url}/api/states/{entity_id}", headers=self._headers()
        )
        resp.raise_for_status()
        data = resp.json()
        # Freshness must key off last_reported (heartbeat — when the platform last
        # AFFIRMED the value), not last_updated (last CHANGE). Otherwise an
        # unchanged-but-fresh sensor looks stale (finding jrn_01KSTYV7MMPG87AFZZJN1XSZY3).
        gen = _parse_ha_time(data.get("last_reported") or data.get("last_updated"))
        return Observation(
            semantic_type=semantic_type_of(entity_id),
            value=data["state"],
            attributes=data.get("attributes", {}),
            source="home_assistant",
            entity_id=entity_id,
            generation_time=gen,
            arrival_time=time.time(),
        )

    def call_service(
        self, domain: str, service: str, data: dict[str, Any] | None = None
    ) -> Observation:
        gen = time.time()
        resp = self._http.post(
            f"{self.base_url}/api/services/{domain}/{service}",
            headers=self._headers(),
            content=json.dumps(data or {}),
        )
        resp.raise_for_status()
        return Observation(
            semantic_type="actuation_ack",
            value="ack",
            attributes={"domain": domain, "service": service, "data": data or {}},
            source="home_assistant",
            entity_id=(data or {}).get("entity_id"),
            generation_time=gen,
            arrival_time=time.time(),
        )

    def entities(self) -> dict[str, str]:
        return dict(ENTITIES)

    # ---- construction ----
    @classmethod
    def from_credentials(cls, path: str | Path = CREDENTIALS_PATH) -> "HomeAssistantAdapter":
        creds = json.loads(Path(path).read_text())
        return cls(
            base_url=creds["base_url"],
            refresh_token=creds["refresh_token"],
            client_id=creds["client_id"],
        )
