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
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .adapter import HomeAdapter, Observation, semantic_type_of
from .virtual_home import ENTITIES

CREDENTIALS_PATH = Path(__file__).resolve().parents[2] / "config" / "ha_credentials.json"
_ENTITY_ID = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")


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
    # Where the freshness stamp comes from. "rest" (every frozen result) takes last_reported from
    # GET /api/states, whose cached JSON HA 2026.8.3 does not invalidate on a same-value write
    # (HA issue #181392), so it moves only on a change. "template" reads the live State object's
    # last_reported through POST /api/template, which advances on every write, update_entity
    # included (results/ha_readpath_2026_8_3.csv).
    stamp_source = "rest"

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
        # Active-poll revalidation (TemporalGuard sets `active_poll` on the adapter at the
        # commit). A plain GET returns the platform's CACHED state, whose generation time is
        # whenever the integration last reported -- so a commit-time re-read of a slow-reporting
        # entity is not fresher than the read the planner already had. Forcing
        # homeassistant.update_entity makes the integration re-poll the device NOW, so the
        # value-age the guard measures is bounded by the poll round-trip rather than by the
        # passive reporting cadence. This is the platform primitive measured in
        # scripts/latency_calibration.py (P99 ~4.4 ms on the bedtime entities). Failures are
        # non-fatal: if the refresh cannot be issued we fall through to the cached read, which
        # the guard then judges on its (older) generation time -- fail-closed, never fail-open.
        if getattr(self, "active_poll", False):
            try:
                self._http.post(
                    f"{self.base_url}/api/services/homeassistant/update_entity",
                    headers=self._headers(),
                    content=json.dumps({"entity_id": entity_id}),
                )
            except Exception:  # noqa: BLE001 - refresh is best-effort; cached read still applies
                pass
        resp = self._http.get(
            f"{self.base_url}/api/states/{entity_id}", headers=self._headers()
        )
        resp.raise_for_status()
        data = resp.json()
        # Freshness must key off last_reported (heartbeat — when the platform last
        # AFFIRMED the value), not last_updated (last CHANGE). Otherwise an
        # unchanged-but-fresh sensor looks stale (finding jrn_01KSTYV7MMPG87AFZZJN1XSZY3).
        stamp = data.get("last_reported") or data.get("last_updated")
        if self.stamp_source == "template":
            stamp = self._live_last_reported(entity_id, data["state"]) or stamp
        gen = _parse_ha_time(stamp)
        return Observation(
            semantic_type=semantic_type_of(entity_id),
            value=data["state"],
            attributes=data.get("attributes", {}),
            source="home_assistant",
            entity_id=entity_id,
            generation_time=gen,
            arrival_time=time.time(),
        )

    def _live_last_reported(self, entity_id: str, rest_value: str) -> str | None:
        """The live object's last_reported, or None to keep the REST stamp.

        None whenever the live read cannot be trusted to describe the value we return: an
        entity id that is not a plain domain.object_id (it is interpolated into a template), a
        failed call, or a live value that differs from the REST value. The REST stamp is never
        newer, so every fallback errs toward blocking.
        """
        if not _ENTITY_ID.match(entity_id):
            return None
        tpl = f"{{{{ states.{entity_id}.state }}}}|{{{{ states.{entity_id}.last_reported.isoformat() }}}}"
        try:
            resp = self._http.post(f"{self.base_url}/api/template", headers=self._headers(),
                                   content=json.dumps({"template": tpl}))
            resp.raise_for_status()
            value, _, stamp = resp.text.strip().rpartition("|")
        except Exception:  # noqa: BLE001 - fall back to the REST stamp
            return None
        return stamp if value == rest_value and stamp else None

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
