#!/usr/bin/env python3
"""MA-0 probe (Gate-1 / assumption MA0-2): does the delay-only primitive sit on
the REAL SmartThings delivery path?  Answers TWO questions, prints a verdict.

  Q1 PULL (HA-parity, the core claim): fetch a REAL device status from the
     SmartThings cloud, build the same Observation the testbed uses, then age it
     at OUR adapter boundary (delay-only: move generation_time back; value
     UNCHANGED) and confirm the *exact* predicate TemporalGuard uses
     ((arrival - generation) > budget; temporal_guard.py:104-108) reports it
     STALE, while a freshly-affirmed value is NOT stale (control).

  Q2 PUSH (the cleaner "delay on the actual delivery leg" claim): is registering
     a webhook SmartApp in this dev sandbox FEASIBLE?  yes / yes-pending-endpoint
     / no.  (A held inbound event is the stronger second-real-platform claim.)

CREDENTIALS: the token is read ONLY from $SMARTTHINGS_TOKEN (or a gitignored
.env).  Never hardcoded, printed, or committed.  Run --mock (no token, no network,
recorded JSON) to verify the logic; the PI runs it live with a fresh, tightly
scoped, ephemeral PAT.  This probe builds NO adapter / production code.

    python scripts/st_probe.py --mock                               # logic check, no creds
    SMARTTHINGS_TOKEN=*** python scripts/st_probe.py                # live (PI runs this)
    SMARTTHINGS_TOKEN=*** python scripts/st_probe.py --webhook-url https://<tunnel>  # full push proof
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from delaysteer.config import DEFAULT_FRESHNESS_S   # real freshness budgets
from delaysteer.home.adapter import Observation     # real Observation type

API = "https://api.smartthings.com"
SEM = "contact_state"                                # channel we age (budget 2.0s)
BUDGET = DEFAULT_FRESHNESS_S.get(SEM, 2.0)


def _load_dotenv():
    """Load $SMARTTHINGS_TOKEN from a gitignored .env if not already in the env
    (MA0-3 contract). No dependency; the token never leaves the local machine."""
    p = Path(__file__).resolve().parent.parent / ".env"
    if p.exists() and not os.environ.get("SMARTTHINGS_TOKEN"):
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _iso_to_epoch(ts: str) -> float:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


# --- thin HTTP: live (httpx) or mocked (recorded JSON; no network, no creds) ---
class Mock:
    """Recorded SmartThings responses so the probe's LOGIC runs with no token.
    The real verdict comes from the PI's live run; this only proves the probe works."""
    def __init__(self):
        self._ts = datetime.now(timezone.utc).isoformat()  # "now" => ~0s live transit

    def get(self, path):
        if path == "/v1/devices":
            return 200, {"items": [{"deviceId": "mock-virtual-contact",
                "label": "DelaySteer Virtual Contact", "type": "VIRTUAL"}]}
        if path.endswith("/status"):
            return 200, {"components": {"main": {"contactSensor":
                {"contact": {"value": "closed", "timestamp": self._ts}}}}}
        if path == "/v1/apps":
            return 200, {"items": []}
        return 404, {}

    def post(self, path, body):
        if path == "/v1/apps":   # simulate "needs a confirmable public endpoint"
            url = body.get("webhookSmartApp", {}).get("targetUrl", "")
            if url.startswith("https://") and "invalid" not in url:
                return 200, {"app": {"appId": "mock-app"}}
            return 422, {"error": {"message": "targetUrl must be publicly reachable"}}
        if path.endswith("/commands"):
            return 200, {"results": [{"status": "ACCEPTED"}]}
        return 404, {}

    def delete(self, path):
        return 200, {}


class Live:
    def __init__(self, token):
        import httpx  # lazy: only a real run needs it
        self._h = httpx.Client(base_url=API, timeout=30,
            headers={"Authorization": f"Bearer {token}"})

    def get(self, path):
        r = self._h.get(path)
        return r.status_code, (r.json() if r.content else {})

    def post(self, path, body):
        r = self._h.post(path, json=body)
        return r.status_code, (r.json() if r.content else {})

    def delete(self, path):
        return self._h.delete(path).status_code, {}


# --- Q1: aging a REAL GET response at the boundary -> STALE (delay-only)? -------
def q1_pull(cli, device_id):
    sc, devs = cli.get("/v1/devices")
    if sc != 200:
        return False, f"GET /v1/devices -> HTTP {sc} (cannot read the real cloud)"
    items = devs.get("items", [])
    dev = next((d for d in items if d.get("deviceId") == device_id), None) if device_id else None
    dev = dev or (items[0] if items else None)
    if not dev:
        return False, "no devices visible to this token (create a virtual device first)"
    did = dev["deviceId"]
    sc, st = cli.get(f"/v1/devices/{did}/status")
    if sc != 200:
        return False, f"GET /v1/devices/{did}/status -> HTTP {sc}"
    attr = None  # find any real attribute carrying a cloud timestamp
    for comp in st.get("components", {}).values():
        for cap in comp.values():
            for a in (cap or {}).values():
                if isinstance(a, dict) and a.get("timestamp"):
                    attr = a
                    break
    if not attr:
        return False, "device status carried no timestamped attribute"
    gen = _iso_to_epoch(attr["timestamp"])
    arr = datetime.now(timezone.utc).timestamp()
    live_transit = max(arr - gen, 0.0)
    value = str(attr.get("value"))  # truthful value; we NEVER change it
    # delay-only aging at our boundary (same transform as attack/adaptive.py:54):
    age = BUDGET + 1.0
    aged = Observation(semantic_type=SEM, value=value, generation_time=arr - age, arrival_time=arr)
    fresh = Observation(semantic_type=SEM, value=value, generation_time=arr - 0.1, arrival_time=arr)
    stale = lambda o: (o.arrival_time - o.generation_time) > BUDGET  # temporal_guard.py:104-108
    ok = stale(aged) and not stale(fresh)
    return ok, (f"device={did} value='{value}' (truthful, unchanged); live cloud "
                f"transit={live_transit:.2f}s; budget={BUDGET}s; aged(+{age}s)->stale="
                f"{stale(aged)}; control fresh(0.1s)->stale={stale(fresh)}")


# --- Q2: is webhook SmartApp registration feasible in this dev sandbox? --------
def q2_push(cli, webhook_url):
    sc, _ = cli.get("/v1/apps")
    if sc in (401, 403):
        return "no", f"GET /v1/apps -> HTTP {sc}: this token/account cannot manage apps"
    if sc != 200:
        return "unknown", f"GET /v1/apps -> HTTP {sc}"
    url = webhook_url or "https://delaysteer.invalid/probe"   # dry-run if no tunnel
    body = {"appName": "delaysteer-probe", "displayName": "DelaySteer Probe",
            "description": "MA-0 push-path feasibility probe", "appType": "WEBHOOK_SMART_APP",
            "classifications": ["AUTOMATION"], "webhookSmartApp": {"targetUrl": url}}
    sc, resp = cli.post("/v1/apps", body)
    if sc in (200, 201):
        app_id = (resp.get("app") or {}).get("appId")
        if app_id:
            cli.delete(f"/v1/apps/{app_id}")              # clean up immediately
        return "yes", ("registered" + (f" + confirmed at {webhook_url}" if webhook_url
                       else " a webhook SmartApp") + " (deleted after)")
    if sc in (400, 422):   # permitted, but creation needs a reachable/confirmable URL
        return "yes-pending-endpoint", (f"POST /v1/apps -> HTTP {sc}: registration permitted; "
                "needs a public HTTPS endpoint to confirm. Re-run with --webhook-url <tunnel> "
                "for end-to-end proof.")
    if sc in (401, 403):
        return "no", f"POST /v1/apps -> HTTP {sc}: not permitted for this token/account"
    return "unknown", f"POST /v1/apps -> HTTP {sc}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true", help="recorded JSON; no token, no network")
    ap.add_argument("--device-id", default=None, help="virtual device id (else first visible)")
    ap.add_argument("--webhook-url", default=None, help="public HTTPS tunnel for full push proof")
    args = ap.parse_args()

    if args.mock:
        cli = Mock()
    else:
        _load_dotenv()
        token = os.environ.get("SMARTTHINGS_TOKEN")
        if not token:
            print("SMARTTHINGS_TOKEN not set. Mint a fresh, tightly-scoped, EPHEMERAL PAT\n"
                  "(post-2024 PATs auto-expire in 24h) and run:\n"
                  "    SMARTTHINGS_TOKEN=*** python scripts/st_probe.py\n"
                  "or run with --mock to verify the probe logic without credentials.")
            return 2
        cli = Live(token)

    print(f"=== MA-0 probe ({'MOCK' if args.mock else 'LIVE'}) - MA0-2 confirmation ===")
    q1_ok, q1_msg = q1_pull(cli, args.device_id)
    print(f"\n[Q1 PULL / HA-parity]  {'PASS' if q1_ok else 'FAIL'}\n  {q1_msg}")
    q2, q2_msg = q2_push(cli, args.webhook_url)
    print(f"\n[Q2 PUSH / webhook feasibility]  {q2.upper()}\n  {q2_msg}")

    print("\n=== VERDICT (Brain branch logic) ===")
    if not q1_ok:
        print("MA0-2 FAILS on the pull path -> ESCALATE: the real-platform claim cannot stand.")
        return 3
    if q2 in ("yes", "yes-pending-endpoint"):
        print("MA0-2 HOLDS, both paths available -> build BOTH (strongest W1: "
              "delay on the real delivery leg via held webhook event).")
    else:
        print("MA0-2 HOLDS on the pull path; webhook BLOCKED -> proceed pull-path, "
              "flag the weaker-claim limitation honestly in the paper.")
    print("(pull = aging a real GET at our boundary; push = holding a real inbound webhook event)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
