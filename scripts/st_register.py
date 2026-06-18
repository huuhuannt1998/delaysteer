#!/usr/bin/env python3
"""MA-0 webhook stage 1: register the WEBHOOK_SMART_APP + complete CONFIRMATION.

Reads SMARTTHINGS_TOKEN + ST_WEBHOOK_URL from .env (never printed). Registers via
POST /v1/apps; SmartThings then POSTs a CONFIRMATION to the receiver, which GETs
the confirmationUrl. We poll the receiver's state file and, if confirmation lags,
re-trigger via PUT /apps/{id}/register {} (normal, per the verified flow note).
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE = Path("/tmp/delaysteer_st_webhook.json")
API = "https://api.smartthings.com"


def env(key: str) -> str | None:
    if os.environ.get(key):
        return os.environ[key]
    e = ROOT / ".env"
    if e.exists():
        for ln in e.read_text().splitlines():
            ln = ln.strip()
            if ln.startswith(key + "=") and "=" in ln:
                return ln.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def req(method, url, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(r, timeout=30)
        return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)[:200]}


def confirmed() -> bool:
    try:
        return bool(json.loads(STATE.read_text()).get("confirmed"))
    except Exception:
        return False


def main() -> int:
    token, url = env("SMARTTHINGS_TOKEN"), env("ST_WEBHOOK_URL")
    if not token or not url:
        print("missing SMARTTHINGS_TOKEN or ST_WEBHOOK_URL in .env")
        return 2
    appName = f"delaysteer-probe-{int(time.time())}"
    code, resp = req("POST", f"{API}/v1/apps", token, {
        "appName": appName, "displayName": "DelaySteer Probe",
        "description": "MA-0 webhook delivery-leg demo (research, signatures stubbed)",
        "appType": "WEBHOOK_SMART_APP", "classifications": ["AUTOMATION"],
        "webhookSmartApp": {"targetUrl": url}})
    print(f"POST /v1/apps -> HTTP {code}")
    appId = (resp.get("app") or resp).get("appId")
    if code not in (200, 201) or not appId:
        print("  registration failed; body:", json.dumps(resp)[:500])
        return 1
    print(f"  appId = {appId}  (200, not the probe's 422 -- the endpoint answered)")
    (Path("/tmp/delaysteer_appid.txt")).write_text(appId)

    for _ in range(20):
        if confirmed():
            break
        time.sleep(1.5)
    if not confirmed():
        print("  confirmation lagging; re-trigger via PUT /apps/{id}/register {}")
        c2, _ = req("PUT", f"{API}/apps/{appId}/register", token, {})
        print(f"  PUT /apps/{appId}/register -> HTTP {c2}")
        for _ in range(20):
            if confirmed():
                break
            time.sleep(1.5)

    print(f"CONFIRMATION handshake completed: {confirmed()}")
    return 0 if confirmed() else 1


if __name__ == "__main__":
    raise SystemExit(main())
