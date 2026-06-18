#!/usr/bin/env python3
"""MA-0 bounded webhook end-to-end demo: a RESEARCH-GRADE SmartThings Webhook
SmartApp receiver (signature verification STUBBED -- not a hardened endpoint).

It handles the SmartApp lifecycles per the primary docs
(https://developer.smartthings.com/docs/connected-services/lifecycles):
  CONFIRMATION  -> GET the confirmationData.confirmationUrl (proves endpoint
                   ownership), respond {"targetUrl": <our public url>}.
  PING          -> echo pingData.challenge.
  CONFIGURATION -> minimal initialize/page so the app can be installed.
  INSTALL/UPDATE-> create a DEVICE subscription to the virtual contact device,
                   using installData.authToken (the installed-app token).
  EVENT         -> capture + HOLD the inbound device event (the delay-only
                   adversary on the real delivery leg); persist to the state file.

State (appId, installedAppId, confirmed, subscription, held events) is written to
/tmp/delaysteer_st_webhook.json so the registrar/demo can observe progress.

Token + public URL come from the gitignored .env (SMARTTHINGS_TOKEN, ST_WEBHOOK_URL);
never hardcoded/committed. The PI brings up ngrok and writes ST_WEBHOOK_URL.

  .venv/bin/python scripts/st_webhook.py --serve --port 8099       # the receiver (run first)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from delaysteer.home.smartthings_adapter import ENTITIES, _LiveClient, _token_from_env

API = "https://api.smartthings.com"
STATE = Path("/tmp/delaysteer_st_webhook.json")
CONTACT = ENTITIES["contact"]


def _env(key: str) -> str | None:
    import os
    if os.environ.get(key):
        return os.environ[key]
    env = Path(__file__).resolve().parent.parent / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            line = line.strip()
            if line.startswith(f"{key}=") and "=" in line:
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def _load() -> dict:
    if STATE.exists():
        return json.loads(STATE.read_text())
    return {"confirmed": False, "appId": None, "installedAppId": None,
            "subscription": None, "events": [], "log": []}


def _save(st: dict) -> None:
    STATE.write_text(json.dumps(st, indent=2))


def _discover_contact_device_id() -> str | None:
    tok = _token_from_env()
    if not tok:
        return None
    code, devs = _LiveClient(tok).get("/v1/devices")
    if code != 200:
        return None
    for d in devs.get("items", []):
        if d.get("label") == "delaysteer-contact":
            return d.get("deviceId")
    return None


class Handler(BaseHTTPRequestHandler):
    public_url = ""           # set at startup (our ST_WEBHOOK_URL)
    contact_device_id = None  # set at startup

    def log_message(self, *a):  # quiet default logging
        pass

    def _json(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # health check
        self._json(200, {"status": "delaysteer research receiver (signatures stubbed)"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": "bad json"})
        lc = req.get("lifecycle")
        st = _load()
        st["log"].append({"t": time.time(), "lifecycle": lc,
                          "keys": list(req.keys())})
        _save(st)  # persist EVERY inbound request so we can see what ST sends
        # NOTE: SmartThings signs every request (HTTP Signatures); verification is
        # STUBBED here -- research demo only, not a hardened endpoint.

        if lc == "CONFIRMATION":
            url = req.get("confirmationData", {}).get("confirmationUrl")
            ok = False
            try:
                urllib.request.urlopen(url, timeout=15)  # GET the confirmationUrl
                ok = True
            except Exception as e:
                st["log"].append({"confirm_error": str(e)[:200]})
            st["confirmed"] = ok
            st["appId"] = req.get("confirmationData", {}).get("appId")
            _save(st)
            return self._json(200, {"targetUrl": _env("ST_WEBHOOK_URL") or self.public_url})

        if lc == "PING":
            return self._json(200, {"pingData": {"challenge": req["pingData"]["challenge"]}})

        if lc == "CONFIGURATION":
            phase = req.get("configurationData", {}).get("phase")
            if phase == "INITIALIZE":
                return self._json(200, {"configurationData": {"initialize": {
                    "id": "app", "name": "DelaySteer Research Probe",
                    "description": "MA-0 webhook delivery-leg demo (research)",
                    "permissions": ["r:devices:*", "x:devices:*"], "firstPageId": "1"}}})
            return self._json(200, {"configurationData": {"page": {
                "pageId": "1", "name": "DelaySteer", "complete": True,
                "nextPageId": None, "previousPageId": None, "sections": []}}})

        if lc in ("INSTALL", "UPDATE"):
            d = req.get("installData") or req.get("updateData") or {}
            auth = d.get("authToken")
            iapp = (d.get("installedApp") or {}).get("installedAppId")
            st["installedAppId"] = iapp
            did = self.contact_device_id or _discover_contact_device_id()
            if auth and iapp and did:
                body = {"sourceType": "DEVICE", "device": {
                    "deviceId": did, "componentId": "main", "capability": "switch",
                    "attribute": "switch", "value": "*", "stateChangeOnly": True,
                    "subscriptionName": "delaysteer_contact"}}
                try:
                    r = urllib.request.Request(
                        f"{API}/installedapps/{iapp}/subscriptions",
                        data=json.dumps(body).encode(),
                        headers={"Authorization": f"Bearer {auth}",
                                 "Content-Type": "application/json"}, method="POST")
                    resp = urllib.request.urlopen(r, timeout=15)
                    st["subscription"] = json.loads(resp.read() or b"{}")
                except Exception as e:
                    st["log"].append({"subscribe_error": str(e)[:300]})
            _save(st)
            key = "installData" if lc == "INSTALL" else "updateData"
            return self._json(200, {key: {}})

        if lc == "EVENT":
            for ev in req.get("eventData", {}).get("events", []):
                de = ev.get("deviceEvent")
                if de:
                    de["_received_at"] = time.time()  # the delivery-leg arrival
                    st["events"].append(de)
            _save(st)
            return self._json(200, {"eventData": {}})

        return self._json(200, {})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--port", type=int, default=8099)
    args = ap.parse_args()
    if not args.serve:
        print("use --serve --port N"); return 2

    Handler.public_url = _env("ST_WEBHOOK_URL") or ""
    Handler.contact_device_id = _discover_contact_device_id()
    _save(_load())  # initialize state file
    print(f"receiver listening on 127.0.0.1:{args.port}")
    print(f"  public_url (ST_WEBHOOK_URL): {Handler.public_url or '(not set yet)'}")
    print(f"  contact deviceId: {Handler.contact_device_id or '(discovery failed)'}")
    print(f"  state file: {STATE}")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
