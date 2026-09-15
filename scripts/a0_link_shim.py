#!/usr/bin/env python3
"""Position-A0 delay shim: the device -> hub link, modelled.

E1 (mission mis_01KZVRMET2H041053M72WN2HB8) needs a delay at position A0 -- the link
between the device and the hub -- as distinct from A1 (inside the hub, the
``delay_attacker`` custom component) and B (hub -> agent, v1's DelayingAdapter).

Placement
---------
Home Assistant bridges the SmartThings virtual devices with its generic ``rest`` platform,
polling ``https://api.smartthings.com/v1/devices/<id>/status`` every 30s. That poll IS the
device->hub link for this deployment. The shim interposes on it:

    HA (container)  ->  http://host.docker.internal:8126/v1/devices/<id>/status
                            |
                            +-- forwards, unmodified, to api.smartthings.com
                            +-- when ARMED, re-serves an EARLIER captured response

No radio hardware is involved and none is implied: per the mission's scope note the A0
link is MODELLED as a shim, and every row it produces is labelled as such.

Delay-only discipline (advisor design report Sec. 8.1)
-----------------------------------------------------
The report requires ``payload(m') = payload(m)`` and ``t_deliver(m') = t_deliver(m) +
delta_m`` with ``delta_m >= 0``: identifiers, values, arguments and canonical payload
hashes must be unchanged. This shim therefore has exactly one primitive -- **replay bytes
it genuinely captured from upstream** -- and no code path that constructs a response body.
Every served frame records the sha256 of the bytes and whether they were captured or
forwarded live, so "the adversary forged nothing" is auditable per frame rather than
asserted. If a hold is armed with no captured frame available, the shim forwards live
rather than inventing one.

That restriction is what keeps the adversary at delay-only. Synthesising a frame would
promote it to compromised-source and invalidate E1's minimal claim (mission checkpoint
trigger 3).

Hold log
--------
Each capture/release is logged with the shim's OWN monotonic-anchored wall clock, never
HA's, giving ground-truth ``t_generated`` independent of the hub under test.

  python scripts/a0_link_shim.py --port 8126
  curl -XPOST localhost:8126/__ctl__/arm    -d '{"device":"<id>","hold_s":45}'
  curl -XPOST localhost:8126/__ctl__/disarm -d '{}'
  curl        localhost:8126/__ctl__/holdlog
"""

from __future__ import annotations

import argparse
import hashlib
import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UPSTREAM = "https://api.smartthings.com"
LOG = ROOT / "results" / "a0_shim_hold.log"


class Shim(ThreadingHTTPServer):
    def __init__(self, addr):
        super().__init__(addr, Handler)
        self.lock = threading.Lock()
        self.armed: dict[str, float] = {}          # device_id -> hold seconds
        self.captured: dict[str, tuple] = {}       # device_id -> (body, ctype, t_capture, sha)
        self.pinned: set = set()                   # devices whose capture is frozen for replay
        self.holds: list[dict] = []                # the hold log
        self.n_forward = self.n_replay = 0

    def note(self, rec: dict) -> None:
        rec["t"] = time.time()
        with self.lock:
            self.holds.append(rec)
        try:
            LOG.parent.mkdir(exist_ok=True)
            with LOG.open("a") as fh:
                fh.write(json.dumps(rec) + "\n")
        except Exception:
            pass


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    @property
    def S(self) -> Shim:
        return self.server  # type: ignore

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _device_of(self, path: str) -> str | None:
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 3 and parts[0] == "v1" and parts[1] == "devices":
            return parts[2]
        return None

    def do_GET(self):
        if self.path.startswith("/__ctl__/"):
            op = self.path.rsplit("/", 1)[1].split("?")[0]
            if op == "stats":
                return self._send(200, json.dumps(
                    {"forward": self.S.n_forward, "replay": self.S.n_replay,
                     "armed": self.S.armed}).encode(), "application/json")
            if op == "holdlog":
                with self.S.lock:
                    return self._send(200, json.dumps(self.S.holds).encode(), "application/json")
            return self._send(404, b"?", "text/plain")

        dev = self._device_of(self.path)
        hold = self.S.armed.get(dev or "", 0.0)
        cap = self.S.captured.get(dev or "")

        # ARMED + a genuine earlier frame on hand -> replay THOSE BYTES. This is the whole
        # attack: content the hub will stamp fresh, unmodified and truthfully captured.
        if hold and cap is not None:
            body, ctype, t_cap, sha = cap
            age = time.time() - t_cap
            if age <= hold:
                self.S.n_replay += 1
                self.S.note({"event": "replay", "device": dev, "sha256": sha,
                             "t_capture": t_cap, "captured_age_s": round(age, 3),
                             "hold_s": hold, "synthesized": False})
                return self._send(200, body, ctype)

        # otherwise forward live, and capture the genuine frame for a future hold
        try:
            req = urllib.request.Request(UPSTREAM + self.path)
            for h in ("Authorization", "Accept", "Content-Type"):
                if self.headers.get(h):
                    req.add_header(h, self.headers[h])
            with urllib.request.urlopen(req, timeout=20) as r:
                body = r.read()
                ctype = r.headers.get("Content-Type", "application/json")
                code = r.status
        except Exception as e:  # upstream failure is reported, never fabricated
            self.S.note({"event": "upstream_error", "device": dev, "err": type(e).__name__})
            return self._send(502, json.dumps({"shim_error": type(e).__name__}).encode(),
                              "application/json")

        sha = hashlib.sha256(body).hexdigest()
        self.S.n_forward += 1
        with self.S.lock:
            # A PINNED frame is the one the operator explicitly chose to replay. Later
            # forwards must not overwrite it -- otherwise arming replays whatever the
            # world most recently said, which is a no-op. (ha_delay_proxy separates
            # capture from arm for this reason; this mirrors it.)
            if dev not in self.S.pinned:
                self.S.captured[dev or ""] = (body, ctype, time.time(), sha)
        self.S.note({"event": "forward_and_capture", "device": dev, "sha256": sha,
                     "synthesized": False})
        return self._send(code, body, ctype)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b"{}"
        if self.path.startswith("/__ctl__/"):
            op = self.path.rsplit("/", 1)[1]
            arg = json.loads(raw or b"{}")
            if op == "capture":
                # Snapshot the CURRENT genuine upstream frame and pin it as the replay
                # source. Separate from arm so the operator controls exactly which
                # truthful frame gets re-delivered later.
                dev = arg["device"]
                req = urllib.request.Request(f"{UPSTREAM}/v1/devices/{dev}/status")
                if arg.get("authorization"):
                    req.add_header("Authorization", arg["authorization"])
                # Backoff on 429. scan_interval x N entities can saturate the cloud's cap,
                # and a capture that dies mid-setup aborts the whole trial.
                body = ctype = None
                delay = 3.0
                for _ in range(5):
                    try:
                        with urllib.request.urlopen(req, timeout=20) as r:
                            body = r.read(); ctype = r.headers.get("Content-Type", "application/json")
                        break
                    except Exception:
                        time.sleep(delay); delay *= 2
                if body is None:
                    return self._send(502, json.dumps({"shim_error": "capture upstream unavailable"}).encode(),
                                      "application/json")
                sha = hashlib.sha256(body).hexdigest()
                with self.S.lock:
                    self.S.captured[dev] = (body, ctype, time.time(), sha)
                    self.S.pinned.add(dev)
                self.S.note({"event": "capture_pin", "device": dev, "sha256": sha,
                             "synthesized": False})
                return self._send(200, json.dumps({"ok": True, "sha256": sha}).encode(),
                                  "application/json")
            if op == "arm":
                dev, hold = arg["device"], float(arg.get("hold_s", 45.0))
                with self.S.lock:
                    self.S.armed[dev] = hold
                self.S.note({"event": "arm", "device": dev, "hold_s": hold})
                return self._send(200, json.dumps({"ok": True}).encode(), "application/json")
            if op == "disarm":
                with self.S.lock:
                    self.S.armed.clear(); self.S.pinned.clear()
                self.S.note({"event": "disarm"})
                return self._send(200, json.dumps({"ok": True}).encode(), "application/json")
            if op == "reset":
                with self.S.lock:
                    self.S.armed.clear(); self.S.captured.clear(); self.S.holds.clear()
                    self.S.pinned.clear()
                    self.S.n_forward = self.S.n_replay = 0
                return self._send(200, json.dumps({"ok": True}).encode(), "application/json")
            return self._send(404, b"?", "text/plain")

        # device commands pass straight through, unmodified
        try:
            req = urllib.request.Request(UPSTREAM + self.path, data=raw, method="POST")
            for h in ("Authorization", "Content-Type"):
                if self.headers.get(h):
                    req.add_header(h, self.headers[h])
            with urllib.request.urlopen(req, timeout=20) as r:
                return self._send(r.status, r.read(),
                                  r.headers.get("Content-Type", "application/json"))
        except Exception as e:
            return self._send(502, json.dumps({"shim_error": type(e).__name__}).encode(),
                              "application/json")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8126)
    args = ap.parse_args()
    srv = Shim(("0.0.0.0", args.port))
    print(f"A0 link shim on :{args.port} -> {UPSTREAM}", flush=True)
    print("  primitive: replay genuinely-captured bytes only; no synthesis path exists",
          flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
