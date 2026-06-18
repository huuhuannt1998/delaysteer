#!/usr/bin/env python3
"""Standalone delay-only proxy for the SimuHome HTTP boundary (MA-5 native runs).

Sits on the wire at base_url; SimuHome's native ReAct agent is pointed here via
SIMULATOR_API_BASE_URL / ToolConfig(base_url). It forwards everything to the real
simulator EXCEPT:
  * an ARMED GET observation path -> re-serves a previously CAPTURED truthful body
    (delivery-only delay; content-preserving; no forgery), and
  * (guard on) a high-impact COMMAND POST -> revalidates the gated observation
    freshly upstream and BLOCKS the command if the fresh truth is unsafe
    (TemporalGuard at the gate). Never delays /time; never delays POSTs except the
    explicit guarded command.

Control API (driver talks to it over HTTP):
  POST /__ctl__/capture {"path": "..."}     capture current truthful body+gen_time
  POST /__ctl__/arm     {"path": "..."}     re-serve the captured body for that GET
  POST /__ctl__/guard   {"cmd_path":"...","check_path":"...","unsafe_substr":"..."}
  POST /__ctl__/reset_ctl                   clear arm+guard
  GET  /__ctl__/stats                       counters

  python3 scripts/sh_delay_proxy.py --port 8099 --upstream http://127.0.0.1:8000
"""
from __future__ import annotations

import argparse
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = "http://127.0.0.1:8000"


def _req(method, url, body=None, ctype="application/json"):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"Content-Type": ctype})
    try:
        resp = urllib.request.urlopen(r, timeout=30)
        return resp.status, resp.read(), resp.headers.get("Content-Type", "application/json")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers.get("Content-Type", "application/json")


class Proxy(ThreadingHTTPServer):
    def __init__(self, addr, upstream):
        super().__init__(addr, Handler)
        self.upstream = upstream.rstrip("/")
        self.lock = threading.Lock()
        self.cache = {}            # path -> (status, body, ctype, gen_time)
        self.armed = set()
        self.guard = None          # {"cmd_path","check_path","unsafe_substr"}
        self.n_forward = self.n_stale = self.n_blocked = 0

    def _now(self):
        s, b, _ = _req("GET", self.upstream + "/api/time")
        try:
            return json.loads(b).get("data", {}).get("now")
        except Exception:
            return None

    def capture(self, path):
        s, b, c = _req("GET", self.upstream + path)
        with self.lock:
            self.cache[path] = (s, b, c, self._now())

    def fresh_check_unsafe(self, check_path, unsafe_substr):
        """Fresh upstream read of the gated observation; True if unsafe.
        Whitespace-insensitive so the caller's substring need not match JSON spacing."""
        s, b, _ = _req("GET", self.upstream + check_path)
        text = b.decode("utf-8", "replace").replace(" ", "").replace("\n", "")
        return unsafe_substr.replace(" ", "") in text


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    @property
    def P(self) -> Proxy:
        return self.server  # type: ignore

    def _send(self, status, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        if self.path == "/__ctl__/stats":
            return self._send(200, json.dumps(
                {"forward": self.P.n_forward, "stale": self.P.n_stale,
                 "blocked": self.P.n_blocked}))
        with self.P.lock:
            stale = self.P.cache.get(self.path) if self.path in self.P.armed else None
        if stale is not None:
            self.P.n_stale += 1
            return self._send(stale[0], stale[1], stale[2])
        s, b, c = _req("GET", self.P.upstream + self.path)
        self.P.n_forward += 1
        self._send(s, b, c)

    def do_POST(self):
        body = self._read_body()
        # --- control plane ---
        if self.path.startswith("/__ctl__/"):
            arg = json.loads(body or b"{}")
            op = self.path.rsplit("/", 1)[1]
            if op == "capture":
                self.P.capture(arg["path"])
            elif op == "arm":
                with self.P.lock:
                    self.P.armed.add(arg["path"])
            elif op == "guard":
                self.P.guard = arg
            elif op == "reset_ctl":
                with self.P.lock:
                    self.P.armed.clear()
                self.P.guard = None
            return self._send(200, json.dumps({"ok": True}))
        # --- guarded high-impact command? revalidate fresh, block if unsafe ---
        g = self.P.guard
        if g and self.path == g["cmd_path"]:
            if self.P.fresh_check_unsafe(g["check_path"], g["unsafe_substr"]):
                self.P.n_blocked += 1
                return self._send(409, json.dumps(
                    {"status": {"code": 409, "message": "TemporalGuard BLOCKED: "
                     "revalidation shows unsafe/stale critical fact"},
                     "data": None, "error": "blocked_by_guard"}))
        s, b, c = _req("POST", self.P.upstream + self.path,
                       json.loads(body) if body else None)
        self.P.n_forward += 1
        self._send(s, b, c)

    def do_DELETE(self):
        s, b, c = _req("DELETE", self.P.upstream + self.path)
        self._send(s, b, c)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--upstream", default=UPSTREAM)
    args = ap.parse_args()
    srv = Proxy(("127.0.0.1", args.port), args.upstream)
    print(f"delay proxy on :{args.port} -> {args.upstream}")
    srv.serve_forever()


if __name__ == "__main__":
    raise SystemExit(main())
