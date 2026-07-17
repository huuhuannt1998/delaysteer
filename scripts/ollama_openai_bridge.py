#!/usr/bin/env python3
"""Transparent OpenAI-compatible bridge: 127.0.0.1:8788 -> ollama 127.0.0.1:11434.

The Hermes TUI is configured (``~/.hermes/config.yaml`` -> ``model.base_url:
http://127.0.0.1:8788/v1`` and the matching ``custom_providers`` entries) to reach
its LLM on :8788. That gateway is not always running; ollama already speaks the same
OpenAI-compatible API on :11434, so this forwards every /v1/* request there and STREAMS
the response back byte-for-byte (SSE-safe). It lets the existing TUI config + already
running workers work unchanged -- no config edit, no worker restart. Kill it to undo.

  python3 scripts/ollama_openai_bridge.py [--port 8788] [--upstream http://127.0.0.1:11434]
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

UPSTREAM = "http://127.0.0.1:11434"
_CLIENT = httpx.Client(timeout=httpx.Timeout(600.0, connect=10.0))
_FWD_HEADERS = ("Content-Type", "Authorization", "Accept")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _pipe(self, method):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n) if n else None
        fwd = {k: self.headers.get(k) for k in _FWD_HEADERS if self.headers.get(k)}
        try:
            with _CLIENT.stream(method, self.server.upstream + self.path,
                                content=body, headers=fwd) as r:
                self.send_response(r.status_code)
                self.send_header("Content-Type", r.headers.get("Content-Type", "application/json"))
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for chunk in r.iter_raw():
                    if chunk:
                        self.wfile.write(b"%X\r\n" % len(chunk) + chunk + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
        except Exception as e:  # upstream unreachable / mid-stream failure
            msg = ('{"error":{"message":"ollama bridge -> upstream failed: %s"}}'
                   % str(e).replace('"', "'")).encode()
            try:
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)
            except Exception:
                pass

    def do_GET(self):
        self._pipe("GET")

    def do_POST(self):
        self._pipe("POST")

    def do_DELETE(self):
        self._pipe("DELETE")


class Bridge(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, upstream):
        super().__init__(addr, Handler)
        self.upstream = upstream.rstrip("/")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8788)
    ap.add_argument("--upstream", default=UPSTREAM)
    args = ap.parse_args()
    srv = Bridge(("127.0.0.1", args.port), args.upstream)
    print(f"ollama OpenAI bridge on :{args.port} -> {args.upstream} (/v1/* passthrough, streaming)",
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    raise SystemExit(main())
