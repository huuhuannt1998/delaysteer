"""The proxy's opt-in two-channel hold (results/au1_two_channel_plan.md), against a fake hub.

Held entities must read stale on BOTH REST paths -- the single-entity GET and the bulk
GET /api/states -- while every other entity in the listing stays current; with no hold the
listing passes through untouched, and reset_ctl ends the hold.
"""
import importlib.util
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "ha_delay_proxy", Path(__file__).resolve().parent.parent / "scripts" / "ha_delay_proxy.py")
proxy_mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(proxy_mod)

DOOR, HELPER, LOCK = "binary_sensor.front_door_contact", "input_boolean.front_door_open", "lock.front_door"


@pytest.fixture(autouse=True)
def _private_log(tmp_path, monkeypatch):
    """The proxy appends to results/attack_proxy.log, the record of real runs; a test must not.
    Until 2026-10-02 it did, and six test runs had left 30 lines there (since removed)."""
    monkeypatch.setattr(proxy_mod, "LOG_PATH", tmp_path / "attack_proxy.log")


@pytest.fixture()
def stack():
    world = {DOOR: "off", HELPER: "off", LOCK: "unlocked"}

    class Hub(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/api/states":
                body = [{"entity_id": e, "state": v} for e, v in world.items()]
            else:
                e = self.path.rsplit("/", 1)[1]
                body = {"entity_id": e, "state": world[e]}
            raw = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    hub = ThreadingHTTPServer(("127.0.0.1", 0), Hub)
    prx = proxy_mod.Proxy(("127.0.0.1", 0), f"http://127.0.0.1:{hub.server_port}")
    for srv in (hub, prx):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{prx.server_port}"

    def get(path):
        with urllib.request.urlopen(base + path, timeout=5) as r:
            return json.loads(r.read())

    def ctl(op, **body):
        req = urllib.request.Request(base + f"/__ctl__/{op}", data=json.dumps(body).encode(), method="POST")
        urllib.request.urlopen(req, timeout=5).read()

    yield world, get, ctl
    hub.shutdown()
    prx.shutdown()


def _states(listing):
    return {r["entity_id"]: r["state"] for r in listing}


def test_no_hold_passes_listing_through(stack):
    world, get, _ = stack
    world[DOOR] = "on"
    assert _states(get("/api/states"))[DOOR] == "on"
    assert get("/__ctl__/stats")["spliced"] == 0


def test_held_entities_stale_on_both_paths_others_current(stack):
    world, get, ctl = stack
    ctl("hold_entities", entities=[DOOR, HELPER])      # captured while the door is closed
    world.update({DOOR: "on", HELPER: "on", LOCK: "locked"})
    listing = _states(get("/api/states"))
    assert listing[DOOR] == "off" and listing[HELPER] == "off"   # held on the bulk path
    assert listing[LOCK] == "locked"                              # everything else is current
    assert get(f"/api/states/{DOOR}")["state"] == "off"          # held on the single-entity path
    assert get(f"/api/states/{LOCK}")["state"] == "locked"
    st = get("/__ctl__/stats")
    assert st["spliced"] == 1 and st["stale"] == 2


def test_reset_ends_the_hold(stack):
    world, get, ctl = stack
    ctl("hold_entities", entities=[DOOR, HELPER])
    world[DOOR] = "on"
    ctl("reset_ctl")
    assert _states(get("/api/states"))[DOOR] == "on"
    assert get(f"/api/states/{DOOR}")["state"] == "on"
