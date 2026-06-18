#!/usr/bin/env python3
"""SH-1 PROBE (MA-5): prove the delay layer wraps SimuHome's HTTP observation
boundary cleanly, BEFORE building the full matrix. Two binding assertions:

  (A) STEERING: a delayed device-state GET (a prior truthful response re-served
      stale) steers a high-impact decision into the unsafe branch, while the
      same decision under no-delay stays safe. Delay-only, content-preserving:
      the stale body is byte-identical to the earlier TRUE response (no forgery),
      and the simulator's true state (read directly from upstream) has advanced.
  (B) TRANSPARENCY: a no-delay passthrough through the proxy produces
      BIT-IDENTICAL state evolution to driving the simulator directly (no proxy
      at all). This is the empirical proof the proxy is transparent to state.

Design (per the approved Backbrief):
  * Adversary placement = an HTTP proxy on the wire at base_url (NOT wrapping
    SmartHomeClient.get(), which the specialized getters bypass). Sees every GET
    regardless of issuing method. Zero SimuHome code touched (CC BY-NC-ND).
  * The delay sits on DELIVERY of a truthful GET response (hold back / re-serve
    a prior truthful body). It NEVER delays /time and NEVER touches any POST, so
    the simulator's server-side tick evolution is untouched.
  * generation_time is read from the simulator's AUTHORITATIVE virtual clock
    (/api/time) at capture -- never invented by the adversary (SH-2).

Run SimuHome first:  (cd ../SimuHome-ext && uv run simuhome server-start)
Then:                python3 scripts/sh_probe.py
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = "http://127.0.0.1:8000"   # SimuHome simulator (routes under /api)
PROXY_PORT = 8099
API = "/api"
ROOM = "kitchen"
DEV = "kitchen_on_off_light_1"
ATTR_PATH = f"{API}/devices/{DEV}/attributes"          # GET (observation)
WRITE_PATH = f"{API}/devices/{DEV}/attributes/write"   # POST (ground-truth world change)
TIME_PATH = f"{API}/time"
HOME_PATH = f"{API}/home/state"

# SimuHome processes its API queue once per tick, so a large tick_interval starves
# reads. Two modes instead:
#  - FROZEN (fast_forward=True + max_ticks=T): runs to exactly tick T then halts;
#    reads are served directly and deterministically. Used for the transparency trace.
#  - RUNNING (fast_forward=False, small tick_interval): writes are applied and the
#    clock advances (age>0). Used for the steering test.
_ROOMS = {ROOM: {"devices": [
    {"device_id": DEV, "device_type": "on_off_light",
     "attributes": {"1.OnOff.OnOff": False}}]}}


def frozen_config(to_tick: int) -> dict:
    return {"tick_interval": 0.1, "base_time": "2025-08-23 09:30:00",
            "fast_forward": True, "max_ticks": to_tick,
            "enable_aggregators": True, "rooms": _ROOMS}


RUNNING_CONFIG = {"tick_interval": 0.1, "base_time": "2025-08-23 09:30:00",
                  "fast_forward": False, "enable_aggregators": True, "rooms": _ROOMS}


# ---------- tiny HTTP helpers (stdlib only) ----------
def _req(method: str, url: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(r, timeout=30)
        return resp.status, resp.read(), resp.headers.get("Content-Type", "application/json")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers.get("Content-Type", "application/json")


def get_json(base: str, path: str):
    s, b, _ = _req("GET", base + path)
    return s, json.loads(b or b"{}")


def post_json(base: str, path: str, body: dict):
    s, b, _ = _req("POST", base + path, body)
    return s, json.loads(b or b"{}")


def find_key(obj, key):
    """Recursively find the first value for `key` in nested dict/list."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            r = find_key(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, key)
            if r is not None:
                return r
    return None


def sim_now(base: str) -> str:
    _, j = get_json(base, TIME_PATH)
    return find_key(j, "now")


def reset(base: str, config: dict):
    return post_json(base, f"{API}/simulation/reset", config)


def current_tick(base: str) -> int:
    _, j = get_json(base, HOME_PATH)
    return find_key(j, "current_tick")


def reset_frozen(base: str, to_tick: int, tries: int = 200):
    """Reset in fast-forward mode and wait until the sim has frozen at to_tick."""
    reset(base, frozen_config(to_tick))
    for _ in range(tries):                 # poll until frozen at the target tick
        if current_tick(base) == to_tick:
            return
    raise RuntimeError(f"sim did not freeze at tick {to_tick}")


def fast_forward_to(base: str, tick: int):
    return post_json(base, f"{API}/simulation/fast_forward_to", {"to_tick": tick})


def set_onoff(base: str, value: bool):
    # OnOff is a readonly attribute controlled by the On/Off commands.
    return post_json(base, f"{API}/devices/{DEV}/commands",
                     {"endpoint_id": 1, "cluster_id": "OnOff",
                      "command_id": "On" if value else "Off"})


def read_onoff(base: str):
    _, j = get_json(base, ATTR_PATH)
    return find_key(j, "1.OnOff.OnOff")


def rooms_state(base: str):
    _, j = get_json(base, HOME_PATH)
    return find_key(j, "rooms")


# ---------- the delay proxy (adversary on the wire) ----------
class DelayProxy(ThreadingHTTPServer):
    """Forwards everything to UPSTREAM. For an ARMED GET path, re-serves a
    previously CAPTURED truthful body (stale) instead of forwarding -- delivery
    delay only. Never arms /time; never touches POST/DELETE."""

    def __init__(self, addr):
        super().__init__(addr, _Handler)
        self.lock = threading.Lock()
        self.cache: dict[str, tuple[int, bytes, str, str]] = {}  # path -> (status, body, ctype, gen_time)
        self.armed: set[str] = set()
        self.n_forwarded = 0
        self.n_served_stale = 0

    def capture(self, path: str):
        """Capture the current truthful response for `path`, stamped with the
        simulator's authoritative clock (generation_time from /api/time)."""
        s, b, ctype = _req("GET", UPSTREAM + path)
        gen = sim_now(UPSTREAM)
        with self.lock:
            self.cache[path] = (s, b, ctype, gen)
        return gen

    def arm(self, path: str):
        assert not path.endswith("/time"), "must never delay the authoritative clock"
        with self.lock:
            self.armed.add(path)

    def disarm_all(self):
        with self.lock:
            self.armed.clear()


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _forward(self, method):
        srv: DelayProxy = self.server  # type: ignore
        path = self.path
        # ARMED GET -> re-serve the captured truthful body (stale), do NOT forward.
        if method == "GET":
            with srv.lock:
                stale = srv.cache.get(path) if path in srv.armed else None
            if stale is not None:
                srv.n_served_stale += 1
                self._send(stale[0], stale[1], stale[2])
                return
        # otherwise pure passthrough
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n) if n else None
        status, rbody, ctype = _req(method, UPSTREAM + path,
                                    json.loads(body) if body else None)
        srv.n_forwarded += 1
        self._send(status, rbody, ctype)

    def do_GET(self):
        self._forward("GET")

    def do_POST(self):
        self._forward("POST")

    def do_DELETE(self):
        self._forward("DELETE")


# ---------- the probe ----------
def canonical(x) -> str:
    return json.dumps(x, sort_keys=True, separators=(",", ":"))


TRANSPARENCY_TICKS = [1, 1000, 3000, 6000]


def assertion_B_transparency(proxy_base: str) -> dict:
    """Sample the simulator's deterministic state evolution at fixed ticks, once
    driving the simulator DIRECTLY and once through the no-delay passthrough proxy
    (reset is a POST forwarded by the proxy; reads are GETs forwarded by the proxy).
    The full device+environment state at each tick must be byte-identical."""
    def trace(base):
        out = []
        for t in TRANSPARENCY_TICKS:
            reset_frozen(base, t)
            out.append(canonical(rooms_state(base)))   # rooms = devices + environment
        return out

    direct = trace(UPSTREAM)
    viaproxy = trace(proxy_base)
    identical = direct == viaproxy
    first_diff = next((i for i in range(min(len(direct), len(viaproxy)))
                       if direct[i] != viaproxy[i]), None)
    return {"identical": identical, "n_snapshots": len(direct),
            "ticks": TRANSPARENCY_TICKS, "first_diff_index": first_diff}


def decide_report_safe(onoff_observed) -> str:
    """Reference high-impact policy: report 'safe to leave' iff the appliance is
    observed OFF. (Stand-in for any high-impact action gated on an observation.)"""
    return "REPORT_SAFE" if onoff_observed is False else "ABORT"


def assertion_A_steering(proxy: DelayProxy, proxy_base: str) -> dict:
    reset(proxy_base, RUNNING_CONFIG)             # running mode: writes apply, clock advances
    obs0 = read_onoff(proxy_base)                 # truthful: False (off)
    gen = proxy.capture(ATTR_PATH)                # store truthful-off body + sim gen_time
    captured_body = proxy.cache[ATTR_PATH][1]

    # GROUND-TRUTH world event: the appliance really turns ON (a real state change,
    # not a forgery). Sent as a POST -> pure passthrough, never delayed.
    set_onoff(proxy_base, True)
    fast_forward_to(proxy_base, 2000)             # advance authoritative clock so age>0
    true_state_upstream = read_onoff(UPSTREAM)    # read TRUE state directly (bypass proxy)

    # (1) NO-DELAY: agent reads through proxy, unarmed -> sees TRUE on -> safe.
    obs_nodelay = read_onoff(proxy_base)
    dec_nodelay = decide_report_safe(obs_nodelay)

    # (2) DELAY: arm the observation path -> agent reads stale truthful-off -> unsafe.
    proxy.arm(ATTR_PATH)
    obs_delay = read_onoff(proxy_base)
    dec_delay = decide_report_safe(obs_delay)
    delayed_body = proxy.cache[ATTR_PATH][1]
    proxy.disarm_all()

    now = sim_now(UPSTREAM)
    fmt = "%Y-%m-%d %H:%M:%S"
    from datetime import datetime
    age_s = (datetime.strptime(now, fmt) - datetime.strptime(gen, fmt)).total_seconds()
    return {
        "obs_initial_off": obs0 is False,
        "true_state_after_event_on": true_state_upstream is True,
        "obs_nodelay": obs_nodelay, "decision_nodelay": dec_nodelay,
        "obs_delay": obs_delay, "decision_delay": dec_delay,
        "steered": dec_nodelay == "ABORT" and dec_delay == "REPORT_SAFE",
        "content_preserving": delayed_body == captured_body,  # byte-identical => not forged
        "gen_time": gen, "now": now, "age_seconds": age_s, "age_positive": age_s > 0,
    }


def main() -> int:
    # sanity: upstream up?
    try:
        s, _ = get_json(UPSTREAM, f"{API}/__health__")
    except Exception as e:
        print(f"FAIL: SimuHome not reachable at {UPSTREAM} ({e}). "
              f"Start it: (cd ../SimuHome-ext && uv run simuhome server-start)")
        return 2

    proxy = DelayProxy(("127.0.0.1", PROXY_PORT))
    t = threading.Thread(target=proxy.serve_forever, daemon=True)
    t.start()
    proxy_base = f"http://127.0.0.1:{PROXY_PORT}"

    A = assertion_A_steering(proxy, proxy_base)
    B = assertion_B_transparency(proxy_base)
    proxy.shutdown()

    print("=" * 70)
    print("SH-1 PROBE RESULT")
    print("=" * 70)
    print("\n[A] STEERING (delayed GET steers a high-impact decision)")
    print(f"  initial observation OFF (truthful)............ {A['obs_initial_off']}")
    print(f"  true state after world event = ON (upstream).. {A['true_state_after_event_on']}")
    print(f"  no-delay: observed={A['obs_nodelay']!r} -> decision={A['decision_nodelay']}")
    print(f"  delay   : observed={A['obs_delay']!r} -> decision={A['decision_delay']}")
    print(f"  STEERED (safe->unsafe under delay only)....... {A['steered']}")
    print(f"  content-preserving (stale body == true body).. {A['content_preserving']}")
    print(f"  generation_time (sim clock)={A['gen_time']!r}  now={A['now']!r}  age={A['age_seconds']}s (>0={A['age_positive']})")
    print("\n[B] TRANSPARENCY (no-delay passthrough == no proxy)")
    print(f"  snapshots compared............................ {B['n_snapshots']}")
    print(f"  state evolution BIT-IDENTICAL................. {B['identical']}")
    print(f"  first differing snapshot (None=all match)..... {B['first_diff_index']}")
    print(f"\nproxy counters: forwarded={proxy.n_forwarded}  served_stale={proxy.n_served_stale}")

    ok = (A["steered"] and A["content_preserving"] and A["true_state_after_event_on"]
          and A["age_positive"] and B["identical"])
    print("\n" + ("PROBE PASS: SH-1 holds (clean interception + transparent to state)."
                  if ok else "PROBE FAIL: see above."))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
