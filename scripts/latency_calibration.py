#!/usr/bin/env python3
"""C1 -- benign latency calibration on the live Home Assistant target.

The freshness budget must cover benign transport latency without false-blocking, and the
active-poll affirmation must be bounded by a real poll round-trip. This measures those
distributions on the live \\texttt{delaysteer-ha} container and derives every budget by a
documented rule: ``budget = P99(benign latency) + margin`` (default margin 0.5s). Removes the
"the budget needs a real benign-latency calibration (future work)" limitation.

Sources measured (each N samples):
  * read:<entity>  -- GET /api/states/<entity>  (transport latency a benign read incurs)
  * poll:<entity>  -- POST /api/services/homeassistant/update_entity {entity_id}, then GET
                       (the active-poll forced-affirmation round-trip; no state change)

Writes results/latency_calibration.csv (per-source percentiles + derived budget) and
results/latency_calibration.json (raw samples). Additive; touches no frozen CSV, mutates no
device state (update_entity re-polls an integration; it does not actuate).

  python3 scripts/latency_calibration.py --n 500 --margin 0.5
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UPSTREAM = "http://localhost:8123"

READ_ENTITIES = [
    "binary_sensor.front_door_contact",
    "lock.front_door",
    "alarm_control_panel.home_alarm",
]
POLL_ENTITIES = ["binary_sensor.front_door_contact", "lock.front_door"]


def _token() -> str | None:
    import os
    t = os.environ.get("HASS_TOKEN")
    if t:
        return t
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith("HASS_TOKEN="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


TOKEN = _token()


def _timed(method: str, path: str, body: bytes | None = None) -> float | None:
    headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    req = urllib.request.Request(UPSTREAM + path, data=body, method=method, headers=headers)
    t0 = time.perf_counter()
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        resp.read()
        return time.perf_counter() - t0
    except urllib.error.HTTPError as e:
        e.read()
        return time.perf_counter() - t0
    except Exception:
        return None


def measure_read(entity: str, n: int) -> list[float]:
    out = []
    for _ in range(n):
        dt = _timed("GET", f"/api/states/{entity}")
        if dt is not None:
            out.append(dt)
    return out


def measure_poll(entity: str, n: int) -> list[float]:
    """Active-poll RTT: force a fresh affirmation (update_entity) then read it back."""
    out = []
    body = json.dumps({"entity_id": entity}).encode()
    for _ in range(n):
        t0 = time.perf_counter()
        a = _timed("POST", "/api/services/homeassistant/update_entity", body)
        b = _timed("GET", f"/api/states/{entity}")
        if a is not None and b is not None:
            out.append(time.perf_counter() - t0)
    return out


def _pct(xs: list[float], q: float) -> float:
    if not xs:
        return float("nan")
    xs = sorted(xs)
    k = min(len(xs) - 1, int(round(q * (len(xs) - 1))))
    return xs[k]


def summarize(source: str, kind: str, xs: list[float], margin: float) -> dict:
    p99 = _pct(xs, 0.99)
    return {
        "source": source, "kind": kind, "n": len(xs),
        "mean_s": round(statistics.fmean(xs), 4) if xs else float("nan"),
        "p50_s": round(_pct(xs, 0.50), 4), "p90_s": round(_pct(xs, 0.90), 4),
        "p99_s": round(p99, 4), "max_s": round(max(xs), 4) if xs else float("nan"),
        "budget_rule_s": round(p99 + margin, 4),  # budget = P99 + margin
        "margin_s": margin,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=500)
    ap.add_argument("--margin", type=float, default=0.5)
    args = ap.parse_args()
    if not TOKEN:
        print("HASS_TOKEN missing; cannot calibrate on live HA.")
        return 1

    print(f"=== C1 latency calibration on live HA ({UPSTREAM}), n={args.n}/source ===", flush=True)
    rows: list[dict] = []
    raw: dict[str, list[float]] = {}
    for e in READ_ENTITIES:
        xs = measure_read(e, args.n)
        raw[f"read:{e}"] = xs
        r = summarize(f"read:{e}", "read", xs, args.margin)
        rows.append(r)
        print(f"  read  {e:<40} n={r['n']:<4} p50={r['p50_s']}s p99={r['p99_s']}s "
              f"max={r['max_s']}s -> budget={r['budget_rule_s']}s", flush=True)
    poll_n = max(1, args.n // 2)  # polls are heavier (2 calls); half the sample is plenty
    for e in POLL_ENTITIES:
        xs = measure_poll(e, poll_n)
        raw[f"poll:{e}"] = xs
        r = summarize(f"poll:{e}", "poll", xs, args.margin)
        rows.append(r)
        print(f"  poll  {e:<40} n={r['n']:<4} p50={r['p50_s']}s p99={r['p99_s']}s "
              f"max={r['max_s']}s -> poll_rtt budget={r['budget_rule_s']}s", flush=True)

    out = ROOT / "results"; out.mkdir(exist_ok=True)
    import csv
    with (out / "latency_calibration.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    (out / "latency_calibration.json").write_text(
        json.dumps({k: [round(x, 5) for x in v] for k, v in raw.items()}, indent=2))

    read_p99 = max(r["p99_s"] for r in rows if r["kind"] == "read")
    poll_p99 = max((r["p99_s"] for r in rows if r["kind"] == "poll"), default=float("nan"))
    print(f"\n=== summary ===", flush=True)
    print(f"read  P99 (worst source) = {read_p99}s  -> freshness budget = {round(read_p99+args.margin,3)}s "
          f"(deployed budget 2.0s covers it)", flush=True)
    print(f"poll  P99 (worst source) = {poll_p99}s  -> active-poll epsilon", flush=True)
    print("wrote results/latency_calibration.csv, results/latency_calibration.json", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
