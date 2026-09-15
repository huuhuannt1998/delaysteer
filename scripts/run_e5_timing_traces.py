#!/usr/bin/env python3
"""E5 (partial) -- measured timing on the paths this machine actually has.

The plan asks for benign timing traces from a heterogeneous device set so the
detector's ceiling stops resting on a modelled benign inter-arrival distribution.
This machine has NO Zigbee/Z-Wave/Matter radio, so the sensor inter-arrival
distribution CANNOT be measured here and the paper's ~27 s ceiling stays modelled
and labelled as such. What can be measured, and is measured here, are the two real
path quantities the defence depends on:

  read RTT        the guard's commit-time revalidation read against live Home
                  Assistant (local path) and, when a token is configured, against
                  the SmartThings cloud (cloud-backed path). This is the paper's
                  poll round-trip, currently a spec-derived constant.
  event cadence   observed state-change inter-arrival per entity on each platform,
                  i.e. how often a fact is re-affirmed in practice. For the
                  template-backed entities on this deployment this is a property of
                  the deployment, not of a radio, and is reported that way.

Long unattended collection is the point: --hours 6 --interval 15 samples each path
every 15 s for six hours. Writes NEW files only.

  results/e5_timing_read_rtt.csv     one row per read
  results/e5_timing_events.csv       one row per observed state change
  results/e5_timing_summary.csv      per path: n, median, P95, P99, max

  .venv/bin/python scripts/run_e5_timing_traces.py --hours 6 --interval 15
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _env(key: str) -> str | None:
    env = ROOT / ".env"
    if not env.exists():
        return None
    for line in env.read_text().splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


HA_URL = (_env("HASS_URL") or "http://localhost:8123").rstrip("/")
HA_TOKEN = _env("HASS_TOKEN")
ST_TOKEN = _env("SMARTTHINGS_TOKEN")

# The facts the paper's contracts actually depend on, plus one cloud-backed path.
HA_ENTITIES = [
    "binary_sensor.front_door_contact",
    "lock.front_door",
    "alarm_control_panel.home_alarm",
    "binary_sensor.front_porch_camera_motion",
    "sensor.living_room_temperature",
]


def ha_get(path: str, timeout: float = 10.0):
    req = urllib.request.Request(HA_URL + path,
                                 headers={"Authorization": f"Bearer {HA_TOKEN}"})
    return json.load(urllib.request.urlopen(req, timeout=timeout))


def st_get(path: str, timeout: float = 15.0):
    req = urllib.request.Request("https://api.smartthings.com/v1" + path,
                                 headers={"Authorization": f"Bearer {ST_TOKEN}"})
    return json.load(urllib.request.urlopen(req, timeout=timeout))


def percentile(xs: list[float], q: float) -> float:
    if not xs:
        return float("nan")
    s = sorted(xs)
    i = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
    return s[i]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--hours", type=float, default=6.0)
    ap.add_argument("--interval", type=float, default=15.0, help="seconds between sweeps")
    ap.add_argument("--out", default="results/e5_timing")
    ap.add_argument("--skip-smartthings", action="store_true")
    a = ap.parse_args()

    if not HA_TOKEN:
        print("HASS_TOKEN not set; nothing to measure.", file=sys.stderr)
        return 2

    st_devices: list[dict] = []
    if ST_TOKEN and not a.skip_smartthings:
        try:
            st_devices = st_get("/devices").get("items", [])[:4]
            print(f"SmartThings: {len(st_devices)} device(s) on the cloud path")
        except Exception as exc:                     # token expiry is the usual cause
            print(f"SmartThings unavailable ({exc.__class__.__name__}): "
                  f"cloud path will be absent from this run")

    rtt_path = Path(f"{a.out}_read_rtt.csv")
    ev_path = Path(f"{a.out}_events.csv")
    rtt_path.parent.mkdir(parents=True, exist_ok=True)
    rtt_f = open(rtt_path, "w", newline="")
    ev_f = open(ev_path, "w", newline="")
    rtt = csv.DictWriter(rtt_f, fieldnames=["t_wall", "platform", "entity", "rtt_s", "ok"])
    ev = csv.DictWriter(ev_f, fieldnames=["t_wall", "platform", "entity", "value",
                                          "last_changed", "inter_arrival_s"])
    rtt.writeheader()
    ev.writeheader()

    last_change: dict[str, str] = {}
    rtts: dict[str, list[float]] = {}
    inters: dict[str, list[float]] = {}
    deadline = time.time() + a.hours * 3600
    sweeps = 0

    while time.time() < deadline:
        for e in HA_ENTITIES:
            t0 = time.perf_counter()
            ok, st = 1, None
            try:
                st = ha_get(f"/api/states/{e}")
            except Exception:
                ok = 0
            dt = time.perf_counter() - t0
            rtt.writerow({"t_wall": time.time(), "platform": "home_assistant",
                          "entity": e, "rtt_s": round(dt, 6), "ok": ok})
            rtts.setdefault("home_assistant", []).append(dt)
            if ok and st:
                lc = st.get("last_changed") or ""
                if lc and last_change.get(e) and lc != last_change[e]:
                    prev, cur = last_change[e], lc
                    try:
                        from datetime import datetime
                        gap = (datetime.fromisoformat(cur) - datetime.fromisoformat(prev)).total_seconds()
                    except Exception:
                        gap = float("nan")
                    inters.setdefault("home_assistant", []).append(gap)
                    ev.writerow({"t_wall": time.time(), "platform": "home_assistant",
                                 "entity": e, "value": st.get("state"),
                                 "last_changed": lc, "inter_arrival_s": round(gap, 3)})
                last_change[e] = lc

        for d in st_devices:
            did, name = d.get("deviceId"), d.get("label") or d.get("name")
            t0 = time.perf_counter()
            ok = 1
            try:
                st_get(f"/devices/{did}/status")
            except Exception:
                ok = 0
            dt = time.perf_counter() - t0
            rtt.writerow({"t_wall": time.time(), "platform": "smartthings_cloud",
                          "entity": name, "rtt_s": round(dt, 6), "ok": ok})
            rtts.setdefault("smartthings_cloud", []).append(dt)

        rtt_f.flush()
        ev_f.flush()
        sweeps += 1
        time.sleep(a.interval)

    rtt_f.close()
    ev_f.close()

    with open(f"{a.out}_summary.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["path", "quantity", "n", "median_s", "p95_s",
                                           "p99_s", "max_s", "mean_s"])
        w.writeheader()
        for plat, xs in rtts.items():
            w.writerow({"path": plat, "quantity": "read_rtt", "n": len(xs),
                        "median_s": round(statistics.median(xs), 6),
                        "p95_s": round(percentile(xs, 0.95), 6),
                        "p99_s": round(percentile(xs, 0.99), 6),
                        "max_s": round(max(xs), 6),
                        "mean_s": round(statistics.mean(xs), 6)})
        for plat, xs in inters.items():
            xs = [x for x in xs if x == x]
            if xs:
                w.writerow({"path": plat, "quantity": "event_inter_arrival", "n": len(xs),
                            "median_s": round(statistics.median(xs), 3),
                            "p95_s": round(percentile(xs, 0.95), 3),
                            "p99_s": round(percentile(xs, 0.99), 3),
                            "max_s": round(max(xs), 3),
                            "mean_s": round(statistics.mean(xs), 3)})
    print(f"E5: {sweeps} sweeps; rtt -> {rtt_path}, events -> {ev_path}, "
          f"summary -> {a.out}_summary.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
