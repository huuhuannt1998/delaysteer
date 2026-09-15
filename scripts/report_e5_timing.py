#!/usr/bin/env python3
"""Render the E5 timing collection into a report, and check it against the guard's constants.

The point of the collection is not the table: it is whether the constants the defence is
configured with survive contact with a measured path. ``Config.poll_rtt_s`` is the tolerance the
active-poll challenge allows between forcing an affirmation and reading it back, and it is
currently a spec-derived 50 ms. If a real path's round trip exceeds it, a genuinely fresh
re-read is judged replayed and the guard false-blocks -- a deployability failure the modelled
number cannot show.

  .venv/bin/python scripts/report_e5_timing.py
"""
from __future__ import annotations

import csv
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def pct(xs: list[float], q: float) -> float:
    s = sorted(xs)
    return s[min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))]


def main() -> int:
    from delaysteer.config import Config

    rtt_p = ROOT / "results" / "e5_timing_read_rtt.csv"
    if not rtt_p.exists():
        print("no collection yet", file=sys.stderr)
        return 2
    rows = list(csv.DictReader(open(rtt_p)))
    by: dict[str, list[float]] = {}
    fails: dict[str, int] = {}
    for r in rows:
        by.setdefault(r["platform"], [])
        fails.setdefault(r["platform"], 0)
        if r["ok"] == "1":
            by[r["platform"]].append(float(r["rtt_s"]))
        else:
            fails[r["platform"]] += 1

    ev_p = ROOT / "results" / "e5_timing_events.csv"
    n_ev = sum(1 for _ in csv.DictReader(open(ev_p))) if ev_p.exists() else 0

    cfg = Config()
    poll_rtt = cfg.poll_rtt_s
    hb = cfg.heartbeat_s

    span_h = 0.0
    if rows:
        span_h = (float(rows[-1]["t_wall"]) - float(rows[0]["t_wall"])) / 3600.0

    L = []
    L.append("# E5 (partial) — measured path timing, and what it does to the guard's constants\n")
    L.append("`scripts/run_e5_timing_traces.py` · `scripts/report_e5_timing.py` · 2026-09-10\n")
    L.append("## What this can and cannot replace\n")
    L.append("The plan asks for benign device timing traces so the detector's ~27 s ceiling stops "
             "resting on a modelled inter-arrival distribution. **It still does.** This machine has "
             "no Zigbee, Z-Wave or Matter radio, so a benign *sensor report* distribution cannot be "
             "measured here, and §8.7 now labels that figure as a property of the model. What is "
             "measured below is the other timing quantity the defence depends on and currently "
             "takes from a spec: the **read round trip** on a local hub path and on a real "
             "cloud path.\n")
    L.append(f"Collection: {len(rows)} reads over {span_h:.1f} h.\n")
    L.append("## Read round trip\n")
    L.append("| path | n | median | P95 | P99 | max | failed reads |")
    L.append("|---|---|---|---|---|---|---|")
    for plat, xs in sorted(by.items()):
        if not xs:
            continue
        L.append(f"| {plat} | {len(xs)} | {statistics.median(xs)*1000:.1f} ms | "
                 f"{pct(xs,0.95)*1000:.1f} ms | {pct(xs,0.99)*1000:.1f} ms | "
                 f"{max(xs)*1000:.1f} ms | {fails[plat]} |")
    L.append("")

    L.append("## The finding: a configured constant that a real cloud path violates\n")
    L.append(f"The active-poll challenge admits a re-read only if its value-age is within "
             f"`poll_rtt_s` = **{poll_rtt*1000:.0f} ms** (`delaysteer/config.py`); the passive "
             f"variant uses `heartbeat_s` = {hb*1000:.0f} ms.\n")
    cloud = by.get("smartthings_cloud") or []
    local = by.get("home_assistant") or []
    if cloud:
        med = statistics.median(cloud)
        over = sum(1 for x in cloud if x > poll_rtt) / len(cloud)
        L.append(f"- **Cloud path**: median {med*1000:.0f} ms, which is "
                 f"{med/poll_rtt:.1f}x the configured tolerance; "
                 f"**{over*100:.1f}%** of reads exceed it. On that path an active poll that "
                 f"succeeds is judged *replayed*, so the guard false-blocks a genuinely fresh "
                 f"re-read. The tolerance is a per-path quantity and cannot be one constant.")
    if local:
        med = statistics.median(local)
        over = sum(1 for x in local if x > poll_rtt) / len(local)
        L.append(f"- **Local hub path**: median {med*1000:.1f} ms, "
                 f"{med/poll_rtt:.2f}x the tolerance; {over*100:.1f}% of reads exceed it. "
                 f"The constant is defensible here, which is why the defect did not surface in "
                 f"the local deployment.")
    if cloud and local:
        L.append(f"- The two paths differ by **{statistics.median(cloud)/statistics.median(local):.0f}x** "
                 f"in the median, on the same machine at the same time.")
    L.append("")
    L.append("## Event cadence\n")
    L.append(f"State changes observed: **{n_ev}**. The live deployment's entities are "
             "template- and helper-backed, so they do not report spontaneously; this collection "
             "therefore says nothing about benign inter-arrival, and no claim is made from it. "
             "That measurement needs hardware.\n")
    L.append("## Caveats\n")
    L.append("- One host's clock throughout; the local figure includes Docker's port forward and "
             "no network beyond loopback.\n"
             "- The cloud figure is one account, one region, one device class, over the collection "
             "window; it is a real path, not a representative survey of cloud platforms.\n"
             "- Read RTT is not the same quantity as a sensor's benign inter-arrival time. The "
             "paper's detector argument depends on the latter and remains modelled.")

    out = ROOT / "results" / "e5_timing_REPORT.md"
    out.write_text("\n".join(L) + "\n")
    print("\n".join(L[-14:]))
    print(f"\n-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
