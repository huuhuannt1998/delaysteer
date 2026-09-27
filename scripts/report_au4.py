#!/usr/bin/env python3
"""Summarize AU4 (cooldown correction suppression). Plan: results/au4_plan.md.

  python3 scripts/report_au4.py
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from report_au1_event_wake import fisher_two_sided, wilson  # noqa: E402


def load(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()] if path.exists() else []


def main() -> int:
    rows = [r for r in load(ROOT / "results/au4_cooldown.jsonl") if not r.get("error")]
    errs = [r for r in load(ROOT / "results/au4_cooldown.jsonl") if r.get("error")]
    by = defaultdict(list)
    for r in rows:
        by[r["arm"]].append(r)
    out = []
    for arm in ("attack", "benign", "natural"):
        rs = by.get(arm, [])
        k = sum(bool(r["correction_suppressed"]) for r in rs)
        lo, hi = wilson(k, len(rs))
        out.append({"arm": arm, "n": len(rs), "suppressed": k, "wilson95": f"{lo}-{hi}",
                    "hold_s": rs[0]["hold_s"] if rs else "", "reopen_s": rs[0]["reopen_s"] if rs else "",
                    "e1_forwarded_after_s_max": max((r["e1_forwarded_after_s"] for r in rs), default="")})
        print(f"{arm:8s} n={len(rs):2d} suppressed={k:2d} [{lo},{hi}]  hold={out[-1]['hold_s']} reopen={out[-1]['reopen_s']}")
    a, b = by.get("attack", []), by.get("benign", [])
    if a and b:
        ka, kb = sum(r["correction_suppressed"] for r in a), sum(r["correction_suppressed"] for r in b)
        print(f"attack vs benign: {ka}/{len(a)} vs {kb}/{len(b)}, Fisher two-sided p={fisher_two_sided(ka, len(a), kb, len(b)):.2g}")
    print(f"errors: {len(errs)}")

    sweep = [r for r in load(ROOT / "results/au4_hold_sweep.jsonl") if not r.get("error")]
    sw = defaultdict(list)
    for r in sweep:
        sw[r["hold_s"]].append(r)
    print("\nhold sweep (reopen at t0+40 s, window 30 s):")
    srows = []
    for h in sorted(sw):
        k = sum(r["correction_suppressed"] for r in sw[h])
        srows.append({"hold_s": h, "n": len(sw[h]), "suppressed": k})
        print(f"  hold {h:5.1f} s: suppressed {k}/{len(sw[h])}")

    with (ROOT / "results/au4_cooldown_summary.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    if srows:
        with (ROOT / "results/au4_hold_sweep_summary.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["hold_s", "n", "suppressed"])
            w.writeheader()
            w.writerows(srows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
