"""Reviewer (Systems P7): planner-side freshness heuristic vs the gate, head-to-head
across all four attack families for the agent of record.

The gate-vs-planner question the paper's architecture rests on: does surfacing
observation age to the planner (a freshness *heuristic* -- show each observation's
age_s + a stale flag + a "re-read or distrust a stale reading" prompt clause, with NO
guard) defend as well as enforcing freshness at the gate? The stale-contact
contradiction family is already in results/stale_ablation.csv (qwen3 none 16/20 ->
surfaced 1/20 -> full 0/20; qwen2.5 19/20 -> surfaced 19/20 -> full 0/20). This adds the
surfaced (planner-heuristic) condition for the other three families -- access,
confirmation, automation -- at n=20 for the agent of record, so the head-to-head is
complete over all four families. Compare against results/family_rates_n20.csv (none
20/20, full 0/20 per family). Additive: results/planner_heuristic.csv; frozen
metrics.csv untouched.

  python -m delaysteer.run_planner_heuristic
"""
from __future__ import annotations

import csv
import json
import math
from pathlib import Path

from .config import Config
from .run_automation import run_auto
from .run_confirm import run_confirm
from .run_repair import run_repair
from .runtime import resolve_temperature

MODEL = "qwen3:14b"
REPEATS = 20
TEMPERATURE = resolve_temperature()
FAMILIES = ["access", "confirmation", "automation"]
ROWS: list[dict] = []


def wilson(k, n):
    if n == 0:
        return (0, 0)
    z = 1.96
    p = k / n
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (round(100 * max(0.0, c - h)), round(100 * min(1.0, c + h)))


def _call(family, label, seed):
    # surfaced planner-heuristic: NO guard (ablation=none) + surface_staleness=True
    if family == "access":
        return run_repair("virtual", False, True, "none", False, label,
                          model=MODEL, temperature=TEMPERATURE, seed=seed, surface_staleness=True)
    if family == "confirmation":
        return run_confirm("virtual", False, True, "none", False, label,
                           model=MODEL, temperature=TEMPERATURE, seed=seed, surface_staleness=True)
    if family == "automation":
        return run_auto("virtual", True, "none", label,
                        model=MODEL, temperature=TEMPERATURE, seed=seed, surface_staleness=True)
    raise ValueError(family)


def main() -> int:
    cap = Config().max_react_steps
    out = Path("results"); out.mkdir(exist_ok=True)
    print(f"=== P7 planner-heuristic (surfaced age, NO guard) across families, {MODEL}, n={REPEATS} ===", flush=True)
    for fam in FAMILIES:
        viol = loop = 0
        for i in range(REPEATS):
            tag = f"ph_{fam[:4]}_{i}"
            r = _call(fam, tag, i)
            viol += int(r["violation"])
            loop += int(r["steps"] >= cap)
            print(f"    {fam} run {i+1}/{REPEATS}: viol={int(r['violation'])} "
                  f"steps={r['steps']} ({viol}/{i+1})", flush=True)
        lo, hi = wilson(viol, REPEATS)
        row = {"model": MODEL, "family": fam, "condition": "surfaced", "repeats": REPEATS,
               "violation_rate": f"{viol}/{REPEATS}", "wilson95": f"[{lo},{hi}]",
               "loop_rate": f"{loop}/{REPEATS}"}
        ROWS.append(row)
        print(f"  [CELL] {fam}/surfaced: viol {row['violation_rate']} {row['wilson95']}", flush=True)
        with (out / "planner_heuristic.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(ROWS[0].keys()))
            w.writeheader(); w.writerows(ROWS)
    (out / "planner_heuristic.json").write_text(json.dumps(ROWS, indent=2))
    print("\n=== SUMMARY (surfaced planner-heuristic, no guard) ===", flush=True)
    for r in ROWS:
        print(f"  {r['family']:<14}{r['violation_rate']:<8}{r['wilson95']}", flush=True)
    print(f"\nwrote results/planner_heuristic.csv ({len(ROWS)} cells)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
