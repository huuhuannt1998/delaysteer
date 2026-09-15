"""Reviewer R2 ablation: does a capable LLM agent SHOWN the staleness still get steered?

The cross-model study exposes only raw generation/arrival timestamps to the planner.
The pivotal reviewer objection is that "no capability gap" is true by construction: no
agent can reject staleness it is never explicitly shown. This ablation surfaces an
explicit per-observation age_s and a stale flag, plus a prompt clause telling the agent
to re-read or distrust a stale reading, then re-measures the contradiction violation
rate. If the rate stays high, the attack survives even an agent explicitly told the
reading is stale -- "no capability gap" becomes measured, not asserted.

Contact_contradiction cell, no guard (the attack alone), on the virtual home. Two
conditions per model (baseline = default prompt; surfaced = explicit staleness), same
seeds. Additive: results/stale_ablation.csv; frozen metrics.csv untouched.

  python -m delaysteer.run_stale_ablation
"""

from __future__ import annotations

import csv
import json
import math
import urllib.request
from pathlib import Path

from .run_m2 import run_cell
from delaysteer.runtime import resolve_temperature

MODELS = [("qwen3:14b", 20), ("qwen2.5:7b", 15)]  # (model, repeats); agent of record + a second capable model
CONDITIONS = [("baseline", False), ("surfaced", True)]
HOLD = 4          # same stale-hold as the frozen cross-model study
TEMPERATURE = resolve_temperature()
ROWS: list[dict] = []


def wilson(k, n):
    if n == 0:
        return (0, 0)
    z = 1.96
    p = k / n
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (round(100 * max(0.0, c - h)), round(100 * min(1.0, c + h)))


def preload(model):
    body = json.dumps({"model": model, "keep_alive": "40m", "prompt": "ok",
                       "stream": False, "options": {"num_predict": 1}}).encode()
    try:
        urllib.request.urlopen("http://localhost:11434/api/generate", body, timeout=240)
        print(f"[preload] pinned {model}", flush=True)
    except Exception as e:
        print(f"[preload] warn: {e}", flush=True)


def main() -> int:
    out = Path("results"); out.mkdir(exist_ok=True)
    print("=== R2 ablation: surfaced staleness vs baseline (contact_contradiction, no guard) ===", flush=True)
    for model, reps in MODELS:
        preload(model)
        for cond, surface in CONDITIONS:
            viol = secure = loop = 0
            for i in range(reps):
                tag = f"stale_{model.replace(':','_').replace('.','')}_{cond}_{i}"
                r = run_cell(model, "contact_contradiction", "none", HOLD, tag, "virtual",
                             seed=i, temperature=TEMPERATURE, surface_staleness=surface)
                viol += int(r["violation"]); secure += int(r["secure_claim"])
                loop += int(r["steps"] >= 24)
                print(f"    {model}/{cond} run {i+1}/{reps}: viol={int(r['violation'])} "
                      f"secure={int(r['secure_claim'])} steps={r['steps']} ({viol}/{i+1})", flush=True)
            lo, hi = wilson(viol, reps)
            row = {"model": model, "condition": cond, "surfaced": surface,
                   "repeats": reps, "violations": viol, "violation_rate": f"{viol}/{reps}",
                   "wilson95": f"[{lo},{hi}]", "secure_rate": f"{secure}/{reps}",
                   "loop_rate": f"{loop}/{reps}"}
            ROWS.append(row)
            print(f"  [CELL] {model}/{cond}: viol {row['violation_rate']} {row['wilson95']} "
                  f"loop {row['loop_rate']}", flush=True)
            with (out / "stale_ablation.csv").open("w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(ROWS[0].keys()))
                w.writeheader(); w.writerows(ROWS)
    (out / "stale_ablation.json").write_text(json.dumps(ROWS, indent=2))
    print("\n=== SUMMARY ===", flush=True)
    for r in ROWS:
        print(f"  {r['model']:<14}{r['condition']:<10}{r['violation_rate']:<8}{r['wilson95']}", flush=True)
    print(f"\nwrote results/stale_ablation.csv ({len(ROWS)} cells)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
