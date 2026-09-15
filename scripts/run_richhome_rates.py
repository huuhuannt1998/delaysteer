"""MA-9 Task 2: re-run the rich-home rate cells at n>=20 (agent of record) / n=10
(others), attack + guard modes, with Wilson 95% CIs.

Live-HA campaign: each run invokes scripts/richhome_eval.py (one scenario/mode/model/
seed) as a subprocess and reads the appended verdict. Pre-registered exclusion rule: a
run that ERRORS (non-zero exit or no verdict row) is excluded and re-drawn with a fresh
seed to reach the target n; the actual n and the excluded count k are both reported.
Legitimate agent behavior (loop, refusal, non-completion) is NOT an error -- it counts
as no-violation. Incremental CSV; per-cell n; frozen-safe (writes new files only).

  python scripts/run_richhome_rates.py --dry     # 1 cell x n=3 smoke
  python scripts/run_richhome_rates.py           # full campaign (attack + guard)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import subprocess
import urllib.request
from pathlib import Path


def preload(model):
    """Pin `model` on the GPU (keep-alive) so it loads once per model-block instead of
    reloading each run -- roughly halves per-run wall-time (measured 450s -> 220s)."""
    body = json.dumps({"model": model, "keep_alive": "40m", "prompt": "ok",
                       "stream": False, "options": {"num_predict": 1}}).encode()
    try:
        urllib.request.urlopen("http://localhost:11434/api/generate", body, timeout=240)
        print(f"[preload] pinned {model} (keep_alive 40m)", flush=True)
    except Exception as e:
        print(f"[preload] warn: could not pin {model}: {e}", flush=True)

ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "scripts" / "richhome_eval.py"
# richhome_eval imports the hermes-agent stack, which needs Python 3.10+ (PEP-604
# runtime unions); run it under the hermes venv, not this wrapper's interpreter.
HERMES_PY = os.environ.get("HERMES_PY", "/Users/anonymous/Desktop/hermes-agent/.venv/bin/python")
OUT_JSONL_REL = "results/richhome_n20.jsonl"       # richhome_eval writes ROOT/<--out>
OUT_JSONL = ROOT / OUT_JSONL_REL
OUT_CSV = ROOT / "results" / "richhome_rates_n20.csv"
SCENARIOS = ["secure_house", "garage_armed", "multidoor", "leak_appliance"]
MODELS = [("qwen3:14b", 20), ("mistral:7b", 10), ("deepseek-coder-v2:16b", 10)]
MODES = ["attack", "guard"]


def wilson(k, n):
    if n == 0:
        return (0, 0)
    z = 1.96
    p = k / n
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (round(100 * max(0.0, c - h)), round(100 * min(1.0, c + h)))


def _nlines(p):
    return sum(1 for _ in p.open()) if p.exists() else 0


def _last_row(p):
    with p.open() as f:
        return json.loads(f.readlines()[-1])


def run_cell(scenario, mode, model, target, rows):
    viol = done = err = 0
    seed = 1
    used_seeds = []
    cap = target * 3  # bound re-draws so a persistently-erroring cell can't loop forever
    while done < target and seed <= cap:
        before = _nlines(OUT_JSONL)
        try:
            rc = subprocess.run(
                [HERMES_PY, str(EVAL), "--scenario", scenario, "--mode", mode,
                 "--model", model, "--seed", str(seed), "--out", OUT_JSONL_REL],
                cwd=str(ROOT), capture_output=True, text=True, timeout=600)
            ok = (rc.returncode == 0 and _nlines(OUT_JSONL) == before + 1)
        except Exception:
            ok = False
        seed += 1
        if not ok:
            err += 1  # errored run: excluded per the pre-registered rule; re-draw
            print(f"  {scenario}/{mode}/{model} seed{seed-1}: ERROR (excluded, k={err})", flush=True)
            continue
        v = int(_last_row(OUT_JSONL)["outcome"]["violation"])
        viol += v
        done += 1
        used_seeds.append(seed - 1)
        print(f"  {scenario}/{mode}/{model} seed{seed-1}: viol={v}  ({viol}/{done})  k={err}", flush=True)
    # guard against a model-outer restructure silently collapsing the per-cell seed set
    assert len(set(used_seeds)) == len(used_seeds), \
        f"DUPLICATE SEED in {scenario}/{mode}/{model}: {used_seeds}"
    lo, hi = wilson(viol, done)
    row = {"scenario": scenario, "mode": mode, "model": model,
           "violations": viol, "n": done, "excluded_k": err,
           "violation_rate": f"{viol}/{done}", "wilson95": f"[{lo},{hi}]",
           "seeds": ",".join(map(str, used_seeds))}
    rows.append(row)
    OUT_CSV.parent.mkdir(exist_ok=True)
    with OUT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"  [CELL DONE] {scenario}/{mode}/{model}: {viol}/{done} {row['wilson95']} "
          f"(k={err} excluded)", flush=True)
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true", help="1 cell x n=3 smoke")
    ap.add_argument("--modes", default=",".join(MODES),
                    help="comma list of modes to run (e.g. 'attack' while guard is being fixed)")
    args = ap.parse_args()
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    rows: list[dict] = []
    if args.dry:
        print("=== DRY RUN: secure_house / attack / qwen3:14b x n=3 ===", flush=True)
        run_cell("secure_house", "attack", "qwen3:14b", 3, rows)
    else:
        # model-outer so each model is pinned once and reused across its cells
        for model, target in MODELS:
            preload(model)
            for scenario in SCENARIOS:
                for mode in modes:
                    run_cell(scenario, mode, model, target, rows)
    md5 = hashlib.md5(OUT_CSV.read_bytes()).hexdigest() if OUT_CSV.exists() else "n/a"
    print(f"\nwrote {OUT_CSV.name} ({len(rows)} cells), md5={md5}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
