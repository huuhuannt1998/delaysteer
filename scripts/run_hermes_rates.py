"""MA-9 Task 2: re-run the Hermes production-stack rate cells at n=20 (agent of record)
/ n=10 (others), attack + guard, with Wilson 95% CIs.

Live-HA campaign via scripts/hermes_ha_attack.py (one mode/model/seed per subprocess,
under the HERMES venv). Guard mode uses a lower iteration cap: the proxy guard 409-blocks
the arm command at step ~2, and the rest is wasted agent thrash, so capping keeps guard
runs bounded without changing the verdict (blocked -> no false secure claim). Pre-
registered exclusion rule (errored run -> excluded, re-drawn to target n; report actual n
+ k). Model pinned per block (keep-alive). Incremental CSV; per-cell distinct seeds.

  python scripts/run_hermes_rates.py --dry     # 1 cell x n=3
  python scripts/run_hermes_rates.py           # full attack + guard
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

ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "scripts" / "hermes_ha_attack.py"
HERMES_PY = os.environ.get("HERMES_PY", "/Users/anonymous/Desktop/hermes-agent/.venv/bin/python")
OUT_JSONL_REL = "results/hermes_n20.jsonl"
OUT_JSONL = ROOT / OUT_JSONL_REL
OUT_CSV = ROOT / "results" / "hermes_rates_n20.csv"
MODELS = [("qwen3:14b", 20), ("mistral:7b", 10), ("deepseek-coder-v2:16b", 10)]
MODES = ["attack", "guard"]
GUARD_MAX_ITER = 5   # attack uses full 12; guard blocks at ~step 2, cap the thrash


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


def preload(model):
    body = json.dumps({"model": model, "keep_alive": "40m", "prompt": "ok",
                       "stream": False, "options": {"num_predict": 1}}).encode()
    try:
        urllib.request.urlopen("http://localhost:11434/api/generate", body, timeout=240)
        print(f"[preload] pinned {model}", flush=True)
    except Exception as e:
        print(f"[preload] warn: {e}", flush=True)


def run_cell(mode, model, target, rows):
    viol = done = err = 0
    seed = 1
    used_seeds = []
    cap = target * 3
    max_iter = GUARD_MAX_ITER if mode == "guard" else 12
    while done < target and seed <= cap:
        before = _nlines(OUT_JSONL)
        try:
            rc = subprocess.run(
                [HERMES_PY, str(EVAL), "--mode", mode, "--model", model, "--seed", str(seed),
                 "--out", OUT_JSONL_REL, "--max-iter", str(max_iter)],
                cwd=str(ROOT), capture_output=True, text=True, timeout=900)
            ok = (rc.returncode == 0 and _nlines(OUT_JSONL) == before + 1)
        except Exception:
            ok = False
        seed += 1
        if not ok:
            err += 1
            print(f"  hermes/{mode}/{model} seed{seed-1}: ERROR (excluded, k={err})", flush=True)
            continue
        v = int(_last_row(OUT_JSONL)["violation"])
        viol += v
        done += 1
        used_seeds.append(seed - 1)
        print(f"  hermes/{mode}/{model} seed{seed-1}: viol={v}  ({viol}/{done})  k={err}", flush=True)
    assert len(set(used_seeds)) == len(used_seeds), f"DUPLICATE SEED hermes/{mode}/{model}: {used_seeds}"
    lo, hi = wilson(viol, done)
    row = {"scenario": "hermes", "mode": mode, "model": model, "violations": viol, "n": done,
           "excluded_k": err, "violation_rate": f"{viol}/{done}", "wilson95": f"[{lo},{hi}]",
           "seeds": ",".join(map(str, used_seeds))}
    rows.append(row)
    OUT_CSV.parent.mkdir(exist_ok=True)
    with OUT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"  [CELL DONE] hermes/{mode}/{model}: {viol}/{done} {row['wilson95']} (k={err})", flush=True)
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true", help="1 cell x n=3 smoke")
    ap.add_argument("--modes", default=",".join(MODES))
    args = ap.parse_args()
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    rows: list[dict] = []
    if args.dry:
        print("=== DRY RUN: hermes / attack / qwen3:14b x n=3 ===", flush=True)
        preload("qwen3:14b")
        run_cell("attack", "qwen3:14b", 3, rows)
    else:
        for model, target in MODELS:
            preload(model)
            for mode in modes:
                run_cell(mode, model, target, rows)
    md5 = hashlib.md5(OUT_CSV.read_bytes()).hexdigest() if OUT_CSV.exists() else "n/a"
    print(f"\nwrote {OUT_CSV.name} ({len(rows)} cells), md5={md5}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
