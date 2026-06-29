"""Cross-model violation RATES on the REAL SmartThings cloud, matching the HA rate
study (run_m2_rates) exactly: the same 3 cross-agent cells, R sampled runs per cell
at temperature>0 with a varying seed, reporting violation / secure-claim / loop rates.

This answers, on a REAL second platform and for ALL claimed cross-model agents
(qwen3:14b, mistral:7b, deepseek-coder-v2:16b), whether the stale-evidence finding
ports and whether the full guard holds -- with rates, not single noisy verdicts
(a single sample already diverged from the HA rate for mistral).

ADDITIVE + frozen-safe: writes a NEW file results/smartthings_llm_rates.csv (flushed
after each model so a long run's partial results survive) and asserts metrics.csv,
smartthings.csv, m2_metrics.csv, m2_rates.csv md5-UNCHANGED. Token from
$SMARTTHINGS_TOKEN / .env at runtime; never printed or committed.

  SMARTTHINGS_TOKEN=*** .venv/bin/python -m delaysteer.run_smartthings_llm_rates \
      --models qwen3:14b,mistral:7b,deepseek-coder-v2:16b --repeats 3 --temperature 0.7
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from .config import Config
from .run_m2 import run_cell
from .run_m2_rates import CELLS

FROZEN = ["results/metrics.csv", "results/smartthings.csv",
          "results/m2_metrics.csv", "results/m2_rates.csv"]
OUT = Path("results/smartthings_llm_rates.csv")
FIELDS = ["home", "model", "scenario", "ablation", "repeats",
          "violation_rate", "secure_rate", "loop_rate"]


def _md5(p: str) -> str:
    pp = Path(p)
    return hashlib.md5(pp.read_bytes()).hexdigest() if pp.exists() else "(absent)"


def _flush(rows):
    Path("results").mkdir(exist_ok=True)
    with OUT.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    Path("results/smartthings_llm_rates.json").write_text(json.dumps(rows, indent=2))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="qwen3:14b,mistral:7b,deepseek-coder-v2:16b")
    ap.add_argument("--repeats", type=int, default=3)       # matches the HA study
    ap.add_argument("--temperature", type=float, default=0.7)
    args = ap.parse_args()
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    cap = Config().max_react_steps
    home = "smartthings"

    before = {p: _md5(p) for p in FROZEN}
    rows: list[dict] = []
    for m in models:
        for scen, abl, hold in CELLS:
            viol = secure = loop = 0
            for i in range(args.repeats):
                tag = f"st_r_{m.replace(':', '_').replace('.', '')}_{scen[:3]}_{abl}_{i}"
                r = run_cell(m, scen, abl, hold, tag, home, seed=i, temperature=args.temperature)
                viol += int(r["violation"])
                secure += int(r["secure_claim"])
                loop += int(r["steps"] >= cap)
            rows.append({"home": home, "model": m, "scenario": scen, "ablation": abl,
                         "repeats": args.repeats, "violation_rate": f"{viol}/{args.repeats}",
                         "secure_rate": f"{secure}/{args.repeats}", "loop_rate": f"{loop}/{args.repeats}"})
        _flush(rows)  # checkpoint after each model
        print(f"[flushed after {m}]  {[r for r in rows if r['model'] == m]}", flush=True)

    print(f"\n=== SmartThings cross-model RATES (temp {args.temperature}, {args.repeats} samples/cell) ===")
    print(f"{'model':<22}{'scenario':<15}{'abl':<6}{'viol':<7}{'secure':<8}{'loop'}")
    for r in rows:
        print(f"{r['model']:<22}{r['scenario'][:13]:<15}{r['ablation']:<6}"
              f"{r['violation_rate']:<7}{r['secure_rate']:<8}{r['loop_rate']}")
    print(f"\nwrote {OUT} ({len(rows)} cells)")
    for p in FROZEN:
        now = _md5(p)
        print(f"  {p} md5 {'UNCHANGED (frozen OK)' if now == before[p] else '!!! CHANGED !!!'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
