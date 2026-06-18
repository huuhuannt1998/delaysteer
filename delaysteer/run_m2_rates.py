"""M2 robust cross-model study: violation RATES over repeated sampled runs.

Single-shot LLM runs are noisy (nondeterminism + looping). This runs each key cell
R times with temperature>0 and a varying seed, and reports the violation rate, the
secure-claim rate, and the loop rate (runs that hit the step cap). Answers
'is the stale-evidence vulnerability just qwen3?' and 'does the full guard hold?'
with rates rather than single verdicts.

  python -m delaysteer.run_m2_rates --models mistral:7b,deepseek-coder-v2:16b,qwen3:14b \
      --homes virtual --repeats 5 --temperature 0.7
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from .config import Config
from .run_m2 import run_cell

# (scenario, ablation, hold) cells that carry the cross-model claim
CELLS = [
    ("contact_contradiction", "none", 4),   # stale-evidence: does it violate?
    ("contact_contradiction", "full", 4),    # does the full guard prevent it?
    ("lock_timeout", "none", 0),             # fail-open path: do LLMs fail open?
]
ROWS: list[dict] = []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="mistral:7b,deepseek-coder-v2:16b,qwen3:14b")
    ap.add_argument("--homes", default="virtual")
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--temperature", type=float, default=0.7)
    args = ap.parse_args()
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    homes = [h.strip() for h in args.homes.split(",") if h.strip()]
    cap = Config().max_react_steps

    for hk in homes:
        for m in models:
            for scen, abl, hold in CELLS:
                viol = secure = loop = 0
                for i in range(args.repeats):
                    tag = f"r_{hk}_{m.replace(':','_').replace('.','')}_{scen[:3]}_{abl}_{i}"
                    r = run_cell(m, scen, abl, hold, tag, hk, seed=i, temperature=args.temperature)
                    viol += int(r["violation"])
                    secure += int(r["secure_claim"])
                    loop += int(r["steps"] >= cap)
                row = {"home": hk, "model": m, "scenario": scen, "ablation": abl,
                       "repeats": args.repeats, "violation_rate": f"{viol}/{args.repeats}",
                       "secure_rate": f"{secure}/{args.repeats}", "loop_rate": f"{loop}/{args.repeats}"}
                ROWS.append(row)

    out = Path("results"); out.mkdir(exist_ok=True)
    with (out / "m2_rates.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(ROWS[0].keys()))
        w.writeheader(); w.writerows(ROWS)
    (out / "m2_rates.json").write_text(json.dumps(ROWS, indent=2))

    print(f"\n=== M2 violation RATES (temp {args.temperature}, {args.repeats} samples/cell) ===")
    print(f"{'home':<8}{'model':<22}{'scenario':<15}{'abl':<6}{'viol':<7}{'secure':<8}{'loop'}")
    for r in ROWS:
        print(f"{r['home']:<8}{r['model']:<22}{r['scenario'][:13]:<15}{r['ablation']:<6}"
              f"{r['violation_rate']:<7}{r['secure_rate']:<8}{r['loop_rate']}")
    print(f"\nwrote results/m2_rates.csv ({len(ROWS)} cells)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
