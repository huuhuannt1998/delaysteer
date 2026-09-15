"""Cross-family robustness at n>1: violation RATES for the access, confirmation,
and automation families (the three non-secure_house families), so the n=20 robustness
study covers all four attack families rather than just the stale-contact contradiction.

Each (family, ablation) cell is run R times at temperature>0 with a varying seed; we
report the violation rate, the loop rate (runs that hit the step cap), and the blocked
rate. The attack cell is ablation=none; the defended cell is ablation=full.

  python -m delaysteer.run_family_rates --models qwen3:14b --repeats 20 --temperature 0.7 --out family_rates_n20
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from .config import Config
from .run_automation import run_auto
from .run_confirm import run_confirm
from .run_repair import run_repair

FAMILIES = ["access", "confirmation", "automation"]
ABLATIONS = ["none", "full"]
ROWS: list[dict] = []


def _call(family, ablation, label, model, temperature, seed):
    """Run one attack (or defended) instance of a family. Returns the runner dict."""
    if family == "access":  # tech absent, stale 'arrived' delivered
        return run_repair("virtual", False, True, ablation, False, label,
                          model=model, temperature=temperature, seed=seed)
    if family == "confirmation":  # stale 'present' -> human approves on stale snapshot
        return run_confirm("virtual", False, True, ablation, False, label,
                           model=model, temperature=temperature, seed=seed)
    if family == "automation":  # delay every door-check probe -> looks unreliable
        return run_auto("virtual", True, ablation, label,
                        model=model, temperature=temperature, seed=seed)
    raise ValueError(family)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="qwen3:14b")
    ap.add_argument("--families", default=",".join(FAMILIES))
    ap.add_argument("--repeats", type=int, default=20)
    ap.add_argument("--temperature", type=float, default=None,
                    help="default: DELAYSTEER_TEMPERATURE, else 0.0. NOTE: this is a "
                         "RATE study -- at T=0 every repeat is identical and the rate "
                         "is meaningless. Pass >0 (historically 0.7) for a real sweep.")
    ap.add_argument("--out", default="family_rates",
                    help="output basename under results/ (use a new name to stay additive-safe)")
    args = ap.parse_args()
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    families = [f.strip() for f in args.families.split(",") if f.strip()]
    cap = Config().max_react_steps

    for m in models:
        for fam in families:
            for abl in ABLATIONS:
                viol = loop = blocked = 0
                for i in range(args.repeats):
                    tag = f"fr_{m.replace(':','_').replace('.','')}_{fam[:4]}_{abl}_{i}"
                    r = _call(fam, abl, tag, m, args.temperature, i)
                    viol += int(r["violation"])
                    loop += int(r["steps"] >= cap)
                    blocked += int(r.get("blocked", 0) > 0)
                    print(f"    run {i+1}/{args.repeats} {m} {fam}/{abl}: "
                          f"viol={int(r['violation'])} steps={r['steps']} blk={r.get('blocked',0)} "
                          f"(running {viol}/{i+1})", flush=True)
                row = {"model": m, "family": fam, "ablation": abl, "repeats": args.repeats,
                       "violation_rate": f"{viol}/{args.repeats}",
                       "loop_rate": f"{loop}/{args.repeats}",
                       "blocked_rate": f"{blocked}/{args.repeats}"}
                ROWS.append(row)
                print(f"  [{m} {fam}/{abl}] viol {row['violation_rate']}  loop {row['loop_rate']}  "
                      f"blocked {row['blocked_rate']}", flush=True)
                _od = Path("results"); _od.mkdir(exist_ok=True)
                with (_od / f"{args.out}.csv").open("w", newline="") as _f:
                    _w = csv.DictWriter(_f, fieldnames=list(row.keys())); _w.writeheader(); _w.writerows(ROWS)

    out = Path("results"); out.mkdir(exist_ok=True)
    (out / f"{args.out}.json").write_text(json.dumps(ROWS, indent=2))
    print(f"\n=== family violation RATES (temp {args.temperature}, {args.repeats} samples/cell) ===")
    print(f"{'model':<16}{'family':<14}{'abl':<6}{'viol':<8}{'loop':<8}{'blocked'}")
    for r in ROWS:
        print(f"{r['model']:<16}{r['family']:<14}{r['ablation']:<6}"
              f"{r['violation_rate']:<8}{r['loop_rate']:<8}{r['blocked_rate']}")
    print(f"\nwrote results/{args.out}.csv ({len(ROWS)} cells)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
