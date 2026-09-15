#!/usr/bin/env python3
"""Stage 5 -- the severity-detectability frontier.

    python scripts/run_detectability.py --attack-holds 600,60,30,10,5

Answers the question the paper cannot avoid: at the false-positive rate a real
deployment would accept, is there room for the attack's schedule inside ordinary
benign jitter?

Every threshold here is calibrated on benign traffic only. Calibrating against
attacked traffic would make the result circular, which is Challenge 4.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from delaysteer.timed.detect import (DETECTORS, BenignJitter, calibrate,
                                     max_undetected_hold)

FIELDS = ["detector", "fpr", "threshold", "n_held", "max_undetected_hold_s",
          "attack_hold_s", "feasible", "jitter_median_s", "jitter_p_stall",
          "modelled"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fprs", default="0.001,0.005,0.01,0.05")
    ap.add_argument("--attack-holds", default="600,120,60,30,10,5")
    ap.add_argument("--held", default="1,2,3")
    ap.add_argument("--out", default="results/detectability.csv")
    a = ap.parse_args()

    fprs = [float(x) for x in a.fprs.split(",")]
    holds = [float(x) for x in a.attack_holds.split(",")]
    n_helds = [int(x) for x in a.held.split(",")]
    j = BenignJitter()

    print("Benign jitter model (MODELLED, not measured -- no physical radio; "
          "per the design's realism commitment this bounds the DEFENSE's "
          "cadence figures, not the attack, because the attack acts on the "
          "arrival timestamp which is identical either way).")
    print(f"  median={j.median_s}s sigma={j.sigma} p_stall={j.p_stall} "
          f"stall={j.stall_s}s\n")

    rows = []
    ceilings: dict[tuple[float, int], float] = {}
    print(f"{'detector':16s} {'fpr':>6s} {'held':>4s} {'threshold':>10s} "
          f"{'max undetected':>15s}")
    print("-" * 60)
    for n_held in n_helds:
        for fpr in fprs:
            per_det = []
            for name in DETECTORS:
                cal = calibrate(name, fpr=fpr, jitter=j)
                p = max_undetected_hold(cal, jitter=j, n_held=n_held)
                per_det.append(p.max_undetected_hold_s)
                print(f"{name:16s} {fpr:6.3f} {n_held:4d} {cal.threshold:10.2f} "
                      f"{p.max_undetected_hold_s:14.1f}s")
                for h in holds:
                    rows.append({
                        "detector": name, "fpr": fpr, "threshold": round(cal.threshold, 3),
                        "n_held": n_held,
                        "max_undetected_hold_s": round(p.max_undetected_hold_s, 2),
                        "attack_hold_s": h,
                        "feasible": int(p.max_undetected_hold_s >= h),
                        "jitter_median_s": j.median_s, "jitter_p_stall": j.p_stall,
                        "modelled": 1,
                    })
            ceilings[(fpr, n_held)] = min(per_det)

    print("\nBINDING CEILING (an adversary must stay under EVERY deployed "
          "detector, so the usable budget is the MINIMUM across families)")
    print(f"{'fpr':>6s} {'n_held':>6s} {'ceiling':>10s}   attack holds that fit")
    print("-" * 66)
    for (fpr, n_held), c in sorted(ceilings.items()):
        fit = [h for h in sorted(holds) if h <= c]
        print(f"{fpr:6.3f} {n_held:6d} {c:9.1f}s   "
              f"{fit if fit else 'NONE -- every measured attack is detectable'}")

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    new = not out.exists() or out.stat().st_size == 0
    with out.open("a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerows(rows)
    print(f"\nwrote {len(rows)} rows -> {out}")

    print("\nREADING THIS HONESTLY")
    print("  The measured Stage 1 and Stage 2 attacks used a 600s hold, which")
    print("  no family tolerates at any usable FPR. Whether the attack survives")
    print("  at the ceiling is a question about GAR(delay magnitude), not about")
    print("  the detector -- and that sweep is the experiment that settles it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
