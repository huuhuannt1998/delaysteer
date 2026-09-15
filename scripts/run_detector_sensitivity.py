#!/usr/bin/env python3
"""B12 (synthetic half) -- is the detection ceiling an artefact of one jitter model?

The paper's central ordering puts a usable hold beneath the largest hold a channel
detector leaves undetected. That ceiling is calibrated on a MODELLED benign
inter-arrival distribution, and reviewers reasonably ask whether it is a property of
the environment or of our parameter choices: on real radios benign traffic is burstier
than a log-normal, and the ceiling could plausibly be much lower or much higher.

This sweeps the five parameters of that model over ranges spanning clean local meshes
to congested cloud-backed ones, and reports the ceiling as a RANGE rather than a point.
It does not answer the question -- only real traces do that (see the manuscript's
threats to validity). What it does establish is how sensitive the ordering is to the
modelling choice, which decides how much a real-trace campaign would change.

Additive: writes results/detector_sensitivity.csv. CPU only.
"""
import argparse, csv, itertools, random, statistics, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from delaysteer.timed.detect import (BenignJitter, calibrate, DETECTORS,  # noqa: E402
                                     max_undetected_hold)

OUT = Path("results/detector_sensitivity.csv")

# Ranges chosen to bracket ordinary consumer deployments rather than to flatter the
# result: the fast end is a local wired-hub mesh, the slow end a congested cloud
# round-trip with frequent retries.
GRID = {
    "median_s":     [0.1, 0.35, 1.0, 2.0],
    "sigma":        [0.5, 0.9, 1.4],
    "p_stall":      [0.01, 0.04, 0.10, 0.20],
    "stall_s":      [5.0, 12.0, 30.0],
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fpr", type=float, default=0.01)
    ap.add_argument("--held", type=int, default=1)
    ap.add_argument("--attack-hold", type=float, default=0.5,
                    help="the hold the attack actually needs (Sec. 5.2 measured 0.5s)")
    ap.add_argument("--out", default=str(OUT))
    a = ap.parse_args()

    names = list(GRID)
    rows, ceilings = [], []
    for combo in itertools.product(*(GRID[k] for k in names)):
        params = dict(zip(names, combo))
        j = BenignJitter(**params)
        per_det = {}
        for det in DETECTORS:
            try:
                cal = calibrate(det, fpr=a.fpr, jitter=j)
                p = max_undetected_hold(cal, jitter=j, n_held=a.held)
                per_det[det] = float(p.max_undetected_hold_s)
            except Exception:
                continue
        if not per_det:
            continue
        binding = min(per_det, key=per_det.get)      # the detector that constrains
        ceiling = per_det[binding]
        ceilings.append(ceiling)
        rows.append({**params, "fpr": a.fpr, "n_held": a.held,
                     "binding_detector": binding,
                     "ceiling_s": round(ceiling, 2),
                     "attack_hold_s": a.attack_hold,
                     "ordering_holds": int(a.attack_hold < ceiling)})

    Path(a.out).parent.mkdir(exist_ok=True)
    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)

    held = sum(r["ordering_holds"] for r in rows)
    print(f"configurations swept : {len(rows)}")
    print(f"binding ceiling      : min {min(ceilings):.2f}s  median "
          f"{statistics.median(ceilings):.2f}s  max {max(ceilings):.2f}s")
    print(f"attack needs         : {a.attack_hold}s  (Sec. 5.2)")
    print(f"ordering holds       : {held}/{len(rows)} configurations")
    if held < len(rows):
        bad = [r for r in rows if not r["ordering_holds"]]
        print(f"  fails in {len(bad)}: e.g. {bad[0]}")
    from collections import Counter
    print(f"binding detector     : {dict(Counter(r['binding_detector'] for r in rows))}")
    print(f"\nwrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
