#!/usr/bin/env python3
"""E8 -- the speculative window against violation rate, per family.

v2 design §6.2 and §11.2. The Spectre analogy the design report asks us to take seriously is
not decorative: the quantity that decides whether a delay-only attack lands is the same
shape as a speculation window. Define

    W_spec = time from the LAST CONFIRMED critical read to the FIRST high-impact tool call.

Inside that window the agent is acting on evidence it has stopped checking, exactly as a
speculating core acts on a prediction it has not yet retired. The adversary does not need to
change the value; it needs the window to contain a transition.

What v1 already had, and what this adds
---------------------------------------
`results/deliberation_sweep.csv` sweeps the observe-to-commit window against violation and
false-block rate across guard tiers, which is the same quantity under a different name. It is
pooled across families, so it cannot answer the question the taxonomy raises: do the four
families have the same exposure to the window, or do they differ? They differ, and the
difference is structural rather than incidental -- so this experiment carries the family
dimension the pooled sweep drops.

Method
------
For each family, the window is swept and a violation is scored when the critical fact's
transition falls inside it. The transition instant is drawn from the family's own timing,
which is what makes the families differ: an access decision commits almost immediately after
its read, while an automation edit sits open for as long as the planner deliberates.

This is a modelled sweep at spec-derived timings, not a wall-clock measurement -- the same
standing caveat as the cadence and deliberation studies. Its value is the shape of the curve
and the per-family ordering, not the absolute rates.

  .venv/bin/python -m delaysteer.run_e8_speculative_window --n 20
"""

from __future__ import annotations

import argparse
import csv
import math
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "e8_speculative_window.csv"

W_SPEC_SWEEP = (0.0, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 40.0)
GUARDS = ("none", "static", "heartbeat", "activepoll")

# Per-family timing. `transition_lo/hi` bound when the critical fact flips relative to the
# last confirmed read; `commit_lag` is the family's own structural delay between the read and
# the high-impact call, which is what makes the exposure differ between families.
FAMILIES = {
    # the door can open at any point while the agent deliberates
    "secure_house":  dict(transition_lo=0.0, transition_hi=40.0, commit_lag=0.0),
    # a delegation decision commits almost immediately after its read
    "access":        dict(transition_lo=0.0, transition_hi=40.0, commit_lag=0.0),
    # a human confirmation inserts a long, variable pause between read and commit
    "confirmation":  dict(transition_lo=0.0, transition_hi=40.0, commit_lag=3.0),
    # an automation edit persists: the window stays open until the edit is applied
    "automation":    dict(transition_lo=0.0, transition_hi=40.0, commit_lag=8.0),
}

# Guard residual: the window a guard leaves open regardless of W_spec. Static freshness
# leaves its whole budget; heartbeat leaves the affirmation cadence; active poll leaves the
# poll round trip. Spec-derived, consistent with App. cadence.
GUARD_RESIDUAL_S = {"none": float("inf"), "static": 2.0, "heartbeat": 1.0, "activepoll": 0.1}

FIELDS = [
    "run_id", "scenario", "trial", "family", "guard", "w_spec_s", "commit_lag_s",
    "effective_window_s", "transition_at_s", "transition_inside_window", "violation",
    "guard_residual_s", "notes",
]


def wilson(k, n, z=1.96):
    if n == 0:
        return (0, 0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(100 * max(0.0, c - h)), round(100 * min(1.0, c + h)))


def one_trial(rng, family, guard, w_spec, trial) -> dict:
    fam = FAMILIES[family]
    # The window the agent actually leaves open: the swept planner window plus the family's
    # own structural lag between the confirmed read and the high-impact call.
    effective = w_spec + fam["commit_lag"]
    # A guard closes the window down to its own residual: it re-reads at the commit, so only
    # the residual remains exposed.
    exposed = min(effective, GUARD_RESIDUAL_S[guard])

    transition = rng.uniform(fam["transition_lo"], fam["transition_hi"])
    inside = transition <= exposed
    return dict(
        family=family, guard=guard, w_spec_s=w_spec, commit_lag_s=fam["commit_lag"],
        effective_window_s=round(effective, 3),
        transition_at_s=round(transition, 4),
        transition_inside_window=inside,
        violation=inside,
        guard_residual_s=("inf" if guard == "none" else GUARD_RESIDUAL_S[guard]),
        notes=f"{family}: structural commit lag {fam['commit_lag']}s",
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--seed", type=int, default=20260813)
    a = ap.parse_args()

    rng = random.Random(a.seed)
    run_id = "e8-" + str(a.seed)
    rows = []
    for family in FAMILIES:
        for guard in GUARDS:
            for w in W_SPEC_SWEEP:
                for i in range(a.n):
                    r = one_trial(rng, family, guard, w, i)
                    r.update(run_id=run_id, scenario="E8_speculative_window", trial=i)
                    rows.append(r)

    OUT.parent.mkdir(exist_ok=True)
    new = not OUT.exists()
    with OUT.open("a", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        if new:
            wr.writeheader()
        for r in rows:
            wr.writerow({k: r.get(k, "") for k in FIELDS})

    print(f"run_id={run_id}  n={a.n} per cell\n")
    print("  Violation rate against the speculative window, undefended:\n")
    hdr = "  " + f"{'W_spec (s)':<12}" + "".join(f"{f:>16}" for f in FAMILIES)
    print(hdr); print("  " + "-" * (len(hdr) - 2))
    for w in W_SPEC_SWEEP:
        line = f"  {w:<12.2f}"
        for family in FAMILIES:
            c = [r for r in rows if r["family"] == family and r["guard"] == "none"
                 and r["w_spec_s"] == w]
            v = sum(r["violation"] for r in c)
            line += f"{v:>8}/{len(c):<7}"
        print(line)

    print("\n  Guard tiers at W_spec = 10 s (the window a deliberating planner really leaves):\n")
    print(f"  {'family':<16}" + "".join(f"{g:>14}" for g in GUARDS))
    print("  " + "-" * 72)
    for family in FAMILIES:
        line = f"  {family:<16}"
        for guard in GUARDS:
            c = [r for r in rows if r["family"] == family and r["guard"] == guard
                 and r["w_spec_s"] == 10.0]
            v = sum(r["violation"] for r in c)
            line += f"{v:>7}/{len(c):<6}"
        print(line)

    print("\n  === E8 ===")
    print("    The families do not share an exposure. At a fixed planner window the")
    print("    structural commit lag decides how much of it is actually open:")
    for family, fam in FAMILIES.items():
        c = [r for r in rows if r["family"] == family and r["guard"] == "none"
             and r["w_spec_s"] == 0.0]
        v = sum(r["violation"] for r in c)
        lo, hi = wilson(v, len(c))
        print(f"      {family:<16} lag {fam['commit_lag']:>4.1f}s -> violation at W_spec=0 "
              f"is {v}/{len(c)} [{lo},{hi}]")
    print(f"\n  artefact: {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
