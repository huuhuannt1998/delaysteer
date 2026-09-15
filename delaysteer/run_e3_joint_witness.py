#!/usr/bin/env python3
"""E3 -- freshness does not imply coherence, and the predicate that repairs it.

v2 design §5.6 (Theorem 5) and §8.3 (mechanism M2). This is the advisor design report's
"snapshot coherence" item, S6, in its sharpest form.

The claim
---------
Every critical fact of a multi-fact action can be individually truthful and individually
inside its freshness budget while the CONJUNCTION the action depends on was never true at
any instant. Formally, with W(B) = { t : for every critical fact tau, the true value of tau
at t equals B(tau) }, there are delay-only schedules under which every conjunct is fresh and
truthful yet W(B) is empty.

The construction (§5.6, reproduced here as executable code)
-----------------------------------------------------------
The bedtime commitment report(secure) requires lock=locked AND contact=closed AND
alarm=armed. At t1 the door is closed and the lock is unlocked. At t2 > t1 the door is open
and the lock is locked. Deliver contact=closed generated at t1 and lock=locked generated at
t2, both aged under the budget. Each conjunct was true when it was generated. The
conjunction was never true. The v1 guard checks each fact against its own budget and admits.

Why a tighter budget cannot fix it
----------------------------------
No per-fact bound implies the existence of a common witness instant. Shrinking the budget
shrinks how far apart the two generation times may be, but the failure needs only that they
straddle a transition, and a transition can occur arbitrarily close to the commit. That is
why M2 is a PREDICATE over the fact set rather than a smaller number:

  spread rule (deployable): max(t_m) - min(t_m) <= sigma_max
  strong rule:              every critical fact affirmed in ONE challenge round, so a common
                            witness instant is attested rather than inferred

Scoring
-------
The headline metric is the one §11.2 asks for: the COHERENCE VIOLATION RATE, the fraction of
*admitted* multi-fact commitments whose joint witness set is empty. It is scored against a
ground-truth timeline the guard does not have -- which is the whole difficulty, and the
reason the v1 guard cannot see the problem it is failing.

A control arm with a coherent world (the lock closes before the door opens) is included so
that a defense which simply refuses everything scores badly: refusing coherent commits shows
up as benign task loss, reported alongside.

  .venv/bin/python -m delaysteer.run_e3_joint_witness --n 20
"""

from __future__ import annotations

import argparse
import csv
import math
import random
from pathlib import Path

from delaysteer.defense.nonce_challenge import (
    FactAffirmation, joint_witness_admits, joint_witness_set,
)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "e3_joint_witness.csv"

BUDGET = 2.0                 # per-fact freshness budget (the shipped static budget)
SIGMA_MAX_SWEEP = (0.05, 0.25, 0.50, 1.00, 2.00)
TIMELINE_STEP = 0.01         # resolution at which W(B) is evaluated

# The three critical facts of report(secure).
FACTS = ("contact", "lock", "alarm")

FIELDS = [
    "run_id", "scenario", "trial", "arm", "guard", "sigma_max_s", "gap_s",
    "t_contact_m", "t_lock_m", "t_alarm_m", "measurement_spread_s",
    "per_fact_fresh", "admitted", "witness_set_size", "coherent",
    "coherence_violation", "benign_task_lost", "reason", "notes",
]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[int, int]:
    if n == 0:
        return (0, 0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(100 * max(0.0, c - h)), round(100 * min(1.0, c + h)))


def make_world(gap: float, t_open: float = 3.0, t_arm: float = 0.0):
    """Ground truth over time.

    ``gap`` is t_lock - t_open. Positive gap => the lock engages only AFTER the door has
    opened, so "closed AND locked" is never simultaneously true and W(B) is empty. Negative
    gap => the lock engages before the door opens, so there is a real witness instant.
    """
    t_lock = t_open + gap

    def truth_at(fact: str, t: float) -> str:
        if fact == "contact":
            return "closed" if t < t_open else "open"
        if fact == "lock":
            return "locked" if t >= t_lock else "unlocked"
        if fact == "alarm":
            return "armed" if t >= t_arm else "disarmed"
        raise KeyError(fact)

    return truth_at, t_open, t_lock


def one_trial(rng: random.Random, arm: str, guard: str, sigma_max: float,
              gap: float) -> dict:
    truth_at, t_open, t_lock = make_world(gap)

    # The adversary picks generation times that are each individually fresh at the commit.
    # contact is taken from just BEFORE the door opens; lock from just AFTER it engages.
    t_contact = t_open - rng.uniform(0.05, 0.35)
    t_lock_m = t_lock + rng.uniform(0.05, 0.35)
    t_alarm = max(0.0, min(t_contact, t_lock_m) - rng.uniform(0.0, 0.20))
    t_commit = max(t_contact, t_lock_m) + rng.uniform(0.05, 0.30)

    belief = {
        "contact": truth_at("contact", t_contact),
        "lock": truth_at("lock", t_lock_m),
        "alarm": truth_at("alarm", t_alarm),
    }
    stamps = {"contact": t_contact, "lock": t_lock_m, "alarm": t_alarm}

    # Every conjunct individually inside its budget -- the precondition of the theorem.
    per_fact_fresh = all(t_commit - s <= BUDGET for s in stamps.values())

    facts = [FactAffirmation(key=k, value=belief[k], measurement_time=stamps[k],
                             challenge_round=(0 if guard == "M2_strong" else None))
             for k in FACTS]
    # Under the strong tier a single batched challenge affirms every fact in one round, so
    # the spread collapses to the round trip. Model that by re-stamping to a common instant.
    if guard == "M2_strong":
        facts = [FactAffirmation(key=f.key, value=truth_at(f.key, t_commit),
                                 measurement_time=t_commit, challenge_round=0)
                 for f in facts]
        belief = {f.key: f.value for f in facts}
        stamps = {f.key: f.measurement_time for f in facts}

    spread = max(stamps.values()) - min(stamps.values())

    if guard == "v1":
        admitted = per_fact_fresh          # per-fact budget only: the published behaviour
        reason = "per-fact freshness only"
    elif guard == "M2_spread":
        v = joint_witness_admits(facts, sigma_max_s=sigma_max, require_single_round=False)
        admitted = per_fact_fresh and v.admitted
        reason = v.reason
    elif guard == "M2_strong":
        v = joint_witness_admits(facts, sigma_max_s=sigma_max, require_single_round=True)
        admitted = per_fact_fresh and v.admitted
        reason = v.reason
    else:
        raise ValueError(guard)

    # Ground-truth oracle: is there ANY instant at which the whole belief held?
    horizon = max(6.0, t_commit + 1.0)
    timeline = [i * TIMELINE_STEP for i in range(int(horizon / TIMELINE_STEP) + 1)]
    W = joint_witness_set(belief, truth_at, timeline)
    coherent = len(W) > 0

    return dict(
        arm=arm, guard=guard, sigma_max_s=sigma_max, gap_s=round(gap, 3),
        t_contact_m=round(t_contact, 4), t_lock_m=round(t_lock_m, 4),
        t_alarm_m=round(t_alarm, 4), measurement_spread_s=round(spread, 4),
        per_fact_fresh=per_fact_fresh, admitted=admitted,
        witness_set_size=len(W), coherent=coherent,
        # The headline metric: an ADMITTED commitment whose joint witness set is empty.
        coherence_violation=(admitted and not coherent),
        # The cost side: refusing a commitment the world actually supported.
        benign_task_lost=(coherent and not admitted),
        reason=reason,
        notes=("incoherent construction (Thm 5): lock engages after the door opens"
               if gap > 0 else "coherent control: lock engages before the door opens"),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--seed", type=int, default=20260813)
    a = ap.parse_args()

    rng = random.Random(a.seed)
    run_id = "e3-" + str(a.seed)
    rows = []
    for arm, gap in (("incoherent", 0.60), ("coherent_control", -0.60)):
        for guard in ("v1", "M2_spread", "M2_strong"):
            for sigma in SIGMA_MAX_SWEEP:
                for i in range(a.n):
                    r = one_trial(rng, arm, guard, sigma, gap)
                    r.update(run_id=run_id, scenario="E3_joint_witness_coherence", trial=i)
                    rows.append(r)

    OUT.parent.mkdir(exist_ok=True)
    new = not OUT.exists()
    with OUT.open("a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        if new:
            w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in FIELDS})

    print(f"run_id={run_id}  n={a.n} per cell  budget={BUDGET}s\n")
    # The precondition is a property of the ADVERSARY's schedule, so it is reported over
    # the arms that leave the belief as delivered. M2_strong re-affirms every fact in one
    # round, which replaces the belief with a genuine snapshot -- coherent by construction,
    # which is the mechanism working, not a weaker construction.
    print("  Theorem 5 precondition, on the belief as delivered (v1 / M2_spread arms):")
    inc = [r for r in rows if r["arm"] == "incoherent" and r["guard"] != "M2_strong"]
    print(f"    every conjunct individually fresh : "
          f"{sum(r['per_fact_fresh'] for r in inc)}/{len(inc)}")
    print(f"    ground-truth witness set EMPTY    : "
          f"{sum(not r['coherent'] for r in inc)}/{len(inc)}")
    strong = [r for r in rows if r["arm"] == "incoherent" and r["guard"] == "M2_strong"]
    print(f"    (M2_strong re-snapshots in one challenge round, so its belief is coherent "
          f"in {sum(r['coherent'] for r in strong)}/{len(strong)})\n")
    print(f"  {'arm':<18}{'guard':<12}{'sigma':>7}  {'coherence viol.':>17}  {'benign lost':>13}")
    print("  " + "-" * 72)
    for arm in ("incoherent", "coherent_control"):
        for guard in ("v1", "M2_spread", "M2_strong"):
            for sigma in SIGMA_MAX_SWEEP:
                c = [r for r in rows if r["arm"] == arm and r["guard"] == guard
                     and r["sigma_max_s"] == sigma]
                cv = sum(r["coherence_violation"] for r in c)
                bl = sum(r["benign_task_lost"] for r in c)
                lo, hi = wilson(cv, len(c))
                print(f"  {arm:<18}{guard:<12}{sigma:>7.2f}  {cv:>5}/{len(c):<4}[{lo:>3},{hi:>3}]"
                      f"  {bl:>6}/{len(c)}")
        print()
    print(f"  artefact: {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
