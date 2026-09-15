#!/usr/bin/env python3
"""E2 -- nonce-bound affirmation across adversary positions, and the round-trip bound.

v2 design §8.2 / §11.1. Experiment L established that the platform's timestamp is minted at
RECEIPT, so upstream of that point a delay-only adversary launders its own delay into a
fresh-looking stamp. Every v1 tier decides freshness by comparing timestamps, so every v1
tier is defeated upstream -- and no tightening of the budget helps, because the quantity
being compared is already adversary-controlled.

E2 asks whether minting the reference instant *downstream of every adversary position*
repairs that, and what it costs.

What is modelled, and what is not
---------------------------------
This is a modelled sweep, not a hardware measurement, and the distinction matters for the
strong tier. The DEPLOYABLE tier needs nothing from the device -- the hub already knows when
it issued a poll and when the reply landed -- so its numbers describe something adoptable
today. The STRONG tier needs the device to bind a nonce (Matter's Interaction Model read
transaction, Zigbee's read-attributes sequence number, a wakeable Z-Wave FLiRS lock). We do
not have firmware that implements it. Its rows are what the mechanism *would* do, and are
labelled `modelled_device_binding=True` in the output so no reader has to take that on trust.

Benign round trips are drawn from the measured band in results/latency_calibration.csv
(read P50 ~1 ms, P99 <=2.7 ms, max 8.6 ms), so a bound in the tens of milliseconds is not a
convenient fiction -- it is above the measured tail.

The result worth reporting
--------------------------
A nonce-bound challenge does not make the adversary go away; it changes what the adversary
can achieve. Holding the response past the bound no longer produces a stale-but-admitted
commit, it produces a BLOCK. That is an integrity failure converted into an availability
failure, and the sweep reports both columns separately rather than collapsing them into one
"secure" number, because the second is a real cost that a deployment has to absorb.

  .venv/bin/python -m delaysteer.run_e2_nonce_challenge --n 20
"""

from __future__ import annotations

import argparse
import csv
import math
import random
from pathlib import Path

from delaysteer.defense.nonce_challenge import (
    Challenge, Response, verify_challenge, TIERS,
)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "e2_nonce_challenge.csv"

# Measured benign read round trips (results/latency_calibration.csv): P50 ~1.0 ms,
# P95 ~2.1 ms, P99 ~2.7 ms, max 8.6 ms. Sampling from this band keeps the benign arm
# honest rather than assuming an idealised zero-latency channel.
BENIGN_RTT_LO, BENIGN_RTT_HI = 0.0008, 0.0090

POSITIONS = ("A0", "A1", "B")
# Swept down through the measured benign tail (max 8.6 ms) so the availability knee is
# visible rather than assumed: bounds at or below ~5 ms start refusing honest replies.
RTT_BOUNDS = (0.001, 0.002, 0.005, 0.025, 0.10, 0.50)
FRESHNESS_BUDGET = 2.0          # the shipped static budget the v1 guard uses
HOLD_S = 6.0                    # the adversary's hold, well past the budget

# Two adversary strategies, because they stress different halves of the mechanism.
#   release_held  -- a frame captured BEFORE the challenge, released the instant the guard
#                    asks. The round trip looks perfectly benign; only a device binding can
#                    tell that the value predates the challenge.
#   delay_response -- the reply itself is held. The value could be genuine, but it lands
#                    late; only a round-trip bound catches this one.
STRATEGIES = ("release_held", "delay_response")

FIELDS = [
    "run_id", "scenario", "trial", "position", "tier", "rtt_bound_s", "arm", "strategy",
    "hold_s", "response_delay_s", "true_age_at_commit_s", "platform_observable_age_s",
    "round_trip_s",
    "admitted", "value_admitted", "true_value_at_commit", "stale_admitted",
    "integrity_failure", "availability_failure", "modelled_device_binding",
    "reason", "notes",
]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[int, int]:
    if n == 0:
        return (0, 0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(100 * max(0.0, c - h)), round(100 * min(1.0, c + h)))


def one_trial(rng: random.Random, position: str, tier: str, bound: float,
              arm: str, strategy: str) -> dict:
    """One challenged commit.

    The guard's admission rule COMPOSES the v1 freshness check with the challenge, which is
    how a real deployment would run it -- adding a challenge does not mean discarding the
    budget. Scoring them as alternatives (an earlier version of this harness did) makes the
    deployable tier look worse than no defense at all at P-B, which is an artefact of the
    scoring, not a property of the mechanism.
    """
    t_m = 0.0
    benign_rtt = rng.uniform(BENIGN_RTT_LO, BENIGN_RTT_HI)

    if arm == "benign":
        hold, response_delay = 0.0, 0.0
        true_value_at_commit = "closed"
    else:
        # the door opens while the frame is held, so the held "closed" is stale by the commit
        true_value_at_commit = "open"
        if strategy == "release_held":
            hold, response_delay = HOLD_S, 0.0
        else:                                    # delay_response
            hold, response_delay = 0.0, HOLD_S

    t_issue = t_m + hold                          # the guard challenges at the commit
    t_recv = t_issue + benign_rtt + response_delay

    # --- where the adversary sits decides what the PLATFORM stamp says ------------------
    # Upstream of the hub's stamping point (A0, A1) the hub re-stamps the held frame at
    # receipt, so its observable age collapses. Downstream (B) the stamp was minted at t_m.
    platform_stamp = (t_m + hold) if position in ("A0", "A1") else t_m

    true_age = t_recv - t_m
    observable_age = t_recv - platform_stamp

    # --- what comes back for the challenge ---------------------------------------------
    ch = Challenge.mint(t_issue)
    if arm == "benign" or strategy == "delay_response":
        # a live device answers this challenge; under delay_response the answer is genuine
        # but late, which is precisely what the round-trip bound is for
        echo = ch.nonce
    else:
        # a frame captured BEFORE this challenge existed cannot echo it
        echo = None
    resp = Response(value="closed", received_at=t_recv,
                    nonce_echo=echo, platform_stamp=platform_stamp)

    v = verify_challenge(ch, resp, tier=tier, rtt_bound_s=bound)

    # v1 freshness: the observable age against the budget. This is the check laundering
    # defeats, and it stays in force under every tier.
    freshness_ok = observable_age <= FRESHNESS_BUDGET
    admitted = freshness_ok and v.admitted
    if not freshness_ok:
        reason = "observable age exceeds the freshness budget"
    else:
        reason = v.reason

    stale = admitted and arm == "attack" and true_value_at_commit != resp.value
    return dict(
        position=position, tier=tier, rtt_bound_s=bound, arm=arm, strategy=strategy,
        hold_s=hold, response_delay_s=response_delay,
        true_age_at_commit_s=round(true_age, 4),
        platform_observable_age_s=round(observable_age, 4),
        round_trip_s=round(v.round_trip_s, 6),
        admitted=admitted, value_admitted=resp.value,
        true_value_at_commit=true_value_at_commit,
        stale_admitted=stale,
        integrity_failure=stale,
        availability_failure=(arm == "benign" and not admitted),
        modelled_device_binding=(tier == "strong"),
        reason=reason,
        notes=("upstream of the hub stamp; the hub re-stamps at receipt"
               if position in ("A0", "A1") else "downstream of the hub stamp"),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--seed", type=int, default=20260813)
    a = ap.parse_args()

    rng = random.Random(a.seed)
    run_id = "e2-" + str(a.seed)
    rows = []
    for position in POSITIONS:
        for tier in TIERS:
            for bound in RTT_BOUNDS:
                for arm, strategy in (("benign", "none"),
                                      ("attack", "release_held"),
                                      ("attack", "delay_response")):
                    for i in range(a.n):
                        r = one_trial(rng, position, tier, bound, arm, strategy)
                        r.update(run_id=run_id, scenario="E2_nonce_bound_affirmation",
                                 trial=i)
                        rows.append(r)

    OUT.parent.mkdir(exist_ok=True)
    new = not OUT.exists()
    with OUT.open("a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        if new:
            w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in FIELDS})

    # ---- report ---------------------------------------------------------------------
    print(f"run_id={run_id}  n={a.n} per cell  budget={FRESHNESS_BUDGET}s  hold={HOLD_S}s\n")
    print("  Integrity: a STALE value admitted at the commit.")
    print("  Availability: a BENIGN run refused.\n")
    print(f"  {'position':<10}{'tier':<12}{'bound':>7}   {'integrity':>12}  {'availability':>14}")
    print("  " + "-" * 62)
    for position in POSITIONS:
        for tier in TIERS:
            for bound in RTT_BOUNDS:
                cell = [r for r in rows if r["position"] == position and r["tier"] == tier
                        and r["rtt_bound_s"] == bound]
                atk = [r for r in cell if r["arm"] == "attack"]
                ben = [r for r in cell if r["arm"] == "benign"]
                i_fail = sum(r["integrity_failure"] for r in atk)
                a_fail = sum(r["availability_failure"] for r in ben)
                ilo, ihi = wilson(i_fail, len(atk))
                alo, ahi = wilson(a_fail, len(ben))
                print(f"  {position:<10}{tier:<12}{bound:>7.3f}   "
                      f"{i_fail:>4}/{len(atk):<3} [{ilo:>3},{ihi:>3}]  "
                      f"{a_fail:>4}/{len(ben):<3} [{alo:>3},{ahi:>3}]")
        print()

    print("  === headline ===")
    for tier in TIERS:
        up = [r for r in rows if r["tier"] == tier and r["position"] in ("A0", "A1")
              and r["arm"] == "attack"]
        dn = [r for r in rows if r["tier"] == tier and r["position"] == "B"
              and r["arm"] == "attack"]
        ub = [r for r in rows if r["tier"] == tier and r["arm"] == "benign"]
        print(f"    {tier:<12} upstream integrity failures {sum(r['integrity_failure'] for r in up)}/{len(up)}"
              f"   downstream {sum(r['integrity_failure'] for r in dn)}/{len(dn)}"
              f"   benign refusals {sum(r['availability_failure'] for r in ub)}/{len(ub)}")
    print(f"\n  artefact: {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
