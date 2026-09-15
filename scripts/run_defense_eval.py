#!/usr/bin/env python3
"""Stage 6 -- defense evaluation: residual reachability per attacker POSITION.

    python scripts/run_defense_eval.py

The headline a reader wants is "TemporalGuard blocks X%". That single number is
the one thing this evaluation refuses to print, because it is not well defined:
a receiver-side check's coverage depends entirely on whether the adversary sits
before or after the point where the timestamp is minted. Reporting one figure
would average over the case that matters and hide it.

Positions (the paper's own lattice, orthogonal to A_M/A_T):
    P-A0  device -> hub      adversary BEFORE the hub stamps
    P-A1  in-hub             also before the stamp
    P-B   hub -> agent       AFTER the truthful stamp is minted

Defenses, matching the design's mandatory baseline list:
    none                   no check
    receiver_max_age       a plain TTL on the receiver's stamp
    reevaluate_conditions  re-read and re-check preconditions, no freshness
    target_versioning      version equality on the read set only
    Lite                   full GuardedCommit on receiver-side origin
    Attested               full GuardedCommit on trusted origin time

Benign rejection is measured on the same axis, because a defense that blocks
everything has a perfect residual and is useless.
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from delaysteer.timed.detect import BenignJitter, calibrate
from delaysteer.timed.guard import (ALLOW, ATTESTED, LITE, SECURITY_WEAKENING,
                                    Action, Entity, ReadObservation,
                                    TemporalGuard, Trigger)

DOOR = "binary_sensor.front_door"

P_A0, P_A1, P_B = "P-A0_device_to_hub", "P-A1_in_hub", "P-B_hub_to_agent"
POSITIONS = (P_A0, P_A1, P_B)

DEFENSES = ("none", "receiver_max_age", "reevaluate_conditions",
            "target_versioning", "Lite", "Counter", "Attested")

# `Counter` models a defense the link layers already ship and the application layer
# throws away: Zigbee APS/NWK frame counters, Z-Wave S2 nonces, Matter per-session
# message counters. Unlike a receiver stamp, the counter is minted AT THE SOURCE,
# carried WITH the message and integrity-bound, so a delay adversary cannot advance
# it -- which is the one property Lite lacks and Attested has to buy with firmware.
#
# What it detects, precisely. Hold one frame while its channel-mates pass and the
# receiver observes counter N AFTER N+1: an INVERSION. Benign loss cannot produce
# that -- loss removes a counter, it cannot make a later one arrive first -- so the
# inversion is the signature of holding and is distinguishable from the loss that
# would otherwise make this a false-positive machine.
#
# What it does NOT detect: a blanket hold of the whole channel preserves counter
# order and is invisible here. That residual is real and we report it, but it is not
# the attack -- an indiscriminate hold is Control B, which reaches the target 0/6
# across holds from 30s to 9000s (results/s4_controls.json). DelaySteer's adversary
# is fact-selective by construction (Sec. 3), and fact-selective IS the inverting case.
#
# MODELLED, like Attested: no hub we measured surfaces link-layer counters to the
# application. The claim is that the evidence exists on the wire today, not that a
# deployer can read it today.


@dataclass
class Episode:
    """One attempted commit under a delay of `hold` seconds at `position`.

    `selective` records whether the adversary held ONE fact while the channel's other
    traffic passed (the threat model of Sec. 3) or held the channel wholesale. Only
    the counter check distinguishes them; every other defense here is indifferent.
    """
    hold: float
    position: str
    now: float = 1000.0
    selective: bool = True

    def trigger(self) -> Trigger:
        gen = self.now - self.hold
        # The stamp is minted at the hub. An adversary at P-A0/P-A1 delays
        # BEFORE that, so the hub stamps the message when it finally arrives and
        # the receiver-side age looks tiny. At P-B the delay happens after the
        # stamp, so the receiver-side age is truthful.
        receipt = self.now - 0.5 if self.position in (P_A0, P_A1) else gen
        return Trigger(DOOR, "off", generation_time=gen, receipt_time=receipt)


def _admits(defense: str, ep: Episode, *, stale_world: bool,
            ttl: float | None = None) -> bool:
    """True if the defense lets the commit through.

    THE MODELLING POINT THIS EVALUATION TURNS ON. The Guard is part of the
    trusted agent runtime, which sits DOWNSTREAM of the adversary at every
    position in the lattice. So when the Guard re-reads an entity to check
    `Current` or re-evaluate `Cond`, that read travels the same delayed channel
    the original observation did. The Guard's notion of "the current version" is
    therefore the ATTACKER'S version, not the world's.

    This is why re-reading cannot rescue a check against an adversary on its own
    read path, and it is easy to get backwards: an earlier draft of this script
    gave the Guard an undelayed view of entity versions, which made every
    version-aware defense appear to block the attack at every position and made
    the Lite/Attested distinction -- the paper's central defense axis --
    disappear entirely.

    Attested is different in kind precisely because its evidence is CARRIED with
    the message and integrity-bound, rather than re-fetched through the channel
    the adversary controls.
    """
    tr = ep.trigger()
    a = Action("arm_alarm", SECURITY_WEAKENING, target="alarm")

    # What the Guard SEES when it re-reads: the stale value, because its read
    # path is the delayed one. The world may have moved; the Guard cannot see it.
    seen_version = 0
    seen_state = "off"

    if defense == "none":
        return True
    if defense == "receiver_max_age":
        from delaysteer.timed.guard import DELTA_CLASS as _DC
        _ttl = ttl if ttl is not None else _DC[SECURITY_WEAKENING]
        return (ep.now - tr.receipt_time) <= _ttl
    if defense == "reevaluate_conditions":
        # Re-reads and re-checks preconditions, with no notion of time. Its
        # re-read is delayed too, so it sees exactly what the agent saw and
        # confirms it. No temporal information anywhere in this check.
        return True
    if defense == "target_versioning":
        ents = {DOOR: Entity(DOOR, seen_state, version=seen_version)}
        g = TemporalGuard(mode=ATTESTED, entities=ents, now=lambda: ep.now)
        return g._current([ReadObservation(DOOR, seen_version)])

    if defense == "Counter":
        # Selective hold => the held frame's counter arrives after its channel-mates'.
        # The check is order, not recency, so it is indifferent to WHERE the delay was
        # applied: it fails at P-A0 and P-A1 exactly as it does at P-B, which is the
        # property the receiver stamp cannot have.
        return not ep.selective          # admits only if the hold was NOT selective

    mode = LITE if defense == "Lite" else ATTESTED
    ents = {DOOR: Entity(DOOR, seen_state, version=seen_version)}
    g = TemporalGuard(mode=mode, entities=ents, now=lambda: ep.now)
    d = g.guarded_commit(a, tr, [ReadObservation(DOOR, seen_version)])
    return d.admitted


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--holds", default="5,27,60,600")
    ap.add_argument("--out", default="results/defense_residual.csv")
    ap.add_argument("--delta", type=float, default=None,
                    help="override the security_weakening class budget (default 30s). "
                         "Our live deployment runs 2s on lock/contact/alarm, and the "
                         "baselines only differentiate below the class default.")
    a = ap.parse_args()
    holds = [float(x) for x in a.holds.split(",")]

    # The residual matrix is otherwise pinned to the class default, which is why every
    # baseline admits at 5s and 27s: the budget is doing what it was configured to do.
    from delaysteer.timed import guard as _g
    _orig_delta = _g.DELTA_CLASS[SECURITY_WEAKENING]
    if a.delta is not None:
        _g.DELTA_CLASS[SECURITY_WEAKENING] = a.delta
        print(f"  [class budget for security_weakening overridden: "
              f"{_orig_delta:g}s -> {a.delta:g}s]\n")

    # Benign rejection: an honest message with ordinary jitter must be admitted.
    j = BenignJitter()
    cal = calibrate("max_age", fpr=0.01, jitter=j)
    import random
    rng = random.Random(0)
    benign_delays = [j.sample(rng) for _ in range(2000)]

    rows = []
    print("RESIDUAL REACHABILITY BY ATTACKER POSITION")
    print("  (fraction of attacked commits the defense still ADMITS;")
    print("   lower is better. A single averaged number would hide P-A0.)\n")
    print(f"{'defense':22s} {'hold':>6s} " + "".join(f"{p:>22s}" for p in POSITIONS))
    print("-" * 92)
    for defense in DEFENSES:
        for hold in holds:
            cells = []
            for pos in POSITIONS:
                ep = Episode(hold=hold, position=pos)
                admitted = _admits(defense, ep, stale_world=True)
                cells.append(admitted)
                rows.append({"defense": defense, "position": pos, "hold_s": hold,
                             "admitted": int(admitted),
                             "residual": int(admitted)})
            print(f"{defense:22s} {hold:6.0f} " +
                  "".join(f"{('ADMITS' if c else 'blocks'):>22s}" for c in cells))
        print()

    # benign rejection, same defenses
    print("BENIGN REJECTION (honest traffic wrongly blocked; lower is better)")
    print(f"{'defense':22s} {'FPR on benign':>16s}")
    print("-" * 42)
    benign_rows = []
    for defense in DEFENSES:
        rejects = 0
        for d in benign_delays:
            ep = Episode(hold=d, position=P_B)      # honest: no attacker
            if not _admits(defense, ep, stale_world=False):
                rejects += 1
        fpr = rejects / len(benign_delays)
        benign_rows.append({"defense": defense, "benign_fpr": round(fpr, 4)})
        print(f"{defense:22s} {100*fpr:15.2f}%")

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["defense", "position", "hold_s",
                                           "admitted", "residual"])
        w.writeheader()
        w.writerows(rows)
    print(f"\nwrote {out}")

    # ---------------------------------------------- the protection frontier
    # Delta_class is a POLICY CHOICE, not a fact, so the interplay between the
    # freshness bound and the detectability ceiling has to be swept rather than
    # asserted from one setting. Tightening Delta blocks shorter holds but
    # rejects more honest traffic; that trade is the design's Fig-9 frontier.
    from delaysteer.timed.guard import DELTA_CLASS
    orig = DELTA_CLASS[SECURITY_WEAKENING]
    print("\nPROTECTION FRONTIER: freshness bound vs benign rejection")
    print("  (Attested, P-A0. The detectability ceiling at 1% FPR is ~27s, so a")
    print("   Delta above it leaves a window that is BOTH undetectable AND")
    print("   admitted.)")
    # The magnitude sweep found the attack fully effective at a 5s hold, so the
    # frontier has to be probed against the hold the attack ACTUALLY needs, not
    # against a convenient one.
    probes = (5.0, 15.0, 27.0)
    print(f"{'Delta_s':>8s} " + "".join(f"{'blocks ' + str(int(h)) + 's':>13s}"
                                        for h in probes)
          + f"{'benign rejected':>17s}")
    print("-" * 70)
    frontier_rows = []
    try:
        for delta in (1.0, 2.0, 3.0, 5.0, 10.0, 20.0, 30.0, 60.0):
            DELTA_CLASS[SECURITY_WEAKENING] = delta
            blocks = [not _admits("Attested", Episode(hold=h, position=P_A0),
                                  stale_world=True) for h in probes]
            rej = sum(1 for d in benign_delays
                      if not _admits("Attested", Episode(hold=d, position=P_B),
                                     stale_world=False))
            fpr = rej / len(benign_delays)
            row = {"delta_s": delta, "benign_fpr": round(fpr, 4)}
            for h, b in zip(probes, blocks):
                row[f"blocks_{int(h)}s"] = int(b)
            frontier_rows.append(row)
            print(f"{delta:8.0f} " + "".join(f"{str(b):>13s}" for b in blocks)
                  + f"{100*fpr:16.2f}%")
    finally:
        DELTA_CLASS[SECURITY_WEAKENING] = orig

    fp = Path("results/defense_frontier.csv")
    with fp.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["delta_s","blocks_5s","blocks_15s","blocks_27s","benign_fpr"])
        w.writeheader()
        w.writerows(frontier_rows)
    print(f"wrote {fp}")

    print("\nTHE DEPLOYABLE ANSWER (design section 11.3, stated as a headline)")
    print("  Lite needs no device cooperation and can be deployed this week.")
    print("  It bounds an adversary at P-B, where the hub's truthful stamp")
    print("  survives the delay. It is BLIND at P-A0 and P-A1, where the delay")
    print("  happens before the stamp is minted, so the freshness check runs on")
    print("  the attacker's own timeline. That is not an implementation gap to")
    print("  be closed later; it is what a receiver-side stamp can mean.")
    print("  Closing P-A0/P-A1 requires attested origin time -- device firmware")
    print("  that no shipping consumer device provides.")
    print("\n  Operationally: security_weakening actions must fail closed or")
    print("  escalate rather than proceed, and config_edit needs an epoch lease")
    print("  (Scenario 5 shows freshness alone provably cannot govern it).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
