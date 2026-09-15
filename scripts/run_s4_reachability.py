#!/usr/bin/env python3
"""Algorithms 2 and 4 over Scenario 4 -- the exact half of the Stage 2 gate.

    python scripts/run_s4_reachability.py

Scenario 4 already exhibits a composed schedule that reaches the target. This
asks the reviewer's next question exhaustively: over the WHOLE schedule space,
is there any single-flow delay that also reaches it? If none exists, I_k = 1 is
a statement about the space rather than about how hard we searched.

Tier 0. The planner here is the deterministic reference, so nothing about a real
agent's behaviour is claimed -- only reachability under the modelled semantics,
which is exactly what an exact enumeration is entitled to say.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from delaysteer.timed import scenario4 as s4
from delaysteer.timed.reachability import (Necessity, enumerate_reachable,
                                           necessity_test, summarize)


def run_plan(plan: tuple[frozenset[str], ...]) -> dict:
    """Execute one schedule described as a per-boundary release set."""
    choices: list[list[str]] = []
    depth = {"i": 0}

    def on_boundary(eligible: list[str]) -> None:
        choices.append(list(eligible))

    def policy(o_t, sched) -> list[str]:
        i = depth["i"]
        depth["i"] = i + 1
        eligible = sched.eligible()
        if i < len(plan):
            # Only ids that are actually eligible here; a plan built on a
            # sibling branch can name a message this branch never generated.
            return [m for m in eligible if m in plan[i]]
        return list(eligible)          # honest completion past the plan's end

    res = s4.run(policy=policy, on_boundary=on_boundary)
    return {
        "choices": choices,
        "target": res["target_reached"],
        "k": res["k"], "k_flows": res["k_flows"],
        "total_hold": res["total_hold"],
        "held": res["delayed_ids"], "flows": res["delayed_flows"],
        "world": repr(res["world"]),
    }


def main() -> int:
    print("=" * 74)
    print("Algorithm 2 -- EnumerateReachable over Scenario 4 (Tier 0, exact)")
    print("=" * 74)
    enum = enumerate_reachable(run_plan=run_plan)
    print(summarize(enum))

    print("\nsuccessful schedules, by witness size:")
    for o in sorted(enum.successes, key=lambda x: (x.k_flows, x.total_hold)):
        print(f"  k={o.k} k_flows={o.k_flows} hold={o.total_hold:8.1f}s "
              f"flows={list(o.flows)}")
    if not enum.successes:
        print("  (none)")

    # ------------------------------------------------------- Algorithm 4
    print("\n" + "=" * 74)
    print("Algorithm 4 -- NecessityTest (chain-minus-one)")
    print("=" * 74)

    def run_with(releases) -> bool:
        rs = list(releases)
        return bool(s4.run(hold=rs)["target_reached"]) if rs else \
            bool(s4.run()["target_reached"])

    nec = necessity_test(run_with=run_with,
                         releases=[s4.delay1, s4.delay2],
                         labels=["delay1 (fresh temperature)",
                                 "delay2 (window confirmation)"])
    print(f"full chain reaches target : {nec.full_reaches}")
    for lab, reached in nec.minus_one.items():
        verdict = "NECESSARY" if not reached else "redundant"
        print(f"  drop {lab:34s} -> target={str(reached):5s}  {verdict}")
    print(f"every release load-bearing: {nec.all_necessary}")

    out = Path("results/s4_reachability.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "algorithm": "EnumerateReachable + NecessityTest",
        "scenario": "S4_ventilation", "tier": "tier0_synthetic",
        "planner": "deterministic_reference",
        "nodes": enum.nodes, "truncated": enum.truncated,
        "schedules": len(enum.outcomes),
        "successes": len(enum.successes),
        "single_flow_successes": len(enum.single_flow_successes),
        "min_witness_k_flows": enum.min_witness_flows,
        "I_k": enum.I_k(),
        "G_k": enum.G_k(),
        "necessity": {"full": nec.full_reaches, "minus_one": nec.minus_one,
                      "all_necessary": nec.all_necessary},
    }, indent=2) + "\n")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
