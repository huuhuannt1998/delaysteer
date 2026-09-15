#!/usr/bin/env python3
"""Algorithm 2 (EnumerateReachable) and Algorithm 4 (NecessityTest).

Scenario 4 exhibits *a* composed schedule that reaches the target. That is a
witness, not a result. The reviewer's question is the next one: could a single
delay have done it? Exhaustive enumeration is the only answer that does not
depend on how hard we happened to search, which is why the design bounds the
micro-scenario to five state variables in the first place -- exact enumeration
is sound only on a small state space (Challenge 6).

What makes enumeration finite
-----------------------------
Proposition 1 (event-boundary reduction). Between consecutive boundaries with no
threshold crossing, pi_sec(tau) is invariant to the exact release time, so the
adversary only ever decides AT boundaries, and at each it chooses a subset of
the eligible set. The schedule space is therefore a finite tree, not a search
over the reals.

Determinism is what lets us walk that tree by replay. A run is a pure function
of its decision prefix, so re-running a prefix reproduces the same message
identities -- which is why `FlowMinter.stamp` had to be idempotent and why the
boundary queue breaks ties by insertion order rather than dict order. Without
both, the same prefix would yield different mids on different visits and the
tree would be nonsense.

The two numbers this produces
-----------------------------
    I_k   composition-only reachability. 1 iff the target is reachable by SOME
          schedule and by NO schedule with k_flows <= 1. This is the honest form
          of "you cannot do this with one delay" -- stated over flows, because
          over messages alone a reviewer can correctly reply that repeatedly
          delaying one sensor is not composition (see Sched.k_flows).

    G_k   composition gain at MATCHED TOTAL HOLD. Not matched delta_max: an
          adversary allowed one long hold and one allowed two short ones have
          not spent the same resource, and comparing them would manufacture the
          gain. The comparison is best-composed vs best-single at the same
          integrated hold time.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

MAX_NODES = 20_000


@dataclass
class Outcome:
    """One leaf of the schedule tree."""

    plan: tuple[frozenset[str], ...]
    target: bool
    k: int
    k_flows: int
    total_hold: float
    held: tuple[str, ...]          # mids actually delayed
    flows: tuple[str, ...]         # flows actually delayed
    world: str = ""

    @property
    def is_single(self) -> bool:
        return self.k_flows <= 1


@dataclass
class Enumeration:
    outcomes: list[Outcome] = field(default_factory=list)
    nodes: int = 0
    truncated: bool = False

    # ------------------------------------------------------------ readouts

    @property
    def successes(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.target]

    @property
    def reachable(self) -> bool:
        return bool(self.successes)

    @property
    def single_flow_successes(self) -> list[Outcome]:
        return [o for o in self.successes if o.is_single]

    @property
    def min_witness_flows(self) -> int | None:
        """The smallest k_flows over all schedules that reach the target."""
        s = self.successes
        return min(o.k_flows for o in s) if s else None

    def I_k(self) -> int:
        """Composition-only reachability, per the design.

        1 iff reachable at all AND not reachable by any single-flow schedule.
        Reported alongside `truncated`: a truncated enumeration can only ever
        support I_k = 0 (a witness found), never I_k = 1 (none exists), because
        the schedule it did not visit might be the single-flow one.
        """
        if not self.reachable:
            return 0
        return 0 if self.single_flow_successes else 1

    def G_k(self, tolerance: float = 1e-6) -> dict[str, Any]:
        """Composition gain at matched total hold.

        For the cheapest composed success, ask whether any single-flow schedule
        that spends AT LEAST as much total hold also reaches the target. If some
        do, there is no gain -- the composition just happened to be the schedule
        we found first. If none do, the gain is real rather than an artifact of
        spending more.

        The comparison set must be NON-EMPTY. If no single-flow schedule can
        even spend that budget, "none of them reached the target" is vacuously
        true and says nothing; reporting gain from it would let any composition
        that simply holds longer than one channel allows claim a win it never
        contested. That is the precise shape of the error this metric exists to
        avoid, so it is reported as `vacuous` rather than as gain.
        """
        composed = sorted((o for o in self.successes if not o.is_single),
                          key=lambda x: x.total_hold)
        if not composed:
            return {"gain": False, "reason": "no composed schedule reaches the target"}

        singles = [s for s in self.outcomes if s.is_single]
        for o in composed:
            peers = [s for s in singles if s.total_hold >= o.total_hold - tolerance]
            if not peers:
                continue                    # nothing to compare against at this budget
            hits = [s for s in peers if s.target]
            if hits:
                return {"gain": False,
                        "reason": "a single-flow schedule reaches the target at "
                                  "or above the composed budget",
                        "composed_total_hold": o.total_hold,
                        "single_flow_hits_at_that_budget": len(hits)}
            return {
                "gain": True,
                "composed_total_hold": o.total_hold,
                "composed_k_flows": o.k_flows,
                "single_flow_schedules_at_or_above_that_budget": len(peers),
                "of_which_reached_target": 0,
            }
        return {"gain": False, "vacuous": True,
                "reason": "no single-flow schedule spends a comparable total "
                          "hold, so there is no matched-budget comparison",
                "cheapest_composed_total_hold": composed[0].total_hold,
                "max_single_flow_total_hold": max((s.total_hold for s in singles),
                                                  default=None)}


def enumerate_reachable(
    *,
    run_plan: Callable[[tuple[frozenset[str], ...]], dict],
    max_flows: int = 3,
    max_nodes: int = MAX_NODES,
) -> Enumeration:
    """Walk the whole schedule tree by replaying decision prefixes.

    `run_plan(plan) -> dict` executes one schedule and must return:
        choices     list of eligible-id sets, one per boundary, in order
        target      whether the target set was reached
        k, k_flows, total_hold, held, flows, world

    Boundaries past `len(plan)` fall back to the honest schedule, so every plan
    is a complete, terminating execution -- the tree's leaves are real runs, not
    truncated ones.
    """
    enum = Enumeration()
    seen: set[tuple[frozenset[str], ...]] = set()
    stack: list[tuple[frozenset[str], ...]] = [()]

    while stack:
        if enum.nodes >= max_nodes:
            enum.truncated = True
            break
        plan = stack.pop()
        if plan in seen:
            continue
        seen.add(plan)
        enum.nodes += 1

        res = run_plan(plan)
        enum.outcomes.append(Outcome(
            plan=plan, target=bool(res["target"]), k=int(res["k"]),
            k_flows=int(res["k_flows"]), total_hold=float(res["total_hold"]),
            held=tuple(res.get("held", ())), flows=tuple(res.get("flows", ())),
            world=str(res.get("world", "")),
        ))

        choices = res["choices"]
        d = len(plan)
        if d >= len(choices):
            continue                       # the plan already covers every boundary
        eligible = sorted(choices[d])
        if not eligible:
            # No choice to make here, but later boundaries may still branch.
            # Extend by the (empty) forced decision rather than stopping, or the
            # subtree beyond a quiet boundary is never visited.
            stack.append(plan + (frozenset(),))
            continue
        if int(res["k_flows"]) > max_flows:
            # Sound with respect to I_k. k_flows is monotone non-decreasing
            # along a branch -- a flow once delayed stays delayed -- so no
            # descendant of a prefix already above `max_flows` can have
            # k_flows <= 1. Pruning here therefore cannot hide a single-flow
            # witness, which is the only thing an I_k = 1 claim rests on. It
            # CAN omit large-k_flows successes, so `min_witness_flows` is exact
            # but the success COUNT is a lower bound when this fires.
            continue
        for r in range(len(eligible) + 1):
            for keep in itertools.combinations(eligible, r):
                stack.append(plan + (frozenset(keep),))

    return enum


def summarize(enum: Enumeration) -> str:
    lines = [
        f"nodes visited        : {enum.nodes}{' (TRUNCATED)' if enum.truncated else ''}",
        f"schedules enumerated : {len(enum.outcomes)}",
        f"reached the target   : {len(enum.successes)}",
        f"  of which single-flow: {len(enum.single_flow_successes)}",
        f"min witness (k_flows): {enum.min_witness_flows}",
        f"I_k                  : {enum.I_k()}",
    ]
    g = enum.G_k()
    lines.append(f"G_k (matched hold)   : {g}")
    if enum.truncated and enum.I_k() == 1:
        lines.append("  WARNING: I_k=1 from a truncated enumeration is NOT sound.")
    return "\n".join(lines)


# ------------------------------------------------------- Algorithm 4


@dataclass
class Necessity:
    """Per-release necessity: is every delay in the chain load-bearing?"""

    full_reaches: bool
    minus_one: dict[str, bool] = field(default_factory=dict)

    @property
    def all_necessary(self) -> bool:
        """True iff dropping ANY single release loses the target.

        This is the claim's other half. Positive gain at matched budget says the
        composition buys something; per-release necessity says the chain has no
        passenger -- i.e. it is a chain, not one working delay with decoration.
        """
        return self.full_reaches and not any(self.minus_one.values())


def necessity_test(*, run_with: Callable[[Iterable[Any]], bool],
                   releases: list[Any], labels: list[str] | None = None) -> Necessity:
    """Algorithm 4 -- chain-minus-one.

    `run_with(subset_of_releases) -> reached_target`.
    """
    labels = labels or [str(r) for r in releases]
    full = run_with(releases)
    out: dict[str, bool] = {}
    for i, lab in enumerate(labels):
        rest = [r for j, r in enumerate(releases) if j != i]
        out[lab] = run_with(rest)
    return Necessity(full_reaches=full, minus_one=out)
