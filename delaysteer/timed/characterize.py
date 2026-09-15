#!/usr/bin/env python3
"""Stage 3 -- characterization: observability curves, selectivity, horizon.

Three things the design asks for that are computable exactly on the bounded
micro-scenario, and therefore need no GPU:

**Observability curves.** The adversary's success as a function of how much it
can see (O_0 blind .. O_4 oracle). This is the claim's honesty check: an attack
that only works at O_3 requires the adversary to read world state, which a
message-aware position does not grant. If the witness survives at O_1, it needs
only timing -- flow boundaries and pending durations -- which is what a relay
genuinely observes.

**Target selectivity.** Whether the adversary can steer to a CHOSEN outcome
rather than merely to *some* violation. A schedule that reliably produces "some
harm" is a reliability bug; one that produces the harm the attacker picked is
steering. The matrix is (intended target x achieved target); a strong diagonal
is the claim, and off-diagonal mass is the honest caveat.

**Steering horizon.** How far ahead of the target the earliest necessary release
sits. A long horizon means the adversary must commit to a plan before the
evidence that it will work exists -- which bounds `preplanned` schedules and is
what makes the `reactive` variant interesting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .sched import Observability


@dataclass
class ObservabilityPoint:
    level: str
    reachable: bool
    n_successes: int
    min_k_flows: int | None
    min_total_hold: float | None
    n_schedules: int


def observability_curve(*, run_at_level: Callable[[str], Any],
                        levels: Iterable[str] = Observability.ORDER
                        ) -> list[ObservabilityPoint]:
    """Enumerate the reachable set at each observability level.

    `run_at_level(level) -> Enumeration`. Because the lattice is NESTED, success
    must be monotone non-decreasing in level: anything a blind adversary can do,
    a sighted one can. A non-monotone curve is a bug in the feature filter, not
    a finding, and `check_monotone` asserts it.
    """
    out = []
    for lvl in levels:
        enum = run_at_level(lvl)
        s = enum.successes
        out.append(ObservabilityPoint(
            level=lvl, reachable=bool(s), n_successes=len(s),
            min_k_flows=min((o.k_flows for o in s), default=None),
            min_total_hold=min((o.total_hold for o in s), default=None),
            n_schedules=len(enum.outcomes)))
    return out


def check_monotone(curve: list[ObservabilityPoint]) -> tuple[bool, str]:
    """The lattice is nested, so reachability cannot DECREASE with more sight."""
    for a, b in zip(curve, curve[1:]):
        if a.reachable and not b.reachable:
            return False, (f"{a.level} reaches the target but {b.level} does "
                           f"not -- the lattice is nested, so this is a feature "
                           f"filter bug, not a result")
    return True, "monotone in observability, as a nested lattice requires"


def minimum_sufficient_level(curve: list[ObservabilityPoint]) -> str | None:
    """The weakest level at which the target is still reachable.

    This is the number the threat model should quote. Reporting success at O_3
    while claiming a message-aware position would overstate the adversary.
    """
    for p in curve:
        if p.reachable:
            return p.level
    return None


# ------------------------------------------------------------ selectivity


@dataclass
class SelectivityMatrix:
    """(intended target -> achieved target) counts."""

    targets: list[str]
    counts: dict[tuple[str, str], int] = field(default_factory=dict)

    def add(self, intended: str, achieved: str | None) -> None:
        key = (intended, achieved or "none")
        self.counts[key] = self.counts.get(key, 0) + 1

    def row_total(self, intended: str) -> int:
        return sum(v for (i, _), v in self.counts.items() if i == intended)

    def precision(self, target: str) -> float:
        """P(achieved == intended | intended == target). The diagonal."""
        n = self.row_total(target)
        return (self.counts.get((target, target), 0) / n) if n else 0.0

    def collateral(self, target: str) -> float:
        """P(achieved is a DIFFERENT violation | intended == target).

        Distinguished from a miss on purpose: hitting the wrong target is a
        different failure from hitting nothing, and averaging them would let a
        scattergun schedule look selective.
        """
        n = self.row_total(target)
        if not n:
            return 0.0
        other = sum(v for (i, a), v in self.counts.items()
                    if i == target and a not in (target, "none"))
        return other / n

    def render(self) -> str:
        cols = self.targets + ["none"]
        w = max(12, max(len(c) for c in cols) + 2)
        lines = ["".ljust(20) + "".join(c.rjust(w) for c in cols)]
        for t in self.targets:
            row = "".join(str(self.counts.get((t, c), 0)).rjust(w) for c in cols)
            lines.append(f"{t:20s}{row}   precision={self.precision(t):.2f} "
                         f"collateral={self.collateral(t):.2f}")
        return "\n".join(lines)


# --------------------------------------------------------- steering horizon


def steering_horizon(*, plan_times: list[float], target_time: float) -> dict[str, Any]:
    """How far ahead of the target the adversary must commit.

    `plan_times` are the times of the NECESSARY releases. The horizon is the
    span from the earliest of them to the target. A large horizon means the
    schedule must be chosen before the evidence it will work exists, which is
    exactly the constraint that separates a preplanned adversary from a reactive
    one -- and it is a cost to the attacker, so it belongs in the paper even
    though it weakens the attack.
    """
    if not plan_times:
        return {"horizon_s": 0.0, "n_releases": 0, "earliest": None}
    earliest = min(plan_times)
    return {"horizon_s": max(0.0, target_time - earliest),
            "n_releases": len(plan_times),
            "earliest": earliest,
            "span_between_releases_s": max(plan_times) - earliest}
