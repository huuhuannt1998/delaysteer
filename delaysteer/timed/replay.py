#!/usr/bin/env python3
"""Algorithm 1 -- SeededReplay, on event-boundary stepping.

The primitive every other algorithm calls. Deterministic given (model, seed) at
temperature 0, which is what makes per-seed reachability exact while keeping a
real agent in the loop.

Proposition 1 (event-boundary reduction) is why this is a *finite* loop. Between
two consecutive boundaries with no threshold crossing, both the world state and
the agent's next input are invariant to the exact delivery time of a message
released in that interval -- so any release time can be canonicalized to the next
boundary without changing pi_sec(tau) or the truth of a property. The adversary
therefore only ever chooses at boundaries, and the schedule space is finite.
That is what makes Algorithm 2's exact enumeration well defined rather than a
search over the reals.

Boundaries are: message generation times, timer expirations, action completions,
freshness deadlines, and detector-threshold crossings.

The loop is written against injected callables rather than a concrete planner,
so the existing scenarios can be ported onto it one at a time instead of in a
single rewrite:

    agent(delivered, history) -> list[Action]     the policy pi
    apply_action(action, world) -> list[Message]  world update + endogenous msgs
    quiescent(world, sched) -> bool               stop condition

`service_delay` is what makes the endogenous set real: an action issued at t
enqueues its result with generation time t + delay, so that message exists only
because the agent took that branch -- and can then itself be delayed, which is
Recursive Temporal Steering.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .sched import Sched, observe
from .trace import ACT, BOUNDARY, DELIVER, GENERATE, GUARD, STATE, Trace


@dataclass(order=True)
class _Boundary:
    """A scheduled decision point.

    Ordered by (t, tiebreak) so the queue is deterministic even when two
    boundaries land on the same instant -- ties break by insertion order, never
    by dict iteration order, which would vary between runs and silently destroy
    the reproducibility this module exists to provide.
    """

    t: float
    tiebreak: int
    reason: str = field(compare=False, default="")


class BoundaryQueue:
    """The finite set B(S, sigma) of Proposition 1."""

    def __init__(self) -> None:
        self._h: list[_Boundary] = []
        self._n = 0

    def push(self, t: float, reason: str = "") -> None:
        self._n += 1
        heapq.heappush(self._h, _Boundary(t, self._n, reason))

    def pop(self) -> _Boundary | None:
        return heapq.heappop(self._h) if self._h else None

    def __bool__(self) -> bool:
        return bool(self._h)

    def __len__(self) -> int:
        return len(self._h)


@dataclass
class Action:
    """An element of the action space A."""

    name: str
    args: dict[str, Any] = field(default_factory=dict)
    is_commit: bool = False        # security-relevant -> routed through Guard

    def __str__(self) -> str:
        return self.name


@dataclass
class ReplayResult:
    trace: Trace
    sched: Sched
    world: Any
    horizon_hit: bool = False

    def certificate(self) -> dict[str, Any]:
        return {**self.sched.certificate(),
                "events": len(self.trace),
                "horizon_hit": self.horizon_hit}


def honest_schedule(o_t: dict, sched: Sched) -> list[str]:
    """sigma_0 -- release everything eligible. The identity interposer."""
    return sched.eligible()


def seeded_replay(
    *,
    world: Any,
    initial_messages: Iterable[Any],
    agent: Callable[[list, list], list],
    apply_action: Callable[[Action, Any], list],
    sched: Sched,
    clock_set: Callable[[float], None],
    quiescent: Callable[[Any, Sched], bool] | None = None,
    guard: Callable[[Action, Any], str] | None = None,
    service_delay: Callable[[Action], float] = lambda a: 0.05,
    horizon: float = 1e6,
    policy: Callable[[dict, Sched], list[str]] | None = None,
    meta: dict[str, Any] | None = None,
) -> ReplayResult:
    """Run one execution and return tau(S, sigma).

    `policy` is sigma: given the filtered observation O_t and the scheduler, it
    returns the ids to release at this boundary. Default is the honest schedule.
    A policy that returns [] forever is a total hold, which `assert_drained`
    will correctly reject as a violation of eventual delivery rather than
    silently producing a "successful" attack.
    """
    trace = Trace(meta=dict(meta or {}))
    bq = BoundaryQueue()
    history: list = []
    policy = policy or honest_schedule

    # eps at t0 -- the exogenous schedule
    for m in initial_messages:
        g = getattr(m, "generation_time", 0.0)
        sched.offer(m)
        trace.record(g, GENERATE, mid=m.mid, flow=m.flow, seq=m.seq,
                     label=getattr(m, "semantic_type", None), endogenous=False)
        bq.push(g, "exogenous")

    horizon_hit = False
    while bq:
        b = bq.pop()
        if b.t > horizon:
            horizon_hit = True
            break
        clock_set(b.t)
        trace.record(b.t, BOUNDARY, label=b.reason)

        # sigma decides, seeing only what its observability level permits
        o_t = observe(sched, world=world)
        to_release = policy(o_t, sched)

        delivered = []
        for mid in list(to_release):
            m = sched.release(mid)      # every feasibility constraint enforced there
            delivered.append(m)
            history.append(m)
            trace.record(b.t, DELIVER, mid=mid, flow=getattr(m, "flow", None),
                         seq=getattr(m, "seq", None),
                         label=getattr(m, "semantic_type", None))

        # pi acts on the delivered history
        for action in agent(delivered, history) or []:
            if action.is_commit and guard is not None:
                verdict = guard(action, world)
                trace.record(b.t, GUARD, label=verdict,
                             payload={"action": action.name})
                if verdict not in ("ALLOW", "SAFE_EXECUTE"):
                    trace.record(b.t, ACT, label=f"{action.name}:blocked")
                    continue
            trace.record(b.t, ACT, label=action.name, payload=dict(action.args))

            # Endogenous generation: the formal seat of "a delayed branch emits
            # a message the clean run never produces".
            for m in apply_action(action, world) or []:
                if not getattr(m, "generation_time", None):
                    m.generation_time = b.t + service_delay(action)
                # The boundary must be where the message actually becomes
                # available, NOT t + service_delay. An action that schedules a
                # timer far in the future (a 20-minute vent cycle) generates its
                # message then, and pushing the boundary at the service delay
                # instead would leave the message pending with no boundary at
                # which it is ever eligible -- silently truncating the branch.
                sched.offer(m)
                trace.record(m.generation_time, GENERATE, mid=m.mid, flow=m.flow,
                             seq=m.seq, label=getattr(m, "semantic_type", None),
                             endogenous=True, cause=action.name)
                bq.push(m.generation_time, f"endogenous:{action.name}")

        trace.record(b.t, STATE, payload={"repr": repr(world)[:200]})
        if quiescent and quiescent(world, sched):
            break

    return ReplayResult(trace=trace, sched=sched, world=world,
                        horizon_hit=horizon_hit)
