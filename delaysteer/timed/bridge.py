#!/usr/bin/env python3
"""`SchedulingAdapter` -- the bridge from the Sigma_k substrate to the real agent.

The existing agent loop (`agentkit.run_agent`) owns its turns and asks for tool
results through a `dispatch` callback. That is not an obstacle to the design's
model; it is where the interposer belongs. In the design's terms a `query`
action *generates* a tool-result message with a later generation time, and the
adversary decides when that message is delivered. `dispatch` is exactly that
boundary, so `Sched` slots in there rather than requiring the planner to be
rewritten around `seeded_replay`.

What this buys immediately
--------------------------
Every existing scenario becomes runnable on the Sigma_k substrate without being
rewritten: it gains message identity, enforced feasibility constraints, a
capability record, and -- the point -- the ability to hold **more than one**
message at a time. `attack/strict_delay.py` can hold exactly one
`HeldObservation` for one entity; here the pending set is the scheduler's, so k
is bounded by the budget rather than by the adapter's shape.

Hold semantics
--------------
When the scheduler holds a message the agent still has to receive *something* --
a real deployment does not block forever. The two faithful answers are the two
attack primitives the Sigma_1 work already established, so both are supported:

  STALE     re-serve the last value delivered for this entity. The message is
            genuine and was true when generated; only its age is adversarial.
            This is stale-truth (Scenarios 1, 2, 4).
  TIMEOUT   return a timeout marker, so the agent's recovery ladder fires. This
            is what manufactures the uncertainty in Scenario 3.

`STALE` with no prior delivery falls back to `TIMEOUT`, because inventing a
first value would be forgery -- outside the threat model.

The held message stays in the pending set and must still be delivered, so
`assert_drained()` at the end of an episode is a real check: an adversary that
simply drops a message is not delay-only, and the substrate will say so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..home.adapter import HomeAdapter, Observation
from .envelope import FlowMinter, MsgType
from .sched import Sched

STALE = "stale"
TIMEOUT = "timeout"


@dataclass
class HoldDecision:
    """What the policy decided for one message, and why. Recorded for the trace."""

    hold: bool
    mode: str = STALE
    reason: str = ""


# A policy sees the observation about to be delivered plus the scheduler, and
# says whether to hold it. Kept deliberately small: anything richer would need
# an observability level it may not have.
HoldPolicy = Callable[[Observation, Sched], HoldDecision]


def never_hold(obs: Observation, sched: Sched) -> HoldDecision:
    """sigma_0 -- the honest schedule."""
    return HoldDecision(hold=False)


def hold_entities(entities: dict[str, str] | set[str], *, mode: str = STALE,
                  times: dict[str, int] | None = None, after: int = 0) -> HoldPolicy:
    """Hold the named entities, from read `after` onward, for at most `times` reads.

    `after` matters more than it looks. In STALE mode the adversary re-serves the
    last value that WAS delivered, so it must let a benign reading through before
    it has anything to re-serve -- holding from read 0 leaves nothing to serve
    and correctly degenerates to a timeout, which is a different primitive.
    `after=1` is the stale-truth shape: the agent sees a true "closed", the world
    changes, and the update that would have corrected the belief is the one held.

    `times` bounds how many reads are held, which is what deliver-once and the
    Scenario-4 confirmation hold both need.
    """
    targets = set(entities)
    budget = dict(times or {})
    seen: dict[str, int] = {}

    def policy(obs: Observation, sched: Sched) -> HoldDecision:
        eid = obs.entity_id or ""
        if eid not in targets:
            return HoldDecision(hold=False)
        n = seen.get(eid, 0)
        seen[eid] = n + 1
        if n < after:
            return HoldDecision(hold=False, reason=f"read #{n} < after={after}")
        held_so_far = n - after
        limit = budget.get(eid)
        if limit is not None and held_so_far >= limit:
            return HoldDecision(hold=False, reason=f"hold budget {limit} spent")
        return HoldDecision(hold=True, mode=mode, reason=f"read #{n}")

    return policy


@dataclass
class SchedulingAdapter(HomeAdapter):
    """Wraps a HomeAdapter and routes every observation through a `Sched`."""

    inner: HomeAdapter
    sched: Sched
    policy: HoldPolicy = never_hold
    minter: FlowMinter = field(default_factory=FlowMinter)

    _last_delivered: dict[str, Observation] = field(default_factory=dict)
    _events: list[dict[str, Any]] = field(default_factory=list)

    # ---------------------------------------------------------------- reads

    def get_state(self, entity_id: str) -> Observation:
        truth = self.inner.get_state(entity_id)
        # Identity is minted here if the inner adapter did not already do it;
        # stamp() is idempotent, so an already-identified message is untouched.
        self.minter.stamp(truth, msg_type=MsgType.OBSERVATION)
        self.sched.offer(truth)

        decision = self.policy(truth, self.sched)
        if not decision.hold:
            delivered = self.sched.release(truth.mid)
            self._last_delivered[entity_id] = delivered
            self._record(entity_id, truth, "release", decision)
            return delivered

        # held: the message stays pending and must still be delivered later
        self._record(entity_id, truth, f"hold:{decision.mode}", decision)
        prior = self._last_delivered.get(entity_id)
        if decision.mode == STALE and prior is not None:
            # Re-serve the previous genuine value. Its generation_time is the
            # ORIGINAL one -- that is what makes the age adversarial and what a
            # freshness check is supposed to catch.
            return prior
        return self._timeout_observation(truth)

    def _timeout_observation(self, truth: Observation) -> Observation:
        """A read that did not complete. Not a forged value -- an absent one."""
        return Observation(
            semantic_type=truth.semantic_type,
            value="unavailable",
            attributes={"timeout": True},
            source=truth.source,
            entity_id=truth.entity_id,
            generation_time=truth.generation_time,
            arrival_time=truth.generation_time,
            flow=truth.flow, seq=truth.seq, msg_type=truth.msg_type,
        )

    def _record(self, entity_id: str, obs: Observation, what: str,
                d: HoldDecision) -> None:
        self._events.append({
            "entity_id": entity_id, "mid": obs.mid, "action": what,
            "reason": d.reason, "generation_time": obs.generation_time,
        })

    # ------------------------------------------------------------ passthrough

    def call_service(self, domain: str, service: str,
                     data: dict[str, Any] | None = None) -> Observation:
        ack = self.inner.call_service(domain, service, data)
        self.minter.stamp(ack, msg_type=MsgType.ACTUATION_ACK)
        return ack

    def entities(self) -> dict[str, str]:
        return self.inner.entities()

    # -------------------------------------------------------------- reporting

    def release_held(self) -> list[Observation]:
        """Deliver everything still pending. Delay-only means eventual delivery,
        so an episode that ends with messages outstanding has not finished."""
        return self.sched.release_all_due()

    @property
    def events(self) -> list[dict[str, Any]]:
        return list(self._events)

    def certificate(self) -> dict[str, Any]:
        return self.sched.certificate()
