#!/usr/bin/env python3
"""`Sched` -- the adversary as a scheduler (consolidated design, section 1.3).

    sigma : (O_t, P(t), B_t) -> { hold, release, wait }

The adversary never touches a payload. At each event boundary it decides, for
each pending message, whether to hold it, release it, or wait. Everything this
module does is bookkeeping around that one decision -- but the bookkeeping *is*
the contribution, because a schedule that breaks a feasibility constraint is not
in Sigma and any result derived from it is void.

So the constraints are **enforced, not documented**. Every one of them raises:

  monotone delay        d(m) >= g(m); a message cannot be delivered before it
                        was generated.
  exactly-once          every generated message is delivered exactly once. No
                        forgery, no duplicate, no permanent drop in the core
                        model. `release()` twice on the same id raises.
  payload integrity     the released object is the object that was offered. The
                        scheduler may reorder time, never content -- checked by
                        identity, so a mutating adversary fails loudly.
  ordering by position  A_M may reorder across flows; A_T may release only the
                        eligible head of a per-flow FIFO. Asking A_T for a
                        non-head message raises rather than silently granting a
                        power the capability record denies.
  budget                B = (delta_max, H_max): no single message held longer
                        than delta_max, total held time at most H_max.

Why enforcement rather than convention: the paper's headline is a *composition
gain at matched budget*. If the k-delay arm could quietly overspend, the gain
would measure resource, not composition -- exactly the trivial reading the
design's matched-total-budget rule exists to forbid. The budget therefore has to
be a hard edge in code, not a number in a table.

Not implemented here: the detector constraint D (Stage 5) and the search
policies (Alg. 2/3). This is the mechanism they will drive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

HOLD, RELEASE, WAIT = "hold", "release", "wait"


class Position:
    """Attacker position (design section 2)."""

    A_M = "A_M"   # message-aware: may reorder across flows. Primary.
    A_T = "A_T"   # transport: per-flow FIFO, head/prefix only. Secondary.
    A_O = "A_O"   # oracle: full semantics. Upper bound ONLY, never a rate.

    ALL = (A_M, A_T, A_O)


class Observability:
    """The nested lattice (design section 2). Each level adds to the one below."""

    O0 = "O_0"   # blind: time + a precommitted schedule
    O1 = "O_1"   # timing: flow/message boundary, direction, length, pending duration
    O2 = "O_2"   # structural: O_1 + tool schema, task, known automation graph
    O3 = "O_3"   # state-aware: O_2 + current world state x and belief b
    O4 = "O_4"   # oracle: full semantics + future exogenous schedule

    ORDER = (O0, O1, O2, O3, O4)

    @classmethod
    def rank(cls, level: str) -> int:
        return cls.ORDER.index(level)

    @classmethod
    def allows(cls, level: str, needed: str) -> bool:
        return cls.rank(level) >= cls.rank(needed)


class InfeasibleSchedule(Exception):
    """A constraint of Sigma(A_pos, O, B, D) was violated.

    Raised rather than returned: a schedule outside Sigma is not a worse result,
    it is not a result.
    """


@dataclass
class Budget:
    """B = (delta_max, H_max). None means unbounded on that axis."""

    delta_max: float | None = None   # max hold for any single message
    h_max: float | None = None       # max total held time, summed over messages

    def __str__(self) -> str:
        d = "inf" if self.delta_max is None else f"{self.delta_max:g}s"
        h = "inf" if self.h_max is None else f"{self.h_max:g}s"
        return f"(delta_max={d}, H_max={h})"


@dataclass
class Pending:
    """A generated-but-undelivered message, with its hold accounting."""

    msg: Any                       # an Observation (or any object carrying flow/seq)
    generated_at: float
    entered_at: float              # when the scheduler took custody
    released_at: float | None = None

    @property
    def mid(self) -> str:
        return getattr(self.msg, "mid", f"{self.flow}#{self.seq}")

    @property
    def flow(self) -> str:
        return getattr(self.msg, "flow", "?")

    @property
    def seq(self) -> int:
        return getattr(self.msg, "seq", -1)

    def held_for(self, now: float) -> float:
        """Hold time so far (or total, once released).

        Measured from when the message EXISTED, not from when the scheduler took
        custody. A scheduler may hold custody of a future event -- a timer that
        fires at t=20 is known about at t=0 -- and the interval before it is
        generated is not a delay: nothing was being withheld, because there was
        nothing to withhold.

        Getting this wrong makes the honest schedule look like an attack: every
        message with a future generation time would register a hold equal to its
        own lead time, so sigma_0 would report k>0 and spend budget it never
        used.
        """
        start = max(self.entered_at, self.generated_at)
        end = self.released_at if self.released_at is not None else now
        return max(0.0, end - start)


@dataclass
class Sched:
    """The interposer. In the honest system this is the identity function.

    Usage is deliberately explicit -- `offer` on generation, `release` on
    delivery -- so that "the adversary did nothing here" is a recorded fact
    rather than an absence of code.
    """

    position: str = Position.A_M
    observability: str = Observability.O1
    budget: Budget = field(default_factory=Budget)
    now: Callable[[], float] = lambda: 0.0
    # Nominal freshness epsilon_0: a hold shorter than this is ordinary
    # transport latency, not an adversarial delay.
    #
    # It defaults to 0 because the manual-clock scenarios release a message at
    # EXACTLY the instant it was offered, so a zero threshold is both correct
    # and maximally strict there. On a WALL CLOCK it is not: an HTTP round trip
    # sits between offer and release, so every honest delivery has a positive
    # hold and k() at epsilon=0 counts ordinary latency as attack. The Tier 2
    # harness hit exactly that and reported k=2 on a never-hold arm.
    #
    # Any run driven by a real clock must set this. Carrying it on the Sched
    # means k()/k_flows() pick it up automatically rather than depending on
    # every call site remembering to pass it.
    epsilon0: float = 0.0

    _pending: dict[str, Pending] = field(default_factory=dict)
    _delivered: dict[str, Pending] = field(default_factory=dict)
    _spent: float = 0.0
    _log: list[tuple[float, str, str]] = field(default_factory=list)

    # ---------------------------------------------------------------- custody

    def offer(self, msg) -> str:
        """A message has been generated. The scheduler takes custody.

        Returns its id. Requires identity (`timed.FlowMinter.stamp`), because an
        unidentified message cannot be held or restored individually.
        """
        if getattr(msg, "seq", None) is None or getattr(msg, "flow", None) is None:
            raise InfeasibleSchedule(
                "message has no identity (flow/seq); stamp it at the adapter "
                "boundary before offering it to the scheduler"
            )
        mid = msg.mid
        if mid in self._delivered:
            raise InfeasibleSchedule(f"{mid} was already delivered (exactly-once)")
        if mid in self._pending:
            raise InfeasibleSchedule(f"{mid} is already pending (duplicate offer)")
        t = self.now()
        g = getattr(msg, "generation_time", t)
        self._pending[mid] = Pending(msg=msg, generated_at=g, entered_at=t)
        self._log.append((t, "offer", mid))
        return mid

    # ------------------------------------------------------------- decisions

    def eligible(self) -> list[str]:
        """Message ids this position is permitted to release right now.

        Two filters, in order.

        First, existence: a message whose generation time has not arrived cannot
        be released, because monotone delay forbids d(m) < g(m). It is in the
        pending set (the scheduler has custody of the future event) but it is not
        *eligible*. Without this the honest schedule sigma_0 -- "release
        everything eligible" -- would construct an infeasible schedule and raise,
        which would be the identity interposer failing on a legal scenario.

        Second, position: A_M sees every existing pending message; A_T sees only
        the head of each flow -- the lowest unsent sequence number -- because a
        FIFO transport cannot let a later message overtake an earlier one on the
        same flow.
        """
        t = self.now()
        exists = {mid: p for mid, p in self._pending.items()
                  if p.generated_at <= t + 1e-9}
        if self.position in (Position.A_M, Position.A_O):
            return list(exists)
        heads: dict[str, Pending] = {}
        for p in exists.values():
            cur = heads.get(p.flow)
            if cur is None or p.seq < cur.seq:
                heads[p.flow] = p
        return [p.mid for p in heads.values()]

    def hold(self, mid: str) -> None:
        """Explicitly decline to release. Recorded so inaction is auditable."""
        if mid not in self._pending:
            raise InfeasibleSchedule(f"cannot hold {mid}: not pending")
        self._log.append((self.now(), HOLD, mid))

    def wait(self) -> None:
        """Advance to the next boundary without touching anything."""
        self._log.append((self.now(), WAIT, "-"))

    def release(self, mid: str):
        """Deliver a message, enforcing every feasibility constraint."""
        p = self._pending.get(mid)
        if p is None:
            if mid in self._delivered:
                raise InfeasibleSchedule(f"{mid} already delivered (exactly-once)")
            raise InfeasibleSchedule(f"{mid} is not pending")

        t = self.now()
        if t < p.generated_at:                       # monotone delay
            raise InfeasibleSchedule(
                f"{mid}: delivery {t:.4f} precedes generation {p.generated_at:.4f}"
            )
        if mid not in self.eligible():               # ordering by position
            head = min((q for q in self._pending.values() if q.flow == p.flow),
                       key=lambda q: q.seq, default=None)
            raise InfeasibleSchedule(
                f"{mid}: position {self.position} may not release it; "
                f"flow {p.flow} head is {head.mid if head else '?'}"
            )

        held = p.held_for(t)
        if self.budget.delta_max is not None and held > self.budget.delta_max + 1e-9:
            raise InfeasibleSchedule(
                f"{mid}: held {held:.4f}s > delta_max {self.budget.delta_max:g}s"
            )
        if self.budget.h_max is not None and self._spent + held > self.budget.h_max + 1e-9:
            raise InfeasibleSchedule(
                f"{mid}: total hold {self._spent + held:.4f}s > H_max "
                f"{self.budget.h_max:g}s -- the matched-budget rule forbids "
                f"buying the result with more resource"
            )

        p.released_at = t
        self._spent += held
        del self._pending[mid]
        self._delivered[mid] = p
        self._log.append((t, RELEASE, mid))
        return p.msg

    def release_all_due(self, until: float | None = None) -> list:
        """Honest behaviour: deliver everything eligible, oldest first."""
        out = []
        while True:
            elig = [m for m in self.eligible()
                    if until is None or self._pending[m].generated_at <= until]
            if not elig:
                return out
            nxt = min(elig, key=lambda m: (self._pending[m].generated_at,
                                           self._pending[m].flow,
                                           self._pending[m].seq))
            out.append(self.release(nxt))

    # ------------------------------------------------------------ accounting

    @property
    def spent(self) -> float:
        """Total held time over delivered messages (design's H_max axis)."""
        return self._spent

    @property
    def max_single_hold(self) -> float:
        """Largest single-message hold (the delta_max axis)."""
        return max((p.held_for(p.released_at or self.now())
                    for p in self._delivered.values()), default=0.0)

    def delayed_ids(self, epsilon: float | None = None) -> list[str]:
        """Messages held beyond a nominal freshness epsilon0.

        This is the design's definition of "a delay": Sigma_k delays at most k
        DISTINCT messages, so the count here -- not the number of release calls
        -- is what k bounds.
        """
        eps = self.epsilon0 if epsilon is None else epsilon
        return sorted(p.mid for p in self._delivered.values()
                      if p.held_for(p.released_at or 0.0) > eps)

    def k(self, epsilon: float | None = None) -> int:
        """How many distinct MESSAGES were delayed."""
        return len(self.delayed_ids(epsilon))

    def delayed_flows(self, epsilon: float | None = None) -> list[str]:
        """Distinct FLOWS on which at least one message was delayed."""
        eps = self.epsilon0 if epsilon is None else epsilon
        return sorted({p.flow for p in self._delivered.values()
                       if p.held_for(p.released_at or 0.0) > eps})

    def k_flows(self, epsilon: float | None = None) -> int:
        """How many distinct CHANNELS were delayed.

        Both counts exist because the design defines Sigma_k over "distinct
        messages (or flow episodes)", and the two diverge exactly where the
        paper's central claim lives.

        Starving a retry ladder holds three messages on ONE channel: k=3,
        k_flows=1. That is a sustained single-channel delay -- the thing already
        mislabelled `family_class="multi_delay"` in the Sigma_1 codebase -- and
        it is NOT composition. Scenario 4's gate witness holds two messages on
        TWO channels: k=2, k_flows=2, with no single delay on either channel
        reaching the target.

        A composition claim must therefore be stated over `k_flows`. Stated over
        `k` alone, the trivial reading -- "you just delayed one sensor
        repeatedly" -- is available to a reviewer, and correct.
        """
        return len(self.delayed_flows(epsilon))

    def assert_drained(self) -> None:
        """Eventual delivery: nothing may be left held at the horizon."""
        if self._pending:
            raise InfeasibleSchedule(
                "eventual delivery violated; still pending: "
                + ", ".join(sorted(self._pending))
            )

    def certificate(self) -> dict[str, Any]:
        """Reproducibility certificate for this schedule."""
        return {
            "position": self.position,
            "observability": self.observability,
            "budget": {"delta_max": self.budget.delta_max, "h_max": self.budget.h_max},
            "delivered": len(self._delivered),
            "still_pending": len(self._pending),
            "k_delayed": self.k(),
            "k_flows": self.k_flows(),
            "delayed_ids": self.delayed_ids(),
            "delayed_flows": self.delayed_flows(),
            "total_hold_s": round(self._spent, 6),
            "max_single_hold_s": round(self.max_single_hold, 6),
        }

    def log(self) -> list[tuple[float, str, str]]:
        return list(self._log)


def observe(sched: Sched, world: Any = None, belief: Any = None) -> dict[str, Any]:
    """O_t -- the features a policy at this observability level may consume.

    A search that peeks above its level would report a rate it is not entitled
    to, so the filter is applied here rather than trusted to the policy.
    """
    lvl = sched.observability
    o: dict[str, Any] = {"t": sched.now()}                       # O_0: time only
    if Observability.allows(lvl, Observability.O1):
        o["pending"] = [
            {"mid": p.mid, "flow": p.flow, "seq": p.seq,
             "pending_for": p.held_for(sched.now())}
            for p in sched._pending.values()
        ]
    if Observability.allows(lvl, Observability.O2):
        o["types"] = sorted({getattr(p.msg, "msg_type", "?")
                             for p in sched._pending.values()})
    if Observability.allows(lvl, Observability.O3):
        o["world"], o["belief"] = world, belief
    if Observability.allows(lvl, Observability.O4):
        o["oracle"] = True
    return o
