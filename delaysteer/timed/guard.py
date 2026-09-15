#!/usr/bin/env python3
"""Algorithm 7 -- GuardedCommit. TemporalGuard's protected-commit boundary.

Contribution C-C. Four predicates decide admission; a fact class decides what
happens when one fails. The split matters: a uniform fail-closed response is
both unsafe (it can block a protective action) and unusable (it escalates
comfort actions to the resident until they stop reading the prompts).

    Fresh    now - origin(trigger) <= Delta_class(a)
    Current  every entity in the read set is still at the version the agent
             evaluated
    Cond     the action's stated preconditions hold on the CURRENT world
    NotSup   this intent has not been superseded by a later one on the same
             target

Lite versus Attested -- the paper's central defense axis
-------------------------------------------------------
The only difference is where `origin` comes from, and it is decisive.

    Lite      origin = the receiver's stamp, i.e. when the hub SAW the message.
              Deployable today, no device cooperation. But a hub that stamps at
              receipt cannot distinguish "generated now" from "generated ten
              minutes ago and delayed in transit" -- the stamp is minted after
              the delay has already happened. Against an adversary positioned
              BEFORE the stamping point (P-A0 device->hub, P-A1 in-hub) the
              freshness check is computed on the attacker's own timeline.
              This is not an implementation weakness; it is what a receiver-side
              stamp can mean.

    Attested  origin = a trusted origin time carried with the message and bound
              to it. Detects pre-ingress delay. Requires device-side attestation
              that no shipping consumer device provides.

So Lite's coverage is POSITION-CONDITIONAL: it bounds an adversary at P-B
(hub->agent, where the hub's truthful stamp survives) and is blind at P-A0/P-A1.
Reporting a single "TemporalGuard blocks X%" would hide exactly the case that
matters, so the residual is always reported per position.

What this does not claim
------------------------
Harm inside the accepted freshness interval; missing or compromised sensors; a
compromised Guard or ingress; actions not routed through the Guard; an
incomplete read set; an unsafe fallback policy; and durable edits whose danger
is realized only in a later episode -- Scenario 5's case, which no per-commit
freshness predicate can see, because at the moment of that edit nothing is
stale. That last one is why `config_edit` gets a lease rather than a freshness
check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

# ------------------------------------------------------------------ verdicts

ALLOW = "ALLOW"
REJECT = "REJECT"
ESCALATE = "ESCALATE"
SAFE_EXECUTE = "SAFE_EXECUTE"
REEVALUATE = "REEVALUATE"
REQUIRE_LEASE = "REQUIRE_EPOCH_INTENT_LEASE"

PASSING = (ALLOW, SAFE_EXECUTE)

# --------------------------------------------------------------------- modes

LITE, ATTESTED = "Lite", "Attested"

# --------------------------------------------------------------- fact classes

SECURITY_WEAKENING = "security_weakening"   # unlock, disarm, relax, disable
PROTECTIVE = "protective"                   # alarm, lock, close valve, notify
COMFORT = "comfort"                         # lights, HVAC, media
CONFIG_EDIT = "config_edit"                 # durable automation writes

# Freshness bound by ACTION CLASS, not by semantic type. The design is explicit
# that Delta is Delta_class(a): how stale a reading may be depends on what is
# about to be done with it, not on what kind of sensor produced it. A five
# minute old contact reading is fine for turning on a lamp and not fine for
# arming an alarm.
DELTA_CLASS: dict[str, float] = {
    SECURITY_WEAKENING: 30.0,
    PROTECTIVE: 300.0,      # generous: a protective action is not the risk
    COMFORT: 600.0,
    CONFIG_EDIT: 60.0,
}


@dataclass
class Entity:
    """A world entity with a version and a generation counter.

    `version` increments on every state change and is what `Current` compares --
    the repo's first version-based check. `generation` increments per committed
    intent against this entity and is what `NotSup` compares.
    """

    entity_id: str
    state: str
    version: int = 0
    generation: int = 0

    def set(self, state: str) -> None:
        if state != self.state:
            self.state = state
            self.version += 1


@dataclass
class Trigger:
    """What caused this action, with both possible origin times.

    Both are carried so a single run can be scored under Lite AND Attested
    without re-running the episode -- the two modes differ only in which field
    the Guard is permitted to read.
    """

    entity_id: str
    value: str
    generation_time: float          # when the device produced it (attested)
    receipt_time: float             # when the hub stamped it (receiver-side)

    def origin(self, mode: str) -> float:
        return self.generation_time if mode == ATTESTED else self.receipt_time


@dataclass
class ReadObservation:
    """One entry of the agent's actual read set R_a, captured at evaluation."""

    entity_id: str
    version_at_eval: int


@dataclass
class Action:
    name: str
    fact_class: str
    target: str | None = None
    preconditions: dict[str, str] = field(default_factory=dict)
    intent_generation: int = 0

    @property
    def delta(self) -> float:
        return DELTA_CLASS.get(self.fact_class, 60.0)


@dataclass
class Decision:
    verdict: str
    fresh: bool
    current: bool
    cond: bool
    not_superseded: bool
    age: float
    mode: str
    reason: str = ""

    @property
    def admitted(self) -> bool:
        return self.verdict in PASSING


@dataclass
class LeaseBook:
    """Epoch + intent lease for durable edits, with anti-thrash.

    Freshness cannot govern a config edit: at the moment of the edit nothing is
    stale (Scenario 5). What distinguishes the attacked edit is the PATTERN --
    repeated weakening of the same predicate driven by evidence gathered over
    time. So the control is a lease plus a counter over the target's history,
    which is what the design means by auditing durable edits against the pattern
    of triggering evidence rather than each edit alone.
    """

    max_weakenings: int = 1
    _weakenings: dict[str, int] = field(default_factory=dict)
    _leases: dict[str, float] = field(default_factory=dict)

    def grant(self, target: str, until: float) -> None:
        self._leases[target] = until

    def has_lease(self, target: str, now: float) -> bool:
        return self._leases.get(target, -1.0) >= now

    def record_weakening(self, target: str) -> int:
        self._weakenings[target] = self._weakenings.get(target, 0) + 1
        return self._weakenings[target]

    def thrashing(self, target: str) -> bool:
        return self._weakenings.get(target, 0) >= self.max_weakenings


class TemporalGuard:
    """The Guard at the protected-commit boundary."""

    def __init__(self, *, mode: str = LITE, entities: dict[str, Entity] | None = None,
                 leases: LeaseBook | None = None,
                 now: Callable[[], float] = lambda: 0.0) -> None:
        if mode not in (LITE, ATTESTED):
            raise ValueError(f"unknown mode {mode!r}")
        self.mode = mode
        self.entities = entities if entities is not None else {}
        self.leases = leases or LeaseBook()
        self.now = now
        self.log: list[Decision] = []

    # ------------------------------------------------------------ predicates

    def _fresh(self, a: Action, trigger: Trigger) -> tuple[bool, float]:
        age = self.now() - trigger.origin(self.mode)
        return (age <= a.delta + 1e-9), age

    def _current(self, read_set: list[ReadObservation]) -> bool:
        for r in read_set:
            e = self.entities.get(r.entity_id)
            if e is None or e.version != r.version_at_eval:
                return False
        return True

    def _cond(self, a: Action) -> bool:
        for eid, want in a.preconditions.items():
            e = self.entities.get(eid)
            if e is None or e.state != want:
                return False
        return True

    def _not_superseded(self, a: Action) -> bool:
        if a.target is None:
            return True
        e = self.entities.get(a.target)
        return True if e is None else a.intent_generation >= e.generation

    # --------------------------------------------------------------- commit

    def guarded_commit(self, a: Action, trigger: Trigger,
                       read_set: list[ReadObservation] | None = None) -> Decision:
        read_set = read_set or []
        fresh, age = self._fresh(a, trigger)
        current = self._current(read_set)
        cond = self._cond(a)
        notsup = self._not_superseded(a)

        if fresh and current and cond and notsup:
            d = Decision(ALLOW, fresh, current, cond, notsup, age, self.mode,
                         "all predicates hold")
            self.log.append(d)
            return d

        failed = [n for n, v in (("Fresh", fresh), ("Current", current),
                                 ("Cond", cond), ("NotSup", notsup)) if not v]
        why = "failed: " + ",".join(failed)

        if a.fact_class == SECURITY_WEAKENING:
            # Attested can prove the trigger was stale, so it refuses outright.
            # Lite cannot distinguish a stale trigger from a slow network, so
            # refusing would break the system on ordinary congestion; it asks a
            # human instead. That asymmetry IS the deployability story.
            verdict = REJECT if self.mode == ATTESTED else ESCALATE
        elif a.fact_class == PROTECTIVE:
            # Never block a protective action on a stale trigger. The failure
            # mode of a spurious siren is noise; the failure mode of a
            # suppressed one is the thing we are defending against.
            verdict = SAFE_EXECUTE
        elif a.fact_class == COMFORT:
            verdict = REEVALUATE
        elif a.fact_class == CONFIG_EDIT:
            verdict = REQUIRE_LEASE
            if self.leases.has_lease(a.target or "", self.now()) and \
                    not self.leases.thrashing(a.target or ""):
                verdict = ALLOW
                why += " (lease held)"
        else:
            verdict = ESCALATE

        d = Decision(verdict, fresh, current, cond, notsup, age, self.mode, why)
        self.log.append(d)
        return d

    # A durable edit is governed by the lease and the pattern, NOT by freshness.
    def guarded_config_edit(self, a: Action, trigger: Trigger,
                            weakens: bool) -> Decision:
        """Scenario 5's boundary.

        Called for an automation write. `weakens` says whether this edit removes
        or relaxes a security-relevant predicate. Note that the freshness
        predicate is evaluated and REPORTED but is not what decides: in the
        attacked case it passes, which is the whole point of the scenario.
        """
        fresh, age = self._fresh(a, trigger)
        target = a.target or ""
        if not weakens:
            d = Decision(ALLOW, fresh, True, True, True, age, self.mode,
                         "edit does not weaken a security predicate")
            self.log.append(d)
            return d

        # Test the counter on its PRIOR state, then record. Recording first
        # makes the very first weakening trip its own anti-thrash check, so a
        # legitimate one-off repair under a valid lease would be refused --
        # a guard that blocks the honest case is not deployable.
        was_thrashing = self.leases.thrashing(target)
        n = self.leases.record_weakening(target)
        if self.leases.has_lease(target, self.now()) and not was_thrashing:
            d = Decision(ALLOW, fresh, True, True, True, age, self.mode,
                         f"weakening under a valid lease (count={n})")
        else:
            d = Decision(REQUIRE_LEASE, fresh, True, True, True, age, self.mode,
                         f"security-weakening edit #{n} on {target} without a "
                         f"lease; freshness at commit was "
                         f"{'OK' if fresh else 'stale'} and is not the control")
        self.log.append(d)
        return d
