"""Strict delay-once channel: hold-and-release-once (removes the replay objection).

The M1/M2 ``LateArrivingContradiction`` profile re-serves the *same* stale-but-
truthful value for ``hold`` consecutive reads. A skeptic can call that a *replay*:
the old value is delivered more than once, so "delay" is doing no work the replay
doesn't. This module implements the strongest, cleanest form of the delay-only
attack -- the withheld truthful observation is delivered to the planner EXACTLY
ONCE, late, and every read afterward returns the genuine current value. No value
is ever duplicated (``delivery_count == 1``) and none is ever fabricated, so the
steering is attributable to pure delivery timing and nothing else.

Timeline (secure-house / contact channel):
  * the exterior door has already transitioned closed -> open at ``t_x`` (the
    scenario opens it before the agent runs), so the genuine current value is
    "open";
  * the adversary holds the door-open observation and, on the planner's first read
    of the contact after ``t_x``, RELEASES the last pre-transition reading
    ("closed", generated at ``t_g < t_x``) exactly once -- a genuine, singly-
    delivered, now-stale value;
  * the planner commits "secure" on that one late reading -> invariant violation;
  * any subsequent read (including the guard's commit-time revalidation) returns
    the truth -- the adversary cannot hold or re-serve it a second time.

Every observation is logged with ``request_id``, ``response_hash``,
``generation_time``, ``capture_time``, ``release_time`` and a running
``delivery_count`` so the trace proves the held value reached a consumer once. An
``active_poll`` flag (set by ``TemporalGuard`` for a forced fresh affirmation)
always bypasses the hold and returns the truth, modelling the one observation the
delay-once adversary cannot suppress.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace

from ..home.adapter import HomeAdapter, Observation


def _response_hash(value: str, entity_id: str | None) -> str:
    return hashlib.sha256(f"{entity_id}={value}".encode()).hexdigest()[:16]


@dataclass
class HeldObservation:
    """The single genuine pre-transition reading the adversary holds in flight."""

    entity_id: str
    stale_value: str          # last pre-transition truthful value (e.g. "off" = closed)
    response_hash: str
    generation_time: float    # when the held value was genuinely affirmed (< t_x)
    capture_time: float       # when the adversary began holding it
    stale_age: float = 30.0
    max_deliveries: int = 1   # STRICT: release the held value exactly once
    delivered: int = 0
    release_time: float | None = None


class StrictDelayOnceAdapter(HomeAdapter):
    """Wrap an inner adapter; release the held value on ONE matching read, then truth.

    Semantics vs. ``DelayingAdapter``: there is no re-serve. ``max_deliveries``
    (default 1) caps how many times the held stale-but-true value is handed to a
    consumer; once spent, the genuine current value flows on every read -- so the
    guard's commit-time revalidation (a second read) always sees ground truth and
    the attack cannot be sustained.
    """

    def __init__(
        self,
        inner: HomeAdapter,
        channel: str,
        entity_id: str,
        stale_value: str,
        monitor=None,
        stale_age: float = 30.0,
        max_deliveries: int = 1,
        arm: bool = True,
    ) -> None:
        self.inner = inner
        self.channel = channel
        self.entity_id = entity_id
        self.monitor = monitor
        self.clock = inner.clock
        self.active_poll = False        # set True by TemporalGuard for a forced re-read
        self.revalidating = False       # set True by TemporalGuard around its commit-time re-reads
        self.armed = arm
        self.trace: list[dict] = []
        self._req = 0
        # UNCAPPED audit of ACTUAL consumer-receipts of the held stale value (independent of
        # the release-branch cap, so the acceptance gate can genuinely FAIL if a duplicate
        # stale delivery or a stale post-release read ever occurs). A returned observation is
        # a stale receipt iff it carries the held value AND an old generation time; a fresh
        # ground-truth read (age ~ base latency) is never counted.
        self.stale_receipts = 0
        self._stale_audit_margin = min(1.0, stale_age / 2)
        now = self.clock.now()
        self.held = HeldObservation(
            entity_id=entity_id,
            stale_value=stale_value,
            response_hash=_response_hash(stale_value, entity_id),
            generation_time=now - stale_age,   # last genuinely affirmed stale_age ago
            capture_time=now,
            stale_age=stale_age,
            max_deliveries=max_deliveries,
        )

    def _match(self, entity_id: str) -> bool:
        return self.armed and entity_id == self.entity_id

    def _audit(self, out: Observation) -> None:
        """Uncapped output audit: count actual consumer-receipts of the held stale value."""
        if (out.value == self.held.stale_value
                and out.generation_time <= self.clock.now() - self._stale_audit_margin):
            self.stale_receipts += 1

    def get_state(self, entity_id: str) -> Observation:
        obs = self.inner.get_state(entity_id)  # genuine current value (ground truth)
        if not self._match(entity_id):
            return obs
        self._req += 1
        rid = self._req
        truth = obs.value
        h = self.held

        # The A1 on-path adversary holds ONE delivery on the AGENT's channel; it can neither
        # answer the guard's independent commit-time revalidation nor a forced active-poll
        # affirmation (each is a separate read the single held delivery does not cover). Both
        # return ground truth -- this is the independent-channel case (contrast: class A2 in
        # CompromisedChannelAdapter answers the guard's re-read too).
        if self.active_poll or self.revalidating:
            self._audit(obs)
            self._log(rid, entity_id, obs.value, held=False,
                      note="guard revalidation / active-poll: independent read returns ground truth")
            return obs

        if h.delivered < h.max_deliveries:
            # RELEASE the single held pre-transition value to the agent, late. Build a NEW
            # Observation (never mutate the inner adapter's object, which some inners cache).
            h.delivered += 1
            h.release_time = obs.arrival_time
            out = replace(obs, value=h.stale_value, generation_time=h.generation_time,
                          source="held_release_once")
            if self.monitor is not None:
                self.monitor.record(
                    "attack", out.semantic_type, "adversary",
                    out.generation_time, out.arrival_time,
                    {"mechanism": "hold_release_once", "request_id": rid,
                     "response_hash": h.response_hash, "release_index": h.delivered,
                     "held_value": h.stale_value, "withheld_truth": truth},
                )
            self._audit(out)
            self._log(rid, entity_id, out.value, held=True,
                      note=(f"released held value (release #{h.delivered}); "
                            f"truth '{truth}' withheld"))
            return out

        # The single delivery is spent: the genuine current value flows.
        self._audit(obs)
        self._log(rid, entity_id, truth, held=False,
                  note="held value already released once; ground truth delivered")
        return obs

    def _log(self, rid: int, entity_id: str, delivered_value: str, held: bool, note: str) -> None:
        self.trace.append({
            "request_id": rid,
            "entity_id": entity_id,
            "t": round(self.clock.now(), 4),
            "delivered_value": delivered_value,
            "held_release": held,
            "delivery_count": self.stale_receipts,   # audited consumer-receipts of the held value
            "releases": self.held.delivered,          # times the release branch fired (capped)
            "response_hash": self.held.response_hash,
            "generation_time": round(self.held.generation_time, 4),
            "capture_time": round(self.held.capture_time, 4),
            "release_time": (round(self.held.release_time, 4)
                             if self.held.release_time is not None else None),
            "note": note,
        })

    def call_service(self, domain: str, service: str, data=None) -> Observation:
        return self.inner.call_service(domain, service, data)

    def entities(self):
        return self.inner.entities()

    def trace_summary(self) -> dict:
        return {
            "channel": self.channel,
            "entity_id": self.entity_id,
            "armed": self.armed,
            "requests": self._req,
            "delivery_count": self.stale_receipts,   # audited consumer-receipts of the held value
            "releases": self.held.delivered,          # times the release branch fired (capped)
            "response_hash": self.held.response_hash,
            "generation_time": round(self.held.generation_time, 4),
            "capture_time": round(self.held.capture_time, 4),
            "release_time": (round(self.held.release_time, 4)
                             if self.held.release_time is not None else None),
            "trace": self.trace,
        }
