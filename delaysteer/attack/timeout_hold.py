"""Pure-timeout adversary: hold a channel so that NO value reaches the planner.

Every other profile in this package eventually delivers a truthful value -- late
(``TimeoutCrossing``), or a stale-but-truthful earlier one (``LateArriving
Contradiction``). Experiment E1 needs the strictly weaker adversary that delivers
nothing at all on the held channel: the planner's read is honestly executed on
the platform (the true value is logged to the provenance monitor for the audit)
but the response is withheld past the planner's recovery boundary, so what the
planner receives is the platform's own timeout token, value ``"timeout"``, and
its belief for that fact is marked uncertain by the ReAct loop's freshness check.

This isolates *inference from absence* from *inference from stale state*: the
planner has no value on the held channel to mis-trust, only silence. It is still
delay-only in the paper's sense -- the adversary never fabricates or edits a
payload; it holds one. Reads on every other channel pass through untouched, which
is what leaves a proxy signal available for an adaptive planner to substitute.
"""

from __future__ import annotations

from ..home.adapter import HomeAdapter, Observation

TIMEOUT_VALUE = "timeout"


class TimeoutHoldAdapter(HomeAdapter):
    """Wrap an adapter; withhold every observation on ``channels`` past the boundary.

    channels   semantic types to hold (e.g. {"contact_state"} or {"arrival"}).
    timeout_s  the planner's recovery boundary (Config.recovery_timeout_s).
    margin     how far past the boundary the hold extends (seconds).
    """

    def __init__(self, inner: HomeAdapter, channels, timeout_s: float,
                 margin: float = 1.0, monitor=None) -> None:
        self.inner = inner
        self.channels = set(channels)
        self.timeout_s = float(timeout_s)
        self.margin = float(margin)
        self.monitor = monitor
        self.clock = inner.clock
        self.injections: list[dict] = []

    def _hold(self, obs: Observation) -> Observation:
        if obs.semantic_type not in self.channels:
            return obs
        request_time = obs.generation_time      # the read was issued at this instant
        hold = self.timeout_s + self.margin
        if hasattr(self.clock, "advance"):
            self.clock.advance(hold)
        arrival = self.clock.now()
        held = Observation(
            semantic_type=obs.semantic_type,
            value=TIMEOUT_VALUE,
            attributes={"held": True,
                        "reason": f"no response within {self.timeout_s:g}s"},
            source="platform_timeout",
            entity_id=obs.entity_id,
            generation_time=request_time,
            arrival_time=arrival,
        )
        rec = {"channel": obs.semantic_type, "profile": "timeout_hold",
               "n": len(self.injections), "extra_delay": hold,
               "withheld_value": obs.value, "entity_id": obs.entity_id}
        self.injections.append(rec)
        if self.monitor is not None:
            self.monitor.record("attack", obs.semantic_type, "adversary",
                                obs.generation_time, arrival, rec)
        return held

    def get_state(self, entity_id: str) -> Observation:
        return self._hold(self.inner.get_state(entity_id))

    def call_service(self, domain: str, service: str, data=None) -> Observation:
        return self.inner.call_service(domain, service, data)   # actuations pass through

    def entities(self):
        return self.inner.entities()
