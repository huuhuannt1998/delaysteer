"""The Delay Injection Layer.

`DelayingAdapter` wraps any `HomeAdapter` and applies `DelaySpec`s to matching
observations as they pass from the platform to the planner. It NEVER changes a
payload's truth — it only (a) inflates `arrival_time` (and advances a manual
clock) and/or (b) substitutes a stale-but-truthful prior value (contradiction
profile). This is the single seam the planner/router are blind to, exactly as in
Figure 1. Each injection is logged to the provenance monitor as an `attack`
record so the trace shows what was delayed.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..home.adapter import HomeAdapter, Observation
from .profiles import DelayProfile


@dataclass
class DelaySpec:
    channel: str  # semantic_type to match, or "*"
    profile: DelayProfile
    on_get_state: bool = True
    on_call_service: bool = False
    entity_id: str | None = None  # optional narrower match


class DelayingAdapter(HomeAdapter):
    def __init__(self, inner: HomeAdapter, specs: list[DelaySpec], monitor=None) -> None:
        self.inner = inner
        self.specs = specs
        self.monitor = monitor
        self.clock = inner.clock
        self._counts: dict[int, int] = {}
        self.injections: list[dict] = []

    def _match(self, obs: Observation, kind: str) -> tuple[int, DelaySpec] | None:
        for i, spec in enumerate(self.specs):
            if kind == "get_state" and not spec.on_get_state:
                continue
            if kind == "call_service" and not spec.on_call_service:
                continue
            if spec.channel not in ("*", obs.semantic_type):
                continue
            if spec.entity_id is not None and spec.entity_id != obs.entity_id:
                continue
            return i, spec
        return None

    def _apply(self, obs: Observation, kind: str) -> Observation:
        m = self._match(obs, kind)
        if m is None:
            return obs
        idx, spec = m
        n = self._counts.get(idx, 0)
        self._counts[idx] = n + 1

        ov = spec.profile.override_value(obs.value, n)
        if ov is not None:
            obs.value = ov  # stale-but-truthful prior value
            # Age its generation time: the delivered value was last affirmed
            # stale_age seconds ago (the fresh value has not arrived yet).
            stale_age = getattr(spec.profile, "stale_age", 0.0)
            if stale_age > 0:
                obs.generation_time = obs.arrival_time - stale_age

        d = spec.profile.extra_delay(n)
        if d > 0:
            if hasattr(self.clock, "advance"):
                self.clock.advance(d)
            obs.arrival_time = obs.arrival_time + d

        if d > 0 or ov is not None:
            rec = {
                "channel": spec.channel,
                "profile": spec.profile.name,
                "n": n,
                "extra_delay": d,
                "override_value": ov,
                "entity_id": obs.entity_id,
            }
            self.injections.append(rec)
            if self.monitor is not None:
                self.monitor.record(
                    "attack", obs.semantic_type, "adversary",
                    obs.generation_time, obs.arrival_time, rec,
                )
        return obs

    def get_state(self, entity_id: str) -> Observation:
        return self._apply(self.inner.get_state(entity_id), "get_state")

    def call_service(self, domain: str, service: str, data=None) -> Observation:
        return self._apply(self.inner.call_service(domain, service, data), "call_service")

    def entities(self):
        return self.inner.entities()
