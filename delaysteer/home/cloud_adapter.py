"""A second adapter shape: cloud-callback delivery semantics.

This adapter wraps the same virtual home but models a cloud-to-cloud platform:
reads and commands incur a higher, slightly variable round-trip latency, and the
source is labelled accordingly. It exists to test the adapter abstraction
empirically (portability section): the SAME planner, delay layer, and TemporalGuard run
through it unchanged. It is a simulated second platform, not a measurement of any
specific commercial product.
"""

from __future__ import annotations

from typing import Any

from .adapter import HomeAdapter, Observation, semantic_type_of
from .clock import Clock
from .virtual_home import ENTITIES, VirtualHome


class CloudCallbackAdapter(HomeAdapter):
    def __init__(self, home: VirtualHome, cloud_latency_s: float = 0.30,
                 jitter_s: float = 0.10) -> None:
        self.home = home
        self.clock: Clock = home.clock
        self.cloud_latency_s = cloud_latency_s
        self.jitter_s = jitter_s
        self._n = 0
        self._is_manual = hasattr(self.clock, "advance")

    def _round_trip(self) -> float:
        # deterministic, seeded per-op jitter on top of the base cloud latency
        self._n += 1
        x = (self._n * 2654435761) & 0x7FFFFFFF
        frac = (x % 1000) / 1000.0
        return self.cloud_latency_s + self.jitter_s * frac

    def _advance(self, dt: float) -> None:
        if self._is_manual:
            self.clock.advance(dt)  # type: ignore[attr-defined]

    def get_state(self, entity_id: str) -> Observation:
        st = self.home.states.get(entity_id)
        if st is None:
            raise KeyError(f"unknown entity {entity_id}")
        gen = self.clock.now()  # heartbeat: cloud reports the value now
        self._advance(self._round_trip())
        return Observation(
            semantic_type=semantic_type_of(entity_id),
            value=st.state,
            attributes=dict(st.attributes),
            source="cloud_platform",
            entity_id=entity_id,
            generation_time=gen,
            arrival_time=self.clock.now(),
        )

    def call_service(self, domain: str, service: str, data: dict[str, Any] | None = None) -> Observation:
        data = data or {}
        self.home.services.call(domain, service, data)
        gen = self.clock.now()
        self._advance(self._round_trip())
        return Observation(
            semantic_type="actuation_ack",
            value="ack",
            attributes={"domain": domain, "service": service, "data": data},
            source="cloud_platform",
            entity_id=data.get("entity_id"),
            generation_time=gen,
            arrival_time=self.clock.now(),
        )

    def entities(self) -> dict[str, str]:
        return dict(ENTITIES)
