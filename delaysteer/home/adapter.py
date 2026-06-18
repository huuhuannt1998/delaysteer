"""Platform-adapter interface.

The planner only ever talks to a `HomeAdapter`; it never touches a platform SDK
directly. This is the Figure-1 separation (PI-approved, jrn_01KSTXVH099XGP6786T81D3GFQ)
that (a) lets the same planner run on the virtual home or real HA and (b) gives
Phase 2 a single place to insert the Delay Injection Layer.

Every value the planner observes is an `Observation` carrying the temporal
provenance fields the formal model (RQ2, ecl_01KSTTPNAS0CVBCANTVWR0H6F2) requires:
source, semantic_type, generation_time, arrival_time, freshness_deadline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from .clock import Clock
from .virtual_home import ENTITIES, VirtualHome

# entity_id -> semantic observation type (drives freshness requirements)
SEMANTIC_TYPE: dict[str, str] = {
    ENTITIES["lock"]: "lock_state",
    ENTITIES["contact"]: "contact_state",
    ENTITIES["alarm"]: "alarm_state",
    ENTITIES["motion"]: "occupancy",
    ENTITIES["leak"]: "leak_state",
    ENTITIES["light"]: "generic_state",
    ENTITIES["thermostat"]: "generic_state",
    ENTITIES["camera"]: "arrival",  # camera-detected arrival/presence at the porch
}


def semantic_type_of(entity_id: str) -> str:
    return SEMANTIC_TYPE.get(entity_id, "generic_state")


@dataclass
class Observation:
    """A value delivered to the planner, with temporal provenance."""

    semantic_type: str
    value: str
    attributes: dict[str, Any] = field(default_factory=dict)
    source: str = "platform"
    entity_id: str | None = None
    # When the underlying state was produced vs. when the planner received it.
    # In Phase 1 arrival_time == generation_time + base latency (no attack).
    generation_time: float = 0.0
    arrival_time: float = 0.0
    freshness_deadline: float | None = None  # arrival must be <= this to be "fresh"

    @property
    def transit_delay(self) -> float:
        return self.arrival_time - self.generation_time


class HomeAdapter(ABC):
    @abstractmethod
    def get_state(self, entity_id: str) -> Observation: ...

    @abstractmethod
    def call_service(
        self, domain: str, service: str, data: dict[str, Any] | None = None
    ) -> Observation: ...

    @abstractmethod
    def entities(self) -> dict[str, str]:
        """Logical name -> entity_id map exposed to the planner."""
        ...


class VirtualHomeAdapter(HomeAdapter):
    def __init__(self, home: VirtualHome, base_latency_s: float = 0.05) -> None:
        self.home = home
        self.clock: Clock = home.clock
        self.base_latency_s = base_latency_s
        self._is_manual = hasattr(self.clock, "advance")

    def _advance(self, dt: float) -> None:
        if self._is_manual:
            self.clock.advance(dt)  # type: ignore[attr-defined]

    def get_state(self, entity_id: str) -> Observation:
        st = self.home.states.get(entity_id)
        if st is None:
            raise KeyError(f"unknown entity {entity_id}")
        # Heartbeat semantics (matches the HA adapter's last_reported fix): a pull
        # read affirms the value NOW, so a benign read is fresh regardless of when
        # the value last CHANGED. The delay layer is what makes age large (attack).
        gen = self.clock.now()
        self._advance(self.base_latency_s)
        arrival = self.clock.now()
        return Observation(
            semantic_type=semantic_type_of(entity_id),
            value=st.state,
            attributes=dict(st.attributes),
            source="virtual_home",
            entity_id=entity_id,
            generation_time=gen,
            arrival_time=arrival,
        )

    def call_service(
        self, domain: str, service: str, data: dict[str, Any] | None = None
    ) -> Observation:
        data = data or {}
        self.home.services.call(domain, service, data)
        gen = self.clock.now()
        self._advance(self.base_latency_s)
        arrival = self.clock.now()
        return Observation(
            semantic_type="actuation_ack",
            value="ack",
            attributes={"domain": domain, "service": service, "data": data},
            source="virtual_home",
            entity_id=data.get("entity_id"),
            generation_time=gen,
            arrival_time=arrival,
        )

    def entities(self) -> dict[str, str]:
        return dict(ENTITIES)
