"""The agent's belief state over the home.

Each belief carries WHEN the supporting observation was generated and when it
arrived, so the planner (and, in Phase 4, TemporalGuard) can reason about
staleness. The whole DelaySteer thesis lives here: a belief can be true-as-data
but stale-as-evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..home.adapter import Observation


@dataclass
class Belief:
    key: str
    value: Any
    generation_time: float       # when the underlying state was produced
    arrival_time: float          # when the planner received it
    freshness_deadline: float | None = None
    certain: bool = True         # False when the agent is uncertain (e.g., timeout)
    source_seq: int | None = None  # trace seq of the observation that set this belief

    def age_at(self, now: float) -> float:
        return now - self.generation_time

    def is_fresh_at(self, now: float) -> bool:
        if self.freshness_deadline is None:
            return True
        return now <= self.freshness_deadline


@dataclass
class BeliefState:
    beliefs: dict[str, Belief] = field(default_factory=dict)
    uncertain: set[str] = field(default_factory=set)

    def update_from(self, key: str, obs: Observation, source_seq: int | None = None) -> Belief:
        b = Belief(
            key=key,
            value=obs.value,
            generation_time=obs.generation_time,
            arrival_time=obs.arrival_time,
            freshness_deadline=obs.freshness_deadline,
            certain=True,
            source_seq=source_seq,
        )
        self.beliefs[key] = b
        self.uncertain.discard(key)
        return b

    def mark_uncertain(self, key: str) -> None:
        self.uncertain.add(key)
        if key in self.beliefs:
            self.beliefs[key].certain = False

    def get(self, key: str) -> Belief | None:
        return self.beliefs.get(key)

    def value(self, key: str) -> Any:
        b = self.beliefs.get(key)
        return b.value if b else None

    def is_certain(self, key: str) -> bool:
        b = self.beliefs.get(key)
        return bool(b and b.certain and key not in self.uncertain)

    def snapshot(self) -> dict[str, Any]:
        return {
            k: {
                "value": b.value,
                "certain": b.certain,
                "generation_time": b.generation_time,
                "arrival_time": b.arrival_time,
                "source_seq": b.source_seq,
            }
            for k, b in self.beliefs.items()
        }
