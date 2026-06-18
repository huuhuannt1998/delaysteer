"""TemporalProvenanceMonitor — the named Phase-1 instrumentation component.

Extends the replayable `Tracer` with a causal-influence graph: each decision
(plan step / final report) is linked to the observations whose beliefs the agent
consulted when it made that decision. Concretely an edge
    {cause: <observation seq>, effect: <decision seq>, relation: ...}
records "observation N influenced decision M". In Phase 2 the same graph, with a
delayed observation, makes the attack's causal path explicit and inspectable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from ..tracing.tracer import Tracer, TraceRecord


class TemporalProvenanceMonitor(Tracer):
    def __init__(self, trial_id: str, metadata: dict[str, Any] | None = None) -> None:
        super().__init__(trial_id, metadata)
        self.edges: list[dict[str, Any]] = []

    def link(self, cause_seq: int, effect_seq: int, relation: str = "influences") -> None:
        self.edges.append({"cause": cause_seq, "effect": effect_seq, "relation": relation})

    def record_observation(
        self,
        semantic_type: str,
        source: str,
        generation_time: float,
        arrival_time: float,
        payload: dict[str, Any] | None = None,
        kind: str = "tool_call",
    ) -> TraceRecord:
        return self.record(kind, semantic_type, source, generation_time, arrival_time, payload)

    def record_decision(
        self,
        kind: str,
        semantic_type: str,
        source: str,
        generation_time: float,
        arrival_time: float,
        payload: dict[str, Any] | None = None,
        causal_input_seqs: Iterable[int | None] = (),
    ) -> TraceRecord:
        rec = self.record(kind, semantic_type, source, generation_time, arrival_time, payload)
        for s in causal_input_seqs:
            if s is not None:
                self.link(s, rec.seq, "observation_influences_decision")
        return rec

    def write(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        header = {"_trial": self.trial_id, "_meta": self.metadata, "_edges": self.edges}
        with path.open("w", encoding="utf-8") as f:
            f.write(json.dumps(header) + "\n")
            for d in self.to_dicts():
                f.write(json.dumps(d) + "\n")
        return path
