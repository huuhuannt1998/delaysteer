"""Trace capture.

Records every planner step, tool call, device event, and the final response with
both generation and delivery timestamps so a trial can be replayed and the causal
path from an observation to a plan branch inspected (mission task 6; assumption
A5). Output is line-delimited JSON (one record per line) — diff-friendly and
streamable.

What is recorded per record:
  seq, kind, semantic_type, source, generation_time, arrival_time, transit_delay,
  payload (kind-specific). For Phase 1, transit_delay == base latency (no attack);
  Phase 2's delay layer will widen arrival_time - generation_time.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TraceRecord:
    seq: int
    kind: str  # goal | reason | tool_call | device_event | response
    semantic_type: str
    source: str
    generation_time: float
    arrival_time: float
    payload: dict[str, Any] = field(default_factory=dict)

    @property
    def transit_delay(self) -> float:
        return self.arrival_time - self.generation_time


class Tracer:
    def __init__(self, trial_id: str, metadata: dict[str, Any] | None = None) -> None:
        self.trial_id = trial_id
        self.metadata = metadata or {}
        self.records: list[TraceRecord] = []
        self._seq = 0

    def record(
        self,
        kind: str,
        semantic_type: str,
        source: str,
        generation_time: float,
        arrival_time: float,
        payload: dict[str, Any] | None = None,
    ) -> TraceRecord:
        rec = TraceRecord(
            seq=self._seq,
            kind=kind,
            semantic_type=semantic_type,
            source=source,
            generation_time=generation_time,
            arrival_time=arrival_time,
            payload=payload or {},
        )
        self.records.append(rec)
        self._seq += 1
        return rec

    def to_dicts(self) -> list[dict[str, Any]]:
        out = []
        for r in self.records:
            d = asdict(r)
            d["transit_delay"] = r.transit_delay
            out.append(d)
        return out

    def write(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            f.write(json.dumps({"_trial": self.trial_id, "_meta": self.metadata}) + "\n")
            for d in self.to_dicts():
                f.write(json.dumps(d) + "\n")
        return path

    @staticmethod
    def load(path: str | Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        path = Path(path)
        header: dict[str, Any] = {}
        recs: list[dict[str, Any]] = []
        with path.open(encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if i == 0 and "_trial" in obj:
                    header = obj
                else:
                    recs.append(obj)
        return header, recs
