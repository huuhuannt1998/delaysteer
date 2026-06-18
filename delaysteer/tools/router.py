"""Tool router / policy layer.

Responsibilities (mission task 4):
  * schema validation of tool arguments
  * risk labelling
  * high-impact action GATE — the explicit seam where TemporalGuard (Phase 4)
    will require fresh revalidation / two-phase commitment. In Phase 1 the gate
    is `AllowAllGate`: it records the decision and always allows.

Every call is emitted to the tracer with full temporal provenance so Phase 3 can
replay the exact causal path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ..home.adapter import HomeAdapter, Observation
from .registry import Risk, ToolRegistry, ToolSpec, _validate


@dataclass
class GateDecision:
    allow: bool
    reason: str
    revalidated: bool = False


class Gate(Protocol):
    def evaluate(
        self, spec: ToolSpec, args: dict[str, Any], context: dict[str, Any]
    ) -> GateDecision: ...


class AllowAllGate:
    """Phase-1 gate: no enforcement, only records that a gate point was reached."""

    def evaluate(self, spec, args, context) -> GateDecision:
        return GateDecision(allow=True, reason="phase1-monitor-only")


@dataclass
class ToolResult:
    tool: str
    args: dict[str, Any]
    risk: str
    gate: GateDecision
    observation: Observation
    trace_seq: int | None = None  # seq of this call's observation in the provenance monitor


class ToolRouter:
    def __init__(
        self,
        registry: ToolRegistry,
        adapter: HomeAdapter,
        config,
        tracer=None,
        gate: Gate | None = None,
    ) -> None:
        self.registry = registry
        self.adapter = adapter
        self.config = config
        self.tracer = tracer
        self.gate = gate or AllowAllGate()

    def call(self, tool_name: str, args: dict[str, Any] | None = None) -> ToolResult:
        args = dict(args or {})
        spec = self.registry.get(tool_name)
        _validate(spec, args)

        # High-impact actions pass through the gate seam. report_status is gated
        # too: claiming the house secure is itself a security-critical commitment.
        gate_decision = GateDecision(allow=True, reason="low-risk")
        if spec.risk_level == Risk.HIGH or tool_name == "report_status":
            gate_decision = self.gate.evaluate(spec, args, {"config": self.config})
            if not gate_decision.allow:
                obs = Observation(
                    semantic_type="actuation_ack",
                    value="blocked",
                    attributes={"reason": gate_decision.reason},
                    source="router",
                )
                result = ToolResult(tool_name, args, spec.risk_level.value, gate_decision, obs)
                result.trace_seq = self._trace(result)
                return result

        if spec.handler is None:
            raise RuntimeError(f"tool {tool_name} has no handler")
        obs = spec.handler(self.adapter, args)

        # Stamp the freshness deadline the observation would need to satisfy.
        req = self.config.freshness_s.get(obs.semantic_type)
        if req is not None:
            obs.freshness_deadline = obs.generation_time + req

        result = ToolResult(tool_name, args, spec.risk_level.value, gate_decision, obs)
        result.trace_seq = self._trace(result)
        return result

    def _trace(self, result: ToolResult) -> int | None:
        if self.tracer is None:
            return None
        obs = result.observation
        rec = self.tracer.record(
            kind="tool_call",
            semantic_type=obs.semantic_type,
            source=obs.source,
            generation_time=obs.generation_time,
            arrival_time=obs.arrival_time,
            payload={
                "tool": result.tool,
                "args": result.args,
                "risk": result.risk,
                "gate": {"allow": result.gate.allow, "reason": result.gate.reason},
                "value": obs.value,
                "attributes": obs.attributes,
                "entity_id": obs.entity_id,
                "freshness_deadline": obs.freshness_deadline,
            },
        )
        return rec.seq
