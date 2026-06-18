"""The ReAct reason-act-observe loop (mission task 2).

Modelled on ReAct (lit_01KSTTK3GCGC0JVRV11J9HH6Z2) and SAGE's discrete-action
assistant (lit_01KSTTJW47JSAVCAP8PBB49VJJ). The loop is backbone-agnostic: it
asks the backbone for the next action, executes it through the tool router,
folds the resulting observation into the belief state (assessing freshness via
the recovery policy), and records everything to the tracer.

Phase 1 is benign: with base latency << the recovery timeout, observations are
always fresh and the agent truthfully reports the house secured.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..llm.backbone import Action, Backbone, PlanningContext
from ..tools.router import ToolRouter
from .belief_state import BeliefState
from .recovery_policy import RecoveryPolicy

# Map an observation's semantic type to the belief key it updates.
SEMANTIC_TO_BELIEF: dict[str, str] = {
    "lock_state": "lock",
    "contact_state": "contact",
    "alarm_state": "alarm",
    "occupancy": "motion",
    "leak_state": "leak",
    "arrival": "arrival",
}


@dataclass
class PlannerOutcome:
    goal: str
    steps: int
    report_message: str | None
    secure_claim: bool
    belief: BeliefState
    history: list[dict[str, Any]] = field(default_factory=list)


class ReActPlanner:
    def __init__(self, router: ToolRouter, backbone: Backbone, config, tracer=None) -> None:
        self.router = router
        self.backbone = backbone
        self.config = config
        self.tracer = tracer
        self.recovery = RecoveryPolicy(config)
        self.clock = router.adapter.clock

    def _now(self) -> float:
        return self.clock.now()

    def _record_decision(self, kind, semantic_type, now, payload, causal_inputs):
        """Record a decision, linking causal-input observations when the tracer
        is a TemporalProvenanceMonitor; otherwise fall back to a plain record."""
        rec_decision = getattr(self.tracer, "record_decision", None)
        if rec_decision is not None:
            rec_decision(kind, semantic_type, "agent", now, now, payload, causal_inputs)
        else:
            self.tracer.record(kind, semantic_type, "agent", now, now, payload)

    def run(self, goal: str) -> PlannerOutcome:
        belief = BeliefState()
        history: list[dict[str, Any]] = []
        report_message: str | None = None
        secure_claim = False

        if self.tracer:
            now = self._now()
            self.tracer.record("goal", "goal", "user", now, now, {"goal": goal})

        steps = 0
        # Anti-thrash: if the guard blocks the SAME high-impact tool repeatedly,
        # a real agent can loop to the step cap retrying it. Give up after
        # guard_antithrash_max consecutive blocks of one tool (backbone-neutral;
        # scripted agents never retry a blocked tool, so their verdicts are
        # unaffected). Mirrors TemporalGuard's anti-thrash escalation budget.
        blocked_tool: str | None = None
        blocked_streak = 0
        for steps in range(1, self.config.max_react_steps + 1):
            ctx = PlanningContext(
                goal=goal,
                belief=belief,
                history=history,
                now=self._now(),
                tools=self.router.registry.describe(),
            )
            action: Action = self.backbone.next_action(ctx)

            # Observations whose beliefs the agent is consulting for THIS decision
            # — recorded as causal antecedents (downstream causal influence, §5).
            causal_inputs = [b.source_seq for b in belief.beliefs.values()]

            if self.tracer:
                now = self._now()
                self._record_decision(
                    "reason",
                    "plan_step",
                    now,
                    {
                        "tool": action.tool,
                        "args": action.args,
                        "reasoning": action.reasoning,
                        "done": action.done,
                    },
                    causal_inputs,
                )

            request_time = self._now()
            try:
                result = self.router.call(action.tool, action.args)
                obs = result.observation
                error = None
            except Exception as e:  # malformed/unknown tool call -> observe & recover
                error = f"{type(e).__name__}: {e}"
                now = self._now()
                if self.tracer:
                    self.tracer.record(
                        "tool_call", "tool_error", "router", now, now,
                        {"tool": action.tool, "args": action.args, "error": error},
                    )
                history.append(
                    {"step": steps, "action": action.tool, "args": action.args,
                     "reasoning": action.reasoning, "error": error}
                )
                continue  # let the agent see the error and try again

            # Fold the observation into the belief state, tagging its provenance.
            # `stale` records the planner's freshness verdict on this observation
            # (past the recovery boundary) so any consumer — not just a specific
            # backbone — can reconstruct per-step staleness from the trace.
            key = SEMANTIC_TO_BELIEF.get(obs.semantic_type)
            stale = False
            if key is not None and obs.value not in ("blocked",):
                belief.update_from(key, obs, source_seq=result.trace_seq)
                if self.recovery.timed_out(request_time, obs.arrival_time):
                    belief.mark_uncertain(key)
                    stale = True

            history.append(
                {
                    "step": steps,
                    "action": action.tool,
                    "args": action.args,
                    "reasoning": action.reasoning,
                    "value": obs.value,
                    "semantic_type": obs.semantic_type,
                    "gate": result.gate.reason,
                    "generation_time": obs.generation_time,
                    "arrival_time": obs.arrival_time,
                    "stale": stale,
                }
            )

            if action.tool == "report_status":
                if not result.gate.allow:
                    # TemporalGuard blocked the secure report -> claim prevented.
                    report_message = "[BLOCKED by TemporalGuard] " + (action.args.get("message") or "")
                    secure_claim = False
                else:
                    report_message = action.args.get("message")
                    secure_claim = bool(action.args.get("secure", False))

            # Track consecutive blocks of the same tool; give up if the agent keeps
            # retrying a guard-blocked action rather than looping to the step cap.
            if not result.gate.allow:
                blocked_streak = blocked_streak + 1 if action.tool == blocked_tool else 1
                blocked_tool = action.tool
                if blocked_streak >= self.config.guard_antithrash_max:
                    report_message = "[gave up: repeatedly blocked by the guard] " + (
                        report_message or ""
                    )
                    secure_claim = False
                    break
            else:
                blocked_tool = None
                blocked_streak = 0

            if action.done:
                break

        if self.tracer:
            now = self._now()
            self._record_decision(
                "response",
                "final_report",
                now,
                {"message": report_message, "secure_claim": secure_claim, "steps": steps},
                [b.source_seq for b in belief.beliefs.values()],
            )

        return PlannerOutcome(
            goal=goal,
            steps=steps,
            report_message=report_message,
            secure_claim=secure_claim,
            belief=belief,
            history=history,
        )
