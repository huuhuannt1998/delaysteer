"""LLM agent paths for the non-bedtime families (mission mis_01KT2E4P, A1/B1).

The single ReAct loop must drive access / confirmation / automation when given a
model, using a per-family procedure prompt (scenario wiring, not a planner fork).
We stub ONLY the network boundary (`_complete`); prompt-building, JSON parsing,
the planner loop, and the backbone-agnostic verdict are all exercised for real.
"""

import json

from delaysteer.config import Config
from delaysteer.llm.backbone import PROCEDURES, OllamaBackbone, PlanningContext
from delaysteer.planner.belief_state import BeliefState
from delaysteer.run_automation import run_auto
from delaysteer.run_confirm import run_confirm
from delaysteer.run_repair import run_repair


def _wrap(actions):
    """A stateful fake _complete returning one canned action JSON per call."""
    seq = iter(actions)

    def _complete(self, prompt):  # bound as a method via setattr on the class
        return json.dumps(next(seq))

    return _complete


def test_ollama_backbone_uses_per_family_procedure(monkeypatch):
    cfg = Config(backbone="ollama", ollama_model="qwen3:14b")
    cfg.llm_family = "access"
    bb = OllamaBackbone(cfg)

    captured = {}

    def fake_complete(prompt):
        captured["prompt"] = prompt
        return json.dumps({"tool": "check_leak", "args": {}, "reasoning": "x", "done": False})

    monkeypatch.setattr(bb, "_complete", fake_complete)
    ctx = PlanningContext(goal="g", belief=BeliefState(), history=[], now=0.0,
                          tools=[{"name": "check_leak"}, {"name": "grant_access"}])
    act = bb.next_action(ctx)

    assert act.tool == "check_leak"
    # The access procedure is injected; the bedtime arm_alarm steps are NOT.
    assert "grant_access" in captured["prompt"]
    assert "arm_alarm" not in captured["prompt"]


def test_run_repair_llm_path_grants_access_when_present(monkeypatch):
    actions = [
        {"tool": "check_leak", "args": {}, "done": False},
        {"tool": "check_arrival", "args": {}, "done": False},
        {"tool": "grant_access", "args": {}, "done": False},
        {"tool": "report_status", "args": {"message": "let the tech in", "secure": False}, "done": True},
    ]
    monkeypatch.setattr(OllamaBackbone, "_complete", _wrap(actions))
    r = run_repair("virtual", present=True, with_delay=False, ablation="none",
                   fail_open=False, label="t_repair_llm",
                   model="qwen3:14b", backbone_override="ollama")
    assert r["granted"] is True
    assert r["violation"] is False  # technician really present


def test_run_confirm_llm_path_runs_under_model(monkeypatch):
    # Benign present: LLM grants to a real guest -> no violation.
    actions = [
        {"tool": "check_arrival", "args": {}, "done": False},
        {"tool": "grant_access", "args": {}, "done": False},
        {"tool": "report_status", "args": {"message": "guest admitted", "secure": False}, "done": True},
    ]
    monkeypatch.setattr(OllamaBackbone, "_complete", _wrap(actions))
    r = run_confirm("virtual", present=True, with_delay=False, ablation="none",
                    hitl=False, label="t_confirm_llm",
                    model="qwen3:14b", backbone_override="ollama")
    assert r["granted"] is True
    assert r["violation"] is False


def test_run_auto_llm_path_removes_predicate_under_delay(monkeypatch):
    actions = (
        [{"tool": "check_safety_signal", "args": {}, "done": False}] * 3
        + [{"tool": "propose_automation_edit",
            "args": {"action": "remove_predicate", "reason": "unresponsive"}, "done": False}]
        + [{"tool": "report_status", "args": {"message": "done", "secure": False}, "done": True}]
    )
    monkeypatch.setattr(OllamaBackbone, "_complete", _wrap(actions))
    r = run_auto("virtual", with_delay=True, ablation="none", label="t_auto_llm",
                 model="qwen3:14b", backbone_override="ollama")
    assert r["violation"] is True
    assert r["probes"] == ["timeout", "timeout", "timeout"]
