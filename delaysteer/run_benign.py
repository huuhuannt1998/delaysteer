"""Benign baseline runner (mission task 7).

Runs the 'secure the house for bedtime' scenario with NO delay injection against
either the virtual home (default, deterministic) or a live Home Assistant
instance (--home ha). Captures a replayable trace and checks the security
invariant.

  python -m delaysteer.run_benign                 # virtual home, scripted backbone
  python -m delaysteer.run_benign --home ha        # live HA (needs ha_bootstrap)
  python -m delaysteer.run_benign --backbone ollama
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .config import Config
from .home.adapter import VirtualHomeAdapter
from .home.clock import ManualClock
from .home.virtual_home import VirtualHome
from .llm.backbone import make_backbone
from .planner.react_planner import ReActPlanner
from .scenarios.secure_house import GOAL, check_invariants
from .provenance import TemporalProvenanceMonitor
from .tools.registry import build_registry
from .tools.router import ToolRouter


def _build_virtual(config: Config):
    home = VirtualHome(ManualClock())
    adapter = VirtualHomeAdapter(home, base_latency_s=config.base_latency_s)
    return home, adapter


def _build_ha(config: Config):
    from .home.ha_adapter import HomeAssistantAdapter

    return None, HomeAssistantAdapter.from_credentials()


def run(
    home_kind: str = "virtual",
    backbone: str = "scripted",
    out: str | None = None,
    model: str | None = None,
):
    config = Config(backbone=backbone)
    if model:
        config.ollama_model = model
    home, adapter = (_build_virtual if home_kind == "virtual" else _build_ha)(config)

    # The scripted backbone IS the matched rule-based baseline (RQ3); any LLM
    # backbone is the agentic planner the proposal studies.
    role = "rule_based_baseline" if backbone == "scripted" else "agentic"
    registry = build_registry()
    tracer = TemporalProvenanceMonitor(
        trial_id=f"benign-{home_kind}-{backbone}",
        metadata={
            "home": home_kind,
            "backbone": backbone,
            "role": role,
            "model": config.ollama_model if backbone == "ollama" else backbone,
            "delay": "none",
            "phase": 1,
        },
    )

    # Enrich the trace with raw device events (virtual home only).
    if home is not None:
        home.bus.subscribe(
            "state_changed",
            lambda e: tracer.record(
                "device_event",
                "state_change",
                "virtual_home",
                e.time_fired,
                e.time_fired,
                {
                    "entity_id": e.data["entity_id"],
                    "new_state": getattr(e.data["new_state"], "state", None),
                },
            ),
        )

    router = ToolRouter(registry, adapter, config, tracer=tracer)
    planner = ReActPlanner(router, make_backbone(config), config, tracer=tracer)

    outcome = planner.run(GOAL)
    inv = check_invariants(outcome, adapter)

    out_path = Path(out or f"traces/benign_{home_kind}_{backbone}.jsonl")
    tracer.write(out_path)
    return outcome, inv, out_path


def _print(outcome, inv, out_path) -> None:
    print(f"\n=== DelaySteer benign baseline ===")
    print(f"goal:        {outcome.goal}")
    print(f"steps:       {outcome.steps}")
    print(f"report:      {outcome.report_message}")
    print(f"secure_claim: {outcome.secure_claim}")
    print(f"actual_locked: {inv.actual_locked}   actual_armed: {inv.actual_armed}")
    print(f"invariant OK: {inv.ok}")
    if inv.violations:
        for v in inv.violations:
            print(f"   VIOLATION: {v}")
    print(f"trace:       {out_path}  ({out_path.stat().st_size} bytes)")
    print("\nplan trace:")
    for h in outcome.history:
        outcome_str = h.get("value", h.get("error", "?"))
        print(f"  [{h['step']}] {h['action']}({h['args']}) -> {outcome_str}  :: {h['reasoning']}")


def main() -> int:
    ap = argparse.ArgumentParser(description="DelaySteer benign baseline runner")
    ap.add_argument("--home", choices=["virtual", "ha"], default="virtual")
    # Canonical Phase-1 artifact is the AGENTIC LLM planner (proposal §3); the
    # scripted backbone is the matched rule-based baseline (RQ3).
    ap.add_argument("--backbone", choices=["scripted", "ollama", "anthropic"], default="ollama")
    ap.add_argument("--model", default=None, help="override Ollama model (e.g. qwen3:14b)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    outcome, inv, out_path = run(args.home, args.backbone, args.out, args.model)
    _print(outcome, inv, out_path)
    # Benign baseline MUST satisfy the invariant and truthfully report secure.
    ok = inv.ok and outcome.secure_claim and inv.actual_locked and inv.actual_armed
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
