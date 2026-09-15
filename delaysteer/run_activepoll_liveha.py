"""Reviewer (Systems W4): is the active-poll benign-block fix real on LIVE HA, not modeled?

The per-agent table records benign false blocks for the language-model agent on the live
Home Assistant target (its own multi-second deliberation ages a belief past the 2s budget,
so the full guard's commit-time freshness check blocks a genuinely-safe arm). App. anchor
shows active-poll clears these under a MODELED deliberation window; this runs it for real on
live HA. We run the benign secure-house scenario (no attack, door truly closed) with qwen3
under the full guard vs the active-poll guard and count benign false blocks. Additive:
results/activepoll_liveha.csv; frozen metrics.csv untouched.

  python -m delaysteer.run_activepoll_liveha
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .config import Config
from .defense import TemporalGuard, apply_ablation
from .llm.backbone import make_backbone
from .planner.react_planner import ReActPlanner
from .provenance import TemporalProvenanceMonitor
from .runtime import resolve_temperature
from .run_m2 import _inner_for
from .scenarios.secure_house import GOAL, check_invariants
from .tools.registry import build_registry
from .tools.router import ToolRouter

MODEL = "qwen3:14b"
N = 6
ROWS: list[dict] = []


def run_one(ablation: str, i: int) -> dict:
    cfg = Config(backbone="ollama", fail_open=False)
    cfg.ollama_model = MODEL
    cfg.seed = i
    cfg.temperature = resolve_temperature()
    apply_ablation(cfg, ablation)
    _, inner = _inner_for("ha", cfg)  # resets live HA to benign pre-bedtime (closed/unlocked/disarmed)
    monitor = TemporalProvenanceMonitor(f"apoll_{ablation}_{i}", {"model": MODEL, "ablation": ablation})
    gate = TemporalGuard(inner, cfg, monitor)
    router = ToolRouter(build_registry(), inner, cfg, tracer=monitor, gate=gate)
    planner = ReActPlanner(router, make_backbone(cfg), cfg, tracer=monitor)
    outcome = planner.run(GOAL)
    inv = check_invariants(outcome, inner)
    return {"blocked": gate.stats.blocked, "secure": outcome.secure_claim,
            "steps": outcome.steps, "violation": not inv.ok}


def run_cell(ablation: str, n: int) -> dict:
    runs_blocked = total_blocks = secure = 0
    for i in range(n):
        r = run_one(ablation, i)
        runs_blocked += int(r["blocked"] > 0)  # benign: any block is a FALSE block
        total_blocks += r["blocked"]
        secure += int(r["secure"])
        print(f"  {ablation} run {i+1}/{n}: blocks={r['blocked']} secure={r['secure']} "
              f"steps={r['steps']} viol={r['violation']}", flush=True)
    row = {"guard": ablation, "n": n, "runs_with_false_block": f"{runs_blocked}/{n}",
           "total_false_blocks": total_blocks, "secure_rate": f"{secure}/{n}"}
    print(f"  [CELL] {ablation}: runs_with_false_block {row['runs_with_false_block']}, "
          f"{total_blocks} total, secure {row['secure_rate']}", flush=True)
    return row


def main() -> int:
    import sys
    n = int(sys.argv[1]) if len(sys.argv) > 1 else N
    abls = sys.argv[2].split(",") if len(sys.argv) > 2 else ["full", "activepoll"]
    print(f"=== active-poll on LIVE HA: benign false blocks, {MODEL}, n={n} ===", flush=True)
    for abl in abls:
        ROWS.append(run_cell(abl, n))
        out = Path("results"); out.mkdir(exist_ok=True)
        with (out / "activepoll_liveha.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(ROWS[0].keys()))
            w.writeheader(); w.writerows(ROWS)
    (Path("results") / "activepoll_liveha.json").write_text(json.dumps(ROWS, indent=2))
    print("\nwrote results/activepoll_liveha.csv", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
