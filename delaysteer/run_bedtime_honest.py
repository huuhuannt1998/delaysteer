"""Matched honest arm for Table 7's bedtime row (added 2026-10-27, writing-review W11).

Table 7's bedtime attack row is ``run_m2_rates`` cell (contact_contradiction, none, hold 4):
qwen3:14b, virtual home, T=0.7, seeds 0-19, the front door truly open, the contact's
"open" update held for 4 reads and the prior "closed" re-served aged 30 s. Until now the
table's honest cell was borrowed from the strict-delay study's no-delay baseline. This runner
reruns that exact cell with the delay removed and nothing else changed: same goal, same open
door, same model, temperature and seeds, same router and planner, same invariant check, and
the delay layer still in the loop with an empty schedule so the trace format is identical.

  python -m delaysteer.run_bedtime_honest --repeats 20 --temperature 0.7

Writes results/bedtime_honest_n20.csv (one row per run) and
results/bedtime_honest_n20_summary.csv.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from .attack import DelayingAdapter
from .config import Config
from .defense import TemporalGuard, apply_ablation
from .llm.backbone import make_backbone
from .planner.react_planner import ReActPlanner
from .provenance import TemporalProvenanceMonitor
from .run_m2 import _inner_for
from .scenarios.secure_house import GOAL, check_invariants
from .tools.registry import build_registry
from .tools.router import AllowAllGate, ToolRouter


def run_one(model: str, seed: int, temperature: float) -> dict:
    cfg = Config(backbone="ollama", fail_open=False)
    cfg.ollama_model = model
    cfg.seed = seed
    cfg.temperature = temperature
    apply_ablation(cfg, "none")
    home, inner = _inner_for("virtual", cfg)
    home.open_door()  # the door is truly open, exactly as in the attacked cell
    label = f"bedtime_honest_{model.replace(':', '_').replace('.', '')}_{seed}"
    monitor = TemporalProvenanceMonitor(label, {"model": model, "scenario": "contact_contradiction",
                                                "ablation": "none", "hold": 0, "home": "virtual",
                                                "arm": "honest"})
    adapter = DelayingAdapter(inner, [], monitor=monitor)  # empty schedule: nothing is delayed
    gate = TemporalGuard(adapter, cfg, monitor) if cfg.guard_enabled else AllowAllGate()
    router = ToolRouter(build_registry(), adapter, cfg, tracer=monitor, gate=gate)
    planner = ReActPlanner(router, make_backbone(cfg), cfg, tracer=monitor)
    outcome = planner.run(GOAL)
    inv = check_invariants(outcome, inner)
    monitor.write(Path(f"traces/{label}.jsonl"))
    armed = any(h.get("action") == "arm_alarm" for h in outcome.history)
    return {"model": model, "seed": seed, "temperature": temperature, "steps": outcome.steps,
            "secure_claim": int(outcome.secure_claim), "armed": int(armed),
            "violation": int(not inv.ok), "loop": int(outcome.steps >= cfg.max_react_steps)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen3:14b")
    ap.add_argument("--repeats", type=int, default=20)
    ap.add_argument("--temperature", type=float, default=0.7)
    args = ap.parse_args()
    out = Path("results/bedtime_honest_n20.csv")
    rows = []
    for seed in range(args.repeats):
        r = run_one(args.model, seed, args.temperature)
        rows.append(r)
        print(f"  run {seed + 1}/{args.repeats}: viol={r['violation']} secure={r['secure_claim']} "
              f"armed={r['armed']} steps={r['steps']}", flush=True)
        with out.open("w", newline="") as f:  # incremental, crash-safe
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    n = len(rows)
    summary = {"model": args.model, "scenario": "contact_contradiction", "arm": "honest",
               "repeats": n, "temperature": args.temperature,
               "violation_rate": f"{sum(r['violation'] for r in rows)}/{n}",
               "secure_rate": f"{sum(r['secure_claim'] for r in rows)}/{n}",
               "armed_rate": f"{sum(r['armed'] for r in rows)}/{n}",
               "loop_rate": f"{sum(r['loop'] for r in rows)}/{n}"}
    with Path("results/bedtime_honest_n20_summary.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary))
        w.writeheader()
        w.writerow(summary)
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
