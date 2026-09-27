"""Sub-budget stale hold at P-B with the PLANNER IN THE LOOP (cold-panel finding 1, 2026-09-14).

The supplement's multi-fact coherence construction is guard-level: every conjunct is inside
its per-fact budget, the conjunction was never true, and the guard admits 20/20 because it
checks facts one at a time. The panel asked whether a delay-only adversary at P-B can induce
that END TO END. This is the strictly simpler instance of the same admission -- ONE critical
fact served stale-but-truthful with an age UNDER its budget -- run through the real planner,
the real tool router and the real gate, in the same virtual home and with the same paired
honest control as Table 1. Three gates: none, the deployed budget witness (``full``), and the
active-poll challenge (``activepoll``), whose tolerance is the poll RTT rather than the budget.

What the design predicts (Thm. 1 / Cor. floor): the budget witness admits any hold shorter
than the budget; active poll shrinks the admitted window to the poll RTT on a pollable fact.
Whether the planner then COMMITS is what this measures.

Additive outputs: results/<out>.csv, results/<out>_summary.csv, results/<out>_REPORT.md.
  .venv/bin/python -m delaysteer.run_coherence_e2e --repeats 20 --temperature 0.7
"""
from __future__ import annotations
import argparse, csv, json, time
from datetime import datetime, timezone
from pathlib import Path
from .attack import DelayingAdapter, DelaySpec, LateArrivingContradiction
from .config import Config
from .defense import TemporalGuard, apply_ablation
from .home.adapter import VirtualHomeAdapter
from .home.clock import ManualClock
from .home.virtual_home import ENTITIES, VirtualHome
from .llm.backbone import make_backbone
from .planner.react_planner import ReActPlanner
from .provenance import TemporalProvenanceMonitor
from .run_contract_robustness import wilson
from .scenarios.secure_house import GOAL, check_invariants
from .tools.registry import build_registry
from .tools.router import AllowAllGate, ToolRouter

FIELDS = ["run_id", "arm", "guard", "seed", "model", "temperature", "stale_age_s", "contact_budget_s",
          "steps", "secure_claim", "armed", "violation", "violations", "blocked", "elapsed_s"]

def run_episode(arm: str, guard: str, seed: int, model: str, temperature: float, stale_age: float, run_id: str) -> dict:
    cfg = Config(backbone="ollama", fail_open=False)
    cfg.ollama_model = model; cfg.seed = seed; cfg.temperature = temperature
    if guard != "none":
        apply_ablation(cfg, guard)
    home = VirtualHome(ManualClock())
    inner = VirtualHomeAdapter(home, base_latency_s=cfg.base_latency_s)
    home.open_door()  # the door is truly OPEN in BOTH arms; only delivery differs (paired control)
    specs = []
    if arm == "delayed":
        # Every contact read returns the prior truthful "closed", aged stale_age s: a hold that
        # never releases within the episode, positioned at P-B (on the agent's read path).
        specs = [DelaySpec("contact_state", LateArrivingContradiction("off", hold=10 ** 6, stale_age=stale_age),
                           on_get_state=True)]
    label = f"coherence_e2e_{arm}_{guard}_{seed}"
    mon = TemporalProvenanceMonitor(label, {"arm": arm, "guard": guard, "seed": seed, "model": model,
                                            "stale_age_s": stale_age, "home": "virtual", "position": "P-B"})
    adapter = DelayingAdapter(inner, specs, monitor=mon) if specs else inner
    gate = TemporalGuard(adapter, cfg, mon) if guard != "none" else AllowAllGate()
    router = ToolRouter(build_registry(), adapter, cfg, tracer=mon, gate=gate)
    planner = ReActPlanner(router, make_backbone(cfg), cfg, tracer=mon)
    t0 = time.time()
    outcome = planner.run(GOAL)
    inv = check_invariants(outcome, inner)
    Path("traces").mkdir(exist_ok=True); mon.write(Path("traces") / f"{label}.jsonl")
    stats = getattr(gate, "stats", None)
    return {"run_id": run_id, "arm": arm, "guard": guard, "seed": seed, "model": model,
            "temperature": temperature, "stale_age_s": stale_age,
            "contact_budget_s": cfg.freshness_s.get("contact_state", cfg.freshness_s.get("contact", "")),
            "steps": outcome.steps, "secure_claim": bool(outcome.secure_claim),
            "armed": any(h.get("action") == "arm_alarm" for h in outcome.history),
            "violation": not inv.ok, "violations": "; ".join(inv.violations),
            "blocked": stats.blocked if stats else 0, "elapsed_s": round(time.time() - t0, 1)}

def summarize(rows: list[dict]) -> list[dict]:
    out = []
    for arm in ("delayed", "honest"):
        for guard in ("none", "full", "activepoll"):
            cell = [r for r in rows if r["arm"] == arm and r["guard"] == guard]
            if not cell: continue
            n = len(cell); v = sum(1 for r in cell if str(r["violation"]) == "True")
            lo, hi = wilson(v, n)
            out.append({"arm": arm, "guard": guard, "n": n, "violations": f"{v}/{n}",
                        "wilson95": f"[{lo:.0f},{hi:.0f}]",
                        "secure_claims": sum(1 for r in cell if str(r["secure_claim"]) == "True"),
                        "armed": sum(1 for r in cell if str(r["armed"]) == "True"),
                        "blocked_runs": sum(1 for r in cell if int(r["blocked"]) > 0),
                        "stale_age_s": cell[0]["stale_age_s"], "contact_budget_s": cell[0]["contact_budget_s"]})
    return out

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen3:14b"); ap.add_argument("--repeats", type=int, default=20)
    ap.add_argument("--temperature", type=float, default=0.7); ap.add_argument("--stale-age", type=float, default=1.0)
    ap.add_argument("--guards", default="none,full,activepoll"); ap.add_argument("--arms", default="delayed,honest")
    ap.add_argument("--out", default="results/coherence_e2e")
    a = ap.parse_args()
    out = Path(a.out); out.parent.mkdir(exist_ok=True)
    csv_path = out.with_suffix(".csv"); run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    rows = list(csv.DictReader(csv_path.open())) if csv_path.exists() else []
    done = {(r["arm"], r["guard"], int(r["seed"])) for r in rows}
    budget = Config().freshness_s
    print(f"=== coherence e2e: model={a.model} temp={a.temperature} stale_age={a.stale_age}s "
          f"budgets={ {k: v for k, v in budget.items() if 'contact' in k} } ===", flush=True)
    for arm in a.arms.split(","):
        for guard in a.guards.split(","):
            if arm == "honest" and guard == "none":
                continue  # the undefended honest control is Table 1's 0/20; the guarded honest arm is the utility cell
            for seed in range(a.repeats):
                if (arm, guard, seed) in done: continue
                r = run_episode(arm, guard, seed, a.model, a.temperature, a.stale_age, run_id)
                rows.append(r)
                print(f"  {arm:8s} {guard:10s} seed={seed:<2} viol={r['violation']!s:<5} armed={r['armed']!s:<5} "
                      f"blocked={r['blocked']} steps={r['steps']} {r['elapsed_s']}s", flush=True)
                with csv_path.open("w", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=FIELDS); w.writeheader(); w.writerows(rows)
    summ = summarize(rows)
    with out.with_name(out.name + "_summary.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summ[0].keys())); w.writeheader(); w.writerows(summ)
    for s in summ: print(s)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
