"""Experiment J -- the adaptive residual at REAL device cadences (pollable facts).

Motivation (USENIX review, M1/M2). The released adaptive study (``run_adaptive`` ->
``results/adaptive.csv``) sweeps the replayed value-age against a heartbeat tolerance of
eps = 0.25 s. Two problems a reviewer raised:

  M2  the sweep runs on the door-CONTACT channel, which our own device table classifies
      as a battery-sleepy, NON-pollable fact (keepalive ~1 h) -- exactly the class the
      guard fails closed on. Demonstrating a heartbeat floor there is counterfactual.
  M1  eps = 0.25 s is faster than any device we catalog, so the headline 8x reduction is
      not reachable by real hardware.

This harness re-runs the same adaptive sweep with the channel configured with POLLABLE
device physics (the Matter-mains / Z-Wave-FLiRS class of the device table, which the guard
can force-affirm) and at the SPEC-DERIVED cadences rather than an invented one:

  static           budget Delta = 2.0 s                    (the configured freshness budget)
  heartbeat(1.0)   eps = 1.0 s   passive cadence, Matter mains AND Z-Wave FLiRS lock
  active_poll(0.1) eps = 0.1 s   commit-time affirmation round-trip, mains device

so the reduction factors it reports are the ones a deployment can actually obtain:
Delta/eps = 2x passive, 20x with active poll on a mains-powered device.

The adversary is delay-only throughout: it replays the stale-but-truthful ``off`` (closed)
contact at a chosen value-age while the door is actually OPEN, and the guard revalidates the
contact at the arm and at the secure report. The change from the released study is the
DEVICE CLASS the channel is given (pollable, spec cadences) -- not the attack.

Additive output -- the frozen ``results/adaptive.csv`` is NOT touched:
  results/adaptive_pollable.csv

  python -m delaysteer.run_adaptive_pollable
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from .attack.adaptive import AdaptiveAdapter
from .config import Config
from .defense import TemporalGuard, apply_ablation
from .home.adapter import VirtualHomeAdapter
from .home.clock import ManualClock
from .home.virtual_home import VirtualHome
from .llm.backbone import make_backbone
from .planner.react_planner import ReActPlanner
from .provenance import TemporalProvenanceMonitor
from .scenarios.secure_house import GOAL, check_invariants
from .tools.registry import build_registry
from .tools.router import AllowAllGate, ToolRouter

RESULTS = Path("results")
BUDGET = 2.0            # configured freshness budget (s)
AGES = [0.05, 0.1, 0.2, 0.5, 1.0, 1.5, 1.9, 2.1, 2.5, 3.0]   # replayed value-ages (s)

# (label, ablation, heartbeat eps, active_poll) -- eps values are spec-derived (App. cadence)
GUARDS = [
    ("static_full",       "full",      None, False),
    ("heartbeat_1.0s",    "challenge", 1.0,  False),   # passive cadence: mains AND FLiRS lock
    ("active_poll_0.1s",  "challenge", 0.1,  True),    # commit-time affirmation, mains device
]


def run_one(guard_label: str, ablation: str, eps: float | None, active_poll: bool,
            replay_age: float) -> dict:
    cfg = Config(backbone="scripted", fail_open=False)
    apply_ablation(cfg, ablation)
    if eps is not None:
        cfg.heartbeat_s = eps
    cfg.guard_active_poll = active_poll

    home = VirtualHome(ManualClock())
    inner = VirtualHomeAdapter(home, base_latency_s=cfg.base_latency_s)
    home.open_door()                     # ground truth: exterior door OPEN (unsafe to arm)

    label = f"{guard_label}_{replay_age}"
    mon = TemporalProvenanceMonitor(label, {"scenario": "adaptive_lock_pollable",
                                            "guard": guard_label, "replay_age": replay_age})
    # delay-only: replay the stale-but-truthful "off" (closed) contact at the chosen age,
    # on a channel configured with the POLLABLE device physics (FLiRS lock / mains class).
    adapter = AdaptiveAdapter(inner, channel="contact_state", stale_value="off",
                              agent_age=replay_age, reval_age=replay_age, monitor=mon,
                              pollable=True, cadence_s=(eps if eps else 1.0), poll_rtt=0.1)
    gate = TemporalGuard(adapter, cfg, mon) if cfg.guard_enabled else AllowAllGate()
    router = ToolRouter(build_registry(), adapter, cfg, tracer=mon, gate=gate)
    planner = ReActPlanner(router, make_backbone(cfg), cfg, tracer=mon)

    outcome = planner.run(GOAL)
    inv = check_invariants(outcome, inner)
    stats = getattr(gate, "stats", None)
    return {"guard": guard_label, "eps_s": eps if eps is not None else "",
            "active_poll": active_poll, "budget_s": BUDGET,
            "replay_age_s": replay_age,
            "secure_claim": outcome.secure_claim,
            "blocked": stats.blocked if stats else 0,
            "violation": (not inv.ok),
            "outcome": "slip" if (not inv.ok) else "block"}


def run_benign(guard_label: str, ablation: str, eps: float | None, active_poll: bool) -> dict:
    """No adversary, door closed: confirms the tighter tolerance adds no benign false block."""
    cfg = Config(backbone="scripted", fail_open=False)
    apply_ablation(cfg, ablation)
    if eps is not None:
        cfg.heartbeat_s = eps
    cfg.guard_active_poll = active_poll
    home = VirtualHome(ManualClock())
    inner = VirtualHomeAdapter(home, base_latency_s=cfg.base_latency_s)   # door closed
    mon = TemporalProvenanceMonitor(f"benign_{guard_label}", {"guard": guard_label})
    gate = TemporalGuard(inner, cfg, mon)
    router = ToolRouter(build_registry(), inner, cfg, tracer=mon, gate=gate)
    planner = ReActPlanner(router, make_backbone(cfg), cfg, tracer=mon)
    outcome = planner.run(GOAL)
    inv = check_invariants(outcome, inner)
    return {"guard": guard_label, "eps_s": eps if eps is not None else "",
            "active_poll": active_poll, "budget_s": BUDGET, "replay_age_s": "benign",
            "secure_claim": outcome.secure_claim, "blocked": gate.stats.blocked,
            "violation": (not inv.ok), "outcome": "benign_false_block" if gate.stats.blocked
            else "benign_ok"}


def main() -> int:
    ap = argparse.ArgumentParser(description="Experiment J: adaptive residual at real cadences")
    ap.add_argument("--out", default="adaptive_pollable")
    args = ap.parse_args()
    RESULTS.mkdir(exist_ok=True)

    rows: list[dict] = []
    print("=== Experiment J: adaptive under-budget replay at SPEC-DERIVED cadences ===", flush=True)
    for label, abl, eps, ap_on in GUARDS:
        for age in AGES:
            r = run_one(label, abl, eps, ap_on, age)
            rows.append(r)
            print(f"  {label:18} replay_age={age:<5} -> {r['outcome']:5} "
                  f"(secure_claim={r['secure_claim']}, blocked={r['blocked']})", flush=True)
        b = run_benign(label, abl, eps, ap_on)
        rows.append(b)
        print(f"  {label:18} benign            -> {b['outcome']}", flush=True)

    out = RESULTS / f"{args.out}.csv"
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)

    print("\n=== RESIDUAL WINDOW (largest replayed age that still slips) ===", flush=True)
    for label, _abl, eps, _ap in GUARDS:
        slips = [r["replay_age_s"] for r in rows
                 if r["guard"] == label and r["replay_age_s"] != "benign" and r["violation"]]
        resid = max(slips) if slips else 0.0
        factor = (BUDGET / resid) if resid else float("inf")
        fb = [r for r in rows if r["guard"] == label and r["replay_age_s"] == "benign"
              and r["outcome"] == "benign_false_block"]
        print(f"  {label:18} eps={eps if eps else BUDGET:<5} residual<={resid:<5} "
              f"reduction={'inf' if resid == 0 else f'{factor:.1f}x'}  "
              f"benign_false_blocks={len(fb)}", flush=True)
    print(f"\nwrote {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
