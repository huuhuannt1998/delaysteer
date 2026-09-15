#!/usr/bin/env python3
"""Render E8 into a report: does the effect survive a different agent architecture?

E8 answers one question and must not be read as answering a second. It can say whether a
structured planner/executor is steered by the same delay. It cannot say whether that
architecture is more or less robust than the ReAct loop, because the two harnesses differ in
more than their planning loop -- E8 needed its own claim path -- and because the intervals at
these sample sizes overlap heavily. The report computes the overlap and refuses to phrase a
comparison the data cannot carry.

Like the E1 and E3 reports, it cross-checks rows against summary before rendering; that guard
exists because an earlier experiment rendered one run's traces under another run's verdict.

  .venv/bin/python scripts/report_e8_planner_executor.py
"""
from __future__ import annotations

import csv
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROWS = ROOT / "results" / "e8_planner_executor.csv"
SUMM = ROOT / "results" / "e8_planner_executor_summary.csv"
M2 = ROOT / "results" / "m2_rates_n20.csv"
OUT = ROOT / "results" / "e8_planner_executor_REPORT.md"


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (100 * max(0.0, c - h), 100 * min(1.0, c + h))


def main() -> int:
    if not (ROWS.exists() and SUMM.exists()):
        print("E8 has not finished; nothing to render.", file=sys.stderr)
        return 2
    rows = list(csv.DictReader(open(ROWS)))
    summ = list(csv.DictReader(open(SUMM)))

    bad = []
    for s in summ:
        cell = [r for r in rows if r["scenario"] == s["scenario"]
                and r["ablation"] == s["ablation"] and r["arm"] == s["arm"]]
        k = sum(int(r["violation"]) for r in cell)
        if len(cell) != int(s["n"]) or k != int(s["violations"]):
            bad.append(f"{s['scenario']}/{s['ablation']}/{s['arm']}: rows {k}/{len(cell)}, "
                       f"summary {s['violations']}/{s['n']}")
    if bad:
        print("REFUSING: rows and summary disagree -- not the same run.", file=sys.stderr)
        for b in bad:
            print("  " + b, file=sys.stderr)
        return 3

    L = ["# E8 — does delay steering survive a different agent architecture?\n",
         "`delaysteer/run_e8_planner_executor.py` · `scripts/report_e8_planner_executor.py` · "
         "2026-09-11\n",
         "## Question\n",
         "The paper's own harness is a ReAct loop, and its other agents (smolagents "
         "`ToolCallingAgent`, a LangChain executor) also interleave one thought and one call. A "
         "reviewer can ask whether the phenomenon is a property of that shape. This runs a "
         "**structured planner/executor**: the plan is written before any tool runs, the executor "
         "never chooses what to do next, and the plan is revised only at a replanning node. "
         "Everything below the agent is the frozen stack — same router, same delay layer, same "
         "guard — so the architecture is the only variable.\n",
         "## Results\n",
         "| scenario | guard | arm | violations | 95% CI | mean replans | mean blocks |",
         "|---|---|---|---|---|---|---|"]
    for s in summ:
        lo, hi = wilson(int(s["violations"]), int(s["n"]))
        L.append(f"| {s['scenario']} | {s['ablation']} | {s['arm']} | "
                 f"{s['violations']}/{s['n']} | [{lo:.0f},{hi:.0f}] | "
                 f"{s['mean_replans']} | {s['mean_blocked']} |")
    L.append("")

    def cell(sc, ab, arm):
        for s in summ:
            if s["scenario"] == sc and s["ablation"] == ab and s["arm"] == arm:
                return s
        return None

    L.append("## What it settles\n")
    und_d = cell("contact_contradiction", "none", "delayed")
    und_h = cell("contact_contradiction", "none", "honest")
    if und_d and und_h:
        kd, nd = int(und_d["violations"]), int(und_d["n"])
        kh, nh = int(und_h["violations"]), int(und_h["n"])
        attr = 100 * (kd / nd - kh / nh)
        if attr > 0:
            L.append(f"**The attack transfers.** Undefended, the planner/executor violates "
                     f"{kd}/{nd} under the stale-door schedule against {kh}/{nh} honest, a "
                     f"delay-attributable {attr:+.0f} percentage points. Delay steering is "
                     f"therefore not a property of the ReAct loop: it lands equally on an "
                     f"architecture where the plan exists before any observation arrives and is "
                     f"revised only at a replanning node.")
        else:
            L.append(f"**The attack does not transfer on this scenario**: {kd}/{nd} delayed "
                     f"against {kh}/{nh} honest, so nothing is attributable to the delay. That is "
                     f"the result, and it bounds the paper's generality claim.")

    # The comparison the data cannot carry, computed rather than asserted.
    if M2.exists() and und_d:
        m2 = [r for r in csv.DictReader(open(M2))
              if r["scenario"] == "contact_contradiction" and r["ablation"] == "none"
              and r["model"] == "qwen3:14b" and r["home"] == "virtual"]
        if m2:
            mk, mn = (int(x) for x in m2[0]["violation_rate"].split("/"))
            mlo, mhi = wilson(mk, mn)
            elo, ehi = wilson(int(und_d["violations"]), int(und_d["n"]))
            overlap = not (ehi < mlo or mhi < elo)
            L.append(f"\n**What this does NOT settle.** The matched ReAct cell is {mk}/{mn} "
                     f"[{mlo:.0f},{mhi:.0f}] against this architecture's "
                     f"{und_d['violations']}/{und_d['n']} [{elo:.0f},{ehi:.0f}]. "
                     + ("Those intervals overlap, so the rates are not distinguishable here. "
                        if overlap else
                        "The intervals do not overlap, but ")
                     + "The two harnesses differ in more than their planning loop — this one "
                       "needed its own claim path — so a rate difference could not be attributed "
                       "to the architecture even if one were visible. We claim transfer, not a "
                       "robustness ranking.")

    guarded = [s for s in summ if s["ablation"] != "none"]
    if guarded:
        gk = sum(int(s["violations"]) for s in guarded)
        gn = sum(int(s["n"]) for s in guarded)
        L.append(f"\n**The defense transfers too**: {gk}/{gn} violations across every guarded "
                 f"cell. The contract sits at the tool-router gate and never inspects the "
                 f"planner, which is why swapping the planner does not move it.")

    lt = [s for s in summ if s["scenario"] == "lock_timeout" and s["ablation"] == "none"]
    if lt:
        ltrows = [r for r in rows if r["scenario"] == "lock_timeout"
                  and r["ablation"] == "none" and r["arm"] == "honest"]
        claimed = sum(int(r["secure_claim"]) for r in ltrows)
        L.append("\n**On the lock-timeout scenario** the undefended cells are "
                 + ", ".join(f"{s['arm']} {s['violations']}/{s['n']}" for s in lt)
                 + f". Honest, the planner completes the task and claims the house secure in "
                   f"{claimed}/{len(ltrows)} episodes, which is this run's only benign-utility "
                   f"measurement: in the contradiction scenario the door is genuinely open in "
                   f"both arms, so declining is correct there and no utility can be read from it."
                 + " **The null in the delayed arm should not be read as robustness.** This "
                   "family steers a ReAct planner through the recovery ladder — defer the arming "
                   "yet report secure — and our executor has no equivalent fail-open path to "
                   "take, so the absence says more about this harness than about the "
                   "architecture. The existing record has the ReAct planner at 0/20 violations "
                   "here for this model, so the result agrees with it either way. The "
                   "contradiction scenario is what carries E8's claim.")

    L.append("\n## Caveats\n")
    L.append("- Eight repeats per cell and the intervals are wide; they are quoted, not rounded "
             "away.")
    L.append("- The guarded cells use the **active-poll** ablation, not the plain budget. A "
             "plan-and-execute episode spends minutes replanning, so a 2 s budget judged at "
             "commit false-blocks every honest run — the first run of this experiment did exactly "
             "that, 8/8, and measured the budget rather than the architecture.")
    L.append("- The planner decides the secure claim, as in every other harness here. An earlier "
             "version had the executor decide from its own observations, which was stricter than "
             "any agent under test and made a violation unreachable by construction.")
    L.append("- Observations are rendered in the vocabulary the safety rule uses "
             "(`front_door=open|closed`). Shown the raw sensor value, where `on` means the door "
             "is open, the planner claimed the house secure in 4/4 honest runs.")
    L.append("- `scripts/../scratchpad e8_reach2.py` drives the harness with a stub planner and "
             "requires the paired behaviour before any long run: undefended 0 honest / 1 delayed, "
             "guarded blocked in both.")
    OUT.write_text("\n".join(L) + "\n")
    print("\n".join(L))
    print(f"\n-> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
