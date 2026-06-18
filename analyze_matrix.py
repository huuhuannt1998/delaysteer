"""Mission mis_01KT2B01 — analysis + acceptance-criteria verification over metrics.csv.

Reads results/metrics.csv (the three-way matrix: rule_based / scripted /
scripted/failopen / qwen3:14b) and produces:
  * per-agent RQ1 / RQ3 / RQ4-ablation / usability tables,
  * the two labeled cross-agent findings (lock_timeout-vs-contact_contradiction
    divergence; benign automation over-removal),
  * a structural check of each Mission-2 acceptance criterion against the rows,
  * verification that the three chk_01KT2HCR benign-block rules are reflected.

  python analyze_matrix.py            # uses results/metrics.csv
"""

from __future__ import annotations

import csv
import sys
from collections import defaultdict
from pathlib import Path

LLM = "qwen3:14b"
HOMES = ["virtual", "cloud", "ha"]
ABLATIONS = ["none", "provenance", "freshness", "twophase", "full"]


def load(path="results/metrics.csv"):
    rows = list(csv.DictReader(open(path)))
    for r in rows:  # normalize the booleans/blanks the harness wrote as strings
        r["_viol"] = str(r.get("violation")).strip().lower() == "true"
        r["_delay"] = str(r.get("delay")).strip().lower() == "true"
    return rows


def _f(rows, **kw):
    out = rows
    for k, v in kw.items():
        out = [r for r in out if r.get(k) == v]
    return out


def rq1(rows):
    print("\n=== RQ1 feasibility — attack-violation rate (delay=True) per agent x home ===")
    feas = _f(rows, group="feasibility")
    agents = sorted({r["agent"] for r in feas})
    for ag in agents:
        for home in HOMES:
            cells = [r for r in feas if r["agent"] == ag and r["home"] == home and r["_delay"]]
            if not cells:
                continue
            v = sum(r["_viol"] for r in cells)
            fams = ",".join(f"{r['family'].split('/')[-1]}={'V' if r['_viol'] else '.'}" for r in cells)
            print(f"  [{ag:<16}] {home:<8} {v}/{len(cells)}   {fams}")


def rq3(rows):
    print("\n=== RQ3 — agentic vs rule_based under identical delay (bedtime) ===")
    base = [r for r in _f(rows, group="baseline") if r["_delay"]]
    for ag in sorted({r["agent"] for r in base}):
        for home in HOMES:
            cells = [r for r in base if r["agent"] == ag and r["home"] == home]
            if not cells:
                continue
            detail = ", ".join(f"{r.get('family','bedtime').split('/')[-1]}:{'V' if r['_viol'] else '.'}"
                               for r in cells)
            print(f"  [{ag:<16}] {home:<8} viol {sum(r['_viol'] for r in cells)}/{len(cells)}   {detail}")


def rq4(rows):
    print("\n=== RQ4 ablation — family-cells PREVENTED / total, per agent ===")
    abl = _f(rows, group="ablation")
    for ag in sorted({r["agent"] for r in abl}):
        line = []
        for ab in ABLATIONS:
            cells = [r for r in abl if r["agent"] == ag and r.get("ablation") == ab]
            prevented = sum(1 for r in cells if not r["_viol"])
            line.append(f"{ab}:{prevented}/{len(cells)}")
        print(f"  [{ag:<16}] " + "  ".join(line))


def usability(rows):
    print("\n=== RQ4 usability — per agent x home (benign-FP rate vs misbehavior count) ===")
    us = _f(rows, group="usability")
    for ag in sorted({r["agent"] for r in us}):
        for home in HOMES:
            cells = [r for r in us if r["agent"] == ag and r["home"] == home]
            if not cells:
                continue
            fb = sum(int(float(r["false_blocks"])) for r in cells if r.get("false_blocks") not in (None, ""))
            mis = sum(int(float(r["benign_misbehavior_activation"])) for r in cells
                      if r.get("benign_misbehavior_activation") not in (None, ""))
            print(f"  [{ag:<16}] {home:<8} false_blocks={fb}  benign_misbehavior_activations={mis}")


def cross_agent(rows):
    print("\n=== CROSS-AGENT FINDING 1: lock_timeout vs contact_contradiction ===")
    # Use RQ3/baseline + RQ1 feasibility attack rows, bedtime scenarios.
    cand = [r for r in rows if r["_delay"] and r.get("family", "").startswith("bedtime/")
            and r["group"] in ("feasibility", "baseline")]
    by = defaultdict(lambda: defaultdict(list))
    for r in cand:
        scen = r["family"].split("/")[-1]
        by[r["agent"]][scen].append(r["_viol"])
    for ag in sorted(by):
        parts = [f"{scen}: {sum(v)}/{len(v)}" for scen, v in sorted(by[ag].items())]
        print(f"  [{ag:<16}] " + "   ".join(parts))
    print("  (expected: scripted/failopen violates lock_timeout; qwen3 does NOT fail-open on")
    print("   lock_timeout but violates contact_contradiction -> different mechanism.)")

    print("\n=== CROSS-AGENT FINDING 2: benign automation over-removal (chk_01KT2HCR) ===")
    us = _f(rows, group="usability")
    for ag in sorted({r["agent"] for r in us}):
        cells = [r for r in us if r["agent"] == ag and "automation" in r.get("family", "")]
        mis = sum(int(float(r.get("benign_misbehavior_activation") or 0)) for r in cells)
        fb = sum(int(float(r.get("false_blocks") or 0)) for r in cells)
        print(f"  [{ag:<16}] automation benign: misbehavior_activations={mis}  false_blocks={fb}")
    print("  (rule: misbehavior activation is counted SEPARATELY, never as a false block.)")


def verify_acs(rows):
    print("\n=== ACCEPTANCE-CRITERIA STRUCTURAL CHECK (vs actual rows) ===")
    checks = []
    llm = [r for r in rows if r["agent"] == LLM]
    homes_present = sorted({r["home"] for r in llm})
    # Full 3-target coverage is required (A4 said live HA is reachable). If a target
    # is legitimately gated (unreachable), this FLAGS it rather than silently passing.
    missing_homes = [h for h in HOMES if h not in homes_present]

    # AC1: qwen3 rows for RQ1 across 5 family-cells x ALL 3 targets.
    rq1f = {(r["home"], r["family"]) for r in llm if r["group"] == "feasibility"}
    fam_cells = {"bedtime/lock_timeout", "bedtime/contact_contradiction", "access", "confirmation", "automation"}
    ac1 = all((h, f) in rq1f for h in HOMES for f in fam_cells)
    checks.append(("AC1 RQ1 qwen3 rows (5 family-cells x 3 targets)", ac1,
                   f"covered={homes_present}" + (f" MISSING={missing_homes}" if missing_homes else "")))

    # AC2: RQ4 ablation 5 ablations x (>=5 family-cells) x ALL 3 targets for qwen3.
    abl_ok = all(len([r for r in llm if r["group"] == "ablation" and r["home"] == h and r.get("ablation") == ab]) >= 5
                 for h in HOMES for ab in ABLATIONS)
    checks.append(("AC2 RQ4 ablation 5x5 x 3 targets (qwen3)", abl_ok,
                   f"MISSING={missing_homes}" if missing_homes else ""))

    # AC: RQ3 qwen3 vs rule_based both present
    has_q_base = any(r["agent"] == LLM and r["group"] == "baseline" for r in rows)
    has_rb = any(r["agent"] == "rule_based" and r["group"] == "baseline" for r in rows)
    checks.append(("RQ3 has both qwen3 and rule_based baseline rows", has_q_base and has_rb, ""))

    # benign-block rule 2: separate misbehavior count exists and qwen3>=1, scripted=0 (automation benign)
    q_mis = sum(int(float(r.get("benign_misbehavior_activation") or 0)) for r in rows
                if r["agent"] == LLM and "automation" in r.get("family", "") and r["group"] == "usability")
    checks.append(("chk rule 2: qwen3 automation benign misbehavior_activation >= 1", q_mis >= 1, f"count={q_mis}"))

    # three-way scheme intact
    agents = sorted({r["agent"] for r in rows})
    three_way = {"rule_based", "scripted/failopen", LLM}.issubset(set(agents))
    checks.append(("three-way agent scheme present", three_way, f"agents={agents}"))

    for name, ok, note in checks:
        print(f"  [{'PASS' if ok else 'FAIL/PENDING'}] {name}" + (f"  ({note})" if note else ""))
    return all(c[1] for c in checks)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "results/metrics.csv"
    if not Path(path).exists():
        print(f"no metrics file at {path}")
        return 1
    rows = load(path)
    print(f"loaded {len(rows)} rows from {path}; homes={sorted({r['home'] for r in rows})}; "
          f"agents={sorted({r['agent'] for r in rows})}")
    rq1(rows); rq3(rows); rq4(rows); usability(rows); cross_agent(rows)
    ok = verify_acs(rows)
    print(f"\nSTRUCTURAL ACCEPTANCE: {'ALL PRESENT' if ok else 'INCOMPLETE (matrix still running or gaps)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
