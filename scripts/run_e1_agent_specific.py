#!/usr/bin/env python3
"""E1 -- agent-specific inference and recovery under a pure timeout.

Reviewer objection: three of four families also break a fixed rule, so the paper
does not show a distinctly agentic problem. Hypothesis: with NO truthful value
ever delivered on the held channel, an adaptive planner reaches decisions a
fixed-rule comparator cannot express -- it substitutes a proxy signal, drops the
dependency, or synthesises a recovery -- because it interprets the failure.

Both arms of each case run under the SAME world and the SAME hold schedule, each
paired with its own honest control (the paper's instrument: a branch that also
occurs with no delay is not delay-attributable). The rule is deterministic (one
run per condition); the planner is sampled over seeds.

Writes (NEW files only; reads no frozen file):
  results/e1_agent_specific.csv           one row per episode
  results/e1_agent_specific_summary.csv   per case/arm/model/delay rates, Wilson
                                          intervals, branch counts, and the
                                          planner-only branch set

  .venv/bin/python scripts/run_e1_agent_specific.py --cases A,B --repeats 20 \
      --model qwen3:14b --temperature 0.7
"""
import argparse, csv, json, math, sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from delaysteer.run_e1_agent_specific import run_e1
from delaysteer.runtime import add_temperature_arg, banner, sampling_record
from delaysteer.scenarios.e1_agent_specific import BRANCHES, CASES, RULE_BRANCHES

OUT = Path("results/e1_agent_specific.csv")
FIELDS = ["case", "family", "arm", "model", "repeat", "seed", "temperature", "sampling_regime",
          "model_digest", "delay", "activation", "violation", "completed", "blocked", "steps",
          "branch", "branch_in_rule_policy", "commit_tool", "n_probes", "n_timeouts",
          "proxy_reads", "asked_user", "scheduled", "errors", "tool_seq", "report", "note"]
SUMMARY_FIELDS = ["case", "arm", "model", "delay", "n", "violations", "violation_rate",
                  "wilson_lo", "wilson_hi", "completed", "activation", "errors",
                  "attributable_pp", "branches", "planner_only_branches"]


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(100 * max(0, c - h), 1), round(100 * min(1, c + h), 1))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="A,B")
    ap.add_argument("--repeats", type=int, default=20)
    ap.add_argument("--model", default="qwen3:14b")
    ap.add_argument("--arms", default="rule,planner",
                    help="rule, planner, guard (planner behind TemporalGuard; E-A cases only)")
    ap.add_argument("--conds", default="held,honest", help="which delay conditions to run")
    ap.add_argument("--seed0", type=int, default=0, help="first seed; seeds are seed0..seed0+n-1")
    ap.add_argument("--out", default=str(OUT))
    add_temperature_arg(ap)
    a = ap.parse_args()

    cases = [c.strip() for c in a.cases.split(",") if c.strip()]
    for c in cases:
        if c not in CASES:
            ap.error(f"unknown case {c!r}; choose from {CASES}")
    arms = [x.strip() for x in a.arms.split(",") if x.strip()]
    conds = [c.strip() for c in a.conds.split(",") if c.strip()]
    if not set(conds) <= {"held", "honest"}:
        ap.error("--conds takes held and/or honest")
    rec = sampling_record(a.model, seed=a.seed0, temperature=a.temperature)
    print(banner(rec))
    if rec.exact and a.repeats > 1 and "planner" in arms:
        print("  NOTE: temperature 0 -- the planner repeats are greedy near-duplicates; "
              "use --temperature 0.7 (or DELAYSTEER_TEMPERATURE) for the resampling arm.")

    rows = []
    for case in cases:
        for arm in arms:
            is_rule = arm == "rule"
            n = 1 if is_rule else a.repeats
            for delayed in [c == "held" for c in ("held", "honest") if c in conds]:
                for i in range(n):
                    seed = a.seed0 + i
                    label = f"{case}_{arm}_{'held' if delayed else 'honest'}_{seed}"
                    base = dict(case=case, arm=arm, model=("--" if is_rule else a.model),
                                repeat=i, seed=(seed if not is_rule else ""),
                                temperature=("" if is_rule else rec.temperature),
                                sampling_regime=("" if is_rule else rec.regime),
                                model_digest=("" if is_rule else rec.model_digest or ""),
                                delay=delayed, blocked=0, note="")
                    guard = arm == "guard"
                    try:
                        r = run_e1(case, delayed, label, rule=is_rule, model=a.model,
                                   seed=seed, temperature=rec.temperature, guard=guard)
                    except Exception as exc:                   # keep the sweep alive
                        rows.append(dict(base, family="", activation="", violation="",
                                         completed="", steps="", branch="", branch_in_rule_policy="",
                                         commit_tool="", n_probes="", n_timeouts="", proxy_reads="",
                                         asked_user="", scheduled="", errors="", tool_seq="",
                                         report="", note=f"ERROR {type(exc).__name__}: {exc}"))
                        print(f"  {case} {arm:8s} {'held  ' if delayed else 'honest'} "
                              f"{i+1}/{n} ERROR {exc}", flush=True)
                        continue
                    base["blocked"] = r.get("blocked", 0)
                    rows.append(dict(base, family=r["family"], activation=int(r["activation"]),
                                     violation=int(r["violation"]), completed=int(r["completed"]),
                                     steps=r["steps"], branch=r["branch"],
                                     branch_in_rule_policy=int(r["branch_in_rule_policy"]),
                                     commit_tool=r["commit_tool"], n_probes=r["n_probes"],
                                     n_timeouts=r["n_timeouts"],
                                     proxy_reads=";".join(r["proxy_reads"]),
                                     asked_user=r["asked_user"], scheduled=int(r["scheduled"]),
                                     errors=r["errors"], tool_seq=r["tool_seq"],
                                     report=(r["report"] or "").replace("\n", " ")))
                    print(f"  {case} {arm:8s} {'held  ' if delayed else 'honest'} {i+1}/{n} "
                          f"branch={r['branch']:20s} violation={int(r['violation'])} "
                          f"steps={r['steps']}", flush=True)

    # Merge with any earlier invocation (arms run separately: the rule takes seconds,
    # the planner an hour), replacing only the (case, arm, model) cells re-run now.
    out = Path(a.out)
    # A --out without a suffix used to write an extensionless rows file NEXT TO a stale
    # <base>.csv from an earlier run, while the summary went to <base>_summary.csv. The
    # pair then disagreed and anything reading them together read one run's rows against
    # another run's summary. Normalise so the two always name the same run.
    if out.suffix != ".csv":
        out = out.with_suffix(".csv")
    out.parent.mkdir(exist_ok=True)
    keep = []
    if out.exists():
        now = {(r["case"], r["arm"], r["model"]) for r in rows}
        with out.open() as fh:
            keep = [r for r in csv.DictReader(fh)
                    if (r.get("case"), r.get("arm"), r.get("model")) not in now]
    allrows = keep + rows
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(allrows)
    if keep:
        print(f"  (merged: kept {len(keep)} rows from a previous invocation)")

    summary = summarize(allrows)
    sout = out.with_name(out.stem + "_summary.csv")
    with sout.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=SUMMARY_FIELDS)
        w.writeheader()
        w.writerows(summary)
    print_summary(summary)
    print(f"\nwrote {out} and {sout}")
    return 0


def _b(v):
    return str(v) in ("1", "True", "true")


def summarize(rows):
    cells = {}
    for r in rows:
        if r.get("note", "").startswith("ERROR") or r.get("branch") in ("", None):
            key = (r["case"], r["arm"], r["model"], _b(r["delay"]))
            cells.setdefault(key, []).append(None)
            continue
        key = (r["case"], r["arm"], r["model"], _b(r["delay"]))
        cells.setdefault(key, []).append(r)
    out = []
    for key in sorted(cells, key=lambda k: (k[0], k[1] != "rule", k[2], not k[3])):
        case, arm, model, delayed = key
        ok = [r for r in cells[key] if r is not None]
        n = len(ok)
        viol = sum(_b(r["violation"]) for r in ok)
        lo, hi = wilson(viol, n)
        branches = Counter(r["branch"] for r in ok)
        honest = [r for r in cells.get((case, arm, model, False), []) if r is not None]
        att = ""
        if delayed and honest:
            att = round(100 * (viol / n - sum(_b(r["violation"]) for r in honest) / len(honest)), 1)
        planner_only = sorted(b for b in branches if b not in RULE_BRANCHES[case]) \
            if arm != "rule" else []
        out.append(dict(case=case, arm=arm, model=model, delay=int(delayed), n=n,
                        violations=viol, violation_rate=round(100 * viol / n, 1) if n else "",
                        wilson_lo=lo, wilson_hi=hi,
                        completed=sum(_b(r["completed"]) for r in ok),
                        activation=sum(_b(r["activation"]) for r in ok),
                        errors=len(cells[key]) - n, attributable_pp=att,
                        branches=";".join(f"{b}={branches[b]}" for b in BRANCHES if b in branches),
                        planner_only_branches=";".join(planner_only)))
    return out


def print_summary(summary):
    print(f"\n{'case':4s} {'arm':8s} {'model':10s} {'cond':6s} {'viol':>7s} {'rate%':>6s} "
          f"{'wilson':>13s} {'attrib':>7s}  branches")
    print("-" * 100)
    for s in summary:
        print(f"{s['case']:4s} {s['arm']:8s} {s['model'][:10]:10s} "
              f"{'held' if s['delay'] else 'honest':6s} "
              f"{s['violations']}/{s['n']:<4d} {str(s['violation_rate']):>6s} "
              f"[{s['wilson_lo']:>4},{s['wilson_hi']:>5}] {str(s['attributable_pp']):>7s}  "
              f"{s['branches']}"
              + (f"   PLANNER-ONLY: {s['planner_only_branches']}" if s['planner_only_branches'] else ""))


if __name__ == "__main__":
    sys.exit(main())
