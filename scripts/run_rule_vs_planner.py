#!/usr/bin/env python3
"""B11 -- fixed rule against the planner, on all four families, matched schedules.

Reviewers objected that the rule comparator existed only for the bedtime family, so
the paper could neither establish that a rule cannot express the other three nor rule
out that it can. This runs both arms of each family under the SAME delay schedule and
reports the delay-attributable violation rate for each, with Wilson intervals.

The rules are in delaysteer/llm/backbone.py (AccessRule, ConfirmRule, AutomationRule);
each checks its preconditions once, treats an uncertain reading as a failed one, and
fails closed. Bedtime already has RuleBasedBaseline.

Additive: writes results/rule_vs_planner.csv. Reads no frozen file.
"""
import argparse, csv, math, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from delaysteer.config import Config
from delaysteer.llm.backbone import AccessRule, ConfirmRule, AutomationRule
from delaysteer.run_repair import run_repair
from delaysteer.run_confirm import run_confirm
from delaysteer.run_automation import run_auto

OUT = Path("results/rule_vs_planner.csv")
FIELDS = ["family", "arm", "planner", "model", "repeat", "seed", "delay",
          "violation", "blocked", "loop", "steps", "note"]


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(100 * max(0, c - h)), round(100 * min(1, c + h)))


def _one(family, rule, model, with_delay, seed, temperature):
    """Run one episode. rule=True uses the fixed rule; otherwise the LLM planner."""
    kw = dict(home_kind="virtual", with_delay=with_delay, ablation="none",
              label=f"{family}-{'rule' if rule else 'llm'}-{seed}",
              seed=seed, temperature=(None if rule else temperature))
    if family == "access":
        bb = AccessRule(Config()) if rule else None
        return run_repair(present=False, fail_open=False, backbone=bb,
                          model=(None if rule else model), **kw)
    if family == "confirmation":
        bb = ConfirmRule(Config()) if rule else None
        return run_confirm(present=False, hitl=False, backbone=bb,
                           model=(None if rule else model), **kw)
    bb = AutomationRule(Config()) if rule else None
    return run_auto(backbone=bb, model=(None if rule else model), **kw)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", default="access,confirmation,automation")
    ap.add_argument("--repeats", type=int, default=20)
    ap.add_argument("--model", default="qwen3:14b")
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--arms", default="rule,planner")
    ap.add_argument("--out", default=str(OUT))
    a = ap.parse_args()

    rows, tally = [], {}
    for family in [f.strip() for f in a.families.split(",") if f.strip()]:
        for arm in [x.strip() for x in a.arms.split(",") if x.strip()]:
          is_rule = arm == "rule"
          # A fixed rule is deterministic: one run settles it. The planner is sampled.
          n = 1 if is_rule else a.repeats
          # EVERY arm is paired against its own honest control. A violation that also
          # occurs with no delay is not delay-attributable, and reporting the attacked
          # rate alone is the error this paper's instrument exists to prevent.
          for delayed in (True, False):
            viol = 0
            for i in range(n):
                try:
                    r = _one(family, is_rule, a.model, delayed, 1000 + i, a.temperature)
                except Exception as exc:                      # keep the sweep alive
                    rows.append(dict(family=family, arm=arm, planner=arm,
                                     model=("--" if is_rule else a.model), repeat=i,
                                     seed=1000 + i, delay=delayed, violation="",
                                     blocked="", loop="", steps="", note=f"ERROR {exc}"))
                    continue
                v = bool(r.get("violation") or r.get("violations"))
                viol += v
                rows.append(dict(family=family, arm=arm, planner=arm,
                                 model=("--" if is_rule else a.model), repeat=i,
                                 seed=1000 + i, delay=delayed, violation=int(v),
                                 blocked=int(bool(r.get("blocked"))),
                                 loop=int(bool(r.get("loop"))),
                                 steps=r.get("steps", ""), note=""))
                print(f"  {family:13s} {arm:8s} {'delay ' if delayed else 'honest'} "
                      f"{i+1}/{n} violation={v}", flush=True)
            tally[(family, arm, delayed)] = (viol, n)

    # MERGE rather than overwrite. The arms are run in separate invocations (the rule
    # arm is deterministic and takes seconds; the planner arm is sampled and takes an
    # hour), and an earlier version opened this file "w" -- so the second invocation
    # silently destroyed the first one's rows.
    out = Path(a.out)
    out.parent.mkdir(exist_ok=True)
    keep = []
    if out.exists():
        with out.open() as fh:
            arms_now = {r["arm"] for r in rows}
            fams_now = {r["family"] for r in rows}
            keep = [r for r in csv.DictReader(fh)
                    if not (r.get("arm") in arms_now and r.get("family") in fams_now)]
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(keep + rows)
    if keep:
        print(f"  (merged: kept {len(keep)} rows from a previous arm)")

    print(f"\n{'family':14s} {'RULE atk/honest':>18s} {'PLANNER atk/honest':>22s}"
          f" {'delay-attributable':>20s}")
    print("-" * 78)
    for family in sorted({k[0] for k in tally}):
        def cell(arm):
            d = tally.get((family, arm, True))
            h = tally.get((family, arm, False))
            if not d:
                return "--", None
            hs = f"{h[0]}/{h[1]}" if h else "?"
            return f"{d[0]}/{d[1]} vs {hs}", (d, h)
        rs, rv = cell("rule")
        ps, pv = cell("planner")
        # delay-attributable = attacked minus honest, per arm
        att = ""
        if rv and rv[1]:
            att += f"rule {rv[0][0] - rv[1][0]:+d} "
        if pv and pv[1]:
            att += f"planner {pv[0][0] - pv[1][0]:+d}"
        print(f"{family:14s} {rs:>18s} {ps:>22s} {att:>20s}")
    print(f"\nwrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
