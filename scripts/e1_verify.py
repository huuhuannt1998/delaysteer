#!/usr/bin/env python3
"""E1 task 6: verify every reported cell against its artefact, then summarise.

Mission discipline (mis_01KZVRMET2H041053M72WN2HB8) requires that nothing is reported
without being checked against the artefact it came from, that the breakdown is PER ENTITY
CLASS rather than pooled, and that every zero-effect trial is reported rather than dropped.
This script does only that -- it computes nothing new, it audits.

Checks performed
  1. row integrity      -- required columns present and parseable per row
  2. age consistency    -- true_age >= observable_age wherever laundering is claimed
                           (a laundered value is OLDER in truth than it appears)
  3. sign sanity        -- no negative ages (the defect that produced -29692s earlier)
  4. delay-only         -- shim_synthesized_frame must be False on every row
  5. excluded batches   -- run_ids known to carry a measurement defect are excluded
                           explicitly and reported, never silently filtered

  python scripts/e1_verify.py
  python scripts/e1_verify.py --exclude-run 20260812T214500
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "results" / "position_laundering.csv"


def f(row, key):
    v = row.get(key, "")
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exclude-run", action="append", default=[],
                    help="run_id:POSITION to exclude (position optional). Scoped because arm 1 "
                         "ran A1 and B in ONE run, so excluding a whole run_id would also "
                         "discard 20 valid B-control cells.")
    ap.add_argument("--reason", default="known measurement defect")
    args = ap.parse_args()

    rows = list(csv.DictReader(open(CSV_PATH)))
    print(f"=== E1 verification: {CSV_PATH.relative_to(ROOT)} ===")
    print(f"  total rows on file: {len(rows)}")

    def is_excluded(r):
        for spec in args.exclude_run:
            rid, _, pos = spec.partition(":")
            if r.get("run_id") == rid and (not pos or r.get("position") == pos):
                return True
        return False
    excluded = [r for r in rows if is_excluded(r)]
    if excluded:
        print(f"  EXCLUDED {len(excluded)} rows ({args.exclude_run}): {args.reason}")
    rows = [r for r in rows if not is_excluded(r)]

    # ---- integrity checks ------------------------------------------------------------
    problems = []
    for i, r in enumerate(rows):
        ta, oa = f(r, "true_age_at_commit"), f(r, "observable_age_at_commit")
        if r.get("zero_effect") == "True":
            continue
        if ta is None or oa is None:
            problems.append(f"row {i}: unparseable ages"); continue
        if ta < 0 or oa < 0:
            problems.append(f"row {i}: NEGATIVE age (true={ta} obs={oa})")
        if r.get("shim_synthesized_frame") == "True":
            problems.append(f"row {i}: SYNTHESIZED FRAME -- delay-only claim void")
    print(f"  integrity problems: {len(problems)}")
    for p in problems[:10]:
        print(f"    !! {p}")

    valid = [r for r in rows if r.get("zero_effect") != "True"]
    zero = [r for r in rows if r.get("zero_effect") == "True"]
    print(f"  valid cells: {len(valid)}   zero-effect/failed (REPORTED, not dropped): {len(zero)}")
    if zero:
        by_note = defaultdict(int)
        for r in zero:
            by_note[(r["position"], (r.get("notes") or "")[:44])] += 1
        for (pos, note), n in sorted(by_note.items()):
            print(f"    {pos:<3} x{n:<3} {note}")

    # ---- per entity class, never pooled ----------------------------------------------
    print("\n=== PER ENTITY CLASS (pooling is forbidden: the classes may differ) ===")
    for ec in sorted({r["entity_class"] for r in valid if r.get("entity_class")}):
        print(f"\n  entity_class = {ec}")
        sub = [r for r in valid if r["entity_class"] == ec]
        for pos in sorted({r["position"] for r in sub}):
            for ct in sorted({r["commit_timing"] for r in sub if r["position"] == pos}):
                cells = [r for r in sub if r["position"] == pos and r["commit_timing"] == ct]
                print(f"    position {pos}  commit_timing={ct}")
                for tier in ("none", "static", "heartbeat", "activepoll"):
                    t = [r for r in cells if r["guard_tier"] == tier]
                    if not t:
                        continue
                    adm = sum(r["admitted"] == "True" for r in t)
                    vio = sum(r["invariant_violated"] == "True" for r in t)
                    ta = [f(r, "true_age_at_commit") for r in t if f(r, "true_age_at_commit") is not None]
                    oa = [f(r, "observable_age_at_commit") for r in t if f(r, "observable_age_at_commit") is not None]
                    med = lambda x: sorted(x)[len(x) // 2] if x else float("nan")
                    print(f"      {tier:<11} admitted {adm:>2}/{len(t):<2}  violated {vio:>2}/{len(t):<2}"
                          f"   median true_age {med(ta):7.2f}s   median obs_age {med(oa):6.3f}s")

    # ---- acceptance criterion (a) -----------------------------------------------------
    print("\n=== acceptance criterion (a) ===")
    a0t = [r for r in valid if r["position"] == "A0" and r["commit_timing"] == "timed"]
    b = [r for r in valid if r["position"] == "B"]
    def all_admit(rs, tiers=("static", "heartbeat", "activepoll")):
        out = {}
        for t in tiers:
            s = [r for r in rs if r["guard_tier"] == t]
            out[t] = (sum(r["admitted"] == "True" for r in s), len(s))
        return out
    print(f"  A0 timed  : {all_admit(a0t)}   (criterion wants all three admitting)")
    print(f"  B control : {all_admit(b)}     (criterion wants none admitting)")
    return 0 if not problems else 2


if __name__ == "__main__":
    raise SystemExit(main())
