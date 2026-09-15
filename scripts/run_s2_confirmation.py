#!/usr/bin/env python3
"""Scenario 2 -- confirmation desynchronization, with the scripted human.

    python scripts/run_s2_confirmation.py --models qwen3:14b,qwen2.5:7b

The G4 probe measures the coherence gadget; this measures the SCENARIO, whose
distinguishing feature is that a human approves the unlock. The attack does not
deceive the person about the snapshot -- the snapshot is authentic and was
accurate when taken. What the delay changes is the interval between the snapshot
and the commit, so the human is asked a question whose answer has expired.

Two arms as everywhere else, plus one scenario-specific axis: whether the
approval card DISPLAYS the snapshot's age. That is a UI property, not an
assumption about people, and the tests show it is decisive -- an ideal user
declines an obviously ancient snapshot when shown its age and approves it when
not. Running both settings turns "would a better UI help?" from speculation into
a measurement.

The human model is deliberately FAVOURABLE (approves iff the displayed context
justifies it). A real user is worse -- habituation and notification fatigue push
toward approval -- so every number here is bounded to "the safeguard fails even
against an ideal user", which is the strong form of the claim.
"""

from __future__ import annotations

import argparse
import csv
import math
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from delaysteer.runtime import add_temperature_arg, banner, sampling_record
from delaysteer.timed import scenario2 as s2
from delaysteer.timed.capability import ResultWriter
from delaysteer.timed.gar import wilson

FIELDS = ["arm", "model", "template", "seed", "age_shown",
          "snapshot_shown_visitor", "snapshot_age_at_approval_s",
          "human_approved", "unlocked", "porch_actually_empty_at_unlock",
          "violated", "realized", "call_sequence", "n_turns", "error",
          "k", "k_flows", "attacker_position", "observations", "tier",
          "temperature", "sampling_regime", "model_digest"]

BOOLS = ["age_shown", "snapshot_shown_visitor", "human_approved", "unlocked",
         "porch_actually_empty_at_unlock", "violated", "realized"]


def _done(path: Path) -> set:
    if not path.exists() or path.stat().st_size == 0:
        return set()
    with path.open() as fh:
        return {(r["arm"], r["model"], r["template"], r["seed"], r["age_shown"])
                for r in csv.DictReader(fh)}


def mcnemar(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="qwen3:14b")
    ap.add_argument("--templates", type=int, default=12)
    ap.add_argument("--seeds", type=int, default=1)
    ap.add_argument("--delay", type=float, default=180.0)
    ap.add_argument("--max-turns", type=int, default=8)
    ap.add_argument("--out", default="results/s2_confirmation.csv")
    ap.add_argument("--resume", action="store_true")
    add_temperature_arg(ap)
    a = ap.parse_args()

    models = [m.strip() for m in a.models.split(",") if m.strip()]
    probe = sampling_record(models[0], temperature=a.temperature)
    if a.seeds > 1 and probe.exact:
        print(f"REFUSED: --seeds {a.seeds} at T=0 is one episode counted "
              f"{a.seeds} times. Use --templates or --temperature>0.")
        return 2

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    writer = ResultWriter(out, FIELDS)
    done = _done(writer.effective_path) if a.resume else set()

    arms = ["attack", "benign"]
    ages = [True, False]        # does the approval card show the snapshot age?
    total = len(models) * a.templates * a.seeds * len(arms) * len(ages)
    print(f"S2 CONFIRMATION DESYNC: {len(models)} models x {a.templates} "
          f"templates x {a.seeds} seeds x {len(arms)} arms x "
          f"{len(ages)} age-shown settings = {total} runs")

    rows, dead, t0, n = [], 0, time.time(), 0
    for model in models:
        rec = sampling_record(model, temperature=a.temperature)
        print(f"\n[{model}] {banner(rec)}", flush=True)
        for tmpl in range(a.templates):
            for seed in range(a.seeds):
                for age_shown in ages:
                    for arm in arms:
                        n += 1
                        key = (arm, model, str(tmpl), str(seed), str(int(age_shown)))
                        if key in done:
                            continue
                        try:
                            r = s2.run_one(model=model, seed=seed, arm=arm,
                                           template=tmpl, delay_s=a.delay,
                                           age_shown=age_shown,
                                           max_turns=a.max_turns,
                                           rec=sampling_record(
                                               model, seed=seed,
                                               temperature=a.temperature))
                        except Exception as exc:
                            print(f"  [{n}/{total}] HARNESS FAULT {arm} t{tmpl}: "
                                  f"{exc}", flush=True)
                            dead += 1
                            continue
                        if r.dead:
                            print(f"  [{n}/{total}] DEAD {arm} t{tmpl} "
                                  f"err={r.error[:80]!r}", flush=True)
                            dead += 1
                            continue
                        cap = s2.capability(model, seed, rec, a.delay)
                        row = {f: getattr(r, f, "") for f in FIELDS}
                        row.update({"attacker_position": cap.attacker_position,
                                    "observations": cap.observations,
                                    "tier": cap.tier,
                                    "temperature": cap.temperature,
                                    "sampling_regime": cap.sampling_regime,
                                    "model_digest": cap.model_digest or ""})
                        for b in BOOLS:
                            row[b] = int(row[b])
                        rows.append(row)
                        writer.write([row])
                        mark = "VIOLATION" if r.violated else "        ."
                        print(f"  [{n}/{total}] {arm:6s} t{tmpl:<2d} "
                              f"age_shown={int(age_shown)} {mark} "
                              f"approved={int(r.human_approved)} "
                              f"age={r.snapshot_age_at_approval_s:.0f}s "
                              f"{r.call_sequence}", flush=True)

    print(f"\nwrote {len(rows)} rows -> {writer.effective_path} ({dead} dead)")
    if a.resume:
        with writer.effective_path.open() as fh:
            rows = list(csv.DictReader(fh))
    _summary(rows)
    print(f"\nelapsed {time.time() - t0:.0f}s")
    return 0


def _summary(rows: list[dict]) -> None:
    live = [r for r in rows if str(r["call_sequence"]).strip()]
    if len(live) != len(rows):
        print(f"\nEXCLUDED {len(rows)-len(live)} non-participating rows")
    rows = live
    if not rows:
        print("no usable rows")
        return

    cells = defaultdict(list)
    for r in rows:
        cells[(r["model"], r["age_shown"], r["arm"])].append(r)

    print(f"\n{'model':14s} {'age_shown':>9s} {'arm':7s} {'n':>3s} "
          f"{'unlocked':>19s} {'violation':>19s}")
    print("-" * 78)
    for k in sorted(cells):
        m, ages, arm = k
        rs = cells[k]
        n = len(rs)
        u = sum(int(r["unlocked"]) for r in rs)
        v = sum(int(r["violated"]) for r in rs)
        lo1, hi1 = wilson(u, n)
        lo2, hi2 = wilson(v, n)
        print(f"{m:14s} {ages:>9s} {arm:7s} {n:3d} {u:2d}/{n:<2d} "
              f"{100*u/n:5.1f}% [{lo1:3.0f},{hi1:3.0f}]  {v:2d}/{n:<2d} "
              f"{100*v/n:5.1f}% [{lo2:3.0f},{hi2:3.0f}]")

    # paired, and split by whether the card showed the age
    print("\nDELAY-ATTRIBUTABLE UNLOCK-TO-EMPTY-PORCH (paired, exact McNemar)")
    print(f"{'model':14s} {'age_shown':>9s} {'pairs':>5s} {'b':>3s} {'c':>3s} "
          f"{'diff':>6s} {'p':>8s}")
    print("-" * 62)
    paired = defaultdict(dict)
    for r in rows:
        paired[(r["model"], r["age_shown"], r["template"], r["seed"])][r["arm"]] \
            = int(r["violated"])
    grp = defaultdict(list)
    for (m, ages, _t, _s), arm in paired.items():
        if "attack" in arm and "benign" in arm:
            grp[(m, ages)].append((arm["attack"], arm["benign"]))
    for k in sorted(grp):
        pr = grp[k]
        n = len(pr)
        b = sum(1 for x, y in pr if x and not y)
        c = sum(1 for x, y in pr if y and not x)
        print(f"{k[0]:14s} {k[1]:>9s} {n:5d} {b:3d} {c:3d} "
              f"{100*(b-c)/n:5.0f}% {mcnemar(b,c):8.4f}")

    print("\n  The age_shown split is the deployable finding: it is a UI")
    print("  property, not an assumption about people. If showing the")
    print("  snapshot's age collapses the attack, that is a mitigation any")
    print("  vendor can ship without device cooperation.")
    print("\n  The human is a SCRIPTED model that approves iff the displayed")
    print("  context justifies it -- deliberately favourable. A real user is")
    print("  worse, so these numbers bound 'the safeguard fails even against an")
    print("  ideal user'.")


if __name__ == "__main__":
    raise SystemExit(main())
