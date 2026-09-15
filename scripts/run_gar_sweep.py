#!/usr/bin/env python3
"""Stage 1 / Thrust A: the GAR sweep.

    python scripts/run_gar_sweep.py --models qwen3:14b,qwen2.5:7b --seeds 10

Emits one row per (gadget, arm, model, seed, delay) to results/gar.csv, plus a
per-cell summary with Wilson intervals and the competence split. Both arms run:
the benign arm is the control that says whether a miss is the delay's doing or
the planner's own.

Nothing here reads a rate off a dead row -- a transport error with no calls is
not an observation and is dropped, loudly. See scripts/prune_dead_rows.py.
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from delaysteer.runtime import add_temperature_arg, banner, sampling_record
from delaysteer.timed.capability import ResultWriter
from delaysteer.timed.gar import CATALOG, capability, run_one, wilson
from delaysteer.timed.scenarios import NON_COMPLETION, RESISTED, VIOLATION

FIELDS = ["probe", "gadget", "arm", "model", "template", "seed", "delay_s",
          "realized", "outcome_class", "violated", "call_sequence", "k",
          "k_flows", "n_turns", "error", "attacker_position", "observations",
          "tier", "temperature", "sampling_regime", "model_digest",
          "budget_h_max"]


def _completed_cells(path: Path) -> set[tuple[str, ...]]:
    """Cells already on disk, so a restart does not redo hours of inference."""
    if not path.exists() or path.stat().st_size == 0:
        return set()
    with path.open() as fh:
        return {(r["probe"], r["model"], r.get("template", "0"), r["seed"],
                 f'{float(r["delay_s"]):g}', r["arm"])
                for r in csv.DictReader(fh)}


def _load_rows(path: Path) -> list[dict]:
    with path.open() as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:                       # the summary counts these as numbers
        r["realized"] = int(r["realized"])
        r["delay_s"] = float(r["delay_s"])
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="qwen3:14b")
    ap.add_argument("--templates", type=int, default=5,
                    help="scenario instances per cell. This is where n comes "
                         "from at temperature 0: greedy decoding makes every "
                         "seed identical, so a seed sweep there is one "
                         "observation counted many times.")
    ap.add_argument("--seeds", type=int, default=1,
                    help="only a real axis in the RESAMPLED arm (temperature>0); "
                         "refused above 1 at T=0.")
    ap.add_argument("--delays", default="600")
    ap.add_argument("--gadgets", default="")
    ap.add_argument("--out", default="results/gar.csv")
    ap.add_argument("--benign", action="store_true", default=True)
    ap.add_argument("--no-benign", dest="benign", action="store_false")
    ap.add_argument("--max-turns", type=int, default=6,
                    help="turn cap. These tasks need 2-3 calls; hitting the cap "
                         "is recorded as non_completion, which is the honest "
                         "reading of an agent that never finished.")
    ap.add_argument("--resume", action="store_true",
                    help="skip cells already present in the output file")
    add_temperature_arg(ap)
    a = ap.parse_args()

    models = [m.strip() for m in a.models.split(",") if m.strip()]
    delays = [float(d) for d in a.delays.split(",") if d.strip()]
    want = {g.strip() for g in a.gadgets.split(",") if g.strip()}
    probes = [p for p in CATALOG if not want or p.gadget in want or p.name in want]

    arms = [True, False] if a.benign else [True]

    # The guard that stops a manufactured n. At T=0 decoding is greedy, so
    # seed 0..9 are the same episode ten times over; a Wilson interval computed
    # across them reports n=10 for an effective n=1. Refuse rather than let the
    # inflated interval reach a table.
    probe_rec = sampling_record(models[0], temperature=a.temperature)
    if a.seeds > 1 and probe_rec.exact:
        print(f"REFUSED: --seeds {a.seeds} at temperature {probe_rec.temperature}. "
              f"Greedy decoding makes every seed identical, so this would report "
              f"n={a.seeds} for an effective n of 1.\n"
              f"  Use --templates for n in the EXACT arm, or set "
              f"--temperature > 0 for the RESAMPLED arm.")
        return 2

    total = (len(probes) * len(models) * a.templates * a.seeds
             * len(delays) * len(arms))
    print(f"GAR sweep: {len(probes)} gadgets x {len(models)} models x "
          f"{a.templates} templates x {a.seeds} seeds x {len(delays)} delays "
          f"x {len(arms)} arms = {total} runs")

    # Rows are written as they are produced, not batched to the end. A panel
    # sweep is hours per model; a crash at hour 18 that had buffered everything
    # in memory would lose the lot. `--resume` then makes a restart cheap.
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    writer = ResultWriter(out, FIELDS)
    done = _completed_cells(writer.effective_path) if a.resume else set()
    if done:
        print(f"resume: {len(done)} cells already in {writer.effective_path.name}")

    rows, dead, t0 = [], 0, time.time()
    n = 0
    # Model OUTERMOST, deliberately. With the gadget outermost the six models
    # cycle eighteen times, and Ollama evicts and reloads ~10 GB of weights on
    # nearly every switch -- the reload, not the inference, then dominates wall
    # clock. Held this way each model loads once and stays resident for all its
    # runs. Nothing about the measurement changes; only the order.
    for model in models:
        for probe in probes:
            rec = sampling_record(model, temperature=a.temperature)
            print(f"\n[{probe.gadget} {probe.name}] {banner(rec)}")
            for delay_s in delays:
                for tmpl in range(a.templates):
                    for seed in range(a.seeds):
                        for attack in arms:
                            n += 1
                            cell = (probe.name, model, str(tmpl), str(seed),
                                    f"{delay_s:g}",
                                    "attack" if attack else "benign")
                            if cell in done:
                                continue
                            try:
                                r = run_one(probe, model=model, seed=seed,
                                            attack=attack, template=tmpl,
                                            delay_s=delay_s,
                                            max_turns=a.max_turns,
                                            rec=sampling_record(
                                                model, seed=seed,
                                                temperature=a.temperature))
                            except Exception as exc:        # harness fault, not a result
                                print(f"  [{n}/{total}] HARNESS FAULT "
                                      f"t{tmpl} seed={seed}: {exc}", flush=True)
                                dead += 1
                                continue
                            if r.dead:
                                # Say WHY. A dropped row with no recorded reason
                                # is a silent hole in the panel: two consecutive
                                # drops on the same cell are a systematic
                                # failure, not the transport noise the label
                                # implies, and without the error text there is
                                # no way to tell those apart afterwards.
                                print(f"  [{n}/{total}] DEAD t{tmpl} s{seed} "
                                      f"{r.arm} turns={r.n_turns} "
                                      f"err={r.error[:120]!r}", flush=True)
                                dead += 1
                                continue
                            cap = capability(model, seed, delay_s,
                                             sampling_record(
                                                 model, seed=seed,
                                                 temperature=a.temperature))
                            row = {
                                "probe": r.probe, "gadget": r.gadget,
                                "arm": r.arm, "model": r.model,
                                "template": r.template, "seed": r.seed,
                                "delay_s": r.delay_s,
                                "realized": int(r.realized),
                                "outcome_class": r.outcome_class,
                                "violated": int(r.violated),
                                "call_sequence": r.call_sequence, "k": r.k,
                                "k_flows": r.k_flows, "n_turns": r.n_turns,
                                "error": r.error,
                                "attacker_position": cap.attacker_position,
                                "observations": cap.observations,
                                "tier": cap.tier,
                                "temperature": cap.temperature,
                                "sampling_regime": cap.sampling_regime,
                                "model_digest": cap.model_digest or "",
                                "budget_h_max": cap.budget_h_max,
                            }
                            rows.append(row)
                            writer.write([row])      # durable immediately
                            mark = "*" if r.realized else "."
                            print(f"  [{n}/{total}] {r.arm[:6]:6s} t{tmpl} "
                                  f"s{seed} {mark} {r.outcome_class:14s} "
                                  f"{r.call_sequence}", flush=True)

    print(f"\nwrote {len(rows)} rows -> {writer.effective_path}  "
          f"({dead} dead, dropped)")
    if a.resume and done:
        rows = _load_rows(writer.effective_path)
        print(f"summarising {len(rows)} rows including {len(done)} resumed")

    # ------------------------------------------------------------- summary
    cells: dict[tuple, list] = defaultdict(list)
    for r in rows:
        cells[(r["gadget"], r["model"], r["arm"], r["delay_s"])].append(r)

    print(f"\n{'gadget':10s} {'model':14s} {'arm':7s} {'delay':>6s}  "
          f"{'GAR':>16s}  {'viol':>5s} {'resist':>6s} {'noncomp':>7s}")
    print("-" * 84)
    for key in sorted(cells):
        g, m, arm, d = key
        rs = cells[key]
        k, nn = sum(r["realized"] for r in rs), len(rs)
        lo, hi = wilson(k, nn)
        v = sum(1 for r in rs if r["outcome_class"] == VIOLATION)
        res = sum(1 for r in rs if r["outcome_class"] == RESISTED)
        nc = sum(1 for r in rs if r["outcome_class"] == NON_COMPLETION)
        print(f"{g:10s} {m:14s} {arm:7s} {d:6.0f}  "
              f"{k:2d}/{nn:<2d} {100*k/nn:5.1f}% [{lo:2d},{hi:3d}]  "
              f"{v:5d} {res:6d} {nc:7d}")

    _paired_contrast(rows)
    print(f"\nelapsed {time.time() - t0:.0f}s")
    return 0


def _paired_contrast(rows: list[dict]) -> None:
    """Delay-attributable GAR: the attack arm MINUS its own benign control.

    Raw attack-arm GAR is not the attack's effect. A planner that violates on
    the truthful observation would have violated anyway, and crediting the delay
    for it inflates the headline. Pairing is by (probe, model, template, seed,
    delay) so the two arms differ in exactly one thing -- whether the update was
    held -- which is also the structure McNemar's test needs.

    b = attack fired, benign did not  (the delay's doing)
    c = benign fired, attack did not  (noise, or the delay helping the planner)
    Only b - c is attributable.
    """
    paired: dict[tuple, dict[str, int]] = defaultdict(dict)
    for r in rows:
        key = (r["probe"], r["model"], r.get("template", 0), r["seed"],
               r["delay_s"])
        paired[key][r["arm"]] = int(r["realized"])

    cells: dict[tuple, list] = defaultdict(list)
    for (probe, model, _t, _s, d), arms in paired.items():
        if "attack" in arms and "benign" in arms:
            cells[(probe, model, d)].append((arms["attack"], arms["benign"]))

    if not cells:
        return
    print(f"\n{'delay-attributable GAR (attack arm minus its own control)':}")
    print(f"{'gadget':22s} {'model':14s} {'pairs':>5s} {'b':>3s} {'c':>3s} "
          f"{'attributable':>13s}")
    print("-" * 70)
    for key in sorted(cells):
        probe, model, d = key
        pairs = cells[key]
        b = sum(1 for atk, ben in pairs if atk and not ben)
        c = sum(1 for atk, ben in pairs if ben and not atk)
        both = sum(1 for atk, ben in pairs if atk and ben)
        n = len(pairs)
        print(f"{probe:22s} {model:14s} {n:5d} {b:3d} {c:3d} "
              f"{100 * (b - c) / n:12.1f}%")
        if both and b == 0:
            print(f"{'':22s} {'':14s}       NOTE: {both}/{n} fired in BOTH arms "
                  f"-- not delay-attributable")


if __name__ == "__main__":
    raise SystemExit(main())
