#!/usr/bin/env python3
"""Delay-budget characterisation per (model, gadget).

Structured after the phantom-delay evaluation (DSN'22 Sec. IV/VI), which reports, per
device and message type, the range of delay an attacker can apply before a timeout
fires -- with 'inf' where no timeout exists at all. The planner-layer analogue is not a
protocol timeout but the range of holds over which a gadget stays delay-attributable:
a LOWER bound (the shortest hold that activates it) and an UPPER bound (the longest
before activation falls off), with 'inf' where activation never falls off.

Reads any number of GAR-schema CSVs and pools them by (model, gadget, delay_s).
Additive: reads only, writes results/delay_budget.json.
"""
import csv, glob, json, sys, collections

def load(paths):
    rows = []
    for p in paths:
        try:
            rows += [r for r in csv.DictReader(open(p))
                     if str(r.get("call_sequence", "")).strip()]
        except FileNotFoundError:
            pass
    return rows

def paired_b(rows, model, gadget, delay):
    """delay-attributable activations b and usable pairs, at one hold."""
    sel = [r for r in rows if r["model"] == model and r["gadget"] == gadget
           and float(r["delay_s"]) == delay]
    a = {r["template"]: int(r["realized"]) for r in sel if r["arm"] == "attack"}
    n = {r["template"]: int(r["realized"]) for r in sel if r["arm"] == "benign"}
    common = sorted(set(a) & set(n))
    b = sum(1 for t in common if a[t] and not n[t])
    c = sum(1 for t in common if n[t] and not a[t])
    return b, c, len(common)

def main(argv):
    paths = argv[1:] or ["results/gar_magnitude.csv", "results/gar_submin.csv"]
    rows = load(paths)
    if not rows:
        print("no rows"); return 1
    out = {"sources": paths, "cells": {}}
    delays = sorted({float(r["delay_s"]) for r in rows})
    print(f"sources: {', '.join(paths)}")
    print(f"holds swept: {', '.join(f'{d:g}s' for d in delays)}\n")
    hdr = f"{'model':14s} {'gadget':9s} " + "".join(f"{d:>9g}s" for d in delays) + "   budget"
    print(hdr); print("-" * len(hdr))
    for m in sorted({r["model"] for r in rows}):
        for g in sorted({r["gadget"] for r in rows}):
            cells, active = [], []
            for d in delays:
                b, c, n = paired_b(rows, m, g, d)
                cells.append((b, c, n))
                if n and b > 0:
                    active.append(d)
            if not any(n for _, _, n in cells):
                continue
            row = "".join(f"{b:>6d}/{n:<3d}" if n else f"{'--':>10s}" for b, _, n in cells)
            swept_hi = max(d for d, (b, c, n) in zip(delays, cells) if n)
            if not active:
                budget = "not activated"
            else:
                hi = "inf" if max(active) == swept_hi else f"{max(active):g}s"
                budget = f"[{min(active):g}s, {hi})"
            print(f"{m:14s} {g:9s} {row}   {budget}")
            out["cells"][f"{m}|{g}"] = {
                "per_hold": {f"{d:g}": {"b": b, "c": c, "pairs": n}
                             for d, (b, c, n) in zip(delays, cells)},
                "budget_low_s": min(active) if active else None,
                "budget_high": ("inf" if active and max(active) == swept_hi
                                else (max(active) if active else None)),
            }
    json.dump(out, open("results/delay_budget.json", "w"), indent=1)
    print("\n'inf' = activation never falls off across the swept range: no upper bound observed.")
    print("wrote results/delay_budget.json")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
