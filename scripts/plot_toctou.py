#!/usr/bin/env python3
"""Summarize + plot the SimuHome TOCTOU small-model sweep (results/toctou.csv).

Per model: benign utility, ASR (no-delay control), ASR (delay attack), ASR under
TemporalGuard. Prints a text table (no deps) and, if matplotlib is available, saves
a grouped-bar figure ordered by model size.
"""
from __future__ import annotations

import argparse
import collections
import csv

# rough param size (B) for x-axis ordering / size-scaling view
SIZE = {"qwen3:0.6b": 0.6, "qwen3:1.7b": 1.7, "llama3.2:3b": 3, "qwen3:4b": 4,
        "mistral:7b": 7, "qwen2.5:7b": 7, "llama3.1:8b": 8, "qwen3:8b": 8,
        "qwen3:14b": 14, "qwen3.6:27b": 27}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="results/toctou.csv")
    ap.add_argument("--out", default="results/toctou.png")
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.csv)))
    for r in rows:
        for k in ("violation", "correct", "checked_main", "set_backup_on",
                  "guard_blocked", "main_true_on", "backup_true_on"):
            r[k] = int(r[k])
    models = sorted({r["model"] for r in rows}, key=lambda m: SIZE.get(m, 99))

    def sub(m, conds):
        return [r for r in rows if r["model"] == m and r["condition"] in conds]

    def rate(rs, field):
        return (sum(r[field] for r in rs) / len(rs)) if rs else float("nan")

    print(f"\n{'model':14s} {'size':>4s} {'benignU':>8s} {'chkMain':>8s} "
          f"{'ASR.noDel':>9s} {'ASR.delay':>9s} {'ASR.guard':>9s}")
    print("-" * 70)
    table = []
    for m in models:
        ben = sub(m, {"benign_main_off", "benign_main_on"})
        nod = sub(m, {"nodelay_main_on"}) or sub(m, {"benign_main_on"})
        dly = sub(m, {"delay_main_on"})
        grd = sub(m, {"guard_main_on"})
        bu, chk = rate(ben, "correct"), rate(ben, "checked_main")
        a0, ad, ag = rate(nod, "violation"), rate(dly, "violation"), rate(grd, "violation")
        table.append((m, bu, chk, a0, ad, ag))
        print(f"{m:14s} {SIZE.get(m,'?'):>4} {100*bu:7.0f}% {100*chk:7.0f}% "
              f"{100*a0:8.0f}% {100*ad:8.0f}% {100*ag:8.0f}%")
    # aggregate
    dd = [r for r in rows if r["condition"] == "delay_main_on"]
    gg = [r for r in rows if r["condition"] == "guard_main_on"]
    print("-" * 70)
    print(f"{'MEAN (all models)':14s} {'':>4} {'':>8} {'':>8} "
          f"{'':>9} {100*rate(dd,'violation'):8.0f}% {100*rate(gg,'violation'):8.0f}%")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        labels = [m for m, *_ in table]
        ad = [t[4] * 100 for t in table]
        ag = [t[5] * 100 for t in table]
        bu = [t[1] * 100 for t in table]
        x = np.arange(len(labels))
        w = 0.38
        fig, axL = plt.subplots(figsize=(11, 4.5))
        axL.bar(x - w / 2, ad, w, label="ASR under delay attack", color="#d1495b")
        axL.bar(x + w / 2, ag, w, label="ASR under TemporalGuard", color="#2e86ab")
        axL.plot(x, bu, "o--", color="#e8a33d", label="benign task utility")
        axL.set_ylabel("Rate (%)")
        axL.set_ylim(0, 105)
        axL.set_xticks(x)
        axL.set_xticklabels(labels, rotation=30, ha="right")
        axL.set_title("Delay-only TOCTOU on SimuHome: small local models "
                      "(attack success vs TemporalGuard)")
        axL.legend(loc="center right")
        axL.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        fig.savefig(args.out, dpi=150)
        print(f"\nsaved figure -> {args.out}")
    except ImportError:
        print("\n(matplotlib not available; table only)")


if __name__ == "__main__":
    raise SystemExit(main())
