#!/usr/bin/env python3
"""Summarize + plot the SimuHome TOCTOU DEFENSE comparison (results/toctou_defenses.csv):
TemporalGuard vs the TOCTOU-Bench defenses (Tool Fuser, SIM, Prompt Rewriting) on
small local models. Per defense: benign task utility vs attack-success-rate (ASR).
"""
from __future__ import annotations

import argparse
import csv

ORDER = ["none", "promptrewrite", "sim", "toolfuser", "temporalguard"]
LABEL = {"none": "No defense", "promptrewrite": "Prompt Rewriting", "sim": "SIM (read→write)",
         "toolfuser": "Tool Fuser", "temporalguard": "TemporalGuard"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="results/toctou_defenses.csv")
    ap.add_argument("--out", default="results/toctou_defenses.png")
    args = ap.parse_args()
    rows = list(csv.DictReader(open(args.csv)))
    for r in rows:
        for k in ("violation", "correct"):
            r[k] = int(r[k])
    defenses = [d for d in ORDER if any(r["defense"] == d for r in rows)]
    models = sorted({r["model"] for r in rows})

    def agg(defense, model=None):
        sel = [r for r in rows if r["defense"] == defense and (model is None or r["model"] == model)]
        ben = [r for r in sel if r["condition"].startswith("benign")]
        dly = [r for r in sel if r["condition"] == "delay_main_on"]
        bu = sum(r["correct"] for r in ben) / len(ben) if ben else float("nan")
        asr = sum(r["violation"] for r in dly) / len(dly) if dly else float("nan")
        return bu, asr

    print(f"\n=== DEFENSE COMPARISON (mean across {len(models)} models) ===")
    print(f"{'defense':18s} {'benign utility':>14s} {'ASR (delay)':>12s}")
    print("-" * 46)
    table = []
    for d in defenses:
        bu, asr = agg(d)
        table.append((d, bu, asr))
        print(f"{LABEL[d]:18s} {100*bu:13.0f}% {100*asr:11.0f}%")
    print("\nper-model ASR(delay) / benign-utility:")
    print(f"{'model':14s} " + " ".join(f"{LABEL[d][:10]:>11s}" for d in defenses))
    for m in models:
        cells = []
        for d in defenses:
            bu, asr = agg(d, m)
            cells.append(f"{100*asr:3.0f}/{100*bu:3.0f}")
        print(f"{m:14s} " + " ".join(f"{c:>11s}" for c in cells))
    print("(cells = ASR% / utility%)")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        labels = [LABEL[d] for d, *_ in table]
        bu = [t[1] * 100 for t in table]
        asr = [t[2] * 100 for t in table]
        x = np.arange(len(labels))
        w = 0.38
        fig, ax = plt.subplots(figsize=(9, 4.8))
        ax.bar(x - w / 2, asr, w, label="Attack success rate (delay)", color="#d1495b")
        ax.bar(x + w / 2, bu, w, label="Benign task utility", color="#2e86ab")
        ax.set_ylabel("Rate (%)")
        ax.set_ylim(0, 105)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=20, ha="right")
        ax.set_title("Defending the delay-only TOCTOU on SimuHome (small local models):\n"
                     "TemporalGuard vs TOCTOU-Bench defenses")
        ax.legend()
        ax.grid(axis="y", alpha=0.3)
        for i, (a, b) in enumerate(zip(asr, bu)):
            ax.text(i - w / 2, a + 1.5, f"{a:.0f}", ha="center", fontsize=8)
            ax.text(i + w / 2, b + 1.5, f"{b:.0f}", ha="center", fontsize=8)
        fig.tight_layout()
        fig.savefig(args.out, dpi=150)
        print(f"\nsaved figure -> {args.out}")
    except ImportError:
        print("\n(matplotlib not available; table only)")


if __name__ == "__main__":
    raise SystemExit(main())
