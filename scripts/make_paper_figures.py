#!/usr/bin/env python3
"""Render the four design-mandated figures the manuscript was missing.

Output names follow IEEE's convention -- submitting author's surname then -figN,
numbered to MATCH the figure number a reader sees. Fig. 1 is the TikZ teaser
and has no graphics file, so these four are supp-fig2 .. supp-fig5.

The research design (section 12) names ten figures. Four had no counterpart in the
paper even though the data was already committed:

    Fig 3   GAR heatmap, gadget x model          <- results/gar.csv
    Fig 4   GAR vs delay magnitude               <- results/gar_magnitude.csv
    Fig 9   protection / benign-cost frontier    <- results/defense_frontier.csv
    Fig 10  severity-detectability Pareto        <- results/detectability.csv

Every number plotted is read from the committed CSVs; nothing here recomputes or
resamples. Output goes to the manuscript's figures/ directory as PDF.

    python3 scripts/make_paper_figures.py
"""
from __future__ import annotations

import argparse
import collections
import csv
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

RESULTS = "results"
DEFAULT_OUT = ("manuscripts/delaysteer-paperspine/paper_rewriting_output/"
               "final_paper/figures")

# One IEEE column is 3.5in; keep figures at that width so they need no scaling.
COL = 3.45
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 7.5,
    "axes.labelsize": 7.5,
    "axes.titlesize": 8,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "legend.fontsize": 7,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.linewidth": 0.6,
    "xtick.major.width": 0.6,
    "ytick.major.width": 0.6,
    "grid.linewidth": 0.4,
    "lines.linewidth": 1.1,
    # IEEE requires >=300 dpi at display size. The heatmap uses imshow, which
    # rasterises; at 200 it measured 200 ppi in the emitted PDF and would have
    # failed the check. 600 leaves margin and costs nothing for line art.
    "figure.dpi": 600,
    "savefig.dpi": 600,
})
INK = "#131A21"
ACCENT = "#0B6E6E"


def rows(name):
    with open(os.path.join(RESULTS, name)) as fh:
        return list(csv.DictReader(fh))


def paired(rs, arms=("attack", "benign")):
    """Group runs into matched attack/control pairs on everything but the arm."""
    def key(r):
        return (r["probe"], r["gadget"], r["model"], r["template"],
                r["seed"], r["delay_s"])
    a = {key(r): r for r in rs if r["arm"] == arms[0]}
    b = {key(r): r for r in rs if r["arm"] == arms[1]}
    return [(a[k], b[k]) for k in sorted(set(a) & set(b))]


def truthy(v):
    return str(v).strip() in ("1", "True", "true")


# --------------------------------------------------------------- Fig 3
def fig_gar_heatmap(out):
    """Delay-attributable GAR per model x gadget: discordant b over usable pairs."""
    pairs = paired(rows("gar.csv"))
    cell = collections.defaultdict(lambda: [0, 0])   # (model, gadget) -> [b, n]
    for atk, ctl in pairs:
        # n is USABLE pairs, as the caption says: a pair in which either arm
        # produced no tool call at all is censored (the paper's capability
        # filter, App. denominators), so a model that never calls a tool gets a
        # dash -- its conditional rate is undefined -- not a measured 0/n.
        if not atk["call_sequence"].strip() or not ctl["call_sequence"].strip():
            continue
        c = cell[(atk["model"], atk["gadget"])]
        c[1] += 1
        if truthy(atk["realized"]) and not truthy(ctl["realized"]):
            c[0] += 1

    gadgets = sorted({g for _, g in cell})
    for atk, _ in pairs:                       # keep fully-censored models as dashed rows
        cell.setdefault((atk["model"], atk["gadget"]), [0, 0])
    gadgets = sorted({g for _, g in cell})
    # order models by overall attributable rate so the competence split is visible
    models = sorted({m for m, _ in cell},
                    key=lambda m: -sum(cell[(m, g)][0] for g in gadgets
                                       if (m, g) in cell))

    grid, notes = [], []
    for m in models:
        r, nr = [], []
        for g in gadgets:
            if (m, g) in cell and cell[(m, g)][1]:
                b, n = cell[(m, g)]
                r.append(b / n)
                nr.append(f"{b}/{n}")
            else:
                r.append(float("nan"))
                nr.append("--")
        grid.append(r)
        notes.append(nr)

    cmap = LinearSegmentedColormap.from_list("tealramp", ["#F4F7F8", ACCENT])
    cmap.set_bad("#E8ECEE")

    fig, ax = plt.subplots(figsize=(COL, 0.42 * len(models) + 1.05))
    im = ax.imshow(grid, cmap=cmap, vmin=0, vmax=1, aspect="auto",
               interpolation="nearest")
    ax.set_xticks(range(len(gadgets)))
    ax.set_xticklabels([g.replace("->", r"$\to$") for g in gadgets])
    ax.set_yticks(range(len(models)))
    ax.set_yticklabels(models)
    for i in range(len(models)):
        for j in range(len(gadgets)):
            v = grid[i][j]
            dark = (v == v) and v > 0.55
            ax.text(j, i, notes[i][j], ha="center", va="center", fontsize=6.5,
                    color="white" if dark else INK)
    ax.set_xlabel("gadget")
    cb = fig.colorbar(im, ax=ax, fraction=0.035, pad=0.03)
    cb.set_label("delay-attributable activation", fontsize=6.5)
    cb.ax.tick_params(labelsize=6)
    cb.outline.set_linewidth(0.5)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    fig.tight_layout(pad=0.35)
    fig.savefig(os.path.join(out, "supp-fig2.pdf"), bbox_inches="tight")
    plt.close(fig)
    return f"supp-fig2.pdf  ({len(models)} models x {len(gadgets)} gadgets)"


# --------------------------------------------------------------- Fig 4
def fig_gar_magnitude(out):
    """GAR against hold length, attack arm vs matched control.

    Plots GAR itself -- the activation rate the design names -- for both arms,
    rather than the discordant fraction b/(b+c). The two are different quantities:
    b/(b+c) is 30/30 here because c is zero, while the attack-arm GAR is 5/6 on G1.
    Showing both arms keeps the figure readable next to the paper's paired counts.
    """
    pairs = paired(rows("gar_magnitude.csv"))
    cell = collections.defaultdict(lambda: [0, 0, 0])   # (g,d) -> [atk, ctl, n]
    for atk, ctl in pairs:
        c = cell[(atk["gadget"], float(atk["delay_s"]))]
        c[2] += 1
        c[0] += truthy(atk["realized"])
        c[1] += truthy(ctl["realized"])

    gadgets = sorted({g for g, _ in cell})
    delays = sorted({d for _, d in cell})

    fig, ax = plt.subplots(figsize=(COL, 2.05))
    marks = ["o", "s", "^", "D"]
    for i, g in enumerate(gadgets):
        col = ACCENT if i == 0 else INK
        n = [cell[(g, d)][2] for d in delays]
        ax.plot(delays, [cell[(g, d)][0] / t for d, t in zip(delays, n)],
                marker=marks[i % len(marks)], markersize=3.4, color=col,
                linestyle="-", label=f"{g} attack")
        ax.plot(delays, [cell[(g, d)][1] / t for d, t in zip(delays, n)],
                marker=marks[i % len(marks)], markersize=3.0, color=col,
                linestyle=":", alpha=0.75, markerfacecolor="white",
                label=f"{g} control")
    ax.set_xscale("log")
    ax.set_xticks(delays)
    ax.set_xticklabels([f"{int(d)}" for d in delays])
    ax.set_xlabel("hold (s, log scale)")
    ax.set_ylabel("GAR")
    ax.set_ylim(-0.06, 1.14)
    ax.grid(axis="y", color="#CFD8DE", alpha=0.7)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, ncol=2, handlelength=1.5, columnspacing=1.0,
              loc="upper center", bbox_to_anchor=(0.5, -0.32))
    fig.tight_layout(pad=0.35)
    fig.savefig(os.path.join(out, "supp-fig3.pdf"), bbox_inches="tight")
    plt.close(fig)
    return f"supp-fig3.pdf  ({len(gadgets)} gadgets x {len(delays)} holds)"


# --------------------------------------------------------------- Fig 9
def fig_frontier(out):
    """What tightening the budget costs in benign rejection, and what it buys."""
    rs = sorted(rows("defense_frontier.csv"), key=lambda r: float(r["delta_s"]))
    delta = [float(r["delta_s"]) for r in rs]
    fpr = [100 * float(r["benign_fpr"]) for r in rs]

    fig, ax = plt.subplots(figsize=(COL, 2.05))
    ax.plot(delta, fpr, marker="o", markersize=3.4, color=ACCENT, zorder=3)
    ax.set_xscale("log")
    ax.set_xticks(delta)
    ax.set_xticklabels([f"{int(d)}" for d in delta])
    ax.set_xlabel(r"freshness budget $\Delta$ (s, log scale)")
    ax.set_ylabel("benign rejection (%)")
    ax.grid(axis="y", color="#CFD8DE", alpha=0.7)
    ax.set_axisbelow(True)

    # Mark the largest budget that still blocks each hold: the protection each buys.
    for col, hold, dy in (("blocks_5s", "5 s", 14), ("blocks_15s", "15 s", 26),
                          ("blocks_27s", "27 s", 38)):
        ok = [float(r["delta_s"]) for r in rs if truthy(r[col])]
        if not ok:
            continue
        d = max(ok)
        y = 100 * float(next(r for r in rs
                             if float(r["delta_s"]) == d)["benign_fpr"])
        ax.annotate(f"blocks {hold}", xy=(d, y), xytext=(0, dy),
                    textcoords="offset points", ha="center", fontsize=6.3,
                    color=INK,
                    arrowprops=dict(arrowstyle="-", lw=0.5, color="#5A6773"))
    fig.tight_layout(pad=0.35)
    fig.savefig(os.path.join(out, "supp-fig5.pdf"), bbox_inches="tight")
    plt.close(fig)
    return f"supp-fig5.pdf  ({len(rs)} budgets)"


# --------------------------------------------------------------- Fig 10
def fig_detectability(out):
    """Undetected hold against false-positive rate, per channel detector."""
    rs = [r for r in rows("detectability.csv") if r["n_held"] == "1"]
    by = collections.defaultdict(dict)
    for r in rs:
        by[r["detector"]][float(r["fpr"])] = float(r["max_undetected_hold_s"])

    fig, ax = plt.subplots(figsize=(COL, 2.35))
    marks = ["o", "s", "^"]
    ymax = 0
    for i, (det, series) in enumerate(sorted(by.items())):
        xs = sorted(series)
        ys = [series[x] for x in xs]
        ymax = max(ymax, max(ys))
        ax.plot([100 * x for x in xs], ys,
                marker=marks[i % len(marks)], markersize=3.4,
                color=ACCENT if det == "max_age" else INK,
                linestyle="-" if det == "max_age" else "--",
                label=det.replace("_", " "))

    ax.set_xscale("log")
    ax.set_ylim(0, ymax * 1.12)
    ax.set_xlabel("detector false-positive rate (%, log scale)")
    ax.set_ylabel("largest undetected hold (s)")
    ax.grid(axis="y", color="#CFD8DE", alpha=0.7)
    ax.set_axisbelow(True)

    # The two reference levels whose ordering against the binding detector is the
    # paper's closing-window result. Labelled hard left so they clear every series.
    x0 = ax.get_xlim()[0]
    for y, col, lab, va in ((30, "#8A5A00", "30 s class bound", "bottom"),
                            (5, "#A32018", "5 s attack hold", "bottom")):
        ax.axhline(y, color=col, lw=0.8, ls=":", zorder=1)
        ax.text(x0 * 1.04, y + ymax * 0.012, lab, va=va, ha="left",
                fontsize=6.3, color=col)

    # Legend below the axes: three series plus two rules leave no clear in-plot gap.
    ax.legend(frameon=False, ncol=3, handlelength=1.5, columnspacing=1.1,
              loc="upper center", bbox_to_anchor=(0.5, -0.30))
    fig.tight_layout(pad=0.35)
    fig.savefig(os.path.join(out, "supp-fig4.pdf"), bbox_inches="tight")
    plt.close(fig)
    return f"supp-fig4.pdf  ({len(by)} detectors)"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=DEFAULT_OUT)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    for fn in (fig_gar_heatmap, fig_gar_magnitude, fig_frontier, fig_detectability):
        try:
            print("  wrote", fn(a.out))
        except Exception as exc:                       # keep going; report honestly
            print(f"  FAILED {fn.__name__}: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
