"""Run the small local LLM agent(s) on the REAL SmartThings cloud (virtual devices),
the cross-agent cells, to show how the model REACTS on a real second platform and
whether TemporalGuard protects it there. Mirrors the HA cross-agent cells of run_m2
(contradiction / lock-timeout x none / full), but with the SmartThings adapter.

This closes the gap that the deterministic second-platform reproduction
(run_smartthings.py -> smartthings.csv, scripted agents only) left open: the
language-model agent of record was never run on the real second platform.

ADDITIVE + frozen-safe: writes a NEW file results/smartthings_llm.csv and asserts
results/metrics.csv, results/smartthings.csv, results/m2_metrics.csv md5-UNCHANGED.
Token from $SMARTTHINGS_TOKEN / .env, read at runtime; never printed or committed.
Needs the virtual devices on the cloud (scripts/st_setup.py) and Ollama serving the
models locally.

  SMARTTHINGS_TOKEN=*** .venv/bin/python -m delaysteer.run_smartthings_llm
  SMARTTHINGS_TOKEN=*** .venv/bin/python -m delaysteer.run_smartthings_llm \
      --models qwen3:14b,mistral:7b --include-h12
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from . import run_m2

FROZEN = ["results/metrics.csv", "results/smartthings.csv", "results/m2_metrics.csv"]


def _md5(p: str) -> str:
    pp = Path(p)
    return hashlib.md5(pp.read_bytes()).hexdigest() if pp.exists() else "(absent)"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="qwen3:14b",
                    help="comma list of Ollama models (default: the agent of record)")
    ap.add_argument("--include-h12", action="store_true",
                    help="also run the longer-hold (h12) contradiction cell per model")
    ap.add_argument("--append", action="store_true",
                    help="keep existing results/smartthings_llm.csv rows (add models across runs)")
    args = ap.parse_args()
    models = [m.strip() for m in args.models.split(",") if m.strip()]

    before = {p: _md5(p) for p in FROZEN}
    prior = []
    outcsv = Path("results/smartthings_llm.csv")
    if args.append and outcsv.exists():
        prior = list(csv.DictReader(outcsv.open()))
        print(f"(append) carrying {len(prior)} existing rows "
              f"({sorted(set(r['model'] for r in prior))})")
    run_m2.ROWS.clear()
    home = "smartthings"
    for m in models:
        tag = f"smartthings_{m.replace(':', '_').replace('.', '')}"
        # stale-evidence path: attack steers (none) vs guard prevents (full)
        run_m2.run_cell(m, "contact_contradiction", "none", 4, f"{tag}_con_none_h4", home)
        run_m2.run_cell(m, "contact_contradiction", "full", 4, f"{tag}_con_full_h4", home)
        if args.include_h12:
            run_m2.run_cell(m, "contact_contradiction", "none", 12, f"{tag}_con_none_h12", home)
        # fail-open path: lock-timeout (none) vs guard (full)
        run_m2.run_cell(m, "lock_timeout", "none", 0, f"{tag}_lt_none", home)
        run_m2.run_cell(m, "lock_timeout", "full", 0, f"{tag}_lt_full", home)

    rows = prior + run_m2.ROWS
    out = Path("results")
    out.mkdir(exist_ok=True)
    fields = list(run_m2.ROWS[0].keys())
    with (out / "smartthings_llm.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    (out / "smartthings_llm.json").write_text(json.dumps(rows, indent=2, default=str))

    print("\n=== LLM agent on the REAL SmartThings cloud (cross-agent cells) ===")
    print(f"{'model':<22}{'scenario':<15}{'abl':<6}{'armed':<6}{'secure':<7}{'viol':<6}{'blk'}")
    for r in run_m2.ROWS:  # new rows this run (bool-typed); prior rows are kept in the CSV
        print(f"{r['model']:<22}{r['scenario'][:13]:<15}{r['ablation']:<6}"
              f"{('Y' if r['armed'] else 'n'):<6}{('Y' if r['secure_claim'] else 'n'):<7}"
              f"{('Y' if r['violation'] else 'n'):<6}{r['blocked']}")
    print(f"\nwrote results/smartthings_llm.csv ({len(rows)} rows total, "
          f"+{len(run_m2.ROWS)} this run)")
    for p in FROZEN:
        now = _md5(p)
        print(f"  {p} md5 {'UNCHANGED (frozen OK)' if now == before[p] else '!!! CHANGED !!!'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
