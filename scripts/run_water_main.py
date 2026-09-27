#!/usr/bin/env python3
"""E-A driver: runs the cells of results/water_main_plan.md in the order the plan fixes.

  .venv/bin/python scripts/run_water_main.py

1. Agent of record (qwen3:14b): the benign world Cb (capability gate), then the test world C
   (fixed rule and planner, held and honest), then the guard arm (C, held).
2. Second model: the first of qwen2.5:7b, mistral:7b whose Cb run passes the capability gate
   (>= 15/20 restored on the fresh dry reading) runs C held and honest.

Everything goes to results/e1_water_main.csv (+ _summary.csv). The underlying runner merges
cells by (case, arm, model), so each invocation below owns distinct cells.
"""
import csv
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "e1_water_main.csv"
PY = sys.executable
GATE = 15
SECOND = ("qwen2.5:7b", "mistral:7b")


def run(*args):
    cmd = [PY, "scripts/run_e1_agent_specific.py", "--repeats", "20", "--seed0", "0",
           "--temperature", "0.7", "--out", str(OUT.relative_to(ROOT)), *args]   # relative: no home path in logs
    print("\n$", " ".join(cmd[1:]), flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True)


def restored(model):
    with OUT.open() as f:
        rows = [r for r in csv.DictReader(f)
                if r["case"] == "Cb" and r["arm"] == "planner" and r["model"] == model]
    return sum(r["branch"] == "restored_confirmed" for r in rows), len(rows)


def main():
    run("--cases", "Cb", "--arms", "planner", "--conds", "honest", "--model", "qwen3:14b")
    k, n = restored("qwen3:14b")
    print(f"\ncapability gate, qwen3:14b: restored {k}/{n} (need {GATE})", flush=True)
    run("--cases", "C", "--arms", "rule,planner", "--conds", "held,honest", "--model", "qwen3:14b")
    run("--cases", "C", "--arms", "guard", "--conds", "held", "--model", "qwen3:14b")
    for m in SECOND:
        run("--cases", "Cb", "--arms", "planner", "--conds", "honest", "--model", m)
        k, n = restored(m)
        print(f"\ncapability gate, {m}: restored {k}/{n} (need {GATE})", flush=True)
        if k >= GATE:
            run("--cases", "C", "--arms", "planner", "--conds", "held,honest", "--model", m)
            break
    else:
        print("\nno second model passed the capability gate", flush=True)


if __name__ == "__main__":
    main()
