#!/usr/bin/env python3
"""E-C step 1: latency screen for the dropped-correction experiment (results/au4_agent_plan.md).

  .venv/bin/python scripts/run_au4_agent_screen.py

Runs AU4's benign timeline with the agent in the loop, 3 episodes per candidate (seeds 97-99, a
screen, not data), and prints each candidate's turn times and whether it locked and armed. A
candidate is eligible when it locked and armed in >= 2/3 episodes AND its median turn is < 25 s.
Rows go to results/au4_agent_screen.jsonl.
"""
import json
import os
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERMES = Path(os.environ.get("HERMES_HOME", Path.home() / "Desktop" / "hermes-agent"))
HPY = HERMES / ".venv" / "bin" / "python"
OUT = Path("results/au4_agent_screen.jsonl")                  # relative: no home path in logs
CANDIDATES = ("qwen3-14b-64k", "qwen2.5-7b-64k", "llama3.1-8b-64k", "mistral-nemo-12b-64k", "qwen3-8b-64k")
SEEDS, CAPABLE, MAX_MEDIAN_S = (97, 98, 99), 2, 25.0


def main():
    for m in CANDIDATES:
        for sd in SEEDS:
            cmd = [str(HPY), "scripts/au4_cooldown_suppression.py", "--arm", "benign", "--seed", str(sd),
                   "--n", "1", "--model", m, "--out", str(OUT)]
            print("\n$", " ".join(cmd[1:]), flush=True)
            subprocess.run(cmd, cwd=ROOT, check=False, env={**os.environ, "HERMES_HOME": str(HERMES)})
    rows = [json.loads(l) for l in (ROOT / OUT).read_text().splitlines() if l.strip()]
    print("\nmodel                  secure  turn_s (per episode)            median  eligible")
    for m in CANDIDATES:
        rs = [r for r in rows if r.get("model") == m and not r.get("error")]
        secure = sum(bool(r.get("acted_secure")) for r in rs)
        turns = [r["turn_s"] for r in rs if r.get("turn_s") is not None]
        med = statistics.median(turns) if turns else float("inf")
        ok = secure >= CAPABLE and med < MAX_MEDIAN_S
        print(f"{m:22s} {secure}/{len(rs)}    {str(turns):32s} {med:7.1f}  {'YES' if ok else 'no'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
