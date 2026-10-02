#!/usr/bin/env python3
"""X1 driver: AU1 under a two-channel hold, in the order results/au1_two_channel_plan.md fixes.

  .venv/bin/python scripts/run_au1_two_channel.py --smoke     # seed 101, not data
  .venv/bin/python scripts/run_au1_two_channel.py             # cells 1-3, 20 seeds each

Cells: (1) entity wording, attack; (2) entity wording, guard; (3) generic wording, attack.
Rows go to results/au1_two_channel.jsonl (the smoke row to results/au1_two_channel_smoke.jsonl).
The controls are the existing AU1 rows in results/au1_event_wake.jsonl.
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERMES = Path(os.environ.get("HERMES_HOME", Path.home() / "Desktop" / "hermes-agent"))
HPY = HERMES / ".venv" / "bin" / "python"
OUT = "results/au1_two_channel.jsonl"            # relative: no home path in logs
SMOKE = "results/au1_two_channel_smoke.jsonl"
CELLS = (("entity", "attack"), ("entity", "guard"), ("generic", "attack"))


def run(policy, arm, seed, n, out):
    cmd = [str(HPY), "scripts/au1_two_channel.py", "--arm", arm, "--policy", policy,
           "--model", "qwen3-14b-64k", "--seed", str(seed), "--n", str(n), "--timeout", "1800",
           "--out", out]
    print("\n$", " ".join(cmd[1:]), flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True, env={**os.environ, "HERMES_HOME": str(HERMES)})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", action="store_true")
    a = ap.parse_args()
    if a.smoke:
        run("entity", "attack", 101, 1, SMOKE)
        return 0
    for policy, arm in CELLS:
        run(policy, arm, 1, 20, OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
