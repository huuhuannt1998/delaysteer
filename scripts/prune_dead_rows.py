#!/usr/bin/env python3
"""Remove rows that record a transport failure rather than an observation.

Why this exists. On 2026-08-13 the ollama server died at the start of E4's attack
arm. The harness kept looping, wrote 20 rows carrying `URLError: Connection
refused` with an empty `call_sequence`, and its own summary then reported them as
"escalation 0/20" -- a clean-looking null that was really twenty runs that never
reached the model. Pooled with the surviving pilot it would have published a false
3/25 rate.

A dead row is identified structurally, not by timing: it carries a non-empty
`error` AND an empty `call_sequence`, i.e. the episode never issued one tool call.
A row that errored *after* doing real work is kept -- that is a genuine partial
observation and the harness records it as such. (One of the 20 above sat for 130 s
before the server closed the connection, so an elapsed-time threshold would have
missed it; the empty call sequence would not.)

  python scripts/prune_dead_rows.py results/e4_privilege_escalation.csv [--run-id X] [--dry-run]

Exit status is the number of dead rows found (0 = clean), so a driver can branch
on it and re-run the campaign.
"""

from __future__ import annotations

import argparse
import csv
import shutil
import sys
from pathlib import Path

FROZEN = {  # never touch these; they are md5-pinned in results/MANIFEST_ma9.md
    "metrics.csv", "m2_rates.csv", "adaptive.csv", "smartthings.csv",
    "recovery_matrix.csv",
}


def is_dead(row: dict) -> bool:
    """True when the episode never reached the model."""
    err = (row.get("error") or "").strip()
    seq = (row.get("call_sequence") or "").strip()
    return bool(err) and not seq


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", type=Path)
    ap.add_argument("--run-id", default=None,
                    help="restrict pruning to one campaign")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if a.csv.name in FROZEN:
        print(f"REFUSING: {a.csv.name} is a frozen artefact", file=sys.stderr)
        return 255
    if not a.csv.exists():
        print(f"missing: {a.csv}", file=sys.stderr)
        return 254

    rows = list(csv.DictReader(a.csv.open()))
    fields = csv.DictReader(a.csv.open()).fieldnames
    if not rows or "call_sequence" not in (fields or []):
        print(f"{a.csv.name}: no call_sequence column, nothing to check")
        return 0

    scope = [r for r in rows if a.run_id is None or r.get("run_id") == a.run_id]
    dead = [r for r in scope if is_dead(r)]
    if not dead:
        print(f"{a.csv.name}: clean ({len(scope)} rows checked)")
        return 0

    by_run: dict[str, int] = {}
    for r in dead:
        by_run[r.get("run_id", "?")] = by_run.get(r.get("run_id", "?"), 0) + 1
    print(f"{a.csv.name}: {len(dead)} dead row(s) of {len(scope)} checked -> {by_run}")
    print(f"  sample error: {(dead[0].get('error') or '')[:70]!r}")

    if a.dry_run:
        return len(dead)

    shutil.copy(a.csv, a.csv.with_suffix(".csv.predead"))
    keep = [r for r in rows if r not in dead]
    with a.csv.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(keep)
    print(f"  removed; {len(rows)} -> {len(keep)} (backup: {a.csv.name}.predead)")
    return len(dead)


if __name__ == "__main__":
    raise SystemExit(main())
