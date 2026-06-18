"""MA-5: run the delay-only attack + TemporalGuard ablation through the SimuHome
benchmark (ICLR 2026, arXiv 2509.24282), single-orchestrator, to demonstrate that
the steering MECHANISM and the defense GENERALIZE to an external benchmark we did
not build (W3). Results are ADDITIVE to a new file; the frozen security matrices
(metrics.csv, smartthings.csv) are asserted md5-unchanged (C3).

FRAMING (binding): SimuHome has no security devices, so its violations are
OPERATIONAL-SAFETY / correctness, NOT security violations. The security-invariant
headline stays on HA/SmartThings. SimuHome carries mechanism transfer only.

Requires a running SimuHome server: (cd ../SimuHome-ext && uv run simuhome server-start)

  python -m delaysteer.run_simuhome
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from .simuhome.client import SimuHomeClient
from .simuhome.harness import ABLATIONS, residual_window, run_window

FROZEN = {"results/metrics.csv": None, "results/smartthings.csv": None}
ABL_ORDER = ["none", "provenance", "freshness", "twophase", "full", "challenge"]


def _md5(p: Path) -> str:
    return hashlib.md5(p.read_bytes()).hexdigest() if p.exists() else "(absent)"


# Episode-to-family mapping (SH-3 inventory): which mechanism families have an
# honest analog on SimuHome's appliance/environment device set.
FAMILY_FIT = [
    {"family": "automation", "scenario": "window_safety_lockout", "fit": "clean",
     "device": "window_covering_controller (1492 episodes)",
     "invariant": "do not override the safety interlock without fresh clear evidence"},
    {"family": "bedtime/fail-open", "scenario": "env_threshold (temp/humidity bound)",
     "fit": "planned", "device": "air_conditioner/heat_pump + room env",
     "invariant": "report room safe only if env within bound (fresh)"},
    {"family": "confirmation/TOCTOU", "scenario": "workflow on stale operational state",
     "fit": "stretch", "device": "laundry_washer/dishwasher operational state",
     "invariant": "commit scheduled action only if precondition fresh at commit"},
    {"family": "access/delegation", "scenario": "(none)", "fit": "excluded",
     "device": "NONE (SimuHome has no access-control/lock/occupancy devices)",
     "invariant": "EXCLUDED: no honest analog -> a finding about SimuHome's scope, not a gap"},
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000/api")
    args = ap.parse_args()
    client = SimuHomeClient(args.base)
    out = Path("results")
    out.mkdir(exist_ok=True)

    for k in FROZEN:
        FROZEN[k] = _md5(Path(k))

    # sanity: server reachable
    if client.get("/__health__")[0] != 200:
        print(f"FAIL: SimuHome not reachable at {args.base}. "
              f"Start: (cd ../SimuHome-ext && uv run simuhome server-start)")
        return 2

    rows: list[dict] = []

    # (1) feasibility + ablation: window-covering safety-lockout (clean automation-drift)
    for ab in ABL_ORDER:
        nd = run_window(client, ab, with_delay=False)
        at = run_window(client, ab, with_delay=True)
        for r, grp in ((nd, "feasibility"), (at, "ablation")):
            rows.append({"group": grp, "home": "simuhome", "agent": "scripted",
                         "violation_kind": "operational_safety", **r})

    # (2) residual exploitable window (L1 tie): static freshness vs challenge-response
    for mode in ("freshness", "challenge"):
        rw = residual_window(client, mode)
        rows.append({"group": "residual", "home": "simuhome", "agent": "scripted",
                     "family": "automation", "scenario": "window_safety_lockout",
                     "ablation": mode, "violation_kind": "operational_safety",
                     "residual_window_s": rw["residual_window_s"],
                     "ages_that_slip": ";".join(str(a) for a in rw["ages_that_slip"])})

    fields = sorted({k for r in rows for k in r})
    with (out / "simuhome.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    (out / "simuhome.json").write_text(json.dumps(rows, indent=2, default=str))
    (out / "simuhome_family_mapping.json").write_text(json.dumps(FAMILY_FIT, indent=2))

    # ---- summary ----
    print(f"\nwrote results/simuhome.csv ({len(rows)} rows)")
    print("\nSH-3 family mapping (operational-safety; SimuHome = mechanism transfer):")
    for fm in FAMILY_FIT:
        print(f"  [{fm['fit']:<8}] {fm['family']:<22} {fm['scenario']}")
    print("\nWindow-covering safety-lockout ablation (attack):")
    for r in rows:
        if r["group"] == "ablation":
            print(f"  {r['ablation']:<11} violation={r['violation']!s:<5} blocked={r['blocked']}")
    for r in rows:
        if r["group"] == "residual":
            print(f"residual[{r['ablation']}] = {r['residual_window_s']}s")
    fr = [r for r in rows if r["group"] == "residual"]
    fresh = next((r["residual_window_s"] for r in fr if r["ablation"] == "freshness"), None)
    chal = next((r["residual_window_s"] for r in fr if r["ablation"] == "challenge"), None)
    if fresh and chal:
        print(f"  -> residual shrinks {fresh}s -> {chal}s (~{fresh/chal:.0f}x), the L1 floor (domain-independent)")

    # ---- C3: frozen artifacts unchanged ----
    print("\nC3 frozen-artifact check:")
    ok = True
    for k, before in FROZEN.items():
        after = _md5(Path(k))
        same = before == after
        ok = ok and same
        print(f"  {k}: {'UNCHANGED' if same else '!!! CHANGED !!!'} ({after})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
