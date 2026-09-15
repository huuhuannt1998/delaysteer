#!/usr/bin/env python3
"""Does a delay-only adversary INSIDE the hub launder on a multi-transition trace?

Why this exists
---------------
E1 measured position A1 (a compromised integration inside Home Assistant) on a SINGLE
world transition and found it blocked at every defended tier: static 0/20, heartbeat
0/18. The E1 report first explained that as "A1 cannot launder under delay-only", deriving
it from "A1 holds only two values, so any other write is synthesis".

That derivation is too strong and was withdrawn. It holds for one transition. It fails on a
trace that changes more than once, because a LAGGED REPLAY of an alternating signal contains
genuine value changes -- and `results/e1_stamp_refresh_rule.csv` establishes that Home
Assistant refreshes `last_reported` on exactly those. If the world goes off -> on -> off, an
adversary running one transition behind publishes `off` (a no-op), then publishes `on` as the
world returns to `off`: a real value change, stamped fresh at receipt, with nothing forged.
Every value it emits is one the world genuinely produced, so it never leaves the delay-only
class.

This script measures whether that happens, and under what condition.

The predicted condition (stated in the E1 report as a PREDICTION, not a result)
------------------------------------------------------------------------------
For a lag-``D`` adversary on a signal whose previous state persisted for ``dwell`` seconds,
the agent's belief flips at ``t = D`` and deception begins at ``t = dwell``. Observable age at
the onset of deception is therefore ``dwell - D``, so a laundered value passes a freshness
budget ``eps`` iff

    D >= dwell - eps

i.e. A1 launders when the lag is at least as long as the dwell time. This run either
supports that or refutes it; both are reportable.

What is measured
----------------
For each (dwell, delay) cell the world is driven through an alternating trace while the
compromised channel is sampled. A sample is DECEIVED when the compromised value disagrees
with ground truth. The headline number is the MINIMUM observable age across deceived samples:
if that is below the deployed freshness budget, a static gate would have admitted a wrong
value, which is laundering.

  python scripts/a1_multitransition.py --dwell 3 --delays 1,2,3,4 --cycles 3
"""

from __future__ import annotations

import argparse
import csv
import json
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "a1_multitransition.csv"
HA = "http://localhost:8123"

SOURCE = "input_boolean.front_door_open"     # ground truth, uncompromised
TARGET = "binary_sensor.front_door_compromised"
BUDGET_S = 2.0                               # deployed contact_state freshness budget

FIELDS = [
    "run_id", "position", "policy", "dwell_s", "delay_s", "cycle", "sample",
    "world_truth", "agent_belief", "belief_last_reported", "observable_age_s",
    "deceived", "would_pass_static_gate", "synthesized_value", "notes",
]


def _tok() -> str:
    for line in (ROOT / ".env").read_text().splitlines():
        if line.startswith("HASS_TOKEN="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("HASS_TOKEN missing")


H = None


def _req(path, data=None):
    r = urllib.request.Request(HA + path,
                               data=json.dumps(data).encode() if data is not None else None,
                               method="POST" if data is not None else "GET")
    r.add_header("Authorization", f"Bearer {H}")
    if data is not None:
        r.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(r, timeout=20) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else {}


def state(entity):
    d = _req(f"/api/states/{entity}")
    return d.get("state"), (d.get("last_reported") or d.get("last_updated"))


def svc(domain_service, payload):
    _req(f"/api/services/{domain_service}", payload)


def age(stamp) -> float:
    try:
        return (datetime.now(timezone.utc)
                - datetime.fromisoformat(stamp.replace("Z", "+00:00"))).total_seconds()
    except Exception:
        return float("nan")


def run_cell(run_id, dwell, delay, cycles, sample_hz=4.0):
    """Drive an alternating trace under a lag-`delay` adversary and sample the belief."""
    svc("delay_attacker/disarm", {})
    svc("input_boolean/turn_off", {"entity_id": SOURCE})
    time.sleep(1.5)
    svc("delay_attacker/arm", {"source": SOURCE, "target": TARGET, "safe": "off",
                               "delay": delay, "policy": "lag"})
    time.sleep(0.5)

    rows, sample = [], 0
    period = 1.0 / sample_hz
    for cycle in range(cycles):
        for want in ("on", "off"):
            svc(f"input_boolean/turn_{want}", {"entity_id": SOURCE})
            t_end = time.time() + dwell
            while time.time() < t_end:
                truth, _ = state(SOURCE)
                belief, stamp = state(TARGET)
                obs = age(stamp)
                # The virtual contact sensor mirrors the input_boolean, so truth is the
                # boolean's own value: "on" = door open.
                deceived = belief != truth
                rows.append({
                    "run_id": run_id, "position": "A1", "policy": "lag",
                    "dwell_s": dwell, "delay_s": delay, "cycle": cycle, "sample": sample,
                    "world_truth": truth, "agent_belief": belief,
                    "belief_last_reported": stamp,
                    "observable_age_s": round(obs, 3),
                    "deceived": deceived,
                    # A static freshness gate admits anything inside the budget. If a DECEIVED
                    # sample is inside it, the gate admits a value the world has contradicted.
                    "would_pass_static_gate": deceived and obs < BUDGET_S,
                    # The adversary only ever replays values the world produced; there is no
                    # code path in the component that constructs one.
                    "synthesized_value": False,
                    "notes": "",
                })
                sample += 1
                time.sleep(period)
    svc("delay_attacker/disarm", {})
    svc("input_boolean/turn_off", {"entity_id": SOURCE})
    return rows


def append(rows):
    OUT.parent.mkdir(exist_ok=True)
    new = not OUT.exists()
    with OUT.open("a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerows(rows)


def main() -> int:
    global H
    ap = argparse.ArgumentParser()
    ap.add_argument("--dwell", type=float, default=3.0, help="seconds the world holds a value")
    ap.add_argument("--delays", default="1,2,3,4", help="comma list of adversary lags")
    ap.add_argument("--cycles", type=int, default=3, help="on/off cycles per cell")
    a = ap.parse_args()
    H = _tok()

    run_id = time.strftime("%Y%m%dT%H%M%S")
    print(f"run_id={run_id}  dwell={a.dwell}s  budget={BUDGET_S}s  -> {OUT.relative_to(ROOT)}",
          flush=True)
    print(f"  prediction: laundering when delay >= dwell - budget = "
          f"{a.dwell - BUDGET_S:.1f}s\n", flush=True)

    print(f"  {'delay':<8}{'samples':<9}{'deceived':<11}{'min_obs_age':<13}"
          f"{'PASSES static gate':<20}verdict")
    print("  " + "-" * 72)
    for d in [float(x) for x in a.delays.split(",")]:
        rows = run_cell(run_id, a.dwell, d, a.cycles)
        append(rows)
        dec = [r for r in rows if r["deceived"]]
        passed = [r for r in dec if r["would_pass_static_gate"]]
        mn = min((r["observable_age_s"] for r in dec), default=float("nan"))
        verdict = ("LAUNDERS" if passed else
                   ("deceives but the gate catches it" if dec else "no deception"))
        print(f"  {d:<8.1f}{len(rows):<9}{len(dec):<11}{mn:<13.3f}"
              f"{len(passed):<20}{verdict}", flush=True)

    print(f"\n  artefact: {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
