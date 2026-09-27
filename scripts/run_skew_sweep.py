#!/usr/bin/env python3
"""Skew sweep: how the device-to-hub clock offset s enters the attested guard's window.

Plan fixed before running: results/skew_plan.md. No model. The E2 relay on its in-process
ACL-enforcing broker; the device signs t_m on its own clock (offset s from the hub), the relay
holds the contact flow from the door's opening, and the guard revalidates the arm_alarm contract
(preset `freshness`, contact budget 2 s) over the attested witness t_m.

  .venv/bin/python scripts/run_skew_sweep.py            # run every cell, append rows
  .venv/bin/python scripts/run_skew_sweep.py --report   # summarize results/skew_sweep.jsonl
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from delaysteer.attack.lp_relay import (  # noqa: E402
    DevicePublisher, EpochClock, HoldPolicy, HubVerifier, InProcessBroker, KeyRing, Relay,
    RelayHomeAdapter,
)
from delaysteer.config import Config  # noqa: E402
from delaysteer.defense import TemporalGuard, apply_ablation  # noqa: E402
from delaysteer.defense.temporal_guard import REQUIRED  # noqa: E402
from delaysteer.home.virtual_home import ENTITIES, VirtualHome  # noqa: E402

OUT = ROOT / "results" / "skew_sweep.jsonl"
SUMMARY = ROOT / "results" / "skew_sweep_summary.csv"
CONTACT, LOCK = ENTITIES["contact"], ENTITIES["lock"]
OFFSETS = (-3.0, -1.0, 0.0, 1.0, 3.0)
HOLDS = (1.0, 2.0, 3.0, 4.0, 5.0, 6.0)
TOL = 0.1                                   # scheduling tolerance on the soundness check


def _stack(offset: float, future_stamp: bool = False):
    broker = InProcessBroker()
    keys = KeyRing()
    home = VirtualHome(EpochClock())
    dev = DevicePublisher(home, broker.client("device"), keys, heartbeat_s=1.0, clock_offset_s=offset)
    relay = Relay(broker.client("relay"))
    hub = HubVerifier(broker.client("hub"), keys)
    adapter = RelayHomeAdapter(home, hub, settle_s=0.05)
    cfg = Config()
    apply_ablation(cfg, "freshness")
    cfg.guard_future_stamp = future_stamp          # E-E; off reproduces the original sweep
    guard = TemporalGuard(adapter, cfg)
    home.services.call("lock", "lock", {"entity_id": LOCK})     # the lock is truly locked
    for e in ENTITIES.values():
        dev.publish_observation(e)
    dev.start_heartbeat()
    broker.drain()
    return broker, home, dev, relay, hub, adapter, cfg, guard


def trial(arm: str, offset: float, hold: float | None, rng: random.Random,
          future_stamp: bool = False) -> dict:
    broker, home, dev, relay, hub, adapter, cfg, guard = _stack(offset, future_stamp)
    try:
        time.sleep(1.2 + rng.random())                         # random heartbeat phase
        t_x = None
        if arm == "attack":
            relay.set_policy(HoldPolicy("hold_entity", CONTACT, 60.0))   # nothing after this arrives
            t_x = time.time()
            home.open_door()                                   # the door is truly open from t_x
            time.sleep(max(0.0, t_x + hold - time.time()))
        n0 = len(adapter.reads)
        problems = guard._reval_problems(REQUIRED["arm_alarm"])
        reads = {r["entity"]: r for r in adapter.reads[n0:]}
        c = reads[CONTACT]
        row = {"arm": arm, "offset_s": offset, "hold_s": hold, "admitted": not problems,
               "problems": problems, "contact_value": c["value"],
               "contact_age_s": round(c["age_s"], 3), "lock_age_s": round(reads[LOCK]["age_s"], 3),
               "t_c": c["t_read"], "door_truly_open": home.states.get(CONTACT).state == "on",
               "budget_s": cfg.freshness_s["contact_state"], "future_stamp_check": future_stamp,
               "future_stamped": any("FUTURE-STAMPED" in x for x in problems)}
        if t_x is not None:
            row.update(t_x=t_x, since_open_s=round(c["t_read"] - t_x, 3),
                       phase_s=round(t_x - (c["t_m"] - offset), 3))
        return row
    finally:
        dev.stop()
        relay.stop()
        broker.close()


def run(n: int, seed: int, out: Path, future_stamp: bool = False) -> None:
    rng = random.Random(seed)
    cells = [("honest", s, None) for s in OFFSETS] + [("attack", s, h) for s in OFFSETS for h in HOLDS]
    for arm, s, h in cells:
        for i in range(n):
            row = trial(arm, s, h, rng, future_stamp)
            row.update(rep=i, seed=seed, scenario="skew_sweep")
            with out.open("a") as f:
                f.write(json.dumps(row) + "\n")
        print(f"{arm:6s} s={s:+.0f} h={h}: done", flush=True)


def report(path: Path) -> int:
    from report_au1_event_wake import wilson
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    cells = defaultdict(list)
    for r in rows:
        cells[(r["arm"], r["offset_s"], r["hold_s"])].append(r)
    out, viol = [], []
    for (arm, s, h), rs in sorted(cells.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2] or 0)):
        k = sum(r["admitted"] for r in rs)
        lo, hi = wilson(k, len(rs))
        out.append({"arm": arm, "offset_s": s, "hold_s": "" if h is None else h, "n": len(rs),
                    "admitted": k, "wilson95": f"{lo}-{hi}",
                    "min_contact_age_s": min(r["contact_age_s"] for r in rs),
                    "max_contact_age_s": max(r["contact_age_s"] for r in rs)})
        for r in rs:
            if arm == "attack" and r["admitted"] and r["since_open_s"] >= r["budget_s"] + s + TOL:
                viol.append(r)
    for o in out:
        print(f"{o['arm']:6s} s={o['offset_s']:+.0f} h={o['hold_s']!s:>4}  admitted {o['admitted']:2d}/{o['n']}"
              f"  [{o['wilson95']}]  age {o['min_contact_age_s']:+.2f}..{o['max_contact_age_s']:+.2f}")
    print("\nboundary (attack): largest admitted hold / smallest blocked hold, prediction Delta+s")
    for s in OFFSETS:
        att = [r for r in rows if r["arm"] == "attack" and r["offset_s"] == s]
        adm = [r["since_open_s"] for r in att if r["admitted"]]
        blk = [r["since_open_s"] for r in att if not r["admitted"]]
        print(f"  s={s:+.0f}: max admitted {max(adm) if adm else None}  min blocked {min(blk) if blk else None}"
              f"  Delta+s = {2.0 + s:+.1f}")
    print(f"\nsoundness violations (admitted with t_c - t_x >= Delta + s + {TOL}): {len(viol)}")
    neg = sum(r["contact_age_s"] < 0 and r["admitted"] for r in rows if r["arm"] == "honest")
    print(f"honest reads admitted with a negative (future-dated) age: {neg}")
    summary = path.with_name(path.stem + "_summary.csv")   # skew_sweep.jsonl -> skew_sweep_summary.csv
    with summary.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--future-stamp", action="store_true", help="E-E: switch the future-stamp check on")
    a = ap.parse_args()
    if a.report:
        return report(Path(a.out))
    run(a.n, a.seed, Path(a.out), a.future_stamp)
    return report(Path(a.out))


if __name__ == "__main__":
    raise SystemExit(main())
