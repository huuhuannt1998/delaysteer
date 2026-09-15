r"""Experiment 3 (revision plan): formal trace-validation oracle.

Enumerate small finite observation traces and check that the *corrected* reachability
predicate (\S formal, quantified over the actual generation trace G_f) matches the *real*
TemporalGuard implementation for the static, heartbeat-bounded, and active-poll guards.

Model: one critical fact (the door contact) reports at cadence h (readings at 0,h,2h,...),
is SAFE (closed, "off") until a dangerous transition at t_x, and UNSAFE (open, "on") after.
A delay-only adversary delivers the freshest authentic *safe* reading it has -- the largest
multiple of h strictly below t_x -- at commit time t_c. We run the real guard on that
delivered observation (via a synthetic adapter) and compare its admit/block decision to the
predicate:

  static     admit  <=>  a safe reading t_g in G_f with t_c - t_g <= Delta
  heartbeat  admit  <=>  a safe reading t_g in G_f with t_c - t_g <= eps
  active-poll admit <=>  the fact is actually safe at commit (fresh re-read, t_c <= t_x)

Zero mismatches means the implementation realizes the corrected predicate. Additive:
results/formal_trace_validation.csv; no live deps, deterministic.

  python -m delaysteer.run_formal_trace_validation
"""
from __future__ import annotations

import csv
import math
from pathlib import Path

from .config import Config
from .defense import TemporalGuard, apply_ablation
from .home.adapter import Observation
from .home.virtual_home import ENTITIES

CONTACT = ENTITIES["contact"]
LOCK = ENTITIES["lock"]


class _Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def now(self) -> float:
        return self.t


class _FakeAdapter:
    """Returns the adversary's delivered observation, or a fresh re-read under active-poll."""

    def __init__(self, t_c: float, t_x: float, h: float) -> None:
        self.clock = _Clock(t_c)
        self.t_c, self.t_x, self.h = t_c, t_x, h
        self.revalidating = False
        self.active_poll = False

    def _freshest_safe_tg(self):
        if self.t_x <= 0:
            return None
        k = math.floor((self.t_x - 1e-9) / self.h)
        return k * self.h if k >= 0 else None

    def get_state(self, entity_id: str) -> Observation:
        if entity_id == LOCK:  # never the transitioning fact: always freshly locked
            return Observation("lock_state", "locked", entity_id=entity_id,
                               generation_time=self.t_c, arrival_time=self.t_c)
        # contact
        if self.active_poll:  # forced fresh re-read: the current truth at commit
            v = "on" if self.t_c > self.t_x else "off"
            return Observation("contact_state", v, entity_id=entity_id,
                               generation_time=self.t_c, arrival_time=self.t_c)
        t_g = self._freshest_safe_tg()
        if t_g is None:  # no authentic safe reading exists -> adversary must deliver truth
            v = "on" if self.t_c > self.t_x else "off"
            return Observation("contact_state", v, entity_id=entity_id,
                               generation_time=self.t_c, arrival_time=self.t_c)
        return Observation("contact_state", "off", entity_id=entity_id,
                           generation_time=t_g, arrival_time=self.t_c)


class _Spec:
    def __init__(self, name: str) -> None:
        self.name = name


def _guard_admits(variant: str, h: float, tol: float, t_x: float, t_c: float) -> bool:
    cfg = Config(backbone="scripted")
    apply_ablation(cfg, "full" if variant == "static" else
                   "challenge" if variant == "heartbeat" else "activepoll")
    # isolate the transitioning fact: lock/alarm thresholds lenient
    cfg.freshness_s = {"contact_state": tol if variant == "static" else 100.0,
                       "lock_state": 100.0, "alarm_state": 100.0}
    cfg.heartbeat_s = tol
    cfg.poll_rtt_s = 1e-6
    adapter = _FakeAdapter(t_c, t_x, h)
    guard = TemporalGuard(adapter, cfg, monitor=None)
    dec = guard.evaluate(_Spec("arm_alarm"), {}, None)
    return bool(getattr(dec, "allow", getattr(dec, "allowed", dec)))


def _predicate_admits(variant: str, h: float, tol: float, t_x: float, t_c: float) -> bool:
    t_g = None if t_x <= 0 else max(0.0, math.floor((t_x - 1e-9) / h) * h)
    if variant == "activepoll":
        return t_c <= t_x  # fresh re-read admits only when the fact is truly safe
    if t_g is None:
        return t_c <= t_x
    return (t_c - t_g) <= tol + 1e-9  # static (Delta) and heartbeat (eps) share this form


def main() -> int:
    HS = [0.1, 0.25, 1.0, 5.0]
    TOLS = [0.5, 1.0, 2.0, 5.0]
    TXS = [0.5, 1.0, 2.0, 3.0]
    rows: list[dict] = []
    mism = 0
    for variant in ("static", "heartbeat", "activepoll"):
        for h in HS:
            for tol in TOLS:
                for t_x in TXS:
                    for dc in (-0.3, 0.0, 0.1, 0.3, 1.0, 2.0):  # commit before/after t_x
                        t_c = round(t_x + dc, 6)
                        if t_c <= 0:
                            continue
                        g = _guard_admits(variant, h, tol, t_x, t_c)
                        p = _predicate_admits(variant, h, tol, t_x, t_c)
                        ok = (g == p)
                        mism += int(not ok)
                        rows.append({"variant": variant, "h": h, "tol": tol, "t_x": t_x,
                                     "t_c": t_c, "guard_admits": g, "predicate_admits": p,
                                     "violation": g and t_c > t_x, "match": ok})
    out = Path("results"); out.mkdir(exist_ok=True)
    with (out / "formal_trace_validation.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print(f"enumerated {len(rows)} (variant, cadence, tolerance, t_x, t_c) cells "
          f"across static / heartbeat-bounded / active-poll guards")
    print(f"predicate<->implementation MISMATCHES: {mism}")
    print("wrote results/formal_trace_validation.csv", flush=True)
    return 1 if mism else 0


if __name__ == "__main__":
    raise SystemExit(main())
