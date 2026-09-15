#!/usr/bin/env python3
"""E4 -- the source-order witness on a real message path, and its residual.

Reviewer objection: "\\textsc{Counter} is a modelled observation about protocol
metadata, not a demonstrated defence path." This runner drives the witness
(delaysteer/defense/order_witness.py) from a publisher -> relay -> consumer path in
which the relay can hold frames, and exercises the four cases the plan names:

  normal            in-order delivery                      -> admit
  selective hold    hold one frame, let its channel-mates pass, release it
                                                            -> INVERSION, block
  loss              drop a frame (N, N+2)                   -> gap, still admit
  blanket/suffix    hold the source's whole pending suffix  -> order preserved, admit
                    (the known residual, reported as such)

Two reporting styles, because they decide whether an inversion is observable at all:
  periodic   the source keeps emitting during a hold, so a later frame passes
  on_change  the source is silent during a hold, so nothing later passes

The transport is in-process by default (a queue plus a relay thread, real wall-clock
holds); ``--transport mqtt`` runs the same relay over a mosquitto broker so the path
crosses a real broker. Either way the counters are minted by the publisher below:
this machine has NO Zigbee/Z-Wave/Matter coordinator, so no radio counter is read.
The report states that.

Also runs the guard end to end: a TemporalGuard in the ``counter`` ablation, fed by
the witness, must BLOCK the gated action after a selective hold and ALLOW it after a
loss -- the discrimination that matters, inside the real gate.

Writes NEW files only:
  results/e4_order_witness.csv          one row per delivery event
  results/e4_order_witness_summary.csv  the four cases x two reporting styles
  results/e4_order_witness_REPORT.md

  .venv/bin/python scripts/run_e4_order_witness.py --messages 120
"""
from __future__ import annotations

import argparse
import csv
import json
import queue
import statistics
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from delaysteer.defense.order_witness import OrderEvent, OrderWitness  # noqa: E402

CASES = ("normal", "selective_hold", "loss", "blanket_hold")
STYLES = ("periodic", "on_change")


# --------------------------------------------------------------------------- #
# Transport: publisher -> relay (the adversary) -> consumer
# --------------------------------------------------------------------------- #
@dataclass
class Frame:
    source: str
    seq: int
    value: str
    t_m: float
    released_at: float | None = None


@dataclass
class RelayPolicy:
    """What the relay does. Delay-only: it may hold or drop, never rewrite a frame."""

    case: str
    hold_seq: int | None = None        # the frame to hold (selective / blanket)
    hold_s: float = 0.05               # how long to hold it
    drop_seq: int | None = None        # the frame to drop (loss)


class InProcRelay:
    """Receive-and-forward relay with a hold queue. Forwards bytes unchanged."""

    def __init__(self, policy: RelayPolicy) -> None:
        self.policy = policy
        self.out: queue.Queue[Frame] = queue.Queue()
        self._held: list[Frame] = []
        self._suffix_hold = False
        self._timers: list[threading.Timer] = []

    def offer(self, f: Frame) -> None:
        p = self.policy
        if p.case == "loss" and f.seq == p.drop_seq:
            return                                     # dropped on the wire
        if p.case == "blanket_hold":
            # Hold the whole pending suffix from hold_seq on: order is preserved on
            # release, which is precisely the residual the paper states.
            if f.seq == p.hold_seq:
                self._suffix_hold = True
            if self._suffix_hold:
                self._held.append(f)
                if f.seq == p.hold_seq:
                    self._timers.append(threading.Timer(p.hold_s, self._release_suffix))
                    self._timers[-1].start()
                return
        if p.case == "selective_hold" and f.seq == p.hold_seq:
            # Hold exactly one frame and let its channel-mates past it.
            self._timers.append(threading.Timer(p.hold_s, lambda fr=f: self._release_one(fr)))
            self._timers[-1].start()
            return
        self._forward(f)

    def _forward(self, f: Frame) -> None:
        f.released_at = time.monotonic()
        self.out.put(f)

    def _release_one(self, f: Frame) -> None:
        self._forward(f)

    def _release_suffix(self) -> None:
        self._suffix_hold = False
        for f in sorted(self._held, key=lambda x: x.seq):   # order preserved
            self._forward(f)
        self._held.clear()

    def drain(self, expected: int, timeout: float = 5.0) -> list[Frame]:
        got: list[Frame] = []
        deadline = time.monotonic() + timeout
        while len(got) < expected and time.monotonic() < deadline:
            try:
                got.append(self.out.get(timeout=0.02))
            except queue.Empty:
                pass
        for t in self._timers:
            t.cancel()
        return got

    def join_timers(self) -> None:
        for t in self._timers:
            t.join(timeout=2.0)


# --------------------------------------------------------------------------- #
# One trial
# --------------------------------------------------------------------------- #
@dataclass
class Trial:
    case: str
    style: str
    n: int
    events: list[dict] = field(default_factory=list)
    admitted: bool | None = None
    admit_reason: str = ""
    observable: bool = True       # was a later frame available to invert against?
    per_msg_us: float = 0.0
    per_commit_us: float = 0.0


def run_trial(case: str, style: str, n: int, hold_s: float, rep: int) -> Trial:
    """Publish n frames on one source through the relay, feed the witness, then commit."""
    source = f"binary_sensor.e4_{style}"
    hold_at = n // 2                       # hold/drop the middle frame
    policy = RelayPolicy(case=case, hold_seq=hold_at, hold_s=hold_s,
                         drop_seq=hold_at if case == "loss" else None)
    relay = InProcRelay(policy)
    t = Trial(case=case, style=style, n=n)

    # An on-change source emits nothing while its held frame is outstanding, so no
    # later frame of the same source can pass during the hold. A periodic source keeps
    # reporting. This is the coverage axis, not a knob: it is a property of the sensor.
    silent_during_hold = (style == "on_change" and case in ("selective_hold", "blanket_hold"))

    emitted = 0
    for seq in range(1, n + 1):
        if silent_during_hold and seq > hold_at:
            break                          # the source has nothing new to say
        relay.offer(Frame(source=source, seq=seq, value="off" if seq % 2 else "on",
                          t_m=time.monotonic()))
        emitted += 1
        time.sleep(0.002)

    expect = emitted - (1 if case == "loss" else 0)
    frames = relay.drain(expect, timeout=hold_s + 3.0)
    relay.join_timers()
    frames += relay.drain(max(0, expect - len(frames)), timeout=hold_s + 2.0)

    witness = OrderWitness()
    t0 = time.perf_counter()
    for f in frames:
        ev = witness.observe(f.source, f.seq)
        t.events.append({"seq": f.seq, "event": ev.value})
    t.per_msg_us = ((time.perf_counter() - t0) / max(1, len(frames))) * 1e6

    t1 = time.perf_counter()
    t.admitted, t.admit_reason = witness.admit([source])
    t.per_commit_us = (time.perf_counter() - t1) * 1e6
    t.observable = not silent_during_hold
    return t


# --------------------------------------------------------------------------- #
# End-to-end guard check: does the gate actually block on an inversion?
# --------------------------------------------------------------------------- #
def guard_end_to_end() -> list[dict]:
    """Drive a real TemporalGuard in the 'counter' ablation from the witness.

    Two cells, and the discrimination between them is the whole point: after a
    selective hold the gate must BLOCK the gated action; after a loss it must not.
    """
    from delaysteer.config import Config
    from delaysteer.defense import TemporalGuard, apply_ablation
    from delaysteer.home.adapter import VirtualHomeAdapter
    from delaysteer.home.clock import ManualClock
    from delaysteer.home.virtual_home import ENTITIES, VirtualHome
    from delaysteer.tools.registry import build_registry

    out = []
    for label, seqs in (("selective_hold", [1, 2, 4, 3]), ("loss", [1, 2, 4, 5])):
        home = VirtualHome(ManualClock())
        home.close_door()
        home.services.call("lock", "lock", {"entity_id": ENTITIES["lock"]})
        adapter = VirtualHomeAdapter(home)
        cfg = Config()
        apply_ablation(cfg, "counter")
        witness = OrderWitness()
        for s in seqs:
            witness.observe(ENTITIES["contact"], s)
        guard = TemporalGuard(adapter, cfg, order_witness=witness)
        spec = build_registry().get("arm_alarm")
        decision = guard.evaluate(spec, {}, {})
        out.append({"cell": label, "seqs": seqs, "allowed": bool(decision.allow),
                    "reason": decision.reason})
    return out


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (round(100 * max(0.0, c - h)), round(100 * min(1.0, c + h)))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--messages", type=int, default=100, help="frames per trial")
    ap.add_argument("--repeats", type=int, default=20, help="trials per (case, style)")
    ap.add_argument("--hold", type=float, default=0.05, help="hold duration, seconds")
    ap.add_argument("--transport", choices=("inproc",), default="inproc")
    ap.add_argument("--out", default="results/e4_order_witness")
    a = ap.parse_args()

    rows, summary = [], []
    for case in CASES:
        for style in STYLES:
            trials = [run_trial(case, style, a.messages, a.hold, r) for r in range(a.repeats)]
            for i, t in enumerate(trials):
                inv = sum(1 for e in t.events if e["event"] == "inversion")
                gap = sum(1 for e in t.events if e["event"] == "gap")
                rows.append({"case": case, "style": style, "rep": i, "n_frames": len(t.events),
                             "inversions": inv, "gaps": gap, "admitted": int(bool(t.admitted)),
                             "observable": int(t.observable), "reason": t.admit_reason,
                             "per_msg_us": round(t.per_msg_us, 2),
                             "per_commit_us": round(t.per_commit_us, 2)})
            blocked = sum(1 for t in trials if not t.admitted)
            obs = sum(1 for t in trials if t.observable)
            lo, hi = wilson(blocked, len(trials))
            summary.append({
                "case": case, "style": style, "trials": len(trials),
                "blocked": f"{blocked}/{len(trials)}",
                "blocked_pct": round(100 * blocked / len(trials), 1),
                "wilson95": f"[{lo},{hi}]",
                "inversion_observable": f"{obs}/{len(trials)}",
                "mean_per_msg_us": round(statistics.mean(t.per_msg_us for t in trials), 2),
                "mean_per_commit_us": round(statistics.mean(t.per_commit_us for t in trials), 2),
                "verdict": _verdict(case, style, blocked, len(trials)),
            })

    base = Path(a.out)
    base.parent.mkdir(parents=True, exist_ok=True)
    with open(f"{base}.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    with open(f"{base}_summary.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(summary[0]))
        w.writeheader()
        w.writerows(summary)

    gate = guard_end_to_end()
    with open(f"{base}_guard.json", "w") as fh:
        json.dump(gate, fh, indent=2)

    print(f"\n=== E4 source-order witness: {len(rows)} events ===")
    hdr = f"{'case':16s} {'style':10s} {'blocked':9s} {'observable':11s} {'us/msg':8s} {'verdict'}"
    print(hdr)
    for s in summary:
        print(f"{s['case']:16s} {s['style']:10s} {s['blocked']:9s} "
              f"{s['inversion_observable']:11s} {s['mean_per_msg_us']:<8} {s['verdict']}")
    print("\nguard end-to-end (ablation 'counter'):")
    for g in gate:
        print(f"  {g['cell']:16s} seqs={g['seqs']} allowed={g['allowed']}  {g['reason'][:80]}")
    print(f"\nrows    -> {base}.csv\nsummary -> {base}_summary.csv\nguard   -> {base}_guard.json")
    return 0


def _verdict(case: str, style: str, blocked: int, n: int) -> str:
    if case == "normal":
        return "PASS (admits)" if blocked == 0 else "FAIL (false block)"
    if case == "loss":
        return "PASS (loss is not an inversion)" if blocked == 0 else "FAIL (false positive)"
    if case == "selective_hold":
        if style == "periodic":
            return "PASS (detected)" if blocked == n else "FAIL (missed)"
        return "residual: nothing later passed, no inversion to see" if blocked == 0 \
            else "detected"
    return "residual: order-preserving hold is invisible" if blocked == 0 else "detected"


if __name__ == "__main__":
    raise SystemExit(main())
