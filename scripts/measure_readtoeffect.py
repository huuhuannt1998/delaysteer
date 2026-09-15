"""Measure the guard's read-to-effect window Delta_re on LIVE Home Assistant.

Delta_re is the exposure window the reachability floor folds into t_c: the interval
from the guard's FINAL revalidation read of a critical fact to the durable platform
effect of the high-impact action. A fact that flips inside (t_c, t_e] defeats a
non-atomic guard, so Delta_re is the residual term the theorems carry unless a
fused / version-bound commit drives it to zero (App. TOCTOU).

Protocol per trial (bedtime arm on live HA virtual devices):
  1. disarm  (reset to benign start)
  2. read binary_sensor.front_door_contact  -> t_c is when this read returns
  3. call alarm_control_panel.alarm_arm_night -> t_e is the platform acknowledgement
  4. Delta_re = t_e - t_c ; confirm the alarm state left 'disarmed'
Additive: writes results/atomicity_readtoeffect.csv ; never alters a frozen CSV.

  python -m scripts.measure_readtoeffect --n 40
  python -m scripts.measure_readtoeffect --probe      # 2 trials, verbose
"""
import argparse, csv, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from delaysteer.home.ha_adapter import HomeAssistantAdapter, ENTITIES

CONTACT = ENTITIES["contact"]     # binary_sensor.front_door_contact  (revalidated critical fact)
ALARM = ENTITIES["alarm"]         # alarm_control_panel.home_alarm     (high-impact action target)


def _pct(xs, p):
    if not xs:
        return 0.0
    s = sorted(xs)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


def trial(a, verbose=False):
    a.call_service("alarm_control_panel", "alarm_disarm", {"entity_id": ALARM})
    # settle the disarm so the arm below is a real transition
    for _ in range(50):
        if a.get_state(ALARM).value == "disarmed":
            break
        time.sleep(0.05)
    # (2) guard's final revalidation read of the critical fact
    contact = a.get_state(CONTACT)
    t_c = time.time()                       # commit-time: final read has returned
    # (3) issue the high-impact action; platform ack marks the durable effect
    a.call_service("alarm_control_panel", "alarm_arm_night", {"entity_id": ALARM})
    t_e = time.time()
    after = a.get_state(ALARM).value
    delta_re_ms = (t_e - t_c) * 1000.0
    if verbose:
        print(f"    contact={contact.value!r} t_c->t_e Delta_re={delta_re_ms:.1f}ms alarm_after={after!r}")
    return {"delta_re_ms": round(delta_re_ms, 2), "contact": contact.value, "alarm_after": after}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--probe", action="store_true")
    args = ap.parse_args()
    n = 2 if args.probe else args.n

    a = HomeAssistantAdapter.from_credentials()
    print(f"=== Delta_re (read-to-effect) on LIVE HA | contact={CONTACT} action=arm_night on {ALARM} | n={n} ===", flush=True)
    rows = []
    for i in range(n):
        r = trial(a, verbose=args.probe or (i < 2))
        r["trial"] = i + 1
        rows.append(r)
        if not args.probe and (i + 1) % 10 == 0:
            print(f"  {i+1}/{n} done", flush=True)
    # leave the house safe: disarm
    a.call_service("alarm_control_panel", "alarm_disarm", {"entity_id": ALARM})

    ds = [r["delta_re_ms"] for r in rows]
    armed = sum(1 for r in rows if str(r["alarm_after"]).startswith("arm"))
    print(f"\n--- Delta_re over n={n} (ms): "
          f"P50={_pct(ds,50):.1f} P95={_pct(ds,95):.1f} P99={_pct(ds,99):.1f} "
          f"max={max(ds):.1f} mean={sum(ds)/len(ds):.1f} ---")
    print(f"    arm landed (state left disarmed): {armed}/{n}")

    if not args.probe:
        out = ROOT / "results" / "atomicity_readtoeffect.csv"
        with open(out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["trial", "delta_re_ms", "contact", "alarm_after"])
            for r in rows:
                w.writerow([r["trial"], r["delta_re_ms"], r["contact"], r["alarm_after"]])
        # summary row file for the paper
        summ = ROOT / "results" / "atomicity_readtoeffect_summary.csv"
        with open(summ, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["metric", "n", "p50_ms", "p95_ms", "p99_ms", "max_ms", "mean_ms", "arm_landed"])
            w.writerow(["read_to_effect_Delta_re", n, round(_pct(ds,50),1), round(_pct(ds,95),1),
                        round(_pct(ds,99),1), round(max(ds),1), round(sum(ds)/len(ds),1), f"{armed}/{n}"])
        print(f"    wrote {out.name} + {summ.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
