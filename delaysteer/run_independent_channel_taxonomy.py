"""EXP G -- independent-channel feasibility taxonomy (what "independence" costs to deploy).

CONSOLIDATION table. TemporalGuard's freshness contract only holds against a channel
compromise (class A2) when the guard revalidates on a channel the adversary does NOT also
control (results/trust_matrix.csv, sec:eval:compromised). That independence is a DEPLOYMENT
property, not a knob. This table enumerates the seven ways a deployment can (or cannot)
obtain an independent revalidation source, and for each records the security outcome, the
cost, and how many testbed facts it can cover.

HONESTY: only two points on this axis are actually MEASURED in the harness --
  * same-integration-same-entity  == the same_source (A2) regime  -> attack lands, guard fooled;
  * corroborating sensor          == the independent (A1) regime  -> guard recovers truth, blocks;
plus the fail-closed floor (no independent source) from the non-pollable pollability case.
The measured cells are recomputed LIVE below by reusing run_trust_matrix.run_one and
run_pollability_matrix.run (scripted, deterministic). The other four configs are a
DEPLOYABILITY taxonomy: reasoned attack_violation / guard_block expectations against the
named adversary, marked measured=0 (feasibility-classified, NOT measured).

Columns:
  config                 the independence configuration
  independence_kind      none / two-path / two-sensor / derived / cryptographic / absent
  defends_against        the adversary class the config's rate is stated against (A1 / A2 / both)
  attack_violation_rate  fraction of attack runs that committed on stale evidence (lower=safer)
  guard_block_rate       fraction of attack runs the guard blocked (the safe outcome)
  added_latency_s        extra commit-time cost of the independent revalidation (grounded where measured)
  deployment_cost        none / low / medium / high (integration + hardware + key-mgmt burden)
  n_facts_supportable    how many of the 7 security-relevant testbed facts this config can cover
  measured               1 = recomputed live from the harness; 0 = feasibility-classified
  basis / note           provenance + the reasoning for a classified row

Additive: writes NEW results/independent_channel_taxonomy.csv. Touches no frozen CSV.

  .venv/bin/python -m delaysteer.run_independent_channel_taxonomy
"""

from __future__ import annotations

import csv
from pathlib import Path

from .config import Config
from .run_pollability_matrix import run as poll_run
from .run_trust_matrix import run_one as trust_run

# 7 security-relevant testbed facts (delaysteer/home/virtual_home.py ENTITIES minus thermostat):
#   lock, contact, alarm, arrival(camera), leak, motion, light
N_FACTS_TOTAL = 7


def _rate(x: int, n: int = 1) -> float:
    return round(x / n, 3)


def measured_rows() -> list[dict]:
    """Recompute the three measured points live (scripted, deterministic, n=1)."""
    cfg = Config()
    read_rtt = 0.0027  # live-HA read P99 (results/latency_calibration.csv); independent re-read cost

    # (1) same-integration-same-entity == same_source (A2): guard re-reads the compromised
    #     channel itself -> fooled. trust_matrix condition "same_source_guard".
    a2 = trust_run("scripted", "scripted", "same_source_guard", 0, "virtual")
    # (4) corroborating sensor == independent (A1): guard re-reads a channel the adversary
    #     cannot answer -> ground truth -> block. trust_matrix condition "independent_guard".
    a1 = trust_run("scripted", "scripted", "independent_guard", 0, "virtual")
    # (7) no independent source: sleepy fact, cannot force-affirm -> fail closed. Reuse the
    #     non-pollable active-poll pollability case (attack blocked; benign also blocked).
    fc_atk = poll_run(pollable=False, guard="activepoll", attack=True, D=3.0)
    fc_ben = poll_run(pollable=False, guard="activepoll", attack=False, D=3.0)

    return [
        {
            "config": "same-integration-same-entity",
            "independence_kind": "none",
            "defends_against": "A2",
            "attack_violation_rate": _rate(int(a2["violation"])),
            "guard_block_rate": _rate(int(a2["blocked"] > 0)),
            "added_latency_s": 0.0,
            "deployment_cost": "none",
            "n_facts_supportable": 7,
            "measured": 1,
            "basis": "trust_matrix.run_one same_source_guard (CompromisedChannelAdapter, A2)",
            "note": "re-reading the SAME compromised channel gains no independence -> guard fooled, attack lands",
        },
        {
            "config": "corroborating-sensor",
            "independence_kind": "two-sensor",
            "defends_against": "A2 (independent source)",
            "attack_violation_rate": _rate(int(a1["violation"])),
            "guard_block_rate": _rate(int(a1["blocked"] > 0)),
            "added_latency_s": read_rtt,
            "deployment_cost": "low-medium",
            "n_facts_supportable": 4,
            "measured": 1,
            "basis": "trust_matrix.run_one independent_guard (StrictDelayOnceAdapter, independent re-read)",
            "note": "a different sensor the adversary does not control returns ground truth -> block; "
                    "facts with a natural corroborator (contact<->motion, arrival<->camera+motion, alarm<->lock+contact)",
        },
        {
            "config": "no-independent-source",
            "independence_kind": "absent",
            "defends_against": "both (fail-closed)",
            "attack_violation_rate": _rate(int(fc_atk["violation"])),
            "guard_block_rate": _rate(int(fc_atk["blocked"] > 0)),
            "added_latency_s": None,  # fail-closed: no commit (or bounded-wait one keepalive)
            "deployment_cost": "none",
            "n_facts_supportable": 2,
            "measured": 1,
            "basis": "run_pollability_matrix.run non-pollable+activepoll (fail-closed); benign blocked="
                     f"{int(fc_ben['false_block'])}",
            "note": "one channel, no corroborator/derivation/signing -> guard fails closed: secure but ZERO "
                    "benign availability (benign also blocked); only sleepy singletons (leak, lone contact)",
        },
    ]


def classified_rows() -> list[dict]:
    """Four feasibility-classified configs (reasoned, NOT measured -> measured=0)."""
    # grounded added-latency references
    read_rtt = 0.0027                 # live-HA read P99 (latency_calibration.csv)
    cloud_path = 0.30                  # cloud_adapter.py modeled cloud round-trip (0.30+0.10 jitter)
    return [
        {
            "config": "same-sensor-two-APIs",
            "independence_kind": "two-path",
            "defends_against": "A1 (on-path delay); NOT A2 at the sensor",
            "attack_violation_rate": 0.0,   # against A1: the 2nd API path recovers truth
            "guard_block_rate": 1.0,
            "added_latency_s": read_rtt,
            "deployment_cost": "low",
            "n_facts_supportable": 3,
            "measured": 0,
            "basis": "feasibility-classified (no two-API adapter in harness)",
            "note": "two API paths to the SAME physical sensor: recovers a delayed path (A1), but a "
                    "sensor/integration compromise (A2) forges BOTH -> no independence vs A2; mains devices "
                    "with a local + platform API (lock, contact, alarm)",
        },
        {
            "config": "direct+cloud-path",
            "independence_kind": "two-path",
            "defends_against": "A1 (path-level); NOT A2 at the device",
            "attack_violation_rate": 0.0,   # against a path-level A1
            "guard_block_rate": 1.0,
            "added_latency_s": cloud_path,
            "deployment_cost": "medium",
            "n_facts_supportable": 5,
            "measured": 0,
            "basis": "feasibility-classified (cloud_adapter.py exists as portability target; not attack-swept)",
            "note": "a local direct radio path + a cloud callback path to the same device: independent vs a "
                    "path-level delay (A1), but a device compromise (A2) forges both; devices reachable both "
                    "locally and via cloud (lock, contact, alarm, motion, light)",
        },
        {
            "config": "derived-physical-fact",
            "independence_kind": "derived",
            "defends_against": "A2 (if the proxy channel is independent)",
            "attack_violation_rate": 0.0,   # if the derived source is independent + honest
            "guard_block_rate": 1.0,
            "added_latency_s": read_rtt,
            "deployment_cost": "medium",
            "n_facts_supportable": 2,
            "measured": 0,
            "basis": "feasibility-classified (no derived-fact estimator in harness)",
            "note": "infer the fact from an independent physical invariant (lock<->bolt-motor current, "
                    "heater<->temperature slope, leak<->humidity); resists A2 on the primary channel but "
                    "needs a modeled invariant + a proxy sensor; few facts have a clean physical proxy",
        },
        {
            "config": "signed-device-heartbeat",
            "independence_kind": "cryptographic",
            "defends_against": "A2 (timestamp forgery infeasible)",
            "attack_violation_rate": 0.0,   # A2 cannot forge a fresh signed affirmation without the key
            "guard_block_rate": 1.0,
            "added_latency_s": 0.005,        # signature verify (~ms) + await next signed heartbeat
            "deployment_cost": "high",
            "n_facts_supportable": 3,
            "measured": 0,
            "basis": "feasibility-classified (no signed-attestation device in harness)",
            "note": "device cryptographically signs its heartbeat (monotonic counter): defeats the A2 fresh-"
                    "timestamp forgery on a SINGLE channel (the strongest single-channel defense), but needs "
                    "device firmware + key management; only attestation-capable mains devices today",
        },
    ]


def main() -> int:
    measured = measured_rows()
    classified = classified_rows()
    # order: measured same-source, then the four two-path/derived/crypto configs, then the two
    # measured independence points (corroborating, fail-closed) framed as the honest endpoints.
    order = [
        "same-integration-same-entity",
        "same-sensor-two-APIs",
        "direct+cloud-path",
        "corroborating-sensor",
        "derived-physical-fact",
        "signed-device-heartbeat",
        "no-independent-source",
    ]
    by_name = {r["config"]: r for r in (measured + classified)}
    rows = [by_name[name] for name in order]

    out = Path("results"); out.mkdir(exist_ok=True)
    with (out / "independent_channel_taxonomy.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)

    print("=== EXP G: independent-channel feasibility taxonomy ===\n")
    hdr = (f"{'config':<30}{'kind':<14}{'defends':<12}{'atk_vio':<9}{'blk':<6}"
           f"{'added_lat':<11}{'cost':<13}{'n_facts':<9}{'measured'}")
    print(hdr); print("-" * len(hdr))
    for r in rows:
        defends = r["defends_against"].split(" ")[0]
        lat = "fail-closed" if r["added_latency_s"] is None else f"{r['added_latency_s']}s"
        print(f"{r['config']:<30}{r['independence_kind']:<14}{defends:<12}"
              f"{r['attack_violation_rate']:<9}{r['guard_block_rate']:<6}{lat:<11}"
              f"{r['deployment_cost']:<13}{r['n_facts_supportable']:<9}{r['measured']}")

    nm = sum(r["measured"] for r in rows)
    print("\n=== Findings ===")
    print(f"  MEASURED points: {nm}/{len(rows)} configs -- same-source(A2)=attack lands, "
          "corroborating(independent)=blocked, no-source=fail-closed.")
    print("  same-integration-same-entity: attack_violation="
          f"{by_name['same-integration-same-entity']['attack_violation_rate']} "
          "(same-source revalidation is fooled -> the A2 result, measured).")
    print("  corroborating-sensor:         attack_violation="
          f"{by_name['corroborating-sensor']['attack_violation_rate']}, guard_block="
          f"{by_name['corroborating-sensor']['guard_block_rate']} "
          "(independent source recovers truth, measured).")
    print("  The other 4 configs are a DEPLOYABILITY taxonomy (measured=0): two-path configs "
          "resist on-path A1 but not endpoint A2; signed heartbeat resists A2 but needs device keys.")
    print(f"\nwrote results/independent_channel_taxonomy.csv ({len(rows)} rows).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
