"""EXP F -- per-platform timestamp + active-poll semantics (one consolidated table).

CONSOLIDATION table (deterministic, code-derived; no runs). For each (fact, platform)
across the four delivery paths the testbed implements behind the SAME HomeAdapter seam
(Figure 1), we record where the freshness clock's `generation_time` comes from, what an
active-poll actually does, and whether the guard's revalidation is trusted against the two
adversary classes. EVERY semantic is derived from the adapter code (cited by file:line) and
the live calibrations -- nothing is invented.

Platforms (adapters):
  virtual_home        delaysteer/home/adapter.py        VirtualHomeAdapter (deterministic)
  live_ha             delaysteer/home/ha_adapter.py     HomeAssistantAdapter (live container)
  smartthings_virtual delaysteer/home/smartthings_adapter.py  SmartThingsAdapter (real cloud)
  cloud_callback      delaysteer/home/cloud_adapter.py  CloudCallbackAdapter (simulated 2nd platform)

timestamp_meaning (where generation_time is minted, from the adapter code):
  virtual_home        adapter-read   gen = clock.now() at read           (adapter.py:92)
  live_ha             device-report  gen = last_reported | last_updated  (ha_adapter.py:85)
  smartthings_virtual platform-update gen = cloud attribute timestamp    (smartthings_adapter.py:155,210)
  cloud_callback      adapter-read   gen = clock.now() at read           (cloud_adapter.py:45)

  A minted-UPSTREAM timestamp (device-report / platform-update) records the true affirmation
  time, so an A1-delayed value arrives with an HONEST OLD age -> passive freshness catches it.
  A minted-AT-READ timestamp (adapter-read heartbeat) stamps every read "now", so a value
  delayed upstream looks fresh -> passive freshness is A1-blind; only an active poll that
  forces a fresh read can then detect/recover it.

poll_semantics (what a forced commit-time re-read does, from the code):
  virtual_home        forces device report (in-memory current state)   adapter.py:85-92
  live_ha             forces integration refresh (update_entity + GET) latency_calibration.py:88; measure_readtoeffect.py
  smartthings_virtual returns platform cache (GET device status)       smartthings_adapter.py:145
  cloud_callback      returns platform cache (re-read + modeled RTT)   cloud_adapter.py:41-55
  A SLEEPY on-change-only fact (Zigbee battery / Z-Wave Wake-Up-CC) cannot be force-affirmed
  on a real radio -> poll unsupported (returns the cached last report). The two virtual sims
  answer any read deterministically, which IDEALIZES a sleepy radio (noted per row).

Threat model (delaysteer/attack, verified in code):
  A1 on-path delay-only (delay_layer.py:66, strict_delay.py:102): delivers a stale-but-TRUE
     value stamped with its HONEST OLD generation_time (age can only grow, never shrink) and
     CANNOT answer the guard's revalidation / active-poll (that read returns ground truth).
  A2 compromised channel (compromised_channel.py:62): forges generation_time = now on EVERY
     read of its fact (age ~ 0) and never reveals truth -> same-source revalidation is fooled.

Derived trust rule (transparent, computed below -- not hand-typed):
  trusted_against_A1 = (timestamp minted upstream) OR (poll forces a fresh independent read)
                       -> the guard either SEES the honest old age or RECOVERS ground truth.
  trusted_against_A2 = FALSE for every single fact/platform read: a compromised integration
                       forges a fresh timestamp on its own channel, so revalidating on that
                       same channel gains nothing. Recovery needs an INDEPENDENT channel --
                       the feasibility taxonomy in EXP G (results/independent_channel_taxonomy.csv).

Basis per platform: virtual_home + live_ha are MEASURED (the frozen anchor / pollability /
trust_matrix runs are on virtual_home; latency_calibration + atomicity_readtoeffect +
activepoll_liveha are live_ha). smartthings_virtual + cloud_callback are DERIVED-FROM-CODE
(the smartthings.csv path is real, but its A1/A2 trust is reasoned from the timestamp/poll
code, not attack-swept; cloud_callback is a simulated portability target).

Additive: writes NEW results/timestamp_semantics.csv. Touches no frozen CSV, makes no calls.

  .venv/bin/python -m delaysteer.run_timestamp_semantics
"""

from __future__ import annotations

import csv
from pathlib import Path

# ---- facts (device class is spec-grounded; see delaysteer/run_cadence.py CLASSES) ----
# (fact, fact_class, one-line device grounding)
FACTS = [
    ("contact", "mains_pollable",    "Matter/Thread mains contact; Subscribe MinIntervalFloor sub-second"),
    ("lock",    "mains_pollable",    "Z-Wave FLiRS lock; beam-wake 250ms-1s, reachable ~1s"),
    ("alarm",   "mains_pollable",    "hub-local alarm panel; hub-receipt on command ack"),
    ("arrival", "mains_pollable",    "camera-detected arrival event; re-queryable device-report"),
    ("leak",    "sleepy_nonpollable", "Zigbee sleepy battery leak; on-change + ~1/hour keepalive"),
]

# ---- per-platform timestamp + poll semantics, cited to the adapter code ----
# platform -> dict(timestamp_meaning, timestamp_code_ref, upstream_honest,
#                  poll_pollable, poll_pollable_ref, forces_fresh, basis, evidence)
PLATFORMS = {
    "virtual_home": dict(
        timestamp_meaning="adapter-read (heartbeat: gen=clock.now() at read)",
        timestamp_code_ref="delaysteer/home/adapter.py:92",
        upstream_honest=False,
        poll_pollable="forces device report (in-memory current state)",
        poll_pollable_ref="delaysteer/home/adapter.py:85-92",
        forces_fresh=True,
        basis="measured",
        evidence="anchor.csv / pollability_matrix.csv / trust_matrix.csv run on this adapter",
    ),
    "live_ha": dict(
        timestamp_meaning="device-report (last_reported; fallback last_updated=physical-change)",
        timestamp_code_ref="delaysteer/home/ha_adapter.py:85",
        upstream_honest=True,
        poll_pollable="forces integration refresh (POST update_entity + GET)",
        poll_pollable_ref="scripts/latency_calibration.py:88; scripts/measure_readtoeffect.py",
        forces_fresh=True,
        basis="measured",
        evidence="latency_calibration.csv poll P99=0.0044s; atomicity_readtoeffect Delta_re~1ms; activepoll_liveha.csv",
    ),
    "smartthings_virtual": dict(
        timestamp_meaning="platform-update (cloud attribute timestamp)",
        timestamp_code_ref="delaysteer/home/smartthings_adapter.py:210,155",
        upstream_honest=True,
        poll_pollable="returns platform cache (GET /v1/devices/{id}/status)",
        poll_pollable_ref="delaysteer/home/smartthings_adapter.py:145",
        forces_fresh=False,
        basis="derived-from-code",
        evidence="smartthings.csv (frozen) real cloud path; timestamp from device-status payload",
    ),
    "cloud_callback": dict(
        timestamp_meaning="adapter-read (heartbeat: gen=clock.now() at read)",
        timestamp_code_ref="delaysteer/home/cloud_adapter.py:45",
        upstream_honest=False,
        poll_pollable="returns platform cache (re-read + modeled RTT 0.30+0.10s)",
        poll_pollable_ref="delaysteer/home/cloud_adapter.py:41-55",
        forces_fresh=False,
        basis="derived-from-code",
        evidence="test_portability.py: same guard/delay-layer run unchanged; simulated 2nd platform",
    ),
}


def poll_semantics(platform: str, fact_class: str) -> tuple[str, bool]:
    """Return (poll_semantics_text, forces_a_fresh_independent_read) for (platform, fact)."""
    p = PLATFORMS[platform]
    if fact_class == "sleepy_nonpollable":
        if platform in ("live_ha", "smartthings_virtual"):
            # a real sleepy radio cannot be force-affirmed -> poll returns the cached last report
            return ("unsupported (sleepy radio; returns cached last report)", False)
        # the deterministic sims answer any read -> idealizes a sleepy radio
        return (p["poll_pollable"] + " [sim idealizes a sleepy radio]", p["forces_fresh"])
    return (p["poll_pollable"], p["forces_fresh"])


def main() -> int:
    rows: list[dict] = []
    for fact, fact_class, grounding in FACTS:
        for platform, p in PLATFORMS.items():
            poll_text, forces = poll_semantics(platform, fact_class)
            # Derived trust rule (transparent):
            trusted_a1 = bool(p["upstream_honest"] or forces)
            trusted_a2 = False  # single channel: A2 forges a fresh timestamp on its own channel
            rows.append({
                "fact": fact,
                "fact_class": fact_class,
                "platform": platform,
                "timestamp_meaning": p["timestamp_meaning"],
                "timestamp_code_ref": p["timestamp_code_ref"],
                "poll_semantics": poll_text,
                "poll_code_ref": p["poll_pollable_ref"],
                "trusted_against_A1": int(trusted_a1),
                "trusted_against_A2": int(trusted_a2),
                "a1_reason": ("timestamp minted upstream (honest old age under delay)"
                              if p["upstream_honest"] else
                              ("active-poll forces a fresh independent read"
                               if forces else
                               "read-time stamp AND cached poll -> A1-blind (no detect/recover)")),
                "basis": p["basis"],
                "evidence": p["evidence"],
                "device_grounding": grounding,
            })

    out = Path("results"); out.mkdir(exist_ok=True)
    with (out / "timestamp_semantics.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)

    # console view
    print("=== EXP F: per-platform timestamp + active-poll semantics ===\n")
    hdr = f"{'fact':<9}{'platform':<20}{'timestamp_meaning':<28}{'poll_semantics':<48}{'A1':<4}{'A2':<4}{'basis'}"
    print(hdr); print("-" * len(hdr))
    for r in rows:
        tm = r["timestamp_meaning"].split(" (")[0]
        ps = r["poll_semantics"][:46]
        print(f"{r['fact']:<9}{r['platform']:<20}{tm:<28}{ps:<48}"
              f"{r['trusted_against_A1']:<4}{r['trusted_against_A2']:<4}{r['basis']}")

    a1 = {p: 0 for p in PLATFORMS}
    for r in rows:
        a1[r["platform"]] += r["trusted_against_A1"]
    print("\n=== Findings ===")
    print("  trusted_against_A1 by platform (out of {} facts):".format(len(FACTS)))
    for p, c in a1.items():
        print(f"    {p:<20} {c}/{len(FACTS)}  ({PLATFORMS[p]['timestamp_meaning'].split(' (')[0]})")
    print("  trusted_against_A2: 0/{} for EVERY platform -- a compromised channel forges a fresh".format(len(rows)))
    print("    timestamp on its own read; independence is required (see EXP G taxonomy).")
    print("  cloud_callback is the A1-blind case: adapter-read timestamp + cached poll -> the")
    print("    guard can neither see the honest old age nor force a fresh read (cloud_adapter.py:45).")
    print(f"\nwrote results/timestamp_semantics.csv ({len(rows)} rows).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
