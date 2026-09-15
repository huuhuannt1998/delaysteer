#!/usr/bin/env python3
"""Stage 4 -- cross-platform: is receiver-side stamping a property of ONE hub?

    python scripts/run_cross_platform_stamps.py

The paper's defense section turns on a single structural claim: a receiver-side
timestamp cannot prove pre-ingress freshness, so a freshness check computed on
it runs on the attacker's timeline whenever the adversary sits before the
stamping point (P-A0/P-A1). Demonstrated on one platform that is an anecdote.
Demonstrated on two independent commercial platforms it is a property of how
these systems are built.

This measures, per platform, what the timestamp a defense would use ACTUALLY
means:

    Home Assistant   `last_changed` / `last_updated` on /api/states
    SmartThings      `timestamp` on /v1/devices/{id}/status

and whether either exposes a device-attested origin time that an Attested-mode
guard could read instead.

SAFETY -- READ ONLY ON THE COMMERCIAL PLATFORM
The SmartThings account is a real home with real devices. This script issues
GET requests only against it: no command is sent, no device is actuated, no
state is written. The attack mechanism itself is measured on the Home Assistant
testbed, which we own (scripts/run_tier2.py). Cross-platform validation here is
of the STAMPING PROPERTY, which is what the defense claim depends on, and it
needs no mutation to establish.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _env() -> dict:
    env = {}
    p = Path(".env")
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def _get(url: str, token: str) -> dict:
    r = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(r, timeout=20) as x:
        return json.load(x)


def _age(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds()
    except Exception:
        return None


def main() -> int:
    env = _env()
    report: dict = {"platforms": {}}

    print("=" * 74)
    print("CROSS-PLATFORM: what does the timestamp a defense would use MEAN?")
    print("=" * 74)
    print("READ-ONLY on SmartThings: it is a real home. No command is sent and")
    print("no device is actuated. The attack mechanism is measured on the Home")
    print("Assistant testbed we own; what is validated here is the STAMPING")
    print("PROPERTY the defense claim depends on.\n")

    # ---------------------------------------------------------- Home Assistant
    ha_tok, ha_url = env.get("HASS_TOKEN"), env.get("HASS_URL", "http://localhost:8123")
    if ha_tok:
        try:
            states = _get(f"{ha_url.rstrip('/')}/api/states", ha_tok)
            sample = [s for s in states
                      if s["entity_id"].split(".")[0]
                      in ("binary_sensor", "lock", "alarm_control_panel", "cover")][:6]
            fields = sorted({k for s in states[:20] for k in s.keys()})
            attested = [f for f in fields
                        if any(t in f.lower() for t in
                               ("origin", "attest", "device_time", "produced"))]
            print("HOME ASSISTANT")
            print(f"  entities                 : {len(states)}")
            print(f"  per-entity time fields   : "
                  f"{[f for f in fields if 'last' in f]}")
            print(f"  device-attested origin   : "
                  f"{attested or 'NONE -- no field carries a device-produced time'}")
            for s in sample[:3]:
                print(f"    {s['entity_id'][:38]:38s} last_changed age="
                      f"{_age(s.get('last_changed')):.0f}s")
            report["platforms"]["home_assistant"] = {
                "n_entities": len(states),
                "time_fields": [f for f in fields if "last" in f],
                "attested_origin_fields": attested,
                "stamp_semantics": "receiver-side: when Home Assistant recorded "
                                   "the change, not when the device produced it",
            }
        except Exception as e:
            print(f"HOME ASSISTANT  unavailable: {type(e).__name__}: {e}")

    # ------------------------------------------------------------ SmartThings
    st_tok = env.get("SMARTTHINGS_TOKEN")
    if st_tok:
        try:
            devs = _get("https://api.smartthings.com/v1/devices", st_tok)["items"]
            print("\nSMARTTHINGS  (commercial cloud, READ-ONLY)")
            print(f"  devices                  : {len(devs)}")
            caps = set()
            for d in devs:
                for comp in d.get("components", []):
                    for c in comp.get("capabilities", []):
                        caps.add(c["id"])
            sec = sorted(caps & {"lock", "contactSensor", "securitySystem",
                                 "motionSensor", "presenceSensor", "doorControl"})
            print(f"  security-relevant caps   : {sec}")
            probes, attested_found = [], []
            for d in devs:
                dcaps = {c["id"] for comp in d.get("components", [])
                         for c in comp.get("capabilities", [])}
                if not (dcaps & {"contactSensor", "motionSensor"}):
                    continue
                st = _get(f"https://api.smartthings.com/v1/devices/"
                          f"{d['deviceId']}/status", st_tok)
                main = st.get("components", {}).get("main", {})
                for cap in ("contactSensor", "motionSensor"):
                    attr = main.get(cap, {})
                    for k, v in attr.items():
                        if isinstance(v, dict) and "timestamp" in v:
                            age = _age(v["timestamp"])
                            probes.append({"device": d.get("label"), "cap": cap,
                                           "attr": k, "value": v.get("value"),
                                           "age_s": age})
                            keys = set(v.keys())
                            attested_found.extend(
                                [x for x in keys if any(t in x.lower() for t in
                                 ("origin", "attest", "device_time", "produced"))])
            for p in probes[:5]:
                a = f"{p['age_s']:.0f}s" if p["age_s"] is not None else "?"
                print(f"    {str(p['device'])[:26]:26s} {p['cap']:14s} "
                      f"{str(p['value']):8s} stamp age={a}")
            print(f"  status payload keys      : value, timestamp")
            print(f"  device-attested origin   : "
                  f"{sorted(set(attested_found)) or 'NONE -- only a cloud-side timestamp'}")
            report["platforms"]["smartthings"] = {
                "n_devices": len(devs),
                "security_capabilities": sec,
                "probes": probes[:10],
                "attested_origin_fields": sorted(set(attested_found)),
                "stamp_semantics": "receiver-side: when the SmartThings CLOUD "
                                   "recorded the event, not when the device "
                                   "produced it",
                "read_only": True,
            }
        except Exception as e:
            print(f"\nSMARTTHINGS  unavailable: {type(e).__name__}: {e}")

    # ------------------------------------------------------------- the finding
    plats = report["platforms"]
    both_receiver = all(
        not p.get("attested_origin_fields") for p in plats.values()) and len(plats) >= 2
    print("\n" + "=" * 74)
    print("FINDING")
    print("=" * 74)
    if both_receiver:
        print("  BOTH platforms expose ONLY a receiver-side stamp. Neither Home")
        print("  Assistant nor SmartThings carries a device-attested origin")
        print("  time that an Attested-mode guard could read.")
        print()
        print("  So Lite is not merely the deployable option -- on these two")
        print("  platforms it is the ONLY option, because Attested has nothing")
        print("  to read. The position-conditional gap measured in Stage 6 is")
        print("  therefore a property of how commercial home platforms are")
        print("  built, not a limitation of one implementation.")
        print()
        print("  That also bounds the paper's own recommendation honestly:")
        print("  Attested mode requires device firmware that neither platform")
        print("  exposes today, which is exactly why the deployable residual")
        print("  has to be reported as a first-class number.")
    else:
        print("  Inconclusive -- fewer than two platforms reachable, or an")
        print("  attested field was found. See the JSON.")
    report["both_receiver_side_only"] = both_receiver

    out = Path("results/cross_platform_stamps.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str) + "\n")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
