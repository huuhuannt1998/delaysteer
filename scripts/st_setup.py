#!/usr/bin/env python3
"""Provision the DelaySteer virtual switches on the real SmartThings cloud (MA-0).

Idempotent: creates only the labels that don't already exist, seeds each with an
initial 'off' event so its status carries a timestamp, and prints the
entity->deviceId map (deviceIds are not secrets). Token from $SMARTTHINGS_TOKEN
or a gitignored .env; never hardcoded/committed.

    SMARTTHINGS_TOKEN=*** .venv/bin/python scripts/st_setup.py            # uses first location
    SMARTTHINGS_TOKEN=*** .venv/bin/python scripts/st_setup.py --location <id>
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from delaysteer.home.smartthings_adapter import ENTITY_LABELS, _LiveClient, _token_from_env


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--location", default=None, help="location id (default: first)")
    args = ap.parse_args()

    token = _token_from_env()
    if not token:
        print("SMARTTHINGS_TOKEN not set (env or .env). Mint a fresh 24h PAT first.")
        return 2
    cli = _LiveClient(token)

    loc = args.location
    if not loc:
        code, locs = cli.get("/v1/locations")
        if code != 200 or not locs.get("items"):
            print(f"GET /v1/locations -> HTTP {code}; cannot pick a location."); return 1
        loc = locs["items"][0]["locationId"]
    print(f"location: {loc}")

    code, devs = cli.get("/v1/devices")
    if code != 200:
        print(f"GET /v1/devices -> HTTP {code}"); return 1
    by_label = {d.get("label"): d.get("deviceId") for d in devs.get("items", [])}

    mapping = {}
    for ent, label in ENTITY_LABELS.items():
        did = by_label.get(label)
        if did:
            print(f"  exists  {label:<20} {did}")
        else:
            code, resp = cli.post("/v1/virtualdevices/prototypes",
                {"name": label, "owner": {"ownerType": "LOCATION", "ownerId": loc},
                 "prototype": "VIRTUAL_SWITCH"})
            if code != 200:
                print(f"  FAILED  {label}: HTTP {code} {resp}"); return 1
            did = resp.get("deviceId")
            cli.post(f"/v1/virtualdevices/{did}/events",
                {"deviceEvents": [{"component": "main", "capability": "switch",
                                   "attribute": "switch", "value": "off"}]})
            print(f"  created {label:<20} {did}")
            time.sleep(0.3)
        mapping[ent] = did

    print("\nentity -> deviceId map (the adapter discovers these by label at runtime):")
    for ent, did in mapping.items():
        print(f"  {ent:<45} {did}")
    print(f"\n{len(mapping)}/{len(ENTITY_LABELS)} devices ready.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
