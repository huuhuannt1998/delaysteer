#!/usr/bin/env python3
"""Re-establish the `last_reported` refresh rule on a VERSION-PINNED live Home Assistant.

Closes the cold-panel item of 2026-09-14 (finding 5): the 12 Aug measurement in
results/e1_stamp_refresh_rule.csv found `last_reported` FROZEN on an identical-value write
(mechanism `states.async_set`), which contradicts Home Assistant's documented Core semantics
since 2024.4. That container's Core version was not pinned. This script repeats the write
through the REST state-machine endpoint (POST /api/states/<entity>, which calls
hass.states.async_set with force_update from the body) on the running container, records
the Core version from /api/config, and reads ALL THREE stamps back (last_changed,
last_updated, last_reported) so the field is never ambiguous again.

Additive: writes results/e1_stamp_refresh_rule_pinned.csv. Touches only a scratch entity.
"""
from __future__ import annotations
import csv, sys, time
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from delaysteer.home.ha_adapter import HomeAssistantAdapter  # noqa: E402

ENTITY = "binary_sensor.e1_writetest_pinned"
OUT = Path("results/e1_stamp_refresh_rule_pinned.csv")
FIELDS = ["run_id", "ha_version", "write_kind", "force_update", "entity", "value_written", "prior_value",
          "last_reported_before", "last_reported_after", "last_reported_advanced",
          "last_updated_before", "last_updated_after", "last_updated_advanced",
          "last_changed_after", "mechanism", "note"]

def main() -> int:
    a = HomeAssistantAdapter.from_credentials()
    H = a._headers(); B = a.base_url
    ver = a._http.get(B + "/api/config", headers=H).json().get("version")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    def read():
        r = a._http.get(f"{B}/api/states/{ENTITY}", headers=H)
        return r.json() if r.status_code == 200 else {}
    def write(value, force=None):
        body = {"state": value, "attributes": {"friendly_name": "E1 pinned write test"}}
        if force is not None: body["force_update"] = force
        r = a._http.post(f"{B}/api/states/{ENTITY}", headers=H, json=body); r.raise_for_status()
    steps = [("create", "off", None), ("republish_same", "off", None), ("republish_same_force", "off", True),
             ("publish_different", "on", None), ("republish_same", "on", None), ("republish_same_force", "on", True),
             ("publish_different", "off", None)]
    rows = []
    for kind, val, force in steps:
        before = read(); time.sleep(1.2)  # > 1 s so any advance is unambiguous at ms resolution
        write(val, force); time.sleep(0.3); after = read()
        lr_b, lr_a = before.get("last_reported"), after.get("last_reported")
        lu_b, lu_a = before.get("last_updated"), after.get("last_updated")
        rows.append({"run_id": run_id, "ha_version": ver, "write_kind": kind, "force_update": bool(force),
                     "entity": ENTITY, "value_written": val, "prior_value": before.get("state"),
                     "last_reported_before": lr_b, "last_reported_after": lr_a,
                     "last_reported_advanced": (lr_b != lr_a) if lr_b else None,
                     "last_updated_before": lu_b, "last_updated_after": lu_a,
                     "last_updated_advanced": (lu_b != lu_a) if lu_b else None,
                     "last_changed_after": after.get("last_changed"),
                     "mechanism": "REST POST /api/states -> hass.states.async_set(force_update=%s)" % bool(force),
                     "note": ""})
        print(f"{kind:22s} force={bool(force)!s:5s} {before.get('state')!s:>4s}->{val:<3s} "
              f"last_reported {'ADVANCED' if rows[-1]['last_reported_advanced'] else 'frozen  '} "
              f"last_updated {'ADVANCED' if rows[-1]['last_updated_advanced'] else 'frozen  '}")
    a._http.delete(f"{B}/api/states/{ENTITY}", headers=H)
    OUT.parent.mkdir(exist_ok=True)
    with OUT.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS); w.writeheader(); w.writerows(rows)
    print(f"\nHA Core {ver}; wrote {OUT}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
