#!/usr/bin/env python3
"""E1 task 2 -- does Home Assistant's ``last_reported`` track RECEIPT or a device-supplied
MEASUREMENT time?

This is the falsifier for mission mis_01KZVRMET2H041053M72WN2HB8 and the cheapest decisive
measurement in it: pure HTTP, no planner, no shim.

Why it can be answered without building the A0 shim
---------------------------------------------------
HA bridges the SmartThings virtual devices with the generic ``rest`` platform on a
``scan_interval: 30``. The natural poll gap IS a hold: whatever the device reported at
t_generated only reaches HA at the next poll. So the question "does HA propagate the
device timestamp or stamp on receipt?" is already observable in the standing deployment.

Vocabulary follows the advisor design report (Sec. 8.1), whose canonical observation is
``o = (source, value, t_generated, t_received, t_model, provenance)``:

  t_generated  the device/cloud measurement time -- for SmartThings, the per-attribute
               ``timestamp`` field in /v1/devices/<id>/status. Read DIRECTLY from the
               SmartThings cloud, never through HA, so it is an independent witness.
  t_received   HA's ``last_reported``.

Two probes
----------
1. baseline_skew  -- for each integration-backed entity, compare t_generated against
   t_received as they stand. No causation, no mutation of any device. If HA propagated a
   measurement time these would track; if HA stamps on receipt they diverge by however
   long ago the device last actually reported.

2. causal_flip    -- flip a device, then watch both witnesses. Records t_cause on the
   HOST clock (independent of HA), then the first t_generated and t_received that reflect
   the change. This distinguishes "HA is stamping when the poll lands" from "HA happens
   to look stale".

Clock discipline
----------------
HA runs in the ``delaysteer-ha`` container, so its clock may be skewed from the host. The
offset is measured from HA's HTTP ``Date`` response header against the host clock and
recorded per row. Note the baseline_skew verdict does not depend on it: a skew of a few
seconds cannot explain a gap of days.

SAFETY (advisor report Sec. 13, risk 4): every SmartThings device touched here is a
CLOUD VIRTUAL DEVICE. No physical lock, alarm, or access-control hardware is actuated.

Additive output only: results/e1_timestamp_semantics.csv. Touches no frozen CSV.
"""

from __future__ import annotations

import csv
import hashlib
import json
import time
import urllib.request
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "e1_timestamp_semantics.csv"
HA = "http://localhost:8123"
ST = "https://api.smartthings.com"

# HA rest-platform entities and the SmartThings device each one polls
# (config/configuration.yaml lines 340-371). value_template extracts only `.value`,
# so the payload's per-attribute timestamp is discarded before HA ever sees it.
INTEGRATION_BACKED = {
    "binary_sensor.st_contact": "c6a2f562-4461-4fbd-867a-48ca0a3bd516",
    "binary_sensor.st_leak":    "87030d7f-925f-4dbc-99d9-ff75b24d10f3",
    "binary_sensor.st_motion":  "cb7f405c-65e8-43be-bf1c-7add2f7fb3e3",
    "binary_sensor.st_arrival": "61af57d1-5f5b-41c1-94d2-d818131557e1",
}

# Hub-resident facts: an input_boolean the harness drives, mirrored by a template
# binary_sensor. There is NO device timestamp anywhere on this path -- the fact is
# minted inside the hub -- so "measurement time" does not exist to be propagated.
TEMPLATE_VIRTUAL = {
    "binary_sensor.front_door_contact": "input_boolean.front_door_open",
    "binary_sensor.back_door_contact":  "input_boolean.back_door_open",
}

FIELDS = [
    "probe", "entity_class", "entity_id", "device_id",
    "t_cause", "t_generated", "t_received", "ha_clock_offset_s",
    "gap_generated_to_received_s", "hold_s", "value",
    "payload_sha256", "verdict", "notes",
]


def _env(key: str) -> str:
    for line in (ROOT / ".env").read_text().splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise KeyError(key)


HASS_TOKEN = _env("HASS_TOKEN")
ST_TOKEN = _env("SMARTTHINGS_TOKEN")


def _get(url: str, token: str, want_headers: bool = False):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        body = r.read()
        return (body, dict(r.headers)) if want_headers else body


def ha_clock_offset() -> float:
    """HA container clock minus host clock, from HA's own HTTP Date header.

    Independent of any entity state. Date has 1 s resolution, which is far below the
    scale of the effect under test but is recorded so the reader can judge.
    """
    try:
        t0 = time.time()
        _, hdrs = _get(f"{HA}/api/", HASS_TOKEN, want_headers=True)
        t1 = time.time()
        server = parsedate_to_datetime(hdrs["Date"]).timestamp()
        return round(server - (t0 + t1) / 2, 3)
    except Exception:
        return float("nan")


def iso(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def st_status(device_id: str) -> tuple[str, float, str]:
    """(value, t_generated, payload_sha256) straight from SmartThings -- never via HA."""
    raw = _get(f"{ST}/v1/devices/{device_id}/status", ST_TOKEN)
    d = json.loads(raw)
    sw = d["components"]["main"]["switch"]["switch"]
    return sw["value"], iso(sw["timestamp"]), hashlib.sha256(raw).hexdigest()


def st_command(device_id: str, on: bool) -> None:
    body = json.dumps({"commands": [{"component": "main", "capability": "switch",
                                     "command": "on" if on else "off"}]}).encode()
    req = urllib.request.Request(f"{ST}/v1/devices/{device_id}/commands", data=body,
                                 headers={"Authorization": f"Bearer {ST_TOKEN}",
                                          "Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=20).read()


def ha_state(entity_id: str) -> tuple[str, float]:
    d = json.loads(_get(f"{HA}/api/states/{entity_id}", HASS_TOKEN))
    return d["state"], iso(d["last_reported"])


def ha_service(domain: str, service: str, entity_id: str) -> None:
    body = json.dumps({"entity_id": entity_id}).encode()
    req = urllib.request.Request(f"{HA}/api/services/{domain}/{service}", data=body,
                                 headers={"Authorization": f"Bearer {HASS_TOKEN}",
                                          "Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=20).read()


def verdict_of(gap_s: float, offset_s: float) -> str:
    """Receipt-stamped vs measurement-propagated.

    A measurement-propagating hub would put t_received within clock noise of
    t_generated. Threshold is deliberately generous -- 5 s, far above the ~1 s Date
    resolution and any plausible container skew -- so the verdict cannot be an artefact
    of clock handling.
    """
    tol = 5.0 + (0.0 if offset_s != offset_s else abs(offset_s))  # NaN-safe
    if abs(gap_s) <= tol:
        return "measurement_propagated"
    return "receipt_stamped"


def main() -> int:
    rows: list[dict] = []
    off = ha_clock_offset()
    print(f"=== E1 timestamp-semantics probe ===")
    print(f"  HA container clock offset vs host: {off:+.3f}s\n")

    # ---- probe 1: baseline skew, integration-backed -------------------------------
    print("  [1] baseline_skew -- integration-backed (SmartThings via HA rest platform)")
    for ent, dev in INTEGRATION_BACKED.items():
        try:
            val, t_gen, sha = st_status(dev)
            ha_val, t_rec = ha_state(ent)
            gap = t_rec - t_gen
            v = verdict_of(gap, off)
            rows.append({
                "probe": "baseline_skew", "entity_class": "integration_backed",
                "entity_id": ent, "device_id": dev, "t_cause": "",
                "t_generated": round(t_gen, 3), "t_received": round(t_rec, 3),
                "ha_clock_offset_s": off, "gap_generated_to_received_s": round(gap, 3),
                "hold_s": "", "value": f"st={val};ha={ha_val}",
                "payload_sha256": sha[:16], "verdict": v,
                "notes": "no causation; standing deployment",
            })
            print(f"    {ent:<34} gap={gap/86400:8.2f} days  -> {v}")
        except Exception as e:
            print(f"    {ent:<34} ERROR {type(e).__name__}: {str(e)[:60]}")

    # ---- probe 2: template/virtual, no device timestamp exists ---------------------
    print("\n  [2] baseline_skew -- template/virtual (hub-resident fact)")
    for ent, helper in TEMPLATE_VIRTUAL.items():
        try:
            ha_val, t_rec = ha_state(ent)
            rows.append({
                "probe": "baseline_skew", "entity_class": "template_virtual",
                "entity_id": ent, "device_id": helper, "t_cause": "",
                "t_generated": "", "t_received": round(t_rec, 3),
                "ha_clock_offset_s": off, "gap_generated_to_received_s": "",
                "hold_s": "", "value": ha_val, "payload_sha256": "",
                "verdict": "receipt_stamped_by_construction",
                "notes": "hub-resident fact: no device measurement timestamp exists to propagate",
            })
            print(f"    {ent:<34} no t_generated exists -> receipt_stamped_by_construction")
        except Exception as e:
            print(f"    {ent:<34} ERROR {type(e).__name__}: {str(e)[:60]}")

    # ---- probe 3: causal_flip -- the campaign's measurement primitive ---------------
    # Cause a change, then watch both witnesses. This separates "HA re-stamps idle polls"
    # from "HA stamps the arrival of a CHANGE", and yields the two ages the campaign needs:
    #   true age at read       = t_read - t_generated   (independent witness)
    #   observable age at read = t_read - t_received    (what a freshness gate sees)
    print("\n  [3] causal_flip -- integration-backed (flip a CLOUD VIRTUAL device, watch both)")
    ent, dev = "binary_sensor.st_contact", INTEGRATION_BACKED["binary_sensor.st_contact"]
    try:
        val0, _, _ = st_status(dev)
        target = (val0 != "on")
        t_cause = time.time()
        st_command(dev, target)
        t_gen = None
        for _ in range(20):                      # wait for the CLOUD to register it
            time.sleep(1.5)
            v, tg, sha = st_status(dev)
            if v == ("on" if target else "off"):
                t_gen = tg; break
        # CORRECTED WAIT CONDITION. An earlier version waited for HA's VALUE to match,
        # which latched onto a pre-existing frozen state and produced a physically
        # impossible NEGATIVE gap (HA stamping before the cloud). The state HA carries
        # before the poll lands is stale by construction, so the only sound condition is
        # that last_reported ADVANCE PAST t_cause -- i.e. HA has written since we acted.
        t_rec, t_read = None, None
        deadline = time.time() + 90              # scan_interval is 30s; allow 3 cycles
        want = "on" if target else "off"
        while time.time() < deadline:
            time.sleep(2)
            hv, tr = ha_state(ent)
            if tr > t_cause and hv == want:
                t_rec, t_read = tr, time.time(); break
        if t_gen and t_rec:
            true_age = t_read - t_gen
            obs_age = t_read - t_rec
            rows.append({
                "probe": "causal_flip", "entity_class": "integration_backed",
                "entity_id": ent, "device_id": dev, "t_cause": round(t_cause, 3),
                "t_generated": round(t_gen, 3), "t_received": round(t_rec, 3),
                "ha_clock_offset_s": off,
                "gap_generated_to_received_s": round(t_rec - t_gen, 3),
                "hold_s": round(t_rec - t_gen, 3), "value": want,
                "payload_sha256": sha[:16],
                "verdict": verdict_of(t_rec - t_gen, off),
                "notes": f"true_age_at_read={true_age:.2f}s observable_age_at_read={obs_age:.2f}s",
            })
            print(f"    cloud registered at t_generated; HA stamped t_received "
                  f"{t_rec - t_gen:+.2f}s later")
            print(f"    at the moment of read:  true age={true_age:.2f}s   "
                  f"observable age={obs_age:.2f}s   -> {verdict_of(t_rec - t_gen, off)}")
        else:
            print(f"    INCONCLUSIVE (t_generated={t_gen}, t_received={t_rec}) -- recorded as such")
            rows.append({"probe": "causal_flip", "entity_class": "integration_backed",
                         "entity_id": ent, "device_id": dev, "t_cause": round(t_cause, 3),
                         "t_generated": t_gen or "", "t_received": t_rec or "",
                         "ha_clock_offset_s": off, "gap_generated_to_received_s": "",
                         "hold_s": "", "value": want, "payload_sha256": "",
                         "verdict": "undetermined", "notes": "zero-effect / no propagation within 75s"})
        st_command(dev, not target)              # restore
    except Exception as e:
        print(f"    ERROR {type(e).__name__}: {str(e)[:80]}")

    OUT.parent.mkdir(exist_ok=True)
    with open(OUT, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"\n  wrote {OUT.relative_to(ROOT)}  ROWS={len(rows)}")
    if not rows:
        print("  !! ROWS=0 -- silent write-path failure, checkpoint trigger (4)")
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
