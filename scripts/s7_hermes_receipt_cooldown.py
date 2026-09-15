#!/usr/bin/env python3
"""S7 -- Hermes receipt-time laundering and cooldown suppression.

Design report Sec. 9.3, S7: "Delay an authentic Home Assistant state_changed event upstream of
the Hermes adapter. On release, Hermes assigns current receipt time to the model-facing message
and does not expose the original event time in the formatted text. Release the authentic
corrective event inside the per-entity cooldown window. Test separately whether the old event
appears fresh and whether receipt-time cooldown suppresses the correction. Invariant: source
time must survive adaptation, and cooldown must not convert finite delay into model-visible
omission. Outcomes: source/receipt age gap, correction visibility, and changed controller
action."

Why this runs offline
---------------------
The mechanism lives entirely inside Hermes's own Home Assistant adapter, so it is measured
against Hermes's own code driven by Hermes's own `FakeHAServer` over a real WebSocket. No live
Home Assistant, no SmartThings cloud, no model inference, no network. That makes S7 fully
reproducible from the artifact, which the live-proxy Hermes study in the paper is not.

Run with the HERMES virtualenv, since it owns aiohttp and the plugin tree:

  HERMES_HOME=~/Desktop/hermes-agent \\
    $HERMES_HOME/.venv/bin/python scripts/s7_hermes_receipt_cooldown.py

What is measured, and why each is the report's own outcome
----------------------------------------------------------
S7a  source/receipt age gap. An authentic event carrying a `last_changed` from T seconds ago is
     released to the adapter now. We record whether the model-facing MessageEvent carries the
     SOURCE time or the RECEIPT time, and whether the formatted text exposes the source time at
     all. If neither does, an arbitrarily old authentic event is indistinguishable from one that
     just happened -- the same laundering E1 measured at the hub, one layer higher.

S7b  correction visibility. A stale event is released, then the authentic CORRECTIVE event is
     released inside the per-entity cooldown window. We record whether the correction reaches
     the model at all. The adapter stamps its cooldown clock at RECEIPT, so a delayed event
     resets the window on arrival and the correction that follows it can be dropped -- turning a
     finite delay into a permanent omission, which is precisely what the invariant forbids.

Nothing here forges a value: every event carries a state the world genuinely produced, and only
delivery timing is chosen.
"""

from __future__ import annotations

import asyncio
import csv
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "s7_hermes_receipt_cooldown.csv"

HERMES = Path(os.environ.get("HERMES_HOME", Path.home() / "Desktop" / "hermes-agent"))
if not (HERMES / "plugins").is_dir():
    raise SystemExit(f"HERMES_HOME does not look like a hermes-agent checkout: {HERMES}")
sys.path.insert(0, str(HERMES))

from plugins.platforms.homeassistant.adapter import HomeAssistantAdapter  # noqa: E402
from tests.fakes.fake_ha_server import FakeHAServer                        # noqa: E402

from gateway.config import PlatformConfig  # noqa: E402

FIELDS = [
    "run_id", "scenario", "arm", "entity_id", "source_age_s", "cooldown_s",
    "forwarded", "model_text", "text_contains_source_time", "message_timestamp",
    "timestamp_is_receipt", "source_receipt_gap_s", "correction_visible",
    "invariant_violated", "notes",
]


def _state(value: str, *, age_s: float, name: str) -> dict:
    """A state payload whose own last_changed is `age_s` in the past.

    This is what makes the event AUTHENTIC-BUT-OLD: Home Assistant really did observe this
    value, at that time. Nothing about the value is invented.
    """
    t = datetime.now(timezone.utc) - timedelta(seconds=age_s)
    stamp = t.isoformat().replace("+00:00", "+00:00")
    return {
        "state": value,
        "attributes": {"friendly_name": name, "device_class": "door"},
        "last_changed": stamp,
        "last_updated": stamp,
        "last_reported": stamp,
    }


async def _adapter(server: FakeHAServer, captured: list, **extra) -> HomeAssistantAdapter:
    cfg = PlatformConfig(enabled=True, token=server.token,
                         extra={"url": server.url, "watch_all": True, **extra})
    ad = HomeAssistantAdapter(cfg)

    async def _capture(ev):
        captured.append(ev)

    ad.handle_message = _capture     # type: ignore[assignment]
    return ad


async def _settle(captured: list, want: int, timeout: float = 3.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if len(captured) >= want:
            return True
        await asyncio.sleep(0.05)
    return False


async def run_s7a(run_id: str, source_age_s: float) -> dict:
    """Does the SOURCE time survive adaptation into the model-facing message?"""
    captured: list = []
    async with FakeHAServer() as server:
        ad = await _adapter(server, captured)
        await ad.connect()
        t_release = datetime.now(timezone.utc)
        await server.push_event({"data": {
            "entity_id": "binary_sensor.front_door_contact",
            "old_state": _state("off", age_s=source_age_s + 1, name="Front Door"),
            "new_state": _state("on", age_s=source_age_s, name="Front Door"),
        }})
        got = await _settle(captured, 1)
        await ad.disconnect() if hasattr(ad, "disconnect") else None

    if not got:
        return dict(run_id=run_id, scenario="S7a_receipt_laundering", arm="delayed_authentic",
                    entity_id="binary_sensor.front_door_contact", source_age_s=source_age_s,
                    forwarded=False, notes="event never forwarded; filters or cooldown")

    ev = captured[0]
    text = getattr(ev, "text", "")
    ts = getattr(ev, "timestamp", None)
    # Does the model-facing TEXT expose the source time in any form?
    has_src = any(tok in text for tok in (str(source_age_s), "last_changed", "ago", "T"))
    has_src = has_src and ("last_changed" in text or "ago" in text)
    # Is the message timestamp the RECEIPT instant rather than the source instant?
    # The adapter stamps `datetime.now()`, which is NAIVE LOCAL time. Coercing it to UTC
    # silently shifts it by the local offset and makes the receipt check fail for a reason
    # that has nothing to do with Hermes -- so compare in the same frame it was produced in.
    gap = ""
    is_receipt = ""
    if isinstance(ts, datetime):
        ts_local = ts.astimezone() if ts.tzinfo else ts.replace(tzinfo=None)
        now_local = t_release.astimezone().replace(tzinfo=None)
        if ts.tzinfo:
            ts_local = ts.astimezone().replace(tzinfo=None)
        # gap between the message's stamp and the event's OWN source time
        src_local = now_local - timedelta(seconds=source_age_s)
        gap = round((ts_local - src_local).total_seconds(), 3)
        is_receipt = abs((ts_local - now_local).total_seconds()) < 2.0
    return dict(
        run_id=run_id, scenario="S7a_receipt_laundering", arm="delayed_authentic",
        entity_id="binary_sensor.front_door_contact", source_age_s=source_age_s,
        forwarded=True, model_text=text[:160],
        text_contains_source_time=has_src, message_timestamp=str(ts),
        timestamp_is_receipt=is_receipt, source_receipt_gap_s=gap,
        # The invariant is "source time must survive adaptation".
        invariant_violated=(not has_src) and (is_receipt is True),
        notes="authentic event released after a delay; nothing about its value altered",
    )


async def run_s7b(run_id: str, cooldown_s: int, correction_delay_s: float) -> dict:
    """Does the per-entity cooldown swallow the authentic CORRECTIVE event?"""
    captured: list = []
    async with FakeHAServer() as server:
        ad = await _adapter(server, captured, cooldown_seconds=cooldown_s)
        await ad.connect()
        # 1. the stale event lands and is forwarded (this also arms the cooldown, at RECEIPT)
        await server.push_event({"data": {
            "entity_id": "binary_sensor.front_door_contact",
            "old_state": _state("on", age_s=61, name="Front Door"),
            "new_state": _state("off", age_s=60, name="Front Door"),
        }})
        await _settle(captured, 1)
        n_after_stale = len(captured)
        # 2. the authentic CORRECTION follows, inside the cooldown window
        await asyncio.sleep(correction_delay_s)
        await server.push_event({"data": {
            "entity_id": "binary_sensor.front_door_contact",
            "old_state": _state("off", age_s=1, name="Front Door"),
            "new_state": _state("on", age_s=0, name="Front Door"),
        }})
        await _settle(captured, n_after_stale + 1, timeout=2.0)
        await ad.disconnect() if hasattr(ad, "disconnect") else None

    visible = len(captured) > n_after_stale
    return dict(
        run_id=run_id, scenario="S7b_cooldown_suppression", arm="correction_in_window",
        entity_id="binary_sensor.front_door_contact", cooldown_s=cooldown_s,
        forwarded=n_after_stale > 0,
        model_text=(getattr(captured[-1], "text", "")[:160] if captured else ""),
        correction_visible=visible,
        # "cooldown must not convert finite delay into model-visible omission"
        invariant_violated=(n_after_stale > 0) and (not visible),
        notes=(f"correction released {correction_delay_s}s after the stale event, inside the "
               f"{cooldown_s}s per-entity cooldown"),
    )


def append(rows):
    OUT.parent.mkdir(exist_ok=True)
    new = not OUT.exists()
    with OUT.open("a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        if new:
            w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in FIELDS})


async def main() -> int:
    run_id = time.strftime("%Y%m%dT%H%M%S")
    print(f"run_id={run_id}  HERMES_HOME={HERMES}", flush=True)
    rows = []

    print("\n  === S7a: does the source time survive adaptation? ===")
    for age in (5.0, 45.0, 600.0):
        r = await run_s7a(run_id, age)
        rows.append(r)
        print(f"    source_age={age:>6.1f}s  forwarded={r.get('forwarded')}  "
              f"text_has_source_time={r.get('text_contains_source_time')}  "
              f"timestamp_is_receipt={r.get('timestamp_is_receipt')}  "
              f"VIOLATED={r.get('invariant_violated')}", flush=True)
    if rows and rows[0].get("model_text"):
        print(f"\n    model sees verbatim: {rows[0]['model_text']!r}")

    print("\n  === S7b: does the cooldown swallow the correction? ===")
    for cd, delay in ((30, 1.0), (30, 0.2), (1, 1.5)):
        r = await run_s7b(run_id, cd, delay)
        rows.append(r)
        print(f"    cooldown={cd:>3}s correction_after={delay:>4.1f}s  "
              f"correction_visible={r.get('correction_visible')}  "
              f"VIOLATED={r.get('invariant_violated')}", flush=True)

    append(rows)
    print(f"\n  appended {len(rows)} rows -> {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
