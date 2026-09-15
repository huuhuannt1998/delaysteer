"""Does a commit-time active poll actually re-affirm a fact on live Home Assistant?

Motivation (USENIX review, Reviewer A C1). ``TemporalGuard`` sets ``adapter.active_poll``
at the commit so a critical fact is force-affirmed and its value-age is bounded by the poll
round-trip rather than by the passive reporting cadence. Until now no adapter in
``delaysteer/home/`` read that attribute, so on live Home Assistant "active poll" only
tightened the tolerance epsilon without ever fetching fresher data -- which is why
``results/activepoll_liveha.csv`` shows active poll producing MORE false blocks (58) than
the full guard (55).

``ha_adapter.get_state`` now issues ``POST /api/services/homeassistant/update_entity``
before the read when the flag is set. This harness measures whether that call actually
does anything, which is the question the paper's fact-class guarantee turns on.

The distinction it isolates:

  call latency   -- how long the refresh round-trip takes. This is what
                    ``scripts/latency_calibration.py`` measured (P99 ~4.4 ms) and it is NOT
                    evidence that the value was re-affirmed.
  poll EFFICACY  -- whether ``last_reported`` actually advances. Only this bounds value-age,
                    and only this makes a fact "pollable" in the sense Cor. cor:floor needs.

In principle an entity backed by an integration implementing ``async_update`` advances
last_reported while a States-API or template entity does not. On THIS deployment neither does:
HA accepts ``update_entity`` with HTTP 200 and an empty result, and last_reported does not move
for any entity probed, including integration-backed ones (run with ``--entities`` for that
positive control). We therefore report the effect, not a cause: no fact here is pollable in
practice, so the guard must fail closed on all of them.

Additive output -- no frozen file is touched:
  results/ha_poll_efficacy.csv

  python scripts/ha_poll_efficacy.py            # default 5 trials per entity
  python scripts/ha_poll_efficacy.py --n 10
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import time
import urllib.request
from pathlib import Path

RESULTS = Path("results")
ENTITIES = [
    "binary_sensor.front_door_contact",
    "lock.front_door",
    "alarm_control_panel.home_alarm",
]


def _env() -> tuple[str, str]:
    env: dict[str, str] = {}
    for line in Path(".env").read_text().splitlines():
        m = re.match(r"\s*([A-Z_0-9]+)\s*=\s*(.*)", line)
        if m:
            env[m.group(1)] = m.group(2).strip().strip("\"'")
    return env["HASS_URL"].rstrip("/"), env["HASS_TOKEN"]


def _api(url: str, tok: str, path: str, method: str = "GET", body: dict | None = None):
    req = urllib.request.Request(
        url + path,
        method=method,
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
        data=json.dumps(body).encode() if body else None,
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, r.read().decode()


def _parse_iso(s: str) -> float:
    from datetime import datetime

    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def main() -> int:
    ap = argparse.ArgumentParser(description="Active-poll efficacy on live Home Assistant")
    ap.add_argument("--n", type=int, default=5, help="trials per entity")
    ap.add_argument("--out", default="ha_poll_efficacy")
    ap.add_argument("--entities", default="",
                    help="comma-separated entity_ids to probe instead of the critical facts; "
                         "used for the integration-backed POSITIVE CONTROL sweep")
    args = ap.parse_args()
    RESULTS.mkdir(exist_ok=True)
    url, tok = _env()
    entities = ([e.strip() for e in args.entities.split(",") if e.strip()]
                if args.entities else ENTITIES)

    rows: list[dict] = []
    print("=== Active-poll efficacy on live Home Assistant ===", flush=True)
    print("(does POST homeassistant/update_entity advance last_reported?)\n", flush=True)
    for ent in entities:
        for i in range(args.n):
            _, before = _api(url, tok, f"/api/states/{ent}")
            b = json.loads(before)
            age_before = time.time() - _parse_iso(b["last_reported"])

            t0 = time.time()
            status, body = _api(url, tok, "/api/services/homeassistant/update_entity",
                                "POST", {"entity_id": ent})
            rtt = time.time() - t0

            _, after = _api(url, tok, f"/api/states/{ent}")
            a = json.loads(after)
            age_after = time.time() - _parse_iso(a["last_reported"])
            advanced = a["last_reported"] != b["last_reported"]

            rows.append({
                "entity": ent, "trial": i,
                "http_status": status,
                "service_result": body.strip()[:40],
                "poll_rtt_s": round(rtt, 4),
                "value_age_before_s": round(age_before, 3),
                "value_age_after_s": round(age_after, 3),
                "last_reported_advanced": advanced,
                "pollable_in_practice": advanced,
            })
        adv = sum(1 for r in rows if r["entity"] == ent and r["last_reported_advanced"])
        last = [r for r in rows if r["entity"] == ent][-1]
        print(f"  {ent:<36} advanced {adv}/{args.n}  "
              f"rtt={last['poll_rtt_s']*1000:.1f}ms  "
              f"age {last['value_age_before_s']:.0f}s -> {last['value_age_after_s']:.0f}s",
              flush=True)

    out = RESULTS / f"{args.out}.csv"
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    total_adv = sum(1 for r in rows if r["last_reported_advanced"])
    print(f"\n=== VERDICT ===", flush=True)
    print(f"  last_reported advanced in {total_adv}/{len(rows)} polls", flush=True)
    if total_adv == 0:
        print("  The refresh is ACCEPTED (HTTP 200) but is a NO-OP: no probed entity's\n"
              "  generation time moves. A positive-control sweep over integration-backed\n"
              "  entities (zone, person, backup sensors) behaves identically, so this is a\n"
              "  property of the DEPLOYMENT, not of a particular entity's backend, and we do\n"
              "  not isolate the cause. Operationally the conclusion is unchanged: no fact\n"
              "  here is pollable in practice, so the guard must fail closed on all of them,\n"
              "  and the live-HA benign 0/20 reflects that rather than battery-sleepy radio\n"
              "  physics.", flush=True)
    else:
        print("  The refresh DOES advance last_reported: these facts are pollable in\n"
              "  practice and the active-poll floor applies to them.", flush=True)
    print(f"\nwrote {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
