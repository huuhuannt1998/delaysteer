#!/usr/bin/env python3
"""Which Home Assistant read paths show a same-value affirmation in last_reported?

The manuscript states that Home Assistant "refreshes last_reported only on a value change". HA's
source (core.py, StateMachine.async_set_internal, 2026.8.3) advances last_reported in memory on
every write and fires state_reported, but does not invalidate the cached JSON the REST and
websocket get_states views serve (HA issue #181392). This probe measures each read path directly.

Per trial: optionally serialize the entity first (one REST read), perform one write, wait, then
read last_reported through four paths:
  rest      GET /api/states/<entity>
  template  POST /api/template  {{ states.<entity>.last_reported }}   (the live in-memory object)
  ws_get    websocket get_states
  ws_event  last_reported carried by the state_reported / state_changed event of that write
A path "advanced" if the value it shows is at or after the write instant.

Writes: `same` (identical state and attributes via POST /api/states), `same_force` (identical,
force_update=true), `change` (new value), and `update_entity` (homeassistant.update_entity on an
integration-backed template entity whose value does not change: the refresh the paper's poll
efficacy probe used).

Run it against a SEPARATE instance, never the live experiment hub:
  ~/Desktop/hermes-agent/.venv/bin/python scripts/ha_readpath_probe.py --base http://localhost:8133 --n 20
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import aiohttp

ROOT = Path(__file__).resolve().parent.parent
SCRATCH = "sensor.readpath_probe"
INTEGRATION = "binary_sensor.front_door_contact"   # template entity over input_boolean.front_door_open


def _env(k: str) -> str | None:
    for line in (ROOT / ".env").read_text().splitlines():
        if line.startswith(k + "="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def _ts(iso: str | None) -> float | None:
    if not iso:
        return None
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


class Probe:
    def __init__(self, base: str, token: str):
        self.base = base.rstrip("/")
        self.h = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        self.token = token
        self.events: list[dict] = []
        self._msg_id = 0

    async def __aenter__(self):
        self.s = aiohttp.ClientSession(headers=self.h)
        self.ws = await self.s.ws_connect(self.base.replace("http", "ws", 1) + "/api/websocket")
        await self.ws.receive_json()                                   # auth_required
        await self.ws.send_json({"type": "auth", "access_token": self.token})
        assert (await self.ws.receive_json())["type"] == "auth_ok"
        for et in ("state_reported", "state_changed"):
            await self._ws_call({"type": "subscribe_events", "event_type": et})
        self.listener = asyncio.create_task(self._listen())
        return self

    async def __aexit__(self, *exc):
        self.listener.cancel()
        await self.ws.close()
        await self.s.close()

    async def _ws_call(self, msg: dict) -> dict:
        self._msg_id += 1
        msg["id"] = self._msg_id
        fut = asyncio.get_event_loop().create_future()
        self._pending = (self._msg_id, fut)
        await self.ws.send_json(msg)
        if not hasattr(self, "listener"):                              # before the listener runs
            while True:
                m = await self.ws.receive_json()
                if m.get("id") == self._msg_id and m.get("type") == "result":
                    return m
        return await asyncio.wait_for(fut, 10)

    async def _listen(self):
        async for msg in self.ws:
            m = json.loads(msg.data)
            if m.get("type") == "event":
                self.events.append(m["event"])
            elif m.get("type") == "result" and getattr(self, "_pending", (None,))[0] == m.get("id"):
                self._pending[1].set_result(m)

    async def rest(self, e):
        async with self.s.get(f"{self.base}/api/states/{e}") as r:
            return (await r.json()).get("last_reported")

    async def template(self, e):
        async with self.s.post(f"{self.base}/api/template",
                               json={"template": f"{{{{ states.{e}.last_reported.isoformat() }}}}"}) as r:
            return (await r.text()).strip()

    async def ws_get(self, e):
        res = await self._ws_call({"type": "get_states"})
        for st in res.get("result", []):
            if st["entity_id"] == e:
                return st.get("last_reported")
        return None

    async def set_state(self, e, state, force=False):
        body = {"state": state, "attributes": {"friendly_name": "Readpath probe"}}
        if force:
            body["force_update"] = True
        async with self.s.post(f"{self.base}/api/states/{e}", json=body) as r:
            await r.read()

    async def update_entity(self, e):
        async with self.s.post(f"{self.base}/api/services/homeassistant/update_entity",
                               json={"entity_id": e}) as r:
            await r.read()


async def trial(p: Probe, kind: str, preserialized: bool, i: int) -> dict:
    e = INTEGRATION if kind == "update_entity" else SCRATCH
    if kind != "update_entity":
        await p.set_state(e, "a")                                      # known baseline value
    await asyncio.sleep(1.2)
    if preserialized:
        await p.rest(e)                                                # builds the cached JSON
    await asyncio.sleep(1.2)
    n_ev = len(p.events)
    t_write = time.time()
    if kind == "same":
        await p.set_state(e, "a")
    elif kind == "same_force":
        await p.set_state(e, "a", force=True)
    elif kind == "change":
        await p.set_state(e, "b" if i % 2 == 0 else "c")
    else:
        await p.update_entity(e)
    await asyncio.sleep(1.0)
    ev = [x for x in p.events[n_ev:] if x.get("data", {}).get("entity_id") == e]
    ev_lr = None
    for x in ev:
        d = x["data"]
        ev_lr = d.get("last_reported") or (d.get("new_state") or {}).get("last_reported") or ev_lr
    reads = {"rest": await p.rest(e), "template": await p.template(e), "ws_get": await p.ws_get(e),
             "ws_event": ev_lr}
    row = {"kind": kind, "preserialized": preserialized, "trial": i, "entity": e,
           "t_write": round(t_write, 3), "event_types": ",".join(x["event_type"] for x in ev) or "none"}
    for k, v in reads.items():
        tv = _ts(v) if v and v != "None" else None
        row[f"{k}_last_reported"] = v
        row[f"{k}_advanced"] = (tv is not None and tv >= t_write - 0.05)
    return row


async def main_async(args):
    token = _env("HASS_TOKEN")
    rows = []
    async with Probe(args.base, token) as p:
        for kind in ("same", "same_force", "change", "update_entity"):
            for pre in (True, False):
                for i in range(args.n):
                    rows.append(await trial(p, kind, pre, i))
                    print(".", end="", flush=True)
    print()
    out = ROOT / args.out
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {out.relative_to(ROOT)} ({len(rows)} trials)")
    print(f"{'kind':<14}{'pre-read':<10}" + "".join(f"{k:>10}" for k in ("rest", "template", "ws_get", "ws_event")))
    for kind in ("same", "same_force", "change", "update_entity"):
        for pre in (True, False):
            rs = [r for r in rows if r["kind"] == kind and r["preserialized"] == pre]
            cells = "".join(f"{sum(r[k + '_advanced'] for r in rs):>7}/{len(rs):<2}"
                            for k in ("rest", "template", "ws_get", "ws_event"))
            print(f"{kind:<14}{str(pre):<10}{cells}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8133")
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--out", default="results/ha_readpath_2026_8_3.csv")
    args = ap.parse_args()
    if ":8123" in args.base:
        raise SystemExit("refusing to probe the live experiment hub on :8123")
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
