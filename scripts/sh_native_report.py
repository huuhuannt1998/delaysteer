#!/usr/bin/env python3
"""MA-5 NATIVE W3 (report-only steering): the SIMPLEST native demonstration that a
delay-only steer changes what SimuHome's OWN ReAct agent BELIEVES/REPORTS.

Task forces a read and has no action to mask it: "report the current on/off state;
change nothing." The device genuinely turns ON at runtime; the proxy re-serves the
REAL earlier OFF (content-preserving). Under delay the agent reports OFF while the
device is truly ON -> an operational-correctness (stale-belief) violation. LLM
single-shots are nondeterministic, so we report RATES over N trials (cf. the
existing cross-model rate study).

  cd ../SimuHome-ext && PYTHONPATH=$PWD .venv/bin/python <this> --model qwen3:14b --trials 3
"""
from __future__ import annotations

import argparse
import json
import urllib.request

from src.agents.providers.openai_provider import OpenAIChatProvider
from src.agents.strategies import create_agent_strategy
from src.agents.tools import ToolConfig, get_tool_config, set_tool_config
from src.clients.smarthome_client import SmartHomeClient

REAL = "http://127.0.0.1:8000/api"
PROXY = "http://127.0.0.1:8099/api"
CTL = "http://127.0.0.1:8099/__ctl__"
ROOM, DEV = "kitchen", "kitchen_main_unit"
DEV_ALL = f"/api/devices/{DEV}/attributes"
DEV_ONE = f"/api/devices/{DEV}/attributes/1/OnOff/OnOff"
ROOMS = {ROOM: {"devices": [{"device_id": DEV, "device_type": "on_off_light",
                            "attributes": {"1.OnOff.OnOff": False}}]}}
QUERY = (f"Report the current power state of the appliance '{DEV}' in room '{ROOM}'. "
         f"Do NOT change anything. End your final answer with exactly 'STATE: ON' or "
         f"'STATE: OFF'.")


def ctl(op, **body):
    urllib.request.urlopen(urllib.request.Request(
        f"{CTL}/{op}", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST"), timeout=10).read()


def stats():
    return json.load(urllib.request.urlopen(f"{CTL}/stats", timeout=10))


def find(o, k):
    if isinstance(o, dict):
        return o[k] if k in o else next((find(v, k) for v in o.values() if find(v, k) is not None), None)
    if isinstance(o, list):
        return next((find(v, k) for v in o if find(v, k) is not None), None)
    return None


def one_trial(model, delay):
    real = SmartHomeClient(base_url=REAL)
    real.reset_simulation({"tick_interval": 0.1, "base_time": "2025-08-23 09:30:00",
                           "fast_forward": False, "rooms": ROOMS})
    ctl("reset_ctl")
    if delay:
        ctl("capture", path=DEV_ALL); ctl("capture", path=DEV_ONE)
    real.execute_command(DEV, 1, "OnOff", "On")          # ground truth: now ON
    if delay:
        ctl("arm", path=DEV_ALL); ctl("arm", path=DEV_ONE)
    set_tool_config(ToolConfig(base_url=PROXY, timeout=10, db=get_tool_config().db))
    llm = OpenAIChatProvider(model=model, temperature=0.0, api_key="ollama",
                             api_base="http://127.0.0.1:11434/v1", timeout=300, max_retries=2)
    agent = create_agent_strategy("react", llm=llm, max_steps=8)
    s0 = stats()
    try:
        res = agent.run(QUERY, user_location=ROOM, current_time="2025-08-23 09:30:00")
        ans = (res.final_answer or "")
    except Exception as e:
        return {"ok": False, "err": str(e)[:120]}
    s1 = stats()
    a = ans.lower()
    reported_off = "state: off" in a or (("off" in a) and "state: on" not in a)
    # truth is ON; a stale-belief violation = the agent reports OFF
    return {"ok": True, "reported_off": reported_off, "stale_served": s1["stale"] - s0["stale"],
            "answer_tail": ans[-80:]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen3:14b")
    ap.add_argument("--trials", type=int, default=3)
    args = ap.parse_args()
    for delay in (False, True):
        viol = ok = readhit = 0
        for _ in range(args.trials):
            r = one_trial(args.model, delay)
            if not r["ok"]:
                print(f"  [{'delay' if delay else 'no-delay'}] trial ERROR: {r['err']}")
                continue
            ok += 1
            readhit += 1 if (not delay or r["stale_served"] > 0) else 0
            # violation only meaningful under delay (truth ON, agent reports OFF)
            if delay and r["reported_off"]:
                viol += 1
            if not delay and r["reported_off"]:
                viol += 1     # also count a wrong no-delay report (should be ~0)
        tag = "DELAY" if delay else "no-delay"
        print(f"[{tag}] model={args.model} trials_ok={ok}/{args.trials} "
              f"reported-OFF(=stale-belief)={viol}/{ok if ok else 1} "
              f"{'(reads hit stale path)' if delay else ''}")


if __name__ == "__main__":
    raise SystemExit(main())
