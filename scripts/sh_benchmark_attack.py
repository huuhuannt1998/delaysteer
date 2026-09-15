#!/usr/bin/env python3
"""Delay-only attack on SimuHome's NATIVE benchmark episodes (their metric).

This forks SimuHome's own ``run_single_config`` (src/pipelines/episode_evaluation/
runner.py) with exactly ONE structural change:

  * the AGENT's tool reads go through our delay proxy (:8099), while
  * the EVALUATOR's ground-truth client talks DIRECTLY to the simulator (:8000).

Under ``nodelay`` the proxy is a transparent forwarder, so that arm is identical
to SimuHome's own runner (sanity anchor). Under ``delay`` an observation channel
is re-served STALE (delivery-only, content-preserving, no forgery) for the
duration of the agent run, then DISARMED before evaluation so the evaluator scores
against true ground truth. We use SimuHome's own episode files and its own
per-(qt,case) evaluators, unmodified -- the success metric is theirs.

Channels (the observation the delay-only adversary re-serves stale):
  device  -- /api/devices/{id}/attributes for each goal/anchor/target device.
             QT4-2: stale-high dishwasher countdown -> agent computes a later
             finish -> schedules the dependent action too late -> fail.
             QT3:   stale device state -> agent mis-sequences an operational dep.
  room    -- /api/rooms/{id}/states (QT2 implicit-intent env reads).
  time    -- /api/time (with --clock-stale-ticks, advances the REAL sim after
             capture so the re-served clock is genuinely that-much delayed).

Run from the SimuHome clone, with its venv:
  cd ../SimuHome-ext && .venv/bin/python \
    /Users/anonymous/Desktop/DelaySteer/scripts/sh_benchmark_attack.py \
    --category qt3 --n 8 --conditions nodelay,delay --channel device \
    --model llama3.1:8b --api-base http://127.0.0.1:11434/v1 --api-key ollama \
    --out /Users/anonymous/Desktop/DelaySteer/results/simuhome_benchmark.csv
"""
from __future__ import annotations

import argparse
import csv
import glob
import importlib
import json
import os
import sys
import time
import urllib.request

SIMU_ROOT = os.environ.get("SIMUHOME_ROOT", "/Users/anonymous/Desktop/SimuHome-ext")
if SIMU_ROOT not in sys.path:
    sys.path.insert(0, SIMU_ROOT)

from src.pipelines.episode_evaluation import runner as R          # noqa: E402
from src.agents.providers.openai_provider import OpenAIChatProvider  # noqa: E402

DIRECT = "http://127.0.0.1:8000/api"
PROXY = "http://127.0.0.1:8099/api"
CTL = "http://127.0.0.1:8099/__ctl__"


def _post(url, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def _get(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read()


def ctl(op, **body):
    return _post(f"{CTL}/{op}", body)


def ctl_stats():
    return json.loads(_get(f"{CTL}/stats"))


def channel_paths(ep, channel):
    ev = ep.get("eval", {})
    goals = ev.get("goals", [])
    if channel == "time":
        return ["/api/time"]
    if channel == "device":
        ids = []
        for g in goals:
            if g.get("device_id"):
                ids.append(g["device_id"])
            anch = g.get("anchor") or {}
            if anch.get("device_id"):
                ids.append(anch["device_id"])
            for t in g.get("targets", []) or []:
                if t.get("device_id"):
                    ids.append(t["device_id"])
        return [f"/api/devices/{i}/attributes" for i in dict.fromkeys(ids)]
    if channel == "room":
        rids = [g.get("room_id") for g in goals if g.get("room_id")]
        for ra in ev.get("required_actions", []) or []:
            r = (ra.get("params") or {}).get("room_id")
            if r:
                rids.append(r)
        return [f"/api/rooms/{r}/states" for r in dict.fromkeys(rids)]
    raise SystemExit(f"unknown channel {channel}")


def fast_forward(ticks):
    """Advance the REAL sim by `ticks` so an armed /api/time read is that stale."""
    st = json.loads(_get(f"{DIRECT}/home/state"))
    cur = int(st.get("data", {}).get("current_tick", 0) or 0)
    _post(f"{DIRECT}/simulation/fast_forward_to", {"to_tick": cur + ticks})


def run_episode(cfg_path, *, delay, channel, llm, judges, timeout, max_steps,
                clock_stale_ticks):
    ep = json.load(open(cfg_path, "r", encoding="utf-8"))
    qt, case = ep["meta"]["query_type"], ep["meta"]["case"]

    agent = R._build_agent(llm, max_steps=max_steps, strategy="react")
    adapter = R.get_strategy_adapter(R._canonical_strategy_name("react"))

    eval_client = R.SmartHomeClient(base_url=DIRECT, timeout=timeout)  # ground truth
    if not eval_client.health():
        raise RuntimeError("simulator health check failed on :8000")
    R._require_ok_response(eval_client.reset_simulation(ep["initial_home_config"]),
                           context="reset_simulation")
    ctl("reset_ctl")

    cur_tc = R.get_tool_config()
    R.set_tool_config(R.ToolConfig(base_url=PROXY, timeout=int(timeout), db=cur_tc.db))

    armed = []
    if delay:
        for p in channel_paths(ep, channel):
            ctl("capture", path=p)
            ctl("arm", path=p)
            armed.append(p)
        if channel == "time" and clock_stale_ticks > 0:
            fast_forward(clock_stale_ticks)

    t0 = time.perf_counter()
    try:
        artifacts = adapter.run(agent, R.EpisodeContext(
            query=ep["query"],
            user_location=ep.get("user_location"),
            current_time=ep["initial_home_config"].get("base_time"),
        ))
    finally:
        stats = ctl_stats()
        ctl("reset_ctl")  # disarm BEFORE evaluation -> evaluator sees true state
    dur = time.perf_counter() - t0

    tools = R._serialize_tool_calls(artifacts.agent_result.tool_calls)
    time.sleep(0.5)
    final = R._require_ok_response(eval_client.get_home_state(), context="get_home_state")
    payload = {"episode": ep, "final_home_state": final,
               "client": eval_client, "tools_invoked": tools}
    payload = R._merge_evaluation_payload(payload, artifacts.evaluation_payload)
    mod = importlib.import_module(R._EVALUATOR_REGISTRY[(qt, case)])
    res = mod.evaluate(payload, judges)
    return {
        "score": res.get("score"),
        "stale_served": int(stats.get("stale", 0)),
        "armed": ";".join(armed),
        "duration_s": round(dur, 1),
        "n_tools": len(tools),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--category", required=True,
                    help="qt2 | qt3 | qt4-1 | qt4-2 | qt4-3")
    ap.add_argument("--n", type=int, default=8)
    ap.add_argument("--conditions", default="nodelay,delay")
    ap.add_argument("--channel", default="device", help="device | room | time")
    ap.add_argument("--clock-stale-ticks", type=int, default=0)
    ap.add_argument("--model", required=True)
    ap.add_argument("--api-base", required=True)
    ap.add_argument("--api-key", required=True)
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--max-steps", type=int, default=30)
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--bench-dir",
                    default=os.path.join(SIMU_ROOT, "data", "benchmark"))
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    def mk_llm(seed):
        return OpenAIChatProvider(model=args.model, temperature=args.temperature,
                                  seed=seed, api_key=args.api_key,
                                  api_base=args.api_base, timeout=args.timeout)

    llm = mk_llm(42)
    judges = [mk_llm(42 + i) for i in range(3)]

    pattern = os.path.join(args.bench_dir, f"{args.category}_feasible_seed_*.json")
    files = sorted(glob.glob(pattern),
                   key=lambda p: int(p.split("_seed_")[1].split(".")[0]))[:args.n]
    if not files:
        raise SystemExit(f"no episodes match {pattern}")
    conditions = [c.strip() for c in args.conditions.split(",") if c.strip()]

    rows = []
    tallies = {c: {"pass": 0, "n": 0} for c in conditions}
    for cfg in files:
        seed = int(cfg.split("_seed_")[1].split(".")[0])
        for cond in conditions:
            delay = (cond != "nodelay")
            tag = f"{args.category} seed={seed} {cond}"
            try:
                r = run_episode(cfg, delay=delay, channel=args.channel, llm=llm,
                                judges=judges, timeout=args.timeout,
                                max_steps=args.max_steps,
                                clock_stale_ticks=args.clock_stale_ticks)
                score = r["score"]
            except Exception as e:  # keep the batch going; record the error
                r = {"score": -1, "stale_served": 0, "armed": "", "duration_s": 0,
                     "n_tools": 0}
                score = -1
                print(f"[{tag}] ERROR: {type(e).__name__}: {e}", flush=True)
            ok = 1 if score == 1 else 0
            tallies[cond]["n"] += 1
            tallies[cond]["pass"] += ok
            print(f"[{tag}] score={score} stale_served={r['stale_served']} "
                  f"tools={r['n_tools']} {r['duration_s']}s armed={r['armed']}",
                  flush=True)
            rows.append({
                "category": args.category, "seed": seed, "condition": cond,
                "channel": args.channel if delay else "", "model": args.model,
                "score": score, "stale_served": r["stale_served"],
                "n_tools": r["n_tools"], "duration_s": r["duration_s"],
                "armed": r["armed"], "temperature": args.temperature,
            })

    # append (additive; never rewrite frozen result files)
    header = ["category", "seed", "condition", "channel", "model", "score",
              "stale_served", "n_tools", "duration_s", "armed", "temperature"]
    exists = os.path.exists(args.out)
    with open(args.out, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header)
        if not exists:
            w.writeheader()
        w.writerows(rows)

    print("\n==== SUMMARY (success = score==1) ====", flush=True)
    for c in conditions:
        t = tallies[c]
        rate = (100.0 * t["pass"] / t["n"]) if t["n"] else 0.0
        print(f"  {args.category} {c:8s}: {t['pass']}/{t['n']}  ({rate:.0f}% success)",
              flush=True)
    print(f"  wrote {len(rows)} rows -> {args.out}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
