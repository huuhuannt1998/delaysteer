#!/usr/bin/env python3
"""TicToc temporal-tool-use alignment, evaluated on SMALL LOCAL models via Ollama.

Reproduces the TicToc methodology (Cheng et al., "Your LLM Agents are Temporally
Blind", arXiv:2510.23853) using its public dataset, on locally served models.

Why this works on small local models where a full agentic benchmark does not: each
sample is a SINGLE decision at the final user turn -- call a tool (refresh) or
answer directly from (possibly stale) context. We give the model the full
conversation + the tool definitions, and detect whether it emits a NATIVE tool
call. No multi-step rollout, no grammar-constrained decoding -> tractable for
0.6B-14B local models.

Metric (paper-faithful):
  ground truth from pref_score: <= 0.5 => prefer-DIRECT (no tool), >= 2.5 => prefer-TOOL
  TP = pref-tool   & attempted     FN = pref-tool   & not attempted
  TN = pref-direct & not attempted FP = pref-direct & attempted
  NAR = 0.5 * ( TP/(TP+FN) + TN/(TN+FP) )           (50% == random)
  Attempt rate (per class) = attempted / total
With/without timestamp: prepend "[<ISO time>] " to each message's content (the
paper's wall-clock injection). Turn-range buckets by len(history): <=7 / 8-12 / >=13.

Run:
  python3 scripts/tictoc_local_eval.py \
    --model llama3.1:8b --data /Users/anonymous/Desktop/TicToc-ext/merged_fully_labeled_data_test.json \
    --conditions nots,ts --out results/tictoc_local.csv
  # qwen3 reasoning models: add --no-think to disable <think> (faster; paper Fig 5
  # shows reasoning does not improve temporal alignment).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import time
import urllib.request

OLLAMA = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/v1/chat/completions")


def load_kept(path):
    """Confident samples only, with paper-faithful ground truth."""
    data = json.load(open(path, encoding="utf-8"))
    kept = []
    for x in data:
        s = x.get("pref_score")
        if not isinstance(s, (int, float)):
            continue
        if s <= 0.5:
            gt = "direct"          # prefer-noTool
        elif s >= 2.5:
            gt = "tool"            # prefer-Tool
        else:
            continue
        kept.append((x, gt))
    return kept


def build_messages(history, with_ts, no_think):
    """Reconstruct OpenAI-format messages; optionally prepend wall-clock time."""
    msgs = []
    for m in history:
        role = m["role"]
        content = m.get("content")
        content = "" if content is None else str(content)
        if with_ts and m.get("time"):
            content = f"[{m['time']}] " + content
        msg = {"role": role, "content": content}
        if m.get("tool_calls"):
            msg["tool_calls"] = [{
                "id": tc.get("id", f"call_{i}"),
                "type": "function",
                "function": {"name": tc["function"]["name"],
                             "arguments": tc["function"]["arguments"]},
            } for i, tc in enumerate(m["tool_calls"])]
        if role == "tool":
            msg["tool_call_id"] = m.get("tool_call_id", "")
            if m.get("name"):
                msg["name"] = m["name"]
        msgs.append(msg)
    if no_think and msgs and msgs[0]["role"] == "system":
        msgs[0]["content"] = msgs[0]["content"].rstrip() + " /no_think"
    return msgs


def call(model, messages, tools, timeout, retries=2):
    body = {"model": model, "messages": messages, "tools": tools,
            "temperature": 0, "stream": False}
    data = json.dumps(body).encode()
    last = None
    for _ in range(retries + 1):
        try:
            req = urllib.request.Request(OLLAMA, data=data, method="POST",
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                d = json.loads(r.read())
            msg = d["choices"][0]["message"]
            return bool(msg.get("tool_calls")), None
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {str(e)[:80]}"
    return None, last


def bucket(n):
    return "<=7" if n <= 7 else ("8-12" if n <= 12 else ">=13")


def nar(rows):
    TP = sum(1 for r in rows if r["gt"] == "tool" and r["attempted"] == 1)
    FN = sum(1 for r in rows if r["gt"] == "tool" and r["attempted"] == 0)
    TN = sum(1 for r in rows if r["gt"] == "direct" and r["attempted"] == 0)
    FP = sum(1 for r in rows if r["gt"] == "direct" and r["attempted"] == 1)
    if (TP + FN) == 0 or (TN + FP) == 0:
        return None, TP, FN, TN, FP
    return 0.5 * (TP / (TP + FN) + TN / (TN + FP)), TP, FN, TN, FP


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--conditions", default="nots,ts", help="nots,ts")
    ap.add_argument("--n", type=int, default=0, help="0 = all kept; else stratified subsample")
    ap.add_argument("--no-think", action="store_true")
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    kept = load_kept(args.data)
    if args.n and args.n < len(kept):
        tools_g = [kg for kg in kept if kg[1] == "tool"]
        dir_g = [kg for kg in kept if kg[1] == "direct"]
        half = args.n // 2
        kept = tools_g[:half] + dir_g[:args.n - half]
    print(f"model={args.model}  kept={len(kept)} "
          f"(tool={sum(1 for _,g in kept if g=='tool')}, "
          f"direct={sum(1 for _,g in kept if g=='direct')})", flush=True)

    conditions = [c.strip() for c in args.conditions.split(",") if c.strip()]
    all_rows = []
    for cond in conditions:
        with_ts = (cond == "ts")
        rows = []
        t0 = time.time()
        for j, (x, gt) in enumerate(kept):
            msgs = build_messages(x["history"], with_ts, args.no_think)
            attempted, err = call(args.model, msgs, x.get("function", []), args.timeout)
            row = {"model": args.model, "condition": cond, "id": x["id"], "gt": gt,
                   "attempted": (1 if attempted else 0) if attempted is not None else -1,
                   "n_msgs": len(x["history"]), "bucket": bucket(len(x["history"])),
                   "error": err or ""}
            rows.append(row)
            all_rows.append(row)
            if (j + 1) % 50 == 0:
                ok = [r for r in rows if r["attempted"] >= 0]
                v = nar(ok)[0]
                print(f"  [{cond}] {j+1}/{len(kept)}  NAR_so_far="
                      f"{('%.1f%%'%(100*v)) if v else 'NA'}  "
                      f"{(time.time()-t0)/(j+1):.1f}s/sample", flush=True)
        ok = [r for r in rows if r["attempted"] >= 0]
        errs = len(rows) - len(ok)
        val, TP, FN, TN, FP = nar(ok)
        at_tool = sum(1 for r in ok if r["gt"] == "tool" and r["attempted"] == 1)
        n_tool = sum(1 for r in ok if r["gt"] == "tool")
        at_dir = sum(1 for r in ok if r["gt"] == "direct" and r["attempted"] == 1)
        n_dir = sum(1 for r in ok if r["gt"] == "direct")
        print(f"\n==== {args.model}  [{cond}]  (errors={errs}) ====", flush=True)
        print(f"  NAR = {('%.1f%%'%(100*val)) if val else 'NA'}   "
              f"(TP={TP} FN={FN} TN={TN} FP={FP})", flush=True)
        print(f"  attempt-rate  prefer-TOOL: {at_tool}/{n_tool}="
              f"{100*at_tool/max(1,n_tool):.0f}%   "
              f"prefer-DIRECT: {at_dir}/{n_dir}={100*at_dir/max(1,n_dir):.0f}%", flush=True)
        for b in ("<=7", "8-12", ">=13"):
            bb = [r for r in ok if r["bucket"] == b]
            v = nar(bb)[0] if bb else None
            ar = sum(r["attempted"] for r in bb) / len(bb) if bb else 0
            print(f"    bucket {b:5s} n={len(bb):4d}  NAR="
                  f"{('%.1f%%'%(100*v)) if v else 'NA':>6s}  attempt={100*ar:.0f}%", flush=True)

    hdr = ["model", "condition", "id", "gt", "attempted", "n_msgs", "bucket", "error"]
    exists = os.path.exists(args.out)
    with open(args.out, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=hdr)
        if not exists:
            w.writeheader()
        w.writerows(all_rows)
    print(f"\nwrote {len(all_rows)} rows -> {args.out}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
