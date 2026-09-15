#!/usr/bin/env python3
"""Is the substrate actually bit-reproducible? Measure, do not assume.

Stage 0's exit criterion is bit-identical temperature-0 replay. Seeding ollama
is necessary but not obviously sufficient: sampling is only one source of
nondeterminism. Batching, KV-cache state, context length, a model reload, and
GPU kernel non-associativity can all move logits, and at T=0 a moved logit
changes the argmax only when two tokens are near-tied -- which is exactly when
it matters and exactly what a short prompt will not surface.

So this probe escalates:

  1. same prompt, same seed, back to back        -- the easy case
  2. same prompt, same seed, interleaved with a  -- does other traffic through
     different prompt                               the server perturb it?
  3. same prompt, same seed, after a long        -- does context length matter?
     context
  4. same prompt, DIFFERENT seed at T=0          -- at T=0 the seed should be
                                                    irrelevant; if it is not,
                                                    "T=0" is not greedy here

If (1) holds but (2) or (3) fails, the substrate is deterministic only in
isolation, and every campaign must be run without interleaving -- a real
constraint on how Thrust A is executed, not a footnote.

If byte-identity fails outright, the honest fallback is pi_sec equality
(trace.security_projection), which is what the reachability claims actually
require. That is a weaker Stage 0 than the design writes, and adopting it is a
decision to record, not a substitution to make quietly.

  .venv/bin/python scripts/determinism_probe.py --model qwen2.5:7b --reps 5
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.request

OLLAMA = "http://localhost:11434/api/chat"

PROMPT = ("You are a home automation agent. The front door contact sensor reads "
          "'closed', measured 600 seconds ago. The current time is 23:04:15. "
          "Decide whether to arm the alarm, and explain your reasoning in exactly "
          "three sentences.")

LONG_PREFIX = ("Here is a log of recent home events.\n"
               + "\n".join(f"[{i:03d}] motion sensor hallway: clear at 22:{i%60:02d}"
                           for i in range(120))
               + "\n\n")


def chat(model: str, prompt: str, seed: int, temperature: float = 0.0,
         timeout: int = 300) -> tuple[str, float]:
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"temperature": temperature, "seed": seed},
    }
    req = urllib.request.Request(
        OLLAMA, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = json.loads(r.read())
    return out["message"]["content"], time.time() - t0


def h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def report(name: str, hashes: list[str], texts: list[str]) -> bool:
    uniq = sorted(set(hashes))
    ok = len(uniq) == 1
    print(f"\n  {name}")
    print(f"    {len(hashes)} runs -> {len(uniq)} distinct output(s): {uniq}")
    if not ok:
        a, b = texts[0], next(t for t in texts if h(t) != hashes[0])
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                lo = max(0, i - 60)
                print(f"    first divergence at char {i}:")
                print(f"      A: ...{a[lo:i]}[{x!r}]{a[i+1:i+40]}...")
                print(f"      B: ...{b[lo:i]}[{y!r}]{b[i+1:i+40]}...")
                break
        else:
            print(f"    one output is a prefix of the other "
                  f"(lengths {len(a)} vs {len(b)})")
    print(f"    -> {'DETERMINISTIC' if ok else 'NONDETERMINISTIC'}")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5:7b")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--seed", type=int, default=1234)
    a = ap.parse_args()

    print(f"determinism probe: model={a.model} seed={a.seed} T=0 reps={a.reps}")
    results: dict[str, bool] = {}

    # 1. back to back
    texts = [chat(a.model, PROMPT, a.seed)[0] for _ in range(a.reps)]
    results["back_to_back"] = report(
        "1. same prompt, same seed, back to back", [h(t) for t in texts], texts)

    # 2. interleaved with different traffic
    texts2 = []
    for _ in range(a.reps):
        texts2.append(chat(a.model, PROMPT, a.seed)[0])
        chat(a.model, "Name three colours.", a.seed + 999)   # perturbing traffic
    results["interleaved"] = report(
        "2. same prompt, same seed, interleaved with other traffic",
        [h(t) for t in texts2], texts2)

    # 3. after a long context
    long_prompt = LONG_PREFIX + PROMPT
    texts3 = [chat(a.model, long_prompt, a.seed)[0] for _ in range(a.reps)]
    results["long_context"] = report(
        "3. same prompt (long context), same seed", [h(t) for t in texts3], texts3)

    # 4. seed should be irrelevant at T=0
    texts4 = [chat(a.model, PROMPT, a.seed + i)[0] for i in range(a.reps)]
    results["seed_invariance"] = report(
        "4. same prompt, DIFFERENT seeds at T=0 (should still be identical)",
        [h(t) for t in texts4], texts4)

    print("\n  === verdict ===")
    for k, v in results.items():
        print(f"    {k:18s} {'ok' if v else 'FAILS'}")
    if all(results.values()):
        print("\n  Stage 0 byte-identity is achievable on this substrate.")
    elif results["back_to_back"]:
        print("\n  Deterministic in isolation only. Campaigns must not interleave,")
        print("  and the failing condition(s) above are a constraint on how Thrust A")
        print("  is executed -- not a footnote.")
    else:
        print("\n  Byte-identity is NOT achievable here. The honest fallback is")
        print("  pi_sec equality (trace.security_projection), which is what the")
        print("  reachability claims actually require. Record that as a decision.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
