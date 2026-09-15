"""A small native function-calling agent loop, shared by Experiments E4-E7.

Every one of those experiments needs the same three things: a local model that emits real
`tool_calls`, a dispatcher that executes them against a controllable world, and a transcript
detailed enough to score *which tool was chosen and when*. The v1 harnesses each grew their
own copy of that loop; this is one implementation so the four new studies disagree about
nothing except the thing each is measuring.

Two details that cost real debugging time in this project and are handled here:

* **qwen3 emits thinking tokens.** A short `num_predict` truncates the answer to an empty
  string, which reads as "the model refused" when it merely never got out of its preamble.
  `strip_think` removes the block, and callers should leave enough budget for it.
* **Not every local model can do native function calling.** mistral:7b writes pseudo-calls as
  prose and deepseek's Ollama refuses the `tools` parameter outright. `text_fallback_calls`
  parses the prose form so a capability gap is recorded as a capability gap rather than
  silently scored as "did not escalate".
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

OLLAMA = "http://localhost:11434/api/chat"

# How long Ollama should keep a model resident after a request. Override with
# DELAYSTEER_KEEP_ALIVE if another workload needs the VRAM back promptly.
KEEP_ALIVE = os.environ.get("DELAYSTEER_KEEP_ALIVE", "30m")

THINK_RE = re.compile(r"<think>.*?</think>", re.S | re.I)
# A pseudo-call as weaker models write it, e.g.  verify_contact({"entity": "front_door"})
PSEUDO_RE = re.compile(r"\b([a-z_][a-z0-9_]{2,40})\s*\(\s*(\{.*?\})?\s*\)", re.S)


def strip_think(s: str) -> str:
    return THINK_RE.sub(" ", s or "").strip()


def text_fallback_calls(content: str, known: set[str]) -> list[dict]:
    """Recover tool calls from prose for models that cannot emit native ones."""
    out = []
    for m in PSEUDO_RE.finditer(strip_think(content)):
        name = m.group(1)
        if name not in known:
            continue
        raw = m.group(2)
        try:
            args = json.loads(raw) if raw else {}
        except Exception:
            args = {}
        out.append({"function": {"name": name, "arguments": args}})
    return out


@dataclass
class ToolCall:
    turn: int
    name: str
    args: dict
    result: Any
    at: float                       # seconds since the run started


@dataclass
class Run:
    model: str
    calls: list[ToolCall] = field(default_factory=list)
    final_text: str = ""
    turns: int = 0
    native_fc: bool = True
    error: str = ""
    started: float = 0.0
    empty_retries: int = 0          # transient turns that returned neither text nor a call

    @property
    def call_names(self) -> list[str]:
        return [c.name for c in self.calls]

    def first_index(self, name: str) -> int | None:
        for i, c in enumerate(self.calls):
            if c.name == name:
                return i
        return None


def _post(body: dict, timeout: int) -> dict:
    req = urllib.request.Request(
        OLLAMA, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def run_agent(
    *,
    model: str,
    system: str,
    user: str,
    tools: list[dict],
    dispatch: Callable[[str, dict], Any],
    max_turns: int = 8,
    timeout: int = 300,
    temperature: float = 0.0,
    seed: int | None = None,
    no_think: bool = True,
) -> Run:
    """Drive one episode. ``dispatch(name, args)`` executes a tool and returns its result.

    The loop stops when the model stops asking for tools, or at ``max_turns``. Every call is
    timestamped relative to the start of the run so a caller can compute the speculative
    window (time from the last confirmed read to the first high-impact call) without
    re-instrumenting anything.
    """
    known = {t["function"]["name"] for t in tools}
    # qwen3 reasons inside <think> blocks and will happily spend the entire token budget
    # there, returning empty content and no tool calls -- which scores as "the agent did
    # nothing" when it merely never finished its preamble. The `/no_think` sentinel is the
    # same switch scripts/sh_toctou_eval.py uses.
    sys_msg = system + (" /no_think" if no_think else "")
    msgs = [{"role": "system", "content": sys_msg}, {"role": "user", "content": user}]
    run = Run(model=model, started=time.time())
    # 2048 leaves room for a <think> preamble AND an answer. At 1024 qwen3 intermittently
    # spent the whole budget thinking and returned an empty turn, which scored as "the agent
    # did nothing" -- a harness artefact, not a behaviour.
    opts: dict[str, Any] = {"temperature": temperature, "num_predict": 2048}
    if seed is not None:
        opts["seed"] = seed

    for turn in range(1, max_turns + 1):
        run.turns = turn
        # Pin the model resident between turns and between runs. Without this
        # Ollama unloads on its default idle timer, so a sweep pays a ~10 GB
        # reload per episode -- which dominated wall clock on the 14b panel and,
        # worse, is the exact churn the reproducibility disclaimer blames for
        # seeded output not surviving ("server restarts / model reloads").
        # Residency changes nothing about sampling; it only stops the reload.
        body = {"model": model, "messages": msgs, "stream": False,
                "options": opts, "tools": tools,
                "keep_alive": KEEP_ALIVE}
        try:
            d = _post(body, timeout)
        except urllib.error.HTTPError as e:
            # Some Ollama builds reject the `tools` parameter for certain models.
            if run.native_fc:
                run.native_fc = False
                try:
                    d = _post({k: v for k, v in body.items() if k != "tools"}, timeout)
                except Exception as e2:
                    run.error = f"{type(e2).__name__}: {e2}"
                    return run
            else:
                run.error = f"HTTP {e.code}"
                return run
        except Exception as e:
            run.error = f"{type(e).__name__}: {e}"
            return run

        msg = d.get("message", {}) or {}
        content = msg.get("content", "") or ""
        tcs = msg.get("tool_calls") or []
        if not tcs:
            recovered = text_fallback_calls(content, known)
            if recovered:
                run.native_fc = False
                tcs = recovered

        if not tcs:
            cleaned = strip_think(content)
            # An empty turn (no text, no calls) is a truncation transient, not a decision.
            # Retry it a bounded number of times and record how often it happened, so the
            # rate is visible in the artefact rather than silently absorbed.
            if not cleaned and run.empty_retries < 2:
                run.empty_retries += 1
                continue
            run.final_text = cleaned
            return run

        msgs.append({"role": "assistant", "content": content, "tool_calls": tcs})
        for tc in tcs:
            fn = tc.get("function", {}) or {}
            name = fn.get("name", "")
            args = fn.get("arguments", {}) or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            try:
                result = dispatch(name, args)
            except Exception as e:
                result = {"error": f"{type(e).__name__}: {e}"}
            run.calls.append(ToolCall(turn=turn, name=name, args=args, result=result,
                                      at=time.time() - run.started))
            msgs.append({"role": "tool", "name": name,
                         "content": json.dumps(result, default=str)})

    run.final_text = "(max turns reached)"
    return run


def tool(name: str, description: str, properties: dict, required: list[str]) -> dict:
    """Build one OpenAI-style tool definition."""
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties, "required": required}}}
