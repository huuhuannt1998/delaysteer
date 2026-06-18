"""Mission mis_01KT2E4P — A1/B3 validation harness.

Drives qwen3:14b (local Ollama) through all FOUR scenario families on the
deterministic VIRTUAL target, benign + attack, plus an A2 guard spot-check on a
non-bedtime family. Reports per-family completion (no loop / no JSON-empty
failure), the verdict, and the step count read back from the written trace.

This is a one-off Mission-1 validation, NOT a matrix run (no cloud / live HA).
"""

from __future__ import annotations

import json
import time
import traceback
from pathlib import Path

from delaysteer.run_attack import run_once
from delaysteer.run_automation import run_auto
from delaysteer.run_confirm import run_confirm
from delaysteer.run_repair import run_repair

MODEL = "qwen3:14b"


def _trace_stats(prefix: str, label: str) -> tuple[int, bool]:
    """(plan_steps, has_final_report) read from the trace — backbone-independent."""
    p = Path("traces") / f"{prefix}_{label}.jsonl"
    if not p.exists():
        return (0, False)
    steps = reported = 0
    has_report = False
    with p.open() as f:
        next(f, None)  # header line
        for line in f:
            rec = json.loads(line)
            if rec.get("kind") == "reason":
                steps += 1
            if rec.get("kind") == "response":
                has_report = True
    return (steps, has_report)


def _run(desc, prefix, label, fn):
    t0 = time.time()
    try:
        r = fn()
        steps, has_report = _trace_stats(prefix, label)
        looped = steps >= 24
        ok = has_report and not looped
        r2 = dict(r)
        r2.update(_desc=desc, _ok=ok, _steps=steps, _report=has_report,
                  _looped=looped, _err=None, _secs=round(time.time() - t0, 1))
        return r2
    except Exception as e:  # JSON-empty / parse / loop-to-error
        return {"_desc": desc, "_ok": False, "_err": f"{type(e).__name__}: {e}",
                "_tb": traceback.format_exc().splitlines()[-1], "_secs": round(time.time() - t0, 1)}


def main() -> int:
    L = dict(model=MODEL, backbone_override="ollama")
    runs = [
        ("bedtime benign",  "attack",  "v_bed_benign",
         lambda: run_once("virtual", "ollama", False, "lock_timeout", False, "v_bed_benign", model=MODEL)),
        ("bedtime attack/lock_timeout", "attack", "v_bed_lt",
         lambda: run_once("virtual", "ollama", False, "lock_timeout", True, "v_bed_lt", model=MODEL)),
        ("bedtime attack/contact_contra", "attack", "v_bed_cc",
         lambda: run_once("virtual", "ollama", False, "contact_contradiction", True, "v_bed_cc", model=MODEL)),
        ("access benign",   "repair",  "v_acc_benign",
         lambda: run_repair("virtual", True,  False, "none", False, "v_acc_benign", **L)),
        ("access attack",   "repair",  "v_acc_attack",
         lambda: run_repair("virtual", False, True,  "none", False, "v_acc_attack", **L)),
        ("access attack+FULL guard (A2)", "repair", "v_acc_def",
         lambda: run_repair("virtual", False, True,  "full", False, "v_acc_def", **L)),
        ("confirmation benign", "confirm", "v_cf_benign",
         lambda: run_confirm("virtual", True,  False, "none", False, "v_cf_benign", **L)),
        ("confirmation attack", "confirm", "v_cf_attack",
         lambda: run_confirm("virtual", False, True,  "none", False, "v_cf_attack", **L)),
        ("automation benign", "auto", "v_au_benign",
         lambda: run_auto("virtual", False, "none", "v_au_benign", **L)),
        ("automation attack", "auto", "v_au_attack",
         lambda: run_auto("virtual", True,  "none", "v_au_attack", **L)),
    ]

    results = []
    for desc, prefix, label, fn in runs:
        print(f"... running: {desc}", flush=True)
        r = _run(desc, prefix, label, fn)
        results.append(r)
        verdict = ("ERR " + r["_err"]) if r.get("_err") else (
            f"viol={r.get('violation')} secure={r.get('secure_claim')} "
            f"granted={r.get('granted')} pred={r.get('predicate_enabled')} "
            f"probes={r.get('probes')} blocked={r.get('blocked')}")
        print(f"    -> ok={r['_ok']} steps={r.get('_steps')} {r.get('_secs')}s | {verdict}", flush=True)

    print("\n==== SUMMARY ====")
    all_ok = all(r["_ok"] for r in results)
    for r in results:
        print(f"  [{'PASS' if r['_ok'] else 'FAIL'}] {r['_desc']}: "
              + (r["_err"] if r.get("_err") else
                 f"viol={r.get('violation')} steps={r.get('_steps')}"))
    print(f"\nALL FOUR FAMILIES COMPLETE ON VIRTUAL UNDER {MODEL}: {all_ok}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
