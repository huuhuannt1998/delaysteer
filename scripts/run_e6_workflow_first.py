#!/usr/bin/env python3
"""E6 -- workflow-first external evaluation: sample first, annotate blind, then attack.

Reviewer objection: "the authors defined the gadget taxonomy and then built scenarios
that instantiate it," which makes the evaluation look constructive rather than
ecological. The repair the plan asks for is a reversal of the experimental causality,
and the reversal is procedural, so this script enforces it in three phases that cannot
see each other's outputs:

  PHASE 1  SAMPLE.    Draw a pseudo-random sample from the whole externally authored
                      blueprint corpus under a recorded seed -- NOT from the rows the
                      earlier census flagged. The sample frame is every blueprint with
                      retrievable YAML. Sampling before annotation is the point: the
                      selection cannot depend on any attack outcome, because none exists
                      yet.
  PHASE 2  ANNOTATE.  Label each sampled workflow on the five fields the plan names,
                      from the YAML alone, by deterministic published rules. Written to
                      the annotation CSV and HASHED before phase 3 runs, so the
                      pre-attack annotation is fixed on disk and any later edit is
                      detectable.
  PHASE 3  AGENTIZE.  Map the sampled workflows onto the agent tool surface where the
                      mapping is faithful, run honest and delayed arms, and label the
                      outcome with the plan's seven-row taxonomy. Workflows that cannot
                      be faithfully agentized are reported as NOT AGENTIZED with the
                      reason, never silently dropped -- a corpus study that quietly
                      discards what does not fit re-introduces exactly the selection
                      effect this experiment exists to remove.

Phases 1-2 are deterministic and need no model. Phase 3 needs a planner and is opt-in
(--agentize), because on this machine it queues behind the other experiments.

  results/e6_workflow_first_sample.csv      phase 1: the frame, the seed, what was drawn
  results/e6_workflow_first_annotation.csv  phase 2: the five fields, per workflow
  results/e6_workflow_first_outcomes.csv    phase 3: the outcome taxonomy, per arm
  results/e6_workflow_first_REPORT.md

  .venv/bin/python scripts/run_e6_workflow_first.py --n 40 --seed 20260910
  .venv/bin/python scripts/run_e6_workflow_first.py --n 40 --seed 20260910 --agentize --repeats 6
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CACHE = ROOT / "results" / "prevalence_cache"
CORPUS = ROOT / "results" / "prevalence_corpus.csv"

# The plan's outcome taxonomy, in its order.
OUTCOMES = (
    "no_meaningful_effect",       # normal completion
    "fail_closed",                # safe non-completion
    "stale_state_failure",        # predicate-level temporal failure, rule-like
    "planner_recovery_steering",  # fallback branch selected
    "inference_driven_steering",  # semantic interpretation of missing/late evidence
    "policy_adaptation",          # persistent configuration change
    "invariant_violation",        # unsafe commitment
)


class _L(yaml.SafeLoader):
    pass


def _tag(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {"__tag__": suffix, "v": loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {"__tag__": suffix, "v": loader.construct_sequence(node)}
    return {"__tag__": suffix, "v": loader.construct_mapping(node)}


_L.add_multi_constructor("!", _tag)


def _flat(obj, out=None):
    """Every scalar in the document, as text, for rule matching."""
    out = [] if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            _flat(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _flat(v, out)
    else:
        out.append(str(obj))
    return out


# --------------------------------------------------------------------------- #
# PHASE 2 -- the five annotation fields, deterministic rules over the YAML
# --------------------------------------------------------------------------- #
_SENSORY = re.compile(r"\b(binary_sensor|sensor|device_tracker|person|lock|cover|"
                      r"alarm_control_panel|climate|camera)\b")
_AGE = re.compile(r"last_changed|last_updated|last_reported|as_timestamp|now\(\)\s*-|"
                  r"\bage\b|timedelta", re.I)
_TIMEOUT = re.compile(r"\bwait_for_trigger\b|\bwait_template\b|\btimeout\b|"
                      r"\bcontinue_on_timeout\b", re.I)
_RECOVERY = re.compile(r"\bcontinue_on_error\b|\bdefault\b|\belse\b|\brepeat\b|\bretry\b", re.I)
_EDIT = re.compile(r"automation\.turn_off|automation\.turn_on|automation\.reload|"
                   r"input_boolean\.turn_(on|off)|script\.reload|"
                   r"homeassistant\.(turn_off|turn_on)", re.I)
_HIGH_IMPACT = re.compile(r"lock\.(unlock|open)|cover\.(open_cover|set_cover_position|toggle)|"
                          r"alarm_control_panel\.alarm_disarm|valve\.open_valve|"
                          r"switch\.turn_on", re.I)


def annotate(topic_id: str, doc: dict) -> dict:
    """The five fields the plan names, from the YAML alone, before any attack."""
    text = " ".join(_flat(doc))
    facts = sorted({m for m in re.findall(
        r"\b(?:binary_sensor|sensor|lock|cover|alarm_control_panel|device_tracker|person)\b",
        text)})
    has_hi = bool(_HIGH_IMPACT.search(text))
    return {
        "topic_id": topic_id,
        # 1. the critical physical facts the workflow reads
        "critical_fact_domains": "|".join(facts),
        "n_critical_fact_domains": len(facts),
        "reads_sensor_state": int(bool(_SENSORY.search(text))),
        # 2. is the age of any of them explicitly bounded?
        "age_bounded": int(bool(_AGE.search(text))),
        # 3. does a timeout trigger a recovery path?
        "timeout_present": int(bool(_TIMEOUT.search(text))),
        "timeout_triggers_recovery": int(bool(_TIMEOUT.search(text) and _RECOVERY.search(text))),
        # 4. may an agent synthesize a fallback? (the workflow leaves an unhandled branch)
        "fallback_latitude": int(bool(_TIMEOUT.search(text)) and not _AGE.search(text)),
        # 5. is policy/automation editing permitted by the workflow's own action set?
        "policy_edit_permitted": int(bool(_EDIT.search(text))),
        "high_impact_action": int(has_hi),
        "n_yaml_bytes": len(text),
    }


def load_frame() -> list[dict]:
    rows = {r["topic_id"]: r for r in csv.DictReader(open(CORPUS))}
    frame = []
    for p in sorted(CACHE.glob("*.yaml")):
        tid = p.stem
        if tid in rows:
            frame.append({"topic_id": tid, "title": rows[tid]["title"], "path": str(p)})
    return frame


def phase1(n: int, seed: int) -> tuple[list[dict], dict]:
    frame = load_frame()
    rng = random.Random(seed)
    drawn = rng.sample(frame, min(n, len(frame)))
    meta = {"frame_size": len(frame), "n_drawn": len(drawn), "seed": seed,
            "sampling": "uniform without replacement over every blueprint with retrievable YAML",
            "selection_depends_on_attack_outcome": False}
    return drawn, meta


def phase2(drawn: list[dict]) -> list[dict]:
    out = []
    for d in drawn:
        try:
            doc = yaml.load(open(d["path"]).read(), Loader=_L) or {}
        except Exception as exc:
            out.append({"topic_id": d["topic_id"], "parse_error": exc.__class__.__name__,
                        "critical_fact_domains": "", "n_critical_fact_domains": 0,
                        "reads_sensor_state": 0, "age_bounded": 0, "timeout_present": 0,
                        "timeout_triggers_recovery": 0, "fallback_latitude": 0,
                        "policy_edit_permitted": 0, "high_impact_action": 0, "n_yaml_bytes": 0})
            continue
        a = annotate(d["topic_id"], doc)
        a["parse_error"] = ""
        a["title"] = d["title"]
        out.append(a)
    return out


# --------------------------------------------------------------------------- #
# PHASE 3a -- eligibility for faithful agentization on this tool surface
# --------------------------------------------------------------------------- #
# The agent tool surface models a front-door contact, a lock, an alarm panel, an
# arrival camera, a leak sensor and an automation-edit action. A sampled workflow can
# be agentized FAITHFULLY only if the fact it gates on and the action it reaches both
# exist there. Anything else would need a tool written for that workflow, which would
# put the experimenter back in the loop -- the exact thing this experiment removes.
_SURFACE_FACTS = {"binary_sensor", "lock", "alarm_control_panel", "person", "device_tracker"}


def eligibility(ann_row: dict) -> dict:
    tid = ann_row["topic_id"]
    facts = set((ann_row.get("critical_fact_domains") or "").split("|")) - {""}
    if ann_row.get("parse_error"):
        return {"topic_id": tid, "agentizable": 0, "reason": "yaml parse error", "facts": ""}
    if not ann_row.get("reads_sensor_state"):
        return {"topic_id": tid, "agentizable": 0, "reason": "no sensor-gated decision",
                "facts": "|".join(sorted(facts))}
    if not ann_row.get("high_impact_action"):
        return {"topic_id": tid, "agentizable": 0,
                "reason": "no high-impact action to commit", "facts": "|".join(sorted(facts))}
    if not (facts & _SURFACE_FACTS):
        return {"topic_id": tid, "agentizable": 0,
                "reason": "gating fact outside the tool surface", "facts": "|".join(sorted(facts))}
    return {"topic_id": tid, "agentizable": 1, "reason": "", "facts": "|".join(sorted(facts))}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--n", type=int, default=40, help="workflows to draw")
    ap.add_argument("--seed", type=int, default=20260910)
    ap.add_argument("--agentize", action="store_true", help="run phase 3 (needs a planner)")
    ap.add_argument("--repeats", type=int, default=6)
    ap.add_argument("--model", default="qwen3:14b")
    ap.add_argument("--out", default="results/e6_workflow_first")
    a = ap.parse_args()

    drawn, meta = phase1(a.n, a.seed)
    with open(f"{a.out}_sample.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["topic_id", "title", "path"])
        w.writeheader()
        w.writerows(drawn)

    ann = phase2(drawn)
    ann_path = f"{a.out}_annotation.csv"
    with open(ann_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(ann[0]))
        w.writeheader()
        w.writerows(ann)
    digest = hashlib.sha256(Path(ann_path).read_bytes()).hexdigest()

    # Prevalence of each annotated property in the RANDOM sample -- this is the
    # ecological statement, and it is fixed before any attack is run.
    def rate(k):
        n = sum(1 for r in ann if r.get(k) == 1)
        return f"{n}/{len(ann)}"

    meta["annotation_sha256"] = digest
    meta["rates"] = {k: rate(k) for k in
                     ("reads_sensor_state", "age_bounded", "timeout_present",
                      "timeout_triggers_recovery", "fallback_latitude",
                      "policy_edit_permitted", "high_impact_action")}
    # The claim the paper makes is about the INTERSECTION, and the two marginals do not
    # give it: a workflow can bound an age somewhere without being sensor-gated. Derive it
    # here so the number cannot be read off the wrong row.
    sg = [r for r in ann if r.get("reads_sensor_state") == 1]
    meta["rates"]["age_bounded_AMONG_sensor_gated"] = \
        f"{sum(1 for r in sg if r.get('age_bounded') == 1)}/{len(sg)}"
    with open(f"{a.out}_meta.json", "w") as fh:
        json.dump(meta, fh, indent=2)

    print(f"=== E6 phase 1-2: sampled {len(drawn)} of {meta['frame_size']} "
          f"(seed {a.seed}) ===")
    for k, v in meta["rates"].items():
        print(f"  {k:28s} {v}")
    print(f"  annotation sha256 {digest[:16]}...  (fixed before any attack)")

    # PHASE 3a -- eligibility, deterministic. Which sampled workflows can be agentized
    # FAITHFULLY on this tool surface, and for the rest, why not. Reported in full so a
    # reader can see the attrition instead of only the survivors.
    elig = [eligibility(r) for r in ann]
    with open(f"{a.out}_eligibility.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(elig[0]))
        w.writeheader()
        w.writerows(elig)
    n_elig = sum(1 for e in elig if e["agentizable"] == 1)
    reasons: dict[str, int] = {}
    for e in elig:
        if e["agentizable"] == 0:
            reasons[e["reason"]] = reasons.get(e["reason"], 0) + 1
    meta["eligible"] = f"{n_elig}/{len(elig)}"
    meta["ineligible_reasons"] = reasons
    with open(f"{a.out}_meta.json", "w") as fh:
        json.dump(meta, fh, indent=2)
    print(f"  agentizable on this tool surface  {n_elig}/{len(elig)}")
    for k, v in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print(f"    not agentizable: {k:34s} {v}")

    if a.agentize:
        print("  phase 3b (run the eligible workflows under delay) is NOT implemented in "
              "this script; the eligible set is in the eligibility CSV.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
