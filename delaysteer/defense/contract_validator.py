"""Experiment C, Deliverable 1 — startup critical-fact CONTRACT validator.

TemporalGuard (\\S sec:defense) enforces, for every high-impact action, a
CRITICAL-FACT CONTRACT: which input facts must be fresh/valid at commit and on
what channel they are revalidated. The empirical guarantee rests on that contract
being *correct* — an omitted fact, a source-controlled timestamp trusted as
fresh, or a revalidation routed back through the compromised channel silently
reopens the delay attack (cf. \\S sec:eval:compromised, results/trust_matrix.csv).
Runtime testing exercises only the paths an attack happens to touch; a contract
bug on an untriggered path ships undetected. This module adds a BEFORE-DEPLOYMENT
gate.

It (1) models the contract (``ActionContract`` / ``CriticalFact``), (2) builds the
ground-truth fact/action REGISTRY from the live repo surface (``tools.registry``
risk levels, ``home`` ENTITIES, ``config.freshness_s``, the guard's ``REQUIRED``
map), (3) VALIDATES a submitted contract against that registry, and (4) defines
the 10 contract mutations used by ``run_contract_robustness.py``.

Validator checks -> ``ValidationReport{errors, warnings, per_action, safe_to_deploy}``:
  (a) every high-impact action has a contract;
  (b) each declared fact source (entity + semantic type) exists;
  (c) a fact marked pollable is actually pollable (active-poll supported);
  (d) the timestamp-trust class is declared AND matches reality
      (trusted vs source_controlled);
  (e) WARN when a fact has no independent revalidation source; ERROR when a
      source-controlled fact is revalidated through the same/compromised channel;
  (f) reject duplicate or contradictory contracts (same action, inconsistent
      requirements);
  (g) log uncovered high-impact actions.
``safe_to_deploy`` is False iff there is >= 1 error.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from typing import Any

from ..home.virtual_home import ENTITIES
from ..tools.registry import Risk, build_registry

# Timestamp-trust classes for a critical fact's affirmation time.
TRUSTED = "trusted"                 # platform-attested actuation ack (cannot be forged on-path)
SOURCE_CONTROLLED = "source_controlled"  # device/integration stamps its own affirmation time
TS_CLASSES = (TRUSTED, SOURCE_CONTROLLED)

# Revalidation channel for the two-phase commit re-read.
INDEPENDENT = "independent"    # a channel the adversary does not control (deliver-once A1 -> truth)
SAME_SOURCE = "same_source"    # the fact's own (possibly compromised) channel (A2 -> fooled)
REVAL_SOURCES = (INDEPENDENT, SAME_SOURCE)


# --------------------------------------------------------------------------- #
# Contract model
# --------------------------------------------------------------------------- #
@dataclass
class CriticalFact:
    """One critical input fact a high-impact action's correctness depends on."""

    key: str                              # belief/entity key: lock, contact, alarm, camera, leak
    expected: Any = None                  # str | tuple[str, ...] | None (None = presence-only)
    semantic_type: str = ""               # lock_state, contact_state, alarm_state, arrival, ...
    pollable: bool = True                 # declared: device answers a forced commit-time read
    timestamp_trust: str = TRUSTED        # trusted | source_controlled
    revalidation_source: str = INDEPENDENT  # independent | same_source
    necessary: bool = True                # False => intentionally over-specified (mutation 9)
    freshness_s: float | None = None      # per-fact budget override (else config.freshness_s)

    def as_reval_tuple(self) -> tuple[str, Any, str]:
        """The (key, expected, semantic_type) triple TemporalGuard revalidates on."""
        return (self.key, self.expected, self.semantic_type)


@dataclass
class ActionContract:
    """The critical-fact contract for one high-impact action."""

    action: str
    facts: list[CriticalFact] = field(default_factory=list)
    high_impact: bool = True

    def semantic_types(self) -> set[str]:
        return {f.semantic_type for f in self.facts}


# --------------------------------------------------------------------------- #
# Ground-truth fact/action registry (physical reality the contract is checked against)
# --------------------------------------------------------------------------- #
@dataclass
class FactRegistry:
    fact_sources: set[str]                 # valid entity keys (home ENTITIES)
    semantic_types: set[str]               # valid semantic types (config.freshness_s)
    pollable: dict[str, bool]              # semantic_type -> physically force-affirmable?
    timestamp_trust: dict[str, str]        # semantic_type -> trusted | source_controlled
    independent_source: dict[str, bool]    # semantic_type -> an independent reval channel exists?
    canonical_entity: dict[str, str]       # semantic_type -> the entity key that carries it
    required_facts: dict[str, set[str]]    # action -> minimal safe semantic-type set
    high_impact_actions: set[str]          # actions that MUST carry a contract
    budget_floor_s: float                  # a budget below this guarantees benign false-blocks
    budget_ceiling_s: dict[str, float]     # semantic_type -> calibrated benign max (loose above)


# Fact-class physics (modeling assumptions made explicit; cf. run_pollability_matrix).
#   pollable         : a status-attestable device answers a forced read (Matter/Z-Wave).
#   non-pollable     : a sleepy / on-change-only sensor (camera-motion, leak) cannot be
#                      force-affirmed; its newest affirmation is one keepalive old.
_POLLABLE = {"lock_state": True, "contact_state": True, "alarm_state": True,
             "arrival": False, "leak_state": False, "occupancy": False}
#   source_controlled: the device/integration stamps its own affirmation time, so a
#                      compromised integration can forge freshness (A2). These are exactly
#                      the channels the delay / compromised-channel attacks target.
#   trusted          : a platform-attested actuation ack the on-path adversary cannot forge.
_TS_TRUST = {"lock_state": TRUSTED, "alarm_state": TRUSTED,
             "contact_state": SOURCE_CONTROLLED, "arrival": SOURCE_CONTROLLED,
             "leak_state": SOURCE_CONTROLLED, "occupancy": SOURCE_CONTROLLED}
_CANONICAL_ENTITY = {"lock_state": "lock", "contact_state": "contact", "alarm_state": "alarm",
                     "arrival": "camera", "leak_state": "leak", "occupancy": "motion"}


def default_registry(config) -> FactRegistry:
    """Build the ground-truth registry from the live repo surface (not invented)."""
    from .temporal_guard import REQUIRED  # local import: REQUIRED is the guard's contract map

    reg = build_registry(automation_state=object())  # include automation-editing tools
    high = {n for n in reg.names() if reg.get(n).risk_level == Risk.HIGH}
    high.add("report_status")  # a secure=true report is itself a security-critical commit

    required = {action: {sem for (_k, _e, sem) in facts} for action, facts in REQUIRED.items()}
    sem_types = set(config.freshness_s)
    ceiling = {s: max(4.0 * config.freshness_s.get(s, 5.0), 6.0) for s in sem_types}
    return FactRegistry(
        fact_sources=set(ENTITIES),
        semantic_types=sem_types,
        pollable=dict(_POLLABLE),
        timestamp_trust=dict(_TS_TRUST),
        independent_source={s: True for s in sem_types},
        canonical_entity=dict(_CANONICAL_ENTITY),
        required_facts=required,
        high_impact_actions=high,
        budget_floor_s=config.base_latency_s + config.poll_rtt_s,
        budget_ceiling_s=ceiling,
    )


# --------------------------------------------------------------------------- #
# Baseline (correct) contract, derived from the guard's REQUIRED map + registry
# --------------------------------------------------------------------------- #
def baseline_contracts(config, registry: FactRegistry | None = None) -> list[ActionContract]:
    """The correct deployment contract: REQUIRED enriched with true fact metadata.

    This validates clean (safe_to_deploy=True, zero errors, zero warnings) and is
    the baseline the 10 mutations perturb.
    """
    from .temporal_guard import REQUIRED

    reg = registry or default_registry(config)
    out: list[ActionContract] = []
    for action, facts in REQUIRED.items():
        cf = [
            CriticalFact(
                key=key,
                expected=expected,
                semantic_type=sem,
                pollable=reg.pollable.get(sem, True),
                timestamp_trust=reg.timestamp_trust.get(sem, TRUSTED),
                revalidation_source=INDEPENDENT,
                necessary=True,
                freshness_s=config.freshness_s.get(sem),
            )
            for (key, expected, sem) in facts
        ]
        out.append(ActionContract(action=action, facts=cf, high_impact=True))
    return out


# --------------------------------------------------------------------------- #
# Validation report + validator
# --------------------------------------------------------------------------- #
@dataclass
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    per_action: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def safe_to_deploy(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {"errors": list(self.errors), "warnings": list(self.warnings),
                "per_action": copy.deepcopy(self.per_action), "safe_to_deploy": self.safe_to_deploy}


def validate_contracts(contracts: list[ActionContract], config,
                       registry: FactRegistry | None = None) -> ValidationReport:
    """Validate a submitted contract set before deployment (checks a-g)."""
    reg = registry or default_registry(config)
    rep = ValidationReport()

    # (f-duplicate) group contracts by action to detect duplicate/contradictory entries.
    by_action: dict[str, list[ActionContract]] = {}
    for c in contracts:
        by_action.setdefault(c.action, []).append(c)

    covered_actions = set(by_action)

    # (a) + (g): every high-impact action must be covered; log the uncovered ones.
    for action in sorted(reg.high_impact_actions - covered_actions):
        rep.errors.append(f"[coverage] high-impact action '{action}' has NO contract")
        rep.per_action.setdefault(action, {}).update(
            {"covered": False, "uncovered_high_impact": True, "errors": [], "warnings": []})

    # cross-action expected-value map, to catch contradictory requirements on a shared fact.
    shared_expected: dict[str, dict[str, Any]] = {}

    for action, entries in by_action.items():
        pa = rep.per_action.setdefault(action, {})
        pa.setdefault("errors", [])
        pa.setdefault("warnings", [])
        pa["covered"] = True
        pa["high_impact"] = action in reg.high_impact_actions

        def _err(msg: str) -> None:
            rep.errors.append(f"[{action}] {msg}")
            pa["errors"].append(msg)

        def _warn(msg: str) -> None:
            rep.warnings.append(f"[{action}] {msg}")
            pa["warnings"].append(msg)

        # (f) duplicate contract for the same action.
        if len(entries) > 1:
            _err(f"DUPLICATE contract ({len(entries)} entries for one action)")
            # ...and contradictory requirements between the duplicates.
            seen: dict[str, Any] = {}
            for c in entries:
                for f in c.facts:
                    if f.semantic_type in seen and seen[f.semantic_type] != f.expected:
                        _err(f"CONTRADICTORY requirement on {f.semantic_type}: "
                             f"{seen[f.semantic_type]!r} vs {f.expected!r}")
                    else:
                        seen[f.semantic_type] = f.expected

        facts = [f for c in entries for f in c.facts]
        pa["facts"] = [f.semantic_type for f in facts]
        covered_sems = {f.semantic_type for f in facts}

        # (a) completeness: the contract must cover the minimal required fact set.
        for sem in sorted(reg.required_facts.get(action, set()) - covered_sems):
            _err(f"MISSING required fact '{sem}' (omitted from contract)")

        for f in facts:
            # (b) declared fact source exists (entity + semantic type).
            if f.semantic_type not in reg.semantic_types:
                _err(f"unknown semantic type '{f.semantic_type}'")
            if f.key not in reg.fact_sources:
                _err(f"unknown fact source entity '{f.key}'")
            else:
                canon = reg.canonical_entity.get(f.semantic_type)
                if canon is not None and f.key != canon:
                    _err(f"fact '{f.semantic_type}' bound to WRONG entity "
                         f"'{f.key}' (expected '{canon}')")

            # (c) a fact marked pollable must actually be pollable.
            if f.pollable and reg.pollable.get(f.semantic_type) is False:
                _err(f"fact '{f.semantic_type}' declared POLLABLE but its class is "
                     f"non-pollable (active-poll cannot force-affirm it)")

            # (d) timestamp-trust class declared AND consistent with reality.
            if f.timestamp_trust not in TS_CLASSES:
                _err(f"fact '{f.semantic_type}' has undeclared/invalid timestamp-trust "
                     f"class {f.timestamp_trust!r}")
            else:
                real = reg.timestamp_trust.get(f.semantic_type)
                if real == SOURCE_CONTROLLED and f.timestamp_trust == TRUSTED:
                    _err(f"fact '{f.semantic_type}' timestamp declared TRUSTED but is "
                         f"source_controlled (a compromised integration can forge freshness)")

            # (e) independent revalidation source.
            if f.revalidation_source == SAME_SOURCE:
                if reg.timestamp_trust.get(f.semantic_type) == SOURCE_CONTROLLED:
                    _err(f"fact '{f.semantic_type}' revalidated through the SAME "
                         f"(compromised) channel — no independent recovery of ground truth")
                else:
                    _warn(f"fact '{f.semantic_type}' revalidated on the same source; "
                          f"prefer an independent channel")
            elif not reg.independent_source.get(f.semantic_type, True):
                _warn(f"fact '{f.semantic_type}' has NO independent revalidation source")

            # (e/robustness) over- and under-tight freshness budgets.
            budget = f.freshness_s if f.freshness_s is not None else config.freshness_s.get(f.semantic_type)
            if budget is not None:
                if budget < reg.budget_floor_s:
                    _warn(f"freshness budget for '{f.semantic_type}' is {budget:g}s < platform "
                          f"floor {reg.budget_floor_s:g}s (benign reads will false-block)")
                elif budget > reg.budget_ceiling_s.get(f.semantic_type, 6.0):
                    _warn(f"freshness budget for '{f.semantic_type}' is {budget:g}s > calibrated "
                          f"max {reg.budget_ceiling_s.get(f.semantic_type, 6.0):g}s (stale values pass)")

            # (9) over-specification: a fact not in the minimal required set.
            if not f.necessary or f.semantic_type not in reg.required_facts.get(action, set()):
                if f.semantic_type not in reg.required_facts.get(action, set()):
                    _warn(f"fact '{f.semantic_type}' is not required for '{action}' "
                          f"(unnecessary — over-specified contract)")

            # accumulate for cross-action contradiction detection.
            bucket = shared_expected.setdefault(f.semantic_type, {})
            bucket[action] = f.expected

    # (f) contradictory requirements on a fact shared across DIFFERENT actions.
    for sem, per in shared_expected.items():
        vals = {a: e for a, e in per.items() if e is not None}
        distinct = {repr(v) for v in vals.values()}
        if len(distinct) > 1:
            rep.warnings.append(
                f"[cross-action] fact '{sem}' has inconsistent expected values across "
                f"actions: {vals}")

    return rep


# --------------------------------------------------------------------------- #
# The 10 contract mutations (Deliverable 2 payload; kept here so validator tests
# and the harness share one definition).
# --------------------------------------------------------------------------- #
# Each scenario mutates ONE pivotal action + one pivotal (attack-relevant) fact.
SCENARIO_PIVOT: dict[str, dict[str, str]] = {
    "secure-house": {"action": "report_status", "semantic": "contact_state", "entity": "contact",
                     "wrong_value": "on"},   # correct expected is "off" (closed)
    "access":       {"action": "grant_access", "semantic": "arrival", "entity": "camera",
                     "wrong_value": "off"},  # correct expected is "on" (present)
    "confirmation": {"action": "grant_access", "semantic": "arrival", "entity": "camera",
                     "wrong_value": "off"},
    "automation":   {"action": "propose_automation_edit", "semantic": "contact_state",
                     "entity": "contact", "wrong_value": "on"},
}

MUTATIONS: list[tuple[int, str, str]] = [
    (0, "baseline", "the correct, unmutated contract"),
    (1, "omit_required_fact", "drop the attack-relevant required fact"),
    (2, "replace_expected_value", "require the wrong expected value for the pivotal fact"),
    (3, "loose_budget", "freshness budget far above the calibrated benign max"),
    (4, "tight_budget", "freshness budget below the platform latency floor"),
    (5, "wrong_entity", "bind the pivotal fact to the wrong entity"),
    (6, "nonpollable_as_pollable", "declare a non-pollable fact as pollable"),
    (7, "untrusted_ts_as_trusted", "treat a source-controlled timestamp as trusted"),
    (8, "compromised_reval", "revalidate the pivotal fact through the compromised channel"),
    (9, "unnecessary_fact", "add a fact the action does not require"),
    (10, "inconsistent_requirements", "duplicate the action with a contradictory requirement"),
]

# Budget sentinels for mutations 3/4.
_LOOSE_BUDGET_S = 1.0e6
_TIGHT_BUDGET_S = 1.0e-4


@dataclass
class MutationMeta:
    id: int
    name: str
    description: str
    pivotal_action: str
    pivotal_semantic: str
    uses_compromised_channel: bool = False
    budget_override: tuple[str, float] | None = None  # (semantic_type, budget_s) for cfg


def _pivotal_fact(contracts: list[ActionContract], action: str, sem: str) -> CriticalFact | None:
    for c in contracts:
        if c.action == action:
            for f in c.facts:
                if f.semantic_type == sem:
                    return f
    return None


def apply_mutation(scenario: str, mut_id: int, config,
                   registry: FactRegistry | None = None
                   ) -> tuple[list[ActionContract], MutationMeta]:
    """Return (mutated contract set, mutation metadata) for a (scenario, mutation)."""
    reg = registry or default_registry(config)
    contracts = baseline_contracts(config, reg)
    pivot = SCENARIO_PIVOT[scenario]
    action, sem, entity = pivot["action"], pivot["semantic"], pivot["entity"]
    name = next(n for (i, n, _d) in MUTATIONS if i == mut_id)
    desc = next(d for (i, _n, d) in MUTATIONS if i == mut_id)
    meta = MutationMeta(id=mut_id, name=name, description=desc,
                        pivotal_action=action, pivotal_semantic=sem)

    ac = next(c for c in contracts if c.action == action)

    if mut_id == 0:  # baseline
        return contracts, meta

    if mut_id == 1:  # omit the attack-relevant required fact
        ac.facts = [f for f in ac.facts if f.semantic_type != sem]
        return contracts, meta

    if mut_id == 2:  # replace the expected value with a wrong one
        for i, f in enumerate(ac.facts):
            if f.semantic_type == sem:
                ac.facts[i] = replace(f, expected=pivot["wrong_value"])
        return contracts, meta

    if mut_id == 3:  # overly loose budget
        for i, f in enumerate(ac.facts):
            if f.semantic_type == sem:
                ac.facts[i] = replace(f, freshness_s=_LOOSE_BUDGET_S)
        meta.budget_override = (sem, _LOOSE_BUDGET_S)
        return contracts, meta

    if mut_id == 4:  # overly tight budget
        for i, f in enumerate(ac.facts):
            if f.semantic_type == sem:
                ac.facts[i] = replace(f, freshness_s=_TIGHT_BUDGET_S)
        meta.budget_override = (sem, _TIGHT_BUDGET_S)
        return contracts, meta

    if mut_id == 5:  # bind to the wrong entity (keep the semantic type)
        wrong = "leak" if entity != "leak" else "motion"
        for i, f in enumerate(ac.facts):
            if f.semantic_type == sem:
                ac.facts[i] = replace(f, key=wrong)
        return contracts, meta

    if mut_id == 6:  # declare a non-pollable fact as pollable
        for i, f in enumerate(ac.facts):
            if f.semantic_type == sem:
                ac.facts[i] = replace(f, pollable=True)
        return contracts, meta

    if mut_id == 7:  # treat a source-controlled timestamp as trusted
        for i, f in enumerate(ac.facts):
            if f.semantic_type == sem:
                ac.facts[i] = replace(f, timestamp_trust=TRUSTED)
        return contracts, meta

    if mut_id == 8:  # revalidate through the compromised channel
        for i, f in enumerate(ac.facts):
            if f.semantic_type == sem:
                ac.facts[i] = replace(f, revalidation_source=SAME_SOURCE)
        meta.uses_compromised_channel = True
        return contracts, meta

    if mut_id == 9:  # add an unnecessary (presence-only, benignly-satisfied) fact
        extra_entity = "leak" if entity != "leak" else "motion"
        extra_sem = "leak_state" if extra_entity == "leak" else "occupancy"
        ac.facts.append(CriticalFact(
            key=extra_entity, expected=None, semantic_type=extra_sem,
            pollable=reg.pollable.get(extra_sem, True),
            timestamp_trust=reg.timestamp_trust.get(extra_sem, TRUSTED),
            revalidation_source=INDEPENDENT, necessary=False,
            freshness_s=config.freshness_s.get(extra_sem)))
        return contracts, meta

    if mut_id == 10:  # duplicate the action with a contradictory requirement
        dup_facts = [replace(f, expected=pivot["wrong_value"]) if f.semantic_type == sem
                     else replace(f) for f in ac.facts]
        contracts.append(ActionContract(action=action, facts=dup_facts, high_impact=True))
        return contracts, meta

    raise ValueError(f"unknown mutation id {mut_id}")


def guard_contract(contracts: list[ActionContract], action: str) -> dict[str, list[tuple]]:
    """Project the (possibly mutated) contract to the TemporalGuard reval map for `action`.

    Duplicates (mutation 10) resolve to the FIRST occurrence, so the runtime guard
    enforces the original requirement while the validator flags the duplicate at startup.
    """
    for c in contracts:
        if c.action == action:
            return {action: [f.as_reval_tuple() for f in c.facts]}
    return {action: []}
