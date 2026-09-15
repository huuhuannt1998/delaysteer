"""TemporalGuard (proposal §8, §10; RQ4).

Middleware at the tool-router gate seam that enforces temporal trust:
  * freshness contracts — high-impact actions require their critical input facts
    to be fresh (age <= the tool's declared freshness requirement);
  * two-phase commitment — immediately before a high-impact action (arm the alarm,
    report the house secure) it REVALIDATES the critical facts with fresh reads;
  * anti-thrashing — repeated blocked high-impact attempts escalate rather than
    silently looping, and a fail-open report cannot commit without fresh evidence.

Key idea (motivated by the Phase-2 cross-agent finding): agents do NOT reliably
honor freshness themselves, so enforcement lives at the gate, independent of the
planner.
"""

from .temporal_guard import GUARD_ABLATIONS, TemporalGuard, apply_ablation  # noqa: F401
from .order_witness import OrderEvent, OrderWitness, SourceState  # noqa: F401
from .contract_validator import (  # noqa: F401
    ActionContract,
    CriticalFact,
    FactRegistry,
    MUTATIONS,
    SCENARIO_PIVOT,
    ValidationReport,
    apply_mutation,
    baseline_contracts,
    default_registry,
    guard_contract,
    validate_contracts,
)
