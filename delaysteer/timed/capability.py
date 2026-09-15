#!/usr/bin/env python3
"""The capability record, and a writer that cannot silently corrupt a CSV.

    "One capability record per run" -- consolidated design, section 6.

The record states the exact powers, knowledge, budget and constraints the
adversary held. Its purpose is negative: **anything not in the record was not
assumed.** Without it, a reader cannot tell whether a 20/20 came from a
transport-constrained attacker with a 2-second budget or from an oracle with
none, and the two are not the same result.

Derived, not declared
---------------------
The scheduler fields are read off the `Sched` that actually ran
(`from_sched`), for the same reason `runtime.regime` is derived from the
temperature rather than passed alongside it: a hand-written record can disagree
with the execution, and the disagreement is invisible. `ordering_constraints`
and `permitted_actions` follow from the position, so they cannot contradict it.

Realism tiers (design section 6)
--------------------------------
  TIER_0  synthetic. Explicitly NO claim. Mechanism demonstration only.
  TIER_1  stock agent. The headline tier.
  TIER_2  production-like. Cross-platform / real framework.
A result without a tier is unreadable, so `tier` has no default.

The CSV problem this also solves
--------------------------------
These fields have to reach the results files, and the E-series CSVs are
append-only. Appending rows with more columns than the existing header silently
produces a file whose rows do not match its header -- which pandas will happily
read, misaligned. `ResultWriter` refuses: if the on-disk header differs from the
declared fields it writes a NEW versioned file instead and says so, which is the
additive-by-file discipline the frozen artefacts already follow.
"""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .sched import Budget, Observability, Position

TIER_0, TIER_1, TIER_2 = "tier0_synthetic", "tier1_stock_agent", "tier2_production_like"
TIERS = (TIER_0, TIER_1, TIER_2)

PREPLANNED, REACTIVE = "preplanned", "reactive"
ONE_SHOT, LEARNER = "one-shot", "learner"


@dataclass
class CapabilityRecord:
    """Section 2's machine-readable schema, plus tier and sampling regime."""

    attacker_position: str
    observations: str
    tier: str
    budget_delta_max: float | None = None
    budget_h_max: float | None = None
    online_revision: str = PREPLANNED
    cross_episode_memory: str = ONE_SHOT
    detector_family: str | None = None
    detector_threshold: float | None = None
    trusted_components: tuple[str, ...] = ("agent_runtime",)
    # sampling regime (delaysteer.runtime)
    model: str | None = None
    temperature: float | None = None
    seed: int | None = None
    sampling_regime: str | None = None
    model_digest: str | None = None
    notes: str = ""

    def __post_init__(self) -> None:
        if self.attacker_position not in Position.ALL:
            raise ValueError(f"unknown position {self.attacker_position!r}")
        if self.observations not in Observability.ORDER:
            raise ValueError(f"unknown observability {self.observations!r}")
        if self.tier not in TIERS:
            raise ValueError(f"unknown realism tier {self.tier!r}; a result "
                             f"without a tier cannot be read")

    # --- derived, so they cannot contradict the position ---

    @property
    def permitted_actions(self) -> str:
        return ("flow-head-only" if self.attacker_position == Position.A_T
                else "{HOLD, RELEASE, WAIT}")

    @property
    def ordering_constraints(self) -> str:
        return ("same-flow-FIFO" if self.attacker_position == Position.A_T
                else "cross-flow-reorder")

    @property
    def is_upper_bound(self) -> bool:
        """A_O and O_4 produce upper bounds, never practical rates."""
        return (self.attacker_position == Position.A_O
                or self.observations == Observability.O4)

    @property
    def claims_licensed(self) -> str:
        """What this record permits the result to be used for."""
        if self.is_upper_bound:
            return "upper-bound only (oracle position or oracle observability)"
        if self.tier == TIER_0:
            return "mechanism demonstration only (synthetic tier, no claim)"
        if self.sampling_regime == "resampled":
            return "rate claims with intervals; NOT reachability"
        if self.sampling_regime == "exact":
            return "reachability and rate claims"
        return "unspecified sampling regime -- declare it before quoting"

    @classmethod
    def from_sched(cls, sched, *, tier: str, sampling=None, **kw) -> "CapabilityRecord":
        """Read the scheduler fields off the run that produced the result."""
        s = {}
        if sampling is not None:
            s = dict(model=sampling.model, temperature=sampling.temperature,
                     seed=sampling.seed, sampling_regime=sampling.regime,
                     model_digest=sampling.model_digest)
        return cls(
            attacker_position=sched.position,
            observations=sched.observability,
            budget_delta_max=sched.budget.delta_max,
            budget_h_max=sched.budget.h_max,
            tier=tier, **s, **kw,
        )

    def as_row(self) -> dict[str, Any]:
        d = asdict(self)
        d["trusted_components"] = "|".join(self.trusted_components)
        d["permitted_actions"] = self.permitted_actions
        d["ordering_constraints"] = self.ordering_constraints
        d["upper_bound_only"] = self.is_upper_bound
        return d

    @classmethod
    def columns(cls) -> list[str]:
        probe = cls(attacker_position=Position.A_M,
                    observations=Observability.O1, tier=TIER_1)
        return list(probe.as_row())

    def summary(self) -> str:
        b = Budget(self.budget_delta_max, self.budget_h_max)
        return (f"{self.attacker_position}/{self.observations} {b} "
                f"[{self.tier}] -> {self.claims_licensed}")


class SchemaConflict(Exception):
    """The on-disk header does not match the declared fields."""


class ResultWriter:
    """Append-only CSV writer that refuses to misalign a file.

    A DictWriter with extrasaction='ignore' will happily append rows carrying
    columns the existing header lacks -- producing a file that loads without
    error and is wrong. That is precisely the class of silent corruption this
    project has already been bitten by, so on a header mismatch this writes a
    NEW versioned file rather than appending.
    """

    def __init__(self, path: str | Path, fields: Iterable[str],
                 *, allow_new_version: bool = True) -> None:
        self.path = Path(path)
        self.fields = list(fields)
        self.allow_new_version = allow_new_version
        self.effective_path = self._resolve()

    def _existing_header(self, p: Path) -> list[str] | None:
        if not p.exists() or p.stat().st_size == 0:
            return None
        with p.open() as fh:
            first = fh.readline().strip()
        return next(csv.reader([first])) if first else None

    def _resolve(self) -> Path:
        hdr = self._existing_header(self.path)
        if hdr is None or hdr == self.fields:
            return self.path
        if not self.allow_new_version:
            raise SchemaConflict(
                f"{self.path.name}: on-disk header has {len(hdr)} columns, "
                f"declared schema has {len(self.fields)}"
            )
        n = 2
        while True:
            cand = self.path.with_name(f"{self.path.stem}.v{n}{self.path.suffix}")
            h = self._existing_header(cand)
            if h is None or h == self.fields:
                added = [c for c in self.fields if c not in hdr]
                print(f"  [schema] {self.path.name} header differs "
                      f"(+{len(added)} cols: {', '.join(added[:6])}"
                      f"{'...' if len(added) > 6 else ''});"
                      f" writing to {cand.name} instead of misaligning it")
                return cand
            n += 1

    def write(self, rows: Iterable[dict]) -> Path:
        rows = list(rows)
        p = self.effective_path
        p.parent.mkdir(parents=True, exist_ok=True)
        new = not p.exists() or p.stat().st_size == 0
        with p.open("a", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=self.fields, extrasaction="ignore")
            if new:
                w.writeheader()
            for r in rows:
                w.writerow({k: r.get(k, "") for k in self.fields})
        return p


def rows_with_capability(rows: Iterable[dict], cap: CapabilityRecord) -> list[dict]:
    """Attach the record to every row, so no number travels without it."""
    c = cap.as_row()
    return [{**r, **c} for r in rows]
