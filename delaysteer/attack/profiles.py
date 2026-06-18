"""Delay profiles (proposal §8).

Each profile is delay-ONLY: it returns extra seconds to add to an observation's
arrival time, and (for the contradiction profile) may substitute a STALE-BUT-
TRUTHFUL prior value — never a forged one. All profiles are deterministic
(seeded) so attacks replay exactly.
"""

from __future__ import annotations

from dataclasses import dataclass


class DelayProfile:
    name = "none"

    def extra_delay(self, n: int) -> float:
        """Extra seconds to add to the n-th affected observation (0-indexed)."""
        return 0.0

    def override_value(self, value: str, n: int) -> str | None:
        """Optionally return a stale-but-truthful value to deliver instead."""
        return None


@dataclass
class FixedDelay(DelayProfile):
    seconds: float
    name: str = "fixed"

    def extra_delay(self, n: int) -> float:
        return self.seconds


@dataclass
class Jitter(DelayProfile):
    base: float
    jitter: float
    seed: int = 1
    name: str = "jitter"

    def extra_delay(self, n: int) -> float:
        # Deterministic pseudo-random in [0,1) via a small LCG (no RNG calls).
        x = (self.seed * 1103515245 + 12345 + n * 2654435761) & 0x7FFFFFFF
        frac = (x % 10_000) / 10_000.0
        return self.base + self.jitter * frac


@dataclass
class BurstDelay(DelayProfile):
    seconds: float
    start_n: int = 0
    count: int = 2
    name: str = "burst"

    def extra_delay(self, n: int) -> float:
        return self.seconds if self.start_n <= n < self.start_n + self.count else 0.0


@dataclass
class TimeoutCrossing(DelayProfile):
    """Guarantees the observation arrives just past the recovery timeout."""

    timeout_s: float
    margin: float = 1.0
    name: str = "timeout_crossing"

    def extra_delay(self, n: int) -> float:
        return self.timeout_s + self.margin


@dataclass
class LateArrivingContradiction(DelayProfile):
    """Deliver a stale-but-truthful prior value for `hold` reads, then the truth.

    Models a truthful observation that arrives late: the agent keeps seeing the
    old (correct-when-generated) value, acts on it, and the new value lands too
    late to change the decision.
    """

    stale_value: str
    hold: int = 2
    extra: float = 0.0
    # How old the delivered stale value actually is — the true (changed) value has
    # not yet arrived, so the agent sees a reading last affirmed `stale_age`s ago.
    stale_age: float = 30.0
    name: str = "late_contradiction"

    def extra_delay(self, n: int) -> float:
        return self.extra

    def override_value(self, value: str, n: int) -> str | None:
        return self.stale_value if n < self.hold else None
