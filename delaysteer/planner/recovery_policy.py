"""Benign recovery policy (mission task 5).

This is the *reasonable, documented* helpfulness that distinguishes an agentic
home from a fixed rule — and exactly what DelaySteer later exploits. It is NOT a
strawman (assumption A3): the user wants to avoid nuisance night alarms, so the
agent is permitted to defer arming when it cannot freshly confirm door state.

Policy when a verification does not return fresh confirmation:
  1. RETRY the verification once (recovery_max_retries).
  2. If still unconfirmed, REQUEST_FRESH state explicitly.
  3. If confirmation remains unavailable past the timeout boundary, take the
     lower-friction FALLBACK (defer arming) — if allowed by config.

Timeout boundary: `Config.recovery_timeout_s` (default 5.0 s). An observation
counts as "timed out" when its arrival lands after request_time + timeout, or
when no confirmation arrives at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RecoveryAction(str, Enum):
    PROCEED = "proceed"            # confirmed fresh — continue the plan
    RETRY = "retry"               # re-issue the verification
    REQUEST_FRESH = "request_fresh"  # ask the platform for a fresh reading
    DEFER_FALLBACK = "defer_fallback"  # give up on confirmation, take safe-ish fallback


@dataclass
class RecoveryState:
    retries_used: int = 0
    fresh_requested: bool = False


class RecoveryPolicy:
    def __init__(self, config) -> None:
        self.timeout_s = config.recovery_timeout_s
        self.max_retries = config.recovery_max_retries
        self.allow_defer = config.allow_defer_arming

    def timed_out(self, request_time: float, arrival_time: float | None) -> bool:
        """True if confirmation never arrived or arrived past the boundary."""
        if arrival_time is None:
            return True
        return (arrival_time - request_time) > self.timeout_s

    def next_action(
        self,
        *,
        confirmed: bool,
        timed_out: bool,
        state: RecoveryState,
    ) -> RecoveryAction:
        if confirmed and not timed_out:
            return RecoveryAction.PROCEED
        # Unconfirmed or stale evidence -> escalate through the ladder.
        if state.retries_used < self.max_retries:
            state.retries_used += 1
            return RecoveryAction.RETRY
        if not state.fresh_requested:
            state.fresh_requested = True
            return RecoveryAction.REQUEST_FRESH
        if self.allow_defer:
            return RecoveryAction.DEFER_FALLBACK
        return RecoveryAction.PROCEED  # no fallback allowed; proceed cautiously
