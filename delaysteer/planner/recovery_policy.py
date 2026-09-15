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


# --------------------------------------------------------------------------- #
# Experiment D — Safe-liveness recovery (reviewer P0: non-pollable facts complete
# 0/20 benign under a naive fail-closed guard, so the defense looks unusable).
#
# When the active-poll guard fails closed at a commit (the critical fact could not
# be force-affirmed fresh), a RECOVERY POLICY decides what to do next. The security
# invariant is preserved by every policy below — none EVER commits on stale or
# untrusted evidence — so they differ only in AVAILABILITY: how much benign
# throughput they recover, and at what cost (latency, a user prompt, or a partial
# action). This is the security-vs-availability tradeoff, resolved per FACT CLASS.
# --------------------------------------------------------------------------- #
class SafeLivenessPolicy(str, Enum):
    """The recovery policies the reviewer requires at the commit gate."""

    FAIL_CLOSED = "fail_closed"                       # block immediately (the 0/20 baseline)
    BOUNDED_WAIT_HEARTBEAT = "bounded_wait_heartbeat"  # wait <= k intervals for the next trusted
    #                                                    affirmation, then commit iff fresh
    BACKOFF = "backoff"                              # exponential retry of a reachable device
    USER_ESCALATION = "user_escalation"             # ask the user on an INDEPENDENT channel
    SAFE_PARTIAL = "safe_partial"                    # perform only the fact-independent safe subset
    DEFERRED = "deferred"                           # take the safe lower-friction fallback


@dataclass
class FactClassPhysics:
    """Modeling assumptions (cf. defense/contract_validator, run_pollability_matrix)
    for how a critical fact yields a fresh TRUSTED affirmation.

    force_pollable      device answers a forced commit-time read (poll)  -> passes the
                        active-poll check with no recovery needed.
    affirmation_trusted the affirmation channel is NOT source-controlled: a delay-only
                        adversary cannot forge a fresh-looking affirmation of a stale
                        value (False => source-compromised: only escalation is safe).
    reachable_by_retry  active retries reach the device (mains/router or a transiently
                        unavailable node that returns); a SLEEPY node ignores retries and
                        is recovered only by waiting for its own keepalive.
    affirmation_delay_s time until the next trusted affirmation (poll-RTT for pollable, a
                        heartbeat for mains, a keepalive cadence for sleepy, a recovery
                        delay for transiently-unavailable).
    keepalive_age_s     age of the last passive report at the first commit check (drives
                        the active-poll fail-closed for every non-pollable class).
    unavailable_reads   backoff retries the device is unreachable before it returns.
    """

    name: str
    force_pollable: bool
    affirmation_trusted: bool
    reachable_by_retry: bool
    affirmation_delay_s: float
    keepalive_age_s: float = 30.0
    unavailable_reads: int = 0


@dataclass
class RecoveryStats:
    """What the recovery policy did on one run (read by the matrix runner)."""

    policy: str = ""
    waits: int = 0                 # bounded-wait affirmations awaited
    retries: int = 0               # backoff retries issued
    prompts: int = 0               # user escalations raised
    latency_added_s: float = 0.0   # recovery cost added to completion latency
    outcome: str = "none"          # none|completed|blocked|partial|deferred|escalated_declined


class RecoverySupervisor:
    """Safe-liveness recovery orchestration, consulted by TemporalGuard on a fail-closed.

    ``resolve`` returns a GateDecision to OVERRIDE the fail-closed, or None to keep the
    guard's default fail-closed behaviour. It never commits on stale/untrusted evidence:
    a commit is returned only after a fresh TRUSTED affirmation re-passes the guard's own
    check (bounded-wait / backoff) or an INDEPENDENT-channel user approves (escalation).
    """

    K_BOUNDED_WAIT = 3            # max affirmation intervals to wait (documented cap)
    BACKOFF_BASE_S = 0.5
    BACKOFF_MAX_RETRIES = 4
    USER_PROMPT_LATENCY_S = 15.0  # modeled human independent-channel check (walk to the door)

    def __init__(self, policy, physics: FactClassPhysics, user_confirm=None) -> None:
        self.policy = SafeLivenessPolicy(policy)
        self.physics = physics
        # user_confirm(tool, problems) -> bool: a user re-prompted with FRESH context on an
        # INDEPENDENT channel (physically checks ground truth). None => escalation cannot
        # approve (behaves fail-closed).
        self.user_confirm = user_confirm
        self.stats = RecoveryStats(policy=self.policy.value)

    # -- policy dispatch ---------------------------------------------------- #
    def resolve(self, guard, tool, spec_list, problems):
        from ..tools.router import GateDecision  # local import avoids a router<->planner cycle

        p = self.policy
        if p is SafeLivenessPolicy.FAIL_CLOSED:
            return None  # keep the guard's default fail-closed path
        if p is SafeLivenessPolicy.USER_ESCALATION:
            return self._escalate(guard, tool, problems)
        if p in (SafeLivenessPolicy.BOUNDED_WAIT_HEARTBEAT, SafeLivenessPolicy.BACKOFF):
            return self._wait_for_affirmation(guard, spec_list, p, problems)
        if p is SafeLivenessPolicy.SAFE_PARTIAL:
            # Perform the fact-INDEPENDENT safe subset (the door is already locked); refuse
            # the fact-dependent commit. Never over-claims, so 0 violation; degraded but usable.
            self.stats.outcome = "partial"
            guard.stats.blocked += 1
            return GateDecision(False, "SAFE-PARTIAL: delivered the fact-independent safe subset "
                                "(door locked); deferred the commit gated on the unconfirmed fact: "
                                + "; ".join(problems), revalidated=True)
        if p is SafeLivenessPolicy.DEFERRED:
            self.stats.outcome = "deferred"
            guard.stats.blocked += 1
            return GateDecision(False, "DEFERRED to the safe fallback (arming deferred, reported "
                                "NOT secure): " + "; ".join(problems), revalidated=True)
        return None

    # -- bounded-wait-heartbeat / backoff ----------------------------------- #
    def _wait_for_affirmation(self, guard, spec_list, policy, problems):
        from ..tools.router import GateDecision

        phys = self.physics
        clock = guard.adapter.clock
        can_advance = hasattr(clock, "advance")

        if not phys.affirmation_trusted:
            # Source-controlled channel: a fresh-LOOKING affirmation could be adversary-forged.
            # Refuse to trust it and fail closed (secure). The safe recovery is escalation to an
            # independent channel (cf. defense/contract_validator: source_controlled timestamps).
            self.stats.outcome = "blocked"
            guard.stats.blocked += 1
            return GateDecision(False, f"{policy.value}: affirmation channel is source-controlled "
                                "(untrusted) -> fail-closed; escalate to an independent channel: "
                                + "; ".join(problems), revalidated=True)

        if policy is SafeLivenessPolicy.BACKOFF and not phys.reachable_by_retry:
            # A sleepy on-change-only node ignores active retries; only its own keepalive
            # (bounded-wait-heartbeat) or a human can recover it.
            self.stats.outcome = "blocked"
            guard.stats.blocked += 1
            return GateDecision(False, "backoff: device is sleepy (unreachable by retry) -> "
                                "fail-closed; use bounded-wait-heartbeat or escalation: "
                                + "; ".join(problems), revalidated=True)

        if policy is SafeLivenessPolicy.BOUNDED_WAIT_HEARTBEAT:
            # Wait for the next trusted affirmation, retrying up to k affirmation intervals and
            # re-checking after each. k therefore bounds BOTH the number of attempts and the
            # total wait (k intervals).
            #
            # The previous form computed min(delay, k*delay), which equals delay for every
            # k >= 1 -- so k was inert and the waiter made exactly one attempt regardless of its
            # configured budget (found in review). With the loop, an adversary that sustains the
            # delay for fewer than k intervals is outlasted, while one that sustains longer
            # defeats the waiter: the availability residual measured in run_availability_attack.
            last_problems = problems
            for attempt in range(self.K_BOUNDED_WAIT):
                if can_advance:
                    clock.advance(phys.affirmation_delay_s)
                self.stats.waits += 1
                self.stats.latency_added_s += phys.affirmation_delay_s
                setattr(guard.adapter, "recovery_affirmed", True)
                last_problems = guard._reval_problems(spec_list)
                if not last_problems:
                    self.stats.outcome = "completed"
                    return GateDecision(
                        True,
                        f"{policy.value}: committed after a fresh trusted affirmation "
                        f"(waited {self.stats.latency_added_s:.2f}s, attempt "
                        f"{attempt + 1}/{self.K_BOUNDED_WAIT})", revalidated=True)
                setattr(guard.adapter, "recovery_affirmed", False)
            self.stats.outcome = "blocked"
            guard.stats.blocked += 1
            return GateDecision(
                False,
                f"{policy.value}: no trusted affirmation passed within "
                f"{self.K_BOUNDED_WAIT} intervals -> fail-closed: "
                + "; ".join(last_problems), revalidated=True)
        else:  # BACKOFF: exponential retry until the device returns (bounded budget)
            total = 0.0
            served = False
            for i in range(self.BACKOFF_MAX_RETRIES):
                d = self.BACKOFF_BASE_S * (2 ** i)
                if can_advance:
                    clock.advance(d)
                total += d
                self.stats.retries += 1
                if i + 1 > phys.unavailable_reads:  # device now reachable and affirms
                    served = True
                    break
            self.stats.latency_added_s += total
            if not served:
                self.stats.outcome = "blocked"
                guard.stats.blocked += 1
                return GateDecision(False, "backoff: retry budget exhausted, still unavailable -> "
                                    "fail-closed: " + "; ".join(problems), revalidated=True)

        # A trusted affirmation is now obtainable: the channel yields the TRUE current value at
        # poll-RTT age for the remainder of this commit transaction. Re-run the guard's own
        # check on that fresh evidence — commit iff it now passes (benign) else fail-closed
        # (attack: the fresh affirmation reveals the true unsafe state).
        setattr(guard.adapter, "recovery_affirmed", True)
        problems2 = guard._reval_problems(spec_list)
        if not problems2:
            self.stats.outcome = "completed"
            return GateDecision(True, f"{policy.value}: committed after a fresh trusted affirmation "
                                f"(waited {self.stats.latency_added_s:.2f}s)", revalidated=True)
        # Fresh affirmation shows the required value is NOT met (the delayed attack is exposed).
        setattr(guard.adapter, "recovery_affirmed", False)
        self.stats.outcome = "blocked"
        guard.stats.blocked += 1
        return GateDecision(False, f"{policy.value}: fresh affirmation revealed an unsafe state -> "
                            "BLOCKED: " + "; ".join(problems2), revalidated=True)

    # -- user escalation (independent channel) ------------------------------ #
    def _escalate(self, guard, tool, problems):
        from ..tools.router import GateDecision

        self.stats.prompts += 1
        guard.stats.escalations += 1
        clock = guard.adapter.clock
        if hasattr(clock, "advance"):
            clock.advance(self.USER_PROMPT_LATENCY_S)
        self.stats.latency_added_s += self.USER_PROMPT_LATENCY_S
        approved = bool(self.user_confirm is not None and self.user_confirm(tool, problems))
        if approved:
            # The user vouched for ground truth on an independent channel: honour the commit
            # and let the rest of this transaction proceed without re-prompting.
            setattr(guard.adapter, "recovery_affirmed", True)
            self.stats.outcome = "completed"
            return GateDecision(True, "user-escalation: approved on fresh independent-channel "
                                "context", revalidated=True)
        self.stats.outcome = "escalated_declined"
        guard.stats.blocked += 1
        return GateDecision(False, "user-escalation: user declined on fresh context (state is "
                            "unsafe) -> BLOCKED: " + "; ".join(problems), revalidated=True)
