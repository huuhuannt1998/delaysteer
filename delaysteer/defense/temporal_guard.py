"""TemporalGuard gate + ablation presets."""

from __future__ import annotations

from dataclasses import dataclass

from ..home.adapter import HomeAdapter
from ..home.virtual_home import ENTITIES
from ..tools.router import GateDecision

ARMED = ("armed_night", "armed_away")

# critical facts each high-impact action depends on: (belief_key, expected, semantic_type)
REQUIRED = {
    "arm_alarm": [("lock", "locked", "lock_state"), ("contact", "off", "contact_state")],
    "report_status": [
        ("lock", "locked", "lock_state"),
        ("contact", "off", "contact_state"),
        ("alarm", ARMED, "alarm_state"),
    ],
    # access delegation: grant access only with FRESH evidence the visitor is present
    "grant_access": [("camera", "on", "arrival")],
    # automation weakening: only remove the door-check predicate with FRESH evidence
    # (a stale/timed-out signal is delay, not a faulty predicate).
    "propose_automation_edit": [("contact", None, "contact_state")],
}


# Ablation presets (proposal §10): none / provenance / freshness / twophase / full.
GUARD_ABLATIONS = {
    "none": dict(guard_enabled=False),
    "provenance": dict(guard_enabled=True, guard_block=False,
                       guard_freshness=False, guard_two_phase=False),
    "freshness": dict(guard_enabled=True, guard_block=True,
                      guard_freshness=True, guard_two_phase=False),
    "twophase": dict(guard_enabled=True, guard_block=True,
                     guard_freshness=False, guard_two_phase=True),
    "full": dict(guard_enabled=True, guard_block=True,
                 guard_freshness=True, guard_two_phase=True),
    # full + challenge-response freshness (M1.1): closes the adaptive under-budget
    # replay by requiring post-challenge affirmation at the commit.
    "challenge": dict(guard_enabled=True, guard_block=True,
                      guard_freshness=True, guard_two_phase=True, guard_challenge=True),
    # full + active-poll challenge (MA-9 Task 1): the guard forces a fresh commit-time
    # re-read, so a pollable fact's value-age collapses to the poll RTT independent of
    # the passive reporting cadence; a non-pollable (sleepy) fact fails closed.
    "activepoll": dict(guard_enabled=True, guard_block=True, guard_freshness=True,
                       guard_two_phase=True, guard_challenge=True, guard_active_poll=True),
    # full + challenge + commit-time deliberation anchoring (MA-9 Task 3): judge freshness
    # at the observe, not the commit. Removes benign false-blocks under real deliberation
    # but reopens the attack (ground truth can change mid-deliberation) -> an unsafe fix,
    # shown here to motivate active-poll.
    "anchored": dict(guard_enabled=True, guard_block=True, guard_freshness=True,
                     guard_two_phase=True, guard_challenge=True,
                     guard_anchor_deliberation=True),
    # full + the source-ORDER witness (E4). Decides on a monotone counter minted at the
    # source instead of on an age, so it is position- and budget-independent; its
    # residual is any order-preserving hold. See defense/order_witness.py.
    "counter": dict(guard_enabled=True, guard_block=True, guard_freshness=True,
                    guard_two_phase=True, guard_order_witness=True),
}


def apply_ablation(config, name: str):
    for k, v in GUARD_ABLATIONS[name].items():
        setattr(config, k, v)
    return config


@dataclass
class GuardStats:
    revalidations: int = 0
    blocked: int = 0
    escalations: int = 0


class TemporalGuard:
    """A Gate (router policy hook) that enforces temporal trust."""

    def __init__(self, adapter: HomeAdapter, config, monitor=None, user_confirm=None,
                 contract=None, recovery=None, order_witness=None) -> None:
        # E4: optional source-order witness. When present AND config.guard_order_witness
        # is set, an unresolved counter inversion on a critical fact's source blocks the
        # commit, whatever the ages say. None keeps every existing call site unchanged.
        self.order_witness = order_witness
        self.adapter = adapter
        self.config = config
        self.monitor = monitor
        # Optional safe-liveness recovery supervisor (Experiment D). Consulted on a
        # fail-closed to WAIT for a trusted affirmation / back off / escalate / take a
        # safe-partial or deferred fallback. None => the frozen fail-closed behaviour
        # (fully backward compatible; the default across all prior experiments).
        self.recovery = recovery
        # Optional human-in-the-loop: called as user_confirm(tool, problems) -> bool
        # when temporal trust is too low. Models re-prompting the user with FRESH
        # context. None => fail closed (block silently).
        self.user_confirm = user_confirm
        # Optional injected critical-fact contract (Experiment C): a
        # {tool: [(belief_key, expected, semantic_type), ...]} map that OVERRIDES the
        # module-level REQUIRED. None => the frozen default contract (backward compatible).
        # Lets run_contract_robustness.py enforce a MUTATED contract without touching REQUIRED.
        self.contract = contract
        self.stats = GuardStats()
        self._blocked_streak = 0
        # Deliberation window (observe -> commit), in seconds, known from the agent's
        # observation trace. Subtracted from the challenge value-age ONLY when
        # guard_anchor_deliberation is set (MA-9 Task 3). Default 0 => no effect.
        self.deliberation_s = 0.0

    def _reval_for(self, tool: str):
        """The (key, expected, semantic) list to revalidate — injected contract or default."""
        if self.contract is not None:
            return self.contract.get(tool, REQUIRED.get(tool, []))
        return REQUIRED[tool]

    def _gated(self, tool: str, args: dict) -> bool:
        # With an injected contract, gate exactly the actions it covers (report_status
        # still only when a secure=true claim is being committed).
        if self.contract is not None:
            if tool not in self.contract:
                return False
            if tool == "report_status":
                return bool(args.get("secure"))
            return True
        if tool in ("arm_alarm", "grant_access", "propose_automation_edit"):
            return True
        if tool == "report_status" and args.get("secure"):
            return True
        return False

    def _reval_problems(self, spec_list) -> list[str]:
        """Two-phase revalidation of the critical facts; returns the freshness/value problems.

        Extracted verbatim from ``evaluate`` so the safe-liveness recovery supervisor
        (Experiment D) can RE-ATTEMPT the check after obtaining a fresh trusted affirmation,
        keeping one source of truth for the freshness + challenge + value logic. Behaviour is
        identical to the inline check that preceded the recovery hook.
        """
        problems: list[str] = []
        # Tag revalidation reads so an adaptive adversary (M1) can be evaluated for
        # whether it can target the re-read specifically. Harmless for plain adapters.
        active_poll = getattr(self.config, "guard_active_poll", False)
        setattr(self.adapter, "revalidating", True)
        if active_poll:
            setattr(self.adapter, "active_poll", True)  # force a fresh commit-time affirmation
        t_challenge = self.adapter.clock.now()  # revalidation time t_c; the heartbeat-bounded
        # check bounds value-age to eps (a bounded-recency condition), while active-poll forces a
        # fresh affirmation so t_g ~= t_c (the truly post-commit variant)
        try:
            reval = [(k, e, s) for (k, e, s) in spec_list]
            obs_by_key = {k: self.adapter.get_state(ENTITIES[k]) for (k, _, _) in reval}
        finally:
            setattr(self.adapter, "revalidating", False)
            setattr(self.adapter, "active_poll", False)
        challenge = getattr(self.config, "guard_challenge", False)
        # Challenge tolerance epsilon: the poll round-trip when actively polling (the
        # value is force-affirmed at the commit), otherwise the passive sensor heartbeat.
        eps = getattr(self.config, "poll_rtt_s", 0.05) if active_poll \
            else getattr(self.config, "heartbeat_s", 0.25)
        anchor = getattr(self.config, "guard_anchor_deliberation", False)
        for key, expected, sem in spec_list:
            obs = obs_by_key[key]  # two-phase REVALIDATION read
            self.stats.revalidations += 1
            age = obs.arrival_time - obs.generation_time
            # Commit-time anchoring (Task 3): the whole freshness clock is judged as of
            # the observe, so the deliberation window is subtracted from BOTH the budget
            # and the challenge checks (one coherent policy, not just the tighter gate).
            if anchor:
                age = max(0.0, age - self.deliberation_s)
            threshold = self.config.freshness_s.get(sem, 5.0)

            tol = getattr(self.config, "future_stamp_tol_s", 0.5)
            if getattr(self.config, "guard_future_stamp", False) and age < -tol:
                problems.append(f"{key} FUTURE-STAMPED (age {age:.2f}s < -{tol:.2f}s): source clock leads")
                continue
            if self.config.guard_freshness and age > threshold:
                problems.append(f"{key} STALE (age {age:.1f}s > {threshold:.1f}s)")
                continue  # stale evidence can't be trusted for the value check
            # Challenge-response freshness: the value must have been AFFIRMED at/after
            # the challenge time (tolerance = sensor heartbeat). This defeats the adaptive
            # under-budget replay at P-B, where the affirmation the adversary would need
            # is one it cannot produce.
            #
            # SCOPE (Experiment L). This check compares TIMESTAMPS -- it is not
            # nonce-bound, despite the historical "(nonce)" label on guard_challenge.
            # Upstream of the hub's stamping point the premise fails with no forgery
            # required: the hub mints the post-challenge affirmation itself when it
            # re-stamps a held frame at receipt, which is the residual that leaks in
            # results/position_laundering.csv. A genuinely nonce-bound affirmation is
            # delaysteer/defense/nonce_challenge.py (Experiment E2); this tier remains
            # the deployable timestamp-based approximation.
            if challenge:
                value_age = t_challenge - obs.generation_time
                # Commit-time anchoring (Task 3): judge freshness as of the observe, not
                # the commit -- subtract the deliberation window. Removes benign
                # false-blocks under real (multi-second) deliberation, but the subtracted
                # window is exactly where a delay adversary hides a ground-truth change.
                if anchor:
                    value_age = max(0.0, value_age - self.deliberation_s)
                if value_age > eps:
                    problems.append(
                        f"{key} REPLAYED (value-age {value_age:.2f}s > heartbeat "
                        f"tolerance {eps:.2f}s)")
                    continue
            if self.config.guard_two_phase and expected is not None:
                ok = obs.value in expected if isinstance(expected, tuple) else obs.value == expected
                if not ok:
                    problems.append(f"{key}={obs.value} (need {expected})")
        # E4 -- source-order witness. Asked LAST and about the same facts: a hold short
        # enough to pass every age check still inverts a counter, which is the residual
        # the time-based witnesses cannot see.
        if self.order_witness is not None and getattr(self.config, "guard_order_witness", False):
            ok, reason = self.order_witness.admit([ENTITIES[k] for (k, _, _) in spec_list])
            if not ok:
                problems.append(reason)
        return problems

    def evaluate(self, spec, args, context) -> GateDecision:
        tool = spec.name
        if not self._gated(tool, args):
            return GateDecision(True, "not-gated")
        if not self.config.guard_freshness and not self.config.guard_two_phase:
            # provenance-only: record but never block
            return GateDecision(True, "provenance-monitor")

        spec_list = self._reval_for(tool)
        problems = self._reval_problems(spec_list)

        if self.monitor is not None:
            self.monitor.record("defense", "guard_eval", "temporalguard",
                                self.adapter.clock.now(), self.adapter.clock.now(),
                                {"tool": tool, "secure": args.get("secure"),
                                 "problems": problems})

        if problems and self.config.guard_block:
            # Safe-liveness recovery (Experiment D): on a fail-closed, consult the recovery
            # supervisor first. It may wait for a trusted affirmation / back off / escalate /
            # take a safe-partial or deferred fallback — never committing on stale/untrusted
            # evidence. A returned decision OVERRIDES the default fail-closed; None keeps it.
            if self.recovery is not None:
                decision = self.recovery.resolve(self, tool, spec_list, problems)
                if decision is not None:
                    self._blocked_streak = 0 if decision.allow else self._blocked_streak
                    return decision
            # Human-in-the-loop: escalate to the user with FRESH context rather than
            # silently failing. A user given fresh evidence makes the safe choice.
            if self.user_confirm is not None:
                self.stats.escalations += 1
                if self.user_confirm(tool, problems):
                    self._blocked_streak = 0
                    return GateDecision(True, "user-confirmed after fresh-context escalation",
                                        revalidated=True)
                self.stats.blocked += 1
                return GateDecision(False, "BLOCKED + user declined after escalation: "
                                    + "; ".join(problems), revalidated=True)
            self.stats.blocked += 1
            self._blocked_streak += 1
            reason = "TemporalGuard BLOCKED " + tool + ": " + "; ".join(problems)
            if self._blocked_streak >= self.config.guard_antithrash_max:
                self.stats.escalations += 1
                reason += " [anti-thrash: escalate to user]"
            return GateDecision(False, reason, revalidated=True)

        self._blocked_streak = 0
        verdict = "ALLOW (revalidated fresh)" if not problems else f"ALLOW (monitor: {problems})"
        return GateDecision(True, verdict, revalidated=True)
