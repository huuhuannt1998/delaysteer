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

    def __init__(self, adapter: HomeAdapter, config, monitor=None, user_confirm=None) -> None:
        self.adapter = adapter
        self.config = config
        self.monitor = monitor
        # Optional human-in-the-loop: called as user_confirm(tool, problems) -> bool
        # when temporal trust is too low. Models re-prompting the user with FRESH
        # context. None => fail closed (block silently).
        self.user_confirm = user_confirm
        self.stats = GuardStats()
        self._blocked_streak = 0

    def _gated(self, tool: str, args: dict) -> bool:
        if tool in ("arm_alarm", "grant_access", "propose_automation_edit"):
            return True
        if tool == "report_status" and args.get("secure"):
            return True
        return False

    def evaluate(self, spec, args, context) -> GateDecision:
        tool = spec.name
        if not self._gated(tool, args):
            return GateDecision(True, "not-gated")
        if not self.config.guard_freshness and not self.config.guard_two_phase:
            # provenance-only: record but never block
            return GateDecision(True, "provenance-monitor")

        problems: list[str] = []
        # Tag revalidation reads so an adaptive adversary (M1) can be evaluated for
        # whether it can target the re-read specifically. Harmless for plain adapters.
        setattr(self.adapter, "revalidating", True)
        t_challenge = self.adapter.clock.now()  # the nonce: facts must be affirmed >= here
        try:
            reval = [(k, e, s) for (k, e, s) in REQUIRED[tool]]
            obs_by_key = {k: self.adapter.get_state(ENTITIES[k]) for (k, _, _) in reval}
        finally:
            setattr(self.adapter, "revalidating", False)
        challenge = getattr(self.config, "guard_challenge", False)
        heartbeat = getattr(self.config, "heartbeat_s", 0.25)
        for key, expected, sem in REQUIRED[tool]:
            obs = obs_by_key[key]  # two-phase REVALIDATION read
            self.stats.revalidations += 1
            age = obs.arrival_time - obs.generation_time
            threshold = self.config.freshness_s.get(sem, 5.0)

            if self.config.guard_freshness and age > threshold:
                problems.append(f"{key} STALE (age {age:.1f}s > {threshold:.1f}s)")
                continue  # stale evidence can't be trusted for the value check
            # Challenge-response (nonce) freshness: the value must have been AFFIRMED
            # at/after the challenge time (tolerance = sensor heartbeat). A delay-only
            # adversary cannot replay a stale value with a post-challenge affirmation,
            # so this defeats the under-budget replay; residual window = heartbeat.
            if challenge:
                value_age = t_challenge - obs.generation_time
                if value_age > heartbeat:
                    problems.append(
                        f"{key} REPLAYED (value-age {value_age:.2f}s > heartbeat "
                        f"{heartbeat:.2f}s; not affirmed post-challenge)")
                    continue
            if self.config.guard_two_phase and expected is not None:
                ok = obs.value in expected if isinstance(expected, tuple) else obs.value == expected
                if not ok:
                    problems.append(f"{key}={obs.value} (need {expected})")

        if self.monitor is not None:
            self.monitor.record("defense", "guard_eval", "temporalguard",
                                self.adapter.clock.now(), self.adapter.clock.now(),
                                {"tool": tool, "secure": args.get("secure"),
                                 "problems": problems})

        if problems and self.config.guard_block:
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
