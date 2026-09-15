"""Adaptive adversaries that KNOW TemporalGuard exists (Mission 1).

The threat model is delay-only: the adversary controls when an observation
arrives and may deliver a stale-but-truthful prior value, but it can never forge
a value or make a value look *fresher* than its true age. Concretely, it may
back-date nothing; it can only make age = arrival - generation LARGER, never
smaller than the value's real age. The two adaptive strategies below stay strictly
within that model.

AdaptiveAdapter spoofs one channel by delivering a stale-but-truthful value with a
chosen (honest) age, and can deliver a DIFFERENT age to the guard's two-phase
revalidation read than to the agent's read (the guard tags its reads via the
`revalidating` flag). The arrival time stays prompt, so the agent's recovery
timeout (which keys off response latency) does not fire; only the value's age is
old, which is what the guard's freshness contract inspects.

  Strategy A (under-budget pacing): deliver the stale value with age just under the
  freshness budget to BOTH the agent and the guard. If the dangerous physical fact
  changed within the budget window, the genuinely-<budget-old value passes the
  freshness check yet is already wrong.

  Strategy B (revalidation-targeting): deliver a small age to the agent but a large
  age to the guard's re-read (delay the re-read). Tests whether targeting the
  re-read helps the adversary.
"""

from __future__ import annotations

from ..home.adapter import HomeAdapter, Observation


class AdaptiveAdapter(HomeAdapter):
    def __init__(self, inner: HomeAdapter, channel: str, stale_value: str,
                 agent_age: float, reval_age: float | None = None, monitor=None,
                 pollable: bool = True, cadence_s: float | None = None,
                 poll_rtt: float = 0.05) -> None:
        self.inner = inner
        self.clock = inner.clock
        self.monitor = monitor
        self.channel = channel              # semantic_type to spoof (e.g. "arrival")
        self.stale_value = stale_value      # truthful-earlier value (delay-only)
        self.agent_age = agent_age          # honest age delivered to AGENT reads
        self.reval_age = agent_age if reval_age is None else reval_age
        self.revalidating = False           # set True by the guard around its re-reads
        # MA-9 Task 1: active-poll axis. When the guard forces a commit-time affirmation
        # (active_poll), a pollable fact returns the TRUE current value at poll-RTT age;
        # a non-pollable (sleepy on-change-only) fact cannot be force-affirmed, so the
        # newest affirmation is one keepalive (cadence_s) old -> the guard fails closed.
        self.active_poll = False            # set True by the guard's active-poll re-read
        # Experiment D (safe-liveness recovery): set True by the recovery supervisor once it
        # has obtained a fresh TRUSTED affirmation (bounded-wait for the next keepalive, or
        # backoff until a transiently-unavailable device returns). While set, the channel
        # yields the TRUE current value at poll-RTT age (fresh) for the rest of the commit
        # transaction. Only ever set for fact classes the supervisor deemed trusted, so a
        # delay-only adversary cannot exploit it.
        self.recovery_affirmed = False
        self.pollable = pollable
        self.cadence_s = cadence_s          # passive keepalive (s); non-pollable affirmation age
        self.poll_rtt = poll_rtt            # active-poll round-trip / fresh-affirmation age (s)
        self.injections: list[dict] = []

    def _spoof(self, obs: Observation) -> Observation:
        if obs.semantic_type != self.channel:
            return obs
        if self.recovery_affirmed:
            # A trusted affirmation was obtained via safe-liveness recovery: return the TRUE
            # current value (obs.value from the inner adapter) at poll-RTT age. Benign -> the
            # required value, fresh; attack -> the true unsafe value, exposing the delay.
            obs.generation_time = obs.arrival_time - self.poll_rtt
            rec = {"reval": True, "recovery_affirmed": True, "age": round(self.poll_rtt, 3),
                   "value": obs.value, "channel": self.channel}
            self.injections.append(rec)
            if self.monitor is not None:
                self.monitor.record("defense", obs.semantic_type, "recovery-affirmation",
                                    obs.generation_time, obs.arrival_time, rec)
            return obs
        if self.active_poll:
            # Guard-forced commit-time affirmation (active-poll challenge).
            if self.pollable:
                # The poll returns the TRUE current value at poll-RTT age. A delay-only
                # adversary cannot forge a post-challenge affirmation of the stale value:
                # it either delivers the truth (guard sees the open door -> blocks) or
                # withholds it (no affirmation -> blocks). Leave obs.value = ground truth.
                obs.generation_time = obs.arrival_time - self.poll_rtt
                rec = {"reval": True, "active_poll": True, "pollable": True,
                       "age": round(self.poll_rtt, 3), "value": obs.value, "channel": self.channel}
            else:
                # Sleepy on-change-only sensor: no fresh affirmation; newest report is one
                # keepalive old -> value-age > epsilon -> fail closed (secure, usability cost).
                obs.value = self.stale_value
                obs.generation_time = obs.arrival_time - (self.cadence_s if self.cadence_s else 1e9)
                rec = {"reval": True, "active_poll": True, "pollable": False,
                       "age": self.cadence_s, "value": self.stale_value, "channel": self.channel}
            self.injections.append(rec)
            if self.monitor is not None:
                self.monitor.record("defense", obs.semantic_type, "active-poll",
                                    obs.generation_time, obs.arrival_time, rec)
            return obs
        age = self.reval_age if self.revalidating else self.agent_age
        obs.value = self.stale_value
        # The value was last truly affirmed `age` seconds ago; arrival stays prompt
        # (the response is fast, the value inside is old). This is delay-only: a
        # stale-but-truthful value, with its honest age. Age can only be >= the
        # value's real staleness, never less.
        obs.generation_time = obs.arrival_time - age
        rec = {"reval": self.revalidating, "age": round(age, 2),
               "value": self.stale_value, "channel": self.channel}
        self.injections.append(rec)
        if self.monitor is not None:
            self.monitor.record("attack", obs.semantic_type, "adaptive-adversary",
                                obs.generation_time, obs.arrival_time, rec)
        return obs

    def get_state(self, entity_id: str) -> Observation:
        return self._spoof(self.inner.get_state(entity_id))

    def call_service(self, domain: str, service: str, data=None) -> Observation:
        return self.inner.call_service(domain, service, data)

    def entities(self):
        return self.inner.entities()
