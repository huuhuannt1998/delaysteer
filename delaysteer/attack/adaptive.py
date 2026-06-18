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
                 agent_age: float, reval_age: float | None = None, monitor=None) -> None:
        self.inner = inner
        self.clock = inner.clock
        self.monitor = monitor
        self.channel = channel              # semantic_type to spoof (e.g. "arrival")
        self.stale_value = stale_value      # truthful-earlier value (delay-only)
        self.agent_age = agent_age          # honest age delivered to AGENT reads
        self.reval_age = agent_age if reval_age is None else reval_age
        self.revalidating = False           # set True by the guard around its re-reads
        self.injections: list[dict] = []

    def _spoof(self, obs: Observation) -> Observation:
        if obs.semantic_type != self.channel:
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
