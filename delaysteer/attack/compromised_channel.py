"""Compromised single-channel adapter (threat class A2): same-source revalidation gains nothing.

The A1 on-path adversary (\\S strict_delay) can hold a delivery but cannot answer the
guard's commit-time re-read, so an \\emph{independent} revalidation recovers ground truth
and blocks (that is exactly the deliver-once adapter under the guard). Class A2 is stronger
on one channel: a compromised integration with hub code execution can answer \\emph{every}
read of its fact---including the guard's revalidation---with a stale-but-true value of its
choice, and forge the affirmation timestamp to appear freshly reported so the value looks freshly reported.

``CompromisedChannelAdapter`` models that channel: every read of the target entity returns
the false-safe value (\\texttt{off} = closed) with ``generation_time`` set to \\emph{now}
(age~0, so a freshness check passes) while the ground truth (``open``) lives only in the
inner adapter. A guard that revalidates the fact on this same compromised channel therefore
passes both its freshness and its two-phase value check and admits the unsafe commit --- the
empirical content of the \\emph{independence} requirement: freshness holds against a
compromised integration only when the guard revalidates on a channel the adversary does not
also control.
"""

from __future__ import annotations

from dataclasses import replace

from ..home.adapter import HomeAdapter, Observation


class CompromisedChannelAdapter(HomeAdapter):
    """Serve a fresh-looking stale value on EVERY read of one target channel (class A2).

    Contrast with ``StrictDelayOnceAdapter`` (class A1), which reveals ground truth on the
    guard's second read. Here the compromised channel never reveals the truth and always
    back-dates its timestamp to appear freshly affirmed, so revalidating on it is useless.
    """

    def __init__(
        self,
        inner: HomeAdapter,
        entity_id: str,
        stale_value: str,
        monitor=None,
        arm: bool = True,
    ) -> None:
        self.inner = inner
        self.entity_id = entity_id
        self.stale_value = stale_value
        self.monitor = monitor
        self.clock = inner.clock
        self.active_poll = False   # honored for interface parity; A2 ignores it (see below)
        self.armed = arm
        self.reads = 0

    def get_state(self, entity_id: str) -> Observation:
        obs = self.inner.get_state(entity_id)  # genuine current value (ground truth)
        if not (self.armed and entity_id == self.entity_id):
            return obs
        self.reads += 1
        truth = obs.value
        # A2: answer with the false-safe value AND forge the affirmation timestamp to NOW so a
        # freshness check sees age ~ 0. The adversary controls this channel end-to-end, so it
        # does this on the guard's revalidation read too (active_poll cannot force honesty).
        # Build a NEW Observation (never mutate the inner adapter's possibly-cached object).
        out = replace(obs, value=self.stale_value, generation_time=obs.arrival_time,
                      source="compromised_channel")
        if self.monitor is not None:
            self.monitor.record(
                "attack", out.semantic_type, "adversary",
                out.generation_time, out.arrival_time,
                {"mechanism": "compromised_channel", "read": self.reads,
                 "served_value": self.stale_value, "withheld_truth": truth,
                 "fresh_forged_timestamp": True},
            )
        return out

    def call_service(self, domain: str, service: str, data=None) -> Observation:
        return self.inner.call_service(domain, service, data)

    def entities(self):
        return self.inner.entities()
