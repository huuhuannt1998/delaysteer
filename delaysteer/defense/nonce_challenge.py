"""M1 nonce-bound affirmation and M2 joint-witness coherence.

These are the two guard mechanisms the v2 design calls for (§8.2, §8.3). Both exist
because of one fact established by Experiment L: the platform's timestamp is minted at
RECEIPT, so a delay-only adversary upstream of the stamping point launders its own delay
into a fresh-looking stamp without forging anything. Every v1 tier that decides freshness
by *reading a timestamp* is therefore defeated upstream, and no tightening of the budget
helps -- the quantity being compared is already adversary-controlled.

The fix is to stop trusting a handed-over reference instant and mint one downstream of
every adversary position.

M1, nonce-bound affirmation (§8.2)
----------------------------------
The guard emits a fresh unpredictable nonce, records its own issue time, and requires the
response to bind that nonce. Two tiers, reported separately because their deployability
differs sharply:

  STRONG (device-bound). The response binds the nonce AT THE DEVICE. A held or replayed
  frame cannot carry an echo of a nonce that did not exist when it was captured, so the
  adversary either releases inside the window (the value genuinely is fresh) or misses it
  (the guard blocks). This is the tier that gives the full guarantee, and it is the tier
  that needs device cooperation -- Matter's Interaction Model read transaction, Zigbee's
  read-attributes sequence number, a wakeable Z-Wave FLiRS lock. We model it; we do not
  have firmware that implements it, and the experiment says so.

  DEPLOYABLE (round-trip only). The hub records poll-issue and poll-response wall times
  and rejects an anomalous round trip. No firmware change, no device cooperation, adoptable
  today. Strictly weaker: a PRE-COMPUTED reply released inside the bound still passes,
  because nothing binds the value to the challenge. What it buys is the conversion of an
  unbounded window into a bounded one -- an integrity failure becomes an availability cost.

An on-change-only sleepy sensor can be challenged by neither tier and must fail closed.
That is the coverage cost v1 already characterises, and the safe-liveness recovery matrix
already supplies the bounded-wait and escalation paths for it.

M2, joint-witness coherence (§8.3)
----------------------------------
Freshness does not imply coherence. Each critical fact can be individually truthful and
individually inside its budget while the CONJUNCTION the action depends on was never true
at any single instant. A tighter per-fact budget cannot fix this, because no per-fact bound
implies the existence of a common witness instant. The defense is a predicate:

  spread rule (deployable): admit only if max(t_m) - min(t_m) <= sigma_max
  strong rule:              admit only if every critical fact was affirmed against ONE
                            challenge round, so a common witness instant is attested
                            rather than inferred

The strong rule composes with M1: one nonce broadcast to every critical fact of an action
buys coherence and freshness in the same round trip.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Callable, Iterable


# --------------------------------------------------------------------------------------
# M1
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Challenge:
    """One guard-minted reference instant. The nonce is unpredictable to the adversary."""

    nonce: str
    issued_at: float

    @staticmethod
    def mint(now: float) -> "Challenge":
        return Challenge(nonce=secrets.token_hex(8), issued_at=now)


@dataclass(frozen=True)
class Response:
    """What comes back for a challenge.

    ``nonce_echo`` is the device's binding of the challenge; it is None for any frame the
    device did not mint in response to THIS challenge -- which is exactly the case for a
    held or replayed frame, however fresh its platform timestamp looks.
    """

    value: str
    received_at: float          # the GUARD's clock, not the platform's
    nonce_echo: str | None = None
    platform_stamp: float | None = None   # what the hub claims; recorded, never trusted


@dataclass
class ChallengeVerdict:
    admitted: bool
    reason: str
    round_trip_s: float
    tier: str
    nonce_bound: bool


def verify_challenge(
    ch: Challenge,
    resp: Response,
    *,
    tier: str,
    rtt_bound_s: float,
) -> ChallengeVerdict:
    """Decide admission for one challenged fact.

    The decision uses only quantities the guard itself minted or measured: the nonce it
    generated and the round trip on its own clock. ``resp.platform_stamp`` is deliberately
    never consulted -- that is the value Experiment L showed to be adversary-controlled
    upstream of the hub.
    """
    rtt = resp.received_at - ch.issued_at
    if rtt < 0:
        return ChallengeVerdict(False, "non-monotonic round trip (fail closed)", rtt, tier, False)

    if tier == "strong":
        # Device-bound: the response must carry an echo of THIS challenge.
        if resp.nonce_echo != ch.nonce:
            return ChallengeVerdict(
                False, "no device binding for this challenge", rtt, tier, False)
        if rtt > rtt_bound_s:
            return ChallengeVerdict(
                False, f"round trip {rtt:.3f}s > bound {rtt_bound_s:.3f}s", rtt, tier, True)
        return ChallengeVerdict(True, "device-bound affirmation inside the bound", rtt, tier, True)

    if tier == "deployable":
        # Round-trip only: nothing binds the value to the challenge, so a pre-computed
        # reply released inside the bound passes. That weakness is the point of the tier.
        if rtt > rtt_bound_s:
            return ChallengeVerdict(
                False, f"round trip {rtt:.3f}s > bound {rtt_bound_s:.3f}s", rtt, tier, False)
        return ChallengeVerdict(True, "response inside the round-trip bound", rtt, tier, False)

    if tier == "none":
        # v1 behaviour: trust the platform stamp. Retained so the sweep has a baseline.
        return ChallengeVerdict(True, "no challenge (v1 timestamp trust)", rtt, tier, False)

    raise ValueError(f"unknown tier {tier!r}")


# --------------------------------------------------------------------------------------
# M2
# --------------------------------------------------------------------------------------

@dataclass
class FactAffirmation:
    """One critical fact as the guard received it, for a multi-fact commitment."""

    key: str
    value: str
    measurement_time: float          # t_m: when the DEVICE measured it (ground truth)
    challenge_round: int | None = None   # which challenge round affirmed it, if any


@dataclass
class CoherenceVerdict:
    admitted: bool
    reason: str
    spread_s: float
    single_round: bool


def joint_witness_admits(
    facts: Iterable[FactAffirmation],
    *,
    sigma_max_s: float,
    require_single_round: bool,
) -> CoherenceVerdict:
    """M2 admission for a multi-fact action.

    ``sigma_max_s`` bounds the measurement spread. ``require_single_round`` is the strong
    tier: every fact must have been affirmed in ONE challenge round, which attests a common
    witness instant instead of inferring one from separate timestamps.
    """
    fl = list(facts)
    if not fl:
        return CoherenceVerdict(True, "no critical facts", 0.0, True)

    times = [f.measurement_time for f in fl]
    spread = max(times) - min(times)
    rounds = {f.challenge_round for f in fl}
    single = len(rounds) == 1 and None not in rounds

    if require_single_round and not single:
        return CoherenceVerdict(
            False, "critical facts were not affirmed in a single challenge round",
            spread, single)
    if spread > sigma_max_s:
        return CoherenceVerdict(
            False, f"measurement spread {spread:.3f}s > sigma_max {sigma_max_s:.3f}s",
            spread, single)
    return CoherenceVerdict(True, "coherent within sigma_max", spread, single)


def joint_witness_set(
    belief: dict[str, str],
    truth_at: Callable[[str, float], str],
    timeline: Iterable[float],
) -> list[float]:
    """W(B) = { t : for every critical fact tau, the true value of tau at t == B(tau) }.

    Definition 9 of the v2 design, evaluated over a sampled timeline. A belief is
    *coherent* iff this set is non-empty. This is the ground-truth oracle the experiment
    scores against -- it is not available to the guard, which is the whole difficulty.
    """
    return [t for t in timeline
            if all(truth_at(k, t) == v for k, v in belief.items())]


# --------------------------------------------------------------------------------------
# convenience for the harnesses
# --------------------------------------------------------------------------------------

TIERS = ("none", "deployable", "strong")


@dataclass
class ChallengeLog:
    """Per-run record so a harness can report round trips without re-deriving them."""

    rows: list[dict] = field(default_factory=list)

    def record(self, key: str, ch: Challenge, resp: Response, v: ChallengeVerdict) -> None:
        self.rows.append(dict(
            key=key, nonce=ch.nonce, issued_at=round(ch.issued_at, 6),
            received_at=round(resp.received_at, 6), round_trip_s=round(v.round_trip_s, 6),
            platform_stamp=(round(resp.platform_stamp, 6)
                            if resp.platform_stamp is not None else ""),
            nonce_echo=(resp.nonce_echo or ""), tier=v.tier,
            admitted=v.admitted, nonce_bound=v.nonce_bound, reason=v.reason))
