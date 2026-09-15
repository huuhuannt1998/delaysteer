#!/usr/bin/env python3
"""Stage 4 -- realism. The Tier 2 boundary, made checkable rather than claimed.

The design is unusually specific about this, because "production-like" is
exactly the phrase papers use to mean nothing:

    a run is Tier 2 only if the planner is a stock agent framework we did not
    write, driving a platform API we did not write, over a transport we did not
    write. Anything else is Tier 1 (our harness, real model) or Tier 0
    (synthetic, no claim).

So the tier is not a label an author applies; it is three independent facts
about a run. `classify_tier` decides it from those facts and refuses to return
Tier 2 unless all three hold, which is why it takes provenance arguments rather
than a tier string. The result goes into the capability record on every row so a
reader never has to infer it.

No hardware, and what that does and does not bound
--------------------------------------------------
The PI's decision is no physical radio, so Stage 4 is cross-PLATFORM, not
cross-hardware. The honest consequence, stated here and carried into every
table:

    what is lost: a hardware-measured re-delivery interval, and any claim about
                  real radio behaviour under contention;
    what is NOT lost: the attack's validity. The attack acts on the arrival
                  timestamp, which is identical whether the frame crossed a real
                  mesh or a simulated one.

That asymmetry is why virtual devices bound the DEFENSE's cadence figures --
heartbeat intervals, poll round-trips, wake latencies -- and not the attack.
Every table carrying a cadence number says so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .capability import TIER_0, TIER_1, TIER_2


@dataclass
class RunProvenance:
    """Who wrote each layer of the thing that produced a run."""

    planner_is_third_party: bool      # a stock agent framework we did not write
    platform_api_is_third_party: bool  # a platform API we did not write
    transport_is_third_party: bool    # a transport we did not write
    planner_name: str = "delaysteer.agentkit"
    platform_name: str = "delaysteer.home.VirtualHome"
    transport_name: str = "in-process"
    physical_radio: bool = False

    def as_row(self) -> dict[str, Any]:
        return {
            "planner": self.planner_name,
            "platform": self.platform_name,
            "transport": self.transport_name,
            "planner_third_party": int(self.planner_is_third_party),
            "platform_third_party": int(self.platform_api_is_third_party),
            "transport_third_party": int(self.transport_is_third_party),
            "physical_radio": int(self.physical_radio),
        }


def classify_tier(p: RunProvenance, *, synthetic_planner: bool = False) -> str:
    """Decide the tier from facts, never from an author's assertion.

    Tier 0 is reserved for a synthetic planner (the deterministic reference),
    which explicitly supports NO claim about agent behaviour. Tier 2 requires
    all three layers to be third-party. Everything between is Tier 1.
    """
    if synthetic_planner:
        return TIER_0
    if (p.planner_is_third_party and p.platform_api_is_third_party
            and p.transport_is_third_party):
        return TIER_2
    return TIER_1


def tier_shortfall(p: RunProvenance) -> list[str]:
    """Exactly which layers keep a run below Tier 2. Named, not summarized."""
    out = []
    if not p.planner_is_third_party:
        out.append(f"planner is ours ({p.planner_name})")
    if not p.platform_api_is_third_party:
        out.append(f"platform is ours ({p.platform_name})")
    if not p.transport_is_third_party:
        out.append(f"transport is ours ({p.transport_name})")
    return out


# The provenance of what this project actually runs today, stated once so the
# tier on every row derives from it rather than from a per-script guess.
CURRENT = RunProvenance(
    planner_is_third_party=False,       # delaysteer.agentkit is ours
    platform_api_is_third_party=False,  # VirtualHome is ours
    transport_is_third_party=False,     # in-process dispatch is ours
)

# What a genuine Tier 2 run would look like, kept here so the gap is concrete
# rather than aspirational.
TIER2_TARGET = RunProvenance(
    planner_is_third_party=True, planner_name="LangChain/LlamaIndex agent",
    platform_api_is_third_party=True, platform_name="Home Assistant REST API",
    transport_is_third_party=True, transport_name="HTTP over localhost",
    physical_radio=False,
)


@dataclass
class CadenceFigure:
    """A defense-side timing number, with its provenance attached.

    Any figure describing how fast a defense can re-check, poll or wake is
    MODELLED here (spec-derived), not measured, because there is no radio. The
    flag travels with the number so a table cannot print it bare.
    """

    name: str
    seconds: float
    source: str = "spec-derived"
    measured_on_hardware: bool = False
    note: str = ""

    def caption(self) -> str:
        return (f"{self.name} = {self.seconds:g}s "
                f"({'measured' if self.measured_on_hardware else 'MODELLED, ' + self.source}"
                f"{'; ' + self.note if self.note else ''})")


# Spec-derived cadences used by the defense evaluation. Values are ordinary
# consumer-mesh figures; the point of collecting them here is that each carries
# its own provenance rather than appearing as a bare constant in a table.
CADENCES = (
    CadenceFigure("zigbee_checkin_interval", 7200.0,
                  note="typical sleepy end-device check-in"),
    CadenceFigure("zwave_wake_interval", 3600.0,
                  note="typical battery device wake"),
    CadenceFigure("hub_poll_roundtrip", 1.5,
                  note="hub-to-device active poll"),
    CadenceFigure("cloud_api_roundtrip", 0.4,
                  note="platform REST round trip"),
)


def realism_statement() -> str:
    """The paragraph the paper must carry before its numbers, not in Limitations."""
    short = tier_shortfall(CURRENT)
    return (
        "Realism. Every run reported here is Tier 1 or Tier 0: "
        + ("; ".join(short) if short else "all layers third-party")
        + ". No physical radio was used, so Stage 4 is cross-platform rather "
          "than cross-hardware. This bounds the DEFENSE's cadence figures "
          "(check-in intervals, poll round-trips, wake latencies), each of "
          "which is spec-derived and labelled, and does NOT bound the attack: "
          "the attack acts on the arrival timestamp, which is identical whether "
          "the frame crossed a real mesh or a simulated one. What we lose is a "
          "hardware-measured re-delivery interval; what we do not lose is the "
          "attack's validity."
    )
