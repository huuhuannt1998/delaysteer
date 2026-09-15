"""E4 -- the source-order witness (\\textsc{Counter}) as a running component.

The paper's third witness decides freshness from *order* rather than from a time.
Zigbee APS and NWK frame counters, Matter per-session message counters and Z-Wave
S2 nonce state are monotone integers minted at the source, carried with the message
and integrity-bound, so a delay-only adversary cannot advance one. Holding one frame
while its channel-mates pass makes the receiver observe counter ``N`` *after* ``N+1``:
an inversion. Until now the paper carried that as a design analysis over modelled
positions (results/defense_residual_counter.csv). This module is the mechanism, in
the guard's own path, with a state machine that separates the three observable cases.

    in order    seq strictly above everything seen on that source   -> admit
    gap         a forward jump (N, N+2): frames were LOST, not held -> admit
    inversion   seq below the high-water mark: a held frame arrived
                after a later one on the same source                -> BLOCK

The residual is stated in the paper and holds here: an *order-preserving* hold is
invisible. Holding a source's whole pending suffix, or holding the only in-flight
frame of an on-change source, produces no inversion because no later frame of that
source passes during the hold. The witness proves ordering, not recency.

SCOPE. The counters this module consumes are minted by ``scripts/run_e4_order_witness.py``'s
publisher, not read from a radio: this machine has no Zigbee/Z-Wave/Matter coordinator.
What is demonstrated is that the witness, the inversion/loss discrimination and the
guard integration work end to end on a real message path, and what a hub would have to
surface (the APS counter, the NWK sequence number, the Matter message counter) to drive
it from real hardware.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class OrderEvent(str, Enum):
    """What the witness saw when a frame arrived."""

    IN_ORDER = "in_order"
    GAP = "gap"                # forward jump: loss, order preserved
    INVERSION = "inversion"    # a held frame released after a later one
    DUPLICATE = "duplicate"    # seq already accepted


@dataclass
class SourceState:
    """Per-source counter state. One of these per (source) the witness tracks."""

    high_water: int | None = None      # highest seq accepted from this source
    accepted: int = 0
    gaps: int = 0
    inversions: int = 0
    duplicates: int = 0
    # Inversions observed since the last ``clear`` -- what a commit decision reads.
    open_inversions: list[int] = field(default_factory=list)
    last_event: OrderEvent | None = None


class OrderWitness:
    """A monotone per-source counter tracker, and a commit-time admission predicate.

    The witness is deliberately dumb about time: it never reads a clock. That is the
    whole point of the mode -- its verdict is identical wherever the hold was applied,
    and no budget makes a half-second hold invisible to it.
    """

    def __init__(self) -> None:
        self.sources: dict[str, SourceState] = {}

    # -- observation path ---------------------------------------------------- #
    def observe(self, source: str, seq: int) -> OrderEvent:
        """Record one arrival and classify it. Returns the event."""
        st = self.sources.setdefault(source, SourceState())
        if st.high_water is None:
            st.high_water, st.accepted, st.last_event = seq, st.accepted + 1, OrderEvent.IN_ORDER
            return OrderEvent.IN_ORDER
        if seq == st.high_water:
            st.duplicates += 1
            st.last_event = OrderEvent.DUPLICATE
            return OrderEvent.DUPLICATE
        if seq < st.high_water:
            # A frame from BELOW the high-water mark: it was held while at least one
            # later frame of the same source went past. This is the attack signature,
            # and it does not depend on where the hold was applied.
            st.inversions += 1
            st.open_inversions.append(seq)
            st.last_event = OrderEvent.INVERSION
            return OrderEvent.INVERSION
        event = OrderEvent.IN_ORDER if seq == st.high_water + 1 else OrderEvent.GAP
        if event is OrderEvent.GAP:
            # N, N+2: frames went missing. Loss is not a hold -- order is preserved and
            # nothing arrived out of sequence, so the witness must NOT block here. This
            # is the case a naive "did I get every counter?" check gets wrong.
            st.gaps += 1
        st.high_water = seq
        st.accepted += 1
        st.last_event = event
        return event

    # -- commit path --------------------------------------------------------- #
    def admit(self, sources: list[str] | tuple[str, ...]) -> tuple[bool, str]:
        """Commit-time predicate: admit iff no source has an unresolved inversion."""
        bad = [s for s in sources
               if (st := self.sources.get(s)) is not None and st.open_inversions]
        if bad:
            detail = "; ".join(
                f"{s} seq {self.sources[s].open_inversions} after "
                f"{self.sources[s].high_water}" for s in bad)
            return False, f"ORDER INVERSION on {detail}"
        return True, "source order intact"

    def clear(self, sources: list[str] | tuple[str, ...] | None = None) -> None:
        """Forget open inversions (after a commit decision has consumed them)."""
        for s in (sources if sources is not None else list(self.sources)):
            if (st := self.sources.get(s)) is not None:
                st.open_inversions.clear()

    def snapshot(self) -> dict[str, dict[str, int]]:
        return {s: {"accepted": st.accepted, "gaps": st.gaps, "inversions": st.inversions,
                    "duplicates": st.duplicates, "high_water": st.high_water or -1,
                    "open_inversions": len(st.open_inversions)}
                for s, st in self.sources.items()}
