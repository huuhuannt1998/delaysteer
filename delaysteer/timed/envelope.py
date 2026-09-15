#!/usr/bin/env python3
"""Message identity: the flow id and per-flow sequence number.

The design models a message as

    m = < src, dst, fl, ty, pl, g(m), sq >

and the two fields this module supplies -- ``fl`` and ``sq`` -- are exactly the
ones `Observation` lacked. Without them a message cannot be identified or
reordered *on its own*: ordering lived in adapter-side counters
(`attack/delay_layer.py:35`, `run_matched_trace.py:143`,
`attack/strict_delay.py:87`), so the object handed to the planner carried no way
to say which message it was or where it sat in its stream.

That is what blocks two things the design needs:

1. **A_T (transport) semantics.** A transport-position adversary "may release
   only an eligible head/prefix of a per-flow FIFO queue, preserving same-flow
   order." You cannot enforce same-flow order without a flow id, and you cannot
   identify the head without a sequence number.
2. **Per-release necessity.** ``sigma_{-i}`` restores *message i* to honest
   delivery while keeping the other releases. Naming message i requires a stable
   identity that survives being held, reordered, and released.

Flow convention
---------------
A flow is one logical stream between two endpoints. Two messages share a flow
iff a FIFO transport would have to keep them in order. Here that is
``src -> dst`` narrowed by the entity when there is one, because two different
sensors do not share a queue in any real deployment:

    platform:binary_sensor.front_door_contact>planner        (observations)
    platform:lock.front_door>planner                          (acks)
    planner>platform                                          (commands)

Sequence numbers are minted **per flow, per run**, by a `FlowMinter` owned by the
adapter -- not a module global. A global counter would leak state between
episodes and silently break the bit-identical replay that Stage 0 exists to
provide.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class MsgType:
    """``ty`` -- the four kinds the design names (design section 1.2)."""

    OBSERVATION = "observation"
    TOOL_RESULT = "tool_result"
    ACTUATION_ACK = "actuation_ack"
    EVENT = "event"

    ALL = (OBSERVATION, TOOL_RESULT, ACTUATION_ACK, EVENT)


def default_flow(src: str, dst: str = "planner", entity_id: str | None = None) -> str:
    """The flow key for a message.

    Narrowed by entity when present: a held door-contact frame must not block a
    lock ack behind it, because they do not share a queue in a real deployment.
    """
    endpoint = f"{src}:{entity_id}" if entity_id else src
    return f"{endpoint}>{dst}"


@dataclass
class FlowMinter:
    """Per-run, per-flow monotonic sequence numbers.

    Owned by whatever creates messages (normally the adapter), so its state dies
    with the episode. Deliberately *not* a module-level counter: replay
    determinism requires that the n-th message of a flow gets the same ``sq`` in
    every run of the same scenario.
    """

    _counters: dict[str, int] = field(default_factory=dict)

    def next_seq(self, flow: str) -> int:
        """Next sequence number for ``flow``, starting at 0."""
        n = self._counters.get(flow, 0)
        self._counters[flow] = n + 1
        return n

    def peek(self, flow: str) -> int:
        """Next value without consuming it (for assertions and tests)."""
        return self._counters.get(flow, 0)

    def stamp(self, obs, *, src: str | None = None, dst: str = "planner",
              msg_type: str = MsgType.OBSERVATION):
        """Attach ``flow``/``seq``/``msg_type`` to an Observation in place.

        Idempotent: an Observation that already carries a seq is returned
        untouched, so a message that passes through several adapters keeps the
        identity it was born with rather than being renumbered by each layer.
        That property is what makes ``sigma_{-i}`` well defined.
        """
        if getattr(obs, "seq", None) is not None:
            return obs
        source = src if src is not None else getattr(obs, "source", "platform")
        flow = default_flow(source, dst, getattr(obs, "entity_id", None))
        obs.flow = flow
        obs.seq = self.next_seq(flow)
        obs.msg_type = msg_type
        obs.dst = dst
        return obs

    def reset(self) -> None:
        self._counters.clear()

    def snapshot(self) -> dict[str, int]:
        """Counter state, for a reproducibility certificate."""
        return dict(self._counters)
