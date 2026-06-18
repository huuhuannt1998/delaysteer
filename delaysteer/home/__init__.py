"""Virtual home + platform-adapter layer.

`VirtualHome` faithfully models the three Home Assistant core abstractions
(state machine, event bus, service registry — HA ref [2], lit_01KSTTKJGREANP6T1W68D9TQ3H)
so the harness is deterministic, safe (no live devices), and replayable. The
`HomeAdapter` interface lets the same planner drive either the virtual home or a
real Home Assistant instance via `HAWebSocketAdapter`.
"""
