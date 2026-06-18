"""A deterministic, in-process model of Home Assistant's core architecture.

Mirrors the three instrumentation points named in HA ref [2]
(lit_01KSTTKJGREANP6T1W68D9TQ3H): the state machine, the event bus, and the
service registry. Devices are virtual only (safety constraint: never a live
lock/alarm). The same service names HA uses are used here so the real
`HAWebSocketAdapter` is a drop-in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .clock import Clock, ManualClock


@dataclass
class State:
    entity_id: str
    state: str
    attributes: dict[str, Any] = field(default_factory=dict)
    last_changed: float = 0.0
    last_updated: float = 0.0


@dataclass
class Event:
    event_type: str
    data: dict[str, Any]
    time_fired: float


class EventBus:
    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._listeners: dict[str, list[Callable[[Event], None]]] = {}
        self.history: list[Event] = []

    def subscribe(self, event_type: str, cb: Callable[[Event], None]) -> None:
        self._listeners.setdefault(event_type, []).append(cb)

    def fire(self, event_type: str, data: dict[str, Any]) -> Event:
        evt = Event(event_type, data, self._clock.now())
        self.history.append(evt)
        for cb in self._listeners.get(event_type, []):
            cb(evt)
        return evt


class StateMachine:
    def __init__(self, clock: Clock, bus: EventBus) -> None:
        self._clock = clock
        self._bus = bus
        self._states: dict[str, State] = {}

    def set(
        self, entity_id: str, state: str, attributes: dict[str, Any] | None = None
    ) -> State:
        now = self._clock.now()
        old = self._states.get(entity_id)
        changed = old is None or old.state != state
        st = State(
            entity_id=entity_id,
            state=state,
            attributes=attributes if attributes is not None else (old.attributes if old else {}),
            last_changed=now if changed else (old.last_changed if old else now),
            last_updated=now,
        )
        self._states[entity_id] = st
        self._bus.fire(
            "state_changed",
            {
                "entity_id": entity_id,
                "old_state": old,
                "new_state": st,
            },
        )
        return st

    def get(self, entity_id: str) -> State | None:
        return self._states.get(entity_id)

    def all(self) -> dict[str, State]:
        return dict(self._states)


class ServiceRegistry:
    def __init__(self) -> None:
        self._services: dict[tuple[str, str], Callable[[dict[str, Any]], None]] = {}

    def register(self, domain: str, service: str, handler: Callable[[dict[str, Any]], None]) -> None:
        self._services[(domain, service)] = handler

    def has(self, domain: str, service: str) -> bool:
        return (domain, service) in self._services

    def call(self, domain: str, service: str, data: dict[str, Any]) -> None:
        key = (domain, service)
        if key not in self._services:
            raise KeyError(f"unknown service {domain}.{service}")
        self._services[key](data)


# Entity IDs for the eight virtual devices in the testbed.
ENTITIES = {
    "lock": "lock.front_door",
    "contact": "binary_sensor.front_door_contact",
    "alarm": "alarm_control_panel.home_alarm",
    "motion": "binary_sensor.hallway_motion",
    "light": "light.hallway",
    "thermostat": "climate.bedroom",
    "leak": "binary_sensor.kitchen_leak",
    # Camera event source (proposal §10): modelled as a camera-detected motion
    # event rather than a video entity, so it is a real, instrumentable signal.
    "camera": "binary_sensor.front_porch_camera_motion",
}


class VirtualHome:
    """The single home graph (single-orchestrator constraint)."""

    def __init__(self, clock: Clock | None = None) -> None:
        self.clock: Clock = clock or ManualClock()
        self.bus = EventBus(self.clock)
        self.states = StateMachine(self.clock, self.bus)
        self.services = ServiceRegistry()
        self._setup_devices()
        self._register_services()

    def _setup_devices(self) -> None:
        # Initial benign night-time conditions: door physically closed but unlocked,
        # alarm disarmed, no motion, no leak.
        self.states.set(ENTITIES["lock"], "unlocked")
        self.states.set(ENTITIES["contact"], "off", {"device_class": "door"})  # off = closed
        self.states.set(ENTITIES["alarm"], "disarmed")
        self.states.set(ENTITIES["motion"], "off", {"device_class": "motion"})
        self.states.set(ENTITIES["light"], "off")
        self.states.set(ENTITIES["thermostat"], "heat", {"temperature": 20.0})
        self.states.set(ENTITIES["leak"], "off", {"device_class": "moisture"})
        self.states.set(ENTITIES["camera"], "off", {"device_class": "motion"})

    def _register_services(self) -> None:
        sm = self.states

        def lock(data):
            sm.set(data.get("entity_id", ENTITIES["lock"]), "locked")

        def unlock(data):
            sm.set(data.get("entity_id", ENTITIES["lock"]), "unlocked")

        def arm_night(data):
            sm.set(data.get("entity_id", ENTITIES["alarm"]), "armed_night")

        def arm_away(data):
            sm.set(data.get("entity_id", ENTITIES["alarm"]), "armed_away")

        def disarm(data):
            sm.set(data.get("entity_id", ENTITIES["alarm"]), "disarmed")

        def turn_on(data):
            sm.set(data["entity_id"], "on")

        def turn_off(data):
            sm.set(data["entity_id"], "off")

        self.services.register("lock", "lock", lock)
        self.services.register("lock", "unlock", unlock)
        self.services.register("alarm_control_panel", "alarm_arm_night", arm_night)
        self.services.register("alarm_control_panel", "alarm_arm_away", arm_away)
        self.services.register("alarm_control_panel", "alarm_disarm", disarm)
        self.services.register("light", "turn_on", turn_on)
        self.services.register("light", "turn_off", turn_off)

    # --- test/scenario helpers (the "physical world" pokes state directly) ---
    def open_door(self) -> None:
        self.states.set(ENTITIES["contact"], "on")  # on = open

    def close_door(self) -> None:
        self.states.set(ENTITIES["contact"], "off")
