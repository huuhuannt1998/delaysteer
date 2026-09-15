"""delay_attacker (LAB TESTBED ONLY).

A deliberately compromised Home Assistant integration that holds back event-bus
state updates for ONE target entity, so any consumer reading Home Assistant sees a
truthful-but-stale value. This realizes the delay-only adversary of the DelaySteer
threat model as a malicious *local integration inside the hub*, rather than an
external on-path proxy: the attacker controls the agent's belief channel (a
binary_sensor) while the ground-truth source entity (an input_boolean) stays
untouched, so a freshness guard that revalidates the independent ground-truth
channel still catches the stale read. Runs only on virtual/lab devices.

Services:
  delay_attacker.arm   {source, target, safe, delay}
  delay_attacker.disarm
"""
from __future__ import annotations

import asyncio
import logging

from homeassistant.core import HomeAssistant, Event, callback
from homeassistant.helpers.event import async_track_state_change_event

_LOGGER = logging.getLogger(__name__)
DOMAIN = "delay_attacker"


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    st = {
        "armed": False,
        "source": None,                                   # ground-truth entity (uncompromised)
        "target": "binary_sensor.front_door_compromised",  # the agent's belief channel
        "safe": "off",                                    # stale value to hold (closed)
        "delay": 600.0,
        "holding": False,
        "unsub": None,
        # "hold"  -- withhold the unsafe value, release only if still unsafe after `delay`.
        #            Cancels on a return to safe, so a single transition emits at most one
        #            write, and that write carries the value already published: a NO-OP under
        #            Home Assistant's rule that last_reported refreshes only on a value CHANGE.
        #            This is why the A1 arm blocked at every defended tier.
        # "lag"   -- true lag replay: EVERY authentic transition is re-emitted `delay` seconds
        #            later, in order, with no cancellation. Still strictly delay-only -- every
        #            value published is one the world genuinely produced -- but on a trace that
        #            changes more than once the delayed stream itself contains value changes,
        #            each of which the hub stamps fresh at receipt.
        "policy": "hold",
    }

    def _publish(value: str) -> None:
        hass.states.async_set(
            st["target"], value,
            {"friendly_name": "Front Door Contact (integration)", "device_class": "door"},
        )

    @callback
    def _on_source(event: Event) -> None:
        new = event.data.get("new_state")
        if new is None:
            return
        v = new.state
        if not st["armed"]:
            _publish(v)
            return

        if st["policy"] == "lag":
            async def _lag_release(value: str) -> None:
                await asyncio.sleep(st["delay"])
                _publish(value)          # unconditional: a lag does not cancel
            hass.async_create_task(_lag_release(v))
            return

        if v == st["safe"]:
            # world returned to the safe value: reflect it, end any hold
            st["holding"] = False
            _publish(st["safe"])
            return
        if not st["holding"]:
            # world moved to UNSAFE: hold the stale-safe value, release the truth after `delay`
            st["holding"] = True
            _publish(st["safe"])

            async def _release(true_value: str) -> None:
                await asyncio.sleep(st["delay"])
                if st["holding"]:
                    _publish(true_value)
                    st["holding"] = False

            hass.async_create_task(_release(v))

    async def _arm(call) -> None:
        st["source"] = call.data["source"]
        st["target"] = call.data.get("target", st["target"])
        st["safe"] = call.data.get("safe", "off")
        st["delay"] = float(call.data.get("delay", 600))
        st["policy"] = call.data.get("policy", "hold")
        st["holding"] = False
        st["armed"] = True
        src = hass.states.get(st["source"])
        _publish(src.state if src else st["safe"])
        if st["unsub"] is None:
            st["unsub"] = async_track_state_change_event(hass, [st["source"]], _on_source)
        _LOGGER.warning(
            "delay_attacker ARMED [%s]: %s tracks %s with delay %ss (safe=%s)",
            st["policy"], st["target"], st["source"], st["delay"], st["safe"],
        )

    async def _disarm(call) -> None:
        st["armed"] = False
        st["holding"] = False
        src = hass.states.get(st["source"]) if st["source"] else None
        if src:
            _publish(src.state)
        _LOGGER.warning("delay_attacker DISARMED")

    hass.services.async_register(DOMAIN, "arm", _arm)
    hass.services.async_register(DOMAIN, "disarm", _disarm)
    _publish("off")  # initialize the compromised entity
    return True
