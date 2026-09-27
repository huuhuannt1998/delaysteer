"""E2 -- least-privilege delay-only relay (delaysteer/attack/lp_relay.py).

Everything here runs on the in-process ACL-enforcing broker, so no docker is
needed. One test exercises the live mosquitto path and skips, with the reason,
when no broker answers on the E2 port.
"""

from __future__ import annotations

import json
import os
import socket
import time

import pytest

from delaysteer.attack.lp_relay import (
    ACL_TEXT,
    DEMO_PASSWORDS,
    DevicePublisher,
    HoldPolicy,
    HubVerifier,
    InProcessBroker,
    KeyRing,
    Relay,
    RelayHomeAdapter,
    EpochClock,
    canonical,
    encode_message,
    parse_acl,
    topic_matches,
)
from delaysteer.home.virtual_home import ENTITIES, VirtualHome

CONTACT = ENTITIES["contact"]


def _stack(policy: HoldPolicy | None = None):
    broker = InProcessBroker()
    keys = KeyRing()
    home = VirtualHome(EpochClock())
    dev = DevicePublisher(home, broker.client("device"), keys)
    relay = Relay(broker.client("relay"), policy)
    hub = HubVerifier(broker.client("hub"), keys)
    return broker, keys, home, dev, relay, hub


def _teardown(broker, dev, relay):
    dev.stop()
    relay.stop()
    broker.close()


def _settle(broker, hub, entity, seq, timeout=2.0):
    broker.drain()
    return hub.wait_for(entity, lambda s: s.seq >= seq, timeout)


# --------------------------------------------------------------------------- #
# ACL and topic matching
# --------------------------------------------------------------------------- #
def test_acl_text_is_least_privilege_for_relay():
    acl = parse_acl(ACL_TEXT)
    assert acl["relay"] == [("read", "dev/#"), ("write", "hub/#")]
    assert ("write", "dev/#") not in acl["relay"]
    assert not any("cmd" in pat for _, pat in acl["relay"])
    assert topic_matches("dev/#", "dev/binary_sensor.front_door_contact")
    assert not topic_matches("dev/#", "hub/binary_sensor.front_door_contact")
    assert topic_matches("cmd/+/read", "cmd/lock.front_door/read")


def test_inprocess_broker_denies_relay_upstream_publish_and_cmd_subscribe():
    broker = InProcessBroker()
    relay_client = broker.client("relay")
    r = relay_client.publish("dev/" + CONTACT, b"{}")
    assert not r.accepted and r.reason == "not_authorized"
    assert ("relay", "dev/" + CONTACT) in broker.denied_publishes
    s = relay_client.subscribe("cmd/#", lambda t, p: None)
    assert not s.accepted and s.reason == "not_authorized"
    assert relay_client.subscribe("dev/#", lambda t, p: None).accepted
    assert relay_client.publish("hub/" + CONTACT, b"{}").accepted
    broker.close()


# --------------------------------------------------------------------------- #
# MAC verification at the hub
# --------------------------------------------------------------------------- #
def test_hub_accepts_forwarded_bytes_unchanged():
    broker, keys, home, dev, relay, hub = _stack()
    for _ in range(5):
        dev.publish_observation(CONTACT)
    st = _settle(broker, hub, CONTACT, 5)
    assert st is not None and st.seq == 5 and st.value == "off"
    assert hub.counts["accepted"] == 5 and hub.counts["bad_mac"] == 0
    # byte equality: what the device sent is what the hub verified
    for r in hub.receipts:
        assert r.sha256 == dev.sent[(r.entity, r.seq)]["sha256"]
    _teardown(broker, dev, relay)


def test_hub_rejects_modified_payload():
    broker, keys, home, dev, relay, hub = _stack()
    dev.publish_observation(CONTACT)
    _settle(broker, hub, CONTACT, 1)
    topic, payload, _ = relay.received[-1]
    relay.try_modify(topic, payload)
    broker.drain()
    assert hub.counts["bad_mac"] == 1
    assert hub.get(CONTACT).value == "off"          # cache untouched
    tampered = json.loads(relay.records[-1].sha256_out and canonical(
        {**json.loads(payload), "value": "on"}).decode())
    assert tampered["value"] == "on"                 # the relay really did flip it
    _teardown(broker, dev, relay)


def test_hub_rejects_originated_message_without_device_key():
    broker, keys, home, dev, relay, hub = _stack()
    dev.publish_observation(CONTACT)
    _settle(broker, hub, CONTACT, 1)
    relay.try_originate(CONTACT, "on", seq=2)
    broker.drain()
    assert hub.counts["bad_mac"] == 1 and hub.counts["accepted"] == 1
    assert hub.get(CONTACT).seq == 1
    # sanity: a message signed with the REAL key would be accepted, so the
    # rejection is about the key, not the format.
    relay.tp.publish("hub/" + CONTACT, encode_message(keys, CONTACT, "on", 2, time.time()))
    _settle(broker, hub, CONTACT, 2)
    assert hub.get(CONTACT).value == "on" and hub.counts["accepted"] == 2
    _teardown(broker, dev, relay)


def test_hub_rejects_replay_after_newer_message():
    broker, keys, home, dev, relay, hub = _stack()
    dev.publish_observation(CONTACT)
    dev.publish_observation(CONTACT)
    _settle(broker, hub, CONTACT, 2)
    old_topic, old_payload, _ = relay.received[0]
    relay.try_replay(old_topic, old_payload)          # byte-identical, but seq 1 < 2
    broker.drain()
    assert hub.counts["seq_regression"] == 1
    assert hub.get(CONTACT).seq == 2
    _teardown(broker, dev, relay)


def test_hub_rejects_topic_entity_mismatch_and_malformed():
    broker, keys, home, dev, relay, hub = _stack()
    lock = ENTITIES["lock"]
    good = encode_message(keys, lock, "locked", 1, time.time())
    relay.tp.publish("hub/" + CONTACT, good)          # valid lock message on the contact topic
    relay.tp.publish("hub/" + CONTACT, b"not json")
    broker.drain()
    time.sleep(0.05)
    assert hub.counts["topic_mismatch"] == 1 and hub.counts["malformed"] == 1
    assert hub.get(CONTACT) is None
    _teardown(broker, dev, relay)


# --------------------------------------------------------------------------- #
# Hold semantics: bytes preserved, delay added, exactly once, FIFO
# --------------------------------------------------------------------------- #
def test_hold_preserves_bytes_adds_delay_exactly_once():
    delta = 0.3
    broker, keys, home, dev, relay, hub = _stack(HoldPolicy("hold_entity", CONTACT, delta))
    t0 = time.time()
    for _ in range(5):
        dev.publish_observation(CONTACT)
    broker.drain()
    assert hub.get(CONTACT) is None                  # nothing through yet
    st = _settle(broker, hub, CONTACT, 5, timeout=delta + 2.0)
    assert st is not None and st.seq == 5
    accepted = [r for r in hub.receipts if r.accepted]
    assert len(accepted) == 5
    assert [r.seq for r in accepted] == [1, 2, 3, 4, 5]                  # FIFO
    assert len({(r.entity, r.seq) for r in accepted}) == 5              # exactly once
    for r in accepted:
        assert r.sha256 == dev.sent[(r.entity, r.seq)]["sha256"]        # bytes unchanged
        assert r.t_recv - dev.sent[(r.entity, r.seq)]["t_send"] >= delta - 0.02
    # the other entities were not held
    dev.publish_observation(ENTITIES["lock"])
    assert _settle(broker, hub, ENTITIES["lock"], 1, timeout=0.5) is not None
    _teardown(broker, dev, relay)


def test_hold_keeps_per_entity_fifo_when_hold_ends():
    """A message that arrives while older ones are still held must queue behind them."""
    broker, keys, home, dev, relay, hub = _stack(HoldPolicy("hold_entity", CONTACT, 0.3))
    dev.publish_observation(CONTACT)
    broker.drain()
    relay.set_policy(HoldPolicy("none"))               # hold ends, but seq 1 is still queued
    dev.publish_observation(CONTACT)                  # seq 2 must not overtake seq 1
    st = _settle(broker, hub, CONTACT, 2, timeout=2.0)
    assert st is not None
    assert [r.seq for r in hub.receipts if r.entity == CONTACT and r.accepted] == [1, 2]
    assert hub.counts["seq_regression"] == 0
    _teardown(broker, dev, relay)


def test_hold_replies_is_fact_selective():
    broker, keys, home, dev, relay, hub = _stack(HoldPolicy("hold_replies", CONTACT, 0.4))
    dev.publish_observation(CONTACT)                 # a plain report flows at once
    dev.publish_observation(ENTITIES["lock"])
    assert _settle(broker, hub, CONTACT, 1, timeout=0.5) is not None
    assert _settle(broker, hub, ENTITIES["lock"], 1, timeout=0.5) is not None
    adapter = RelayHomeAdapter(home, hub, read_mode={CONTACT: "poll"}, poll_timeout_s=2.0)
    t0 = time.time()
    obs = adapter.get_state(CONTACT)                  # the reply is what gets held
    assert time.time() - t0 >= 0.38
    assert obs.value == "off" and obs.attributes["read_mode"] == "poll"
    assert not obs.attributes["poll_timed_out"]       # delivered late, not dropped
    lock_obs = adapter.get_state(ENTITIES["lock"])   # other facts unaffected (cache)
    assert lock_obs.value == "unlocked"
    _teardown(broker, dev, relay)


def test_hold_until_read_releases_after_the_agent_reads():
    broker, keys, home, dev, relay, hub = _stack()
    dev.publish_observation(CONTACT)                 # verified "closed" in the cache
    _settle(broker, hub, CONTACT, 1)
    relay.set_policy(HoldPolicy("hold_until_read", CONTACT))
    relay.engage_hold()
    home.open_door()                                   # the truthful "open" is now held
    broker.drain()
    time.sleep(0.05)
    assert hub.get(CONTACT).value == "off"
    adapter = RelayHomeAdapter(home, hub, read_mode={CONTACT: "cache_refresh"})
    obs = adapter.get_state(CONTACT)
    assert obs.value == "off"                          # the agent got the stale value ...
    st = hub.wait_for(CONTACT, lambda s: s.value == "on", 2.0)
    assert st is not None                              # ... and the truth landed right after
    assert hub.counts["seq_regression"] == 0 and hub.counts["bad_mac"] == 0
    _teardown(broker, dev, relay)


# --------------------------------------------------------------------------- #
# The planner-facing adapter
# --------------------------------------------------------------------------- #
def test_relay_adapter_reads_verified_cache_and_commands_go_to_home():
    broker, keys, home, dev, relay, hub = _stack()
    adapter = RelayHomeAdapter(home, hub, settle_s=0.05)
    for e in ENTITIES.values():
        dev.publish_observation(e)
    broker.drain()
    time.sleep(0.05)
    obs = adapter.get_state(ENTITIES["lock"])
    assert obs.value == "unlocked" and obs.attributes["mac_verified"]
    assert obs.arrival_time >= obs.generation_time
    assert obs.identified                              # FlowMinter stamped it
    adapter.call_service("lock", "lock", {"entity_id": ENTITIES["lock"]})
    assert home.states.get(ENTITIES["lock"]).state == "locked"     # command took effect
    assert _settle(broker, hub, ENTITIES["lock"], 2, timeout=1.0).value == "locked"
    assert adapter.get_state(ENTITIES["lock"]).value == "locked"
    # a held entity keeps its stale t_m: the age is visible to whoever looks
    relay.set_policy(HoldPolicy("hold_entity", CONTACT, 5.0))
    t_before = hub.get(CONTACT).t_m
    home.open_door()
    broker.drain()
    obs = adapter.get_state(CONTACT)
    assert obs.value == "off" and obs.generation_time == t_before
    _teardown(broker, dev, relay)


# --------------------------------------------------------------------------- #
# Live broker (skipped without docker)
# --------------------------------------------------------------------------- #
def _broker_up(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not _broker_up(int(os.environ.get("E2_BROKER_PORT", "1884"))),
                    reason="no mosquitto on the E2 port; start it with scripts/run_e2_lp_relay.py "
                           "--broker-only (docker) to run the live-ACL test")
def test_live_mosquitto_acl_denies_relay_upstream_publish():
    pytest.importorskip("paho.mqtt")
    from delaysteer.attack.lp_relay import MqttTransport

    port = int(os.environ.get("E2_BROKER_PORT", "1884"))
    try:
        relay_tp = MqttTransport("127.0.0.1", port, "relay", DEMO_PASSWORDS["relay"], connect_timeout=3)
    except RuntimeError as e:
        pytest.skip(f"broker on {port} refused the demo relay credentials: {e}")
    try:
        r = relay_tp.publish("dev/" + CONTACT, b"{}")
        assert not r.accepted and r.reason == "not_authorized"
        assert relay_tp.publish("hub/" + CONTACT, b"{}").accepted
    finally:
        relay_tp.close()


def test_device_clock_offset_shifts_t_m_only():
    broker = InProcessBroker()
    keys = KeyRing()
    home = VirtualHome(EpochClock())
    dev = DevicePublisher(home, broker.client("device"), keys, clock_offset_s=3.0)
    relay = Relay(broker.client("relay"))
    hub = HubVerifier(broker.client("hub"), keys)
    t0 = time.time()
    dev.publish_observation(CONTACT)
    st = _settle(broker, hub, CONTACT, 1)
    assert st is not None and st.value == "off"
    assert 2.9 < st.t_m - t0 < 3.5                     # the stamp leads the hub by the offset
    assert st.t_g - t0 < 0.5                           # the hub's receipt time does not
    _teardown(broker, dev, relay)


def test_future_stamp_check_is_opt_in_and_flags_a_leading_clock():
    from delaysteer.config import Config
    from delaysteer.defense import TemporalGuard, apply_ablation
    from delaysteer.defense.temporal_guard import REQUIRED
    broker = InProcessBroker()
    keys = KeyRing()
    home = VirtualHome(EpochClock())
    dev = DevicePublisher(home, broker.client("device"), keys, clock_offset_s=3.0)
    relay = Relay(broker.client("relay"))
    hub = HubVerifier(broker.client("hub"), keys)
    adapter = RelayHomeAdapter(home, hub, settle_s=0.05)
    home.services.call("lock", "lock", {"entity_id": ENTITIES["lock"]})
    for e in ENTITIES.values():
        dev.publish_observation(e)
    broker.drain()
    cfg = Config()
    apply_ablation(cfg, "freshness")
    assert not cfg.guard_future_stamp                              # off by default
    assert TemporalGuard(adapter, cfg)._reval_problems(REQUIRED["arm_alarm"]) == []
    cfg.guard_future_stamp = True
    probs = TemporalGuard(adapter, cfg)._reval_problems(REQUIRED["arm_alarm"])
    assert any("FUTURE-STAMPED" in p for p in probs)
    _teardown(broker, dev, relay)
