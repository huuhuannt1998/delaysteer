"""E2 -- the least-privilege delay-only attacker (a receive-and-forward relay).

The objection this answers
--------------------------
The paper's live-deployment delay components (`scripts/ha_delay_proxy.py`,
`scripts/sh_delay_proxy.py`) hold a platform token or run in-hub. They *could*
forge a value; the delay-only claim rests on the {hold, release, wait} interface
they expose and on the released traces. A reviewer can fairly say that
"delay-only" is then an artificial restriction on an omnipotent attacker.
Section 9.1 of the manuscript proposes the repair: a broker consumer with
receive-and-forward rights and no publish right would close the privilege gap.
This module realizes that path and measures it.

The path
--------

    device (holds K_e) --dev/<e>--> broker --dev/#--> relay --hub/<e>--> broker --hub/#--> hub (holds K_e)
                                                    ^ the attacker                            |
                                                                                   RelayHomeAdapter -> agent

* ``DevicePublisher`` signs every observation with a per-device HMAC-SHA256 key
  derived from a master secret the relay never sees, and stamps a per-entity
  monotonic ``seq`` and the device measurement time ``t_m``.
* ``Relay`` is the adversary. Its broker credentials grant READ on ``dev/#`` and
  WRITE on ``hub/#`` and nothing else (see ``config/e2_mosquitto/acl``). It can
  buffer selected messages and forward the bytes unchanged later. It can also
  *try* to modify, originate, replay, or publish upstream -- those attempts are
  what the mechanism table counts.
* ``HubVerifier`` consumes ``hub/#``, verifies the MAC with the device key,
  requires strictly increasing ``seq`` per entity, and maintains the verified
  state cache. Anything failing verification is counted and dropped.
* ``RelayHomeAdapter`` exposes that verified cache to the planner through the
  normal ``HomeAdapter`` tool path. Commands go straight to the virtual home:
  commands are not the attack surface here.

Two transports implement the same seam: ``InProcessBroker`` (an ACL-enforcing
fake, so the tests need no docker) and ``MqttTransport`` (paho-mqtt, MQTT v5, so
the broker's own ACL verdict is observable as a PUBACK/SUBACK reason code).

What this is and is not
-----------------------
This realizes compromise minimality under MESSAGE AUTHENTICATION on an MQTT
path. The relay's inability to forge is a property of the HMAC and the key
distribution, not of the relay's good manners. It is not a compromised Zigbee
coordinator, and a relay that never releases is a drop (availability), which
the mechanism table reports as a hold longer than the episode.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import secrets
import statistics
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from ..home.adapter import HomeAdapter, Observation, semantic_type_of
from ..home.virtual_home import ENTITIES, VirtualHome
from ..timed.envelope import FlowMinter, MsgType

# --------------------------------------------------------------------------- #
# Topics and credentials
# --------------------------------------------------------------------------- #
DEV_PREFIX = "dev/"      # device -> relay (authenticated source)
HUB_PREFIX = "hub/"      # relay -> hub (the only thing the relay may write)
CMD_PREFIX = "cmd/"      # hub -> device read requests (the relay has no right here)

ROLES = ("device", "relay", "hub")
# DEMO PASSWORDS. Fixed so the run is reproducible; they protect nothing outside
# this experiment's throwaway broker on a loopback port. The password file is
# generated at run time from these and is git-ignored.
DEMO_PASSWORDS = {r: f"delaysteer-e2-demo-{r}" for r in ROLES}

# The relay's effective privilege set, as mosquitto ACL lines. This is the text
# the report quotes; ``write_acl_file`` writes exactly this.
ACL_TEXT = """\
# E2 least-privilege relay -- mosquitto ACL.
# With an acl_file present, anything not granted here is denied.

# device: originate authenticated observations; receive read requests.
user device
topic write dev/#
topic read cmd/#

# relay (THE ADVERSARY): receive-and-forward only.
#   may consume dev/#, may write hub/#. No publish right on dev/#, no right
#   of any kind on cmd/#. It holds no device key.
user relay
topic read dev/#
topic write hub/#

# hub: consume forwarded observations; issue read requests.
user hub
topic read hub/#
topic write cmd/#
"""

MOSQUITTO_CONF = """\
# E2 least-privilege relay -- throwaway broker for scripts/run_e2_lp_relay.py.
listener 1883
allow_anonymous false
password_file /mosquitto/config/passwd
acl_file /mosquitto/config/acl
log_dest stdout
log_type all
"""


def topic_matches(pattern: str, topic: str) -> bool:
    """MQTT topic-filter match (`+` one level, `#` the rest)."""
    p = pattern.split("/")
    t = topic.split("/")
    for i, seg in enumerate(p):
        if seg == "#":
            return True
        if i >= len(t):
            return False
        if seg != "+" and seg != t[i]:
            return False
    return len(p) == len(t)


# --------------------------------------------------------------------------- #
# Transport seam
# --------------------------------------------------------------------------- #
@dataclass
class PublishResult:
    accepted: bool
    reason: str          # "granted" | "not_authorized" | "timeout" | ...
    topic: str
    sha256: str
    t_send: float


@dataclass
class SubscribeResult:
    accepted: bool
    reason: str


Handler = Callable[[str, bytes], None]


class Transport(Protocol):
    def publish(self, topic: str, payload: bytes) -> PublishResult: ...
    def subscribe(self, topic_filter: str, handler: Handler) -> SubscribeResult: ...
    def close(self) -> None: ...


class InProcessBroker:
    """An in-process broker with mosquitto-style ACL semantics.

    Deliveries are dispatched on one worker thread so a handler that publishes
    (the relay) never runs re-entrantly inside the publisher's call, which is
    how a real broker behaves. Publish to a denied topic returns not_authorized
    and is not delivered; subscribe to a denied filter is refused.
    """

    def __init__(self, acl: dict[str, list[tuple[str, str]]] | None = None) -> None:
        self.acl = acl if acl is not None else parse_acl(ACL_TEXT)
        self._subs: list[tuple[str, str, Handler]] = []   # (username, filter, handler)
        self._lock = threading.Lock()
        self._q: queue.Queue = queue.Queue()
        self._stop = False
        self.denied_publishes: list[tuple[str, str]] = []   # (username, topic)
        self.denied_subscribes: list[tuple[str, str]] = []
        self._worker = threading.Thread(target=self._pump, name="inproc-broker", daemon=True)
        self._worker.start()

    def _allowed(self, username: str, access: str, topic: str) -> bool:
        return any(a == access and topic_matches(pat, topic)
                   for a, pat in self.acl.get(username, []))

    def _pump(self) -> None:
        while not self._stop:
            try:
                item = self._q.get(timeout=0.1)
            except queue.Empty:
                continue
            topic, payload = item
            with self._lock:
                targets = [(u, h) for u, f, h in self._subs if topic_matches(f, topic)]
            for u, h in targets:
                try:
                    h(topic, payload)
                except Exception as e:  # pragma: no cover - defensive
                    print(f"[inproc-broker] handler error for {u}: {e!r}")

    def client(self, username: str) -> "InProcessClient":
        return InProcessClient(self, username)

    def publish(self, username: str, topic: str, payload: bytes) -> PublishResult:
        h = hashlib.sha256(payload).hexdigest()
        if not self._allowed(username, "write", topic):
            self.denied_publishes.append((username, topic))
            return PublishResult(False, "not_authorized", topic, h, time.time())
        t = time.time()
        self._q.put((topic, payload))
        return PublishResult(True, "granted", topic, h, t)

    def subscribe(self, username: str, topic_filter: str, handler: Handler) -> SubscribeResult:
        if not self._allowed(username, "read", topic_filter):
            self.denied_subscribes.append((username, topic_filter))
            return SubscribeResult(False, "not_authorized")
        with self._lock:
            self._subs.append((username, topic_filter, handler))
        return SubscribeResult(True, "granted")

    def drain(self, timeout: float = 2.0) -> None:
        """Wait until every queued delivery has been handed to its handlers."""
        deadline = time.time() + timeout
        while not self._q.empty() and time.time() < deadline:
            time.sleep(0.005)
        time.sleep(0.02)

    def close(self) -> None:
        self._stop = True
        self._worker.join(timeout=1.0)


class InProcessClient:
    def __init__(self, broker: InProcessBroker, username: str) -> None:
        self.broker = broker
        self.username = username

    def publish(self, topic: str, payload: bytes) -> PublishResult:
        return self.broker.publish(self.username, topic, payload)

    def subscribe(self, topic_filter: str, handler: Handler) -> SubscribeResult:
        return self.broker.subscribe(self.username, topic_filter, handler)

    def close(self) -> None:
        pass


def parse_acl(text: str) -> dict[str, list[tuple[str, str]]]:
    """Parse the mosquitto ACL subset used here into {user: [(access, pattern)]}."""
    acl: dict[str, list[tuple[str, str]]] = {}
    user = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):   # '#' mid-line is the MQTT wildcard
            continue
        parts = line.split()
        if parts[0] == "user":
            user = parts[1]
            acl.setdefault(user, [])
        elif parts[0] == "topic" and user is not None:
            if len(parts) == 3:
                access, pattern = parts[1], parts[2]
                accesses = ["read", "write"] if access == "readwrite" else [access]
            else:
                accesses, pattern = ["read", "write"], parts[1]
            for a in accesses:
                acl[user].append((a, pattern))
    return acl


class MqttTransport:
    """paho-mqtt (MQTT v5, QoS 1) so the broker's ACL verdict is a reason code.

    A denied publish surfaces as PUBACK reason 0x87 (Not authorized); a denied
    subscribe as SUBACK 0x87. MQTT 3.1.1 would drop silently, which is why v5.
    """

    def __init__(self, host: str, port: int, username: str, password: str,
                 client_id: str | None = None, connect_timeout: float = 10.0) -> None:
        try:
            import paho.mqtt.client as mqtt
            from paho.mqtt.enums import CallbackAPIVersion
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "paho-mqtt is required for the live broker path: "
                "uv pip install --python .venv/bin/python paho-mqtt") from e
        self._mqtt = mqtt
        self.username = username
        self._handlers: list[tuple[str, Handler]] = []
        self._hlock = threading.Lock()
        self._pub_rc: dict[int, str] = {}
        self._pub_ev: dict[int, threading.Event] = {}
        self._sub_rc: dict[int, str] = {}
        self._sub_ev: dict[int, threading.Event] = {}
        self._connected = threading.Event()
        # Handlers run on a dispatcher thread, not paho's network thread: a
        # handler that publishes and waits for its PUBACK (the relay) would
        # otherwise block the very thread that delivers that PUBACK.
        self._inbox: queue.Queue = queue.Queue()
        self._stopped = threading.Event()
        self._dispatcher = threading.Thread(target=self._dispatch, name=f"mqtt-dispatch-{username}",
                                            daemon=True)
        self._dispatcher.start()
        c = mqtt.Client(CallbackAPIVersion.VERSION2,
                        client_id=client_id or f"e2-{username}-{secrets.token_hex(3)}",
                        protocol=mqtt.MQTTv5)
        c.username_pw_set(username, password)
        c.on_connect = self._on_connect
        c.on_message = self._on_message
        c.on_publish = self._on_publish
        c.on_subscribe = self._on_subscribe
        self.client = c
        c.connect(host, port, keepalive=30)
        c.loop_start()
        if not self._connected.wait(connect_timeout):
            raise RuntimeError(f"MQTT connect timeout for {username}@{host}:{port}")

    # paho callbacks (network thread)
    def _on_connect(self, client, userdata, flags, reason_code, properties):
        if reason_code.is_failure:
            print(f"[mqtt:{self.username}] connect refused: {reason_code}")
        else:
            self._connected.set()

    def _on_message(self, client, userdata, msg):
        self._inbox.put((msg.topic, bytes(msg.payload)))

    def _dispatch(self) -> None:
        while not self._stopped.is_set():
            try:
                topic, payload = self._inbox.get(timeout=0.1)
            except queue.Empty:
                continue
            with self._hlock:
                hs = [h for f, h in self._handlers if topic_matches(f, topic)]
            for h in hs:
                try:
                    h(topic, payload)
                except Exception as e:  # pragma: no cover - defensive
                    print(f"[mqtt:{self.username}] handler error: {e!r}")

    def _on_publish(self, client, userdata, mid, reason_code, properties):
        self._pub_rc[mid] = str(reason_code)
        ev = self._pub_ev.get(mid)
        if ev:
            ev.set()

    def _on_subscribe(self, client, userdata, mid, reason_codes, properties):
        self._sub_rc[mid] = ",".join(str(r) for r in reason_codes)
        ev = self._sub_ev.get(mid)
        if ev:
            ev.set()

    def publish(self, topic: str, payload: bytes, timeout: float = 5.0) -> PublishResult:
        h = hashlib.sha256(payload).hexdigest()
        t = time.time()
        info = self.client.publish(topic, payload, qos=1)
        ev = threading.Event()
        self._pub_ev[info.mid] = ev
        if info.mid in self._pub_rc:      # ack raced ahead of the event registration
            ev.set()
        if not ev.wait(timeout):
            return PublishResult(False, "timeout", topic, h, t)
        rc = self._pub_rc.pop(info.mid, "?")
        self._pub_ev.pop(info.mid, None)
        ok = rc in ("Success", "No matching subscribers")
        return PublishResult(ok, "granted" if ok else
                             ("not_authorized" if "authorized" in rc.lower() else rc),
                             topic, h, t)

    def subscribe(self, topic_filter: str, handler: Handler, timeout: float = 5.0) -> SubscribeResult:
        with self._hlock:
            self._handlers.append((topic_filter, handler))
        rc, mid = self.client.subscribe(topic_filter, qos=1)
        ev = threading.Event()
        self._sub_ev[mid] = ev
        if mid in self._sub_rc:
            ev.set()
        if not ev.wait(timeout):
            return SubscribeResult(False, "timeout")
        r = self._sub_rc.pop(mid, "?")
        self._sub_ev.pop(mid, None)
        ok = r.startswith("Granted")
        if not ok:
            with self._hlock:
                self._handlers = [(f, h) for f, h in self._handlers if f != topic_filter]
        return SubscribeResult(ok, "granted" if ok else
                               ("not_authorized" if "authorized" in r.lower() else r))

    def close(self) -> None:
        self._stopped.set()
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Message authentication
# --------------------------------------------------------------------------- #
def canonical(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


class KeyRing:
    """Per-device keys derived from a master secret. The relay never holds one."""

    def __init__(self, master: bytes | None = None) -> None:
        self.master = master or secrets.token_bytes(32)

    def key_for(self, entity: str) -> bytes:
        return hmac.new(self.master, entity.encode(), hashlib.sha256).digest()

    def mac(self, entity: str, body: dict[str, Any]) -> str:
        return hmac.new(self.key_for(entity), canonical(body), hashlib.sha256).hexdigest()

    def verify(self, entity: str, body: dict[str, Any], mac: str) -> bool:
        return hmac.compare_digest(self.mac(entity, body), str(mac))


def encode_message(keys: KeyRing, entity: str, value: str, seq: int, t_m: float,
                   kind: str = "report", req: str | None = None,
                   attributes: dict[str, Any] | None = None) -> bytes:
    body: dict[str, Any] = {"entity": entity, "value": value, "t_m": t_m, "seq": seq, "kind": kind}
    if req is not None:
        body["req"] = req
    if attributes:
        body["attributes"] = attributes
    body["mac"] = keys.mac(entity, body)
    return canonical(body)


def split_mac(payload: bytes) -> tuple[dict[str, Any], str] | None:
    try:
        obj = json.loads(payload.decode())
    except Exception:
        return None
    if not isinstance(obj, dict) or "mac" not in obj:
        return None
    mac = obj.pop("mac")
    return obj, mac


# --------------------------------------------------------------------------- #
# Device publisher (authenticated source)
# --------------------------------------------------------------------------- #
class DevicePublisher:
    """Publishes signed observations for every virtual-home entity.

    Three triggers: a state change on the home's event bus, a periodic
    heartbeat, and a read request on ``cmd/<entity>/read`` (answered with a
    ``kind="reply"`` message carrying the request id).
    """

    def __init__(self, home: VirtualHome, transport: Transport, keys: KeyRing,
                 heartbeat_s: float = 1.0, entities: dict[str, str] | None = None,
                 clock_offset_s: float = 0.0) -> None:
        self.home = home
        # Device clock minus hub clock. >0 leads the hub, <0 lags it. Only the skew sweep
        # (scripts/run_skew_sweep.py) sets it; 0 keeps every earlier campaign unchanged.
        self.clock_offset_s = clock_offset_s
        self.tp = transport
        self.keys = keys
        self.heartbeat_s = heartbeat_s
        self.entities = dict(entities or ENTITIES)
        self._seq: dict[str, int] = {}
        self._lock = threading.Lock()
        self.sent: dict[tuple[str, int], dict[str, Any]] = {}   # (entity, seq) -> {sha256, t_send, ...}
        self._stop = threading.Event()
        self._hb: threading.Thread | None = None
        self.home.bus.subscribe("state_changed", self._on_state_changed)
        r = self.tp.subscribe(CMD_PREFIX + "#", self._on_cmd)
        self.cmd_subscribe = r

    def _next_seq(self, entity: str) -> int:
        with self._lock:
            n = self._seq.get(entity, 0) + 1
            self._seq[entity] = n
            return n

    def last_seq(self, entity: str) -> int:
        return self._seq.get(entity, 0)

    def publish_observation(self, entity: str, value: str | None = None, *,
                            kind: str = "report", req: str | None = None) -> PublishResult:
        st = self.home.states.get(entity)
        if value is None:
            if st is None:
                raise KeyError(entity)
            value = st.state
        seq = self._next_seq(entity)
        t_m = time.time() + self.clock_offset_s
        payload = encode_message(self.keys, entity, value, seq, t_m, kind=kind, req=req)
        res = self.tp.publish(DEV_PREFIX + entity, payload)
        self.sent[(entity, seq)] = {"sha256": res.sha256, "t_send": res.t_send, "value": value,
                                    "kind": kind, "accepted_by_broker": res.accepted}
        return res

    def _on_state_changed(self, evt) -> None:
        entity = evt.data.get("entity_id")
        if entity in self.entities.values():
            self.publish_observation(entity)

    def _on_cmd(self, topic: str, payload: bytes) -> None:
        # cmd/<entity>/read  {"req": id}
        parts = topic.split("/")
        if len(parts) < 3 or parts[-1] != "read":
            return
        entity = "/".join(parts[1:-1])
        try:
            req = json.loads(payload.decode()).get("req")
        except Exception:
            req = None
        if entity in self.entities.values():
            self.publish_observation(entity, kind="reply", req=req)

    def start_heartbeat(self) -> None:
        def loop():
            while not self._stop.wait(self.heartbeat_s):
                for e in self.entities.values():
                    try:
                        self.publish_observation(e, kind="heartbeat")
                    except Exception as ex:  # pragma: no cover
                        print(f"[device] heartbeat publish failed: {ex!r}")
        self._hb = threading.Thread(target=loop, name="device-heartbeat", daemon=True)
        self._hb.start()

    def stop(self) -> None:
        self._stop.set()
        if self._hb:
            self._hb.join(timeout=2.0)


# --------------------------------------------------------------------------- #
# The relay (the adversary)
# --------------------------------------------------------------------------- #
@dataclass
class HoldPolicy:
    """What the relay does with messages of one entity.

    kind:
      none            forward immediately
      hold_entity     FIFO delay line: every message of `entity` is forwarded
                      `delay_s` after receipt (transitions, heartbeats, replies)
      hold_replies    fact-selective: only `kind == "reply"` messages of `entity`
                      (answers to the hub's read requests) are delayed `delay_s`;
                      everything else forwards at once
      hold_until_read hold every message of `entity` until a device reply for
                      it is seen on dev/# (evidence the hub/agent just read the
                      fact), then release the buffer in order after `grace_s`
    """

    kind: str = "none"
    entity: str | None = None
    delay_s: float = 0.0
    grace_s: float = 0.0


@dataclass
class ForwardRecord:
    entity: str
    seq: int | None
    action: str            # forward | modify | originate | replay | publish_to_dev
    topic: str
    sha256_in: str | None
    sha256_out: str
    t_recv: float | None
    t_send: float
    broker_accepted: bool
    broker_reason: str


class Relay:
    """Receive-and-forward broker client with a hold policy and a malice menu.

    Holds NO device key. Everything it can do to a message is visible in
    ``records``: forwarding (bytes unchanged), holding (bytes unchanged, later),
    and the attempted violations the mechanism table measures.
    """

    def __init__(self, transport: Transport, policy: HoldPolicy | None = None) -> None:
        self.tp = transport
        self.policy = policy or HoldPolicy()
        self.records: list[ForwardRecord] = []
        self.received: list[tuple[str, bytes, float]] = []
        self._lock = threading.Lock()
        self._delay_q: queue.PriorityQueue = queue.PriorityQueue()
        self._seqno = 0
        self._buffer: list[tuple[str, bytes, float]] = []      # hold_until_read
        self._buffer_open = False
        self._stop = threading.Event()
        # Per-entity FIFO: a transport-position adversary may reorder across
        # flows, never within one. A message that would overtake something still
        # held for its entity is queued behind it instead.
        self._last_when: dict[str, float] = {}
        self.paused = False        # for the mechanism harness: capture without forwarding
        self._worker = threading.Thread(target=self._release_loop, name="relay-delay", daemon=True)
        self._worker.start()
        self.subscribe_result = self.tp.subscribe(DEV_PREFIX + "#", self._on_dev)

    # -- policy control -------------------------------------------------------
    def set_policy(self, policy: HoldPolicy) -> None:
        with self._lock:
            self.policy = policy
            self._buffer_open = policy.kind == "hold_until_read"

    def engage_hold(self) -> None:
        """Start holding now (hold_until_read): everything after this buffers."""
        with self._lock:
            self._buffer_open = True

    # -- the receive path -------------------------------------------------------
    @staticmethod
    def _entity_of(topic: str) -> str:
        return topic[len(DEV_PREFIX):]

    @staticmethod
    def _peek(payload: bytes) -> dict[str, Any]:
        try:
            return json.loads(payload.decode())
        except Exception:
            return {}

    def _on_dev(self, topic: str, payload: bytes) -> None:
        t_recv = time.time()
        with self._lock:
            self.received.append((topic, payload, t_recv))
            if self.paused:
                return
            pol = self.policy
        entity = self._entity_of(topic)
        meta = self._peek(payload)
        hub_topic = HUB_PREFIX + entity
        if pol.kind == "hold_entity" and entity == pol.entity:
            self._schedule(t_recv + pol.delay_s, hub_topic, payload, t_recv)
            return
        if pol.kind == "hold_replies" and entity == pol.entity and meta.get("kind") == "reply":
            self._schedule(t_recv + pol.delay_s, hub_topic, payload, t_recv)
            return
        if pol.kind == "hold_until_read" and entity == pol.entity:
            to_release: list[tuple[str, bytes, float]] = []
            with self._lock:
                buffered = self._buffer_open
                if buffered:
                    self._buffer.append((hub_topic, payload, t_recv))
                    if meta.get("kind") == "reply":
                        # The hub just read this fact: the stale value is already
                        # in the agent's hands. Release everything, in order.
                        self._buffer_open = False
                        to_release = list(self._buffer)
                        self._buffer.clear()
            if buffered:
                release_at = time.time() + pol.grace_s
                for tpc, pl, tr in to_release:      # outside the lock: _schedule locks too
                    self._schedule(release_at, tpc, pl, tr)
                return
        with self._lock:
            behind = self._last_when.get(entity, 0.0) > time.time()
        if behind:
            self._schedule(time.time(), hub_topic, payload, t_recv)   # queue behind the hold
        else:
            self._forward(hub_topic, payload, t_recv, "forward")

    def _schedule(self, when: float, topic: str, payload: bytes, t_recv: float) -> None:
        entity = topic.split("/", 1)[-1]
        with self._lock:
            when = max(when, self._last_when.get(entity, 0.0))
            self._last_when[entity] = when
            self._seqno += 1
            n = self._seqno
        self._delay_q.put((when, n, topic, payload, t_recv))

    def _release_loop(self) -> None:
        while not self._stop.is_set():
            try:
                when, n, topic, payload, t_recv = self._delay_q.get(timeout=0.05)
            except queue.Empty:
                continue
            wait = when - time.time()
            while wait > 0 and not self._stop.is_set():
                time.sleep(min(wait, 0.02))
                wait = when - time.time()
            if self._stop.is_set():
                self._delay_q.put((when, n, topic, payload, t_recv))
                return
            self._forward(topic, payload, t_recv, "forward")

    def _forward(self, topic: str, payload: bytes, t_recv: float | None, action: str,
                 sha_in: str | None = None) -> PublishResult:
        res = self.tp.publish(topic, payload)
        meta = self._peek(payload)
        rec = ForwardRecord(
            entity=meta.get("entity", topic.split("/", 1)[-1]), seq=meta.get("seq"),
            action=action, topic=topic,
            sha256_in=sha_in if sha_in is not None else hashlib.sha256(payload).hexdigest(),
            sha256_out=res.sha256, t_recv=t_recv, t_send=res.t_send,
            broker_accepted=res.accepted, broker_reason=res.reason)
        with self._lock:
            self.records.append(rec)
        return res

    def pending(self) -> int:
        return self._delay_q.qsize() + len(self._buffer)

    def flush_pending(self) -> int:
        """Drop everything still held (a hold longer than the episode is a drop)."""
        n = 0
        while True:
            try:
                self._delay_q.get_nowait()
                n += 1
            except queue.Empty:
                break
        with self._lock:
            n += len(self._buffer)
            self._buffer.clear()
        return n

    # -- the malice menu (every one of these must fail downstream) --------------
    def try_modify(self, topic: str, payload: bytes) -> PublishResult:
        """Flip the value and forward. The MAC no longer matches."""
        obj = self._peek(payload)
        flip = {"off": "on", "on": "off", "locked": "unlocked", "unlocked": "locked",
                "armed_night": "disarmed", "disarmed": "armed_night"}
        obj["value"] = flip.get(obj.get("value"), "tampered")
        tampered = canonical(obj)
        return self._forward(HUB_PREFIX + self._entity_of(topic), tampered, None, "modify",
                             sha_in=hashlib.sha256(payload).hexdigest())

    def try_originate(self, entity: str, value: str, seq: int) -> PublishResult:
        """Fabricate a fresh message. The relay has no device key, so it makes one up."""
        fake_keys = KeyRing()
        payload = encode_message(fake_keys, entity, value, seq, time.time())
        return self._forward(HUB_PREFIX + entity, payload, None, "originate", sha_in=None)

    def try_replay(self, topic: str, payload: bytes) -> PublishResult:
        """Re-send an old, byte-identical message after newer ones were delivered."""
        return self._forward(HUB_PREFIX + self._entity_of(topic), payload, None, "replay")

    def try_publish_to_dev(self, entity: str, payload: bytes) -> PublishResult:
        """Publish upstream on dev/<entity> with the relay's credentials (ACL test)."""
        return self._forward(DEV_PREFIX + entity, payload, None, "publish_to_dev")

    def stop(self) -> None:
        self._stop.set()
        self._worker.join(timeout=1.0)


# --------------------------------------------------------------------------- #
# The hub verifier
# --------------------------------------------------------------------------- #
@dataclass
class VerifiedState:
    entity: str
    value: str
    t_m: float             # device measurement time
    t_g: float             # hub receipt (verification) time
    seq: int
    kind: str
    sha256: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReceiptRecord:
    entity: str
    seq: int | None
    topic: str
    sha256: str
    t_recv: float
    t_m: float | None
    accepted: bool
    reason: str            # accepted | bad_mac | seq_regression | malformed | topic_mismatch | unknown_entity
    kind: str | None = None
    req: str | None = None


class HubVerifier:
    """Verifies MAC + seq monotonicity on hub/#, keeps the verified state cache."""

    REASONS = ("accepted", "bad_mac", "seq_regression", "malformed", "topic_mismatch", "unknown_entity")

    def __init__(self, transport: Transport, keys: KeyRing,
                 entities: dict[str, str] | None = None) -> None:
        self.tp = transport
        self.keys = keys
        self.entities = set((entities or ENTITIES).values())
        self.state: dict[str, VerifiedState] = {}
        self.last_seq: dict[str, int] = {}
        self.receipts: list[ReceiptRecord] = []
        self.counts: dict[str, int] = {r: 0 for r in self.REASONS}
        self.cv = threading.Condition()
        self.subscribe_result = self.tp.subscribe(HUB_PREFIX + "#", self._on_hub)

    def _on_hub(self, topic: str, payload: bytes) -> None:
        t = time.time()
        sha = hashlib.sha256(payload).hexdigest()
        entity_from_topic = topic[len(HUB_PREFIX):]
        parsed = split_mac(payload)
        if parsed is None:
            return self._reject(entity_from_topic, None, topic, sha, t, None, "malformed")
        body, mac = parsed
        entity = body.get("entity")
        seq = body.get("seq")
        t_m = body.get("t_m")
        kind = body.get("kind")
        req = body.get("req")
        if entity != entity_from_topic:
            return self._reject(entity_from_topic, seq, topic, sha, t, t_m, "topic_mismatch", kind, req)
        if entity not in self.entities:
            return self._reject(entity, seq, topic, sha, t, t_m, "unknown_entity", kind, req)
        if not isinstance(seq, int) or not isinstance(t_m, (int, float)) or "value" not in body:
            return self._reject(entity, seq, topic, sha, t, t_m, "malformed", kind, req)
        if not self.keys.verify(entity, body, mac):
            return self._reject(entity, seq, topic, sha, t, t_m, "bad_mac", kind, req)
        with self.cv:
            if seq <= self.last_seq.get(entity, 0):
                self.counts["seq_regression"] += 1
                self.receipts.append(ReceiptRecord(entity, seq, topic, sha, t, t_m, False,
                                                   "seq_regression", kind, req))
                return
            self.last_seq[entity] = seq
            self.state[entity] = VerifiedState(entity, str(body["value"]), float(t_m), t, seq,
                                               str(kind), sha, dict(body.get("attributes") or {}))
            self.counts["accepted"] += 1
            self.receipts.append(ReceiptRecord(entity, seq, topic, sha, t, t_m, True,
                                               "accepted", kind, req))
            self.cv.notify_all()

    def _reject(self, entity, seq, topic, sha, t, t_m, reason, kind=None, req=None) -> None:
        with self.cv:
            self.counts[reason] += 1
            self.receipts.append(ReceiptRecord(entity, seq, topic, sha, t, t_m, False, reason, kind, req))

    def get(self, entity: str) -> VerifiedState | None:
        with self.cv:
            return self.state.get(entity)

    def wait_for(self, entity: str, pred: Callable[[VerifiedState], bool],
                 timeout: float) -> VerifiedState | None:
        """Block until the verified state for `entity` satisfies `pred` or timeout."""
        deadline = time.time() + timeout
        with self.cv:
            while True:
                st = self.state.get(entity)
                if st is not None and pred(st):
                    return st
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self.cv.wait(remaining)

    def wait_for_reply(self, entity: str, req: str, timeout: float) -> ReceiptRecord | None:
        deadline = time.time() + timeout
        with self.cv:
            while True:
                for r in reversed(self.receipts):
                    if r.accepted and r.entity == entity and r.req == req:
                        return r
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self.cv.wait(remaining)

    def request_read(self, entity: str) -> str:
        req = secrets.token_hex(6)
        self.tp.publish(f"{CMD_PREFIX}{entity}/read", canonical({"req": req, "t": time.time()}))
        return req


# --------------------------------------------------------------------------- #
# The planner-facing adapter
# --------------------------------------------------------------------------- #
class EpochClock:
    """Wall clock in epoch seconds, so device t_m and planner `now` share an axis."""

    def now(self) -> float:
        return time.time()


class RelayHomeAdapter(HomeAdapter):
    """Reads come from the hub's verified cache; commands go to the virtual home.

    read_mode per entity:
      cache          serve the last verified value; generation_time = its t_m,
                     arrival_time = now (a cache read affirms the value now, as
                     HA's /api/states does)
      cache_refresh  as cache, and also fire a read request so the device
                     re-reports (a read-through cache); non-blocking
      poll           fire a read request and BLOCK until the verified reply
                     lands or `poll_timeout_s` elapses; on timeout return the
                     cached value with arrival_time = now, which the planner's
                     recovery policy scores as timed out
    """

    def __init__(self, home: VirtualHome, hub: HubVerifier, *,
                 read_mode: dict[str, str] | None = None, default_mode: str = "cache",
                 poll_timeout_s: float = 8.0, settle_s: float = 0.25) -> None:
        self.home = home
        self.hub = hub
        self.clock = EpochClock()
        self.read_mode = dict(read_mode or {})
        self.default_mode = default_mode
        self.poll_timeout_s = poll_timeout_s
        self.settle_s = settle_s
        self.minter = FlowMinter()
        self.reads: list[dict[str, Any]] = []

    def _mode(self, entity: str) -> str:
        return self.read_mode.get(entity, self.default_mode)

    def _obs_from(self, st: VerifiedState, entity: str, arrival: float, mode: str,
                  timed_out: bool = False) -> Observation:
        obs = Observation(
            semantic_type=semantic_type_of(entity), value=st.value,
            attributes={**st.attributes, "hub_seq": st.seq, "t_g": st.t_g, "mac_verified": True,
                        "read_mode": mode, "poll_timed_out": timed_out},
            source="relay_hub", entity_id=entity,
            generation_time=st.t_m, arrival_time=arrival)
        self.reads.append({"entity": entity, "mode": mode, "value": st.value, "t_m": st.t_m,
                           "t_g": st.t_g, "seq": st.seq, "t_read": arrival,
                           "age_s": arrival - st.t_m, "timed_out": timed_out})
        return self.minter.stamp(obs, msg_type=MsgType.OBSERVATION)

    def get_state(self, entity_id: str) -> Observation:
        mode = self._mode(entity_id)
        st = self.hub.get(entity_id)
        if mode == "poll":
            req = self.hub.request_read(entity_id)
            rec = self.hub.wait_for_reply(entity_id, req, self.poll_timeout_s)
            st2 = self.hub.get(entity_id)
            if rec is not None:
                return self._obs_from(st2, entity_id, rec.t_recv, mode)
            if st2 is None:
                raise TimeoutError(f"no verified state for {entity_id}")
            return self._obs_from(st2, entity_id, time.time(), mode, timed_out=True)
        if mode == "cache_refresh":
            self.hub.request_read(entity_id)
        if st is None:
            st = self.hub.wait_for(entity_id, lambda s: True, self.poll_timeout_s)
            if st is None:
                raise TimeoutError(f"no verified state for {entity_id}")
        return self._obs_from(st, entity_id, time.time(), mode)

    def call_service(self, domain: str, service: str, data: dict[str, Any] | None = None) -> Observation:
        data = data or {}
        t0 = time.time()
        self.home.services.call(domain, service, data)   # commands: not the attack surface
        time.sleep(self.settle_s)                          # let the device report land
        now = time.time()
        return Observation(semantic_type="actuation_ack", value="ack",
                           attributes={"domain": domain, "service": service, "data": data},
                           source="virtual_home", entity_id=data.get("entity_id"),
                           generation_time=t0, arrival_time=now)

    def entities(self) -> dict[str, str]:
        return dict(ENTITIES)


# --------------------------------------------------------------------------- #
# Mosquitto helpers (config/e2_mosquitto)
# --------------------------------------------------------------------------- #
def write_broker_config(cfg_dir: str, passwords: dict[str, str] | None = None) -> None:
    """Write mosquitto.conf, acl, and a .gitignore; the password file is hashed
    separately by `mosquitto_passwd` (see scripts/run_e2_lp_relay.py)."""
    os.makedirs(cfg_dir, exist_ok=True)
    with open(os.path.join(cfg_dir, "mosquitto.conf"), "w") as f:
        f.write(MOSQUITTO_CONF)
    with open(os.path.join(cfg_dir, "acl"), "w") as f:
        f.write(ACL_TEXT)
    with open(os.path.join(cfg_dir, ".gitignore"), "w") as f:
        f.write("# generated at run time; demo credentials, never committed\npasswd\n")


# --------------------------------------------------------------------------- #
# Accounting helpers for the mechanism table
# --------------------------------------------------------------------------- #
def summarize_condition(name: str, relay: Relay, hub: HubVerifier, publisher: DevicePublisher,
                        action: str, sent_keys: list[tuple[str, int]],
                        first_receipt_index: int, first_record_index: int,
                        baseline_latency_s: float = 0.0) -> dict[str, Any]:
    """One row of results/e2_lp_relay_mechanism.csv."""
    recs = [r for r in relay.records[first_record_index:] if r.action == action]
    receipts = hub.receipts[first_receipt_index:]
    n_attempted = len(recs)
    broker_accepted = sum(1 for r in recs if r.broker_accepted)
    acl_denied = sum(1 for r in recs if r.broker_reason == "not_authorized")
    delivered = [r for r in receipts]
    accepted = [r for r in delivered if r.accepted]
    rejected = [r for r in delivered if not r.accepted]
    reasons: dict[str, int] = {}
    for r in rejected:
        reasons[r.reason] = reasons.get(r.reason, 0) + 1
    src_sha = {k: publisher.sent[k]["sha256"] for k in sent_keys if k in publisher.sent}
    bytes_equal = sum(1 for r in delivered if src_sha.get((r.entity, r.seq)) == r.sha256)
    seen: dict[tuple[str, int | None], int] = {}
    for r in delivered:
        seen[(r.entity, r.seq)] = seen.get((r.entity, r.seq), 0) + 1
    dup = sum(c - 1 for c in seen.values() if c > 1)
    lat = []
    for r in accepted:
        s = publisher.sent.get((r.entity, r.seq))
        if s:
            lat.append(r.t_recv - s["t_send"])
    return {
        "condition": name, "action": action, "n_source_messages": len(sent_keys),
        "n_relay_attempts": n_attempted, "broker_accepted": broker_accepted,
        "broker_acl_denied": acl_denied, "delivered_at_hub": len(delivered),
        "accepted_at_hub": len(accepted), "rejected_at_hub": len(rejected),
        "reject_reasons": ";".join(f"{k}={v}" for k, v in sorted(reasons.items())) or "",
        "bytes_equal_to_source": bytes_equal, "duplicates_at_hub": dup,
        "exactly_once": (dup == 0 and len(accepted) == len(set((r.entity, r.seq) for r in accepted))),
        "latency_median_s": round(statistics.median(lat), 4) if lat else "",
        "latency_p95_s": round(sorted(lat)[max(0, int(0.95 * len(lat)) - 1)], 4) if lat else "",
        "latency_max_s": round(max(lat), 4) if lat else "",
        "added_latency_median_s": round(statistics.median(lat) - baseline_latency_s, 4) if lat else "",
    }
