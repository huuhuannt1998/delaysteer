// matter.js controller with an in-process, delay-only adversary on its UDP receive path.
//
// The hold shim wraps NodeJsUdpSocket.onData (the controller's network layer). Datagrams whose source port is the
// device's operational port are, while a hold is active, queued unmodified (the original Buffer object is kept, its
// SHA-256 recorded on arrival) and later handed to the matter.js listener in arrival order, after re-hashing to prove
// the bytes are unchanged. Nothing is dropped, modified, forged or reordered. All other datagrams (mDNS, other
// hosts) pass straight through. The controller never learns that a hold happened except through timing.
import { DEVICE_PORT, DISCRIMINATOR, PASSCODE, emit, installLogTap, parseHeader, sha256 } from "./common.mjs";
import { NodeJsUdpSocket } from "@matter/nodejs";
import { Environment, Logger } from "@matter/main";
import { GeneralCommissioning } from "@matter/main/clusters";
import { BooleanStateClient } from "@matter/main/behaviors/boolean-state";
import { NodeId } from "@matter/main/types";
import { MRP, SessionIntervals } from "@matter/protocol";
import { CommissioningController } from "@project-chip/matter.js";
import { NodeStates } from "@project-chip/matter.js/device";

const ROLE = "controller";

installLogTap(Logger, ROLE, [
    ["sub_timeout", /Subscription\s+\S+\s+to peer\s+.*timed out after/],
    ["peer_unresponsive", /Peer is no longer responding/],
    ["sub_ok", /Subscription successful/],
    ["sub_req", /Subscribe »/],
    ["sub_established", /[Ss]ubscription.*(established|active)/],
    ["invalid_sub", /[Ii]nvalid ?[Ss]ubscription|unknown subscription/i],
    ["dup", /[Dd]uplicate/],
    ["warn_or_error", /\b(WARN|ERROR)\b/],
    ["resubscribe", /[Rr]esubscri|[Rr]econnect/],
]);

// ------------------------------------------------------------------ hold shim
let seq = 0;
let holdSeq = 0;
let hold = { active: false };
let lastDeliveredT; // last time a device datagram was handed to matter.js

function deliver(listener, ni, address, port, data) {
    lastDeliveredT = Date.now();
    listener(ni, address, port, data);
}

function onDatagram(listener, ni, address, port, data) {
    if (port !== DEVICE_PORT) {
        listener(ni, address, port, data);
        return;
    }
    const t = Date.now();
    const s = ++seq;
    const h = parseHeader(data);
    const key = `${h?.sessionId}:${h?.counter}`;
    const sha = sha256(data);
    let held = false;
    if (hold.active) {
        if (hold.mode === "all") {
            held = true;
        } else if (hold.mode === "select") {
            // Select a value-bearing message by its cleartext (session, counter) and hold it plus its MRP
            // retransmissions (byte-identical copies); pass every other datagram.
            if (hold.key === undefined && data.length >= hold.minLen) {
                hold.key = key;
            }
            held = hold.key === key;
        }
    }
    emit(ROLE, "rx", { seq: s, addr: address, port, len: data.length, sha, sess: h?.sessionId, ctr: h?.counter, held, holdId: hold.active ? hold.id : undefined, t });
    if (held) {
        hold.queue.push({ seq: s, t, listener, ni, address, port, data, sha, key });
        return;
    }
    deliver(listener, ni, address, port, data);
}

const origOnData = NodeJsUdpSocket.prototype.onData;
NodeJsUdpSocket.prototype.onData = function (listener) {
    return origOnData.call(this, (ni, address, port, data) => onDatagram(listener, ni, address, port, data));
};

function startHold({ mode, durationMs, releaseOnLost, capMs, minLen }) {
    if (hold.active) release("superseded");
    const id = ++holdSeq;
    hold = { id, active: true, mode, queue: [], key: undefined, minLen: minLen ?? 60, tStart: Date.now(), releaseOnLost: !!releaseOnLost };
    if (durationMs !== undefined && durationMs !== null) {
        hold.timer = setTimeout(() => release("timer"), durationMs);
    } else if (capMs) {
        hold.timer = setTimeout(() => release("cap"), capMs);
    }
    emit(ROLE, "hold_start", { holdId: id, mode, durationMs, releaseOnLost: !!releaseOnLost, capMs, lastDeliveredT, t: hold.tStart });
    return id;
}

function release(reason) {
    if (!hold.active) return;
    const h = hold;
    h.active = false;
    if (h.timer) clearTimeout(h.timer);
    const tRel = Date.now();
    let allMatch = true;
    const items = h.queue;
    h.queue = [];
    const seqs = [];
    for (const it of items) {
        const sha2 = sha256(it.data);
        const match = sha2 === it.sha;
        if (!match) allMatch = false;
        seqs.push(it.seq);
        emit(ROLE, "rx_release", { holdId: h.id, seq: it.seq, t_arrival: it.t, t_release: Date.now(), len: it.data.length, sha_arrival: it.sha, sha_release: sha2, match, key: it.key });
        deliver(it.listener, it.ni, it.address, it.port, it.data);
    }
    const inOrder = seqs.every((v, i) => i === 0 || v > seqs[i - 1]);
    const distinct = new Set(items.map((i) => i.key)).size;
    emit(ROLE, "released", { holdId: h.id, reason, n: items.length, distinct, allMatch, inOrder, selectKey: h.key, tStart: h.tStart, t: tRel });
}

// ------------------------------------------------------------------ Q6 order witness (off unless HOLD_WITNESS=1)
const WITNESS = process.env.HOLD_WITNESS === "1";
if (WITNESS) {
    const { installWitness } = await import("./witness.mjs");
    await installWitness((type, fields) => emit(ROLE, type, fields));
}

// ------------------------------------------------------------------ controller
const environment = Environment.default;
const controller = new CommissioningController({
    environment: { environment, id: "holdprobe-controller" },
    autoConnect: false,
    adminFabricLabel: "holdprobe",
});

let node;
let nodeState;

function currentValue() {
    try {
        return node?.parts.get(1)?.stateOf(BooleanStateClient)?.stateValue;
    } catch {
        return undefined;
    }
}

function attachNode(n) {
    node = n;
    n.events.attributeChanged.on(({ path: { endpointId, clusterId, attributeName }, value, version }) => {
        emit(ROLE, "attr", {
            endpointId, clusterId, attributeName,
            value: typeof value === "boolean" || typeof value === "number" || typeof value === "string" ? value : undefined,
            ...(WITNESS ? { version } : {}),
        });
    });
    n.events.eventTriggered.on(({ path: { endpointId, clusterId, eventName }, events }) => {
        emit(ROLE, "event", {
            endpointId,
            clusterId,
            eventName,
            events: events.map((e) => ({
                eventNumber: String(e.eventNumber),
                priority: e.priority,
                epochTimestamp: e.epochTimestamp !== undefined ? Number(e.epochTimestamp) : undefined,
                systemTimestamp: e.systemTimestamp !== undefined ? Number(e.systemTimestamp) : undefined,
                data: e.data && typeof e.data === "object" ? { stateValue: e.data.stateValue } : undefined,
            })),
        });
    });
    n.events.stateChanged.on((s) => {
        nodeState = s;
        emit(ROLE, "node_state", { state: NodeStates[s], lastDeliveredT });
        if (s !== NodeStates.Connected && hold.active && hold.releaseOnLost) {
            emit(ROLE, "lost_declared", { holdId: hold.id, via: "node_state", state: NodeStates[s] });
            release("lost");
        }
    });
    n.events.connectionAlive.on(() => emit(ROLE, "alive"));
}

// Release on the subscription-timeout log line too (it precedes the node state change).
const destWrite = Logger.destinations.default.write;
Logger.destinations.default.write = (text, message) => {
    destWrite(text, message);
    if (/Subscription\s+\S+\s+to peer\s+.*timed out after/.test(text) && hold.active && hold.releaseOnLost) {
        emit(ROLE, "lost_declared", { holdId: hold.id, via: "timeout_log" });
        release("lost");
    }
};

function params() {
    return {
        mrp: {
            maxTransmissions: MRP.MAX_TRANSMISSIONS,
            backoffBase: MRP.BACKOFF_BASE,
            backoffMargin: MRP.BACKOFF_MARGIN,
            backoffJitter: MRP.BACKOFF_JITTER,
            backoffThreshold: MRP.BACKOFF_THRESHOLD,
            standaloneAckTimeoutMs: MRP.STANDALONE_ACK_TIMEOUT,
        },
        sessionIntervals: {
            idleIntervalMs: SessionIntervals.defaults.idleInterval,
            activeIntervalMs: SessionIntervals.defaults.activeInterval,
            activeThresholdMs: SessionIntervals.defaults.activeThreshold,
        },
    };
}

process.on("message", async (msg) => {
    try {
        switch (msg.cmd) {
            case "commission": {
                if (!controller.isCommissioned()) {
                    const nodeId = await controller.commissionNode({
                        commissioning: {
                            regulatoryLocation: GeneralCommissioning.RegulatoryLocationType.IndoorOutdoor,
                            regulatoryCountryCode: "XX",
                        },
                        discovery: {
                            knownAddress: { ip: "127.0.0.1", port: DEVICE_PORT, type: "udp" },
                            identifierData: { longDiscriminator: DISCRIMINATOR },
                            discoveryCapabilities: { ble: false },
                        },
                        passcode: PASSCODE,
                    });
                    emit(ROLE, "commissioned", { nodeId: String(nodeId) });
                } else {
                    emit(ROLE, "commissioned", { nodeId: String(controller.getCommissionedNodes()[0]), already: true });
                }
                break;
            }
            case "connect": {
                const nodeId = controller.getCommissionedNodes()[0];
                if (!node) attachNode(await controller.getNode(NodeId(nodeId)));
                const opts = { subscribeMinIntervalFloorSeconds: msg.minFloor, subscribeMaxIntervalCeilingSeconds: msg.maxCeiling };
                node.connect(opts);
                emit(ROLE, "connect_called", { ...opts });
                break;
            }
            case "status": {
                emit(ROLE, "status", {
                    tag: msg.tag,
                    value: currentValue(),
                    nodeState: nodeState !== undefined ? NodeStates[nodeState] : undefined,
                    connectionState: node ? NodeStates[node.connectionState] : undefined,
                    maxIntervalS: node?.currentSubscriptionIntervalSeconds,
                    lastDeliveredT,
                    holdActive: hold.active,
                    sessions: controller.getActiveSessionInformation().map((s) => ({ name: s.name, isPeerActive: s.isPeerActive, subs: s.numberOfActiveSubscriptions })),
                    params: params(),
                });
                break;
            }
            case "hold":
                startHold(msg);
                break;
            case "release":
                release(msg.reason ?? "command");
                break;
            case "shutdown":
                release("shutdown");
                await controller.close();
                emit(ROLE, "closed");
                process.exit(0);
        }
    } catch (e) {
        emit(ROLE, "error", { cmd: msg.cmd, msg: String(e?.stack ?? e) });
    }
});

await controller.start();
emit(ROLE, "ready", { commissioned: controller.isCommissioned(), params: params() });
