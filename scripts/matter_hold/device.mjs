// Virtual Matter contact sensor (BooleanState with the StateChange event) for the hold probe.
// Runs as its own Node process; the runner drives it over IPC ({cmd:"set", value}).
// It only observes its own UDP traffic (tx/rx log); it never alters it.
import { DEVICE_PORT, DISCRIMINATOR, PASSCODE, emit, installLogTap, parseHeader, sha256, u8 } from "./common.mjs";
import { NodeJsUdpSocket } from "@matter/nodejs";
import { Logger, ServerNode, VendorId } from "@matter/main";
import { ContactSensorDevice } from "@matter/main/devices/contact-sensor";
import { BooleanStateServer } from "@matter/main/behaviors/boolean-state";

const ROLE = "device";

installLogTap(Logger, ROLE, [
    ["update_error", /Error sending subscription update message/],
    ["sub_giveup", /Giving up on subscription/],
    ["sub_failed", /Sending subscription update failed/],
    ["retransmit", /[Rr]etransmi|[Rr]esubmi/],
    ["sub_cancel", /cancelled by peer|Subscription .* (closed|ended|cancel)/],
    ["new_sub", /New subscription|Subscription successful|Subscribe request|subscribe/i],
    ["session", /[Ss]ession (closed|established|created)|CASE/],
]);

// Observe (never alter) the device's own datagrams to/from the controller.
const origSend = NodeJsUdpSocket.prototype.send;
NodeJsUdpSocket.prototype.send = function (host, port, data) {
    if (port !== 5353) {
        try {
            const h = parseHeader(data);
            emit(ROLE, "tx", { host, port, len: u8(data)?.length, sha: sha256(data), sess: h?.sessionId, ctr: h?.counter });
        } catch (e) {
            emit(ROLE, "tx_log_error", { msg: String(e) });
        }
    }
    return origSend.call(this, host, port, data);
};
const origOnData = NodeJsUdpSocket.prototype.onData;
NodeJsUdpSocket.prototype.onData = function (listener) {
    return origOnData.call(this, (netInterface, address, port, data) => {
        if (port !== 5353) {
            const h = parseHeader(data);
            emit(ROLE, "rx", { address, port, len: data.length, sha: sha256(data), sess: h?.sessionId, ctr: h?.counter });
        }
        listener(netInterface, address, port, data);
    });
};

const server = await ServerNode.create({
    id: "hold-probe-contact",
    network: { port: DEVICE_PORT },
    commissioning: { passcode: PASSCODE, discriminator: DISCRIMINATOR },
    productDescription: { name: "HoldProbe Contact", deviceType: ContactSensorDevice.deviceType },
    basicInformation: {
        vendorName: "HoldProbe",
        vendorId: VendorId(0xfff1),
        nodeLabel: "HoldProbe Contact",
        productName: "HoldProbe Contact",
        productLabel: "HoldProbe Contact",
        productId: 0x8000,
        serialNumber: "holdprobe-0001",
        uniqueId: "holdprobe-0001",
    },
});

// BooleanStateServer in matter.js 0.17 includes the ChangeEvent feature, so StateChange events are emitted on change.
const contact = await server.add(ContactSensorDevice.with(BooleanStateServer), {
    id: "contact",
    booleanState: { stateValue: true }, // true = contact = closed
});

server.lifecycle.commissioned.on(() => emit(ROLE, "commissioned"));

contact.events.booleanState.stateChange?.on?.((payload) => emit(ROLE, "state_change_event", { value: payload?.stateValue }));

process.on("message", async (msg) => {
    try {
        if (msg.cmd === "set") {
            const t0 = Date.now();
            await contact.set({ booleanState: { stateValue: msg.value } });
            emit(ROLE, "set_done", { value: msg.value, tag: msg.tag, t_req: t0 });
        } else if (msg.cmd === "get") {
            emit(ROLE, "value", { value: contact.state.booleanState.stateValue, tag: msg.tag });
        } else if (msg.cmd === "shutdown") {
            await server.close();
            emit(ROLE, "closed");
            process.exit(0);
        }
    } catch (e) {
        emit(ROLE, "error", { msg: String(e?.stack ?? e) });
    }
});

await server.start();
emit(ROLE, "ready", {
    port: DEVICE_PORT,
    commissioned: server.lifecycle.isCommissioned,
    value: contact.state.booleanState.stateValue,
});
