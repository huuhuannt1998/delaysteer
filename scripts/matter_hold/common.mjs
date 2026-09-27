// Shared helpers for the Matter hold probe (device, controller, runner).
import { createHash } from "node:crypto";

export const DEVICE_PORT = 5550;
export const PASSCODE = 20202021;
export const DISCRIMINATOR = 3841;

/** Normalise matter.js Bytes (ArrayBuffer | ArrayBufferView) to a Uint8Array view without copying. */
export function u8(buf) {
    if (buf instanceof Uint8Array) return buf;
    if (ArrayBuffer.isView(buf)) return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    if (buf instanceof ArrayBuffer) return new Uint8Array(buf);
    return undefined;
}

export function sha256(buf) {
    return createHash("sha256").update(u8(buf)).digest("hex");
}

/**
 * Parse the unencrypted Matter message header (Matter Core spec 4.4.1).
 * Byte 0: message flags; bytes 1-2: session id (LE); byte 3: security flags; bytes 4-7: message counter (LE).
 * The adversary can read these because they are sent in the clear; everything after is encrypted (CASE).
 */
export function parseHeader(buf) {
    const b = u8(buf);
    if (!b || b.length < 8) return undefined;
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const flags = dv.getUint8(0);
    const sessionId = dv.getUint16(1, true);
    const securityFlags = dv.getUint8(3);
    const counter = dv.getUint32(4, true);
    return { flags, sessionId, securityFlags, counter };
}

/** Structured line to stdout, prefixed with wall-clock epoch ms, and mirrored to the parent over IPC. */
export function emit(role, type, fields = {}) {
    const rec = { t: Date.now(), role, type, ...fields };
    if (process.send) {
        try {
            process.send(rec);
        } catch {
            // parent gone
        }
    }
    return rec;
}

/** Route matter.js log output to stdout with an epoch-ms prefix; forward selected lines to the parent. */
export function installLogTap(Logger, role, patterns) {
    const dest = Logger.destinations.default;
    const origWrite = dest.write.bind(dest);
    dest.write = (text, message) => {
        const now = Date.now();
        process.stdout.write(`@${now} ${text}\n`);
        for (const [name, re] of patterns) {
            if (re.test(text)) {
                emit(role, "log_match", { pattern: name, text: text.slice(0, 600), t: now });
            }
        }
        void origWrite; // default console write replaced; stdout above is the log of record
    };
}
