// Q6 controller-side order witness (the paper's Counter witness) for the matter.js controller.
//
// Where: ClientStructure.prototype.mutate in @matter/node 0.17.9. This is the point where a decoded ReportData
// (an async stream of chunks of "attr-value" / "event-value" changes, each attr-value carrying its cluster
// DataVersion as `version`) is applied to the controller's node cache. Only after this does the application see the
// value (PairedNode.events.attributeChanged, which does expose `version`, but only after the cache was updated, so a
// check there could not keep the previous value).
//
// What: a pass-through filter over that stream. It never alters a change object, a value, a byte, or the adversary.
// It forwards each change object by reference, except an attribute value whose DataVersion is older (32-bit
// serial-number arithmetic) than the highest already applied for its (endpoint, cluster); that change is withheld, so
// the cache keeps the previously applied value, and the rejection is logged with both versions. Events are never
// withheld; an event whose number is not above the highest seen for the node is flagged and logged, split into
// "duplicate" (this event number was delivered before) and "older" (never seen, but below the highest).
import { fileURLToPath } from "node:url";

const HALF = 0x80000000;
/** true if a is older than b under 32-bit serial-number arithmetic (RFC 1982 style). */
export function isOlder32(a, b) {
    if (a === b) return false;
    return ((b - a) >>> 0) < HALF;
}

export async function installWitness(emit) {
    const url = new URL("./node_modules/@matter/node/dist/esm/node/client/ClientStructure.js", import.meta.url);
    const { ClientStructure } = await import(url.href);
    const origMutate = ClientStructure.prototype.mutate;
    const state = new WeakMap(); // ClientStructure instance -> { highestVersion: Map, highestEvent, seenEvents: Set }
    let reportSeq = 0;
    const totals = { reports: 0, attrIn: 0, attrPassed: 0, attrRejected: 0, eventsIn: 0, dupFlags: 0, olderFlags: 0 };

    function stateOf(structure) {
        let s = state.get(structure);
        if (!s) {
            s = { highestVersion: new Map(), highestEvent: undefined, seenEvents: new Set() };
            state.set(structure, s);
        }
        return s;
    }

    function prim(v) {
        return typeof v === "boolean" || typeof v === "number" || typeof v === "string" ? v : undefined;
    }

    async function* filterChunk(chunk, s, rep) {
        for await (const change of chunk) {
            if (change?.kind === "attr-value") {
                const { endpointId, clusterId, attributeId } = change.path;
                const key = `${endpointId}/${clusterId}`;
                const v = change.version >>> 0;
                const prev = s.highestVersion.get(key);
                totals.attrIn++;
                rep.attrIn++;
                let cl = rep.clusters.get(key);
                if (!cl) {
                    cl = { endpointId, clusterId, versions: new Set(), prevHighest: prev, attrs: [], rejected: 0, passed: 0 };
                    rep.clusters.set(key, cl);
                }
                cl.versions.add(v);
                if (prev !== undefined && isOlder32(v, prev)) {
                    totals.attrRejected++;
                    rep.attrRejected++;
                    cl.rejected++;
                    cl.attrs.push({ attributeId, value: prim(change.value), decision: "rejected" });
                    emit("witness_reject", {
                        report: rep.seq, endpointId, clusterId, attributeId, value: prim(change.value),
                        version: v, highestApplied: prev,
                    });
                    continue; // withheld: the node cache keeps the previously applied value
                }
                if (prev === undefined || isOlder32(prev, v)) s.highestVersion.set(key, v);
                totals.attrPassed++;
                rep.attrPassed++;
                cl.passed++;
                cl.attrs.push({ attributeId, value: prim(change.value), decision: "applied" });
                yield change;
            } else if (change?.kind === "event-value") {
                const n = BigInt(change.number);
                const { endpointId, clusterId, eventId } = change.path;
                totals.eventsIn++;
                let flag;
                if (s.highestEvent !== undefined && n <= s.highestEvent) {
                    flag = s.seenEvents.has(n) ? "duplicate" : "older";
                    if (flag === "duplicate") totals.dupFlags++;
                    else totals.olderFlags++;
                    emit("witness_event_flag", {
                        report: rep.seq, flag, eventNumber: String(n), highestSeen: String(s.highestEvent),
                        endpointId, clusterId, eventId, epochTimestamp: change.epochTimestamp !== undefined ? Number(change.epochTimestamp) : undefined,
                    });
                }
                if (s.highestEvent === undefined || n > s.highestEvent) s.highestEvent = n;
                s.seenEvents.add(n);
                rep.events.push({ number: String(n), endpointId, clusterId, eventId, flag: flag ?? "in_order" });
                yield change; // events are flagged, never withheld
            } else {
                yield change;
            }
        }
    }

    async function* filterReport(changes, structure, request) {
        const s = stateOf(structure);
        const rep = { seq: ++reportSeq, t0: Date.now(), attrIn: 0, attrPassed: 0, attrRejected: 0, clusters: new Map(), events: [] };
        totals.reports++;
        try {
            for await (const chunk of changes) {
                yield filterChunk(chunk, s, rep);
            }
        } finally {
            emit("witness_report", {
                report: rep.seq,
                attrIn: rep.attrIn, attrPassed: rep.attrPassed, attrRejected: rep.attrRejected,
                clusters: [...rep.clusters.values()].map((c) => ({
                    endpointId: c.endpointId, clusterId: c.clusterId, versions: [...c.versions], prevHighest: c.prevHighest,
                    passed: c.passed, rejected: c.rejected,
                    // keep attribute detail only for the probed BooleanState cluster (0x45) to bound log size
                    attrs: c.clusterId === 0x45 ? c.attrs : undefined,
                })),
                events: rep.events,
                totals: { ...totals },
            });
        }
    }

    ClientStructure.prototype.mutate = function (request, changes) {
        return origMutate.call(this, request, filterReport(changes, this, request));
    };
    emit("witness_installed", { hook: "ClientStructure.prototype.mutate", module: fileURLToPath(url).replace(/^.*\/node_modules\//, "node_modules/") });
    return totals;
}
