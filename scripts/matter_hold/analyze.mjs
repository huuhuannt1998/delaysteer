// Summarise results/matter_hold.csv into markdown tables, one per plan question.
// Usage: node analyze.mjs [path/to/matter_hold.csv] [--run-id main]
import { readFileSync } from "node:fs";

const args = process.argv.slice(2);
const csvPath = args.find((a) => a.endsWith(".csv")) ?? new URL("../../results/matter_hold.csv", import.meta.url).pathname;
const runIdx = args.indexOf("--run-id");
const RUN = runIdx >= 0 ? args[runIdx + 1] : undefined;

function parseCsv(text) {
    const rows = [];
    let row = [], cell = "", q = false;
    for (let i = 0; i < text.length; i++) {
        const c = text[i];
        if (q) {
            if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; }
            else if (c === '"') q = false;
            else cell += c;
        } else if (c === '"') q = true;
        else if (c === ",") { row.push(cell); cell = ""; }
        else if (c === "\n") { row.push(cell); rows.push(row); row = []; cell = ""; }
        else cell += c;
    }
    if (cell || row.length) { row.push(cell); rows.push(row); }
    const [h, ...body] = rows;
    return body.filter((r) => r.length === h.length).map((r) => Object.fromEntries(h.map((k, i) => [k, r[i]])));
}

const all = parseCsv(readFileSync(csvPath, "utf8")).filter((r) => !RUN || r.run_id === RUN);
const num = (v) => (v === "" || v === undefined ? undefined : Number(v));
const vals = (rows, k) => rows.map((r) => num(r[k])).filter((v) => v !== undefined && !Number.isNaN(v));
function stats(xs) {
    if (!xs.length) return "n/a";
    const s = [...xs].sort((a, b) => a - b);
    const med = s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
    const f = (x) => (Math.abs(x) >= 100 ? Math.round(x) : Math.round(x * 10) / 10);
    return `${f(med)} [${f(s[0])}, ${f(s.at(-1))}]`;
}
const count = (rows, pred) => rows.filter(pred).length;
const isTrue = (k) => (r) => r[k] === "true";
const nonEmpty = (k) => (r) => r[k] !== "" && r[k] !== undefined;
const uniq = (rows, k) => [...new Set(rows.map((r) => r[k]))].join(", ");
function table(header, lines) {
    console.log(`| ${header.join(" | ")} |`);
    console.log(`|${header.map(() => "---").join("|")}|`);
    for (const l of lines) console.log(`| ${l.join(" | ")} |`);
    console.log("");
}
const byCell = (rows) => {
    const m = new Map();
    for (const r of rows) {
        if (!m.has(r.cell)) m.set(r.cell, []);
        m.get(r.cell).push(r);
    }
    return m;
};

console.log(`Source: ${csvPath.replace(/^.*\/results\//, "results/")}${RUN ? ` (run ${RUN})` : ""}; ${all.length} trials. Timings in ms, shown as median [min, max].\n`);

// ---------------------------------------------------------------- Q1
const q1 = all.filter((r) => r.question === "Q1");
console.log("### Q1 acceptance (hold all device datagrams for d, then release)\n");
table(
    ["d (s)", "n", "applied", "trials with controller WARN/ERROR", "update after toggle", "update after release", "held datagrams", "distinct msgs held", "bytes unchanged", "in order", "device gave up report before release", "device give-up after toggle", "dup event callbacks"],
    [...byCell(q1)].map(([cell, rs]) => [
        cell.replace("d=", "").replace("s", ""), rs.length, `${count(rs, isTrue("applied"))}/${rs.length}`,
        count(rs, (r) => Number(r.ctrl_warn_error_count) > 0),
        stats(vals(rs, "applied_minus_toggle_ms")), stats(vals(rs, "applied_minus_release_ms")),
        stats(vals(rs, "n_held")), stats(vals(rs, "n_distinct_held_msgs")),
        `${count(rs, isTrue("held_bytes_unchanged"))}/${rs.length}`, `${count(rs, isTrue("release_in_order"))}/${rs.length}`,
        `${count(rs, (r) => nonEmpty("dev_giveup_t")(r) && Number(r.dev_giveup_t) < Number(r.t_release))}/${rs.length}`,
        stats(vals(rs, "dev_giveup_after_toggle_ms")), count(rs, nonEmpty("dup_event_callbacks")),
    ]),
);
const warnQ1 = q1.filter((r) => Number(r.ctrl_warn_error_count) > 0);
if (warnQ1.length) {
    console.log("Controller WARN/ERROR lines seen in Q1 trials:\n");
    for (const r of warnQ1) console.log(`- ${r.trial_id} (${r.cell}): ${r.ctrl_warn_error_first.replace(/^\S+ \S+ /, "").slice(0, 160)}`);
    console.log("");
}

// ---------------------------------------------------------------- Q3
const q3 = all.filter((r) => (r.question === "Q1" || r.question === "Q5") && nonEmpty("event_epoch_ts")(r));
console.log("### Q3 event time (StateChange event carried in the same held report)\n");
table(
    ["d (s)", "n", "epochTimestamp present", "receipt - event time", "(receipt - event time) - d", "event time - toggle", "receipt - release"],
    [...byCell(q3)].map(([cell, rs]) => {
        const d = Number(cell.replace(/[^0-9.]/g, "")) * 1000;
        return [
            cell.replace("d=", "").replace("s", ""), rs.length, `${count(rs, nonEmpty("event_epoch_ts"))}/${rs.length}`,
            stats(vals(rs, "event_age_ms")), stats(vals(rs, "event_age_ms").map((x) => x - d)),
            stats(vals(rs, "event_minus_toggle_ms")),
            stats(rs.filter((r) => nonEmpty("event_receipt_t")(r) && nonEmpty("t_release")(r)).map((r) => Number(r.event_receipt_t) - Number(r.t_release))),
        ];
    }),
);

// ---------------------------------------------------------------- Q2
const q2 = all.filter((r) => r.question === "Q2");
console.log("### Q2 liveness bound (hold all device datagrams until the controller declares the subscription lost)\n");
table(
    ["requested MaxInterval (s)", "n", "ceiling on wire (s)", "negotiated MaxInterval (s)", "controller timeout (s)", "loss declared", "loss after last delivered datagram", "loss - negotiated MaxInterval", "loss - controller timeout", "declared before MaxInterval", "fresh value after release", "fresh value via", "device dropped its subscription first"],
    [...byCell(q2)].map(([cell, rs]) => [
        cell.replace("maxCeiling=", "").replace("s", ""), rs.length, uniq(rs, "wire_max_ceiling_s"), uniq(rs, "negotiated_max_interval_s"), uniq(rs, "controller_timeout_s"),
        `${count(rs, nonEmpty("t_lost_declared"))}/${rs.length}`,
        stats(vals(rs, "lost_after_last_delivered_ms")),
        stats(rs.filter(nonEmpty("lost_after_last_delivered_ms")).map((r) => Number(r.lost_after_last_delivered_ms) - Number(r.negotiated_max_interval_s) * 1000)),
        stats(rs.filter(nonEmpty("lost_after_last_delivered_ms")).map((r) => Number(r.lost_after_last_delivered_ms) - Number(r.controller_timeout_s) * 1000)),
        count(rs, (r) => nonEmpty("lost_after_last_delivered_ms")(r) && Number(r.lost_after_last_delivered_ms) < Number(r.negotiated_max_interval_s) * 1000),
        stats(vals(rs, "fresh_after_release_ms")),
        [...new Set(rs.map((r) => r.fresh_via))].map((v) => `${v || "none"}: ${count(rs, (r) => r.fresh_via === v)}`).join(", "),
        `${count(rs, isTrue("dev_sub_terminated"))}/${rs.length}`,
    ]),
);

// ---------------------------------------------------------------- Q4
const q4 = all.filter((r) => r.question === "Q4");
// Parse the controller's stateValue attribute sequence recorded in notes ("A:false@20018 ... A:true@56219", ms after the
// first toggle). Inversion: the controller already held the newer value (closed) when the released report set it back
// to the older one (open). Stale window: from that overwrite to the next attribute update back to closed.
for (const r of q4) {
    const toks = [...(r.notes ?? "").matchAll(/A:(true|false)@(\d+)/g)].map((m) => ({ v: m[1] === "true", t: Number(m[2]) }));
    const relAt = Number(r.t_release) - Number(r.t_toggle);
    const overwrite = toks.find((x) => x.v === false && x.t >= relAt - 5);
    const laterBefore = r.later_report_before_release === "true";
    r._inverted = !!(overwrite && laterBefore && !toks.some((x) => x.v === true && x.t >= overwrite.t && x.t - overwrite.t < 200));
    if (r._inverted) {
        const back = toks.find((x) => x.v === true && x.t > overwrite.t);
        r._staleMs = back ? back.t - overwrite.t : undefined;
        r._staleOpen = back ? "" : `>=${r.mismatch_observed_until_ms_after_release || "?"}`;
    }
}
console.log("### Q4 order (hold one value-bearing report, toggle again during the hold)\n");
table(
    ["cell", "n", "later report reached controller before release", "value datagrams passed during hold", "controller callbacks during hold", "released older value overwrote newer (inversion)", "stale window after release (ms)", "stale at end of trial", "mismatch self-corrected in window", "mismatch observed until (ms after release)", "keepalives during mismatch", "device gave up held report before release", "device give-up after toggle", "dup event callbacks"],
    [...byCell(q4)].map(([cell, rs]) => [
        cell, rs.length, `${count(rs, isTrue("later_report_before_release"))}/${rs.length}`,
        stats(vals(rs, "n_passed_value_datagrams_during_hold")), stats(vals(rs, "ctrl_callbacks_during_hold")),
        `${count(rs, (r) => r._inverted)}/${rs.length}`,
        stats(rs.filter((r) => r._staleMs !== undefined).map((r) => r._staleMs)) + (rs.some((r) => r._staleOpen) ? ` (+${count(rs, (r) => r._staleOpen)} unresolved)` : ""),
        `${count(rs, isTrue("stale_mismatch_after_release"))}/${rs.length}`,
        count(rs, nonEmpty("mismatch_resolved")) ? `${count(rs, isTrue("mismatch_resolved"))}/${count(rs, nonEmpty("mismatch_resolved"))}` : "n/a",
        stats(vals(rs, "mismatch_observed_until_ms_after_release")), stats(vals(rs, "keepalives_during_mismatch")),
        `${count(rs, (r) => nonEmpty("dev_giveup_t")(r) && Number(r.dev_giveup_t) < Number(r.t_release))}/${rs.length}`,
        stats(vals(rs, "dev_giveup_after_toggle_ms")), count(rs, nonEmpty("dup_event_callbacks")),
    ]),
);

// ---------------------------------------------------------------- Q5 (+ Q1 rows past the give-up)
const q5 = all.filter((r) => r.question === "Q5");
console.log("### Q5 late release after the device gave up\n");
const q5plus = all.filter((r) => (r.question === "Q5" || r.question === "Q1") && nonEmpty("dev_giveup_t")(r) && Number(r.dev_giveup_t) < Number(r.t_release));
table(
    ["set", "n", "report transmissions (MRP)", "last retransmission after toggle", "device give-up after toggle", "device logged give-up before release", "controller applied late value", "update after release", "controller WARN/ERROR trials"],
    [["Q5 (d=25 s)", q5], ["all rows with give-up before release (Q1 d>=20 + Q5)", q5plus]].map(([name, rs]) => [
        name, rs.length, stats(vals(rs, "dev_report_tx_count")),
        stats(rs.filter(nonEmpty("dev_report_last_tx_t")).map((r) => Number(r.dev_report_last_tx_t) - Number(r.t_toggle))),
        stats(vals(rs, "dev_giveup_after_toggle_ms")),
        `${count(rs, (r) => nonEmpty("dev_giveup_t")(r) && Number(r.dev_giveup_t) < Number(r.t_release))}/${rs.length}`,
        `${count(rs, isTrue("applied"))}/${rs.length}`, stats(vals(rs, "applied_minus_release_ms")),
        count(rs, (r) => Number(r.ctrl_warn_error_count) > 0),
    ]),
);

// ---------------------------------------------------------------- integrity
console.log("### Adversary integrity (all trials)\n");
table(
    ["trials", "datagrams held", "released with identical SHA-256", "releases in arrival order", "trials with a missing release"],
    [[all.length, vals(all, "n_held").reduce((a, b) => a + b, 0), `${count(all, isTrue("held_bytes_unchanged"))}/${count(all, nonEmpty("held_bytes_unchanged"))}`, `${count(all, isTrue("release_in_order"))}/${count(all, nonEmpty("release_in_order"))}`, count(all, (r) => !nonEmpty("t_release")(r))]],
);

// ---------------------------------------------------------------- end-to-end byte check from the raw event log
const evIdx = args.indexOf("--events");
if (evIdx >= 0) {
    const lines = readFileSync(args[evIdx + 1], "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const devTx = new Map(); // sha -> [times]
    for (const r of lines) if (r.role === "device" && r.type === "tx") {
        if (!devTx.has(r.sha)) devTx.set(r.sha, []);
        devTx.get(r.sha).push(r.t);
    }
    const rel = lines.filter((r) => r.role === "controller" && r.type === "rx_release");
    const rx = lines.filter((r) => r.role === "controller" && r.type === "rx");
    const relMatchDevice = rel.filter((r) => devTx.has(r.sha_release)).length;
    const relUnchanged = rel.filter((r) => r.sha_arrival === r.sha_release).length;
    const heldRx = rx.filter((r) => r.held).length;
    // every held rx must be released exactly once
    const releasedSeqs = new Set(rel.map((r) => r.seq));
    const heldNotReleased = rx.filter((r) => r.held && !releasedSeqs.has(r.seq)).length;
    // arrival-order check across each hold
    let orderViolations = 0;
    const byHold = new Map();
    for (const r of rel) {
        if (!byHold.has(r.holdId)) byHold.set(r.holdId, []);
        byHold.get(r.holdId).push(r);
    }
    for (const rs of byHold.values()) for (let i = 1; i < rs.length; i++) if (rs[i].seq <= rs[i - 1].seq || rs[i].t_arrival < rs[i - 1].t_arrival) orderViolations++;
    const maxHoldMs = Math.max(...rel.map((r) => r.t_release - r.t_arrival));
    console.log("### End-to-end byte check (raw event log)\n");
    table(
        ["held datagrams (rx)", "released", "held but never released", "SHA-256 unchanged arrival->release", "released bytes identical to a datagram the device sent", "order violations", "longest single hold (ms)"],
        [[heldRx, rel.length, heldNotReleased, `${relUnchanged}/${rel.length}`, `${relMatchDevice}/${rel.length}`, orderViolations, maxHoldMs]],
    );
}

// ---------------------------------------------------------------- aftermath attributed to the trial that caused it
if (evIdx >= 0) {
    const lines = readFileSync(args[evIdx + 1], "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const trials = [...all].filter((r) => nonEmpty("t_hold_start")(r)).sort((a, b) => Number(a.t_hold_start) - Number(b.t_hold_start));
    const trialAt = (t) => {
        let cur;
        for (const r of trials) if (Number(r.t_hold_start) <= t) cur = r;
        return cur;
    };
    const parseDurS = (s) => {
        let tot = 0;
        for (const m of s.matchAll(/([\d.]+)(ms|h|m|s)/g)) tot += m[2] === "h" ? m[1] * 3600 : m[2] === "m" ? m[1] * 60 : m[2] === "s" ? Number(m[1]) : m[1] / 1000;
        return tot;
    };
    // peer-unresponsive: the controller's own reliable message (e.g. StatusResponse to a report) was never acknowledged.
    const pu = lines.filter((r) => r.role === "controller" && r.type === "log_match" && r.pattern === "peer_unresponsive");
    const puRows = pu.map((r) => {
        const m = /timed out after ([^)]+)\)/.exec(r.text);
        const waited = m ? parseDurS(m[1]) * 1000 : 0;
        const start = r.t - waited;
        const tr = trialAt(start);
        const since = tr && nonEmpty("t_release")(tr) ? Math.round(start - Number(tr.t_release)) : undefined;
        return { tr, start, waited, since, what: /Error sending success after final data report/.test(r.text) ? "StatusResponse to a report" : "other" };
    });
    const puBy = new Map();
    for (const p of puRows) {
        const key = p.tr ? `${p.tr.question} ${p.tr.cell}` : "before first trial";
        if (!puBy.has(key)) puBy.set(key, []);
        puBy.get(key).push(p);
    }
    console.log("### Controller-side peer-unresponsive (INFO/WARN log only), attributed to the trial whose traffic started the unacknowledged exchange\n");
    table(
        ["cell", "occurrences", "trials in cell", "exchange start - release (ms)", "waited before giving up (ms)", "kind"],
        [...puBy].map(([k, ps]) => [k, ps.length, all.filter((r) => `${r.question} ${r.cell}` === k).length, stats(ps.filter((p) => p.since !== undefined).map((p) => p.since)), stats(ps.map((p) => p.waited)), [...new Set(ps.map((p) => p.what))].join(", ")]),
    );
    // duplicate event deliveries to the controller application
    const deliveries = new Map();
    for (const r of lines) if (r.role === "controller" && r.type === "event") for (const e of r.events ?? []) {
        if (!deliveries.has(e.eventNumber)) deliveries.set(e.eventNumber, []);
        deliveries.get(e.eventNumber).push(r.t);
    }
    const dups = [...deliveries].filter(([, ts]) => ts.length > 1);
    const dupBy = new Map();
    for (const [n, ts] of dups) {
        const tr = trialAt(ts[0]);
        const key = tr ? `${tr.question} ${tr.cell}` : "before first trial";
        if (!dupBy.has(key)) dupBy.set(key, []);
        dupBy.get(key).push({ n, gap: ts[1] - ts[0], count: ts.length });
    }
    console.log("### Event numbers delivered to the controller application more than once (attributed by first delivery)\n");
    table(
        ["cell", "event numbers delivered twice or more", "trials in cell", "gap between first and second delivery (ms)"],
        [...dupBy].map(([k, ds]) => [k, ds.length, all.filter((r) => `${r.question} ${r.cell}` === k).length, stats(ds.map((d) => d.gap))]),
    );
    console.log(`Total distinct event numbers delivered: ${deliveries.size}; delivered more than once: ${dups.length}.\n`);
}
