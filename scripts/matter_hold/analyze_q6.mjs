// Summarise the Q6 order-witness run (results/matter_hold_q6.csv + its events.jsonl) into markdown tables.
// Usage: node analyze_q6.mjs <matter_hold_q6.csv> <events.jsonl> [<Q1-Q5 matter_hold.csv for the witness-off comparison>]
import { readFileSync } from "node:fs";

const [csvPath, eventsPath, baselineCsv] = process.argv.slice(2);

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
const T = (k) => (r) => r[k] === "true";
function table(header, lines) {
    console.log(`| ${header.join(" | ")} |`);
    console.log(`|${header.map(() => "---").join("|")}|`);
    for (const l of lines) console.log(`| ${l.join(" | ")} |`);
    console.log("");
}
function byCell(rows) {
    const m = new Map();
    for (const r of rows) {
        if (!m.has(r.cell)) m.set(r.cell, []);
        m.get(r.cell).push(r);
    }
    return m;
}
const ORDER = ["Q4:mode=select,d=20s", "Q4:mode=select,d=2s", "Q4:mode=select,d=10s", "Q4:mode=all,d=20s", "Q1:d=1s", "Q1:d=10s", "Q1:d=30s"];
const rows = parseCsv(readFileSync(csvPath, "utf8"));
const cells = byCell(rows);
const ordered = ORDER.filter((c) => cells.has(c)).map((c) => [c, cells.get(c)]);
const expectReject = (cell) => cell === "Q4:mode=select,d=20s";

console.log(`Source: ${csvPath.replace(/^.*\/results\//, "results/")}; ${rows.length} trials, witness on. Timings in ms, median [min, max].\n`);

console.log("### Q6 per cell: witness decisions and outcome\n");
table(
    ["cell", "n", "trials with an attribute rejection", "rejections", "later report reached controller before release", "stale older value applied (inversion)", "controller final value = device value", "late value applied (residual)", "event flags: duplicate", "event flags: older", "update after release"],
    ordered.map(([cell, rs]) => [
        cell, rs.length,
        `${count(rs, (r) => Number(r.w_attr_rejections) > 0)}/${rs.length}`,
        vals(rs, "w_attr_rejections").reduce((a, b) => a + b, 0),
        cell.startsWith("Q4") ? `${count(rs, T("later_report_before_release"))}/${rs.length}` : "n/a",
        // inversion = the older (held) value reached the application after the newer one
        cell.startsWith("Q4") ? `${count(rs, (r) => r.later_report_before_release === "true" && r.applied === "true")}/${rs.length}` : "n/a",
        `${count(rs, (r) => r.final_ctrl_value === r.final_device_value)}/${rs.length}`,
        `${count(rs, T("late_value_applied"))}/${rs.length}`,
        vals(rs, "w_event_flags_duplicate").reduce((a, b) => a + b, 0),
        vals(rs, "w_event_flags_older").reduce((a, b) => a + b, 0),
        stats(vals(rs, "applied_minus_release_ms")),
    ]),
);

console.log("### Prediction check (addendum Q6)\n");
table(
    ["cell", "prediction", "measured", "held?"],
    ordered.map(([cell, rs]) => {
        const rej = count(rs, (r) => Number(r.w_attr_rejections) > 0);
        const correct = count(rs, (r) => r.final_ctrl_value === r.final_device_value && r.final_device_value === "true");
        if (expectReject(cell)) {
            const ok = rej === rs.length && correct === rs.length;
            return [cell, "stale overwrite rejected 5/5, controller keeps closed", `rejected ${rej}/${rs.length}; controller closed = device closed ${correct}/${rs.length}`, ok ? "yes" : "NO"];
        }
        if (cell.startsWith("Q4")) {
            return [cell, "0 rejections", `${vals(rs, "w_attr_rejections").reduce((a, b) => a + b, 0)} rejections in ${rej}/${rs.length} trials`, rej === 0 ? "yes" : "NO"];
        }
        const applied = count(rs, T("late_value_applied"));
        return [cell, "0 rejections, late value still applied", `${vals(rs, "w_attr_rejections").reduce((a, b) => a + b, 0)} rejections; late value applied ${applied}/${rs.length}`, rej === 0 && applied === rs.length ? "yes" : "NO"];
    }),
);

console.log("### BooleanState data versions per trial (as decoded from each ReportData; offsets from the version applied before the hold)\n");
const off = (v, base) => (v === "" || v === undefined ? "" : v.split(" ").filter(Boolean).map((x) => x.split("/").map((y) => { const d = (Number(y) - base) >>> 0; return d > 0x7fffffff ? `-${(0x100000000 - d)}` : `+${d}`; }).join("/")).join(" "));
table(
    ["trial", "cell", "version before hold", "reports during hold (newer)", "reports at release (held)", "rejected", "all BooleanState reports in window (ms after toggle : version offset : stateValue : decision)"],
    ordered.flatMap(([cell, rs]) => rs.map((r) => {
        const base = Number(r.w_bs_version_before_hold);
        const reps = (r.w_bs_reports || "").split(" ").filter(Boolean).map((x) => {
            const [t, v, val, dec] = x.split(":");
            return `${t}:${off(v.slice(1), base)}:${val}:${dec}`;
        }).join(" ");
        return [r.trial_id, cell, r.w_bs_version_before_hold, off(r.w_bs_versions_during_hold, base) || "-", off(r.w_bs_versions_at_release, base) || "-", r.w_attr_rejections, reps];
    })),
);

if (eventsPath) {
    const lines = readFileSync(eventsPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const wr = lines.filter((r) => r.role === "controller" && r.type === "witness_report");
    const last = wr.at(-1)?.totals;
    const perReportConserved = wr.filter((r) => r.attrIn === r.attrPassed + r.attrRejected).length;
    const inst = lines.find((r) => r.type === "witness_installed");
    console.log("### Witness accounting (whole run, including connect/priming reads)\n");
    table(
        ["hook", "reports seen", "attribute values in", "forwarded unchanged", "withheld (rejected)", "reports with in = forwarded + withheld", "event values in (all forwarded)", "flags duplicate", "flags older"],
        [[inst ? `${inst.hook} (${inst.module})` : "n/a", last?.reports, last?.attrIn, last?.attrPassed, last?.attrRejected, `${perReportConserved}/${wr.length}`, last?.eventsIn, last?.dupFlags, last?.olderFlags]],
    );
    // Versions seen by the application after the commit vs versions the witness forwarded / withheld.
    const attr = lines.filter((r) => r.role === "controller" && r.type === "attr" && r.attributeName === "stateValue");
    const fwd = new Set(), rejV = new Set();
    for (const w of wr) for (const c of w.clusters ?? []) if (c.endpointId === 1 && c.clusterId === 69) for (const a of c.attrs ?? []) if (a.attributeId === 0) (a.decision === "applied" ? fwd : rejV).add(`${c.versions[0]}:${a.value}`);
    for (const r of lines) if (r.type === "witness_reject" && r.endpointId === 1 && r.clusterId === 69) rejV.add(`${r.version}:${r.value}`);
    const inFwd = attr.filter((a) => fwd.has(`${a.version}:${a.value}`)).length;
    const inRej = attr.filter((a) => rejV.has(`${a.version}:${a.value}`) && !fwd.has(`${a.version}:${a.value}`)).length;
    console.log(`Application-visible stateValue callbacks: ${attr.length}; (DataVersion, value) forwarded by the witness: ${inFwd}/${attr.length}; matching a withheld (DataVersion, value): ${inRej}.\n`);

    // Duplicate-event flags, attributed to the trial in which that event number was first delivered.
    const trials = [...rows].sort((a, b) => Number(a.t_hold_start) - Number(b.t_hold_start));
    const trialAt = (t) => { let cur; for (const r of trials) if (Number(r.t_hold_start) <= t) cur = r; return cur; };
    const firstSeen = new Map();
    for (const r of lines) if (r.role === "controller" && r.type === "event") for (const e of r.events ?? []) if (!firstSeen.has(e.eventNumber)) firstSeen.set(e.eventNumber, r.t);
    const flags = lines.filter((r) => r.role === "controller" && r.type === "witness_event_flag");
    const byOrigin = new Map();
    for (const f of flags) {
        const origin = trialAt(firstSeen.get(f.eventNumber) ?? f.t);
        const flaggedIn = trialAt(f.t);
        const k = `${origin?.cell ?? "before first trial"}|${f.flag}|${origin?.trial_id === flaggedIn?.trial_id ? "same trial" : "next trial"}`;
        byOrigin.set(k, (byOrigin.get(k) ?? 0) + 1);
    }
    console.log("### Event flags by the trial in which the event was first delivered\n");
    table(["event first delivered in cell", "flag", "flagged in", "count"], [...byOrigin].map(([k, n]) => [...k.split("|"), n]));

    const devTx = new Set(lines.filter((r) => r.role === "device" && r.type === "tx").map((r) => r.sha));
    const rel = lines.filter((r) => r.role === "controller" && r.type === "rx_release");
    const rx = lines.filter((r) => r.role === "controller" && r.type === "rx" && r.held);
    const relSeq = new Set(rel.map((r) => r.seq));
    let orderViol = 0;
    const byHold = new Map();
    for (const r of rel) { if (!byHold.has(r.holdId)) byHold.set(r.holdId, []); byHold.get(r.holdId).push(r); }
    for (const rs of byHold.values()) for (let i = 1; i < rs.length; i++) if (rs[i].seq <= rs[i - 1].seq) orderViol++;
    console.log("### Adversary integrity (Q6 run)\n");
    table(
        ["held datagrams", "released", "held but never released", "SHA-256 unchanged arrival->release", "released bytes identical to a device-sent datagram", "order violations"],
        [[rx.length, rel.length, rx.filter((r) => !relSeq.has(r.seq)).length, `${rel.filter((r) => r.sha_arrival === r.sha_release).length}/${rel.length}`, `${rel.filter((r) => devTx.has(r.sha_release)).length}/${rel.length}`, orderViol]],
    );
}

if (baselineCsv) {
    const base = parseCsv(readFileSync(baselineCsv, "utf8"));
    console.log("### Witness off (Q1-Q5 run) vs on (Q6): same cells\n");
    const map = [["Q4:mode=select,d=20s", "Q4", "mode=select,d=20s"], ["Q4:mode=select,d=2s", "Q4", "mode=select,d=2s"], ["Q4:mode=select,d=10s", "Q4", "mode=select,d=10s"], ["Q4:mode=all,d=20s", "Q4", "mode=all,d=20s"], ["Q1:d=1s", "Q1", "d=1s"], ["Q1:d=10s", "Q1", "d=10s"], ["Q1:d=30s", "Q1", "d=30s"]];
    table(
        ["cell", "off: older value applied after newer", "on: older value applied after newer", "off: update after release", "on: update after release", "off: final = device", "on: final = device"],
        map.filter(([c]) => cells.has(c)).map(([c, q, bc]) => {
            const off_ = base.filter((r) => r.question === q && r.cell === bc);
            const on = cells.get(c);
            const inv = (rs) => `${count(rs, (r) => r.later_report_before_release === "true" && r.applied === "true")}/${rs.length}`;
            return [c, q === "Q4" ? inv(off_) : "n/a", q === "Q4" ? inv(on) : "n/a", stats(vals(off_, "applied_minus_release_ms")), stats(vals(on, "applied_minus_release_ms")),
                // Q1-Q5 Q4 select d=20 trials ended correct only after the device's next report; use the inversion column there
                `${count(off_, (r) => r.final_ctrl_value === r.final_device_value)}/${off_.length}`, `${count(on, (r) => r.final_ctrl_value === r.final_device_value)}/${on.length}`];
        }),
    );
}
