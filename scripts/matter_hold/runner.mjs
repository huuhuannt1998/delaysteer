// Orchestrates the Matter hold probe: spawns the device and the controller as separate Node processes,
// commissions (once), then runs the trials defined in results/matter_hold_plan.md and writes one CSV row per trial.
//
// Usage: node runner.mjs [--questions Q1,Q2,Q3,Q4,Q5,Q7] [--reps 5] [--smoke] [--run-id NAME] [--q7-holds 60,300,1800,7200]
import { fork } from "node:child_process";
import { createWriteStream, mkdirSync, existsSync, appendFileSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { sanitizePath } from "./sanitize.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..");
const RESULTS = join(REPO, "results");
const rel = (p) => relative(REPO, p);

const args = process.argv.slice(2);
const argVal = (name, dflt) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : dflt;
};
const SMOKE = args.includes("--smoke");
// Q6: controller-side order witness (scripts/matter_hold/witness.mjs). Off by default; Q1-Q5 behaviour unchanged.
const WITNESS = args.includes("--witness");
const QUESTIONS = (argVal("--questions", "Q1,Q5,Q4,Q2")).split(",");
const REPS = Number(argVal("--reps", SMOKE ? 1 : 5));
const RUN_ID = argVal("--run-id", `run-${new Date().toISOString().replace(/[:.]/g, "-")}`);
const CSV = argVal("--csv", join(RESULTS, "matter_hold.csv"));
const LOGDIR = join(argVal("--logroot", join(RESULTS, "matter_hold_logs")), RUN_ID);
mkdirSync(LOGDIR, { recursive: true });

const PKG = JSON.parse(readFileSync(join(HERE, "node_modules", "@matter", "main", "package.json"), "utf8"));
const MATTERJS_VERSION = PKG.version;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------------------------ process plumbing
const EV = []; // every IPC record from both children, in receipt order
const eventsOut = createWriteStream(join(LOGDIR, "events.jsonl"));
const waiters = [];

// Parse matter.js duration strings such as "1m 8s", "58.6s", "0", "1h 2m".
function parseDur(str) {
    if (str === undefined) return undefined;
    if (/^0$/.test(str.trim())) return 0;
    let total = 0;
    let any = false;
    for (const m of str.matchAll(/([\d.]+)(ms|h|m|s)/g)) {
        any = true;
        const v = Number(m[1]);
        total += m[2] === "h" ? v * 3600 : m[2] === "m" ? v * 60 : m[2] === "s" ? v : v / 1000;
    }
    return any ? Math.round(total * 1000) / 1000 : undefined;
}
// Latest subscription parameters as logged by the controller (authoritative, not recomputed).
const sub = { wireMin: undefined, wireCeiling: undefined, negotiatedMax: undefined, timeout: undefined, id: undefined };

function onRecord(rec) {
    rec.recv = Date.now();
    if (rec.role === "controller" && rec.type === "log_match") {
        if (rec.pattern === "sub_req") {
            const m = /min: (.+?) max: (.+?) attributes/.exec(rec.text);
            if (m) {
                sub.wireMin = parseDur(m[1]);
                sub.wireCeiling = parseDur(m[2]);
            }
        } else if (rec.pattern === "sub_ok") {
            const m = /id: (\S+) interval: (.+?) timeout: (.+?)$/.exec(rec.text.trim());
            if (m) {
                sub.id = m[1];
                sub.negotiatedMax = parseDur(m[2]);
                sub.timeout = parseDur(m[3]);
            }
        }
    }
    EV.push(rec);
    eventsOut.write(JSON.stringify(rec) + "\n");
    for (const w of [...waiters]) {
        if (w.pred(rec)) {
            waiters.splice(waiters.indexOf(w), 1);
            clearTimeout(w.timer);
            w.resolve(rec);
        }
    }
}

/** Wait for a record satisfying pred, looking back from index `from` first. Resolves undefined on timeout. */
function waitFor(pred, timeoutMs, from = EV.length) {
    for (let i = from; i < EV.length; i++) if (pred(EV[i])) return Promise.resolve(EV[i]);
    return new Promise((resolve) => {
        const w = { pred, resolve };
        w.timer = setTimeout(() => {
            waiters.splice(waiters.indexOf(w), 1);
            resolve(undefined);
        }, timeoutMs);
        waiters.push(w);
    });
}

function spawn(name, script, storage) {
    const env = {
        ...process.env,
        MATTER_STORAGE_PATH: join(HERE, ".storage", storage),
        MATTER_MDNS_NETWORKINTERFACE: "lo0",
        MATTER_LOG_LEVEL: "info",
        MATTER_LOG_FORMAT: "plain",
        ...(WITNESS && name === "controller" ? { HOLD_WITNESS: "1" } : {}),
    };
    const child = fork(join(HERE, script), [], { env, stdio: ["ignore", "pipe", "pipe", "ipc"], cwd: HERE });
    const log = createWriteStream(join(LOGDIR, `${name}.log`), { flags: "a" });
    child.stdout.pipe(log);
    child.stderr.pipe(log);
    child.on("message", onRecord);
    child.on("exit", (code, sig) => onRecord({ t: Date.now(), role: name, type: "exit", code, sig }));
    return child;
}

// ------------------------------------------------------------------ helpers
let device, controller;
let params; // MRP + session parameters reported by the controller process
let currentIntervals; // {minFloor, maxCeiling}
let negotiatedMax;

const isC = (type) => (r) => r.role === "controller" && r.type === type;
const isD = (type) => (r) => r.role === "device" && r.type === type;

async function status(tag = `s${Date.now()}`) {
    controller.send({ cmd: "status", tag });
    return waitFor((r) => r.role === "controller" && r.type === "status" && r.tag === tag, 5000);
}
async function deviceValue() {
    const tag = `g${Date.now()}`;
    device.send({ cmd: "get", tag });
    const r = await waitFor((x) => x.role === "device" && x.type === "value" && x.tag === tag, 5000);
    return r?.value;
}
async function setDevice(value) {
    const tag = `v${Date.now()}${Math.random()}`;
    const from = EV.length;
    device.send({ cmd: "set", value, tag });
    return waitFor((r) => r.role === "device" && r.type === "set_done" && r.tag === tag, 5000, from);
}
function attrPred(value, after) {
    return (r) => r.role === "controller" && r.type === "attr" && r.attributeName === "stateValue" && r.value === value && r.t >= after;
}

async function connect(minFloor, maxCeiling) {
    const from = EV.length;
    controller.send({ cmd: "connect", minFloor, maxCeiling });
    const ok = await waitFor((r) => r.role === "controller" && r.type === "log_match" && r.pattern === "sub_ok", 60000, from);
    if (!ok) throw new Error(`subscription not established for ${minFloor}/${maxCeiling}`);
    await sleep(1500);
    const st = await status();
    currentIntervals = { minFloor, maxCeiling };
    negotiatedMax = sub.negotiatedMax;
    onRecord({ t: Date.now(), role: "runner", type: "connected", minFloor, maxCeiling, sub: { ...sub }, subOkText: ok.text });
    return st;
}

/** Bring the system to: requested intervals active, subscription connected, device closed, controller shows closed. */
async function baseline(minFloor, maxCeiling) {
    let st = await status();
    const needReconnect = !currentIntervals || currentIntervals.minFloor !== minFloor || currentIntervals.maxCeiling !== maxCeiling || st?.connectionState !== "Connected";
    if (needReconnect) {
        if (st?.connectionState !== "Connected" && currentIntervals && currentIntervals.minFloor === minFloor && currentIntervals.maxCeiling === maxCeiling) {
            // Wait for the sustained subscription to come back on its own.
            const back = await waitFor((r) => r.role === "controller" && r.type === "node_state" && r.state === "Connected", 120000);
            if (!back) await connect(minFloor, maxCeiling);
        } else {
            await connect(minFloor, maxCeiling);
        }
    }
    // Device to closed, and make sure the controller reflects it.
    for (let attempt = 0; attempt < 3; attempt++) {
        const dv = await deviceValue();
        st = await status();
        if (dv === true && st?.value === true) break;
        if (dv === true && st?.value !== true) {
            // controller stale (e.g. after an inversion): cycle the contact so a fresh report carries the truth
            const t = Date.now();
            await setDevice(false);
            await waitFor((r) => r.role === "controller" && r.type === "event" && r.eventName === "stateChange" && r.t >= t, 10000);
            await sleep(2500);
        }
        const t2 = Date.now();
        await setDevice(true);
        await waitFor(attrPred(true, t2), 20000);
    }
    await sleep(3000); // quiet period > min interval floor
    st = await status();
    return st;
}

// ------------------------------------------------------------------ CSV
const COLS = [
    "run_id", "trial_id", "question", "cell", "rep", "hold_mode", "hold_d_s", "second_toggle_s",
    "req_min_floor_s", "req_max_ceiling_s", "wire_min_floor_s", "wire_max_ceiling_s", "subscription_id", "negotiated_max_interval_s", "controller_timeout_s", "controller_timeout_formula_s",
    "matterjs_version", "node_version", "mrp_idle_ms", "mrp_active_ms", "mrp_active_threshold_ms", "mrp_max_transmissions",
    "mrp_backoff_base", "mrp_backoff_margin", "mrp_backoff_jitter", "mrp_backoff_threshold",
    "t_hold_start", "t_toggle", "t_release", "release_reason", "n_held", "n_distinct_held_msgs", "held_bytes_unchanged", "release_in_order",
    "dev_report_tx_count", "dev_report_first_tx_t", "dev_report_last_tx_t", "dev_giveup_t", "dev_giveup_after_toggle_ms", "dev_sub_terminated",
    "applied", "t_applied", "applied_minus_toggle_ms", "applied_minus_release_ms",
    "event_number", "event_epoch_ts", "event_receipt_t", "event_age_ms", "event_minus_toggle_ms",
    "ctrl_warn_error_count", "ctrl_warn_error_first", "ctrl_peer_unresponsive_ms_after_hold", "ctrl_peer_unresponsive_text",
    "n_passed_value_datagrams_during_hold", "later_report_before_release", "ctrl_callbacks_during_hold",
    "final_ctrl_value", "final_device_value", "stale_mismatch_after_release",
    "mismatch_observed_until_ms_after_release", "mismatch_resolved", "keepalives_during_mismatch", "dup_event_callbacks",
    "t_last_delivered_before_hold", "t_lost_declared", "lost_after_hold_start_ms", "lost_after_last_delivered_ms", "lost_via",
    "t_fresh_value", "fresh_after_release_ms", "fresh_after_hold_start_ms", "fresh_via",
    "notes",
];
const WCOLS = [
    "witness_on", "w_attr_rejections", "w_reject_detail", "w_event_flags_duplicate", "w_event_flags_older", "w_event_flag_detail",
    "w_bs_version_before_hold", "w_bs_versions_during_hold", "w_bs_versions_at_release", "w_bs_reports",
    "w_ctrl_attr_versions", "late_value_applied", "w_window_ms",
];
if (WITNESS) COLS.push(...WCOLS);
const LCOLS = [
    "stale_ms", "corrected_before_release", "correction_via", "n_status_polls",
    "sub_timeout_during_trial", "node_not_connected_during_trial", "resubscribe_during_trial", "keepalives_during_stale",
];
if (QUESTIONS.includes("Q7")) COLS.push(...LCOLS);

if (!existsSync(CSV)) writeFileSync(CSV, COLS.join(",") + "\n");
function csvCell(v) {
    if (v === undefined || v === null) return "";
    const s = String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
let trialNo = 0;
const pendingRows = [];

const BS = "1/69"; // endpoint 1, BooleanState (0x45)
function bsOf(rep) {
    return rep.clusters?.find((c) => `${c.endpointId}/${c.clusterId}` === BS);
}
function witnessColumns(row, t0, t1) {
    const inWin = (r) => r.t >= t0 && r.t < t1;
    const tToggle = Number(row.t_toggle);
    const tRel = Number(row.t_release);
    const rej = EV.filter((r) => r.role === "controller" && r.type === "witness_reject" && inWin(r));
    const flags = EV.filter((r) => r.role === "controller" && r.type === "witness_event_flag" && inWin(r));
    const reps = EV.filter((r) => r.role === "controller" && r.type === "witness_report" && inWin(r) && bsOf(r));
    const before = [...EV.filter((r) => r.role === "controller" && r.type === "witness_report" && r.t < t0 && bsOf(r))].pop();
    const beforeBs = before ? bsOf(before) : undefined;
    const fmtRep = (r) => {
        const c = bsOf(r);
        const vals = (c.attrs ?? []).filter((a) => a.attributeId === 0).map((a) => `${a.value}:${a.decision}`).join("|");
        return `${r.t - tToggle}ms:v${c.versions.join("/")}:${vals || "-"}${c.rejected ? ":REJ" : ""}`;
    };
    const during = reps.filter((r) => r.t < tRel);
    const atRel = reps.filter((r) => r.t >= tRel && r.t < tRel + 3000);
    const ctrlAttr = EV.filter((r) => r.role === "controller" && r.type === "attr" && r.attributeName === "stateValue" && inWin(r));
    return {
        witness_on: true,
        w_attr_rejections: rej.length,
        w_reject_detail: rej.map((r) => `attr ${r.endpointId}/${r.clusterId}/${r.attributeId}=${r.value} v${r.version} < highest v${r.highestApplied} @${r.t - tToggle}ms`).join("; "),
        w_event_flags_duplicate: flags.filter((f) => f.flag === "duplicate").length,
        w_event_flags_older: flags.filter((f) => f.flag === "older").length,
        w_event_flag_detail: flags.map((f) => `${f.flag}:${f.eventNumber}(max ${f.highestSeen})@${f.t - tToggle}ms`).join(" "),
        w_bs_version_before_hold: beforeBs ? Math.max(...beforeBs.versions) : undefined,
        w_bs_versions_during_hold: during.map((r) => bsOf(r).versions.join("/")).join(" "),
        w_bs_versions_at_release: atRel.map((r) => bsOf(r).versions.join("/")).join(" "),
        w_bs_reports: reps.map(fmtRep).join(" "),
        w_ctrl_attr_versions: ctrlAttr.map((r) => `${r.value}:v${r.version}@${r.t - tToggle}ms`).join(" "),
        late_value_applied: row.applied,
        w_window_ms: Math.round(t1 - t0),
    };
}
function flushWitnessRows() {
    const sorted = [...pendingRows].sort((a, b) => Number(a.t_hold_start) - Number(b.t_hold_start));
    for (let i = 0; i < sorted.length; i++) {
        const t0 = Number(sorted[i].t_hold_start);
        const t1 = i + 1 < sorted.length ? Number(sorted[i + 1].t_hold_start) : Date.now();
        Object.assign(sorted[i], witnessColumns(sorted[i], t0, t1));
        appendFileSync(CSV, COLS.map((c) => csvCell(sorted[i][c])).join(",") + "\n");
    }
    pendingRows.length = 0;
}
function writeRow(row) {
    const p = params ?? {};
    const full = {
        run_id: RUN_ID,
        matterjs_version: MATTERJS_VERSION,
        node_version: process.version,
        mrp_idle_ms: p.sessionIntervals?.idleIntervalMs,
        mrp_active_ms: p.sessionIntervals?.activeIntervalMs,
        mrp_active_threshold_ms: p.sessionIntervals?.activeThresholdMs,
        mrp_max_transmissions: p.mrp?.maxTransmissions,
        mrp_backoff_base: p.mrp?.backoffBase,
        mrp_backoff_margin: p.mrp?.backoffMargin,
        mrp_backoff_jitter: p.mrp?.backoffJitter,
        mrp_backoff_threshold: p.mrp?.backoffThreshold,
        req_min_floor_s: currentIntervals?.minFloor,
        req_max_ceiling_s: currentIntervals?.maxCeiling,
        wire_min_floor_s: row._sub?.wireMin,
        wire_max_ceiling_s: row._sub?.wireCeiling,
        subscription_id: row._sub?.id,
        negotiated_max_interval_s: row._sub?.negotiatedMax,
        controller_timeout_s: row._sub?.timeout,
        controller_timeout_formula_s: controllerTimeoutS(row._sub?.negotiatedMax),
        ...row,
    };
    delete full._sub;
    if (WITNESS) {
        // Witness columns are attributed over [this hold start, next hold start) once the run ends, so that a report
        // the device re-sends after the trial (e.g. its re-queued data at the next report) is counted where it belongs.
        pendingRows.push(full);
    } else {
        appendFileSync(CSV, COLS.map((c) => csvCell(full[c])).join(",") + "\n");
    }
    onRecord({ t: Date.now(), role: "runner", type: "row", row: full });
    console.log(`[row] ${full.trial_id} ${full.question} ${full.cell} applied=${full.applied} age=${full.event_age_ms} lost=${full.lost_after_last_delivered_ms} later=${full.later_report_before_release} mismatch=${full.stale_mismatch_after_release}`);
}

// Controller subscription timeout in matter.js: maxInterval + 2 * maxPeerResponseTime(10 s processing).
function controllerTimeoutS(maxIntervalS) {
    const p = params;
    if (!p || maxIntervalS === undefined) return undefined;
    const { idleIntervalMs: sii, activeIntervalMs: sai, activeThresholdMs: sat } = p.sessionIntervals;
    const m = p.mrp;
    let fin = 0;
    let active = true;
    for (let i = 0; i < m.maxTransmissions; i++) {
        if (active && fin > sat) active = false;
        const base = active ? sai : sii;
        fin += Math.floor(base * m.backoffMargin * Math.pow(m.backoffBase, Math.max(0, i - m.backoffThreshold)) * (1 + m.backoffJitter));
    }
    const maxPeer = fin + 10000 + 5000;
    return (maxIntervalS * 1000 + 2 * maxPeer) / 1000;
}

// ------------------------------------------------------------------ trial analysis
function windowRecs(from) {
    return EV.slice(from);
}
function analyzeHold(recs, holdId, tToggle) {
    const released = recs.find((r) => r.role === "controller" && r.type === "released" && r.holdId === holdId);
    const relItems = recs.filter((r) => r.role === "controller" && r.type === "rx_release" && r.holdId === holdId);
    const selectKey = released?.selectKey;
    // device-side transmissions of the (first) held value-bearing message
    const keyOfFirstHeld = relItems.find((x) => x.len >= 60)?.key ?? relItems[0]?.key;
    const devTx = recs.filter((r) => r.role === "device" && r.type === "tx" && `${r.sess}:${r.ctr}` === keyOfFirstHeld);
    const giveup = recs.find((r) => r.role === "device" && r.type === "log_match" && r.pattern === "update_error" && r.t >= tToggle);
    const subTerm = recs.find((r) => r.role === "device" && r.type === "log_match" && r.pattern === "sub_giveup" && r.t >= tToggle);
    return {
        released,
        relItems,
        selectKey,
        keyOfFirstHeld,
        devTx,
        giveup,
        subTerm,
        n_held: released?.n,
        n_distinct_held_msgs: released?.distinct,
        held_bytes_unchanged: released ? released.allMatch : undefined,
        release_in_order: released ? released.inOrder : undefined,
        t_release: released?.t,
        release_reason: released?.reason,
        dev_report_tx_count: devTx.length,
        dev_report_first_tx_t: devTx[0]?.t,
        dev_report_last_tx_t: devTx.at(-1)?.t,
        dev_giveup_t: giveup?.t,
        dev_giveup_after_toggle_ms: giveup ? giveup.t - tToggle : undefined,
        dev_sub_terminated: !!subTerm,
    };
}
/** Event numbers handed to the controller application more than once within the trial window. */
function dupEvents(recs) {
    const seen = new Map();
    for (const r of recs) {
        if (r.role === "controller" && r.type === "event") for (const e of r.events ?? []) seen.set(e.eventNumber, (seen.get(e.eventNumber) ?? 0) + 1);
    }
    return [...seen.entries()].filter(([, n]) => n > 1).map(([k, n]) => `${k}x${n}`).join(" ");
}
function ctrlWarnErrors(recs, t0, t1) {
    const w = recs.filter((r) => r.role === "controller" && r.type === "log_match" && r.pattern === "warn_or_error" && r.t >= t0 && r.t <= t1);
    const pu = recs.find((r) => r.role === "controller" && r.type === "log_match" && r.pattern === "peer_unresponsive" && r.t >= t0 && r.t <= t1);
    return {
        ctrl_warn_error_count: w.length,
        ctrl_warn_error_first: w[0]?.text?.slice(0, 200),
        ctrl_peer_unresponsive_ms_after_hold: pu ? pu.t - t0 : undefined,
        ctrl_peer_unresponsive_text: pu?.text?.replace(/^\S+ \S+ /, "").slice(0, 200),
    };
}

// ------------------------------------------------------------------ Q1 / Q3 / Q5: hold ALL device datagrams for d
async function trialHoldAll(question, d, rep, notes = "", cellPrefix = "") {
    const id = `T${String(++trialNo).padStart(3, "0")}`;
    await baseline(1, 60);
    const from = EV.length;
    const tHold = Date.now();
    controller.send({ cmd: "hold", mode: "all", durationMs: d * 1000 });
    const hs = await waitFor(isC("hold_start"), 3000, from);
    const subAtHold = { ...sub };
    const sd = await setDevice(false); // closed -> open
    const tToggle = sd?.t_req ?? Date.now();
    const rel = await waitFor((r) => r.role === "controller" && r.type === "released" && r.holdId === hs?.holdId, d * 1000 + 10000, from);
    const applied = await waitFor(attrPred(false, tToggle), 15000, from);
    const ev = await waitFor((r) => r.role === "controller" && r.type === "event" && r.eventName === "stateChange" && r.events?.some((e) => e.data?.stateValue === false && e.epochTimestamp >= tToggle - 5), 15000, from);
    await sleep(4000);
    const recs = windowRecs(from);
    const a = analyzeHold(recs, hs?.holdId, tToggle);
    const e = ev?.events?.find((x) => x.data?.stateValue === false);
    const st = await status();
    const dv = await deviceValue();
    const cbDuringHold = recs.filter((r) => r.role === "controller" && (r.type === "attr" || r.type === "event") && r.t >= tHold && r.t < (a.t_release ?? Infinity)).length;
    writeRow({
        trial_id: id, question, cell: `${cellPrefix}d=${d}s`, rep, hold_mode: "all", hold_d_s: d,
        _sub: subAtHold,
        t_hold_start: hs?.t, t_toggle: tToggle,
        ...pick(a),
        applied: !!applied && applied.t >= (a.t_release ?? 0),
        t_applied: applied?.t,
        applied_minus_toggle_ms: applied ? applied.t - tToggle : undefined,
        applied_minus_release_ms: applied && a.t_release ? applied.t - a.t_release : undefined,
        event_number: e?.eventNumber, event_epoch_ts: e?.epochTimestamp, event_receipt_t: ev?.t,
        event_age_ms: e && ev ? ev.t - e.epochTimestamp : undefined,
        event_minus_toggle_ms: e ? e.epochTimestamp - tToggle : undefined,
        ...ctrlWarnErrors(recs, tHold, Date.now()),
        ctrl_callbacks_during_hold: cbDuringHold,
        dup_event_callbacks: dupEvents(recs),
        final_ctrl_value: st?.value, final_device_value: dv, stale_mismatch_after_release: st?.value !== dv,
        t_last_delivered_before_hold: hs?.lastDeliveredT,
        notes: [notes, rel ? "" : "release not observed", applied ? "" : "value not applied within 15 s of release"].filter(Boolean).join("; "),
    });
}

function pick(a) {
    const { released, relItems, selectKey, keyOfFirstHeld, devTx, giveup, subTerm, ...rest } = a;
    return rest;
}

// ------------------------------------------------------------------ Q4: hold one value-bearing report, toggle again
async function trialOrder(mode, d, rep, secondToggleS = 3, observeMs = 0, question = "Q4", cellPrefix = "", postReleaseMs = 8000) {
    const id = `T${String(++trialNo).padStart(3, "0")}`;
    await baseline(1, 60);
    const from = EV.length;
    const tHold = Date.now();
    controller.send({ cmd: "hold", mode, durationMs: d * 1000, minLen: 60 });
    const hs = await waitFor(isC("hold_start"), 3000, from);
    const subAtHold = { ...sub };
    const sd1 = await setDevice(false); // R1: closed -> open (held)
    const tToggle = sd1?.t_req ?? Date.now();
    await sleep(secondToggleS * 1000);
    const sd2 = await setDevice(true); // R2: open -> closed
    const tToggle2 = sd2?.t_req;
    const rel = await waitFor((r) => r.role === "controller" && r.type === "released" && r.holdId === hs?.holdId, d * 1000 + 10000, from);
    // Q1-Q5: 8 s after release. Q6 select d=20 s: long enough to include the device's next scheduled report.
    await sleep(rel ? Math.max(0, rel.t + postReleaseMs - Date.now()) : 8000);
    const recs = windowRecs(from);
    const a = analyzeHold(recs, hs?.holdId, tToggle);
    const tRel = a.t_release ?? Infinity;
    const passed = recs.filter((r) => r.role === "controller" && r.type === "rx" && !r.held && r.t >= tHold && r.t < tRel && r.len >= 60);
    const cbDuring = recs.filter((r) => r.role === "controller" && (r.type === "attr" || r.type === "event") && r.t >= tHold && r.t < tRel);
    let st = await status();
    let dv = await deviceValue();
    // If the held report overwrote a newer value, watch whether the controller ever self-corrects (no new changes
    // are made during this window; only the device's own keepalive reports can arrive).
    let mismatchUntil, mismatchResolved, keepalives;
    if (observeMs > 0 && st?.value !== dv && a.t_release) {
        const tObsFrom = EV.length;
        const deadline = a.t_release + observeMs;
        while (Date.now() < deadline) {
            await sleep(2000);
            st = await status();
            if (st?.value === dv) break;
        }
        mismatchResolved = st?.value === dv;
        mismatchUntil = Date.now() - a.t_release;
        keepalives = EV.slice(tObsFrom).filter((r) => r.role === "controller" && r.type === "alive").length;
    }
    const recsAll = windowRecs(from);
    const ctrlSeq = recsAll
        .filter((r) => r.role === "controller" && (r.type === "attr" && r.attributeName === "stateValue" || r.type === "event" && r.eventName === "stateChange"))
        .map((r) => r.type === "attr" ? `A:${r.value}@${r.t - tToggle}` : `E:${r.events.map((e) => `${e.eventNumber}=${e.data?.stateValue}`).join("|")}@${r.t - tToggle}`)
        .join(" ");
    const applied = recs.find((r) => attrPred(false, tToggle)(r));
    writeRow({
        trial_id: id, question, cell: `${cellPrefix}mode=${mode},d=${d}s`, rep, hold_mode: mode, hold_d_s: d, second_toggle_s: secondToggleS,
        _sub: subAtHold,
        t_hold_start: hs?.t, t_toggle: tToggle,
        ...pick(a),
        applied: !!applied, t_applied: applied?.t,
        applied_minus_toggle_ms: applied ? applied.t - tToggle : undefined,
        applied_minus_release_ms: applied && a.t_release ? applied.t - a.t_release : undefined,
        ...ctrlWarnErrors(recs, tHold, Date.now()),
        n_passed_value_datagrams_during_hold: passed.length,
        later_report_before_release: passed.length > 0 || cbDuring.length > 0,
        ctrl_callbacks_during_hold: cbDuring.length,
        final_ctrl_value: st?.value, final_device_value: dv, stale_mismatch_after_release: st?.value !== dv,
        mismatch_observed_until_ms_after_release: mismatchUntil, mismatch_resolved: mismatchResolved, keepalives_during_mismatch: keepalives,
        dup_event_callbacks: dupEvents(recsAll),
        t_last_delivered_before_hold: hs?.lastDeliveredT,
        notes: `second toggle at +${tToggle2 - tToggle} ms; controller sequence (ms after first toggle): ${ctrlSeq}` + (rel ? "" : "; release not observed"),
    });
    return { mismatch: st?.value !== dv };
}

// ------------------------------------------------------------------ Q7 (E-D): hold ONE report for a long time; the door stays open
// Plan: results/matter_longhold_plan.md. The report carrying closed->open is held for d; nothing else is held and no
// further change is made. The controller's cached value is polled (local read, no network) until the first "open".
async function trialLongSelect(d, rep, pollMs = 2000, postReleaseMs = 30000) {
    const id = `T${String(++trialNo).padStart(3, "0")}`;
    await baseline(1, 60);
    const from = EV.length;
    const tHold = Date.now();
    controller.send({ cmd: "hold", mode: "select", durationMs: d * 1000, minLen: 60 });
    const hs = await waitFor(isC("hold_start"), 3000, from);
    const subAtHold = { ...sub };
    const sd = await setDevice(false); // closed -> open; held; the door then stays open
    const tToggle = sd?.t_req ?? Date.now();
    let tFirstOpen, polls = 0, rel;
    const hardStop = tToggle + d * 1000 + postReleaseMs + 60000;
    while (Date.now() < hardStop) {
        await sleep(pollMs);
        polls++;
        const st = await status();
        if (tFirstOpen === undefined && st?.value === false) tFirstOpen = st.t;
        rel = rel || EV.slice(from).find((r) => r.role === "controller" && r.type === "released" && r.holdId === hs?.holdId);
        if (rel && Date.now() >= rel.t + postReleaseMs) break;
    }
    const recs = windowRecs(from);
    const a = analyzeHold(recs, hs?.holdId, tToggle);
    const tRel = a.t_release ?? Infinity;
    const firstOpen = recs.find((r) => attrPred(false, tToggle)(r));
    const tCorr = firstOpen?.t ?? tFirstOpen;
    const before = (pred) => recs.some((r) => pred(r) && r.t >= tToggle && (tCorr === undefined || r.t <= tCorr));
    const subTimeout = recs.some((r) => r.role === "controller" && r.type === "log_match" && r.pattern === "sub_timeout" && r.t >= tHold);
    const notConnected = recs.some((r) => r.role === "controller" && r.type === "node_state" && r.state !== "Connected" && r.t >= tHold);
    const resub = recs.some((r) => r.role === "controller" && r.type === "log_match" && (r.pattern === "sub_req" || r.pattern === "resubscribe") && r.t >= tToggle);
    let via;
    if (tCorr === undefined) via = "never";
    else if (tCorr >= tRel) via = "released_report";
    else if (before((r) => r.role === "controller" && r.type === "log_match" && r.pattern === "sub_timeout")) via = "liveness_loss_then_resubscribe";
    else if (before((r) => r.role === "controller" && r.type === "log_match" && (r.pattern === "sub_req" || r.pattern === "resubscribe"))) via = "resubscribe";
    else via = "later_device_report";
    const keepalives = recs.filter((r) => r.role === "controller" && r.type === "alive" && r.t >= tToggle && (tCorr === undefined || r.t <= tCorr)).length;
    const passed = recs.filter((r) => r.role === "controller" && r.type === "rx" && !r.held && r.t >= tHold && r.t < tRel && r.len >= 60);
    const st = await status();
    const dv = await deviceValue();
    const ctrlSeq = recs
        .filter((r) => r.role === "controller" && (r.type === "attr" && r.attributeName === "stateValue" || r.type === "node_state" || r.type === "log_match" && ["sub_timeout", "sub_req", "resubscribe"].includes(r.pattern)))
        .map((r) => r.type === "attr" ? `A:${r.value}@${r.t - tToggle}` : r.type === "node_state" ? `N:${r.state}@${r.t - tToggle}` : `L:${r.pattern}@${r.t - tToggle}`)
        .join(" ");
    writeRow({
        trial_id: id, question: "Q7", cell: `mode=select,d=${d}s`, rep, hold_mode: "select", hold_d_s: d,
        _sub: subAtHold,
        t_hold_start: hs?.t, t_toggle: tToggle,
        ...pick(a),
        applied: !!firstOpen, t_applied: firstOpen?.t,
        applied_minus_toggle_ms: firstOpen ? firstOpen.t - tToggle : undefined,
        applied_minus_release_ms: firstOpen && a.t_release ? firstOpen.t - a.t_release : undefined,
        ...ctrlWarnErrors(recs, tHold, Date.now()),
        n_passed_value_datagrams_during_hold: passed.length,
        final_ctrl_value: st?.value, final_device_value: dv, stale_mismatch_after_release: st?.value !== dv,
        t_last_delivered_before_hold: hs?.lastDeliveredT,
        stale_ms: tCorr !== undefined ? tCorr - tToggle : undefined,
        corrected_before_release: tCorr !== undefined && tCorr < tRel,
        correction_via: via,
        n_status_polls: polls,
        sub_timeout_during_trial: subTimeout,
        node_not_connected_during_trial: notConnected,
        resubscribe_during_trial: resub,
        keepalives_during_stale: keepalives,
        notes: `controller sequence (ms after toggle): ${ctrlSeq}` + (rel ? "" : "; release not observed"),
    });
    // Let exchanges orphaned by a long-held backlog time out before the next trial.
    await sleep(20000);
}

// ------------------------------------------------------------------ Q2: hold ALL until the controller declares the subscription lost
async function trialLiveness(maxCeiling, rep) {
    const id = `T${String(++trialNo).padStart(3, "0")}`;
    await baseline(1, maxCeiling);
    // Fresh report right before the hold so the controller's liveness timer has just been reset.
    const tA = Date.now();
    await setDevice(false);
    const openSeen = await waitFor(attrPred(false, tA), 20000);
    // Let the report exchange finish (device's standalone ACK of our StatusResponse) so that the controller has no
    // outstanding reliable message when the hold starts; only the subscription liveness timer can then detect it.
    await sleep(1000);
    const from = EV.length;
    const timeoutS = sub.timeout ?? controllerTimeoutS(sub.negotiatedMax);
    const capMs = Math.round((timeoutS ?? maxCeiling + 60) * 1000 * 2 + 30000);
    controller.send({ cmd: "hold", mode: "all", durationMs: null, releaseOnLost: true, capMs });
    const hs = await waitFor(isC("hold_start"), 3000, from);
    const subAtHold = { ...sub };
    await sleep(1000);
    const sd = await setDevice(true); // the fresh value the controller should eventually learn
    const tToggle = sd?.t_req;
    const rel = await waitFor((r) => r.role === "controller" && r.type === "released" && r.holdId === hs?.holdId, capMs + 10000, from);
    const lost = EV.slice(from).find((r) => r.role === "controller" && r.type === "lost_declared" && r.holdId === hs?.holdId);
    const fresh = await waitFor(attrPred(true, tToggle), 120000, from);
    await sleep(3000);
    const recs = windowRecs(from);
    const a = analyzeHold(recs, hs?.holdId, tToggle);
    // Was the fresh value carried by a released (held) report, or by the re-subscription priming report?
    const subReqAfter = recs.find((r) => r.role === "controller" && r.type === "log_match" && r.pattern === "sub_req" && r.t >= (a.t_release ?? 0));
    let freshVia;
    if (fresh) freshVia = subReqAfter && subReqAfter.t <= fresh.t ? "resubscribe_priming" : "released_held_report";
    const st = await status();
    const dv = await deviceValue();
    writeRow({
        trial_id: id, question: "Q2", cell: `maxCeiling=${maxCeiling}s`, rep, hold_mode: "all", hold_d_s: "until_lost",
        _sub: subAtHold,
        t_hold_start: hs?.t, t_toggle: tToggle,
        ...pick(a),
        applied: !!fresh, t_applied: fresh?.t,
        applied_minus_toggle_ms: fresh ? fresh.t - tToggle : undefined,
        applied_minus_release_ms: fresh && a.t_release ? fresh.t - a.t_release : undefined,
        ...ctrlWarnErrors(recs, hs?.t ?? 0, Date.now()),
        final_ctrl_value: st?.value, final_device_value: dv, stale_mismatch_after_release: st?.value !== dv,
        dup_event_callbacks: dupEvents(recs),
        t_last_delivered_before_hold: hs?.lastDeliveredT,
        t_lost_declared: lost?.t,
        lost_after_hold_start_ms: lost ? lost.t - hs.t : undefined,
        lost_after_last_delivered_ms: lost && hs?.lastDeliveredT ? lost.t - hs.lastDeliveredT : undefined,
        lost_via: lost?.via,
        t_fresh_value: fresh?.t,
        fresh_after_release_ms: fresh && a.t_release ? fresh.t - a.t_release : undefined,
        fresh_after_hold_start_ms: fresh ? fresh.t - hs.t : undefined,
        fresh_via: freshVia,
        notes: [openSeen ? "" : "pre-hold report not seen", rel ? "" : "release not observed", lost ? "" : "loss never declared (released at cap)"].filter(Boolean).join("; "),
    });
    // Let the sustained subscription settle before the next trial.
    await waitFor((r) => r.role === "controller" && r.type === "node_state" && r.state === "Connected", 60000, from);
    // Settle so exchanges orphaned by the released backlog time out before the next trial (they otherwise surface
    // as a controller WARN inside the next trial's window).
    await sleep(20000);
}

// ------------------------------------------------------------------ main
async function main() {
    device = spawn("device", "device.mjs", "device");
    const dReady = await waitFor(isD("ready"), 30000);
    if (!dReady) throw new Error("device did not start");
    controller = spawn("controller", "controller.mjs", "controller");
    const cReady = await waitFor(isC("ready"), 30000);
    if (!cReady) throw new Error("controller did not start");
    params = cReady.params;
    controller.send({ cmd: "commission" });
    const com = await waitFor(isC("commissioned"), 120000);
    if (!com) throw new Error("commissioning failed");
    console.log("commissioned", com.nodeId, com.already ? "(stored)" : "(new)");

    const header = { run_id: RUN_ID, matterjs_version: MATTERJS_VERSION, node_version: process.version, params, platform: process.platform, arch: process.arch, witness: WITNESS };
    writeFileSync(join(LOGDIR, "run_header.json"), JSON.stringify(header, null, 2));

    await connect(1, 60);

    if (SMOKE && WITNESS) {
        await trialOrder("select", 20, 1, 3, 0, "Q6", "Q4:", 45000);
        await trialHoldAll("Q6", 30, 1, "smoke", "Q1:");
    } else if (SMOKE) {
        await trialHoldAll("Q1", 2, 1, "smoke");
        await trialOrder("select", 2, 1, 1);
        await trialOrder("select", 20, 1, 3, 90000);
    } else {
        for (const q of QUESTIONS) {
            if (q === "Q1") {
                for (let rep = 1; rep <= REPS; rep++) for (const d of [1, 5, 10, 20, 30]) await trialHoldAll("Q1", d, rep, "Q3 measured on the same report");
            } else if (q === "Q5") {
                for (let rep = 1; rep <= REPS; rep++) await trialHoldAll("Q5", 25, rep, "hold past the device's report give-up (~15 s); Q3 measured on the same report");
            } else if (q === "Q4") {
                for (let rep = 1; rep <= REPS; rep++) {
                    await trialOrder("select", 2, rep, 1);
                    await trialOrder("select", 10, rep, 3);
                    await trialOrder("select", 20, rep, 3, 90000);
                    await trialOrder("all", 20, rep, 3);
                }
            } else if (q === "Q6") {
                // Addendum Q6 (plan): order witness on. Cells run sequentially, n = REPS each.
                for (let rep = 1; rep <= REPS; rep++) {
                    await trialOrder("select", 20, rep, 3, 0, "Q6", "Q4:", 45000);
                    await trialOrder("select", 2, rep, 1, 0, "Q6", "Q4:");
                    await trialOrder("select", 10, rep, 3, 0, "Q6", "Q4:");
                    await trialOrder("all", 20, rep, 3, 0, "Q6", "Q4:");
                    for (const d of [1, 10, 30]) await trialHoldAll("Q6", d, rep, "witness on", "Q1:");
                }
            } else if (q === "Q7") {
                const holds = argVal("--q7-holds", "60,300,1800,7200").split(",").map(Number);
                for (let rep = 1; rep <= REPS; rep++) for (const d of holds) await trialLongSelect(d, rep);
            } else if (q === "Q2") {
                for (const mc of [10, 60]) for (let rep = 1; rep <= REPS; rep++) await trialLiveness(mc, rep);
            }
        }
    }
}

async function shutdown(code) {
    try {
        if (WITNESS) flushWitnessRows();
    } catch (e) {
        console.error("flush failed:", e);
    }
    try {
        controller?.send({ cmd: "shutdown" });
        device?.send({ cmd: "shutdown" });
        await sleep(3000);
    } catch {}
    for (const c of [controller, device]) {
        try {
            if (c && c.exitCode === null) c.kill("SIGTERM");
        } catch {}
    }
    await sleep(1000);
    for (const c of [controller, device]) {
        try {
            if (c && c.exitCode === null) c.kill("SIGKILL");
        } catch {}
    }
    await new Promise((r) => eventsOut.end(r));
    await sleep(500);
    // Double-anonymous: rewrite absolute paths (account name) that matter.js prints in logs and stack traces.
    try {
        sanitizePath(LOGDIR);
        sanitizePath(CSV);
    } catch (e) {
        console.error("sanitize failed:", e);
    }
    console.log(`logs: ${rel(LOGDIR)}  csv: ${rel(CSV)}`);
    process.exit(code);
}

process.on("SIGINT", () => shutdown(130));
process.on("SIGTERM", () => shutdown(143));
main().then(() => shutdown(0), (e) => {
    console.error("runner failed:", e);
    onRecord({ t: Date.now(), role: "runner", type: "fatal", msg: String(e?.stack ?? e) });
    shutdown(1);
});
