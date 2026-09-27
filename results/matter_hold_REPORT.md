# Matter hold probe: results

Plan: `results/matter_hold_plan.md` (fixed before the run; not modified). Data: `results/matter_hold.csv` (60 rows, one per
trial, run id `main`). Raw logs: `results/matter_hold_logs/main/` (`device.log`, `controller.log`, `events.jsonl` with every
device datagram hash, every hold/release and every controller callback, `run_header.json`). Code and exact commands:
`scripts/matter_hold/` (see its `README.md`). Tables below were produced by `node scripts/matter_hold/analyze.mjs
results/matter_hold.csv --events results/matter_hold_logs/main/events.jsonl`.

Run window: 2026-09-25 06:38–07:18 UTC, one host, loopback only.

## Header: versions and parameters (also in every CSV row)

| Item | Value |
|---|---|
| matter.js | `@matter/main`, `@matter/nodejs`, `@matter/node`, `@matter/protocol`, `@matter/general`, `@matter/types`, `@matter/model`, `@project-chip/matter.js` all **0.17.9** (pinned in `package.json`, locked in `package-lock.json`) |
| Runtime | Node v26.3.0, macOS 26.6.2 (Darwin 25.6.0), arm64 |
| Device | Virtual contact sensor, `ContactSensorDevice` + `BooleanStateServer` (0.17.9 includes the ChangeEvent feature, so `StateChange` events are emitted on every change). Separate Node process. `stateValue=true` = closed. |
| Controller | `CommissioningController` from `@project-chip/matter.js` in a separate Node process; commissioned over IP (PASE to `127.0.0.1:5550`, then CASE, operational fabric); `autoSubscribe` wildcard subscription (all attributes, events `isUrgent: true`). mDNS restricted to `lo0`. |
| MRP (both sides, stack defaults, not overridden) | SII 500 ms, SAI 300 ms, active threshold 4000 ms; MAX_TRANSMISSIONS 5; backoff base 1.6, margin 1.1, jitter 0.25, threshold 1; standalone-ACK timeout 200 ms; network profile "fast" (additional MRP delay 0) |
| Subscription intervals | App requested MinIntervalFloor 1 s and MaxIntervalCeiling 60 s (Q1, Q3, Q4, Q5) or 10/60 s (Q2). The matter.js controller adds jitter of up to max(10 %, 10 s) to the ceiling before sending it; the matter.js device adds up to 10 s randomisation when it picks MaxInterval. Recorded per row: `wire_max_ceiling_s`, `negotiated_max_interval_s`, `controller_timeout_s` (as logged by the controller). Q1/Q3/Q4/Q5 ran on one subscription: wire ceiling 63 s, negotiated MaxInterval 66 s, controller timeout 104 s. |
| Controller liveness timeout (matter.js 0.17.9) | negotiated MaxInterval + 2 × maxPeerResponseTime(10 s processing) = MaxInterval + 38.458 s (formula also recomputed per row as `controller_timeout_formula_s`) |
| Device report give-up (matter.js 0.17.9) | 5 transmissions of the ReportData within ~3.1 s, then a final wait for "processing time and peer resubmissions"; the device declares the report failed at 14.0–15.3 s ("Peer is no longer responding to active session (timed out after ~14 s)") |

## How the hold was implemented

The adversary is a wrapper around `NodeJsUdpSocket.prototype.onData` in the **controller** process, i.e. the controller's
UDP network layer, installed before the controller opens its sockets (`scripts/matter_hold/controller.mjs`). Datagrams
whose source port is the device's operational port (5550) are, while a hold is active, appended to a FIFO queue together
with the original buffer object and its SHA-256; nothing is decoded or changed. On release (timer, or for Q2 the
controller's own subscription-timeout log line), each queued buffer is re-hashed and handed to the unchanged matter.js
listener in arrival order. mDNS (port 5353) and everything else passes straight through. Two modes:

- `all`: hold every device→controller datagram (Q1, Q2, Q3, Q5, and the Q4 control cell).
- `select`: hold one value-bearing message, chosen as the first device datagram ≥ 60 bytes after the hold is armed,
  identified by its cleartext header (session id, message counter), plus its byte-identical MRP retransmissions; pass every
  other datagram (Q4). An on-path attacker can read these header fields without keys.

Evidence it only held (all 60 trials): 380 datagrams held, 380 released, 0 held-but-not-released; SHA-256 identical at
arrival and release 380/380; every released datagram is byte-identical to a datagram the device's own send hook logged
380/380; 0 order violations; longest single hold 105.4 s (Q2). Example (Q4 select, trial T033): the device sent the same
129-byte message (session 18793, counter 99139567, SHA-256 `ce220764beaa017c…`) at +62, +720, +1348, +2292 and +3869 ms
after the toggle; the controller received all five copies with that hash, held them, and released all five with that hash
at +20.0 s.

### Adversary integrity (all trials)

| trials | datagrams held | released with identical SHA-256 | releases in arrival order | trials with a missing release |
|---|---|---|---|---|
| 60 | 380 | 60/60 | 60/60 | 0 |

| held datagrams (rx) | released | held but never released | SHA-256 unchanged arrival->release | released bytes identical to a datagram the device sent | order violations | longest single hold (ms) |
|---|---|---|---|---|---|---|
| 380 | 380 | 0 | 380/380 | 380/380 | 0 | 105422 |

## Results

Timings in ms, shown as median [min, max]. "Update" = the controller application's `attributeChanged` callback for
`BooleanState.stateValue` (wall clock in the controller process).

### Q1 acceptance (hold all device datagrams for d, then release)

| d (s) | n | applied | trials with controller WARN/ERROR | update after toggle | update after release | held datagrams | distinct msgs held | bytes unchanged | in order | device gave up report before release | device give-up after toggle | dup event callbacks |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 5 | 5/5 | 0 | 1005 [1000, 1012] | 7 [3, 13] | 3 [2, 3] | 1 [1, 1] | 5/5 | 5/5 | 0/5 | n/a | 0 |
| 5 | 5 | 5/5 | 0 | 5025 [5013, 5028] | 22 [11, 26] | 5 [5, 5] | 1 [1, 1] | 5/5 | 5/5 | 0/5 | n/a | 0 |
| 10 | 5 | 5/5 | 0 | 10018 [10012, 10039] | 16 [12, 36] | 5 [5, 5] | 1 [1, 1] | 5/5 | 5/5 | 0/5 | n/a | 0 |
| 20 | 5 | 5/5 | 0 | 20016 [20014, 20026] | 13 [11, 24] | 5 [5, 5] | 1 [1, 1] | 5/5 | 5/5 | 5/5 | 14245 [14032, 14331] | 0 |
| 30 | 5 | 5/5 | 0 | 30014 [29987, 30028] | 13 [12, 26] | 5 [5, 5] | 1 [1, 1] | 5/5 | 5/5 | 5/5 | 14328 [14167, 14346] | 0 |

- The controller applied the held value in 25/25 trials, 3–36 ms after release. It raised no WARN or ERROR in any Q1
  trial, and its node state stayed `Connected` throughout (the only `node_state` changes in the whole run are the initial
  connect, the Q2 trials, the deliberate re-subscription before Q2, and shutdown).
- For d ≥ 20 s the device had already declared the report failed (10/10) before release; the value was still applied
  (see Q5). In those trials the controller's StatusResponse to the late report is never acknowledged by the device, and the
  controller logs an INFO line `Error sending success after final data report chunk [peer-unresponsive]` 13.5–13.7 s
  **after** the release (15/15 in Q1 d ≥ 20 + Q5). It is not surfaced as an API event or state change, and it comes after the
  stale value has already been applied.
- Side effect, measured: after a report the device had abandoned, the device re-sent the same `StateChange` event in its
  next report, so the controller application received the same event number twice (10/10 Q1 d ≥ 20 trials; second copy
  ~4.1 s later, which is when the runner's baseline reset caused the next report). The controller does not deduplicate by
  event number.

**Prediction ("accepted, no error, while d stays inside the liveness window"): held.** All d were inside the liveness
window (104 s). Acceptance also held past the device's own give-up.

### Q2 liveness bound (hold all device datagrams until the controller declares the subscription lost)

Procedure per trial: a report (open) is delivered, 1 s later (so no reliable exchange is outstanding) the hold starts,
1 s after that the contact is set to closed (the "fresh value"), and the hold is released at the instant the controller
logs `Subscription … to peer … timed out after …`.

| requested MaxInterval (s) | n | ceiling on wire (s) | negotiated MaxInterval (s) | controller timeout (s) | loss declared | loss after last delivered datagram | loss - negotiated MaxInterval | declared before MaxInterval | fresh value after release | fresh value via | device dropped its subscription first |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 10 | 5 | 18 | 21, 21, 25, 24, 25 | 59.5, 59.5, 63, 62, 63 | 5/5 | 62481 [59472, 63480] | 38478 [38472, 38481] | 0 | 52 [31, 82] | re-subscribe priming report: 5 | 5/5 |
| 60 | 5 | 60 | 69, 61, 64, 64, 62 | 107, 99, 102, 102, 100 | 5/5 | 102475 [99474, 107453] | 38474 [38453, 38478] | 0 | 41 [29, 84] | re-subscribe priming report: 5 | 0/5 |

- Detection came at negotiated MaxInterval + 38.47 s in 10/10 trials (spread 25 ms), never before MaxInterval. The
  constant is matter.js's 2 × maxPeerResponseTime. Measured undetected-hold bound: 59.5–63.5 s for requested 10 s
  (negotiated 21–25 s) and 99.5–107.5 s for requested 60 s (negotiated 61–69 s), counted from the last delivered datagram.
- Node state went `Reconnecting` 11–30 ms after the timeout line and back to `Connected` 46–96 ms after it (10/10).
- The fresh value reached the controller 29–84 ms after release, every time through the priming report of the controller's
  re-subscription. The released held reports carried the same value but belonged to the closed subscription, so the
  controller did not apply them; its responses to them were never acknowledged and it logged
  `WARN … Unhandled error handling incoming message: [peer-unresponsive]` about 13.6 s later (25 lines in total, all after
  detection).
- With requested 10 s the device itself gave up the subscription first ("Giving up on subscription … after 3 failed
  updates") in 5/5 trials. The controller did not learn this and still declared loss only on its own timer.

**Prediction ("detection near the negotiated MaxInterval plus a margin, never before it"): held.** Margin = 38.47 s.

### Q3 event time (StateChange event carried in the same held report)

Measured on the Q1 and Q5 trials (the device sends the urgent event and the attribute in one ReportData, so the same hold
covers both; the d = 25 row is Q5).

| d (s) | n | epochTimestamp present | receipt - event time | (receipt - event time) - d | event time - toggle | receipt - release |
|---|---|---|---|---|---|---|
| 1 | 5 | 5/5 | 1015 [998, 1021] | 15 [-2, 21] | 5 [1, 11] | 17 [16, 27] |
| 5 | 5 | 5/5 | 5034 [5018, 5035] | 34 [18, 35] | 5 [4, 9] | 35 [25, 39] |
| 10 | 5 | 5/5 | 10024 [10018, 10036] | 24 [18, 36] | 11 [5, 12] | 30 [27, 45] |
| 20 | 5 | 5/5 | 20023 [20016, 20039] | 23 [16, 39] | 10 [2, 18] | 34 [22, 40] |
| 30 | 5 | 5/5 | 30018 [29992, 30038] | 18 [-8, 38] | 5 [3, 15] | 23 [20, 42] |
| 25 | 5 | 5/5 | 25023 [25014, 25034] | 23 [14, 34] | 8 [3, 12] | 28 [24, 41] |

- Every delivered `StateChange` event carried a device-minted `epochTimestamp` (ms since the Unix epoch; the matter.js
  device stamps `Time.nowMs` when the event is recorded). It is exposed to the controller application in
  `eventTriggered` (`DecodedEventData.epochTimestamp`). All 163 event deliveries in the run carried `epochTimestamp`;
  none carried `systemTimestamp`.
- Receipt minus event time = d + 15–34 ms (medians; range −8 to +39 ms over 30 trials). The small negative values happen
  because the hold starts a few ms before the event is minted; receipt − release (controller processing) is 16–45 ms.
- The matter.js controller logs the event (`ClientEventEmitter Received event …`) but does not compare the timestamp with
  its clock; nothing flagged a 30 s old event.

**Prediction ("receipt minus event time ≈ d; the age witness exists at the controller API"): held.** Shared clock:
both processes read the same host clock.

### Q4 order (hold one value-bearing report, toggle again during the hold)

Cells (not fixed by the plan, chosen before the main run): `select` d = 2 s (second toggle at +1 s) and d = 10 s (+3 s),
both inside the device's report give-up time; `select` d = 20 s (+3 s), past it; `all` d = 20 s (+3 s) as the
hold-everything control. For `select` d = 20 the runner then watched the controller for up to 90 s after release with no
further changes.

| cell | n | later report reached controller before release | value datagrams passed during hold | controller callbacks during hold | released older value overwrote newer (inversion) | stale window after release (ms) | stale at end of trial | mismatch self-corrected in window | keepalives during mismatch | device gave up held report before release | device give-up after toggle | dup event callbacks |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| select, d=2s | 5 | 0/5 | 0 | 0 | 0/5 | n/a | 0/5 | n/a | n/a | 0/5 | n/a | 0 |
| select, d=10s | 5 | 0/5 | 0 | 0 | 0/5 | n/a | 0/5 | n/a | n/a | 0/5 | n/a | 0 |
| select, d=20s | 5 | 5/5 | 1 [1, 1] | 2 [2, 2] | 5/5 | 36193 [36175, 36202] | 0/5 | 5/5 | 1 [1, 1] | 5/5 | 15121 [14926, 15343] | 5 |
| all, d=20s | 5 | 0/5 | 0 | 0 | 0/5 | n/a | 0/5 | n/a | n/a | 5/5 | 15085 [14944, 15295] | 5 |

- While the device's report exchange is outstanding (d = 2 and 10 s, 10/10) nothing later is sent: the second change waits
  behind the held report, and after release the controller sees open then closed within ~15 ms. Stall, no inversion.
- Past the device's give-up (select, d = 20 s, 5/5): at 14.9–15.3 s the device abandons report R1 (open) and immediately
  sends a new report R2 (new counter) carrying the current value closed and both `StateChange` events. R2 passes the
  selective hold and reaches the controller (events delivered; the attribute callback does not fire because the controller
  already showed closed). At release, the held R1 is applied: the controller's `stateValue` goes back to **open while the
  device is closed**, in 5/5 trials. The matter.js controller applied the older report after the newer one. R1 was built
  before R2, so it carries the older cluster DataVersion and the lower event number; the controller used neither to reject
  it. DataVersion values themselves were not logged. The wrong value persisted for 36.2 s [36.18, 36.20]. It was
  corrected only when the device's next scheduled report (keepalive tick, ~56 s after the first toggle) carried
  `stateValue` and both events again. Why the device re-sent that data is inferred from the matter.js source, not
  measured: it re-queues a failed report's data, and it logged the R1 failure twice. So the correction depends on the
  device's keepalive period (here negotiated MaxInterval 66 s, send interval ~53 s), not on anything the controller did.
- `all` d = 20 s (5/5): R2 is also held and both are released in order, so the controller ends correct (stall, no
  inversion), with duplicate event deliveries.

Sequence recorded in T033 (ms after the first toggle; A = attribute callback, E = event callback with event number):
`E:4067=false@15158 E:4068=true@15164 | release | A:false@20018 E:4067=false@20020 … A:true@56219 E:4067=false@56230 E:4068=true@56230`.

**Prediction ("no later report reaches the controller before the held one is released; the hold stalls the stream"):
held for holds shorter than the device's report give-up (~15 s) and for the hold-everything adversary; FAILED for a
selective hold past the give-up (5/5 later report delivered first, 5/5 inversion).**

### Q5 late release after the device gave up

| set | n | report transmissions (MRP) | last retransmission after toggle | device give-up after toggle | device logged give-up before release | controller applied late value | update after release | controller WARN/ERROR trials |
|---|---|---|---|---|---|---|---|---|
| Q5 (d=25 s) | 5 | 5 [5, 5] | 3082 [2990, 3163] | 14325 [14250, 14412] | 5/5 | 5/5 | 14 [12, 19] | 0 |
| all rows with give-up before release (Q1 d>=20 + Q5) | 15 | 5 [5, 5] | 3065 [2781, 3163] | 14309 [14032, 14412] | 15/15 | 15/15 | 14 [11, 26] | 0 |

- The device transmitted the report 5 times (1 + 4 MRP retransmissions) within ~3.1 s, then logged at 14.0–14.4 s
  `Error sending subscription update message (error count=1): Peer is no longer responding to active session (timed out
  after ~14 s)`. It keeps the subscription (it terminates only after 3 consecutive failures, which happened only in Q2).
- The controller applied the late-released value in 15/15 trials, 11–26 ms after release, with no WARN/ERROR and no state
  change. The only trace is the INFO `peer-unresponsive` line 13.5–13.7 s after release described under Q1, plus a
  duplicate event delivery at the device's next report.

No prediction was fixed for Q5 in the plan; recorded outcome: **a value the sender had given up on is still accepted when
released late.**

### Controller-side traces of the hold (attributed to the trial whose traffic started the unacknowledged exchange)

| cell | occurrences | trials in cell | exchange start - release (ms) | waited before giving up (ms) | kind |
|---|---|---|---|---|---|
| Q1 d=20s | 5 | 5 | 19 [-1, 49] | 13500 [13500, 13600] | StatusResponse to a report (INFO) |
| Q1 d=30s | 5 | 5 | 18 [-24, 51] | 13600 [13500, 13700] | StatusResponse to a report (INFO) |
| Q5 d=25s | 5 | 5 | 32 [-7, 64] | 13500 [13500, 13600] | StatusResponse to a report (INFO) |
| Q4 select, d=20s | 5 | 5 | 8 [-14, 65] | 13600 [13500, 13700] | StatusResponse to a report (INFO) |
| Q4 all, d=20s | 5 | 5 | 28 [-20, 50] | 13500 [13500, 13500] | StatusResponse to a report (INFO) |
| Q2 maxCeiling=10s | 15 | 5 | 3 [-27, 55] | 13600 [13400, 13700] | response to a released report on the closed subscription (WARN) |
| Q2 maxCeiling=60s | 10 | 5 | 26 [-22, 61] | 13600 [13500, 13600] | response to a released report on the closed subscription (WARN) |

All of these start at the release (exchange start ≈ release, ±65 ms, from rounding of the logged duration) and end
~13.5 s later. None occurs during a hold, so none is a detection of the hold. No hold in Q1, Q3, Q4 or Q5 was detected.

## Decision rule outcomes (plan §"Decision rule for the paper")

1. **Rule 1 applies.** Q1: 25/25 accepted with no error (and 15/15 accepted even after the sender gave up). Q2: detection
   at negotiated MaxInterval + 38.47 s in 10/10 trials, never before MaxInterval. Stated as measured on matter.js 0.17.9:
   Matter bounds an undetected hold by subscription liveness, not by message time. Measured bound, from the last delivered
   datagram: 59.5–63.5 s at requested MaxInterval 10 s (negotiated 21–25 s), 99.5–107.5 s at requested 60 s (negotiated
   61–69 s). This supports δ_max as instantiated after Thm. blindness, with the stack-specific constant
   δ_max = MaxInterval_negotiated + 38.46 s for this controller.
2. **Rule 2 applies.** Q3: receipt − event time = d + 15–34 ms (30/30 events carried `epochTimestamp`). Stated as
   measured: the Attested witness (a device-minted event time) is present at the Matter controller API. The loss is in the
   hub. That HA's code discards it is the paper's source-code claim and was not re-measured here (HA was not involved).
3. **Rule 3 applies to Q4.** The prediction failed in the `select`, d = 20 s cell (5/5). As measured: per-subscription
   serialization holds only while the device's report exchange is outstanding (≈15 s in matter.js). A delay-only adversary
   that holds a single value-bearing report past that point gets the device to send a newer report. When the old report
   is released afterwards, the controller applies the older value over the newer one (5/5), and the controller shows the
   wrong state until the device's next data-bearing report (36.2 s here). The paper's claim 4 ("a subscription sends one
   report at a time", so a hold stalls the stream and cannot produce an inversion) must be corrected accordingly. Per the
   rule, this cell was not re-run. The paper text was not edited here.

## Deviations from the plan (all decided before the main run unless stated)

- **Q3 did not have separate trials.** It was measured on the Q1 and Q5 trials, because the device carries the `StateChange`
  event (subscribed as urgent) and the attribute in the same ReportData, so one hold covers both.
- **Q4 cells and a `select` mode were added.** The plan did not fix d for Q4. Holding everything (the Q1 adversary) makes
  "no later report arrives" trivially true, so a selective adversary that holds one message by its cleartext
  (session, counter) was added; `all` d = 20 s was kept as the control.
- **Q5 used d = 25 s.** The smoke test showed the matter.js device gives up at ~14–15 s, not at the ~4–7 s the MRP
  retransmission schedule alone implies (matter.js adds a final wait for processing time). d = 25 s is clearly past
  that and inside the controller's liveness window. Q1 d = 20/30 are also past it and are reported with Q5.
- **Q2 used a specific procedure.** The hold starts 1 s after a delivered report, so no reliable exchange is outstanding
  and only the subscription timer can detect it. A fresh value is set 1 s into the hold. Release happens at the moment of
  detection. "Requested MaxInterval" is the application request; the ceiling on the wire and the negotiated value differ
  because both matter.js sides add jitter. Both are recorded.
- **Pre-run fix.** In a smoke run (not part of the data, written outside `results/`), Q2 released on the wrong log line
  (the controller's `peer-unresponsive` for an unacknowledged StatusResponse also contains "timed out after"). The match
  was narrowed to `Subscription … to peer … timed out after` before the main run.
- **Where the adversary sits.** It is in the controller's network layer, in-process, not a separate on-path host. The
  datagrams never leave loopback.

## Limitations

- **One stack.** The device and controller are both matter.js 0.17.9. HA uses python-matter-server on the CHIP SDK, and its
  constants may differ: the 38.46 s liveness margin, the ~15 s report give-up, the re-queue-and-resend after a failed report
  (which is what ended the Q4 stale window), and the lack of a DataVersion/event-number check. None of this was measured on
  the CHIP SDK.
- **Localhost.** Loopback only: no real network delay, loss or reordering, and one host clock shared by device and
  controller. That clock is what makes Q3's age exact; a real device's `epochTimestamp` is only as good as its time sync,
  and devices without time use `systemTimestamp`.
- **Virtual device.** One virtual contact sensor, one fabric, one subscription, and a mains-powered, non-ICD profile.
  Sleepy/ICD devices negotiate much longer MaxIntervals, which would widen both the Q2 bound and the Q4 stale window.
- **Q4 is narrow.** Measured at one second-toggle offset (3 s) and one MaxInterval (66 s negotiated). The stale-window
  length (36.2 s) is a consequence of that keepalive period and is not general.
- **n = 5 per cell.** No hold was ever detected in Q1/Q3/Q4/Q5, but 5 repetitions cannot exclude rare timing races.
