# Matter hold probe, Q6: a controller-side order witness

Plan: the Q6 addendum at the end of `results/matter_hold_plan.md` (fixed 2026-09-25 03:50 EDT, before any Q6 run; not
modified). Data: `results/matter_hold_q6.csv` (35 rows, one per trial, run id `q6`). Raw logs:
`results/matter_hold_q6_logs/q6/` (`controller.log`, `device.log`, `events.jsonl` with every datagram hash,
hold/release, witness decision and controller callback, `run_header.json`). Code: `scripts/matter_hold/witness.mjs`,
switched on by `runner.mjs --witness`. Tables: `node scripts/matter_hold/analyze_q6.mjs results/matter_hold_q6.csv
results/matter_hold_q6_logs/q6/events.jsonl results/matter_hold.csv`. The Q1-Q5 files were not touched.

Run window: 2026-09-25 07:52-08:09 UTC. The stack, host, adversary, device and MRP parameters are the same as Q1-Q5
(matter.js 0.17.9, Node v26.3.0, macOS arm64, loopback). The whole run used one subscription: requested 1 s / 60 s, 68 s on
the wire, negotiated MaxInterval 68 s, controller liveness timeout 106 s. Cells ran sequentially, one repetition of each
cell per round, 5 rounds, with the runner at `nice 10`.

## Where the witness hooks, and evidence that it only reads

**Where.** The witness wraps `ClientStructure.prototype.mutate` in `@matter/node` 0.17.9
(`node_modules/@matter/node/dist/esm/node/client/ClientStructure.js`). This is where the matter.js controller applies a
decoded ReportData to its node cache. The report arrives there as a stream of `attr-value` and `event-value` changes, and
each `attr-value` carries its cluster DataVersion (`version`, taken from `AttributeReportIB.DataVersion`). The
application-level `PairedNode.events.attributeChanged` also exposes `version`, but only after the value is already in the
cache, so a check there could not keep the previous value. `mutate` is therefore the lowest point where DataVersion is
visible before the application accepts the value. No event-number-only fallback was needed.

**What it does.** It keeps, in the controller process:
- the highest DataVersion applied per (endpoint, cluster), compared with 32-bit serial-number arithmetic
  (`isOlder32(a, b) = a ≠ b and ((b − a) mod 2^32) < 2^31`);
- the highest event number seen per node, and the set of event numbers already seen.

An attribute value whose DataVersion is older than the highest applied for its cluster is withheld from `mutate`, so the
cache keeps the previously applied value, and a `witness_reject` record is logged with both versions. Events are never
withheld. An event whose number is not above the highest seen is logged as `witness_event_flag`, marked `duplicate` if
that number was delivered before and `older` if it was never seen but is below the highest. Everything else is forwarded
by reference. The witness never modifies a change object, a value, a datagram, or the adversary. It is loaded only when
`HOLD_WITNESS=1`, so the Q1-Q5 code path is unchanged when the flag is off.

**Evidence it only reads (whole run, including the connect-time priming read).**

| hook | reports seen | attribute values in | forwarded unchanged | withheld (rejected) | reports with in = forwarded + withheld | event values in (all forwarded) | flags duplicate | flags older |
|---|---|---|---|---|---|---|---|---|
| ClientStructure.prototype.mutate | 76 | 187 | 182 | 5 | 76/76 | 105 | 34 | 0 |

- The application saw 59 `stateValue` callbacks. For all 59, the callback's (DataVersion, value) pair was one the
  witness had forwarded; none matched a withheld pair.
- The adversary was unaffected: 175 datagrams were held and 175 released, SHA-256 unchanged 175/175, bytes identical to
  what the device sent 175/175, 0 order violations.
- No cost on the accepting path. Update after release, witness on vs off (Q1-Q5 run) in the same cells, as median
  [min, max] ms: 3 [2, 7] vs 7 [3, 13] (Q1 d=1), 3 [3, 6] vs 16 [12, 36] (Q1 d=10), and 7 [3, 13] vs 13 [12, 26]
  (Q1 d=30).
- Wrap-around: the comparison passes 9/9 unit cases, including 0xFFFFFFFF → 0 and 0xFFFFFFF0 → 5 (run by hand, recorded
  here). No wrap occurred on the wire; measured versions were around 2.214 × 10^9.

## Results

Counts are n/5. Timings are ms, median [min, max].

| cell | n | trials with an attribute rejection | rejections | later report reached controller before release | older value applied after newer (inversion) | controller final value = device value | late value applied (residual) | event flags: duplicate | event flags: older | update after release |
|---|---|---|---|---|---|---|---|---|---|---|
| Q4 select d=20s | 5 | 5/5 | 5 | 5/5 | 0/5 | 5/5 | 0/5 | 15 | 0 | n/a (nothing applied) |
| Q4 select d=2s | 5 | 0/5 | 0 | 0/5 | 0/5 | 5/5 | 5/5 | 0 | 0 | 3 [2, 6] |
| Q4 select d=10s | 5 | 0/5 | 0 | 0/5 | 0/5 | 5/5 | 5/5 | 0 | 0 | 4 [4, 9] |
| Q4 all d=20s | 5 | 0/5 | 0 | 0/5 | 0/5 | 5/5 | 5/5 | 5 | 0 | 6 [6, 11] |
| Q1 d=1s | 5 | 0/5 | 0 | n/a | n/a | 5/5 | 5/5 | 10 (from the preceding Q4 all trial, see below) | 0 | 3 [2, 7] |
| Q1 d=10s | 5 | 0/5 | 0 | n/a | n/a | 5/5 | 5/5 | 0 | 0 | 3 [3, 6] |
| Q1 d=30s | 5 | 0/5 | 0 | n/a | n/a | 5/5 | 5/5 | 4 | 0 | 7 [3, 13] |

Same cells with the witness off (Q1-Q5 run) and on (Q6):

| cell | off: older value applied after newer | on: older value applied after newer | off: update after release | on: update after release |
|---|---|---|---|---|
| Q4 select d=20s | 5/5 (wrong state for 36.2 s) | 0/5 | 17 [13, 21] | n/a |
| Q4 select d=2s | 0/5 | 0/5 | 12 [9, 20] | 3 [2, 6] |
| Q4 select d=10s | 0/5 | 0/5 | 18 [6, 25] | 4 [4, 9] |
| Q4 all d=20s | 0/5 | 0/5 | 14 [10, 21] | 6 [6, 11] |
| Q1 d=1s / 10s / 30s | n/a | n/a | 7 / 16 / 13 | 3 / 3 / 7 |

### Q4 select d=20 s: the inversion, with the data versions measured

In every trial the sequence was the same. v0 is the BooleanState DataVersion applied at baseline (closed); times are
measured from the first toggle:

| trial | v0 (closed, before hold) | newer report R2, delivered during the hold | held report R1, released at +20 s | witness decision on R1 | device's next report |
|---|---|---|---|---|---|
| T001 | 2213995259 | v0+2 = 2213995261, closed, at +15088 ms | v0+1 = 2213995260, open | rejected (v0+1 < v0+2) at +20005 ms | v0+2, closed, +57793 ms, applied (equal version, no change) |
| T008 | 2213995273 | v0+2 = 2213995275, closed, at +14287 ms | v0+1 = 2213995274, open | rejected at +20005 ms | v0+2, +57792 ms, applied |
| T015 | 2213995287 | v0+2 = 2213995289, closed, at +14271 ms | v0+1 = 2213995288, open | rejected at +20006 ms | v0+2, +57792 ms, applied |
| T022 | 2213995301 | v0+2 = 2213995303, closed, at +14284 ms | v0+1 = 2213995302, open | rejected at +20006 ms | v0+2, +57797 ms, applied |
| T029 | 2213995315 | v0+2 = 2213995317, closed, at +14261 ms | v0+1 = 2213995316, open | rejected at +20004 ms | v0+2, +57801 ms, applied |

- **As measured, not by the spec:** the held report carries the older DataVersion (v0+1), and the newer report that
  overtook it carries v0+2.
- The device gave up on R1 at 14.3-15.1 s. It then sent R2 at once, and R2 passed the selective hold.
- With the witness on, the controller never showed "open": no `stateValue` callback fired in these trials, and the final
  value matched the device (closed) in 5/5. With the witness off, the same cell showed "open" for 36.2 s in 5/5 (Q1-Q5
  report).
- In the other 30 trials each new report carried v0+1 and then v0+2, in order, and all were applied.

### Event-number flags

All 34 flags were `duplicate`; there were 0 `older`. Each is an event the device re-sent after it had abandoned a report.
In the table they are attributed to the trial in which that event number was first delivered:

| event first delivered in cell | flag | flagged in | count |
|---|---|---|---|
| Q4 select d=20s | duplicate | same trial | 15 (3 per trial: E1 in the released R1, then E1 and E2 in the device's next report) |
| Q4 all d=20s | duplicate | same trial | 5 (E1 released twice, once in R1 and once in R2) |
| Q4 all d=20s | duplicate | next trial (Q1 d=1s) | 10 (E1 and E2 re-sent in the next report) |
| Q1 d=30s | duplicate | same trial | 4 (the 5th trial ended the run before the re-send) |

No flag was an older event arriving after a newer one. So in these cells the event-number check separates "device
re-send" from "reordering" cleanly, and on its own it would not have caught the Q4 inversion: R1's event was a duplicate,
not an older unseen one. The DataVersion check is what blocked it.

## Predictions (addendum Q6)

| cell | prediction | measured | held? |
|---|---|---|---|
| Q4 select d=20s | stale overwrite rejected 5/5, controller keeps closed | rejected 5/5; controller closed = device closed 5/5 | yes |
| Q4 select d=2s | 0 rejections | 0 | yes |
| Q4 select d=10s | 0 rejections | 0 | yes |
| Q4 all d=20s | 0 rejections | 0 | yes |
| Q1 d=1s | 0 rejections, late value still applied | 0; applied 5/5 | yes |
| Q1 d=10s | 0 rejections, late value still applied | 0; applied 5/5 | yes |
| Q1 d=30s | 0 rejections, late value still applied | 0; applied 5/5 (30 s old, event age 30.0 s) | yes |

## Decision rule outcome

**Inversion blocked 5/5, with 0 false rejections across the 30 in-order trials.** All 5 rejections in the run were the
5 inversions, and no other attribute value (182 forwarded) was withheld. So the rule's first branch applies. The paper
may state:
- Counter is implementable on Matter's application-layer sequence numbers (cluster DataVersion, 32-bit serial-number
  comparison).
- It was measured end to end on matter.js 0.17.9, where it turns the Q4 stale overwrite into a rejection that keeps the
  newer value.
- By design it admits order-preserving late delivery: the Q1 residual. 15/15 late values were still applied, including
  30 s old ones. Counter bounds order, not age.

## Deviations and notes

- **Where the witness lives.** It sits inside the matter.js controller stack (the node-cache apply step), not in user
  code on top of `PairedNode`. Data versions are visible to the application only after the cache update, so this was the
  lowest pre-commit point. Neither bytes nor the adversary were altered. This is where the addendum's "before a reported
  value is accepted" had to be implemented; the event-number-only fallback was not needed.
- **Attribution window.** Witness counts in the CSV are attributed over [this trial's hold start, next trial's hold
  start). This catches reports the device sends between trials, such as re-sent events. As a result, the Q1 d=1s cell
  carries 10 duplicate flags whose events come from the preceding Q4 all d=20s trial (table above).
- **Longer observation for Q4 select d=20 s.** The runner waited 45 s after release, instead of 8 s, so that the
  device's next scheduled report (+57.8 s) fell inside the trial. That report was applied without a flag on the
  attribute (equal version).
- **Events are only flagged.** Per the addendum, duplicates still reach the application; the witness logs them and does
  not suppress them.

## Limitations

- **One stack, one cluster.** matter.js on both sides; not measured on the CHIP SDK or on python-matter-server.
- **Witness state lives in memory.** It is lost when the controller restarts. Not tested:
  - a device reboot or factory reset, where the spec lets DataVersion start from a new random value, which this rule
    would read as "older" until a re-read;
  - re-subscription after a loss. The Q6 run had no loss; that is Q2 territory.
- **No recovery action.** A rejection keeps the previous value but does not trigger a read. Here the kept value was
  already the newer one, because a newer version must have been applied for a rejection to occur.
- **The witness bounds order, not age.** A hold-everything adversary (Q1, Q4 all) passes it untouched, by design.
- **n = 5 per cell, loopback, one virtual device.**
