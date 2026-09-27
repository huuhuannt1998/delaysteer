# Matter long selective hold (E-D, "Q7"): analysis plan (fixed before any run)

Written 2026-09-26, before any Q7 code ran. Extends `results/matter_hold_plan.md`. Same stack, device, controller and adversary.

## Why
The advisor asked what happens if a delay lasts two hours. The existing probe measured:
- holding **every** device datagram: the controller declares the device lost at the negotiated MaxInterval + 38.5 s (Q2);
- holding **one** value-carrying report for up to 20 s (Q4).

It did not measure a long hold of one report while everything else passes. That is the case where the hub might show a stale value for hours with no alarm.

## Pre-run observation: an attacker without keys selects by timing, not by size
In the recorded Q1–Q5 log (`results/matter_hold_logs/main/events.jsonl`), the datagrams that carried keep-alives and those that carried value reports share sizes. Both 129-byte and 168-byte device datagrams carried each kind.

So an on-path attacker who cannot decrypt cannot "hold every value report and pass the keep-alives" by size. The realistic selective attacker holds the report that follows a physical change, chosen by timing. That is the existing `select` mode: the first device datagram of at least 60 bytes after the hold is armed, plus its byte-identical retransmissions. Everything else passes, including later reports and keep-alives.

The stronger option, holding everything, is Q2, which is already measured.

## Design
- **Trial.** Baseline: the door is closed and the controller shows closed. Arm a `select` hold of duration d. Toggle the device closed → open (the report carrying this change is held). Make **no further change**: the door stays open.
- **Polling.** Poll the controller's cached value every 2 s from the toggle until 30 s after release. This is a local read and never touches the network.
- **Cells.** d ∈ {60, 300, 1800, 7200} s, n = 3 each (12 trials, ≈ 8.5 h). Same subscription parameters as Q1–Q5: requested 1 s / 60 s.
- **Recorded per trial:**
  - `stale_ms`: from the toggle until the controller first shows "open";
  - whether that correction came **before** the held report's release;
  - the path of the correction: a later device report, a resubscription, or the release itself;
  - whether liveness was declared lost;
  - controller warnings or errors;
  - the device's give-up time;
  - the final values on both ends.

## Outcomes and decision rule (fixed now)
1. **The controller corrects well before release in every trial, at a bounded time independent of d** (for example, the device's next scheduled report). Then a single held report keeps the hub stale for that bound, not for d. A two-hour stale state on this stack needs holding every report, which is detected at about 100 s (Q2). Report the measured bound.
2. **The controller shows "closed" for the whole hold with no alarm, in some trials.** Then the two-hour case is real on this stack. Report the rate and the longest silent stale period measured.
3. **Anything else** (for example, a correction only via liveness loss and resubscription): report the path and its timing as measured.

In every case the paper states the result as measured on matter.js with one virtual device on one host.

## Result (written after the run; data: `results/matter_longhold.csv`, logs `results/matter_longhold_logs/q7/`)
12 trials, 3 per hold of 60, 300, 1800 and 7200 s. One subscription throughout: negotiated MaxInterval 65 s.

- **Adversary integrity.** In every trial the held report (5 datagrams: the value report and its retransmissions) was released byte-identical and in order.
- **Every trial followed outcome 1.** The controller showed the stale "closed" for 52.49-52.53 s (median 52.51 s) after the door opened, whatever the hold. The device's next scheduled report corrected it, carrying the door's current state (`later_device_report`), in 12/12 trials, always before the held report was released.
- **No detection signal of any kind.** No subscription timeout, no node-state change, no resubscription, and no controller warning or error (0 in 12).
- **Device give-up.** The device gave up on the held report 14.1-15.1 s after the change.
- **Final state.** At the end the controller and device agreed ("open") in 12/12.

**Decision (rule 1).** On this stack, holding the one report that carries a change keeps the hub wrong for about one reporting interval (here 52.5 s, under the 65 s MaxInterval), not for the length of the hold. A two-hour stale state would require holding every report, and the controller declares that device lost at MaxInterval + 38.5 s (Q2). The stale window is also silent: nothing in it signals that anything was held.
