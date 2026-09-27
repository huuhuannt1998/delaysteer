# E-E: flag future-dated timestamps: analysis plan (fixed before any run)

Written 2026-09-26, before the check existed in code. No row of this experiment has been seen.

## Why
The skew sweep (`results/skew_plan.md`, `results/skew_sweep.jsonl`) found that the guard bounds a reading's age only from above. When the device clock runs ahead, honest readings arrive stamped in the future (ages −2.96 to −0.13 s) and are admitted (20/20). Meanwhile the attack window widens one-for-one with the lead.

A reading stamped later than its own receipt proves the device clock leads by at least that much, because delay can only add age. The guard ignores that signal.

## Change (opt-in; default off, so every recorded run reproduces)
Two new config fields:
- `guard_future_stamp` (default `False`);
- `future_stamp_tol_s` (default 0.5 s: well above loopback latency, well below the 2 s budget).

When the flag is on, the revalidation read of a contract fact whose age (arrival − generation) is below −`future_stamp_tol_s` becomes a problem ("FUTURE-STAMPED"), so the commit is blocked. Nothing else in the guard changes.

## Design
- The skew-sweep harness (`scripts/run_skew_sweep.py`), with the check switched on (`--future-stamp`).
- Every cell of the original sweep, n=10 each (350 trials, no model):
  - s ∈ {−3, −1, 0, +1, +3} s;
  - honest cells, and attack cells with holds h ∈ {1…6} s.
- Output: `results/future_stamp_sweep.jsonl` (+ summary). The original sweep's files are not touched.

## Predictions
1. **s ≤ 0: nothing changes.** Every cell's admitted count equals the original sweep's.
2. **s = +1 and +3, honest: the lead is caught.** Every honest read is flagged and blocked (0/10 admitted, against 10/10 without the check). This is the detection: a leading clock is visible at the first honest read.
3. **s = +1 and +3, attack:**
   - Holds shorter than the lead still yield a future stamp, so they are flagged and blocked.
   - Holds longer than the lead yield a positive age and pass the check, so those cells are unchanged. At s = +3, h = 4 s is still admitted.

   The check detects a leading clock; within a trial that sees only the held reading, it does not restore the window.

## Decision rule (fixed now)
- **Predictions 1 and 2 hold.** Report the check as detection of a leading device clock at the first honest read, which a deployment uses to correct or distrust the device before an attack. State prediction 3 as the residual. The stronger fix, subtracting a per-device lead estimated from earlier honest reads, is named as future work.
- **Prediction 1 fails** (any s ≤ 0 cell changes). The check has a bug: fix it and re-run before any claim.
- **Prediction 2 fails** (an honest lead read is admitted). Report the measured rate, and do not claim detection.

## Result (written after the run; data: `results/future_stamp_sweep.jsonl`, `results/future_stamp_sweep_summary.csv`)
350 trials; no admission reached Δ + s (0/350).

1. **Prediction 1 held.** Every s ≤ 0 cell equals the original sweep: −3: all 0/10; −1: attack 0/10, honest 10/10; 0: h = 1 10/10, h ≥ 2 0/10, honest 10/10.
2. **Prediction 2 held at s = +3 and failed at s = +1.**
   - At s = +3 every honest read was flagged (0/10 admitted, against 10/10 without the check).
   - At s = +1, 4/10 were admitted. With a 1 s heartbeat a reading is up to 1 s old, so a 1 s lead drives the age below the −0.5 s tolerance only when the reading is younger than 0.5 s.
   - Per the decision rule: detection is certain for a lead well above the tolerance plus the report interval, and per-read (6/10) near it. The paper does **not** claim "caught at the first honest read" for small leads.
3. **Prediction 3 was wrong, in the protective direction.**
   - At s = +3 every attack cell was blocked (0/10), including holds longer than the lead (h = 3, 4, 5, 6).
   - At s = +1, h = 1 and 2 dropped to 2/10 and 5/10 admitted (from 10/10).
   - Every one of these blocks reads "lock FUTURE-STAMPED". The held door reading had a positive age, but the arming contract also re-reads the **lock**. The lock is not held, and on this relay it is signed by the same device publisher with the same leading clock, so its fresh reading revealed the lead.

**Interpretation (post hoc, labeled as such).** The check blocks the widened-window attack whenever the commitment's contract re-reads some unheld fact stamped by the same leading clock. That depends on the relay's single signer: one clock for every entity. With separate devices, each on its own clock, only the held fact's own clock matters, and prediction 3's residual stands. The paper states the result with this condition.
