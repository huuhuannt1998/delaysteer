# Matter hold probe: analysis plan (fixed before any run)

Written 2026-09-25 02:20 EDT, before the first run.

## Why
The paper argues from specifications and source that Matter does not bound the age of a delivered observation. Four claims:
1. Message counters give replay protection, not age.
2. Subscription liveness bounds silence, not staleness.
3. Events carry a device-minted time that Home Assistant discards.
4. A subscription sends one report at a time.

A reviewer can reasonably say "Matter devices check timestamps". This probe measures the four claims on a real Matter stack, with an on-path adversary that only holds authentic, encrypted datagrams: it never forges, modifies, drops or reorders their content.

## Stack
- matter.js (Node), a virtual contact sensor (BooleanState cluster, StateChange event enabled) and a matter.js controller, in separate processes on one host.
- Commissioned over IP (CASE session, operational credentials). No Home Assistant, no LLM.
- The adversary holds device-to-controller UDP datagrams in the controller's network layer for a set time, then releases them unchanged. Nothing is dropped.

## Questions and outcomes
- **Q1 Acceptance.** The contact changes (closed to open). The report carrying it is held for d ∈ {1, 5, 10, 20, 30} s and released.
  - *Recorded:* whether the controller applies the value, any error or warning it raises, and the controller-visible time of the update.
  - *Prediction:* accepted, no error, while d stays inside the liveness window.
- **Q2 Liveness bound.** All device-to-controller datagrams are held, for requested MaxInterval ∈ {10, 60} s.
  - *Recorded:* the time until the controller declares the subscription lost, and when a fresh value next reaches it.
  - *Prediction:* detection near the negotiated MaxInterval plus a margin, never before it. So an undetected hold is bounded by liveness, not by any per-message time.
- **Q3 Event time.** The StateChange event report is held by d.
  - *Recorded:* the event's device timestamp (epoch or system time) and the controller receipt time.
  - *Prediction:* receipt minus event time ≈ d on the shared clock. The age witness exists at the controller API.
- **Q4 Order.** While one value-bearing report is held, the contact is toggled again.
  - *Recorded:* whether any later report reaches the controller before the held one is released.
  - *Prediction:* no. Reports are serialized per subscription, so the hold stalls the stream instead of producing an inversion.
- **Q5 Late release after device give-up.** The report is held past the device's reliable-messaging retry budget.
  - *Recorded:* when the device abandons the report, and whether the controller still applies the value when it is released.

## Repetitions
At least 5 per cell. Record the matter.js version, the negotiated subscription intervals and the MRP parameters in every row.

## Decision rule for the paper (fixed now)
1. **Q1 accepted and Q2 detection ≥ MaxInterval:** state as measured that Matter bounds an undetected hold by subscription liveness, not by message time. Give the measured bound for each MaxInterval. This supports δ_max as instantiated after Thm. blindness.
2. **Q3 age ≈ d:** state as measured that the Attested witness is present at the Matter controller API. The loss is in the hub, which HA's code shows discards it.
3. **Any prediction fails:** report it as measured and correct the paper's text. Do not re-run until it passes.

## Addendum Q6: a controller-side order witness (fixed 2026-09-25 03:50 EDT, before any Q6 run)

**Why.** Q4 showed that on Matter an inversion reaches the application: a report held past the device's give-up was applied after a newer one. The order evidence arrives with it: event numbers, and cluster data versions per the spec. Q6 asks whether a controller-side check on that evidence (the paper's Counter witness) blocks the inversion without false blocks.

**Witness.** In the controller application, before a reported value is accepted:
- keep the highest data version applied per (endpoint, cluster), compared with 32-bit wrap-around arithmetic, and the highest event number seen per node;
- reject an attribute value whose data version is older than the last one applied for its cluster;
- flag an event whose number is not above the highest seen.

A rejection keeps the previously applied value and is logged. If matter.js does not expose data versions to the application, use event numbers alone and record that deviation.

**Cells.** n=5 each, same stack and adversary as Q1-Q5:
- Q4 select d=20 s, the inversion. *Prediction:* the stale overwrite is rejected in 5/5, and the controller keeps "closed".
- Q4 select d=2 and d=10 s, and Q4 all d=20 s: in-order stalls. *Prediction:* 0 rejections.
- Q1 hold-all at d=1, 10 and 30 s: late but in order. *Prediction:* 0 rejections, and the late value is still applied. This is the witness's residual: it bounds order, not age.

**Decision rule.**
- **Inversion blocked 5/5 with 0 false rejections:** the paper states that Counter is implementable on Matter's application-layer sequence numbers and measured end to end on matter.js, and that it admits order-preserving late delivery by design.
- **Anything else:** report as measured.
