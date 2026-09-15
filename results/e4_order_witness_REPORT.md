# E4 — the source-order witness, running

`scripts/run_e4_order_witness.py` · `delaysteer/defense/order_witness.py` · 2026-09-10

## Question

The paper's third witness decides admission from source *order* rather than from an age, and
until now carried it as a design analysis over modelled positions
(`results/defense_residual_counter.csv`). Reviewer objection: "COUNTER is a modelled observation
about protocol metadata, not a demonstrated defence path." This is the mechanism, running, with
its two residuals measured rather than asserted.

## Commands

```
.venv/bin/python scripts/run_e4_order_witness.py --messages 100 --repeats 20 --out results/e4_order_witness
.venv/bin/python -m pytest tests/test_e4_order_witness.py -q      # 11 passed
```

## What was built

`OrderWitness` is a per-source monotone counter tracker with four observable events and a
commit-time predicate `admit(sources)`. It never reads a clock, which is why its verdict does
not move with the attacker's position or with any freshness budget.

| event | condition | verdict |
|---|---|---|
| `in_order` | seq == high-water + 1 | admit |
| `gap` | seq > high-water + 1 (N, N+2) | admit — frames were **lost**, order intact |
| `inversion` | seq < high-water | **block** — a held frame arrived after a later one |
| `duplicate` | seq == high-water | admit |

It is wired into the real gate as the `counter` ablation
(`GUARD_ABLATIONS["counter"]`, `Config.guard_order_witness`, `TemporalGuard(..., order_witness=w)`).
The hook is asked last and about the same critical facts as the freshness checks; with the flag
off the witness is inert, so every existing call site is unchanged (`test_witness_is_inert_without_the_flag`).

## Results — 8 cells, 20 trials each, 100 frames per trial

| case | reporting style | blocked | inversion observable | µs/frame | verdict |
|---|---|---|---|---|---|
| normal | periodic | 0/20 | 20/20 | 4.43 | admits |
| normal | on-change | 0/20 | 20/20 | 1.26 | admits |
| selective hold | periodic | **20/20** | 20/20 | 0.84 | **detected** |
| selective hold | on-change | 0/20 | **0/20** | 1.24 | residual: nothing later passed |
| loss | periodic | 0/20 | 20/20 | 1.37 | loss is not an inversion |
| loss | on-change | 0/20 | 20/20 | 1.17 | loss is not an inversion |
| blanket/suffix hold | periodic | 0/20 | 20/20 | 1.27 | residual: order preserved |
| blanket/suffix hold | on-change | 0/20 | 0/20 | 1.63 | residual: order preserved |

Detection on a selective hold against a periodic source: **20/20**. False positives under loss:
**0/40** across both styles. Cost is under 5 µs per frame and under 2 µs per commit decision, on
one core, so the witness is not a latency argument either way.

The two zero rows are the residuals the paper already states, now measured. A **blanket or suffix
hold** releases in order, so no counter ever goes backwards. An **on-change** source is silent
while its one in-flight frame is held, so no later frame of that source can pass it; the
`inversion observable` column is the coverage statement — in those 40 trials there was nothing
for an order check to see, and the witness correctly does not invent a detection. **COUNTER
proves ordering, not recency.**

## End-to-end through the gate

`results/e4_order_witness_guard.json`, the discrimination that matters, inside a real
`TemporalGuard`:

```
selective_hold  seqs=[1,2,4,3]  allowed=False  TemporalGuard BLOCKED arm_alarm: ORDER INVERSION on binary_sensor.front_door_contact seq [3] after 4
loss            seqs=[1,2,4,5]  allowed=True   ALLOW (revalidated fresh)
```

## Caveats — read these before citing the numbers

- **No radio counter was read.** This machine has no Zigbee, Z-Wave or Matter coordinator. The
  counters are minted by the publisher in the runner. What is demonstrated is the witness, the
  inversion/loss discrimination, the guard integration and the residual boundary — not that a
  particular hub exposes the field.
- **What a hub would have to surface** to drive this from hardware: the Zigbee **APS counter** or
  **NWK sequence number**, the **Matter message counter** (per session), or Z-Wave **S2** nonce
  sequence state. Each is already on the wire and integrity-bound; none is exposed by the hubs the
  paper measured, which remains the finding: the evidence exists and is being discarded.
- The transport is in-process (a queue plus a relay thread) with real wall-clock holds. E2's MQTT
  path shows the same relay shape crossing a real broker; nothing in the witness depends on which.
- Reporting style is a property of the sensor, not a knob: a periodic source supplies the later
  frame an inversion needs, an on-change source may never.
