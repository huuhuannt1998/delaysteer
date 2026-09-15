# E5 (partial) — measured path timing, and what it does to the guard's constants

`scripts/run_e5_timing_traces.py` · `scripts/report_e5_timing.py` · 2026-09-10

## What this can and cannot replace

The plan asks for benign device timing traces so the detector's ~27 s ceiling stops resting on a modelled inter-arrival distribution. **It still does.** This machine has no Zigbee, Z-Wave or Matter radio, so a benign *sensor report* distribution cannot be measured here, and §8.7 now labels that figure as a property of the model. What is measured below is the other timing quantity the defence depends on and currently takes from a spec: the **read round trip** on a local hub path and on a real cloud path.

Collection: 6318 reads over 6.0 h.

## Read round trip

| path | n | median | P95 | P99 | max | failed reads |
|---|---|---|---|---|---|---|
| home_assistant | 3510 | 3.3 ms | 16.0 ms | 24.6 ms | 91.3 ms | 0 |
| smartthings_cloud | 2808 | 184.6 ms | 259.1 ms | 326.6 ms | 686.4 ms | 0 |

## The finding: a configured constant that a real cloud path violates

The active-poll challenge admits a re-read only if its value-age is within `poll_rtt_s` = **50 ms** (`delaysteer/config.py`); the passive variant uses `heartbeat_s` = 250 ms.

- **Cloud path**: median 185 ms, which is 3.7x the configured tolerance; **100.0%** of reads exceed it. On that path an active poll that succeeds is judged *replayed*, so the guard false-blocks a genuinely fresh re-read. The tolerance is a per-path quantity and cannot be one constant.
- **Local hub path**: median 3.3 ms, 0.07x the tolerance; 0.1% of reads exceed it. The constant is defensible here, which is why the defect did not surface in the local deployment.
- The two paths differ by **56x** in the median, on the same machine at the same time.

## Event cadence

State changes observed: **104**. The live deployment's entities are template- and helper-backed, so they do not report spontaneously; this collection therefore says nothing about benign inter-arrival, and no claim is made from it. That measurement needs hardware.

## Caveats

- One host's clock throughout; the local figure includes Docker's port forward and no network beyond loopback.
- The cloud figure is one account, one region, one device class, over the collection window; it is a real path, not a representative survey of cloud platforms.
- Read RTT is not the same quantity as a sensor's benign inter-arrival time. The paper's detector argument depends on the latter and remains modelled.
