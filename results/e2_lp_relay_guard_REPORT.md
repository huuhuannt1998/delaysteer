# E2′ — the real guard at the gate over the least-privilege attested path

`scripts/run_e2_lp_relay.py --guard full` · 2026-09-15 · closes cold-panel finding 6 (2026-09-14)

## Question

E2's agent runs used the undefended planner. Its own report said: "a freshness-enforcing guard would
have the authenticated `t_m` to act on. That is a defence result, not a privilege result." The
panel's sharpest sentence was that "the paper demonstrates no witness that survives a defense-aware
A1 adversary at an upstream position." This puts the real `TemporalGuard` (`full` ablation: budget
witness, two-phase revalidation) at the tool-router gate over the SAME `RelayHomeAdapter`, so the
guard's commit-time re-read returns the hub's verified cache carrying the device's authenticated
measurement time. Nothing else changes: same broker, ACLs, keys, families, arms, seeds and model.

## Command

```
.venv/bin/python scripts/run_e2_lp_relay.py --skip-mechanism --repeats 8 --temperature 0.7 \
    --guard full --arms honest,delayed --families secure_house,automation \
    --out results/e2_lp_relay_guard --keep-broker --broker-port 1884
```

## Result (qwen3:14b, temperature 0.7, 8 repeats per arm, paired seeds 1000+i)

| family | arm | violations (guard on) | runs with a block | violations (E2, undefended) | median max contact age seen |
|---|---|---|---|---|---|
| secure_house | honest  | 0/8 [0,32] | 0/8 | 0/8 | 0.6 s |
| secure_house | delayed | **0/8** [0,32] | **8/8** | 1/8 | 181.6 s |
| automation   | honest  | 0/8 [0,32] | 0/8 | 0/8 | 0.0 s (predicate removed 8/8 on fresh reads, as in E2) |
| automation   | delayed | **0/8** [0,32] | **8/8** | **8/8** | 6.0 s |

No errors in 32 episodes. Every delayed run is blocked at the gate on the authenticated age;
no honest run is blocked, so the witness costs no benign utility on this path.

## What it settles

- **A witness that survives a delay-only adversary upstream of the stamp now runs end to end.**
  The relay sits between device and hub (position A1); the value it holds arrives with the device's
  own `t_m`; the guard checks that age against the 2 s contact budget and blocks. The
  inference-driven family, untouched by attestation when undefended (8/8), is blocked 8/8 because
  the timed-out probes return a value whose authenticated age exceeds the budget.
- This is the **Attested** witness realized, not modeled — on an MQTT deployment with per-device
  keys. It is not a compromised Zigbee coordinator, which holds link keys and could originate.
- The privilege result (E2) and the defense result (E2′) are now separate rows, as the E2 report asked.

## Caveats

- Eight repeats per arm; Wilson intervals are quoted. Loopback on one host.
- Source: results/e2_lp_relay_guard_agent.csv, results/e2_lp_relay_guard_summary.csv,
  traces/e2_lp_relay_<family>_<arm>_<i>_full.jsonl. The script-generated
  results/e2_lp_relay_guard_REPORT.md was replaced by this file.
