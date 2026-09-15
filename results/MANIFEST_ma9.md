# DelaySteer results manifest (MA-9 reviewer-hardening)

Every reported table cell traces to a source CSV under `results/`. md5 as of
integration. **Frozen** files are byte-identical to the pre-MA-9 release and were
never rewritten; all MA-9 work is additive (new files only).

| Table (label) | Content | Source CSV | md5 | frozen |
|---|---|---|---|---|
| main results (Tab. metrics) | deterministic + LLM per-family cells | `metrics.csv` | `e787eb4c9e45e1919a818a6a65868e59` | YES |
| `tab:crossmodel` (orig 3 models, n=3) | virtual / live-HA / SmartThings-cloud | `m2_rates.csv` | `6cd5b9cb555f45c942c8aefe584fde14` | YES |
| `tab:crossmodel` SmartThings/HA rows (n=3, caveated) | cloud + live-HA portability demo | `smartthings_llm_rates.csv` | `6eadb1933dcf1d94766991003c8913ed` | (existing) |
| `tab:crossmodel_n20` (6 models, n=20) | virtual-home resample, Wilson CIs | `m2_rates_n20.csv` + `m2_rates_extra.csv` | `a6d05aac60414a0480b36837f7154de0` + `373efefdf48cf67fe876e57a2d113d77` | no (additive) |
| `tab:family_n20` (n=20) | access / confirmation / automation families | `family_rates_n20.csv` | `a54da39349b6202ff5847028183a3de6` | no (additive) |
| `tab:richhome` attack cells (n=20/10) | richhome attack, Wilson CIs | `richhome_rates_n20.csv` | `621d692c18177d2842945afbf0e2d9c9` | no (additive) |
| `tab:richhome` guard cells (n=3, caveated) | richhome guard | `richhome_rates.csv` | `d23595d89215761cb951ca3d286ee766` | (existing) |
| `tab:hermes` (n=3, caveated) | Hermes production-stack portability demo | `hermes_ha_rates.csv` | `a39590c60218a107fed39f9a0ae6d06c` | (existing) |
| `tab:cadence` + `tab:cadence_family` (Task 1) | challenge-response under realistic cadences | `cadence.csv` | `106fb2ddf04847e24b58829c46682b87` | no (additive) |
| `tab:anchor` (Task 3) | deliberation-window anchoring vs active-poll | `anchor.csv` | `aace0f5de15fd96a005e23a19a86d43a` | no (additive) |
| adaptive-adversary table | delay-inside-budget adaptive attack | `adaptive.csv` | `7997ce45104224956623a49d2ad306aa` | no |

## Caveated cells (portability demos at n=3, PI decision "(b)")

`tab:hermes` (production stack) and the SmartThings-cloud rows of `tab:crossmodel`
are **portability demonstrations at n=3** — they show the delay attack and
TemporalGuard transfer across a real agent framework and a real IoT cloud. The
attack/guard *rates* they instantiate are quantified at n=20 on the virtual home in
`tab:crossmodel_n20` and `tab:family_n20`. Framed as scope, not shortfall: all
caveated cells are clean (real verdicts) and unanimous (guard cells 0/N block).

## Test suite

115 tests (pytest collects 115 under `.venv`, all passing, 0 import errors; the
suite grew past the 74 recorded here as Experiments A-H and the S7-S10 harnesses
landed). Matches the paper's "115 tests".

## Open escalation (routed to Writer, not an Executor fix)

At n=20 the lock-timeout fail-open is not uniformly 0: qwen3/mistral/deepseek/gemma3
0/20, but **qwen2.5:7b 4/20** and **phi4-mini 1/20** (`m2_rates_extra.csv`). This
contradicts the body's "0/3 for every model" generalization (Fig.4 "different
doors"). The n=3 caveated cells (hermes, SmartThings) are 0/3 and consistent with
the body; the contradiction is only at n=20 on the virtual home and is a Writer
softening item, not a caveat-blocking issue.

## Reviewer-response experiment (2026-07-03)

| Table (label) | Content | Source CSV | md5 |
|---|---|---|---|
| `tab:staleness` (App. staleness) | surfaced-staleness ablation: does a capable agent shown the age still get steered? | `stale_ablation.csv` | `ee255e0cd9ed27e981b4cc242014a96c` |
| `tab:grid` (App. grid) | model x family grid: mistral:7b + qwen2.5:7b x access/confirmation/automation, attack vs full guard, n=10 | `family_grid.csv` | `8395a5c1f50c82a68b67ec12c7615301` |

Runner (staleness): `delaysteer/run_stale_ablation.py` (config `surface_staleness`, guard-neutral, default OFF).
Result (both models n=20): qwen3:14b 16/20 (raw ts) -> 1/20 (age surfaced); qwen2.5:7b 19/20 either
way (its 19/20 baseline matches tab:crossmodel_n20 exactly). Answers the NDSS ML-reviewer's "would a
stronger planner notice?" empirically: a capable planner shown the age re-reads and refuses, a weaker
one ignores it, so the defense belongs at the gate, not the planner.

Runner (grid): `delaysteer/run_family_rates.py --models mistral:7b,qwen2.5:7b --families
access,confirmation,automation --repeats 10`. Result: the full guard holds violations to 0/10 in
ALL 6 model x family cells (uniform defense). The attack steers both planners at 10/10 on access +
confirmation and mistral on automation; qwen2.5:7b LOOPS on automation (8/10 non-completions) so the
attack lands only 2/10 there (a weaker-planner competence artifact, not a defense gap -- the guard
still blocks both). Closes the ML-reviewer "two single-axis studies, not a grid" breadth ask.

NOT A PAPER TABLE (diagnostic only): `results/activepoll_liveha.csv` (md5 d3912dc37fbf537009a6c5946a3e34e2)
+ `delaysteer/run_activepoll_liveha.py`. The live-HA active-poll benign-block demonstration was
attempted and DROPPED: the live-HA testbed entities are non-pollable template devices (last_reported
== last_updated, only advances on change; homeassistant.update_entity is a no-op), so active-poll
cannot be demonstrated on them (the non-pollable fail-closed case the paper already documents). The
clean active-poll result stays the MODELED `tab:anchor`. No paper claim rests on this CSV.

All frozen files (metrics.csv e787eb4c, m2_rates.csv 6cd5b9cb, adaptive.csv 7997ce45) untouched; additive only.
