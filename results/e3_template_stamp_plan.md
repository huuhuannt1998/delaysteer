# E3 live cells with the guard reading the live object: analysis plan (fixed before any run)

Written 2026-09-25 02:45 EDT, before the first run.

## Why
The recorded live E3 cells (`results/e3_live_safeliveness.csv`) judge freshness from `last_reported` as the REST view serves it.
- On HA 2026.8.3 that view is a cached JSON that a same-value write never invalidates (HA issue #181392).
- So a commit-time `update_entity` refresh never advances the stamp there: REST 0/20 vs the live object 20/20 (`results/ha_readpath_2026_8_3.csv`).
- The paper's "no critical fact proved actively pollable" and the naive guard's benign false blocks (normal/fail_closed 0/6 completed) may therefore be a property of the read path, not of the facts.

## Design
Identical to the recorded cells except for one switch: the adapter's freshness stamp is read from the live State object through `POST /api/template` (`--stamp-source template`).
- The value still comes from REST. If the live value differs from the REST value, the REST stamp is kept, which errs toward blocking.
- Guard: `fail_closed` only, the naive active-poll baseline. The supervisor arms model a non-pollable fact, so they are out of scope.
- Conditions: normal, transient, attack, sustained. Seeds 0-5, paired with the recorded cells. qwen3:14b at T=0, HA 2026.8.3, same entities, same delay layer.

```
.venv/bin/python -m delaysteer.run_e3_live_safeliveness --stamp-source template --guards fail_closed \
    --conditions normal,transient,attack,sustained --baseline-conditions normal,transient,attack,sustained \
    --repeats 6 --out e3_live_template_stamp
```

## Predictions
- **normal:** completes (the recorded REST cell is 0/6).
- **transient:** completes, since a 1 s hold is under the 2 s budget.
- **attack:** 0 violations. The delay layer serves the stale value with its old stamp, and a downstream adversary cannot forge a newer one.
- **sustained:** blocked, 0 completions. Every read is 10 s old, so the availability cost remains.

## Decision rule (fixed now)
1. **normal and transient complete, attack 0 violations.** The live fail-closed cost is a property of the REST view. The paper says so:
   - the live facts are pollable through the live object;
   - the naive guard then completes benign runs and still blocks the attack;
   - the safe-liveness supervisor is needed where a fact is genuinely not pollable (the sleepy-sensor class), or where only the REST view is available.

   The recorded cells stay as the REST-view measurement.
2. **normal still fails.** Report the first block reason, and keep "not pollable" with the reason made explicit.
3. **Any attack violation.** Report it as a guard failure under the live stamp, and investigate before any claim changes.

## Caveat carried into the text
These facts are template entities whose source is HA's own input_boolean. So the live stamp certifies a re-derivation from the source. For an integration that keeps its old state when a device poll fails (`rest/switch.py`), the same stamp records the hub's poll, not the device's answer (§5 of `feedback/Manuscript_Audit_Fixes_2026-09-25.md`).

## Addendum (2026-09-25 ~11:00 EDT): the first run did not test the refresh under delay

**What went wrong.** In `results/e3_live_template_stamp.csv`, TemporalGuard set `active_poll` on the `DelayingAdapter`, which did not forward it. So the HA adapter behind it never issued the commit-time `update_entity` in the transient, attack and sustained cells.
- The contact's stamp age grows across seeds (31 → 625 s transient, → 2694 s sustained). Its block reasons are therefore stale stamps the guard never refreshed.
- The normal cell has no delay layer, so it is valid: 6/6 completed, 0 blocks, against the recorded REST view's 0/6.

**Scope of the gap.**
- Only the live HA adapter reads the flag through a wrapper. Every virtual-home adversary wrapper handles `active_poll` itself.
- The recorded REST-view E3 cells cannot change outcome, since the REST stamp never advances either way.

**Fix.** An opt-in `DelayingAdapter.forward_active_poll` (default off, so every recorded run reproduces), tested in `tests/test_delay_layer_poll_forward.py`, and a `--forward-poll` runner flag. Rows record `poll_forwarded`.

**Re-run.** Same seeds, model and conditions, output `results/e3_live_template_stamp_fwd`:

```
.venv/bin/python -m delaysteer.run_e3_live_safeliveness --stamp-source template --forward-poll --guards fail_closed \
    --conditions normal,transient,attack,sustained --baseline-conditions normal,transient,attack,sustained \
    --repeats 6 --out e3_live_template_stamp_fwd
```

**Predictions and decision rule:** unchanged from the plan above. The first file is kept as the record of the gap.
