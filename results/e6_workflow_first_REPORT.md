# E6 — workflow-first external evaluation: sample first, annotate blind

`scripts/run_e6_workflow_first.py` · 2026-09-10

## Question

Reviewer objection: "the authors defined the gadget taxonomy and then built scenarios that
instantiate it." The repair is procedural, so the script enforces the order rather than
asserting it: draw the sample before anything is annotated, annotate before anything is
attacked, and hash the annotation so the pre-attack labels are fixed on disk.

## Commands

```
.venv/bin/python scripts/run_e6_workflow_first.py --n 40 --seed 20260910
```

Frame: all **305** Home Assistant Blueprint Exchange blueprints with retrievable YAML
(`results/prevalence_cache/`). Draw: **40**, uniform without replacement, seed `20260910`.
The draw does not read the earlier census's labels and no attack existed when it was made.
Annotation digest, fixed before any later phase:
`e25cc7d9cdeded1898f624d65ce9efa2b3b167b7ff5a8bbe9d299b112136bd33`.

## Phase 2 — the five fields the plan names, in a random sample of 40

| property | rate in the sample |
|---|---|
| reads sensor state to decide | 21/40 |
| **age of that fact explicitly bounded** | **10/40** |
| a timeout exists | 9/40 |
| that timeout reaches a recovery path | 9/40 |
| fallback latitude (timeout, no age bound) | 7/40 |
| policy / automation editing permitted by its own action set | 10/40 |
| reaches a high-impact action | 4/40 |

Read against the paper's argument, the useful line is the intersection, not either row alone:
of the 21 sampled workflows that decide on sensor state, only **5 bound the age of the fact they
decide on**, so **16 bound none**. (Ten of the forty carry an age bound somewhere, but five of
those ten are not sensor-gated, so the marginal count overstates the protected set.) The ingredients of the
agent-amplified group are also present without being sought — every sampled workflow that has
a timeout reaches a recovery path from it (9/9), 7 leave that recovery unbounded by any age
check, and a quarter of the sample can turn automations on or off. None of that was selected
for; it is what a uniform draw from the corpus contains.

## Phase 3a — how many can be agentized faithfully, and why not the rest

| outcome | n |
|---|---|
| **agentizable on this tool surface** | **2/40** |
| not agentizable: no sensor-gated decision | 19 |
| not agentizable: no high-impact action to commit | 18 |
| not agentizable: gating fact outside the tool surface | 1 |

This is the honest cost of the reversal and it is reported rather than absorbed. A faithful
agentization needs the workflow's gating fact *and* its committed action to exist on the agent's
tool surface; writing a tool per workflow would put the experimenter back into the selection
loop, which is the effect this experiment exists to remove. At n=40 the eligible set is two
workflows (`967636`, `469873`), too small to carry a rate, so **no attack rate is claimed from
this sample**. Two routes are open, and both are future work: enlarge the draw (the frame is
305, so a draw of ~200 would be expected to yield ~10 eligible), or widen the tool surface,
which trades ecological validity for coverage.

## Phase 3b — not run

Running the eligible workflows under delay and labelling them with the plan's seven-row outcome
taxonomy (`no_meaningful_effect`, `fail_closed`, `stale_state_failure`,
`planner_recovery_steering`, `inference_driven_steering`, `policy_adaptation`,
`invariant_violation`) is implemented as far as the eligible set and no further. The taxonomy is
in the script so the later run cannot redefine it after seeing outcomes.

## What this does and does not support

- **Does support**: the temporal dependencies the paper attacks occur in externally authored
  workflows at a measurable rate, in a sample drawn before any attack, with the labels hashed.
  The paper's scenario families instantiate a shape the corpus already contains.
- **Does not support**: any claim about how often delay *steers* an externally authored
  workflow. That needs phase 3b on a larger eligible set.
- The annotation rules are syntactic and deterministic (the same rule class as the existing
  census, `scripts/classify_prevalence.py`), so they are reproducible but not human-validated
  here; the census's own hand-audit covers rule validity for the overlapping labels.
