# Human spot-check of the unattended-agent message coding (written 2026-10-02, before any human code)

## Why
Every "says secured" figure in the paper comes from two blind *model* coders (App. au1 says so). The paper's
headline unattended result now rests on three coded batches:

| Batch | Messages | Paper figure |
|---|---|---|
| AU1, single read path (`results/au1_coding/`) | 160 | 12/20 delayed vs 0/20 honest |
| X1, both read paths (`results/au1_two_channel_coding/`) | 60 | 19/20; 2/20 behind the guard |
| E-B, second model (`results/au1_second_model_coding/`) | 76 | 19/19 vs 0/19; 3/20 behind the guard |

A human check of a sample tells a reader whether the model coders read the messages the way a person does.

## Sample (fixed before coding)
`scripts/au1_coding_sheet.py human`, seed 20260926, five messages from every (wording, arm) cell of each batch:
AU1 40 (drawn 2026-09-26, unchanged), X1 15 and E-B 20 (drawn 2026-10-02). 75 messages in all.
`scripts/human_check.py page` shuffles them into one page with neutral ids (H01..H75); `map.csv` links each id to its
batch and item and says nothing about the arm.

## Procedure
One person who has not read the model coders' sheets codes all 75 on `results/human_check/index.html`, using the
codebook printed on the page, without opening any `key.csv` or `sheet_coder*.csv`. The page saves to a CSV.
`scripts/human_check.py import <that csv>` writes the codes into each batch's `sheet_human.csv` and scores them
against both model coders.

## Decision rule (primary code: claims_secure)
1. Human agrees with both model coders on at least 90% of the 75 items and Cohen's kappa is at least 0.8: the paper
   adds one clause at App. au1 ("a human spot-check of 75 messages agrees with them on k") and nothing else changes.
2. Agreement 80-90% or kappa 0.6-0.8: report the figure in App. au1 and list the disputed items; the body's
   "says secured" counts stay but are described as model-coded with the human agreement beside them.
3. Below that: the "says secured" counts are re-coded by the human in full for the cells the body cites before any
   resubmission, and the body reports the human counts.
The two other codes are reported, not used for a decision.
