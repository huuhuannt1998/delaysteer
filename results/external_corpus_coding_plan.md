# X2: blind double annotation of the 18-task external corpus: analysis plan (fixed before any coding)

Written 2026-10-01, before the coding sheet was built and before any coder saw a task. Experiment H's data and labels are unchanged (`results/external_corpus.csv`, `results/external_corpus_manifest.md`).

## Why
Experiment H's headline is that 10 of 18 tasks carry a plausible delay-only attack surface. That figure rests on one author's labels and reports no agreement statistic (App. extcorpus, "Annotation limitation"). The round-4 review (Reviewer C, and the associate editor's item 7) asked for a second annotation and a κ, as the AU1 message coding already reports.

## Procedure
- **Sheet.** The 18 tasks are put in a random order under neutral ids (T01–T18, seed 20261001). Each row shows only the task's source type and its text (`user_goal`): no task id, no author label, no field derived from the annotation.
- **Key.** It maps each neutral id to its task and the author's label. It stays outside the repository during coding, and its sha256 is recorded before and after.
- **Coders.** Two fresh-context model coders on two different models. Each is given only the codebook and its own copy of the sheet, and is told not to read any file. These are model coders, not human coders, as in AU1.
- **Codebook.** It restates the published criterion (App. extcorpus): a task carries a plausible delay-only attack surface only if it (a) takes or reports a high-impact action, **and** (b) decides to do so on a sensor or state reading that could arrive late. It gives general definitions and no example drawn from the corpus.
  - Disclosure: the codebook was written by the session agent, which had seen the author's labels. It adds no task-specific rule.
- **Codes per task:** `high_impact`, `delay_sensitive_fact` and `attack_surface` (yes/no each), plus an optional note.

## Endpoints
- **Primary:** Cohen's κ on `attack_surface`, between each coder and the author, and between the two coders. Raw agreement is reported alongside κ.
- **Also:** each coder's count of applicable tasks (x/18), and the two coders' consensus count (tasks both coders mark yes).

## Decision rule (fixed now)
1. **Both coder-vs-author κ ≥ 0.6 and coder-vs-coder κ ≥ 0.6.** The 10/18 is supported by independent annotation. The supplement reports the three κ and the coders' counts, and the "single-annotator" limitation is replaced by them.
2. **Any κ below 0.6.** Report the κ values, the coders' counts as the range of the estimate, and every disputed task with the coders' notes. The 10/18 stays a scoped single-annotator estimate, now with its measured disagreement.

In both cases the body claims nothing new beyond the supplement's figure.

## Result (written after coding; data: `results/external_corpus_coding/`)
- **Coding.** Coder A was `opus` and coder B was `sonnet`, both fresh-context, given only the codebook and the sheet, with no file access (one tool call each: the hand-back). The key's sha256 was unchanged before and after (`5acfb1c2…`). It was then copied into the folder as `key.csv`.
- **Agreement on `attack_surface`:**

  | Comparison | Agree | κ |
  |---|---|---|
  | coder A vs author | 13/18 | 0.44 |
  | coder B vs author | 13/18 | 0.44 |
  | coder A vs coder B | 18/18 | 1.00 |

- **Applicable:** author 10/18; each coder 9/18 (both coders agree on the same 9).
- **The five disputes, both ways:**
  - **Coders yes, author no.**
    - T02, a door-open alert: the coders treat it as a security report the resident relies on; the author required a commit.
    - T18, access delegation: the coders judged it from the text; the author excluded it because SimuHome cannot pose it, which is a platform-scope reason.
  - **Author yes, coders no.** On each, the author inferred a state the text does not name:
    - T04, a sunset lock-up (doors checked first);
    - T08, a confirm-to-unlock prompt (the presence behind the prompt);
    - T10, an appliance precondition.

**Decision (rule 2): κ against the author is below 0.6.** The supplement reports the three κ values, the coders' count, the 9–10 of 18 range and every dispute, and the 10/18 is read as a scoped estimate with its measured disagreement. The body claims nothing new.
