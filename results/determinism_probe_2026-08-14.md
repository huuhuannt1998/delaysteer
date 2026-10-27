# Determinism probe, 14 August 2026 (transcribed)

`scripts/determinism_probe.py` prints its verdicts to standard output and writes no file. This file
transcribes the 14 August 2026 run, which was recorded in the project's research log (RKA journal
entry `jrn_01M00ZWB7EKREFN8CFTBH7ZPWM`, created 2026-08-14T20:37:10Z). It was added on 27 October
2026 so that the article's statement about temperature-0 determinism (§5.3) points to a file in the
repository. A fresh run of the same probe is in `determinism_probe_2026-10-27.txt`.

The probe escalates through four conditions at temperature 0, with the same prompt and seed unless
stated:

1. back to back;
2. interleaved with a different prompt through the same server;
3. after a 120-line context;
4. with a different seed (at T = 0 the seed should be irrelevant if decoding is greedy).

| Model | Repeats | Back to back | Interleaved | Long context | Different seed |
|---|---|---|---|---|---|
| qwen2.5:7b | 4 | deterministic | deterministic | deterministic | deterministic |
| qwen3:14b (agent of record) | 3 | deterministic | deterministic | deterministic | deterministic |

The journal entry's caveat applies: the result pins the server and model blobs of that date and is not
a guarantee across an Ollama upgrade or a model re-pull. Model digests are in `model_digests.json`.
