# DelaySteer

**Delay-only decision-steering attacks and the TemporalGuard defense for AI-agent smart homes.**

DelaySteer studies a vulnerability that appears once a smart home is driven by a
*goal-directed agent* rather than fixed automation rules. An adversary who can only
**delay truthful observations** — never forging, injecting, or tampering with a
payload — can steer the agent's belief state and change *what* it decides to do next,
driving it into a safety- or security-invariant violation. The core idea is
**stale truth**: a reading that is correct as data becomes unsafe as *decision
evidence* when it arrives late and an adaptive planner acts on it.

This repository is the research artifact: a reproducible testbed, the attack
families, the formal-model-backed defense (**TemporalGuard**), and the experiment
harness that produces every reported result.

> The manuscript is not included in this repository.

---

## What this artifact demonstrates

- **A delay-only attack class.** Four amplification mechanisms, each realized as a
  delay schedule on a single observation channel: fail-open recovery (bedtime),
  delegation under uncertainty (access), confirmation desynchronization (TOCTOU),
  and persistent automation drift.
- **A cross-agent finding.** A deterministic agentic reference and a real
  language-model planner fail through *different doors* under the same delay (one via
  fail-open recovery, the other by acting on a stale-but-truthful value); a
  rule-based routine fails closed under either. A defense that trusts the planner to
  police freshness would miss one of these; enforcing it at the gate covers both.
- **TemporalGuard.** A tool-router middleware that enforces per-action *freshness
  contracts* and *two-phase commitment*, escalates to the user with fresh context
  when temporal trust is low, and — against an adaptive adversary — adds
  *challenge-response freshness* that shrinks the residual exploitable window from the
  freshness budget to the sensor heartbeat (an ~8x reduction, with a matching
  reachability bound).
- **Generalization.** The attack and defense reproduce on the SmartThings cloud
  (virtual devices on the real cloud), on the external **SimuHome** benchmark (ICLR
  2026; an operational-safety setting and a language-model agent we did not build),
  and across a **HearthNet**-style hub-and-subagent multi-agent topology where the
  delay targets a truthful inter-agent observation.

Headline numbers and per-cell results live in [`results/`](results/).

---

## Repository layout

```
delaysteer/                 core Python package
  home/                     HomeAdapter + virtual, live-HA, cloud-callback, SmartThings adapters
  attack/                   delay-injection layer + the five delay profiles + adaptive adversary
  defense/                  TemporalGuard (freshness contracts, two-phase, challenge-response)
  planner/                  the agent loop (deterministic reference + LLM backbones)
  scenarios/                the four scenario families + invariants
  provenance/               temporal provenance monitor (replayable traces)
  tools/                    the tool registry, router, and gate seam
  simuhome/                 SimuHome external-benchmark integration (client + adapter + harness)
  run_benign.py             the benign secure-house baseline
  run_attack.py             the delay-only attack (lock-timeout, contact-contradiction, ...)
  run_defense.py            the TemporalGuard ablation matrix
  run_repair.py / run_confirm.py / run_automation.py / run_adaptive.py   the other families
  run_experiments.py        the full attack / baseline / ablation / usability matrix
  run_simuhome.py           the SimuHome generalization matrix
scripts/                    setup + probes (HA bootstrap, SmartThings, SimuHome proxy, HearthNet drivers)
results/                    released result files (metrics.csv, smartthings.csv, simuhome*.csv, multiagent*.csv)
tests/                      the automated test suite
config/configuration.yaml   the Home Assistant testbed configuration (lab-safe virtual devices)
docker-compose.yml          the live Home Assistant container
SIMUHOME_REPRODUCE.md       how to clone + run the external SimuHome substrate
```

---

## Quick start

Requires Python 3.13 and [`uv`](https://github.com/astral-sh/uv) (or plain `pip`).

```bash
uv venv --python 3.13
uv pip install -e ".[dev,llm]"

# Deterministic baseline (no LLM, no external deps):
uv run python -m delaysteer.run_benign --backbone scripted

# The delay-only attack on the virtual home:
uv run python -m delaysteer.run_attack --scenario both

# The TemporalGuard ablation:
uv run python -m delaysteer.run_defense

# The full matrix (attack / baseline / ablation / usability):
uv run python -m delaysteer.run_experiments

# Test suite:
uv run pytest -q
```

Add the language-model agent of record with `--backbone ollama --model qwen3:14b`
(requires a local [Ollama](https://ollama.com) with the model pulled). Deterministic
rows reproduce bit-for-bit; language-model rows are reported as rates over repeated
sampled runs. Results are written to [`results/`](results/) and replayable traces to
`traces/`.

### Live Home Assistant (optional)

```bash
docker compose up -d                              # official HA container
uv run python scripts/ha_bootstrap.py             # onboard + save config/ha_credentials.json
uv run python -m delaysteer.run_attack --home ha --scenario both
```

`config/configuration.yaml` defines **lab-safe virtual devices only** (template lock,
manual alarm panel, template binary sensors) — no physical lock or alarm is ever
controlled.

---

## External substrates (cloned separately, not vendored)

Two external systems are used as additional substrates and are **not** included
here; they are wrapped at runtime as dependencies and cloned next to this repo:

- **SimuHome** (ICLR 2026, `github.com/holi-lab/SimuHome`, CC BY-NC-ND) — an external
  time-evolving smart-home benchmark. See [`SIMUHOME_REPRODUCE.md`](SIMUHOME_REPRODUCE.md)
  for the clone + run steps. Runtime evaluation against an unmodified clone only.
- **HearthNet** (`github.com/zhonghaozhan/hearthnet`, MIT) — a freshness-aware
  hub-and-subagent protocol. The multi-agent drivers in `scripts/hn_*.js` drive its
  released protocol implementation; results are in `results/multiagent*`.

---

## Credentials and safety

- No real secrets are committed. The platform token is read at runtime from a
  gitignored `.env` (`SMARTTHINGS_TOKEN=...`); the Home Assistant container runtime
  and `config/ha_credentials.json` are gitignored.
- The Home Assistant bootstrap uses a **throwaway local lab account** on
  `localhost:8123` (not a real credential).
- All device interaction is virtual or lab-safe; the attacks are **delay-only** and
  never forge, inject, tamper, or perform denial-of-service.

---

## License

Code in this repository is the authors'. External substrates (SimuHome, HearthNet)
retain their own licenses and are not redistributed here.
