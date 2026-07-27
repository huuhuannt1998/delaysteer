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

> The manuscript is not included in this repository. This README is a **reproduction
> guide**: clone the repo, install, run the experiments, and compare your output
> against the released files in [`results/`](results/).

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

## Prerequisites

You only need the pieces for the experiments you intend to run. The **core** results
need nothing but Python.

| To run | You need |
|---|---|
| Core results + all tests | **Python 3.11+** and [`uv`](https://github.com/astral-sh/uv) (3.13 was used for the released runs) |
| Language-model agent rows | a local [**Ollama**](https://ollama.com) with the models pulled (below) |
| Live Home Assistant rows | **Docker** (the official HA container in `docker-compose.yml`) |
| SmartThings rows | a SmartThings **developer token** in a gitignored `.env` (`SMARTTHINGS_TOKEN=...`) |
| Multi-agent (HearthNet) rows | **Node.js 18+** and the HearthNet clone (see [External substrates](#external-substrates)) |
| SimuHome rows | the SimuHome clone + server (see [`SIMUHOME_REPRODUCE.md`](SIMUHOME_REPRODUCE.md)) |

Pull the Ollama models used in the paper (only what you plan to run):

```bash
ollama pull qwen3:14b                 # agent of record (the core LLM rows)
ollama pull mistral:7b                # cross-model study
ollama pull deepseek-coder-v2:16b     # cross-model study (resistant looping outlier)

# Small-model TOCTOU sweep (nine models, 0.6B–14B) — only for the TOCTOU experiment:
ollama pull qwen3:0.6b qwen3:1.7b qwen3:4b qwen3:8b qwen2.5:7b llama3.1:8b
```

---

## Setup

```bash
git clone https://github.com/huuhuannt1998/delaysteer.git
cd delaysteer

uv venv --python 3.13                  # 3.11+ works; 3.13 used for the released runs
uv pip install -e ".[dev,llm,ha]"      # core + Ollama/LLM + Home Assistant adapters
```

(Plain `pip install -e ".[dev,llm,ha]"` inside a virtualenv works too.)

---

## Reproduce the results

There are two kinds of rows, and they reproduce differently:

- **Deterministic rows** — the scripted agentic reference, the attack/defense matrix,
  the adaptive analysis, and the test suite — reproduce **bit-for-bit**. No Ollama needed.
- **Language-model rows** are reported as **rates over repeated sampled runs**. With a
  local model at temperature 0.7 you should see the **same verdict and approximately
  the same rate**, not identical per-run cells.

Every command writes (or overwrites) a file in [`results/`](results/); the table in
each step lists the output file and the headline it supports.

### Step 1 — Core matrix, defense, and tests (no external services)

```bash
# Headline attack/baseline/ablation/usability matrix  →  results/metrics.csv
uv run python -m delaysteer.run_experiments

# Adaptive adversary + challenge-response floor (the 8x window)  →  results/adaptive.csv
uv run python -m delaysteer.run_adaptive

# TemporalGuard ablation (which mechanism does the work)
uv run python -m delaysteer.run_defense

# The full automated test suite (74 tests)
uv run pytest -q
```

| Output | Supports |
|---|---|
| `results/metrics.csv` | the core attack/defense matrix (deterministic agentic reference) |
| `results/adaptive.csv` | the static-budget-only-bounds result and the ~8x challenge-response reduction (2.0 s → 0.25 s) |
| `pytest` (74 passing) | the artifact's correctness checks |

### Step 2 — Language-model agent rows (needs Ollama + the models)

```bash
# The same matrix driven by the LLM agent of record:
uv run python -m delaysteer.run_experiments --llm qwen3:14b

# Cross-model rate study (qwen3:14b, mistral:7b, deepseek-coder-v2:16b)  →  results/m2_rates.csv
uv run python -m delaysteer.run_m2_rates
```

| Output | Supports |
|---|---|
| `results/m2_rates.csv` | the cross-agent "different doors" finding (qwen3/mistral con 3/3, lock-timeout 0/3; deepseek loops) |

### Step 3 — Generalization studies

| Study | Command | Output | Needs |
|---|---|---|---|
| SmartThings (deterministic) | `uv run python -m delaysteer.run_smartthings` | `results/smartthings.csv` | `SMARTTHINGS_TOKEN` in `.env` |
| SmartThings (cross-model) | `uv run python -m delaysteer.run_smartthings_llm_rates` | `results/smartthings_llm_rates.csv` | token + Ollama |
| SimuHome (external benchmark) | `uv run python -m delaysteer.run_simuhome` | `results/simuhome.csv` | SimuHome clone + server (`SIMUHOME_REPRODUCE.md`) |
| TOCTOU small-model sweep | `python scripts/sh_toctou_eval.py --model qwen2.5:7b --out results/toctou.csv` | `results/toctou.csv` | Ollama (sweep models) |
| TOCTOU defense comparison | `python scripts/sh_toctou_eval.py --model qwen2.5:7b --defense temporalguard --out results/toctou_defenses.csv` | `results/toctou_defenses.csv` | Ollama |
| Multi-agent (HearthNet) | `node scripts/hn_multiagent.js` | `results/multiagent*.csv` | Node.js + HearthNet clone |

The TOCTOU defense comparison runs once per defense; `--defense` accepts
`none`, `temporalguard`, `toolfuser`, `sim`, `promptrewrite`, `generic_gate`
(append each to the same `--out` file or use separate files, then plot with
`scripts/plot_toctou_defenses.py`).

### Step 4 — Live Home Assistant + the rich-home / Hermes studies (extra setup)

The live-HA matrix and the appendix generalization studies need the running HA
container:

```bash
docker compose up -d                          # official Home Assistant container
uv run python scripts/ha_bootstrap.py         # onboard + save config/ha_credentials.json (gitignored)
uv run python -m delaysteer.run_experiments --homes ha --llm qwen3:14b
```

`config/configuration.yaml` defines **lab-safe virtual devices only** (template lock,
manual alarm panel, template binary sensors) — no physical lock or alarm is ever
controlled.

> **Note on the rich-home and Hermes (production-framework) studies.** These two
> appendix studies (`scripts/run_richhome_matrix.sh`, `scripts/hermes_ha_attack.py`)
> additionally require a local checkout of the [Hermes agent
> framework](https://github.com/NousResearch/hermes-agent) and a `qwen3-14b-64k`
> Ollama alias (a `qwen3:14b` Modelfile with a 64k context window).
> `scripts/run_richhome_matrix.sh` hardcodes a local Python path at the top
> (`PY=.../hermes-agent/.venv/bin/python`) — **edit that line** to point at your own
> Hermes virtualenv before running. These rows are additive; the core results above
> do not depend on them.

### Watch the attack live (interactive dashboard)

A browser dashboard that **shows and explains the attack in real time** — the real door
state beside what the agent reads through the delay proxy, a live stage rail, and the
verdict. Needs only the Home Assistant container from Step 4 — **no LLM, no cloud** — plus a
one-time local Home Assistant token (below).

```bash
docker compose up -d                 # Home Assistant on :8123 (once)
# --- one-time: put a Home Assistant token in .env (see "Home Assistant token" below) ---
scripts/launch_demo.sh               # starts the delay proxy (:8125) + the monitor (:9120)
# open http://localhost:9120
```

#### Home Assistant token (`.env`)

The dashboard, the delay proxy (`:8125`), and `scripts/demo_attack.py` read the Home
Assistant API, which requires a token. Create one once and put it in a `.env` at the repo
root:

1. Open `http://localhost:8123` and finish first-run onboarding (create a local user).
2. In the HA UI, click your **profile** (bottom of the left sidebar) -> scroll to
   **Long-Lived Access Tokens** -> **Create Token**, name it (e.g. `delaysteer`), and copy it.
3. Create/edit `.env` at the repo root (it is **gitignored -- never commit it**):
   ```bash
   HASS_TOKEN=<paste the long-lived token>
   HASS_URL=http://localhost:8125   # only used by the real-LLM tier (routes reads via the proxy)
   ```
4. **Restart the demo services after any `.env` change** -- the proxy and monitor read the
   token once at startup, so a new token is not picked up until they restart:
   ```bash
   scripts/launch_demo.sh stop && scripts/launch_demo.sh
   ```

**If the dashboard shows `OFFLINE` / "Home Assistant offline"** (or `demo_attack.py` prints
`cannot read Home Assistant on :8123 (token/entity)`), the token is missing or expired:
regenerate it (step 2), update `.env`, and restart the services (step 4). Long-lived tokens
last ~10 years, so this is normally a one-time setup. The experiment runners under
`delaysteer/` authenticate separately via `config/ha_credentials.json` (written by
`scripts/ha_bootstrap.py`, a refresh-token flow that renews automatically), so they are
unaffected by the `.env` token.

Use the dashboard's one-click **RUN** buttons, or the driver directly — a deterministic
"secure the house for bedtime" routine (no LLM needed):

```bash
python scripts/demo_attack.py --mode attack     # -> VIOLATION: arms an OPEN door on a stale read
python scripts/demo_attack.py --mode guard      # -> TemporalGuard BLOCK (409 on the arm)
python scripts/demo_attack.py --clear           # reset;  scripts/launch_demo.sh stop  tears it down
```

Watch `:9120`: **Ground Truth** (`OPEN`) and **Agent Belief** (`CLOSED`) diverge, the stage
rail walks `PROXY ARMED → DOOR OPENS → TOOL-CALL DELAYED → OUTCOME`, and the banner shows
**VIOLATION** or **TEMPORALGUARD BLOCKED** (staying on the outcome until you clear).

To drive a **real LLM agent** instead of the deterministic routine, install the Hermes
framework (as in the note above) with Ollama, point its Home Assistant tool at the proxy
(`HASS_URL=http://localhost:8125`, so its tool calls cross the delay), arm the delay
(`python scripts/demo_attack.py --mode attack --prep-only`), and in the agent chat send a
prompt that makes it **read the door before arming** — call `ha_get_state` on
`binary_sensor.front_door_contact` first, then `ha_call_service` to arm
`alarm_control_panel.home_alarm` only if it reads `off` (closed). A ready-made CLI version
(no chat) is `scripts/hermes_ha_native_demo.py` (set `HERMES_HOME`).

### Verify you reproduced the same results

The released `results/` files are the reference. The frozen core matrix ships at a
fixed checksum:

```bash
md5 results/metrics.csv        # macOS  → e787eb4c9e45e1919a818a6a65868e59
md5sum results/metrics.csv     # Linux  → e787eb4c9e45e1919a818a6a65868e59
```

- **Deterministic rows** (the scripted reference, the matrix, the adaptive analysis)
  reproduce the released verdicts exactly.
- **Language-model rows** are stochastic: a run matches if the **violated/prevented
  verdict** agrees and the **rate is within one sampled run** of the released cell.

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
  run_experiments.py        the full attack / baseline / ablation / usability matrix  → metrics.csv
  run_adaptive.py           adaptive adversary + challenge-response floor             → adaptive.csv
  run_m2_rates.py           cross-model LLM rate study                                → m2_rates.csv
  run_smartthings*.py       SmartThings deterministic + cross-model                   → smartthings*.csv
  run_simuhome.py           the SimuHome generalization matrix                        → simuhome.csv
  run_benign.py / run_attack.py / run_defense.py   single-stage entry points used by the matrix
scripts/                    setup + probes + additive studies
  ha_bootstrap.py           onboard the live Home Assistant container
  sh_toctou_eval.py         small-model TOCTOU sweep + defense comparison             → toctou*.csv
  run_richhome_matrix.sh    rich multi-room home generalization (needs Hermes)        → richhome*.csv
  hermes_ha_attack.py       production-framework (Hermes) stack                       → hermes_ha_rates.csv
  hn_multiagent.js          HearthNet multi-agent driver (Node)                       → multiagent*.csv
  st_*.py                   SmartThings registration / probes
results/                    released result files (compare your runs against these)
tests/                      the automated test suite (74 tests)
config/configuration.yaml   the Home Assistant testbed configuration (lab-safe virtual devices)
docker-compose.yml          the live Home Assistant container
SIMUHOME_REPRODUCE.md       how to clone + run the external SimuHome substrate
```

---

## External substrates

Two external systems are used as additional substrates and are **not** included here;
they are wrapped at runtime and cloned **next to** this repo (never inside it):

- **SimuHome** (ICLR 2026, [`github.com/holi-lab/SimuHome`](https://github.com/holi-lab/SimuHome),
  CC BY-NC-ND) — an external time-evolving smart-home benchmark. See
  [`SIMUHOME_REPRODUCE.md`](SIMUHOME_REPRODUCE.md) for the clone + server steps. Runtime
  evaluation against an unmodified clone only; we never fork or redistribute it.
- **HearthNet** ([`github.com/zhonghaozhan/hearthnet`](https://github.com/zhonghaozhan/hearthnet),
  MIT) — a freshness-aware hub-and-subagent protocol. The drivers in `scripts/hn_*.js`
  drive its released protocol implementation; results land in `results/multiagent*`.

---

## Credentials and safety

- No real secrets are committed. The SmartThings token is read at runtime from a
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
