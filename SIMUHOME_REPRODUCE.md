# Reproducing the SimuHome generalization (MA-5)

SimuHome (ICLR 2026, arXiv 2509.24282) is used as an **external** CPS benchmark to
show that the delay-only decision-steering **mechanism** and **TemporalGuard**
generalize to a benchmark + agents we did **not** build (closing W1/W3). On
SimuHome the violations are **operational-safety / correctness**, not
security-invariant violations (SimuHome has no security devices); the
security-invariant headline stays on the Home Assistant / SmartThings testbeds.

## License (read first)

SimuHome is **CC BY-NC-ND 4.0** (non-commercial, **no-derivatives**). We therefore:

- **never fork or modify** SimuHome; we wrap it **at runtime** as an external service;
- **never commit** the SimuHome source into this repo — it is cloned *outside* the
  repo at `../SimuHome-ext` and is git-ignored by being outside the tree;
- run a **PI/legal check before distributing any derivative** (e.g. a packaged
  "DelaySteer-Bench on SimuHome"). Runtime evaluation against an unmodified clone is
  fine; redistribution of a modified version is not.

## Setup (one time)

```bash
# clone OUTSIDE this repo (sibling dir); never committed
git clone --depth 1 https://github.com/holi-lab/SimuHome.git ../SimuHome-ext
cd ../SimuHome-ext && uv sync          # materializes SimuHome's own .venv
uv run simuhome server-start           # simulator REST API on http://127.0.0.1:8000 (routes under /api)
uv run simuhome health                 # sanity
```

Our wrapper code lives entirely in **this** repo:
`delaysteer/simuhome/` (client + adapter + guard + scenarios),
`delaysteer/run_simuhome.py`, and `scripts/sh_*.py`.

## Reproduce the results

```bash
# 1) reference-agent matrix (deterministic): ablation + residual window -> results/simuhome.csv
python -m delaysteer.run_simuhome

# 2) cross-substrate consistency (SH-4) -> results/simuhome_cross_substrate.json
python scripts/sh_cross_substrate.py

# 3) native W3 (SimuHome's OWN ReAct agent we did not build), via the delay proxy + Ollama
python scripts/sh_delay_proxy.py --port 8099 &            # delay proxy on the wire at base_url
#   non-reasoning model recommended (see limitation below); run inside SimuHome's venv:
cd ../SimuHome-ext && PYTHONPATH=$PWD .venv/bin/python \
    ../DelaySteer/scripts/sh_native_report.py --model llama3.1:8b --trials 3
#   -> no-delay 0/3 stale-belief ; delay 3/3 stale-belief (delay-only steer)
```

Offline tests (no server, no network): `pytest tests/test_simuhome.py`.

## Results produced

- `results/simuhome.csv` — reference-agent ablation (window-covering safety-lockout,
  clean automation-drift) + residual-window rows (2.0s static freshness → 0.25s
  challenge-response, ~8× = the L1 floor, reproduced on SimuHome).
- `results/simuhome_native.csv` — native ReAct (SimuHome's own agent) steering +
  guard rows (llama3.1:8b: no-delay 0/3, delay 3/3 stale-belief; guard blocks the
  high-impact command).
- `results/simuhome_cross_substrate.json` — SH-4: ablation buckets ALL CONSISTENT
  across own-testbed / SmartThings / SimuHome.
- `results/simuhome_family_mapping.json` — SH-3 mechanism-family coverage.

## Frozen artifacts (C3)

The SimuHome runs are **additive**. The security matrices are frozen and
md5-asserted unchanged by `run_simuhome.py`:
`results/metrics.csv` = `e787eb4c9e45e1919a818a6a65868e59`,
`results/smartthings.csv` = `94681536f03ebd7b09b9beaac97900cb`.

## Honest scope / limitations

- **One clean family.** Window-covering safety-lockout maps to SimuHome **without
  tuning the benchmark** and fully carries the generalization claim (matrixed,
  natively steered, cross-substrate-consistent, L1 residual reproduced). We
  deliberately did **not** add env-threshold / confirmation families: they would
  require tuning a benchmark we chose *because* we did not build it, which would
  undercut its independence, and the mechanism conclusions do not change with breadth.
- **Access/delegation is excluded by design — and that is a finding:** SimuHome's
  appliance/environment device set has **no access-control / lock / occupancy
  analog**, so the delegation family has no honest mapping. This is a fact about the
  benchmark's scope, not a gap in the attack/defense.
- **Agent of record vs native harness.** `qwen3:14b` (our agent of record) is
  **not usable inside SimuHome's native ReAct harness** here: SimuHome forces
  `response_format=json_schema` (grammar-constrained decoding), which conflicts with
  a reasoning model's generation and causes request timeouts. `qwen3:14b` remains the
  agent of record on our **own** testbed (no grammar constraint); SimuHome's native
  generalization uses non-reasoning models (`llama3.1:8b`). `mistral:7b` was flaky
  (invalid structured output / unknown-tool).
- **Synthesized-timestamp honesty (SH-2).** SimuHome observations carry no native
  generation timestamp; we derive `generation_time` from SimuHome's **authoritative
  virtual clock** (`/home/state.current_time`, equivalently `/time`), never from the
  adversary, which controls only delivery.
