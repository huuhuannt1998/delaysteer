#!/usr/bin/env bash
# Additive rich-home experiment matrix. Logs full trajectories to results/richhome.jsonl.
# Frozen results/metrics.csv is never touched.
set -u
PY="${HERMES_PY:-$HOME/hermes-agent/.venv/bin/python}"   # override with HERMES_PY=/path/to/hermes/.venv/bin/python
cd "$(cd "$(dirname "$0")/.." && pwd)"                    # repo root (this script lives in scripts/)
RUN() {  # scenario mode model seed
  echo "### $(date +%H:%M:%S)  $1 / $2 / $3 / seed$4"
  $PY scripts/richhome_eval.py --scenario "$1" --mode "$2" --model "$3" --seed "$4" 2>&1 \
     | grep -E "DELAYED OBSERVATION|agent_saw_stale|>>> VIOLATION"
  sleep 4
}

echo "===== SCENARIO 1: secure_house (headline) -- cross-model generalization ====="
for M in qwen3-14b-64k mistral-7b-64k deepseek-coder-v2:16b; do
  RUN secure_house baseline "$M" 1
  RUN secure_house attack   "$M" 1
  RUN secure_house attack   "$M" 2
  RUN secure_house guard    "$M" 1
  RUN secure_house guard    "$M" 2
done

echo "===== NEW SCENARIOS 2-4 -- qwen3 (agent of record) + mistral spot-check ====="
for S in garage_armed multidoor leak_appliance; do
  RUN "$S" baseline qwen3-14b-64k 1
  RUN "$S" attack   qwen3-14b-64k 1
  RUN "$S" attack   qwen3-14b-64k 2
  RUN "$S" guard    qwen3-14b-64k 1
  RUN "$S" attack   mistral-7b-64k 1
  RUN "$S" guard    mistral-7b-64k 1
done
echo "ALL_RICHHOME_DONE"
