#!/usr/bin/env bash
# Clean cross-model text-fallback dataset on the layered HA -> SmartThings stack.
# baseline x1 (seed 1) + attack x3 + guard x3 (seeds 1,2,3) per model.
# Sleep between runs to respect SmartThings' per-device rate limit.
set -u
PY=/Users/anonymous/Desktop/hermes-agent/.venv/bin/python
cd /Users/anonymous/Desktop/DelaySteer
RUN() {  # model mode seed
  echo "### $(date +%H:%M:%S)  model=$1 mode=$2 seed=$3"
  $PY scripts/textagent_ha_attack.py --mode "$2" --model "$1" --seed "$3" 2>&1 \
     | grep -E "VIOLATION|claimed secure|true door|lock / alarm|tool actions|WARN"
  sleep 10
}
for MODEL in mistral-7b-64k deepseek-coder-v2:16b; do
  echo "========================= $MODEL ========================="
  RUN "$MODEL" baseline 1
  for S in 1 2 3; do RUN "$MODEL" attack "$S"; done
  for S in 1 2 3; do RUN "$MODEL" guard  "$S"; done
done
echo "ALL_TEXTAGENT_RUNS_DONE"
