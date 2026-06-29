#!/usr/bin/env bash
set -u
PY="${HERMES_PY:-$HOME/hermes-agent/.venv/bin/python}"   # override with HERMES_PY=...
cd "$(cd "$(dirname "$0")/.." && pwd)"                    # repo root
RUN(){ echo "### $(date +%H:%M:%S) $1/$2/deepseek/s$3"
  $PY scripts/richhome_eval.py --scenario "$1" --mode "$2" --model deepseek-coder-v2:16b --seed "$3" 2>&1 | grep -E "DELAYED|>>> VIOLATION"; sleep 4; }
for S in garage_armed multidoor leak_appliance; do
  RUN "$S" attack 1; RUN "$S" attack 2; RUN "$S" guard 1
done
echo "DEEPSEEK_RICHHOME_DONE"
