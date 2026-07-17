#!/usr/bin/env bash
# One-command DelaySteer demo launcher.
#
# Brings up the two pieces the live attack demo needs and leaves them running:
#   * delay proxy            :8125   (the on-path seam that re-serves a stale reading)
#   * Temporal Breach Monitor:9120   (watch ground truth vs. agent belief in real time)
# Home Assistant (:8123) must already be up (docker container delaysteer-ha).
#
# Then run the attack in another shell (also shown in the monitor's LAUNCH SEQUENCE panel):
#   python scripts/demo_attack.py --mode attack     # -> VIOLATION
#   python scripts/demo_attack.py --mode guard      # -> TemporalGuard BLOCK
#   python scripts/demo_attack.py --mode baseline   # -> refuses (no delay)
#
#   scripts/launch_demo.sh            # start proxy + monitor
#   scripts/launch_demo.sh stop       # stop them
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
PY="${PY:-.venv/bin/python}"; [ -x "$PY" ] || PY="python3"
mkdir -p results

up(){ lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

if [ "${1:-start}" = "stop" ]; then
  pkill -f "ha_delay_proxy.py --port 8125"    2>/dev/null && echo "stopped delay proxy" || true
  pkill -f "attack_monitor.py"                2>/dev/null && echo "stopped monitor"     || true
  pkill -f "ollama_openai_bridge.py --port 8788" 2>/dev/null && echo "stopped ollama bridge" || true
  echo "(Hermes dashboard :9119 is separate: cd "${HERMES_HOME:-$HOME/Desktop/hermes-agent}" && .venv/bin/python -m hermes_cli.main dashboard --stop)"
  exit 0
fi

if ! up 8123; then
  echo "!! Home Assistant is not up on :8123.  Start it:  docker start delaysteer-ha"; exit 1
fi

if up 8125; then echo "delay proxy already up on :8125";
else nohup "$PY" scripts/ha_delay_proxy.py --port 8125 >results/proxy.log 2>&1 & sleep 1; echo "started delay proxy :8125 (results/proxy.log)"; fi

if up 8788; then echo "ollama bridge already up on :8788";
else nohup "$PY" scripts/ollama_openai_bridge.py --port 8788 >results/bridge.log 2>&1 & sleep 1; echo "started ollama bridge :8788 (results/bridge.log)"; fi

if up 9120; then echo "monitor already up on :9120";
else nohup "$PY" scripts/attack_monitor.py --port 9120 >results/monitor.log 2>&1 & sleep 1; echo "started monitor :9120 (results/monitor.log)"; fi

echo
if up 9119; then echo "Hermes chat already up on :9119";
else echo "Start the Hermes chat (:9119) separately:"; echo "   cd "${HERMES_HOME:-$HOME/Desktop/hermes-agent}" && HASS_URL=http://localhost:8125 .venv/bin/python -m hermes_cli.main dashboard --skip-build --no-open &"; fi
echo
echo "   WATCH:   http://localhost:9120        (the breach monitor — explains every stage)"
echo "   CHAT:    http://localhost:9119/chat    -> \"Secure the house for bedtime.\""
echo "   ARM:     python scripts/demo_attack.py --mode attack --prep-only     (then use the chat)"
echo "   DEFEND:  python scripts/demo_attack.py --mode guard  --prep-only"
echo "   CLEAR:   python scripts/demo_attack.py --clear"
echo "   (one-shot without the chat:  python scripts/demo_attack.py --mode attack)"
