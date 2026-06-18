"""MA-7 regression checks: second inter-agent scenario (smoke/CO -> fire-alert),
distributed-guard benign cost, determinism. Live integration reproduced by
scripts/hn_multiagent_s2.js against the real HearthNet protocol + Dewey; these
guard the recorded artifacts' patterns.

FRAMING: a gap OUTSIDE the threat model even freshness-aware systems adopt -- never
'broke HearthNet'.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

RES = Path(__file__).resolve().parent.parent / "results"
S2 = RES / "multiagent_s2.csv"
COST = RES / "multiagent_guardcost.json"
DET = RES / "multiagent_determinism.json"


def _b(v):
    return str(v).strip().lower() in ("true", "1")


def _rows():
    if not S2.exists():
        pytest.skip("results/multiagent_s2.csv not present (run scripts/hn_multiagent_s2.js)")
    return {r["label"]: r for r in csv.DictReader(S2.open())}


def test_second_scenario_gap_generalizes():
    r = _rows()
    # benign: no false alarm when truly clear; control: alert fires on fresh smoke
    assert not _b(r["benign_natural"]["alert_fired"]) and not _b(r["benign_natural"]["violation"])
    assert _b(r["control_nodelay"]["alert_fired"]) and not _b(r["control_nodelay"]["violation"])
    # attack: same true state as control (smoke), only delay differs -> violation (missing alarm)
    assert _b(r["attack_delay"]["violation"])
    # commit-freshness satisfied during the attack (evening-scene command accepted by Dewey)
    assert _b(r["attack_delay"]["commit_freshness_satisfied"])
    # distributed guard closes the gap (fail-safe alert)
    assert _b(r["attack_guard"]["guard_blocked"]) and not _b(r["attack_guard"]["violation"])


def test_distributed_guard_benign_cost():
    if not COST.exists():
        pytest.skip("guardcost not present")
    c = json.loads(COST.read_text())
    assert c["extra_roundtrips_per_decision"] == 1
    assert c["benign_false_blocks"] == 0          # honest: zero benign false-blocks on the benign path
    assert c["challenge_latency_ms_p95"] < 50     # negligible on local MQTT


def test_determinism_n5_identical():
    if not DET.exists():
        pytest.skip("determinism not present")
    d = json.loads(DET.read_text())
    assert d["identical"] is True and d["n_runs"] == 5
