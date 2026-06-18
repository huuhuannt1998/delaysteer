"""MA-6 regression check on the multi-agent (HearthNet) Phase-B result.

Asserts the recorded outcome pattern in results/multiagent.csv. The live
integration (real HearthNet protocol + Dewey over MQTT) is reproduced by
scripts/hn_multiagent.js; this guards the produced artifact's pattern so a
regression (or an accidental reframing) is caught.

FRAMING: SimuHome/HearthNet results are mechanism-transfer demonstrations of a
gap OUTSIDE the threat model even freshness-aware systems adopt -- never a claim
that HearthNet was 'broken'.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

CSV = Path(__file__).resolve().parent.parent / "results" / "multiagent.csv"


def _rows():
    if not CSV.exists():
        pytest.skip("results/multiagent.csv not present (run scripts/hn_multiagent.js against live Dewey)")
    return {r["label"]: r for r in csv.DictReader(CSV.open())}


def _b(v):
    return str(v).strip().lower() in ("true", "1")


def test_benign_baseline_completes_correctly():
    r = _rows()["benign_natural"]
    # hub heats when the user is truly present; no violation -> the scenario is not rigged to fail
    assert _b(r["heating"]) and not _b(r["violation"])


def test_delay_only_steers_inter_agent_observation():
    rows = _rows()
    # same true state (user away); only the delay differs: control safe, delayed -> violation
    assert not _b(rows["control_nodelay"]["violation"])
    assert _b(rows["attack_delay"]["violation"])


def test_commit_freshness_satisfied_while_evidence_stale():
    # the precise gap: Dewey accepted the command (base_commit/lease valid) while the
    # decision rode a stale observation
    r = _rows()["attack_delay"]
    assert _b(r["commit_freshness_satisfied"]) and _b(r["evidence_freshness_violated"])


def test_distributed_temporalguard_closes_the_gap():
    r = _rows()["attack_guard"]
    assert _b(r["guard_blocked"]) and not _b(r["violation"])
