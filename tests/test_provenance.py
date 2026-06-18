"""The Temporal Provenance Monitor must record causal-influence edges."""

from delaysteer.provenance import TemporalProvenanceMonitor
from delaysteer.run_benign import run


def test_monitor_links_observation_to_decision():
    m = TemporalProvenanceMonitor("t", {})
    obs = m.record_observation("lock_state", "virtual_home", 0.0, 0.1, {"value": "locked"})
    dec = m.record_decision("response", "final_report", "agent", 0.2, 0.2,
                            {"secure": True}, causal_input_seqs=[obs.seq])
    assert {"cause": obs.seq, "effect": dec.seq, "relation": "observation_influences_decision"} in m.edges


def test_benign_run_emits_causal_graph(tmp_path):
    out = tmp_path / "trace.jsonl"
    run(home_kind="virtual", backbone="scripted", out=str(out))
    header, recs = TemporalProvenanceMonitor.load(out)

    edges = header["_edges"]
    assert edges, "expected causal-influence edges"

    # The final report must be causally linked to the lock/alarm observations
    # that justified the 'secure' claim.
    by_seq = {r["seq"]: r for r in recs}
    report_seq = next(r["seq"] for r in recs if r["kind"] == "response")
    causes = [e["cause"] for e in edges if e["effect"] == report_seq]
    assert causes, "final report has no causal antecedents"
    cause_types = {by_seq[c]["semantic_type"] for c in causes}
    assert {"lock_state", "alarm_state"} & cause_types
