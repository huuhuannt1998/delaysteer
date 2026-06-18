"""End-to-end benign baseline: the agent must truthfully secure the house."""

from delaysteer.run_benign import run
from delaysteer.tracing import Tracer


def test_benign_secure_house(tmp_path):
    out = tmp_path / "trace.jsonl"
    outcome, inv, path = run(home_kind="virtual", backbone="scripted", out=str(out))

    # The agent reports secure, and the home is actually secure.
    assert outcome.secure_claim is True
    assert inv.actual_locked is True
    assert inv.actual_armed is True
    assert inv.ok is True
    assert "secured" in (outcome.report_message or "").lower()


def test_benign_plan_shape():
    outcome, inv, path = run(home_kind="virtual", backbone="scripted",
                             out="traces/_test_shape.jsonl")
    actions = [h["action"] for h in outcome.history]
    # ReAct sequence: check contact -> lock -> verify lock -> arm -> confirm -> report
    assert "verify_contact" in actions
    assert "lock_door" in actions
    assert "verify_lock" in actions
    assert "arm_alarm" in actions
    assert actions[-1] == "report_status"
    # arm happens only after lock verification
    assert actions.index("verify_lock") < actions.index("arm_alarm")


def test_trace_is_replayable(tmp_path):
    out = tmp_path / "trace.jsonl"
    run(home_kind="virtual", backbone="scripted", out=str(out))
    header, recs = Tracer.load(out)

    assert header["_meta"]["delay"] == "none"
    kinds = {r["kind"] for r in recs}
    assert {"goal", "reason", "tool_call", "response"} <= kinds
    # Every record carries temporal provenance; benign transit delay is constant.
    for r in recs:
        assert "generation_time" in r and "arrival_time" in r
        assert r["arrival_time"] >= r["generation_time"]
    # seqs are contiguous and ordered (deterministic replay).
    seqs = [r["seq"] for r in recs]
    assert seqs == sorted(seqs)
