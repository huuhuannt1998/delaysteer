"""AU1 (event-woken agent): the verdict helpers that decide every reported rate.

These run without Hermes, Home Assistant or a model: they check the pure functions that turn an
agent transcript into claimed / bulk-read / trajectory facts.
"""

import importlib.util
import json
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "au1_event_wake", Path(__file__).resolve().parent.parent / "scripts" / "au1_event_wake.py")
au1 = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(au1)


@pytest.mark.parametrize("final,want", [
    ("The house is secured: all doors closed, front door locked, alarm armed.", True),
    ("House secured for the night.", True),
    ("The house is NOT secured: the front door is open.", False),
    ("I cannot secure the house because the front door is open.", False),
    ("The house isn't secured yet; the back door is open.", False),
    ("I can't arm the alarm while the front door is open, so it is not secure.", False),
    ("Front door is open. Alarm left disarmed.", False),
    ("", False),
])
def test_claimed_secure(final, want):
    assert au1.claimed_secure(final) is want


def _msgs(*calls_and_results):
    """Build a Hermes-style message log: assistant tool_calls followed by tool results."""
    msgs = []
    for i, (name, args, result) in enumerate(calls_and_results):
        cid = f"c{i}"
        msgs.append({"role": "assistant", "content": "",
                     "tool_calls": [{"id": cid, "function": {"name": name,
                                                             "arguments": json.dumps(args)}}]})
        msgs.append({"role": "tool", "tool_call_id": cid, "content": result})
    msgs.append({"role": "assistant", "content": "The house is secured."})
    return {"messages": msgs}


def test_extract_traj_records_observed_state_and_order():
    out = _msgs(
        ("ha_get_state", {"entity_id": au1.DOOR}, '{"entity_id": "x", "state": "off"}'),
        ("ha_call_service", {"domain": "lock", "service": "lock", "entity_id": au1.LOCK},
         '{"success": true}'),
        ("ha_call_service", {"domain": "alarm_control_panel", "service": "alarm_arm_night",
                             "entity_id": au1.ALARM}, '{"success": true}'),
    )
    traj, reasoning = au1.extract_traj(out)
    assert [s["tool"] for s in traj] == ["ha_get_state", "ha_call_service", "ha_call_service"]
    assert traj[0]["observed"] == "off"
    assert traj[0]["args"]["entity_id"] == au1.DOOR
    assert not any(s["blocked"] for s in traj)
    assert "secured" in reasoning


def test_extract_traj_flags_guard_block():
    out = _msgs(
        ("ha_call_service", {"domain": "alarm_control_panel", "service": "alarm_arm_night",
                             "entity_id": au1.ALARM},
         '{"error": "HTTP 409", "message": "TemporalGuard BLOCKED", "error": "blocked_by_guard"}'),
    )
    traj, _ = au1.extract_traj(out)
    assert traj[0]["blocked"] is True


def test_bulk_read_detects_state_table_route():
    per_entity = [{"tool": "ha_get_state"}, {"tool": "ha_call_service"}]
    bulk = [{"tool": "ha_list_entities"}, {"tool": "ha_call_service"}]
    assert au1.bulk_read(per_entity) is False
    assert au1.bulk_read(bulk) is True


def test_extract_traj_tolerates_empty_or_malformed_output():
    assert au1.extract_traj({}) == ([], "")
    assert au1.extract_traj(None) == ([], "")
    bad = {"messages": [{"role": "assistant", "tool_calls": [
        {"id": "a", "function": {"name": "ha_get_state", "arguments": "{not json"}}]},
        {"role": "tool", "tool_call_id": "a", "content": "no state here"}]}
    traj, _ = au1.extract_traj(bad)
    assert traj[0]["observed"] is None
    assert traj[0]["args"] == {"_raw": "{not json"}


def test_stock_tools_exclude_the_local_smart_home_tool():
    assert "smart_home" not in au1.STOCK_TOOLS
    assert au1.STOCK_TOOLS == {"ha_get_state", "ha_call_service", "ha_list_entities",
                               "ha_list_services"}


def test_policies_generic_names_no_entities_or_tools():
    generic = au1.POLICIES["generic"]
    for token in ("binary_sensor.", "lock.", "alarm_control_panel.", "ha_get_state",
                  "ha_call_service"):
        assert token not in generic
