from delaysteer.config import Config
from delaysteer.home.adapter import VirtualHomeAdapter
from delaysteer.home.clock import ManualClock
from delaysteer.home.virtual_home import ENTITIES, VirtualHome
from delaysteer.tools.registry import SchemaError, build_registry
from delaysteer.tools.router import AllowAllGate, GateDecision, ToolRouter


def _router():
    home = VirtualHome(ManualClock())
    adapter = VirtualHomeAdapter(home)
    return ToolRouter(build_registry(), adapter, Config()), home


def test_schema_rejects_unknown_param():
    router, _ = _router()
    try:
        router.call("query_device_state", {"bogus": 1})
        assert False, "expected SchemaError"
    except SchemaError:
        pass


def test_schema_requires_entity_id():
    router, _ = _router()
    try:
        router.call("query_device_state", {})
        assert False, "expected SchemaError"
    except SchemaError:
        pass


def test_enum_validation():
    router, _ = _router()
    try:
        router.call("arm_alarm", {"mode": "vacation"})
        assert False, "expected SchemaError for bad enum"
    except SchemaError:
        pass


def test_high_impact_action_passes_through_gate():
    seen = {}

    class RecordingGate(AllowAllGate):
        def evaluate(self, spec, args, context):
            seen["tool"] = spec.name
            return GateDecision(allow=True, reason="recorded")

    home = VirtualHome(ManualClock())
    router = ToolRouter(build_registry(), VirtualHomeAdapter(home), Config(), gate=RecordingGate())
    result = router.call("arm_alarm", {"mode": "night"})
    assert seen["tool"] == "arm_alarm"  # high-risk tool hit the gate
    assert result.gate.reason == "recorded"


def test_low_risk_skips_gate():
    router, _ = _router()
    result = router.call("verify_lock", {})
    assert result.gate.reason == "low-risk"


def test_freshness_deadline_stamped():
    router, _ = _router()
    result = router.call("verify_lock", {})
    obs = result.observation
    assert obs.semantic_type == "lock_state"
    assert obs.freshness_deadline == obs.generation_time + Config().freshness_s["lock_state"]
