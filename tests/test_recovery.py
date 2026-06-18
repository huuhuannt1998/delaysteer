from delaysteer.config import Config
from delaysteer.planner.recovery_policy import (
    RecoveryAction,
    RecoveryPolicy,
    RecoveryState,
)


def test_proceed_when_confirmed_fresh():
    p = RecoveryPolicy(Config())
    assert p.next_action(confirmed=True, timed_out=False, state=RecoveryState()) is RecoveryAction.PROCEED


def test_ladder_retry_then_request_fresh_then_defer():
    p = RecoveryPolicy(Config(recovery_max_retries=1, allow_defer_arming=True))
    st = RecoveryState()
    a1 = p.next_action(confirmed=False, timed_out=True, state=st)
    a2 = p.next_action(confirmed=False, timed_out=True, state=st)
    a3 = p.next_action(confirmed=False, timed_out=True, state=st)
    assert [a1, a2, a3] == [
        RecoveryAction.RETRY,
        RecoveryAction.REQUEST_FRESH,
        RecoveryAction.DEFER_FALLBACK,
    ]


def test_no_defer_when_disallowed():
    p = RecoveryPolicy(Config(recovery_max_retries=0, allow_defer_arming=False))
    st = RecoveryState()
    a1 = p.next_action(confirmed=False, timed_out=True, state=st)  # request_fresh
    a2 = p.next_action(confirmed=False, timed_out=True, state=st)  # proceed (cautious)
    assert a1 is RecoveryAction.REQUEST_FRESH
    assert a2 is RecoveryAction.PROCEED


def test_timeout_boundary():
    p = RecoveryPolicy(Config(recovery_timeout_s=5.0))
    assert p.timed_out(request_time=0.0, arrival_time=None) is True
    assert p.timed_out(request_time=0.0, arrival_time=4.9) is False
    assert p.timed_out(request_time=0.0, arrival_time=5.1) is True
