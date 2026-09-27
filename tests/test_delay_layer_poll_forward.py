"""The guard's active-poll request and the delay layer."""
from delaysteer.attack.delay_layer import DelayingAdapter


class _Inner:
    clock = object()


def test_default_does_not_forward_so_recorded_runs_reproduce():
    inner = _Inner()
    d = DelayingAdapter(inner, [])
    d.active_poll = True
    assert d.active_poll is True and not hasattr(inner, "active_poll")


def test_opt_in_forwards_set_and_clear():
    inner = _Inner()
    d = DelayingAdapter(inner, [])
    d.forward_active_poll = True
    d.active_poll = True
    assert inner.active_poll is True
    d.active_poll = False
    assert inner.active_poll is False
