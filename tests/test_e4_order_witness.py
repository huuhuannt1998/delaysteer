"""E4 -- the source-order witness: classification, the commit predicate, and the gate.

The three observable cases must stay separated. A gap is loss and must NOT block; an
inversion is a held frame released after a later one and MUST block; and the two
order-preserving holds the paper names as residuals must be admitted, because claiming
otherwise would overstate what an order check can see.
"""
from __future__ import annotations

import pytest

from delaysteer.config import Config
from delaysteer.defense import TemporalGuard, apply_ablation
from delaysteer.defense.order_witness import OrderEvent, OrderWitness
from delaysteer.home.adapter import VirtualHomeAdapter
from delaysteer.home.clock import ManualClock
from delaysteer.home.virtual_home import ENTITIES, VirtualHome
from delaysteer.tools.registry import build_registry

SRC = "binary_sensor.test_contact"


def observe_all(seqs):
    w = OrderWitness()
    events = [w.observe(SRC, s) for s in seqs]
    return w, events


def test_in_order_is_admitted():
    w, events = observe_all([1, 2, 3, 4])
    assert all(e is OrderEvent.IN_ORDER for e in events)
    assert w.admit([SRC])[0] is True


def test_forward_gap_is_loss_not_inversion():
    """N, N+2: frames were lost. Order is intact, so the witness must admit."""
    w, events = observe_all([1, 2, 4, 5])
    assert events[2] is OrderEvent.GAP
    assert not any(e is OrderEvent.INVERSION for e in events)
    admitted, reason = w.admit([SRC])
    assert admitted is True, reason
    assert w.sources[SRC].gaps == 1


def test_selective_hold_is_an_inversion_and_blocks():
    """The held frame arrives after a later one: the attack signature."""
    w, events = observe_all([1, 2, 4, 3])
    assert events[3] is OrderEvent.INVERSION
    admitted, reason = w.admit([SRC])
    assert admitted is False
    assert "ORDER INVERSION" in reason


def test_order_preserving_suffix_hold_is_the_residual():
    """A blanket/suffix hold releases in order, so nothing inverts. Stated, not hidden."""
    w, events = observe_all([1, 2, 3, 4, 5])  # released late, but in order
    assert not any(e is OrderEvent.INVERSION for e in events)
    assert w.admit([SRC])[0] is True


def test_duplicate_is_not_an_inversion():
    w, events = observe_all([1, 2, 2, 3])
    assert events[2] is OrderEvent.DUPLICATE
    assert w.admit([SRC])[0] is True


def test_admission_is_per_source():
    w = OrderWitness()
    for s in [1, 2, 4, 3]:
        w.observe("a", s)
    for s in [1, 2, 3]:
        w.observe("b", s)
    assert w.admit(["b"])[0] is True
    assert w.admit(["a"])[0] is False
    assert w.admit(["a", "b"])[0] is False


def test_clear_consumes_open_inversions():
    w, _ = observe_all([1, 2, 4, 3])
    assert w.admit([SRC])[0] is False
    w.clear([SRC])
    assert w.admit([SRC])[0] is True
    assert w.sources[SRC].inversions == 1  # the count is history, not state


def test_unknown_source_admits():
    """A fact with no counter evidence is not evidence of an inversion."""
    assert OrderWitness().admit(["binary_sensor.never_seen"])[0] is True


@pytest.mark.parametrize("seqs,expect_allow", [([1, 2, 4, 3], False), ([1, 2, 4, 5], True)])
def test_guard_blocks_on_inversion_and_allows_on_loss(seqs, expect_allow):
    """End to end through the real gate in the 'counter' ablation."""
    home = VirtualHome(ManualClock())
    home.close_door()
    home.services.call("lock", "lock", {"entity_id": ENTITIES["lock"]})
    cfg = Config()
    apply_ablation(cfg, "counter")
    witness = OrderWitness()
    for s in seqs:
        witness.observe(ENTITIES["contact"], s)
    guard = TemporalGuard(VirtualHomeAdapter(home), cfg, order_witness=witness)
    decision = guard.evaluate(build_registry().get("arm_alarm"), {}, {})
    assert bool(decision.allow) is expect_allow
    if not expect_allow:
        assert "ORDER INVERSION" in decision.reason


def test_witness_is_inert_without_the_flag():
    """Every existing call site keeps its behaviour: no flag, no order check."""
    home = VirtualHome(ManualClock())
    home.close_door()
    home.services.call("lock", "lock", {"entity_id": ENTITIES["lock"]})
    cfg = Config()
    apply_ablation(cfg, "full")           # NOT 'counter'
    witness = OrderWitness()
    for s in [1, 2, 4, 3]:                # an inversion the guard must ignore
        witness.observe(ENTITIES["contact"], s)
    guard = TemporalGuard(VirtualHomeAdapter(home), cfg, order_witness=witness)
    assert guard.evaluate(build_registry().get("arm_alarm"), {}, {}).allow is True
