"""Experiment H -- Independent Scenario Corpus: deterministic regression guard.

Locks the frozen-corpus scope invariants so the external-validity story cannot
silently drift, and asserts the honest annotations stay consistent with the
guard's live contract surface. All checks are deterministic (scripted reference
backbone; no LLM, no servers).
"""

from __future__ import annotations

from delaysteer.config import Config
from delaysteer.defense.contract_validator import default_registry
from delaysteer.defense.temporal_guard import REQUIRED
from delaysteer.run_external_corpus import (
    CSV_COLUMNS,
    build_corpus,
    compute_metrics,
    csv_row,
    evaluate_task,
)


def _corpus_and_verdicts():
    corpus = build_corpus()
    verdicts = {t.task_id: evaluate_task(t) for t in corpus}
    return corpus, verdicts


def test_corpus_shape_and_sources():
    corpus = build_corpus()
    assert len(corpus) == 18
    assert len({t.task_id for t in corpus}) == 18  # unique ids
    by_source = {}
    for t in corpus:
        by_source[t.source] = by_source.get(t.source, 0) + 1
    assert by_source == {"HA core blueprint": 4, "SimuHome family": 4,
                         "independent prompt": 10}


def test_scope_metrics_are_frozen():
    corpus, verdicts = _corpus_and_verdicts()
    m = compute_metrics(corpus, verdicts)
    # Honest scope headline: 10/18 have a delay-only surface; 8 non-applicable.
    assert m["n_surface"] == 10
    assert m["n_na"] == 8
    assert m["n_reference"] == 8 and m["n_external"] == 2
    # Deterministic reference: attack succeeds on every mapped task; guard covers 6,
    # leaves 2 uncovered (actions outside the shipped contract map).
    assert m["n_attack_success"] == 8
    assert m["n_guard_covered"] == 6
    assert m["n_guard_uncovered"] == 2


def test_verdict_semantics_are_consistent():
    corpus, verdicts = _corpus_and_verdicts()
    for t in corpus:
        v = verdicts[t.task_id]
        if not t.delay_attack_surface:
            assert v == {"attack_success": "n/a", "guard_coverage": "na",
                         "benign_completion": "n/a"}
        elif t.eval_mode == "external":
            assert v["attack_success"].endswith("(ext-server)")
            assert v["guard_coverage"].endswith("(ext-server)")
        else:  # in-repo deterministic reference
            assert v["attack_success"] == "yes"       # the delay attack lands
            assert v["benign_completion"] == "yes"     # benign task still completes
            # covered iff the high-impact action is in the shipped contract map.
            expected = "covered" if t.action_in_guard_contract else "uncovered"
            assert v["guard_coverage"] == expected


def test_uncovered_tasks_are_the_out_of_contract_actions():
    corpus, verdicts = _corpus_and_verdicts()
    uncovered = {t.task_id for t in corpus
                 if verdicts[t.task_id]["guard_coverage"] == "uncovered"}
    # disarm_alarm + open_cover are high-impact but outside temporal_guard.REQUIRED.
    assert uncovered == {"ind_presence_disarm", "ind_garage_car_arrival"}


def test_covered_tasks_map_to_real_guard_actions():
    corpus = build_corpus()
    for t in corpus:
        if t.action_in_guard_contract:
            assert t.guard_action in REQUIRED, t.task_id


def test_unsupported_fact_classes_are_truly_outside_guard_support():
    """Any fact class flagged unsupported must genuinely be outside the guard's set."""
    reg = default_registry(Config())
    supported = set(reg.canonical_entity)  # lock/contact/alarm/arrival/leak/occupancy
    corpus, verdicts = _corpus_and_verdicts()
    m = compute_metrics(corpus, verdicts)
    assert len(m["unsupported_fact_classes"]) >= 6
    for cls in m["unsupported_fact_classes"]:
        assert cls not in supported


def test_csv_row_has_exactly_the_spec_columns():
    corpus, verdicts = _corpus_and_verdicts()
    for t in corpus:
        row = csv_row(t, verdicts[t.task_id])
        assert list(row.keys()) == CSV_COLUMNS
        assert row["delay_attack_surface"] in ("yes", "no")


def test_evaluation_is_deterministic():
    _, v1 = _corpus_and_verdicts()
    _, v2 = _corpus_and_verdicts()
    assert v1 == v2
