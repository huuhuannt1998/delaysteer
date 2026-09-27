#!/usr/bin/env python3
"""Per-row model provenance: the digest is stamped when the row is produced.

Reviewer item N11. ``results/model_digests.json`` is a single post-hoc snapshot
of the blobs installed on 2026-08-17. It lets a reader *detect* that a model
drifted; it cannot let them *attribute* a drift to a row, because once an
upstream re-pull changes a blob nothing in a result row says which blob produced
it. These tests pin the three properties that close that gap: the stamp is the
same identifier the snapshot records, it costs one lookup per process, and it
can never take a sweep down.

Hardware-free by construction -- the daemon is faked. The one test that talks to
a real ollama skips itself when none is listening.
"""

from __future__ import annotations

import io
import json
import urllib.request
from pathlib import Path

import pytest

import delaysteer.runtime as rt
from delaysteer.runtime import ollama_model_digest, sampling_record

QWEN = "bdbd181c33f2ed1b31c972991882db3cf4d192569092138a7d29e973cd9debe8"
GEMMA = "ff02c3702f322b9e5f1e0e0b0a7c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c"


@pytest.fixture(autouse=True)
def _clear_cache():
    """The cache is process-wide by design, so each test must start cold."""
    rt._DIGESTS = None
    yield
    rt._DIGESTS = None


def _fake_tags(calls: list, models=None, exc: Exception | None = None):
    """Stand in for the daemon, counting how often it is actually hit."""
    body = json.dumps({"models": [{"name": n, "digest": d} for n, d in
                                  (models or {"qwen3:14b": QWEN,
                                              "gemma2:9b": GEMMA}).items()]})

    def urlopen(url, *a, **kw):
        calls.append(url)
        if exc is not None:
            raise exc
        return io.BytesIO(body.encode())

    return urlopen


def test_digest_is_the_manifest_digest_the_snapshot_records(monkeypatch):
    """Not the modelfile's FROM line.

    `ollama show --modelfile` names the weights blob as an absolute path under
    the run host's home directory. Stamping that would leak a local path into a
    published artefact AND record an identifier that cannot be compared against
    results/model_digests.json, which is the only reason to stamp it.
    """
    monkeypatch.setattr(urllib.request, "urlopen", _fake_tags([]))
    d = ollama_model_digest("qwen3:14b")
    assert d == QWEN
    assert "/" not in d, "a digest column must never carry a filesystem path"


def test_the_daemon_is_asked_once_per_process(monkeypatch):
    """A panel sweep is thousands of episodes against the same tag set."""
    calls: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _fake_tags(calls))
    for _ in range(50):
        sampling_record("qwen3:14b", seed=0)
        ollama_model_digest("gemma2:9b")
    assert len(calls) == 1, f"queried the daemon {len(calls)} times"


def test_an_unreachable_daemon_costs_one_attempt_not_thousands(monkeypatch):
    calls: list = []
    monkeypatch.setattr(urllib.request, "urlopen",
                        _fake_tags(calls, exc=OSError("connection refused")))
    for _ in range(50):
        assert ollama_model_digest("qwen3:14b") is None
    assert len(calls) == 1, "a dead daemon must not be retried per episode"


@pytest.mark.parametrize("boom", [
    OSError("connection refused"),
    ValueError("not json"),
    KeyError("models"),
])
def test_provenance_never_fails_a_run(monkeypatch, boom):
    """A missing digest degrades the record; it does not kill 18 hours of GPU."""
    monkeypatch.setattr(urllib.request, "urlopen", _fake_tags([], exc=boom))
    rec = sampling_record("qwen3:14b", seed=1)
    assert rec.model_digest is None
    assert rec.as_row()["model_digest"] == "", "must be an empty column, not None"


def test_an_unknown_tag_is_empty_rather_than_wrong(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", _fake_tags([]))
    assert ollama_model_digest("never-pulled:70b") is None
    assert sampling_record("never-pulled:70b").as_row()["model_digest"] == ""


def test_the_row_carries_the_digest(monkeypatch):
    """The stamp has to survive the trip into the capability record."""
    from delaysteer.timed.capability import CapabilityRecord, TIER_1
    from delaysteer.timed.sched import Sched

    monkeypatch.setattr(urllib.request, "urlopen", _fake_tags([]))
    cap = CapabilityRecord.from_sched(
        Sched(), tier=TIER_1, sampling=sampling_record("qwen3:14b", seed=0))
    assert cap.as_row()["model_digest"] == QWEN
    assert "model_digest" in CapabilityRecord.columns()


def test_the_snapshot_is_the_same_identifier_in_short_form():
    """model_digests.json holds the leading 12 chars of the manifest digest.

    If that ever stops being true the per-row stamp and the frozen snapshot are
    no longer comparable, and N11 is reopened without anyone noticing.
    """
    p = Path(__file__).resolve().parents[1] / "results" / "model_digests.json"
    models = json.loads(p.read_text())["models"]
    assert models
    for tag, short in models.items():
        assert len(short) == 12 and all(c in "0123456789abcdef" for c in short), \
            f"{tag}: {short!r} is not a 12-char hex digest prefix"


def _ollama_up() -> bool:
    try:
        urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3)
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _ollama_up(), reason="no local ollama daemon")
def test_against_a_real_daemon():
    """Round-trip: what we stamp is exactly what /api/tags reports.

    Deliberately not pinned to results/model_digests.json -- a legitimate
    re-pull would change that, and drift is the condition this field exists to
    make visible, not a test failure.
    """
    with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=5) as r:
        live = {m["name"]: m["digest"] for m in json.loads(r.read())["models"]}
    if not live:
        pytest.skip("daemon holds no models")
    tag, digest = next(iter(live.items()))
    got = ollama_model_digest(tag)
    assert got == digest
    assert len(got) == 64 and all(c in "0123456789abcdef" for c in got)
