#!/usr/bin/env python3
"""Single source of truth for the sampling regime.

Stage 0 of the consolidated research design
(``manuscripts/feedback/DelaySteer_Research_Design_Detailed.md``) requires a
seeded, temperature-0, bit-reproducible substrate: with model, decoding seed and
temperature fixed at 0, the agent policy is a deterministic function of the
delivered history, and that is what makes per-seed reachability *exact* while
keeping a real agent in the loop.

Why this module exists
----------------------
Until 2026-08-14 the repository declared temperature 0.0 in exactly two places --
``config.py`` (``# determinism for causal replay``) and ``agentkit.run_agent`` --
and then overrode it to 0.7 at ~25 call sites. The stated default was therefore
dead code: *every* language-model result in the paper was sampled, while the
config claimed determinism. The two regimes were never distinguished in an
output file, so a reader could not tell which one produced a number.

The design does not ask us to throw the sampled runs away. Challenge 1 says:
"seeded temp-0 exact reachability (Alg. 1, 2) plus resampling for robustness
(Alg. 5); report both." So both regimes are legitimate -- they answer different
questions, and the requirement is that every result declares which one it is.

  EXACT      temperature == 0. The Stage 0 substrate. Licenses reachability
             claims, exact enumeration, per-release necessity, and any statement
             of the form "no feasible single delay reaches this".
  RESAMPLED  temperature > 0. The robustness arm. Licenses *rate* claims with
             intervals, and nothing about reachability.

Resolution order: explicit argument > ``DELAYSTEER_TEMPERATURE`` > 0.0.

So the historical sampled campaigns are reproducible with

    DELAYSTEER_TEMPERATURE=0.7 .venv/bin/python -m delaysteer.run_e9_...

while a bare invocation now gets the deterministic substrate.
"""

from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass, asdict
from typing import Any

EXACT = "exact"
RESAMPLED = "resampled"

_ENV = "DELAYSTEER_TEMPERATURE"


def resolve_temperature(explicit: float | None = None) -> float:
    """Return the temperature this run should use.

    ``explicit`` wins so a harness can still pin a regime deliberately (a
    resampling sweep legitimately asks for >0). Otherwise the environment may
    override, and the floor is the deterministic default.
    """
    if explicit is not None:
        return float(explicit)
    raw = os.environ.get(_ENV)
    if raw is None or not raw.strip():
        return 0.0
    try:
        return float(raw)
    except ValueError as exc:                       # loud, not silently 0.0 --
        raise ValueError(                           # a typo here would silently
            f"{_ENV}={raw!r} is not a number"       # change the paper's regime
        ) from exc


def regime(temperature: float) -> str:
    """Which claim class this temperature licenses."""
    return EXACT if temperature == 0.0 else RESAMPLED


_TAGS_URL = "http://localhost:11434/api/tags"
_DIGESTS: dict[str, str] | None = None       # per-process cache; see below


def _ollama_digests() -> dict[str, str]:
    """Tag -> manifest digest for every model the local daemon holds.

    Resolved once per process. A panel sweep is thousands of episodes and the
    installed tag set does not change underneath a run, so a lookup per episode
    would be pure overhead against the same daemon that is busy doing the
    inference. A failure is cached too: if the daemon cannot be reached the
    first time, retrying on every episode would pay the timeout thousands of
    times over to keep failing.
    """
    global _DIGESTS
    if _DIGESTS is None:
        try:
            with urllib.request.urlopen(_TAGS_URL, timeout=5) as r:
                payload = json.loads(r.read())
            _DIGESTS = {m["name"]: m["digest"] for m in payload.get("models", [])
                        if m.get("name") and m.get("digest")}
        except Exception:                    # unreachable, malformed, anything
            _DIGESTS = {}
    return _DIGESTS


def ollama_model_digest(model: str) -> str | None:
    """The model's content digest, so a replay can be pinned to it.

    Seeding ollama does not by itself buy reproducibility across a model pull or
    a server upgrade; the digest is what makes "same model" checkable later.
    Returns None rather than raising when ollama is absent -- a missing digest
    should degrade the capability record, not kill the run.

    Why the HTTP tag list and not `ollama show --modelfile`
    ------------------------------------------------------
    The modelfile's FROM line names the *weights blob* on disk, as an absolute
    path under the run host's home directory. That is the wrong identifier for
    a results column twice over: it leaks a local path into a published
    artefact, and it is not the digest `ollama list` reports, so a stamped row
    could not be compared against ``results/model_digests.json`` -- which is
    the whole point of stamping it. /api/tags returns the manifest digest, of
    which that file's short form is the leading 12 characters.
    """
    return _ollama_digests().get(model) or None


@dataclass(frozen=True)
class SamplingRecord:
    """The part of the capability record that describes decoding.

    Attached to every emitted row so a number can never be read without its
    regime. ``regime`` is derived rather than passed, so it cannot disagree with
    the temperature that actually ran.
    """

    model: str
    temperature: float
    seed: int | None
    model_digest: str | None = None

    @property
    def regime(self) -> str:
        return regime(self.temperature)

    @property
    def exact(self) -> bool:
        return self.regime == EXACT

    def as_row(self) -> dict[str, Any]:
        """Flat columns for a results CSV."""
        return {
            "model": self.model,
            "temperature": self.temperature,
            "seed": self.seed,
            "sampling_regime": self.regime,
            "model_digest": self.model_digest or "",
        }

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["sampling_regime"] = self.regime
        return d


def sampling_record(model: str, seed: int | None = None,
                    temperature: float | None = None,
                    with_digest: bool = True) -> SamplingRecord:
    """Build the record for a run, resolving the temperature per the order above.

    The digest is resolved here, at run time, rather than swept up afterwards.
    A single post-hoc snapshot of the installed blobs (``results/model_digests
    .json``) lets a reader *detect* that a model drifted but not *attribute* a
    drift to a row: once an upstream re-pull changes a blob, nothing in a row
    says which blob produced it. Stamping each row closes that gap. Resolution
    is cached per process and degrades to None, so it costs one localhost call
    per run and can never fail a sweep.
    """
    t = resolve_temperature(temperature)
    return SamplingRecord(
        model=model, temperature=t, seed=seed,
        model_digest=ollama_model_digest(model) if with_digest else None,
    )


def add_temperature_arg(ap) -> None:
    """Standard CLI flag. Default None so the env var can still speak."""
    ap.add_argument(
        "--temperature", type=float, default=None,
        help=(f"decoding temperature; default 0.0 (exact/Stage-0 substrate). "
              f"Set >0 for the resampling arm, or export {_ENV}."),
    )


def banner(rec: SamplingRecord) -> str:
    """One line for a harness to print, so the regime is visible in the log."""
    tag = "EXACT (deterministic substrate)" if rec.exact else "RESAMPLED (robustness arm)"
    return (f"regime={rec.regime}  temperature={rec.temperature}  "
            f"model={rec.model}  seed={rec.seed}  -- {tag}")
