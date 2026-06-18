"""Testbed configuration.

All knobs that later phases will sweep live here so the benign baseline and the
adversarial runs share one config surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Default freshness requirements (seconds) by semantic observation type.
# Phase 1 RECORDS these on every tool/observation but does NOT enforce them —
# enforcement is TemporalGuard's job in Phase 4. They are calibrated later from
# benign latency distributions (see Research Protocol jrn_01KSTTG7XSNAQWY9S6PPTT483Y).
DEFAULT_FRESHNESS_S: dict[str, float] = {
    "lock_state": 2.0,
    "contact_state": 2.0,
    "alarm_state": 2.0,
    "occupancy": 5.0,
    "arrival": 5.0,
    "leak_state": 5.0,
    "generic_state": 5.0,
    "actuation_ack": 2.0,
    "confirmation_context": 2.0,
}


@dataclass
class Config:
    # --- planner backbone (PI-approved: local default, hosted switch) ---
    backbone: str = "scripted"  # scripted | ollama | anthropic
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    anthropic_model: str = "claude-opus-4-8"
    temperature: float = 0.0  # determinism for causal replay (A5)
    seed: int = 0
    # Which family procedure an LLM backbone follows (bedtime | access |
    # confirmation | automation). Scenario wiring for the single ReAct loop —
    # the planner is unchanged; only the prompt's procedure section varies.
    llm_family: str = "bedtime"

    # --- recovery policy (benign default; documented timeout boundary) ---
    recovery_timeout_s: float = 5.0  # lock-verification timeout boundary
    recovery_max_retries: int = 1    # "retry once"
    allow_defer_arming: bool = True  # lower-friction fallback if unconfirmed
    # Fail-open policy: on defer, report best-effort "secured" anyway (the
    # vulnerable agent of proposal §7). Conservative policy (False) reports
    # NOT secure when it defers.
    fail_open: bool = False

    # --- simulated platform latency (benign; Phase-2 delay layer adds to this) ---
    base_latency_s: float = 0.05

    # --- planner loop ---
    max_react_steps: int = 24

    # --- freshness requirements (recorded in Phase 1; ENFORCED by TemporalGuard) ---
    freshness_s: dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_FRESHNESS_S)
    )

    # --- TemporalGuard (Phase 4 / RQ4) ---
    # ablation presets set these: provenance-only / freshness / twophase / full.
    guard_enabled: bool = False      # False => AllowAllGate (no defense)
    guard_block: bool = True         # False => monitor-only (label, don't block)
    guard_freshness: bool = True     # enforce per-fact freshness contracts
    guard_two_phase: bool = True     # revalidate critical fact VALUES before commit
    guard_antithrash_max: int = 3    # max blocked high-impact attempts before escalation
    # Challenge-response (nonce) freshness (M1.1): at the commit revalidation,
    # require the critical fact to have been AFFIRMED after the action was proposed,
    # i.e. value-age (now - generation) <= heartbeat tolerance, separating staleness
    # tolerance from the transport budget. Defeats the adaptive under-budget replay;
    # residual window shrinks from the freshness budget to the sensor heartbeat.
    guard_challenge: bool = False
    heartbeat_s: float = 0.25        # sensor affirmation cadence / challenge tolerance
