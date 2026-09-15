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
    "window_state": 2.0,        # E7
    "alarm_ready_state": 2.0,   # E7
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
    # Surfaced-staleness ablation (reviewer R2): annotate each belief the LLM sees
    # with an explicit age_s and a stale flag, plus a prompt clause telling the agent
    # to re-read or distrust stale evidence. Tests whether a capable planner SHOWN the
    # staleness still commits on a stale-but-truthful value (vs. the default harness,
    # which shows only raw timestamps). Off by default; the frozen results use False.
    surface_staleness: bool = False
    # Recovery-posture sweep (Experiment I, run_recovery_policy_sweep): text appended to
    # the family procedure to vary ONLY the recovery posture (defer / escalate / persist /
    # convenience) while holding the task, tools, and observation trace byte-identical.
    # Empty by default, so every previously-released result is unaffected.
    extra_procedure: str = ""

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
    # Challenge-response freshness (M1.1): at the commit revalidation, require the
    # critical fact to have been AFFIRMED after the action was proposed, i.e. value-age
    # (now - generation) <= heartbeat tolerance, separating staleness tolerance from the
    # transport budget. Defeats the adaptive under-budget replay at P-B; residual window
    # shrinks from the freshness budget to the sensor heartbeat.
    # NOTE: this compares timestamps and is NOT nonce-bound. It is defeated upstream of
    # the hub's stamping point, where the hub re-stamps a held frame at receipt (App. L).
    # The nonce-bound mechanism is defense/nonce_challenge.py (M1, Experiment E2).
    guard_challenge: bool = False
    # M1 nonce-bound affirmation (E2): "none" | "deployable" (round-trip bound only) |
    # "strong" (device-bound nonce echo). Only "strong" survives an upstream adversary.
    guard_nonce_tier: str = "none"
    nonce_rtt_bound_s: float = 0.25   # calibrated round-trip bound for the challenge
    # M2 joint-witness coherence (E3): bound on the measurement spread across the
    # critical facts of ONE multi-fact action, and whether a single challenge round is
    # required (the strong tier, which attests a common witness instant).
    guard_joint_witness: bool = False
    sigma_max_s: float = 0.5
    joint_witness_single_round: bool = False
    heartbeat_s: float = 0.25        # sensor affirmation cadence / challenge tolerance
    # Active-poll challenge (MA-9 Task 1): at the commit the guard FORCES a fresh read
    # (an explicit re-read/ping) so a pollable fact's value-age is bounded by the poll
    # round-trip, independent of the passive reporting cadence. Non-pollable (sleepy,
    # on-change-only) facts cannot be force-affirmed -> the guard fails closed. When
    # active, the challenge tolerance epsilon is poll_rtt_s, not heartbeat_s.
    guard_active_poll: bool = False
    poll_rtt_s: float = 0.05         # active-poll round-trip (affirmation) latency
    # Commit-time freshness anchoring (MA-9 Task 3): judge the challenge freshness as of
    # when the agent OBSERVED the fact, not at the commit, i.e. subtract the deliberation
    # window (observe -> commit) from the value-age. Removes benign false-blocks when a
    # real agent deliberates for seconds under the tiny heartbeat tolerance -- BUT trusting
    # the observe-time value reopens the delay attack if ground truth changes mid-deliberation
    # (an adversary cannot be excluded from the window). Kept as an ABLATION to demonstrate
    # that anchoring alone is unsafe; active-poll (fresh commit-time re-read) dominates it.
    guard_anchor_deliberation: bool = False
    # Source-ORDER witness (E4). Decides admission from a monotone counter minted at the
    # source rather than from an age, so its verdict is identical wherever the hold was
    # applied and no budget hides a short hold from it. Requires a TemporalGuard built
    # with order_witness=<OrderWitness>; see defense/order_witness.py for the residual.
    guard_order_witness: bool = False
