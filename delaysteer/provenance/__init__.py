"""Temporal Provenance Monitor (proposal §5).

Records, for every observation, its generation time, arrival time, source,
semantic type, AND its downstream causal influence on the agent's decisions.
The causal edges are what let Phase 2 prove that a *specific delayed observation*
caused a *specific harmful plan branch*.
"""

from .monitor import TemporalProvenanceMonitor  # noqa: F401
