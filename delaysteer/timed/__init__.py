"""Timed agentic execution model (consolidated research design, Stage 0).

The message envelope, the adversary scheduler, and deterministic replay. Kept in
its own package so the Sigma_1 machinery in `delaysteer/attack/` keeps working
unchanged while the Sigma_k substrate is built alongside it.
"""

from .envelope import FlowMinter, default_flow, MsgType

__all__ = ["FlowMinter", "default_flow", "MsgType"]
