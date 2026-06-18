"""Phase 2 — the delay-only adversary.

The adversary may ONLY delay (or briefly withhold) selected observations on
selected channels; it never modifies payloads, forges values, or controls
devices. The Delay Injection Layer sits at the HomeAdapter seam (proposal §5,
Figure 1).
"""

from .delay_layer import DelayingAdapter, DelaySpec  # noqa: F401
from .profiles import (  # noqa: F401
    BurstDelay,
    DelayProfile,
    FixedDelay,
    Jitter,
    LateArrivingContradiction,
    TimeoutCrossing,
)
