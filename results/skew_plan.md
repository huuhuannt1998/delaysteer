# Skew sweep on the attested relay — analysis plan (fixed before any run)

Written 2026-09-26, before the harness existed. No skew row has been seen.

## Why
Round-2 meta-review, A-W3: Thm. 1's residual is α + s, with s the inter-clock skew. The paper never
measures s, and Attested runs end to end only on one clock. The claim we can test without new hardware
is how s enters on the *implementation*: in the direction and magnitude the theorem says, or not.

## Substrate
The E2 least-privilege relay (`delaysteer/attack/lp_relay.py`) on its in-process ACL-enforcing broker.
Device publisher signs (value, seq, t_m); relay holds no key; hub verifies MAC and seq order.
`RelayHomeAdapter` serves `generation_time = t_m`, so the guard's age `arrival − generation` is the
Attested witness. There is no model: the endpoint is the guard's admission decision at revalidation
(`TemporalGuard._reval_problems` over the `arm_alarm` contract, preset `freshness`: contact budget
Δ = 2 s, lock budget per config).

The only change to the code is an opt-in `clock_offset_s` on `DevicePublisher` (default 0, so every
earlier run is unchanged). With it, t_m = true time + s: s > 0 is a device clock that leads the hub, and
s < 0 is one that lags.

## Cells
- s ∈ {−3, −1, 0, +1, +3} s.
- **honest** (n=10 per s): the door is closed and the lock is locked, with no hold. The guard revalidates after a
  random 0–1 s phase. Endpoint `admitted` (liveness).
- **attack** (n=10 per s × h): the door closed at start, then opens at t_x. From t_x the relay holds every
  message of the contact flow (`hold_entity`, 60 s, so nothing after the open arrives). The guard
  revalidates at t_c = t_x + h, with h ∈ {1, 2, 3, 4, 5, 6} s. Endpoint `admitted`: an unsafe admission, since
  the door is truly open.
- Recorded per trial:
  - t_x, t_c, and the cached contact t_m;
  - φ = t_x − (t_m − s), the phase of the last closed report before the open;
  - the age the guard computed, and the guard's problem strings.

## Predictions (Thm. 1 at α = Δ = 2 s)
1. **Soundness.** Every admitted attack trial has t_c − t_x < Δ + s, up to a scheduling tolerance of
   0.1 s. One violation falsifies the implementation's match to the theorem.
2. **Direction.** The admitted-hold boundary moves one-for-one with s. A leading device clock widens the window to
   Δ + s − φ; a lagging one narrows it.
3. **Honest cost.** For s < −(Δ − heartbeat) (here s = −3), honest readings age past the budget and are
   blocked: the lag is paid as liveness, not as safety.
4. **Future stamps.** For s > 0, honest ages can be negative. The shipped guard checks only
   `age > budget`, so it admits a future-dated reading. This is recorded, not changed.

## Analysis
- Per s, the largest admitted h and the smallest blocked h.
- Per cell, admitted k/n with a Wilson 95% interval.
- The count of soundness violations.
- A fitted slope is not claimed with 5 offsets and 1 s hold steps. We report the boundary table and whether it
  tracks Δ + s within one hold step.

## Scope (stated in the paper)
The skew is injected, one host, in-process broker. It measures how the implementation consumes s, not
what s a real deployment has. The deployment requirement that follows: the residual widens by the
device's clock lead, so the lead must be bounded (e.g., by time synchronization) well below the budget.
