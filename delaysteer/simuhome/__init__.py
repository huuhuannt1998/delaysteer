"""SimuHome integration (MA-5): wrap the ICLR-2026 SimuHome benchmark
(arXiv 2509.24282) as an external CPS substrate to demonstrate that the
delay-only decision-steering MECHANISM and TemporalGuard generalize to a
benchmark we did not build, across appliance/environment domains.

SCOPE / FRAMING (binding, dec_01KVBER0BQJ01QT829MJEK20J2): SimuHome has no
security devices (no locks/contacts/alarms/access-control). A delay-only steer on
appliance/environment state is therefore an OPERATIONAL-SAFETY / CORRECTNESS
violation, NOT a security-invariant violation. SimuHome's role is mechanism
transfer / W3 generalization; the security-invariant headline stays on the
HA/SmartThings testbed. SimuHome violations are NEVER labelled security violations.

The delay layer is the SAME `DelayingAdapter` seam used by every other target;
SimuHomeAdapter is the HTTP-boundary wrapper (the direct analog of the
HA/SmartThings adapter), and generation_time comes from SimuHome's authoritative
virtual clock (/time), never from the adversary (SH-2).
"""
