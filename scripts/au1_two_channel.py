#!/usr/bin/env python3
"""AU1 under a two-channel hold (results/au1_two_channel_plan.md).

Runs the UNCHANGED AU1 harness, scripts/au1_event_wake.py, whose sha256 is pinned in
results/au1_provenance.md and is checked here before anything runs. The one difference is in the
adversary: when the harness arms its single-entity re-serve of the door contact -- which it does
while the door is still closed -- this wrapper also arms the proxy's opt-in two-channel hold for
the contact and the testbed's ground-truth helper, so the bulk GET /api/states carries their
pre-open records as well. Takes the harness's own arguments; run under Hermes's python:

  $HERMES_HOME/.venv/bin/python scripts/au1_two_channel.py --arm attack --policy entity \
      --seed 1 --n 20 --timeout 1800 --out results/au1_two_channel.jsonl
"""
import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "scripts" / "au1_event_wake.py"
PINNED_SHA256 = "f8b1ebaa02920fe3ef7d067419e81546307142c1f887f2288866d87a02ee9d3e"

got = hashlib.sha256(HARNESS.read_bytes()).hexdigest()
if got != PINNED_SHA256:
    raise SystemExit(f"AU1 harness changed since it was pinned: {got}")

_spec = importlib.util.spec_from_file_location("au1_event_wake", HARNESS)
au1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(au1)

HELD = [au1.DOOR, au1.DOOR_GT]          # the contact and the testbed helper that drives it
_proxy_ctl = au1.proxy_ctl


def proxy_ctl(op: str, **body) -> None:
    _proxy_ctl(op, **body)
    if op == "arm" and body.get("path") == au1.STALE_PATH:
        # stage() arms the single-entity re-serve before it opens the door, so both records
        # captured here are the authentic pre-open ones.
        _proxy_ctl("hold_entities", entities=HELD)


au1.proxy_ctl = proxy_ctl

if __name__ == "__main__":
    sys.exit(au1.main())
