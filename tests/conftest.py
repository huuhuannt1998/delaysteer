"""Collection guard for tests that import a live-Home-Assistant harness.

scripts/au1_event_wake.py reads the Home Assistant token from `.env` at import time, and both
it and tests/test_au1_event_wake.py are hash-pinned in results/au1_provenance.md, so neither is
edited to relax that. Without a `.env` (see README, "Home Assistant token") the test module is
left out of collection and the header says so, instead of the whole run erroring.
"""
from pathlib import Path

_ENV = Path(__file__).resolve().parent.parent / ".env"
collect_ignore = [] if _ENV.exists() else ["test_au1_event_wake.py"]


def pytest_report_header(config):
    if collect_ignore:
        return "no .env at the repo root: tests/test_au1_event_wake.py not collected (needs the HA token)"
    return None
