"""Bootstrap a fresh Home Assistant container for the DelaySteer testbed.

Drives HA's REST onboarding flow to create a throwaway local owner account and
mint a refresh token, then saves config/ha_credentials.json for the adapter.
REST-only (no WebSocket long-lived token needed). Idempotent-ish: if the
instance is already onboarded and credentials exist, it just verifies them.

Usage:
  uv run python scripts/ha_bootstrap.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import httpx

BASE_URL = "http://localhost:8123"
CLIENT_ID = "http://localhost:8123/"
CREDS = Path(__file__).resolve().parents[1] / "config" / "ha_credentials.json"

USERNAME = "delaysteer"
PASSWORD = "delaysteer-lab-pw"  # throwaway local lab account


def wait_up(timeout: float = 300.0) -> None:
    print(f"waiting for {BASE_URL} ...", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(f"{BASE_URL}/api/onboarding", timeout=5)
            if r.status_code in (200, 404):
                print("HA is responding.")
                return
        except Exception:
            pass
        time.sleep(3)
    raise SystemExit("HA did not come up within timeout")


def onboarding_steps() -> list[dict]:
    r = httpx.get(f"{BASE_URL}/api/onboarding", timeout=10)
    if r.status_code != 200:
        return []
    return r.json()


def create_owner() -> str:
    r = httpx.post(
        f"{BASE_URL}/api/onboarding/users",
        json={
            "client_id": CLIENT_ID,
            "name": "DelaySteer",
            "username": USERNAME,
            "password": PASSWORD,
            "language": "en-US",
        },
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["auth_code"]


def exchange(auth_code: str) -> dict:
    r = httpx.post(
        f"{BASE_URL}/auth/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "client_id": CLIENT_ID,
        },
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def finalize(access_token: str) -> None:
    h = {"Authorization": f"Bearer {access_token}"}
    for step, body in [
        ("core_config", {}),
        ("analytics", {}),
        ("integration", {"client_id": CLIENT_ID, "redirect_uri": CLIENT_ID}),
    ]:
        try:
            r = httpx.post(f"{BASE_URL}/api/onboarding/{step}", headers=h, json=body, timeout=30)
            print(f"  onboarding/{step}: {r.status_code}")
        except Exception as e:  # tolerate — core API already works
            print(f"  onboarding/{step}: skipped ({e})")


def verify(refresh_token: str) -> None:
    r = httpx.post(
        f"{BASE_URL}/auth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": CLIENT_ID,
        },
        timeout=30,
    )
    r.raise_for_status()
    access = r.json()["access_token"]
    r2 = httpx.get(
        f"{BASE_URL}/api/states/lock.front_door",
        headers={"Authorization": f"Bearer {access}"},
        timeout=30,
    )
    if r2.status_code == 200:
        print(f"verify: lock.front_door state = {r2.json()['state']}")
    else:
        print(f"verify: lock.front_door not found yet (status {r2.status_code}) — "
              f"entities may still be loading.")


def main() -> int:
    wait_up()
    steps = onboarding_steps()
    user_done = any(s.get("step") == "user" and s.get("done") for s in steps)

    if user_done:
        if CREDS.exists():
            print("already onboarded; verifying saved credentials.")
            verify(json.loads(CREDS.read_text())["refresh_token"])
            return 0
        print(
            "HA already onboarded but no credentials saved. Remove the container "
            "volume (docker compose down -v) to re-bootstrap, or supply credentials.",
            file=sys.stderr,
        )
        return 1

    print("creating owner account ...")
    auth_code = create_owner()
    tok = exchange(auth_code)
    print("got tokens; finalizing onboarding ...")
    finalize(tok["access_token"])

    CREDS.parent.mkdir(parents=True, exist_ok=True)
    CREDS.write_text(
        json.dumps(
            {"base_url": BASE_URL, "client_id": CLIENT_ID, "refresh_token": tok["refresh_token"]},
            indent=2,
        )
    )
    print(f"saved credentials -> {CREDS}")
    # Give HA a moment to finish loading config entities, then verify.
    time.sleep(5)
    verify(tok["refresh_token"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
