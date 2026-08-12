#!/usr/bin/env python3
"""Refresh the demo's Home Assistant access tokens (manual, button-driven).

Why this exists
---------------
The demo stack authenticates to Home Assistant from two places, each with its own
copy of ``HASS_TOKEN``:

  * DelaySteer   -- ``.env``            (proxy :8125, monitor :9120, all scripts)
  * Hermes agent -- ``~/.hermes/.env``  (the chat's ``ha_get_state`` / ``ha_call_service``)

Home Assistant issues two very different kinds of bearer token, and mixing them up is
what breaks the demo mid-run:

  long-lived access token (LLAT)   ~3650 days   minted in HA Profile -> Security
  OAuth access token               1800 s       minted from a stored refresh_token

A 30-day token had been installed for Hermes and silently expired, so the agent's
second ``ha_get_state`` returned **401 Unauthorized** and it refused to continue --
while DelaySteer's own calls kept working on its 10-year LLAT. That asymmetry is the
failure this script exists to prevent.

What it does
------------
1. Reads every target's current token and decodes its JWT ``exp`` (no network needed).
2. Picks the best source token: the **longest-lived token that actually authenticates
   against live HA**. If none does, it mints a fresh one from the refresh_token in
   ``config/ha_credentials.json``.
3. Writes that token only into targets that are expired, expiring soon, missing, or
   already broken -- and **never downgrades** a longer-lived working token to a
   shorter-lived one.
4. Re-validates every target against live HA and reports the verdict.

SmartThings is deliberately OUT OF SCOPE and is never read, written, or refreshed --
its credential is a rotating OAuth grant whose refresh invalidates the prior token,
so an unattended rewrite can lock the account out of the frozen SmartThings results.
It is reported as ``skipped`` and left exactly as-is.

Token VALUES are never printed, logged, or included in JSON output -- only lengths,
expiry timestamps, and pass/fail verdicts.

  python scripts/refresh_tokens.py            # refresh what needs it
  python scripts/refresh_tokens.py --check    # report only, write nothing
  python scripts/refresh_tokens.py --force    # refresh even if current tokens are fine
  python scripts/refresh_tokens.py --json     # machine-readable (used by the :9120 button)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import stat
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DS_ENV = ROOT / ".env"
HERMES_ENV = Path.home() / ".hermes" / ".env"
CREDS = ROOT / "config" / "ha_credentials.json"
HA_DIRECT = "http://localhost:8123"

# A token with less than this much life left is refreshed proactively, so it cannot
# expire in the middle of a demo. 24h comfortably covers any single session.
MIN_REMAINING_S = 24 * 3600

# Probed to confirm a token really works. The back door is the entity whose 401
# stopped the agent, so it is the honest check.
PROBE = "/api/states/binary_sensor.back_door_contact"

_KV = re.compile(r"^\s*(?:export\s+)?([A-Z_0-9]+)\s*=\s*(.*)$")


# --------------------------------------------------------------------------- env I/O

def read_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        m = _KV.match(line)
        if m:
            out[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    return out


def write_env_key(path: Path, key: str, value: str) -> None:
    """Replace (or append) one key, preserving every other line, atomically.

    Written via a temp file in the same directory + ``os.replace`` so a crash can never
    leave a half-written .env -- which would take out the whole demo stack. Permissions
    are carried over from the original (or 0600 for a new file): these files hold
    bearer tokens and are gitignored.
    """
    lines = path.read_text().splitlines() if path.exists() else []
    replaced = False
    for i, line in enumerate(lines):
        m = _KV.match(line)
        if m and m.group(1) == key:
            lines[i] = f"{key}={value}"
            replaced = True
            break
    if not replaced:
        lines.append(f"{key}={value}")

    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".env.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


# ------------------------------------------------------------------------ token facts

def jwt_exp(token: str) -> tuple[int | None, int | None]:
    """Return (issued_at, expires_at) from a JWT payload, or (None, None).

    Local decode only -- no signature check and no network. We are reading HA's own
    token to schedule a refresh, not authenticating anyone with it.
    """
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        payload = json.loads(base64.urlsafe_b64decode(part))
        return payload.get("iat"), payload.get("exp")
    except Exception:
        return None, None


def probe(token: str) -> tuple[bool, str]:
    """Does this token actually authenticate against live HA right now?

    The JWT ``exp`` says when HA *intended* the token to die; only a real call proves
    it has not also been revoked from the Profile page.
    """
    if not token:
        return False, "absent"
    req = urllib.request.Request(HA_DIRECT + PROBE,
                                 headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return (r.status == 200), f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, type(e).__name__


def mint_from_refresh() -> tuple[str | None, str]:
    """Mint a fresh access token from the stored refresh_token grant.

    This is the fallback, not the preferred path: HA returns a 1800 s token here, so a
    stack running on it needs re-refreshing every 30 minutes. An LLAT is strictly better
    and is what ``--check`` will nudge toward.
    """
    if not CREDS.exists():
        return None, f"{CREDS.name} not found"
    try:
        c = json.loads(CREDS.read_text())
        base = c["base_url"].rstrip("/")
        data = urllib.parse.urlencode({
            "grant_type": "refresh_token",
            "refresh_token": c["refresh_token"],
            "client_id": c["client_id"],
        }).encode()
        req = urllib.request.Request(
            base + "/auth/token", data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=12) as r:
            tok = json.load(r)
        return tok.get("access_token"), f"minted, expires_in={tok.get('expires_in')}s"
    except Exception as e:
        return None, f"{type(e).__name__}: {str(e)[:80]}"


def describe(path: Path, label: str) -> dict:
    env = read_env(path)
    tok = env.get("HASS_TOKEN", "")
    iat, exp = jwt_exp(tok)
    now = time.time()
    ok, detail = probe(tok) if tok else (False, "absent")
    return {
        "label": label,
        "path": str(path).replace(str(Path.home()), "~"),
        "present": bool(tok),
        "chars": len(tok),
        "issued_at": iat,
        "expires_at": exp,
        "remaining_s": int(exp - now) if exp else None,
        "lifetime_days": round((exp - iat) / 86400) if (exp and iat) else None,
        "works": ok,
        "detail": detail,
        "url": env.get("HASS_URL", ""),
    }


def needs_refresh(t: dict, force: bool) -> bool:
    if force:
        return True
    if not t["present"] or not t["works"]:
        return True
    rem = t["remaining_s"]
    return rem is not None and rem < MIN_REMAINING_S


def human(sec: int | None) -> str:
    if sec is None:
        return "unknown"
    if sec <= 0:
        return "EXPIRED"
    d, h = divmod(int(sec) // 3600, 24)
    return f"{d}d {h}h" if d else f"{h}h"


def main() -> int:
    ap = argparse.ArgumentParser(description="Refresh Home Assistant tokens for the demo stack")
    ap.add_argument("--check", action="store_true", help="report only; write nothing")
    ap.add_argument("--force", action="store_true", help="refresh even if current tokens are healthy")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    targets = [describe(DS_ENV, "DelaySteer"), describe(HERMES_ENV, "Hermes")]
    report: dict = {"targets": [], "smartthings": "skipped (excluded by operator)",
                    "actions": [], "hermes_reload_needed": False}

    if not args.json:
        print("=== Home Assistant token status ===\n")
        for t in targets:
            mark = "OK  " if t["works"] else "FAIL"
            print(f"  [{mark}] {t['label']:<11} {t['path']:<22} "
                  f"{t['chars']:>4} chars  life={t['lifetime_days'] or '?'}d  "
                  f"remaining={human(t['remaining_s'])}  ({t['detail']})")
        print(f"  [SKIP] SmartThings  .env SMARTTHINGS_TOKEN   "
              f"not touched -- excluded by operator\n")

    stale = [t for t in targets if needs_refresh(t, args.force)]
    if not stale:
        report["targets"] = targets
        report["actions"].append("all tokens healthy; nothing to do")
        if args.json:
            print(json.dumps(report))
        else:
            print("All tokens are valid and not expiring soon. Nothing to do.")
        return 0

    if args.check:
        report["targets"] = targets
        for t in stale:
            report["actions"].append(f"{t['label']} needs refresh ({t['detail']})")
        if args.json:
            print(json.dumps(report))
        else:
            print("Would refresh: " + ", ".join(t["label"] for t in stale)
                  + "\n(--check: nothing written)")
        return 1

    # Best source = the longest-lived token that actually works right now. Preferring
    # a proven-working LLAT over a freshly minted 1800 s token is the whole point:
    # minting is correct but produces a token that dies again in 30 minutes.
    working = [t for t in targets if t["works"] and t["remaining_s"]]
    best_token, source = None, ""
    if working:
        best = max(working, key=lambda t: t["remaining_s"])
        if best["remaining_s"] >= MIN_REMAINING_S:
            best_token = read_env(DS_ENV if best["label"] == "DelaySteer" else HERMES_ENV)["HASS_TOKEN"]
            source = (f"existing long-lived token from {best['label']} "
                      f"({human(best['remaining_s'])} remaining)")

    if not best_token:
        best_token, detail = mint_from_refresh()
        source = f"refresh_token grant ({detail})"
        if not best_token:
            msg = f"no valid token available and minting failed -- {detail}"
            report["actions"].append(msg)
            print(json.dumps(report) if args.json else f"FAILED: {msg}", file=sys.stderr)
            return 2

    ok, detail = probe(best_token)
    if not ok:
        msg = f"candidate token does not authenticate ({detail}); refusing to install it"
        report["actions"].append(msg)
        print(json.dumps(report) if args.json else f"FAILED: {msg}", file=sys.stderr)
        return 2

    if not args.json:
        print(f"Source: {source}\n")

    for t in stale:
        path = DS_ENV if t["label"] == "DelaySteer" else HERMES_ENV
        write_env_key(path, "HASS_TOKEN", best_token)
        if t["label"] == "Hermes":
            report["hermes_reload_needed"] = True
        line = f"{t['label']}: token replaced ({t['detail']} -> refreshed)"
        report["actions"].append(line)
        if not args.json:
            print(f"  wrote {t['label']:<11} {str(path).replace(str(Path.home()), '~')}")

    after = [describe(DS_ENV, "DelaySteer"), describe(HERMES_ENV, "Hermes")]
    report["targets"] = after
    all_ok = all(t["works"] for t in after)

    if args.json:
        report["ok"] = all_ok
        print(json.dumps(report))
        return 0 if all_ok else 2

    print("\n=== after refresh ===")
    for t in after:
        print(f"  [{'OK  ' if t['works'] else 'FAIL'}] {t['label']:<11} "
              f"remaining={human(t['remaining_s'])}  ({t['detail']})")
    if report["hermes_reload_needed"]:
        print("\n  NOTE: Hermes loaded its old token into the process environment at\n"
              "  startup, so the new value applies only after it re-reads the file.\n"
              "  Type  /reload  in the Hermes chat (or restart it) to pick it up.")
    print("\n  SmartThings was not touched.")
    return 0 if all_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
