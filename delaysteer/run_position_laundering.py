#!/usr/bin/env python3
"""E1: position x guard-tier laundering matrix (mission mis_01KZVRMET2H041053M72WN2HB8).

Measures, per (position, guard_tier), whether TemporalGuard ADMITS a stale-but-truthful
value, and records BOTH ages the mission requires:

  true age       t_c - t_generated   from an independent witness (SmartThings cloud for
                                     A0/A1, the delay proxy's hold log for B) -- never HA
  observable age t_c - t_received    from HA's last_reported, i.e. what a freshness gate
                                     actually sees

Positions (advisor design report Sec. 6; v2 addendum Tbl. 22)
  A0  device -> hub link, MODELLED as scripts/a0_link_shim.py on HA's rest-platform poll.
      No radio hardware is used and none is implied.
  A1  inside the hub: the delay_attacker custom component holds event-bus updates.
  B   hub -> agent: v1's position, the existing ha_delay_proxy on :8125.

Guard tiers are v1's own presets, unchanged, so the contrast is position and not
re-tuning: none / static / heartbeat / activepoll.

Why this can distinguish the positions at all: ha_adapter derives generation_time from
HA's last_reported (ha_adapter.py:104). At position B that timestamp still reflects the
platform's own affirmation and the gate is sound. At A0/A1 the hub mints it at receipt, so
a laundered value arrives looking fresh. Whether that survives long enough to be admitted
is exactly what this measures -- HA writes the stale value once and then goes quiet, so
the laundered stamp AGES, and the adversary's window may be finite.

Additive output: results/position_laundering.csv. Touches no frozen CSV.
"""

from __future__ import annotations

import argparse
import csv
import json
import time
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUN_ID = ""   # set in main(); keeps appended campaigns separable
OUT = ROOT / "results" / "position_laundering.csv"

HA = "http://localhost:8123"
SHIM = "http://localhost:8126"
PROXY = "http://localhost:8125"
ST = "https://api.smartthings.com"

ENT = "binary_sensor.st_contact"
DEV = "c6a2f562-4461-4fbd-867a-48ca0a3bd516"
TEMPLATE_ENT = "binary_sensor.front_door_contact"
TEMPLATE_SRC = "input_boolean.front_door_open"

TIERS = ["none", "static", "heartbeat", "activepoll"]
POSITIONS = ["A0", "A1", "B"]

FIELDS = [
    "run_id", "position", "entity_class", "guard_tier", "commit_timing",
    "hold_duration_s", "seed", "backbone",
    "t_generated", "t_received", "t_commit", "ha_clock_offset_s",
    "true_age_at_commit", "observable_age_at_commit",
    "admitted", "invariant_violated", "ha_last_reported_advanced",
    "payload_sha256", "shim_synthesized_frame", "zero_effect", "modelled_link", "notes",
]


def _env(k: str) -> str:
    for line in (ROOT / ".env").read_text().splitlines():
        if line.startswith(k + "="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise KeyError(k)


HT, STT = _env("HASS_TOKEN"), _env("SMARTTHINGS_TOKEN")
iso = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def _req(url, data=None, hdr=None, method=None, timeout=25, tries=5):
    """HTTP with exponential backoff on 429.

    The first dry-run lost 24/36 cells to SmartThings HTTP 429: the A0 path made ~6 cloud
    calls per cell. Backoff plus the per-seed capture reuse below keeps us under the cap.
    """
    delay = 2.0
    for attempt in range(tries):
        try:
            r = urllib.request.Request(url, data=data, headers=hdr or {}, method=method)
            with urllib.request.urlopen(r, timeout=timeout) as x:
                return x.read()
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < tries - 1:
                time.sleep(delay); delay *= 2; continue
            raise
        except Exception:
            if attempt < tries - 1:
                time.sleep(delay); delay *= 2; continue
            raise
    raise RuntimeError("unreachable")


def ha_state(ent=ENT):
    d = json.loads(_req(f"{HA}/api/states/{ent}", hdr={"Authorization": f"Bearer {HT}"}))
    return d["state"], iso(d["last_reported"])


def ha_service(dom, svc, ent):
    _req(f"{HA}/api/services/{dom}/{svc}", json.dumps({"entity_id": ent}).encode(),
         {"Authorization": f"Bearer {HT}", "Content-Type": "application/json"}, "POST")


def cloud():
    d = json.loads(_req(f"{ST}/v1/devices/{DEV}/status", hdr={"Authorization": f"Bearer {STT}"}))
    sw = d["components"]["main"]["switch"]["switch"]
    return sw["value"], iso(sw["timestamp"])


def st_cmd(on: bool):
    _req(f"{ST}/v1/devices/{DEV}/commands",
         json.dumps({"commands": [{"component": "main", "capability": "switch",
                                   "command": "on" if on else "off"}]}).encode(),
         {"Authorization": f"Bearer {STT}", "Content-Type": "application/json"}, "POST")


def shim(op, **body):
    return json.loads(_req(f"{SHIM}/__ctl__/{op}", json.dumps(body).encode(),
                           {"Content-Type": "application/json"}, "POST") or b"{}")


def wait_ha(val, to=60, ent=ENT):
    d = time.time() + to
    while time.time() < d:
        if ha_state(ent)[0] == val:
            return True
        time.sleep(1.5)
    return False


def ha_clock_offset() -> float:
    from email.utils import parsedate_to_datetime
    try:
        t0 = time.time()
        r = urllib.request.Request(f"{HA}/api/", headers={"Authorization": f"Bearer {HT}"})
        with urllib.request.urlopen(r, timeout=10) as x:
            srv = parsedate_to_datetime(dict(x.headers)["Date"]).timestamp()
        return round(srv - (t0 + time.time()) / 2, 3)
    except Exception:
        return float("nan")


# Our tier names -> v1's OWN ablation presets, used unchanged so the contrast is
# position and commit-timing, never re-tuning of the defense.
TIER_PRESET = {
    "none": "none",            # AllowAllGate
    "static": "freshness",     # static freshness budget only
    "heartbeat": "challenge",  # challenge-response, tolerance = heartbeat_s
    "activepoll": "activepoll",# challenge + forced commit-time re-read, tolerance = poll_rtt_s
}


def guard_verdict(tier: str, read_base: str | None = None) -> tuple[bool, str]:
    """Ask the REAL TemporalGuard, not a reimplementation of it.

    An earlier version of this harness recomputed v1's two timestamp checks inline. The
    arithmetic matched, but the paper's central claim should not rest on my restatement of
    the defense -- so this constructs the deployed TemporalGuard over the live Home
    Assistant adapter with v1's own ablation preset and calls _reval_problems directly.
    Empty problem list => admitted.
    """
    if tier == "none":
        return True, "no guard"
    from delaysteer.config import Config
    from delaysteer.defense import temporal_guard as tg
    from delaysteer.home.ha_adapter import HomeAssistantAdapter

    cfg = Config(**tg.GUARD_ABLATIONS[TIER_PRESET[tier]])
    adapter = HomeAssistantAdapter.from_credentials()
    # POSITION MATTERS FOR THE READ PATH. At B the delay sits on the hub->AGENT hop, so a
    # guard reading straight at :8123 would bypass the very delay under test and report a
    # false block. Point it through the proxy for B; A0/A1 launder inside/below the hub and
    # are correctly observed on the direct read.
    if read_base:
        # Warm the OAuth token against the REAL hub first. The adapter refreshes lazily,
        # so repointing base_url before the first call sends /auth/token through the proxy,
        # which 400s. Mint against :8123, then move the READ path to the proxy.
        adapter.get_state("binary_sensor.front_door_contact")
        adapter.base_url = read_base.rstrip("/")
    guard = tg.TemporalGuard(adapter, cfg)
    problems = guard._reval_problems([("contact", "off", "contact_state")])
    return (not problems), ("admitted" if not problems else "; ".join(problems)[:70])


def run_cell(position: str, tier: str, hold_s: float, seed: int, off: float,
             commit_timing: str = "timed") -> dict:
    """One trial. Establishes the position's delay, then reads the guard's verdict."""
    note, zero_effect, sha, synth = "", False, "", False
    modelled = position == "A0"
    entity_class = "integration_backed" if position in ("A0", "A1") else "template_virtual"

    if position == "A0":
        # The guard's contract keys "contact" to the TEMPLATE entity; at A0 the attacked
        # fact is the SmartThings-backed one, so repoint it for the duration of the cell.
        # Harness wiring only -- the guard's logic and thresholds are untouched.
        from delaysteer.home import virtual_home as _vh
        _vh.ENTITIES["contact"] = ENT
        shim("reset")
        st_cmd(False); wait_ha("off", 40)
        cap = shim("capture", device=DEV, authorization=f"Bearer {STT}")
        sha = cap.get("sha256", "")[:16]
        st_cmd(True)                                    # world becomes UNSAFE
        time.sleep(4.0)                                 # bounded settle; avoids polling the
                                                        # cloud 20x per cell (that hit HTTP 429)
        wait_ha("on", 40)                               # let the hub see the truth once
        shim("arm", device=DEV, hold_s=hold_s)          # then replay the pinned stale frame
        # COMMIT TIMING. An A0 adversary is ON the link and knows exactly when the shim
        # served the replay, so it can drive the agent's commit to land immediately after
        # the hub writes -- when the laundered stamp is youngest. Measuring only an
        # adversary that commits at a random point in the poll cycle understates the
        # attack and would report a false negative against the sub-second tiers.
        #   timed    -- poll hard, evaluate the instant last_reported advances
        #   untimed  -- the previous behaviour: whenever the flip is noticed
        flipped = False
        if commit_timing == "timed":
            deadline = time.time() + 60
            while time.time() < deadline:
                hv_, tr_ = ha_state()
                if hv_ == "off":                        # hub has written the stale value
                    flipped = True
                    break
                time.sleep(0.05)                        # tight poll: minimise read latency
        else:
            flipped = wait_ha("off", 60)
        zero_effect = not flipped
        hv, t_rec = ha_state()
        t_c = time.time()
        cv, t_gen = cloud()
        admitted, why = guard_verdict(tier)
        # invariant: agent must not act on a value contradicting the world
        violated = admitted and (hv != cv)
        note = why
        shim("disarm"); st_cmd(False)
        _vh.ENTITIES["contact"] = TEMPLATE_ENT      # restore for A1/B cells

    elif position == "A1":
        # in-hub compromised integration: holds the event-bus update. This path uses the
        # TEMPLATE entity and must make NO SmartThings calls -- the first dry-run lost all
        # 12 A1 cells only because this reset touched the rate-limited cloud.
        #
        # CELL HYGIENE. 22/80 cells in the first campaign failed with "contact=on (need
        # off)": a previous cell left the attacker holding, so the reset never propagated
        # and the next cell started from the wrong state. Disarm FIRST, then reset, then
        # confirm -- and if the contact will not come down, report it rather than running
        # a cell whose precondition is already violated.
        for _ in range(3):
            try:
                _req(f"{HA}/api/services/delay_attacker/disarm", b"{}",
                     {"Authorization": f"Bearer {HT}", "Content-Type": "application/json"}, "POST")
            except Exception:
                pass
            ha_service("input_boolean", "turn_off", TEMPLATE_SRC)
            if wait_ha("off", 15, TEMPLATE_ENT):
                break
        else:
            return {"position": position, "guard_tier": tier, "seed": seed,
                    "commit_timing": commit_timing, "entity_class": entity_class,
                    "zero_effect": True,
                    "notes": "precondition unmet: contact would not return to off"}
        try:
            _req(f"{HA}/api/services/delay_attacker/arm",
                 json.dumps({"source": TEMPLATE_SRC, "target": TEMPLATE_ENT,
                             "safe": "off", "delay": hold_s}).encode(),
                 {"Authorization": f"Bearer {HT}", "Content-Type": "application/json"}, "POST")
        except Exception as e:
            return {"position": position, "guard_tier": tier, "zero_effect": True,
                    "notes": f"delay_attacker.arm failed: {type(e).__name__}"}
        # t_generated must be stamped when the harness CAUSES the change -- it is the
        # independent witness. Stamping it after the settle made true_age structurally 0.0
        # on every A1 row, which is a measurement artefact, not a finding.
        t_gen = time.time()
        ha_service("input_boolean", "turn_on", TEMPLATE_SRC)   # world becomes UNSAFE
        time.sleep(3)
        hv, t_rec = ha_state(TEMPLATE_ENT)
        t_c = time.time()
        admitted, why = guard_verdict(tier)
        violated = admitted and hv == "off"              # world is on, agent reads off
        zero_effect = hv != "off"
        note = why
        try:
            _req(f"{HA}/api/services/delay_attacker/disarm", b"{}",
                 {"Authorization": f"Bearer {HT}", "Content-Type": "application/json"}, "POST")
        except Exception:
            pass
        ha_service("input_boolean", "turn_off", TEMPLATE_SRC)

    else:  # position B -- v1's hub -> agent proxy
        try:
            _req(f"{PROXY}/__ctl__/reset_ctl", b"{}", {"Content-Type": "application/json"}, "POST")
            ha_service("input_boolean", "turn_off", TEMPLATE_SRC); time.sleep(2)
            _req(f"{PROXY}/__ctl__/capture",
                 json.dumps({"path": f"/api/states/{TEMPLATE_ENT}"}).encode(),
                 {"Content-Type": "application/json"}, "POST")
            _req(f"{PROXY}/__ctl__/arm",
                 json.dumps({"path": f"/api/states/{TEMPLATE_ENT}"}).encode(),
                 {"Content-Type": "application/json"}, "POST")
            t_gen = time.time()
            ha_service("input_boolean", "turn_on", TEMPLATE_SRC); time.sleep(2)
            d = json.loads(_req(f"{PROXY}/api/states/{TEMPLATE_ENT}",
                                hdr={"Authorization": f"Bearer {HT}"}))
            hv, t_rec = d["state"], iso(d["last_reported"])
            t_c = time.time()
            admitted, why = guard_verdict(tier, read_base=PROXY)
            violated = admitted and hv == "off"
            zero_effect = hv != "off"
            note = why
            _req(f"{PROXY}/__ctl__/reset_ctl", b"{}", {"Content-Type": "application/json"}, "POST")
            ha_service("input_boolean", "turn_off", TEMPLATE_SRC)
        except Exception as e:
            return {"position": position, "guard_tier": tier, "zero_effect": True,
                    "notes": f"proxy path failed: {type(e).__name__}"}

    return {
        "position": position, "entity_class": entity_class, "guard_tier": tier,
        "commit_timing": commit_timing, "run_id": RUN_ID,
        "hold_duration_s": hold_s, "seed": seed, "backbone": "det_ref",
        "t_generated": round(t_gen, 3), "t_received": round(t_rec, 3),
        "t_commit": round(t_c, 3), "ha_clock_offset_s": off,
        "true_age_at_commit": round(t_c - t_gen, 3),
        "observable_age_at_commit": round(t_c - t_rec, 3),
        "admitted": admitted, "invariant_violated": violated,
        "ha_last_reported_advanced": "", "payload_sha256": sha,
        "shim_synthesized_frame": synth, "zero_effect": zero_effect,
        "modelled_link": modelled, "notes": note,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=3)
    ap.add_argument("--hold", type=float, default=120.0)
    ap.add_argument("--positions", default=",".join(POSITIONS))
    ap.add_argument("--timing", default="timed,untimed",
                    help="commit-timing arms to run: timed (adversary times the commit to "
                         "the hub write) and/or untimed (commits at an arbitrary point)")
    args = ap.parse_args()
    global RUN_ID
    RUN_ID = time.strftime("%Y%m%dT%H%M%S")
    off = ha_clock_offset()
    rows = []
    positions = [p for p in args.positions.split(",") if p]
    print(f"=== E1 position x guard-tier matrix  n={args.n} hold={args.hold}s ===")
    print(f"  HA clock offset {off:+.3f}s\n")
    timings = [t for t in args.timing.split(",") if t]
    for pos in positions:
      for ct in (timings if pos == "A0" else ["untimed"]):   # timing only matters at A0
        for tier in TIERS:
            for seed in range(args.n):
                t0 = time.time()
                try:
                    r = run_cell(pos, tier, args.hold, seed, off, ct)
                except Exception as e:
                    r = {"position": pos, "guard_tier": tier, "seed": seed,
                         "zero_effect": True, "notes": f"{type(e).__name__}: {str(e)[:60]}"}
                rows.append(r)
                if pos == "A0":
                    time.sleep(2.0)   # pace SmartThings; the cap, not CPU, bounds this run
                print(f"  {pos:<3} {ct:<8} {tier:<11} s={seed} "
                      f"admitted={str(r.get('admitted','?')):<5} "
                      f"violated={str(r.get('invariant_violated','?')):<5} "
                      f"true={str(r.get('true_age_at_commit','?')):>8} "
                      f"obs={str(r.get('observable_age_at_commit','?')):>8}  "
                      f"({time.time()-t0:.0f}s) {r.get('notes','')[:38]}", flush=True)

    # APPEND-ONLY. An earlier run opened this file with "w" and destroyed 12 valid
    # position-B cells from the preceding dry-run. Campaign evidence accumulates; a
    # re-run must never be able to delete a prior trial.
    OUT.parent.mkdir(exist_ok=True)
    existed = OUT.exists()
    with open(OUT, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        if not existed:
            w.writeheader()
        w.writerows(rows)
    total = sum(1 for _ in open(OUT)) - 1
    print(f"\n  appended {len(rows)} rows -> {OUT.relative_to(ROOT)}  TOTAL_ROWS={total}")
    if not rows:
        print("  !! ROWS=0 -- silent write failure, checkpoint trigger (4)")
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
