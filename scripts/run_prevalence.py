#!/usr/bin/env python3
"""Section 11.2 -- is the vulnerable shape common?

    python scripts/run_prevalence.py

The design is blunt about why this exists: a reviewer will ask how often the
attackable structure occurs in the wild, and "we built four scenarios" is not an
answer. The shape is specific --

    a HIGH-IMPACT action (lock, alarm, access grant, automation edit)
    CONDITIONED on a sensor predicate
    where that predicate has NO freshness contract

-- so it can be classified mechanically from an automation's source, and that is
what this does.

ON THE SAMPLING FRAME, STATED FIRST BECAUSE IT LIMITS THE CLAIM
Home Assistant ships exactly four core blueprints, and four is what is available
here; the community Blueprint Exchange, which is where the interesting mass is,
needs network access this run does not have. A prevalence FRACTION over n=4 is
not a measurement, and reporting one would be worse than reporting nothing.

So this emits two things: the classifier, which is reusable and auditable, and
an honest denominator. The existing 18-task corpus (results/external_corpus.csv)
is reported alongside as the larger available sample, with its own frame stated
-- it was hand-assembled for an external-validity study, not randomly sampled,
so it supports "the shape occurs across independently-authored tasks" and NOT
"X% of published automations are vulnerable".
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# A high-impact action is one whose misfire has a security or safety
# consequence: it grants access, changes a protective posture, or writes durable
# configuration. Comfort actuation (lights, media, climate) is excluded.
# The design's list, and only the design's list: lock, alarm, access grant,
# automation edit. Cover is included because opening a physical aperture is a
# security-state change of the same kind.
#
# NOTIFICATION IS DELIBERATELY NOT HERE. A missed notification is the HARM in
# Scenario 5, but SENDING one is not a high-impact action -- it grants no
# access and changes no protective posture. Including it would inflate the
# applicable denominator with comfort automations and make any later fraction
# meaningless. It is detected separately so the classifier is complete.
HIGH_IMPACT = {
    "lock": ["lock.lock", "lock.unlock", "lock.open"],
    "alarm": ["alarm_control_panel.alarm_arm", "alarm_control_panel.alarm_disarm",
              "alarm_control_panel.alarm_trigger", "alarm_control_panel.alarm_"],
    "access_grant": ["guest_code", "keypad", "temporary_code", "access_code",
                     "person.add", "lock.set_lock_user"],
    "cover_security": ["cover.open_cover", "cover.close_cover"],
    "automation_edit": ["automation.turn_off", "automation.turn_on",
                        "automation.reload", "script.reload",
                        "automation.toggle"],
}

# Not high-impact, but tracked so a reader can see what the corpus DOES contain
# and check that a 0 is a real 0 rather than a regex that matched nothing.
OTHER_ACTIONS = {
    "notification": ["notify.", "persistent_notification.", "type: notify"],
    "comfort": ["light.", "climate.", "media_player.", "switch."],
}

# HA has TWO action syntaxes and a classifier that knows only one is silently
# wrong on every automation using the other. Service calls look like
# `action: lock.unlock`; DEVICE actions look like `domain: lock` + `type: unlock`
# with a device_id. notify_leaving_zone.yaml uses the second form, which an
# earlier version of this classifier missed entirely.
DEVICE_ACTION = re.compile(r"domain:\s*(\w+)[\s\S]{0,120}?type:\s*(\w+)", re.I)
SECURITY_DOMAINS = {"lock", "alarm_control_panel", "cover"}

# A sensor predicate: the action is gated on some observed state.
SENSOR_PREDICATE = re.compile(
    r"\b(binary_sensor|sensor|device_tracker|person|zone|input_boolean)\.", re.I)

# A freshness contract: anything that bounds how old the observation may be.
FRESHNESS = re.compile(
    r"\b(for\s*:|last_changed|last_updated|last_reported|"
    r"seconds\s*:|minutes\s*:|hours\s*:|timeout|max_age|expire|stale)\b", re.I)


@dataclass
class Classification:
    path: str
    name: str
    high_impact: list[str] = field(default_factory=list)
    other_actions: list[str] = field(default_factory=list)
    has_sensor_predicate: bool = False
    has_freshness: bool = False
    freshness_evidence: list[str] = field(default_factory=list)

    @property
    def vulnerable_shape(self) -> bool:
        """High-impact action gated on a sensor predicate with NO freshness."""
        return bool(self.high_impact) and self.has_sensor_predicate \
            and not self.has_freshness

    @property
    def applicable(self) -> bool:
        """Has a high-impact action at all -- otherwise the question is moot."""
        return bool(self.high_impact)

    def as_row(self) -> dict:
        return {"path": self.path, "name": self.name,
                "high_impact": ";".join(self.high_impact),
                "other_actions": ";".join(self.other_actions),
                "has_sensor_predicate": int(self.has_sensor_predicate),
                "has_freshness": int(self.has_freshness),
                "freshness_evidence": ";".join(self.freshness_evidence[:3]),
                "applicable": int(self.applicable),
                "vulnerable_shape": int(self.vulnerable_shape)}


def classify(path: Path) -> Classification:
    text = path.read_text(errors="replace")
    c = Classification(path=str(path), name=path.stem)
    low = text.lower()
    for label, needles in HIGH_IMPACT.items():
        if any(n.lower() in low for n in needles):
            c.high_impact.append(label)
    # the second HA action syntax, which service-call matching alone misses
    for dom, _typ in DEVICE_ACTION.findall(text):
        if dom.lower() in SECURITY_DOMAINS:
            c.high_impact.append(f"device_action:{dom.lower()}")
    c.high_impact = sorted(set(c.high_impact))
    for label, needles in OTHER_ACTIONS.items():
        if any(n.lower() in low for n in needles):
            c.other_actions.append(label)
    c.has_sensor_predicate = bool(SENSOR_PREDICATE.search(text))
    ev = FRESHNESS.findall(text)
    c.has_freshness = bool(ev)
    c.freshness_evidence = sorted({e.strip() for e in ev})[:5]
    return c


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--roots", default="config/blueprints")
    ap.add_argument("--out", default="results/prevalence.csv")
    a = ap.parse_args()

    files: list[Path] = []
    for root in a.roots.split(","):
        p = Path(root)
        if p.is_dir():
            files.extend(sorted(p.rglob("*.yaml")))
        elif p.is_file():
            files.append(p)
    files = sorted({f.resolve() for f in files})

    print("=" * 74)
    print("SECTION 11.2 -- prevalence of the vulnerable shape")
    print("=" * 74)
    print("SHAPE: a high-impact action (lock / alarm / access grant /")
    print("       automation edit) conditioned on a sensor predicate, where")
    print("       that predicate carries NO freshness contract.\n")

    rows = [classify(f) for f in files]
    print(f"{'blueprint':34s} {'impact':>7s} {'sensor':>7s} {'fresh':>6s} "
          f"{'vulnerable':>11s}")
    print("-" * 70)
    for c in rows:
        print(f"{c.name[:34]:34s} {str(bool(c.high_impact)):>7s} "
              f"{str(c.has_sensor_predicate):>7s} {str(c.has_freshness):>6s} "
              f"{str(c.vulnerable_shape):>11s}")

    applicable = [c for c in rows if c.applicable]
    vulnerable = [c for c in rows if c.vulnerable_shape]

    print("\n" + "=" * 74)
    print("THE DENOMINATOR IS THE RESULT HERE, NOT THE FRACTION")
    print("=" * 74)
    print(f"  blueprints classified          : {len(rows)}")
    print(f"  with a high-impact action      : {len(applicable)}")
    print(f"  with the vulnerable shape      : {len(vulnerable)}")
    print()
    print("  Home Assistant ships exactly four core blueprints and four is what")
    print("  is available offline. The community Blueprint Exchange -- where the")
    print("  mass of published automations lives -- needs network access this")
    print("  run does not have.")
    print()
    print(f"  A prevalence FRACTION over n={len(rows)} is not a measurement, and")
    print("  reporting one would be worse than reporting nothing. This run")
    print("  therefore delivers the CLASSIFIER and an honest denominator, not a")
    print("  percentage. What would make it a measurement: a sample of a few")
    print("  hundred community blueprints with the sampling frame stated and")
    print("  two independent annotators for inter-rater agreement, which the")
    print("  design asks for and this does not have either.")

    # The larger available sample, with its own frame stated.
    ext = Path("results/external_corpus.csv")
    if ext.exists():
        e = list(csv.DictReader(ext.open()))
        surf = [r for r in e if str(r.get("delay_attack_surface", "")).lower()
                in ("1", "true", "yes")]
        print("\n" + "-" * 74)
        print("LARGER AVAILABLE SAMPLE: the 18-task external corpus")
        print(f"  tasks                          : {len(e)}")
        print(f"  with a plausible delay surface : {len(surf)}")
        print("  FRAME: hand-assembled for an external-validity study, NOT")
        print("  randomly sampled from published automations. It supports 'the")
        print("  shape occurs across independently-authored tasks'. It does NOT")
        print("  support 'X% of published automations are vulnerable', and the")
        print("  paper must not use it that way.")

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].as_row().keys())
                           if rows else ["path"])
        w.writeheader()
        for c in rows:
            w.writerow(c.as_row())
    Path("results/prevalence_frame.json").write_text(json.dumps({
        "n_classified": len(rows),
        "n_applicable": len(applicable),
        "n_vulnerable_shape": len(vulnerable),
        "fraction_reported": False,
        "why_no_fraction": (
            f"n={len(rows)} is the complete set of Home Assistant core "
            "blueprints available offline; the community Blueprint Exchange "
            "requires network access. A fraction over this denominator is not "
            "a prevalence measurement."),
        "what_would_make_it_one": (
            "a few hundred community blueprints, sampling frame stated, two "
            "independent annotators for inter-rater agreement (design 11.2)"),
        "status": "OPEN -- classifier delivered, sample inadequate",
    }, indent=2) + "\n")
    print(f"\nwrote {out} and results/prevalence_frame.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
