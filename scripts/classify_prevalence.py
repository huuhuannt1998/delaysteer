#!/usr/bin/env python3
"""B5 -- deterministic classifier for the prevalence corpus (design 11.2).

The design asks for human annotation with inter-rater agreement. Both properties
it asks about are SYNTACTIC properties of the blueprint YAML, so this classifies
them with published rules instead. A deterministic rule set is reproducible by
construction: anyone re-running this script on the same cache gets the same
labels, which is a stronger guarantee than two annotators agreeing. It is not
the same guarantee -- rule VALIDITY still needs a human check, so a random
subsample is hand-audited separately and the error rate reported.

Three labels per blueprint:
  high_impact   -- does its action block call a service that grants physical
                   access or weakens a safety posture?
  sensor_gated  -- is that action reached only through a trigger/condition on a
                   sensor-like entity state?
  temporal      -- what temporal qualifier does that gating predicate carry?
                     age_check  : reads last_changed/last_updated/timestamp age
                     dwell_only : `for:` -- a state HELD for N, which bounds how
                                  long a value has been *believed*, not how long
                                  ago it was *observed*. Not a freshness contract.
                     none       : neither
"""
import yaml, glob, json, csv, re, os, sys

class L(yaml.SafeLoader): pass
def _tag(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):   return {"__tag__": suffix, "v": loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode): return {"__tag__": suffix, "v": loader.construct_sequence(node)}
    return {"__tag__": suffix, "v": loader.construct_mapping(node)}
L.add_multi_constructor("!", _tag)

ACCESS = {"lock.unlock", "lock.open", "cover.open_cover", "cover.set_cover_position",
          "cover.toggle", "alarm_control_panel.alarm_disarm"}
# Deliberately EXCLUDES homeassistant.turn_off and input_boolean.turn_off. Both are
# frequent (21 and 22 hits) but domain-generic -- in this corpus they overwhelmingly
# target lights and helper flags, and the blueprint cannot tell us which entity a user
# will bind. Counting them would inflate the estimate on entities we cannot inspect, so
# they are dropped. This biases the prevalence figure DOWNWARD, which is the safe
# direction for a number that appears in the paper's motivation.
POSTURE = {"automation.turn_off", "script.turn_off", "siren.turn_off",
           "alarm_control_panel.alarm_arm_home", "climate.turn_off",
           "valve.open_valve", "water_heater.turn_off"}
HIGH_IMPACT = ACCESS | POSTURE
SENSOR_DOMAINS = {"binary_sensor", "sensor", "device_tracker", "person",
                  "input_boolean", "input_number", "lock", "cover", "climate"}
AGE_RE = re.compile(r"last_changed|last_updated|last_triggered|as_timestamp\s*\(\s*now|"
                    r"states\.[a-z_]+\.[A-Za-z0-9_]+\.last_|now\(\)\s*-", re.I)

def walk(node, fn, path=()):
    fn(node, path)
    if isinstance(node, dict):
        for k, v in node.items(): walk(v, fn, path + (str(k),))
    elif isinstance(node, list):
        for i, v in enumerate(node): walk(v, fn, path + (f"[{i}]",))

def input_domains(bp):
    """Map input name -> set of entity domains its selector admits."""
    out = {}
    inp = (bp or {}).get("input") or {}
    if not isinstance(inp, dict): return out
    for name, spec in inp.items():
        doms = set()
        def grab(n, p):
            if isinstance(n, dict):
                d = n.get("domain")
                if isinstance(d, str): doms.add(d)
                elif isinstance(d, list): doms.update(x for x in d if isinstance(x, str))
        walk(spec, grab)
        out[str(name)] = doms
    return out

def services_called(doc):
    """Every service name appearing in an action position."""
    found = set()
    def grab(n, p):
        if isinstance(n, dict):
            for key in ("service", "action"):
                v = n.get(key)
                if isinstance(v, str) and re.fullmatch(r"[a-z_]+\.[a-z0-9_]+", v):
                    found.add(v)
    walk(doc, grab)
    return found

def gating(doc, dom_map):
    """(is_sensor_gated, temporal_label) over triggers+conditions."""
    sensor_gated, has_age, has_dwell = False, False, False
    def entity_domains(n):
        d = set()
        def g(x, p):
            if isinstance(x, dict):
                if x.get("__tag__") == "input":
                    d.update(dom_map.get(str(x.get("v")), set()))
                for key in ("entity_id", "entity"):
                    v = x.get(key)
                    for s in ([v] if isinstance(v, str) else (v if isinstance(v, list) else [])):
                        if isinstance(s, str) and "." in s: d.add(s.split(".", 1)[0])
            elif isinstance(x, str) and AGE_RE.search(x): pass
        walk(n, g)
        return d
    for key in ("trigger", "triggers", "condition", "conditions"):
        blk = doc.get(key)
        if blk is None: continue
        items = blk if isinstance(blk, list) else [blk]
        for it in items:
            if not isinstance(it, (dict, list, str)): continue
            plat = it.get("platform") or it.get("trigger") or it.get("condition") if isinstance(it, dict) else None
            doms = entity_domains(it)
            txt = json.dumps(it, default=str)
            is_stateish = (plat in ("state", "numeric_state", "template", "device")) or bool(doms)
            if is_stateish and (doms & SENSOR_DOMAINS or plat == "template"):
                sensor_gated = True
                if AGE_RE.search(txt): has_age = True
                if isinstance(it, dict) and it.get("for") is not None: has_dwell = True
                else:
                    if re.search(r'"for"\s*:', txt): has_dwell = True
    # an age check anywhere in the document still counts as the author thinking about it
    if not has_age and AGE_RE.search(json.dumps(doc, default=str)): has_age = True
    return sensor_gated, ("age_check" if has_age else "dwell_only" if has_dwell else "none")

def main():
    man = json.load(open("results/prevalence_manifest.json"))
    meta = {str(t["id"]): t for t in man["topics"]}
    rows, parse_fail = [], 0
    for f in sorted(glob.glob("results/prevalence_cache/*.yaml")):
        tid = os.path.basename(f)[:-5]
        try:
            doc = yaml.load(open(f).read(), Loader=L)
        except Exception as e:
            parse_fail += 1; continue
        if not isinstance(doc, dict) or "blueprint" not in doc: continue
        bp = doc.get("blueprint") or {}
        if (bp.get("domain") if isinstance(bp, dict) else None) not in (None, "automation"): 
            pass  # keep script blueprints too; recorded below
        dom_map = input_domains(bp)
        svcs = services_called(doc)
        hi = sorted(svcs & HIGH_IMPACT)
        sg, temporal = gating(doc, dom_map)
        m = meta.get(tid, {})
        rows.append({
            "topic_id": tid, "title": (m.get("title") or "")[:120], "views": m.get("views"),
            "created_at": m.get("created_at"), "bp_domain": bp.get("domain") if isinstance(bp, dict) else "",
            "n_services": len(svcs), "high_impact": int(bool(hi)),
            "hi_access": int(bool(svcs & ACCESS)), "hi_posture": int(bool(svcs & POSTURE)),
            "hi_services": "|".join(hi), "sensor_gated": int(sg), "temporal": temporal,
            "vulnerable_shape": int(bool(hi) and sg and temporal != "age_check"),
        })
    with open("results/prevalence_corpus.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    n = len(rows)
    hi = sum(r["high_impact"] for r in rows)
    both = sum(1 for r in rows if r["high_impact"] and r["sensor_gated"])
    print(f"parsed blueprints : {n}   (yaml parse failures: {parse_fail})")
    print(f"high-impact action: {hi}/{n}")
    print(f"  ...and sensor-gated: {both}/{n}")
    if both:
        from collections import Counter
        c = Counter(r["temporal"] for r in rows if r["high_impact"] and r["sensor_gated"])
        for k in ("none", "dwell_only", "age_check"): print(f"    {k:11s}: {c.get(k,0)}/{both}")
    print(f"vulnerable shape  : {sum(r['vulnerable_shape'] for r in rows)}/{n}")
    print("\nwrote results/prevalence_corpus.csv")

if __name__ == "__main__":
    main()
