#!/usr/bin/env python3
"""B5 -- prevalence corpus fetcher (design 11.2).

Enumerates the Home Assistant Blueprint Exchange as a CENSUS of a contiguous
window of the category listing, and retrieves each topic's blueprint YAML from
whichever of three places the author put it: inline in a <pre> block, a GitHub
gist, or a raw file in a GitHub repo.

Sampling frame is pre-registered here rather than chosen after seeing results:
  * source      : community.home-assistant.io category 53 (Blueprints Exchange)
  * ordering    : the category's own default listing order
  * window      : the first PAGES pages of that listing, as of the run date
  * inclusion   : every topic in the window except the pinned "About" meta-post
  * extraction  : first YAML document containing a top-level `blueprint:` key
  * exclusion   : topics from which no such document can be retrieved
Read-only GETs, one at a time, with a delay between requests.
"""
import json, urllib.request, urllib.error, re, time, html, os, sys, hashlib

# The User-Agent names the study rather than a person. A contact address is the polite
# convention for a research crawler, but this file is published on the public repository
# and the anonymized review mirror is served from it, so an institutional address here
# identifies the authors to any reviewer who opens the mirror. Restore a contact address
# after the double-anonymous review embargo lifts.
UA = {"User-Agent": "DelaySteer-research/1.0 (academic study of public automation blueprints)"}
BASE = "https://community.home-assistant.io"
CACHE = "results/prevalence_cache"
PAGES = int(os.environ.get("PAGES", "10"))
DELAY = 0.8

def fetch(url, as_json=False, timeout=30):
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
                raw = r.read()
            return json.loads(raw) if as_json else raw.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code in (429, 503):
                time.sleep(5 * (attempt + 1)); continue
            return None
        except Exception:
            time.sleep(2); continue
    return None

def yaml_docs_from_html(cooked):
    """Every <pre>/<code> block that looks like a blueprint."""
    out = []
    for blk in re.findall(r'<pre[^>]*>(.*?)</pre>', cooked, re.S):
        txt = html.unescape(re.sub(r'<[^>]+>', '', blk))
        if re.search(r'^\s*blueprint\s*:', txt, re.M):
            out.append(txt)
    return out

def gist_yaml(cooked):
    out = []
    for gid in set(re.findall(r'gist\.github\.com/[\w.-]+/([0-9a-f]{20,})', cooked)):
        j = fetch(f"https://api.github.com/gists/{gid}", as_json=True); time.sleep(DELAY)
        if not j or "files" not in j: continue
        for f in j["files"].values():
            c = f.get("content") or ""
            if re.search(r'^\s*blueprint\s*:', c, re.M): out.append(c)
    return out

def github_yaml(cooked):
    """Raw .yaml links, blob links, and my.home-assistant import URLs."""
    cands = set()
    for m in re.findall(r'https://raw\.githubusercontent\.com/[^\s"\'<>)]+\.ya?ml', cooked):
        cands.add(m)
    for m in re.findall(r'https://github\.com/([\w.-]+)/([\w.-]+)/blob/([^\s"\'<>)]+\.ya?ml)', cooked):
        cands.add(f"https://raw.githubusercontent.com/{m[0]}/{m[1]}/{m[2]}")
    for m in re.findall(r'blueprint_url=([^\s"\'<>&]+)', cooked):
        u = urllib.parse.unquote(m) if 'urllib.parse' in dir() else m
        u = u.replace("%3A", ":").replace("%2F", "/")
        if u.endswith((".yaml", ".yml")):
            if "github.com" in u and "/blob/" in u:
                u = u.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            cands.add(u)
    out = []
    for u in sorted(cands)[:4]:
        c = fetch(u); time.sleep(DELAY)
        if c and re.search(r'^\s*blueprint\s*:', c, re.M): out.append(c)
    return out

def main():
    seen, manifest = set(), []
    for page in range(PAGES):
        j = fetch(f"{BASE}/c/blueprints-exchange/53.json?page={page}", as_json=True)
        time.sleep(DELAY)
        if not j: print(f"page {page}: FAILED", flush=True); continue
        topics = j.get("topic_list", {}).get("topics", [])
        if not topics: break
        print(f"page {page}: {len(topics)} topics", flush=True)
        for t in topics:
            if t["id"] in seen: continue
            seen.add(t["id"])
            if "About Blueprints" in t["title"]: continue
            manifest.append({"id": t["id"], "title": t["title"], "views": t.get("views"),
                             "likes": t.get("like_count"), "created_at": t.get("created_at"),
                             "posts": t.get("posts_count")})
    print(f"\nwindow: {len(manifest)} topics; retrieving YAML", flush=True)
    got = 0
    for i, m in enumerate(manifest):
        cp = f"{CACHE}/{m['id']}.yaml"
        if os.path.exists(cp):
            m["yaml_source"] = "cache"; got += 1; continue
        tj = fetch(f"{BASE}/t/{m['id']}.json", as_json=True); time.sleep(DELAY)
        if not tj: m["yaml_source"] = "topic_fetch_failed"; continue
        posts = tj.get("post_stream", {}).get("posts", [])
        cooked = posts[0].get("cooked", "") if posts else ""
        docs, src = yaml_docs_from_html(cooked), "inline"
        if not docs: docs, src = gist_yaml(cooked), "gist"
        if not docs: docs, src = github_yaml(cooked), "github"
        if docs:
            open(cp, "w").write(max(docs, key=len)); m["yaml_source"] = src; got += 1
        else:
            m["yaml_source"] = "no_yaml_found"
        if (i + 1) % 25 == 0: print(f"  {i+1}/{len(manifest)}  retrieved={got}", flush=True)
    json.dump({"frame": {"source": "community.home-assistant.io category 53",
                         "ordering": "category default listing order",
                         "pages": PAGES, "fetched_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                         "inclusion": "all topics in window except pinned About post",
                         "extraction": "longest YAML document containing a top-level blueprint: key"},
               "n_topics": len(manifest), "n_with_yaml": got, "topics": manifest},
              open("results/prevalence_manifest.json", "w"), indent=2)
    print(f"\nDONE  topics={len(manifest)}  yaml={got}", flush=True)

if __name__ == "__main__":
    import urllib.parse  # noqa
    main()
