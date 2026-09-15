#!/usr/bin/env python3
"""Generate the reviewer-facing artifact guide (docs/artifact_guide.html).

Why a generator rather than a hand-written page
-----------------------------------------------
The reviewer guide has to state, accurately, which experiment produces which result
file and what number to expect. That mapping lives in the paper's regeneration table
(App. `tab:repromap`) and in ``results/MANIFEST_ma9.md``; a hand-maintained HTML copy
would drift the first time an experiment was re-run. So the results inventory and the
integrity checksums are DERIVED here at build time; only the explanatory prose
(purpose, threat model, how to drive the demo) is authored.

The claim index was previously derived from a separate ``CLAIMS.md``. That file
duplicated the paper's own regeneration table and has been removed, so the guide no
longer carries a claim index -- the table in the paper is the single source.

Re-run after any experiment changes:

    .venv/bin/python scripts/build_artifact_guide.py

Output is a single self-contained HTML file with no external requests -- it opens
offline from the artifact tarball, and the live monitor also serves it at
http://localhost:9120/howto when the demo stack is running.

VENUE: written for IEEE TDSC, which is single-anonymous -- the IEEE Computer Society
author resources list TDSC among the journals that do NOT offer double-anonymous
review. There is accordingly nothing to anonymise, and the guide points at the public
repository. The identifying-pattern guard at the end of this script is kept anyway: it
costs nothing and would catch a credential or a local path leaking into a published
page, which is a different hazard from author identity.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "results" / "MANIFEST_ma9.md"
RESULTS = ROOT / "results"
OUT = ROOT / "docs" / "artifact_guide.html"

# Public: TDSC is single-anonymous, so the guide links the real repository.
REPO_URL = "https://anonymous.4open.science/r/delaysteer"

# The datasets under an additive-only freeze: byte-identical to the pre-hardening
# release, never rewritten, every later experiment writing a NEW file instead.
#
# These are listed explicitly rather than scraped from MANIFEST_ma9.md because the
# manifest is not self-consistent about them: its per-table "frozen" column marks only
# metrics.csv and m2_rates.csv as YES, while its own summary line names three, and two
# further files (smartthings, recovery_matrix) are pinned operationally but appear in
# the table as "(existing)" / "no". Scraping any one of those would under-report the
# freeze set, so the authoritative list lives here and is VERIFIED on every build --
# a mismatch fails the build rather than quietly publishing a wrong checksum.
FROZEN_EXPECTED: dict[str, str] = {
    "metrics.csv": "e787eb4c9e45e1919a818a6a65868e59",
    "m2_rates.csv": "6cd5b9cb555f45c942c8aefe584fde14",
    "adaptive.csv": "7997ce45104224956623a49d2ad306aa",
    "smartthings.csv": "94681536f03ebd7b09b9beaac97900cb",
    "recovery_matrix.csv": "352827fae06b6c09ef45f94af1a7e0e3",
}

# Patterns that must never reach a published page. This guard used to enforce
# double-blind anonymity; TDSC is single-anonymous and the repository is public, so
# the author's identity is no longer the thing being protected. What is still worth
# failing the build over is a secret or a machine-local path that the generator
# scraped out of a config file or a stack trace and would otherwise publish.
LEAKS = [
    # a local home directory: identifies the build machine and never resolves for a reader
    ("local filesystem path", re.compile(r"/(?:Users|home)/[A-Za-z0-9_.-]+/")),
    # an e-mail address, which in this repo would come from a credentials file
    ("e-mail address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    # a Home Assistant long-lived access token (JWT)
    ("bearer token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")),
    # a SmartThings personal access token (bare UUID)
    ("SmartThings PAT",
     re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)),
]


# ----------------------------------------------------------------- derived inputs



def verify_frozen() -> tuple[dict[str, str], list[str]]:
    """Check every pinned dataset against its recorded md5.

    Returns (name -> live md5, problems). A non-empty problem list means a frozen file
    was altered or has gone missing, which is a data-integrity failure -- the build
    stops rather than publish a guide that certifies a checksum it did not verify.
    """
    live: dict[str, str] = {}
    problems: list[str] = []
    for name, expected in FROZEN_EXPECTED.items():
        p = RESULTS / name
        if not p.exists():
            problems.append(f"{name}: MISSING")
            continue
        got = hashlib.md5(p.read_bytes()).hexdigest()
        live[name] = got
        if got != expected:
            problems.append(f"{name}: expected {expected}, found {got}")
    return live, problems


def scan_results() -> list[dict]:
    out = []
    for p in sorted(RESULTS.glob("*.csv")):
        try:
            n = max(0, sum(1 for _ in p.open()) - 1)
        except Exception:
            n = 0
        out.append({"name": p.name, "rows": n,
                    "md5": hashlib.md5(p.read_bytes()).hexdigest()})
    return out


def git_rev() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(ROOT),
                              capture_output=True, text=True, timeout=10).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def md_inline(s: str) -> str:
    """Render the small subset of markdown that appears in the derived tables."""
    s = esc(s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"\*([^*]+)\*", r"<i>\1</i>", s)
    return s


# ------------------------------------------------------------------------- page

CSS = """
*{box-sizing:border-box}
:root{
  --bg:#080a0f; --panel:#0e1119; --panel2:#121724; --line:#1c2130; --dim:#6b7488;
  --text:#e8edf6; --danger:#ff2d55; --safe:#26d17c; --guard:#3d9bff; --amber:#ffb020;
  --mono:ui-monospace,"JetBrains Mono","SF Mono",Menlo,Consolas,monospace;
}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);
  font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
  background-image:radial-gradient(circle at 12% 0%,#111a2b 0%,transparent 55%);}
.wrap{max-width:1080px;margin:0 auto;padding:36px 22px 90px}
h1{font-size:30px;letter-spacing:-.4px;margin:0 0 6px}
h2{font-size:20px;margin:44px 0 12px;padding-top:14px;border-top:1px solid var(--line);letter-spacing:-.2px}
h3{font-size:15px;margin:26px 0 8px;color:var(--guard);letter-spacing:.02em}
p{margin:11px 0}
a{color:var(--guard)}
code{font-family:var(--mono);font-size:.88em;background:#0b0f18;border:1px solid var(--line);
  border-radius:4px;padding:1px 5px}
pre{background:#0b0f18;border:1px solid var(--line);border-radius:10px;padding:14px 16px;
  overflow-x:auto;font-family:var(--mono);font-size:12.6px;line-height:1.6}
pre code{background:none;border:0;padding:0;font-size:inherit}
.sub{color:var(--dim);font-size:13.5px;margin:0 0 18px}
.banner{border:1px solid var(--amber);background:linear-gradient(90deg,#3a2a08,var(--panel));
  border-radius:10px;padding:11px 15px;font-size:13px;margin:16px 0 26px}
.banner b{color:var(--amber)}
.lead{font-size:16.5px;line-height:1.72;border-left:3px solid var(--guard);padding-left:16px;color:#cfd8e8}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(232px,1fr));gap:13px;margin:16px 0}
.card{border:1px solid var(--line);background:var(--panel);border-radius:11px;padding:14px 16px}
.card .k{font-size:10.5px;letter-spacing:.13em;color:var(--dim);text-transform:uppercase}
.card .v{font-size:23px;font-weight:700;margin-top:5px;font-family:var(--mono)}
.card .d{font-size:12.5px;color:var(--dim);margin-top:4px}
table{width:100%;border-collapse:collapse;margin:14px 0;font-size:13px}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
th{background:var(--panel2);font-size:11px;letter-spacing:.09em;text-transform:uppercase;color:var(--dim)}
td code{font-size:11.6px;white-space:nowrap}
.scroll{overflow-x:auto;border-radius:10px}
.tag{display:inline-block;font-family:var(--mono);font-size:10.5px;padding:1px 7px;border-radius:20px;
  border:1px solid var(--line);color:var(--dim)}
.tag.ok{border-color:var(--safe);color:var(--safe)}
.tag.bad{border-color:var(--danger);color:var(--danger)}
.tag.warn{border-color:var(--amber);color:var(--amber)}
.tag.g{border-color:var(--guard);color:var(--guard)}
.note{border:1px solid var(--line);border-left:3px solid var(--amber);background:var(--panel);
  border-radius:0 10px 10px 0;padding:12px 16px;margin:16px 0;font-size:13.6px}
.note b{color:var(--amber)}
.good{border-left-color:var(--safe)} .good b{color:var(--safe)}
.flow{display:flex;align-items:stretch;gap:10px;flex-wrap:wrap;margin:18px 0}
.flow .n{flex:1;min-width:150px;border:1px solid var(--line);background:var(--panel);
  border-radius:10px;padding:12px 13px;font-size:12.6px}
.flow .n .t{font-family:var(--mono);font-size:11px;color:var(--dim);letter-spacing:.08em}
.flow .n.atk{border-color:var(--danger)} .flow .n.def{border-color:var(--guard)}
.toc{border:1px solid var(--line);background:var(--panel);border-radius:11px;padding:14px 18px;margin:22px 0}
.toc ol{margin:6px 0 0;padding-left:20px;columns:2;font-size:13.4px}
.toc li{margin:3px 0;break-inside:avoid}
.foot{margin-top:50px;padding-top:16px;border-top:1px solid var(--line);color:var(--dim);font-size:12px}
#live .v{font-size:15px}
@media (max-width:640px){ .toc ol{columns:1} .wrap{padding:22px 14px 60px} h1{font-size:24px} }
@media print{ body{background:#fff;color:#000} .card,pre,table,th,td{border-color:#bbb}
  pre,.card,.note,.toc{background:#f6f6f6} a{color:#000} }
"""


def build() -> str:
    frozen, _ = verify_frozen()
    results = scan_results()
    rev = git_rev()
    scripts = sorted(p.name for p in (ROOT / "delaysteer").glob("run_*.py"))
    total_rows = sum(r["rows"] for r in results)

    # --- claim index ------------------------------------------------------------

    # --- results inventory ------------------------------------------------------
    res_rows = "\n".join(
        f"<tr><td><code>{esc(r['name'])}</code></td><td>{r['rows']}</td>"
        f"<td><code>{r['md5'][:12]}…</code></td>"
        f"<td>{'<span class=\"tag ok\">frozen</span>' if r['name'] in frozen else '<span class=\"tag\">additive</span>'}</td></tr>"
        for r in results)

    frozen_rows = "\n".join(
        f"<tr><td><code>{esc(k)}</code></td><td><code>{esc(v)}</code></td></tr>"
        for k, v in sorted(frozen.items()))

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DelaySteer — Artifact Guide</title>
<style>{CSS}</style>
</head><body><div class="wrap">

<h1>DelaySteer — Artifact &amp; Demo Guide</h1>
<p class="sub">Delay-only decision-steering attacks and defenses for AI-agent smart homes ·
generated {date.today().isoformat()} · tree <code>{esc(rev)}</code></p>

<div class="banner"><b>ANONYMOUS SUBMISSION.</b> This page is written for double-blind review and
carries no author, affiliation, or identifying code URL. Anonymized artifact:
<a href="{REPO_URL}">{REPO_URL}</a></div>

<p class="lead">An AI-agent smart home runs a reason–act–observe loop: a language-model planner
reads device state and calls high-impact tools. We show an adversary who <b>only delays truthful
observations</b> — forging no value, altering no payload, compromising no model — can change
<i>what the planner decides next</i> and drive it into a security-invariant violation.
<b>TemporalGuard</b>, our defense, revalidates declarative critical facts at the commitment point.
This page explains the system, tells you how to run the live demo, and maps every claim in the
paper to the script and result file that produce it.</p>

<div class="toc"><b>Contents</b>
<ol>
<li><a href="#what">What the attack is</a></li>
<li><a href="#threat">Threat model — what the adversary may and may not do</a></li>
<li><a href="#quick">Quick start (5 minutes)</a></li>
<li><a href="#demo">The live demo — what you are looking at</a></li>
<li><a href="#scenarios">Running the two scenarios</a></li>
<li><a href="#results">Results inventory ({len(results)} files)</a></li>
<li><a href="#integrity">Data integrity &amp; reproducibility</a></li>
<li><a href="#limits">Limitations we do not paper over</a></li>
</ol></div>

<div class="grid">
    <div class="d">each mapped to a script + result file</div></div>
  <div class="card"><div class="k">Experiment entrypoints</div><div class="v">{len(scripts)}</div>
    <div class="d"><code>delaysteer/run_*.py</code></div></div>
  <div class="card"><div class="k">Result files</div><div class="v">{len(results)}</div>
    <div class="d">{total_rows:,} data rows under <code>results/</code></div></div>
  <div class="card"><div class="k">Frozen datasets</div><div class="v">{len(frozen)}</div>
    <div class="d">md5-pinned, never rewritten</div></div>
</div>

<h2 id="what">1 · What the attack is</h2>
<p>A door is <b>truly open</b>. The adversary withholds the sensor's "open" transition, so the agent
is still served the last <i>truthful</i> reading — "closed" — carrying its <b>original timestamp</b>.
The agent locks up, arms the alarm, and reports the house secured. The alarm is genuinely armed
around a genuinely open door.</p>

<div class="flow">
  <div class="n"><div class="t">GROUND TRUTH</div>front door is <b>OPEN</b></div>
  <div class="n atk"><div class="t">ADVERSARY</div>withholds the "open" transition; re-serves the
     earlier truthful "closed" <b>unmodified</b></div>
  <div class="n"><div class="t">AGENT BELIEF</div>reads <b>CLOSED</b> and commits</div>
  <div class="n atk"><div class="t">NO DEFENSE</div>arms the alarm, reports secured →
     <b>VIOLATION</b></div>
  <div class="n def"><div class="t">TEMPORALGUARD</div>revalidates freshness at the commit →
     <b>BLOCKED</b></div>
</div>

<p>The distinction that makes this a new class: prior smart-home timing work studies fixed
trigger-action rules, where a delay changes <i>when</i> a routine runs. In an agentic home the same
delay changes <i>what the system does next</i> — which recovery branch it takes, what it asks you to
confirm, whether it edits a future automation. We call the underlying condition <b>stale truth</b>,
or temporal TOCTOU: only the observation's <i>age</i> is adversarial, never its content.</p>

<div class="note good"><b>Why the defense is possible at all.</b> Because the adversary re-serves the
original payload, it also re-serves the original timestamp. It delays; it does not forge. A guard
that checks <i>freshness</i> at the commitment point therefore sees an old timestamp and refuses.
That is exactly what TemporalGuard does, and it is why the guarantee is real rather than
heuristic.</div>

<h2 id="threat">2 · Threat model</h2>
<div class="scroll"><table>
<tr><th>The adversary MAY</th><th>The adversary MAY NOT</th></tr>
<tr><td>Delay delivery of sensor observations, actuation acknowledgements, tool results,
confirmation context, and automation-edit feedback</td>
<td>Modify a payload, forge a value, or fabricate a device</td></tr>
<tr><td>Choose <i>which</i> fact to delay (requires hub- or integration-level placement)</td>
<td>Rewrite a timestamp (hypothesis H2: timestamp-unforgeability)</td></tr>
<tr><td>Adapt its delay to stay inside a configured freshness budget (A3)</td>
<td>Compromise the planner, the model, or steal credentials</td></tr>
<tr><td>Compromise an integration and control one channel's timestamps (A2)</td>
<td>Cause the platform's own state to become self-inconsistent</td></tr>
</table></div>
<p><b>Adversary lattice.</b> <span class="tag">A1</span> on-path, deliver-once — the strict case: one
stale-but-truthful observation, delivered exactly once and audited.
<span class="tag">A2</span> compromised integration — controls a channel's timestamps, so
same-channel freshness cannot be trusted.
<span class="tag">A3</span> adaptive — delays inside the budget. A static budget <i>bounds</i> A3;
active affirmation on a pollable fact shrinks the residual further.</p>

<h2 id="quick">3 · Quick start</h2>
<p>Deterministic results need no LLM, no cloud account, and no smart-home hardware. The live-agent
and live-platform experiments additionally need a local Ollama and a Home Assistant instance.</p>
<pre><code>python3 -m venv .venv &amp;&amp; .venv/bin/pip install -r requirements.txt

# 1. test suite (no external services required)
PYTHONPATH=. .venv/bin/pytest -q

# 2. the headline deterministic matrix -> results/metrics.csv
.venv/bin/python -m delaysteer.run_experiments

# 3. any single experiment (35 entrypoints; see the claim index below)
.venv/bin/python -m delaysteer.run_strict_delay
.venv/bin/python -m delaysteer.run_recovery_matrix</code></pre>
<div class="note"><b>Deterministic vs sampled.</b> Runs on the deterministic reference planner
reproduce <i>bit-for-bit</i>. Runs on a language-model backbone are sampled at non-zero temperature
and will not; those tables report <code>n</code> and Wilson 95% intervals, and each row records
<code>planner_runs_executed</code> so you can tell replication from sampling. Do not expect an
LLM row to match to the digit.</div>

<h2 id="demo">4 · The live demo</h2>
<p>The demo makes the deception visible in real time by putting <i>ground truth</i> and <i>what the
agent is served</i> side by side. Start the stack:</p>
<pre><code>scripts/launch_demo.sh          # delay proxy :8125, bridge :8788, monitor :9120
# then open http://localhost:9120</code></pre>
<div class="scroll"><table>
<tr><th>Port</th><th>Component</th><th>Role in the demo</th></tr>
<tr><td><code>:8123</code></td><td>Home Assistant</td><td><b>Ground truth.</b> The platform. Always
self-consistent and always correct — the deception never exists here.</td></tr>
<tr><td><code>:8125</code></td><td>Delay proxy</td><td><b>The adversary.</b> Sits between agent and
platform; captures a truthful response and re-serves it while armed.</td></tr>
<tr><td><code>:9120</code></td><td>Attack monitor</td><td>The dashboard: ground truth vs agent belief,
proxy counters, on-path event stream.</td></tr>
<tr><td><code>:9119</code></td><td>Agent chat</td><td>A production agent framework with native
function-calling; its tool calls are routed through <code>:8125</code>.</td></tr>
</table></div>
<h3>Reading the panels</h3>
<p><b>GROUND TRUTH</b> is a direct read of the platform on <code>:8123</code>. <b>AGENT BELIEF</b> is
the same entity read through the delay proxy on <code>:8125</code>. When they disagree, the agent is
committing on stale evidence. The <b>back door</b> is never attacked and is shown as a control: its
two panels should always agree.</p>
<div class="note"><b>Check the platform yourself.</b> Open Home Assistant during an attack. Everything
there is consistent and correct — door open, contact reports open. The split exists <i>only</i> in
what the agent is served. If the platform itself ever disagreed with itself, that would be forging,
not delaying, and would falsify the paper's central restriction.</div>

<h2 id="scenarios">5 · Running the two scenarios</h2>
<h3>Scenario A — the OPEN transition is delayed (security violation)</h3>
<p>Doors closed; an attacker opens one and launches the delay, so the "open" never arrives and the
agent still believes "closed".</p>
<pre><code>.venv/bin/python scripts/demo_attack.py --mode attack --arm-only
#   then open the front door yourself in Home Assistant
#   -> GROUND TRUTH becomes OPEN, AGENT BELIEF stays CLOSED
#   then send the chat prompt  ->  the agent arms the alarm  ->  VIOLATION

.venv/bin/python scripts/demo_attack.py --mode guard  --prep-only   # defense on -> BLOCKED
.venv/bin/python scripts/demo_attack.py --clear                     # reset between runs</code></pre>
<div class="note"><b>Ordering is the mechanism, not a convenience.</b> The proxy snapshots the
truthful reading when it is <i>armed</i>. Arm first, then move the door. If you open the door and
arm afterwards, the proxy captures "open" and nobody is deceived — the demo will appear to do
nothing.</div>

<h3>Scenario B — the CLOSED transition is delayed (availability)</h3>
<p>The mirror case: the door really closes, that update is withheld, and the agent keeps reading
"open" — so it refuses to arm a house that is already secure.</p>
<pre><code>.venv/bin/python scripts/demo_attack.py --mode availability --arm-only
#   then close the door yourself in Home Assistant
#   -> GROUND TRUTH becomes CLOSED, AGENT BELIEF stays OPEN  ->  FALSE REFUSAL</code></pre>
<div class="note"><b>This is not a security violation, and the interface says so.</b> No invariant is
broken: the house is genuinely secure and merely unarmed. It is an <i>availability</i> failure, shown
amber rather than red. Only Scenario A produces the paper's headline result.</div>

<h3>One-shot forms (no chat, no manual steps)</h3>
<pre><code>.venv/bin/python scripts/demo_attack.py --mode attack        # -> VIOLATION
.venv/bin/python scripts/demo_attack.py --mode guard         # -> BLOCKED
.venv/bin/python scripts/demo_attack.py --mode baseline      # -> NO VIOLATION
.venv/bin/python scripts/demo_attack.py --mode availability  # -> FALSE REFUSAL</code></pre>

<h2 id="results">6 · Results inventory</h2>
<p>{len(results)} result files, {total_rows:,} data rows. <span class="tag ok">frozen</span> files are
byte-identical to the pre-hardening release and are never rewritten; all later work is
<span class="tag">additive</span> — a new experiment writes a new file.</p>
<div class="scroll"><table>
<tr><th>File</th><th>Rows</th><th>md5 (prefix)</th><th>Status</th></tr>
{res_rows}
</table></div>

<h2 id="integrity">7 · Data integrity &amp; reproducibility</h2>
<p>Verify the frozen datasets have not been altered:</p>
<pre><code>md5 -q results/metrics.csv     # macOS
md5sum results/metrics.csv     # Linux</code></pre>
<div class="scroll"><table>
<tr><th>Frozen file</th><th>Expected md5</th></tr>
{frozen_rows}
</table></div>
<p>Cross-reference <code>results/MANIFEST_ma9.md</code> for the per-table mapping. Claim-level
traceability -- paper location, regenerating command and result file for every reported number --
is the regeneration table in the paper's artifact appendix.</p>

<h2 id="limits">8 · Limitations we do not paper over</h2>
<ul>
<li><b>Fact-selective delay needs placement.</b> Choosing <i>which</i> fact to delay requires a hub- or
integration-level position. We do not claim a remote or unprivileged attacker.</li>
<li><b>The guard's residual is availability.</b> A sustained delay cannot make the guard commit
unsafely, but past the recovery budget only escalation over a channel the adversary does not control
still completes the task.</li>
<li><b>Active poll was a no-op on our live deployment.</b> The refresh returns HTTP 200 in about
1.7&nbsp;ms, but <code>last_reported</code> did not advance on any probed entity, including an
integration-backed positive control. We report the effect and do <i>not</i> claim to have isolated the
cause. Poll latency is not poll efficacy.</li>
<li><b>Some portability cells are n=3.</b> They are demonstrations of portability, not rate estimates,
and are labelled as such wherever they appear.</li>
<li><b>LLM rows are sampled, not replicated.</b> See the note in §3.</li>
</ul>

<div class="foot">DelaySteer artifact guide · regenerate with
<code>.venv/bin/python scripts/build_artifact_guide.py</code> ·
served live at <code>http://localhost:9120/howto</code> when the demo stack is running.</div>
</div></body></html>"""


def main() -> int:
    _, problems = verify_frozen()
    if problems:
        print("FROZEN-DATA CHECK FAILED -- refusing to build the reviewer guide:")
        for pr in problems:
            print("  " + pr)
        print("A frozen dataset must be byte-identical to its recorded md5. Restore it, or\n"
              "if the change is intentional, write a NEW additive file instead.")
        return 3
    html = build()
    for label, pat in LEAKS:
        hit = pat.search(html)
        if hit:
            print(f"LEAK GUARD FAILED: output contains a {label} ({hit.group(0)[:12]!r}...)\n"
                  f"Refusing to write a page that would publish a secret or a local path.")
            return 2
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(html)
    results = scan_results()
    print(f"wrote {OUT.relative_to(ROOT)}  ({len(html):,} bytes)")
    print(f"  {len(results)} result files")
    print(f"  frozen-data check: passed ({len(FROZEN_EXPECTED)} datasets verified byte-identical)")
    print(f"  leak guard:        passed ({len(LEAKS)} secret/path patterns checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
