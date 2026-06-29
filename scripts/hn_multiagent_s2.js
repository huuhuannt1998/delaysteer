#!/usr/bin/env node
/*
 * MA-7: second inter-agent scenario + distributed-guard benign cost + determinism,
 * on the REAL HearthNet protocol (released implementation, scripted-hub config).
 * FRAMING: a gap OUTSIDE the threat model even freshness-aware systems adopt -- never
 * "broke HearthNet". Different OBSERVATION type than MA-6 (smoke/CO hazard vs presence)
 * driving a different action on different devices (audible alert via speakers), to show
 * the commit-fresh/evidence-stale gap is a property of the OBSERVATION CHANNEL.
 *
 * Pattern (natural HA automation: smoke detector -> smart-speaker alert): jeeves (HA
 * manager) observes a smoke/CO sensor and reports it via a real `response` message
 * (which Dewey does NOT freshness-check). Hub rule: if smoke is detected, fire the
 * emergency alert (speakers -> alarm); if clear, the normal evening scene (speakers ->
 * ambient/low). The delay-only adversary re-serves the stale-but-truthful prior
 * "all-clear" after smoke is real; the hub omits the alert and instead commits the
 * normal evening scene -- a real command Dewey ACCEPTS with a valid lease + fresh
 * base_commit (commit-freshness satisfied) -- while a fire is real (evidence-freshness
 * violated). Violation = the missing alarm.
 *
 * Items: (1) four-row lattice; (2) distributed-guard benign cost (extra round-trip,
 * latency, benign false-blocks counted separately); (3) determinism (argued + N=5).
 */
'use strict';
const path = require('path');
const fs = require('fs');

const HN = process.env.HEARTHNET_HOME || require('os').homedir() + '/hearthnet-ext';
const { createClient, msg, send, sleep, getHEAD, issueLease } = require(path.join(HN, 'demo/demo-common'));
const DEVICES = path.join(HN, 'groundplane-state', 'state', 'devices.json');
const SPK = 'speakers';                 // existing device, authorized for jeeves
const HEARTBEAT_MS = 250;               // L1 challenge-response tolerance
const STALE_MS = 30000;                 // the delayed observation is 30s old

function spk() { try { return JSON.parse(fs.readFileSync(DEVICES, 'utf8'))[SPK] || {}; } catch { return {}; } }

// One real actuation: hub issues a signed lease; manager executes (consumes lease) and
// reports the result (updates the Git shadow). Returns the lease_id for log correlation.
async function actuate(rupert, jeeves, desired, content) {
  const lease = issueLease('jeeves', SPK, 'set_state', desired, content);
  if (!lease) return null;
  await send(rupert, 'agents/inbox/jeeves',
    msg('rupert', 'jeeves', 'lease_grant', `Lease: ${SPK}`, { lease, base_commit: getHEAD(), target_device: SPK }));
  await send(rupert, 'agents/mirror',
    msg('rupert', 'jeeves', 'lease_grant', `Lease: ${SPK}`, { lease, base_commit: getHEAD(), target_device: SPK }));
  await sleep(250);
  await send(jeeves, 'agents/mirror',
    msg('jeeves', 'device', 'execute', content,
      { lease, target_device: SPK, operation: 'set_state', desired_state: desired, base_commit: getHEAD(), scene: 'ma7' }));
  await sleep(400);
  await send(jeeves, 'agents/inbox/rupert',
    msg('jeeves', 'rupert', 'execute_result', `${content} — done`,
      { lease: { lease_id: lease.lease_id }, target_device: SPK, desired_state: desired, resulting_commit: getHEAD(), scene: 'ma7' }));
  await send(jeeves, 'agents/mirror',
    msg('jeeves', 'rupert', 'execute_result', `${content} — done`,
      { lease: { lease_id: lease.lease_id }, target_device: SPK, desired_state: desired, resulting_commit: getHEAD(), scene: 'ma7' }));
  await sleep(400);
  return lease.lease_id;
}

// A real inter-agent challenge->re-affirm round-trip (what the distributed guard adds).
// darcy replies with a re-sampled observation; under the delay adversary the re-affirm
// is itself delayed/stale (the adversary cannot produce a post-challenge affirmation for
// the stale value without forging a timestamp). Returns {affirmed_at, latency_ms}.
function challengeRoundTrip(rupert, darcy, delayed) {
  return new Promise(async (resolve) => {
    const id = 'chal-' + Math.floor(getHEAD().length * 1) + '-' + (delayed ? 'd' : 'f') + '-' + Date.now() % 100000;
    const t0 = Date.now();
    const handler = (t, m) => {
      try {
        const o = JSON.parse(m.toString());
        if (o.type === 'response' && o.parent_msg_id === id) {
          rupert.removeListener('message', handler);
          resolve({ affirmed_at: o.affirmed_at, latency_ms: Date.now() - t0 });
        }
      } catch {}
    };
    rupert.on('message', handler);
    // darcy re-affirms on challenge
    const onChal = (t, m) => {
      try {
        const o = JSON.parse(m.toString());
        if (o.type === 'task' && o.content === id) {
          darcy.removeListener('message', onChal);
          const affirmed_at = delayed ? Date.now() - STALE_MS : Date.now();   // adversary delays the re-affirm too
          send(darcy, 'agents/inbox/rupert',
            msg('darcy', 'rupert', 'response', 're-affirm', { observed: { smoke: 'clear' }, affirmed_at, parent_msg_id: id }));
        }
      } catch {}
    };
    darcy.subscribe('agents/inbox/darcy');
    darcy.on('message', onChal);
    await send(rupert, 'agents/inbox/darcy', msg('rupert', 'darcy', 'task', id, {}));
    setTimeout(() => { rupert.removeListener('message', handler); resolve({ affirmed_at: null, latency_ms: Date.now() - t0 }); }, 3000);
  });
}

async function runConfig({ label, trulySmoke, delay, guard }) {
  const rupert = createClient('rupert'), darcy = createClient('darcy'), jeeves = createClient('jeeves');
  rupert.subscribe('agents/inbox/rupert');
  await sleep(300);
  await actuate(rupert, jeeves, { volume: 30, source: 'idle' }, 'S2-RESET speakers idle');   // baseline

  // (1) manager observes smoke and reports (real `response`; Dewey does not freshness-check it)
  const observed = delay ? 'clear' : (trulySmoke ? 'detected' : 'clear');
  const affirmed_at = Date.now() - (delay ? STALE_MS : 0);
  await send(darcy, 'agents/inbox/rupert',
    msg('darcy', 'rupert', 'response', `smoke: ${observed}`, { observed: { smoke: observed }, affirmed_at, base_commit: getHEAD() }));
  await send(darcy, 'agents/mirror',
    msg('darcy', 'rupert', 'response', `smoke: ${observed}`, { observed: { smoke: observed }, affirmed_at, base_commit: getHEAD() }));
  await sleep(200);

  // (2) hub decides. Distributed TemporalGuard: challenge-response on the observation.
  let guardBlocked = false, guardLatency = null;
  if (guard) {
    const t_challenge = Date.now();
    const rt = await challengeRoundTrip(rupert, darcy, delay);
    guardLatency = rt.latency_ms;
    const valueAge = rt.affirmed_at == null ? Infinity : (t_challenge - rt.affirmed_at);
    if (valueAge > HEARTBEAT_MS) guardBlocked = true;     // stale/absent affirmation -> cannot trust the observation
  }

  // hub action: alert on detected, OR fail-safe alert when the guard rejects a stale obs; else normal scene
  if ((observed === 'detected') || guardBlocked) {
    await actuate(rupert, jeeves, { volume: 100, source: 'alarm' },
      guardBlocked ? 'S2-ALERT (guard: stale obs -> fail-safe)' : 'S2-ALERT smoke detected');
  } else {
    await actuate(rupert, jeeves, { volume: 15, source: 'ambient' }, 'S2-EVENING normal scene');   // commit-fresh artifact in attack arm
  }

  const alertFired = spk().source === 'alarm';
  const violation = trulySmoke && !alertFired;            // missing alarm during a real fire
  rupert.end(); darcy.end(); jeeves.end();
  await sleep(150);
  return { label, trulySmoke, delay, guard, observed, alert_fired: alertFired,
    guard_blocked: guardBlocked, guard_latency_ms: guardLatency,
    commit_freshness_satisfied: (!alertFired && spk().source === 'ambient') || alertFired,
    evidence_freshness_violated: violation, violation };
}

async function lattice() {
  const configs = [
    { label: 'benign_natural',  trulySmoke: false, delay: false, guard: false },
    { label: 'control_nodelay', trulySmoke: true,  delay: false, guard: false },
    { label: 'attack_delay',    trulySmoke: true,  delay: true,  guard: false },
    { label: 'attack_guard',    trulySmoke: true,  delay: true,  guard: true  },
  ];
  const rows = [];
  for (const c of configs) rows.push(await runConfig(c));
  return rows;
}

async function guardBenignCost(n = 20) {
  // benign path (truly clear, FRESH observation) with the guard on: measure the extra
  // challenge round-trip latency and any benign false-blocks (a fresh obs wrongly rejected).
  const rupert = createClient('rupert'), darcy = createClient('darcy');
  rupert.subscribe('agents/inbox/rupert');
  await sleep(300);
  const lat = []; let falseBlocks = 0;
  for (let i = 0; i < n; i++) {
    const t_challenge = Date.now();
    const rt = await challengeRoundTrip(rupert, darcy, false);   // fresh re-affirm
    lat.push(rt.latency_ms);
    const valueAge = rt.affirmed_at == null ? Infinity : (t_challenge - rt.affirmed_at);
    if (valueAge > HEARTBEAT_MS) falseBlocks++;                  // fresh obs wrongly blocked = false alarm
    await sleep(50);
  }
  rupert.end(); darcy.end();
  lat.sort((a, b) => a - b);
  return { trials: n, extra_roundtrips_per_decision: 1, extra_messages_per_decision: 2,
    challenge_latency_ms_mean: +(lat.reduce((a, b) => a + b, 0) / lat.length).toFixed(2),
    challenge_latency_ms_p95: lat[Math.floor(0.95 * (lat.length - 1))],
    challenge_latency_ms_max: lat[lat.length - 1],
    benign_false_blocks: falseBlocks, benign_false_block_rate: +(falseBlocks / n).toFixed(3),
    heartbeat_ms: HEARTBEAT_MS };
}

async function main() {
  const out = path.join(__dirname, '..', 'results');
  // Item 1 + Item 3: run the lattice N=5 for determinism
  const runs = [];
  for (let r = 0; r < 5; r++) runs.push(await lattice());
  const sig = rows => rows.map(r => `${r.label}:${r.violation?1:0}:${r.alert_fired?1:0}:${r.guard_blocked?1:0}`).join('|');
  const sigs = runs.map(sig);
  const identical = sigs.every(s => s === sigs[0]);

  const rows = runs[0];
  console.log('\n=== MA-7 Item 1: second scenario (smoke/CO -> fire-alert) on real HearthNet ===');
  for (const r of rows)
    console.log(`[${r.label}] truly_smoke=${r.trulySmoke} delay=${r.delay} guard=${r.guard} -> observed=${r.observed} ` +
      `alert_fired=${r.alert_fired} commit_fresh=${r.commit_freshness_satisfied} VIOLATION=${r.violation}${r.guard_blocked?' [guard fail-safe]':''}`);

  // Item 2
  console.log('\n=== MA-7 Item 2: distributed-guard benign cost ===');
  const cost = await guardBenignCost(20);
  console.log(`  extra round-trips/decision=${cost.extra_roundtrips_per_decision} (+${cost.extra_messages_per_decision} msgs); ` +
    `challenge latency mean=${cost.challenge_latency_ms_mean}ms p95=${cost.challenge_latency_ms_p95}ms max=${cost.challenge_latency_ms_max}ms; ` +
    `benign false-blocks=${cost.benign_false_blocks}/${cost.trials} (rate ${cost.benign_false_block_rate})`);

  // Item 3
  console.log('\n=== MA-7 Item 3: determinism ===');
  console.log(`  N=5 lattice runs identical: ${identical}  (signature: ${sigs[0]})`);

  const cols = ['label','trulySmoke','delay','guard','observed','alert_fired','guard_blocked','commit_freshness_satisfied','evidence_freshness_violated','violation'];
  fs.writeFileSync(path.join(out, 'multiagent_s2.csv'),
    [cols.join(',')].concat(rows.map(r => cols.map(c => r[c]).join(','))).join('\n') + '\n');
  fs.writeFileSync(path.join(out, 'multiagent_guardcost.json'), JSON.stringify(cost, null, 2));
  fs.writeFileSync(path.join(out, 'multiagent_determinism.json'),
    JSON.stringify({ n_runs: 5, identical, signature: sigs[0], all_signatures: sigs,
      by_construction: 'scripted hub + deterministic relays + fixed 30s stale schedule + fixed heartbeat => identical outcome each run' }, null, 2));

  const L = Object.fromEntries(rows.map(r => [r.label, r]));
  console.log('\n--- summary ---');
  console.log(`benign baseline completes (no false alarm when truly clear): ${!L.benign_natural.alert_fired && !L.benign_natural.violation}`);
  console.log(`safety mechanism works on fresh evidence (control fires alert): ${L.control_nodelay.alert_fired && !L.control_nodelay.violation}`);
  console.log(`STEERED by delay only (control safe; same true state, delayed -> violation): ${!L.control_nodelay.violation && L.attack_delay.violation}`);
  console.log(`commit-fresh evening-scene committed while fire real (attack arm): ${L.attack_delay.commit_freshness_satisfied && L.attack_delay.violation}`);
  console.log(`distributed guard closes the gap (fail-safe alert): ${L.attack_guard.violation === false && L.attack_guard.guard_blocked}`);
  console.log('wrote results/multiagent_s2.csv, multiagent_guardcost.json, multiagent_determinism.json');
}
main().catch(e => { console.error(e); process.exit(1); });
