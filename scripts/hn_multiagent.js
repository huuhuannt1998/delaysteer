#!/usr/bin/env node
/*
 * MA-6 Phase B: delay-only steering of a truthful INTER-AGENT OBSERVATION in the
 * REAL HearthNet protocol (released implementation, scripted-hub demo configuration).
 *
 * FRAMING (binding): a gap OUTSIDE the threat model even freshness-aware systems
 * adopt -- NEVER "broke HearthNet". HearthNet's base_commit freshness is structurally
 * gated to command messages (task/lease_request/execute, dewey-librarian.js:561); the
 * observation channel (response/execute_result) is never freshness-checked. The gap is
 * in the protocol's freshness handling, which is hub-agnostic; we use the scripted hub
 * for a clean single-cause demonstration (NOT the LLM-hub version).
 *
 * Pattern (the most basic multi-agent home pattern: manager observes -> reports -> hub
 * decides): a mobile manager (darcy) observes PRESENCE and reports it to the hub
 * (rupert) as a real `response` message (which Dewey does NOT freshness-check). Hub
 * rule: run the thermostat in comfort/HEAT only when the user is present; keep it OFF
 * when away (don't run climate for an empty home). The delay-only adversary re-serves a
 * stale-but-truthful prior "home" observation after the user has truly left; the hub
 * starts heating an empty home while the resulting execute carries a FRESH base_commit
 * that Dewey ACCEPTS (commit-freshness satisfied, evidence-freshness violated).
 *
 * Uses ONLY real HearthNet message types + real Dewey enforcement (real signed leases,
 * real base_commit/lease validation, real Git shadow). Requires Dewey already running.
 */
'use strict';
const path = require('path');
const fs = require('fs');

const HN = '/Users/huanbui/Desktop/hearthnet-ext';
const { createClient, msg, send, sleep, getHEAD, issueLease } = require(path.join(HN, 'demo/demo-common'));
const DEVICES = path.join(HN, 'groundplane-state', 'state', 'devices.json');
const DEV = 'thermostat';            // authorized for jeeves (policy: set_state)
const HEARTBEAT_MS = 250;            // L1 challenge-response tolerance (sensor heartbeat)

function thermostatMode() {
  try { return (JSON.parse(fs.readFileSync(DEVICES, 'utf8'))[DEV] || {}).mode; } catch { return undefined; }
}

// One real actuation: hub issues a signed lease, manager executes (consumes lease) and
// reports the result (updates the Git shadow). Returns {issued, rejected}.
async function actuate(rupert, jeeves, desired, content, onReject) {
  const lease = issueLease('jeeves', DEV, 'set_state', desired, content);
  if (!lease) return { issued: false, rejected: true };   // policy denied (shouldn't happen for thermostat)
  const grant = msg('rupert', 'jeeves', 'lease_grant', `Lease: ${DEV} set_state`,
    { lease, base_commit: getHEAD(), target_device: DEV });
  await send(rupert, 'agents/inbox/jeeves', grant);
  await send(rupert, 'agents/mirror', grant);
  await sleep(250);
  const exec = msg('jeeves', 'device', 'execute', content,
    { lease, target_device: DEV, operation: 'set_state', desired_state: desired,
      base_commit: getHEAD(), scene: 'ma6' });               // FRESH base_commit (current HEAD)
  await send(jeeves, 'agents/mirror', exec);
  await sleep(450);                                           // Dewey validates + consumes the lease
  const res = msg('jeeves', 'rupert', 'execute_result', `${content} — done`,
    { lease: { lease_id: lease.lease_id }, target_device: DEV, desired_state: desired,
      resulting_commit: getHEAD(), scene: 'ma6' });
  await send(jeeves, 'agents/inbox/rupert', res);
  await send(jeeves, 'agents/mirror', res);
  await sleep(450);                                           // Dewey updates the shadow
  return { issued: true, rejected: false };
}

async function runConfig({ label, trulyPresent, delay, guard }) {
  const rupert = createClient('rupert');
  const darcy = createClient('darcy');
  const jeeves = createClient('jeeves');
  await sleep(300);

  let heatRejected = false;
  rupert.subscribe('agents/mirror');
  rupert.on('message', (t, m) => {
    try { const o = JSON.parse(m.toString());
      if (o.type === 'rejection' && (o.content || '').includes('MA6-HEAT')) heatRejected = true;
    } catch {}
  });

  // baseline: thermostat OFF (real actuation) so each run starts clean
  await actuate(rupert, jeeves, { mode: 'off' }, 'MA6-RESET thermostat off');

  // (1) manager OBSERVES presence and reports to the hub (real `response`; not freshness-checked).
  //     delay => re-serve the stale-but-truthful prior "home" reading (sampled 30s ago).
  const observedPresent = delay ? true : trulyPresent;
  const affirmed_at = Date.now() - (delay ? 30000 : 0);
  const obs = msg('darcy', 'rupert', 'response',
    `presence: ${observedPresent ? 'HOME' : 'AWAY'}`,
    { observed: { presence: observedPresent ? 'home' : 'away' }, affirmed_at, base_commit: getHEAD() });
  await send(darcy, 'agents/inbox/rupert', obs);
  await send(darcy, 'agents/mirror', obs);
  await sleep(250);

  // (2) hub decides. Distributed TemporalGuard (optional): challenge-response on the
  //     inter-agent observation -- require it AFFIRMED within one heartbeat of the commit.
  const t_challenge = Date.now();
  const guardBlocked = guard && (t_challenge - affirmed_at > HEARTBEAT_MS);

  let hubActed = false;
  if (observedPresent && !guardBlocked) {           // rule: heat only if user present
    hubActed = true;
    await actuate(rupert, jeeves, { mode: 'heat', setpoint: 22 }, 'MA6-HEAT comfort (user present)');
  }

  const heating = thermostatMode() === 'heat';
  const deweyAccepted = hubActed && heating && !heatRejected;   // shadow only updates on valid lease + base_commit
  const violation = heating && !trulyPresent;                   // running climate in an empty home

  rupert.end(); darcy.end(); jeeves.end();
  await sleep(150);
  return { label, trulyPresent, delay, guard, observed: observedPresent ? 'home' : 'away',
    hub_acted: hubActed, guard_blocked: guardBlocked, heating,
    commit_freshness_satisfied: deweyAccepted, evidence_freshness_violated: violation, violation };
}

async function main() {
  const configs = [
    { label: 'benign_natural',  trulyPresent: true,  delay: false, guard: false },
    { label: 'control_nodelay', trulyPresent: false, delay: false, guard: false },
    { label: 'attack_delay',    trulyPresent: false, delay: true,  guard: false },
    { label: 'attack_guard',    trulyPresent: false, delay: true,  guard: true  },
  ];
  const rows = [];
  for (const c of configs) rows.push(await runConfig(c));

  const cols = ['label','trulyPresent','delay','guard','observed','hub_acted','guard_blocked',
    'heating','commit_freshness_satisfied','evidence_freshness_violated','violation'];
  console.log('\n=== MA-6 Phase B: delay-only inter-agent OBSERVATION steering (real HearthNet protocol, scripted-hub) ===');
  for (const r of rows)
    console.log(`[${r.label}] truly_present=${r.trulyPresent} delay=${r.delay} guard=${r.guard} -> observed=${r.observed} ` +
      `heating=${r.heating} commit_fresh=${r.commit_freshness_satisfied} VIOLATION=${r.violation}${r.guard_blocked?' [guard blocked obs]':''}`);

  const out = '/Users/huanbui/Desktop/DelaySteer/results';
  fs.writeFileSync(path.join(out, 'multiagent.csv'),
    [cols.join(',')].concat(rows.map(r => cols.map(c => r[c]).join(','))).join('\n') + '\n');
  fs.writeFileSync(path.join(out, 'multiagent.json'), JSON.stringify(rows, null, 2));

  const L = Object.fromEntries(rows.map(r => [r.label, r]));
  console.log(`\nbenign baseline completes correctly (heats when truly present, no violation): ${L.benign_natural.heating && !L.benign_natural.violation}`);
  console.log(`STEERED by delay only (control safe; same true state, delayed -> violation): ${!L.control_nodelay.violation && L.attack_delay.violation}`);
  console.log(`commit-freshness SATISFIED while evidence stale during the attack: ${L.attack_delay.commit_freshness_satisfied && L.attack_delay.violation}`);
  console.log(`distributed TemporalGuard closes the gap (challenge-response, heartbeat ${HEARTBEAT_MS}ms): ${L.attack_guard.violation === false && L.attack_guard.guard_blocked}`);
  console.log('wrote results/multiagent.csv');
}
main().catch(e => { console.error(e); process.exit(1); });
