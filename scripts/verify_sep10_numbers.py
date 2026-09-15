#!/usr/bin/env python3
"""Check every number the Sep 10 revision put into the body against its source file.

Written after one of them was wrong: the body said "21 decide on sensor state and only 10
bound that fact's age", which silently read two marginals as an intersection -- only 5 of
the 21 bound an age. A number that is right in the CSV and wrong in the prose is the failure
mode a build gate cannot see, so this script exists to be re-run after every edit that moves
a number.

  .venv/bin/python scripts/verify_sep10_numbers.py
"""
import csv, json, re, os
os.chdir('/Users/anonymous/Desktop/DelaySteer')
ok = True
def chk(label, got, want):
    global ok
    good = (str(got) == str(want))
    ok &= good
    print(f"  [{'ok ' if good else 'BAD'}] {label:52s} paper={want}  source={got}")

# --- E4 ---
s = {(r['case'], r['style']): r for r in csv.DictReader(open('results/e4_order_witness_summary.csv'))}
chk("E4 selective hold, periodic, blocked", s[('selective_hold','periodic')]['blocked'], "20/20")
loss = int(s[('loss','periodic')]['blocked'].split('/')[0]) + int(s[('loss','on_change')]['blocked'].split('/')[0])
lossn = int(s[('loss','periodic')]['blocked'].split('/')[1]) + int(s[('loss','on_change')]['blocked'].split('/')[1])
chk("E4 loss admitted (0 blocked of 40)", f"{lossn-loss}/{lossn}", "40/40")
chk("E4 blanket hold periodic blocked", s[('blanket_hold','periodic')]['blocked'], "0/20")
chk("E4 selective hold on_change blocked", s[('selective_hold','on_change')]['blocked'], "0/20")
g = json.load(open('results/e4_order_witness_guard.json'))
chk("E4 gate blocks on inversion", str(g[0]['allowed']), "False")
chk("E4 gate allows on loss", str(g[1]['allowed']), "True")

# --- E6 ---
m = json.load(open('results/e6_workflow_first_meta.json'))
chk("E6 frame size", m['frame_size'], 305)
chk("E6 drawn", m['n_drawn'], 40)
chk("E6 sensor-gated", m['rates']['reads_sensor_state'], "21/40")
chk("E6 age bounded AMONG sensor-gated", m['rates']['age_bounded_AMONG_sensor_gated'], "5/21")
chk("E6 timeout -> recovery", m['rates']['timeout_triggers_recovery'], "9/40")
chk("E6 fallback latitude", m['rates']['fallback_latitude'], "7/40")
chk("E6 policy edit permitted", m['rates']['policy_edit_permitted'], "10/40")
chk("E6 eligible", m['eligible'], "2/40")
r = m['ineligible_reasons']
chk("E6 ineligible: no sensor-gated decision", r['no sensor-gated decision'], 19)
chk("E6 ineligible: no high-impact action", r['no high-impact action to commit'], 18)
chk("E6 ineligible: fact off surface", r['gating fact outside the tool surface'], 1)

# --- E2 mechanism (not yet in the body, but checked so it is ready) ---
mech = {r['condition']: r for r in csv.DictReader(open('results/e2_lp_relay_mechanism.csv'))}
chk("E2 modify rejected", mech['modify']['rejected_at_hub'], "50")
chk("E2 originate rejected", mech['originate']['rejected_at_hub'], "50")
chk("E2 replay rejected", mech['replay']['rejected_at_hub'], "50")
chk("E2 publish-to-dev ACL denied", mech['publish_to_dev']['broker_acl_denied'], "50")
chk("E2 hold 15s accepted", mech['hold_15s']['accepted_at_hub'], "50")
chk("E2 hold 15s byte-equal", mech['hold_15s']['bytes_equal_to_source'], "50")
# --- E1 ---
e1 = {(r['case'], r['arm'], r['delay']): r
      for r in csv.DictReader(open('results/e1_agent_specific_summary.csv'))}
chk("E1 case A delayed violations", e1[('A','planner','1')]['violations'] + "/" + e1[('A','planner','1')]['n'], "0/20")
chk("E1 case A honest violations", e1[('A','planner','0')]['violations'] + "/" + e1[('A','planner','0')]['n'], "0/20")
chk("E1 case A planner-only branch", e1[('A','planner','1')]['planner_only_branches'], "escalated")
chk("E1 case B delayed violations", e1[('B','planner','1')]['violations'] + "/" + e1[('B','planner','1')]['n'], "12/20")
chk("E1 case B honest violations", e1[('B','planner','0')]['violations'] + "/" + e1[('B','planner','0')]['n'], "0/20")
chk("E1 case B attributable pp", e1[('B','planner','1')]['attributable_pp'], "60.0")
chk("E1 case B honest branch", e1[('B','planner','0')]['branches'], "granted_confirmed=20")
chk("E1 case B rule under delay", e1[('B','rule','1')]['branches'], "failed_closed=1")

# --- E3 (live) ---
e3 = {(r['condition'], r['guard_mode']): r
      for r in csv.DictReader(open('results/e3_live_safeliveness_summary.csv'))}
e3rows = list(csv.DictReader(open('results/e3_live_safeliveness.csv')))
chk("E3 episodes total", len(e3rows), 36)
chk("E3 violations anywhere", sum(1 for r in e3rows if r['invariant_violation']=='True'), 0)
chk("E3 normal fail_closed completion", e3[('normal','fail_closed')]['benign_completion'], "0/6")
chk("E3 normal safe-liveness completion", e3[('normal','user_escalation')]['benign_completion'], "6/6")
chk("E3 attack safe-liveness escalated", e3[('attack','user_escalation')]['escalated'], "6/6")
chk("E3 sustained physically secured", sum(1 for r in e3rows if r['condition']=='sustained'
    and r['actual_locked']=='True' and r['actual_armed']=='True'), 6)
chk("E3 sustained claimed secure", sum(1 for r in e3rows if r['condition']=='sustained'
    and r['secure_claim']=='True'), 0)
chk("E3 normal safe-liveness mean wall (s, rounded)", round(float(e3[('normal','user_escalation')]['mean_wall_s'])), 85)
chk("E3 normal fail_closed mean wall (s, rounded)", round(float(e3[('normal','fail_closed')]['mean_wall_s'])), 219)
chk("E3 attack safe-liveness mean wall (s, rounded)", round(float(e3[('attack','user_escalation')]['mean_wall_s'])), 347)
# P95 wall column added to the E3 appendix table on 2026-09-11 (plan-listed metric)
for (c, g), want in {('normal','fail_closed'): 321, ('normal','user_escalation'): 86,
                     ('transient','user_escalation'): 90, ('attack','fail_closed'): 293,
                     ('attack','user_escalation'): 419, ('sustained','user_escalation'): 121}.items():
    chk(f"E3 {c}/{g} P95 wall (s, rounded)", round(float(e3[(c, g)]['p95_wall_s'])), want)
chk("E3 recovery time never measured (column reads ---)",
    all(not e3[k]['mean_recovery_time_s'] for k in e3), True)

# --- E7 ---
e7 = {(r['task_class'], r['defense']): r
      for r in csv.DictReader(open('results/e7_fusion_applicability_summary.csv'))}
for cls in ("atomic", "multifact", "human"):
    chk(f"E7 {cls}: contract ASR interval", e7[(cls,'guard')]['asr_interval'], "0/8")
    chk(f"E7 {cls}: contract utility honest", e7[(cls,'guard')]['utility_honest'], "8/8")
    chk(f"E7 {cls}: fusion ASR interval", e7[(cls,'fusion')]['asr_interval'], "0/8")
    chk(f"E7 {cls}: undefended ASR standard", e7[(cls,'none')]['asr_standard'], "8/8")
chk("E7 per-device fusion FAILS on interval", e7[('multifact','fusion_perdevice')]['asr_interval'], "8/8")
chk("E7 naive human fusion FAILS on interval", e7[('human','fusion_naive')]['asr_interval'], "8/8")
chk("E7 multifact mega-tool facts absorbed", e7[('multifact','fusion')]['facts_absorbed'], "3")
chk("E7 multifact mega-tool LOC", e7[('multifact','fusion')]['loc'], "14")
chk("E7 atomic fusion LOC", e7[('atomic','fusion')]['loc'], "8")
chk("E7 human fusion LOC", e7[('human','fusion')]['loc'], "16")
chk("E7 human fusion atomicity enforceable", e7[('human','fusion')]['atomicity_enforceable'], "no")
chk("E7 multifact mega-tool changed semantics", e7[('multifact','fusion')]['semantics_changed'], "yes")
# fused-tool count column added to the E7 appendix table on 2026-09-11 (plan-listed metric)
for (c, d), want in {('atomic','fusion'): "1", ('multifact','fusion'): "1",
                     ('multifact','fusion_perdevice'): "3", ('human','fusion'): "1",
                     ('human','fusion_naive'): "1"}.items():
    chk(f"E7 {c}/{d} fused tools", e7[(c, d)]['fused_tools'], want)

# --- E5 (measured path timing) ---
e5 = {(r['path'], r['quantity']): r
      for r in csv.DictReader(open('results/e5_timing_summary.csv'))}
ha, cl = e5[('home_assistant','read_rtt')], e5[('smartthings_cloud','read_rtt')]
chk("E5 local reads n", ha['n'], "3510")
chk("E5 cloud reads n", cl['n'], "2808")
chk("E5 local median ms", round(float(ha['median_s'])*1000, 1), 3.3)
chk("E5 local P99 ms", round(float(ha['p99_s'])*1000, 1), 24.6)
chk("E5 local max ms", round(float(ha['max_s'])*1000, 1), 91.3)
chk("E5 cloud median ms", round(float(cl['median_s'])*1000, 1), 184.6)
chk("E5 cloud P99 ms", round(float(cl['p99_s'])*1000, 1), 326.6)
chk("E5 cloud max ms", round(float(cl['max_s'])*1000, 1), 686.4)
chk("E5 median ratio cloud/local", round(float(cl['median_s'])/float(ha['median_s'])), 56)
_rtt = [float(r['rtt_s']) for r in csv.DictReader(open('results/e5_timing_read_rtt.csv'))
        if r['platform'] == 'home_assistant' and r['ok'] == '1']
chk("E5 local pct over the 50 ms tolerance",
    round(100*sum(1 for x in _rtt if x > 0.05)/len(_rtt), 1), 0.1)
_cl = [float(r['rtt_s']) for r in csv.DictReader(open('results/e5_timing_read_rtt.csv'))
       if r['platform'] == 'smartthings_cloud' and r['ok'] == '1']
chk("E5 cloud pct over the 50 ms tolerance",
    round(100*sum(1 for x in _cl if x > 0.05)/len(_cl), 1), 100.0)

# --- E8 ---
e8 = {(r['scenario'], r['ablation'], r['arm']): r
      for r in csv.DictReader(open('results/e8_planner_executor_summary.csv'))}
e8rows = list(csv.DictReader(open('results/e8_planner_executor.csv')))
chk("E8 episodes total", len(e8rows), 64)
chk("E8 contradiction undefended delayed",
    f"{e8[('contact_contradiction','none','delayed')]['violations']}/"
    f"{e8[('contact_contradiction','none','delayed')]['n']}", "4/8")
chk("E8 contradiction undefended honest",
    f"{e8[('contact_contradiction','none','honest')]['violations']}/"
    f"{e8[('contact_contradiction','none','honest')]['n']}", "0/8")
chk("E8 violations across all guarded cells",
    sum(int(r['violation']) for r in e8rows if r['ablation'] != 'none'), 0)
chk("E8 guarded cells n", sum(1 for r in e8rows if r['ablation'] != 'none'), 32)
chk("E8 lock_timeout undefended delayed",
    f"{e8[('lock_timeout','none','delayed')]['violations']}/"
    f"{e8[('lock_timeout','none','delayed')]['n']}", "0/8")
chk("E8 lock_timeout honest benign claims",
    sum(int(r['secure_claim']) for r in e8rows
        if r['scenario'] == 'lock_timeout' and r['ablation'] == 'none' and r['arm'] == 'honest'), 4)

print("\nALL NUMBERS MATCH THEIR SOURCE:", ok)
