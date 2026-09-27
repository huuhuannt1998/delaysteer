# Matter hold probe

Delay-only adversary against a Matter subscription, measured on matter.js. The analysis plan is fixed in
`results/matter_hold_plan.md`; results are in `results/matter_hold.csv`, `results/matter_hold_REPORT.md` and
`results/matter_hold_logs/`.

## Pieces

| File | Role |
|---|---|
| `device.mjs` | Virtual contact sensor (`ContactSensorDevice` + `BooleanStateServer`, which emits `StateChange`). Own Node process, UDP port 5550, mDNS on `lo0` only. Logs every datagram it sends/receives (observation only). |
| `controller.mjs` | matter.js `CommissioningController` in its own Node process, plus the hold shim on `NodeJsUdpSocket.onData` (the controller's network layer). |
| `runner.mjs` | Forks both processes, commissions once over IP (PASE to `127.0.0.1:5550`, then CASE), runs the trials, writes one CSV row per trial and raw logs. |
| `analyze.mjs` | Summarises `results/matter_hold.csv` into the per-question tables used in the report. |
| `common.mjs` | Header parsing, hashing, log tap. |
| `witness.mjs` | Q6 order witness, loaded by the controller only when `HOLD_WITNESS=1` (runner flag `--witness`). Wraps `ClientStructure.prototype.mutate` (@matter/node 0.17.9), where a decoded ReportData is applied to the controller's node cache. It withholds an attribute value whose cluster DataVersion is older (32-bit serial-number arithmetic) than the highest applied for that (endpoint, cluster), and flags events whose number is not above the highest seen (duplicate vs older). Forwards everything else by reference, unmodified. |
| `analyze_q6.mjs` | Summarises `results/matter_hold_q6.csv` and its event log into the Q6 tables. |
| `sanitize.mjs` | Rewrites absolute paths (matter.js prints its storage path and stack traces) to repo-relative ones in everything the runner writes under `results/` (double-anonymous review). The runner calls it on exit; it can also be run by hand: `node sanitize.mjs ../../results/matter_hold_logs ../../results/matter_hold.csv`. |

The hold shim queues datagrams whose source port is the device's (5550) while a hold is active, keeps the original
buffer, records its SHA-256 on arrival, and on release re-hashes and hands every datagram to the matter.js listener in
arrival order. It never drops, edits, forges or reorders. Mode `all` holds every device datagram; mode `select`
holds one value-bearing message chosen by its cleartext (session id, message counter) together with its byte-identical
MRP retransmissions and passes everything else.

## Reproduce

Requires Node >= 20 (measured with v26.3.0) on macOS or Linux; everything runs on one host over loopback.

```sh
cd scripts/matter_hold
npm ci                      # installs the pinned matter.js 0.17.9 packages from package-lock.json
rm -rf .storage             # optional: start from an uncommissioned device and an empty controller fabric

# quick check (~2 min): one Q1 trial, Q4 select d=2 and d=20
node runner.mjs --smoke --csv /tmp/matter_hold_smoke.csv --logroot /tmp/matter_hold_smoke_logs

# full run (~1 h): all cells in the plan, 5 repetitions each
node runner.mjs --questions Q1,Q5,Q4,Q2 --reps 5 --run-id main

# tables
node analyze.mjs ../../results/matter_hold.csv

# Q6 (addendum in the plan): order witness on, separate outputs (~20 min)
node runner.mjs --witness --questions Q6 --reps 5 --run-id q6 \
    --csv ../../results/matter_hold_q6.csv --logroot ../../results/matter_hold_q6_logs
node analyze_q6.mjs ../../results/matter_hold_q6.csv ../../results/matter_hold_q6_logs/q6/events.jsonl ../../results/matter_hold.csv
```

`runner.mjs` appends to `results/matter_hold.csv` (header written if the file is new) and writes raw logs to
`results/matter_hold_logs/<run-id>/` (`device.log`, `controller.log`, `events.jsonl` with every datagram hash and
callback, `run_header.json`). It kills both child processes on exit.

Environment used by the children (set by the runner): `MATTER_STORAGE_PATH=.storage/{device,controller}`,
`MATTER_MDNS_NETWORKINTERFACE=lo0`, `MATTER_LOG_LEVEL=info`, `MATTER_LOG_FORMAT=plain`.
