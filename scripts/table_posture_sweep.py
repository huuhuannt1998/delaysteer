"""Render the Experiment I (recovery-posture sweep) appendix table from its CSV.

  python scripts/table_posture_sweep.py            # emit LaTeX tabular body
Every cell is read from results/recovery_policy_sweep.csv; nothing is hard-coded.
"""
import csv, sys
from pathlib import Path

ABBR = {"report_not_secure": "RNS", "defer_report_not_secure": "DRNS",
        "secure_true_armed": "STA", "secure_true_unarmed": r"\textbf{STU}"}

def main() -> int:
    rows = list(csv.DictReader(open(Path("results/recovery_policy_sweep.csv"))))
    out, tot_oor, tot_unsafe, tot_n = [], 0, 0, 0
    for r in rows:
        br = ", ".join(f"{ABBR.get(k, k)}\\,{v}" for k, v in
                       (p.split("=") for p in r["branches"].split(";") if p))
        out.append(f"\\texttt{{{r['model'].replace('_','-')}}} & {r['posture']} & "
                   f"${r['violation_rate'].replace('/','/')}$ & ${r['out_of_repertoire']}$ & "
                   f"${r['unsafe_out_of_repertoire']}$ & {r['unsafe_oor_wilson95'].replace('[','[').replace(',',',\\,')} & {br} \\\\")
        n = int(r["n"]); tot_n += n
        tot_oor += int(r["out_of_repertoire"].split("/")[0])
        tot_unsafe += int(r["unsafe_out_of_repertoire"].split("/")[0])
    print("\n".join(out))
    print(f"% TOTALS out-of-repertoire {tot_oor}/{tot_n} | unsafe-oor {tot_unsafe}/{tot_n}",
          file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
