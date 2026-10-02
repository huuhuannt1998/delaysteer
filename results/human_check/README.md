# Human check of the message coding (about 40 minutes)

Plan and decision rule: `results/human_check_plan.md` (written before any human code).

1. Open `index.html` in a browser. It shows 75 short messages under neutral ids (H01..H75) and the codebook.
2. Code each message on its own: three yes/no answers and an optional note. Answers are kept in the browser while you work.
3. Do not open any `key.csv`, `sheet_coder*.csv` or `coded_summary.csv` before you finish.
4. Press **Save CSV**; it downloads `human_codes.csv`.
5. Run `.venv/bin/python scripts/human_check.py import ~/Downloads/human_codes.csv` from the repository root (or send the file back).
   It writes the codes into the three `sheet_human.csv` files, scores them against both model coders,
   and prints which branch of the decision rule applies. It refuses to overwrite codes already there.
