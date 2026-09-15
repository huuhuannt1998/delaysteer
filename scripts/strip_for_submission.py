"""Produce an anonymized submission build: copy the NDSS manuscript and strip the
internal LaTeX comments (RKA provenance IDs, source-file paths, the refs.bib "VERIFIED
lit_" note, and "moved to the appendix to fit the budget" notes) that must not ship in a
double-blind source/AE submission. Comments do not render in the PDF, but they leak in
submitted .tex source; this yields a clean source tree + PDF while leaving the working
copy untouched.

  python -m scripts.strip_for_submission [OUT_DIR]

Strips only FULL-LINE comments matching internal-hygiene patterns; never touches code,
inline comments, or layout-affecting spacing comments.
"""
import re, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "manuscripts" / "delaysteer" / "ndss"
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else (ROOT / "manuscripts" / "delaysteer" / "ndss" / "submission")

# a full-line comment is stripped iff it matches one of these internal-hygiene markers
MARKERS = ("provenance", "jrn_", "dec_", "mis_", "ecl_", "clm_", "lit_", "RKA",
           ".py", "moved to the appendix", "moved to Appendix", "to fit the NDSS",
           "to fit the 13-page", "13-page text budget")
COMMENT_LINE = re.compile(r"^\s*%")


def strip_text(text: str) -> tuple[str, int]:
    out, n = [], 0
    for line in text.splitlines(keepends=True):
        if COMMENT_LINE.match(line) and any(m in line for m in MARKERS):
            n += 1
            continue
        out.append(line)
    return "".join(out), n


def main() -> int:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    (OUT / "sections").mkdir()
    total = 0
    files = [SRC / "main.tex"] + sorted((SRC / "sections").glob("*.tex")) + [SRC / "refs.bib"]
    for f in files:
        rel = f.relative_to(SRC)
        text = f.read_text(encoding="utf-8")
        stripped, n = strip_text(text)
        total += n
        (OUT / rel).write_text(stripped, encoding="utf-8")
    print(f"stripped {total} internal comment lines across {len(files)} files -> {OUT}")
    # residual leak check
    residual = 0
    for f in OUT.rglob("*"):
        if f.suffix in (".tex", ".bib"):
            for ln in f.read_text(encoding="utf-8").splitlines():
                if COMMENT_LINE.match(ln) and any(m in ln for m in ("provenance", "jrn_", "dec_", "mis_", "ecl_", "lit_")):
                    residual += 1
    print(f"residual RKA-ID/provenance comment lines: {residual}")
    # build
    env_path = "/Library/TeX/texbin:" + __import__("os").environ.get("PATH", "")
    for i in range(3):
        subprocess.run(["pdflatex", "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
                       cwd=OUT, env={**__import__("os").environ, "PATH": env_path},
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if i == 0:
            subprocess.run(["bibtex", "main"], cwd=OUT,
                           env={**__import__("os").environ, "PATH": env_path},
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pdf = OUT / "main.pdf"
    print(f"submission PDF: {'built ' + str(pdf) if pdf.exists() else 'BUILD FAILED'}")
    return 0 if residual == 0 and pdf.exists() else 1


if __name__ == "__main__":
    raise SystemExit(main())
