#!/bin/zsh
# Rebuild the IEEE TDSC submission and report every hard gate in one line each.
#
# Venue changed USENIX Security '27 -> IEEE TDSC on 2026-08-22 (advisor).
# The USENIX gate is preserved at scripts/paper_gate_usenix2027.sh.bak; it
# enforced a 13-page BODY ceiling, which is a USENIX rule and does NOT apply here.
#
# TDSC counts differently from USENIX: there is no "body excluding references and
# appendices" concept. What matters is the total article length against TDSC's
# regular-paper allowance and its overlength-page charge threshold.
#
# CONFIRMED 2026-08-23 from the IEEE Computer Society author resources:
#   "The regular paper page length limit is defined at 12 formatted pages for
#    Transactions ... including references and author biographies. Any pages or
#    fraction thereof exceeding this limit are charged $220 per page."
# The charge is MANDATORY (MOPC) and TDSC offers no way to avoid it. The limit
# therefore binds on body+references; appendices count too unless they are moved
# to supplementary material, which is submitted as a separate file.
TDSC_PAGE_MAX=12
TDSC_MOPC=220
set -e
GATE_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$(dirname "$0")/../manuscripts/delaysteer-paperspine/paper_rewriting_output/final_paper"
export PATH="/Library/TeX/texbin:$PATH"

# Palatino fallback. TDSC/compsoc sets the body in Palatino; IEEEtran loads it
# during \documentclass, so a machine without the URW Palladio metrics cannot
# build at all. When that is this machine, put localbuild/ on TEXINPUTS -- it
# holds .fd files that resolve Palatino to Times. main.tex is untouched, so the
# fallback never follows the source to Prism or any full TeX Live install.
if kpsewhich pplr7t.tfm >/dev/null 2>&1; then
  PPL=yes
else
  PPL=no
  export TEXINPUTS="./localbuild:$TEXINPUTS"
fi

# TWO documents. The appendices ship as supplementary material, which IEEE does not
# count against the 12-page limit. main.tex pulls the supplementary labels in with xr,
# so SUPPLEMENTARY MUST BUILD FIRST -- otherwise every App.~\ref in the body renders
# as ?? and the gate would report undefined references that are really a build-order bug.
# The reference dependency is CIRCULAR: the body cites appendices, the appendices cite
# body sections, and each document reads the other's .aux via xr. Two full rounds of
# building both documents is what makes it converge. Building either one alone leaves
# ?? in the other, which looks like undefined references but is a build-order bug.
for _round in 1 2; do
  pdflatex -interaction=nonstopmode supplementary.tex >/tmp/pgs1.log 2>&1 || true
  bibtex supplementary >/tmp/pgsbib.log 2>&1 || true
  pdflatex -interaction=nonstopmode main.tex        >/tmp/pg1.log  2>&1 || true
  bibtex main        >/tmp/pgbib.log 2>&1 || true
done
pdflatex -interaction=nonstopmode supplementary.tex >/tmp/pgs2.log 2>&1 || true
pdflatex -interaction=nonstopmode supplementary.tex >/tmp/pgs3.log 2>&1 || true
pdflatex -interaction=nonstopmode main.tex >/tmp/pg2.log 2>&1 || true
pdflatex -interaction=nonstopmode main.tex >/tmp/pg3.log 2>&1 || true

# Count only REFERENCE/CITATION problems. A bare 'undefined' grep also catches
# "LaTeX Font Warning: Font shape ... undefined", which is a typography notice,
# not a broken cross-reference, and made the gate fail for the wrong reason.
und=$(python3 -c "
import re
t=open('/tmp/pg3.log',errors='ignore').read()
print(len(re.findall(r'(Reference|Citation)\s+\`[^\']*\'\s+on page.*undefined|Undefined control sequence',t)))")
ctr=$(python3 -c "print(sum('Counter too large' in l for l in open('/tmp/pg3.log',errors='ignore')))")
bib=$(grep -cE '^I found no|error message' /tmp/pgbib.log || true)
pages=$(pdfinfo main.pdf | awk '/Pages/{print $2}')
supp_pages=$(pdfinfo supplementary.pdf 2>/dev/null | awk '/Pages/{print $2}')
supp_und=$(python3 -c "
import re
t=open('/tmp/pgs3.log',errors='ignore').read()
print(len(re.findall(r'(Reference|Citation)\s+\`[^\']*\'\s+on page.*undefined|Undefined control sequence',t)))")

# Structural landmarks. Same technique as the USENIX gate: pdftotext reorders
# two-column pages, so match flattened per-page text, never line-by-line.
concl=""; refs=""; appx=""
for p in $(seq 1 "$pages"); do
  t=$(pdftotext -f "$p" -l "$p" main.pdf - 2>/dev/null | tr '\n' ' ' | tr -s ' ')
  # Match the SECTION HEADING, not a sentence. The previous sentinel was the
  # conclusion's opening words ("We introduced delay-only"); rewriting that sentence
  # on 2026-09-10 made this report "p?" while the conclusion was present and correct,
  # i.e. the check silently measured prose churn instead of structure. pdftotext
  # letter-spaces small caps, hence the spaced form.
  [[ -z "$concl" ]] && echo "$t" | grep -qE "C ONCLUSION|CONCLUSION" && concl=$p
  [[ -z "$refs"  ]] && echo "$t" | grep -qE "R EFERENCES|REFERENCES" && refs=$p

done

# Palatino shim must be gone from the FINAL pdf: a shimmed build is set in Times
# and runs shorter than the real Computer Society output.
ppl=$PPL

# IEEE: "All images and graphs should be high resolution and adhere to a minimum
# of 300 dpi at the intended display size." Vector art has no ceiling; rasterised
# panels (matplotlib imshow) do, and the GAR heatmap silently shipped at 200 ppi
# until this check existed.
dpi_bad=$(python3 -c "
import glob, subprocess
bad = 0
for f in sorted(glob.glob('figures/*.pdf')):
    out = subprocess.run(['pdfimages','-list',f], capture_output=True, text=True).stdout
    for line in out.split(chr(10))[2:]:
        p = line.split()
        if len(p) > 14:
            try:
                if min(int(p[12]), int(p[13])) < 300: bad += 1
            except ValueError: pass
print(bad)")

tic=$(python3 /Users/anonymous/rka/build/lib/rka/skills/writer/scripts/ai_tic_lint.py sections/*.tex main.tex 2>/dev/null \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['summary']['blocks'])")

# IEEE CS abstract rules for a regular Transactions paper (100-200 words, no mathematical
# expressions, no bibliographic references). The 100-200 rule was already written in a comment
# directly above the abstract and the text still drifted to 229 words with three $...$ numerals.
# A comment is not a check.
abs_out=$(python3 "$GATE_DIR/check_abstract.py" main.tex 2>/dev/null || echo "BAD 0 0 0")
abs_ok=${abs_out%% *}
abs_rest=${abs_out#* }

cd - >/dev/null
md5ok=1
for f in metrics:e787eb4c9e45e1919a818a6a65868e59 m2_rates:6cd5b9cb555f45c942c8aefe584fde14 \
         adaptive:7997ce45104224956623a49d2ad306aa smartthings:94681536f03ebd7b09b9beaac97900cb \
         recovery_matrix:352827fae06b6c09ef45f94af1a7e0e3; do
  n=${f%%:*}; w=${f##*:}
  [[ "$(md5 -q results/$n.csv)" == "$w" ]] || { echo "  md5 FAIL $n"; md5ok=0; }
done

verdict="PASS"
[[ "${supp_und:-0}" != "0" ]] && verdict="FAIL"
[[ "${dpi_bad:-0}" != "0" ]] && verdict="FAIL"
[[ "$und" != "0" || "$ctr" != "0" || "$bib" != "0" || "$tic" != "0" || "$md5ok" != "1" ]] && verdict="FAIL"
[[ "${abs_ok:-BAD}" != "OK" ]] && verdict="FAIL"


echo "  undefined refs/cites : $und"
echo "  counter too large    : $ctr"
echo "  bibtex problems      : $bib"
echo "  ai_tic BLOCKs        : $tic"
echo "  abstract             : $abs_rest (words math cites; IEEE 100-200, 0, 0) -> $abs_ok"
echo "  figures below 300dpi : $dpi_bad  (IEEE minimum)"
echo "  frozen md5s intact   : $([[ $md5ok == 1 ]] && echo yes || echo NO)"
echo "  conclusion / refs    : p${concl:-?} / p${refs:-?}"
echo "  body sections        : 1-10 in main; appendices in supplementary"
echo "  supplementary        : ${supp_pages:-?} pages, $supp_und undefined  (not counted by IEEE)"
echo "  MAIN pages           : $pages  (TDSC limit $TDSC_PAGE_MAX incl. refs)"
if [[ "$pages" -gt "$TDSC_PAGE_MAX" ]]; then
  over=$(( pages - TDSC_PAGE_MAX ))
  echo "  OVERLENGTH           : $over pages -> \$$(( over * TDSC_MOPC )) mandatory charge"
  echo "                         (appendices are ALREADY supplementary; this is the body)"
fi
if [[ $ppl == yes ]]; then
  echo "  typeface             : Palatino (official Computer Society build)"
else
  echo "  typeface             : Times via localbuild/ FALLBACK"
  echo "                         -> Palatino is wider; this PDF runs SHORT."
  echo "                         -> page count is NOT the submission length."
fi
echo "  GATE                 : $verdict"
