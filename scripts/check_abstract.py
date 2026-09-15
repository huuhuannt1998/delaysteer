#!/usr/bin/env python3
"""Enforce the IEEE CS abstract rules for a regular Transactions paper.

Confirmed 31 Aug 2026 from the computer.org author resources:
  - "Word limits for journal abstracts are as follows: Regular/special-issue paper -
     100 to 200 words"
  - "Abstracts must not include mathematical expressions or bibliographic references."

All three drifted silently once already: the 100-200 rule was written in a comment directly
above the abstract and the text still reached 229 words with three $...$ numerals in it. A
comment is not a check, so the gate runs this.

Prints "OK|BAD <words> <math> <cites>" and exits non-zero when the abstract violates a rule.
"""
import re
import sys
from pathlib import Path

MIN_WORDS, MAX_WORDS = 100, 200


def audit(tex: str) -> tuple[bool, int, int, int]:
    m = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", tex, re.S)
    if not m:
        return False, 0, 0, 0
    body = re.sub(r"^\s*%.*$", "", m.group(1), flags=re.M)   # strip LaTeX comments
    words = len(body.split())
    math = len(re.findall(r"\$[^$]+\$", body))
    cites = len(re.findall(r"\\cite", body))
    ok = MIN_WORDS <= words <= MAX_WORDS and math == 0 and cites == 0
    return ok, words, math, cites


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "main.tex")
    ok, words, math, cites = audit(path.read_text())
    print(f"{'OK' if ok else 'BAD'} {words} {math} {cites}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
