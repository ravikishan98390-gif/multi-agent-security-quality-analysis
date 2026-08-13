"""
run_analysis.py -- Manual smoke-test runner.

Feeds all four fixture files through the Code Analysis Agent and prints
a findings table per file. Run from the project root:

    python run_analysis.py
"""

from __future__ import annotations
import pathlib, sys, textwrap

# Force UTF-8 output on Windows so box chars don't crash
sys.stdout = open(sys.stdout.fileno(), mode="w", encoding="utf-8", buffering=1, closefd=False)
from agents.code_analysis_agent import analyze
from agents.models import Severity

FIXTURES = pathlib.Path("tests/fixtures")

FILES = [
    ("bad_python.py",  "python"),
    ("good_python.py", "python"),
    ("bad_java.java",  "java"),
    ("good_java.java", "java"),
]

# Planted issues we expect to see in the "bad" files
EXPECTED = {
    "bad_python.py": [
        "long_method",
        "poor_naming",
        "high_complexity",
        "deep_nesting",
        "duplicate_code",
    ],
    "bad_java.java": [
        "long_method",
        "poor_naming",
        "high_complexity",
        "deep_nesting",
        "duplicate_code",
    ],
}

SEV_COLOUR = {
    Severity.CRITICAL: "\033[91m",   # red
    Severity.HIGH:     "\033[93m",   # yellow
    Severity.MEDIUM:   "\033[94m",   # blue
    Severity.LOW:      "\033[37m",   # grey
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def sev_badge(sev: Severity) -> str:
    col = SEV_COLOUR.get(sev, "")
    return f"{col}{sev.value.upper():8}{RESET}"


def run(filename: str, language: str) -> None:
    code = (FIXTURES / filename).read_text(encoding="utf-8")
    findings = analyze(code, language)

    # Filter out javalang-not-installed notice for cleaner output
    real = [f for f in findings if f.category != "tooling_warning"]

    print(f"\n{'='*72}")
    print(f"{BOLD}  {filename}  ({language})  — {len(real)} finding(s){RESET}")
    print(f"{'='*72}")

    if not real:
        print("  ✅  No findings above threshold — clean file.")
        return

    for i, f in enumerate(real, 1):
        badge = sev_badge(f.severity)
        loc   = f"L{f.line_start}" if f.line_start == f.line_end else f"L{f.line_start}–{f.line_end}"
        print(f"\n  [{i:02d}] {badge}  {loc:12}  [{f.category}]")
        print(f"        {BOLD}{f.title}{RESET}")
        wrapped = textwrap.fill(f.description, width=66,
                                initial_indent="        ",
                                subsequent_indent="        ")
        print(wrapped)

    # -- Coverage check against expected planted issues ------------------
    if filename in EXPECTED:
        print(f"\n  {'-'*66}")
        print(f"  {BOLD}Coverage vs. planted issues:{RESET}")
        found_cats = {f.category for f in real}
        all_ok = True
        for expected_cat in EXPECTED[filename]:
            hit = expected_cat in found_cats
            mark = "✅" if hit else "❌ MISSED"
            print(f"    {mark}  {expected_cat}")
            if not hit:
                all_ok = False
        print()
        if all_ok:
            print(f"  ✅  All planted issues detected.")
        else:
            print(f"  ⚠️   Some planted issues were NOT detected — see above.")


def false_positive_check(filename: str, language: str) -> None:
    """Verify clean files produce zero HIGH/CRITICAL findings."""
    code = (FIXTURES / filename).read_text(encoding="utf-8")
    findings = analyze(code, language)
    bad = [f for f in findings
           if f.category != "tooling_warning"
           and f.severity in (Severity.CRITICAL, Severity.HIGH)]
    print(f"\n{'='*72}")
    print(f"{BOLD}  False-positive check: {filename}{RESET}")
    print(f"{'='*72}")
    if not bad:
        print(f"  ✅  Zero HIGH/CRITICAL findings on clean file — no false positives.")
    else:
        print(f"  ❌  {len(bad)} unexpected HIGH/CRITICAL finding(s) on clean file:")
        for f in bad:
            print(f"      {f.severity.value.upper():8}  {f.category}  L{f.line_start}: {f.title}")


if __name__ == "__main__":
    print(f"\n{BOLD}Code Analysis Agent — Full Fixture Run{RESET}")
    print("Run against: bad_python.py | good_python.py | bad_java.java | good_java.java\n")

    run("bad_python.py",  "python")
    false_positive_check("good_python.py", "python")
    run("bad_java.java",  "java")
    false_positive_check("good_java.java", "java")

    print(f"\n{'='*72}\nDone.\n")
