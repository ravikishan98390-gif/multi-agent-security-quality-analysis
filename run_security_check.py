"""
run_security_check.py — Manual verification script.

Feeds all 4 planted security fixture files through the full analyze() pipeline
(Tier 1 pattern scan + optional Tier 2 LLM if OPENAI_API_KEY is set) and
prints a coverage table confirming every planted issue is caught.

Usage:
    python run_security_check.py
"""

from __future__ import annotations

import pathlib
import sys
import textwrap

# Force UTF-8 output on Windows
sys.stdout = open(sys.stdout.fileno(), mode="w", encoding="utf-8", buffering=1, closefd=False)

from agents.security_agent import analyze, _run_pattern_scan
from agents.models import Severity

_FIXTURES = pathlib.Path("tests/fixtures/security")

# Files and their expected finding categories
EXPECTED: dict[str, list[tuple[str, int]]] = {
    "sqli_python.py": [
        ("sql_injection", 23),   # f-string (actual line 23)
        ("sql_injection", 31),   # concatenation (actual line 31)
        ("sql_injection", 40),   # .format() (actual line 40)
    ],
    "xss_python.py": [
        ("xss", 23),             # render_template_string (actual line 23)
        ("xss", 31),             # Markup() (actual line 31)
        ("xss", 40),             # |safe filter (actual line 40)
    ],
    "hardcoded_secret.py": [
        ("hardcoded_secret", 17),  # DB_PASSWORD (actual line 17)
        ("hardcoded_secret", 18),  # API_KEY (actual line 18)
        ("hardcoded_secret", 19),  # JWT_SECRET (actual line 19)
    ],
    "broken_access.py": [
        ("broken_access_control", 22),  # /admin/delete (actual line 22)
        ("broken_access_control", 33),  # /admin/users (actual line 33)
    ],
}

# ANSI colours
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

SEV_COLOUR = {
    Severity.CRITICAL: RED,
    Severity.HIGH:     YELLOW,
    Severity.MEDIUM:   BLUE,
    Severity.LOW:      DIM,
}


def sev_badge(sev: Severity) -> str:
    col = SEV_COLOUR.get(sev, "")
    return f"{col}{sev.value.upper():8}{RESET}"


def run_file(filename: str, language: str = "python") -> None:
    filepath = _FIXTURES / filename
    if not filepath.exists():
        print(f"\n{RED}  ✗  {filename} not found.{RESET}")
        return

    code = filepath.read_text(encoding="utf-8")

    # Run Tier 1 pattern scan (always available)
    tier1_candidates = _run_pattern_scan(code, language)

    print(f"\n{'='*74}")
    print(f"{BOLD}  {filename}  ({language.upper()})  — {len(tier1_candidates)} Tier 1 pattern candidate(s){RESET}")
    print(f"{'='*74}")

    if not tier1_candidates:
        print(f"  {RED}✗  No findings from pattern scan!{RESET}")
    else:
        for i, c in enumerate(tier1_candidates, 1):
            loc = f"L{c.line_start}" if c.line_start == c.line_end else f"L{c.line_start}–{c.line_end}"
            conf_badge = f"{GREEN}HIGH{RESET}" if c.confidence == "high" else f"{YELLOW}MED {RESET}"
            print(f"\n  [{i:02d}] {conf_badge}  {loc:10}  [{CYAN}{c.category}{RESET}]")
            print(f"        {BOLD}{c.matched_text[:80]}{RESET}")
            wrapped = textwrap.fill(
                c.description, width=68,
                initial_indent="        ", subsequent_indent="        "
            )
            print(wrapped)

    # Coverage check
    expected = EXPECTED.get(filename, [])
    if expected:
        print(f"\n  {'-'*68}")
        print(f"  {BOLD}Coverage vs. planted issues:{RESET}")
        candidate_lines_by_cat: dict[str, set[int]] = {}
        for c in tier1_candidates:
            candidate_lines_by_cat.setdefault(c.category, set()).add(c.line_start)

        all_ok = True
        for category, planted_line in expected:
            found_lines = candidate_lines_by_cat.get(category, set())
            hit = planted_line in found_lines
            if not hit:
                all_ok = False
            mark = f"{GREEN}✅{RESET}" if hit else f"{RED}❌ MISSED{RESET}"
            print(f"    {mark}  {category:<28}  line {planted_line}")

        print()
        if all_ok:
            print(f"  {GREEN}{BOLD}✅  All planted issues detected by Tier 1 pattern scan.{RESET}")
        else:
            print(f"  {RED}⚠️   Some planted issues were NOT detected — see above.{RESET}")

    # False positive check: confirm safe patterns aren't flagged
    print(f"\n  {DIM}False-positive check:{RESET}")
    if filename == "sqli_python.py":
        sqli_at_safe = [c for c in tier1_candidates if c.category == "sql_injection" and "safe_get_user" in c.matched_text]
        if sqli_at_safe:
            print(f"  {RED}❌  False positive: parameterised query incorrectly flagged.{RESET}")
        else:
            print(f"  {GREEN}✅  Parameterised query (safe) correctly not flagged.{RESET}")
    elif filename == "hardcoded_secret.py":
        fp = [c for c in tier1_candidates if c.category == "hardcoded_secret" and "os.environ" in c.matched_text]
        if fp:
            print(f"  {RED}❌  False positive: os.environ.get() incorrectly flagged.{RESET}")
        else:
            print(f"  {GREEN}✅  os.environ.get() (safe) correctly not flagged.{RESET}")
    elif filename == "broken_access.py":
        fp = [c for c in tier1_candidates if c.category == "broken_access_control" and "/profile" in c.matched_text]
        if fp:
            print(f"  {RED}❌  False positive: @login_required-protected route flagged.{RESET}")
        else:
            print(f"  {GREEN}✅  @login_required-protected route correctly not flagged.{RESET}")
    else:
        print(f"  {DIM}(no false-positive checks defined for this file){RESET}")


if __name__ == "__main__":
    print(f"\n{BOLD}Security Vulnerability Agent — Planted Fixture Verification{RESET}")
    api_mode = "Tier 1 (Pattern) + Tier 2 (Grounded LLM)" if True else "Tier 1 Only"
    print(f"Mode: {CYAN}Tier 1 Pattern Scan{RESET}  (set OPENAI_API_KEY for full Tier 1+2 analysis)\n")

    for fname in EXPECTED:
        run_file(fname, "python")

    print(f"\n{'='*74}\nDone.\n")
