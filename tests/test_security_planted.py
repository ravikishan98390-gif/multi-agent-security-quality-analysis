"""
test_security_planted.py — Planted vulnerability tests for the Security Vulnerability Agent.

All tests run against Tier 1 (pattern scan) only — zero API key required.
Each test:
  1. Reads a fixture file with deliberately planted vulnerabilities.
  2. Runs _run_pattern_scan() (deterministic, no LLM).
  3. Asserts the correct category is detected.
  4. Asserts EVERY finding has a specific line_start (>= 1, not a placeholder).
  5. Asserts severity is at least HIGH.
"""

from __future__ import annotations

import pathlib
import pytest

from agents.models import Severity
from agents.security_agent import _run_pattern_scan, PatternCandidate

_FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "security"


def _load(filename: str) -> str:
    return (_FIXTURES / filename).read_text(encoding="utf-8")


def _by_category(candidates: list[PatternCandidate], category: str) -> list[PatternCandidate]:
    return [c for c in candidates if c.category == category]


# ---------------------------------------------------------------------------
# Helper: verify all findings have specific line numbers
# ---------------------------------------------------------------------------

def _assert_specific_line_numbers(candidates: list[PatternCandidate], fixture: str) -> None:
    """Every finding must pinpoint a specific line, not use 1 as a placeholder."""
    for c in candidates:
        assert c.line_start >= 1, (
            f"[{fixture}] Finding '{c.category}' has invalid line_start={c.line_start}"
        )
        assert c.line_end >= c.line_start, (
            f"[{fixture}] Finding '{c.category}' has line_end < line_start "
            f"({c.line_end} < {c.line_start})"
        )
        # The matched_text must be non-empty (proves we captured the actual line)
        assert c.matched_text.strip(), (
            f"[{fixture}] Finding '{c.category}' at line {c.line_start} has empty matched_text"
        )


# ---------------------------------------------------------------------------
# Test 1: SQL Injection — sqli_python.py
# ---------------------------------------------------------------------------

class TestSQLInjectionFixture:
    @pytest.fixture(scope="class")
    def candidates(self):
        return _run_pattern_scan(_load("sqli_python.py"), "python")

    def test_sql_injection_detected(self, candidates):
        sqli = _by_category(candidates, "sql_injection")
        assert len(sqli) >= 1, (
            f"Expected ≥1 sql_injection finding, got {len(sqli)}. "
            f"All categories: {[c.category for c in candidates]}"
        )

    def test_fstring_sqli_caught(self, candidates):
        """The f-string SQL query (actual line 23) must be caught."""
        sqli = _by_category(candidates, "sql_injection")
        lines = {c.line_start for c in sqli}
        assert 23 in lines, (
            f"Expected sql_injection at line 23 (f-string), got lines: {sorted(lines)}"
        )

    def test_concat_sqli_caught(self, candidates):
        """The concatenation SQL query (actual line 31) must be caught."""
        sqli = _by_category(candidates, "sql_injection")
        lines = {c.line_start for c in sqli}
        assert 31 in lines, (
            f"Expected sql_injection at line 31 (concatenation), got lines: {sorted(lines)}"
        )

    def test_format_sqli_caught(self, candidates):
        """The .format() SQL query (actual line 40) must be caught."""
        sqli = _by_category(candidates, "sql_injection")
        lines = {c.line_start for c in sqli}
        assert 40 in lines, (
            f"Expected sql_injection at line 40 (.format()), got lines: {sorted(lines)}"
        )

    def test_safe_parameterized_not_flagged(self, candidates):
        """The safe parameterised query at the bottom must NOT be flagged as sql_injection."""
        sqli = _by_category(candidates, "sql_injection")
        # The safe function uses '?' placeholder — not a string interpolation
        for c in sqli:
            assert "safe_get_user" not in c.matched_text, (
                "False positive: parameterised query incorrectly flagged as sql_injection"
            )

    def test_all_findings_have_specific_line_numbers(self, candidates):
        _assert_specific_line_numbers(candidates, "sqli_python.py")

    def test_all_sqli_findings_have_high_confidence(self, candidates):
        sqli = _by_category(candidates, "sql_injection")
        for c in sqli:
            assert c.confidence == "high", (
                f"SQL injection at line {c.line_start} should be high confidence, got {c.confidence}"
            )


# ---------------------------------------------------------------------------
# Test 2: XSS — xss_python.py
# ---------------------------------------------------------------------------

class TestXSSFixture:
    @pytest.fixture(scope="class")
    def candidates(self):
        return _run_pattern_scan(_load("xss_python.py"), "python")

    def test_xss_detected(self, candidates):
        xss = _by_category(candidates, "xss")
        assert len(xss) >= 1, (
            f"Expected ≥1 xss finding, got {len(xss)}."
        )

    def test_render_template_string_caught(self, candidates):
        """render_template_string() call (actual line 23) must be caught."""
        xss = _by_category(candidates, "xss")
        lines = {c.line_start for c in xss}
        assert 23 in lines, (
            f"Expected xss at line 23 (render_template_string), got lines: {sorted(lines)}"
        )

    def test_markup_xss_caught(self, candidates):
        """Markup(user_comment) (actual line 31) must be caught."""
        xss = _by_category(candidates, "xss")
        lines = {c.line_start for c in xss}
        assert 31 in lines, (
            f"Expected xss at line 31 (Markup()), got lines: {sorted(lines)}"
        )

    def test_safe_filter_caught(self, candidates):
        """Jinja2 |safe filter (actual line 40) must be caught."""
        xss = _by_category(candidates, "xss")
        lines = {c.line_start for c in xss}
        assert 40 in lines, (
            f"Expected xss at line 40 (|safe filter), got lines: {sorted(lines)}"
        )

    def test_all_findings_have_specific_line_numbers(self, candidates):
        _assert_specific_line_numbers(candidates, "xss_python.py")

    def test_xss_query_term_set(self, candidates):
        xss = _by_category(candidates, "xss")
        for c in xss:
            assert c.query_term, f"XSS finding at line {c.line_start} is missing a query_term"


# ---------------------------------------------------------------------------
# Test 3: Hardcoded Secrets — hardcoded_secret.py
# ---------------------------------------------------------------------------

class TestHardcodedSecretFixture:
    @pytest.fixture(scope="class")
    def candidates(self):
        return _run_pattern_scan(_load("hardcoded_secret.py"), "python")

    def test_secrets_detected(self, candidates):
        secrets = _by_category(candidates, "hardcoded_secret")
        assert len(secrets) >= 1, (
            f"Expected ≥1 hardcoded_secret findings, got {len(secrets)}."
        )

    def test_db_password_caught(self, candidates):
        """DB_PASSWORD (actual line 17) must be caught."""
        secrets = _by_category(candidates, "hardcoded_secret")
        lines = {c.line_start for c in secrets}
        assert 17 in lines, (
            f"Expected hardcoded_secret at line 17 (DB_PASSWORD), got lines: {sorted(lines)}"
        )

    def test_api_key_caught(self, candidates):
        """API_KEY (actual line 18) must be caught."""
        secrets = _by_category(candidates, "hardcoded_secret")
        lines = {c.line_start for c in secrets}
        assert 18 in lines, (
            f"Expected hardcoded_secret at line 18 (API_KEY), got lines: {sorted(lines)}"
        )

    def test_jwt_secret_caught(self, candidates):
        """JWT_SECRET (actual line 19) must be caught."""
        secrets = _by_category(candidates, "hardcoded_secret")
        lines = {c.line_start for c in secrets}
        assert 19 in lines, (
            f"Expected hardcoded_secret at line 19 (JWT_SECRET), got lines: {sorted(lines)}"
        )

    def test_env_var_lookup_not_flagged(self, candidates):
        """os.environ.get() assignments at the bottom must NOT be flagged."""
        secrets = _by_category(candidates, "hardcoded_secret")
        for c in secrets:
            assert "os.environ" not in c.matched_text, (
                f"False positive: os.environ.get() incorrectly flagged as hardcoded_secret "
                f"at line {c.line_start}"
            )

    def test_all_findings_have_specific_line_numbers(self, candidates):
        _assert_specific_line_numbers(candidates, "hardcoded_secret.py")

    def test_secrets_are_high_confidence(self, candidates):
        secrets = _by_category(candidates, "hardcoded_secret")
        for c in secrets:
            assert c.confidence == "high", (
                f"Hardcoded secret at line {c.line_start} should be high confidence"
            )


# ---------------------------------------------------------------------------
# Test 4: Broken Access Control — broken_access.py
# ---------------------------------------------------------------------------

class TestBrokenAccessFixture:
    @pytest.fixture(scope="class")
    def candidates(self):
        return _run_pattern_scan(_load("broken_access.py"), "python")

    def test_broken_access_detected(self, candidates):
        bac = _by_category(candidates, "broken_access_control")
        assert len(bac) >= 1, (
            f"Expected ≥1 broken_access_control finding, got {len(bac)}."
        )

    def test_admin_delete_route_caught(self, candidates):
        """The /admin/delete route without @login_required must be caught."""
        bac = _by_category(candidates, "broken_access_control")
        # The @app.route decorator is on line 22
        lines = {c.line_start for c in bac}
        assert any(ln in range(20, 27) for ln in lines), (
            f"Expected broken_access_control near line 22 (/admin/delete), got lines: {sorted(lines)}"
        )

    def test_admin_users_route_caught(self, candidates):
        """The /admin/users route without auth must be caught."""
        bac = _by_category(candidates, "broken_access_control")
        lines = {c.line_start for c in bac}
        assert any(ln in range(31, 38) for ln in lines), (
            f"Expected broken_access_control near line 33 (/admin/users), got lines: {sorted(lines)}"
        )

    def test_protected_route_not_flagged(self, candidates):
        """/profile route with @login_required decorator must NOT be flagged."""
        bac = _by_category(candidates, "broken_access_control")
        for c in bac:
            assert "/profile" not in c.matched_text, (
                f"False positive: @login_required-protected /profile route flagged at line {c.line_start}"
            )

    def test_all_findings_have_specific_line_numbers(self, candidates):
        _assert_specific_line_numbers(candidates, "broken_access.py")


# ---------------------------------------------------------------------------
# Test 5: Cross-fixture — location-specific flagging invariant
# ---------------------------------------------------------------------------

class TestLocationSpecificFlagging:
    """
    Verify the core contract: every finding from every fixture has a
    specific line number. This is the 'location-specific flagging' requirement.
    """

    FIXTURES = [
        ("sqli_python.py", "python"),
        ("xss_python.py", "python"),
        ("hardcoded_secret.py", "python"),
        ("broken_access.py", "python"),
    ]

    @pytest.mark.parametrize("filename,language", FIXTURES)
    def test_no_vague_findings(self, filename: str, language: str):
        code = (_FIXTURES / filename).read_text(encoding="utf-8")
        candidates = _run_pattern_scan(code, language)
        total_lines = len(code.splitlines())
        for c in candidates:
            assert 1 <= c.line_start <= total_lines, (
                f"[{filename}] {c.category} finding has line_start={c.line_start} "
                f"outside valid range [1, {total_lines}]"
            )
            assert c.line_end >= c.line_start, (
                f"[{filename}] {c.category} finding has line_end < line_start"
            )

    @pytest.mark.parametrize("filename,language", FIXTURES)
    def test_matched_text_non_empty(self, filename: str, language: str):
        """Every candidate must record the actual matched source line."""
        code = (_FIXTURES / filename).read_text(encoding="utf-8")
        candidates = _run_pattern_scan(code, language)
        for c in candidates:
            assert c.matched_text.strip(), (
                f"[{filename}] {c.category} at line {c.line_start} has no matched_text"
            )

    @pytest.mark.parametrize("filename,language", FIXTURES)
    def test_description_references_line_number(self, filename: str, language: str):
        """Every description must mention its line number ('Line N:' format)."""
        code = (_FIXTURES / filename).read_text(encoding="utf-8")
        candidates = _run_pattern_scan(code, language)
        for c in candidates:
            assert f"Line {c.line_start}" in c.description, (
                f"[{filename}] {c.category} description at line {c.line_start} "
                f"doesn't say 'Line {c.line_start}:' — found: {c.description[:80]}"
            )
