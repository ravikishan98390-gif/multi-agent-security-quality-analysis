"""
test_security_agent.py — Unit tests for the Security Vulnerability Agent.

Tests cover: Tier 1 pattern scanner, analyze() fallback behaviour, and RAG retrieval.
"""

from __future__ import annotations

import os
import pytest

from agents.models import Severity
from agents.security_agent import _run_pattern_scan, analyze, PatternCandidate, _candidate_to_finding
from agents.rag_engine import retrieve


# ---------------------------------------------------------------------------
# Tier 1 Pattern Scanner Tests
# ---------------------------------------------------------------------------

def test_python_pattern_scan_sql_injection_fstring():
    code = """
def search_user(username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    db.execute(query)
"""
    candidates = _run_pattern_scan(code, "python")
    sqli = [c for c in candidates if c.category == "sql_injection"]
    assert len(sqli) >= 1, f"Expected sql_injection, got: {[c.category for c in candidates]}"
    # Line 3 in the inline code block (line 1 is blank, 2 is def, 3 is query=f"SELECT...")
    assert sqli[0].line_start == 3
    assert sqli[0].confidence == "high"
    assert "Line 3" in sqli[0].description


def test_python_pattern_scan_sql_injection_concat():
    code = """
def delete_record(table, record_id):
    query = "DELETE FROM " + table + " WHERE id = " + record_id
    db.execute(query)
"""
    candidates = _run_pattern_scan(code, "python")
    sqli = [c for c in candidates if c.category == "sql_injection"]
    assert len(sqli) >= 1
    assert sqli[0].line_start == 3


def test_python_pattern_scan_hardcoded_secret():
    code = """
API_KEY = "sk-live-abcdef1234567890"
def connect():
    pass
"""
    candidates = _run_pattern_scan(code, "python")
    secrets = [c for c in candidates if c.category == "hardcoded_secret"]
    assert len(secrets) == 1
    assert secrets[0].line_start == 2
    assert secrets[0].confidence == "high"
    assert "Line 2" in secrets[0].description


def test_java_pattern_scan_xss_and_hash():
    code = """
public class Auth {
    public void login(HttpServletRequest req, HttpServletResponse res) {
        String input = req.getParameter("username");
        res.getWriter().println("<h1>User: " + input + "</h1>");
        
        MessageDigest md = MessageDigest.getInstance("MD5");
    }
}
"""
    candidates = _run_pattern_scan(code, "java")
    hash_findings = [c for c in candidates if c.category == "broken_auth"]
    assert len(hash_findings) >= 1
    assert hash_findings[0].line_start == 7


def test_pattern_scan_no_false_positive_on_parameterized():
    """Safe parameterised query must NOT be flagged."""
    code = """
def get_user(user_id):
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
"""
    candidates = _run_pattern_scan(code, "python")
    sqli = [c for c in candidates if c.category == "sql_injection"]
    assert len(sqli) == 0, f"False positive: parameterised query flagged: {sqli}"


def test_pattern_scan_no_false_positive_on_env_var_secret():
    """os.environ.get() assignments must NOT be flagged as hardcoded secrets."""
    code = """
import os
API_KEY = os.environ.get("API_KEY", "")
PASSWORD = os.getenv("DB_PASSWORD")
"""
    candidates = _run_pattern_scan(code, "python")
    secrets = [c for c in candidates if c.category == "hardcoded_secret"]
    assert len(secrets) == 0, f"False positive: env var lookup flagged: {secrets}"


def test_all_candidates_have_specific_line_numbers():
    """Every candidate from the pattern scanner must have a valid line number."""
    code = """
API_KEY = "sk-live-abc12345"
query = f"SELECT * FROM users WHERE name = '{name}'"
"""
    candidates = _run_pattern_scan(code, "python")
    for c in candidates:
        assert c.line_start >= 1
        assert c.line_end >= c.line_start
        assert c.matched_text.strip()


def test_description_contains_line_reference():
    """All descriptions must mention 'Line N:' for location-specific flagging."""
    code = """
DB_PASSWORD = "super-secret-db-password"
"""
    candidates = _run_pattern_scan(code, "python")
    secrets = [c for c in candidates if c.category == "hardcoded_secret"]
    assert len(secrets) == 1
    assert f"Line {secrets[0].line_start}" in secrets[0].description


# ---------------------------------------------------------------------------
# candidate_to_finding conversion
# ---------------------------------------------------------------------------

def test_candidate_to_finding_conversion():
    """PatternCandidate → Finding conversion preserves line numbers and category."""
    cand = PatternCandidate(
        category="sql_injection",
        line_start=10,
        line_end=10,
        matched_text='query = f"SELECT * FROM users WHERE id = \'{uid}\'"',
        query_term="parameterized queries",
        confidence="high",
        description="Line 10: SQL f-string detected.",
    )
    finding = _candidate_to_finding(cand, [{"document": "sql_injection.md", "section": "Prevention"}])
    assert finding.line_start == 10
    assert finding.line_end == 10
    assert finding.category == "sql_injection"
    assert finding.severity == Severity.CRITICAL
    assert "sql_injection.md" in finding.description


# ---------------------------------------------------------------------------
# analyze() Fallback Behaviour
# ---------------------------------------------------------------------------

def test_analyze_fallback_when_no_api_key(monkeypatch):
    """Without a key, analyze() must return Tier 1 results + a tooling_warning."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    code = "API_KEY = 'super-secret-key-12345'\n"
    findings = analyze(code, "python")

    secret = [f for f in findings if f.category == "hardcoded_secret"]
    assert len(secret) == 1, f"Expected hardcoded_secret, got: {[f.category for f in findings]}"

    warning = [f for f in findings if f.category == "tooling_warning"]
    assert len(warning) == 1
    assert warning[0].severity == Severity.LOW


def test_analyze_all_findings_have_source_agent(monkeypatch):
    """All returned findings must carry source_agent='security'."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    code = "DB_PASSWORD = 'mysecretpassword123'\n"
    findings = analyze(code, "python")
    for f in findings:
        assert f.source_agent == "security", f"Finding {f.title} has wrong source_agent: {f.source_agent}"


# ---------------------------------------------------------------------------
# RAG Retrieval
# ---------------------------------------------------------------------------

def test_rag_retrieval_sql_injection():
    results = retrieve("sql injection parameterized queries", k=1)
    assert len(results) >= 1
    assert "sql_injection.md" in results[0]["document"]
    assert results[0]["section"] != ""
    assert "text" in results[0]


def test_rag_retrieval_xss():
    results = retrieve("xss cross site scripting escaping", k=1)
    assert len(results) >= 1
    assert results[0]["section"] != ""
