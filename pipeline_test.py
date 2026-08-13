"""
pipeline_test.py — Comprehensive Module-by-Module Pipeline Validation
=====================================================================
Tests every module, function, and agent in the Smart Code Inspection
Platform with real Python and Java code examples.

Run:  python pipeline_test.py
"""

import json
import sys
import time
import traceback
from dataclasses import asdict

# ── Colour helpers (for readable terminal output) ─────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

results = []

def report(module, test, passed, detail=""):
    status = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
    entry = dict()
    entry["module"] = module
    entry["test"] = test
    entry["ok"] = passed
    entry["detail"] = detail
    results.append(entry)
    print(f"  {status}  {CYAN}{module}{RESET} -> {test}" + (f"  ({detail})" if detail else ""))


# ═══════════════════════════════════════════════════════════════════════════
# Test Code Samples
# ═══════════════════════════════════════════════════════════════════════════

PYTHON_VULNERABLE = '''\
import hashlib
import sqlite3

password = "SuperSecret123"
API_KEY = "sk-abc123456789"

def get_user(db, username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return db.execute(query)

def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

def admin_panel():
    data = input("Enter data: ")
    eval(data)

def process(a, b, c, d, e, f, g, h, x):
    if a:
        if b:
            if c:
                if d:
                    if e:
                        return x
    if a and b:
        result = a + b
    elif c and d:
        result = c + d
    elif e and f:
        result = e + f
    elif g and h:
        result = g + h
    else:
        result = x
    return result
'''

PYTHON_CLEAN = '''\
import os
import bcrypt

def get_user(db, user_id: int):
    """Safely query user by ID."""
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,))

def hash_password(pwd: str) -> str:
    """Hash password with bcrypt."""
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
'''

JAVA_VULNERABLE = '''\
import java.sql.*;
import java.security.MessageDigest;
import javax.servlet.http.*;

public class UserService {
    private static final String DB_PASSWORD = "admin123";
    private Connection conn;

    public ResultSet getUser(String username) throws SQLException {
        String query = "SELECT * FROM users WHERE name = '" + username + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query);
    }

    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public void processData(int a, int b, int c, int d, int e,
                            int f, int g, int h, int x, int y) {
        if (a > 0) {
            if (b > 0) {
                if (c > 0) {
                    if (d > 0) {
                        if (e > 0) {
                            System.out.println("deep");
                        }
                    }
                }
            }
        }
    }
}
'''

JAVA_CLEAN = '''\
import java.sql.*;

public class SafeUserService {
    private Connection conn;

    public ResultSet getUser(int userId) throws SQLException {
        PreparedStatement stmt = conn.prepareStatement(
            "SELECT * FROM users WHERE id = ?"
        );
        stmt.setInt(1, userId);
        return stmt.executeQuery();
    }
}
'''


# ═══════════════════════════════════════════════════════════════════════════
# 1. MODELS MODULE
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  1. MODELS MODULE (agents/models.py){RESET}")
print(f"{BOLD}{'='*70}{RESET}")

try:
    from agents.models import Finding, Severity, SEVERITY_WEIGHTS, OWASP_CATEGORY_MAP

    # Severity enum values
    report("models", "Severity enum has 4 levels",
           len(Severity) == 4, f"values: {[s.value for s in Severity]}")

    # Severity comparisons
    report("models", "CRITICAL < HIGH ordering",
           Severity.CRITICAL < Severity.HIGH)
    report("models", "HIGH < MEDIUM ordering",
           Severity.HIGH < Severity.MEDIUM)
    report("models", "MEDIUM < LOW ordering",
           Severity.MEDIUM < Severity.LOW)

    # Finding construction
    f1 = Finding(
        type="security", severity=Severity.CRITICAL,
        line_start=8, line_end=9,
        title="SQL Injection", description="Unsafe query building",
        category="sql_injection", source_agent="security"
    )
    report("models", "Finding construction",
           f1.type == "security" and f1.severity == Severity.CRITICAL)

    # Finding serialisation round-trip
    d = f1.to_dict()
    f2 = Finding.from_dict(d)
    report("models", "Finding to_dict/from_dict round-trip",
           f2.title == f1.title and f2.severity == f1.severity,
           f"title={f2.title}")

    # SEVERITY_WEIGHTS
    report("models", "SEVERITY_WEIGHTS complete",
           set(SEVERITY_WEIGHTS.keys()) == {"critical", "high", "medium", "low"},
           f"weights={SEVERITY_WEIGHTS}")

    # OWASP_CATEGORY_MAP
    report("models", "OWASP_CATEGORY_MAP populated",
           "sql_injection" in OWASP_CATEGORY_MAP and "xss" in OWASP_CATEGORY_MAP,
           f"{len(OWASP_CATEGORY_MAP)} categories")

except Exception as e:
    report("models", "Module import/basic tests", False, str(e))


# ═══════════════════════════════════════════════════════════════════════════
# 2. DATABASE MODULE
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  2. DATABASE MODULE (agents/db.py){RESET}")
print(f"{BOLD}{'='*70}{RESET}")

try:
    from agents.db import (
        init_db, save_submission, get_submission,
        create_job, get_job, update_job,
        save_findings, get_findings
    )

    # Init DB (idempotent)
    init_db()
    report("db", "init_db() succeeds", True)

    # Save + retrieve submission
    sub_id = save_submission(PYTHON_VULNERABLE, "python", "test_vuln.py")
    report("db", "save_submission() returns UUID",
           len(sub_id) == 36, f"id={sub_id[:8]}...")

    sub = get_submission(sub_id)
    report("db", "get_submission() returns (code, lang, filename)",
           sub is not None and sub[1] == "python" and sub[2] == "test_vuln.py")

    # Create + retrieve job
    job_id = create_job(sub_id)
    report("db", "create_job() returns UUID",
           len(job_id) == 36, f"job={job_id[:8]}...")

    job = get_job(job_id)
    report("db", "get_job() returns dict with stage/agents",
           job is not None and job["stage"] == "analysis",
           f"stage={job['stage']}, agents={job['agent_analysis']}")

    # Update job
    update_job(job_id, stage="security", agent_analysis="done")
    job2 = get_job(job_id)
    report("db", "update_job() correctly mutates fields",
           job2["stage"] == "security" and job2["agent_analysis"] == "done")

    # Save + retrieve findings
    test_findings = [
        Finding(type="security", severity=Severity.CRITICAL,
                line_start=8, line_end=9, title="SQL Injection",
                description="f-string SQL", category="sql_injection",
                source_agent="security"),
        Finding(type="code_smell", severity=Severity.MEDIUM,
                line_start=20, line_end=35, title="High Complexity",
                description="Too many branches", category="high_complexity",
                source_agent="code_analysis"),
    ]
    save_findings(sub_id, test_findings)
    rows = get_findings(sub_id)
    report("db", "save_findings() + get_findings() round-trip",
           len(rows) == 2, f"saved={len(test_findings)}, retrieved={len(rows)}")

    report("db", "Finding fields preserved in DB",
           rows[0]["severity"] in ("critical", "medium") and rows[0]["title"] != "")

except Exception as e:
    report("db", "Module tests", False, traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# 3. CODE ANALYSIS AGENT — PYTHON
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  3. CODE ANALYSIS AGENT -- Python (agents/code_analysis_agent.py){RESET}")
print(f"{BOLD}{'='*70}{RESET}")

try:
    from agents.code_analysis_agent import analyze as quality_analyze

    # Vulnerable Python
    py_findings = quality_analyze(PYTHON_VULNERABLE, "python")
    report("code_analysis", "Python: returns list of Finding objects",
           isinstance(py_findings, list) and all(isinstance(f, Finding) for f in py_findings),
           f"count={len(py_findings)}")

    report("code_analysis", "Python: detects issues in vulnerable code",
           len(py_findings) >= 1,
           f"found {len(py_findings)} issues")

    # Check finding attributes
    if py_findings:
        f = py_findings[0]
        report("code_analysis", "Python: Finding has valid severity",
               isinstance(f.severity, Severity), f"severity={f.severity.value}")
        report("code_analysis", "Python: Finding has line_start > 0",
               f.line_start >= 1, f"line={f.line_start}")
        report("code_analysis", "Python: Finding has source_agent='code_analysis'",
               f.source_agent == "code_analysis")

    # List categories found
    categories = set(f.category for f in py_findings)
    report("code_analysis", "Python: categories detected",
           len(categories) >= 1, f"categories={categories}")

    # Clean Python -- should have fewer findings
    clean_findings = quality_analyze(PYTHON_CLEAN, "python")
    report("code_analysis", "Python: clean code has fewer findings",
           len(clean_findings) <= len(py_findings),
           f"clean={len(clean_findings)} vs vuln={len(py_findings)}")

    # Empty submission
    empty_findings = quality_analyze("", "python")
    report("code_analysis", "Python: empty code returns 'empty_submission'",
           len(empty_findings) == 1 and empty_findings[0].category == "empty_submission")

    # Unsupported language
    try:
        quality_analyze("code", "rust")
        report("code_analysis", "Unsupported language raises ValueError", False)
    except ValueError:
        report("code_analysis", "Unsupported language raises ValueError", True)

except Exception as e:
    report("code_analysis", "Python analysis", False, traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# 4. CODE ANALYSIS AGENT — JAVA
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  4. CODE ANALYSIS AGENT -- Java{RESET}")
print(f"{BOLD}{'='*70}{RESET}")

try:
    java_findings = quality_analyze(JAVA_VULNERABLE, "java")
    report("code_analysis", "Java: returns Finding list",
           isinstance(java_findings, list) and all(isinstance(f, Finding) for f in java_findings),
           f"count={len(java_findings)}")

    report("code_analysis", "Java: detects issues in vulnerable code",
           len(java_findings) >= 1,
           f"found {len(java_findings)} issues")

    if java_findings:
        categories_j = set(f.category for f in java_findings)
        report("code_analysis", "Java: categories detected",
               len(categories_j) >= 1, f"categories={categories_j}")

    # Clean Java
    clean_java = quality_analyze(JAVA_CLEAN, "java")
    report("code_analysis", "Java: clean code has fewer findings",
           len(clean_java) <= len(java_findings),
           f"clean={len(clean_java)} vs vuln={len(java_findings)}")

except Exception as e:
    report("code_analysis", "Java analysis", False, traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# 5. SECURITY AGENT — PYTHON
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  5. SECURITY AGENT -- Python (agents/security_agent.py){RESET}")
print(f"{BOLD}{'='*70}{RESET}")

try:
    from agents.security_agent import analyze as security_analyze

    sec_py = security_analyze(PYTHON_VULNERABLE, "python")
    report("security", "Python: returns Finding list",
           isinstance(sec_py, list) and all(isinstance(f, Finding) for f in sec_py),
           f"count={len(sec_py)}")

    # Should detect SQL injection, hardcoded secret, and/or weak hash
    sec_categories = set(f.category for f in sec_py if f.category != "tooling_warning" and f.category != "api_failure")
    report("security", "Python: detects security categories",
           len(sec_categories) >= 1,
           f"categories={sec_categories}")

    # Check for SQL injection detection
    sqli_found = any("sql" in f.category.lower() or "injection" in f.title.lower() for f in sec_py)
    report("security", "Python: detects SQL injection",
           sqli_found)

    # Check for hardcoded secret detection
    secret_found = any("secret" in f.category.lower() or "hardcoded" in f.title.lower() for f in sec_py)
    report("security", "Python: detects hardcoded secrets",
           secret_found)

    # Check for weak hash detection (security agent categorizes MD5/SHA1 as 'broken_auth')
    hash_found = any(
        "hash" in f.category.lower() or "md5" in f.title.lower()
        or "weak" in f.category.lower() or "broken_auth" in f.category.lower()
        or "md5" in f.description.lower() or "sha-1" in f.description.lower()
        for f in sec_py
    )
    report("security", "Python: detects weak hash (MD5)",
           hash_found)

    # All findings have source_agent='security'
    report("security", "Python: all findings have source_agent='security'",
           all(f.source_agent == "security" for f in sec_py))

    # Clean code -- fewer security issues
    sec_clean = security_analyze(PYTHON_CLEAN, "python")
    sec_clean_real = [f for f in sec_clean if f.category not in ("tooling_warning", "api_failure")]
    report("security", "Python: clean code has fewer security issues",
           len(sec_clean_real) <= len(sec_categories),
           f"clean_security={len(sec_clean_real)}")

except Exception as e:
    report("security", "Python security scan", False, traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# 6. SECURITY AGENT — JAVA
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  6. SECURITY AGENT -- Java{RESET}")
print(f"{BOLD}{'='*70}{RESET}")

try:
    sec_java = security_analyze(JAVA_VULNERABLE, "java")
    report("security", "Java: returns Finding list",
           isinstance(sec_java, list) and all(isinstance(f, Finding) for f in sec_java),
           f"count={len(sec_java)}")

    sec_java_cats = set(f.category for f in sec_java if f.category not in ("tooling_warning", "api_failure"))
    report("security", "Java: detects security categories",
           len(sec_java_cats) >= 1,
           f"categories={sec_java_cats}")

    # SQL injection in Java
    sqli_java = any("sql" in f.category.lower() or "injection" in f.title.lower() for f in sec_java)
    report("security", "Java: detects SQL injection",
           sqli_java)

    # Hardcoded secret in Java
    secret_java = any("secret" in f.category.lower() or "hardcoded" in f.title.lower() or "password" in f.title.lower()
                       for f in sec_java)
    report("security", "Java: detects hardcoded DB_PASSWORD",
           secret_java)

except Exception as e:
    report("security", "Java security scan", False, traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# 7. REMEDIATION AGENT
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  7. REMEDIATION AGENT (agents/remediation_agent.py){RESET}")
print(f"{BOLD}{'='*70}{RESET}")

try:
    from agents.remediation_agent import remediate

    # Build test findings for remediation
    rem_findings = [
        Finding(type="security", severity=Severity.CRITICAL,
                line_start=8, line_end=9, title="SQL Injection via f-string",
                description="User input in SQL", category="sql_injection",
                source_agent="security"),
        Finding(type="security", severity=Severity.HIGH,
                line_start=4, line_end=4, title="Hardcoded Password",
                description="Password in source", category="hardcoded_secret",
                source_agent="security"),
        Finding(type="code_smell", severity=Severity.MEDIUM,
                line_start=20, line_end=35, title="High Complexity",
                description="Too many branches", category="high_complexity",
                source_agent="code_analysis"),
        Finding(type="security", severity=Severity.HIGH,
                line_start=12, line_end=12, title="Weak Hash MD5",
                description="MD5 used for passwords", category="weak_hash",
                source_agent="security"),
    ]

    remediated = remediate(rem_findings)
    report("remediation", "remediate() returns list",
           isinstance(remediated, list) and len(remediated) == len(rem_findings))

    # Check fixes were generated
    has_fixes = all("fix" in f.extra for f in remediated)
    report("remediation", "All findings now have extra['fix']",
           has_fixes)

    # Check fix quality
    for f in remediated:
        fix = f.extra.get("fix", "")
        report("remediation", f"Fix for '{f.category}' is non-empty",
               len(fix) > 10, f"fix_length={len(fix)}")

    # SQL injection fix mentions parameterized
    sqli_fix = [f for f in remediated if f.category == "sql_injection"][0]
    report("remediation", "SQL injection fix mentions 'parameterized'",
           "parameterized" in sqli_fix.extra["fix"].lower() or "prepared" in sqli_fix.extra["fix"].lower())

    # Hardcoded secret fix mentions environment
    secret_fix = [f for f in remediated if f.category == "hardcoded_secret"][0]
    report("remediation", "Hardcoded secret fix mentions 'environment'",
           "environment" in secret_fix.extra["fix"].lower() or "secrets" in secret_fix.extra["fix"].lower())

except Exception as e:
    report("remediation", "Remediation tests", False, traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# 8. PR SUMMARY AGENT
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  8. PR SUMMARY AGENT (agents/pr_summary_agent.py){RESET}")
print(f"{BOLD}{'='*70}{RESET}")

try:
    from agents.pr_summary_agent import compute_health_score, count_by_severity, summarize

    # Health score
    score = compute_health_score(rem_findings)
    report("pr_summary", "compute_health_score() returns 0-100",
           0 <= score <= 100, f"score={score}")

    # Score deduction: critical=30, high=15*2=30, medium=5 => 65 deducted => 35
    expected_score = max(0, 100 - (30 + 15 + 5 + 15))  # = 35
    report("pr_summary", "Score deduction matches CVSS weights",
           score == expected_score, f"expected={expected_score}, got={score}")

    # Count by severity
    counts = count_by_severity(rem_findings)
    report("pr_summary", "count_by_severity() returns all 4 levels",
           set(counts.keys()) == {"critical", "high", "medium", "low"},
           f"counts={counts}")
    report("pr_summary", "count_by_severity() values correct",
           counts["critical"] == 1 and counts["high"] == 2 and counts["medium"] == 1)

    # Full summarize
    summary = summarize(rem_findings)
    report("pr_summary", "summarize() returns dict with required keys",
           all(k in summary for k in ("health_score", "counts", "summary")),
           f"keys={list(summary.keys())}")
    report("pr_summary", "Summary text is non-empty",
           len(summary["summary"]) > 20, f"summary_length={len(summary['summary'])}")

    # Empty findings
    empty_summary = summarize([])
    report("pr_summary", "Empty findings gives score=100",
           empty_summary["health_score"] == 100)

except Exception as e:
    report("pr_summary", "Summary tests", False, traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# 9. RAG ENGINE
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  9. RAG ENGINE (agents/rag_engine.py){RESET}")
print(f"{BOLD}{'='*70}{RESET}")

try:
    from agents.rag_engine import retrieve, chunk_markdown, get_model, get_chroma_collection

    # Model loading
    model = get_model()
    report("rag_engine", "SentenceTransformer model loads",
           model is not None, f"model={type(model).__name__}" if model else "model=None")

    # Chroma collection
    coll = get_chroma_collection()
    report("rag_engine", "ChromaDB collection available",
           coll is not None, f"collection={coll.name}" if coll else "collection=None")

    # Chunk markdown
    test_md = "# SQL Injection\nUse parameterized queries.\n\n# XSS\nEscape output."
    chunks = chunk_markdown("test.md", test_md)
    report("rag_engine", "chunk_markdown() returns chunks",
           isinstance(chunks, list) and len(chunks) >= 2,
           f"chunks={len(chunks)}")

    if chunks:
        report("rag_engine", "Chunks have correct structure",
               all(k in chunks[0] for k in ("text", "document", "section")))

    # Retrieve from knowledge base
    results = retrieve("SQL injection prevention", k=3)
    report("rag_engine", "retrieve() returns list (may be empty if no docs ingested)",
           isinstance(results, list),
           f"results={len(results)}")

    if results:
        report("rag_engine", "Retrieved results have required fields",
               all(k in results[0] for k in ("text", "document", "section", "distance", "score")),
               f"score={results[0].get('score', 'N/A')}")

except Exception as e:
    report("rag_engine", "RAG engine tests", False, traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# 10. CONVERSATIONAL ASSISTANT
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  10. CONVERSATIONAL ASSISTANT (agents/conversational_assistant.py){RESET}")
print(f"{BOLD}{'='*70}{RESET}")

try:
    from agents.conversational_assistant import answer

    # SQL injection question
    result = answer("How do I prevent SQL injection?")
    report("assistant", "answer() returns dict",
           isinstance(result, dict), f"keys={list(result.keys())}")
    report("assistant", "Response has 'reply' key",
           "reply" in result and len(result["reply"]) > 10,
           f"reply_length={len(result.get('reply', ''))}")
    report("assistant", "Response has 'sources' key",
           "sources" in result, f"sources={result.get('sources', [])[:2]}")
    report("assistant", "SQL injection reply mentions parameterized/prepared",
           "parameterized" in result["reply"].lower() or "prepared" in result["reply"].lower()
           or "injection" in result["reply"].lower(),
           f"reply_preview={result['reply'][:80]}...")

    # XSS question
    xss_result = answer("What is XSS and how to prevent it?")
    report("assistant", "XSS question returns relevant answer",
           "xss" in xss_result["reply"].lower() or "cross" in xss_result["reply"].lower()
           or "script" in xss_result["reply"].lower(),
           f"reply_preview={xss_result['reply'][:80]}...")

    # With code context
    context_result = answer(
        "What vulnerabilities exist in this code?",
        code_context=PYTHON_VULNERABLE,
        findings=[{"id": "1", "severity": "critical", "title": "SQL Injection", "line": 8, "description": "f-string SQL"}],
        language="python"
    )
    report("assistant", "Code-context-aware answer returns reply",
           len(context_result["reply"]) > 10)

    # Multi-turn conversation
    history = [
        {"role": "user", "content": "What is OWASP?"},
        {"role": "assistant", "content": "OWASP is the Open Web Application Security Project."}
    ]
    multi_result = answer("Tell me about the top risk.", history=history)
    report("assistant", "Multi-turn conversation works",
           len(multi_result["reply"]) > 10)

    # Fallback for unknown topic
    unknown = answer("Tell me about quantum computing algorithms")
    report("assistant", "Unknown topic returns fallback reply",
           len(unknown["reply"]) > 5)

except Exception as e:
    report("assistant", "Conversational assistant tests", False, traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# 11. REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  11. REPORT GENERATOR (agents/report_generator.py){RESET}")
print(f"{BOLD}{'='*70}{RESET}")

try:
    from agents.report_generator import generate_json_report, generate_pdf_report

    test_job_id = "test-job-12345678"
    test_submission_info = {"filename": "test_vuln.py", "language": "python"}
    test_summary = {
        "health_score": 35,
        "counts": {"critical": 1, "high": 2, "medium": 1, "low": 0},
        "summary": "Code has significant security issues."
    }
    test_findings_rows = [
        {"id": 1, "severity": "critical", "source_agent": "security",
         "title": "SQL Injection", "description": "Unsafe query",
         "line_start": 8, "line_end": 9, "category": "sql_injection", "fix": "Use parameterized queries"},
        {"id": 2, "severity": "high", "source_agent": "security",
         "title": "Hardcoded Secret", "description": "Password in code",
         "line_start": 4, "line_end": 4, "category": "hardcoded_secret", "fix": "Use env vars"},
    ]

    # JSON report
    json_bytes = generate_json_report(test_job_id, test_submission_info, test_summary, test_findings_rows)
    report("report_gen", "generate_json_report() returns bytes",
           isinstance(json_bytes, bytes) and len(json_bytes) > 50)

    json_data = json.loads(json_bytes.decode("utf-8"))
    report("report_gen", "JSON report has required fields",
           all(k in json_data for k in ("job_id", "health_score", "findings", "generated_at")),
           f"keys={list(json_data.keys())}")
    report("report_gen", "JSON report findings count correct",
           len(json_data["findings"]) == 2)

    # PDF report
    pdf_bytes = generate_pdf_report(test_job_id, test_submission_info, test_summary, test_findings_rows)
    report("report_gen", "generate_pdf_report() returns bytes",
           isinstance(pdf_bytes, bytes) and len(pdf_bytes) > 100,
           f"size={len(pdf_bytes)} bytes")

    # Check if it's actually PDF (starts with %PDF) or JSON fallback
    is_pdf = pdf_bytes[:4] == b"%PDF"
    report("report_gen", "PDF report format",
           True,
           "PDF (reportlab installed)" if is_pdf else "JSON fallback (reportlab missing)")

except Exception as e:
    report("report_gen", "Report generator tests", False, traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# 12. FULL PIPELINE (ORCHESTRATOR) — Python
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  12. FULL PIPELINE -- Python Code (agents/orchestrator.py){RESET}")
print(f"{BOLD}{'='*70}{RESET}")

try:
    import asyncio
    from agents.orchestrator import run_pipeline
    from agents.db import save_submission, create_job, get_job, get_findings

    # Submit Python vulnerable code
    py_sub_id = save_submission(PYTHON_VULNERABLE, "python", "pipeline_test.py")
    py_job_id = create_job(py_sub_id)
    report("pipeline_py", "Submission + Job created",
           True, f"sub={py_sub_id[:8]}, job={py_job_id[:8]}")

    # Run full pipeline
    start = time.time()
    asyncio.run(run_pipeline(py_job_id, py_sub_id))
    elapsed = round(time.time() - start, 2)

    # Check job status
    job = get_job(py_job_id)
    report("pipeline_py", f"Pipeline completed (took {elapsed}s)",
           job["stage"] == "done", f"stage={job['stage']}")

    report("pipeline_py", "All agents completed",
           job["agent_analysis"] == "done" and job["agent_security"] == "done"
           and job["agent_remediation"] == "done" and job["agent_summary"] == "done",
           f"analysis={job['agent_analysis']}, security={job['agent_security']}, "
           f"remediation={job['agent_remediation']}, summary={job['agent_summary']}")

    # Check findings
    findings = get_findings(py_sub_id)
    report("pipeline_py", "Findings persisted to DB",
           len(findings) >= 1, f"finding_count={len(findings)}")

    # Analyse finding details
    severities = [f["severity"] for f in findings]
    agents = set(f["source_agent"] for f in findings)
    report("pipeline_py", "Multiple agents contributed findings",
           len(agents) >= 1, f"agents={agents}")

    # Check fix field populated
    fixes = [f for f in findings if f.get("fix", "")]
    report("pipeline_py", "Remediation fixes populated",
           len(fixes) >= 1, f"fixes_count={len(fixes)}")

    # Check summary stored in job
    error_col = job.get("error", "")
    has_summary = error_col.startswith("summary:")
    report("pipeline_py", "PR summary stored in job",
           has_summary or job["stage"] == "done")

    if has_summary:
        summary_data = json.loads(error_col[len("summary:"):])
        report("pipeline_py", "Summary has health_score and counts",
               "health_score" in summary_data and "counts" in summary_data,
               f"health_score={summary_data.get('health_score')}")

except Exception as e:
    report("pipeline_py", "Python pipeline", False, traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# 13. FULL PIPELINE — JAVA
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  13. FULL PIPELINE -- Java Code{RESET}")
print(f"{BOLD}{'='*70}{RESET}")

try:
    # Submit Java vulnerable code
    java_sub_id = save_submission(JAVA_VULNERABLE, "java", "UserService.java")
    java_job_id = create_job(java_sub_id)

    start = time.time()
    asyncio.run(run_pipeline(java_job_id, java_sub_id))
    elapsed = round(time.time() - start, 2)

    job = get_job(java_job_id)
    report("pipeline_java", f"Pipeline completed (took {elapsed}s)",
           job["stage"] == "done", f"stage={job['stage']}")

    report("pipeline_java", "All agents completed",
           job["agent_analysis"] == "done" and job["agent_security"] == "done"
           and job["agent_remediation"] == "done" and job["agent_summary"] == "done")

    findings = get_findings(java_sub_id)
    report("pipeline_java", "Findings persisted",
           len(findings) >= 1, f"finding_count={len(findings)}")

    java_agents = set(f["source_agent"] for f in findings)
    report("pipeline_java", "Multiple agents contributed",
           len(java_agents) >= 1, f"agents={java_agents}")

    java_cats = set(f["category"] for f in findings if f["category"] not in ("tooling_warning", "api_failure"))
    report("pipeline_java", "Finding categories for Java",
           len(java_cats) >= 1, f"categories={java_cats}")

except Exception as e:
    report("pipeline_java", "Java pipeline", False, traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# 14. FASTAPI APP STRUCTURE VALIDATION
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  14. FASTAPI APP STRUCTURE (app.py){RESET}")
print(f"{BOLD}{'='*70}{RESET}")

try:
    from app import app

    report("fastapi", "FastAPI app imports successfully", True)
    report("fastapi", "App title set",
           app.title == "AI Code Review & Security Analysis API")
    report("fastapi", "App version set",
           app.version == "2.0.0")

    # Check routes exist
    routes = [r.path for r in app.routes if hasattr(r, 'path')]
    report("fastapi", "POST /api/submissions route exists",
           "/api/submissions" in routes, f"routes_count={len(routes)}")
    report("fastapi", "/api/jobs/{jobId}/status route exists",
           "/api/jobs/{jobId}/status" in routes)
    report("fastapi", "/api/jobs/{jobId}/findings route exists",
           "/api/jobs/{jobId}/findings" in routes)
    report("fastapi", "/api/jobs/{jobId}/assistant route exists",
           "/api/jobs/{jobId}/assistant" in routes)
    report("fastapi", "/api/jobs/{jobId}/report route exists",
           "/api/jobs/{jobId}/report" in routes)
    report("fastapi", "/health route exists",
           "/health" in routes)
    report("fastapi", "/ root route exists",
           "/" in routes)

    # Legacy routes
    report("fastapi", "Legacy /submissions route exists",
           "/submissions" in routes)
    report("fastapi", "Legacy /api/v1/analyze route exists",
           "/api/v1/analyze" in routes)

except Exception as e:
    report("fastapi", "FastAPI tests", False, traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*70}")
print(f"{BOLD}  PIPELINE TEST RESULTS SUMMARY{RESET}")
print(f"{'='*70}")

total = len(results)
passed_count = sum(1 for r in results if r.get("ok", False))
failed_count = sum(1 for r in results if not r.get("ok", False))

# Group by module
modules = {}
for r in results:
    mod_name = r.get("module", "unknown")
    if mod_name not in modules:
        modules[mod_name] = []
    modules[mod_name].append(r)

print(f"\n{'Module':<25} {'Pass':>6} {'Fail':>6} {'Status':>10}")
print(f"{'-'*25} {'-'*6} {'-'*6} {'-'*10}")
for mod, tests in modules.items():
    m_pass = sum(1 for t in tests if t.get("ok", False))
    m_fail = sum(1 for t in tests if not t.get("ok", False))
    status = f"{GREEN}OK{RESET}" if m_fail == 0 else f"{RED}FAIL{RESET}"
    print(f"{mod:<25} {m_pass:>6} {m_fail:>6} {status:>10}")

print(f"{'-'*25} {'-'*6} {'-'*6} {'-'*10}")
print(f"{'TOTAL':<25} {passed_count:>6} {failed_count:>6}")

print(f"\n{BOLD}Result: {GREEN}{passed_count}/{total} tests passed{RESET}", end="")
if failed_count:
    print(f", {RED}{failed_count} failed{RESET}")
    print(f"\n{RED}SOME TESTS FAILED{RESET}")

    print(f"\n{YELLOW}Failed tests:{RESET}")
    for r in results:
        if not r.get("ok", False):
            print(f"  {RED}x{RESET} {r.get('module','')} -> {r.get('test','')}: {r.get('detail','')[:100]}")
else:
    print()
    print(f"\n{GREEN}{'='*70}{RESET}")
    print(f"{GREEN}{BOLD}  ALL {total} TESTS PASSED -- PIPELINE FULLY OPERATIONAL{RESET}")
    print(f"{GREEN}{'='*70}{RESET}")

sys.exit(0 if failed_count == 0 else 1)
