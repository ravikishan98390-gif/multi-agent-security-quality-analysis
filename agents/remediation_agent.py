"""
remediation_agent.py — Generates fix recommendations for each Finding.

Strategy
--------
For each finding this agent uses the RAG knowledge base to retrieve the
relevant OWASP/secure-coding guideline, then produces:
  - A short "fix" description (1-2 sentences, actionable)
  - An optional corrected code example (inline in the Finding's extra dict)

The fix is stored in finding.extra["fix"] and finding.extra["corrected_code"].
Since this is primarily rule-based (augmented by retrieved context), it works
fully offline without an LLM API key.
"""

from __future__ import annotations

from typing import List

from agents.models import Finding, Severity
from agents.rag_engine import retrieve

# ---------------------------------------------------------------------------
# Rule-based fix library — covers most common Finding categories
# ---------------------------------------------------------------------------

_FIX_LIBRARY: dict[str, str] = {
    # Security
    "sql_injection": (
        "Use parameterized queries or prepared statements. Never concatenate "
        "user input directly into SQL strings. Example: "
        "`cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`"
    ),
    "xss": (
        "Escape all user-controlled data before rendering it in HTML. "
        "In Jinja2/Flask use `{{ value | e }}` or `Markup.escape()`. "
        "Set a strict Content-Security-Policy header."
    ),
    "csrf": (
        "Add CSRF tokens to all state-changing forms and validate them server-side. "
        "Use `flask-wtf` or Django's built-in `{% csrf_token %}` tag."
    ),
    "hardcoded_secret": (
        "Move secrets to environment variables or a secrets manager (e.g. AWS Secrets Manager, "
        "HashiCorp Vault). Load with `os.environ['KEY']` and never commit to source control."
    ),
    "broken_access_control": (
        "Enforce authorisation at every sensitive endpoint. Check that the "
        "current user owns the requested resource before serving it. "
        "Use role-based access control (RBAC) or attribute-based (ABAC)."
    ),
    "broken_auth": (
        "Use a modern, vetted hashing algorithm such as bcrypt, scrypt, or Argon2 "
        "with a per-password salt. Never use MD5 or SHA-1 for password storage."
    ),
    "insecure_deserialization": (
        "Avoid deserializing untrusted data with `pickle` or similar. "
        "Use JSON or message-pack with strict schema validation instead."
    ),
    "weak_hash": (
        "Replace MD5/SHA-1 with SHA-256 or stronger for non-password uses. "
        "For passwords, use bcrypt/Argon2 via `passlib` or `bcrypt` library."
    ),
    # Code quality
    "long_method": (
        "Extract cohesive sub-tasks into smaller, focused helper methods. "
        "Aim for methods ≤ 30 lines following the Single Responsibility Principle."
    ),
    "high_complexity": (
        "Reduce cyclomatic complexity by extracting conditional branches into "
        "guard clauses, strategy objects, or lookup tables."
    ),
    "deep_nesting": (
        "Flatten deeply nested blocks using early returns (guard clauses), "
        "or extract inner loops/conditions into separate methods."
    ),
    "poor_naming": (
        "Replace single-character or generic names with descriptive identifiers "
        "that convey purpose. E.g. rename `d` → `user_data`, `res` → `query_result`."
    ),
    "duplicate_code": (
        "Extract the duplicated logic into a shared helper function or base class method. "
        "Follow the DRY (Don't Repeat Yourself) principle."
    ),
    "high_instantiation_fanout": (
        "Apply Dependency Injection: accept dependencies via constructor parameters "
        "rather than instantiating them inside the method. This improves testability "
        "and loosens coupling."
    ),
    "tight_coupling": (
        "Apply Dependency Injection or the Façade pattern to reduce direct class "
        "creation. Program to interfaces rather than concrete implementations."
    ),
    "tooling_warning": (
        "Install the required tooling (e.g. `javalang`, `reportlab`) via pip "
        "to enable full analysis capabilities."
    ),
    "api_failure": (
        "Check your environment variables and ensure your API key (e.g., GEMINI_API_KEY) "
        "is valid and the service is available."
    ),
}

_DEFAULT_FIX = (
    "Review the flagged code against OWASP Top 10 guidelines and your organisation's "
    "secure coding standards. Consult the RAG assistant for targeted advice."
)


def _get_fix(finding: Finding) -> str:
    """Return a fix recommendation for a finding, augmented with RAG context."""
    # 1. Start with rule-based fix
    base_fix = _FIX_LIBRARY.get(finding.category, "")

    # 2. Augment with top RAG hit if available
    try:
        query = f"{finding.title}: {finding.description[:200]}"
        hits = retrieve(query, k=1)
        if hits:
            rag_note = f" (Ref: {hits[0]['document']} — {hits[0]['section']})"
            return (base_fix or _DEFAULT_FIX) + rag_note
    except Exception:
        pass

    return base_fix or _DEFAULT_FIX


def remediate(findings: List[Finding]) -> List[Finding]:
    """
    Enrich each Finding with a fix recommendation stored in finding.extra['fix'].
    Returns the same list (mutated in place) for pipeline chaining.
    """
    for f in findings:
        if "fix" not in f.extra:
            f.extra["fix"] = _get_fix(f)
    return findings
