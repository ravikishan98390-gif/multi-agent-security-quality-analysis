"""
security_agent.py — Security Vulnerability Agent (Hybrid Pattern + Grounded LLM).

Architecture
------------
Tier 1 — Deterministic Pattern Scanner (_run_pattern_scan):
    Line-precise regex rules that catch unambiguous vulnerability patterns.
    Returns PatternCandidate objects with exact line_start/line_end, matched text,
    confidence level, and a RAG query term.

    Tier 2 — Grounded LLM Judge (Google Gemini):
    Receives the full source code, all Tier 1 candidates with their exact line numbers,
    and OWASP RAG context for each candidate category.
    Tasks: (a) validate/reject Tier 1 hits, (b) detect subtler issues the regex missed.
    ALL returned findings must carry specific line_start/line_end — not vague ranges.

Fallback — If no API key: Tier 1 only (pattern scan), results returned directly.

Edit the two module-level prompt strings (SECURITY_HYBRID_PROMPT,
SECURITY_CANDIDATE_SYSTEM_PROMPT) to tune LLM behaviour without touching logic.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, List, Optional

import httpx
from dotenv import load_dotenv

from agents.models import Finding, Severity, OWASP_CATEGORY_MAP
from agents.rag_engine import retrieve

# Load environment variables
load_dotenv()

# ---------------------------------------------------------------------------
# Editable LLM Prompt Strings
# ---------------------------------------------------------------------------

SECURITY_HYBRID_PROMPT = """\
You are a senior application-security engineer conducting a grounded OWASP Top 10 code review.

INPUTS PROVIDED:
1. `language`         — programming language of the submitted code.
2. `source_code`      — full file with 1-indexed line numbers prepended (format: "  42: <code>").
3. `tier1_candidates` — potential vulnerabilities from a deterministic regex scanner.
   Each entry includes: line_start, line_end, category, matched_text, confidence, description, rag_context.
4. `rag_context`      — OWASP knowledge-base excerpts embedded in each candidate for grounding.

STEP-BY-STEP REASONING (follow this order):

Step 1 — VALIDATE each tier1_candidate:
  a. Look at the exact source lines (line_start to line_end). Confirm the matched_text is real code,
     NOT inside a comment (#, //, /* */), docstring (triple-quotes), or string literal used as a label.
  b. If it is a genuine vulnerability → keep it. Use rag_context to enrich the description.
     Preserve the EXACT line_start and line_end from the candidate. Do NOT change them.
  c. If it is a false positive → DISCARD completely. Do not include it in output.

Step 2 — SCAN for SUBTLE issues the regex missed:
  Focus on: insecure direct object references (IDOR), missing authorization checks,
  timing-attack-prone comparisons (== on secrets), JWT without algorithm verification,
  open redirects, path traversal, XXE, unsafe deserialization, debug/verbose error leaks.
  For every new finding, pinpoint the EXACT line_start and line_end — not a vague range.

SEVERITY ASSIGNMENT (CVSS v3.1 aligned — be consistent):
  CRITICAL (≈ CVSS 9.0+) — Remote code execution, direct data exfiltration, auth bypass
                            Examples: SQL injection with user input, hardcoded admin credentials
  HIGH     (≈ CVSS 7.0–8.9) — Significant data exposure or privilege escalation
                               Examples: Stored XSS, weak password hashing (MD5/SHA-1),
                               missing auth on sensitive route
  MEDIUM   (≈ CVSS 4.0–6.9) — Requires user interaction or specific conditions to exploit
                               Examples: Reflected XSS, CSRF on non-critical endpoint,
                               insecure cookie flags
  LOW      (< CVSS 4.0)     — Defense-in-depth improvement, no immediate exploitability
                               Examples: Missing security headers, verbose error messages

CRITICAL RULES:
- Every finding MUST have specific integer line_start and line_end (1-indexed).
- NEVER set line_start = 1 as a catch-all unless the vulnerability genuinely starts at line 1.
- Descriptions MUST: (a) cite the OWASP category, (b) state WHY it is exploitable,
  (c) give a 1-sentence concrete remediation. Max 3 sentences total.
- Do NOT hallucinate vulnerabilities. If uncertain, omit.
- Return ONLY a valid JSON array. No markdown fences, no prose, no trailing commas.

OUTPUT SCHEMA (one object per finding):
[
  {
    "line_start": <integer>,
    "line_end": <integer>,
    "title": <string, ≤ 80 chars>,
    "description": <string, max 3 sentences — OWASP ref + exploit rationale + fix>,
    "severity": "critical" | "high" | "medium" | "low",
    "category": "sql_injection" | "xss" | "hardcoded_secret" | "broken_auth"
              | "broken_access_control" | "csrf" | "insecure_deserialization"
              | "security_misconfiguration" | "other",
    "owasp_category": <string, e.g. "A03:2021-Injection">,
    "grounding_sources": [{"document": <string>, "section": <string>}],
    "detection_tier": "pattern" | "llm"
  }
]
If no vulnerabilities found, return: []
"""

# Legacy two-pass prompts kept for reference (not used in the hybrid flow)
SECURITY_CANDIDATE_SYSTEM_PROMPT = """\
You are an expert security code auditor. Identify potential security vulnerabilities,
returning a JSON array of {line_start, line_end, category, query_term, description}.
Categories: sql_injection, xss, csrf, hardcoded_secret, broken_auth, broken_access_control.
Return ONLY a JSON array. If no issues, return [].
"""


# ---------------------------------------------------------------------------
# PatternCandidate — internal result from Tier 1 scan
# ---------------------------------------------------------------------------

@dataclass
class PatternCandidate:
    """Intermediate result from the deterministic Tier 1 pattern scanner."""
    category: str
    line_start: int
    line_end: int
    matched_text: str           # the offending source snippet
    query_term: str             # used to retrieve RAG context
    confidence: str             # "high" | "medium"
    description: str            # human-readable one-liner for the LLM

    def to_dict(self) -> dict:
        return {
            "line_start": self.line_start,
            "line_end": self.line_end,
            "category": self.category,
            "matched_text": self.matched_text,
            "query_term": self.query_term,
            "confidence": self.confidence,
            "description": self.description,
        }


# ---------------------------------------------------------------------------
# Tier 1 — Deterministic Pattern Scanner
# ---------------------------------------------------------------------------

# ── Pattern definitions ────────────────────────────────────────────────────

# SQL Injection: f-string — matches f"...SQL..." or f'...SQL...' with any {var}
# The f-prefix must immediately precede the opening quote
_SQLI_FSTRING = re.compile(
    r"""\bf[\"'][^\"'\n]*?\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b""",
    re.IGNORECASE,
)

# SQL Injection: string concatenation with SQL keyword on same line
# Either the SQL keyword is before the + (right side of concat) OR after
_SQLI_CONCAT = re.compile(
    r"""(['"]).*?\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*?\1\s*\+""",
    re.IGNORECASE,
)
_SQLI_CONCAT_REV = re.compile(
    r"""\+\s*.*?(['"]).*?\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*?\1""",
    re.IGNORECASE,
)

# SQL Injection: .format() — SQL keyword anywhere on line + .format( call
_SQLI_FORMAT = re.compile(
    r"""\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*?\.format\s*\(""",
    re.IGNORECASE,
)

# Hardcoded secrets: password/key/secret/token literal assignment
_SECRET_LITERAL = re.compile(
    r"""(?:password|passwd|pwd|secret|api_key|apikey|token|auth_token|aws_secret|aws_secret_access_key|jwt_secret)\s*=\s*['"]"""
    r"""[^'"]{6,}['"]""",
    re.IGNORECASE,
)

# XSS: render_template_string() — any call (flag for LLM to decide if user-controlled)
_XSS_RTS = re.compile(
    r"""\brender_template_string\s*\(""",
    re.IGNORECASE,
)

# XSS: Markup() from markupsafe/flask — wrapping a variable (not a literal string)
_XSS_MARKUP = re.compile(
    r"""\bMarkup\s*\(\s*(?!['"])""",
    re.IGNORECASE,
)

# XSS: Jinja2 |safe filter applied to a variable in a template string
_XSS_SAFE_FILTER = re.compile(
    r"""\|\s*safe\b""",
    re.IGNORECASE,
)

# Insecure auth: MD5 or SHA-1 used (broken for passwords)
_WEAK_HASH = re.compile(
    r"""hashlib\.(md5|sha1)\b|MessageDigest\.getInstance\(\s*['"](?:MD5|SHA-1)['"]""",
    re.IGNORECASE,
)

# Broken access control: Flask route decorator NOT immediately followed by @login_required
# Detect bare @app.route on admin/delete/dashboard/users paths
_ADMIN_ROUTE = re.compile(
    r"""@(?:app|bp|blueprint)\s*\.\s*route\s*\(['"]/(?:admin|dashboard|internal|manage)[^'"]*['"]""",
    re.IGNORECASE,
)

# Access control: IDOR pattern — route uses <int:id> or <user_id> without session check
_IDOR_ROUTE = re.compile(
    r"""@(?:app|bp|blueprint)\s*\.\s*route\s*\(.*<(?:int:)?(?:user_id|account_id|record_id|id)>""",
    re.IGNORECASE,
)


def _run_pattern_scan(code: str, language: str) -> list[PatternCandidate]:
    """
    Tier 1 deterministic scanner.
    Returns PatternCandidate objects with exact line_start/line_end.
    Never raises — returns empty list on any error.
    """
    candidates: list[PatternCandidate] = []
    lines = code.splitlines()

    in_docstring = False
    docstring_quote = None

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Track triple-quoted docstrings to avoid matching pattern text inside them
        for quote in ('"""', "'''"):
            count = stripped.count(quote)
            if not in_docstring and count >= 1:
                in_docstring = True
                docstring_quote = quote
                if count >= 2:  # opened and closed on same line
                    in_docstring = False
                    docstring_quote = None
                continue
            if in_docstring and quote == docstring_quote and count >= 1:
                in_docstring = False
                docstring_quote = None

        if in_docstring:
            continue

        # Skip pure comment lines
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue

        # ── SQL Injection: f-string ─────────────────────────────────────
        if _SQLI_FSTRING.search(stripped):
            candidates.append(PatternCandidate(
                category="sql_injection",
                line_start=i,
                line_end=i,
                matched_text=stripped[:120],
                query_term="parameterized queries sql injection prevention",
                confidence="high",
                description=(
                    f"Line {i}: SQL query constructed using an f-string with variable "
                    "interpolation. An attacker can manipulate the query structure by "
                    "controlling the interpolated value."
                ),
            ))

        # ── SQL Injection: string concatenation ──────────────────────────
        elif _SQLI_CONCAT.search(stripped) or _SQLI_CONCAT_REV.search(stripped):
            candidates.append(PatternCandidate(
                category="sql_injection",
                line_start=i,
                line_end=i,
                matched_text=stripped[:120],
                query_term="parameterized queries sql injection prevention",
                confidence="high",
                description=(
                    f"Line {i}: SQL query assembled via string concatenation (+). "
                    "Any untrusted component of the concatenation is an injection vector."
                ),
            ))

        # ── SQL Injection: .format() ──────────────────────────────────────
        elif _SQLI_FORMAT.search(stripped):
            candidates.append(PatternCandidate(
                category="sql_injection",
                line_start=i,
                line_end=i,
                matched_text=stripped[:120],
                query_term="parameterized queries sql injection prevention",
                confidence="high",
                description=(
                    f"Line {i}: SQL query built using str.format(), which does not "
                    "sanitise inputs. Use parameterised queries instead."
                ),
            ))

        # ── Hardcoded Secret ─────────────────────────────────────────────
        if _SECRET_LITERAL.search(stripped):
            candidates.append(PatternCandidate(
                category="hardcoded_secret",
                line_start=i,
                line_end=i,
                matched_text=stripped[:120],
                query_term="hardcoded secrets environment variables vault",
                confidence="high",
                description=(
                    f"Line {i}: A credential or secret is hardcoded as a string literal. "
                    "It will be exposed to anyone with read access to the source file or "
                    "version control history."
                ),
            ))

        # ── XSS: render_template_string ──────────────────────────────────
        if language == "python" and _XSS_RTS.search(stripped):
            candidates.append(PatternCandidate(
                category="xss",
                line_start=i,
                line_end=i,
                matched_text=stripped[:120],
                query_term="xss template injection escaping prevention",
                confidence="medium",
                description=(
                    f"Line {i}: render_template_string() executes a Jinja2 template from "
                    "a string. If the template string includes user-controlled data, an "
                    "attacker can inject template expressions (SSTI) or HTML/JS (XSS)."
                ),
            ))

        # ── XSS: Markup() on variable ────────────────────────────────────
        if language == "python" and _XSS_MARKUP.search(stripped):
            candidates.append(PatternCandidate(
                category="xss",
                line_start=i,
                line_end=i,
                matched_text=stripped[:120],
                query_term="xss markupsafe flask escaping",
                confidence="medium",
                description=(
                    f"Line {i}: Markup() marks content as HTML-safe, bypassing Jinja2's "
                    "auto-escaping. Wrapping unsanitised user input with Markup() allows "
                    "arbitrary script injection."
                ),
            ))

        # ── XSS: |safe filter ────────────────────────────────────────────
        if _XSS_SAFE_FILTER.search(stripped):
            candidates.append(PatternCandidate(
                category="xss",
                line_start=i,
                line_end=i,
                matched_text=stripped[:120],
                query_term="xss jinja safe filter escaping",
                confidence="medium",
                description=(
                    f"Line {i}: Jinja2 '|safe' filter disables HTML auto-escaping for "
                    "this value. If the value originates from user input, XSS is possible."
                ),
            ))

        # ── Insecure Hashing ─────────────────────────────────────────────
        if _WEAK_HASH.search(stripped):
            candidates.append(PatternCandidate(
                category="broken_auth",
                line_start=i,
                line_end=i,
                matched_text=stripped[:120],
                query_term="bcrypt argon2 password hashing insecure md5 sha1",
                confidence="high",
                description=(
                    f"Line {i}: MD5 or SHA-1 is used. These algorithms are "
                    "cryptographically broken and trivially reversible for passwords. "
                    "Use bcrypt, Argon2, or scrypt for credential storage."
                ),
            ))

        # ── Broken Access Control: admin route ───────────────────────────
        if language == "python" and _ADMIN_ROUTE.search(stripped):
            # Look ahead up to 3 lines for a @login_required decorator
            lookahead = lines[i : min(i + 3, len(lines))]
            has_auth = any(
                re.search(r"@\s*login_required|Depends\s*\(|require_permission|auth_required", ln, re.IGNORECASE)
                for ln in lookahead
            )
            if not has_auth:
                candidates.append(PatternCandidate(
                    category="broken_access_control",
                    line_start=i,
                    line_end=i,
                    matched_text=stripped[:120],
                    query_term="broken access control authentication authorization flask",
                    confidence="medium",
                    description=(
                        f"Line {i}: A route to a sensitive admin/dashboard path is defined "
                        "without a visible authentication decorator (@login_required or "
                        "equivalent) in the next 3 lines. Unauthenticated users may access "
                        "privileged functionality."
                    ),
                ))

        # ── Broken Access Control: IDOR route ─────────────────────────────
        if language == "python" and _IDOR_ROUTE.search(stripped):
            # Check if function body (next 10 lines) contains a session/user check
            lookahead = lines[i : min(i + 10, len(lines))]
            has_ownership_check = any(
                re.search(r"session\[|current_user|get_jwt_identity|user_id\s*==|\.user_id\b", ln, re.IGNORECASE)
                for ln in lookahead
            )
            if not has_ownership_check:
                candidates.append(PatternCandidate(
                    category="broken_access_control",
                    line_start=i,
                    line_end=i,
                    matched_text=stripped[:120],
                    query_term="IDOR insecure direct object reference broken access control",
                    confidence="medium",
                    description=(
                        f"Line {i}: Route accepts a user/account/record ID in the URL but "
                        "no ownership check (session comparison) is visible in the next "
                        "10 lines. Any authenticated user may access any other user's data "
                        "(Insecure Direct Object Reference / IDOR)."
                    ),
                ))

    return candidates


def _candidate_to_finding(cand: PatternCandidate, rag_sources: list[dict]) -> Finding:
    """Convert a PatternCandidate directly to a Finding (Tier 1 fallback path)."""
    _SEVERITY_MAP = {
        "sql_injection": Severity.CRITICAL,
        "hardcoded_secret": Severity.CRITICAL,
        "xss": Severity.HIGH,
        "broken_auth": Severity.HIGH,
        "broken_access_control": Severity.HIGH,
        "csrf": Severity.HIGH,
    }
    _TITLE_MAP = {
        "sql_injection": "SQL Injection via String Interpolation",
        "hardcoded_secret": "Hardcoded Credential / Secret",
        "xss": "Cross-Site Scripting (XSS) Risk",
        "broken_auth": "Insecure / Weak Hashing Algorithm",
        "broken_access_control": "Broken Access Control — Missing Auth Guard",
        "csrf": "Cross-Site Request Forgery (CSRF) Risk",
    }

    # Enrich description with first RAG source name if available
    rag_note = ""
    if rag_sources:
        first = rag_sources[0]
        rag_note = (
            f" [OWASP ref: {first.get('document', '')} — {first.get('section', '')}]"
        )

    return Finding(
        type="security",
        severity=_SEVERITY_MAP.get(cand.category, Severity.HIGH),
        line_start=cand.line_start,
        line_end=cand.line_end,
        title=_TITLE_MAP.get(cand.category, f"Security Issue: {cand.category}"),
        description=cand.description + rag_note,
        category=cand.category,
        source_agent="security",
        extra={
            "owasp_category": OWASP_CATEGORY_MAP.get(cand.category, "OWASP Top 10"),
            "grounding_sources": [
                {"document": s.get("document", ""), "section": s.get("section", ""),
                 "score": s.get("score", 0)}
                for s in rag_sources
            ],
            "detection_tier": "pattern",
            "matched_text": cand.matched_text,
            "confidence": cand.confidence,
        },
    )


# ---------------------------------------------------------------------------
# Google Gemini API Client
# ---------------------------------------------------------------------------

def _get_api_key() -> str | None:
    """Retrieve Google Gemini API key from environment."""
    return (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "").strip() or None


def _call_gemini_api(
    system_prompt: str,
    user_content: str,
    model_name: str = "gemini-1.5-pro",
) -> str:
    """Call Google Gemini API using the google-generativeai SDK."""
    api_key = _get_api_key()
    if not api_key:
        raise ValueError("Gemini API key is not configured.")

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
        
        # Combine system prompt and user content for Gemini
        combined_prompt = f"{system_prompt}\n\n{user_content}"
        
        response = model.generate_content(
            combined_prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.05,  # low temperature for deterministic security analysis
            )
        )
        return response.text or "[]"
    except Exception as exc:
        raise exc


# ---------------------------------------------------------------------------
# RAG Retrieval Helper
# ---------------------------------------------------------------------------

def _retrieve_rag_for_candidates(candidates: list[PatternCandidate]) -> dict[str, list[dict]]:
    """
    For each unique query_term in the candidate list, retrieve RAG context.
    Uses the candidate's category as a hint to improve retrieval precision.
    Returns a dict keyed by query_term → list of {document, section, text, score} hits.
    """
    seen: dict[str, list[dict]] = {}
    for cand in candidates:
        qt = cand.query_term
        if qt in seen:
            continue
        try:
            docs = retrieve(qt, k=2, category_hint=cand.category)
            seen[qt] = docs
        except Exception:
            seen[qt] = []
    return seen


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def analyze(code: str, language: str) -> list[Finding]:
    """
    Analyze code for OWASP security vulnerabilities using the hybrid strategy.

    If GEMINI_API_KEY is set:
      Tier 1 (pattern scan) → RAG retrieval → Tier 2 (grounded LLM validation + extension)

    If no API key:
      Tier 1 (pattern scan) only, with inline RAG source citations.
    """
    lang = language.lower().strip()

    # ── Tier 1: Deterministic Pattern Scan ──────────────────────────────────
    tier1_candidates = _run_pattern_scan(code, lang)

    # Retrieve RAG context for each unique query term
    rag_by_query = _retrieve_rag_for_candidates(tier1_candidates)

    api_key = _get_api_key()

    if not api_key:
        # Tier 1 only — convert candidates directly to Findings
        findings: list[Finding] = []
        for cand in tier1_candidates:
            rag_docs = rag_by_query.get(cand.query_term, [])
            rag_sources = [{"document": d["document"], "section": d["section"]} for d in rag_docs]
            findings.append(_candidate_to_finding(cand, rag_sources))

        findings.append(
            Finding(
                type="security",
                severity=Severity.LOW,
                line_start=1,
                line_end=1,
                title="Gemini API Key Missing — Pattern Scan Active",
                description=(
                    "No GEMINI_API_KEY found. The deterministic pattern scanner (Tier 1) ran "
                    "and caught high-confidence issues. Set GEMINI_API_KEY to enable grounded "
                    "LLM verification and detection of subtler vulnerabilities."
                ),
                category="tooling_warning",
                source_agent="security",
            )
        )
        return findings

    # ── Tier 2: Grounded LLM Judge ───────────────────────────────────────────
    # Build candidate dicts with their RAG context attached
    candidates_with_rag = []
    for cand in tier1_candidates:
        rag_docs = rag_by_query.get(cand.query_term, [])
        rag_texts = [
            f"Source: {d['document']} / {d['section']}\nGuidance: {d['text']}"
            for d in rag_docs
        ]
        candidates_with_rag.append({
            **cand.to_dict(),
            "rag_context": "\n---\n".join(rag_texts),
        })

    # Annotate source code with line numbers for the LLM
    annotated_lines = "\n".join(f"{i+1:4d}: {l}" for i, l in enumerate(code.splitlines()))

    llm_input = json.dumps(
        {
            "language": lang,
            "source_code": annotated_lines,
            "tier1_candidates": candidates_with_rag,
        },
        indent=2,
        ensure_ascii=False,
    )

    try:
        raw_response = _call_gemini_api(
            system_prompt=SECURITY_HYBRID_PROMPT,
            user_content=llm_input,
        )
        verified_list = json.loads(raw_response)
    except Exception as exc:
        # LLM failed — fall back to Tier 1 results + warning
        findings = []
        for cand in tier1_candidates:
            rag_docs = rag_by_query.get(cand.query_term, [])
            rag_sources = [{"document": d["document"], "section": d["section"]} for d in rag_docs]
            findings.append(_candidate_to_finding(cand, rag_sources))
        findings.append(
            Finding(
                type="security",
                severity=Severity.LOW,
                line_start=1,
                line_end=1,
                title="LLM Verification Failed — Pattern Scan Active",
                description=f"Gemini API call failed ({exc}). Tier 1 pattern scan results returned.",
                category="api_failure",
                source_agent="security",
            )
        )
        return findings

    # ── Translate LLM JSON response to Finding objects ────────────────────────
    findings = []
    for item in verified_list:
        try:
            sev = Severity(item["severity"].lower())
        except (ValueError, KeyError):
            sev = Severity.HIGH

        findings.append(
            Finding(
                type="security",
                severity=sev,
                line_start=int(item.get("line_start", 1)),
                line_end=int(item.get("line_end", item.get("line_start", 1))),
                title=item.get("title", "Security Vulnerability"),
                description=item.get("description", ""),
                category=item.get("category", "unknown"),
                source_agent="security",
                extra={
                    "owasp_category": item.get("owasp_category", "OWASP Top 10"),
                    "grounding_sources": item.get("grounding_sources", []),
                    "detection_tier": item.get("detection_tier", "llm"),
                },
            )
        )

    return findings
