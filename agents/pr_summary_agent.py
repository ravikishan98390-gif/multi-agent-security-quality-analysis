"""
pr_summary_agent.py — Generates a structured, human-readable PR review summary.

Produces a plain-English summary from the aggregated findings, without
requiring an LLM (fully offline). If a Gemini API key is available, it
enriches the summary with an LLM-generated narrative.
"""

from __future__ import annotations

import os
from typing import List

from agents.models import Finding, Severity, SEVERITY_WEIGHTS


# ---------------------------------------------------------------------------
# Score calculator (matches frontend health score expectations)
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHT = {
    "critical": 25,
    "high": 10,
    "medium": 4,
    "low": 1,
}


def compute_health_score(findings: List[Finding]) -> int:
    """
    Compute a 0–100 health score (CVSS v3.1-aligned deduction model).
    Tooling warnings are excluded from the deduction.
    Weights: critical=30, high=15, medium=5, low=1.
    """
    deduction = sum(
        SEVERITY_WEIGHTS.get(f.severity.value, 0)
        for f in findings
        if f.category != "tooling_warning"
    )
    return max(0, 100 - deduction)


def count_by_severity(findings: List[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Rule-based summary generator
# ---------------------------------------------------------------------------

def _rule_based_summary(findings: List[Finding], score: int, counts: dict[str, int]) -> str:
    total = len(findings)
    if total == 0:
        return (
            "No issues detected. The submitted code passes all quality and security "
            "checks. Great work — it's ready for review."
        )

    security_count = sum(1 for f in findings if f.source_agent == "security")
    quality_count = total - security_count
    critical_high = counts["critical"] + counts["high"]

    parts = [f"Code Health Score: {score}/100."]

    if counts["critical"] > 0:
        parts.append(
            f"{counts['critical']} CRITICAL issue(s) require immediate attention before merging."
        )
    if counts["high"] > 0:
        parts.append(f"{counts['high']} HIGH severity issue(s) should be addressed in this PR.")

    if security_count > 0:
        parts.append(
            f"{security_count} security vulnerability(s) were detected (OWASP Top 10 relevant). "
            "Review and remediate before deployment."
        )
    if quality_count > 0:
        parts.append(
            f"{quality_count} code quality issue(s) were flagged (complexity, naming, duplication). "
            "Addressing these will improve long-term maintainability."
        )

    if score >= 80:
        parts.append("Overall: Code is in good shape with minor issues to address.")
    elif score >= 50:
        parts.append("Overall: Code needs improvement before merge.")
    else:
        parts.append("Overall: Significant issues found — a thorough review is strongly recommended.")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Optional LLM enrichment via Gemini
# ---------------------------------------------------------------------------

def _llm_summary(findings: List[Finding], score: int) -> str | None:
    """Generate a structured LLM-based PR review summary. Returns None on any failure."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        import openai
        client = openai.OpenAI(api_key=api_key)

        # Build compact finding list for the prompt (cap at 20 to stay within token budget)
        finding_lines = []
        for f in findings[:20]:
            if f.category == "tooling_warning":
                continue
            finding_lines.append(
                f"- [{f.severity.value.upper()}] {f.title} "
                f"(line {f.line_start}, agent: {f.source_agent}, category: {f.category})"
            )
        findings_text = "\n".join(finding_lines) if finding_lines else "(No findings to report.)"

        counts = count_by_severity(
            [f for f in findings if f.category != "tooling_warning"]
        )
        severity_table = (
            f"🔴 Critical: {counts['critical']}  "
            f"🟠 High: {counts['high']}  "
            f"🟡 Medium: {counts['medium']}  "
            f"🟢 Low: {counts['low']}"
        )

        system_msg = (
            "You are an Expert DevSecOps Engineer writing a concise, constructive Pull Request review.\n"
            "ROLE: Synthesize the findings below into a structured review using ONLY the data provided.\n"
            "RULES:\n"
            "  1. Do NOT invent or hallucinate vulnerabilities not listed below.\n"
            "  2. Maintain a professional, collaborative tone.\n"
            "  3. Use Markdown: headings, bold, code blocks, emojis for scannability.\n"
            "  4. Output EXACTLY the 5 sections below — no extra sections.\n\n"
            "OUTPUT STRUCTURE:\n"
            "## 📊 Executive Overview\n"
            "  2–3 sentences: overall health, what was done well, main risk areas.\n\n"
            "## 🛡️ Severity Breakdown\n"
            "  Display the severity table provided. Do not recount.\n\n"
            "## 🔥 Critical & High Security Findings\n"
            "  List ONLY Critical/High security findings with: location, risk, one-line fix.\n"
            "  If none, write 'No critical or high security issues detected.'\n\n"
            "## 🔧 Code Quality & Technical Debt\n"
            "  Summarize quality/complexity findings with refactoring suggestions.\n"
            "  If none, write 'No code quality issues detected.'\n\n"
            "## ✅ Top 3 Recommended Actions\n"
            "  Bulleted, prioritized list of the 3 most impactful things to fix."
        )

        user_msg = (
            f"Health Score: {score}/100\n"
            f"Severity Breakdown: {severity_table}\n\n"
            f"Findings:\n{findings_text}"
        )

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.1,
        )
        return response.choices[0].message.content.strip()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def summarize(findings: List[Finding]) -> dict:
    """
    Generate a PR review summary from the full finding list.

    Returns
    -------
    {
        "health_score": int,          # 0-100
        "counts": {...},              # per-severity counts
        "summary": str,               # human-readable summary paragraph
    }
    """
    score = compute_health_score(findings)
    counts = count_by_severity(findings)

    # Try LLM first, fall back to rule-based
    summary_text = _llm_summary(findings, score) or _rule_based_summary(findings, score, counts)

    return {
        "health_score": score,
        "counts": counts,
        "summary": summary_text,
    }
