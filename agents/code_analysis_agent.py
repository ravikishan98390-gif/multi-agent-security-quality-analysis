"""
code_analysis_agent.py — Public entry point for the Code Analysis Agent.

This is the file the Orchestrator imports. It exposes a single `analyze()`
function that dispatches to the correct language-specific analyzer.

Sync vs. async
--------------
`analyze()` is intentionally *synchronous*. The Orchestrator wraps it with
`asyncio.to_thread(analyze, ...)` so it doesn't block the event loop when
run in parallel with the Security Vulnerability Agent. This keeps parsing
logic free of async boilerplate while remaining Orchestrator-compatible.

Usage
-----
    from agents.code_analysis_agent import analyze

    findings = analyze(code="def foo(): ...", language="python")
    for f in findings:
        print(f.to_dict())
"""

from __future__ import annotations

from typing import List

from agents.analyzers.java_analyzer import JavaAnalyzer
from agents.analyzers.python_analyzer import PythonAnalyzer
from agents.models import Finding, Severity


# Editable system prompt template — tune without touching parsing logic
# (Used when an optional LLM re-ranking pass is added in Milestone 3)
CODE_ANALYSIS_SYSTEM_PROMPT: str = """\
You are an expert software engineer specializing in code quality, maintainability, and CVSS-aligned
severity assessment. You review findings produced by a static analysis tool.

Your role:
1. Confirm whether each finding is valid in the given context.
2. Enrich the description with a concrete, actionable refactoring tip (≤2 sentences).
3. Re-assign severity only when clearly warranted using the table below.

SEVERITY RE-ASSIGNMENT TABLE (CVSS v3.1 aligned):
  CRITICAL — Only for security-class issues; code quality findings should NEVER be CRITICAL.
  HIGH     — The issue makes the code demonstrably unmaintainable or breaks core logic.
             Example: a 200-line function with cyclomatic complexity > 30.
  MEDIUM   — Significant technical debt; likely to cause bugs during future changes.
             Example: cyclomatic complexity 15–30, deep nesting > 5 levels, poor naming.
  LOW      — Minor style/best-practice nudge; does not affect maintainability immediately.
             Example: a variable named `x`, a 40-line function.

DESCRIPTION QUALITY RULES:
  - MAX 2 sentences.
  - Sentence 1: State WHY this pattern is a problem.
  - Sentence 2: Give the specific refactoring action (use imperative: "Extract...", "Replace...").
  - DO NOT repeat the finding title.
  - DO NOT use vague advice like "fix this" or "improve readability".

RESPOND ONLY with a JSON array. No markdown fences, no extra keys.
Schema per finding:
{
  "id": <integer>,
  "type": <string>,
  "severity": "critical" | "high" | "medium" | "low",
  "line_start": <integer>,
  "line_end": <integer>,
  "title": <string, ≤ 80 chars>,
  "description": <string, max 2 sentences>,
  "category": <string>,
  "source_agent": "code_analysis"
}
"""

# Supported language identifiers
_SUPPORTED = {"python", "java"}

_ANALYZERS = {
    "python": PythonAnalyzer,
    "java": JavaAnalyzer,
}


def analyze(code: str, language: str) -> List[Finding]:
    """
    Statically analyze `code` for code smells, complexity, and coupling issues.

    Parameters
    ----------
    code     : Source code as a plain string.
    language : "python" or "java" (case-insensitive).

    Returns
    -------
    List[Finding] sorted by severity (most severe first), then by line number.
    An empty list means no issues were detected above threshold.

    Raises
    ------
    ValueError  — if `language` is not in the supported set.
    """
    lang = language.lower().strip()
    if lang not in _SUPPORTED:
        raise ValueError(
            f"Unsupported language '{language}'. "
            f"Supported: {', '.join(sorted(_SUPPORTED))}."
        )

    if not code or not code.strip():
        return [
            Finding(
                type="code_smell",
                severity=Severity.LOW,
                line_start=1,
                line_end=1,
                title="Empty submission",
                description="No code was provided for analysis.",
                category="empty_submission",
            )
        ]

    analyzer_cls = _ANALYZERS[lang]
    analyzer = analyzer_cls()
    findings = analyzer.analyze(code)

    # Sort: severity ascending (CRITICAL first in _order), then line number
    findings.sort(key=lambda f: (f.severity, f.line_start))
    return findings
