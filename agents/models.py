"""
models.py — Shared data types for all agents.

Finding is the canonical output object every agent returns. The Orchestrator
merges lists of Findings from multiple agents before persisting to the DB.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

# Module-level order map — kept OUTSIDE the Enum body intentionally.
# Inside an Enum, Python resolves attribute access via the member machinery,
# so `self._order` would try to index the enum's string value with a string
# key, raising TypeError. A plain module-level dict sidesteps this entirely.
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

# ---------------------------------------------------------------------------
# Shared severity scoring weights (CVSS v3.1-aligned deduction model)
# Used by pr_summary_agent for health-score calculation.
# critical ≈ CVSS 9.0+, high ≈ 7.0–8.9, medium ≈ 4.0–6.9, low < 4.0
# ---------------------------------------------------------------------------
SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 30,
    "high": 15,
    "medium": 5,
    "low": 1,
}

# ---------------------------------------------------------------------------
# Canonical OWASP category strings — used in prompts & fallback Finding objects
# ---------------------------------------------------------------------------
OWASP_CATEGORY_MAP: dict[str, str] = {
    "sql_injection":         "A03:2021-Injection",
    "xss":                   "A03:2021-Injection",
    "csrf":                  "A01:2021-Broken Access Control",
    "hardcoded_secret":      "A02:2021-Cryptographic Failures",
    "broken_auth":           "A07:2021-Identification and Authentication Failures",
    "broken_access_control": "A01:2021-Broken Access Control",
    "insecure_deserialization": "A08:2021-Software and Data Integrity Failures",
    "security_misconfiguration": "A05:2021-Security Misconfiguration",
    "vulnerable_components": "A06:2021-Vulnerable and Outdated Components",
}



class Severity(str, Enum):
    """
    Four-tier severity scale anchored to maintainability / security impact.

    CRITICAL  — immediate risk; blocks merge / must fix now
    HIGH      — significant technical debt or exploitable pattern
    MEDIUM    — degrades readability / long-term maintenance cost
    LOW       — style / best-practice nudge

    Comparison operators are defined so findings can be sorted:
        Severity.CRITICAL < Severity.HIGH  →  True  (most severe = smallest)
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    def __lt__(self, other: "Severity") -> bool:
        return _SEVERITY_ORDER[self.value] < _SEVERITY_ORDER[other.value]

    def __le__(self, other: "Severity") -> bool:
        return _SEVERITY_ORDER[self.value] <= _SEVERITY_ORDER[other.value]

    def __gt__(self, other: "Severity") -> bool:
        return _SEVERITY_ORDER[self.value] > _SEVERITY_ORDER[other.value]

    def __ge__(self, other: "Severity") -> bool:
        return _SEVERITY_ORDER[self.value] >= _SEVERITY_ORDER[other.value]


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    One detected issue from any analysis agent.

    Fields
    ------
    type         : broad category — "code_smell" | "complexity" | "coupling" |
                   "security" | "style"
    severity     : Severity enum value
    line_start   : 1-indexed first affected line
    line_end     : 1-indexed last affected line (== line_start for point issues)
    title        : short human label  (≤ 80 chars)
    description  : full explanation + actionable guidance
    source_agent : which agent produced this (default "code_analysis")
    category     : optional sub-category (e.g. "long_method", "sql_injection")
    extra        : catch-all dict for agent-specific metadata
                   (e.g. cyclomatic_complexity_score, owasp_category)
    """
    type: str
    severity: Severity
    line_start: int
    line_end: int
    title: str
    description: str
    source_agent: str = "code_analysis"
    category: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict (Severity → str)."""
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Reconstruct a Finding from a plain dict (e.g. loaded from DB)."""
        data = dict(data)
        data["severity"] = Severity(data["severity"])
        return cls(**data)

    def __repr__(self) -> str:
        return (
            f"Finding({self.severity.value.upper()} [{self.type}] "
            f"L{self.line_start}-{self.line_end}: {self.title!r})"
        )
