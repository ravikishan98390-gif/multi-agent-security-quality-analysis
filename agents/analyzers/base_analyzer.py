"""
base_analyzer.py — Abstract base class every language analyzer inherits from.

Design rules:
  1. Subclasses implement `_run(code)` and return List[Finding].
  2. `analyze(code)` is the public entry point; it wraps `_run` with error
     handling so a bad parse never crashes the Orchestrator.
  3. Shared helpers (line splitting, dedup, hash-based duplicate detection)
     live here so they're not copy-pasted across language analyzers.
"""

from __future__ import annotations

import hashlib
import re
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import List

from agents.models import Finding, Severity


# ---------------------------------------------------------------------------
# Generic name patterns shared across languages
# ---------------------------------------------------------------------------

# Single character variable names — always suspicious except loop counters
_SINGLE_CHAR_RE = re.compile(r"^[a-zA-Z]$")

# Common "lazy" generic names developers use as placeholders
_GENERIC_NAMES: frozenset[str] = frozenset(
    {
        "data", "temp", "tmp", "result", "res", "obj", "item",
        "value", "val", "info", "stuff", "thing", "foo", "bar",
        "baz", "test", "flag", "helper", "util", "manager",
        "handler", "processor", "service", "controller",
    }
)

# Allowed single-char names (conventional loop / math usage)
_ALLOWED_SINGLE_CHARS: frozenset[str] = frozenset("ijknxyzabcedf")


# ---------------------------------------------------------------------------
# BaseAnalyzer
# ---------------------------------------------------------------------------

class BaseAnalyzer(ABC):
    """
    Abstract base for language-specific analyzers.

    Subclass contract
    -----------------
    Implement `_run(code: str) -> List[Finding]`.  The method may raise
    any exception; `analyze()` will catch it and return a single CRITICAL
    Finding describing the parse failure so the pipeline can keep running.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, code: str) -> List[Finding]:
        """
        Parse `code` and return all detected findings, deduplicated and
        sorted by severity (most severe first).
        """
        try:
            findings = self._run(code)
        except Exception as exc:  # noqa: BLE001
            return [
                Finding(
                    type="parse_error",
                    severity=Severity.CRITICAL,
                    line_start=1,
                    line_end=1,
                    title="Code could not be parsed",
                    description=(
                        f"The analyzer raised an exception while parsing the "
                        f"submitted code: {type(exc).__name__}: {exc}. "
                        "Fix any syntax errors and resubmit."
                    ),
                    category="parse_error",
                )
            ]

        findings = self._deduplicate(findings)
        findings.sort(key=lambda f: (f.severity, f.line_start))
        return findings

    # ------------------------------------------------------------------
    # Abstract
    # ------------------------------------------------------------------

    @abstractmethod
    def _run(self, code: str) -> List[Finding]:
        """Language-specific implementation; may raise on bad input."""

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    # --- naming ---

    @staticmethod
    def is_poor_name(name: str) -> bool:
        """
        Return True if `name` looks like a lazy placeholder.

        Rules:
        - Single character, *unless* it's a conventional loop/math var.
        - Appears in the generic-name allowlist (case-insensitive).
        """
        if _SINGLE_CHAR_RE.match(name) and name not in _ALLOWED_SINGLE_CHARS:
            return True
        if name.lower() in _GENERIC_NAMES:
            return True
        return False

    @staticmethod
    def naming_severity(name: str) -> Severity:
        """Single-char names are more severe than generic ones."""
        if _SINGLE_CHAR_RE.match(name):
            return Severity.HIGH
        return Severity.MEDIUM

    # --- complexity ---

    @staticmethod
    def complexity_severity(score: int) -> Severity | None:
        """
        Map cyclomatic complexity score to a Severity level.
        Returns None when the score is below the reporting threshold.

        Thresholds (McCabe, adapted for maintainability focus):
          < 5  → no finding
          5–9  → low
          10–14 → medium
          ≥ 15  → high
        """
        if score >= 15:
            return Severity.HIGH
        if score >= 10:
            return Severity.MEDIUM
        if score >= 5:
            return Severity.LOW
        return None

    # --- method length ---

    @staticmethod
    def length_severity(line_count: int) -> Severity | None:
        """
        Map a method's line count to a Severity level.
        Returns None when below threshold.

          < 40  → no finding
          40–79 → medium
          80–119 → high
          ≥ 120  → critical
        """
        if line_count >= 120:
            return Severity.CRITICAL
        if line_count >= 80:
            return Severity.HIGH
        if line_count >= 40:
            return Severity.MEDIUM
        return None

    # --- nesting ---

    @staticmethod
    def nesting_severity(depth: int) -> Severity | None:
        """
        Map maximum nesting depth to a Severity level.

          < 4 → no finding
          4–5 → medium
          ≥ 6 → high
        """
        if depth >= 6:
            return Severity.HIGH
        if depth >= 4:
            return Severity.MEDIUM
        return None

    # --- duplicate blocks ---

    @staticmethod
    def find_duplicate_blocks(
        lines: List[str],
        block_size: int = 6,
        similarity_threshold: float = 0.85,
    ) -> List[tuple[int, int, int, int]]:
        """
        Sliding-window hash-based duplicate block detection.

        Returns a list of (start_a, end_a, start_b, end_b) tuples (1-indexed)
        for pairs of blocks that are at least `similarity_threshold` similar.

        Algorithm
        ---------
        1. Normalise each line (strip whitespace + comments) to reduce false
           negatives from indentation differences.
        2. Slide a window of `block_size` lines across the file.
        3. Hash each window.  Identical hashes → exact duplicate.
        4. For near-duplicate pairs, compute token-level Jaccard similarity.
        """
        normalised = [
            re.sub(r"\s+", " ", l).strip().split("//")[0].split("#")[0].strip()
            for l in lines
        ]

        # Build hash → list of start indices
        hashes: dict[str, list[int]] = defaultdict(list)
        for i in range(len(normalised) - block_size + 1):
            window = normalised[i : i + block_size]
            if all(not ln for ln in window):  # skip blank blocks
                continue
            key = hashlib.md5("\n".join(window).encode()).hexdigest()
            hashes[key].append(i)

        duplicates: list[tuple[int, int, int, int]] = []
        seen: set[tuple[int, int]] = set()

        for starts in hashes.values():
            if len(starts) < 2:
                continue
            for idx, a in enumerate(starts):
                for b in starts[idx + 1 :]:
                    pair = (a, b)
                    if pair in seen:
                        continue
                    seen.add(pair)
                    # Jaccard on token sets
                    tokens_a = set(" ".join(normalised[a : a + block_size]).split())
                    tokens_b = set(" ".join(normalised[b : b + block_size]).split())
                    if not tokens_a and not tokens_b:
                        continue
                    sim = len(tokens_a & tokens_b) / len(tokens_a | tokens_b)
                    if sim >= similarity_threshold:
                        duplicates.append(
                            (a + 1, a + block_size, b + 1, b + block_size)
                        )

        return _merge_duplicate_pairs(duplicates, block_size)

    # --- deduplication ---

    @staticmethod
    def _deduplicate(findings: List[Finding]) -> List[Finding]:
        """
        Remove exact-duplicate findings (same type + category + line_start).
        Keeps the one with the higher severity.
        """
        seen: dict[tuple, Finding] = {}
        for f in findings:
            key = (f.type, f.category, f.line_start)
            if key not in seen or f.severity < seen[key].severity:
                seen[key] = f
        return list(seen.values())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _merge_duplicate_pairs(
    pairs: list[tuple[int, int, int, int]],
    block_size: int,
) -> list[tuple[int, int, int, int]]:
    """
    Collapse overlapping sliding-window hits into one canonical pair per
    logical duplicate region.

    Pairs are grouped when both their A-start and B-start are within
    `block_size` lines of an existing group's representative.  The merged
    result uses the minimum start and maximum end across the group, giving
    the true extent of the duplicated block.
    """
    if not pairs:
        return []

    # Sort by (a_start, b_start) for stable, deterministic output
    pairs = sorted(pairs)

    merged: list[tuple[int, int, int, int]] = []
    cur_sa, cur_ea, cur_sb, cur_eb = pairs[0]

    for sa, ea, sb, eb in pairs[1:]:
        # Same logical region if both A and B start overlap within block_size
        if sa - cur_sa <= block_size and sb - cur_sb <= block_size:
            # Expand the current group to cover the full extent
            cur_sa = min(cur_sa, sa)
            cur_ea = max(cur_ea, ea)
            cur_sb = min(cur_sb, sb)
            cur_eb = max(cur_eb, eb)
        else:
            merged.append((cur_sa, cur_ea, cur_sb, cur_eb))
            cur_sa, cur_ea, cur_sb, cur_eb = sa, ea, sb, eb

    merged.append((cur_sa, cur_ea, cur_sb, cur_eb))
    return merged

