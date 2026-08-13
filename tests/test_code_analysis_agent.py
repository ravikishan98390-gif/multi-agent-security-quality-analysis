"""
test_code_analysis_agent.py — pytest test suite for the Code Analysis Agent.

Run:
    pip install javalang pytest
    pytest tests/test_code_analysis_agent.py -v

Structure
---------
- Fixtures load the four sample files from tests/fixtures/
- TestModels       — unit tests for Finding / Severity data model
- TestPythonAgent  — bad_python.py triggers ≥ 3 findings (≥1 HIGH)
                   — good_python.py has 0 HIGH/CRITICAL findings
- TestJavaAgent    — bad_java.java triggers ≥ 2 findings
                   — good_java.java has 0 HIGH/CRITICAL findings
- TestAPIContract  — validate the public analyze() interface behaviour
- TestSerialization — Finding.to_dict() / from_dict() round-trip
"""

from __future__ import annotations

import json
import pathlib
import pytest

from agents.code_analysis_agent import analyze
from agents.models import Finding, Severity

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _load(filename: str) -> str:
    return (_FIXTURES / filename).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _severities(findings: list[Finding]) -> list[str]:
    return [f.severity.value for f in findings]


def _has_category(findings: list[Finding], category: str) -> bool:
    return any(f.category == category for f in findings)


def _highest_severity(findings: list[Finding]) -> Severity | None:
    if not findings:
        return None
    return min(f.severity for f in findings)  # CRITICAL < HIGH < MEDIUM < LOW


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TestModels:
    def test_severity_ordering(self):
        assert Severity.CRITICAL < Severity.HIGH
        assert Severity.HIGH < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.LOW
        assert Severity.CRITICAL < Severity.LOW

    def test_severity_equality(self):
        assert Severity.HIGH == Severity.HIGH

    def test_finding_to_dict_has_string_severity(self):
        f = Finding(
            type="code_smell",
            severity=Severity.HIGH,
            line_start=10,
            line_end=20,
            title="Test finding",
            description="Test description",
        )
        d = f.to_dict()
        assert d["severity"] == "high"
        assert isinstance(d["severity"], str)

    def test_finding_round_trip(self):
        original = Finding(
            type="complexity",
            severity=Severity.MEDIUM,
            line_start=5,
            line_end=15,
            title="Round-trip test",
            description="Testing serialisation",
            category="high_complexity",
            extra={"cyclomatic_complexity": 12},
        )
        restored = Finding.from_dict(original.to_dict())
        assert restored.severity == original.severity
        assert restored.type == original.type
        assert restored.extra == original.extra

    def test_finding_repr(self):
        f = Finding(
            type="code_smell",
            severity=Severity.CRITICAL,
            line_start=1,
            line_end=1,
            title="Bad thing",
            description="Very bad.",
        )
        assert "CRITICAL" in repr(f)
        assert "Bad thing" in repr(f)


# ---------------------------------------------------------------------------
# Python Agent — bad file
# ---------------------------------------------------------------------------

class TestPythonAgentBadFile:
    @pytest.fixture(scope="class")
    @classmethod
    def findings(cls):
        code = _load("bad_python.py")
        return analyze(code, language="python")

    def test_returns_list(self, findings):
        assert isinstance(findings, list)

    def test_minimum_three_findings(self, findings):
        assert len(findings) >= 3, (
            f"Expected ≥3 findings, got {len(findings)}: "
            + str([f.title for f in findings])
        )

    def test_at_least_one_high_or_critical(self, findings):
        high_or_critical = [
            f for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        assert len(high_or_critical) >= 1, (
            "Expected at least one HIGH/CRITICAL finding in bad_python.py"
        )

    def test_long_method_detected(self, findings):
        assert _has_category(findings, "long_method"), (
            "long_method not detected — check _LongMethodVisitor"
        )

    def test_poor_naming_detected(self, findings):
        assert _has_category(findings, "poor_naming"), (
            "poor_naming not detected — check _PoorNamingVisitor"
        )

    def test_high_complexity_detected(self, findings):
        assert _has_category(findings, "high_complexity"), (
            "high_complexity not detected — check _ComplexityVisitor"
        )

    def test_deep_nesting_detected(self, findings):
        assert _has_category(findings, "deep_nesting"), (
            "deep_nesting not detected — check _NestingDepthVisitor"
        )

    def test_duplicate_code_detected(self, findings):
        assert _has_category(findings, "duplicate_code"), (
            "duplicate_code not detected — check _DuplicateBlockDetector"
        )

    def test_findings_sorted_by_severity(self, findings):
        """Most severe finding should be first."""
        for i in range(len(findings) - 1):
            assert findings[i].severity <= findings[i + 1].severity, (
                f"Findings not sorted: {findings[i].severity} > {findings[i+1].severity} "
                f"at indices {i}, {i+1}"
            )

    def test_all_findings_have_required_fields(self, findings):
        for f in findings:
            assert f.type, "Finding missing 'type'"
            assert f.title, "Finding missing 'title'"
            assert f.description, "Finding missing 'description'"
            assert f.source_agent == "code_analysis"
            assert isinstance(f.severity, Severity)
            assert f.line_start >= 1
            assert f.line_end >= f.line_start

    def test_findings_json_serialisable(self, findings):
        dicts = [f.to_dict() for f in findings]
        json_str = json.dumps(dicts)  # must not raise
        reloaded = json.loads(json_str)
        assert len(reloaded) == len(findings)


# ---------------------------------------------------------------------------
# Python Agent — good file
# ---------------------------------------------------------------------------

class TestPythonAgentGoodFile:
    @pytest.fixture(scope="class")
    @classmethod
    def findings(cls):
        code = _load("good_python.py")
        return analyze(code, language="python")

    def test_no_high_or_critical(self, findings):
        bad = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert not bad, (
            f"Expected no HIGH/CRITICAL in good_python.py, got: "
            + str([f.title for f in bad])
        )


# ---------------------------------------------------------------------------
# Java Agent — bad file
# ---------------------------------------------------------------------------

class TestJavaAgentBadFile:
    @pytest.fixture(scope="class")
    @classmethod
    def findings(cls):
        code = _load("bad_java.java")
        return analyze(code, language="java")

    def test_returns_list(self, findings):
        assert isinstance(findings, list)

    def test_minimum_two_findings(self, findings):
        # Filter out the javalang-not-installed warning
        real = [f for f in findings if f.category != "tooling_warning"]
        assert len(real) >= 2, (
            f"Expected ≥2 real findings, got {len(real)}: "
            + str([f.title for f in real])
        )

    def test_at_least_one_high_or_critical(self, findings):
        real = [f for f in findings if f.category != "tooling_warning"]
        high_or_critical = [
            f for f in real
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        assert len(high_or_critical) >= 1, (
            "Expected at least one HIGH/CRITICAL finding in bad_java.java"
        )

    def test_all_findings_have_required_fields(self, findings):
        for f in findings:
            assert f.type
            assert f.title
            assert f.description
            assert isinstance(f.severity, Severity)
            assert f.line_start >= 1
            assert f.line_end >= f.line_start


# ---------------------------------------------------------------------------
# Java Agent — good file
# ---------------------------------------------------------------------------

class TestJavaAgentGoodFile:
    @pytest.fixture(scope="class")
    @classmethod
    def findings(cls):
        code = _load("good_java.java")
        return analyze(code, language="java")

    def test_no_high_or_critical(self, findings):
        real = [f for f in findings if f.category != "tooling_warning"]
        bad = [f for f in real if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert not bad, (
            f"Expected no HIGH/CRITICAL in good_java.java, got: "
            + str([f.title for f in bad])
        )


# ---------------------------------------------------------------------------
# API Contract
# ---------------------------------------------------------------------------

class TestAPIContract:
    def test_unsupported_language_raises(self):
        with pytest.raises(ValueError, match="Unsupported language"):
            analyze("print('hi')", language="ruby")

    def test_language_case_insensitive(self):
        code = "def hello(): pass"
        findings_lower = analyze(code, "python")
        findings_upper = analyze(code, "PYTHON")
        assert len(findings_lower) == len(findings_upper)

    def test_empty_code_returns_finding(self):
        findings = analyze("", "python")
        assert len(findings) == 1
        assert findings[0].category == "empty_submission"

    def test_whitespace_only_returns_finding(self):
        findings = analyze("   \n\n\t  ", "python")
        assert len(findings) == 1
        assert findings[0].category == "empty_submission"

    def test_syntax_error_returns_parse_error_finding(self):
        bad_code = "def foo(:\n  pass"
        findings = analyze(bad_code, "python")
        assert len(findings) == 1
        assert findings[0].category == "parse_error"
        assert findings[0].severity == Severity.CRITICAL

    def test_clean_minimal_python_returns_empty(self):
        code = "def greet(name: str) -> str:\n    return f'Hello, {name}!'"
        findings = analyze(code, "python")
        bad = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        assert not bad

    def test_return_type_is_list(self):
        result = analyze("x = 1", "python")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Serialisation round-trip
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_all_bad_python_findings_round_trip(self):
        code = _load("bad_python.py")
        original = analyze(code, "python")
        dicts = [f.to_dict() for f in original]
        restored = [Finding.from_dict(d) for d in dicts]
        for orig, rest in zip(original, restored):
            assert orig.severity == rest.severity
            assert orig.type == rest.type
            assert orig.title == rest.title
            assert orig.line_start == rest.line_start
            assert orig.extra == rest.extra

    def test_dict_has_correct_keys(self):
        code = "def a():\n    pass"
        findings = analyze(code, "python")
        required_keys = {
            "type", "severity", "line_start", "line_end",
            "title", "description", "source_agent", "category", "extra"
        }
        for f in findings:
            d = f.to_dict()
            assert required_keys.issubset(d.keys()), (
                f"Missing keys: {required_keys - d.keys()}"
            )
