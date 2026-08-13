"""
java_analyzer.py — Static analysis of Java source code using `javalang`.

If javalang is not installed, falls back to a regex-based fallback that
catches the most common issues without a full parse (with a warning Finding).

Detectors (mirrors python_analyzer.py for consistency)
-------------------------------------------------------
1. Long methods        — MethodDeclaration spanning > 40 lines
2. Poor naming         — single-char or generic field/method/variable names
3. Cyclomatic complexity — branching node count per method
4. Nesting depth       — recursive block depth per method
5. Duplicate blocks    — same sliding-window hash from base class
6. Tight coupling      — ClassCreator fan-out per method body
"""

from __future__ import annotations

import re
from typing import Any, List, Optional

from agents.analyzers.base_analyzer import BaseAnalyzer
from agents.models import Finding, Severity

# Try to import javalang; gracefully degrade if not installed
try:
    import javalang  # type: ignore[import]
    _JAVALANG_AVAILABLE = True
except ImportError:
    _JAVALANG_AVAILABLE = False


# ---------------------------------------------------------------------------
# Javalang-based analysis
# ---------------------------------------------------------------------------

class _JavalangAnalyzer:
    """Full AST-based analysis via the javalang library."""

    # Nodes that increment cyclomatic complexity
    _BRANCH_TYPES = (
        "IfStatement", "ForStatement", "EnhancedForStatement",
        "WhileStatement", "DoStatement", "SwitchStatement",
        "CatchClause", "ConditionalExpression", "AssertStatement",
    )

    def __init__(self, base: BaseAnalyzer) -> None:
        self._b = base

    def analyze(self, code: str) -> List[Finding]:
        try:
            tree = javalang.parse.parse(code)
        except javalang.parser.JavaSyntaxError as exc:
            raise SyntaxError(f"Java syntax error: {exc}") from exc

        lines = code.splitlines()
        findings: List[Finding] = []

        # Walk all method declarations
        for _, method in tree.filter(javalang.tree.MethodDeclaration):
            start_line = method.position.line if method.position else 1
            end_line = self._method_end_line(method, lines, start_line)
            line_count = end_line - start_line + 1

            # 1. Long method
            sev = self._b.length_severity(line_count)
            if sev is not None:
                findings.append(
                    Finding(
                        type="code_smell",
                        severity=sev,
                        line_start=start_line,
                        line_end=end_line,
                        title=f"Long method: '{method.name}' ({line_count} lines)",
                        description=(
                            f"'{method.name}' spans {line_count} lines, exceeding "
                            "the recommended 40-line limit. Extract cohesive "
                            "sub-tasks into smaller focused methods."
                        ),
                        category="long_method",
                        extra={"line_count": line_count, "method_name": method.name},
                    )
                )

            # 2. Poor naming — method name
            if self._b.is_poor_name(method.name):
                findings.append(
                    Finding(
                        type="code_smell",
                        severity=self._b.naming_severity(method.name),
                        line_start=start_line,
                        line_end=start_line,
                        title=f"Poor method name: '{method.name}'",
                        description=(
                            f"The method name '{method.name}' is ambiguous. "
                            "Use descriptive, verb-phrase names like "
                            "'calculateInvoiceTotal' or 'sendWelcomeEmail'."
                        ),
                        category="poor_naming",
                        extra={"identifier": method.name, "context": "method"},
                    )
                )

            # 2b. Poor naming — parameters
            if method.parameters:
                for param in method.parameters:
                    if self._b.is_poor_name(param.name):
                        findings.append(
                            Finding(
                                type="code_smell",
                                severity=self._b.naming_severity(param.name),
                                line_start=start_line,
                                line_end=start_line,
                                title=f"Poor parameter name: '{param.name}' in '{method.name}'",
                                description=(
                                    f"Parameter '{param.name}' in method "
                                    f"'{method.name}' is not descriptive. "
                                    "Use names that convey the parameter's role."
                                ),
                                category="poor_naming",
                                extra={"identifier": param.name, "context": "parameter"},
                            )
                        )

            # 3. Cyclomatic complexity
            cc = self._cyclomatic_complexity(method)
            sev_cc = self._b.complexity_severity(cc)
            if sev_cc is not None:
                findings.append(
                    Finding(
                        type="complexity",
                        severity=sev_cc,
                        line_start=start_line,
                        line_end=end_line,
                        title=f"High cyclomatic complexity in '{method.name}' (CC={cc})",
                        description=(
                            f"'{method.name}' has a cyclomatic complexity of {cc}. "
                            "Refactor by extracting conditionals into helper methods "
                            "or applying the Strategy pattern."
                        ),
                        category="high_complexity",
                        extra={"cyclomatic_complexity": cc, "method_name": method.name},
                    )
                )

            # 4. Nesting depth
            max_depth = self._max_nesting(method)
            sev_nd = self._b.nesting_severity(max_depth)
            if sev_nd is not None:
                findings.append(
                    Finding(
                        type="complexity",
                        severity=sev_nd,
                        line_start=start_line,
                        line_end=end_line,
                        title=f"Deep nesting in '{method.name}' (depth {max_depth})",
                        description=(
                            f"'{method.name}' has a nesting depth of {max_depth}. "
                            "Apply guard clauses, extract nested blocks, or use "
                            "polymorphism to flatten the structure."
                        ),
                        category="deep_nesting",
                        extra={"max_depth": max_depth, "method_name": method.name},
                    )
                )

            # 6. Tight coupling — count ClassCreator nodes per method
            class_creators: set[str] = set()
            for _, node in method.filter(javalang.tree.ClassCreator):
                class_creators.add(node.type.name)
            if len(class_creators) > 5:
                findings.append(
                    Finding(
                        type="coupling",
                        severity=Severity.MEDIUM,
                        line_start=start_line,
                        line_end=end_line,
                        title=(
                            f"Tight coupling in '{method.name}' "
                            f"({len(class_creators)} direct instantiations)"
                        ),
                        description=(
                            f"'{method.name}' directly instantiates "
                            f"{len(class_creators)} different classes "
                            f"({', '.join(sorted(class_creators))}). "
                            "This violates the Dependency Inversion Principle. "
                            "Use dependency injection or factories instead."
                        ),
                        category="high_instantiation_fanout",
                        extra={
                            "class_count": len(class_creators),
                            "classes": sorted(class_creators),
                        },
                    )
                )

        # 2c. Poor naming — fields
        for _, field_decl in tree.filter(javalang.tree.FieldDeclaration):
            for declarator in field_decl.declarators:
                if self._b.is_poor_name(declarator.name):
                    pos = field_decl.position
                    lineno = pos.line if pos else 1
                    findings.append(
                        Finding(
                            type="code_smell",
                            severity=self._b.naming_severity(declarator.name),
                            line_start=lineno,
                            line_end=lineno,
                            title=f"Poor field name: '{declarator.name}'",
                            description=(
                                f"Field '{declarator.name}' is not descriptive. "
                                "Field names should convey their role in the class."
                            ),
                            category="poor_naming",
                            extra={"identifier": declarator.name, "context": "field"},
                        )
                    )

        # 5. Duplicate blocks (line-based, same as Python)
        findings.extend(
            _DupFindingAdapter.adapt(
                self._b.find_duplicate_blocks(code.splitlines())
            )
        )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _method_end_line(
        method: Any, lines: List[str], start: int
    ) -> int:
        """
        Approximate end line of a method by scanning for the matching
        closing brace from the start position.
        """
        depth = 0
        for i in range(start - 1, len(lines)):
            depth += lines[i].count("{") - lines[i].count("}")
            if i >= start and depth <= 0:
                return i + 1
        return len(lines)

    def _cyclomatic_complexity(self, method: Any) -> int:
        """Count branching nodes inside a MethodDeclaration."""
        score = 1
        for path, node in method:
            node_type = type(node).__name__
            if node_type in self._BRANCH_TYPES:
                score += 1
            # ternary / conditional chains
            if node_type == "SwitchStatement" and hasattr(node, "cases"):
                score += max(0, len(node.cases) - 1)
        return score

    @staticmethod
    def _max_nesting(method: Any) -> int:
        """Approximate max nesting depth via brace counting on the path."""
        _BLOCK_TYPES = {
            "IfStatement", "ForStatement", "EnhancedForStatement",
            "WhileStatement", "DoStatement", "TryStatement", "CatchClause",
        }
        max_depth = 0
        current_depth = 0
        for path, node in method:
            node_type = type(node).__name__
            if node_type in _BLOCK_TYPES:
                # depth = number of enclosing block nodes in the path
                depth = sum(1 for p in path if type(p).__name__ in _BLOCK_TYPES)
                max_depth = max(max_depth, depth + 1)
        return max_depth


class _DupFindingAdapter:
    @staticmethod
    def adapt(pairs: list[tuple[int, int, int, int]]) -> List[Finding]:
        findings = []
        for (sa, ea, sb, eb) in pairs:
            findings.append(
                Finding(
                    type="code_smell",
                    severity=Severity.HIGH,
                    line_start=sa,
                    line_end=ea,
                    title=f"Duplicate code block (lines {sa}–{ea} and {sb}–{eb})",
                    description=(
                        f"Lines {sa}–{ea} appear to be a near-copy of lines "
                        f"{sb}–{eb}. Extract the shared logic into a reusable method."
                    ),
                    category="duplicate_code",
                    extra={"duplicate_of_lines": (sb, eb)},
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Regex-based fallback (when javalang is not installed)
# ---------------------------------------------------------------------------

class _RegexJavaAnalyzer:
    """
    Lightweight regex-based Java analyzer used when javalang is unavailable.
    Less precise but still catches the most obvious issues.
    """

    _METHOD_RE = re.compile(
        r"(?:public|private|protected|static|final|\s)+"
        r"[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+\s*)?\{",
        re.MULTILINE,
    )
    _SINGLE_CHAR_VAR_RE = re.compile(r"\b(int|String|long|double|float|boolean)\s+([a-z])\b")
    _GENERIC_VAR_RE = re.compile(
        r"\b(?:int|String|long|double|float|boolean|Object)\s+"
        r"(data|temp|tmp|result|res|obj|item|value|val|info)\b"
    )

    def __init__(self, base: BaseAnalyzer) -> None:
        self._b = base

    def analyze(self, code: str) -> List[Finding]:
        findings: List[Finding] = [
            Finding(
                type="code_smell",
                severity=Severity.LOW,
                line_start=1,
                line_end=1,
                title="javalang not installed — reduced Java analysis accuracy",
                description=(
                    "The `javalang` package is not installed. "
                    "Java analysis is running in regex-fallback mode; "
                    "results may miss some issues. Run `pip install javalang` "
                    "for full AST-based analysis."
                ),
                category="tooling_warning",
            )
        ]

        lines = code.splitlines()

        # Long methods by brace matching
        in_method: Optional[tuple[str, int]] = None
        depth = 0
        for i, line in enumerate(lines, start=1):
            m = self._METHOD_RE.search(line)
            if m and in_method is None:
                in_method = (m.group(1), i)
            depth += line.count("{") - line.count("}")
            if in_method and depth <= 0:
                name, start = in_method
                count = i - start + 1
                sev = self._b.length_severity(count)
                if sev:
                    findings.append(
                        Finding(
                            type="code_smell",
                            severity=sev,
                            line_start=start,
                            line_end=i,
                            title=f"Long method: '{name}' ({count} lines)",
                            description=(
                                f"'{name}' spans {count} lines. "
                                "Consider extracting sub-tasks into smaller methods."
                            ),
                            category="long_method",
                            extra={"line_count": count, "method_name": name},
                        )
                    )
                in_method = None

        # Poor naming (regex)
        for i, line in enumerate(lines, start=1):
            for m in self._SINGLE_CHAR_VAR_RE.finditer(line):
                char = m.group(2)
                if char not in "ijkn":
                    findings.append(
                        Finding(
                            type="code_smell",
                            severity=Severity.HIGH,
                            line_start=i,
                            line_end=i,
                            title=f"Poor variable name: '{char}'",
                            description=(
                                f"Single-character variable '{char}' at line {i}. "
                                "Use descriptive names."
                            ),
                            category="poor_naming",
                            extra={"identifier": char},
                        )
                    )
            for m in self._GENERIC_VAR_RE.finditer(line):
                name = m.group(1)
                findings.append(
                    Finding(
                        type="code_smell",
                        severity=Severity.MEDIUM,
                        line_start=i,
                        line_end=i,
                        title=f"Generic variable name: '{name}'",
                        description=(
                            f"'{name}' at line {i} is not descriptive. "
                            "Choose a name that expresses intent."
                        ),
                        category="poor_naming",
                        extra={"identifier": name},
                    )
                )

        # Duplicate blocks
        findings.extend(_DupFindingAdapter.adapt(self._b.find_duplicate_blocks(lines)))

        return findings


# ---------------------------------------------------------------------------
# JavaAnalyzer — public entry point
# ---------------------------------------------------------------------------

class JavaAnalyzer(BaseAnalyzer):
    """
    Full static analysis pipeline for Java source code.

    Usage::

        analyzer = JavaAnalyzer()
        findings = analyzer.analyze(java_source_code)
    """

    def _run(self, code: str) -> List[Finding]:
        if _JAVALANG_AVAILABLE:
            return _JavalangAnalyzer(self).analyze(code)
        else:
            return _RegexJavaAnalyzer(self).analyze(code)
