"""
python_analyzer.py — Static analysis of Python source code.

Uses the stdlib `ast` module exclusively; no third-party parser needed.
All six detectors are implemented as separate AST visitor passes so each
can be enabled/disabled independently and tested in isolation.

Detectors
---------
1. LongMethodVisitor      — functions/methods exceeding line thresholds
2. PoorNamingVisitor      — single-char and generic variable/function names
3. ComplexityVisitor      — McCabe cyclomatic complexity per function
4. NestingDepthVisitor    — maximum nesting depth per function
5. DuplicateBlockDetector — sliding-window hash on raw source lines
6. TightCouplingVisitor   — deep attribute chains (a.b.c.d) and high import fan-out
"""

from __future__ import annotations

import ast
import re
from typing import List

from agents.analyzers.base_analyzer import BaseAnalyzer
from agents.models import Finding, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _func_line_count(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Return the number of source lines spanned by a function definition."""
    return getattr(node, "end_lineno", node.lineno) - node.lineno + 1


# ---------------------------------------------------------------------------
# Visitor 1 — Long methods
# ---------------------------------------------------------------------------

class _LongMethodVisitor(ast.NodeVisitor):
    def __init__(self, analyzer: BaseAnalyzer) -> None:
        self._a = analyzer
        self.findings: List[Finding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def _check(self, node: ast.FunctionDef) -> None:
        count = _func_line_count(node)
        sev = self._a.length_severity(count)
        if sev is None:
            return
        end = getattr(node, "end_lineno", node.lineno)
        self.findings.append(
            Finding(
                type="code_smell",
                severity=sev,
                line_start=node.lineno,
                line_end=end,
                title=f"Long method: '{node.name}' ({count} lines)",
                description=(
                    f"'{node.name}' spans {count} lines, exceeding the "
                    f"recommended 40-line limit. Long methods are hard to "
                    "understand, test, and maintain. Consider extracting "
                    "cohesive sub-tasks into smaller, focused functions."
                ),
                category="long_method",
                extra={"line_count": count, "function_name": node.name},
            )
        )


# ---------------------------------------------------------------------------
# Visitor 2 — Poor naming
# ---------------------------------------------------------------------------

class _PoorNamingVisitor(ast.NodeVisitor):
    def __init__(self, analyzer: BaseAnalyzer) -> None:
        self._a = analyzer
        self.findings: List[Finding] = []
        self._reported: set[tuple[str, int]] = set()

    def _report(self, name: str, lineno: int, context: str) -> None:
        key = (name, lineno)
        if key in self._reported:
            return
        self._reported.add(key)
        sev = self._a.naming_severity(name)
        self.findings.append(
            Finding(
                type="code_smell",
                severity=sev,
                line_start=lineno,
                line_end=lineno,
                title=f"Poor identifier name: '{name}' in {context}",
                description=(
                    f"The identifier '{name}' at line {lineno} is ambiguous. "
                    "Descriptive names improve readability and reduce the "
                    "cognitive load on future readers. Rename it to something "
                    "that expresses intent (e.g., 'user_count', 'invoice_id')."
                ),
                category="poor_naming",
                extra={"identifier": name, "context": context},
            )
        )

    # Function / method names
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self._a.is_poor_name(node.name):
            self._report(node.name, node.lineno, "function definition")
        # Check argument names
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            if self._a.is_poor_name(arg.arg):
                self._report(arg.arg, arg.col_offset or node.lineno, "function argument")
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    # Class names
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if self._a.is_poor_name(node.name):
            self._report(node.name, node.lineno, "class definition")
        self.generic_visit(node)

    # Variable assignments: x = ... or x, y = ...
    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._scan_target(target)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._scan_target(node.target)
        self.generic_visit(node)

    def _scan_target(self, target: ast.expr) -> None:
        if isinstance(target, ast.Name) and self._a.is_poor_name(target.id):
            self._report(target.id, target.lineno, "variable assignment")
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:  # type: ignore[attr-defined]
                self._scan_target(elt)

    # For-loop variables
    def visit_For(self, node: ast.For) -> None:
        self._scan_target(node.target)
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Visitor 3 — Cyclomatic complexity (McCabe)
# ---------------------------------------------------------------------------

# Nodes that each add 1 to the complexity score
_BRANCH_TYPES = (
    ast.If, ast.For, ast.AsyncFor, ast.While,
    ast.ExceptHandler, ast.With, ast.AsyncWith,
    ast.Assert, ast.comprehension,
)

# Boolean operators also count (and / or)
_BOOL_OPS_COUNT = True


class _ComplexityVisitor(ast.NodeVisitor):
    def __init__(self, analyzer: BaseAnalyzer) -> None:
        self._a = analyzer
        self.findings: List[Finding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        score = self._score(node)
        sev = self._a.complexity_severity(score)
        if sev is not None:
            end = getattr(node, "end_lineno", node.lineno)
            self.findings.append(
                Finding(
                    type="complexity",
                    severity=sev,
                    line_start=node.lineno,
                    line_end=end,
                    title=f"High cyclomatic complexity in '{node.name}' (CC={score})",
                    description=(
                        f"'{node.name}' has a cyclomatic complexity of {score}. "
                        "A score above 10 indicates the function is difficult to test "
                        "exhaustively and prone to subtle bugs. Refactor by extracting "
                        "conditional logic into smaller, single-responsibility helpers "
                        "or using polymorphism to eliminate branching."
                    ),
                    category="high_complexity",
                    extra={"cyclomatic_complexity": score, "function_name": node.name},
                )
            )
        # Don't recurse — nested functions are scored independently
        # by the top-level walk; avoid double-counting.
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    @staticmethod
    def _score(func_node: ast.FunctionDef) -> int:
        """McCabe CC = 1 + number of branching nodes inside the function."""
        score = 1
        for node in ast.walk(func_node):
            if isinstance(node, _BRANCH_TYPES):
                score += 1
            # Each 'and' / 'or' operand pair adds one branch path
            if _BOOL_OPS_COUNT and isinstance(node, ast.BoolOp):
                score += len(node.values) - 1
        return score


# ---------------------------------------------------------------------------
# Visitor 4 — Nesting depth
# ---------------------------------------------------------------------------

_NESTING_NODES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With,
                  ast.AsyncWith, ast.Try, ast.ExceptHandler)


class _NestingDepthVisitor(ast.NodeVisitor):
    def __init__(self, analyzer: BaseAnalyzer) -> None:
        self._a = analyzer
        self.findings: List[Finding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        max_depth = [0]
        self._walk(node.body, depth=0, max_depth=max_depth)
        sev = self._a.nesting_severity(max_depth[0])
        if sev is not None:
            end = getattr(node, "end_lineno", node.lineno)
            self.findings.append(
                Finding(
                    type="complexity",
                    severity=sev,
                    line_start=node.lineno,
                    line_end=end,
                    title=(
                        f"Deep nesting in '{node.name}' "
                        f"(max depth {max_depth[0]})"
                    ),
                    description=(
                        f"'{node.name}' has a maximum nesting depth of "
                        f"{max_depth[0]}. Deeply nested code is hard to follow. "
                        "Apply early returns (guard clauses), extract nested blocks "
                        "into helper functions, or flatten conditionals."
                    ),
                    category="deep_nesting",
                    extra={"max_depth": max_depth[0], "function_name": node.name},
                )
            )
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def _walk(self, stmts: list, depth: int, max_depth: list[int]) -> None:
        for stmt in stmts:
            if isinstance(stmt, _NESTING_NODES):
                current = depth + 1
                max_depth[0] = max(max_depth[0], current)
                # Recurse into child bodies
                for child_attr in ("body", "orelse", "finalbody", "handlers"):
                    children = getattr(stmt, child_attr, [])
                    if isinstance(children, list):
                        self._walk(children, current, max_depth)


# ---------------------------------------------------------------------------
# Detector 5 — Duplicate code blocks (line-based, no AST needed)
# ---------------------------------------------------------------------------

class _DuplicateBlockDetector:
    def __init__(self, analyzer: BaseAnalyzer) -> None:
        self._a = analyzer

    def detect(self, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        pairs = self._a.find_duplicate_blocks(lines, block_size=6)
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
                        f"{sb}–{eb}. Duplicate code increases maintenance cost — "
                        "a bug fix in one copy must be replicated in all others. "
                        "Extract the repeated logic into a shared function or class."
                    ),
                    category="duplicate_code",
                    extra={"duplicate_of_lines": (sb, eb)},
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Visitor 6 — Tight coupling
# ---------------------------------------------------------------------------

class _TightCouplingVisitor(ast.NodeVisitor):
    """
    Two heuristics:
    a) Deep attribute chains: a.b.c.d (depth ≥ 3) — accessing internals of internals
       signals Law of Demeter violation.
    b) High import fan-out at module level: > 10 distinct top-level imports
       (excluding __future__, typing, standard lib sentinels).
    """

    _STDLIB_SENTINELS = frozenset({
        "os", "sys", "re", "math", "json", "io", "abc", "typing",
        "collections", "itertools", "functools", "pathlib", "datetime",
        "logging", "unittest", "dataclasses", "enum", "copy", "time",
        "__future__",
    })

    def __init__(self, analyzer: BaseAnalyzer) -> None:
        self._a = analyzer
        self.findings: List[Finding] = []
        self._imports: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = alias.name.split(".")[0]
            if top not in self._STDLIB_SENTINELS:
                self._imports.add(top)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            top = node.module.split(".")[0]
            if top not in self._STDLIB_SENTINELS:
                self._imports.add(top)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        depth = self._chain_depth(node)
        if depth >= 4:
            self.findings.append(
                Finding(
                    type="coupling",
                    severity=Severity.MEDIUM if depth < 6 else Severity.HIGH,
                    line_start=node.lineno,
                    line_end=node.lineno,
                    title=f"Deep attribute chain (depth {depth}) — Law of Demeter violation",
                    description=(
                        f"An attribute access chain of depth {depth} was found at "
                        f"line {node.lineno}. Accessing nested internals like "
                        "'a.b.c.d' tightly couples this code to the internal "
                        "structure of its dependencies. Introduce intermediate "
                        "variables or delegate the access into the relevant class."
                    ),
                    category="deep_attribute_chain",
                    extra={"chain_depth": depth},
                )
            )
        self.generic_visit(node)

    def finalize(self, tree: ast.AST) -> None:
        """Call after visiting the full tree to emit import-fan-out findings."""
        fan_out = len(self._imports)
        if fan_out > 10:
            self.findings.append(
                Finding(
                    type="coupling",
                    severity=Severity.MEDIUM,
                    line_start=1,
                    line_end=1,
                    title=f"High import fan-out ({fan_out} external dependencies)",
                    description=(
                        f"This module imports {fan_out} distinct external packages. "
                        "A high fan-out means the module is coupled to many external "
                        "contracts, making it brittle to upstream changes. Consider "
                        "grouping related imports behind a facade or splitting the "
                        "module into smaller, focused units."
                    ),
                    category="high_import_fanout",
                    extra={"import_count": fan_out, "imports": sorted(self._imports)},
                )
            )

    @staticmethod
    def _chain_depth(node: ast.expr) -> int:
        depth = 0
        cur: ast.expr = node
        while isinstance(cur, ast.Attribute):
            depth += 1
            cur = cur.value  # type: ignore[assignment]
        return depth


# ---------------------------------------------------------------------------
# PythonAnalyzer — orchestrates all visitors
# ---------------------------------------------------------------------------

class PythonAnalyzer(BaseAnalyzer):
    """
    Full static analysis pipeline for Python source code.

    Usage::

        analyzer = PythonAnalyzer()
        findings = analyzer.analyze(source_code)
    """

    def _run(self, code: str) -> List[Finding]:
        tree = ast.parse(code)  # raises SyntaxError on bad input → caught by base
        lines = code.splitlines()
        findings: List[Finding] = []

        # 1. Long methods
        lmv = _LongMethodVisitor(self)
        lmv.visit(tree)
        findings.extend(lmv.findings)

        # 2. Poor naming
        pnv = _PoorNamingVisitor(self)
        pnv.visit(tree)
        findings.extend(pnv.findings)

        # 3. Cyclomatic complexity
        ccv = _ComplexityVisitor(self)
        ccv.visit(tree)
        findings.extend(ccv.findings)

        # 4. Nesting depth
        ndv = _NestingDepthVisitor(self)
        ndv.visit(tree)
        findings.extend(ndv.findings)

        # 5. Duplicate blocks
        dbd = _DuplicateBlockDetector(self)
        findings.extend(dbd.detect(lines))

        # 6. Tight coupling
        tcv = _TightCouplingVisitor(self)
        tcv.visit(tree)
        tcv.finalize(tree)
        findings.extend(tcv.findings)

        return findings
