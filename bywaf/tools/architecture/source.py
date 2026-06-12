"""Source-code metric helpers for architecture reports.

Used by:
- maintainers measuring coupling, complexity, documentation pressure, and
  release-readiness signals.
- CI/manual validation runs that track architecture drift.
"""

from __future__ import annotations

import ast
import io
import tokenize
from pathlib import Path

from .models import ModuleStaticStats


SECURITY_SURFACE_TOKENS = (
    "secret",
    "password",
    "token",
    "credential",
    "capability",
    "subprocess",
    "multiprocessing",
    "socket",
    "pickle",
    "eval(",
    "exec(",
    "chmod",
    "artifact",
)
"""Token hints used by `security_surface_hits()`.

These are not vulnerability findings. They are cheap review-priority signals
for modules that touch secrets, subprocesses, sockets, artifacts, or capability
checks.
"""


def module_name(root: Path, path: Path, package: str) -> str:
    """Return the dotted module name for a Python file below root.

    Called by: `collect_architecture_metrics()`.
    """

    relative = path.relative_to(root).with_suffix("")
    parts = (package, *relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def source_loc(path: Path) -> int:
    """Count non-empty, non-comment source lines for a rough size signal.

    Called by: `collect_architecture_metrics()`.
    """

    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            count += 1
    return count


def module_static_stats(tree: ast.AST, source: str) -> ModuleStaticStats:
    """Return complexity, documentation-pressure, and security-surface metrics.

    Called by: `collect_architecture_metrics()` for every inspected module.
    """

    functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)]
    function_complexities = [complexity_score(function) for function in functions]
    complexity = complexity_score(tree)
    max_function_complexity = max(function_complexities, default=0)
    # Comment/docstring counts are measured separately because they are used as
    # a readability credit against complexity and dense constructs.
    comment_lines = source_comment_lines(source)
    docstring_lines = ast_docstring_lines(tree)
    dense_constructs = dense_construct_score(tree)
    loc = sum(1 for line in source.splitlines() if line.strip() and not line.strip().startswith("#"))
    return ModuleStaticStats(
        function_count=len(functions),
        complexity=complexity,
        max_function_complexity=max_function_complexity,
        comment_lines=comment_lines,
        docstring_lines=docstring_lines,
        dense_constructs=dense_constructs,
        documentation_pressure=documentation_pressure_score(
            loc=loc,
            complexity=complexity,
            max_function_complexity=max_function_complexity,
            dense_constructs=dense_constructs,
            comment_lines=comment_lines,
            docstring_lines=docstring_lines,
        ),
        security_hits=security_surface_hits(source),
    )


def complexity_score(node: ast.AST) -> int:
    """Approximate cyclomatic pressure using Python branch/control nodes.

    Called by: `module_static_stats()`.
    """

    score = 1
    branch_nodes = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.ExceptHandler,
        ast.IfExp,
        ast.Match,
        ast.Assert,
        ast.comprehension,
    )
    for child in ast.walk(node):
        if isinstance(child, branch_nodes):
            # Each explicit branch/control construct adds one point; this is a
            # rough pressure signal, not a full McCabe implementation.
            score += 1
        elif isinstance(child, ast.BoolOp):
            # `a and b and c` adds pressure proportional to the number of
            # decisions packed into the expression.
            score += max(1, len(child.values) - 1)
    return score


def dense_construct_score(tree: ast.AST) -> int:
    """Return a rough count of compact constructs that often need orientation.

    Called by: `module_static_stats()`.
    """

    score = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.ListComp | ast.DictComp | ast.SetComp | ast.GeneratorExp):
            # Comprehensions often pack filtering/mapping logic into one line,
            # so they receive a higher orientation-pressure score.
            score += 2
        elif isinstance(node, ast.Dict) and len(node.keys) >= 4:
            score += 1
        elif isinstance(node, ast.List | ast.Tuple) and len(node.elts) >= 4:
            score += 1
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            end = getattr(node, "end_lineno", node.lineno)
            if end - node.lineno + 1 >= 35:
                # Long functions are not automatically bad, but they usually
                # benefit from phase comments or extraction.
                score += 2
    return score


def source_comment_lines(source: str) -> int:
    """Count standalone and inline `#` comments in Python source.

    Called by: `module_static_stats()`.
    """

    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        return sum(1 for token in tokens if token.type == tokenize.COMMENT)
    except tokenize.TokenError:
        return 0


def ast_docstring_lines(tree: ast.AST) -> int:
    """Count module/class/function docstring lines from AST source spans.

    Called by: `module_static_stats()`.
    """

    total = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        body = getattr(node, "body", ())
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
            # AST source spans give a stable line count for triple-quoted
            # docstrings without needing token-level parsing.
            end = getattr(first, "end_lineno", first.lineno)
            total += max(1, end - first.lineno + 1)
    return total


def documentation_pressure_score(
    *,
    loc: int,
    complexity: int,
    max_function_complexity: int,
    dense_constructs: int,
    comment_lines: int,
    docstring_lines: int,
) -> int:
    """Score modules where dense code likely needs more orientation comments.

    Called by: `module_static_stats()`.
    """

    pressure = loc // 25 + complexity + max_function_complexity + dense_constructs
    credit = comment_lines // 3 + docstring_lines // 4
    # Comments and docstrings reduce pressure but do not erase it entirely for
    # complex modules; reviewers still see high-complexity files in the report.
    return max(0, pressure - credit)


def security_surface_hits(source: str) -> int:
    """Count security-relevant tokens that merit review when modules grow.

    Called by: `module_static_stats()`.
    """

    lowered = source.casefold()
    return sum(lowered.count(token) for token in SECURITY_SURFACE_TOKENS)
