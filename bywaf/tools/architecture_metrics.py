"""Lightweight architecture metrics for Bywaf source and documentation.

Provides import dependency, size, fan-in/fan-out, complexity, test-reference,
churn, security-surface, cycle, and documentation pressure metrics without
requiring optional analysis dependencies.

Used by:
- maintainers: spot coupling pressure before refactors.
- release checks: compare module size and dependency drift over time.
"""

from __future__ import annotations

import argparse
import ast
import io
import json
import subprocess
import tokenize
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .architecture_formatting import format_documentation_impact, format_metrics
from .documentation_metrics import (
    DocumentationMetrics,
    collect_documentation_impact,
    collect_documentation_metrics,
)


@dataclass(frozen=True, slots=True)
class ModuleMetric:
    """Metrics for one Python module."""

    name: str
    path: str
    loc: int
    fan_in: int
    fan_out: int
    function_count: int
    complexity: int
    max_function_complexity: int
    comment_lines: int
    docstring_lines: int
    dense_constructs: int
    documentation_pressure: int
    test_refs: int
    churn: int
    security_hits: int
    imports: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ArchitectureMetrics:
    """Repository-level architecture metrics."""

    package: str
    module_count: int
    edge_count: int
    cycles: tuple[tuple[str, ...], ...]
    modules: tuple[ModuleMetric, ...]
    docs: "DocumentationMetrics | None" = None


def collect_architecture_metrics(
    root: Path,
    *,
    package: str | None = None,
    tests_root: Path | None = None,
    docs_root: Path | None = None,
    include_churn: bool = False,
) -> ArchitectureMetrics:
    """Collect import and size metrics for a Python package directory."""
    root = root.resolve()
    repo_root = root.parent
    package = package or root.name
    module_paths = sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)
    modules = {module_name(root, path, package): path for path in module_paths}
    packages = {name for name, path in modules.items() if path.name == "__init__.py"}
    adjacency: dict[str, set[str]] = {name: set() for name in modules}
    loc_by_module = {name: source_loc(path) for name, path in modules.items()}
    stats_by_module: dict[str, ModuleStaticStats] = {}

    for name, path in modules.items():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        stats_by_module[name] = module_static_stats(tree, source)
        for imported in internal_imports(tree, name, package, set(modules), packages):
            if imported != name:
                adjacency[name].add(imported)

    fan_in: dict[str, set[str]] = defaultdict(set)
    for source, targets in adjacency.items():
        for target in targets:
            fan_in[target].add(source)

    test_refs = test_reference_counts(modules, tests_root or repo_root / "tests")
    churn = git_churn_counts(repo_root, modules) if include_churn else defaultdict(int)
    module_metrics = tuple(
        ModuleMetric(
            name=name,
            path=str(modules[name].relative_to(root.parent)),
            loc=loc_by_module[name],
            fan_in=len(fan_in[name]),
            fan_out=len(adjacency[name]),
            function_count=stats_by_module[name].function_count,
            complexity=stats_by_module[name].complexity,
            max_function_complexity=stats_by_module[name].max_function_complexity,
            comment_lines=stats_by_module[name].comment_lines,
            docstring_lines=stats_by_module[name].docstring_lines,
            dense_constructs=stats_by_module[name].dense_constructs,
            documentation_pressure=stats_by_module[name].documentation_pressure,
            test_refs=test_refs[name],
            churn=churn[name],
            security_hits=stats_by_module[name].security_hits,
            imports=tuple(sorted(adjacency[name])),
        )
        for name in sorted(modules)
    )
    cycles = tuple(tuple(sorted(component)) for component in strongly_connected_components(adjacency) if len(component) > 1)
    edge_count = sum(len(targets) for targets in adjacency.values())
    docs = collect_documentation_metrics(repo_root, docs_root=docs_root)
    return ArchitectureMetrics(package, len(modules), edge_count, tuple(sorted(cycles)), module_metrics, docs)


@dataclass(frozen=True, slots=True)
class ModuleStaticStats:
    """AST-derived metrics that do not need imports or git metadata."""

    function_count: int
    complexity: int
    max_function_complexity: int
    comment_lines: int
    docstring_lines: int
    dense_constructs: int
    documentation_pressure: int
    security_hits: int


def module_name(root: Path, path: Path, package: str) -> str:
    """Return the dotted module name for a Python file below root."""
    relative = path.relative_to(root).with_suffix("")
    parts = (package, *relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def source_loc(path: Path) -> int:
    """Count non-empty, non-comment source lines for a rough size signal."""
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            count += 1
    return count


def module_static_stats(tree: ast.AST, source: str) -> ModuleStaticStats:
    """Return simple complexity and security-surface metrics for one module."""
    functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)]
    function_complexities = [complexity_score(function) for function in functions]
    complexity = complexity_score(tree)
    max_function_complexity = max(function_complexities, default=0)
    comment_lines = source_comment_lines(source)
    docstring_lines = ast_docstring_lines(tree)
    dense_constructs = dense_construct_score(tree)
    return ModuleStaticStats(
        function_count=len(functions),
        complexity=complexity,
        max_function_complexity=max_function_complexity,
        comment_lines=comment_lines,
        docstring_lines=docstring_lines,
        dense_constructs=dense_constructs,
        documentation_pressure=documentation_pressure_score(
            loc=sum(1 for line in source.splitlines() if line.strip() and not line.strip().startswith("#")),
            complexity=complexity,
            max_function_complexity=max_function_complexity,
            dense_constructs=dense_constructs,
            comment_lines=comment_lines,
            docstring_lines=docstring_lines,
        ),
        security_hits=security_surface_hits(source),
    )


def complexity_score(node: ast.AST) -> int:
    """Approximate cyclomatic pressure using Python branch/control nodes."""
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
            score += 1
        elif isinstance(child, ast.BoolOp):
            score += max(1, len(child.values) - 1)
    return score


def dense_construct_score(tree: ast.AST) -> int:
    """Return a rough count of compact constructs that often need orientation."""
    score = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.ListComp | ast.DictComp | ast.SetComp | ast.GeneratorExp):
            score += 2
        elif isinstance(node, ast.Dict) and len(node.keys) >= 4:
            score += 1
        elif isinstance(node, ast.List | ast.Tuple) and len(node.elts) >= 4:
            score += 1
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            end = getattr(node, "end_lineno", node.lineno)
            if end - node.lineno + 1 >= 35:
                score += 2
    return score


def source_comment_lines(source: str) -> int:
    """Count standalone and inline `#` comments in Python source."""
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        return sum(1 for token in tokens if token.type == tokenize.COMMENT)
    except tokenize.TokenError:
        return 0


def ast_docstring_lines(tree: ast.AST) -> int:
    """Count module/class/function docstring lines from AST source spans."""
    total = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        body = getattr(node, "body", ())
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
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
    """Score modules where dense code likely needs more orientation comments."""
    pressure = loc // 25 + complexity + max_function_complexity + dense_constructs
    credit = comment_lines // 3 + docstring_lines // 4
    return max(0, pressure - credit)


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


def security_surface_hits(source: str) -> int:
    """Count security-relevant tokens that merit review when modules grow."""
    lowered = source.casefold()
    return sum(lowered.count(token) for token in SECURITY_SURFACE_TOKENS)


def test_reference_counts(modules: dict[str, Path], tests_root: Path) -> defaultdict[str, int]:
    """Count rough references to module names and paths from tests."""
    counts: defaultdict[str, int] = defaultdict(int)
    if not tests_root.exists():
        return counts
    test_text = "\n".join(path.read_text(encoding="utf-8") for path in tests_root.rglob("*.py"))
    for name, path in modules.items():
        relative = path.as_posix()
        counts[name] = test_text.count(name) + test_text.count(relative)
    return counts


def git_churn_counts(repo_root: Path, modules: dict[str, Path]) -> defaultdict[str, int]:
    """Count commits touching each module when git history is available."""
    counts: defaultdict[str, int] = defaultdict(int)
    try:
        completed = subprocess.run(
            ["git", "log", "--name-only", "--pretty=format:"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return counts
    paths_to_modules = {path.relative_to(repo_root).as_posix(): name for name, path in modules.items()}
    for line in completed.stdout.splitlines():
        name = paths_to_modules.get(line.strip())
        if name is not None:
            counts[name] += 1
    return counts


def internal_imports(
    tree: ast.AST,
    current_module: str,
    package: str,
    modules: set[str],
    packages: set[str],
) -> Iterable[str]:
    """Yield normalized imports that point inside the measured package."""
    known = modules | packages
    for node in runtime_import_nodes(tree):
        match node:
            case ast.Import(names=names):
                for alias in names:
                    normalized = normalize_absolute_import(alias.name, package, known)
                    if normalized is not None:
                        yield normalized
            case ast.ImportFrom(module=module, level=level, names=names):
                if level:
                    imported = resolve_relative_import(current_module, module, level)
                else:
                    imported = module or ""
                normalized = normalize_absolute_import(imported, package, known)
                normalized_children = []
                for alias in names:
                    child = f"{imported}.{alias.name}" if imported else alias.name
                    normalized_child = normalize_absolute_import(child, package, known)
                    if normalized_child is not None:
                        normalized_children.append(normalized_child)
                if normalized is not None and not normalized_children:
                    yield normalized
                yield from normalized_children


def runtime_import_nodes(tree: ast.AST) -> Iterable[ast.Import | ast.ImportFrom]:
    """Yield import statements that execute at runtime.

    Type-only imports still matter to a type checker, but they do not create a
    runtime dependency edge. The architecture graph is intentionally focused on
    runtime coupling and import cycles.
    """

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.imports: list[ast.Import | ast.ImportFrom] = []

        def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
            self.imports.append(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
            self.imports.append(node)

        def visit_If(self, node: ast.If) -> None:  # noqa: N802
            if is_type_checking_guard(node.test):
                for child in node.orelse:
                    self.visit(child)
                return
            self.generic_visit(node)

    visitor = Visitor()
    visitor.visit(tree)
    return tuple(visitor.imports)


def is_type_checking_guard(node: ast.AST) -> bool:
    """Return whether an `if` test is a TYPE_CHECKING guard."""
    match node:
        case ast.Name(id="TYPE_CHECKING"):
            return True
        case ast.Attribute(value=ast.Name(id="typing"), attr="TYPE_CHECKING"):
            return True
        case _:
            return False


def normalize_absolute_import(imported: str, package: str, known: set[str]) -> str | None:
    """Collapse an import target to the nearest known internal module/package."""
    if imported != package and not imported.startswith(f"{package}."):
        return None
    candidate = imported
    while candidate:
        if candidate in known:
            return candidate
        if "." not in candidate:
            break
        candidate = candidate.rsplit(".", 1)[0]
    return package if package in known else None


def resolve_relative_import(current_module: str, imported: str | None, level: int) -> str:
    """Resolve `from .x import y` style imports to dotted module candidates."""
    package_parts = current_module.split(".")[:-1]
    if level > 1:
        package_parts = package_parts[: -(level - 1)]
    if imported:
        package_parts.extend(imported.split("."))
    return ".".join(package_parts)


def strongly_connected_components(adjacency: dict[str, set[str]]) -> list[set[str]]:
    """Return Tarjan strongly connected components for dependency cycles."""
    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    components: list[set[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for target in adjacency[node]:
            if target not in indices:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])
        if lowlinks[node] != indices[node]:
            return
        component: set[str] = set()
        while True:
            current = stack.pop()
            on_stack.remove(current)
            component.add(current)
            if current == node:
                break
        components.append(component)

    for node in adjacency:
        if node not in indices:
            visit(node)
    return components


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for `scripts/architecture_metrics.py`."""
    parser = argparse.ArgumentParser(description="Report lightweight Bywaf architecture metrics.")
    parser.add_argument("root", nargs="?", default="bywaf", help="Python package directory to inspect")
    parser.add_argument("--package", default=None, help="Dotted package name; defaults to root directory name")
    parser.add_argument("--tests-root", default=None, help="Test directory for rough module reference counts")
    parser.add_argument("--docs-root", default=None, help="Docs directory for Markdown cohesion/coupling metrics")
    parser.add_argument("--doc-impact", default=None, help="Rank docs related to this changed Markdown file")
    parser.add_argument("--top", type=int, default=12, help="Rows to show in each section")
    parser.add_argument("--churn", action="store_true", help="Include git churn counts from local history")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)
    repo_root = Path(args.root).resolve().parent
    docs_root = Path(args.docs_root) if args.docs_root else None
    if args.doc_impact:
        impact = collect_documentation_impact(
            repo_root,
            Path(args.doc_impact),
            docs_root=docs_root,
            top=args.top,
        )
        if args.json:
            print(json.dumps(asdict(impact), indent=2, sort_keys=True))
        else:
            print(format_documentation_impact(impact))
        return 0
    metrics = collect_architecture_metrics(
        Path(args.root),
        package=args.package,
        tests_root=Path(args.tests_root) if args.tests_root else None,
        docs_root=docs_root,
        include_churn=args.churn,
    )
    if args.json:
        print(json.dumps(asdict(metrics), indent=2, sort_keys=True))
    else:
        print(format_metrics(metrics, top=args.top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
