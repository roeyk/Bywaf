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
import json
import subprocess
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path

from .architecture_formatting import format_documentation_impact, format_metrics
from .architecture_graph import (
    internal_imports,
    is_type_checking_guard as is_type_checking_guard,
    normalize_absolute_import as normalize_absolute_import,
    resolve_relative_import as resolve_relative_import,
    runtime_import_nodes as runtime_import_nodes,
    strongly_connected_components,
)
from .architecture_models import ArchitectureMetrics, ModuleMetric, ModuleStaticStats
from .architecture_source import (
    SECURITY_SURFACE_TOKENS as SECURITY_SURFACE_TOKENS,
    ast_docstring_lines as ast_docstring_lines,
    complexity_score as complexity_score,
    dense_construct_score as dense_construct_score,
    documentation_pressure_score as documentation_pressure_score,
    module_name,
    module_static_stats,
    security_surface_hits as security_surface_hits,
    source_comment_lines as source_comment_lines,
    source_loc,
)
from .documentation_metrics import (
    collect_documentation_impact,
    collect_documentation_metrics,
)


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
