"""Architecture metric collection pipeline.

Used by:
- `bywaf.tools.architecture.cli`: collect source/doc metrics for CLI output.
- tests and maintainer scripts: import `collect_architecture_metrics()` through
  the package facade for synthetic-package validation.
"""

from __future__ import annotations

import ast
import subprocess
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path

from .graph import internal_imports, strongly_connected_components
from .models import ArchitectureMetrics, ModuleMetric, ModuleStaticStats
from .source import module_name, module_static_stats, source_loc
from ..documentation.metrics import collect_documentation_metrics

ModulePaths = dict[str, Path]
ImportGraph = dict[str, set[str]]


def collect_architecture_metrics(
    root: Path,
    *,
    package: str | None = None,
    tests_root: Path | None = None,
    docs_root: Path | None = None,
    include_churn: bool = False,
) -> ArchitectureMetrics:
    """Collect import and size metrics for a Python package directory.

    Called by: the architecture CLI, release/refactor checks, and tests that
    validate metric behavior with synthetic packages.
    """
    root = root.resolve()
    repo_root = root.parent
    package = package or root.name
    # The collector is intentionally phased: first discover source files, then
    # parse them once for import/static metrics, then enrich with test/churn and
    # documentation signals.
    modules = discover_modules(root, package)
    adjacency, loc_by_module, stats_by_module = analyze_modules(root, package, modules)
    fan_in = fan_in_map(adjacency)
    module_metrics = build_module_metrics(
        root,
        repo_root,
        modules,
        adjacency,
        fan_in,
        loc_by_module,
        stats_by_module,
        tests_root=tests_root or repo_root / "tests",
        include_churn=include_churn,
    )
    edge_count = sum(len(targets) for targets in adjacency.values())
    # Documentation metrics ride along with source metrics so a single command
    # can guide code and docs refactor slices.
    docs = collect_documentation_metrics(repo_root, docs_root=docs_root)
    return ArchitectureMetrics(package, len(modules), edge_count, dependency_cycles(adjacency), module_metrics, docs)


def discover_modules(root: Path, package: str) -> ModulePaths:
    """Return importable package modules keyed by dotted module name.

    Called by: `collect_architecture_metrics()` before AST analysis.
    """
    module_paths = sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)
    return {module_name(root, path, package): path for path in module_paths}


def analyze_modules(
    root: Path,
    package: str,
    modules: ModulePaths,
) -> tuple[ImportGraph, dict[str, int], dict[str, ModuleStaticStats]]:
    """Return import graph, LOC, and static source metrics for modules.

    Called by: `collect_architecture_metrics()`.
    """
    packages = {name for name, path in modules.items() if path.name == "__init__.py"}
    adjacency: ImportGraph = {name: set() for name in modules}
    loc_by_module = {name: source_loc(path) for name, path in modules.items()}
    stats_by_module: dict[str, ModuleStaticStats] = {}
    for name, path in modules.items():
        # Each file is parsed once. The AST feeds both source-pressure metrics
        # and runtime import graph extraction, so both signals refer to the same
        # source snapshot.
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        stats_by_module[name] = module_static_stats(tree, source)
        for imported in internal_imports(tree, name, package, set(modules), packages):
            if imported != name:
                adjacency[name].add(imported)
    return adjacency, loc_by_module, stats_by_module


def fan_in_map(adjacency: ImportGraph) -> dict[str, set[str]]:
    """Return reverse import edges keyed by imported module.

    Called by: `collect_architecture_metrics()` before `ModuleMetric`
    construction.
    """
    fan_in: dict[str, set[str]] = defaultdict(set)
    for source, targets in adjacency.items():
        for target in targets:
            fan_in[target].add(source)
    return fan_in


def build_module_metrics(
    root: Path,
    repo_root: Path,
    modules: ModulePaths,
    adjacency: ImportGraph,
    fan_in: Mapping[str, set[str]],
    loc_by_module: Mapping[str, int],
    stats_by_module: Mapping[str, ModuleStaticStats],
    *,
    tests_root: Path,
    include_churn: bool,
) -> tuple[ModuleMetric, ...]:
    """Return per-module architecture metrics from collected source signals.

    Called by: `collect_architecture_metrics()` after import/static analysis.
    """
    test_refs = test_reference_counts(modules, tests_root or repo_root / "tests")
    churn = git_churn_counts(repo_root, modules) if include_churn else defaultdict(int)
    # ModuleMetric is the report boundary: all source, dependency, test, churn,
    # and security signals are normalized here before text/JSON rendering.
    return tuple(
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


def dependency_cycles(adjacency: ImportGraph) -> tuple[tuple[str, ...], ...]:
    """Return sorted multi-module dependency cycles.

    Called by: `collect_architecture_metrics()` for the top-level summary.
    """
    cycles = tuple(tuple(sorted(component)) for component in strongly_connected_components(adjacency) if len(component) > 1)
    return tuple(sorted(cycles))


def test_reference_counts(modules: dict[str, Path], tests_root: Path) -> defaultdict[str, int]:
    """Count rough references to module names and paths from tests.

    Called by: `build_module_metrics()` to flag high-hub modules with low
    visible test coverage.
    """
    counts: defaultdict[str, int] = defaultdict(int)
    if not tests_root.exists():
        return counts
    # This is a cheap textual signal rather than a precise coverage metric; it
    # is useful for prioritizing review but should not be treated as proof of
    # runtime coverage.
    test_text = "\n".join(path.read_text(encoding="utf-8") for path in tests_root.rglob("*.py"))
    for name, path in modules.items():
        relative = path.as_posix()
        counts[name] = test_text.count(name) + test_text.count(relative)
    return counts


def git_churn_counts(repo_root: Path, modules: dict[str, Path]) -> defaultdict[str, int]:
    """Count commits touching each module when git history is available.

    Called by: `build_module_metrics()` only when `--churn` is requested.
    """
    counts: defaultdict[str, int] = defaultdict(int)
    try:
        # Git history is optional because release packaging and source archives
        # may not include a usable `.git` directory.
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
        # Empty lines separate commits; only changed file paths that map to
        # measured modules increment churn.
        name = paths_to_modules.get(line.strip())
        if name is not None:
            counts[name] += 1
    return counts
