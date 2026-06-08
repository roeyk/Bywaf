"""Data models shared by architecture metric collection and rendering."""

from __future__ import annotations

from dataclasses import dataclass

from .documentation_metrics import DocumentationMetrics


@dataclass(frozen=True, slots=True)
class ModuleMetric:
    """Metrics for one Python module.

    Constructed by: `collect_architecture_metrics()`.
    Used by: architecture report formatters and JSON output.
    """

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
    """Repository-level architecture metrics.

    Constructed by: `collect_architecture_metrics()`.
    Used by: text/JSON reports and release/refactor checks.
    """

    package: str
    module_count: int
    edge_count: int
    cycles: tuple[tuple[str, ...], ...]
    modules: tuple[ModuleMetric, ...]
    docs: DocumentationMetrics | None = None


@dataclass(frozen=True, slots=True)
class ModuleStaticStats:
    """AST-derived metrics that do not need imports or git metadata.

    Constructed by: `module_static_stats()`.
    Used by: `collect_architecture_metrics()` when building `ModuleMetric`.
    """

    function_count: int
    complexity: int
    max_function_complexity: int
    comment_lines: int
    docstring_lines: int
    dense_constructs: int
    documentation_pressure: int
    security_hits: int
