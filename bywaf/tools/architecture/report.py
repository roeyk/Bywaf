"""Source architecture report sections for `architecture.formatting`.

Used by:
- maintainers measuring coupling, complexity, documentation pressure, and
  release-readiness signals.
- CI/manual validation runs that track architecture drift.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .report_sections import detail_section, section

if TYPE_CHECKING:
    from .models import ArchitectureMetrics, ModuleMetric


def architecture_report_sections(metrics: ArchitectureMetrics, *, top: int) -> list[str]:
    """Build source-code sections for the architecture report.

    Called by: `architecture.formatting.format_metrics()`.
    """
    modules = list(metrics.modules)
    ranked = _ranked_architecture_modules(modules, top=top)
    lines = [
        f"Architecture metrics for {metrics.package}",
        f"modules={metrics.module_count} internal_edges={metrics.edge_count} cycles={len(metrics.cycles)}",
        "",
        section("Largest modules", ((module.name, module.loc) for module in ranked["largest"]), "loc"),
        section("Highest fan-out", ((module.name, module.fan_out) for module in ranked["fan_out"]), "imports"),
        section("Highest fan-in", ((module.name, module.fan_in) for module in ranked["fan_in"]), "importers"),
        section(
            "Highest hub score",
            ((module.name, module.fan_in + module.fan_out) for module in ranked["hubs"]),
            "fan-in+fan-out",
        ),
        section(
            "Highest module complexity",
            ((module.name, module.complexity) for module in ranked["complex_modules"]),
            "score",
        ),
        section(
            "Highest single-function complexity",
            ((module.name, module.max_function_complexity) for module in ranked["complex_functions"]),
            "score",
        ),
        detail_section(
            "Highest documentation pressure",
            (
                (
                    module.name,
                    (
                        f"score={module.documentation_pressure} "
                        f"complexity={module.complexity} "
                        f"dense={module.dense_constructs} "
                        f"comments={module.comment_lines} "
                        f"docstrings={module.docstring_lines}"
                    ),
                )
                for module in ranked["documentation_pressure"]
            ),
        ),
        detail_section(
            "High hub score with low test references",
            (
                (
                    module.name,
                    f"hub={module.fan_in + module.fan_out} test_refs={module.test_refs}",
                )
                for module in ranked["low_test_hubs"]
            ),
        ),
        section(
            "Highest security-surface hits",
            ((module.name, module.security_hits) for module in ranked["security_surface"]),
            "hits",
        ),
    ]
    if any(module.churn for module in modules):
        lines.append(
            section("Highest git churn", ((module.name, module.churn) for module in ranked["churned"]), "commits")
        )
    if metrics.cycles:
        lines.extend(["", "Import cycles:"])
        for cycle in metrics.cycles[:top]:
            lines.append(f"- {', '.join(cycle)}")
    return lines


def _ranked_architecture_modules(modules: list[ModuleMetric], *, top: int) -> dict[str, list[ModuleMetric]]:
    """Return the ranked module buckets used by `architecture_report_sections()`.

    The dictionary is a local dispatch table for report dimensions. Keeping
    the ranking keys here makes `architecture_report_sections()` read as report
    assembly instead of a long sort-and-render ladder.
    """
    return {
        "largest": sorted(modules, key=lambda module: module.loc, reverse=True)[:top],
        "fan_out": sorted(modules, key=lambda module: module.fan_out, reverse=True)[:top],
        "fan_in": sorted(modules, key=lambda module: module.fan_in, reverse=True)[:top],
        "hubs": sorted(modules, key=lambda module: module.fan_in + module.fan_out, reverse=True)[:top],
        "complex_modules": sorted(modules, key=lambda module: module.complexity, reverse=True)[:top],
        "complex_functions": sorted(modules, key=lambda module: module.max_function_complexity, reverse=True)[:top],
        "documentation_pressure": sorted(
            modules,
            key=lambda module: module.documentation_pressure,
            reverse=True,
        )[:top],
        "low_test_hubs": sorted(
            modules,
            key=lambda module: (module.test_refs == 0, module.fan_in + module.fan_out, module.security_hits),
            reverse=True,
        )[:top],
        "security_surface": sorted(modules, key=lambda module: module.security_hits, reverse=True)[:top],
        "churned": sorted(modules, key=lambda module: module.churn, reverse=True)[:top],
    }
