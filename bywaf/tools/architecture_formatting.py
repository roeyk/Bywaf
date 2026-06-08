"""Human-readable formatting for architecture and documentation metrics."""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from .architecture_metrics import ArchitectureMetrics
    from .documentation_metrics import DocumentationImpact, DocumentationMetrics


def format_metrics(metrics: ArchitectureMetrics, *, top: int = 12) -> str:
    """Render a compact human-readable architecture metrics report."""
    modules = list(metrics.modules)
    largest = sorted(modules, key=lambda module: module.loc, reverse=True)[:top]
    fan_out = sorted(modules, key=lambda module: module.fan_out, reverse=True)[:top]
    fan_in = sorted(modules, key=lambda module: module.fan_in, reverse=True)[:top]
    hubs = sorted(modules, key=lambda module: module.fan_in + module.fan_out, reverse=True)[:top]
    complex_modules = sorted(modules, key=lambda module: module.complexity, reverse=True)[:top]
    complex_functions = sorted(modules, key=lambda module: module.max_function_complexity, reverse=True)[:top]
    documentation_pressure = sorted(modules, key=lambda module: module.documentation_pressure, reverse=True)[:top]
    low_test_hubs = sorted(
        modules,
        key=lambda module: (module.test_refs == 0, module.fan_in + module.fan_out, module.security_hits),
        reverse=True,
    )[:top]
    security_surface = sorted(modules, key=lambda module: module.security_hits, reverse=True)[:top]
    churned = sorted(modules, key=lambda module: module.churn, reverse=True)[:top]
    lines = [
        f"Architecture metrics for {metrics.package}",
        f"modules={metrics.module_count} internal_edges={metrics.edge_count} cycles={len(metrics.cycles)}",
        "",
        section("Largest modules", ((module.name, module.loc) for module in largest), "loc"),
        section("Highest fan-out", ((module.name, module.fan_out) for module in fan_out), "imports"),
        section("Highest fan-in", ((module.name, module.fan_in) for module in fan_in), "importers"),
        section("Highest hub score", ((module.name, module.fan_in + module.fan_out) for module in hubs), "fan-in+fan-out"),
        section("Highest module complexity", ((module.name, module.complexity) for module in complex_modules), "score"),
        section(
            "Highest single-function complexity",
            ((module.name, module.max_function_complexity) for module in complex_functions),
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
                for module in documentation_pressure
            ),
        ),
        detail_section(
            "High hub score with low test references",
            (
                (
                    module.name,
                    f"hub={module.fan_in + module.fan_out} test_refs={module.test_refs}",
                )
                for module in low_test_hubs
            ),
        ),
        section("Highest security-surface hits", ((module.name, module.security_hits) for module in security_surface), "hits"),
    ]
    if any(module.churn for module in modules):
        lines.append(section("Highest git churn", ((module.name, module.churn) for module in churned), "commits"))
    if metrics.cycles:
        lines.extend(["", "Import cycles:"])
        for cycle in metrics.cycles[:top]:
            lines.append(f"- {', '.join(cycle)}")
    if metrics.docs is not None:
        lines.extend(["", format_documentation_metrics(metrics.docs, top=top)])
    return "\n".join(lines)


def format_documentation_metrics(metrics: DocumentationMetrics, *, top: int = 12) -> str:
    """Render documentation cohesion and coupling pressure sections."""
    documents = list(metrics.documents)
    largest = sorted(documents, key=lambda document: document.words, reverse=True)[:top]
    many_headings = sorted(documents, key=lambda document: document.headings, reverse=True)[:top]
    doc_hubs = sorted(
        documents,
        key=lambda document: document.inbound_links + document.outbound_links,
        reverse=True,
    )[:top]
    stale = sorted(documents, key=lambda document: document.stale_terms, reverse=True)[:top]
    mixed_audience = sorted(documents, key=lambda document: document.audience_hits, reverse=True)[:top]
    duplicate_headings = sorted(documents, key=lambda document: document.duplicate_headings, reverse=True)[:top]
    lines = [
        "Documentation metrics:",
        f"documents={metrics.document_count} links={metrics.link_count} broken_links={len(metrics.broken_links)}",
        "",
        section("Largest docs", ((document.path, document.words) for document in largest), "words"),
        section("Most doc headings", ((document.path, document.headings) for document in many_headings), "headings"),
        detail_section(
            "Highest doc link coupling",
            (
                (
                    document.path,
                    f"in={document.inbound_links} out={document.outbound_links}",
                )
                for document in doc_hubs
            ),
        ),
        section("Most stale-term hits", ((document.path, document.stale_terms) for document in stale), "hits"),
        section(
            "Most audience-mixing hints",
            ((document.path, document.audience_hits) for document in mixed_audience),
            "hints",
        ),
        section(
            "Most duplicate headings",
            ((document.path, document.duplicate_headings) for document in duplicate_headings),
            "duplicates",
        ),
    ]
    if metrics.broken_links:
        lines.append(detail_section("Broken local doc links", ((link, "") for link in metrics.broken_links[:top])))
    return "\n".join(lines)


def format_documentation_impact(impact: DocumentationImpact) -> str:
    """Render related docs to inspect after editing one document."""
    lines = [f"Documentation impact for {impact.source}"]
    if not impact.related:
        lines.append("No related documents found.")
        return "\n".join(lines)
    for item in impact.related:
        lines.append(f"- score={item.score:>3}  {item.path}")
        for reason in item.reasons:
            lines.append(f"  - {reason}")
    return "\n".join(lines)


def section(title: str, rows: Iterable[tuple[str, int]], unit: str) -> str:
    """Format one ranked metric section."""
    lines = [f"{title}:"]
    for name, value in rows:
        lines.append(f"- {value:>4} {unit}  {name}")
    return "\n".join(lines)


def detail_section(title: str, rows: Iterable[tuple[str, str]]) -> str:
    """Format one section whose value contains several compact dimensions."""
    lines = [f"{title}:"]
    for name, value in rows:
        lines.append(f"- {value}  {name}")
    return "\n".join(lines)
