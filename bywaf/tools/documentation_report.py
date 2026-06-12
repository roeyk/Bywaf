"""Documentation metrics report rendering.

Used by:
- maintainer tools, documentation/report generation, and validation scripts.
- tests and release checks that exercise developer-facing tooling.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .architecture.report_sections import detail_section, section

if TYPE_CHECKING:
    from .documentation_metrics import DocumentMetric, DocumentationImpact, DocumentationMetrics


def format_documentation_metrics(metrics: DocumentationMetrics, *, top: int = 12) -> str:
    """Render documentation cohesion and coupling pressure sections.

    Called by: `architecture.formatting.format_metrics()`.
    """
    documents = list(metrics.documents)
    ranked = _ranked_documents(documents, top=top)
    lines = [
        "Documentation metrics:",
        f"documents={metrics.document_count} links={metrics.link_count} broken_links={len(metrics.broken_links)}",
        "",
        section("Largest docs", ((document.path, document.words) for document in ranked["largest"]), "words"),
        section(
            "Most doc headings",
            ((document.path, document.headings) for document in ranked["many_headings"]),
            "headings",
        ),
        detail_section(
            "Highest doc link coupling",
            (
                (
                    document.path,
                    f"in={document.inbound_links} out={document.outbound_links}",
                )
                for document in ranked["doc_hubs"]
            ),
        ),
        section("Most stale-term hits", ((document.path, document.stale_terms) for document in ranked["stale"]), "hits"),
        section(
            "Most audience-mixing hints",
            ((document.path, document.audience_hits) for document in ranked["mixed_audience"]),
            "hints",
        ),
        section(
            "Most duplicate headings",
            ((document.path, document.duplicate_headings) for document in ranked["duplicate_headings"]),
            "duplicates",
        ),
    ]
    if metrics.broken_links:
        lines.append(detail_section("Broken local doc links", ((link, "") for link in metrics.broken_links[:top])))
    return "\n".join(lines)


def format_documentation_impact(impact: DocumentationImpact) -> str:
    """Render related docs to inspect after editing one document.

    Called by: `architecture.main()` for the documentation-impact CLI
    mode and by tests that verify ranking reasons.
    """
    lines = [f"Documentation impact for {impact.source}"]
    if not impact.related:
        lines.append("No related documents found.")
        return "\n".join(lines)
    for item in impact.related:
        lines.append(f"- score={item.score:>3}  {item.path}")
        for reason in item.reasons:
            lines.append(f"  - {reason}")
    return "\n".join(lines)


def _ranked_documents(documents: list[DocumentMetric], *, top: int) -> dict[str, list[DocumentMetric]]:
    """Return ranked documentation buckets used by `format_documentation_metrics()`.

    The dictionary is a local dispatch table for documentation report sections.
    It keeps each sort criterion named so the renderer can stay close to the
    final output order.
    """
    return {
        "largest": sorted(documents, key=lambda document: document.words, reverse=True)[:top],
        "many_headings": sorted(documents, key=lambda document: document.headings, reverse=True)[:top],
        "doc_hubs": sorted(
            documents,
            key=lambda document: document.inbound_links + document.outbound_links,
            reverse=True,
        )[:top],
        "stale": sorted(documents, key=lambda document: document.stale_terms, reverse=True)[:top],
        "mixed_audience": sorted(documents, key=lambda document: document.audience_hits, reverse=True)[:top],
        "duplicate_headings": sorted(documents, key=lambda document: document.duplicate_headings, reverse=True)[:top],
    }
