"""Human-readable formatting for architecture and documentation metrics."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .report import architecture_report_sections
from .report_sections import detail_section, section
from ..documentation_report import format_documentation_impact, format_documentation_metrics

if TYPE_CHECKING:
    from . import ArchitectureMetrics


def format_metrics(metrics: ArchitectureMetrics, *, top: int = 12) -> str:
    """Render a compact human-readable architecture metrics report.

    Called by: `architecture.main()` for CLI output and by tests that
    verify refactor pressure sections.
    """
    lines = architecture_report_sections(metrics, top=top)
    if metrics.docs is not None:
        lines.extend(["", format_documentation_metrics(metrics.docs, top=top)])
    return "\n".join(lines)


__all__ = [
    "detail_section",
    "format_documentation_impact",
    "format_documentation_metrics",
    "format_metrics",
    "section",
]
