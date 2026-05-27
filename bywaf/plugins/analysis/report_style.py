"""Report style helpers.

Maps report, table, finding, and generic output subjects to configured terminal
styles without coupling report code to concrete colors.

Used by:
- analysis.report_render: style headings and table cells.
- analysis.report_details: style detail labels and provenance values."""

from __future__ import annotations

from collections.abc import Mapping

from bywaf.plugin import CommandContext
from bywaf.style import styled_subject_text


def subject_text(context: CommandContext, subject: str, value: object) -> str:
    """Style a generic output subject such as serial, job, step, or pipeline."""
    return styled_subject_text(lambda key, default="": display_var(context, key, default), subject, value)


def report_text(context: CommandContext, subject: str, value: object) -> str:
    """Style report UI text such as headings, sections, and labels."""
    return styled_subject_text(lambda key, default="": display_var(context, key, default), f"report.{subject}", value)


def table_text(context: CommandContext, subject: str, value: object) -> str:
    """Style table text using table-specific subject names."""
    return styled_subject_text(lambda key, default="": display_var(context, key, default), f"table.{subject}", value)


def finding_text(context: CommandContext, subject: str, value: object) -> str:
    """Style finding-specific text using normalized finding subjects."""
    return styled_subject_text(lambda key, default="": display_var(context, key, default), f"finding.{subject}", value)


def display_var(context: CommandContext, key: str, default: str = "") -> str:
    """Return a display variable from the step snapshot, then session globals."""
    run_vars = context.metadata.get("run_vars", {})
    if isinstance(run_vars, Mapping) and key in run_vars:
        return str(run_vars[key])
    display_vars = context.metadata.get("display_vars")
    return str(display_vars.get(key, default)) if isinstance(display_vars, Mapping) else default
