"""Styled terminal rendering for analysis report tables.

Called by: `analysis.report.render` after `report.tables` builds a `Table`
model for finding-grouped or host-grouped rows.
"""

from __future__ import annotations

from collections.abc import Mapping

from bywaf.finding import severity_class
from bywaf.plugin import CommandContext
from bywaf.rendering import Table, align_text, table_values
from bywaf.runtime_display import shrink_table_widths, terminal_table_width, truncate_cell

from .style import finding_text, report_text, table_text


def render_styled_report_table(context: CommandContext, table: Table) -> str:
    """Render a report table with theme-driven baseline and subject styles."""
    if not table.columns:
        return report_text(context, "section", table.title or "")
    values = table_values(table)
    widths = [
        max(len(column.heading), *(len(row[index]) for row in values))
        for index, column in enumerate(table.columns)
    ]
    widths = shrink_table_widths(widths, [column.heading for column in table.columns], terminal_table_width())
    values = [
        [truncate_cell(value, widths[index]) for index, value in enumerate(row)]
        for row in values
    ]
    lines: list[str] = []
    if table.title:
        lines.append(report_text(context, "section", table.title))
    headings = [
        table_text(context, "header", align_text(column.heading, widths[index], column.align))
        for index, column in enumerate(table.columns)
    ]
    lines.append("  ".join(headings))
    lines.append(
        "  ".join(
            table_text(context, "header", "-" * width)
            for width in widths
        )
    )
    for row_index, row in enumerate(values):
        cells: list[str] = []
        row_mapping = table.rows[row_index]
        for index, value in enumerate(row):
            column = table.columns[index]
            aligned = align_text(value, widths[index], column.align)
            cells.append(styled_report_cell(context, column.key, aligned, row_mapping))
        lines.append("  ".join(cells))
    return "\n".join(lines)


def styled_report_cell(
    context: CommandContext,
    column_key: str,
    value: str,
    row: Mapping[str, object],
) -> str:
    """Apply the most specific report-table style for one cell."""
    if column_key == "index":
        return table_text(context, "index", value)
    if column_key == "host":
        return table_text(context, "index", value)
    if column_key == "finding_name":
        return finding_text(context, "title", value)
    if column_key == "severity":
        severity = str(row.get("severity") or "").strip().casefold()
        if severity:
            styled = finding_text(context, f"severity.{severity}", value)
            if styled != value:
                return styled
            severity_class_name = severity_class(severity)
            styled = finding_text(context, f"severity_class.{severity_class_name}", value)
            if styled != value:
                return styled
    return table_text(context, "body", value)
