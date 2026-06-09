"""Text table exporters.

Used by: `rendering.exporters.render_table()` for Markdown, CSV, JSONL, and
HTML outputs that do not require optional third-party packages.
"""

from __future__ import annotations

import csv
import html
import io
import json

from .model import Align, Table, json_safe_value, table_values


def render_markdown_table(table: Table) -> str:
    """Render a GitHub-flavored Markdown table."""
    lines: list[str] = []
    if table.title:
        lines.extend((f"### {table.title}", ""))
    headers = [escape_markdown_cell(column.heading) for column in table.columns]
    alignments = [markdown_alignment(column.align) for column in table.columns]
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(alignments) + " |")
    for row in table_values(table):
        lines.append("| " + " | ".join(escape_markdown_cell(value) for value in row) + " |")
    return "\n".join(lines)


def render_csv_table(table: Table) -> str:
    """Render a CSV table."""
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow([column.heading for column in table.columns])
    writer.writerows(table_values(table))
    return stream.getvalue()


def render_jsonl_table(table: Table) -> str:
    """Render table rows as newline-delimited JSON objects."""
    return "\n".join(
        json.dumps({column.key: json_safe_value(row.get(column.key, "")) for column in table.columns}, sort_keys=True)
        for row in table.rows
    )


def render_html_table(table: Table) -> str:
    """Render a minimal escaped HTML table."""
    lines = ["<table>"]
    if table.title:
        lines.append(f"  <caption>{html.escape(table.title)}</caption>")
    lines.append("  <thead>")
    lines.append("    <tr>" + "".join(f"<th>{html.escape(column.heading)}</th>" for column in table.columns) + "</tr>")
    lines.append("  </thead>")
    lines.append("  <tbody>")
    for row in table_values(table):
        lines.append("    <tr>" + "".join(f"<td>{html.escape(value)}</td>" for value in row) + "</tr>")
    lines.append("  </tbody>")
    lines.append("</table>")
    return "\n".join(lines)


def markdown_alignment(align: Align) -> str:
    """Return one Markdown alignment marker."""
    return {"right": "---:", "center": ":---:"}.get(align, "---")


def escape_markdown_cell(value: str) -> str:
    """Escape Markdown table separators inside a cell."""
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>")
