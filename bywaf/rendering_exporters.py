"""Output-format renderers for structured tables."""

from __future__ import annotations

import csv
import html
import importlib
import io
import json
from collections.abc import Callable
from typing import Any, Literal, cast

from .rendering_model import Align, Table, json_safe_value, table_values

TableFormat = Literal["console", "md", "csv", "jsonl", "html", "docx", "xlsx"]
TableRenderer = Callable[[Table], str | bytes]


def render_table(table: Table, fmt: TableFormat = "console") -> str | bytes:
    """Render a table in one supported format."""
    # This lookup uses the table_renderers() dispatch table in place of an
    # if/elif ladder over output formats.
    renderer = table_renderers().get(fmt)
    if renderer is None:
        raise ValueError(f"unsupported table format: {fmt}")
    return renderer(table)


def table_renderers() -> dict[str, TableRenderer]:
    """Return table renderers keyed by output format."""
    return {
        "console": render_console_table,
        "md": render_markdown_table,
        "csv": render_csv_table,
        "jsonl": render_jsonl_table,
        "html": render_html_table,
        "docx": render_docx_table,
        "xlsx": render_xlsx_table,
    }


def render_console_table(table: Table, style_getter=None) -> str:
    """Render a table for monospaced terminal output."""
    if not table.columns:
        return table.title or ""
    from .runtime_display import shrink_table_widths, style_table_cell, style_table_header, terminal_table_width, truncate_cell

    # Console rendering first converts every cell to display text, then computes
    # the widest required width for each column before terminal-width shrinking.
    values = table_values(table)
    widths = [
        max(len(column.heading), *(len(row[index]) for row in values))
        for index, column in enumerate(table.columns)
    ]
    # shrink_table_widths() preserves readable headings where possible while
    # forcing the whole table into the current terminal width.
    widths = shrink_table_widths(widths, [column.heading for column in table.columns], terminal_table_width())
    # Once final widths are known, truncate cell text up front so alignment and
    # styling operate on exactly the text that will be printed.
    values = [
        [truncate_cell(value, widths[index]) for index, value in enumerate(row)]
        for row in values
    ]
    lines: list[str] = []
    if table.title:
        lines.append(table.title)
    # Render header and separator rows before body rows; per-cell styling is
    # applied after alignment so ANSI escape codes do not affect width math.
    lines.append(
        "  ".join(
            style_table_header(
                align_text(truncate_cell(column.heading, widths[index]), widths[index], column.align),
                style_getter,
            )
            for index, column in enumerate(table.columns)
        )
    )
    lines.append("  ".join(style_table_header("-" * width, style_getter) for width in widths))
    lines.extend(
        "  ".join(
            style_table_cell(
                align_text(value, widths[index], table.columns[index].align),
                "",
                style_getter,
                column_index=index,
                row_subject="",
            )
            for index, value in enumerate(row)
        )
        for row in values
    )
    return "\n".join(lines)


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


def render_docx_table(table: Table) -> bytes:
    """Render a DOCX document containing one table."""
    try:
        # Optional exporters are imported lazily so the core CLI remains light
        # unless a user actually asks for DOCX output.
        document_class = importlib.import_module("docx").Document
    except ImportError as exc:  # pragma: no cover - depends on optional package
        raise RuntimeError("DOCX rendering requires python-docx") from exc
    document = document_class()
    if table.title:
        document.add_heading(table.title, level=1)
    doc_table = document.add_table(rows=1, cols=len(table.columns))
    header = doc_table.rows[0].cells
    for index, column in enumerate(table.columns):
        header[index].text = column.heading
    for row in table_values(table):
        cells = doc_table.add_row().cells
        for index, value in enumerate(row):
            cells[index].text = value
    stream = io.BytesIO()
    document.save(stream)
    return stream.getvalue()


def render_xlsx_table(table: Table) -> bytes:
    """Render an XLSX workbook containing one worksheet table."""
    try:
        # Keep openpyxl optional for the same reason as DOCX rendering: most
        # operator workflows only need console/Markdown/CSV output.
        workbook_class = importlib.import_module("openpyxl").Workbook
        font_class = importlib.import_module("openpyxl.styles").Font
    except ImportError as exc:  # pragma: no cover - depends on optional package
        raise RuntimeError("XLSX rendering requires openpyxl") from exc
    workbook = workbook_class()
    worksheet = cast(Any, workbook.active)
    worksheet.title = safe_sheet_title(table.title or "Bywaf Table")
    worksheet.append([column.heading for column in table.columns])
    for cell in worksheet[1]:
        cell.font = font_class(bold=True)
    for row in table_values(table):
        worksheet.append(row)
    stream = io.BytesIO()
    workbook.save(stream)
    return stream.getvalue()


def align_text(value: str, width: int, align: Align) -> str:
    """Align one text cell."""
    aligner = {"right": str.rjust, "center": str.center}.get(align, str.ljust)
    return aligner(value, width)


def markdown_alignment(align: Align) -> str:
    """Return one Markdown alignment marker."""
    return {"right": "---:", "center": ":---:"}.get(align, "---")


def escape_markdown_cell(value: str) -> str:
    """Escape Markdown table separators inside a cell."""
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>")


def safe_sheet_title(title: str) -> str:
    """Return an Excel-compatible worksheet title."""
    safe = "".join("_" if char in "[]:*?/\\\\" else char for char in title).strip()
    return (safe or "Bywaf Table")[:31]
