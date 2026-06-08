"""Generic console table rendering primitives.

Provides Column, Table, and renderer helpers for aligned terminal output without
coupling callers to a specific UI framework.

Used by:
- REPL display and runtime commandlets: render inspectable tabular output.
- tests: verify stable formatting for command output."""


from __future__ import annotations

import csv
import html
import importlib
import io
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

TableFormat = Literal["console", "md", "csv", "jsonl", "html", "docx", "xlsx"]
Align = Literal["left", "right", "center"]


@dataclass(frozen=True, slots=True)
class Column:
    """One display column in a structured table.

    This represents stable presentation metadata for one row key.
    Constructed by: commandlets, report renderers, `Table.from_rows()`, and
    `Table.from_payload()`.
    Used by: `Table`, `normalize_columns()`, and the format renderers when
    producing console, Markdown, CSV, JSONL, HTML, DOCX, or XLSX output.
    """

    key: str
    title: str | None = None
    align: Align = "left"

    @property
    def heading(self) -> str:
        """Return the visible table heading."""
        return self.title or self.key


@dataclass(frozen=True, slots=True)
class Table:
    """Structured tabular data that can be rendered in several formats.

    This represents display-ready rows independently of the final output format.
    Constructed by: runtime commandlets, reports, `Table.from_rows()`, and
    `Table.from_payload()`.
    Used by: `ContextRender.table()`, `handle_render_table_request()`, and the
    `render_*_table()` functions. `to_payload()`/`from_payload()` carry it
    across the plugin/framework event boundary.
    """

    columns: tuple[Column, ...]
    rows: tuple[Mapping[str, object], ...]
    title: str | None = None

    @classmethod
    def from_rows(
        cls,
        rows: Iterable[Mapping[str, object] | Sequence[object]],
        columns: Sequence[str | Column] | None = None,
        *,
        title: str | None = None,
    ) -> "Table":
        """Build a table from mapping rows or positional sequence rows.

        Called by: commandlets and reports that have row data but do not need to
        manually construct `Column` objects.
        """
        normalized_rows = tuple(rows)
        normalized_columns = normalize_columns(columns, normalized_rows)
        mapped_rows = tuple(map_row(row, normalized_columns) for row in normalized_rows)
        return cls(normalized_columns, mapped_rows, title=title)

    def to_payload(self) -> dict[str, object]:
        """Return a JSON-safe payload for framework request events.

        Called by: `ContextRender.table()` before sending a render request
        through the event boundary.
        """
        # Tables can cross the plugin/framework boundary as events. Keep the
        # payload simple so commandlets can request rendering without importing
        # terminal-specific code.
        return {
            "title": self.title,
            "columns": [
                {"key": column.key, "title": column.title, "align": column.align}
                for column in self.columns
            ],
            "rows": [
                {key: json_safe_value(value) for key, value in row.items()}
                for row in self.rows
            ],
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> "Table":
        """Build a table from a framework request payload.

        Called by: `handle_render_table_request()` when the framework services
        a plugin render request.
        """
        raw_columns = payload.get("columns", ())
        if not isinstance(raw_columns, Sequence):
            raise ValueError("table columns must be a sequence")
        columns: list[Column] = []
        for raw_column in raw_columns:
            if not isinstance(raw_column, Mapping):
                raise ValueError("table column entries must be objects")
            key = raw_column.get("key")
            if not isinstance(key, str) or not key:
                raise ValueError("table column key must be a non-empty string")
            title = raw_column.get("title")
            align = raw_column.get("align", "left")
            if title is not None and not isinstance(title, str):
                raise ValueError("table column title must be a string")
            if align not in {"left", "right", "center"}:
                raise ValueError("table column align must be left, right, or center")
            columns.append(Column(key, title, align))  # type: ignore[arg-type]
        raw_rows = payload.get("rows", ())
        if not isinstance(raw_rows, Sequence):
            raise ValueError("table rows must be a sequence")
        rows: list[Mapping[str, object]] = []
        for raw_row in raw_rows:
            if not isinstance(raw_row, Mapping):
                raise ValueError("table row entries must be objects")
            rows.append({str(key): value for key, value in raw_row.items()})
        title = payload.get("title")
        if title is not None and not isinstance(title, str):
            raise ValueError("table title must be a string")
        return cls(tuple(columns), tuple(rows), title=title)


TableRenderer = Callable[[Table], str | bytes]


def normalize_columns(
    columns: Sequence[str | Column] | None,
    rows: Sequence[Mapping[str, object] | Sequence[object]],
) -> tuple[Column, ...]:
    """Return normalized column metadata for rows."""
    if columns is not None:
        return tuple(column if isinstance(column, Column) else Column(str(column)) for column in columns)
    if not rows:
        return ()
    first = rows[0]
    if isinstance(first, Mapping):
        return tuple(Column(str(key)) for key in first.keys())
    return tuple(Column(str(index)) for index in range(len(first)))


def map_row(row: Mapping[str, object] | Sequence[object], columns: Sequence[Column]) -> Mapping[str, object]:
    """Return a mapping row keyed by normalized column names."""
    if isinstance(row, Mapping):
        return {column.key: row.get(column.key, "") for column in columns}
    return {
        column.key: row[index] if index < len(row) else ""
        for index, column in enumerate(columns)
    }


def json_safe_value(value: object) -> object:
    """Return a value safe for JSON event payloads."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    return str(value)


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


def table_values(table: Table) -> list[list[str]]:
    """Return display values for a table."""
    return [
        [value_to_text(row.get(column.key, "")) for column in table.columns]
        for row in table.rows
    ]


def value_to_text(value: object) -> str:
    """Return a compact display string for one table cell."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


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
