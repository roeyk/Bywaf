"""Generic console table rendering primitives.

Provides Column, Table, and renderer helpers for aligned terminal output without
coupling callers to a specific UI framework.

Used by:
- REPL display and runtime commandlets: render inspectable tabular output.
- tests: verify stable formatting for command output.
"""

from __future__ import annotations

from .rendering_exporters import (
    TableFormat,
    TableRenderer,
    align_text,
    escape_markdown_cell,
    markdown_alignment,
    render_console_table,
    render_csv_table,
    render_docx_table,
    render_html_table,
    render_jsonl_table,
    render_markdown_table,
    render_table,
    render_xlsx_table,
    safe_sheet_title,
    table_renderers,
)
from .rendering_model import (
    Align,
    Column,
    Table,
    json_safe_value,
    map_row,
    normalize_columns,
    table_values,
    value_to_text,
)

__all__ = [
    "Align",
    "Column",
    "Table",
    "TableFormat",
    "TableRenderer",
    "align_text",
    "escape_markdown_cell",
    "json_safe_value",
    "map_row",
    "markdown_alignment",
    "normalize_columns",
    "render_console_table",
    "render_csv_table",
    "render_docx_table",
    "render_html_table",
    "render_jsonl_table",
    "render_markdown_table",
    "render_table",
    "render_xlsx_table",
    "safe_sheet_title",
    "table_renderers",
    "table_values",
    "value_to_text",
]
