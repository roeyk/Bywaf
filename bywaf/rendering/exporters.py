"""Output-format renderers for structured tables.

Used by: `bywaf.rendering` as the stable facade for console, text, HTML, DOCX,
and XLSX table export helpers.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from .console import align_text as align_text
from .console import render_console_table as render_console_table
from .model import Table
from .office_exporters import render_docx_table as render_docx_table
from .office_exporters import render_xlsx_table as render_xlsx_table
from .office_exporters import safe_sheet_title as safe_sheet_title
from .text_exporters import escape_markdown_cell as escape_markdown_cell
from .text_exporters import markdown_alignment as markdown_alignment
from .text_exporters import render_csv_table as render_csv_table
from .text_exporters import render_html_table as render_html_table
from .text_exporters import render_jsonl_table as render_jsonl_table
from .text_exporters import render_markdown_table as render_markdown_table

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
