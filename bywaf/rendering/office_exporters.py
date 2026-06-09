"""Optional Office table exporters.

Used by: `rendering.exporters.render_table()` for DOCX and XLSX output. These
imports stay lazy so common CLI workflows do not require optional packages.
"""

from __future__ import annotations

import importlib
import io
from typing import Any, cast

from .model import Table, table_values


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


def safe_sheet_title(title: str) -> str:
    """Return an Excel-compatible worksheet title."""
    safe = "".join("_" if char in "[]:*?/\\\\" else char for char in title).strip()
    return (safe or "Bywaf Table")[:31]
