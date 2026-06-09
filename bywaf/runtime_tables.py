"""Shared console table rendering helpers for runtime views."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from .runtime_table_widths import shrink_table_widths, truncate_cell
from .style import styled_subject_text, subject_style

StyleGetter = Callable[[str, str], object]
TextRows = list[list[str]]


def render_table(
    headers: tuple[str, ...],
    rows: Sequence[Sequence[object]],
    *,
    cell_subjects: Sequence[str] = (),
    row_subjects: Sequence[str] = (),
    active_column_indexes: Sequence[int] = (),
    style_getter: StyleGetter | None = None,
    max_width: int | None = None,
) -> str:
    """Render a small table, optionally styling aligned cells by subject."""
    if not rows:
        return ""
    # Rendering is a four-phase transformation: normalize values to strings,
    # calculate column widths, optionally shrink/truncate to the terminal, then
    # apply styles after padding so ANSI escape codes do not affect alignment.
    text_rows = table_text_rows(rows)
    widths = table_widths(headers, text_rows)
    if max_width is not None:
        widths = shrink_table_widths(widths, headers, max_width)
        text_rows = truncated_rows(text_rows, widths)
    return "\n".join(
        [
            *table_header_lines(headers, widths, style_getter),
            *table_body_lines(
                text_rows,
                widths,
                cell_subjects,
                row_subjects,
                active_column_indexes,
                style_getter,
            ),
        ]
    )


def table_text_rows(rows: Sequence[Sequence[object]]) -> TextRows:
    """Return table row values normalized to display strings."""
    return [[str(value) if value is not None else "" for value in row] for row in rows]


def table_widths(headers: tuple[str, ...], text_rows: TextRows) -> list[int]:
    """Return the natural display width for each table column."""
    return [
        max(len(header), *(len(row[index]) for row in text_rows))
        for index, header in enumerate(headers)
    ]


def truncated_rows(text_rows: TextRows, widths: Sequence[int]) -> TextRows:
    """Return rows with cells truncated to their already-computed widths."""
    return [[truncate_cell(value, widths[index]) for index, value in enumerate(row)] for row in text_rows]


def table_header_lines(
    headers: tuple[str, ...],
    widths: Sequence[int],
    style_getter: StyleGetter | None,
) -> list[str]:
    """Return the styled header and ruler lines for a runtime table."""
    # Header/ruler rows are built before body rows so the styling code can keep
    # column subjects separate from row subjects.
    return [
        "  ".join(
            style_table_header(
                truncate_cell(header, widths[index]).ljust(widths[index]),
                style_getter,
            )
            for index, header in enumerate(headers)
        ),
        "  ".join(style_table_header("-" * width, style_getter) for width in widths),
    ]


def table_body_lines(
    text_rows: TextRows,
    widths: Sequence[int],
    cell_subjects: Sequence[str],
    row_subjects: Sequence[str],
    active_column_indexes: Sequence[int],
    style_getter: StyleGetter | None,
) -> list[str]:
    """Return styled body lines for a runtime table."""
    return [
        table_body_line(
            row,
            widths,
            cell_subjects,
            row_subjects[row_index] if row_index < len(row_subjects) else "",
            active_column_indexes,
            style_getter,
        )
        for row_index, row in enumerate(text_rows)
    ]


def table_body_line(
    row: Sequence[str],
    widths: Sequence[int],
    cell_subjects: Sequence[str],
    row_subject: str,
    active_column_indexes: Sequence[int],
    style_getter: StyleGetter | None,
) -> str:
    """Return one styled body line for a runtime table."""
    # The row subject is resolved once, then each padded cell can combine its
    # column subject with active-row/active-column state.
    return "  ".join(
        style_table_cell(
            value.ljust(widths[index]),
            cell_subjects[index] if index < len(cell_subjects) else "",
            style_getter,
            column_index=index,
            row_subject=row_subject,
            active_column=bool(row_subject) and index in active_column_indexes,
        )
        for index, value in enumerate(row)
    )


def style_table_header(value: str, style_getter: StyleGetter | None) -> str:
    """Apply the configured table-heading style to one header/ruler cell."""
    if style_getter is None or not value.strip():
        return value
    return styled_subject_text(style_getter, "table.header", value)


def style_table_cell(
    value: str,
    subject: str,
    style_getter: StyleGetter | None,
    *,
    column_index: int,
    row_subject: str = "",
    active_column: bool = False,
) -> str:
    """Apply a subject style to a padded table cell when configured."""
    if style_getter is None or not value.strip():
        return value
    cell_subject = table_cell_subject(
        subject,
        style_getter,
        column_index=column_index,
        row_subject=row_subject,
        active_column=active_column,
    )
    return styled_subject_text(style_getter, cell_subject, value) if cell_subject else value


def table_cell_subject(
    subject: str,
    style_getter: StyleGetter,
    *,
    column_index: int,
    row_subject: str = "",
    active_column: bool = False,
) -> str:
    """Return the most specific configured style subject for a table cell."""
    if active_column and subject_style(style_getter, "table.active_column"):
        return "table.active_column"
    if row_subject and subject_style(style_getter, row_subject):
        return row_subject
    if subject and subject_style(style_getter, subject):
        return subject
    if column_index == 0 and subject_style(style_getter, "table.index"):
        return "table.index"
    if subject_style(style_getter, "table.body"):
        return "table.body"
    return subject
