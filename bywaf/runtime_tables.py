"""Shared console table rendering helpers for runtime views."""

from __future__ import annotations

import shutil
from collections.abc import Callable, Sequence

from .style import styled_subject_text, subject_style

StyleGetter = Callable[[str, str], object]


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
    text_rows = [[str(value) if value is not None else "" for value in row] for row in rows]
    widths = [
        max(len(header), *(len(row[index]) for row in text_rows))
        for index, header in enumerate(headers)
    ]
    if max_width is not None:
        widths = shrink_table_widths(widths, headers, max_width)
        text_rows = [[truncate_cell(value, widths[index]) for index, value in enumerate(row)] for row in text_rows]
    # Header/ruler rows are built before body rows so the styling code can keep
    # column subjects separate from row subjects.
    lines = [
        "  ".join(
            style_table_header(
                truncate_cell(header, widths[index]).ljust(widths[index]),
                style_getter,
            )
            for index, header in enumerate(headers)
        ),
        "  ".join(style_table_header("-" * width, style_getter) for width in widths),
    ]
    lines.extend(
        # Each generated body row computes its row subject once, then styles
        # individual padded cells by column subject and active-row state.
        "  ".join(
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
        for row_index, row in enumerate(text_rows)
        for row_subject in (row_subjects[row_index] if row_index < len(row_subjects) else "",)
    )
    return "\n".join(lines)


def terminal_table_width(fallback: int = 100) -> int:
    """Return the current terminal width for view-command tables."""
    return shutil.get_terminal_size(fallback=(fallback, 24)).columns


def shrink_table_widths(widths: list[int], headers: Sequence[str], max_width: int) -> list[int]:
    """Shrink wide columns until a table fits the requested display width."""
    if not widths:
        return widths
    # Account for the two-space separators before comparing column widths
    # against the display budget.
    available = max(1, max_width - (2 * (len(widths) - 1)))
    minimums = [min(max(len(header), 3), width) for header, width in zip(headers, widths)]
    if available < sum(minimums):
        # When even minimum widths do not fit, distribute the tiny remaining
        # budget to the originally widest columns so the most informative cells
        # get the most room.
        compressed = [1] * len(widths)
        remaining = max(0, available - len(compressed))
        for index in sorted(range(len(widths)), key=lambda item: widths[item], reverse=True):
            if remaining <= 0:
                break
            room = max(0, min(widths[index], minimums[index]) - compressed[index])
            growth = min(room, remaining)
            compressed[index] += growth
            remaining -= growth
        return compressed
    shrunk = list(widths)
    while sum(shrunk) > available:
        # Repeatedly trim the column with the most room above its minimum. This
        # keeps narrow/key columns readable while wide free-text columns absorb
        # most of the truncation.
        candidates = [index for index, width in enumerate(shrunk) if width > minimums[index]]
        if not candidates:
            break
        index = max(candidates, key=lambda candidate: shrunk[candidate] - minimums[candidate])
        shrunk[index] -= 1
    return shrunk


def truncate_cell(value: str, width: int) -> str:
    """Trim one table cell to width, preserving a visible ellipsis."""
    if len(value) <= width:
        return value
    if width <= 1:
        return value[:width]
    return value[: width - 1] + "…"


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
