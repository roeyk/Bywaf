"""Console table rendering.

Used by: `rendering.exporters.render_table()` and REPL/runtime display code
when tables need terminal-width-aware, monospaced output.
"""

from __future__ import annotations

from .model import Align, Table, table_values


def render_console_table(table: Table, style_getter=None) -> str:
    """Render a table for monospaced terminal output."""
    if not table.columns:
        return table.title or ""
    from ..runtime.display import shrink_table_widths, style_table_cell, style_table_header, terminal_table_width, truncate_cell

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


def align_text(value: str, width: int, align: Align) -> str:
    """Align one text cell."""
    aligner = {"right": str.rjust, "center": str.center}.get(align, str.ljust)
    return aligner(value, width)
