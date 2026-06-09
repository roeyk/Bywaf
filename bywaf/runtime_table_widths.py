"""Width and truncation helpers for runtime table rendering.

Used by:
- `runtime_tables.render_table()`: fit runtime tables to the active terminal.
- Console/report renderers: share the same shrink/truncate behavior when they
  render richer table objects outside the simple runtime-table helper.
"""

from __future__ import annotations

import shutil
from collections.abc import Sequence


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
