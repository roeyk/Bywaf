"""Shared text section helpers for metrics report renderers.

Used by:
- maintainers measuring coupling, complexity, documentation pressure, and
  release-readiness signals.
- CI/manual validation runs that track architecture drift.
"""

from __future__ import annotations

from collections.abc import Iterable


def section(title: str, rows: Iterable[tuple[str, int]], unit: str) -> str:
    """Format one ranked metric section.

    Called by: source and documentation metrics report builders.
    """
    lines = [f"{title}:"]
    for name, value in rows:
        lines.append(f"- {value:>4} {unit}  {name}")
    return "\n".join(lines)


def detail_section(title: str, rows: Iterable[tuple[str, str]]) -> str:
    """Format a ranked section whose value has several compact dimensions.

    Called by: report builders for multi-field rows such as link coupling or
    documentation-pressure summaries.
    """
    lines = [f"{title}:"]
    for name, value in rows:
        lines.append(f"- {value}  {name}")
    return "\n".join(lines)
