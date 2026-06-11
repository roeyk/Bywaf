"""File-share result sections for the results command."""

from __future__ import annotations

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width


def render_smb_shares_section(context: CommandContext, events: list[Event]) -> str:
    """Render SMB shares as a compact result table."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("share", ""),
            event.payload.get("access", ""),
            format_bool(event.payload.get("authenticated")),
            event.payload.get("remark", ""),
        )
        for event in sorted(
            events,
            key=lambda event: (
                str(event.payload.get("host") or ""),
                str(event.payload.get("share") or ""),
                event.id or 0,
            ),
        )
    ]
    table = render_table(
        ("HOST", "SHARE", "ACCESS", "AUTH", "REMARK"),
        rows,
        cell_subjects=("host", "value", "status", "", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"SMB shares ({len(events)})\n{table}"


def format_bool(value: object) -> str:
    """Format optional bools for result tables."""
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return ""
