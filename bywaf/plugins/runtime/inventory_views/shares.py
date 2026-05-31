"""Inventory renderer for shares facts."""

from __future__ import annotations

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

from .shared import host_sort_value, sort_note, split_sort


def render_shares_inventory(context: CommandContext, events: list[Event], scope: str, sort: str = "host") -> str:
    """Render SMB share inventory."""
    share_events = [event for event in events if event.topic == "smb.share.found"]
    if not share_events:
        return "Shares: no share inventory"
    sort_key, descending = split_sort(sort, "host")
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("share", ""),
            event.payload.get("access", ""),
            "yes" if event.payload.get("authenticated") is True else "no" if event.payload.get("authenticated") is False else "",
            event.payload.get("remark", ""),
        )
        for event in sorted(share_events, key=lambda event: share_sort_key(event, sort_key), reverse=descending)
    ]
    table = render_table(
        ("HOST", "SHARE", "ACCESS", "AUTH", "REMARK"),
        rows,
        cell_subjects=("host", "value", "status", "", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Shares: {scope} ({len(rows)} shares)\n{sort_note(sort, 'host')}\n{table}"

def share_sort_key(event: Event, key: str) -> object:
    """Return a sortable share event value."""
    payload = event.payload
    if key == "share":
        return (str(payload.get("share") or ""), host_sort_value(str(payload.get("host") or "")))
    if key == "access":
        return (str(payload.get("access") or ""), host_sort_value(str(payload.get("host") or "")))
    return (host_sort_value(str(payload.get("host") or "")), str(payload.get("share") or ""))

def share_event_keys(event: Event) -> set[tuple[str, str, str]]:
    """Return stable share inventory identity keys for one event."""
    if event.topic != "smb.share.found":
        return set()
    host = str(event.payload.get("host") or "")
    share = str(event.payload.get("share") or "")
    return {("share", host, share)} if host and share else set()
