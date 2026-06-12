"""Inventory renderer for banners facts."""

from __future__ import annotations

from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

from .shared import host_sort_value, sort_note, split_sort


def render_banners_inventory(context: CommandContext, events: list[Event], scope: str, sort: str = "host") -> str:
    """Render TCP banner inventory.

    Called by: runtime inventory commandlets for the `banners` view.
    """
    banner_events = [event for event in events if event.topic == "tcp.banner"]
    if not banner_events:
        return "Banners: no banner inventory"
    sort_key, descending = split_sort(sort, "host")
    # Rows are derived directly from tcp.banner facts; errors are shown in the
    # same column as banner text because both describe probe output.
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("port", ""),
            event.payload.get("banner", "") or event.payload.get("error", ""),
        )
        for event in sorted(banner_events, key=lambda event: banner_sort_key(event, sort_key), reverse=descending)
    ]
    table = render_table(
        ("HOST", "PORT", "BANNER / ERROR"),
        rows,
        cell_subjects=("host", "port", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Banners: {scope} ({len(rows)} banners)\n{sort_note(sort, 'host')}\n{table}"

def banner_sort_key(event: Event, key: str) -> Any:
    """Return a sortable banner event value.

    Called by: `render_banners_inventory()`.
    """
    payload = event.payload
    if key == "port":
        return (int(payload.get("port") or 0), host_sort_value(str(payload.get("host") or "")))
    return (host_sort_value(str(payload.get("host") or "")), int(payload.get("port") or 0))

def banner_event_keys(event: Event) -> set[tuple[str, str, int]]:
    """Return stable banner identity keys for one event.

    Called by: inventory delta/key helpers.
    """
    if event.topic != "tcp.banner":
        return set()
    host = str(event.payload.get("host") or "")
    port = int(event.payload.get("port") or 0)
    return {("banner", host, port)} if host and port else set()
