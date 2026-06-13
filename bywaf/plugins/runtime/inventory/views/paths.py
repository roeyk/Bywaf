"""Inventory renderer for paths facts.

Used by:
- runtime commandlets and REPL display paths that present persisted jobs,
  events, inventory, or result state.
- tests and future plugins that need stable runtime helper behavior.
"""

from __future__ import annotations

from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime.display import command_context_style_getter, render_table, terminal_table_width

from .shared import host_sort_value, sort_note, split_sort


def render_paths_inventory(context: CommandContext, events: list[Event], scope: str, sort: str = "host") -> str:
    """Render HTTP path inventory.

    Called by: runtime inventory commandlets for the `paths` view.
    """
    path_events = [event for event in events if event.topic == "http.path"]
    if not path_events:
        return "Paths: no path inventory"
    sort_key, descending = split_sort(sort, "host")
    # Interesting paths are already classified by the probing plugin; inventory
    # only presents that fact without promoting it to a finding.
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("path", ""),
            event.payload.get("status", ""),
            "yes" if event.payload.get("interesting") else "",
            event.payload.get("url", ""),
        )
        for event in sorted(path_events, key=lambda event: path_sort_key(event, sort_key), reverse=descending)
    ]
    table = render_table(
        ("HOST", "PATH", "STATUS", "INTERESTING", "URL"),
        rows,
        cell_subjects=("host", "url", "status", "status", "url"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Paths: {scope} ({len(rows)} paths)\n{sort_note(sort, 'host')}\n{table}"

def path_sort_key(event: Event, key: str) -> Any:
    """Return a sortable path event value.

    Called by: `render_paths_inventory()`.
    """
    payload = event.payload
    if key == "path":
        return (str(payload.get("path") or ""), host_sort_value(str(payload.get("host") or "")))
    if key == "status":
        return (str(payload.get("status") or ""), host_sort_value(str(payload.get("host") or "")))
    if key == "url":
        return str(payload.get("url") or "")
    return (host_sort_value(str(payload.get("host") or "")), str(payload.get("path") or ""))

def path_event_keys(event: Event) -> set[tuple[str, str]]:
    """Return stable HTTP path identity keys for one event.

    Called by: inventory delta/key helpers.
    """
    if event.topic != "http.path":
        return set()
    url = str(event.payload.get("url") or "")
    return {("path", url)} if url else set()
