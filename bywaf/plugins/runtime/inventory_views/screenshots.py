"""Inventory renderer for screenshots facts."""

from __future__ import annotations

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

from .shared import add_value, host_sort_value, join_values, sort_note, split_sort


def render_screenshots_inventory(context: CommandContext, events: list[Event], scope: str, sort: str = "host") -> str:
    """Render screenshot artifact inventory."""
    screenshot_events = [event for event in events if event.topic == "web.screenshotted_host"]
    if not screenshot_events:
        return "Screenshots: no screenshot inventory"
    sort_key, descending = split_sort(sort, "host")
    rows = [
        (
            event.payload.get("host", ""),
            ", ".join(str(url) for url in event.payload.get("urls", [])[:2]),
            len(event.payload.get("screenshots", [])),
            screenshot_refs(event),
            event.payload.get("tool", ""),
        )
        for event in sorted(screenshot_events, key=lambda event: screenshot_sort_key(event, sort_key), reverse=descending)
    ]
    table = render_table(
        ("HOST", "URLS", "SHOTS", "ARTIFACTS", "TOOL"),
        rows,
        cell_subjects=("host", "url", "", "artifact", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Screenshots: {scope} ({len(rows)} hosts)\n{sort_note(sort, 'host')}\n{table}"

def screenshot_sort_key(event: Event, key: str) -> object:
    """Return a sortable screenshot event value."""
    payload = event.payload
    if key == "shots":
        return (len(payload.get("screenshots", [])), host_sort_value(str(payload.get("host") or "")))
    if key == "tool":
        return (str(payload.get("tool") or ""), host_sort_value(str(payload.get("host") or "")))
    return (host_sort_value(str(payload.get("host") or "")), event.id or 0)

def screenshot_refs(event: Event) -> str:
    """Return compact screenshot artifact references."""
    refs: set[str] = set()
    screenshots = event.payload.get("screenshots", [])
    if not isinstance(screenshots, list):
        return ""
    for screenshot in screenshots:
        if isinstance(screenshot, dict):
            add_value(refs, screenshot.get("artifact_id") or screenshot.get("path"))
    return join_values(refs)

def screenshot_event_keys(event: Event) -> set[tuple[str, str]]:
    """Return stable screenshot identity keys for one event."""
    if event.topic != "web.screenshotted_host":
        return set()
    host = str(event.payload.get("host") or "")
    return {("screenshot", host)} if host else set()
