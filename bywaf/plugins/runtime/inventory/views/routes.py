"""Inventory renderer for routes facts."""

from __future__ import annotations

from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

from .shared import host_sort_value, sort_note, split_sort


def render_routes_inventory(context: CommandContext, events: list[Event], scope: str, sort: str = "target") -> str:
    """Render route hop inventory.

    Called by: runtime inventory commandlets for the `routes` view.
    """
    route_events = [event for event in events if event.topic == "network.route.hop"]
    if not route_events:
        return "Routes: no route inventory"
    sort_key, descending = split_sort(sort, "target")
    # Route events describe hop-by-hop observations. Missing hosts are shown as
    # status text so failed/time-out hops remain visible.
    rows = [
        (
            event.payload.get("target", ""),
            event.payload.get("hop", ""),
            event.payload.get("host", "") or event.payload.get("status", ""),
            event.payload.get("ip", ""),
            format_rtt(event.payload.get("rtt_ms")),
        )
        for event in sorted(route_events, key=lambda event: route_sort_key(event, sort_key), reverse=descending)
    ]
    table = render_table(
        ("TARGET", "HOP", "HOST / STATUS", "IP", "RTT"),
        rows,
        cell_subjects=("host", "step", "host", "host", "value"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Routes: {scope} ({len(rows)} hops)\n{sort_note(sort, 'target')}\n{table}"

def route_sort_key(event: Event, key: str) -> Any:
    """Return a sortable route event value.

    Called by: `render_routes_inventory()`.
    """
    payload = event.payload
    if key == "hop":
        return (int(payload.get("hop") or 0), str(payload.get("target") or ""))
    if key == "host":
        return (host_sort_value(str(payload.get("host") or "")), str(payload.get("target") or ""))
    if key == "ip":
        return (host_sort_value(str(payload.get("ip") or "")), str(payload.get("target") or ""))
    if key == "rtt":
        return (float(payload.get("rtt_ms") or 0), str(payload.get("target") or ""))
    return (str(payload.get("target") or ""), int(payload.get("hop") or 0))

def format_rtt(value: object) -> str:
    """Format a route hop round-trip value.

    Called by: route inventory and result renderers.
    """
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)):
        return f"{value:g} ms"
    return str(value)

def route_event_keys(event: Event) -> set[tuple[str, str, int]]:
    """Return stable route hop identity keys for one event.

    Called by: inventory delta/key helpers.
    """
    if event.topic != "network.route.hop":
        return set()
    target = str(event.payload.get("target") or "")
    hop = int(event.payload.get("hop") or 0)
    return {("route", target, hop)} if target and hop else set()
