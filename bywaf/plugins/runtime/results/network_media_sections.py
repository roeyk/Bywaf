"""Screenshot and route result sections for the results command.

Used by: `runtime.results.network_sections` to keep the public section import
surface stable while separating artifact-heavy and route-hop renderers from
basic host/port/service sections.
"""

from __future__ import annotations

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width


def render_screenshots_section(context: CommandContext, events: list[Event]) -> str:
    """Render screenshot artifact references as a compact result table."""
    # Screenshot events may include several URLs and artifact records; keep the
    # table scannable by showing the first URLs, screenshot count, and compact
    # artifact references.
    rows = [
        (
            event.payload.get("host", ""),
            ", ".join(str(url) for url in event.payload.get("urls", [])[:2]),
            len(event.payload.get("screenshots", [])),
            screenshot_artifact_refs(event),
            event.payload.get("tool", ""),
        )
        for event in sorted(
            events, key=lambda event: (str(event.payload.get("host") or ""), event.id or 0)
        )
    ]
    table = render_table(
        ("HOST", "URLS", "SHOTS", "ARTIFACTS", "TOOL"),
        rows,
        cell_subjects=("host", "url", "", "artifact", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Screenshots ({len(events)})\n{table}"


def screenshot_artifact_refs(event: Event) -> str:
    """Return compact artifact references for one screenshot event."""
    refs: list[str] = []
    screenshots = event.payload.get("screenshots", [])
    if not isinstance(screenshots, list):
        return ""
    for screenshot in screenshots:
        if not isinstance(screenshot, dict):
            continue
        ref = screenshot.get("artifact_id") or screenshot.get("artifact") or screenshot.get("path")
        if ref:
            refs.append(str(ref))
    return ", ".join(refs)


def render_route_hops_section(context: CommandContext, events: list[Event]) -> str:
    """Render route traces as a compact result table."""
    rows = [
        (
            event.payload.get("target", ""),
            event.payload.get("hop", ""),
            event.payload.get("host", "") or event.payload.get("status", ""),
            event.payload.get("ip", ""),
            format_rtt(event.payload.get("rtt_ms")),
        )
        for event in sorted(
            events,
            key=lambda event: (
                str(event.payload.get("target") or ""),
                int(event.payload.get("hop") or 0),
                event.id or 0,
            ),
        )
    ]
    table = render_table(
        ("TARGET", "HOP", "HOST / STATUS", "IP", "RTT"),
        rows,
        cell_subjects=("host", "step", "host", "host", "value"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Route hops ({len(events)})\n{table}"


def format_rtt(value: object) -> str:
    """Format one route hop round-trip time."""
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)):
        return f"{value:g} ms"
    return str(value)
