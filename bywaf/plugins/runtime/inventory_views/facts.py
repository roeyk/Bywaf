"""Single-topic inventory renderers and identity keys."""

from __future__ import annotations

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

from .shared import add_value, join_values

def render_shares_inventory(context: CommandContext, events: list[Event], scope: str) -> str:
    """Render SMB share inventory."""
    share_events = [event for event in events if event.topic == "smb.share.found"]
    if not share_events:
        return "Shares: no share inventory"
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("share", ""),
            event.payload.get("access", ""),
            "yes" if event.payload.get("authenticated") is True else "no" if event.payload.get("authenticated") is False else "",
            event.payload.get("remark", ""),
        )
        for event in sorted(share_events, key=lambda event: (str(event.payload.get("host") or ""), str(event.payload.get("share") or "")))
    ]
    table = render_table(
        ("HOST", "SHARE", "ACCESS", "AUTH", "REMARK"),
        rows,
        cell_subjects=("host", "value", "status", "", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Shares: {scope} ({len(rows)} shares)\n{table}"

def render_routes_inventory(context: CommandContext, events: list[Event], scope: str) -> str:
    """Render route hop inventory."""
    route_events = [event for event in events if event.topic == "network.route.hop"]
    if not route_events:
        return "Routes: no route inventory"
    rows = [
        (
            event.payload.get("target", ""),
            event.payload.get("hop", ""),
            event.payload.get("host", "") or event.payload.get("status", ""),
            event.payload.get("ip", ""),
            format_rtt(event.payload.get("rtt_ms")),
        )
        for event in sorted(route_events, key=lambda event: (str(event.payload.get("target") or ""), int(event.payload.get("hop") or 0)))
    ]
    table = render_table(
        ("TARGET", "HOP", "HOST / STATUS", "IP", "RTT"),
        rows,
        cell_subjects=("host", "step", "host", "host", "value"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Routes: {scope} ({len(rows)} hops)\n{table}"

def render_certs_inventory(context: CommandContext, events: list[Event], scope: str) -> str:
    """Render TLS certificate inventory."""
    cert_events = [event for event in events if event.topic == "tls.certificate"]
    if not cert_events:
        return "Certificates: no certificate inventory"
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("port", ""),
            event.payload.get("subject", ""),
            event.payload.get("issuer", ""),
            event.payload.get("not_after", ""),
        )
        for event in sorted(cert_events, key=lambda event: (str(event.payload.get("host") or ""), int(event.payload.get("port") or 0)))
    ]
    table = render_table(
        ("HOST", "PORT", "SUBJECT", "ISSUER", "VALID UNTIL"),
        rows,
        cell_subjects=("host", "port", "", "", "value"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Certificates: {scope} ({len(rows)} certificates)\n{table}"

def render_banners_inventory(context: CommandContext, events: list[Event], scope: str) -> str:
    """Render TCP banner inventory."""
    banner_events = [event for event in events if event.topic == "tcp.banner"]
    if not banner_events:
        return "Banners: no banner inventory"
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("port", ""),
            event.payload.get("banner", "") or event.payload.get("error", ""),
        )
        for event in sorted(banner_events, key=lambda event: (str(event.payload.get("host") or ""), int(event.payload.get("port") or 0)))
    ]
    table = render_table(
        ("HOST", "PORT", "BANNER / ERROR"),
        rows,
        cell_subjects=("host", "port", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Banners: {scope} ({len(rows)} banners)\n{table}"

def render_paths_inventory(context: CommandContext, events: list[Event], scope: str) -> str:
    """Render HTTP path inventory."""
    path_events = [event for event in events if event.topic == "http.path"]
    if not path_events:
        return "Paths: no path inventory"
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("path", ""),
            event.payload.get("status", ""),
            "yes" if event.payload.get("interesting") else "",
            event.payload.get("url", ""),
        )
        for event in sorted(path_events, key=lambda event: (str(event.payload.get("host") or ""), str(event.payload.get("path") or "")))
    ]
    table = render_table(
        ("HOST", "PATH", "STATUS", "INTERESTING", "URL"),
        rows,
        cell_subjects=("host", "url", "status", "status", "url"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Paths: {scope} ({len(rows)} paths)\n{table}"

def render_screenshots_inventory(context: CommandContext, events: list[Event], scope: str) -> str:
    """Render screenshot artifact inventory."""
    screenshot_events = [event for event in events if event.topic == "web.screenshotted_host"]
    if not screenshot_events:
        return "Screenshots: no screenshot inventory"
    rows = [
        (
            event.payload.get("host", ""),
            ", ".join(str(url) for url in event.payload.get("urls", [])[:2]),
            len(event.payload.get("screenshots", [])),
            screenshot_refs(event),
            event.payload.get("tool", ""),
        )
        for event in sorted(screenshot_events, key=lambda event: (str(event.payload.get("host") or ""), event.id or 0))
    ]
    table = render_table(
        ("HOST", "URLS", "SHOTS", "ARTIFACTS", "TOOL"),
        rows,
        cell_subjects=("host", "url", "", "artifact", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Screenshots: {scope} ({len(rows)} hosts)\n{table}"

def format_rtt(value: object) -> str:
    """Format a route hop round-trip value."""
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)):
        return f"{value:g} ms"
    return str(value)

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

def share_event_keys(event: Event) -> set[tuple[str, str, str]]:
    """Return stable share inventory identity keys for one event."""
    if event.topic != "smb.share.found":
        return set()
    host = str(event.payload.get("host") or "")
    share = str(event.payload.get("share") or "")
    return {("share", host, share)} if host and share else set()

def route_event_keys(event: Event) -> set[tuple[str, str, int]]:
    """Return stable route hop identity keys for one event."""
    if event.topic != "network.route.hop":
        return set()
    target = str(event.payload.get("target") or "")
    hop = int(event.payload.get("hop") or 0)
    return {("route", target, hop)} if target and hop else set()

def cert_event_keys(event: Event) -> set[tuple[str, str, int]]:
    """Return stable certificate identity keys for one event."""
    if event.topic != "tls.certificate":
        return set()
    host = str(event.payload.get("host") or "")
    port = int(event.payload.get("port") or 0)
    return {("cert", host, port)} if host and port else set()

def banner_event_keys(event: Event) -> set[tuple[str, str, int]]:
    """Return stable banner identity keys for one event."""
    if event.topic != "tcp.banner":
        return set()
    host = str(event.payload.get("host") or "")
    port = int(event.payload.get("port") or 0)
    return {("banner", host, port)} if host and port else set()

def path_event_keys(event: Event) -> set[tuple[str, str]]:
    """Return stable HTTP path identity keys for one event."""
    if event.topic != "http.path":
        return set()
    url = str(event.payload.get("url") or "")
    return {("path", url)} if url else set()

def screenshot_event_keys(event: Event) -> set[tuple[str, str]]:
    """Return stable screenshot identity keys for one event."""
    if event.topic != "web.screenshotted_host":
        return set()
    host = str(event.payload.get("host") or "")
    return {("screenshot", host)} if host else set()
