"""Web endpoint and WAF inventory aggregation and rendering."""

from __future__ import annotations

from dataclasses import dataclass, field

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

from .shared import add_value, finding_urls, join_values


@dataclass(slots=True)
class WebInventory:
    """Aggregated operator-facing facts for one web endpoint."""

    url: str
    host: str = ""
    status: str = ""
    server: str = ""
    paths: set[str] = field(default_factory=set)
    wafs: set[str] = field(default_factory=set)
    screenshots: set[str] = field(default_factory=set)
    findings: set[str] = field(default_factory=set)


@dataclass(slots=True)
class WafInventory:
    """Aggregated operator-facing facts for one WAF signal."""

    url: str
    host: str = ""
    vendor: str = ""
    product: str = ""
    confidence: str = ""
    evidence: set[str] = field(default_factory=set)
def render_web_inventory(context: CommandContext, events: list[Event], scope: str) -> str:
    """Render web inventory from endpoint, WAF, path, screenshot, and finding facts."""
    inventory = build_web_inventory(events)
    if not inventory:
        return "Web: no web inventory"
    rows = [
        (
            web.url,
            web.status,
            web.server,
            join_values(web.paths, limit=3),
            join_values(web.wafs),
            len(web.screenshots),
            join_values(web.findings, limit=2),
        )
        for web in sorted(inventory.values(), key=lambda item: item.url)
    ]
    table = render_table(
        ("URL", "STATUS", "SERVER", "PATHS", "WAF", "SHOTS", "FINDINGS"),
        rows,
        cell_subjects=("url", "status", "", "url", "value", "artifact", "finding.title"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Web: {scope} ({len(rows)} endpoints)\n{table}"

def build_web_inventory(events: list[Event]) -> dict[str, WebInventory]:
    """Aggregate web endpoint facts."""
    web: dict[str, WebInventory] = {}
    for event in events:
        payload = event.payload
        if event.topic == "http.endpoint":
            row = web_record(web, payload.get("url"))
            row.host = str(payload.get("host") or row.host)
            row.status = str(payload.get("status") or row.status)
            row.server = str(payload.get("server") or row.server)
        elif event.topic == "http.path":
            row = web_record(web, payload.get("url"))
            row.host = str(payload.get("host") or row.host)
            add_value(row.paths, payload.get("path"))
        elif event.topic == "web.waf.detected":
            row = web_record(web, payload.get("url"))
            row.host = str(payload.get("host") or row.host)
            add_value(row.wafs, payload.get("product") or payload.get("vendor"))
        elif event.topic == "web.screenshotted_host":
            for url in payload.get("urls", []):
                row = web_record(web, url)
                row.host = str(payload.get("host") or row.host)
                for screenshot in payload.get("screenshots", []):
                    if isinstance(screenshot, dict):
                        add_value(row.screenshots, screenshot.get("artifact_id") or screenshot.get("path"))
        elif event.topic == "finding.candidate":
            for target in finding_urls(payload):
                row = web_record(web, target)
                add_value(row.findings, payload.get("title") or payload.get("class"))
    return web

def render_wafs_inventory(context: CommandContext, events: list[Event], scope: str) -> str:
    """Render WAF inventory from edge-protection fingerprint facts."""
    inventory = build_waf_inventory(events)
    if not inventory:
        return "WAFs: no WAF inventory"
    rows = [
        (
            waf.url,
            waf.host,
            waf.vendor,
            waf.product,
            waf.confidence,
            join_values(waf.evidence, limit=2),
        )
        for waf in sorted(inventory.values(), key=lambda item: (item.vendor.casefold(), item.url))
    ]
    table = render_table(
        ("URL", "HOST", "VENDOR", "PRODUCT", "CONF", "EVIDENCE"),
        rows,
        cell_subjects=("url", "host", "value", "value", "status", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"WAFs: {scope} ({len(rows)} signals)\n{table}"

def build_waf_inventory(events: list[Event]) -> dict[tuple[str, str], WafInventory]:
    """Aggregate WAF fingerprint facts."""
    wafs: dict[tuple[str, str], WafInventory] = {}
    for event in events:
        if event.topic != "web.waf.detected":
            continue
        payload = event.payload
        url = str(payload.get("url") or "unknown")
        vendor = str(payload.get("vendor") or "unknown")
        row = wafs.setdefault((url, vendor), WafInventory(url=url, vendor=vendor))
        row.host = str(payload.get("host") or row.host)
        row.product = str(payload.get("product") or row.product)
        row.confidence = str(payload.get("confidence") or row.confidence)
        add_value(row.evidence, payload.get("evidence"))
    return wafs

def web_record(web: dict[str, WebInventory], value: object) -> WebInventory:
    """Return a web inventory row, creating it if needed."""
    url = str(value or "")
    if not url:
        url = "unknown"
    return web.setdefault(url, WebInventory(url))

def web_event_keys(event: Event) -> set[tuple[str, str]]:
    """Return stable web inventory identity keys for one event."""
    payload = event.payload
    values: set[str] = set()
    if event.topic in {"http.endpoint", "http.path", "web.waf.detected"}:
        add_value(values, payload.get("url"))
    elif event.topic == "web.screenshotted_host":
        for url in payload.get("urls", []):
            add_value(values, url)
    elif event.topic == "finding.candidate":
        values.update(finding_urls(payload))
    return {("web", value) for value in values}

def waf_event_keys(event: Event) -> set[tuple[str, str, str]]:
    """Return stable WAF inventory identity keys for one event."""
    if event.topic != "web.waf.detected":
        return set()
    url = str(event.payload.get("url") or "")
    vendor = str(event.payload.get("vendor") or "")
    if not url or not vendor:
        return set()
    return {("waf", url, vendor)}
