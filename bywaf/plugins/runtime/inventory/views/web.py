"""Web endpoint and WAF inventory aggregation and rendering.

Used by:
- runtime commandlets and REPL display paths that present persisted jobs,
  events, inventory, or result state.
- tests and future plugins that need stable runtime helper behavior.
"""

from __future__ import annotations

from typing import Any

from collections.abc import Callable
from dataclasses import dataclass, field

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

from .shared import add_value, finding_urls, host_sort_value, join_values, sort_note, split_sort


@dataclass(slots=True)
class WebInventory:
    """Aggregated operator-facing facts for one web endpoint.

    Constructed by: `web_record()` while `build_web_inventory()` walks events.

    Used by: `render_web_inventory()` to display endpoint, technology, WAF,
    screenshot, and finding summaries.
    """

    url: str
    host: str = ""
    status: str = ""
    server: str = ""
    technologies: set[str] = field(default_factory=set)
    observations: int = 0
    paths: set[str] = field(default_factory=set)
    wafs: set[str] = field(default_factory=set)
    screenshots: set[str] = field(default_factory=set)
    findings: set[str] = field(default_factory=set)


@dataclass(slots=True)
class WafInventory:
    """Aggregated operator-facing facts for one WAF signal.

    Constructed by: `build_waf_inventory()` from `web.waf.detected` events.

    Used by: `render_wafs_inventory()` to display WAF vendor/product evidence.
    """

    url: str
    host: str = ""
    vendor: str = ""
    product: str = ""
    confidence: str = ""
    evidence: set[str] = field(default_factory=set)


def render_web_inventory(context: CommandContext, events: list[Event], scope: str, sort: str = "url") -> str:
    """Render web inventory from endpoint, WAF, path, screenshot, and finding facts.

    Called by: `runtime.inventory.WebInventoryCommand.render()`.
    """
    # First reduce all relevant event topics into one row per URL.
    inventory = build_web_inventory(events)
    if not inventory:
        return "Web: no web inventory"

    # Split the user-provided sort expression into a key and direction.
    sort_key, descending = split_sort(sort, "url")

    # Convert WebInventory objects into render_table rows. The set-valued
    # fields are capped so a single noisy host cannot dominate the terminal.
    rows = [
        (
            web.url,
            web.status,
            web.server,
            join_values(web.technologies, limit=3),
            web.observations or "",
            join_values(web.paths, limit=3),
            join_values(web.wafs),
            len(web.screenshots),
            join_values(web.findings, limit=2),
        )
        for web in sorted(inventory.values(), key=lambda item: web_inventory_sort_key(item, sort_key), reverse=descending)
    ]

    # Render with subject hints so URLs, findings, status, and artifact counts
    # can receive the same styling as other inventory views.
    table = render_table(
        ("URL", "STATUS", "SERVER", "TECH", "OBS", "PATHS", "WAF", "SHOTS", "FINDINGS"),
        rows,
        cell_subjects=("url", "status", "", "value", "value", "url", "value", "artifact", "finding.title"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Web: {scope} ({len(rows)} endpoints)\n{sort_note(sort, 'url')}\n{table}"


def web_inventory_sort_key(web: WebInventory, key: str) -> Any:
    """Return a sortable web inventory value.

    Called by: `render_web_inventory()` while ordering rows.
    """
    # Return tuples for stable tie-breaking by URL when primary fields match.
    if key == "host":
        return (host_sort_value(web.host), web.url)
    if key == "status":
        return (web.status, web.url)
    if key == "server":
        return (web.server.casefold(), web.url)
    if key == "tech":
        return (join_values(web.technologies).casefold(), web.url)
    return web.url


def build_web_inventory(events: list[Event]) -> dict[str, WebInventory]:
    """Aggregate web endpoint facts.

    Called by: `render_web_inventory()` and identity/deduplication tests.
    """
    web: dict[str, WebInventory] = {}
    for event in events:
        # This lookup uses WEB_EVENT_HANDLERS, defined below, in place of an
        # if/elif ladder over web inventory event topics.
        handler = WEB_EVENT_HANDLERS.get(event.topic)
        if handler is not None:
            # Apply the topic-specific merge function to the shared inventory
            # dictionary.
            handler(web, event.payload)
    return web


WebEventHandler = Callable[[dict[str, WebInventory], dict[str, object]], None]


def apply_http_endpoint(web: dict[str, WebInventory], payload: dict[str, object]) -> None:
    """Merge one HTTP endpoint payload into web inventory.

    Called by: `build_web_inventory()` through `WEB_EVENT_HANDLERS`.
    """
    # Create or fetch the row keyed by endpoint URL.
    row = web_record(web, payload.get("url"))

    # Merge endpoint-level host/status/server details, preserving earlier
    # values when this payload omits them.
    row.host = str(payload.get("host") or row.host)
    row.status = str(payload.get("status") or row.status)
    row.server = str(payload.get("server") or row.server)


def apply_http_path(web: dict[str, WebInventory], payload: dict[str, object]) -> None:
    """Merge one HTTP path payload into web inventory.

    Called by: `build_web_inventory()` through `WEB_EVENT_HANDLERS`.
    """
    # Add a discovered route/path to the row for this URL.
    row = web_record(web, payload.get("url"))
    row.host = str(payload.get("host") or row.host)
    add_value(row.paths, payload.get("path"))


def apply_web_fingerprint(web: dict[str, WebInventory], payload: dict[str, object]) -> None:
    """Merge one web fingerprint payload into web inventory.

    Called by: `build_web_inventory()` through `WEB_EVENT_HANDLERS`.
    """
    # Merge web fingerprint facts into the same URL row used by endpoints.
    row = web_record(web, payload.get("url"))
    row.host = str(payload.get("host") or row.host)
    row.status = str(payload.get("status") or row.status)
    row.server = str(payload.get("server") or row.server)

    # Add normalized technology names when the fingerprint payload provides
    # them as a list.
    technologies = payload.get("technologies", [])
    if isinstance(technologies, list):
        for technology in technologies:
            add_value(row.technologies, technology)

    # Keep the highest observation count seen for this URL.
    observations = payload.get("observations", [])
    if isinstance(observations, list):
        row.observations = max(row.observations, len(observations))


def apply_waf_signal(web: dict[str, WebInventory], payload: dict[str, object]) -> None:
    """Merge one WAF payload into web inventory.

    Called by: `build_web_inventory()` through `WEB_EVENT_HANDLERS`.
    """
    # Record the WAF product/vendor on the URL row.
    row = web_record(web, payload.get("url"))
    row.host = str(payload.get("host") or row.host)
    add_value(row.wafs, payload.get("product") or payload.get("vendor"))


def apply_screenshotted_host(web: dict[str, WebInventory], payload: dict[str, object]) -> None:
    """Merge one screenshot payload into web inventory.

    Called by: `build_web_inventory()` through `WEB_EVENT_HANDLERS`.
    """
    # Screenshot inventory facts carry a list of URLs represented by the
    # screenshot group.
    urls = payload.get("urls", [])
    if not isinstance(urls, list):
        return
    for url in urls:
        # Merge screenshot artifact refs into each represented URL row.
        row = web_record(web, url)
        row.host = str(payload.get("host") or row.host)
        add_screenshot_refs(row, payload.get("screenshots", []))


def add_screenshot_refs(row: WebInventory, screenshots: object) -> None:
    """Merge screenshot artifact references into one inventory row.

    Called by: `apply_screenshotted_host()` for each represented URL.
    """
    if not isinstance(screenshots, list):
        return
    for screenshot in screenshots:
        if isinstance(screenshot, dict):
            # Prefer artifact IDs, then fall back to path-like refs.
            add_value(row.screenshots, screenshot.get("artifact_id") or screenshot.get("path"))


def apply_finding_candidate(web: dict[str, WebInventory], payload: dict[str, object]) -> None:
    """Merge URL-targeted finding candidates into web inventory.

    Called by: `build_web_inventory()` through `WEB_EVENT_HANDLERS`.
    """
    for target in finding_urls(payload):
        # Findings may affect URLs that were not otherwise present in endpoint
        # facts, so create rows as needed.
        row = web_record(web, target)
        add_value(row.findings, payload.get("title") or payload.get("class"))


# The web inventory merges URL/service/finding facts from different event
# topics into one per-target row. `build_web_inventory()` uses this dispatch
# table to route each topic to the right merge helper instead of an if/elif
# ladder.
WEB_EVENT_HANDLERS: dict[str, WebEventHandler] = {
    "http.endpoint": apply_http_endpoint,
    "http.path": apply_http_path,
    "web.fingerprint": apply_web_fingerprint,
    "web.waf.detected": apply_waf_signal,
    "web.screenshotted_host": apply_screenshotted_host,
    "finding.candidate": apply_finding_candidate,
}


def render_wafs_inventory(context: CommandContext, events: list[Event], scope: str, sort: str = "vendor") -> str:
    """Render WAF inventory from edge-protection fingerprint facts.

    Called by: `runtime.inventory.WafInventoryCommand.render()`.
    """
    # Reduce WAF detection events into one row per URL/vendor pair.
    inventory = build_waf_inventory(events)
    if not inventory:
        return "WAFs: no WAF inventory"

    # Split sort expression and render WAF rows in that order.
    sort_key, descending = split_sort(sort, "vendor")
    rows = [
        (
            waf.url,
            waf.host,
            waf.vendor,
            waf.product,
            waf.confidence,
            join_values(waf.evidence, limit=2),
        )
        for waf in sorted(inventory.values(), key=lambda item: waf_inventory_sort_key(item, sort_key), reverse=descending)
    ]

    # Render with subject hints so URL, host, status/confidence, and values are
    # styled consistently with other inventory tables.
    table = render_table(
        ("URL", "HOST", "VENDOR", "PRODUCT", "CONF", "EVIDENCE"),
        rows,
        cell_subjects=("url", "host", "value", "value", "status", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"WAFs: {scope} ({len(rows)} signals)\n{sort_note(sort, 'vendor')}\n{table}"


def waf_inventory_sort_key(waf: WafInventory, key: str) -> Any:
    """Return a sortable WAF inventory value.

    Called by: `render_wafs_inventory()` while ordering rows.
    """
    # Return tuples for stable tie-breaking by vendor and URL.
    if key == "url":
        return (waf.url, waf.vendor.casefold())
    if key == "host":
        return (host_sort_value(waf.host), waf.vendor.casefold(), waf.url)
    if key == "product":
        return (waf.product.casefold(), waf.vendor.casefold(), waf.url)
    if key == "confidence":
        return (waf.confidence, waf.vendor.casefold(), waf.url)
    return (waf.vendor.casefold(), waf.url)


def build_waf_inventory(events: list[Event]) -> dict[tuple[str, str], WafInventory]:
    """Aggregate WAF fingerprint facts.

    Called by: `render_wafs_inventory()`.
    """
    wafs: dict[tuple[str, str], WafInventory] = {}
    for event in events:
        if event.topic != "web.waf.detected":
            continue
        payload = event.payload
        # Key by URL and vendor so multiple detections for the same edge
        # protection product collapse into one row.
        url = str(payload.get("url") or "unknown")
        vendor = str(payload.get("vendor") or "unknown")
        row = wafs.setdefault((url, vendor), WafInventory(url=url, vendor=vendor))

        # Merge optional product/confidence/evidence details onto the row.
        row.host = str(payload.get("host") or row.host)
        row.product = str(payload.get("product") or row.product)
        row.confidence = str(payload.get("confidence") or row.confidence)
        add_value(row.evidence, payload.get("evidence"))
    return wafs


def web_record(web: dict[str, WebInventory], value: object) -> WebInventory:
    """Return a web inventory row, creating it if needed.

    Called by: web inventory merge helpers.
    """
    # Normalize missing URL-like values into an explicit unknown row.
    url = str(value or "")
    if not url:
        url = "unknown"
    return web.setdefault(url, WebInventory(url))


def web_event_keys(event: Event) -> set[tuple[str, str]]:
    """Return stable web inventory identity keys for one event.

    Called by: inventory freshness/deduplication logic.
    """
    payload = event.payload
    values: set[str] = set()
    if event.topic in {"http.endpoint", "http.path", "web.fingerprint", "web.waf.detected"}:
        # These web facts all carry one primary URL.
        add_value(values, payload.get("url"))
    elif event.topic == "web.screenshotted_host":
        # Screenshot facts can represent several URLs.
        for url in payload.get("urls", []):
            add_value(values, url)
    elif event.topic == "finding.candidate":
        # Findings identify affected URLs through their normalized target data.
        values.update(finding_urls(payload))
    return {("web", value) for value in values}


def waf_event_keys(event: Event) -> set[tuple[str, str, str]]:
    """Return stable WAF inventory identity keys for one event.

    Called by: inventory freshness/deduplication logic.
    """
    if event.topic != "web.waf.detected":
        return set()

    # URL+vendor is the same identity used by `build_waf_inventory()`.
    url = str(event.payload.get("url") or "")
    vendor = str(event.payload.get("vendor") or "")
    if not url or not vendor:
        return set()
    return {("waf", url, vendor)}
