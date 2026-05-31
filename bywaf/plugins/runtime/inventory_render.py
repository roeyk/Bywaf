"""Aggregation and rendering for operator inventory commands."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

SERVICE_TOPICS = ("port.open", "service.detected", "http.endpoint", "tcp.banner", "tls.certificate")


@dataclass(slots=True)
class HostInventory:
    """Aggregated operator-facing facts for one host."""

    host: str
    names: set[str] = field(default_factory=set)
    statuses: set[str] = field(default_factory=set)
    ports: set[str] = field(default_factory=set)
    web_urls: set[str] = field(default_factory=set)
    findings: set[str] = field(default_factory=set)


@dataclass(slots=True)
class ServiceInventory:
    """Aggregated operator-facing facts for one host/port service."""

    host: str
    port: int
    protocol: str
    services: set[str] = field(default_factory=set)
    products: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    evidence: set[str] = field(default_factory=set)


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


def render_hosts_inventory(context: CommandContext, events: list[Event], scope: str) -> str:
    """Render host inventory from schema-backed event facts."""
    inventory = build_host_inventory(events)
    if not inventory:
        return "Hosts: no host inventory"
    rows = [
        (
            host.host,
            join_values(host.names),
            join_values(host.statuses),
            join_values(host.ports, limit=6),
            len(host.web_urls),
            len(host.findings),
        )
        for host in sorted(inventory.values(), key=lambda item: host_sort_value(item.host))
    ]
    table = render_table(
        ("HOST", "NAMES", "STATUS", "OPEN PORTS", "WEB", "FINDINGS"),
        rows,
        cell_subjects=("host", "host.name", "status", "port", "url", "finding.title"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Hosts: {scope} ({len(rows)} hosts)\n{table}"


def build_host_inventory(events: list[Event]) -> dict[str, HostInventory]:
    """Aggregate host-level event facts."""
    hosts: dict[str, HostInventory] = {}
    for event in events:
        payload = event.payload
        if event.topic == "host.found":
            host = host_record(hosts, payload.get("host"))
            add_value(host.names, payload.get("name"))
            add_value(host.statuses, payload.get("status"))
        elif event.topic == "name.resolved":
            host = host_record(hosts, payload.get("host"))
            add_value(host.names, payload.get("name"))
        elif event.topic == "port.open":
            host = host_record(hosts, payload.get("host"))
            add_value(host.ports, port_label(payload))
        elif event.topic == "http.endpoint":
            host = host_record(hosts, payload.get("host"))
            add_value(host.web_urls, payload.get("url"))
        elif event.topic == "service.detected":
            host = host_record(hosts, payload.get("host"))
            add_value(host.ports, port_label(payload))
        elif event.topic == "finding.candidate":
            for target in finding_hosts(payload):
                host = host_record(hosts, target)
                add_value(host.findings, payload.get("title") or payload.get("class"))
    return hosts


def render_services_inventory(context: CommandContext, events: list[Event], scope: str) -> str:
    """Render service inventory from network and web service facts."""
    inventory = build_service_inventory(events)
    if not inventory:
        return "Services: no service inventory"
    rows = [
        (
            service.host,
            service.port,
            service.protocol,
            join_values(service.services),
            join_values(service.products),
            join_values(service.urls, limit=2) or join_values(service.evidence, limit=2),
        )
        for service in sorted(inventory.values(), key=lambda item: (host_sort_value(item.host), item.port, item.protocol))
    ]
    table = render_table(
        ("HOST", "PORT", "PROTO", "SERVICE", "PRODUCT", "URL / EVIDENCE"),
        rows,
        cell_subjects=("host", "port", "protocol", "service", "value", "url"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Services: {scope} ({len(rows)} services)\n{table}"


def build_service_inventory(events: list[Event]) -> dict[tuple[str, int, str], ServiceInventory]:
    """Aggregate service-level event facts."""
    services: dict[tuple[str, int, str], ServiceInventory] = {}
    for event in events:
        payload = event.payload
        if event.topic == "port.open":
            service = service_record(services, payload)
            add_value(service.services, payload.get("service"))
            add_value(service.evidence, payload.get("reason"))
        elif event.topic == "service.detected":
            service = service_record(services, payload)
            add_value(service.services, payload.get("service"))
            add_value(service.products, format_product(payload))
            add_value(service.evidence, payload.get("evidence"))
        elif event.topic == "http.endpoint":
            service = service_record(services, payload)
            add_value(service.services, payload.get("scheme") or "http")
            add_value(service.products, payload.get("server"))
            add_value(service.urls, payload.get("url"))
        elif event.topic == "tcp.banner":
            service = service_record(services, payload)
            add_value(service.evidence, payload.get("banner") or payload.get("error"))
        elif event.topic == "tls.certificate":
            service = service_record(services, payload)
            add_value(service.services, "tls")
            add_value(service.evidence, payload.get("subject") or payload.get("issuer"))
    return services


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


def host_record(hosts: dict[str, HostInventory], value: object) -> HostInventory:
    """Return a host inventory row, creating it if needed."""
    host = str(value or "")
    if not host:
        host = "unknown"
    return hosts.setdefault(host, HostInventory(host))


def service_record(services: dict[tuple[str, int, str], ServiceInventory], payload: dict[str, Any]) -> ServiceInventory:
    """Return a service inventory row, creating it if needed."""
    host = str(payload.get("host") or "unknown")
    port = int(payload.get("port") or default_port(payload))
    protocol = str(payload.get("protocol") or "tcp")
    return services.setdefault((host, port, protocol), ServiceInventory(host, port, protocol))


def web_record(web: dict[str, WebInventory], value: object) -> WebInventory:
    """Return a web inventory row, creating it if needed."""
    url = str(value or "")
    if not url:
        url = "unknown"
    return web.setdefault(url, WebInventory(url))


def add_value(values: set[str], value: object) -> None:
    """Add a non-empty string value to a set."""
    if value not in (None, ""):
        values.add(str(value))


def join_values(values: set[str], *, limit: int | None = None) -> str:
    """Join a set of values with a bounded display length."""
    ordered = sorted(values, key=str)
    visible = ordered[:limit] if limit is not None else ordered
    suffix = "" if limit is None or len(ordered) <= limit else f", +{len(ordered) - limit}"
    return ", ".join(visible) + suffix


def port_label(payload: dict[str, Any]) -> str:
    """Return compact port/protocol/service text."""
    if payload.get("port") in (None, ""):
        return ""
    endpoint = f"{payload.get('port')}/{payload.get('protocol') or 'tcp'}"
    service = str(payload.get("service") or "")
    return f"{endpoint} {service}".strip()


def default_port(payload: dict[str, Any]) -> int:
    """Return the implied port for common web schemes."""
    scheme = str(payload.get("scheme") or "").lower()
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return 0


def format_product(payload: dict[str, Any]) -> str:
    """Return product/version text."""
    product = str(payload.get("product") or "")
    version = str(payload.get("version") or "")
    return f"{product} {version}".strip()


def finding_hosts(payload: dict[str, Any]) -> set[str]:
    """Extract host-like finding targets."""
    values: set[str] = set()
    for candidate in finding_target_values(payload):
        if "://" not in candidate:
            values.add(candidate)
    return values


def finding_urls(payload: dict[str, Any]) -> set[str]:
    """Extract URL-like finding targets."""
    return {candidate for candidate in finding_target_values(payload) if "://" in candidate}


def finding_target_values(payload: dict[str, Any]) -> set[str]:
    """Extract target strings from common finding payload shapes."""
    values: set[str] = set()
    for key in ("target", "target_scope"):
        target = payload.get(key)
        if isinstance(target, dict):
            add_value(values, target.get("value") or target.get("host") or target.get("url"))
    affected = payload.get("affected")
    if isinstance(affected, list):
        for item in affected:
            if isinstance(item, dict):
                add_value(values, item.get("value") or item.get("host") or item.get("url"))
            else:
                add_value(values, item)
    return values


def host_event_keys(event: Event) -> set[tuple[str, str]]:
    """Return stable host inventory identity keys for one event."""
    payload = event.payload
    values: set[str] = set()
    if event.topic in {"host.found", "name.resolved", "port.open", "http.endpoint", "service.detected"}:
        add_value(values, payload.get("host"))
    if event.topic == "finding.candidate":
        values.update(finding_hosts(payload))
    return {("host", value) for value in values}


def service_event_keys(event: Event) -> set[tuple[str, str, int, str]]:
    """Return stable service inventory identity keys for one event."""
    payload = event.payload
    if event.topic not in SERVICE_TOPICS:
        return set()
    host = str(payload.get("host") or "")
    if not host:
        return set()
    port = int(payload.get("port") or default_port(payload))
    protocol = str(payload.get("protocol") or "tcp")
    return {("service", host, port, protocol)}


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


def host_sort_value(value: str) -> tuple[int, bytes | str]:
    """Sort IPs numerically and names lexically."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return (99, value)
    return (address.version, address.packed)
