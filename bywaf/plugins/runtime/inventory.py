"""Operator inventory views over shared event schemas.

Provides high-level `hosts`, `services`, and `web` commandlets so operators can
ask direct questions about the accumulated project knowledge instead of
remembering which scanner emitted which event topic.
"""

from __future__ import annotations

import ipaddress
from argparse import Namespace
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet
from bywaf.plugins.runtime.job import require_job
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

HOST_TOPICS = ("host.found", "name.resolved", "port.open", "http.endpoint", "service.detected", "finding.candidate")
SERVICE_TOPICS = ("port.open", "service.detected", "http.endpoint", "tcp.banner", "tls.certificate")
WEB_TOPICS = ("http.endpoint", "http.path", "web.waf.detected", "web.screenshotted_host", "finding.candidate")
SCOPE_KEYS = {"all", "job", "pipeline", "step"}


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


class InventoryCommand(CommandletBase):
    """Shared parser and selector behavior for inventory commandlets."""

    topics: tuple[str, ...] = ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete common inventory selectors."""
        del context, args
        candidates = ["--page", "all=true", "job=", "job=latest", "pipeline=", "step="]
        return [candidate for candidate in candidates if candidate.startswith(prefix)]

    def selected_events(self, context: CommandContext, args: list[str]) -> tuple[Namespace, list[Event], bool]:
        """Parse scope selectors and return matching events."""
        parser = self.parser()
        parser.add_argument("--page", action="store_true")
        parser.add_argument("selectors", nargs="*")
        parsed = parser.parse_args(args)
        selectors = parse_inventory_selectors(parsed.selectors)
        context.require_foreground(f"{self.spec.name} inventory views")
        events = select_inventory_events(context, self.topics, selectors)
        return selectors, events, bool(parsed.page)


@commandlet(
    name="hosts",
    description="Show host inventory from accumulated scan results.",
    usage="hosts [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("hosts", "hosts pipeline=12", "hosts step=portscanner-...", "hosts --page"),
    consumes=HOST_TOPICS,
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Hosts(InventoryCommand):
    """Render a compact host inventory."""

    topics = HOST_TOPICS

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render host inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_hosts_inventory(context, events, inventory_scope_label(selectors))
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()


@commandlet(
    name="services",
    description="Show service inventory by host and port.",
    usage="services [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("services", "services pipeline=12", "services step=portscanner-...", "services --page"),
    consumes=SERVICE_TOPICS,
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Services(InventoryCommand):
    """Render a compact service inventory."""

    topics = SERVICE_TOPICS

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render service inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_services_inventory(context, events, inventory_scope_label(selectors))
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()


@commandlet(
    name="web",
    description="Show web endpoint inventory from accumulated scan results.",
    usage="web [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("web", "web pipeline=12", "web step=http-probe-...", "web --page"),
    consumes=WEB_TOPICS,
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Web(InventoryCommand):
    """Render a compact web endpoint inventory."""

    topics = WEB_TOPICS

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render web inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_web_inventory(context, events, inventory_scope_label(selectors))
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()


def parse_inventory_selectors(tokens: list[str]) -> Namespace:
    """Parse shared inventory scope selectors."""
    scope: dict[str, str] = {}
    for token in tokens:
        if token.startswith("--"):
            raise ValueError(f"inventory views use selector syntax; use key=value, not {token}")
        key, separator, value = token.partition("=")
        if not separator or not key or not value:
            raise ValueError("inventory selectors must be key=value")
        if key not in SCOPE_KEYS:
            raise ValueError("inventory selectors must be one of: all, job, pipeline, step")
        scope[key] = value
    all_value = scope.get("all", "true")
    if all_value not in {"true", "false"}:
        raise ValueError("inventory all= must be true or false")
    explicit = [key for key in ("job", "pipeline", "step") if key in scope]
    if len(explicit) > 1:
        raise ValueError("inventory accepts only one runtime scope: job=, pipeline=, or step=")
    if explicit and "all" in scope:
        raise ValueError("inventory all= cannot be combined with job=, pipeline=, or step=")
    return Namespace(scope=scope)


def select_inventory_events(context: CommandContext, topics: tuple[str, ...], selectors: Namespace) -> list[Event]:
    """Return matching inventory events for the selected scope."""
    events = context.event_store("inventory")
    runtime = context.runtime_store("inventory")
    scope = selectors.scope
    if "job" in scope:
        if scope["job"] == "latest":
            row = latest_non_view_job(runtime)
        else:
            row = require_job(context, scope["job"])
        return [event for event in events.events_for_job(row["id"], limit=10000) if event.topic in topics]
    if "pipeline" in scope:
        pipeline_id = runtime.resolve_pipeline_serial(scope["pipeline"])
        return [event for event in events.events_matching(pipeline_id=pipeline_id, limit=10000) if event.topic in topics]
    if "step" in scope:
        run_id = runtime.resolve_run_serial(scope["step"])
        return [event for event in events.events_matching(command_run_id=run_id, limit=10000) if event.topic in topics]
    rows: list[Event] = []
    for topic in topics:
        rows.extend(events.events_matching(topic=topic, limit=10000))
    return sorted(rows, key=lambda event: event.id or 0)


def latest_non_view_job(runtime: Any) -> dict[str, Any]:
    """Return the newest non-view job row."""
    for row in reversed(runtime.jobs(limit=1000)):
        command = str(row.get("command_line") or "").split(maxsplit=1)[0].rsplit("/", 1)[-1]
        if command not in {"event", "events", "hosts", "job", "pipeline", "ports", "report", "result", "results", "services", "step", "web"}:
            return row
    raise ValueError("no non-view jobs found")


def inventory_scope_label(selectors: Namespace) -> str:
    """Return a short operator-facing scope label."""
    scope = selectors.scope
    if "job" in scope:
        return f"job={scope['job']}"
    if "pipeline" in scope:
        return f"pipeline={scope['pipeline']}"
    if "step" in scope:
        return f"step={scope['step']}"
    return "project inventory"


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


def host_sort_value(value: str) -> tuple[int, bytes | str]:
    """Sort IPs numerically and names lexically."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return (99, value)
    return (address.version, address.packed)


def plugins() -> tuple[Commandlet, ...]:
    """Return inventory commandlets."""
    return (Hosts(), Services(), Web())
