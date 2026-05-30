"""Network overview rendering for reports.

Builds host-centric report sections from shared event-schema facts in the
selected report scope.

Used by:
- analysis.report_render: add network context above finding moderation rows.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.network.portscanner_ports import ip_sort_value, port_endpoint_text, sort_port_events
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

from .report_style import report_text


@dataclass
class HostOverview:
    """Aggregated report context for one host."""

    host: str
    names: set[str] = field(default_factory=set)
    ports: list[Event] = field(default_factory=list)
    services: set[str] = field(default_factory=set)
    endpoints: list[str] = field(default_factory=list)
    web: set[str] = field(default_factory=set)
    findings: set[str] = field(default_factory=set)


def render_network_overview(context: CommandContext, context_events: list[Event], finding_events: list[Event]) -> str:
    """Return a host-centric overview for report output."""
    hosts = host_overviews(context_events, finding_events)
    if not hosts:
        return ""
    rows = [
        (
            host.host,
            ", ".join(sorted(host.names)),
            ", ".join(dict.fromkeys(port_endpoint_text(event) for event in sort_port_events(host.ports, "port"))),
            ", ".join(sorted(host.services)),
            ", ".join(dict.fromkeys([*host.endpoints, *sorted(host.web)])),
            ", ".join(sorted(host.findings)),
        )
        for host in sorted(hosts.values(), key=lambda item: ip_sort_value(item.host))
    ]
    table = render_table(
        ("HOST", "NAMES", "OPEN PORTS", "SERVICES", "WEB", "FINDINGS"),
        rows,
        cell_subjects=("host", "host.name", "port", "value", "url", "finding.title"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return report_text(context, "section", "Network overview") + "\n" + table


def host_overviews(context_events: list[Event], finding_events: list[Event]) -> dict[str, HostOverview]:
    """Aggregate shared facts into one row per host."""
    hosts: dict[str, HostOverview] = {}
    for event in context_events:
        add_context_event(hosts, event)
    for event in finding_events:
        add_finding_event(hosts, event)
    return hosts


def add_context_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add one shared network fact to host overview buckets."""
    payload = event.payload
    if event.topic in {"host.found", "name.resolved"}:
        add_named_host(hosts, payload.get("host"), payload.get("name"))
    elif event.topic == "port.open":
        add_port_event(hosts, event)
    elif event.topic == "service.detected":
        add_service_event(hosts, event)
    elif event.topic == "http.endpoint":
        add_http_endpoint(hosts, payload.get("host"), payload.get("url"))
    elif event.topic == "http.path":
        add_http_path(hosts, payload.get("host"), payload.get("url"), payload.get("interesting"))
    elif event.topic == "tls.certificate":
        add_web_note(hosts, payload.get("host"), "tls")
    elif event.topic == "web.waf.detected":
        add_web_note(hosts, payload.get("host"), f"waf:{payload.get('vendor', '')}".strip(":"))


def add_named_host(hosts: dict[str, HostOverview], host_value: object, name_value: object) -> None:
    """Add a host and optional DNS/operator name."""
    host = ensure_host(hosts, host_value)
    if host and name_value:
        host.names.add(str(name_value))


def add_port_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add one open-port fact to a host bucket."""
    host = ensure_host(hosts, event.payload.get("host"))
    if host:
        host.ports.append(event)


def add_http_endpoint(hosts: dict[str, HostOverview], host_value: object, url_value: object) -> None:
    """Add one HTTP endpoint fact to a host bucket."""
    host = ensure_host(hosts, host_value)
    if host:
        host.endpoints.append(str(url_value or ""))


def add_service_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add a normalized service classification to a host bucket."""
    host = ensure_host(hosts, event.payload.get("host"))
    service = str(event.payload.get("service") or "").strip()
    port = event.payload.get("port")
    if host and service:
        host.services.add(f"{service}:{port}" if port else service)


def add_http_path(hosts: dict[str, HostOverview], host_value: object, url_value: object, interesting: object) -> None:
    """Add interesting path observations to the web notes bucket."""
    if not interesting:
        return
    host = ensure_host(hosts, host_value)
    if host:
        host.web.add(str(url_value or "interesting path"))


def add_web_note(hosts: dict[str, HostOverview], host_value: object, note: str) -> None:
    """Add one short web/service note to a host bucket."""
    host = ensure_host(hosts, host_value)
    if host and note:
        host.web.add(note)


def add_finding_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add one finding title to all affected host buckets."""
    payload = event.payload
    title = str(payload.get("title") or payload.get("class") or event.topic)
    for host_value in finding_hosts(payload):
        host = ensure_host(hosts, host_value)
        if host:
            host.findings.add(title)


def ensure_host(hosts: dict[str, HostOverview], value: object) -> HostOverview | None:
    """Return the host bucket for a non-empty host value."""
    host = str(value or "").strip()
    if not host:
        return None
    return hosts.setdefault(host, HostOverview(host))


def finding_hosts(payload: dict) -> set[str]:
    """Extract host-like values from a normalized finding payload."""
    hosts: set[str] = set()
    for key in ("target", "target_scope"):
        value = payload.get(key)
        if isinstance(value, dict) and value.get("host"):
            hosts.add(str(value["host"]))
    affected = payload.get("affected")
    if isinstance(affected, list):
        for item in affected:
            if isinstance(item, dict) and item.get("host"):
                hosts.add(str(item["host"]))
            elif isinstance(item, str):
                hosts.add(item)
    return hosts
