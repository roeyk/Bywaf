"""Network overview rendering for reports.

Builds host-centric report sections from shared event-schema facts in the
selected report scope.

Used by:
- analysis.report.render: add network context above finding moderation rows.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.network.portscanner.ports import ip_sort_value, port_endpoint_text, sort_port_events
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

from .style import report_text


@dataclass
class HostOverview:
    """Aggregated report context for one host."""

    host: str
    names: set[str] = field(default_factory=set)
    ports: list[Event] = field(default_factory=list)
    services: set[str] = field(default_factory=set)
    endpoints: list[str] = field(default_factory=list)
    web: set[str] = field(default_factory=set)
    routes: set[str] = field(default_factory=set)
    screenshots: set[str] = field(default_factory=set)
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
            ", ".join(dict.fromkeys([*sorted(host.screenshots), *sorted(host.routes), *host.endpoints, *sorted(host.web)])),
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
    details = render_host_details(context, sorted(hosts.values(), key=lambda item: ip_sort_value(item.host)))
    return report_text(context, "section", "Network overview") + "\n" + table + ("\n" + details if details else "")


def render_host_details(context: CommandContext, hosts: list[HostOverview]) -> str:
    """Return readable per-host fact sections below the compact overview."""
    lines = [report_text(context, "section", "Host details")]
    for host in hosts:
        lines.append(report_text(context, "label", host.host))
        append_host_fact(lines, "names", sorted(host.names))
        append_host_fact(lines, "open ports", dict.fromkeys(port_endpoint_text(event) for event in sort_port_events(host.ports, "port")))
        append_host_fact(lines, "services", sorted(host.services))
        append_host_fact(lines, "web", [*sorted(host.screenshots), *sorted(host.routes), *host.endpoints, *sorted(host.web)])
        append_host_fact(lines, "findings", sorted(host.findings))
    return "\n".join(lines) if len(lines) > 1 else ""


def append_host_fact(lines: list[str], label: str, values) -> None:
    """Append one host detail line if values are present."""
    unique = [str(value) for value in dict.fromkeys(values) if str(value)]
    if unique:
        lines.append(f"  {label}: {', '.join(unique)}")


def host_overviews(context_events: list[Event], finding_events: list[Event]) -> dict[str, HostOverview]:
    """Aggregate shared facts into one row per host."""
    hosts: dict[str, HostOverview] = {}
    for event in context_events:
        add_context_event(hosts, event)
    for event in finding_events:
        add_finding_event(hosts, event)
    return hosts


ContextEventHandler = Callable[[dict[str, HostOverview], Event], None]


def add_context_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add one shared network fact to host overview buckets."""
    handler = CONTEXT_EVENT_HANDLERS.get(event.topic)
    if handler:
        handler(hosts, event)


def add_named_host_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add host/name facts from a shared event."""
    add_named_host(hosts, event.payload.get("host"), event.payload.get("name"))


def add_http_endpoint_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add HTTP endpoint facts from a shared event."""
    add_http_endpoint(hosts, event.payload.get("host"), event.payload.get("url"))


def add_http_path_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add interesting HTTP path facts from a shared event."""
    add_http_path(hosts, event.payload.get("host"), event.payload.get("url"), event.payload.get("interesting"))


def add_tls_certificate_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add TLS observations from a shared event."""
    add_web_note(hosts, event.payload.get("host"), "tls")


def add_waf_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add WAF observations from a shared event."""
    add_web_note(hosts, event.payload.get("host"), f"waf:{event.payload.get('vendor', '')}".strip(":"))


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


def add_screenshot_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add screenshot artifact references to a host bucket."""
    host = ensure_host(hosts, event.payload.get("host"))
    if not host:
        return
    screenshots = event.payload.get("screenshots")
    if isinstance(screenshots, list) and screenshots:
        host.screenshots.add(f"screenshots:{len(screenshots)}")
    else:
        host.screenshots.add("screenshotted")


def add_route_hop(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add route-hop observations to the responding host bucket."""
    payload = event.payload
    host_value = payload.get("ip") or payload.get("host")
    host = ensure_host(hosts, host_value)
    if not host:
        return
    hop = payload.get("hop")
    status = payload.get("status")
    parts = [f"hop:{hop}" if hop is not None else "hop", str(status or "")]
    host.routes.add(" ".join(part for part in parts if part).strip())


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


# Network reports synthesize context from several event topics, each with a
# different payload shape. network_context() uses this dispatch table to route
# each topic to the right normalizer without topic-specific branches.
CONTEXT_EVENT_HANDLERS: dict[str, ContextEventHandler] = {
    "host.found": add_named_host_event,
    "name.resolved": add_named_host_event,
    "port.open": add_port_event,
    "service.detected": add_service_event,
    "http.endpoint": add_http_endpoint_event,
    "http.path": add_http_path_event,
    "tls.certificate": add_tls_certificate_event,
    "web.waf.detected": add_waf_event,
    "web.screenshotted_host": add_screenshot_event,
    "network.route.hop": add_route_hop,
}
