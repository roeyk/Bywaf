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
from bywaf.runtime.display import command_context_style_getter, render_table, terminal_table_width

from .style import report_text


@dataclass
class HostOverview:
    """Aggregated report context for one host.

    This represents the network-context row and detail block for one host.
    Constructed by: `host_overviews()` from context and finding events.
    Used by: `render_network_overview()` and `render_host_details()`.
    """

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
    """Return a host-centric overview for report output.

    Called by: `render_finding_report()` for contextual report sections and by
    `render_network_report()` for explicit `report network` output.
    """
    hosts = host_overviews(context_events, finding_events)
    if not hosts:
        return ""
    # The overview table compresses each host bucket into one scanline row:
    # names, ports, services, web context, and finding titles are each
    # de-duplicated while preserving a stable display order where it matters.
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
    # The detail block reuses the same host buckets for users who need the
    # expanded facts after scanning the compact overview table.
    details = render_host_details(context, sorted(hosts.values(), key=lambda item: ip_sort_value(item.host)))
    return report_text(context, "section", "Network overview") + "\n" + table + ("\n" + details if details else "")


def render_host_details(context: CommandContext, hosts: list[HostOverview]) -> str:
    """Return readable per-host fact sections below the compact overview.

    Called by: `render_network_overview()` after the compact table is built.
    The detail block uses the same host buckets so it cannot drift from the
    table rows.
    """
    lines = [report_text(context, "section", "Host details")]
    for host in hosts:
        lines.append(report_text(context, "label", host.host))
        # Append only populated fact groups so sparse host buckets do not create
        # empty labels in the human-facing report.
        append_host_fact(lines, "names", sorted(host.names))
        append_host_fact(lines, "open ports", dict.fromkeys(port_endpoint_text(event) for event in sort_port_events(host.ports, "port")))
        append_host_fact(lines, "services", sorted(host.services))
        append_host_fact(lines, "web", [*sorted(host.screenshots), *sorted(host.routes), *host.endpoints, *sorted(host.web)])
        append_host_fact(lines, "findings", sorted(host.findings))
    return "\n".join(lines) if len(lines) > 1 else ""


def append_host_fact(lines: list[str], label: str, values) -> None:
    """Append one host detail line if values are present.

    Called by: `render_host_details()` for each optional host fact group. It
    de-duplicates values while preserving their incoming order.
    """
    unique = [str(value) for value in dict.fromkeys(values) if str(value)]
    if unique:
        lines.append(f"  {label}: {', '.join(unique)}")


def host_overviews(context_events: list[Event], finding_events: list[Event]) -> dict[str, HostOverview]:
    """Aggregate shared facts into one row per host.

    Called by: network report rendering. Context events populate observed
    topology and service facts; finding events attach moderation-worthy titles
    to the host buckets they affect.
    """
    hosts: dict[str, HostOverview] = {}
    # Context facts are schema-backed observations such as host, port, service,
    # route, endpoint, TLS, WAF, and screenshot data.
    for event in context_events:
        add_context_event(hosts, event)
    # Finding facts may reference one or more affected hosts. Add only the
    # titles here so the overview remains a network-context summary, not a full
    # finding detail renderer.
    for event in finding_events:
        add_finding_event(hosts, event)
    return hosts


ContextEventHandler = Callable[[dict[str, HostOverview], Event], None]


def add_context_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add one shared network fact to host overview buckets.

    Called by: `host_overviews()` for every scoped context event.
    """
    # This lookup uses CONTEXT_EVENT_HANDLERS, defined below, in place of an
    # if/elif ladder over network context event topics.
    handler = CONTEXT_EVENT_HANDLERS.get(event.topic)
    if handler:
        handler(hosts, event)


def add_named_host_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add host/name facts from a shared event.

    Called by: `CONTEXT_EVENT_HANDLERS` for `host.found` and `name.resolved`.
    """
    add_named_host(hosts, event.payload.get("host"), event.payload.get("name"))


def add_http_endpoint_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add HTTP endpoint facts from a shared event.

    Called by: `CONTEXT_EVENT_HANDLERS` for `http.endpoint`.
    """
    add_http_endpoint(hosts, event.payload.get("host"), event.payload.get("url"))


def add_http_path_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add interesting HTTP path facts from a shared event.

    Called by: `CONTEXT_EVENT_HANDLERS` for `http.path`.
    """
    add_http_path(hosts, event.payload.get("host"), event.payload.get("url"), event.payload.get("interesting"))


def add_tls_certificate_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add TLS observations from a shared event.

    Called by: `CONTEXT_EVENT_HANDLERS` for `tls.certificate`.
    """
    add_web_note(hosts, event.payload.get("host"), "tls")


def add_waf_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add WAF observations from a shared event.

    Called by: `CONTEXT_EVENT_HANDLERS` for `web.waf.detected`.
    """
    add_web_note(hosts, event.payload.get("host"), f"waf:{event.payload.get('vendor', '')}".strip(":"))


def add_named_host(hosts: dict[str, HostOverview], host_value: object, name_value: object) -> None:
    """Add a host and optional DNS/operator name.

    Called by: host/name event handlers after extracting payload fields.
    """
    host = ensure_host(hosts, host_value)
    if host and name_value:
        host.names.add(str(name_value))


def add_port_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add one open-port fact to a host bucket.

    Called by: `CONTEXT_EVENT_HANDLERS` for `port.open`. The raw Event is kept
    so existing port formatting/sorting helpers can render protocol and service
    context consistently with the `ports` command.
    """
    host = ensure_host(hosts, event.payload.get("host"))
    if host:
        host.ports.append(event)


def add_http_endpoint(hosts: dict[str, HostOverview], host_value: object, url_value: object) -> None:
    """Add one HTTP endpoint fact to a host bucket.

    Called by: endpoint event handlers and reusable helpers that already split
    host/url payload fields.
    """
    host = ensure_host(hosts, host_value)
    if host:
        host.endpoints.append(str(url_value or ""))


def add_service_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add a normalized service classification to a host bucket.

    Called by: `CONTEXT_EVENT_HANDLERS` for `service.detected`.
    """
    host = ensure_host(hosts, event.payload.get("host"))
    service = str(event.payload.get("service") or "").strip()
    port = event.payload.get("port")
    if host and service:
        host.services.add(f"{service}:{port}" if port else service)


def add_http_path(hosts: dict[str, HostOverview], host_value: object, url_value: object, interesting: object) -> None:
    """Add interesting path observations to the web notes bucket.

    Called by: `add_http_path_event()`. Non-interesting path probes are omitted
    so report network context highlights only review-worthy web observations.
    """
    if not interesting:
        return
    host = ensure_host(hosts, host_value)
    if host:
        host.web.add(str(url_value or "interesting path"))


def add_web_note(hosts: dict[str, HostOverview], host_value: object, note: str) -> None:
    """Add one short web/service note to a host bucket.

    Called by: TLS/WAF handlers and other helpers that need to attach a compact
    web-context label without creating a new report section.
    """
    host = ensure_host(hosts, host_value)
    if host and note:
        host.web.add(note)


def add_screenshot_event(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add screenshot artifact references to a host bucket.

    Called by: `CONTEXT_EVENT_HANDLERS` for `web.screenshotted_host`.
    """
    host = ensure_host(hosts, event.payload.get("host"))
    if not host:
        return
    screenshots = event.payload.get("screenshots")
    if isinstance(screenshots, list) and screenshots:
        host.screenshots.add(f"screenshots:{len(screenshots)}")
    else:
        host.screenshots.add("screenshotted")


def add_route_hop(hosts: dict[str, HostOverview], event: Event) -> None:
    """Add route-hop observations to the responding host bucket.

    Called by: `CONTEXT_EVENT_HANDLERS` for `network.route.hop`. The route
    event may identify the hop by `ip` or `host`; prefer IP when present.
    """
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
    """Add one finding title to all affected host buckets.

    Called by: `host_overviews()` for grouped report finding events.
    """
    payload = event.payload
    title = str(payload.get("title") or payload.get("class") or event.topic)
    for host_value in finding_hosts(payload):
        host = ensure_host(hosts, host_value)
        if host:
            host.findings.add(title)


def ensure_host(hosts: dict[str, HostOverview], value: object) -> HostOverview | None:
    """Return the host bucket for a non-empty host value.

    Called by: all aggregation helpers before mutating a `HostOverview`.
    """
    host = str(value or "").strip()
    if not host:
        return None
    return hosts.setdefault(host, HostOverview(host))


def finding_hosts(payload: dict) -> set[str]:
    """Extract host-like values from a normalized finding payload.

    Called by: `add_finding_event()` so one finding can appear in every affected
    host bucket. It inspects normalized `target`, `target_scope`, and
    `affected` shapes used by finding producers.
    """
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
