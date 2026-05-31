"""Host inventory aggregation and rendering."""

from __future__ import annotations

from dataclasses import dataclass, field

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

from .shared import add_value, finding_hosts, host_sort_value, join_values, port_label


@dataclass(slots=True)


class HostInventory:
    """Aggregated operator-facing facts for one host."""

    host: str
    names: set[str] = field(default_factory=set)
    statuses: set[str] = field(default_factory=set)
    ports: set[str] = field(default_factory=set)
    web_urls: set[str] = field(default_factory=set)
    findings: set[str] = field(default_factory=set)


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

def host_record(hosts: dict[str, HostInventory], value: object) -> HostInventory:
    """Return a host inventory row, creating it if needed."""
    host = str(value or "")
    if not host:
        host = "unknown"
    return hosts.setdefault(host, HostInventory(host))

def host_event_keys(event: Event) -> set[tuple[str, str]]:
    """Return stable host inventory identity keys for one event."""
    payload = event.payload
    values: set[str] = set()
    if event.topic in {"host.found", "name.resolved", "port.open", "http.endpoint", "service.detected"}:
        add_value(values, payload.get("host"))
    if event.topic == "finding.candidate":
        values.update(finding_hosts(payload))
    return {("host", value) for value in values}
