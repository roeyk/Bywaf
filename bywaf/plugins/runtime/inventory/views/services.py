"""Service inventory aggregation and rendering."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

from .shared import add_value, default_port, format_product, host_sort_value, join_values, sort_note, split_sort

SERVICE_TOPICS = ("port.open", "service.detected", "http.endpoint", "tcp.banner", "tls.certificate")


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


def render_services_inventory(context: CommandContext, events: list[Event], scope: str, sort: str = "host") -> str:
    """Render service inventory from network and web service facts."""
    inventory = build_service_inventory(events)
    if not inventory:
        return "Services: no service inventory"
    sort_key, descending = split_sort(sort, "host")
    rows = [
        (
            service.host,
            service.port,
            service.protocol,
            join_values(service.services),
            join_values(service.products),
            join_values(service.urls, limit=2) or join_values(service.evidence, limit=2),
        )
        for service in sorted(inventory.values(), key=lambda item: service_inventory_sort_key(item, sort_key), reverse=descending)
    ]
    table = render_table(
        ("HOST", "PORT", "PROTO", "SERVICE", "PRODUCT", "URL / EVIDENCE"),
        rows,
        cell_subjects=("host", "port", "protocol", "service", "value", "url"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Services: {scope} ({len(rows)} services)\n{sort_note(sort, 'host')}\n{table}"


def service_inventory_sort_key(service: ServiceInventory, key: str) -> Any:
    """Return a sortable service inventory value."""
    if key == "port":
        return (service.port, host_sort_value(service.host), service.protocol)
    if key == "service":
        return (join_values(service.services), host_sort_value(service.host), service.port)
    if key == "product":
        return (join_values(service.products), host_sort_value(service.host), service.port)
    return (host_sort_value(service.host), service.port, service.protocol)

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

def service_record(services: dict[tuple[str, int, str], ServiceInventory], payload: dict[str, Any]) -> ServiceInventory:
    """Return a service inventory row, creating it if needed."""
    host = str(payload.get("host") or "unknown")
    port = int(payload.get("port") or default_port(payload))
    protocol = str(payload.get("protocol") or "tcp")
    return services.setdefault((host, port, protocol), ServiceInventory(host, port, protocol))

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
