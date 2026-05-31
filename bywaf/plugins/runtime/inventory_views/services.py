"""Service inventory aggregation and rendering."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

from .shared import add_value, default_port, format_product, host_sort_value, join_values

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
