"""Rendering helpers for the `ports` view commandlet."""

from __future__ import annotations

import ipaddress

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import (
    command_context_style_getter,
    render_table,
    runtime_sort_key,
    runtime_sort_reverse,
    terminal_table_width,
)


def render_ports_table(context: CommandContext, events: list[Event], sort_key: str) -> str:
    """Render either grouped scan results or raw event rows."""
    display_key = runtime_sort_key(sort_key)
    reverse = runtime_sort_reverse(sort_key)
    if display_key == "host":
        return render_ports_by_host(context, events, reverse=reverse)
    if display_key == "port":
        return render_ports_by_port(context, events, reverse=reverse)
    sorted_events = sort_port_events(events, sort_key)
    rows = [raw_port_row(event) for event in sorted_events]
    return render_table(
        ("HOST", "PORT", "PROTO", "SERVICE", "REASON", "EVENT"),
        rows,
        cell_subjects=("host", "port", "protocol", "service", "", "event"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )


def render_ports_by_host(context: CommandContext, events: list[Event], *, reverse: bool = False) -> str:
    """Render one host row with all ports discovered on that host."""
    grouped: dict[str, list[Event]] = {}
    for event in events:
        grouped.setdefault(str(event.payload.get("host", "")), []).append(event)
    rows = [
        (
            host,
            ", ".join(dict.fromkeys(port_endpoint_text(event) for event in sort_port_events(grouped[host], "port"))),
        )
        for host in sorted(grouped, key=ip_sort_value, reverse=reverse)
    ]
    return render_table(
        ("HOST", "OPEN PORTS"),
        rows,
        cell_subjects=("host", "port"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )


def render_ports_by_port(context: CommandContext, events: list[Event], *, reverse: bool = False) -> str:
    """Render one port row with all hosts exposing that port."""
    grouped: dict[tuple[int, str, str], list[Event]] = {}
    for event in events:
        payload = event.payload
        grouped.setdefault(
            (
                int(payload.get("port") or 0),
                str(payload.get("protocol") or ""),
                str(payload.get("service") or ""),
            ),
            [],
        ).append(event)
    rows = [
        (
            port,
            protocol,
            service,
            ", ".join(sorted(hosts_for_events(grouped[key]), key=ip_sort_value)),
        )
        for key, port, protocol, service in (
            (key, key[0], key[1], key[2])
            for key in sorted(grouped, key=lambda item: (item[0], item[1], item[2]), reverse=reverse)
        )
    ]
    return render_table(
        ("PORT", "PROTO", "SERVICE", "HOSTS"),
        rows,
        cell_subjects=("port", "protocol", "service", "host"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )


def sort_port_events(events: list[Event], sort_key: str) -> list[Event]:
    """Sort port rows by the requested operator-facing column."""
    display_key = runtime_sort_key(sort_key)
    reverse = runtime_sort_reverse(sort_key)
    if display_key in {"event", "time"}:
        return sorted(events, key=lambda event: event.id or 0, reverse=reverse)
    return sorted(events, key=lambda event: port_sort_value(event, display_key), reverse=reverse)


def port_sort_value(event: Event, sort_key: str) -> tuple[object, ...]:
    """Return stable sort values for port rows."""
    payload = event.payload
    if sort_key == "host":
        return (ip_sort_value(payload.get("host")), int(payload.get("port") or 0), event.id or 0)
    if sort_key == "port":
        return (int(payload.get("port") or 0), str(payload.get("host") or ""), event.id or 0)
    return (str(payload.get(sort_key) or ""), str(payload.get("host") or ""), int(payload.get("port") or 0), event.id or 0)


def ip_sort_value(value: object) -> tuple[int, bytes | str]:
    """Sort IP addresses numerically and fall back to text for host names."""
    text = str(value or "")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return (99, text)
    return (address.version, address.packed)


def raw_port_row(event: Event) -> tuple[object, ...]:
    """Return a one-event table row."""
    return (
        event.payload.get("host", ""),
        event.payload.get("port", ""),
        event.payload.get("protocol", ""),
        event.payload.get("service", ""),
        event.payload.get("reason", ""),
        event.id,
    )


def port_endpoint_text(event: Event) -> str:
    """Return compact `port/proto service` text for grouped host rows."""
    payload = event.payload
    endpoint = f"{payload.get('port', '')}/{payload.get('protocol', '')}".rstrip("/")
    service = str(payload.get("service") or "")
    return f"{endpoint} {service}".strip()


def hosts_for_events(events: list[Event]) -> set[str]:
    """Return unique hosts from a group of port events."""
    return {str(event.payload.get("host", "")) for event in events if event.payload.get("host") is not None}


__all__ = [
    "hosts_for_events",
    "ip_sort_value",
    "port_endpoint_text",
    "port_sort_value",
    "raw_port_row",
    "render_ports_by_host",
    "render_ports_by_port",
    "render_ports_table",
    "sort_port_events",
]
