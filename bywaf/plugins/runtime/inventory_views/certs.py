"""Inventory renderer for certs facts."""

from __future__ import annotations

from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

from .shared import host_sort_value, sort_note, split_sort


def render_certs_inventory(context: CommandContext, events: list[Event], scope: str, sort: str = "host") -> str:
    """Render TLS certificate inventory."""
    cert_events = [event for event in events if event.topic == "tls.certificate"]
    if not cert_events:
        return "Certificates: no certificate inventory"
    sort_key, descending = split_sort(sort, "host")
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("port", ""),
            event.payload.get("subject", ""),
            event.payload.get("issuer", ""),
            event.payload.get("not_after", ""),
        )
        for event in sorted(cert_events, key=lambda event: cert_sort_key(event, sort_key), reverse=descending)
    ]
    table = render_table(
        ("HOST", "PORT", "SUBJECT", "ISSUER", "VALID UNTIL"),
        rows,
        cell_subjects=("host", "port", "", "", "value"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Certificates: {scope} ({len(rows)} certificates)\n{sort_note(sort, 'host')}\n{table}"

def cert_sort_key(event: Event, key: str) -> Any:
    """Return a sortable certificate event value."""
    payload = event.payload
    if key == "port":
        return (int(payload.get("port") or 0), host_sort_value(str(payload.get("host") or "")))
    if key == "subject":
        return (str(payload.get("subject") or ""), host_sort_value(str(payload.get("host") or "")))
    if key == "issuer":
        return (str(payload.get("issuer") or ""), host_sort_value(str(payload.get("host") or "")))
    if key == "not_after":
        return (str(payload.get("not_after") or ""), host_sort_value(str(payload.get("host") or "")))
    return (host_sort_value(str(payload.get("host") or "")), int(payload.get("port") or 0))

def cert_event_keys(event: Event) -> set[tuple[str, str, int]]:
    """Return stable certificate identity keys for one event."""
    if event.topic != "tls.certificate":
        return set()
    host = str(event.payload.get("host") or "")
    port = int(event.payload.get("port") or 0)
    return {("cert", host, port)} if host and port else set()
