"""Event payload filtering helpers.

Provides small query helpers for matching structured event payload fields,
including host shortcuts and stable display sorting.

Used by:
- REPL event inspection: filter and sort `event <topic> field=value` output.
- runtime listings: narrow jobs, pipelines, and steps by associated events."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .events import Event

EVENT_SORT_ALIASES = {"transport": "protocol", "status": "state"}


def parse_event_sort(raw: str) -> str:
    """Parse event sort keys and friendly aliases."""
    key = EVENT_SORT_ALIASES.get(raw, raw)
    if key not in {"time", "id", "host", "protocol", "state", "topic", "source"}:
        raise ValueError("event sort= must be one of time, host, protocol, state, topic, source")
    return key


def filter_events_by_payload(events: Sequence[Event], filters: dict[str, str]) -> list[Event]:
    """Return events whose JSON payload satisfies all requested field filters."""
    if not filters:
        return list(events)
    return [event for event in events if event_matches_payload_filters(event, filters)]


def select_event_rows(events: Sequence[Event], filters: dict[str, str], sort_key: str, limit: int) -> list[Event]:
    """Apply payload filters, optional sorting, and the display limit."""
    rows = filter_events_by_payload(events, filters)
    if sort_key not in {"time", "id"}:
        rows = sorted(rows, key=lambda event: event_sort_value(event, sort_key))
    return rows[:limit]


def event_sort_value(event: Event, sort_key: str) -> tuple[str, int]:
    """Return stable sort values for event rows."""
    if sort_key in {"topic", "source"}:
        return (str(getattr(event, sort_key)), event.id or 0)
    values = payload_filter_values(event.payload, sort_key)
    value = values[0] if values else ""
    return (str(value), event.id or 0)


def event_matches_payload_filters(event: Event, filters: dict[str, str]) -> bool:
    """Check one event against comma-separated payload field filters."""
    for key, raw_values in filters.items():
        accepted = {value.strip() for value in raw_values.split(",") if value.strip()}
        if not accepted:
            raise ValueError(f"{key}= requires at least one value")
        values = payload_filter_values(event.payload, key)
        if not any(str(value) in accepted for value in values):
            return False
    return True


def any_event_matches_payload_filters(events: Sequence[Event], filters: dict[str, str]) -> bool:
    """Return whether any event in a runtime scope matches all payload filters."""
    if not filters:
        return True
    return any(event_matches_payload_filters(event, filters) for event in events)


def parse_payload_filter_tokens(tokens: Sequence[str]) -> dict[str, str]:
    """Parse generic `field=value` payload filters."""
    filters: dict[str, str] = {}
    for token in tokens:
        key, separator, value = token.partition("=")
        if not separator or not key or not value:
            raise ValueError("filters must be field=value")
        filters[key] = value
    return filters


def payload_filter_values(payload: dict[str, Any], key: str) -> list[Any]:
    """Return candidate payload values for a filter key.

    Dotted keys traverse nested dictionaries, for example
    `target.host=192.0.2.10`. The plain `host=` shortcut also checks common
    nested target/source host fields because vulnerability finding events often
    wrap host identity in a structured target object.
    """
    values = value_at_path(payload, key)
    if key == "host":
        for path in ("target.host", "source.host", "endpoint.host"):
            values.extend(value_at_path(payload, path))
    flattened: list[Any] = []
    for value in values:
        if isinstance(value, (list, tuple, set)):
            flattened.extend(value)
        else:
            flattened.append(value)
    return [value for value in flattened if value is not None]


def value_at_path(payload: dict[str, Any], key: str) -> list[Any]:
    """Read one exact payload field path."""
    current: Any = payload
    for part in key.split("."):
        if not isinstance(current, dict) or part not in current:
            return []
        current = current[part]
    return [current]
