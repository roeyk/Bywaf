"""Event payload filtering helpers.

Provides small query helpers for matching structured event payload fields,
including host shortcuts and stable display sorting.

Used by:
- REPL event inspection: filter and sort `event <topic> field=value` output.
- runtime listings: narrow jobs, pipelines, and steps by associated events."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .model import Event

EVENT_SORT_ALIASES = {"transport": "protocol", "status": "state"}


@dataclass(frozen=True, slots=True)
class SelectorExpression:
    """Parsed selector values with positive matches and negated exclusions.

    Constructed by: `parse_selector_expression()`.
    Consumed by: `selector_matches_values()` when applying event payload
    filters to REPL, job, pipeline, and step views.
    """

    include: tuple[str, ...]
    exclude: tuple[str, ...]


def parse_event_sort(raw: str) -> str:
    """Parse event sort keys and friendly aliases.

    Called by: runtime display parsing before event rows are sorted.
    """
    key = EVENT_SORT_ALIASES.get(raw, raw)
    if key not in {"time", "id", "host", "protocol", "state", "topic", "source"}:
        raise ValueError("event sort= must be one of time, host, protocol, state, topic, source")
    return key


def filter_events_by_payload(events: Sequence[Event], filters: dict[str, str]) -> list[Event]:
    """Return events whose JSON payload satisfies all requested field filters.

    Used by: `select_event_rows()` and callers that already have candidate
    events in memory.
    """
    if not filters:
        return list(events)
    return [event for event in events if event_matches_payload_filters(event, filters)]


def select_event_rows(events: Sequence[Event], filters: dict[str, str], sort_key: str, limit: int) -> list[Event]:
    """Apply payload filters, optional sorting, and the display limit.

    Called by: REPL event display paths after fetching candidate events from
    the store.
    """
    rows = filter_events_by_payload(events, filters)
    # Event queries already arrive in chronological/id order. Only secondary
    # payload sorts need explicit reordering before the limit is applied.
    if sort_key not in {"time", "id"}:
        rows = sorted(rows, key=lambda event: event_sort_value(event, sort_key))
    return rows[:limit]


def event_sort_value(event: Event, sort_key: str) -> tuple[str, int]:
    """Return stable sort values for event rows."""
    if sort_key in {"topic", "source"}:
        return (str(getattr(event, sort_key)), event.id or 0)
    # Payload sorts may resolve to multiple candidate values, especially for
    # host shortcuts. Use the first candidate plus event id for stable display.
    values = payload_filter_values(event.payload, sort_key)
    value = values[0] if values else ""
    return (str(value), event.id or 0)


def event_matches_payload_filters(event: Event, filters: dict[str, str]) -> bool:
    """Check one event against comma-separated payload field filters.

    Values inside one selector are ORed, leading `!` values are exclusions, and
    different selector keys are ANDed by the caller's loop.  For example,
    `host=10.0.0.0/24,!10.0.0.5 port=80,443` means host is inside that network
    except one address, and port is either 80 or 443.
    """
    for key, raw_values in filters.items():
        selector = parse_selector_expression(raw_values, key)
        values = payload_filter_values(event.payload, key)
        if not selector_matches_values(selector, values):
            return False
    return True


def any_event_matches_filters(events: Sequence[Event], filters: dict[str, str]) -> bool:
    """Return whether any event in a runtime scope matches all payload filters.

    Used by: job/pipeline/step listing filters when a runtime row should remain
    visible if any associated event matches the payload selectors.
    """
    if not filters:
        return True
    return any(event_matches_payload_filters(event, filters) for event in events)


def parse_payload_filter_tokens(tokens: Sequence[str]) -> dict[str, str]:
    """Parse generic `field=value` payload filters.

    Called by: REPL event parsing and runtime commandlets that accept arbitrary
    event-payload filters after their own command-specific selectors.
    """
    filters: dict[str, str] = {}
    for token in tokens:
        # Payload filters intentionally use a narrow key=value grammar. More
        # specialized selectors such as sort= are stripped by callers first.
        key, separator, value = token.partition("=")
        if not separator or not key or not value:
            raise ValueError("filters must be field=value")
        filters[key] = value
    return filters


def parse_selector_expression(raw_values: str, key: str = "selector") -> SelectorExpression:
    """Parse comma-separated selector values with `!` exclusions.

    Called by: `event_matches_payload_filters()` for every payload filter.
    """
    # Split the selector into positive and negative terms in one pass. Matching
    # later treats positives as OR choices and negatives as exclusions.
    include: list[str] = []
    exclude: list[str] = []
    for raw_value in raw_values.split(","):
        value = raw_value.strip()
        if not value:
            raise ValueError(f"{key}= contains an empty selector value")
        if value.startswith("!"):
            excluded = value[1:].strip()
            if not excluded:
                raise ValueError(f"{key}= contains an empty excluded value")
            exclude.append(excluded)
        else:
            include.append(value)
    if not include and not exclude:
        raise ValueError(f"{key}= requires at least one value")
    return SelectorExpression(tuple(include), tuple(exclude))


def selector_matches_values(selector: SelectorExpression, values: Sequence[Any]) -> bool:
    """Return whether candidate values satisfy include-minus-exclude semantics.

    Called by: `event_matches_payload_filters()` after payload values have been
    extracted and flattened.
    """
    # Normalize payload candidates to strings once, then apply the two selector
    # phases: at least one include must match, and no exclusion may match.
    text_values = [str(value) for value in values if value is not None]
    if not text_values:
        return False
    if selector.include and not any(selector_value_matches(value, pattern) for value in text_values for pattern in selector.include):
        return False
    return not any(selector_value_matches(value, pattern) for value in text_values for pattern in selector.exclude)


def selector_value_matches(value: str, pattern: str) -> bool:
    """Return exact, CIDR, or IPv4 last-octet-range match for one value.

    Used by: `selector_matches_values()` for both include and exclude terms.
    """
    # Preserve cheap exact matching first, then support the two network-friendly
    # selector forms operators commonly use during scan review.
    if value == pattern:
        return True
    if ipv4_octet_range_matches(value, pattern):
        return True
    if "/" not in pattern:
        return False
    try:
        return ipaddress.ip_address(value) in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return False


def ipv4_octet_range_matches(value: str, pattern: str) -> bool:
    """Match compact IPv4 ranges like `192.168.50.1-128`.

    Used by: `selector_value_matches()` before falling back to CIDR parsing.
    """
    if "-" not in pattern:
        return False
    prefix, separator, end = pattern.rpartition(".")
    if not separator or "-" not in end:
        return False
    start_text, end_text = end.split("-", 1)
    try:
        start = int(start_text)
        stop = int(end_text)
        value_ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    # The range shorthand is intentionally IPv4-only and only covers the final
    # octet. CIDR selectors handle broader network expressions.
    if value_ip.version != 4 or not (0 <= start <= stop <= 255):
        return False
    octets = value.split(".")
    if len(octets) != 4 or ".".join(octets[:3]) != prefix:
        return False
    try:
        last = int(octets[3])
    except ValueError:
        return False
    return start <= last <= stop


def payload_filter_values(payload: dict[str, Any], key: str) -> list[Any]:
    """Return candidate payload values for a filter key.

    Dotted keys traverse nested dictionaries, for example
    `target.host=192.0.2.10`. The plain `host=` shortcut also checks common
    nested target/source host fields because vulnerability finding events often
    wrap host identity in a structured target object.
    """
    # Start with the exact key path. The special host= selector then broadens
    # the candidate set to common nested host locations used by finding events.
    values = value_at_path(payload, key)
    if key == "host":
        for path in ("target.host", "source.host", "endpoint.host"):
            values.extend(value_at_path(payload, path))
    # Flatten one level so selectors work the same way against scalar payload
    # fields and simple list-valued fields such as identifiers or tags.
    flattened: list[Any] = []
    for value in values:
        if isinstance(value, (list, tuple, set)):
            flattened.extend(value)
        else:
            flattened.append(value)
    return [value for value in flattened if value is not None]


def value_at_path(payload: dict[str, Any], key: str) -> list[Any]:
    """Read one exact payload field path.

    Used by: `payload_filter_values()` for direct and nested payload selectors.
    """
    current: Any = payload
    for part in key.split("."):
        # Walk dotted keys one object at a time. If any component is absent or
        # points at a scalar value, the path simply contributes no candidates.
        if not isinstance(current, dict) or part not in current:
            return []
        current = current[part]
    return [current]
