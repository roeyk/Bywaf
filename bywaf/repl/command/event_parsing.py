"""Selector parsing helpers for REPL event commands.

Used by:
- interactive REPL commands, app-dispatch helpers, and display tests.
- operators who inspect runtime state through built-in commands.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ...event.filters import parse_event_sort


EVENT_SELECTOR_KEYS = {"job", "step", "pipeline", "serial", "topic"}
EVENT_FOLLOW_SCOPE_KEYS = {"job", "step", "pipeline"}


@dataclass(frozen=True, slots=True)
class EventFollowQuery:
    """Parsed `event follow` query with one runtime scope and payload filters.

    Constructed by: `parse_event_follow_query()` from REPL selector tokens.
    Used by: `events.follow_events()` to decide polling scope, filters, and
    one-shot/follow behavior.
    """

    scope_key: str | None
    scope_value: str | None
    topic: str | None
    filters: dict[str, str]
    since: str
    limit: int
    interval: float
    once: bool


def parse_event_query(tokens: Sequence[str]) -> tuple[str, dict[str, str], int, str]:
    """Split `event` input into one scope selector, payload filters, and limit."""
    selector = ""
    filters: dict[str, str] = {}
    limit = 100
    sort_key = "time"
    for token in tokens:
        key, separator, value = token.partition("=")
        if separator:
            if not key or not value:
                raise ValueError("event filters must be key=value")
            if key == "limit":
                limit = parse_event_limit(value)
            elif key == "sort":
                sort_key = parse_event_sort(value)
            elif key in EVENT_SELECTOR_KEYS and not selector:
                selector = token
            elif key in EVENT_SELECTOR_KEYS:
                raise ValueError("event accepts only one scope selector")
            else:
                filters[key] = value
            continue
        if selector:
            raise ValueError("usage: event <id|topic|job=id|step=id|pipeline=id|serial=id> [field=value ...]")
        selector = token
    return selector, filters, limit, sort_key


def parse_event_follow_query(tokens: Sequence[str]) -> EventFollowQuery:
    """Parse `event follow` selectors and payload filters."""
    scope_key: str | None = None
    scope_value: str | None = None
    topic: str | None = None
    filters: dict[str, str] = {}
    since = "now"
    limit = 100
    interval = 0.25
    once = False
    for token in tokens:
        key, separator, value = token.partition("=")
        if not separator or not key or not value:
            raise ValueError("event follow selectors must be key=value")
        if key in EVENT_FOLLOW_SCOPE_KEYS:
            if scope_key is not None:
                raise ValueError("event follow accepts only one runtime scope selector")
            scope_key, scope_value = key, value
        elif key == "topic":
            topic = value
        elif key == "since":
            if value not in {"now", "beginning"}:
                raise ValueError("event follow since= must be now or beginning")
            since = value
        elif key == "limit":
            limit = parse_event_limit(value)
        elif key == "interval":
            interval = parse_event_interval(value)
        elif key == "once":
            once = parse_event_boolean(value, "once")
        else:
            filters[key] = value
    return EventFollowQuery(scope_key, scope_value, topic, filters, since, limit, interval, once)


def parse_event_limit(raw: str) -> int:
    """Parse the maximum number of event rows to display."""
    try:
        limit = int(raw)
    except ValueError as exc:
        raise ValueError(f"invalid event limit= value: {raw}") from exc
    if limit < 1:
        raise ValueError("event limit= must be at least 1")
    return limit


def parse_event_interval(raw: str) -> float:
    """Parse polling interval seconds for `event follow`."""
    try:
        interval = float(raw)
    except ValueError as exc:
        raise ValueError(f"invalid event follow interval= value: {raw}") from exc
    if interval <= 0:
        raise ValueError("event follow interval= must be greater than 0")
    return interval


def parse_event_boolean(raw: str, key: str) -> bool:
    """Parse true/false selector values for event options."""
    value = raw.casefold()
    if value in {"true", "yes", "1", "on"}:
        return True
    if value in {"false", "no", "0", "off"}:
        return False
    raise ValueError(f"event follow {key}= must be true or false")


def parse_events_selectors(selectors: Sequence[str]) -> int:
    """Parse `events [tail|--tail] [last=N]` and return the requested tail size."""
    limit = 25
    seen_last = False
    for selector in selectors:
        if selector in {"tail", "--tail"}:
            continue
        if selector.startswith("last="):
            if seen_last:
                raise ValueError("events last= may only be provided once")
            seen_last = True
            limit = parse_events_last_value(selector.split("=", 1)[1])
            continue
        raise ValueError("usage: events [tail|--tail] [last=N]")
    return limit


def parse_events_last_value(raw: str) -> int:
    """Parse a positive integer event tail size."""
    try:
        limit = int(raw)
    except ValueError as exc:
        raise ValueError(f"invalid events last= value: {raw}") from exc
    if limit < 1:
        raise ValueError("events last= must be at least 1")
    return limit
