"""REPL event query and filtering built-ins.

Provides `event` and `events`, including selector parsing, variable expansion
for built-in filters, and the bridge from job/step/pipeline selectors to event
rows.

Used by:
- bywaf.repl.commands: registers event handlers in the built-in dispatch table.
"""

from __future__ import annotations

import shlex
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..command.parser import expand_variables_in_text
from ..event.filters import event_matches_payload_filters, parse_event_sort, select_event_rows
from ..runner import Runner
from .display import display_expansion_preview, print_event_info, print_events, print_job, print_run_variables

if TYPE_CHECKING:
    from .state import ShellState


EVENT_SELECTOR_KEYS = {"job", "step", "pipeline", "serial", "topic"}
EVENT_FOLLOW_SCOPE_KEYS = {"job", "step", "pipeline"}


@dataclass(frozen=True, slots=True)
class EventFollowQuery:
    """Parsed `event follow` query with one runtime scope and payload filters."""

    scope_key: str | None
    scope_value: str | None
    topic: str | None
    filters: dict[str, str]
    since: str
    limit: int
    interval: float
    once: bool


def handle_event_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print matching events."""
    del line
    if rest is None:
        print("usage: event <id|topic|job=id|step=id|pipeline=id|serial=id> [field=value ...]")
        return None
    rest = expand_builtin_filter_text(runner, state, rest, "event")
    tokens = shlex.split(rest)
    if tokens and tokens[0] == "follow":
        follow_events(runner, parse_event_follow_query(tokens[1:]))
        return None
    selector, filters, limit, sort_key = parse_event_query(tokens)
    if selector.isdigit():
        print_filtered_event_id(runner, selector, filters)
    elif selector.startswith("job=") and not filters:
        print_job(runner, str(resolve_job_selector(runner, selector.split("=", 1)[1])))
    elif selector.startswith("job="):
        source_limit = event_source_limit(limit, filters)
        events = runner.events.events_for_job(resolve_job_selector(runner, selector.split("=", 1)[1]), limit=source_limit)
        print_events(select_event_rows(events, filters, sort_key, limit), runner)
    elif selector.startswith("step="):
        run_id = runner.runtime.resolve_run_serial(selector.split("=", 1)[1])
        print_run_variables(runner, run_id)
        source_limit = event_source_limit(limit, filters)
        events = runner.events.events_matching(command_run_id=run_id, limit=source_limit)
        print_events(select_event_rows(events, filters, sort_key, limit), runner)
    elif selector.startswith("pipeline="):
        pipeline_id = runner.runtime.resolve_pipeline_serial(selector.split("=", 1)[1])
        source_limit = event_source_limit(limit, filters)
        events = runner.events.events_matching(pipeline_id=pipeline_id, limit=source_limit)
        print_events(select_event_rows(events, filters, sort_key, limit), runner)
    elif selector.startswith("serial="):
        source_limit = event_source_limit(limit, filters)
        events = runner.events.events_for_serial(selector.split("=", 1)[1], limit=source_limit)
        print_events(select_event_rows(events, filters, sort_key, limit), runner)
    elif selector.startswith("topic="):
        topic = selector.split("=", 1)[1]
        source_limit = event_source_limit(limit, filters)
        events = runner.events.events_matching(topic=topic, limit=source_limit)
        print_events(select_event_rows(events, filters, sort_key, limit), runner)
    else:
        source_limit = event_source_limit(limit, filters)
        events = runner.events.events_matching(topic=selector or None, limit=source_limit)
        print_events(select_event_rows(events, filters, sort_key, limit), runner)
    return None


def follow_events(runner: Runner, query: EventFollowQuery) -> None:
    """Stream event-ledger rows until Ctrl-C or a one-shot follow completes."""
    pipeline_id, command_run_id = resolve_event_follow_scope(runner, query)
    job_id = resolve_job_selector(runner, str(query.scope_value)) if query.scope_key == "job" else None
    after_id = 0 if query.since == "beginning" else runner.events.latest_event_id()
    print("following events; press Ctrl-C to stop")
    try:
        while True:
            if job_id is not None:
                events = runner.events.events_for_job(job_id, after_id=after_id, limit=max(query.limit * 20, 100))
                if query.topic is not None:
                    events = [event for event in events if event.topic == query.topic]
            else:
                events = runner.events.events_after(
                    after_id,
                    topic=query.topic,
                    pipeline_id=pipeline_id,
                    command_run_id=command_run_id,
                    limit=max(query.limit * 20, 100),
                )
            if events:
                after_id = max(event.id or after_id for event in events)
                print_events(select_event_rows(events, query.filters, "time", query.limit), runner)
                if query.once:
                    return
            elif query.once:
                return
            else:
                time.sleep(query.interval)
    except KeyboardInterrupt:
        print("stopped following events")


def resolve_event_follow_scope(runner: Runner, query: EventFollowQuery) -> tuple[str | None, str | None]:
    """Resolve follow selectors to durable pipeline and step serials."""
    if query.scope_key == "job":
        return None, None
    if query.scope_key == "pipeline":
        return runner.runtime.resolve_pipeline_serial(str(query.scope_value)), None
    if query.scope_key == "step":
        return None, runner.runtime.resolve_run_serial(str(query.scope_value))
    return None, None


def handle_events_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print recent events."""
    del state, line
    limit = parse_events_selectors(shlex.split(rest)) if rest else 25
    print_events(runner.events.recent_events(limit), runner)
    return None


def print_filtered_event_id(runner: Runner, selector: str, filters: dict[str, str]) -> None:
    """Print a single event id, optionally only when it matches payload filters."""
    if not filters:
        print_event_info(runner, selector)
        return
    event = runner.events.event_by_id(int(selector))
    if event and event_matches_payload_filters(event, filters):
        print_events([event], runner)


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


def event_source_limit(display_limit: int, filters: dict[str, str]) -> int:
    """Fetch extra source rows when filtering so older matches are not hidden."""
    if not filters:
        return display_limit
    return max(1000, display_limit * 20)


def expand_builtin_filter_text(runner: Runner, state: ShellState, text: str | None, command: str) -> str | None:
    """Expand `$vars` in built-in query/filter text."""
    if text is None:
        display_expansion_preview(runner, command, changed=False)
        return None
    if "$" not in text:
        display_expansion_preview(runner, f"{command} {text}".strip(), changed=False)
        return text
    scope = state.active_context or command
    expanded, _names = expand_variables_in_text(text, runner.registry.varstore, scope)
    display_expansion_preview(runner, f"{command} {expanded}".strip(), changed=expanded != text)
    return expanded


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


def resolve_job_selector(runner: Runner, value: str) -> int:
    """Resolve a local job id or durable job serial for built-in selectors."""
    try:
        return int(value)
    except ValueError:
        resolved = runner.runtime.job_id_for_serial(value)
        if resolved is None:
            raise ValueError(f"unknown job: {value}") from None
        return int(resolved)
