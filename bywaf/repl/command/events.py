"""REPL event query and filtering built-ins.

Provides `event` and `events`, including selector parsing, variable expansion
for built-in filters, and the bridge from job/step/pipeline selectors to event
rows.

Used by:
- bywaf.repl.commands: registers event handlers in the built-in dispatch table.
"""

from __future__ import annotations

import shlex
from collections.abc import Callable
from typing import TYPE_CHECKING

from ...command.parser import expand_variables_in_text
from ...event.filters import event_matches_payload_filters, select_event_rows
from ...runner import Runner
from ..display import display_expansion_preview, print_event_info, print_events, print_job, print_run_variables
from .event.follow import follow_events, resolve_job_selector
from .event.parsing import (
    parse_event_follow_query,
    parse_event_query,
    parse_events_selectors,
)

if TYPE_CHECKING:
    from ..state import ShellState


EventQueryHandler = Callable[[Runner, str, dict[str, str], int, str], None]


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
    print_event_query(runner, selector, filters, limit, sort_key)
    return None


def print_event_query(runner: Runner, selector: str, filters: dict[str, str], limit: int, sort_key: str) -> None:
    """Print one parsed `event` query."""
    if selector.isdigit():
        print_filtered_event_id(runner, selector, filters)
        return
    key, _separator, value = selector.partition("=")
    # This lookup uses EVENT_QUERY_HANDLERS, defined below, in place of an
    # if/elif ladder over scoped event selectors.
    handler = EVENT_QUERY_HANDLERS.get(key)
    if handler is not None and selector:
        handler(runner, value, filters, limit, sort_key)
        return
    print_topic_query(runner, selector, filters, limit, sort_key)


def print_job_query(runner: Runner, value: str, filters: dict[str, str], limit: int, sort_key: str) -> None:
    """Print events, or a job summary, for one job selector."""
    job_id = resolve_job_selector(runner, value)
    if not filters:
        print_job(runner, str(job_id))
        return
    source_limit = event_source_limit(limit, filters)
    events = runner.events.events_for_job(job_id, limit=source_limit)
    print_events(select_event_rows(events, filters, sort_key, limit), runner)


def print_step_query(runner: Runner, value: str, filters: dict[str, str], limit: int, sort_key: str) -> None:
    """Print variables and events for one pipeline-step selector."""
    run_id = runner.runtime.resolve_run_serial(value)
    print_run_variables(runner, run_id)
    source_limit = event_source_limit(limit, filters)
    events = runner.events.events_matching(command_run_id=run_id, limit=source_limit)
    print_events(select_event_rows(events, filters, sort_key, limit), runner)


def print_pipeline_query(runner: Runner, value: str, filters: dict[str, str], limit: int, sort_key: str) -> None:
    """Print events for one pipeline selector."""
    pipeline_id = runner.runtime.resolve_pipeline_serial(value)
    source_limit = event_source_limit(limit, filters)
    events = runner.events.events_matching(pipeline_id=pipeline_id, limit=source_limit)
    print_events(select_event_rows(events, filters, sort_key, limit), runner)


def print_serial_query(runner: Runner, value: str, filters: dict[str, str], limit: int, sort_key: str) -> None:
    """Print events for one durable event serial selector."""
    source_limit = event_source_limit(limit, filters)
    events = runner.events.events_for_serial(value, limit=source_limit)
    print_events(select_event_rows(events, filters, sort_key, limit), runner)


def print_topic_query(runner: Runner, value: str, filters: dict[str, str], limit: int, sort_key: str) -> None:
    """Print events for one topic selector or the default recent-event query."""
    source_limit = event_source_limit(limit, filters)
    events = runner.events.events_matching(topic=value or None, limit=source_limit)
    print_events(select_event_rows(events, filters, sort_key, limit), runner)


# handle_event_command() uses this dispatch table after parse_event_query()
# identifies the selector kind.
EVENT_QUERY_HANDLERS: dict[str, EventQueryHandler] = {
    "job": print_job_query,
    "pipeline": print_pipeline_query,
    "serial": print_serial_query,
    "step": print_step_query,
    "topic": print_topic_query,
}


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
