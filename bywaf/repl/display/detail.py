"""Detailed event inspection rendering.

Provides sectioned event detail output with runtime scope, causality, payload,
and captured command-variable context.

Used by:
- repl.commands: implement `event <id>` and scoped event detail views."""

from __future__ import annotations

from ...runner import Runner
from .detail_context import (
    event_actor,
    print_event_causality,
    print_event_command_context,
    print_event_job_context,
    print_event_payload,
    print_event_scope,
    print_run_variables,  # noqa: F401 - re-exported for repl.display facade
)
from .detail_format import (
    event_color_enabled,  # noqa: F401 - preserves older detail-module import path
    format_event_heading,
    format_event_kv,
    format_event_timestamp,
)


def print_event_info(runner: Runner, event_id_text: str) -> None:
    """Print one event with runtime context and readable payload fields."""
    try:
        event_id = int(event_id_text)
    except ValueError:
        print(f"error: invalid event id: {event_id_text}")
        return
    event = runner.events.event_by_id(event_id)
    if event is None:
        print(f"error: unknown event: {event_id}")
        return
    payload = event.payload
    # Detail view is deliberately layered: identity first, then provenance,
    # then causality, then raw payload fields.
    print(format_event_heading(runner, event.id))
    print(format_event_kv(runner, "Topic", event.topic))
    print(format_event_kv(runner, "Created", format_event_timestamp(event.created_at)))
    print(format_event_kv(runner, "Source", event.source))
    print(format_event_kv(runner, "Actor", event_actor(event.source, event.topic, payload)))
    print_event_scope(runner, event, payload)
    print_event_job_context(runner, payload)
    print_event_command_context(runner, payload, event.command_run_id)
    print_event_causality(runner, payload)
    print_event_payload(runner, payload)
