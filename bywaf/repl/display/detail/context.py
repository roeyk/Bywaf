"""Runtime context sections for detailed event inspection.

Used by: `repl.display.detail.print_event_info()` to render event scope,
associated runtime context, causality, and payload rows.
"""

from __future__ import annotations

from typing import Any

from ....runner import Runner
from .format import (
    format_event_kv,
    format_event_section_header,
    format_payload_value,
)
from .runtime import (
    print_event_command_context,
    print_event_job_context,
    print_run_variables,
)

__all__ = [
    "event_actor",
    "print_event_causality",
    "print_event_command_context",
    "print_event_job_context",
    "print_event_payload",
    "print_event_scope",
    "print_run_variables",
]


def event_actor(source: str, topic: str, payload: dict[str, Any]) -> str:
    """Infer the component most likely responsible for an event.

    Called by: `print_event_info()` for the summary header rows.
    """
    if topic.startswith("framework.trigger."):
        trigger_id = payload.get("trigger_id") or payload.get("name")
        return f"trigger:{trigger_id}" if trigger_id else "trigger"
    commandlet = payload.get("commandlet")
    if commandlet:
        return f"commandlet:{commandlet}"
    if source in {"framework", "runner"}:
        return source
    return f"plugin:{source}"


def print_event_scope(runner: Runner, event, payload: dict[str, Any]) -> None:
    """Print job, pipeline, step, and parent-step scope for an event."""
    scope = {
        "Job": payload.get("job_id"),
        "Pipeline": event.pipeline_id or payload.get("pipeline_id"),
        "Step": event.command_run_id or payload.get("command_run_id"),
        "Parent step": event.parent_command_run_id
        or payload.get("parent_command_run_id"),
    }
    rows = [(label, value) for label, value in scope.items() if value not in (None, "")]
    if not rows:
        return
    print(format_event_section_header(runner, "Scope"))
    for label, value in rows:
        print(format_event_kv(runner, label, value, prefix="  "))


def print_event_causality(runner: Runner, payload: dict[str, Any]) -> None:
    """Print event ids that this event claims as its cause."""
    cause_fields = (
        ("Request event", "request_event_id"),
        ("Trigger event", "trigger_event_id"),
        ("Parent event", "parent_event_id"),
    )
    rows = [
        (label, payload[key])
        for label, key in cause_fields
        if payload.get(key) not in (None, "")
    ]
    if not rows:
        return
    print(format_event_section_header(runner, "Cause"))
    for label, value in rows:
        print(format_event_kv(runner, label, value, prefix="  "))


def print_event_payload(runner: Runner, payload: dict[str, Any]) -> None:
    """Print payload fields as readable key/value rows."""
    if not payload:
        return
    print(format_event_section_header(runner, "Payload"))
    for key in sorted(payload):
        print(format_event_kv(runner, key, format_payload_value(payload[key]), prefix="  "))
