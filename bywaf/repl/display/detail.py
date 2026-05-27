"""Detailed event inspection rendering.

Provides sectioned event detail output with runtime scope, causality, payload,
and captured command-variable context.

Used by:
- repl.commands: implement `event <id>` and scoped event detail views."""

from __future__ import annotations

import sys
from datetime import datetime
from typing import Any

from ...runtime_display import commandlet_from_command_line, display_runtime_serial
from ...runner import Runner
from ...style import ansi_color
from ...time_format import format_operator_timestamp
from .settings import (
    DEFAULT_EVENT_COLOR_MODE,
    DEFAULT_EVENT_KEY_COLOR,
    EVENT_COLOR_MODE_VAR,
    EVENT_COMMANDLET_COLOR,
    EVENT_HEADING_KEY_COLOR,
    EVENT_HEADING_VALUE_COLOR,
    EVENT_KEY_COLOR_VAR,
)
from .variables import format_var_assignment

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


def format_event_timestamp(value: datetime) -> str:
    """Render full event time in the operator's local timezone."""
    return format_operator_timestamp(value)


def format_event_heading(runner: Runner, event_id: int | None) -> str:
    """Return the highlighted detail heading for one event."""
    if not event_color_enabled(runner):
        return f"Event ID: {event_id}"
    return (
        f"{ansi_color('Event ID', EVENT_HEADING_KEY_COLOR)}: "
        f"{ansi_color(str(event_id), EVENT_HEADING_VALUE_COLOR)}"
    )


def event_actor(source: str, topic: str, payload: dict[str, Any]) -> str:
    """Infer the component most likely responsible for an event."""
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
        "Parent step": event.parent_command_run_id or payload.get("parent_command_run_id"),
    }
    rows = [(label, value) for label, value in scope.items() if value not in (None, "")]
    if not rows:
        return
    print(format_event_section_header(runner, "Scope"))
    for label, value in rows:
        print(format_event_kv(runner, label, value, prefix="  "))


def print_event_job_context(runner: Runner, payload: dict[str, Any]) -> None:
    """Print the job row associated with an event payload, when present."""
    job_id = payload.get("job_id")
    if job_id in (None, ""):
        return
    try:
        job = runner.runtime.job(int(job_id))
    except (TypeError, ValueError):
        job = None
    if job is None:
        print(format_event_kv(runner, "Job", "missing"))
        return
    command = str(job["command_line"] or "")
    print(format_event_section_header(runner, "Job"))
    print(format_event_kv(runner, "ID", job["id"], prefix="  "))
    print(format_event_kv(runner, "Serial", display_runtime_serial(job["serial"]), prefix="  "))
    print(format_event_kv(runner, "Status", job["status"], prefix="  "))
    if job["started_at"]:
        print(format_event_kv(runner, "Launched", format_event_timestamp(datetime.fromisoformat(job["started_at"])), prefix="  "))
    if job["finished_at"]:
        print(format_event_kv(runner, "Finished", format_event_timestamp(datetime.fromisoformat(job["finished_at"])), prefix="  "))
    if command:
        print(format_event_kv(runner, "Commandlet", commandlet_from_command_line(command), prefix="  "))
        print(format_event_kv(runner, "Command", command, prefix="  "))


def print_event_command_context(runner: Runner, payload: dict[str, Any], command_run_id: str | None) -> None:
    """Print pipeline-step context from payload or its argument event."""
    run_id = command_run_id or payload.get("command_run_id")
    command = payload.get("command")
    commandlet = payload.get("commandlet")
    args: list[Any] | None = None
    launched: str | None = None
    if run_id and (commandlet is None or command is None):
        # Many events only carry a step id. Look up the framework-owned
        # command.run.arguments event to recover commandlet/arg context.
        matches = runner.events.events_matching(topic="command.run.arguments", command_run_id=str(run_id), limit=1)
        if matches:
            args_payload = matches[0].payload
            commandlet = commandlet or args_payload.get("commandlet")
            args_value = args_payload.get("args")
            args = args_value if isinstance(args_value, list) else None
            launched = format_event_timestamp(matches[0].created_at)
    if not any((run_id, commandlet, command, args, launched)):
        return
    print(format_event_section_header(runner, "Command"))
    if run_id:
        print(format_event_kv(runner, "Run", run_id, prefix="  "))
    if launched:
        print(format_event_kv(runner, "Launched", launched, prefix="  "))
    if commandlet:
        print(format_event_kv(runner, "Commandlet", commandlet, prefix="  "))
    if command:
        print(format_event_kv(runner, "Line", command, prefix="  "))
    if args is not None:
        print(format_event_kv(runner, "Args", " ".join(str(arg) for arg in args), prefix="  "))


def print_event_causality(runner: Runner, payload: dict[str, Any]) -> None:
    """Print event ids that this event claims as its cause."""
    cause_fields = (
        ("Request event", "request_event_id"),
        ("Trigger event", "trigger_event_id"),
        ("Parent event", "parent_event_id"),
    )
    rows = [(label, payload[key]) for label, key in cause_fields if payload.get(key) not in (None, "")]
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


def format_event_kv(runner: Runner, key: str, value: object, *, prefix: str = "") -> str:
    """Return an event detail key/value row with optional colored keys."""
    if not event_color_enabled(runner):
        return f"{prefix}{key}: {value}"
    key_color = runner.registry.varstore.get(EVENT_KEY_COLOR_VAR, DEFAULT_EVENT_KEY_COLOR) or DEFAULT_EVENT_KEY_COLOR
    return f"{prefix}{ansi_color(key, key_color)}: {format_event_value(key, value)}"


def format_event_value(key: str, value: object) -> str:
    """Return special value styling for event detail fields."""
    text = str(value)
    if key.casefold() == "commandlet":
        return ansi_color(text, EVENT_COMMANDLET_COLOR)
    return text


def format_event_section_header(runner: Runner, label: str) -> str:
    """Return a highlighted section header for event detail output."""
    if not event_color_enabled(runner):
        return f"{label}:"
    return f"{ansi_color(label, EVENT_HEADING_KEY_COLOR)}:"


def event_color_enabled(runner: Runner) -> bool:
    """Return whether event detail listings should include ANSI color escapes."""
    mode = (
        runner.registry.varstore.get(EVENT_COLOR_MODE_VAR, DEFAULT_EVENT_COLOR_MODE) or DEFAULT_EVENT_COLOR_MODE
    ).casefold()
    if mode in {"0", "false", "no", "never", "off", "plain"}:
        return False
    if mode in {"1", "true", "yes", "always", "on"}:
        return True
    return sys.stdout.isatty()


def format_payload_value(value: Any) -> str:
    """Render nested payload values without a one-line raw dict dump."""
    if isinstance(value, list | tuple):
        return ", ".join(format_payload_value(item) for item in value)
    if isinstance(value, dict):
        # Sort nested keys so event detail output remains stable across Python
        # versions and plugin payload construction order.
        return ", ".join(f"{key}={format_payload_value(value[key])}" for key in sorted(value))
    return str(value)


def print_run_variables(runner: Runner, command_run_id: str) -> None:
    """Print the variable snapshot captured for a pipeline step."""
    rows = runner.runtime.command_run_var_rows(command_run_id)
    if not rows:
        return
    print("Variables:")
    for row in rows:
        print(format_var_assignment(runner, row["name"], row["value"], prefix="  "))
