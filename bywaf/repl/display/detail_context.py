"""Runtime context sections for detailed event inspection.

Used by: `repl.display.detail.print_event_info()` to render event scope,
associated job/command context, causality, and captured variables.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ...runtime_display import commandlet_from_command_line, display_runtime_serial
from ...runner import Runner
from .detail_format import (
    format_event_kv,
    format_event_section_header,
    format_event_timestamp,
    format_payload_value,
)
from .variables import format_var_assignment, subject_text


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
        print(
            format_event_kv(
                runner,
                "Launched",
                format_event_timestamp(datetime.fromisoformat(job["started_at"])),
                prefix="  ",
            )
        )
    if job["finished_at"]:
        print(
            format_event_kv(
                runner,
                "Finished",
                format_event_timestamp(datetime.fromisoformat(job["finished_at"])),
                prefix="  ",
            )
        )
    if command:
        print(format_event_kv(runner, "Commandlet", commandlet_from_command_line(command), prefix="  "))
        print(format_event_kv(runner, "Command", subject_text(runner, "command_line", command), prefix="  "))


def print_event_command_context(
    runner: Runner, payload: dict[str, Any], command_run_id: str | None
) -> None:
    """Print pipeline-step context from payload or its argument event."""
    run_id = command_run_id or payload.get("command_run_id")
    command = payload.get("command")
    commandlet = payload.get("commandlet")
    args: list[Any] | None = None
    launched: str | None = None
    if run_id and (commandlet is None or command is None):
        # Many events only carry a step id. Look up the framework-owned
        # command.run.arguments event to recover commandlet/arg context.
        matches = runner.events.events_matching(
            topic="command.run.arguments", command_run_id=str(run_id), limit=1
        )
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
        print(format_event_kv(runner, "Line", subject_text(runner, "command_line", command), prefix="  "))
    if args is not None:
        print(
            format_event_kv(
                runner,
                "Args",
                subject_text(runner, "command_line", " ".join(str(arg) for arg in args)),
                prefix="  ",
            )
        )


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


def print_run_variables(runner: Runner, command_run_id: str) -> None:
    """Print the variable snapshot captured for a pipeline step."""
    rows = runner.runtime.command_run_var_rows(command_run_id)
    if not rows:
        return
    print("Variables:")
    for row in rows:
        print(format_var_assignment(runner, row["name"], row["value"], prefix="  "))
