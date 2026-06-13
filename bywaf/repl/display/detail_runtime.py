"""Runtime lookup sections for detailed event inspection.

Used by: `repl.display.detail_context` and `repl.display.detail` while
rendering job, command-run, and captured-variable context for `event <id>` and
`event vars <run_id>` output.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ...runtime.display import commandlet_from_command_line, display_runtime_serial
from ...runner import Runner
from .detail_format import format_event_kv, format_event_section_header, format_event_timestamp
from .variables import format_var_assignment, subject_text


def print_event_job_context(runner: Runner, payload: dict[str, Any]) -> None:
    """Print the job row associated with an event payload, when present.

    Called by: `print_event_info()` through `detail_context`.
    """
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
        print(
            format_event_kv(
                runner,
                "Commandlet",
                commandlet_from_command_line(command),
                prefix="  ",
            )
        )
        print(
            format_event_kv(
                runner,
                "Command",
                subject_text(runner, "command_line", command),
                prefix="  ",
            )
        )


def print_event_command_context(
    runner: Runner, payload: dict[str, Any], command_run_id: str | None
) -> None:
    """Print pipeline-step context from payload or its argument event.

    Called by: `print_event_info()` through `detail_context`.
    """
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
        print(
            format_event_kv(
                runner,
                "Line",
                subject_text(runner, "command_line", command),
                prefix="  ",
            )
        )
    if args is not None:
        print(
            format_event_kv(
                runner,
                "Args",
                subject_text(runner, "command_line", " ".join(str(arg) for arg in args)),
                prefix="  ",
            )
        )


def print_run_variables(runner: Runner, command_run_id: str) -> None:
    """Print the variable snapshot captured for a pipeline step.

    Called by: `event vars <run_id>` through `repl.command.events`.
    """
    rows = runner.runtime.command_run_var_rows(command_run_id)
    if not rows:
        return
    print("Variables:")
    for row in rows:
        print(format_var_assignment(runner, row["name"], row["value"], prefix="  "))
