"""Framework request processing for plugin-to-shell interactions.

Provides handlers for framework request events such as console output,
notifications, and control-plane actions that should be processed by the shell.

Used by:
- REPL shell and non-interactive run helpers: drain pending framework requests.
- commandlets: communicate with the framework through request events."""


from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .db import Subscription
from .pager import page_file
from .plugin.process import normalize_argv, run_process_argv
from .rendering import Table, render_console_table
from .runner import Runner


class FrameworkRequestState(Protocol):
    """Mutable state needed while draining framework request events."""

    prompt_pattern: str
    handled_request_ids: set[int]
    framework_request_after_id: int


def process_framework_requests(runner: Runner, state: FrameworkRequestState) -> None:
    """Apply interpreter-owned requests that plugins wrote to the event bus."""
    for event in runner.events.fetch(
        Subscription(
            topics=(
                "shell.prompt.requested",
                "framework.console.alert.requested",
                "framework.console.output.requested",
                "framework.file.page.requested",
                "framework.process.run.requested",
                "framework.process.stream.requested",
                "framework.render.table.requested",
            ),
            after_id=state.framework_request_after_id,
            limit=1000,
        )
    ):
        if event.id is not None:
            state.framework_request_after_id = max(state.framework_request_after_id, event.id)
        if event.id is None or event.id in state.handled_request_ids:
            continue
        # Request events are durable; this in-memory handled set prevents a REPL
        # drain cycle from applying the same request twice.
        state.handled_request_ids.add(event.id)
        handle_framework_request(runner, state, event)


def handle_framework_request(runner: Runner, state: FrameworkRequestState, event) -> None:
    """Validate and apply one framework request event."""
    handler = FRAMEWORK_REQUEST_HANDLERS.get(event.topic)
    if handler is None:
        deny_framework_request(runner, event, f"unsupported request topic: {event.topic}")
        return
    handler(runner, state, event)


def handle_prompt_request(runner: Runner, state: FrameworkRequestState, event) -> None:
    """Validate and apply a prompt-change request."""
    requested_prompt = event.payload.get("prompt")
    if isinstance(requested_prompt, str) and requested_prompt:
        old_prompt = state.prompt_pattern
        state.prompt_pattern = requested_prompt
        runner.events.publish(
            "shell.prompt.updated",
            {
                "old_prompt": old_prompt,
                "new_prompt": requested_prompt,
                "request_event_id": event.id,
            },
            "framework",
        )
        return
    deny_framework_request(runner, event, "prompt must be a non-empty string")


def emit_console_alert(runner: Runner, event) -> None:
    """Validate, audit, and display a plugin-requested console alert."""
    message = event.payload.get("message")
    if not isinstance(message, str) or not message:
        deny_framework_request(runner, event, "alert message must be a non-empty string")
        return
    level = event.payload.get("level", "alert")
    if not isinstance(level, str) or not level:
        deny_framework_request(runner, event, "alert level must be a non-empty string")
        return
    source = event.payload.get("source")
    if not isinstance(source, str) or not source:
        source = event.source
    command_id = event.command_run_id or event.payload.get("command_run_id") or "interactive"
    payload = {
        "message": message,
        "level": level,
        "source": source,
        "job_id": event.payload.get("job_id"),
        "request_event_id": event.id,
    }
    runner.events.publish(
        "console.alert",
        payload,
        "framework",
        pipeline_id=event.pipeline_id,
        command_run_id=event.command_run_id,
        parent_command_run_id=event.parent_command_run_id,
    )
    if not bool(event.payload.get("silent")):
        print(f"{source} <{command_id}>: {message}", flush=True)


def handle_console_alert_request(runner: Runner, state: FrameworkRequestState, event) -> None:
    """Handle a console-alert framework request."""
    del state
    emit_console_alert(runner, event)


def emit_console_output(runner: Runner, event) -> None:
    """Validate, audit, and display plugin-requested command output."""
    text = event.payload.get("text", "")
    end = event.payload.get("end", "\n")
    if not isinstance(text, str):
        deny_framework_request(runner, event, "console output text must be a string")
        return
    if not isinstance(end, str):
        deny_framework_request(runner, event, "console output end must be a string")
        return
    runner.events.publish(
        "console.output",
        {
            "text": text,
            "end": end,
            "source": event.payload.get("source", event.source),
            "job_id": event.payload.get("job_id"),
            "request_event_id": event.id,
        },
        "framework",
        pipeline_id=event.pipeline_id,
        command_run_id=event.command_run_id,
        parent_command_run_id=event.parent_command_run_id,
    )
    print(text, end=end, flush=True)


def handle_console_output_request(runner: Runner, state: FrameworkRequestState, event) -> None:
    """Handle a console-output framework request."""
    del state
    emit_console_output(runner, event)


def handle_render_table_request(runner: Runner, state: FrameworkRequestState, event) -> None:
    """Validate, audit, and display a plugin-requested structured table."""
    del state
    try:
        table = Table.from_payload(event.payload)
    except ValueError as exc:
        deny_framework_request(runner, event, str(exc))
        return
    rendered = render_console_table(table, runner.registry.varstore.get)
    runner.events.publish(
        "render.table",
        {
            "title": table.title,
            "columns": [column.key for column in table.columns],
            "row_count": len(table.rows),
            "format": "console",
            "source": event.payload.get("source", event.source),
            "job_id": event.payload.get("job_id"),
            "request_event_id": event.id,
        },
        "framework",
        pipeline_id=event.pipeline_id,
        command_run_id=event.command_run_id,
        parent_command_run_id=event.parent_command_run_id,
    )
    if rendered:
        print(rendered, flush=True)


def handle_file_page_request(runner: Runner, state: FrameworkRequestState, event) -> None:
    """Validate, audit, and display a plugin-requested local file page."""
    del state
    raw_path = event.payload.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        deny_framework_request(runner, event, "page path must be a non-empty string")
        return
    path = Path(raw_path).expanduser()
    if not path.exists():
        deny_framework_request(runner, event, f"{path} does not exist")
        return
    if path.is_dir():
        deny_framework_request(runner, event, f"{path} is a directory")
        return
    if bool(event.payload.get("background")):
        deny_framework_request(runner, event, "file paging requires a foreground commandlet")
        return
    runner.events.publish(
        "console.page",
        {
            "path": str(path),
            "source": event.payload.get("source", event.source),
            "job_id": event.payload.get("job_id"),
            "request_event_id": event.id,
        },
        "framework",
        pipeline_id=event.pipeline_id,
        command_run_id=event.command_run_id,
        parent_command_run_id=event.parent_command_run_id,
    )
    try:
        page_file(path)
    finally:
        if bool(event.payload.get("temporary")):
            path.unlink(missing_ok=True)


def handle_process_run_request(runner: Runner, state: FrameworkRequestState, event) -> None:
    """Validate, execute, and audit a framework-mediated process request."""
    del state
    if bool(event.payload.get("handled")):
        return
    raw_argv = event.payload.get("argv")
    if not isinstance(raw_argv, list) or not all(isinstance(part, str) for part in raw_argv):
        deny_framework_request(runner, event, "process argv must be a list of strings")
        return
    try:
        argv = normalize_argv(raw_argv)
    except (TypeError, ValueError) as exc:
        deny_framework_request(runner, event, str(exc))
        return
    # Process requests are validated in the shell process, even though the
    # commandlet asked for them. This keeps subprocess execution mediated.
    raw_cwd = event.payload.get("cwd")
    if raw_cwd is not None and not isinstance(raw_cwd, str):
        deny_framework_request(runner, event, "process cwd must be a string")
        return
    raw_timeout = event.payload.get("timeout")
    if raw_timeout is not None and not isinstance(raw_timeout, int | float):
        deny_framework_request(runner, event, "process timeout must be numeric")
        return
    try:
        completed = run_process_argv(argv, cwd=raw_cwd, timeout=raw_timeout)
    except Exception as exc:
        deny_framework_request(runner, event, str(exc))
        return
    runner.events.publish(
        "process.run",
        {
            "argv": list(argv),
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "ok": completed.returncode == 0,
            "source": event.payload.get("source", event.source),
            "job_id": event.payload.get("job_id"),
            "request_event_id": event.id,
        },
        "framework",
        pipeline_id=event.pipeline_id,
        command_run_id=event.command_run_id,
        parent_command_run_id=event.parent_command_run_id,
    )


def handle_process_stream_request(runner: Runner, state: FrameworkRequestState, event) -> None:
    """Handle or deny externally inserted process-stream requests."""
    del state
    if bool(event.payload.get("handled")):
        return
    deny_framework_request(
        runner,
        event,
        "process streaming requests must be handled by context.process.stream",
    )


FRAMEWORK_REQUEST_HANDLERS = {
    "shell.prompt.requested": handle_prompt_request,
    "framework.console.alert.requested": handle_console_alert_request,
    "framework.console.output.requested": handle_console_output_request,
    "framework.file.page.requested": handle_file_page_request,
    "framework.process.run.requested": handle_process_run_request,
    "framework.process.stream.requested": handle_process_stream_request,
    "framework.render.table.requested": handle_render_table_request,
}


def deny_framework_request(runner: Runner, event, reason: str) -> None:
    """Record a denied framework request for auditability."""
    runner.events.publish(
        "framework.request.denied",
        {
            "request_event_id": event.id,
            "request_topic": event.topic,
            "reason": reason,
        },
        "framework",
    )
