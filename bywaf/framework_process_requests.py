"""Framework process request handlers.

Provides host-side handling for process execution requests emitted by plugin
contexts.

Used by:
- `framework_requests.FRAMEWORK_REQUEST_HANDLERS`: dispatches process request
  topics to these handlers.
- plugin process services: emit durable request events that the shell drains.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from .db import EventStore
from .plugin.process import normalize_argv, run_process_argv
from .plugin.services import attach_generated_artifact
from .runner import Runner


def handle_process_run_request(runner: Runner, state, event) -> None:
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
    artifact_payload = attach_framework_process_output(runner, event, argv, completed)
    payload = {
        "argv": list(argv),
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "ok": completed.returncode == 0,
        "source": event.payload.get("source", event.source),
        "job_id": event.payload.get("job_id"),
        "request_event_id": event.id,
    }
    payload.update(artifact_payload)
    runner.events.publish(
        "process.run",
        payload,
        "framework",
        pipeline_id=event.pipeline_id,
        command_run_id=event.command_run_id,
        parent_command_run_id=event.parent_command_run_id,
    )


def attach_framework_process_output(runner: Runner, event, argv: tuple[str, ...], completed) -> dict[str, object]:
    """Attach one stdout/stderr transcript for shell-handled process requests."""
    transcript = "\n".join(
        (
            "argv: " + " ".join(argv),
            f"returncode: {completed.returncode}",
            f"ok: {str(completed.returncode == 0).lower()}",
            "",
            "stdout:",
            completed.stdout,
            "",
            "stderr:",
            completed.stderr,
        )
    )
    name = f"{Path(argv[0]).name}-{event.id}-output.txt" if event.id is not None else f"{Path(argv[0]).name}-output.txt"
    artifact = attach_generated_artifact(
        cast(EventStore, runner.events),
        transcript.encode("utf-8"),
        name=name,
        content_type="text/plain; charset=utf-8",
        note="framework-mediated process stdout/stderr",
        commandlet=str(event.payload.get("source") or event.source),
        job_id=event.payload.get("job_id"),
        pipeline_id=event.pipeline_id,
        command_run_id=event.command_run_id,
        parent_command_run_id=event.parent_command_run_id,
    )
    return {
        "artifact_id": artifact.artifact_id,
        "artifact_row_id": artifact.id,
        "artifact_name": artifact.name,
        "artifact_sha256": artifact.sha256,
    }


def handle_process_stream_request(runner: Runner, state, event) -> None:
    """Handle or deny externally inserted process-stream requests."""
    del state
    if bool(event.payload.get("handled")):
        return
    deny_framework_request(
        runner,
        event,
        "process streaming requests must be handled by context.process.stream",
    )


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
