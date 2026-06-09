"""Runtime note event storage, lookup, and formatting helpers.

Used by: `note.Note.run()` after selector parsing has identified whether the
operator is adding or showing notes.
"""

from __future__ import annotations

from pathlib import Path

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.time_format import format_operator_timestamp


def add_note(context: CommandContext, selectors: dict[str, str]) -> None:
    """Append a note to an existing runtime entity."""
    events = context.event_store("note")
    selectors = resolve_note_selectors(context, selectors)
    note_text = selectors.get("text")
    if note_text is None:
        # file= imports operator-authored text into the audit stream; the file
        # itself is not retained unless separately attached as an artifact.
        path = Path(selectors["file"]).expanduser()
        context.audit_capability("filesystem.read")
        note_text = path.read_text(errors="replace").strip()
    payload = {
        "note": note_text,
        "job_id": int(selectors["job"]) if "job" in selectors else None,
        "pipeline_id": selectors.get("pipeline"),
        "command_run_id": selectors.get("step"),
        "parent_command_run_id": None,
        "commandlet": "note",
    }
    events.publish(
        "note.attached",
        payload,
        "framework",
        pipeline_id=selectors.get("pipeline"),
        command_run_id=selectors.get("step"),
    )
    context.output("note added")


def select_note_events(context: CommandContext, selectors: dict[str, str]) -> list[Event]:
    """Return note events matching the selected runtime entity."""
    events = context.event_store("note")
    selectors = resolve_note_selectors(context, selectors)
    if "job" in selectors:
        job_id = int(selectors["job"])
        return events.events_for_job_topic(job_id, "note.attached")
    return events.events_matching(
        topic="note.attached",
        command_run_id=selectors.get("step"),
        pipeline_id=selectors.get("pipeline"),
    )


def format_note_event(event: Event) -> str:
    """Format one note with timestamp first."""
    timestamp = format_operator_timestamp(event.created_at)
    job_id = event.payload.get("job_id", "")
    pipeline_id = event.payload.get("pipeline_id") or event.pipeline_id or ""
    run_id = event.payload.get("command_run_id") or event.command_run_id or ""
    commandlet = event.payload.get("commandlet", event.source)
    note = event.payload.get("note", "")
    return f"{timestamp} job={job_id} pipeline={pipeline_id} step={run_id} {commandlet}: {note}"


def resolve_note_selectors(context: CommandContext, selectors: dict[str, str]) -> dict[str, str]:
    """Resolve user-facing runtime IDs to durable serials for note events."""
    resolved = dict(selectors)
    runtime = context.runtime_store("note")
    if "step" in resolved:
        resolved["step"] = runtime.resolve_run_serial(resolved["step"])
    if "pipeline" in resolved:
        resolved["pipeline"] = runtime.resolve_pipeline_serial(resolved["pipeline"])
    if "job" in resolved:
        resolved["job"] = resolve_job_selector(context, resolved["job"])
    return resolved


def resolve_job_selector(context: CommandContext, value: str) -> str:
    """Resolve a local job id or durable job serial for note selectors."""
    if value.isdigit():
        return value
    resolved = context.runtime_store("note").job_id_for_serial(value)
    if resolved is None:
        raise ValueError(f"unknown job: {value}")
    return resolved
