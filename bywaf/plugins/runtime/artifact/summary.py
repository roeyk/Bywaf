"""Compact artifact summaries for operator-facing detail views."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter
from bywaf.style import styled_subject_text


def artifact_events_for_step(context: CommandContext, step_id: str) -> list[Event]:
    """Return artifact attachment events for one command run."""
    return unique_artifact_events(
        context.event_store("artifact summary").events_matching(
            topic="artifact.attached",
            command_run_id=step_id,
            limit=10000,
        )
    )


def artifact_events_for_pipeline(context: CommandContext, pipeline_id: str) -> list[Event]:
    """Return artifact attachment events for one pipeline."""
    return unique_artifact_events(
        context.event_store("artifact summary").events_matching(
            topic="artifact.attached",
            pipeline_id=pipeline_id,
            limit=10000,
        )
    )


def artifact_events_for_job(context: CommandContext, job_id: int | str) -> list[Event]:
    """Return artifact attachment events for one job."""
    events = context.event_store("artifact summary").events_for_job_topic(int(job_id), "artifact.attached", limit=10000)
    return unique_artifact_events(events)


def unique_artifact_events(events: Iterable[Event]) -> list[Event]:
    """Return stable unique artifact events by row/id."""
    unique: dict[tuple[str, str], Event] = {}
    for event in sorted(events, key=lambda item: item.id or 0):
        payload = event.payload
        key = (str(payload.get("artifact_row_id") or ""), str(payload.get("artifact_id") or ""))
        if key != ("", ""):
            unique.setdefault(key, event)
    return list(unique.values())


def format_artifact_reference(context: CommandContext, event: Event) -> str:
    """Return one compact artifact reference for reports and runtime details."""
    style_getter = command_context_style_getter(context)
    payload = event.payload
    row_id = str(payload.get("artifact_row_id") or "")
    artifact_id = str(payload.get("artifact_id") or "")
    name = str(payload.get("name") or artifact_id or "artifact")
    content_type = str(payload.get("content_type") or "")
    size = str(payload.get("size") or "")
    prefix = f"#{row_id}" if row_id else artifact_id
    parts = [
        styled_subject_text(style_getter, "artifact", prefix),
        styled_subject_text(style_getter, "path", name),
    ]
    if content_type:
        parts.append(content_type)
    if size:
        parts.append(f"size={size}")
    if artifact_id:
        parts.append(styled_subject_text(style_getter, "serial", artifact_id))
    return " ".join(part for part in parts if part)


def render_artifact_summary(
    context: CommandContext,
    events: list[Event],
    *,
    inspect_command: str,
    limit: int = 8,
) -> str:
    """Render an artifact section with evidence pointers and the exact inspect command."""
    if not events:
        return ""
    style_getter = command_context_style_getter(context)
    heading = styled_subject_text(style_getter, "report.section", "Artifacts")
    lines = [heading]
    for event in events[:limit]:
        lines.append(f"  {format_artifact_reference(context, event)}")
    if len(events) > limit:
        lines.append(f"  +{len(events) - limit} more")
    command = styled_subject_text(style_getter, "command_line", inspect_command)
    label = styled_subject_text(style_getter, "report.label", "inspect artifacts with")
    lines.append(f"{label}: {command}")
    return "\n".join(lines)
