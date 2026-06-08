"""Artifact detail helpers for finding reports.

Called by: `report.details.render_group_details()` when a selected finding
group has step or pipeline artifacts that should be shown alongside evidence
and provenance.
"""

from __future__ import annotations

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.analysis.finding_display import unique_compact_values
from bywaf.plugins.runtime.artifact.summary import format_artifact_reference

from .model import FindingGroup, sort_unique_events
from .style import subject_text


def artifact_values(context: CommandContext, group: FindingGroup) -> list[str]:
    """Return artifacts associated with a finding group by step or pipeline."""
    return unique_compact_values(format_artifact_reference(context, event) for event in finding_artifact_events(context, group))


def finding_artifact_events(context: CommandContext, group: FindingGroup) -> list[Event]:
    """Return artifact events associated with a finding group.

    Called by: `artifact_values()` and `artifact_group_values()` before report
    detail rendering formats artifact references.
    """
    steps = unique_compact_values(event.command_run_id or "" for event in group.events)
    pipelines = unique_compact_values(event.pipeline_id or "" for event in group.events)
    events: list[Event] = []
    for step in steps:
        events.extend(context.events.query(topic="artifact.attached", step=step, limit=1000))
    if not steps:
        for pipeline in pipelines:
            events.extend(context.events.query(topic="artifact.attached", pipeline=pipeline, limit=1000))
    return sort_unique_events(events)


def artifact_group_values(context: CommandContext, group: FindingGroup) -> list[str]:
    """Return grouped artifact references by producing commandlet/step."""
    events = finding_artifact_events(context, group)
    grouped: dict[str, list[str]] = {}
    for event in events:
        payload = event.payload
        label = str(payload.get("commandlet") or event.source or "")
        step = str(payload.get("command_run_id") or event.command_run_id or "")
        if step:
            label = f"{label}/{step}" if label else step
        grouped.setdefault(label or "artifact", []).append(format_artifact_reference(context, event))
    if len(grouped) <= 1:
        return []
    return [f"{label}: {', '.join(values)}" for label, values in sorted(grouped.items())]


def artifact_commands(context: CommandContext, group: FindingGroup) -> list[str]:
    """Return artifact-list commands for a finding's runtime scope."""
    steps = unique_compact_values(event.command_run_id or "" for event in group.events)
    pipelines = unique_compact_values(event.pipeline_id or "" for event in group.events)
    commands = [f"artifact list step={step}" for step in steps]
    if not commands:
        commands = [f"artifact list pipeline={pipeline}" for pipeline in pipelines]
    return [subject_text(context, "command_line", command) for command in commands]
