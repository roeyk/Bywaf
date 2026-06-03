"""Report detail-section rendering.

Builds the per-finding detail block that accompanies the high-level findings
table: affected resources, evidence snippets, sources, artifacts, provenance,
and latest update time.

Used by:
- analysis.report.render: append detailed context under report rows."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.analysis.finding_display import affected_values, compact_table_text, unique_compact_values
from bywaf.plugins.runtime.artifact.summary import format_artifact_reference

from .model import FindingGroup, effective_finding_payload, sort_unique_events
from .style import finding_text, report_text, subject_text


def render_group_details(context: CommandContext, groups: list[FindingGroup]) -> str:
    """Return compact per-group details for the currently displayed rows."""
    lines = [report_text(context, "section", "Details")]
    for index, group in enumerate(groups, start=1):
        payloads = [effective_finding_payload(event) for event in group.events]
        representative = effective_finding_payload(group.representative)
        title = str(representative.get("title") or representative.get("class") or group.finding_id)
        lines.append(f"{report_text(context, 'index', f'{index}.')} {finding_text(context, 'title', title)}")
        append_detail_line(context, lines, "Finding status", finding_status_values(group))
        append_detail_line(context, lines, "Affected", affected_values(payloads))
        append_detail_line(context, lines, "Evidence", evidence_values(payloads), limit=3)
        append_detail_line(context, lines, "Sources", source_values(group))
        artifacts = artifact_values(context, group)
        append_detail_line(context, lines, "Artifacts", artifacts)
        if artifacts:
            append_detail_line(context, lines, "Artifact groups", artifact_group_values(context, group))
            append_detail_line(context, lines, "Inspect artifacts with", artifact_commands(context, group))
        append_detail_line(context, lines, "Provenance", provenance_values(context, group))
        latest = max(group.events, key=lambda event: event.created_at).created_at.isoformat()
        append_detail_line(context, lines, "Latest update", [latest])
    return "\n".join(lines)


def finding_status_values(group: FindingGroup) -> list[str]:
    """Return candidate/confirmed status labels represented in one group."""
    values = [
        "confirmed" if event.topic == "finding.confirmed" else str(effective_finding_payload(event).get("status") or "")
        for event in group.events
    ]
    return unique_compact_values(values)


def append_detail_line(
    context: CommandContext,
    lines: list[str],
    label: str,
    values: list[str],
    *,
    limit: int = 5,
) -> None:
    """Append one formatted detail line, truncating long value lists."""
    if not values:
        return
    shown = values[:limit]
    suffix = f"; +{len(values) - limit} more" if len(values) > limit else ""
    label_text = report_text(context, "label", label)
    lines.append(f"  {label_text}: {'; '.join(shown)}{suffix}")


def evidence_values(payloads: list[Mapping[str, Any]]) -> list[str]:
    """Return unique evidence snippets from all payloads in a group."""
    return unique_compact_values(
        compact_table_text(payload.get("evidence") or payload.get("description") or "")
        for payload in payloads
    )


def source_values(group: FindingGroup) -> list[str]:
    """Return unique source descriptions from payload and event provenance."""
    values: list[str] = []
    for event in group.events:
        payload = effective_finding_payload(event)
        raw_sources = payload.get("sources")
        if isinstance(raw_sources, list):
            for source in raw_sources:
                values.append(compact_source_value(source))
        values.append(f"{event.source}:{event.topic}")
    return unique_compact_values(values)


def compact_source_value(raw: object) -> str:
    """Return a compact source string."""
    if not isinstance(raw, Mapping):
        return str(raw) if raw else ""
    tool = raw.get("tool") or raw.get("source") or raw.get("name")
    topic = raw.get("topic")
    if tool and topic:
        return f"{tool}:{topic}"
    if tool:
        return str(tool)
    return compact_table_text(raw)


def artifact_values(context: CommandContext, group: FindingGroup) -> list[str]:
    """Return artifacts associated with a finding group by step or pipeline."""
    return unique_compact_values(format_artifact_reference(context, event) for event in finding_artifact_events(context, group))


def finding_artifact_events(context: CommandContext, group: FindingGroup) -> list[Event]:
    """Return artifact events associated with a finding group."""
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


def provenance_values(context: CommandContext, group: FindingGroup) -> list[str]:
    """Return event, pipeline, and step provenance strings for one group."""
    event_ids = [str(event.id) for event in group.events if event.id is not None]
    pipelines = unique_compact_values(event.pipeline_id or "" for event in group.events)
    steps = unique_compact_values(event.command_run_id or "" for event in group.events)
    values = []
    if event_ids:
        values.append(f"events={','.join(event_ids)}")
    if pipelines:
        values.append(f"pipeline={','.join(subject_text(context, 'pipeline', item) for item in pipelines)}")
    if steps:
        values.append(f"step={','.join(subject_text(context, 'step', item) for item in steps)}")
    return values
