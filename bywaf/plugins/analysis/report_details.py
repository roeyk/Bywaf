"""Report detail-section rendering.

Builds the per-finding detail block that accompanies the high-level findings
table: affected resources, evidence snippets, sources, artifacts, provenance,
and latest update time.

Used by:
- analysis.report_render: append detailed context under report rows."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from bywaf.events import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.analysis.finding_report import compact_table_text

from .report_model import FindingGroup, effective_finding_payload, sort_unique_events
from .report_style import finding_text, report_text, subject_text


def render_group_details(context: CommandContext, groups: list[FindingGroup]) -> str:
    """Return compact per-group details for the currently displayed rows."""
    lines = [report_text(context, "section", "Details")]
    for index, group in enumerate(groups, start=1):
        payloads = [effective_finding_payload(event) for event in group.events]
        representative = effective_finding_payload(group.representative)
        title = str(representative.get("title") or representative.get("class") or group.finding_id)
        lines.append(f"{report_text(context, 'index', f'{index}.')} {finding_text(context, 'title', title)}")
        append_detail_line(context, lines, "Affected", affected_values(payloads))
        append_detail_line(context, lines, "Evidence", evidence_values(payloads), limit=3)
        append_detail_line(context, lines, "Sources", source_values(group))
        append_detail_line(context, lines, "Artifacts", artifact_values(context, group))
        append_detail_line(context, lines, "Provenance", provenance_values(context, group))
        latest = max(group.events, key=lambda event: event.created_at).created_at.isoformat()
        append_detail_line(context, lines, "Latest update", [latest])
    return "\n".join(lines)


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


def affected_values(payloads: list[Mapping[str, Any]]) -> list[str]:
    """Return unique affected targets from all payloads in a group."""
    values: list[str] = []
    for payload in payloads:
        values.extend(values_from_affected(payload.get("affected")))
        target_value = compact_target_value(payload.get("target"))
        if target_value:
            values.append(target_value)
    return unique_compact_values(values)


def values_from_affected(raw: object) -> list[str]:
    """Return display strings from a normalized affected list."""
    if not isinstance(raw, list):
        return []
    values: list[str] = []
    for item in raw:
        value = compact_target_value(item)
        if value:
            values.append(value)
    return values


def compact_target_value(raw: object) -> str:
    """Return one compact target/affected resource string."""
    if not isinstance(raw, Mapping):
        return str(raw) if raw else ""
    url = raw.get("url")
    if url:
        return str(url)
    host = str(raw.get("host") or raw.get("ip") or "")
    port = str(raw.get("port") or "")
    protocol = str(raw.get("protocol") or "")
    path = str(raw.get("path") or "")
    scheme = str(raw.get("scheme") or "")
    if host:
        authority = f"{host}:{port}" if port else host
        if protocol:
            authority = f"{authority}/{protocol}"
        return f"{scheme}://{authority}{path}" if scheme else f"{authority}{path}"
    return compact_table_text(raw)


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
    steps = unique_compact_values(event.command_run_id or "" for event in group.events)
    pipelines = unique_compact_values(event.pipeline_id or "" for event in group.events)
    events: list[Event] = []
    for step in steps:
        events.extend(context.events.query(topic="artifact.attached", step=step, limit=1000))
    if not steps:
        for pipeline in pipelines:
            events.extend(context.events.query(topic="artifact.attached", pipeline=pipeline, limit=1000))
    return unique_compact_values(format_artifact_event(context, event) for event in sort_unique_events(events))


def format_artifact_event(context: CommandContext, event: Event) -> str:
    """Return compact display text for one artifact attachment event."""
    payload = event.payload
    row_id = str(payload.get("artifact_row_id") or "")
    artifact_id = str(payload.get("artifact_id") or "")
    name = str(payload.get("name") or artifact_id or "artifact")
    content_type = str(payload.get("content_type") or "")
    size = str(payload.get("size") or "")
    prefix = subject_text(context, "artifact", f"#{row_id}") if row_id else subject_text(context, "artifact", artifact_id)
    name_text = subject_text(context, "path", name)
    serial_text = subject_text(context, "serial", artifact_id)
    parts = [prefix, name_text]
    if content_type:
        parts.append(content_type)
    if size:
        parts.append(f"size={size}")
    if artifact_id:
        parts.append(serial_text)
    return " ".join(part for part in parts if part)


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


def unique_compact_values(values: Iterable[object]) -> list[str]:
    """Return stable unique non-empty compact strings."""
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = compact_table_text(value)
        if text and text not in seen:
            unique.append(text)
            seen.add(text)
    return unique
