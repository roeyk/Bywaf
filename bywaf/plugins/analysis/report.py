"""Operator-facing report commandlet.

Provides the first reporting inbox over normalized finding events. It renders
grouped findings for recent, step-scoped, job-scoped, or pipeline-scoped work
without requiring operators to inspect raw event payloads.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from argparse import Namespace
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from bywaf.events import Event
from bywaf.finding.grouping import finding_group_key as derive_finding_group_key
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    CommandletBase,
    CompletionContext,
    commandlet,
    option,
)
from bywaf.plugins._args import key_value_to_long_options
from bywaf.plugins.analysis.finding_report import REPORT_FINDING_TOPICS, compact_table_text, finding_rows
from bywaf.plugins.runtime.audit import resolve_pipeline_selector, resolve_run_selector
from bywaf.rendering import Column, Table, render_table

REPORT_ACTIONS = ("accept", "defer", "reject")
REPORT_OPTION_KEYS = {"job", "pipeline", "step", "limit", "note", "status"}
REPORT_STATUS_CHOICES = ("all", "accepted", "deferred", "rejected", "unreviewed")
REVIEW_DECISIONS = {"accept": "accepted", "defer": "deferred", "reject": "rejected"}


@dataclass(frozen=True)
class FindingGroup:
    """A derived reporting group for one logical finding."""

    finding_id: str
    events: tuple[Event, ...]

    @property
    def representative(self) -> Event:
        """Return the newest event to render for this group."""
        return max(self.events, key=lambda event: event.id or 0)


@dataclass(frozen=True)
class ReviewDecision:
    """Latest review state for one finding group."""

    decision: str
    note: str = ""
    event_id: int | None = None


@commandlet(
    name="report",
    description="Show grouped finding reports for recent, step, job, or pipeline scopes.",
    usage=(
        "report [accept|defer|reject <index-range|all>] "
        "[pipeline=<ids>] [job=<ids>] [step=<ids>] [status=<filter>]"
    ),
    examples=(
        "report",
        "report accept 1-3,7",
        "report defer 4 note=needs manual validation",
        "report pipeline=1",
        "report pipeline=1,2,3",
        "report job=7",
        "report step=12",
    ),
    consumes=REPORT_FINDING_TOPICS,
    emits=("report.rendered",),
    capabilities=(
        "db.read:finding.new",
        "db.read:finding.candidate",
        "db.read:finding.merge_candidate",
        "db.read:finding.reviewed",
        "db.write:report.rendered",
        "db.write:finding.reviewed",
        "framework.console.output",
    ),
)
@option("job", "job id or comma-separated job ids", completion="job")
@option("pipeline", "pipeline id or comma-separated pipeline ids", completion="pipeline")
@option("step", "step id or comma-separated step ids", completion="step")
@option("limit", "maximum events to inspect", "1000")
@option("status", "finding review status filter", "unreviewed", REPORT_STATUS_CHOICES)
class Report(CommandletBase):
    """Render grouped finding inboxes and scoped finding reports."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse and render one report view."""
        parser = self.parser()
        parser.usage = self.spec.usage
        parser.add_argument("action", nargs="?", choices=REPORT_ACTIONS)
        parser.add_argument("selection", nargs="?")
        parser.add_argument("--job", default="", help="job id or comma-separated job ids")
        parser.add_argument(
            "--pipeline",
            default="",
            help="pipeline id or comma-separated pipeline ids",
        )
        parser.add_argument("--step", default="", help="step id or comma-separated step ids")
        parser.add_argument("--limit", type=int, default=1000)
        parser.add_argument("--note", default="")
        parser.add_argument("--status", choices=REPORT_STATUS_CHOICES, default="unreviewed")
        parsed = parser.parse_args(normalize_report_args(args))

        input_findings = [event for event in input_events if event.topic in REPORT_FINDING_TOPICS]
        events = input_findings or select_report_scope_events(context, parsed)
        if parsed.action:
            review_report_groups(context, parsed, events)
            return ()
        render_finding_report(context, events, parsed)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete report selectors."""
        del context, args
        candidates = (
            *REPORT_ACTIONS,
            "all",
            "pipeline=",
            "job=",
            "step=",
            "limit=",
            "note=",
            "status=",
            "status=accepted",
            "status=all",
            "status=deferred",
            "status=rejected",
            "status=unreviewed",
        )
        return [candidate for candidate in candidates if candidate.startswith(prefix)]


def normalize_report_args(args: list[str]) -> list[str]:
    """Normalize report key=value selectors, letting final note= consume trailing text."""
    normalized: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token.startswith("note="):
            note = " ".join([token.split("=", 1)[1], *args[index + 1:]]).strip()
            if not note:
                raise ValueError("report note= requires a value")
            normalized.extend(["--note", note])
            break
        normalized.append(token)
        index += 1
    return key_value_to_long_options(normalized, REPORT_OPTION_KEYS)


def select_report_scope_events(context: CommandContext, parsed: Namespace) -> list[Event]:
    """Return finding events selected by explicit scope or latest completed pipeline."""
    limit = int(parsed.limit)
    if parsed.job:
        return events_for_jobs(context, split_selector_values(parsed.job), limit=limit)
    if parsed.pipeline:
        return events_for_pipelines(context, split_selector_values(parsed.pipeline), limit=limit)
    if parsed.step:
        return events_for_steps(context, split_selector_values(parsed.step), limit=limit)
    pipeline_id = latest_completed_pipeline(context)
    if pipeline_id is not None:
        return events_for_pipelines(context, [pipeline_id], limit=limit)
    return events_for_topics(context, REPORT_FINDING_TOPICS, limit=limit)


def events_for_jobs(context: CommandContext, job_ids: list[str], *, limit: int) -> list[Event]:
    """Return finding events associated with one or more jobs."""
    events: list[Event] = []
    event_store = context.event_store("report job selector")
    for job_id in job_ids:
        try:
            numeric_id = int(job_id)
        except ValueError as exc:
            raise ValueError(f"invalid job id: {job_id}") from exc
        job_events = event_store.events_for_job(numeric_id, limit=limit)
        for event in job_events:
            if event.topic in REPORT_FINDING_TOPICS:
                events.append(event)
        pipelines = {event.pipeline_id for event in job_events if event.pipeline_id}
        runs = {event.command_run_id for event in job_events if event.command_run_id}
        for pipeline_id in pipelines:
            events.extend(
                events_for_topics(context, REPORT_FINDING_TOPICS, pipeline=pipeline_id, limit=limit)
            )
        for run_id in runs:
            events.extend(
                events_for_topics(context, REPORT_FINDING_TOPICS, step=run_id, limit=limit)
            )
    return sort_unique_events(events)


def events_for_pipelines(
    context: CommandContext,
    pipeline_ids: list[str],
    *,
    limit: int,
) -> list[Event]:
    """Return finding events associated with one or more pipelines."""
    events: list[Event] = []
    for pipeline_id in pipeline_ids:
        resolved = resolve_pipeline_selector(context, pipeline_id)
        events.extend(
            events_for_topics(context, REPORT_FINDING_TOPICS, pipeline=resolved, limit=limit)
        )
    return sort_unique_events(events)


def events_for_steps(context: CommandContext, step_ids: list[str], *, limit: int) -> list[Event]:
    """Return finding events associated with one or more pipeline steps."""
    events: list[Event] = []
    for step_id in step_ids:
        resolved = resolve_run_selector(context, step_id)
        events.extend(events_for_topics(context, REPORT_FINDING_TOPICS, step=resolved, limit=limit))
    return sort_unique_events(events)


def events_for_topics(
    context: CommandContext,
    topics: tuple[str, ...],
    *,
    step: str | None = None,
    pipeline: str | None = None,
    limit: int,
) -> list[Event]:
    """Query multiple finding topics and return event-ordered results."""
    events: list[Event] = []
    for topic in topics:
        events.extend(context.events.query(topic=topic, step=step, pipeline=pipeline, limit=limit))
    return sort_unique_events(events)


def latest_completed_pipeline(context: CommandContext) -> str | None:
    """Return the most recently seen pipeline that produced finding events."""
    events = events_for_topics(context, REPORT_FINDING_TOPICS, limit=1000)
    events = [event for event in events if event.pipeline_id]
    if not events:
        return None
    newest = max(events, key=lambda event: event.id or 0)
    return newest.pipeline_id


def render_finding_report(context: CommandContext, events: list[Event], parsed: Namespace) -> None:
    """Render report results and emit a report-rendered audit event."""
    # Rendering starts from raw events every time. Reports do not own findings;
    # they are scoped views over the event log plus review-state events.
    groups = group_finding_events(events)
    decisions = latest_review_decisions(context)
    filtered_groups = filter_groups_by_status(groups, decisions, parsed.status)
    filtered_events = events_for_groups(filtered_groups)
    context.output(report_heading(parsed, events, groups))
    context.output(review_summary_line(review_counts(groups, decisions)))
    if not filtered_groups:
        context.output(
            "no unreviewed findings"
            if parsed.status == "unreviewed"
            else f"no {parsed.status} findings"
        )
        context.events.publish(
            "report.rendered",
            report_rendered_payload(
                parsed,
                filtered_events,
                groups=filtered_groups,
                rows=0,
                counts=review_counts(groups, decisions),
            ),
        )
        return
    context.output(render_status_heading(parsed.status))
    table = indexed_findings_table(filtered_groups)
    context.output(render_table(table, "console"))
    context.output(render_group_details(filtered_groups))
    context.events.publish(
        "report.rendered",
        report_rendered_payload(
            parsed,
            filtered_events,
            groups=filtered_groups,
            rows=len(table.rows),
            counts=review_counts(groups, decisions),
        ),
    )


def report_heading(parsed: Namespace, events: list[Event], groups: list[FindingGroup]) -> str:
    """Return a compact heading for one report view."""
    if parsed.job:
        action = "scope"
        scope = f"job={parsed.job}"
    elif parsed.pipeline:
        action = "scope"
        scope = f"pipeline={parsed.pipeline}"
    elif parsed.step:
        action = "scope"
        scope = f"step={parsed.step}"
    else:
        action = "inbox"
        scope = "latest completed pipeline"
    event_count = len(events)
    group_count = len(groups)
    return (
        f"Report {action}: {scope} "
        f"({group_count} finding group{'s' if group_count != 1 else ''}, "
        f"{event_count} event{'s' if event_count != 1 else ''})"
    )


def report_rendered_payload(
    parsed: Namespace,
    events: list[Event],
    *,
    groups: list[FindingGroup] | None = None,
    rows: int,
    counts: Mapping[str, int] | None = None,
) -> dict[str, object]:
    """Return a structured payload describing one rendered report."""
    return {
        "action": "show" if any((parsed.job, parsed.pipeline, parsed.step)) else "inbox",
        "job": parsed.job,
        "pipeline": parsed.pipeline,
        "step": parsed.step,
        "status": parsed.status,
        "events": [event.id for event in events if event.id is not None],
        "groups": [group.finding_id for group in groups or []],
        "counts": dict(counts or {}),
        "rows": rows,
    }


def review_report_groups(context: CommandContext, parsed: Namespace, events: list[Event]) -> None:
    """Emit review events for selected report groups."""
    if not parsed.selection:
        raise ValueError(f"report {parsed.action} requires a selection such as 1, 1-3, or all")
    # Review actions operate on the same filtered inbox the operator sees. That
    # keeps `report accept 1-3` aligned with the currently displayed row numbers.
    groups = group_finding_events(events)
    decisions = latest_review_decisions(context)
    visible_groups = filter_groups_by_status(groups, decisions, parsed.status)
    selected = selected_groups(visible_groups, str(parsed.selection))
    if not selected:
        raise ValueError("report selection matched no findings")
    decision = REVIEW_DECISIONS[str(parsed.action)]
    for group in selected:
        context.events.publish(
            "finding.reviewed",
            {
                "finding_id": group.finding_id,
                "decision": decision,
                "note": parsed.note,
                "source": "report",
            },
        )
    context.output(f"{decision} {len(selected)} finding{'s' if len(selected) != 1 else ''}")


def selected_groups(groups: list[FindingGroup], selection: str) -> list[FindingGroup]:
    """Resolve report row indexes and ranges into finding groups."""
    if selection == "all":
        return groups
    selected_indexes = parse_index_selection(selection, maximum=len(groups))
    return [groups[index - 1] for index in selected_indexes]


def parse_index_selection(selection: str, *, maximum: int) -> list[int]:
    """Parse comma-separated 1-based indexes and inclusive ranges."""
    indexes: list[int] = []
    seen: set[int] = set()
    for part in selection.split(","):
        token = part.strip()
        if not token:
            raise ValueError("empty report selection range")
        if "-" in token:
            start_raw, end_raw = token.split("-", 1)
            start = parse_positive_index(start_raw)
            end = parse_positive_index(end_raw)
            if start > end:
                raise ValueError(f"invalid descending report range: {token}")
            values = range(start, end + 1)
        else:
            values = (parse_positive_index(token),)
        for value in values:
            if value > maximum:
                raise ValueError(f"report selection index out of range: {value}")
            if value not in seen:
                indexes.append(value)
                seen.add(value)
    return indexes


def parse_positive_index(value: str) -> int:
    """Return a positive integer report row index."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"invalid report selection index: {value}") from exc
    if parsed < 1:
        raise ValueError(f"invalid report selection index: {value}")
    return parsed


def latest_review_decisions(context: CommandContext) -> dict[str, ReviewDecision]:
    """Return the latest review decision for each finding group."""
    decisions: dict[str, ReviewDecision] = {}
    for event in context.events.query(topic="finding.reviewed", limit=100000):
        finding_id = str(event.payload.get("finding_id") or "")
        if not finding_id:
            continue
        decision = str(event.payload.get("decision") or "accepted")
        if decision not in {"accepted", "deferred", "rejected"}:
            decision = "accepted"
        if (
            event.id is not None
            and decisions.get(finding_id)
            and (decisions[finding_id].event_id or 0) > event.id
        ):
            continue
        # Review state is append-only. The latest marker wins, which lets an
        # operator defer a finding and later accept or reject it without mutating
        # the original finding event.
        decisions[finding_id] = ReviewDecision(
            decision=decision,
            note=str(event.payload.get("note") or ""),
            event_id=event.id,
        )
    return decisions


def review_status(group: FindingGroup, decisions: Mapping[str, ReviewDecision]) -> str:
    """Return the effective review status for one finding group."""
    decision = review_decision_for_group(group, decisions)
    return decision.decision if decision is not None else "unreviewed"


def review_decision_for_group(
    group: FindingGroup,
    decisions: Mapping[str, ReviewDecision],
) -> ReviewDecision | None:
    """Return the latest review decision matching a group key or raw finding id."""
    # Older review events and external tooling may reference a raw finding_id,
    # while the report inbox may group several raw findings under a derived key.
    # Check both forms so review markers remain valid after grouping improves.
    matches = [
        decisions[key]
        for key in review_lookup_keys(group)
        if key in decisions
    ]
    if not matches:
        return None
    return max(matches, key=lambda decision: decision.event_id or 0)


def review_lookup_keys(group: FindingGroup) -> tuple[str, ...]:
    """Return review identifiers that may refer to one finding group."""
    keys = [group.finding_id]
    seen = {group.finding_id}
    for event in group.events:
        raw_finding_id = str(effective_finding_payload(event).get("finding_id") or "")
        if raw_finding_id and raw_finding_id not in seen:
            keys.append(raw_finding_id)
            seen.add(raw_finding_id)
    return tuple(keys)


def filter_groups_by_status(
    groups: list[FindingGroup],
    decisions: Mapping[str, ReviewDecision],
    status: str,
) -> list[FindingGroup]:
    """Return report groups matching the requested review status."""
    if status == "all":
        return groups
    return [group for group in groups if review_status(group, decisions) == status]


def review_counts(
    groups: list[FindingGroup],
    decisions: Mapping[str, ReviewDecision],
) -> dict[str, int]:
    """Count finding groups by current review status."""
    counts = {key: 0 for key in ("total", "accepted", "deferred", "rejected", "unreviewed")}
    counts["total"] = len(groups)
    for group in groups:
        counts[review_status(group, decisions)] += 1
    return counts


def review_summary_line(counts: Mapping[str, int]) -> str:
    """Return a compact review-state summary for the report heading."""
    return (
        "Findings: "
        f"{counts.get('total', 0)} total, "
        f"{counts.get('accepted', 0)} accepted, "
        f"{counts.get('deferred', 0)} deferred, "
        f"{counts.get('rejected', 0)} rejected, "
        f"{counts.get('unreviewed', 0)} unreviewed"
    )


def render_status_heading(status: str) -> str:
    """Return the subheading shown before filtered report rows."""
    return "All findings:" if status == "all" else f"{status.capitalize()} findings:"


def indexed_findings_table(groups: list[FindingGroup]) -> Table:
    """Return a report table with stable 1-based row indexes."""
    representatives = [group.representative for group in groups]
    rows = [
        {"index": index, **row}
        for index, row in enumerate(finding_rows(representatives, include_candidates=True), start=1)
    ]
    return Table.from_rows(
        rows,
        (
            Column("index", "#", "right"),
            Column("finding_name", "Finding name"),
            Column("description", "Description"),
            Column("hosts_affected", "Host(s) affected"),
            Column("cve", "CVE"),
            Column("severity", "Severity rating"),
            Column("recommendation", "Recommendation"),
        ),
        title="Findings",
    )


def render_group_details(groups: list[FindingGroup]) -> str:
    """Return compact per-group details for the currently displayed rows."""
    lines = ["Details"]
    for index, group in enumerate(groups, start=1):
        payloads = [effective_finding_payload(event) for event in group.events]
        representative = effective_finding_payload(group.representative)
        title = str(representative.get("title") or representative.get("class") or group.finding_id)
        lines.append(f"#{index} {title}")
        append_detail_line(lines, "Affected", affected_values(payloads))
        append_detail_line(lines, "Evidence", evidence_values(payloads), limit=3)
        append_detail_line(lines, "Sources", source_values(group))
        append_detail_line(lines, "Provenance", provenance_values(group))
        latest = max(group.events, key=lambda event: event.created_at).created_at.isoformat()
        append_detail_line(lines, "Latest update", [latest])
    return "\n".join(lines)


def append_detail_line(lines: list[str], label: str, values: list[str], *, limit: int = 5) -> None:
    """Append one formatted detail line, truncating long value lists."""
    if not values:
        return
    shown = values[:limit]
    suffix = f"; +{len(values) - limit} more" if len(values) > limit else ""
    lines.append(f"  {label}: {'; '.join(shown)}{suffix}")


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


def provenance_values(group: FindingGroup) -> list[str]:
    """Return event, pipeline, and step provenance strings for one group."""
    event_ids = [str(event.id) for event in group.events if event.id is not None]
    pipelines = unique_compact_values(event.pipeline_id or "" for event in group.events)
    steps = unique_compact_values(event.command_run_id or "" for event in group.events)
    values = []
    if event_ids:
        values.append(f"events={','.join(event_ids)}")
    if pipelines:
        values.append(f"pipeline={','.join(pipelines)}")
    if steps:
        values.append(f"step={','.join(steps)}")
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


def events_for_groups(groups: list[FindingGroup]) -> list[Event]:
    """Return sorted events from the selected report groups."""
    return sort_unique_events(event for group in groups for event in group.events)


def group_finding_events(events: list[Event]) -> list[FindingGroup]:
    """Return derived finding groups keyed by normalized finding id."""
    grouped: dict[str, list[Event]] = {}
    ordered_keys: list[str] = []
    for event in events:
        # Preserve first-seen group order for stable row numbers, then sort each
        # group's events chronologically so the representative can be chosen
        # deterministically.
        key = finding_group_key(event)
        if key not in grouped:
            grouped[key] = []
            ordered_keys.append(key)
        grouped[key].append(event)
    return [
        FindingGroup(key, tuple(sorted(grouped[key], key=lambda event: event.id or 0)))
        for key in ordered_keys
    ]


def finding_group_key(event: Event) -> str:
    """Return the stable grouping key for one finding event."""
    payload = effective_finding_payload(event)
    key = derive_finding_group_key(payload, fallback="")
    if key:
        return key
    if event.id is not None:
        return f"event:{event.id}"
    return f"event:{id(event)}"


def effective_finding_payload(event: Event) -> Mapping[str, Any]:
    """Return the reportable finding payload for raw or merge-candidate events."""
    if event.topic == "finding.merge_candidate":
        candidate = event.payload.get("candidate")
        if isinstance(candidate, Mapping):
            return candidate
    return event.payload


def split_selector_values(value: str) -> list[str]:
    """Split comma-separated selectors while rejecting empty entries."""
    values = [item.strip() for item in str(value).split(",") if item.strip()]
    if not values:
        raise ValueError("report selector requires a value")
    return values


def sort_unique_events(events: Iterable[Event]) -> list[Event]:
    """Return events de-duplicated by id and ordered chronologically."""
    by_id: dict[int, Event] = {}
    no_id: list[Event] = []
    for event in events:
        if event.id is None:
            no_id.append(event)
        else:
            by_id[event.id] = event
    return [*sorted(by_id.values(), key=lambda event: event.id or 0), *no_id]


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return Report()
