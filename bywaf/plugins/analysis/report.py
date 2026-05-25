"""Operator-facing report commandlet.

Provides the first reporting inbox over normalized finding events. It renders
grouped findings for recent, run-scoped, job-scoped, or pipeline-scoped work
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
from bywaf.finding_grouping import finding_group_key as derive_finding_group_key
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet, option
from bywaf.plugins._args import key_value_to_long_options
from bywaf.plugins.analysis.finding_report import REPORT_FINDING_TOPICS, finding_rows, findings_table
from bywaf.plugins.runtime.audit import resolve_pipeline_selector, resolve_run_selector
from bywaf.rendering import render_table

REPORT_ACTIONS = ("new",)
REPORT_OPTION_KEYS = {"job", "pipeline", "run", "limit", "status"}
REPORT_STATUS_CHOICES = ("all", "unreviewed")


@dataclass(frozen=True)
class FindingGroup:
    """A derived reporting group for one logical finding."""

    finding_id: str
    events: tuple[Event, ...]

    @property
    def representative(self) -> Event:
        """Return the newest event to render for this group."""
        return max(self.events, key=lambda event: event.id or 0)


@commandlet(
    name="report",
    description="Show grouped finding reports for recent, run, job, or pipeline scopes.",
    usage="report [new] [pipeline=<id>[,<id>...]] [job=<id>[,<id>...]] [run=<id>[,<id>...]]",
    examples=(
        "report",
        "report new",
        "report pipeline=1",
        "report pipeline=1,2,3",
        "report job=7",
        "report run=12",
    ),
    consumes=REPORT_FINDING_TOPICS,
    emits=("report.rendered",),
    capabilities=(
        "db.read:finding.new",
        "db.read:finding.candidate",
        "db.read:finding.merge_candidate",
        "db.read:finding.reviewed",
        "db.write:report.rendered",
        "framework.console.output",
    ),
)
@option("job", "job id or comma-separated job ids", completion="job")
@option("pipeline", "pipeline id or comma-separated pipeline ids", completion="pipeline")
@option("run", "run id or comma-separated run ids", completion="run")
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
        parser.add_argument("--job", default="", help="job id or comma-separated job ids")
        parser.add_argument("--pipeline", default="", help="pipeline id or comma-separated pipeline ids")
        parser.add_argument("--run", default="", help="run id or comma-separated run ids")
        parser.add_argument("--limit", type=int, default=1000)
        parser.add_argument("--status", choices=REPORT_STATUS_CHOICES, default="unreviewed")
        parsed = parser.parse_args(key_value_to_long_options(args, REPORT_OPTION_KEYS))

        input_findings = [event for event in input_events if event.topic in REPORT_FINDING_TOPICS]
        events = input_findings or select_report_scope_events(context, parsed)
        events = filter_reviewed_events(context, events, include_reviewed=parsed.status == "all")
        render_finding_report(context, events, parsed)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete report actions and selectors."""
        del context, args
        candidates = ("new", "pipeline=", "job=", "run=", "limit=", "status=", "status=all", "status=unreviewed")
        return [candidate for candidate in candidates if candidate.startswith(prefix)]


def select_report_scope_events(context: CommandContext, parsed: Namespace) -> list[Event]:
    """Return finding events selected by explicit scope or latest completed pipeline."""
    limit = int(parsed.limit)
    if parsed.job:
        return events_for_jobs(context, split_selector_values(parsed.job), limit=limit)
    if parsed.pipeline:
        return events_for_pipelines(context, split_selector_values(parsed.pipeline), limit=limit)
    if parsed.run:
        return events_for_runs(context, split_selector_values(parsed.run), limit=limit)
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
            events.extend(events_for_topics(context, REPORT_FINDING_TOPICS, pipeline=pipeline_id, limit=limit))
        for run_id in runs:
            events.extend(events_for_topics(context, REPORT_FINDING_TOPICS, run=run_id, limit=limit))
    return sort_unique_events(events)


def events_for_pipelines(context: CommandContext, pipeline_ids: list[str], *, limit: int) -> list[Event]:
    """Return finding events associated with one or more pipelines."""
    events: list[Event] = []
    for pipeline_id in pipeline_ids:
        resolved = resolve_pipeline_selector(context, pipeline_id)
        events.extend(events_for_topics(context, REPORT_FINDING_TOPICS, pipeline=resolved, limit=limit))
    return sort_unique_events(events)


def events_for_runs(context: CommandContext, run_ids: list[str], *, limit: int) -> list[Event]:
    """Return finding events associated with one or more command runs."""
    events: list[Event] = []
    for run_id in run_ids:
        resolved = resolve_run_selector(context, run_id)
        events.extend(events_for_topics(context, REPORT_FINDING_TOPICS, run=resolved, limit=limit))
    return sort_unique_events(events)


def events_for_topics(
    context: CommandContext,
    topics: tuple[str, ...],
    *,
    run: str | None = None,
    pipeline: str | None = None,
    limit: int,
) -> list[Event]:
    """Query multiple finding topics and return event-ordered results."""
    events: list[Event] = []
    for topic in topics:
        events.extend(context.events.query(topic=topic, run=run, pipeline=pipeline, limit=limit))
    return sort_unique_events(events)


def latest_completed_pipeline(context: CommandContext) -> str | None:
    """Return the most recently seen pipeline that produced finding events."""
    events = events_for_topics(context, REPORT_FINDING_TOPICS, limit=1000)
    events = [event for event in events if event.pipeline_id]
    if not events:
        return None
    newest = max(events, key=lambda event: event.id or 0)
    return newest.pipeline_id


def filter_reviewed_events(context: CommandContext, events: list[Event], *, include_reviewed: bool) -> list[Event]:
    """Remove already reviewed findings unless requested otherwise."""
    if include_reviewed:
        return events
    reviewed = reviewed_finding_ids(context)
    return [
        event
        for event in events
        if str(effective_finding_payload(event).get("finding_id") or "") not in reviewed
    ]


def reviewed_finding_ids(context: CommandContext) -> set[str]:
    """Return finding ids marked reviewed."""
    return {
        str(event.payload.get("finding_id"))
        for event in context.events.query(topic="finding.reviewed", limit=100000)
        if event.payload.get("finding_id")
    }


def render_finding_report(context: CommandContext, events: list[Event], parsed: Namespace) -> None:
    """Render report results and emit a report-rendered audit event."""
    if not events:
        context.output("no unreviewed findings" if parsed.status == "unreviewed" else "no findings")
        context.events.publish("report.rendered", report_rendered_payload(parsed, events, rows=0))
        return
    groups = group_finding_events(events)
    representatives = [group.representative for group in groups]
    context.output(report_heading(parsed, events, groups))
    table = findings_table(finding_rows(representatives, include_candidates=True))
    context.output(render_table(table, "console"))
    context.events.publish("report.rendered", report_rendered_payload(parsed, events, groups=groups, rows=len(table.rows)))


def report_heading(parsed: Namespace, events: list[Event], groups: list[FindingGroup]) -> str:
    """Return a compact heading for one report view."""
    action = "new" if parsed.action == "new" else "scope"
    if parsed.job:
        scope = f"job={parsed.job}"
    elif parsed.pipeline:
        scope = f"pipeline={parsed.pipeline}"
    elif parsed.run:
        scope = f"run={parsed.run}"
    else:
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
) -> dict[str, object]:
    """Return a structured payload describing one rendered report."""
    return {
        "action": parsed.action or "show",
        "job": parsed.job,
        "pipeline": parsed.pipeline,
        "run": parsed.run,
        "status": parsed.status,
        "events": [event.id for event in events if event.id is not None],
        "groups": [group.finding_id for group in groups or []],
        "rows": rows,
    }


def group_finding_events(events: list[Event]) -> list[FindingGroup]:
    """Return derived finding groups keyed by normalized finding id."""
    grouped: dict[str, list[Event]] = {}
    ordered_keys: list[str] = []
    for event in events:
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
