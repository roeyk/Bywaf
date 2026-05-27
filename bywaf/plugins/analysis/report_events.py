"""Report event selection helpers.

Selects finding events by explicit job/pipeline/step scope or by the latest
completed pipeline that produced finding events.

Used by:
- analysis.report: choose the event set for rendering and review actions."""

from __future__ import annotations

from argparse import Namespace

from bywaf.events import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.analysis.finding_report import REPORT_FINDING_TOPICS
from bywaf.plugins.runtime.audit import resolve_pipeline_selector, resolve_run_selector

from .report_model import sort_unique_events


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
    runtime = context.runtime_store("report job selector")
    for job_id in job_ids:
        try:
            numeric_id = int(job_id)
        except ValueError:
            resolved = runtime.job_id_for_serial(job_id)
            if resolved is None:
                raise ValueError(f"unknown job: {job_id}") from None
            numeric_id = int(resolved)
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


def split_selector_values(value: str) -> list[str]:
    """Split comma-separated selectors while rejecting empty entries."""
    values = [item.strip() for item in str(value).split(",") if item.strip()]
    if not values:
        raise ValueError("report selector requires a value")
    return values
