"""Report event selection helpers.

Selects finding events by explicit job/pipeline/step scope or by the latest
completed pipeline that produced finding events.

Used by:
- analysis.report: choose the event set for rendering and review actions."""

from __future__ import annotations

from argparse import Namespace

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.analysis.finding.report import REPORT_FINDING_TOPICS
from bywaf.plugins.runtime.audit import resolve_pipeline_selector, resolve_run_selector

from .delta import finding_event_keys, host_event_keys, new_topic_events, service_event_keys, web_event_keys
from .model import sort_unique_events

REPORT_CONTEXT_TOPICS = (
    "host.found",
    "name.resolved",
    "port.open",
    "service.detected",
    "tcp.banner",
    "http.endpoint",
    "http.path",
    "tls.certificate",
    "web.fingerprint",
    "web.waf.detected",
    "web.screenshotted_host",
    "network.route.hop",
)


def select_report_scope_events(context: CommandContext, parsed: Namespace) -> list[Event]:
    """Return finding events selected by explicit scope or latest report pipeline."""
    limit = int(parsed.limit)
    if parsed.job:
        return events_for_jobs(context, split_selector_values(parsed.job), limit=limit)
    if parsed.pipeline:
        return events_for_pipelines(context, split_selector_values(parsed.pipeline), limit=limit)
    if parsed.step:
        return events_for_steps(context, split_selector_values(parsed.step), limit=limit)
    pipeline_id = latest_report_pipeline(context)
    if pipeline_id is not None:
        return events_for_pipelines(context, [pipeline_id], limit=limit)
    return events_for_topics(context, REPORT_FINDING_TOPICS, limit=limit)


def select_report_context_events(context: CommandContext, parsed: Namespace) -> list[Event]:
    """Return shared network facts for the selected report scope."""
    limit = int(parsed.limit)
    if parsed.job:
        return context_events_for_jobs(context, split_selector_values(parsed.job), limit=limit)
    if parsed.pipeline:
        return context_events_for_pipelines(context, split_selector_values(parsed.pipeline), limit=limit)
    if parsed.step:
        return context_events_for_steps(context, split_selector_values(parsed.step), limit=limit)
    pipeline_id = latest_report_pipeline(context)
    if pipeline_id is not None:
        return context_events_for_pipelines(context, [pipeline_id], limit=limit)
    return events_for_topics(context, REPORT_CONTEXT_TOPICS, limit=limit)


def select_new_scope_events(context: CommandContext, parsed: Namespace) -> list[Event]:
    """Return finding events newly introduced by the selected/latest finding scope."""
    del parsed
    return new_topic_events(context, REPORT_FINDING_TOPICS, finding_event_keys, limit=10000)


def select_new_context_events(context: CommandContext, parsed: Namespace) -> list[Event]:
    """Return composite inventory facts newly introduced by latest relevant scans."""
    del parsed
    events: list[Event] = []
    events.extend(new_topic_events(context, ("host.found", "name.resolved"), host_event_keys, limit=10000))
    events.extend(new_topic_events(context, ("port.open", "service.detected"), service_event_keys, limit=10000))
    events.extend(
        new_topic_events(
            context,
            ("http.endpoint", "http.path", "tls.certificate", "web.waf.detected", "web.screenshotted_host", "network.route.hop"),
            web_event_keys,
            limit=10000,
        )
    )
    return sort_unique_events(events)


def events_for_jobs(context: CommandContext, job_ids: list[str], *, limit: int) -> list[Event]:
    """Return finding events associated with one or more jobs."""
    return job_topic_events(context, job_ids, REPORT_FINDING_TOPICS, limit=limit)


def job_topic_events(
    context: CommandContext,
    job_ids: list[str],
    topics: tuple[str, ...],
    *,
    limit: int,
) -> list[Event]:
    """Return selected topic events associated with one or more jobs."""
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
        events.extend(event_store.events_for_job_topics(numeric_id, topics, limit=limit))
    return sort_unique_events(events)


def context_events_for_jobs(context: CommandContext, job_ids: list[str], *, limit: int) -> list[Event]:
    """Return shared network facts associated with one or more jobs."""
    return job_topic_events(context, job_ids, REPORT_CONTEXT_TOPICS, limit=limit)


def events_for_pipelines(
    context: CommandContext,
    pipeline_ids: list[str],
    *,
    limit: int,
) -> list[Event]:
    """Return finding events associated with one or more pipelines."""
    return pipeline_topic_events(context, pipeline_ids, REPORT_FINDING_TOPICS, limit=limit)


def pipeline_topic_events(
    context: CommandContext,
    pipeline_ids: list[str],
    topics: tuple[str, ...],
    *,
    limit: int,
) -> list[Event]:
    """Return selected topic events associated with one or more pipelines."""
    events: list[Event] = []
    for pipeline_id in pipeline_ids:
        resolved = resolve_pipeline_selector(context, pipeline_id)
        events.extend(events_for_topics(context, topics, pipeline=resolved, limit=limit))
    return sort_unique_events(events)


def context_events_for_pipelines(
    context: CommandContext,
    pipeline_ids: list[str],
    *,
    limit: int,
) -> list[Event]:
    """Return shared network facts associated with one or more pipelines."""
    return pipeline_topic_events(context, pipeline_ids, REPORT_CONTEXT_TOPICS, limit=limit)


def events_for_steps(context: CommandContext, step_ids: list[str], *, limit: int) -> list[Event]:
    """Return finding events associated with one or more pipeline steps."""
    return step_topic_events(context, step_ids, REPORT_FINDING_TOPICS, limit=limit)


def step_topic_events(
    context: CommandContext,
    step_ids: list[str],
    topics: tuple[str, ...],
    *,
    limit: int,
) -> list[Event]:
    """Return selected topic events associated with one or more pipeline steps."""
    events: list[Event] = []
    for step_id in step_ids:
        resolved = resolve_run_selector(context, step_id)
        events.extend(events_for_topics(context, topics, step=resolved, limit=limit))
    return sort_unique_events(events)


def context_events_for_steps(context: CommandContext, step_ids: list[str], *, limit: int) -> list[Event]:
    """Return shared network facts associated with one or more pipeline steps."""
    return step_topic_events(context, step_ids, REPORT_CONTEXT_TOPICS, limit=limit)


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


def latest_report_pipeline(context: CommandContext) -> str | None:
    """Return the most recent pipeline that produced reportable or network facts."""
    events = events_for_topics(context, (*REPORT_FINDING_TOPICS, *REPORT_CONTEXT_TOPICS), limit=1000)
    events = [event for event in events if event.pipeline_id]
    if not events:
        return None
    newest = max(events, key=lambda event: event.id or 0)
    return newest.pipeline_id


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
