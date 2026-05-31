"""Rendering helpers for runtime result views.

Provides domain-specific sections for the `results` command while keeping
command parsing and runtime-scope selection in `results.py`.
"""

from __future__ import annotations

from argparse import Namespace
from collections import Counter

from bywaf.event import Event
from bywaf.event.schemas import event_schema
from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.results.sections import (
    render_artifacts_section,
    render_hosts_section,
    render_http_endpoints_section,
    render_http_headers_section,
    render_http_paths_section,
    render_name_resolution_section,
    render_ports_section,
    render_route_hops_section,
    render_screenshots_section,
    render_services_section,
    render_smb_shares_section,
    render_tcp_banners_section,
    render_tls_certificates_section,
    render_waf_section,
    render_web_fingerprints_section,
)
from bywaf.repl.display.events import format_event
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width


def render_results(context: CommandContext, scope: Namespace) -> str:
    """Render result-like events with specialized views where possible."""
    sections = [render_results_header(scope)]
    events_by_topic = group_events_by_topic(scope.events)
    section_renderers = (
        ("host.found", render_hosts_section),
        ("name.resolved", render_name_resolution_section),
        ("port.open", lambda ctx, events: render_ports_section(ctx, events, scope)),
        ("tcp.banner", render_tcp_banners_section),
        ("service.detected", render_services_section),
        ("tls.certificate", render_tls_certificates_section),
        ("network.route.hop", render_route_hops_section),
        ("http.endpoint", render_http_endpoints_section),
        ("http.headers", render_http_headers_section),
        ("http.path", render_http_paths_section),
        ("web.fingerprint", render_web_fingerprints_section),
        ("web.waf.detected", render_waf_section),
        ("web.screenshotted_host", render_screenshots_section),
        ("smb.share.found", render_smb_shares_section),
        ("artifact.attached", render_artifacts_section),
    )
    summarized_topics = {topic for topic, _ in section_renderers}
    for topic, renderer in section_renderers:
        events = events_by_topic.get(topic, [])
        if events:
            sections.append(renderer(context, events))
    other_events = [event for event in scope.events if event.topic not in summarized_topics]
    if other_events:
        sections.append(render_event_topic_summary(context, other_events))
        sections.append(render_representative_events(other_events))
    return "\n\n".join(section for section in sections if section)


def group_events_by_topic(events: list[Event]) -> dict[str, list[Event]]:
    """Group events by topic while preserving original order within each topic."""
    grouped: dict[str, list[Event]] = {}
    for event in events:
        grouped.setdefault(event.topic, []).append(event)
    return grouped


def render_results_header(scope: Namespace) -> str:
    """Render the result scope and the shared schemas represented in it."""
    lines = [f"Results: {scope.label}"]
    topics = schema_backed_topics(scope.events)
    if topics:
        lines.append("Shared schemas: " + ", ".join(topics))
    return "\n".join(lines)


def schema_backed_topics(events: list[Event]) -> tuple[str, ...]:
    """Return shared event-schema topics present in this result set."""
    return tuple(sorted({event.topic for event in events if event_schema(event.topic) is not None}))


def no_results_message(context: CommandContext) -> str:
    """Explain an empty result view and mention active work when relevant."""
    runtime = context.runtime_store("results active jobs")
    active_jobs = [
        row
        for row in runtime.jobs(active_only=True)
        if context.job_id is None or str(row["id"]) != str(context.job_id)
    ]
    if not active_jobs:
        return "no results"
    rows = [(row["id"], row["status"], str(row["command_line"])) for row in active_jobs[-5:]]
    table = render_table(
        ("JOB", "STATUS", "COMMAND"),
        rows,
        cell_subjects=("job", "status", "command"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    latest_job = active_jobs[-1]["id"]
    return (
        "no results yet; active work is still running\n"
        f"{table}\n"
        f"Try again with `results`, or inspect progress with `job {latest_job}`."
    )


def render_event_topic_summary(context: CommandContext, events: list[Event]) -> str:
    """Render inserted event topic counts."""
    counts = Counter(event.topic for event in events)
    rows = [(topic, count) for topic, count in sorted(counts.items())]
    return "Inserted events\n" + render_table(
        ("TOPIC", "COUNT"),
        rows,
        cell_subjects=("event.topic", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )


def render_representative_events(events: list[Event], *, limit: int = 10) -> str:
    """Render a small sample of raw records for unfamiliar result topics."""
    return "Representative events\n" + "\n".join(format_event(event) for event in events[:limit])
