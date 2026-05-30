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
from bywaf.plugins.network.portscanner.ports import render_ports
from bywaf.repl.display.events import format_event
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width
from bywaf.style import styled_subject_text


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
        ("http.path", render_http_paths_section),
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


def render_hosts_section(context: CommandContext, events: list[Event]) -> str:
    """Render discovered hosts as a compact result table."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("name", ""),
            event.payload.get("status", ""),
            event.payload.get("scanner", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("host") or ""), event.id or 0))
    ]
    table = render_table(
        ("HOST", "NAME", "STATUS", "SCANNER"),
        rows,
        cell_subjects=("host", "host.name", "status", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Hosts discovered ({len(events)})\n{table}"


def render_name_resolution_section(context: CommandContext, events: list[Event]) -> str:
    """Render name-to-address mappings as one row per original name."""
    grouped: dict[str, list[str]] = {}
    for event in events:
        name = str(event.payload.get("name") or "")
        host = event.payload.get("host")
        if host is None:
            continue
        grouped.setdefault(name, []).append(str(host))
    rows = [(name, ", ".join(dict.fromkeys(sorted(hosts)))) for name, hosts in sorted(grouped.items())]
    table = render_table(
        ("NAME", "RESOLVED HOSTS"),
        rows,
        cell_subjects=("host.name", "host"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Name resolutions ({len(events)})\n{table}"


def render_ports_section(context: CommandContext, events: list[Event], scope: Namespace) -> str:
    """Render delegated open-port results with the equivalent view command."""
    command = equivalent_ports_command(scope)
    command = styled_subject_text(command_context_style_getter(context), "command_line", command)
    table = render_ports(context, events, Namespace(scope=scope.scope, filters={}, sort=scope.sort))
    return f"Output of: ports\nEquivalent command: {command}\n\n{table}"


def equivalent_ports_command(scope: Namespace) -> str:
    """Return the `ports` command that would render the same result section."""
    args = [f"{key}={value}" for key, value in scope.scope.items()]
    args.append(f"sort={scope.sort}")
    if args:
        return "ports " + " ".join(args)
    return "ports"


def render_http_endpoints_section(context: CommandContext, events: list[Event]) -> str:
    """Render reachable HTTP endpoints as a compact result table."""
    rows = [
        (
            event.payload.get("url", ""),
            event.payload.get("status", ""),
            event.payload.get("server", ""),
            event.payload.get("error", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("url") or ""), event.id or 0))
    ]
    table = render_table(
        ("URL", "STATUS", "SERVER", "ERROR"),
        rows,
        cell_subjects=("url", "status", "", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"HTTP endpoints ({len(events)})\n{table}"


def render_tcp_banners_section(context: CommandContext, events: list[Event]) -> str:
    """Render TCP banner probe results as a compact result table."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("port", ""),
            event.payload.get("banner", "") or event.payload.get("error", ""),
        )
        for event in sorted(
            events,
            key=lambda event: (
                str(event.payload.get("host") or ""),
                int(event.payload.get("port") or 0),
                event.id or 0,
            ),
        )
    ]
    table = render_table(
        ("HOST", "PORT", "BANNER / ERROR"),
        rows,
        cell_subjects=("host", "port", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"TCP banners ({len(events)})\n{table}"


def render_services_section(context: CommandContext, events: list[Event]) -> str:
    """Render normalized service classifications."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("port", ""),
            event.payload.get("protocol", ""),
            event.payload.get("service", ""),
            event.payload.get("product", "") or event.payload.get("evidence", ""),
        )
        for event in sorted(
            events,
            key=lambda event: (
                str(event.payload.get("host") or ""),
                int(event.payload.get("port") or 0),
                event.id or 0,
            ),
        )
    ]
    table = render_table(
        ("HOST", "PORT", "PROTO", "SERVICE", "EVIDENCE"),
        rows,
        cell_subjects=("host", "port", "protocol", "value", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Services detected ({len(events)})\n{table}"


def render_tls_certificates_section(context: CommandContext, events: list[Event]) -> str:
    """Render TLS certificate metadata."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("port", ""),
            event.payload.get("subject", ""),
            event.payload.get("issuer", ""),
            event.payload.get("not_after", ""),
        )
        for event in sorted(
            events,
            key=lambda event: (
                str(event.payload.get("host") or ""),
                int(event.payload.get("port") or 0),
                event.id or 0,
            ),
        )
    ]
    table = render_table(
        ("HOST", "PORT", "SUBJECT", "ISSUER", "VALID UNTIL"),
        rows,
        cell_subjects=("host", "port", "", "", "value"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"TLS certificates ({len(events)})\n{table}"


def render_screenshots_section(context: CommandContext, events: list[Event]) -> str:
    """Render screenshot artifact references as a compact result table."""
    rows = [
        (
            event.payload.get("host", ""),
            ", ".join(str(url) for url in event.payload.get("urls", [])[:2]),
            len(event.payload.get("screenshots", [])),
            screenshot_artifact_refs(event),
            event.payload.get("tool", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("host") or ""), event.id or 0))
    ]
    table = render_table(
        ("HOST", "URLS", "SHOTS", "ARTIFACTS", "TOOL"),
        rows,
        cell_subjects=("host", "url", "", "artifact", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Screenshots ({len(events)})\n{table}"


def screenshot_artifact_refs(event: Event) -> str:
    """Return compact artifact references for one screenshot event."""
    refs: list[str] = []
    screenshots = event.payload.get("screenshots", [])
    if not isinstance(screenshots, list):
        return ""
    for screenshot in screenshots:
        if not isinstance(screenshot, dict):
            continue
        ref = screenshot.get("artifact_id") or screenshot.get("artifact") or screenshot.get("path")
        if ref:
            refs.append(str(ref))
    return ", ".join(refs)


def render_smb_shares_section(context: CommandContext, events: list[Event]) -> str:
    """Render SMB shares as a compact result table."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("share", ""),
            event.payload.get("access", ""),
            format_bool(event.payload.get("authenticated")),
            event.payload.get("remark", ""),
        )
        for event in sorted(
            events,
            key=lambda event: (
                str(event.payload.get("host") or ""),
                str(event.payload.get("share") or ""),
                event.id or 0,
            ),
        )
    ]
    table = render_table(
        ("HOST", "SHARE", "ACCESS", "AUTH", "REMARK"),
        rows,
        cell_subjects=("host", "value", "status", "", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"SMB shares ({len(events)})\n{table}"


def format_bool(value: object) -> str:
    """Format optional bools for result tables."""
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return ""


def render_artifacts_section(context: CommandContext, events: list[Event]) -> str:
    """Render attached artifacts as a compact result table."""
    rows = [
        (
            event.payload.get("artifact_id", ""),
            event.payload.get("name", ""),
            event.payload.get("content_type", ""),
            event.payload.get("size", ""),
            event.payload.get("note", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("name") or ""), event.id or 0))
    ]
    table = render_table(
        ("ARTIFACT", "NAME", "TYPE", "SIZE", "NOTE"),
        rows,
        cell_subjects=("artifact", "value", "", "", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Artifacts ({len(events)})\n{table}"


def render_route_hops_section(context: CommandContext, events: list[Event]) -> str:
    """Render route traces as a compact result table."""
    rows = [
        (
            event.payload.get("target", ""),
            event.payload.get("hop", ""),
            event.payload.get("host", "") or event.payload.get("status", ""),
            event.payload.get("ip", ""),
            format_rtt(event.payload.get("rtt_ms")),
        )
        for event in sorted(
            events,
            key=lambda event: (
                str(event.payload.get("target") or ""),
                int(event.payload.get("hop") or 0),
                event.id or 0,
            ),
        )
    ]
    table = render_table(
        ("TARGET", "HOP", "HOST / STATUS", "IP", "RTT"),
        rows,
        cell_subjects=("host", "step", "host", "host", "value"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Route hops ({len(events)})\n{table}"


def render_http_paths_section(context: CommandContext, events: list[Event]) -> str:
    """Render HTTP path observations."""
    rows = [
        (
            event.payload.get("url", ""),
            event.payload.get("status", ""),
            event.payload.get("title", ""),
            "yes" if event.payload.get("interesting") else "",
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("url") or ""), event.id or 0))
    ]
    table = render_table(
        ("URL", "STATUS", "TITLE", "INTERESTING"),
        rows,
        cell_subjects=("url", "status", "", "status"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"HTTP paths ({len(events)})\n{table}"


def render_waf_section(context: CommandContext, events: list[Event]) -> str:
    """Render WAF or edge protection fingerprints."""
    rows = [
        (
            event.payload.get("url", ""),
            event.payload.get("vendor", ""),
            event.payload.get("product", ""),
            event.payload.get("confidence", ""),
            event.payload.get("evidence", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("url") or ""), event.id or 0))
    ]
    table = render_table(
        ("URL", "VENDOR", "PRODUCT", "CONF", "EVIDENCE"),
        rows,
        cell_subjects=("url", "value", "value", "status", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"WAF signals ({len(events)})\n{table}"


def format_rtt(value: object) -> str:
    """Format one route hop round-trip time."""
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)):
        return f"{value:g} ms"
    return str(value)


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
