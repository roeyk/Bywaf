"""Operator-facing report rendering.

Turns grouped finding events and review decisions into styled report text,
tables, details, and `report.rendered` audit payloads.

Used by:
- analysis.report: render report views after event selection."""

from __future__ import annotations

from argparse import Namespace

from bywaf.event import Event
from bywaf.plugin import CommandContext

from .details import render_group_details
from .model import events_for_groups, filter_groups_by_cve, group_finding_events
from .network import host_overviews, render_network_overview
from .output import emit_report_output, publish_report_rendered
from .review import (
    filter_groups_by_status,
    latest_review_decisions,
    review_counts,
    selected_groups,
)
from .render_summary import (
    empty_status_message,
    network_report_heading,
    order_report_groups,
    render_status_heading,
    report_grouping_line,
    report_heading,
    resume_focus_line,
    resume_summary_line,
    review_summary_line,
    severity_class_counts,
)
from .style import report_text
from .tables import indexed_findings_table, indexed_hosts_table, render_styled_report_table


def render_finding_report(
    context: CommandContext,
    events: list[Event],
    parsed: Namespace,
    *,
    context_events: list[Event] | None = None,
) -> None:
    """Render report results and emit a report-rendered audit event."""
    # Rendering starts from raw events every time. Reports do not own findings;
    # they are scoped views over the event log plus review-state events.
    groups = filter_groups_by_cve(group_finding_events(events), str(getattr(parsed, "cve", "")))
    decisions = latest_review_decisions(context)
    filtered_groups = filter_groups_by_status(groups, decisions, parsed.status)
    filtered_groups = order_report_groups(filtered_groups, decisions, parsed)
    displayed_groups = filtered_groups
    if parsed.action == "detail":
        if not parsed.selection:
            raise ValueError("report detail requires a selection such as 1, 1-3, or all")
        displayed_groups = selected_groups(filtered_groups, str(parsed.selection))
    filtered_events = events_for_groups(filtered_groups)
    output_lines = [
        report_text(context, "heading", report_grouping_line(parsed)),
        report_text(context, "heading", report_heading(parsed, events, groups)),
        report_text(
            context,
            "summary",
            review_summary_line(review_counts(groups, decisions), severity_class_counts(groups)),
        ),
        report_text(context, "summary", resume_summary_line(review_counts(groups, decisions))),
        report_text(context, "summary", resume_focus_line(groups, decisions)),
    ]
    network_overview = render_network_overview(context, context_events or [], events_for_groups(displayed_groups))
    if network_overview:
        output_lines.append(network_overview)
    if not displayed_groups:
        output_lines.append(empty_status_message(parsed.status))
        emit_report_output(context, output_lines, parsed)
        publish_report_rendered(
            context,
            parsed,
            filtered_events,
            groups=displayed_groups,
            rows=0,
            counts=review_counts(groups, decisions),
        )
        return
    output_lines.append(report_text(context, "section", render_status_heading(parsed)))
    table = (
        indexed_hosts_table(displayed_groups, decisions=decisions)
        if parsed.sort == "host" and parsed.action != "detail"
        else indexed_findings_table(displayed_groups, decisions=decisions, show_review_status=True)
    )
    output_lines.append(render_styled_report_table(context, table))
    if parsed.action == "detail":
        output_lines.append(render_group_details(context, displayed_groups))
    else:
        output_lines.append(
            report_text(context, "hint", "Use `report <#>` for detail.")
        )
    emit_report_output(context, output_lines, parsed)
    publish_report_rendered(
        context,
        parsed,
        events_for_groups(displayed_groups),
        groups=displayed_groups,
        rows=len(table.rows),
        counts=review_counts(groups, decisions),
    )


def render_network_report(
    context: CommandContext,
    context_events: list[Event],
    finding_events: list[Event],
    parsed: Namespace,
) -> None:
    """Render a network-first report view for one selected scope."""
    output_lines = [
        report_text(context, "heading", network_report_heading(parsed, context_events, finding_events)),
    ]
    network_overview = render_network_overview(context, context_events, finding_events)
    if network_overview:
        output_lines.append(network_overview)
    else:
        output_lines.append("no network observations")
    emit_report_output(context, output_lines, parsed)
    publish_report_rendered(
        context,
        parsed,
        [*context_events, *finding_events],
        groups=[],
        rows=len(host_overviews(context_events, finding_events)),
        counts={},
        action="network",
    )
