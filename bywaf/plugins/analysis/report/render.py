"""Operator-facing report rendering.

Turns grouped finding events and review decisions into styled report text,
tables, details, and `report.rendered` audit payloads.

Used by:
- analysis.report: render report views after event selection."""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Mapping

from bywaf.event import Event
from bywaf.finding import SEVERITY_CLASS_ORDER, severity_class
from bywaf.plugin import CommandContext

from .details import render_group_details
from .model import FindingGroup, effective_finding_payload, events_for_groups, group_finding_events
from .network import host_overviews, render_network_overview
from .review import (
    ReviewDecision,
    filter_groups_by_status,
    latest_review_decisions,
    review_counts,
    review_status,
    selected_groups,
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
    groups = group_finding_events(events)
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
    ]
    network_overview = render_network_overview(context, context_events or [], events_for_groups(displayed_groups))
    if network_overview:
        output_lines.append(network_overview)
    if not displayed_groups:
        output_lines.append(empty_status_message(parsed.status))
        emit_report_output(context, output_lines, parsed)
        context.events.publish(
            "report.rendered",
            report_rendered_payload(
                parsed,
                filtered_events,
                groups=displayed_groups,
                rows=0,
                counts=review_counts(groups, decisions),
            ),
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
    context.events.publish(
        "report.rendered",
        report_rendered_payload(
            parsed,
            events_for_groups(displayed_groups),
            groups=displayed_groups,
            rows=len(table.rows),
            counts=review_counts(groups, decisions),
        ),
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
    context.events.publish(
        "report.rendered",
        report_rendered_payload(
            parsed,
            [*context_events, *finding_events],
            groups=[],
            rows=len(host_overviews(context_events, finding_events)),
            counts={},
            action="network",
        ),
    )


def emit_report_output(context: CommandContext, lines: list[str], parsed: Namespace) -> None:
    """Page or print one complete rendered report."""
    rendered = "\n".join(line for line in lines if line)
    if parse_bool_selector(parsed.page):
        context.page_text(rendered)
    else:
        context.output(rendered)


def parse_bool_selector(value: object) -> bool:
    """Parse a selector-style boolean such as `page=false`."""
    normalized = str(value).strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean value: {value}")


def empty_status_message(status: str) -> str:
    """Return a natural empty-state message for one report status filter."""
    if status == "open":
        return "no open findings"
    if status == "unreviewed":
        return "no unreviewed findings"
    if status == "all":
        return "no findings"
    return f"no {status} findings"


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
    elif getattr(parsed, "last", False):
        action = "scope"
        scope = "latest scan"
    elif getattr(parsed, "new", False):
        action = "new"
        scope = "since prior inventory"
    else:
        action = "inbox"
        scope = "latest scan"
    event_count = len(events)
    group_count = len(groups)
    return (
        f"Report {action}: {scope} "
        f"({group_count} finding group{'s' if group_count != 1 else ''}, "
        f"{event_count} event{'s' if event_count != 1 else ''})"
    )


def network_report_heading(parsed: Namespace, context_events: list[Event], finding_events: list[Event]) -> str:
    """Return a compact heading for the network report view."""
    if parsed.job:
        scope = f"job={parsed.job}"
    elif parsed.pipeline:
        scope = f"pipeline={parsed.pipeline}"
    elif parsed.step:
        scope = f"step={parsed.step}"
    elif getattr(parsed, "last", False):
        scope = "latest scan"
    elif getattr(parsed, "new", False):
        scope = "new since prior inventory"
    else:
        scope = "latest scan"
    event_count = len(context_events) + len(finding_events)
    host_count = len(host_overviews(context_events, finding_events))
    return (
        f"Report network: {scope} "
        f"({host_count} host{'s' if host_count != 1 else ''}, "
        f"{event_count} event{'s' if event_count != 1 else ''})"
    )


def report_rendered_payload(
    parsed: Namespace,
    events: list[Event],
    *,
    groups: list[FindingGroup] | None = None,
    rows: int,
    counts: Mapping[str, int] | None = None,
    action: str | None = None,
) -> dict[str, object]:
    """Return a structured payload describing one rendered report."""
    return {
        "action": action or ("show" if any((parsed.job, parsed.pipeline, parsed.step)) else "new" if getattr(parsed, "new", False) else "inbox"),
        "job": parsed.job,
        "pipeline": parsed.pipeline,
        "step": parsed.step,
        "status": parsed.status,
        "sort": getattr(parsed, "sort", "finding"),
        "order": report_order(parsed),
        "events": [event.id for event in events if event.id is not None],
        "groups": [group.finding_id for group in groups or []],
        "counts": dict(counts or {}),
        "rows": rows,
    }


def order_report_groups(
    groups: list[FindingGroup],
    decisions: Mapping[str, ReviewDecision],
    parsed: Namespace,
) -> list[FindingGroup]:
    """Return report groups in the requested operator-priority order."""
    if getattr(parsed, "accepted_first", False):
        return sorted(groups, key=lambda group: (review_status(group, decisions) != "accepted", first_group_event_id(group)))
    if getattr(parsed, "candidates_first", False):
        return sorted(groups, key=lambda group: (not group_has_candidate_status(group), first_group_event_id(group)))
    return groups


def report_order(parsed: Namespace) -> str:
    """Return the report row ordering label for audit payloads."""
    if getattr(parsed, "accepted_first", False):
        return "accepted-first"
    if getattr(parsed, "candidates_first", False):
        return "candidates-first"
    return "default"


def first_group_event_id(group: FindingGroup) -> int:
    """Return a stable chronological key for one finding group."""
    return min((event.id or 0) for event in group.events)


def group_has_candidate_status(group: FindingGroup) -> bool:
    """Return whether a group represents candidate or potential finding evidence."""
    return any(
        event.topic in {"finding.candidate", "finding.merge_candidate"}
        or str(effective_finding_payload(event).get("status") or "").casefold() in {"candidate", "potential"}
        for event in group.events
    )


def review_summary_line(
    counts: Mapping[str, int],
    severity_counts: Mapping[str, int] | None = None,
) -> str:
    """Return a compact review-state summary for the report heading."""
    summary = (
        f"Findings: {counts.get('total', 0)} total\n"
        "Review: "
        f"{counts.get('accepted', 0)} accepted, "
        f"{counts.get('confirmed', 0)} confirmed, "
        f"{counts.get('deferred', 0)} deferred, "
        f"{counts.get('rejected', 0)} rejected, "
        f"{counts.get('unreviewed', 0)} unreviewed"
    )
    if not severity_counts:
        return summary
    class_summary = ", ".join(
        f"{severity_counts[item]} {item}"
        for item in SEVERITY_CLASS_ORDER
        if severity_counts.get(item, 0)
    )
    return f"{summary}\nseverity classes: {class_summary}" if class_summary else summary


def resume_summary_line(counts: Mapping[str, int]) -> str:
    """Return a short field-resume summary for open report work."""
    open_count = counts.get("confirmed", 0) + counts.get("unreviewed", 0)
    if not open_count:
        return "Resume: no open findings need review"
    finding_word = "finding" if open_count == 1 else "findings"
    verb = "needs" if open_count == 1 else "need"
    return (
        f"Resume: {open_count} open {finding_word} {verb} review "
        f"({counts.get('confirmed', 0)} confirmed, "
        f"{counts.get('unreviewed', 0)} unreviewed)"
    )


def report_grouping_line(parsed: Namespace) -> str:
    """Return the report grouping mode and the inverse selector hint."""
    if parsed.sort == "host":
        return "Report: grouped by host\nUse sort=finding to group affected hosts under each finding."
    return "Report: grouped by finding\nUse sort=host to group findings under each host."


def severity_class_counts(groups: list[FindingGroup]) -> dict[str, int]:
    """Count finding groups by broad operational severity class."""
    counts = {key: 0 for key in SEVERITY_CLASS_ORDER}
    for group in groups:
        payload = effective_finding_payload(group.representative)
        counts[severity_class(payload.get("severity"))] += 1
    return counts


def render_status_heading(parsed: Namespace) -> str:
    """Return the subheading shown before filtered report rows."""
    status = parsed.status
    if parsed.action == "detail":
        selection = parsed.selection or ""
        return f"Finding detail: {selection}"
    if status == "open":
        return "Open findings:"
    return "All findings:" if status == "all" else f"{status.capitalize()} findings:"
