"""Report heading, summary, ordering, and audit-payload helpers.

Used by: `analysis.report.render` while assembling operator-facing report
views and `report.rendered` audit events.
"""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Mapping

from bywaf.event import Event
from bywaf.finding import SEVERITY_CLASS_ORDER, severity_class

from .model import FindingGroup, effective_finding_payload
from .network import host_overviews
from .review import ReviewDecision, review_status


def empty_status_message(status: str) -> str:
    """Return a natural empty-state message for one report status filter.

    Called by: report rendering when the filtered finding set is empty.
    """
    if status == "open":
        return "no open findings"
    if status == "unreviewed":
        return "no unreviewed findings"
    if status == "all":
        return "no findings"
    return f"no {status} findings"


def report_heading(parsed: Namespace, events: list[Event], groups: list[FindingGroup]) -> str:
    """Return a compact heading for one report view.

    Called by: `analysis.report.render` before rendering finding rows.
    """
    # Convert mutually exclusive report selectors into one operator-facing
    # action/scope phrase. This keeps report headings consistent across inbox,
    # explicit job/pipeline/step scopes, latest-scan, and new-delta views.
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
    """Return a compact heading for the network report view.

    Called by: network-focused report rendering before host/service sections.
    """
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
    """Return a structured payload describing one rendered report.

    Consumed by: audit/event views that need to explain which report command
    rendered which finding groups and runtime scope.
    """
    # Keep the audit payload compact and referential: store event IDs and group
    # IDs rather than repeating full finding payloads already in the event log.
    #
    # The action field is derived from the mutually exclusive selector state:
    # explicit job/pipeline/step selectors are "show", the delta view is "new",
    # and the default view is the operator's report inbox.
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
    """Return report groups in the requested operator-priority order.

    Called by: report rendering after grouping and review-decision collection.
    """
    # The default order is established earlier by grouping/synthesis. These
    # optional orderings only promote review states without re-sorting the whole
    # report by unrelated fields.
    if getattr(parsed, "accepted_first", False):
        # Sort key shape: accepted groups first, then original event chronology.
        # This lets a reviewer confirm what has already been accepted without
        # losing the stable ordering inside that bucket.
        return sorted(groups, key=lambda group: (review_status(group, decisions) != "accepted", first_group_event_id(group)))
    if getattr(parsed, "candidates_first", False):
        # Sort key shape: candidate/potential groups first, then original event
        # chronology. Confirmed findings are not demoted by severity here; this
        # mode is specifically for triaging uncertain evidence.
        return sorted(groups, key=lambda group: (not group_has_candidate_status(group), first_group_event_id(group)))
    return groups


def report_order(parsed: Namespace) -> str:
    """Return the report row ordering label for audit payloads.

    Used by: `report_rendered_payload()` so audit events record which optional
    ordering mode shaped the displayed report.
    """
    if getattr(parsed, "accepted_first", False):
        return "accepted-first"
    if getattr(parsed, "candidates_first", False):
        return "candidates-first"
    return "default"


def first_group_event_id(group: FindingGroup) -> int:
    """Return a stable chronological key for one finding group.

    Used by: optional report ordering modes to preserve original chronology
    inside promoted review-state buckets.
    """
    # Event IDs are assigned by the store, so the minimum event ID is the
    # earliest persisted evidence in the group.
    return min((event.id or 0) for event in group.events)


def group_has_candidate_status(group: FindingGroup) -> bool:
    """Return whether a group represents candidate or potential finding evidence.

    Used by: `order_report_groups()` when `candidates_first` is selected.
    """
    # A group can be candidate-like either by its event topic or by a normalized
    # status field inside the effective finding payload. Checking both keeps
    # older and newer finding producers compatible with report ordering.
    return any(
        event.topic in {"finding.candidate", "finding.merge_candidate"}
        or str(effective_finding_payload(event).get("status") or "").casefold() in {"candidate", "potential"}
        for event in group.events
    )


def review_summary_line(
    counts: Mapping[str, int],
    severity_counts: Mapping[str, int] | None = None,
) -> str:
    """Return a compact review-state summary for the report heading.

    Called by: report rendering after review counts are computed.
    """
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
    # Severity classes are appended only when useful so simple reports do not
    # grow an empty second summary line.
    # The class order is fixed by `SEVERITY_CLASS_ORDER`, which keeps report
    # summaries visually stable even when dict insertion order varies upstream.
    class_summary = ", ".join(
        f"{severity_counts[item]} {item}"
        for item in SEVERITY_CLASS_ORDER
        if severity_counts.get(item, 0)
    )
    return f"{summary}\nseverity classes: {class_summary}" if class_summary else summary


def resume_summary_line(counts: Mapping[str, int]) -> str:
    """Return a short field-resume summary for open report work.

    Called by: report rendering to show whether operator review work remains.
    """
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


def resume_focus_line(groups: list[FindingGroup], decisions: Mapping[str, ReviewDecision]) -> str:
    """Return severity focus for findings still needing operator attention.

    Called by: report rendering after grouping and review-status resolution.
    """
    # Resume guidance ignores accepted/deferred/rejected groups; the goal is to
    # orient an operator toward work still pending in the current scope.
    open_groups = [group for group in groups if review_status(group, decisions) in {"confirmed", "unreviewed"}]
    if not open_groups:
        return ""
    counts = severity_class_counts(open_groups)
    # Use broad classes rather than exact severities so the line stays short
    # enough to act as a prompt for the next review action.
    class_summary = ", ".join(
        f"{counts[item]} {item}"
        for item in SEVERITY_CLASS_ORDER
        if counts.get(item, 0)
    )
    return f"Resume focus: {class_summary}" if class_summary else ""


def report_grouping_line(parsed: Namespace) -> str:
    """Return the report grouping mode and the inverse selector hint.

    Called by: report rendering near the top of the output so operators can
    switch between finding-first and host-first views without checking help.
    """
    if parsed.sort == "host":
        return "Report: grouped by host\nUse sort=finding to group affected hosts under each finding."
    return "Report: grouped by finding\nUse sort=host to group findings under each host."


def severity_class_counts(groups: list[FindingGroup]) -> dict[str, int]:
    """Count finding groups by broad operational severity class.

    Used by: summary and resume-focus lines to collapse raw severities into the
    project’s operator-facing severity classes.
    """
    counts = {key: 0 for key in SEVERITY_CLASS_ORDER}
    for group in groups:
        # Count each finding group once using the representative payload chosen
        # by grouping logic, not every raw event in the group.
        payload = effective_finding_payload(group.representative)
        counts[severity_class(payload.get("severity"))] += 1
    return counts


def render_status_heading(parsed: Namespace) -> str:
    """Return the subheading shown before filtered report rows.

    Called by: report rendering immediately before the row body.
    """
    status = parsed.status
    if parsed.action == "detail":
        selection = parsed.selection or ""
        return f"Finding detail: {selection}"
    if status == "open":
        return "Open findings:"
    return "All findings:" if status == "all" else f"{status.capitalize()} findings:"
