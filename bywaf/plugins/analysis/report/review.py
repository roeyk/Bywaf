"""Report review-state helpers.

Handles append-only review markers and status filtering for grouped findings.

Used by:
- analysis.report: implement report accept/defer/reject actions.
- analysis.report.render: count and filter reviewed groups."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from bywaf.plugin import CommandContext

from .model import FindingGroup, effective_finding_payload, group_finding_events

REVIEW_DECISIONS = {"accept": "accepted", "defer": "deferred", "reject": "rejected"}


@dataclass(frozen=True)
class ReviewDecision:
    """Latest review state for one finding group."""

    decision: str
    note: str = ""
    event_id: int | None = None


def review_report_groups(context: CommandContext, parsed, events) -> None:
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
    context.audit_capability("finding.review")
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
