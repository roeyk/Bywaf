"""Report review-state helpers.

Handles append-only review markers and status filtering for grouped findings.

Used by:
- analysis.report: implement report accept/defer/reject actions.
- analysis.report.render: count and filter reviewed groups."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from bywaf.plugin import CommandContext

from .model import FindingGroup, effective_finding_payload, filter_groups_by_cve, group_finding_events

# report review actions are verbs, while persisted finding.reviewed events store
# statuses. review_report_groups() uses this lookup table to convert the operator
# action into the durable review decision written to the event stream.
REVIEW_DECISIONS = {
    "accept": "accepted",
    "confirm": "confirmed",
    "defer": "deferred",
    "reject": "rejected",
    "unconfirm": "unreviewed",
}
# latest_review_decisions() and review_counts() use this closed set to validate
# stored review decisions and initialize status counters for report summaries.
REVIEW_STATUSES = ("accepted", "confirmed", "deferred", "rejected", "unreviewed")

# Review actions and stored statuses use different user-facing words.
# review_output_label() uses this lookup table to keep output labels stable.
ACTION_OUTPUT_LABELS = {
    "accepted": "accepted",
    "confirmed": "confirmed",
    "deferred": "deferred",
    "rejected": "rejected",
    "unreviewed": "unconfirmed",
}


@dataclass(frozen=True)
class ReviewDecision:
    """Latest operator review marker for one finding group.

    Constructed by: `latest_review_decisions()` while replaying
    `finding.reviewed` events from the EventStore.
    Used by: report rendering, report review actions, and the `finding`
    command facade when deciding whether a row is accepted, rejected,
    deferred, confirmed, or still unreviewed.
    """

    decision: str
    note: str = ""
    event_id: int | None = None


def review_report_groups(context: CommandContext, parsed, events, *, source: str = "report") -> None:
    """Append review-state events for selected report rows.

    Called by: `Report.run()` and `Finding.run()` after argparse normalization.
    The function deliberately writes append-only `finding.reviewed` events
    instead of editing original finding payloads, so the review history remains
    auditable and `latest_review_decisions()` can reconstruct current state.
    """
    if not parsed.selection:
        raise ValueError(f"report {parsed.action} requires a selection such as 1, 1-3, or all")
    # Review actions operate on the same filtered inbox the operator sees. That
    # keeps `report accept 1-3` aligned with the currently displayed row numbers.
    groups = filter_groups_by_cve(group_finding_events(events), str(getattr(parsed, "cve", "")))
    decisions = latest_review_decisions(context)
    visible_groups = filter_groups_by_status(groups, decisions, parsed.status)
    selected = selected_groups(visible_groups, str(parsed.selection))
    if not selected:
        raise ValueError("report selection matched no findings")

    # Translate the operator's verb into the durable status stored on the
    # review marker. `unconfirm` becomes `unreviewed`, while confirmation is a
    # distinct explicit operator decision from plugin-produced proof.
    decision = REVIEW_DECISIONS[str(parsed.action)]
    context.audit_capability("finding.review")
    for group in selected:
        # Persist the grouped finding id, not the display row number. Later
        # reports can then resolve review state even if the visible ordering or
        # status filter changes between commands.
        context.events.publish(
            "finding.reviewed",
            {
                "finding_id": group.finding_id,
                "decision": decision,
                "note": parsed.note,
                "source": source,
            },
        )
    label = ACTION_OUTPUT_LABELS.get(decision, decision)
    context.output(f"{label} {len(selected)} finding{'s' if len(selected) != 1 else ''}")


def selected_groups(groups: list[FindingGroup], selection: str) -> list[FindingGroup]:
    """Resolve report row indexes and ranges into finding groups.

    Called by: `review_report_groups()` after status/CVE filtering has already
    produced the same visible row set the operator reviewed on screen.
    """
    if selection == "all":
        return groups
    selected_indexes = parse_index_selection(selection, maximum=len(groups))
    return [groups[index - 1] for index in selected_indexes]


def parse_index_selection(selection: str, *, maximum: int) -> list[int]:
    """Parse comma-separated 1-based indexes and inclusive ranges.

    Called by: review action selection and detail rendering code that accepts
    forms such as `1`, `1-3`, and `1-2,4`. Duplicate indexes are collapsed while
    preserving the operator's requested order.
    """
    indexes: list[int] = []
    seen: set[int] = set()
    for part in selection.split(","):
        token = part.strip()
        if not token:
            raise ValueError("empty report selection range")
        if "-" in token:
            # A hyphen denotes an inclusive report-row range. Both endpoints are
            # validated through the same positive-index helper as scalar rows.
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
    """Return a positive integer report row index.

    Called by: `parse_index_selection()` for both scalar selections and range
    endpoints before converting 1-based display rows to zero-based list indexes.
    """
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"invalid report selection index: {value}") from exc
    if parsed < 1:
        raise ValueError(f"invalid report selection index: {value}")
    return parsed


def latest_review_decisions(context: CommandContext) -> dict[str, ReviewDecision]:
    """Return the latest review decision for each finding id.

    Called by: report rendering and review mutation paths before calculating
    effective row status. Because review markers are append-only, this function
    replays `finding.reviewed` events and keeps the highest event id for each
    finding id.
    """
    decisions: dict[str, ReviewDecision] = {}
    for event in context.events.query(topic="finding.reviewed", limit=100000):
        finding_id = str(event.payload.get("finding_id") or "")
        if not finding_id:
            continue
        decision = str(event.payload.get("decision") or "accepted")
        if decision not in REVIEW_STATUSES:
            # Old review events predated explicit decision values. Treat those
            # markers as accepted so historical "reviewed" rows stay hidden by
            # default rather than reappearing as open findings.
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
    """Return the effective review status for one finding group.

    Called by: report tables, summary lines, status filters, and render-order
    helpers. Explicit operator review markers take precedence over plugin
    evidence; otherwise plugin-confirmed proof promotes the row to `confirmed`.
    """
    decision = review_decision_for_group(group, decisions)
    if decision is not None:
        return decision.decision
    if group_has_confirmed_proof(group):
        return "confirmed"
    return "unreviewed"


def review_decision_for_group(
    group: FindingGroup,
    decisions: Mapping[str, ReviewDecision],
) -> ReviewDecision | None:
    """Return the latest review decision matching a group key or raw finding id.

    Called by: `review_status()` to bridge grouped report rows and historical
    review markers that may have been written before grouping logic changed.
    """
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
    """Return review identifiers that may refer to one finding group.

    Called by: `review_decision_for_group()`. The first key is the current
    report group id; later keys are raw `finding_id` values carried by member
    events inside that group.
    """
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
    """Return report groups matching the requested review status.

    Called by: report rendering and review actions after grouping and optional
    CVE filtering. `open` is a convenience view over confirmed and unreviewed
    rows, because both still require operator attention.
    """
    if status == "all":
        return groups
    if status == "open":
        return [group for group in groups if review_status(group, decisions) in {"confirmed", "unreviewed"}]
    return [group for group in groups if review_status(group, decisions) == status]


def review_counts(
    groups: list[FindingGroup],
    decisions: Mapping[str, ReviewDecision],
) -> dict[str, int]:
    """Count finding groups by current review status.

    Called by: report summary rendering and `report.rendered` audit payload
    construction. The returned mapping always includes all known statuses so
    display code can render stable summary lines.
    """
    counts = {key: 0 for key in ("total", *REVIEW_STATUSES)}
    counts["total"] = len(groups)
    for group in groups:
        counts[review_status(group, decisions)] += 1
    return counts


def group_has_confirmed_proof(group: FindingGroup) -> bool:
    """Return whether a group includes a plugin-produced confirmed finding.

    Called by: `review_status()` when no explicit operator review marker exists.
    This keeps scanner-produced proof visible as confirmed while still allowing
    later operator accept/reject/defer markers to override it.
    """
    return any(
        event.topic == "finding.confirmed"
        or str(effective_finding_payload(event).get("status") or "").casefold() == "confirmed"
        for event in group.events
    )
