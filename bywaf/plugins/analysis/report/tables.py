"""Report table construction and styling helpers."""

from __future__ import annotations

from collections.abc import Mapping

from bywaf.plugins.analysis.finding_display import affected_values
from bywaf.plugins.analysis.finding_report import finding_rows
from bywaf.rendering import Column, Table

from .model import FindingGroup, effective_finding_payload
from .review import ReviewDecision, review_status
from .table_rendering import render_styled_report_table, styled_report_cell

__all__ = [
    "affected_hosts_from_row",
    "finding_affected_summary",
    "finding_affected_values",
    "finding_basis_summary",
    "finding_display_name",
    "finding_host_summary",
    "group_has_confirmed_event",
    "indexed_findings_table",
    "indexed_hosts_table",
    "render_styled_report_table",
    "styled_report_cell",
]


def indexed_findings_table(
    groups: list[FindingGroup],
    *,
    decisions: Mapping[str, ReviewDecision],
    show_review_status: bool = False,
) -> Table:
    """Return a report table with stable 1-based row indexes."""
    representatives = [group.representative for group in groups]
    rows = [
        {
            "index": index,
            **row,
            "finding_name": finding_display_name(row, group),
            "hosts_affected": finding_affected_summary(row, group),
            "basis": finding_basis_summary(group),
            "review": review_status(group, decisions),
        }
        for index, (group, row) in enumerate(zip(groups, finding_rows(representatives, include_candidates=True), strict=True), start=1)
    ]
    columns = [
        Column("index", "#", "right"),
        Column("finding_name", "Finding"),
        Column("hosts_affected", "Affected"),
        Column("cve", "CVE"),
        Column("severity", "Severity"),
    ]
    if any(row.get("basis") for row in rows):
        columns.append(Column("basis", "Basis"))
    if show_review_status:
        columns.append(Column("review", "Review"))
    return Table.from_rows(
        rows,
        tuple(columns),
        title="Findings",
    )


def indexed_hosts_table(
    groups: list[FindingGroup],
    *,
    decisions: Mapping[str, ReviewDecision],
) -> Table:
    """Return report rows grouped by affected host."""
    rows_by_host: dict[str, list[str]] = {}
    host_order: list[str] = []
    representatives = [group.representative for group in groups]
    for group, row in zip(groups, finding_rows(representatives, include_candidates=True), strict=True):
        row = {**row, "finding_name": finding_display_name(row, group)}
        review = review_status(group, decisions)
        summary = finding_host_summary(row, review)
        hosts = finding_affected_values(group) or affected_hosts_from_row(row)
        for host in hosts:
            if host not in rows_by_host:
                rows_by_host[host] = []
                host_order.append(host)
            rows_by_host[host].append(summary)
    rows = [
        {
            "index": index,
            "host": host,
            "findings": "; ".join(dict.fromkeys(rows_by_host[host])),
        }
        for index, host in enumerate(host_order, start=1)
    ]
    return Table.from_rows(
        rows,
        (
            Column("index", "#", "right"),
            Column("host", "Host"),
            Column("findings", "Findings"),
        ),
        title="Hosts",
    )


def finding_host_summary(row: Mapping[str, object], review: str) -> str:
    """Return one compact finding description for a host-grouped report."""
    title = str(row.get("finding_name") or "finding")
    severity = str(row.get("severity") or "").strip()
    suffix = ", ".join(value for value in (severity, review) if value)
    return f"{title} [{suffix}]" if suffix else title


def finding_display_name(row: Mapping[str, object], group: FindingGroup) -> str:
    """Return finding title annotated with stronger evidence state when useful."""
    title = str(row.get("finding_name") or "finding")
    if group_has_confirmed_event(group) and "confirmed" not in title.casefold():
        return f"{title} (confirmed)"
    return title


def finding_basis_summary(group: FindingGroup) -> str:
    """Return compact confidence-basis labels represented by one group."""
    values = []
    for event in group.events:
        value = str(effective_finding_payload(event).get("confidence_basis") or "").strip()
        if value:
            values.append(value.replace("_", " "))
    return ", ".join(dict.fromkeys(values))


def group_has_confirmed_event(group: FindingGroup) -> bool:
    """Return whether a report group includes a confirmed finding observation."""
    return any(
        event.topic == "finding.confirmed"
        or str(effective_finding_payload(event).get("status") or "").casefold() == "confirmed"
        for event in group.events
    )


def finding_affected_summary(row: Mapping[str, object], group: FindingGroup) -> str:
    """Return a compact affected-resource summary for one finding table row."""
    values = finding_affected_values(group)
    if not values:
        return str(row.get("hosts_affected") or "")
    if len(values) == 1:
        return values[0]
    shown = values[:2]
    suffix = f"; +{len(values) - len(shown)} more" if len(values) > len(shown) else ""
    return f"{len(values)} affected: {'; '.join(shown)}{suffix}"


def finding_affected_values(group: FindingGroup) -> list[str]:
    """Return unique affected resources represented by one finding group."""
    values: list[str] = []
    for event in group.events:
        payload = effective_finding_payload(event)
        values.extend(affected_values([payload]))
    return list(dict.fromkeys(values))


def affected_hosts_from_row(row: Mapping[str, object]) -> list[str]:
    """Return affected-host display values from one finding row."""
    raw = str(row.get("hosts_affected") or "").strip()
    if not raw:
        return ["(unknown)"]
    hosts = [host.strip() for host in raw.split(",") if host.strip()]
    return hosts or ["(unknown)"]
