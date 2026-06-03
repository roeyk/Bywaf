"""Report table construction and styling helpers."""

from __future__ import annotations

from collections.abc import Mapping

from bywaf.finding import severity_class
from bywaf.plugin import CommandContext
from bywaf.plugins.analysis.finding_display import affected_values
from bywaf.plugins.analysis.finding_report import finding_rows
from bywaf.rendering import Column, Table, align_text, table_values
from bywaf.runtime_display import shrink_table_widths, terminal_table_width, truncate_cell

from .model import FindingGroup, effective_finding_payload
from .review import ReviewDecision, review_status
from .style import finding_text, report_text, table_text


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


def render_styled_report_table(context: CommandContext, table: Table) -> str:
    """Render a report table with theme-driven baseline and subject styles."""
    if not table.columns:
        return report_text(context, "section", table.title or "")
    values = table_values(table)
    widths = [
        max(len(column.heading), *(len(row[index]) for row in values))
        for index, column in enumerate(table.columns)
    ]
    widths = shrink_table_widths(widths, [column.heading for column in table.columns], terminal_table_width())
    values = [
        [truncate_cell(value, widths[index]) for index, value in enumerate(row)]
        for row in values
    ]
    lines: list[str] = []
    if table.title:
        lines.append(report_text(context, "section", table.title))
    headings = [
        table_text(context, "header", align_text(column.heading, widths[index], column.align))
        for index, column in enumerate(table.columns)
    ]
    lines.append("  ".join(headings))
    lines.append(
        "  ".join(
            table_text(context, "header", "-" * width)
            for width in widths
        )
    )
    for row_index, row in enumerate(values):
        cells: list[str] = []
        row_mapping = table.rows[row_index]
        for index, value in enumerate(row):
            column = table.columns[index]
            aligned = align_text(value, widths[index], column.align)
            cells.append(styled_report_cell(context, column.key, aligned, row_mapping))
        lines.append("  ".join(cells))
    return "\n".join(lines)


def styled_report_cell(
    context: CommandContext,
    column_key: str,
    value: str,
    row: Mapping[str, object],
) -> str:
    """Apply the most specific report-table style for one cell."""
    if column_key == "index":
        return table_text(context, "index", value)
    if column_key == "host":
        return table_text(context, "index", value)
    if column_key == "finding_name":
        return finding_text(context, "title", value)
    if column_key == "severity":
        severity = str(row.get("severity") or "").strip().casefold()
        if severity:
            styled = finding_text(context, f"severity.{severity}", value)
            if styled != value:
                return styled
            severity_class_name = severity_class(severity)
            styled = finding_text(context, f"severity_class.{severity_class_name}", value)
            if styled != value:
                return styled
    return table_text(context, "body", value)
