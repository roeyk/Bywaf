"""Finding report table and export helpers.

Used by: `finding_report.FindingReport` after event selection and row
normalization have produced the final report rows.
"""

from __future__ import annotations

from pathlib import Path

from bywaf.plugin import CommandContext
from bywaf.rendering import Column, Table, render_table

FORMAT_CHOICES = ("md", "csv", "jsonl", "html", "docx", "xlsx")


def findings_table(rows: list[dict[str, str]]) -> Table:
    """Build the report table with stable user-facing headings."""
    return Table.from_rows(
        rows,
        (
            Column("finding_name", "Finding name"),
            Column("description", "Description"),
            Column("hosts_affected", "Host(s) affected"),
            Column("cve", "CVE"),
            Column("severity", "Severity rating"),
            Column("recommendation", "Recommendation"),
        ),
        title="Findings",
    )


def write_table_artifact(context: CommandContext, table: Table, path: Path, format_name: str) -> None:
    """Render a table to disk and attach it as a report artifact."""
    context.audit_capability("filesystem.write")
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = render_table(table, format_name)  # type: ignore[arg-type]
    if isinstance(rendered, bytes):
        path.write_bytes(rendered)
    else:
        path.write_text(rendered, encoding="utf-8")
    context.artifacts.attach_file(path, name=path.name, note="Finding report table")


def infer_export_format(path: Path, fallback: str) -> str:
    """Infer a table renderer from an export filename suffix."""
    suffix = path.suffix.lower().lstrip(".")
    if suffix == "json":
        return "jsonl"
    if suffix in FORMAT_CHOICES:
        return suffix
    if fallback in FORMAT_CHOICES:
        return fallback
    return "md"
