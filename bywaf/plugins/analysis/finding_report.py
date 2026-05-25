"""Finding report commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Collects finding events and writes human-readable or machine-readable reports.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet, option
from bywaf.plugins._args import key_value_to_long_options
from bywaf.plugins.analysis.finding_dedupe import FINDING_INPUT_TOPICS, normalize_event
from bywaf.rendering import Column, Table, render_table
from bywaf.utils import complete_path

DEDUP_FINDING_TOPICS = ("finding.new", "finding.merge_candidate")
REPORT_FINDING_TOPICS = ("finding.candidate", *DEDUP_FINDING_TOPICS)
SOURCE_CHOICES = ("auto", "dedupe", "tools", "all")
FORMAT_CHOICES = ("md", "csv", "jsonl", "html", "docx", "xlsx")
OPTION_KEYS = {"export", "file", "format", "limit", "source"}


@commandlet(
    name="finding_report",
    description="Render normalized or raw tool findings as a table.",
    usage="finding_report [source=auto|dedupe|tools|all] [export=report.md] [--candidates]",
    examples=(
        "finding_dedupe | finding_report",
        "finding_report",
        "finding_report source=tools",
        "finding_report export=findings.md",
        "finding_report export=findings.xlsx",
    ),
    consumes=(*REPORT_FINDING_TOPICS, *FINDING_INPUT_TOPICS),
    emits=("framework.render.table.requested", "artifact.attached"),
    capabilities=(
        "artifact.write",
        "db.read:finding.candidate",
        "db.read:finding.new",
        "db.read:finding.merge_candidate",
        "db.read:nikto.finding",
        "db.read:vulnerability.found",
        "db.read:vulnerability.potential",
        "db.read:vulnerability.confirmed",
        "db.read:vulnerability.speculative",
        "db.read:vulnerability.false_positive",
        "filesystem.read",
        "filesystem.write",
        "framework.render.table",
    ),
)
@option("export", "write and attach a table file; format is inferred from suffix", completion="path")
@option("file", "compatibility alias for export=", completion="path")
@option("format", "file format when suffix is ambiguous", "md", FORMAT_CHOICES)
@option("limit", "maximum events to inspect when no pipeline input exists", "1000")
@option("source", "finding source", "auto", SOURCE_CHOICES)
class FindingReport(CommandletBase):
    """Create a findings table through the framework table renderer."""

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render a findings report from dedupe output or raw tool events."""
        parser = self.parser()
        parser.usage = self.spec.usage
        parser.add_argument("--candidates", action="store_true")
        parser.add_argument("--export", default="", help=argparse.SUPPRESS)
        parser.add_argument("--file", default="", help=argparse.SUPPRESS)
        parser.add_argument("--format", choices=FORMAT_CHOICES, default="md", help=argparse.SUPPRESS)
        parser.add_argument("--limit", type=int, default=1000, help=argparse.SUPPRESS)
        parser.add_argument("--source", choices=SOURCE_CHOICES, default="auto", help=argparse.SUPPRESS)
        parsed = parser.parse_args(key_value_to_long_options(args, OPTION_KEYS))

        events = select_report_events(
            context,
            list(input_events),
            source=str(parsed.source),
            include_candidates=bool(parsed.candidates),
            limit=int(parsed.limit),
        )
        rows = finding_rows(events, include_candidates=bool(parsed.candidates))
        table = findings_table(rows)
        export_path = str(parsed.export or parsed.file or "")
        if export_path:
            write_table_artifact(
                context,
                table,
                Path(export_path).expanduser(),
                infer_export_format(Path(export_path), str(parsed.format)),
            )
        context.render.table(table)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete explicit named arguments separate from `--option` flags."""
        del context, args
        if prefix.startswith("export="):
            return [f"export={candidate}" for candidate in complete_path(prefix.removeprefix("export="))]
        if prefix.startswith("file="):
            return [f"file={candidate}" for candidate in complete_path(prefix.removeprefix("file="))]
        if prefix.startswith("format="):
            return [f"format={choice}" for choice in FORMAT_CHOICES]
        if prefix.startswith("source="):
            return [f"source={choice}" for choice in SOURCE_CHOICES]
        return [candidate for candidate in ("export=", "file=", "format=", "source=") if candidate.startswith(prefix)]


def select_report_events(
    context: CommandContext,
    input_events: list[Event],
    *,
    source: str,
    include_candidates: bool,
    limit: int,
) -> list[Event]:
    """Prefer pipeline input, otherwise choose deduped or raw DB findings."""
    usable_input = [event for event in input_events if report_topic_allowed(event.topic, source, include_candidates)]
    if usable_input:
        return usable_input

    # In standalone use, prefer normalized dedupe output when it exists. Raw tool
    # findings are still available through source=tools for troubleshooting or
    # before a pipeline has adopted finding_dedupe.
    dedupe_events = query_topics(context, REPORT_FINDING_TOPICS, limit)
    if not include_candidates:
        dedupe_events = [event for event in dedupe_events if event.topic != "finding.merge_candidate"]
    tool_events = query_topics(context, FINDING_INPUT_TOPICS, limit)
    sources = {
        "dedupe": dedupe_events,
        "tools": tool_events,
        "all": sorted([*dedupe_events, *tool_events], key=lambda event: event.id or 0),
        "auto": dedupe_events if dedupe_events else tool_events,
    }
    try:
        return sources[source]
    except KeyError as exc:
        raise ValueError(f"unknown finding report source: {source}") from exc


def query_topics(context: CommandContext, topics: tuple[str, ...], limit: int) -> list[Event]:
    """Query several topics and return them in event order."""
    events: list[Event] = []
    for topic in topics:
        events.extend(context.events.query(topic=topic, limit=limit))
    return sorted(events, key=lambda event: event.id or 0)


def report_topic_allowed(topic: str, source: str, include_candidates: bool) -> bool:
    """Return whether a topic is acceptable for this report source."""
    if topic == "finding.merge_candidate" and not include_candidates:
        return False
    if source == "dedupe":
        return topic in REPORT_FINDING_TOPICS
    if source == "tools":
        return topic in FINDING_INPUT_TOPICS
    return topic in REPORT_FINDING_TOPICS or topic in FINDING_INPUT_TOPICS


def finding_rows(events: list[Event], *, include_candidates: bool) -> list[dict[str, str]]:
    """Convert finding events into the requested report columns."""
    rows: list[dict[str, str]] = []
    seen_finding_ids: set[str] = set()
    for event in events:
        if event.topic == "finding.merge_candidate" and not include_candidates:
            continue
        row = row_from_event(event)
        finding_id = str(event.payload.get("finding_id") or "")
        if finding_id and event.topic in {"finding.candidate", "finding.new"}:
            # Keep the table readable when a commandlet emitted the same
            # normalized finding more than once in the selected scope.
            if finding_id in seen_finding_ids:
                continue
            seen_finding_ids.add(finding_id)
        rows.append(row)
    return rows


def row_from_event(event: Event) -> dict[str, str]:
    """Return one reporting row from a normalized or raw finding event."""
    if event.topic in REPORT_FINDING_TOPICS:
        payload = event.payload
        if event.topic == "finding.merge_candidate":
            payload = candidate_payload(payload)
        return row_from_payload(payload)
    normalized = normalize_event(event)
    return {
        "finding_name": normalized.title,
        "description": normalized.evidence or normalized.finding_class,
        "hosts_affected": host_from_target(normalized.target.as_payload()),
        "cve": cve_values(normalized.identifiers),
        "severity": normalized.severity,
        "recommendation": recommendation_for(normalized.finding_class, normalized.raw),
    }


def row_from_payload(payload: Mapping[str, Any]) -> dict[str, str]:
    """Return one reporting row from a normalized finding payload."""
    title = str(payload.get("title") or payload.get("class") or "finding")
    finding_class = str(payload.get("class") or "")
    description = str(payload.get("description") or payload.get("evidence") or finding_class)
    identifiers = identifiers_from_payload(payload)
    return {
        "finding_name": title,
        "description": description,
        "hosts_affected": host_from_target(payload.get("target")),
        "cve": cve_values(identifiers),
        "severity": str(payload.get("severity") or "unknown"),
        "recommendation": recommendation_for(finding_class, dict(payload)),
    }


def candidate_payload(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the nested candidate payload for merge-candidate rows."""
    candidate = payload.get("candidate")
    if isinstance(candidate, Mapping):
        return candidate
    return payload


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


def identifiers_from_payload(payload: Mapping[str, Any]) -> dict[str, list[str]]:
    """Return normalized identifiers from a finding payload."""
    raw = payload.get("identifiers")
    if not isinstance(raw, Mapping):
        return {}
    identifiers: dict[str, list[str]] = {}
    for key, value in raw.items():
        values = value if isinstance(value, list) else [value]
        identifiers[str(key).lower()] = [str(item) for item in values if str(item)]
    return identifiers


def cve_values(identifiers: Mapping[str, list[str]]) -> str:
    """Return comma-separated CVE identifiers."""
    return ", ".join(identifiers.get("cve", ()))


def host_from_target(target: object) -> str:
    """Return a compact affected-host string from a target payload."""
    if not isinstance(target, Mapping):
        return ""
    host = str(target.get("host") or "")
    scheme = str(target.get("scheme") or "")
    port = str(target.get("port") or "")
    path = str(target.get("path") or "")
    if host:
        authority = host if not port else f"{host}:{port}"
        return f"{scheme}://{authority}{path}" if scheme else f"{authority}{path}"
    url = target.get("url")
    return str(url) if url else ""


def recommendation_for(finding_class: str, payload: Mapping[str, Any]) -> str:
    """Return a supplied remediation or a conservative class-based suggestion."""
    for key in ("recommendation", "remediation", "solution", "fix"):
        value = payload.get(key)
        if value:
            return str(value)
    recommendations = {
        "missing_security_header": "Add the missing security header and verify it is present on affected responses.",
        "directory_listing": "Disable directory listing or restrict access to the affected path.",
        "default_credentials": "Change default credentials and verify authentication controls.",
        "known_vulnerable_component": "Upgrade or patch the affected component and retest.",
        "exposed_admin_interface": "Restrict administrative interfaces to authorized networks and require strong authentication.",
        "tls_weak_cipher": "Disable weak TLS protocols/ciphers and retest the service.",
        "sql_injection_possible": "Validate input handling and confirm with safe, authorized testing before remediation.",
    }
    return recommendations.get(finding_class, "Review the source evidence, confirm impact, and remediate according to the affected component.")


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return FindingReport()
