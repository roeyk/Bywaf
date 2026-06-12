"""Finding report commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Collects finding events and writes human-readable or machine-readable reports.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.

Public surface: re-exports the package API so callers can import the
subsystem without depending on internal module layout.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import argparse
from collections.abc import Iterable
from pathlib import Path

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet, option
from bywaf.plugin import kv_to_args
from bywaf.plugins.analysis.finding.dedupe import FINDING_INPUT_TOPICS
from bywaf.plugins.analysis.finding.report.export import FORMAT_CHOICES, findings_table, infer_export_format, write_table_artifact
from bywaf.plugins.analysis.finding.report.rows import (
    candidate_payload,
    cve_values,
    finding_rows,
    host_from_target,
    identifiers_from_payload,
    recommendation_for,
    row_from_event,
    row_from_payload,
)
from bywaf.plugins.analysis.finding.topics import DEDUP_FINDING_TOPICS, REPORT_FINDING_TOPICS, SOURCE_CHOICES
from bywaf.utils import complete_path

OPTION_KEYS = {"export", "file", "format", "limit", "source"}

__all__ = [
    "DEDUP_FINDING_TOPICS",
    "FORMAT_CHOICES",
    "FindingReport",
    "REPORT_FINDING_TOPICS",
    "SOURCE_CHOICES",
    "candidate_payload",
    "cve_values",
    "finding_rows",
    "findings_table",
    "host_from_target",
    "identifiers_from_payload",
    "infer_export_format",
    "recommendation_for",
    "report_topic_allowed",
    "row_from_event",
    "row_from_payload",
    "select_report_events",
    "write_table_artifact",
]


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
        parsed = parser.parse_args(kv_to_args(args, OPTION_KEYS))

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


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return FindingReport()
