"""Finding deduplication commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Consumes finding events and emits deduplicated findings for reporting workflows.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch.

Public surface: re-exports the package API so callers can import the
subsystem without depending on internal module layout.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugin import kv_to_args
from bywaf.plugins.analysis.finding.dedupe.model import CanonicalFinding, NormalizedFinding
from bywaf.plugins.analysis.finding.dedupe.normalize import (
    count_decisions,
    matched_on,
    normalize_event,
    stable_finding_id,
    status_rank,
)
from bywaf.plugins.analysis.finding.dedupe.publish import (
    publish_dedupe_result,
    summary_line,
    write_summary_artifact,
)

FINDING_INPUT_TOPICS = (
    "finding.candidate",
    "finding.confirmed",
    "nikto.finding",
    "vulnerability.found",
    "vulnerability.potential",
    "vulnerability.confirmed",
    "vulnerability.speculative",
    "vulnerability.false_positive",
)
FINDING_OUTPUT_TOPICS = (
    "finding.new",
    "finding.duplicate",
    "finding.updated",
    "finding.merge_candidate",
)
STATUS_RANKS = {
    "false_positive": 0,
    "speculative": 1,
    "potential": 2,
    "confirmed": 3,
}
OPTION_KEYS = {"file", "format", "limit", "threshold"}

@commandlet(
    name="finding_dedupe",
    description="Normalize and deduplicate vulnerability finding events.",
    usage="finding_dedupe [file=summary.json|summary.md] [format=json|md] [threshold=0.82]",
    examples=(
        "nikto source=webfin | finding_dedupe",
        "finding_dedupe file=dedupe-summary.json",
        "finding_dedupe format=md file=findings.md",
    ),
)
@option("file", "write and attach a JSON or Markdown dedupe summary", completion="path")
@option("format", "summary format", "json", ("json", "md"))
@option("limit", "maximum historical input events when no pipeline input exists", "1000")
@option("threshold", "minimum fuzzy score for merge candidates", "0.82")
class FindingDedupe(CommandletBase):
    """Build normalized finding records without destroying original tool output."""

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Deduplicate input findings and publish normalized finding events."""
        parser = self.parser()
        parser.usage = self.spec.usage
        parser.add_argument("-s", "--silent", action="store_true")
        parser.add_argument("--file", default="", help=argparse.SUPPRESS)
        parser.add_argument("--format", choices=("json", "md"), default="json", help=argparse.SUPPRESS)
        parser.add_argument("--limit", type=int, default=1000, help=argparse.SUPPRESS)
        parser.add_argument("--threshold", type=float, default=0.82, help=argparse.SUPPRESS)
        parsed = parser.parse_args(kv_to_args(args, OPTION_KEYS))

        events = selected_finding_events(context, list(input_events), parsed.limit)
        result = dedupe_findings(
            (normalize_event(event) for event in events if event.topic in FINDING_INPUT_TOPICS),
            fuzzy_threshold=float(parsed.threshold),
        )
        publish_dedupe_result(context, result, threshold=float(parsed.threshold), silent=bool(parsed.silent))
        if parsed.file:
            write_summary_artifact(context, result, Path(parsed.file).expanduser(), str(parsed.format))
        context.output(summary_line(result))
        return ()

def selected_finding_events(context: CommandContext, input_events: list[Event], limit: int) -> list[Event]:
    """Use pipeline input first, otherwise query historical finding topics."""
    selected = [event for event in input_events if event.topic in FINDING_INPUT_TOPICS]
    if selected:
        return selected
    events: list[Event] = []
    for topic in FINDING_INPUT_TOPICS:
        events.extend(context.events.query(topic=topic, limit=limit))
    return sorted(events, key=lambda event: event.id or 0)

def dedupe_findings(findings: Iterable[NormalizedFinding], *, fuzzy_threshold: float = 0.82) -> dict[str, Any]:
    """Classify findings as new, duplicate, update, or candidate merge."""
    canonical_by_key: dict[str, CanonicalFinding] = {}
    canonical: list[CanonicalFinding] = []
    decisions: list[dict[str, Any]] = []
    for finding in findings:
        # Exact keys are intentionally conservative: target plus identifier when
        # one exists, otherwise a fingerprint of stable evidence. Ambiguous
        # similarity is emitted as a merge candidate for human review.
        key = finding.exact_key()
        existing = canonical_by_key.get(key)
        if existing is None:
            fuzzy = best_fuzzy_candidate(finding, canonical, threshold=fuzzy_threshold)
            if fuzzy is None:
                finding_id = stable_finding_id(key)
                existing = CanonicalFinding(finding_id, finding, [finding.source_event_id])
                canonical_by_key[key] = existing
                canonical.append(existing)
                decisions.append({"decision": "new", "finding_id": finding_id, "finding": finding})
                continue
            decisions.append(
                {
                    "decision": "merge_candidate",
                    "finding_id": fuzzy[0].finding_id,
                    "candidate": finding,
                    "score": fuzzy[1],
                    "matched_on": ["target", "class", "fuzzy_text"],
                }
            )
            continue

        if status_rank(finding.status) > status_rank(existing.finding.status):
            # A later source can upgrade the canonical record, for example from
            # potential to confirmed. The original source trail remains attached.
            previous = existing.finding
            existing.source_event_ids.append(finding.source_event_id)
            previous.merge_from(finding)
            finding.merge_from(previous)
            existing.finding = finding
            decisions.append(
                {
                    "decision": "updated",
                    "finding_id": existing.finding_id,
                    "previous": previous,
                    "finding": finding,
                }
            )
        else:
            existing.add_source(finding)
            decisions.append(
                {
                    "decision": "duplicate",
                    "finding_id": existing.finding_id,
                    "duplicate": finding,
                    "matched_on": matched_on(finding),
                }
            )
    return {
        "canonical": canonical,
        "decisions": decisions,
        "counts": count_decisions(decisions),
    }

def best_fuzzy_candidate(
    finding: NormalizedFinding,
    canonical: list[CanonicalFinding],
    threshold: float = 0.82,
) -> tuple[CanonicalFinding, float] | None:
    """Return a fuzzy merge candidate when target and class already match."""
    best: tuple[CanonicalFinding, float] | None = None
    for candidate in canonical:
        if candidate.finding.target_identity_key() != finding.target_identity_key():
            continue
        if candidate.finding.finding_class != finding.finding_class:
            continue
        score = SequenceMatcher(None, finding.fuzzy_basis(), candidate.finding.fuzzy_basis()).ratio()
        if score >= threshold and (best is None or score > best[1]):
            best = (candidate, score)
    return best

def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return FindingDedupe()
