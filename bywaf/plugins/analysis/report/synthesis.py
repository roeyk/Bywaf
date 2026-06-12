"""Report-time passive synthesis orchestration.

Runs approved fact-only analyzers before report rendering without moving their
rule logic into the report commandlet.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.
"""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Iterable, Mapping

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.analysis.finding.dedupe import FINDING_INPUT_TOPICS, dedupe_findings
from bywaf.plugins.analysis.finding.dedupe.normalize import normalize_event
from bywaf.plugins.analysis.finding.dedupe.publish import publish_dedupe_result
from bywaf.plugins.analysis.finding.report import DEDUP_FINDING_TOPICS, REPORT_FINDING_TOPICS
from bywaf.plugins.analysis.technology_indicators import findings_from_event

from .model import sort_unique_events

# Passive synthesis is deliberately limited to schema-backed facts. The report
# command can interpret these without running probes, scanners, or network IO.
PASSIVE_SYNTHESIS_TOPICS = ("service.detected", "tcp.banner", "http.endpoint", "web.fingerprint")


def report_input_findings(context: CommandContext, input_events: Iterable[Event]) -> list[Event]:
    """Return reportable upstream findings, deduping raw finding input first.

    Called by: `analysis.report.Report.run()` when report receives pipeline
    input from an upstream commandlet.
    """
    events = list(input_events)
    # Already-deduped/reportable topics can flow straight through. This keeps
    # `http_methods | finding_dedupe | report` from deduping the same groups
    # twice.
    reportable = [event for event in events if event.topic in REPORT_FINDING_TOPICS]
    if any(event.topic in DEDUP_FINDING_TOPICS for event in reportable):
        return sort_unique_events(reportable)

    raw_findings = [event for event in events if event.topic in FINDING_INPUT_TOPICS]
    if not raw_findings:
        return []

    # If the user pipes raw findings directly into report, report implies the
    # safe dedupe analysis step before rendering.
    result = dedupe_findings((normalize_event(event) for event in raw_findings), fuzzy_threshold=0.82)
    published = publish_dedupe_result(context, result, threshold=0.82, silent=True)
    return sort_unique_events(event for event in published if event.topic in REPORT_FINDING_TOPICS)


def synthesize_report_findings(
    context: CommandContext,
    context_events: Iterable[Event],
    parsed: Namespace,
) -> list[Event]:
    """Return passive findings synthesized from selected report facts.

    Called by: `analysis.report.Report.run()` before report rendering when
    `analyze=passive` is active.
    """
    mode = str(parsed.analyze)
    if mode == "off":
        return []
    if mode != "passive":
        raise ValueError(f"unknown report analyze mode: {mode}")

    facts = [event for event in context_events if event.topic in PASSIVE_SYNTHESIS_TOPICS]
    if not facts:
        return []

    # Existing report findings are indexed first so repeated `report` commands
    # can reuse prior finding events instead of publishing duplicates.
    existing_by_marker = report_findings_by_marker(context, limit=int(parsed.limit))
    candidates: list[dict[str, object]] = []
    reusable: list[Event] = []
    seen_markers: set[tuple[str, str]] = set()
    for fact in facts:
        # Technology-indicator rules turn passive facts into candidate finding
        # payloads; report only orchestrates the safe rule bundle.
        for candidate in findings_from_event(fact):
            marker = finding_marker(candidate)
            if marker in seen_markers:
                continue
            seen_markers.add(marker)
            existing = existing_by_marker.get(marker)
            if existing is not None:
                reusable.append(existing)
                continue
            candidates.append(candidate)

    if not candidates:
        return sort_unique_events(reusable)

    # New candidate findings are persisted as ordinary events, then the same
    # dedupe path used by explicit `finding_dedupe` promotes grouped findings.
    candidate_events = [
        context.events.publish("finding.candidate", candidate)
        for candidate in candidates
    ]
    result = dedupe_findings((normalize_event(event) for event in candidate_events), fuzzy_threshold=0.82)
    dedupe_events = publish_dedupe_result(context, result, threshold=0.82, silent=True)
    return sort_unique_events([*reusable, *candidate_events, *dedupe_events])


def report_findings_by_marker(context: CommandContext, *, limit: int) -> dict[tuple[str, str], Event]:
    """Return already stored report findings keyed by class and target scope.

    Called by: `synthesize_report_findings()` to avoid duplicate report-time
    synthesis on repeated report runs.
    """
    existing: dict[tuple[str, str], Event] = {}
    for topic in REPORT_FINDING_TOPICS:
        for event in context.events.query(topic=topic, limit=limit):
            marker = finding_marker(event.payload)
            if marker == ("", ""):
                continue
            current = existing.get(marker)
            # Keep the newest event for each marker. Newer review/report data
            # should win when the event store already contains equivalent
            # findings.
            if current is None or (event.id or 0) > (current.id or 0):
                existing[marker] = event
    return existing


def finding_marker(payload: Mapping[str, object]) -> tuple[str, str]:
    """Return a stable marker for suppressing repeated report synthesis.

    Called by: report synthesis when comparing candidate payloads with stored
    report findings.
    """
    finding_class = str(payload.get("class") or "")
    target_scope = payload.get("target_scope")
    if not finding_class or not isinstance(target_scope, Mapping):
        return "", ""
    # Sort target-scope keys so equivalent payloads produce the same marker
    # regardless of dictionary insertion order.
    return finding_class, "|".join(f"{key}={target_scope[key]}" for key in sorted(target_scope))
