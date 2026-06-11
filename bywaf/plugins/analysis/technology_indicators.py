"""Passive technology/version indicator findings.

Promotes existing banner, service, endpoint, and web fingerprint facts into
candidate findings when they match a small curated vulnerable-version table.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import cast

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, ManifestCommandlet, RunConfig
from bywaf.plugins.analysis.finding.dedupe import dedupe_findings
from bywaf.plugins.analysis.finding.dedupe.normalize import normalize_event
from bywaf.plugins.analysis.finding.dedupe.publish import publish_dedupe_result, summary_line

from .technology_indicator_payloads import candidate_for_rule, evidence_text
from .technology_indicator_rules import RULES, VersionIndicatorRule, matching_rules

INDICATOR_INPUT_TOPICS = {"service.detected", "tcp.banner", "http.endpoint", "web.fingerprint"}


class TechnologyIndicators(ManifestCommandlet):
    """Emit candidate findings for passive vulnerable-version indicators."""

    manifest_name = "technology_indicators"

    def handle(self, context: CommandContext, cfg: RunConfig, input_events: Iterable[Event]):
        """Emit candidate findings for passive vulnerable-version indicators."""
        cfg = cast(TechnologyIndicatorsConfig, cfg)
        publish_indicator_candidates(context, input_events, silent=cfg.silent)
        return ()


class TechReview(ManifestCommandlet):
    """Emit and deduplicate passive technology/version indicator findings."""

    manifest_name = "tech_review"

    def handle(self, context: CommandContext, cfg: RunConfig, input_events: Iterable[Event]):
        """Emit and deduplicate passive technology/version indicator findings."""
        cfg = cast(TechnologyIndicatorsConfig, cfg)
        candidate_events = publish_indicator_candidates(context, input_events, silent=cfg.silent)
        result = dedupe_findings((normalize_event(event) for event in candidate_events), fuzzy_threshold=0.82)
        publish_dedupe_result(context, result, threshold=0.82, silent=cfg.silent)
        context.output("tech_review: " + summary_line(result).removeprefix("finding_dedupe: "))
        return ()


class TechnologyIndicatorsConfig(RunConfig):
    """Typed effective config for technology indicator commandlets."""

    silent: bool


def publish_indicator_candidates(context: CommandContext, input_events: Iterable[Event], *, silent: bool) -> list[Event]:
    """Publish deduped indicator candidates from upstream passive facts.

    Called by: `TechnologyIndicators.handle()` and `TechReview.handle()`.
    """
    published: list[Event] = []
    seen: set[tuple[str, str]] = set()
    for event in input_events:
        for finding in findings_from_event(event):
            marker = (str(finding["class"]), str(finding["target_scope"]))
            if marker in seen:
                continue
            seen.add(marker)
            published.append(context.events.publish("finding.candidate", finding))
            context.alert(str(finding["title"]), level="finding", silent=silent)
    return published


def findings_from_event(event: Event) -> list[dict[str, object]]:
    """Return candidate findings derived from one upstream fact event.

    Called by: `technology_indicators`, `tech_review`, and report passive
    synthesis.
    """
    if event.topic not in INDICATOR_INPUT_TOPICS:
        return []
    payload = dict(event.payload)
    evidence = evidence_text(payload)
    return [candidate_for_rule(rule, payload=payload, evidence=evidence, source_topic=event.topic) for rule in matching_rules(evidence)]


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return technology_indicators


def plugins() -> tuple[Commandlet, ...]:
    """Return technology indicator commandlets."""
    return technology_indicators, tech_review


technology_indicators = TechnologyIndicators()
tech_review = TechReview()


__all__ = [
    "RULES",
    "TechReview",
    "TechnologyIndicators",
    "TechnologyIndicatorsConfig",
    "VersionIndicatorRule",
    "findings_from_event",
    "matching_rules",
    "plugin",
    "plugins",
    "publish_indicator_candidates",
    "tech_review",
    "technology_indicators",
]
